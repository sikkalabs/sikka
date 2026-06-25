//! Outbound HTTP client.
//!
//! One `reqwest` client stack, reused for every peer. Messages are already
//! signed at the application layer. Production dials use Tor SOCKS5h for
//! `.onion` peers; loopback unit tests dial directly.

use std::path::Path;
use std::time::Duration;

use sikka_common::bytes::Hash;
use sikka_common::checkpoint::Checkpoint;
use sikka_common::constants::{
    BULK_REQUEST_TIMEOUT_SECS, MAX_HTTP_BODY_BYTES, MAX_RPC_BODY_BYTES, PEER_REQUEST_TIMEOUT_SECS,
};
use sikka_common::error::{Error, Result};
use sikka_common::transaction::Transaction;
use sikka_common::vote::Vote;
use sikka_consensus::proposal::CheckpointProposal;
use sikka_state::{
    SnapshotDownload, SnapshotManifest, StateSnapshot, SNAPSHOT_MAX_COMPRESSED_CHUNK_BYTES,
    SNAPSHOT_MAX_MANIFEST_BYTES,
};
use tracing::{info, warn};

use crate::bloom::BloomFilter;
use crate::peers::{is_loopback_endpoint, is_onion_endpoint, Peer, PeerAnnounce};
use crate::wire::{
    Health, PeersRequest, PeersResponse, ProposalResponse, SubmitCheckpoint, SubmitProposal,
    SubmitTransaction, SubmitTransactionResponse, SubmitVote, TxSyncRequest, TxSyncResponse,
};

/// How a node reaches its peers.
#[derive(Debug, Clone)]
pub struct ClientConfig {
    /// Timeout for ordinary peer calls (health, votes, single transactions).
    pub timeout: Duration,
    /// Timeout for large transfers (proposals, finalized checkpoints, sync,
    /// and each independently resumable snapshot chunk).
    pub bulk_timeout: Duration,
    /// SOCKS5h proxy (`host:port`) for `.onion` dials. `None` for loopback-only tests.
    pub socks_proxy: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(PEER_REQUEST_TIMEOUT_SECS),
            bulk_timeout: Duration::from_secs(BULK_REQUEST_TIMEOUT_SECS),
            socks_proxy: None,
        }
    }
}

/// Typed client for the federation endpoints.
#[derive(Debug, Clone)]
pub struct PeerClient {
    direct: reqwest::Client,
    tor: Option<reqwest::Client>,
    timeout: Duration,
    bulk_timeout: Duration,
}

impl PeerClient {
    pub fn new(config: &ClientConfig) -> Result<Self> {
        let direct = build_http_client(config.timeout, None)?;
        let tor = match &config.socks_proxy {
            Some(addr) => Some(build_http_client(config.timeout, Some(addr))?),
            None => None,
        };
        Ok(Self {
            direct,
            tor,
            timeout: config.timeout,
            bulk_timeout: config.bulk_timeout,
        })
    }

    fn http_for(&self, endpoint: &str) -> Result<&reqwest::Client> {
        if is_loopback_endpoint(endpoint) {
            return Ok(&self.direct);
        }
        if is_onion_endpoint(endpoint) {
            return self.tor.as_ref().ok_or_else(|| {
                Error::Network("onion peer dial requires socks_proxy".into())
            });
        }
        Err(Error::Network(format!(
            "refusing to dial non-onion peer endpoint {endpoint}"
        )))
    }

    fn url(endpoint: &str, path: &str) -> String {
        format!(
            "{}/api/{}",
            endpoint.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    async fn post<B: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        path: &str,
        body: &B,
    ) -> Result<R> {
        self.post_timed(endpoint, path, body, self.timeout).await
    }

    async fn post_bulk<B: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        path: &str,
        body: &B,
    ) -> Result<R> {
        self.post_timed(endpoint, path, body, self.bulk_timeout)
            .await
    }

    async fn post_timed<B: serde::Serialize, R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        path: &str,
        body: &B,
        timeout: Duration,
    ) -> Result<R> {
        let maximum = if timeout >= self.bulk_timeout {
            MAX_HTTP_BODY_BYTES
        } else {
            MAX_RPC_BODY_BYTES
        };
        let response = self
            .http_for(endpoint)?
            .post(Self::url(endpoint, path))
            .timeout(timeout)
            .json(body)
            .send()
            .await
            .map_err(|e| Error::Network(format!("{path} to {endpoint}: {e}")))?;
        Self::decode(response, endpoint, path, maximum).await
    }

    async fn get<R: serde::de::DeserializeOwned>(&self, endpoint: &str, path: &str) -> Result<R> {
        self.get_timed(endpoint, path, self.timeout).await
    }

    async fn get_timed<R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        path: &str,
        timeout: Duration,
    ) -> Result<R> {
        let maximum = if timeout >= self.bulk_timeout {
            MAX_HTTP_BODY_BYTES
        } else {
            MAX_RPC_BODY_BYTES
        };
        let response = self
            .http_for(endpoint)?
            .get(Self::url(endpoint, path))
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| Error::Network(format!("{path} from {endpoint}: {e}")))?;
        Self::decode(response, endpoint, path, maximum).await
    }

    async fn get_bytes_timed(
        &self,
        endpoint: &str,
        path: &str,
        timeout: Duration,
        maximum: usize,
    ) -> Result<Vec<u8>> {
        let mut response = self
            .http_for(endpoint)?
            .get(Self::url(endpoint, path))
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| Error::Network(format!("{path} from {endpoint}: {e}")))?;
        let status = response.status();
        if !status.is_success() {
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|e| Error::Network(format!("{path} from {endpoint}: {e}")))?
            {
                let remaining = 8 * 1024usize - body.len();
                body.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
                if body.len() == 8 * 1024 {
                    break;
                }
            }
            return Err(Error::Network(format!(
                "{endpoint}{path} returned {status}: {}",
                String::from_utf8_lossy(&body)
                    .chars()
                    .take(200)
                    .collect::<String>()
            )));
        }
        if response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
        {
            return Err(Error::Network(format!(
                "{endpoint}{path} exceeds the {maximum}-byte response limit"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::Network(format!("{path} from {endpoint}: {e}")))?
        {
            if body.len().saturating_add(chunk.len()) > maximum {
                return Err(Error::Network(format!(
                    "{endpoint}{path} exceeds the {maximum}-byte response limit"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    async fn decode<R: serde::de::DeserializeOwned>(
        response: reqwest::Response,
        endpoint: &str,
        path: &str,
        maximum: usize,
    ) -> Result<R> {
        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > maximum as u64)
        {
            return Err(Error::Network(format!(
                "{endpoint}{path} exceeds the {maximum}-byte response limit"
            )));
        }
        let mut body = Vec::new();
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::Network(e.to_string()))?
        {
            if body.len().saturating_add(chunk.len()) > maximum {
                return Err(Error::Network(format!(
                    "{endpoint}{path} exceeds the {maximum}-byte response limit"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(body).map_err(|e| {
            Error::Network(format!("{endpoint}{path} sent non-UTF8 body: {e}"))
        })?;
        if !status.is_success() {
            // Surface the peer's own reason when it sent one.
            let reason = serde_json::from_str::<crate::wire::ErrorBody>(&body)
                .map(|e| e.error)
                .unwrap_or_else(|_| body.chars().take(200).collect());
            return Err(Error::Network(format!(
                "{endpoint}{path} returned {status}: {reason}"
            )));
        }
        serde_json::from_str(&body).map_err(|e| {
            Error::Network(format!("{endpoint}{path} sent an unreadable response: {e}"))
        })
    }

    pub async fn health(&self, endpoint: &str) -> Result<Health> {
        self.get(endpoint, "health").await
    }

    pub async fn submit_transaction(
        &self,
        endpoint: &str,
        transaction: &Transaction,
    ) -> Result<SubmitTransactionResponse> {
        self.post(
            endpoint,
            "tx",
            &SubmitTransaction {
                transaction: transaction.clone(),
            },
        )
        .await
    }

    /// Exchange mempool contents with a peer in one round trip.
    pub async fn sync_transactions(
        &self,
        endpoint: &str,
        filter: BloomFilter,
        limit: usize,
    ) -> Result<TxSyncResponse> {
        self.post_bulk(endpoint, "tx/sync", &TxSyncRequest { filter, limit })
            .await
    }

    pub async fn submit_vote(&self, endpoint: &str, vote: &Vote) -> Result<()> {
        let _: serde_json::Value = self
            .post(endpoint, "vote", &SubmitVote { vote: vote.clone() })
            .await?;
        Ok(())
    }

    pub async fn submit_proposal(
        &self,
        endpoint: &str,
        proposal: &CheckpointProposal,
    ) -> Result<ProposalResponse> {
        self.post_bulk(
            endpoint,
            "checkpoint/proposal",
            &SubmitProposal {
                proposal: proposal.clone(),
            },
        )
        .await
    }

    /// Fetch a peer's open (pending or locked) proposal for the height still
    /// being decided, if it has one.
    pub async fn pending_proposal(
        &self,
        endpoint: &str,
    ) -> Result<Option<CheckpointProposal>> {
        let response: crate::wire::PendingProposalResponse =
            self.get(endpoint, "checkpoint/pending").await?;
        Ok(response.proposal)
    }

    pub async fn submit_checkpoint(
        &self,
        endpoint: &str,
        checkpoint: &Checkpoint,
        transactions: &[Transaction],
        evidence: &[sikka_consensus::Equivocation],
    ) -> Result<()> {
        let body = SubmitCheckpoint {
            checkpoint: checkpoint.clone(),
            transactions: transactions.to_vec(),
            evidence: evidence.to_vec(),
        };
        let _: serde_json::Value = self
            .post_bulk(endpoint, "checkpoint/finalized", &body)
            .await?;
        Ok(())
    }

    pub async fn checkpoint(&self, endpoint: &str, height: u64) -> Result<Checkpoint> {
        self.get(endpoint, &format!("checkpoint/{height}")).await
    }

    pub async fn latest_checkpoint(&self, endpoint: &str) -> Result<Checkpoint> {
        self.get(endpoint, "checkpoint/latest").await
    }

    /// Announce ourselves and learn the peer's peers.
    pub async fn announce(
        &self,
        endpoint: &str,
        announce: Option<&PeerAnnounce>,
    ) -> Result<Vec<Peer>> {
        let body = PeersRequest {
            announce: announce.cloned(),
        };
        let response: PeersResponse = self.post(endpoint, "peers", &body).await?;
        Ok(response.peers)
    }

    pub async fn snapshot_manifest(&self, endpoint: &str) -> Result<SnapshotManifest> {
        let manifest_bytes = self
            .get_bytes_timed(
                endpoint,
                "state/snapshot/manifest",
                self.bulk_timeout,
                SNAPSHOT_MAX_MANIFEST_BYTES,
            )
            .await?;
        let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes).map_err(|e| {
            Error::Network(format!(
                "{endpoint} sent an unreadable snapshot manifest: {e}"
            ))
        })?;
        manifest.validate()?;
        Ok(manifest)
    }

    /// Download a chunked snapshot, resuming valid chunks already on disk.
    ///
    /// The caller should validate checkpoint trust from the manifest first so
    /// a malicious peer cannot waste bandwidth with unauthorised chunks.
    pub async fn snapshot_from_manifest(
        &self,
        endpoint: &str,
        download_root: impl AsRef<Path>,
        manifest: SnapshotManifest,
    ) -> Result<StateSnapshot> {
        let download = SnapshotDownload::open(download_root, manifest)?;
        info!(
            snapshot = %download.manifest().snapshot_id,
            chunks = download.manifest().chunks.len(),
            accounts = download.manifest().account_count,
            "downloading state snapshot"
        );

        for meta in download.manifest().chunks.clone() {
            if download.has_chunk(&meta) {
                info!(
                    snapshot = %download.manifest().snapshot_id,
                    chunk = meta.index + 1,
                    total = download.manifest().chunks.len(),
                    "reusing verified snapshot chunk"
                );
                continue;
            }
            let path = format!(
                "state/snapshot/{}/chunk/{}",
                download.manifest().snapshot_id.to_hex(),
                meta.index
            );
            let mut last_error = None;
            for attempt in 0..3u32 {
                match self
                    .get_bytes_timed(
                        endpoint,
                        &path,
                        self.bulk_timeout,
                        (meta.compressed_bytes as usize).min(SNAPSHOT_MAX_COMPRESSED_CHUNK_BYTES),
                    )
                    .await
                    .and_then(|bytes| download.store_chunk(&meta, &bytes))
                {
                    Ok(()) => {
                        last_error = None;
                        break;
                    }
                    Err(error) => {
                        warn!(
                            peer = %endpoint,
                            chunk = meta.index + 1,
                            attempt = attempt + 1,
                            %error,
                            "snapshot chunk download failed"
                        );
                        last_error = Some(error);
                        if attempt < 2 {
                            tokio::time::sleep(Duration::from_secs(1u64 << attempt)).await;
                        }
                    }
                }
            }
            if let Some(error) = last_error {
                return Err(error);
            }
            info!(
                snapshot = %download.manifest().snapshot_id,
                chunk = meta.index + 1,
                total = download.manifest().chunks.len(),
                bytes = meta.compressed_bytes,
                "downloaded snapshot chunk"
            );
        }

        tokio::task::spawn_blocking(move || download.decode())
            .await
            .map_err(|e| Error::Other(format!("snapshot decode task failed: {e}")))?
    }

    /// Convenience wrapper for callers that validate trust after download.
    pub async fn snapshot(
        &self,
        endpoint: &str,
        download_root: impl AsRef<Path>,
    ) -> Result<StateSnapshot> {
        let manifest = self.snapshot_manifest(endpoint).await?;
        self.snapshot_from_manifest(endpoint, download_root, manifest)
            .await
    }

    /// Ask a peer whether it holds a transaction, used only by diagnostics.
    pub async fn has_transaction(&self, endpoint: &str, id: &Hash) -> Result<bool> {
        let response: serde_json::Value =
            self.get(endpoint, &format!("tx/{}", id.to_hex())).await?;
        Ok(response
            .get("known")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }
}

fn build_http_client(timeout: Duration, socks: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .pool_max_idle_per_host(2)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("sikka/", env!("CARGO_PKG_VERSION")));
    if let Some(addr) = socks {
        let proxy_url = if addr.contains("://") {
            addr.to_string()
        } else {
            format!("socks5h://{addr}")
        };
        let proxy = reqwest::Proxy::all(&proxy_url).map_err(|e| Error::Network(e.to_string()))?;
        builder = builder.proxy(proxy);
    }
    builder
        .build()
        .map_err(|e| Error::Network(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_join_without_doubling_slashes() {
        assert_eq!(
            PeerClient::url("http://127.0.0.1:8080", "tx"),
            "http://127.0.0.1:8080/api/tx"
        );
        assert_eq!(
            PeerClient::url("http://127.0.0.1:8080/", "/tx"),
            "http://127.0.0.1:8080/api/tx"
        );
        assert_eq!(
            PeerClient::url("http://127.0.0.1:8080", "checkpoint/7"),
            "http://127.0.0.1:8080/api/checkpoint/7"
        );
    }

    #[test]
    fn client_builds_with_defaults() {
        PeerClient::new(&ClientConfig::default()).unwrap();
        PeerClient::new(&ClientConfig {
            timeout: Duration::from_secs(5),
            bulk_timeout: Duration::from_secs(60),
            socks_proxy: None,
        })
        .unwrap();
        PeerClient::new(&ClientConfig {
            socks_proxy: Some("127.0.0.1:9050".into()),
            ..ClientConfig::default()
        })
        .unwrap();
    }

    /// A peer that answers every request with `307` must not be followed to the
    /// redirect target: otherwise a malicious peer could replay signed bodies
    /// (or probe) internal hosts the node can reach.
    #[tokio::test]
    async fn redirects_are_not_followed() {
        let client = PeerClient::new(&ClientConfig {
            timeout: Duration::from_secs(5),
            bulk_timeout: Duration::from_secs(30),
            socks_proxy: None,
        })
        .unwrap();

        // The would-be redirect target: had the client followed the 307 it
        // would get a valid health response here and succeed.
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let target_hit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let target_hit2 = target_hit.clone();
        let target_task = tokio::spawn(async move {
            let Ok((mut socket, _)) = target.accept().await else {
                return;
            };
            target_hit2.store(true, std::sync::atomic::Ordering::SeqCst);
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
            let body = br#"{"chain_id":"sikka","height":0,"state_root":"0000000000000000000000000000000000000000000000000000000000000000","mempool":0,"peers":0,"validator":false}"#;
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ",
            )
            .await;
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                body.len().to_string().as_bytes(),
            )
            .await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, b"\r\n\r\n").await;
            let _ = tokio::io::AsyncWriteExt::write_all(&mut socket, body).await;
        });

        let redirect = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let redirect_addr = redirect.local_addr().unwrap();
        let redirect_task = tokio::spawn(async move {
            let Ok((mut socket, _)) = redirect.accept().await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut socket,
                format!(
                    "HTTP/1.1 307 Temporary Redirect\r\nlocation: http://{target_addr}/api/health\r\ncontent-length: 0\r\n\r\n"
                )
                .as_bytes(),
            )
            .await;
        });

        let endpoint = format!("http://{redirect_addr}");
        assert!(client.health(&endpoint).await.is_err());
        assert!(
            !target_hit.load(std::sync::atomic::Ordering::SeqCst),
            "the redirect target must never be reached"
        );
        // Neither server should still be waiting; give them a moment. The
        // target is *expected* to still be blocked accept()ing — that is the
        // point — so bound the wait instead of awaiting it forever.
        let _ = tokio::time::timeout(Duration::from_secs(2), redirect_task).await;
        target_task.abort();
    }
}
