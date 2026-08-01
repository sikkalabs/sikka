//! Outbound HTTP client.
//!
//! One `reqwest` client, reused for every peer. Messages are already signed at
//! the application layer, so plain HTTP(S) is enough — reverse proxies and TLS
//! terminators are fine.

use std::path::Path;
use std::time::Duration;

use sikka_common::bytes::Hash;
use sikka_common::checkpoint::Checkpoint;
use sikka_common::constants::{BULK_REQUEST_TIMEOUT_SECS, MAX_HTTP_BODY_BYTES, MAX_RPC_BODY_BYTES};
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
use crate::peers::{Peer, PeerAnnounce};
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
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            bulk_timeout: Duration::from_secs(BULK_REQUEST_TIMEOUT_SECS),
        }
    }
}

/// Typed client for the federation endpoints.
#[derive(Debug, Clone)]
pub struct PeerClient {
    http: reqwest::Client,
    timeout: Duration,
    bulk_timeout: Duration,
}

impl PeerClient {
    pub fn new(config: &ClientConfig) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            // Federation is request/response with many peers; pooling idle
            // sockets to all of them buys nothing.
            .pool_max_idle_per_host(2)
            .user_agent(concat!("sikka/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(Self {
            http,
            timeout: config.timeout,
            bulk_timeout: config.bulk_timeout,
        })
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
            .http
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
            .http
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
            .http
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_join_without_doubling_slashes() {
        assert_eq!(
            PeerClient::url("http://a:8080", "tx"),
            "http://a:8080/api/tx"
        );
        assert_eq!(
            PeerClient::url("http://a:8080/", "/tx"),
            "http://a:8080/api/tx"
        );
        assert_eq!(
            PeerClient::url("http://a:8080", "checkpoint/7"),
            "http://a:8080/api/checkpoint/7"
        );
    }

    #[test]
    fn client_builds_with_defaults() {
        PeerClient::new(&ClientConfig::default()).unwrap();
        PeerClient::new(&ClientConfig {
            timeout: Duration::from_secs(5),
            bulk_timeout: Duration::from_secs(60),
        })
        .unwrap();
    }
}
