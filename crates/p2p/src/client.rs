//! Outbound HTTP client.
//!
//! One `reqwest` client, reused for every peer. If a SOCKS5 proxy is configured
//! all traffic goes through it, which is how a node reaches `.onion` peers — the
//! protocol itself needs no changes, because every message is already signed and
//! there is nothing to protect in transit beyond metadata.

use std::time::Duration;

use sikka_common::bytes::Hash;
use sikka_common::checkpoint::Checkpoint;
use sikka_common::constants::BULK_REQUEST_TIMEOUT_SECS;
use sikka_common::error::{Error, Result};
use sikka_common::transaction::Transaction;
use sikka_common::vote::Vote;
use sikka_consensus::proposal::CheckpointProposal;

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
    /// snapshots). Full JSON checkpoints can be hundreds of MiB over Tor.
    pub bulk_timeout: Duration,
    /// `socks5h://host:port`, typically a local Tor daemon. `socks5h` resolves
    /// names through the proxy, which is required for `.onion`.
    pub socks_proxy: Option<String>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            bulk_timeout: Duration::from_secs(BULK_REQUEST_TIMEOUT_SECS),
            socks_proxy: None,
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
        let mut builder = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            // Federation is request/response with many peers; pooling idle
            // sockets to all of them buys nothing.
            .pool_max_idle_per_host(2)
            .user_agent(concat!("sikka/", env!("CARGO_PKG_VERSION")));

        if let Some(proxy) = &config.socks_proxy {
            let proxy = reqwest::Proxy::all(proxy)
                .map_err(|e| Error::Network(format!("invalid SOCKS proxy: {e}")))?;
            builder = builder.proxy(proxy);
        }

        let http = builder.build().map_err(|e| Error::Network(e.to_string()))?;
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
        let response = self
            .http
            .post(Self::url(endpoint, path))
            .timeout(timeout)
            .json(body)
            .send()
            .await
            .map_err(|e| Error::Network(format!("{path} to {endpoint}: {e}")))?;
        Self::decode(response, endpoint, path).await
    }

    async fn get<R: serde::de::DeserializeOwned>(&self, endpoint: &str, path: &str) -> Result<R> {
        self.get_timed(endpoint, path, self.timeout).await
    }

    async fn get_bulk<R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        path: &str,
    ) -> Result<R> {
        self.get_timed(endpoint, path, self.bulk_timeout).await
    }

    async fn get_timed<R: serde::de::DeserializeOwned>(
        &self,
        endpoint: &str,
        path: &str,
        timeout: Duration,
    ) -> Result<R> {
        let response = self
            .http
            .get(Self::url(endpoint, path))
            .timeout(timeout)
            .send()
            .await
            .map_err(|e| Error::Network(format!("{path} from {endpoint}: {e}")))?;
        Self::decode(response, endpoint, path).await
    }

    async fn decode<R: serde::de::DeserializeOwned>(
        response: reqwest::Response,
        endpoint: &str,
        path: &str,
    ) -> Result<R> {
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| Error::Network(e.to_string()))?;
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

    pub async fn submit_checkpoint(
        &self,
        endpoint: &str,
        checkpoint: &Checkpoint,
        transactions: &[Transaction],
    ) -> Result<()> {
        let body = SubmitCheckpoint {
            checkpoint: checkpoint.clone(),
            transactions: transactions.to_vec(),
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

    /// Fetch a full state snapshot for fast sync.
    ///
    /// Any node can serve this, validator or not: the snapshot is verified
    /// against the checkpoint's signatures, so the source does not need trusting.
    pub async fn snapshot(&self, endpoint: &str) -> Result<sikka_state::StateSnapshot> {
        self.get_bulk(endpoint, "state/snapshot").await
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
        assert_eq!(PeerClient::url("http://a:8080", "tx"), "http://a:8080/api/tx");
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
    fn client_builds_with_and_without_a_proxy() {
        PeerClient::new(&ClientConfig::default()).unwrap();
        PeerClient::new(&ClientConfig {
            timeout: Duration::from_secs(5),
            bulk_timeout: Duration::from_secs(60),
            socks_proxy: Some("socks5h://127.0.0.1:9050".into()),
        })
        .unwrap();
    }

    #[test]
    fn an_invalid_proxy_is_reported() {
        let result = PeerClient::new(&ClientConfig {
            timeout: Duration::from_secs(5),
            bulk_timeout: Duration::from_secs(60),
            socks_proxy: Some("not a url".into()),
        });
        assert!(result.is_err());
    }
}
