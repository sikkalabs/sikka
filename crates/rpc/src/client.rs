//! JSON-RPC client used by the wallet and the CLI.

use std::time::Duration;

use sikka_common::bytes::{Address, Hash};
use sikka_common::checkpoint::Checkpoint;
use sikka_common::constants::MAX_RPC_BODY_BYTES;
use sikka_common::error::{Error, Result};
use sikka_common::transaction::Transaction;

use crate::types::{
    AccountInfo, AccountProof, ChainInfo, MempoolInfo, TxReceipt, TxStatus, ValidatorInfo,
};
use crate::{method, RpcRequest, RpcResponse};

/// A client for one node's JSON-RPC endpoint.
#[derive(Debug, Clone)]
pub struct RpcClient {
    endpoint: String,
    http: reqwest::Client,
}

impl RpcClient {
    pub fn new(endpoint: impl Into<String>) -> Result<Self> {
        Self::with_timeout(endpoint, Duration::from_secs(15))
    }

    pub fn with_timeout(endpoint: impl Into<String>, timeout: Duration) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| Error::Network(e.to_string()))?;
        Ok(Self {
            endpoint: endpoint.into().trim_end_matches('/').to_string(),
            http,
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Issue a call and deserialise its result.
    pub async fn call<R: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<R> {
        let request = RpcRequest::new(method, params);
        let response = self
            .http
            .post(format!("{}/api/rpc", self.endpoint))
            .json(&request)
            .send()
            .await
            .map_err(|e| Error::Network(format!("{method}: {e}")))?;

        let status = response.status();
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_BODY_BYTES as u64)
        {
            return Err(Error::Network(format!(
                "{} exceeded the {MAX_RPC_BODY_BYTES}-byte response limit",
                self.endpoint
            )));
        }
        let mut raw = Vec::new();
        let mut response = response;
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| Error::Network(e.to_string()))?
        {
            if raw.len().saturating_add(chunk.len()) > MAX_RPC_BODY_BYTES {
                return Err(Error::Network(format!(
                    "{} exceeded the {MAX_RPC_BODY_BYTES}-byte response limit",
                    self.endpoint
                )));
            }
            raw.extend_from_slice(&chunk);
        }
        let body = String::from_utf8(raw).map_err(|e| {
            Error::Network(format!("{} sent non-UTF8 body: {e}", self.endpoint))
        })?;
        if !status.is_success() {
            return Err(Error::Network(format!(
                "{} returned {status}: {}",
                self.endpoint,
                body.chars().take(200).collect::<String>()
            )));
        }

        let envelope: RpcResponse = serde_json::from_str(&body)
            .map_err(|e| Error::Network(format!("{method} sent an unreadable response: {e}")))?;
        if let Some(error) = envelope.error {
            return Err(Error::Other(format!(
                "{method}: {} ({})",
                error.message, error.code
            )));
        }
        let result = envelope.result.ok_or_else(|| {
            Error::Network(format!("{method} returned neither a result nor an error"))
        })?;
        serde_json::from_value(result)
            .map_err(|e| Error::Network(format!("{method} result did not parse: {e}")))
    }

    pub async fn chain_info(&self) -> Result<ChainInfo> {
        self.call(method::CHAIN_INFO, serde_json::Value::Null).await
    }

    pub async fn account(&self, address: &Address) -> Result<AccountInfo> {
        self.call(
            method::ACCOUNT_GET,
            serde_json::json!({ "address": address }),
        )
        .await
    }

    pub async fn account_proof(&self, address: &Address) -> Result<AccountProof> {
        self.call(
            method::ACCOUNT_PROOF,
            serde_json::json!({ "address": address }),
        )
        .await
    }

    pub async fn submit(&self, transaction: &Transaction) -> Result<TxReceipt> {
        self.call(
            method::TX_SUBMIT,
            serde_json::json!({ "transaction": transaction }),
        )
        .await
    }

    pub async fn transaction_status(&self, id: &Hash) -> Result<TxStatus> {
        self.call(method::TX_STATUS, serde_json::json!({ "id": id }))
            .await
    }

    /// Fetch a checkpoint, or the latest one when `height` is `None`.
    pub async fn checkpoint(&self, height: Option<u64>) -> Result<Checkpoint> {
        let params = match height {
            Some(height) => serde_json::json!({ "height": height }),
            None => serde_json::Value::Null,
        };
        self.call(method::CHECKPOINT_GET, params).await
    }

    pub async fn validators(&self) -> Result<Vec<ValidatorInfo>> {
        self.call(method::VALIDATOR_LIST, serde_json::Value::Null)
            .await
    }

    pub async fn peers(&self) -> Result<Vec<sikka_common::bytes::Address>> {
        let peers: Vec<serde_json::Value> = self
            .call(method::PEER_LIST, serde_json::Value::Null)
            .await?;
        Ok(peers
            .into_iter()
            .filter_map(|p| p.get("address").cloned())
            .filter_map(|a| serde_json::from_value(a).ok())
            .collect())
    }

    pub async fn mempool(&self) -> Result<MempoolInfo> {
        self.call(method::MEMPOOL_INFO, serde_json::Value::Null)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoints_are_normalised() {
        let client = RpcClient::new("http://localhost:64552/").unwrap();
        assert_eq!(client.endpoint(), "http://localhost:64552");
    }
}
