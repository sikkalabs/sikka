//! JSON-RPC 2.0 protocol for wallets and clients.
//!
//! The RPC surface is shaped by what a stateless wallet actually needs: a
//! balance, a nonce, a battery level, a way to submit a signed transaction, and a
//! Merkle proof it can check against a signed checkpoint. There are no
//! history-walking methods, because there is no history to walk.

pub mod client;
pub mod types;

pub use client::RpcClient;
pub use types::*;

use serde::{Deserialize, Serialize};

/// A JSON-RPC 2.0 request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcRequest {
    #[serde(default = "jsonrpc_version")]
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    #[serde(default)]
    pub id: serde_json::Value,
}

fn jsonrpc_version() -> String {
    "2.0".to_string()
}

impl RpcRequest {
    pub fn new(method: impl Into<String>, params: serde_json::Value) -> Self {
        Self {
            jsonrpc: jsonrpc_version(),
            method: method.into(),
            params,
            id: serde_json::Value::from(1),
        }
    }
}

/// A JSON-RPC 2.0 response: exactly one of `result` or `error`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: serde_json::Value,
}

impl RpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: jsonrpc_version(),
            result: Some(result),
            error: None,
            id,
        }
    }

    pub fn failure(id: serde_json::Value, error: RpcError) -> Self {
        Self {
            jsonrpc: jsonrpc_version(),
            result: None,
            error: Some(error),
            id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcError {
    /// JSON-RPC reserved: the method does not exist.
    pub fn method_not_found(method: &str) -> Self {
        Self {
            code: -32601,
            message: format!("unknown method '{method}'"),
        }
    }

    /// JSON-RPC reserved: parameters were missing or the wrong shape.
    pub fn invalid_params(message: impl std::fmt::Display) -> Self {
        Self {
            code: -32602,
            message: message.to_string(),
        }
    }

    /// JSON-RPC reserved: the request itself was malformed.
    pub fn invalid_request(message: impl std::fmt::Display) -> Self {
        Self {
            code: -32600,
            message: message.to_string(),
        }
    }

    /// Application error: the request was well formed but could not be served.
    pub fn application(message: impl std::fmt::Display) -> Self {
        Self {
            code: -32000,
            message: message.to_string(),
        }
    }
}

/// Every method the node serves.
pub mod method {
    pub const CHAIN_INFO: &str = "chain.info";
    pub const ACCOUNT_GET: &str = "account.get";
    pub const ACCOUNT_PROOF: &str = "account.proof";
    pub const TX_SUBMIT: &str = "tx.submit";
    pub const TX_STATUS: &str = "tx.status";
    pub const CHECKPOINT_GET: &str = "checkpoint.get";
    pub const VALIDATOR_LIST: &str = "validator.list";
    pub const PEER_LIST: &str = "peer.list";
    pub const MEMPOOL_INFO: &str = "mempool.info";

    /// All method names, for discovery and for the CLI's help text.
    pub const ALL: &[&str] = &[
        CHAIN_INFO,
        ACCOUNT_GET,
        ACCOUNT_PROOF,
        TX_SUBMIT,
        TX_STATUS,
        CHECKPOINT_GET,
        VALIDATOR_LIST,
        PEER_LIST,
        MEMPOOL_INFO,
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_defaults_the_version() {
        let parsed: RpcRequest = serde_json::from_str(r#"{"method":"chain.info","id":7}"#).unwrap();
        assert_eq!(parsed.jsonrpc, "2.0");
        assert_eq!(parsed.method, "chain.info");
        assert_eq!(parsed.id, serde_json::Value::from(7));
        assert_eq!(parsed.params, serde_json::Value::Null);
    }

    #[test]
    fn responses_carry_result_or_error_but_not_both() {
        let ok = RpcResponse::success(1.into(), serde_json::json!({"height": 5}));
        let json = serde_json::to_string(&ok).unwrap();
        assert!(!json.contains("error"));

        let err = RpcResponse::failure(1.into(), RpcError::method_not_found("nope"));
        let json = serde_json::to_string(&err).unwrap();
        assert!(!json.contains("result"));
        assert!(json.contains("-32601"));
    }

    #[test]
    fn every_method_name_is_namespaced() {
        for name in method::ALL {
            assert!(name.contains('.'), "{name} should be namespaced");
        }
        assert_eq!(method::ALL.len(), 9);
    }
}
