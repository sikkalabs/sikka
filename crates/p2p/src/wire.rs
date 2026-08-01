//! Wire messages exchanged between nodes.
//!
//! Everything is JSON over plain HTTP. There is no custom framing, no persistent
//! connection state and no handshake: a node is just an HTTP server, which is
//! what makes it deployable behind anything — a reverse proxy, a Tor onion
//! service, a home router.

use serde::{Deserialize, Serialize};

use sikka_common::bytes::Hash;
use sikka_common::checkpoint::Checkpoint;
use sikka_common::transaction::Transaction;
use sikka_common::vote::Vote;
use sikka_consensus::proposal::CheckpointProposal;

use crate::bloom::BloomFilter;
use crate::peers::{Peer, PeerAnnounce};

/// The message kinds a node handles, mirroring the endpoint set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKind {
    Transaction,
    Vote,
    Checkpoint,
    StateRequest,
    StateResponse,
    PeerAnnounce,
}

/// `POST /api/tx`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTransaction {
    pub transaction: Transaction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitTransactionResponse {
    pub id: Hash,
    /// False when the transaction was already known.
    pub accepted: bool,
}

/// `POST /api/tx/sync` — "here is what I have; send me what I am missing".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxSyncRequest {
    pub filter: BloomFilter,
    /// Cap on how many transactions to return.
    #[serde(default = "default_sync_limit")]
    pub limit: usize,
}

fn default_sync_limit() -> usize {
    1_000
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxSyncResponse {
    pub transactions: Vec<Transaction>,
    /// The responder's own filter, so a single round trip syncs both ways.
    pub filter: BloomFilter,
}

/// `POST /api/vote`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitVote {
    pub vote: Vote,
}

/// `POST /api/checkpoint/proposal`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitProposal {
    pub proposal: CheckpointProposal,
}

/// The reply to a proposal: the vote, when this node agrees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProposalResponse {
    pub accepted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vote: Option<Vote>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// `POST /api/checkpoint/finalized`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubmitCheckpoint {
    pub checkpoint: Checkpoint,
    /// The transactions the checkpoint applied, for nodes that missed the
    /// proposal and need to replay it.
    #[serde(default)]
    pub transactions: Vec<Transaction>,
}

/// `POST /api/peers`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeersRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce: Option<PeerAnnounce>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeersResponse {
    pub peers: Vec<Peer>,
}

/// `GET /api/checkpoint/pending` — open proposal this node would still like
/// the network to finalize, if any.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingProposalResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposal: Option<CheckpointProposal>,
}

/// `GET /api/health`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Health {
    pub chain_id: String,
    pub height: u64,
    pub state_root: Hash,
    pub mempool: usize,
    pub peers: usize,
    pub validator: bool,
}

/// A uniform error body, so a client can tell a rejection from an outage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

impl ErrorBody {
    pub fn new(error: impl std::fmt::Display) -> Self {
        Self {
            error: error.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::Address;
    use sikka_crypto::Keypair;

    #[test]
    fn transaction_submission_roundtrips() {
        let kp = Keypair::generate().unwrap();
        let tx = Transaction::transfer(&kp, Address([1u8; 32]), 10, 0, 1_700_000_000).unwrap();
        let message = SubmitTransaction {
            transaction: tx.clone(),
        };
        let json = serde_json::to_string(&message).unwrap();
        let parsed: SubmitTransaction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.transaction, tx);
    }

    #[test]
    fn sync_request_has_a_default_limit() {
        let filter = BloomFilter::default();
        let json = serde_json::to_string(&serde_json::json!({ "filter": filter })).unwrap();
        let parsed: TxSyncRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.limit, 1_000);
    }

    #[test]
    fn proposal_response_omits_empty_fields() {
        let response = ProposalResponse {
            accepted: true,
            vote: None,
            reason: None,
        };
        let json = serde_json::to_string(&response).unwrap();
        assert_eq!(json, r#"{"accepted":true}"#);
    }

    #[test]
    fn peers_request_allows_a_bare_query() {
        let parsed: PeersRequest = serde_json::from_str("{}").unwrap();
        assert!(parsed.announce.is_none());
    }
}
