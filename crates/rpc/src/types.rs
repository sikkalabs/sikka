//! RPC result types.

use serde::{Deserialize, Serialize};

use sikka_common::account::Account;
use sikka_common::bytes::{Address, Hash, PublicKey};
use sikka_common::checkpoint::Checkpoint;
use sikka_common::transaction::Transaction;
use sikka_state::smt::Proof;

/// `chain.info`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInfo {
    pub chain_id: String,
    pub genesis_fingerprint: Hash,
    /// Height of the last finalized checkpoint.
    pub height: u64,
    pub state_root: Hash,
    pub validator_root: Hash,
    pub last_checkpoint_hash: Hash,
    pub last_checkpoint_time: u64,
    /// Total supply in CHILLAR. Grows by 1.5% annually, forever.
    pub total_supply: u64,
    pub total_bonded: u64,
    pub accounts: u64,
    pub active_validators: usize,
    pub checkpoint_tx_interval: u32,
    pub mempool: usize,
    pub peers: usize,
    /// This node's own address.
    pub node_address: Address,
    /// Peer advertise URL (Tor onion in production).
    pub advertise: String,
    /// Whether this node holds a bonded validator key.
    pub validator: bool,
}

/// `account.get`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountInfo {
    pub address: Address,
    /// False for an address that has never received coins.
    pub exists: bool,
    pub balance: u64,
    pub nonce: u64,
    /// Battery as of the last transaction this account sent.
    pub battery: u64,
    /// Battery available right now, including regeneration since then.
    pub battery_now: u64,
    pub last_regen_time: u64,
    /// Seconds until the next battery unit, when there are none left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_until_battery: Option<u64>,
    /// The nonce a new transaction should use, counting anything pending.
    pub next_nonce: u64,
    /// Bond, if this account is a validator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<u64>,
}

impl AccountInfo {
    pub fn from_account(
        address: Address,
        account: Option<Account>,
        now: u64,
        next_nonce: u64,
        bond: Option<u64>,
    ) -> Self {
        match account {
            Some(account) => Self {
                address,
                exists: true,
                balance: account.balance,
                nonce: account.nonce,
                battery: u64::from(account.battery),
                battery_now: u64::from(account.battery_at(now)),
                last_regen_time: account.last_regen_time,
                seconds_until_battery: account.seconds_until_battery(now),
                next_nonce,
                bond,
            },
            None => Self {
                address,
                exists: false,
                balance: 0,
                nonce: 0,
                battery: 0,
                battery_now: 0,
                last_regen_time: 0,
                seconds_until_battery: None,
                next_nonce: 0,
                bond: None,
            },
        }
    }
}

/// `account.proof` — everything a stateless wallet needs to verify a balance
/// without trusting the node that served it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountProof {
    pub address: Address,
    /// `None` together with a valid proof is a proof of *absence*.
    pub account: Option<Account>,
    pub proof: Proof,
    /// The root the proof is against.
    pub state_root: Hash,
    /// The signed checkpoint committing to that root.
    pub checkpoint: Checkpoint,
}

/// `tx.submit`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxReceipt {
    pub id: Hash,
    /// False when the node already had it.
    pub accepted: bool,
}

/// `tx.status`
///
/// A transaction is either pending or forgotten: once its checkpoint is final,
/// only the state it produced remains. To confirm a payment, read the recipient's
/// balance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxStatus {
    pub id: Hash,
    pub pending: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction: Option<Transaction>,
}

/// `validator.list`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub address: Address,
    pub public_key: PublicKey,
    pub bond: u64,
    pub active_from: u64,
    pub active: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unbonding_since: Option<u64>,
    pub slashed: bool,
    /// Consecutive full-batch proposer timeouts; forced unbond at the chain's
    /// `max_missed_proposer_slots` threshold.
    #[serde(default)]
    pub missed_proposer_slots: u32,
}

/// `mempool.info`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolInfo {
    pub pending: usize,
    pub capacity: usize,
    /// Transactions still needed before the next checkpoint fires.
    pub until_checkpoint: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_info_reflects_battery_regeneration() {
        let account = Account {
            balance: 500,
            nonce: 3,
            battery: 2,
            last_regen_time: 1_000,
        };
        let info =
            AccountInfo::from_account(Address([1u8; 32]), Some(account), 1_000 + 180, 3, None);
        assert!(info.exists);
        assert_eq!(info.battery, 2);
        assert_eq!(info.battery_now, 5);
        assert_eq!(info.seconds_until_battery, None);
    }

    #[test]
    fn account_info_for_an_unknown_address_is_all_zero() {
        let info = AccountInfo::from_account(Address([1u8; 32]), None, 1_000, 0, None);
        assert!(!info.exists);
        assert_eq!(info.balance, 0);
        assert_eq!(info.next_nonce, 0);
        assert!(info.bond.is_none());
    }

    #[test]
    fn a_battery_starved_account_reports_the_wait() {
        let account = Account {
            balance: 1,
            nonce: 0,
            battery: 0,
            last_regen_time: 1_000,
        };
        let info = AccountInfo::from_account(Address([1u8; 32]), Some(account), 1_020, 0, None);
        assert_eq!(info.battery_now, 0);
        assert_eq!(info.seconds_until_battery, Some(40));
    }

    #[test]
    fn types_roundtrip_through_json() {
        let info = AccountInfo::from_account(
            Address([1u8; 32]),
            Some(Account {
                balance: 1,
                nonce: 2,
                battery: 3,
                last_regen_time: 4,
            }),
            4,
            2,
            Some(1_000),
        );
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(serde_json::from_str::<AccountInfo>(&json).unwrap(), info);
    }
}
