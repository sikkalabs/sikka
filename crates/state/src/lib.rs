//! SIKKA state: the Sparse Merkle Tree, the account database and the execution
//! rules that connect them.
//!
//! There is no block store here and no transaction archive. What the network
//! secures is current balances, current nonces and the state root over them; the
//! transactions that produced that state are forgotten once a checkpoint is
//! final.

pub mod ledger;
pub mod smt;
pub mod store;

pub use ledger::{
    ExecutionContext, ExecutionOutcome, GenesisOutcome, Ledger, Staged, StateSnapshot,
};
pub use smt::{Proof, ProofLeaf, Smt, EMPTY_HASH};
pub use store::{LedgerMeta, StateStore, WriteBatch};
