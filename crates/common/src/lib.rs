//! Core SIKKA types shared by every other crate.
//!
//! SIKKA secures *current state*, not history, so the types here are
//! deliberately small: an [`Account`] is 28 bytes on the wire, a
//! [`Checkpoint`] header is a fixed-size commitment to the whole ledger, and a
//! [`Transaction`] carries only what is needed to move value.

pub mod account;
pub mod amount;
pub mod bytes;
pub mod checkpoint;
pub mod codec;
pub mod constants;
pub mod default_genesis;
pub mod error;
pub mod genesis;
pub mod inflation;
pub mod time;
pub mod transaction;
pub mod validator;
pub mod vote;

pub use account::Account;
pub use amount::{format_sikka, parse_sikka};
pub use bytes::{Address, Hash, PublicKey, Signature};
pub use checkpoint::{Checkpoint, CheckpointHeader, ValidatorSignature};
pub use codec::{Decode, Encode, Reader, Writer};
pub use constants::*;
pub use default_genesis::{
    admin_address, admin_allocation_chillar, default_genesis, default_genesis_bond_chillar,
    default_genesis_bond_sikka, DEFAULT_GENESIS_SUPPLY_SIKKA, GENESIS_VALIDATOR_STAKE_SIKKA,
};
pub use error::{Error, Result};
pub use genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};
pub use inflation::{checkpoint_inflation, distribute_rewards};
pub use time::now_secs;
pub use transaction::{Transaction, TxKind};
pub use validator::Validator;
pub use vote::Vote;
