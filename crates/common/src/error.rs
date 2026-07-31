//! One error type for the whole protocol.
//!
//! Keeping validation, storage and consensus failures in a single enum avoids a
//! tower of `From` conversions between crates, and every variant carries enough
//! context to explain a rejected transaction to a wallet.

use crate::bytes::{Address, Hash};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    // ---- encoding -------------------------------------------------------
    #[error("invalid hex")]
    InvalidHex,
    #[error("invalid length: expected {expected} bytes, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("unexpected end of input while decoding")]
    UnexpectedEof,
    #[error("{0} bytes of trailing data after decoding")]
    TrailingBytes(usize),
    #[error("invalid tag {tag} for {kind}")]
    InvalidTag { kind: &'static str, tag: u8 },
    #[error("json error: {0}")]
    Json(String),

    // ---- transaction validation ----------------------------------------
    #[error("invalid signature")]
    InvalidSignature,
    #[error("sender address does not match public key")]
    AddressKeyMismatch,
    #[error("bad nonce for {address}: expected {expected}, got {actual}")]
    BadNonce {
        address: Address,
        expected: u64,
        actual: u64,
    },
    #[error("timestamp {timestamp} is outside the ±{tolerance}s window around {now}")]
    TimestampOutOfRange {
        timestamp: u64,
        now: u64,
        tolerance: u64,
    },
    #[error("insufficient balance for {address}: has {balance}, needs {needed}")]
    InsufficientBalance {
        address: Address,
        balance: u64,
        needed: u64,
    },
    #[error("insufficient credits for {address}: has {credits}, needs {needed}")]
    InsufficientCredits {
        address: Address,
        credits: u32,
        needed: u32,
    },
    #[error("amount must be greater than zero")]
    ZeroAmount,
    #[error("cannot send to self")]
    SelfTransfer,
    #[error("balance overflow")]
    BalanceOverflow,
    #[error("transaction is not applicable to this account state")]
    NotApplicable,

    // ---- validators / bonding ------------------------------------------
    #[error("bond of {bond} is below the minimum of {minimum}")]
    BondTooSmall { bond: u64, minimum: u64 },
    #[error("{0} is not a validator")]
    NotAValidator(Address),
    #[error("{0} is already unbonding")]
    AlreadyUnbonding(Address),
    #[error("{0} has been slashed")]
    ValidatorSlashed(Address),

    // ---- consensus ------------------------------------------------------
    #[error("checkpoint height mismatch: expected {expected}, got {actual}")]
    BadCheckpointHeight { expected: u64, actual: u64 },
    #[error("checkpoint links to {actual}, expected parent {expected}")]
    BadCheckpointParent { expected: Hash, actual: Hash },
    #[error("state root mismatch: expected {expected}, computed {computed}")]
    StateRootMismatch { expected: Hash, computed: Hash },
    #[error("proposer {actual} is not the expected proposer {expected} for this height")]
    WrongProposer { expected: Address, actual: Address },
    #[error("not enough validator signatures: {got} of {needed}")]
    QuorumNotReached { got: usize, needed: usize },
    #[error("duplicate validator signature from {0}")]
    DuplicateSignature(Address),
    #[error("vote from {0} is not from an active validator")]
    UnknownVoter(Address),
    #[error("equivocation by {validator} at height {height}")]
    Equivocation { validator: Address, height: u64 },
    #[error("no active validators")]
    NoActiveValidators,
    #[error("checkpoint {0} not found")]
    CheckpointNotFound(u64),

    // ---- genesis / config -----------------------------------------------
    #[error("genesis is invalid: {0}")]
    InvalidGenesis(String),
    #[error("chain is already initialised with a different genesis")]
    GenesisMismatch,
    #[error("chain id mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: String, actual: String },

    // ---- infrastructure -------------------------------------------------
    #[error("storage error: {0}")]
    Storage(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("state proof is invalid")]
    InvalidProof,
    #[error("network error: {0}")]
    Network(String),
    #[error("{0}")]
    Other(String),
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e.to_string())
    }
}

impl From<sikka_crypto::CryptoError> for Error {
    fn from(e: sikka_crypto::CryptoError) -> Self {
        Error::Crypto(e.to_string())
    }
}

impl Error {
    /// Whether the error is caused by the submitter (4xx) rather than the node
    /// (5xx). Used by the HTTP layer to pick a status code.
    pub fn is_client_error(&self) -> bool {
        !matches!(
            self,
            Error::Storage(_) | Error::Network(_) | Error::Other(_)
        )
    }
}
