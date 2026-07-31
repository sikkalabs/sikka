//! Transactions.
//!
//! SIKKA does one thing — move value — so there are only three transaction
//! kinds and no fee field: validators are paid by protocol inflation, and spam
//! is bounded by per-account credits instead of price.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash, PublicKey, Signature};
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::constants::TX_TIME_TOLERANCE_SECS;
use crate::error::{Error, Result};

/// Domain tag covering the signed payload of a transaction.
pub const TX_SIGNING_TAG: &[u8] = b"SIKKA/tx/v1";
/// Domain tag for transaction ids.
pub const TX_ID_TAG: &[u8] = b"SIKKA/tx-id/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxKind {
    /// Move CHILLAR from one account to another.
    Transfer,
    /// Lock CHILLAR as a validator bond.
    Bond,
    /// Start the unbonding cooldown for a validator bond.
    Unbond,
}

impl TxKind {
    pub const fn tag(self) -> u8 {
        match self {
            TxKind::Transfer => 0,
            TxKind::Bond => 1,
            TxKind::Unbond => 2,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(TxKind::Transfer),
            1 => Ok(TxKind::Bond),
            2 => Ok(TxKind::Unbond),
            tag => Err(Error::InvalidTag {
                kind: "TxKind",
                tag,
            }),
        }
    }
}

/// A signed transaction.
///
/// `public_key` is carried explicitly because the ledger stores only 32-byte
/// addresses (`SHA3-256` of the key): a verifier holding just the state cannot
/// recover an ML-DSA-87 key, so the sender supplies it and the protocol checks
/// that it hashes to `from`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    #[serde(default = "default_kind")]
    pub kind: TxKind,
    pub from: Address,
    pub to: Address,
    /// Amount in CHILLAR.
    pub amount: u64,
    pub nonce: u64,
    /// Sender-signed unix timestamp; the consensus clock for credit regen.
    pub timestamp: u64,
    pub public_key: PublicKey,
    pub signature: Signature,
}

fn default_kind() -> TxKind {
    TxKind::Transfer
}

impl Transaction {
    /// Build and sign a transaction. `from` is derived from the signing key.
    pub fn sign(
        keypair: &sikka_crypto::Keypair,
        kind: TxKind,
        to: Address,
        amount: u64,
        nonce: u64,
        timestamp: u64,
    ) -> Result<Self> {
        let public_key = PublicKey::new(*keypair.public_bytes());
        let mut tx = Self {
            kind,
            from: public_key.address(),
            to,
            amount,
            nonce,
            timestamp,
            public_key,
            signature: Signature::default(),
        };
        tx.signature = Signature::new(keypair.sign(&tx.signing_bytes())?);
        Ok(tx)
    }

    /// Convenience constructor for a transfer.
    pub fn transfer(
        keypair: &sikka_crypto::Keypair,
        to: Address,
        amount: u64,
        nonce: u64,
        timestamp: u64,
    ) -> Result<Self> {
        Self::sign(keypair, TxKind::Transfer, to, amount, nonce, timestamp)
    }

    /// Convenience constructor for a bond.
    pub fn bond(
        keypair: &sikka_crypto::Keypair,
        amount: u64,
        nonce: u64,
        timestamp: u64,
    ) -> Result<Self> {
        Self::sign(
            keypair,
            TxKind::Bond,
            Address::ZERO,
            amount,
            nonce,
            timestamp,
        )
    }

    /// Convenience constructor for an unbond.
    pub fn unbond(keypair: &sikka_crypto::Keypair, nonce: u64, timestamp: u64) -> Result<Self> {
        Self::sign(keypair, TxKind::Unbond, Address::ZERO, 0, nonce, timestamp)
    }

    /// The bytes covered by the signature. Excludes the signature itself and
    /// the public key, which is bound through `from`.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(96);
        w.raw(TX_SIGNING_TAG)
            .u8(self.kind.tag())
            .raw(self.from.as_bytes())
            .raw(self.to.as_bytes())
            .u64(self.amount)
            .u64(self.nonce)
            .u64(self.timestamp);
        w.finish()
    }

    /// Transaction id: hash of the signed payload.
    ///
    /// The signature is excluded so that re-signing the same payload — ML-DSA
    /// signatures are randomised by default — yields the same id and cannot
    /// enter the mempool twice.
    pub fn id(&self) -> Hash {
        Hash::digest(&[TX_ID_TAG, &self.signing_bytes()])
    }

    /// Verify the sender's key binding and the signature itself.
    pub fn verify_signature(&self) -> Result<()> {
        if self.public_key.address() != self.from {
            return Err(Error::AddressKeyMismatch);
        }
        if !sikka_crypto::verify(
            self.public_key.as_slice(),
            &self.signing_bytes(),
            self.signature.as_slice(),
        ) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    /// Checks that need no ledger access: shape and clock skew.
    pub fn check_static(&self, now: u64) -> Result<()> {
        let skew = self.timestamp.abs_diff(now);
        if skew > TX_TIME_TOLERANCE_SECS {
            return Err(Error::TimestampOutOfRange {
                timestamp: self.timestamp,
                now,
                tolerance: TX_TIME_TOLERANCE_SECS,
            });
        }
        match self.kind {
            TxKind::Transfer => {
                if self.amount == 0 {
                    return Err(Error::ZeroAmount);
                }
                if self.to == self.from {
                    return Err(Error::SelfTransfer);
                }
                if self.to.is_zero() {
                    return Err(Error::Other(
                        "transfer target must not be the zero address".into(),
                    ));
                }
            }
            TxKind::Bond => {
                if self.amount == 0 {
                    return Err(Error::ZeroAmount);
                }
                if !self.to.is_zero() {
                    return Err(Error::Other("bond must not set a target address".into()));
                }
            }
            TxKind::Unbond => {
                if self.amount != 0 {
                    return Err(Error::Other("unbond must not carry an amount".into()));
                }
                if !self.to.is_zero() {
                    return Err(Error::Other("unbond must not set a target address".into()));
                }
            }
        }
        Ok(())
    }

    /// Full stateless validation: shape, clock skew and signature.
    pub fn validate_stateless(&self, now: u64) -> Result<()> {
        self.check_static(now)?;
        self.verify_signature()
    }
}

impl Encode for Transaction {
    fn encode(&self, w: &mut Writer) {
        w.u8(self.kind.tag())
            .raw(self.from.as_bytes())
            .raw(self.to.as_bytes())
            .u64(self.amount)
            .u64(self.nonce)
            .u64(self.timestamp)
            .raw(self.public_key.as_slice())
            .raw(self.signature.as_slice());
    }
}

impl Decode for Transaction {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            kind: TxKind::from_tag(r.u8()?)?,
            from: Address::decode(r)?,
            to: Address::decode(r)?,
            amount: r.u64()?,
            nonce: r.u64()?,
            timestamp: r.u64()?,
            public_key: PublicKey::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_crypto::Keypair;

    fn keypair() -> Keypair {
        Keypair::generate().unwrap()
    }

    #[test]
    fn signed_transfer_validates() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000).unwrap();
        assert_eq!(tx.from, PublicKey::new(*kp.public_bytes()).address());
        tx.verify_signature().unwrap();
        tx.validate_stateless(1_000).unwrap();
    }

    #[test]
    fn tampering_invalidates_signature() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000).unwrap();

        let mut tampered = tx.clone();
        tampered.amount = 101;
        assert_eq!(
            tampered.verify_signature().unwrap_err(),
            Error::InvalidSignature
        );

        let mut tampered = tx.clone();
        tampered.to = Address([8u8; 32]);
        assert_eq!(
            tampered.verify_signature().unwrap_err(),
            Error::InvalidSignature
        );

        let mut tampered = tx.clone();
        tampered.nonce = 1;
        assert_eq!(
            tampered.verify_signature().unwrap_err(),
            Error::InvalidSignature
        );

        let mut tampered = tx;
        tampered.timestamp += 1;
        assert_eq!(
            tampered.verify_signature().unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn foreign_public_key_is_rejected() {
        let kp = keypair();
        let other = keypair();
        let mut tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000).unwrap();
        tx.public_key = PublicKey::new(*other.public_bytes());
        assert_eq!(
            tx.verify_signature().unwrap_err(),
            Error::AddressKeyMismatch
        );
    }

    #[test]
    fn clock_skew_bounds_are_enforced() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 10_000).unwrap();
        tx.check_static(10_000 + TX_TIME_TOLERANCE_SECS).unwrap();
        tx.check_static(10_000 - TX_TIME_TOLERANCE_SECS).unwrap();
        assert!(matches!(
            tx.check_static(10_000 + TX_TIME_TOLERANCE_SECS + 1),
            Err(Error::TimestampOutOfRange { .. })
        ));
        assert!(matches!(
            tx.check_static(10_000 - TX_TIME_TOLERANCE_SECS - 1),
            Err(Error::TimestampOutOfRange { .. })
        ));
    }

    #[test]
    fn shape_rules_per_kind() {
        let kp = keypair();
        let me = PublicKey::new(*kp.public_bytes()).address();

        let zero = Transaction::transfer(&kp, Address([9u8; 32]), 0, 0, 100).unwrap();
        assert_eq!(zero.check_static(100).unwrap_err(), Error::ZeroAmount);

        let to_self = Transaction::transfer(&kp, me, 5, 0, 100).unwrap();
        assert_eq!(to_self.check_static(100).unwrap_err(), Error::SelfTransfer);

        Transaction::bond(&kp, 10, 0, 100)
            .unwrap()
            .check_static(100)
            .unwrap();
        Transaction::unbond(&kp, 0, 100)
            .unwrap()
            .check_static(100)
            .unwrap();

        let mut bad_bond = Transaction::bond(&kp, 10, 0, 100).unwrap();
        bad_bond.to = Address([1u8; 32]);
        assert!(bad_bond.check_static(100).is_err());
    }

    #[test]
    fn id_ignores_signature_but_covers_payload() {
        let kp = keypair();
        let a = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000).unwrap();
        let b = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000).unwrap();
        // ML-DSA signing is randomised, so the two signatures differ...
        assert_ne!(a.signature, b.signature);
        // ...but the transaction id is stable.
        assert_eq!(a.id(), b.id());

        let c = Transaction::transfer(&kp, Address([9u8; 32]), 101, 0, 1_000).unwrap();
        assert_ne!(a.id(), c.id());
    }

    #[test]
    fn binary_and_json_roundtrip() {
        let kp = keypair();
        let tx = Transaction::bond(&kp, 42, 7, 1_000).unwrap();

        let bytes = tx.to_bytes();
        assert_eq!(Transaction::from_bytes(&bytes).unwrap(), tx);

        let json = serde_json::to_string(&tx).unwrap();
        assert_eq!(serde_json::from_str::<Transaction>(&json).unwrap(), tx);
    }

    #[test]
    fn json_defaults_kind_to_transfer() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 1, 0, 1).unwrap();
        let mut value = serde_json::to_value(&tx).unwrap();
        value.as_object_mut().unwrap().remove("kind");
        let parsed: Transaction = serde_json::from_value(value).unwrap();
        assert_eq!(parsed.kind, TxKind::Transfer);
        assert_eq!(parsed, tx);
    }
}
