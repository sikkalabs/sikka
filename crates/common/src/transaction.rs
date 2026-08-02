//! Transactions.
//!
//! SIKKA does one thing — move value — so there are only three transaction
//! kinds and no fee field: validators are paid by protocol inflation, and spam
//! is bounded by per-account battery instead of price.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash, PublicKey, Signature};
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::constants::TX_TIME_TOLERANCE_SECS;
use crate::error::{Error, Result};

/// Domain tag covering the signed payload of a transaction.
pub const TX_SIGNING_TAG: &[u8] = b"SIKKA/tx/v3";
/// Domain tag for transaction ids.
pub const TX_ID_TAG: &[u8] = b"SIKKA/tx-id/v2";

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
///
/// `chain_id` is bound into the signature and id so a transaction signed for
/// one chain cannot be replayed on another that shares the same keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    #[serde(default = "default_kind")]
    pub kind: TxKind,
    pub from: Address,
    pub to: Address,
    /// Amount in CHILLAR.
    pub amount: u64,
    pub nonce: u64,
    /// Sender-signed unix timestamp; the consensus clock for battery regen.
    pub timestamp: u64,
    /// Human-readable chain this transaction is valid for.
    pub chain_id: String,
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
        chain_id: impl Into<String>,
    ) -> Result<Self> {
        let public_key = PublicKey::new(*keypair.public_bytes());
        let mut tx = Self {
            kind,
            from: public_key.address(),
            to,
            amount,
            nonce,
            timestamp,
            chain_id: chain_id.into(),
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
        chain_id: impl Into<String>,
    ) -> Result<Self> {
        Self::sign(
            keypair,
            TxKind::Transfer,
            to,
            amount,
            nonce,
            timestamp,
            chain_id,
        )
    }

    /// Convenience constructor for a bond.
    pub fn bond(
        keypair: &sikka_crypto::Keypair,
        amount: u64,
        nonce: u64,
        timestamp: u64,
        chain_id: impl Into<String>,
    ) -> Result<Self> {
        Self::sign(
            keypair,
            TxKind::Bond,
            Address::ZERO,
            amount,
            nonce,
            timestamp,
            chain_id,
        )
    }

    /// Convenience constructor for an unbond.
    pub fn unbond(
        keypair: &sikka_crypto::Keypair,
        nonce: u64,
        timestamp: u64,
        chain_id: impl Into<String>,
    ) -> Result<Self> {
        Self::sign(
            keypair,
            TxKind::Unbond,
            Address::ZERO,
            0,
            nonce,
            timestamp,
            chain_id,
        )
    }

    /// The bytes covered by the signature.
    ///
    /// Includes the public key so a proposer cannot take a cached mempool id,
    /// swap in a different key, and skip verification: the id and the signature
    /// both bind the key that must hash to `from`. Includes the chain id so the
    /// same payload cannot be replayed on another chain.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut w = Writer::with_capacity(128 + self.public_key.as_slice().len() + self.chain_id.len());
        w.raw(TX_SIGNING_TAG)
            .str(&self.chain_id)
            .u8(self.kind.tag())
            .raw(self.from.as_bytes())
            .raw(self.to.as_bytes())
            .u64(self.amount)
            .u64(self.nonce)
            .u64(self.timestamp)
            .raw(self.public_key.as_slice());
        w.finish()
    }

    /// Transaction id: hash of the signed payload (which includes the public key).
    ///
    /// The signature itself is excluded so that re-signing the same payload —
    /// ML-DSA signatures are randomised by default — yields the same id and
    /// cannot enter the mempool twice.
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

    /// Reject a transaction whose chain binding is not this chain's.
    pub fn check_chain_id(&self, expected: &str) -> Result<()> {
        if self.chain_id != expected {
            return Err(Error::ChainIdMismatch {
                expected: expected.to_string(),
                actual: self.chain_id.clone(),
            });
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
            .str(&self.chain_id)
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
            chain_id: r.str()?,
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

    fn chain_id() -> &'static str {
        "sikka-test"
    }

    #[test]
    fn signed_transfer_validates() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000, chain_id()).unwrap();
        assert_eq!(tx.from, PublicKey::new(*kp.public_bytes()).address());
        assert_eq!(tx.chain_id, chain_id());
        tx.verify_signature().unwrap();
        tx.validate_stateless(1_000).unwrap();
        tx.check_chain_id(chain_id()).unwrap();
    }

    #[test]
    fn wrong_chain_id_is_rejected() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000, chain_id()).unwrap();
        assert_eq!(
            tx.check_chain_id("other").unwrap_err(),
            Error::ChainIdMismatch {
                expected: "other".into(),
                actual: chain_id().into(),
            }
        );
    }

    #[test]
    fn tampering_invalidates_signature() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000, chain_id()).unwrap();

        let mut tampered = tx.clone();
        tampered.amount += 1;
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
        let mut tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000, chain_id()).unwrap();
        tx.public_key = PublicKey::new(*other.public_bytes());
        assert_eq!(
            tx.verify_signature().unwrap_err(),
            Error::AddressKeyMismatch
        );
    }

    #[test]
    fn clock_skew_bounds_are_enforced() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 10_000, chain_id()).unwrap();
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
        Transaction::transfer(&kp, Address([9u8; 32]), 1, 0, 100, chain_id())
            .unwrap()
            .check_static(100)
            .unwrap();
        assert!(Transaction::transfer(&kp, me, 1, 0, 100, chain_id())
            .unwrap()
            .check_static(100)
            .is_err());
        Transaction::bond(&kp, 10, 0, 100, chain_id())
            .unwrap()
            .check_static(100)
            .unwrap();
        Transaction::unbond(&kp, 0, 100, chain_id())
            .unwrap()
            .check_static(100)
            .unwrap();

        let mut bad_bond = Transaction::bond(&kp, 10, 0, 100, chain_id()).unwrap();
        bad_bond.to = Address([1u8; 32]);
        assert!(bad_bond.check_static(100).is_err());
    }

    #[test]
    fn id_ignores_signature_but_covers_payload() {
        let kp = keypair();
        let a = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000, chain_id()).unwrap();
        let b = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000, chain_id()).unwrap();
        assert_ne!(a.signature, b.signature);
        assert_eq!(a.id(), b.id());

        let c = Transaction::transfer(&kp, Address([9u8; 32]), 101, 0, 1_000, chain_id()).unwrap();
        assert_ne!(a.id(), c.id());

        let other_chain =
            Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000, "other").unwrap();
        assert_ne!(a.id(), other_chain.id());
    }

    #[test]
    fn swapping_the_public_key_changes_the_id() {
        let kp = keypair();
        let other = keypair();
        let mut tx = Transaction::transfer(&kp, Address([9u8; 32]), 100, 0, 1_000, chain_id()).unwrap();
        let original_id = tx.id();
        tx.public_key = PublicKey::new(*other.public_bytes());
        assert_ne!(
            tx.id(),
            original_id,
            "a pubkey swap must not keep the mempool cache id"
        );
        assert_eq!(
            tx.verify_signature().unwrap_err(),
            Error::AddressKeyMismatch
        );
    }

    #[test]
    fn binary_and_json_roundtrip() {
        let kp = keypair();
        let tx = Transaction::bond(&kp, 42, 7, 1_000, chain_id()).unwrap();

        let bytes = tx.to_bytes();
        assert_eq!(Transaction::from_bytes(&bytes).unwrap(), tx);

        let json = serde_json::to_string(&tx).unwrap();
        assert_eq!(serde_json::from_str::<Transaction>(&json).unwrap(), tx);
    }

    #[test]
    fn json_defaults_kind_to_transfer() {
        let kp = keypair();
        let tx = Transaction::transfer(&kp, Address([9u8; 32]), 1, 0, 1_000, chain_id()).unwrap();
        let mut value = serde_json::to_value(&tx).unwrap();
        value.as_object_mut().unwrap().remove("kind");
        let decoded: Transaction = serde_json::from_value(value).unwrap();
        assert_eq!(decoded.kind, TxKind::Transfer);
    }

    /// Layout must stay byte-identical to `public/wallet.html` (`encodeStr` + LE u64s).
    #[test]
    fn wallet_html_v3_preimage_layout() {
        let pk = PublicKey::new([0xABu8; 2592]);
        let tx = Transaction {
            kind: TxKind::Transfer,
            from: pk.address(),
            to: Address([0x11u8; 32]),
            amount: 1_500_000_000,
            nonce: 7,
            timestamp: 1_720_000_000,
            chain_id: "sikka-test".into(),
            public_key: pk,
            signature: Signature::default(),
        };
        let bytes = tx.signing_bytes();
        assert!(bytes.starts_with(TX_SIGNING_TAG));
        let rest = &bytes[TX_SIGNING_TAG.len()..];
        // Writer::str("sikka-test") = u32le(10) ‖ utf8
        assert_eq!(&rest[..4], &10u32.to_le_bytes());
        assert_eq!(&rest[4..14], b"sikka-test");
        assert_eq!(rest[14], 0); // transfer
        assert_eq!(&rest[15..47], tx.from.as_bytes());
        assert_eq!(&rest[47..79], &[0x11u8; 32]);
        assert_eq!(&rest[79..87], &1_500_000_000u64.to_le_bytes());
        assert_eq!(&rest[87..95], &7u64.to_le_bytes());
        assert_eq!(&rest[95..103], &1_720_000_000u64.to_le_bytes());
        assert_eq!(&rest[103..], tx.public_key.as_slice());
        // tag(11) + 4+10 + 1 + 32 + 32 + 8 + 8 + 8 + 2592
        assert_eq!(bytes.len(), 2706);
    }
}
