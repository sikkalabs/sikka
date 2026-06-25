//! Equivocation: the one slashable offence.
//!
//! A validator that signs two different checkpoint hashes for the same
//! `(height, round, kind)` is trying to split the network. That is provable
//! with nothing more than the two signatures. Being offline, being slow, or
//! prevoting differently across rounds never burns stake. Persistent full-batch
//! proposer timeouts instead start the normal unbonding cooldown.
//!
//! Precommits at different rounds but the same height with different hashes are
//! also slashable: that is how a validator can finalize two forks after a
//! partition heals.

use serde::{Deserialize, Serialize};

use sikka_common::bytes::{Address, Hash};
use sikka_common::codec::{Decode, Encode, Reader, Writer};
use sikka_common::error::{Error, Result};
use sikka_common::vote::{Vote, VoteKind};

/// Two conflicting votes from the same validator at the same step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Equivocation {
    pub validator: Address,
    pub height: u64,
    pub first: Vote,
    pub second: Vote,
}

impl Equivocation {
    /// Build evidence from two votes, normalising their order so the same pair
    /// always produces identical evidence.
    pub fn new(a: Vote, b: Vote, chain_id: &str, genesis_fingerprint: &Hash) -> Result<Self> {
        let (first, second) = if a.checkpoint_hash <= b.checkpoint_hash {
            (a, b)
        } else {
            (b, a)
        };
        let evidence = Self {
            validator: first.validator,
            height: first.height,
            first,
            second,
        };
        evidence.verify(chain_id, genesis_fingerprint)?;
        Ok(evidence)
    }

    /// Check that this really is proof of equivocation.
    pub fn verify(&self, chain_id: &str, genesis_fingerprint: &Hash) -> Result<()> {
        if self.first.validator != self.validator || self.second.validator != self.validator {
            return Err(Error::Other(
                "evidence votes are from different validators".into(),
            ));
        }
        if self.first.height != self.height || self.second.height != self.height {
            return Err(Error::Other(
                "evidence votes are from different heights".into(),
            ));
        }
        if self.first.kind != self.second.kind {
            return Err(Error::Other(
                "evidence votes are from different vote kinds".into(),
            ));
        }
        if self.first.kind == VoteKind::Prevote && self.first.round != self.second.round {
            return Err(Error::Other(
                "evidence votes are from different rounds".into(),
            ));
        }
        if self.first.checkpoint_hash == self.second.checkpoint_hash {
            return Err(Error::Other(
                "evidence votes agree; that is not equivocation".into(),
            ));
        }
        self.first.verify(chain_id, genesis_fingerprint)?;
        self.second.verify(chain_id, genesis_fingerprint)?;
        Ok(())
    }
}

impl Encode for Equivocation {
    fn encode(&self, w: &mut Writer) {
        w.raw(self.validator.as_bytes()).u64(self.height);
        self.first.encode(w);
        self.second.encode(w);
    }
}

impl Decode for Equivocation {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            validator: Address::decode(r)?,
            height: r.u64()?,
            first: Vote::decode(r)?,
            second: Vote::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::Hash;
    use sikka_common::vote::VoteKind;
    use sikka_crypto::Keypair;

    fn chain_id() -> &'static str {
        "sikka-test"
    }

    fn fingerprint() -> Hash {
        Hash([0xAA; 32])
    }

    #[test]
    fn conflicting_same_step_votes_are_evidence() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            Hash([1u8; 32]),
        )
        .unwrap();
        let b = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            Hash([2u8; 32]),
        )
        .unwrap();
        let evidence = Equivocation::new(a.clone(), b.clone(), chain_id(), &fingerprint()).unwrap();
        evidence.verify(chain_id(), &fingerprint()).unwrap();
        assert_eq!(evidence.validator, a.validator);
        assert_eq!(evidence.height, 5);
        assert_eq!(
            Equivocation::new(b, a, chain_id(), &fingerprint()).unwrap(),
            evidence
        );
    }

    #[test]
    fn agreeing_votes_are_not_evidence() {
        let kp = Keypair::generate().unwrap();
        let hash = Hash([1u8; 32]);
        let a = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            hash,
        )
        .unwrap();
        let b = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            hash,
        )
        .unwrap();
        assert!(Equivocation::new(a, b, chain_id(), &fingerprint()).is_err());
    }

    #[test]
    fn different_rounds_are_not_prevote_equivocation() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            Hash([1u8; 32]),
        )
        .unwrap();
        let b = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            1,
            VoteKind::Prevote,
            Hash([2u8; 32]),
        )
        .unwrap();
        assert!(Equivocation::new(a, b, chain_id(), &fingerprint()).is_err());
    }

    #[test]
    fn different_round_precommits_are_equivocation() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Precommit,
            Hash([1u8; 32]),
        )
        .unwrap();
        let b = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            1,
            VoteKind::Precommit,
            Hash([2u8; 32]),
        )
        .unwrap();
        let evidence = Equivocation::new(a, b, chain_id(), &fingerprint()).unwrap();
        evidence.verify(chain_id(), &fingerprint()).unwrap();
    }

    #[test]
    fn prevote_and_precommit_are_not_equivocation() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            Hash([1u8; 32]),
        )
        .unwrap();
        let b = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Precommit,
            Hash([2u8; 32]),
        )
        .unwrap();
        assert!(Equivocation::new(a, b, chain_id(), &fingerprint()).is_err());
    }

    #[test]
    fn votes_at_different_heights_are_not_evidence() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            Hash([1u8; 32]),
        )
        .unwrap();
        let b = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            6,
            0,
            VoteKind::Prevote,
            Hash([2u8; 32]),
        )
        .unwrap();
        assert!(Equivocation::new(a, b, chain_id(), &fingerprint()).is_err());
    }

    #[test]
    fn votes_from_different_validators_are_not_evidence() {
        let a_kp = Keypair::generate().unwrap();
        let b_kp = Keypair::generate().unwrap();
        let a = Vote::sign(
            &a_kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            Hash([1u8; 32]),
        )
        .unwrap();
        let b = Vote::sign(
            &b_kp,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            Hash([2u8; 32]),
        )
        .unwrap();
        assert!(Equivocation::new(a, b, chain_id(), &fingerprint()).is_err());
    }

    #[test]
    fn forged_evidence_is_rejected() {
        let victim = Keypair::generate().unwrap();
        let real = Vote::sign(
            &victim,
            chain_id(),
            fingerprint(),
            5,
            0,
            VoteKind::Prevote,
            Hash([1u8; 32]),
        )
        .unwrap();
        let mut fake = real.clone();
        fake.checkpoint_hash = Hash([2u8; 32]);
        let evidence = Equivocation {
            validator: real.validator,
            height: 5,
            first: real,
            second: fake,
        };
        assert_eq!(
            evidence.verify(chain_id(), &fingerprint()).unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn evidence_serialises() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            1,
            0,
            VoteKind::Precommit,
            Hash([1u8; 32]),
        )
        .unwrap();
        let b = Vote::sign(
            &kp,
            chain_id(),
            fingerprint(),
            1,
            0,
            VoteKind::Precommit,
            Hash([2u8; 32]),
        )
        .unwrap();
        let evidence = Equivocation::new(a, b, chain_id(), &fingerprint()).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: Equivocation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, evidence);
        let decoded = Equivocation::from_bytes(&evidence.to_bytes()).unwrap();
        assert_eq!(decoded, evidence);
    }
}
