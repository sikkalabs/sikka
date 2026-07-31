//! Equivocation: the one slashable offence.
//!
//! A validator that signs two different checkpoints at the same height is trying
//! to split the network, and that is provable with nothing more than the two
//! signatures. Everything else — being offline, being slow, missing a
//! checkpoint — costs only the forgone reward. Liveness failures are not
//! punished, so validators can come and go freely.

use serde::{Deserialize, Serialize};

use sikka_common::bytes::Address;
use sikka_common::codec::{Decode, Encode, Reader, Writer};
use sikka_common::error::{Error, Result};
use sikka_common::vote::Vote;

/// Two conflicting votes from the same validator at the same height.
///
/// Self-contained: anyone can check it against nothing but the two signatures,
/// which is what lets a proposer include it in a checkpoint and have every other
/// node independently agree the slash is justified.
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
    pub fn new(a: Vote, b: Vote) -> Result<Self> {
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
        evidence.verify()?;
        Ok(evidence)
    }

    /// Check that this really is proof of equivocation.
    pub fn verify(&self) -> Result<()> {
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
        if self.first.checkpoint_hash == self.second.checkpoint_hash {
            return Err(Error::Other(
                "evidence votes agree; that is not equivocation".into(),
            ));
        }
        // Both signatures must be genuine, or anyone could frame a validator.
        self.first.verify()?;
        self.second.verify()?;
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
    use sikka_crypto::Keypair;

    #[test]
    fn conflicting_votes_are_provable() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(&kp, 5, Hash([1u8; 32])).unwrap();
        let b = Vote::sign(&kp, 5, Hash([2u8; 32])).unwrap();

        let evidence = Equivocation::new(a.clone(), b.clone()).unwrap();
        evidence.verify().unwrap();
        assert_eq!(evidence.validator, a.validator);
        assert_eq!(evidence.height, 5);

        // Order does not matter: the same pair yields the same evidence.
        assert_eq!(Equivocation::new(b, a).unwrap(), evidence);
    }

    #[test]
    fn agreeing_votes_are_not_evidence() {
        let kp = Keypair::generate().unwrap();
        let hash = Hash([1u8; 32]);
        let a = Vote::sign(&kp, 5, hash).unwrap();
        let b = Vote::sign(&kp, 5, hash).unwrap();
        assert!(Equivocation::new(a, b).is_err());
    }

    #[test]
    fn votes_at_different_heights_are_not_evidence() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(&kp, 5, Hash([1u8; 32])).unwrap();
        let b = Vote::sign(&kp, 6, Hash([2u8; 32])).unwrap();
        assert!(Equivocation::new(a, b).is_err());
    }

    #[test]
    fn votes_from_different_validators_are_not_evidence() {
        let a_kp = Keypair::generate().unwrap();
        let b_kp = Keypair::generate().unwrap();
        let a = Vote::sign(&a_kp, 5, Hash([1u8; 32])).unwrap();
        let b = Vote::sign(&b_kp, 5, Hash([2u8; 32])).unwrap();
        assert!(Equivocation::new(a, b).is_err());
    }

    #[test]
    fn forged_evidence_is_rejected() {
        let victim = Keypair::generate().unwrap();
        let real = Vote::sign(&victim, 5, Hash([1u8; 32])).unwrap();

        // Take a real vote and fabricate a second one by editing the hash.
        let mut forged = real.clone();
        forged.checkpoint_hash = Hash([2u8; 32]);

        let evidence = Equivocation {
            validator: real.validator,
            height: 5,
            first: real,
            second: forged,
        };
        assert_eq!(evidence.verify().unwrap_err(), Error::InvalidSignature);
    }

    #[test]
    fn evidence_serialises() {
        let kp = Keypair::generate().unwrap();
        let a = Vote::sign(&kp, 1, Hash([1u8; 32])).unwrap();
        let b = Vote::sign(&kp, 1, Hash([2u8; 32])).unwrap();
        let evidence = Equivocation::new(a, b).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: Equivocation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, evidence);
        parsed.verify().unwrap();

        let decoded = Equivocation::from_bytes(&evidence.to_bytes()).unwrap();
        assert_eq!(decoded, evidence);
        decoded.verify().unwrap();
    }
}
