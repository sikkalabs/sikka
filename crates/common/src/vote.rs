//! Checkpoint votes.
//!
//! Consensus votes in two phases (Tendermint-style):
//!
//! 1. **Prevote** — a soft preference for a checkpoint hash in a given round.
//!    Different rounds may prevote different hashes without equivocation.
//! 2. **Precommit** — cast only after ≥2/3 bonded stake has prevoted the same
//!    hash in that round. Precommits are what finalize, and once cast they lock
//!    the validator onto that hash for the height.
//!
//! Equivocation is signing two different hashes for the same
//! `(height, round, kind)`. That is the only slashable offence.
//!
//! Every vote is bound to a genesis fingerprint so signatures cannot be
//! replayed across chains that share validator keys.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash, PublicKey, Signature};
use crate::checkpoint::ValidatorSignature;
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::{Error, Result};

/// Domain tag for the signed vote payload.
pub const VOTE_TAG: &[u8] = b"SIKKA/vote/v3";

/// Which consensus step a vote belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteKind {
    Prevote,
    Precommit,
}

impl VoteKind {
    pub const fn tag(self) -> u8 {
        match self {
            VoteKind::Prevote => 0,
            VoteKind::Precommit => 1,
        }
    }

    pub fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0 => Ok(VoteKind::Prevote),
            1 => Ok(VoteKind::Precommit),
            tag => Err(Error::InvalidTag {
                kind: "VoteKind",
                tag,
            }),
        }
    }
}

/// The exact bytes a validator signs when voting.
///
/// Height, round, kind, and genesis fingerprint are all bound so a signature
/// cannot be replayed across steps, rounds, or chains.
pub fn vote_signing_bytes(
    genesis_fingerprint: &Hash,
    height: u64,
    round: u32,
    kind: VoteKind,
    checkpoint_hash: &Hash,
) -> Vec<u8> {
    let mut w = Writer::with_capacity(88);
    w.raw(VOTE_TAG)
        .raw(genesis_fingerprint.as_bytes())
        .u64(height)
        .u32(round)
        .u8(kind.tag())
        .raw(checkpoint_hash.as_bytes());
    w.finish()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub round: u32,
    pub kind: VoteKind,
    pub checkpoint_hash: Hash,
    pub validator: Address,
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub fn sign(
        keypair: &sikka_crypto::Keypair,
        genesis_fingerprint: Hash,
        height: u64,
        round: u32,
        kind: VoteKind,
        checkpoint_hash: Hash,
    ) -> Result<Self> {
        let public_key = PublicKey::new(*keypair.public_bytes());
        let signature = Signature::new(keypair.sign(&vote_signing_bytes(
            &genesis_fingerprint,
            height,
            round,
            kind,
            &checkpoint_hash,
        ))?);
        Ok(Self {
            height,
            round,
            kind,
            checkpoint_hash,
            validator: public_key.address(),
            public_key,
            signature,
        })
    }

    pub fn verify(&self, genesis_fingerprint: &Hash) -> Result<()> {
        if self.public_key.address() != self.validator {
            return Err(Error::AddressKeyMismatch);
        }
        let payload = vote_signing_bytes(
            genesis_fingerprint,
            self.height,
            self.round,
            self.kind,
            &self.checkpoint_hash,
        );
        if !sikka_crypto::verify(
            self.public_key.as_slice(),
            &payload,
            self.signature.as_slice(),
        ) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    /// Convert a precommit into the form embedded in a finalized checkpoint.
    pub fn into_signature(self) -> ValidatorSignature {
        ValidatorSignature {
            validator: self.validator,
            public_key: self.public_key,
            signature: self.signature,
        }
    }
}

impl Encode for Vote {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.height)
            .u32(self.round)
            .u8(self.kind.tag())
            .raw(self.checkpoint_hash.as_bytes())
            .raw(self.validator.as_bytes())
            .raw(self.public_key.as_slice())
            .raw(self.signature.as_slice());
    }
}

impl Decode for Vote {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            height: r.u64()?,
            round: r.u32()?,
            kind: VoteKind::from_tag(r.u8()?)?,
            checkpoint_hash: Hash::decode(r)?,
            validator: Address::decode(r)?,
            public_key: PublicKey::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_crypto::Keypair;

    fn fp() -> Hash {
        Hash([7u8; 32])
    }

    #[test]
    fn a_signed_vote_verifies() {
        let kp = Keypair::generate().unwrap();
        let vote = Vote::sign(&kp, fp(), 42, 1, VoteKind::Prevote, Hash([7u8; 32])).unwrap();
        vote.verify(&fp()).unwrap();
        assert_eq!(vote.validator, PublicKey::new(*kp.public_bytes()).address());
        assert_eq!(vote.kind, VoteKind::Prevote);
        assert_eq!(vote.round, 1);
    }

    #[test]
    fn vote_survives_a_codec_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let vote = Vote::sign(&kp, fp(), 42, 3, VoteKind::Precommit, Hash([7u8; 32])).unwrap();
        let decoded = Vote::from_bytes(&vote.to_bytes()).unwrap();
        assert_eq!(decoded, vote);
    }

    #[test]
    fn tampering_invalidates_a_vote() {
        let kp = Keypair::generate().unwrap();
        let mut vote = Vote::sign(&kp, fp(), 1, 0, VoteKind::Prevote, Hash([1u8; 32])).unwrap();
        vote.checkpoint_hash = Hash([9u8; 32]);
        assert_eq!(vote.verify(&fp()).unwrap_err(), Error::InvalidSignature);
    }

    #[test]
    fn prevote_and_precommit_have_distinct_domains() {
        let kp = Keypair::generate().unwrap();
        let hash = Hash([1u8; 32]);
        let prevote = Vote::sign(&kp, fp(), 1, 0, VoteKind::Prevote, hash).unwrap();
        let mut forged = prevote.clone();
        forged.kind = VoteKind::Precommit;
        assert_eq!(forged.verify(&fp()).unwrap_err(), Error::InvalidSignature);
    }

    #[test]
    fn a_vote_from_another_chain_is_rejected() {
        let kp = Keypair::generate().unwrap();
        let vote = Vote::sign(&kp, fp(), 1, 0, VoteKind::Prevote, Hash([1u8; 32])).unwrap();
        assert_eq!(
            vote.verify(&Hash([9u8; 32])).unwrap_err(),
            Error::InvalidSignature
        );
    }
}
