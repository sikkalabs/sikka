//! Checkpoint votes.
//!
//! Consensus never votes on individual transactions — only on the state
//! checkpoint they produce. A vote is therefore tiny: a height, the checkpoint
//! hash, and a signature over both.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash, PublicKey, Signature};
use crate::checkpoint::ValidatorSignature;
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::{Error, Result};

/// Domain tag for the signed vote payload.
pub const VOTE_TAG: &[u8] = b"SIKKA/vote/v1";

/// The exact bytes a validator signs when voting for a checkpoint.
///
/// The height is included alongside the hash so a signature can never be
/// replayed at another height, even if two heights somehow shared a hash.
pub fn vote_signing_bytes(height: u64, checkpoint_hash: &Hash) -> Vec<u8> {
    let mut w = Writer::with_capacity(48);
    w.raw(VOTE_TAG).u64(height).raw(checkpoint_hash.as_bytes());
    w.finish()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vote {
    pub height: u64,
    pub checkpoint_hash: Hash,
    pub validator: Address,
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl Vote {
    pub fn sign(
        keypair: &sikka_crypto::Keypair,
        height: u64,
        checkpoint_hash: Hash,
    ) -> Result<Self> {
        let public_key = PublicKey::new(*keypair.public_bytes());
        let signature =
            Signature::new(keypair.sign(&vote_signing_bytes(height, &checkpoint_hash))?);
        Ok(Self {
            height,
            checkpoint_hash,
            validator: public_key.address(),
            public_key,
            signature,
        })
    }

    pub fn verify(&self) -> Result<()> {
        if self.public_key.address() != self.validator {
            return Err(Error::AddressKeyMismatch);
        }
        let payload = vote_signing_bytes(self.height, &self.checkpoint_hash);
        if !sikka_crypto::verify(
            self.public_key.as_slice(),
            &payload,
            self.signature.as_slice(),
        ) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }

    /// Convert to the form embedded in a finalized checkpoint.
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

    #[test]
    fn signed_vote_verifies() {
        let kp = Keypair::generate().unwrap();
        let vote = Vote::sign(&kp, 42, Hash([7u8; 32])).unwrap();
        vote.verify().unwrap();
        assert_eq!(vote.validator, PublicKey::new(*kp.public_bytes()).address());
    }

    #[test]
    fn height_and_hash_are_both_bound() {
        let kp = Keypair::generate().unwrap();
        let vote = Vote::sign(&kp, 42, Hash([7u8; 32])).unwrap();

        let mut wrong_height = vote.clone();
        wrong_height.height = 43;
        assert_eq!(wrong_height.verify().unwrap_err(), Error::InvalidSignature);

        let mut wrong_hash = vote.clone();
        wrong_hash.checkpoint_hash = Hash([8u8; 32]);
        assert_eq!(wrong_hash.verify().unwrap_err(), Error::InvalidSignature);
    }

    #[test]
    fn claimed_identity_must_match_key() {
        let kp = Keypair::generate().unwrap();
        let mut vote = Vote::sign(&kp, 1, Hash([1u8; 32])).unwrap();
        vote.validator = Address([9u8; 32]);
        assert_eq!(vote.verify().unwrap_err(), Error::AddressKeyMismatch);
    }

    #[test]
    fn roundtrips() {
        let kp = Keypair::generate().unwrap();
        let vote = Vote::sign(&kp, 1, Hash([1u8; 32])).unwrap();
        assert_eq!(Vote::from_bytes(&vote.to_bytes()).unwrap(), vote);
        let json = serde_json::to_string(&vote).unwrap();
        assert_eq!(serde_json::from_str::<Vote>(&json).unwrap(), vote);
    }
}
