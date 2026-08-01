//! Checkpoints: the only thing consensus votes on.
//!
//! A checkpoint is a signed commitment to the *entire current state*, not a
//! block of history. Once ≥2/3 of the active bonded stake signs one, the state
//! it commits to is final and everything that produced it can be thrown away.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash, PublicKey, Signature};
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::error::{Error, Result};

/// Domain tag for the checkpoint hash preimage.
pub const CHECKPOINT_TAG: &[u8] = b"SIKKA/checkpoint/v2";
/// Domain tag for the transaction-set commitment.
pub const TX_ROOT_TAG: &[u8] = b"SIKKA/tx-root/v1";

/// The signed part of a checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointHeader {
    pub height: u64,
    /// Hash of the previous checkpoint header; `ZERO` at genesis.
    pub prev_hash: Hash,
    /// Sparse Merkle Tree root over all accounts.
    pub state_root: Hash,
    /// Sparse Merkle Tree root over all validator records.
    pub validator_root: Hash,
    /// Commitment to the ordered transaction ids applied in this checkpoint.
    pub tx_root: Hash,
    pub tx_count: u32,
    pub timestamp: u64,
    /// Round-robin proposer for this height and round.
    pub proposer: Address,
    /// Which turn of the round-robin produced this checkpoint.
    ///
    /// Zero in normal operation. It advances when the validator whose turn it
    /// is fails to propose, handing the turn to the next validator in line, and
    /// it is in the signed header so anyone can check that the proposer really
    /// was entitled to propose.
    pub round: u32,
    /// Total supply after this checkpoint's inflation was minted.
    pub total_supply: u64,
    /// Sum of every validator bond after this checkpoint, unbonding included.
    pub total_bonded: u64,
    /// Genesis fingerprint of the chain this checkpoint belongs to.
    ///
    /// Bound into the header hash so votes and proposals cannot be replayed
    /// across chains that share validator keys.
    pub genesis_fingerprint: Hash,
}

impl CheckpointHeader {
    /// Checkpoint hash: what validators actually sign.
    pub fn hash(&self) -> Hash {
        Hash::digest(&[CHECKPOINT_TAG, &self.to_bytes()])
    }

    /// Commitment to an ordered list of transaction ids.
    ///
    /// A flat hash chain rather than a Merkle tree: nobody needs an inclusion
    /// proof for a transaction, since transactions are not retained after
    /// finalization — only the state they produced is.
    pub fn compute_tx_root(tx_ids: &[Hash]) -> Hash {
        let mut w = Writer::with_capacity(32 * tx_ids.len() + 8);
        w.u32(tx_ids.len() as u32);
        for id in tx_ids {
            w.raw(id.as_bytes());
        }
        Hash::digest(&[TX_ROOT_TAG, w.as_slice()])
    }
}

impl Encode for CheckpointHeader {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.height)
            .raw(self.prev_hash.as_bytes())
            .raw(self.state_root.as_bytes())
            .raw(self.validator_root.as_bytes())
            .raw(self.tx_root.as_bytes())
            .u32(self.tx_count)
            .u64(self.timestamp)
            .raw(self.proposer.as_bytes())
            .u32(self.round)
            .u64(self.total_supply)
            .u64(self.total_bonded)
            .raw(self.genesis_fingerprint.as_bytes());
    }
}

impl Decode for CheckpointHeader {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            height: r.u64()?,
            prev_hash: Hash::decode(r)?,
            state_root: Hash::decode(r)?,
            validator_root: Hash::decode(r)?,
            tx_root: Hash::decode(r)?,
            tx_count: r.u32()?,
            timestamp: r.u64()?,
            proposer: Address::decode(r)?,
            round: r.u32()?,
            total_supply: r.u64()?,
            total_bonded: r.u64()?,
            genesis_fingerprint: Hash::decode(r)?,
        })
    }
}

/// One validator's signature over a checkpoint hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator: Address,
    pub public_key: PublicKey,
    pub signature: Signature,
}

impl Encode for ValidatorSignature {
    fn encode(&self, w: &mut Writer) {
        w.raw(self.validator.as_bytes())
            .raw(self.public_key.as_slice())
            .raw(self.signature.as_slice());
    }
}

impl Decode for ValidatorSignature {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            validator: Address::decode(r)?,
            public_key: PublicKey::decode(r)?,
            signature: Signature::decode(r)?,
        })
    }
}

/// A checkpoint header plus the signatures that finalize it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    #[serde(flatten)]
    pub header: CheckpointHeader,
    pub validator_signatures: Vec<ValidatorSignature>,
}

impl Checkpoint {
    pub fn new(header: CheckpointHeader) -> Self {
        Self {
            header,
            validator_signatures: Vec::new(),
        }
    }

    pub fn height(&self) -> u64 {
        self.header.height
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    pub fn state_root(&self) -> Hash {
        self.header.state_root
    }

    /// Add a signature, ignoring duplicates from the same validator.
    pub fn add_signature(&mut self, sig: ValidatorSignature) {
        if !self
            .validator_signatures
            .iter()
            .any(|s| s.validator == sig.validator)
        {
            self.validator_signatures.push(sig);
        }
    }

    /// Sort signatures by validator address so the encoded checkpoint is
    /// byte-identical on every node.
    pub fn canonicalize(&mut self) {
        self.validator_signatures.sort_by_key(|a| a.validator);
    }

    /// Verify every signature against `authorized`, requiring ≥2/3 of the
    /// **bonded stake** of the active set.
    ///
    /// `authorized` is `(address, public_key, bond)` for each validator active
    /// at this height. Signatures from anyone else are rejected outright rather
    /// than ignored, so a proposer cannot pad a checkpoint. Equal bonds reduce
    /// to the old one-address-one-vote rule.
    pub fn verify_signatures<'a, I>(&self, authorized: I) -> Result<usize>
    where
        I: IntoIterator<Item = (&'a Address, &'a PublicKey, u64)>,
    {
        let authorized: std::collections::HashMap<&Address, (&PublicKey, u64)> = authorized
            .into_iter()
            .map(|(address, key, bond)| (address, (key, bond)))
            .collect();
        let hash = self.hash();
        let mut seen = std::collections::HashSet::new();
        let mut bonded: u64 = 0;

        for sig in &self.validator_signatures {
            if !seen.insert(sig.validator) {
                return Err(Error::DuplicateSignature(sig.validator));
            }
            let Some((expected_key, bond)) = authorized.get(&sig.validator) else {
                return Err(Error::UnknownVoter(sig.validator));
            };
            if expected_key.as_slice() != sig.public_key.as_slice() {
                return Err(Error::AddressKeyMismatch);
            }
            let payload = crate::vote::vote_signing_bytes(
                &self.header.genesis_fingerprint,
                self.header.height,
                self.header.round,
                crate::vote::VoteKind::Precommit,
                &hash,
            );
            if !sikka_crypto::verify(
                sig.public_key.as_slice(),
                &payload,
                sig.signature.as_slice(),
            ) {
                return Err(Error::InvalidSignature);
            }
            bonded = bonded.saturating_add(*bond);
        }

        let total_bond: u64 = authorized.values().map(|(_, bond)| *bond).sum();
        let needed = crate::constants::quorum_bond(total_bond);
        if bonded < needed {
            return Err(Error::QuorumNotReached {
                got: bonded,
                needed,
            });
        }
        Ok(seen.len())
    }
}

impl Encode for Checkpoint {
    fn encode(&self, w: &mut Writer) {
        self.header.encode(w);
        self.validator_signatures.encode(w);
    }
}

impl Decode for Checkpoint {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            header: CheckpointHeader::decode(r)?,
            validator_signatures: Vec::<ValidatorSignature>::decode(r)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vote::{Vote, VoteKind};
    use sikka_crypto::Keypair;

    fn header(height: u64) -> CheckpointHeader {
        CheckpointHeader {
            height,
            prev_hash: Hash([1u8; 32]),
            state_root: Hash([2u8; 32]),
            validator_root: Hash([3u8; 32]),
            tx_root: Hash([4u8; 32]),
            tx_count: 10_000,
            timestamp: 1_700_000_000,
            proposer: Address([5u8; 32]),
            round: 0,
            total_supply: 21_000_000,
            total_bonded: 1_000,
            genesis_fingerprint: Hash([0x42u8; 32]),
        }
    }
    #[test]
    fn header_roundtrips_and_hash_covers_fields() {
        let h = header(7);
        assert_eq!(CheckpointHeader::from_bytes(&h.to_bytes()).unwrap(), h);

        let mut other = h.clone();
        other.state_root = Hash([9u8; 32]);
        assert_ne!(h.hash(), other.hash());

        let mut other = h.clone();
        other.height = 8;
        assert_ne!(h.hash(), other.hash());

        // The round is signed too: a validator cannot claim someone else's turn
        // by presenting the same state under a different round.
        let mut other = h.clone();
        other.round = 1;
        assert_ne!(h.hash(), other.hash());
        assert_eq!(
            CheckpointHeader::from_bytes(&other.to_bytes()).unwrap(),
            other
        );
    }

    #[test]
    fn tx_root_is_order_sensitive() {
        let a = Hash([1u8; 32]);
        let b = Hash([2u8; 32]);
        assert_ne!(
            CheckpointHeader::compute_tx_root(&[a, b]),
            CheckpointHeader::compute_tx_root(&[b, a])
        );
        assert_ne!(
            CheckpointHeader::compute_tx_root(&[a]),
            CheckpointHeader::compute_tx_root(&[a, a])
        );
        assert_eq!(
            CheckpointHeader::compute_tx_root(&[a, b]),
            CheckpointHeader::compute_tx_root(&[a, b])
        );
    }

    #[test]
    fn quorum_of_signatures_is_required() {
        let keys: Vec<Keypair> = (0..4).map(|_| Keypair::generate().unwrap()).collect();
        let pubkeys: Vec<PublicKey> = keys
            .iter()
            .map(|k| PublicKey::new(*k.public_bytes()))
            .collect();
        // Equal bonds of 1 → quorum is 3 of 4.
        let authorized: Vec<(Address, PublicKey, u64)> = pubkeys
            .iter()
            .map(|pk| (pk.address(), pk.clone(), 1))
            .collect();

        let mut cp = Checkpoint::new(header(1));
        let hash = cp.hash();

        // Two of four signatures is short of the three required.
        for kp in keys.iter().take(2) {
            cp.add_signature(Vote::sign(kp, cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        }
        let refs: Vec<(&Address, &PublicKey, u64)> = authorized
            .iter()
            .map(|(a, k, b)| (a, k, *b))
            .collect();
        assert!(matches!(
            cp.verify_signatures(refs.clone()),
            Err(Error::QuorumNotReached { got: 2, needed: 3 })
        ));

        cp.add_signature(Vote::sign(&keys[2], cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        assert_eq!(cp.verify_signatures(refs).unwrap(), 3);
    }

    #[test]
    fn stake_weighted_quorum_accepts_a_whale() {
        let keys: Vec<Keypair> = (0..3).map(|_| Keypair::generate().unwrap()).collect();
        let pubkeys: Vec<PublicKey> = keys
            .iter()
            .map(|k| PublicKey::new(*k.public_bytes()))
            .collect();
        let bonds = [70u64, 15, 15];
        let authorized: Vec<(Address, PublicKey, u64)> = pubkeys
            .iter()
            .zip(bonds)
            .map(|(pk, bond)| (pk.address(), pk.clone(), bond))
            .collect();

        let mut cp = Checkpoint::new(header(1));
        let hash = cp.hash();
        cp.add_signature(Vote::sign(&keys[0], cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        let refs: Vec<(&Address, &PublicKey, u64)> = authorized
            .iter()
            .map(|(a, k, b)| (a, k, *b))
            .collect();
        assert_eq!(cp.verify_signatures(refs).unwrap(), 1);
    }

    #[test]
    fn outsider_and_duplicate_signatures_are_rejected() {
        let insider = Keypair::generate().unwrap();
        let outsider = Keypair::generate().unwrap();
        let insider_pk = PublicKey::new(*insider.public_bytes());
        let authorized = [(insider_pk.address(), insider_pk.clone(), 1u64)];
        let refs: Vec<(&Address, &PublicKey, u64)> =
            authorized.iter().map(|(a, k, b)| (a, k, *b)).collect();

        let mut cp = Checkpoint::new(header(1));
        let hash = cp.hash();
        cp.add_signature(Vote::sign(&insider, cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        cp.verify_signatures(refs.clone()).unwrap();

        cp.validator_signatures
            .push(Vote::sign(&outsider, cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        assert!(matches!(
            cp.verify_signatures(refs.clone()),
            Err(Error::UnknownVoter(_))
        ));

        let mut cp = Checkpoint::new(header(1));
        let sig = Vote::sign(&insider, cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature();
        cp.validator_signatures.push(sig.clone());
        cp.validator_signatures.push(sig);
        assert!(matches!(
            cp.verify_signatures(refs),
            Err(Error::DuplicateSignature(_))
        ));
    }

    #[test]
    fn signature_over_another_height_is_rejected() {
        let kp = Keypair::generate().unwrap();
        let pk = PublicKey::new(*kp.public_bytes());
        let authorized = [(pk.address(), pk.clone(), 1u64)];
        let refs: Vec<(&Address, &PublicKey, u64)> =
            authorized.iter().map(|(a, k, b)| (a, k, *b)).collect();

        let mut cp = Checkpoint::new(header(1));
        let hash = cp.hash();
        cp.add_signature(Vote::sign(&kp, cp.header.genesis_fingerprint, 2, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        assert_eq!(
            cp.verify_signatures(refs).unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn canonicalize_sorts_signatures() {
        let keys: Vec<Keypair> = (0..3).map(|_| Keypair::generate().unwrap()).collect();
        let mut cp = Checkpoint::new(header(1));
        let hash = cp.hash();
        for kp in &keys {
            cp.add_signature(Vote::sign(kp, cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        }
        cp.canonicalize();
        let addrs: Vec<Address> = cp
            .validator_signatures
            .iter()
            .map(|s| s.validator)
            .collect();
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(addrs, sorted);
        assert_eq!(Checkpoint::from_bytes(&cp.to_bytes()).unwrap(), cp);
    }

    #[test]
    fn add_signature_ignores_repeats() {
        let kp = Keypair::generate().unwrap();
        let mut cp = Checkpoint::new(header(1));
        let hash = cp.hash();
        cp.add_signature(Vote::sign(&kp, cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        cp.add_signature(Vote::sign(&kp, cp.header.genesis_fingerprint, 1, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        assert_eq!(cp.validator_signatures.len(), 1);
    }
}
