//! Persistent store for this node's own consensus commitments.
//!
//! Votes for heights that are not yet final must survive restarts. Forgetting a
//! signed vote and then signing a rival at the same height is equivocation and
//! burns the bond. Peer votes stay in RAM; only our own signatures are written
//! here.
//!
//! The checkpoint a vote was cast for is written in the same transaction as the
//! vote, because the vote alone is a commitment with nothing left to commit: it
//! forbids signing anything else at that height, which leaves that one
//! checkpoint as the only one this node can still help finalize. A vote restored
//! without it would bind the node to a checkpoint it could no longer name, and
//! the height could never close.

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use sikka_common::codec::{Decode, Encode, Reader, Writer};
use sikka_common::error::{Error, Result};
use sikka_common::vote::Vote;
use sikka_consensus::CheckpointProposal;

const COMMITMENTS: TableDefinition<u64, &[u8]> = TableDefinition::new("commitments");

fn storage_error<E: std::fmt::Display>(e: E) -> Error {
    Error::Storage(e.to_string())
}

/// A vote this node signed, and the checkpoint it was signed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    pub vote: Vote,
    pub proposal: CheckpointProposal,
}

impl Commitment {
    pub fn height(&self) -> u64 {
        self.vote.height
    }

    /// Check that the vote really is a signature over this proposal.
    ///
    /// A mismatched pair would be worse than no record at all: the vote would
    /// still forbid signing anything else at that height, while the proposal it
    /// came back with could not be offered in its place.
    pub fn verify(&self) -> Result<()> {
        if self.vote.height != self.proposal.height()
            || self.vote.checkpoint_hash != self.proposal.hash()
        {
            return Err(Error::Other("commitment vote and proposal disagree".into()));
        }
        Ok(())
    }
}

impl Encode for Commitment {
    fn encode(&self, w: &mut Writer) {
        self.vote.encode(w);
        self.proposal.encode(w);
    }
}

impl Decode for Commitment {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            vote: Vote::decode(r)?,
            proposal: CheckpointProposal::decode(r)?,
        })
    }
}

/// This node's commitments at heights that are not yet final.
pub struct CommitmentStore {
    db: Database,
}

impl CommitmentStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(storage_error)?;
        let store = Self { db };
        let write = store.db.begin_write().map_err(storage_error)?;
        write.open_table(COMMITMENTS).map_err(storage_error)?;
        write.commit().map_err(storage_error)?;
        Ok(store)
    }

    /// Record a vote we just signed and what we signed it over. Must succeed
    /// before the vote is broadcast.
    ///
    /// Keyed by height: a prevote may be upgraded to a precommit for the *same*
    /// checkpoint hash, but a second hash at the same height is rejected — that
    /// would be durable equivocation against ourselves.
    pub fn put(&self, commitment: &Commitment) -> Result<()> {
        commitment.verify()?;
        let height = commitment.height();
        if let Some(existing) = self.get(height)? {
            if existing.vote.checkpoint_hash != commitment.vote.checkpoint_hash {
                return Err(Error::Other(format!(
                    "conflicting commitment at height {height}"
                )));
            }
            if &existing == commitment {
                return Ok(());
            }
            // Same hash, different step (prevote → precommit) or proposal body:
            // overwrite below.
        }
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(COMMITMENTS).map_err(storage_error)?;
            table
                .insert(commitment.height(), commitment.to_bytes().as_slice())
                .map_err(storage_error)?;
        }
        write.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn get(&self, height: u64) -> Result<Option<Commitment>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(COMMITMENTS).map_err(storage_error)?;
        match table.get(height).map_err(storage_error)? {
            Some(bytes) => Ok(Some(Commitment::from_bytes(bytes.value())?)),
            None => Ok(None),
        }
    }

    /// Commitments strictly above `min_height` (already-finalized heights are
    /// ignored), ascending.
    pub fn load_above(&self, min_height: u64) -> Result<Vec<Commitment>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(COMMITMENTS).map_err(storage_error)?;
        let mut out = Vec::new();
        for entry in table.range(min_height + 1..).map_err(storage_error)? {
            let (_, bytes) = entry.map_err(storage_error)?;
            out.push(Commitment::from_bytes(bytes.value())?);
        }
        Ok(out)
    }

    /// Drop commitments for heights that are already final (`height <
    /// min_height`).
    pub fn prune_below(&self, min_height: u64) -> Result<()> {
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(COMMITMENTS).map_err(storage_error)?;
            let stale: Vec<u64> = table
                .range(..min_height)
                .map_err(storage_error)?
                .map(|entry| entry.map(|(k, _)| k.value()).map_err(storage_error))
                .collect::<Result<Vec<u64>>>()?;
            for height in stale {
                table.remove(height).map_err(storage_error)?;
            }
        }
        write.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn len(&self) -> Result<u64> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(COMMITMENTS).map_err(storage_error)?;
        table.len().map_err(storage_error)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::{Address, Hash};
    use sikka_common::checkpoint::CheckpointHeader;
    use sikka_common::transaction::Transaction;
    use sikka_crypto::Keypair;

    fn store() -> (CommitmentStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = CommitmentStore::open(dir.path().join("commitments.redb")).unwrap();
        (store, dir)
    }

    /// A commitment at `height`, distinguishable by the byte fill it uses.
    fn commitment(kp: &Keypair, height: u64) -> Commitment {
        let fill = height as u8;
        let proposal = CheckpointProposal {
            header: CheckpointHeader {
                height,
                prev_hash: Hash([fill; 32]),
                state_root: Hash([fill; 32]),
                validator_root: Hash([fill; 32]),
                tx_root: Hash([fill; 32]),
                tx_count: 1,
                timestamp: 1_700_000_000 + height,
                proposer: Address(kp.address_bytes()),
                round: 0,
                total_supply: 1_000_000,
                total_bonded: 1_000,
                chain_id: "sikka-test".into(),
                genesis_fingerprint: Hash([0xAA; 32]),
            },
            transactions: vec![
                Transaction::transfer(kp, Address([fill; 32]), 1, 0, 1_700_000_000, "sikka-test", Hash([0xAA; 32])).unwrap(),
            ],
            evidence: Vec::new(),
            proposer_signature: sikka_common::bytes::Signature::default(),
        };
        let mut proposal = proposal;
        proposal.sign(kp).unwrap();
        let vote = Vote::sign(kp, "sikka-test", Hash([0xAA; 32]), height, 0, sikka_common::vote::VoteKind::Prevote, proposal.hash()).unwrap();
        Commitment { vote, proposal }
    }

    #[test]
    fn put_get_and_load_above() {
        let (store, _dir) = store();
        let kp = Keypair::generate().unwrap();
        let c1 = commitment(&kp, 1);
        let c2 = commitment(&kp, 2);
        store.put(&c1).unwrap();
        store.put(&c2).unwrap();

        assert_eq!(store.get(1).unwrap().as_ref(), Some(&c1));
        assert_eq!(store.get(3).unwrap(), None);

        let above0 = store.load_above(0).unwrap();
        assert_eq!(above0, vec![c1.clone(), c2.clone()]);
        assert_eq!(store.load_above(1).unwrap(), vec![c2]);
        assert!(store.load_above(2).unwrap().is_empty());
    }

    #[test]
    fn a_stored_vote_still_names_the_checkpoint_it_was_cast_for() {
        let (store, _dir) = store();
        let kp = Keypair::generate().unwrap();
        let stored = commitment(&kp, 4);
        store.put(&stored).unwrap();

        // The point of keeping both: the restored vote can be matched back to a
        // checkpoint this node can offer again.
        let loaded = store.get(4).unwrap().unwrap();
        assert_eq!(loaded.vote.checkpoint_hash, loaded.proposal.hash());
        assert_eq!(loaded.proposal.transactions, stored.proposal.transactions);
    }

    #[test]
    fn a_vote_paired_with_the_wrong_proposal_is_refused() {
        let (store, _dir) = store();
        let kp = Keypair::generate().unwrap();
        let mut mismatched = commitment(&kp, 5);
        mismatched.proposal.header.timestamp += 1;
        assert!(store.put(&mismatched).is_err());
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn prune_below_drops_finalized_heights() {
        let (store, _dir) = store();
        let kp = Keypair::generate().unwrap();
        for height in 1..=3 {
            store.put(&commitment(&kp, height)).unwrap();
        }

        store.prune_below(3).unwrap();
        assert!(store.get(1).unwrap().is_none());
        assert!(store.get(2).unwrap().is_none());
        assert!(store.get(3).unwrap().is_some());
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("commitments.redb");
        let kp = Keypair::generate().unwrap();
        let stored = commitment(&kp, 7);
        {
            let store = CommitmentStore::open(&path).unwrap();
            assert!(store.is_empty().unwrap());
            store.put(&stored).unwrap();
        }
        let store = CommitmentStore::open(&path).unwrap();
        assert_eq!(store.get(7).unwrap().as_ref(), Some(&stored));
    }
}
