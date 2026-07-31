//! Persistent store for this node's own checkpoint votes.
//!
//! Votes for unfinalized heights must survive restarts. Forgetting a signed vote
//! and then signing a rival at the same height is equivocation and burns the
//! bond. Peer votes stay in RAM; only our own signatures are written here.

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use sikka_common::codec::{Decode, Encode};
use sikka_common::error::{Error, Result};
use sikka_common::vote::Vote;

const LOCAL_VOTES: TableDefinition<u64, &[u8]> = TableDefinition::new("local_votes");

fn storage_error<E: std::fmt::Display>(e: E) -> Error {
    Error::Storage(e.to_string())
}

/// This node's signed votes for heights that are not yet final.
pub struct LocalVoteStore {
    db: Database,
}

impl LocalVoteStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(storage_error)?;
        let store = Self { db };
        let write = store.db.begin_write().map_err(storage_error)?;
        write.open_table(LOCAL_VOTES).map_err(storage_error)?;
        write.commit().map_err(storage_error)?;
        Ok(store)
    }

    /// Persist a vote we just signed. Must succeed before the vote is broadcast.
    pub fn put(&self, vote: &Vote) -> Result<()> {
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(LOCAL_VOTES).map_err(storage_error)?;
            table
                .insert(vote.height, vote.to_bytes().as_slice())
                .map_err(storage_error)?;
        }
        write.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn get(&self, height: u64) -> Result<Option<Vote>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(LOCAL_VOTES).map_err(storage_error)?;
        match table.get(height).map_err(storage_error)? {
            Some(bytes) => Ok(Some(Vote::from_bytes(bytes.value())?)),
            None => Ok(None),
        }
    }

    /// Votes strictly above `min_height` (already-finalized heights are ignored).
    pub fn load_above(&self, min_height: u64) -> Result<Vec<Vote>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(LOCAL_VOTES).map_err(storage_error)?;
        let mut out = Vec::new();
        for entry in table.range(min_height + 1..).map_err(storage_error)? {
            let (_, bytes) = entry.map_err(storage_error)?;
            out.push(Vote::from_bytes(bytes.value())?);
        }
        Ok(out)
    }

    /// Drop votes for heights that are already final (`height < min_height`).
    pub fn prune_below(&self, min_height: u64) -> Result<()> {
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(LOCAL_VOTES).map_err(storage_error)?;
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
        let table = read.open_table(LOCAL_VOTES).map_err(storage_error)?;
        table.len().map_err(storage_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::Hash;
    use sikka_crypto::Keypair;

    fn store() -> (LocalVoteStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalVoteStore::open(dir.path().join("local_votes.redb")).unwrap();
        (store, dir)
    }

    #[test]
    fn put_get_and_load_above() {
        let (store, _dir) = store();
        let kp = Keypair::generate().unwrap();
        let v1 = Vote::sign(&kp, 1, Hash([1u8; 32])).unwrap();
        let v2 = Vote::sign(&kp, 2, Hash([2u8; 32])).unwrap();
        store.put(&v1).unwrap();
        store.put(&v2).unwrap();

        assert_eq!(store.get(1).unwrap().as_ref(), Some(&v1));
        assert_eq!(store.get(3).unwrap(), None);

        let above0 = store.load_above(0).unwrap();
        assert_eq!(above0, vec![v1.clone(), v2.clone()]);
        assert_eq!(store.load_above(1).unwrap(), vec![v2]);
        assert!(store.load_above(2).unwrap().is_empty());
    }

    #[test]
    fn prune_below_drops_finalized_heights() {
        let (store, _dir) = store();
        let kp = Keypair::generate().unwrap();
        store
            .put(&Vote::sign(&kp, 1, Hash([1u8; 32])).unwrap())
            .unwrap();
        store
            .put(&Vote::sign(&kp, 2, Hash([2u8; 32])).unwrap())
            .unwrap();
        store
            .put(&Vote::sign(&kp, 3, Hash([3u8; 32])).unwrap())
            .unwrap();

        store.prune_below(3).unwrap();
        assert!(store.get(1).unwrap().is_none());
        assert!(store.get(2).unwrap().is_none());
        assert!(store.get(3).unwrap().is_some());
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local_votes.redb");
        let kp = Keypair::generate().unwrap();
        let vote = Vote::sign(&kp, 7, Hash([7u8; 32])).unwrap();
        {
            let store = LocalVoteStore::open(&path).unwrap();
            store.put(&vote).unwrap();
        }
        let store = LocalVoteStore::open(&path).unwrap();
        assert_eq!(store.get(7).unwrap().as_ref(), Some(&vote));
    }
}
