//! Checkpoint storage.
//!
//! Only the last [`CHECKPOINT_HISTORY`] checkpoints are kept. Older ones are
//! deleted: a finalized checkpoint's only job is to attest to the state root,
//! and once a newer one has done that, the older attestation is redundant. This
//! is why a ten-year-old chain is no larger than a new one.
//!
//! [`CHECKPOINT_HISTORY`]: sikka_common::constants::CHECKPOINT_HISTORY

mod local_votes;

pub use local_votes::LocalVoteStore;

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use sikka_common::bytes::Hash;
use sikka_common::checkpoint::Checkpoint;
use sikka_common::codec::{Decode, Encode};
use sikka_common::constants::CHECKPOINT_HISTORY;
use sikka_common::error::{Error, Result};

const CHECKPOINTS: TableDefinition<u64, &[u8]> = TableDefinition::new("checkpoints");

fn storage_error<E: std::fmt::Display>(e: E) -> Error {
    Error::Storage(e.to_string())
}

/// A bounded, append-only window of finalized checkpoints.
pub struct CheckpointStore {
    db: Database,
    /// How many recent checkpoints to keep. Configurable so tests can exercise
    /// pruning without writing a hundred checkpoints.
    retention: u64,
}

impl CheckpointStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_retention(path, CHECKPOINT_HISTORY)
    }

    pub fn open_with_retention(path: impl AsRef<Path>, retention: u64) -> Result<Self> {
        let db = Database::create(path).map_err(storage_error)?;
        let store = Self {
            db,
            retention: retention.max(1),
        };
        let write = store.db.begin_write().map_err(storage_error)?;
        write.open_table(CHECKPOINTS).map_err(storage_error)?;
        write.commit().map_err(storage_error)?;
        Ok(store)
    }

    pub fn retention(&self) -> u64 {
        self.retention
    }

    /// Store a checkpoint and prune anything that fell out of the window.
    pub fn put(&self, checkpoint: &Checkpoint) -> Result<()> {
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(CHECKPOINTS).map_err(storage_error)?;
            table
                .insert(checkpoint.header.height, checkpoint.to_bytes().as_slice())
                .map_err(storage_error)?;

            // Genesis is always retained: a node that has pruned everything
            // else can still prove which chain it is on.
            let height = checkpoint.header.height;
            if height >= self.retention {
                let cutoff = height - self.retention + 1;
                let stale: Vec<u64> = table
                    .range(1..cutoff)
                    .map_err(storage_error)?
                    .map(|entry| entry.map(|(k, _)| k.value()).map_err(storage_error))
                    .collect::<Result<Vec<u64>>>()?;
                for height in stale {
                    table.remove(height).map_err(storage_error)?;
                }
            }
        }
        write.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn get(&self, height: u64) -> Result<Option<Checkpoint>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(CHECKPOINTS).map_err(storage_error)?;
        match table.get(height).map_err(storage_error)? {
            Some(bytes) => Ok(Some(Checkpoint::from_bytes(bytes.value())?)),
            None => Ok(None),
        }
    }

    pub fn require(&self, height: u64) -> Result<Checkpoint> {
        self.get(height)?.ok_or(Error::CheckpointNotFound(height))
    }

    /// The highest stored checkpoint.
    pub fn latest(&self) -> Result<Option<Checkpoint>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(CHECKPOINTS).map_err(storage_error)?;
        let latest = match table.last().map_err(storage_error)? {
            Some((_, bytes)) => Some(Checkpoint::from_bytes(bytes.value())?),
            None => None,
        };
        Ok(latest)
    }

    pub fn latest_height(&self) -> Result<Option<u64>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(CHECKPOINTS).map_err(storage_error)?;
        let height = table.last().map_err(storage_error)?.map(|(k, _)| k.value());
        Ok(height)
    }

    /// Heights currently retained, ascending.
    pub fn heights(&self) -> Result<Vec<u64>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(CHECKPOINTS).map_err(storage_error)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(storage_error)? {
            out.push(entry.map_err(storage_error)?.0.value());
        }
        Ok(out)
    }

    pub fn len(&self) -> Result<u64> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(CHECKPOINTS).map_err(storage_error)?;
        table.len().map_err(storage_error)
    }

    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Walk back from `height` and confirm each checkpoint links to its parent.
    ///
    /// Only checks the range still retained; the chain before the window is
    /// vouched for by the state root, not by links.
    pub fn verify_links(&self, height: u64) -> Result<()> {
        let mut current = self.require(height)?;
        loop {
            let parent_height = match current.header.height.checked_sub(1) {
                Some(h) => h,
                None => return Ok(()),
            };
            let Some(parent) = self.get(parent_height)? else {
                return Ok(());
            };
            let parent_hash: Hash = parent.hash();
            if current.header.prev_hash != parent_hash {
                return Err(Error::BadCheckpointParent {
                    expected: parent_hash,
                    actual: current.header.prev_hash,
                });
            }
            current = parent;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::Address;
    use sikka_common::checkpoint::CheckpointHeader;

    fn store(retention: u64) -> (CheckpointStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store =
            CheckpointStore::open_with_retention(dir.path().join("checkpoints.redb"), retention)
                .unwrap();
        (store, dir)
    }

    fn checkpoint(height: u64, prev: Hash) -> Checkpoint {
        Checkpoint::new(CheckpointHeader {
            height,
            prev_hash: prev,
            state_root: Hash([height as u8; 32]),
            validator_root: Hash([2u8; 32]),
            tx_root: Hash([3u8; 32]),
            tx_count: 10_000,
            timestamp: 1_700_000_000 + height,
            proposer: Address([4u8; 32]),
            round: 0,
            total_supply: 1_000_000,
            total_bonded: 1_000,
        })
    }

    /// Write `count` linked checkpoints starting at height 0.
    fn fill(store: &CheckpointStore, count: u64) -> Vec<Checkpoint> {
        let mut prev = Hash::ZERO;
        let mut all = Vec::new();
        for height in 0..count {
            let cp = checkpoint(height, prev);
            prev = cp.hash();
            store.put(&cp).unwrap();
            all.push(cp);
        }
        all
    }

    #[test]
    fn put_and_get() {
        let (store, _dir) = store(100);
        assert!(store.is_empty().unwrap());
        let cp = checkpoint(0, Hash::ZERO);
        store.put(&cp).unwrap();
        assert_eq!(store.get(0).unwrap().as_ref(), Some(&cp));
        assert_eq!(store.get(1).unwrap(), None);
        assert_eq!(store.require(1).unwrap_err(), Error::CheckpointNotFound(1));
    }

    #[test]
    fn latest_tracks_the_highest_height() {
        let (store, _dir) = store(100);
        let all = fill(&store, 5);
        assert_eq!(store.latest().unwrap().unwrap(), all[4]);
        assert_eq!(store.latest_height().unwrap(), Some(4));
    }

    #[test]
    fn pruning_keeps_the_window_and_genesis() {
        let (store, _dir) = store(3);
        fill(&store, 10);

        // Genesis plus the last three.
        assert_eq!(store.heights().unwrap(), vec![0, 7, 8, 9]);
        assert!(
            store.get(0).unwrap().is_some(),
            "genesis must survive pruning"
        );
        assert!(store.get(6).unwrap().is_none());
    }

    #[test]
    fn nothing_is_pruned_before_the_window_fills() {
        let (store, _dir) = store(100);
        fill(&store, 10);
        assert_eq!(store.len().unwrap(), 10);
        assert_eq!(store.heights().unwrap(), (0..10).collect::<Vec<u64>>());
    }

    #[test]
    fn links_verify_and_a_broken_link_is_caught() {
        let (store, _dir) = store(100);
        fill(&store, 6);
        store.verify_links(5).unwrap();

        // Overwrite height 3 with a checkpoint pointing at the wrong parent.
        store.put(&checkpoint(3, Hash([0x99u8; 32]))).unwrap();
        assert!(matches!(
            store.verify_links(5),
            Err(Error::BadCheckpointParent { .. })
        ));
    }

    #[test]
    fn survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoints.redb");
        {
            let store = CheckpointStore::open(&path).unwrap();
            fill(&store, 4);
        }
        let store = CheckpointStore::open(&path).unwrap();
        assert_eq!(store.latest_height().unwrap(), Some(3));
        assert_eq!(store.len().unwrap(), 4);
    }

    #[test]
    fn default_retention_is_a_hundred() {
        let (store, _dir) = store(CHECKPOINT_HISTORY);
        assert_eq!(store.retention(), 100);
        fill(&store, 150);
        // Genesis plus heights 50..149.
        assert_eq!(store.len().unwrap(), 101);
        assert!(store.get(50).unwrap().is_some());
        assert!(store.get(49).unwrap().is_none());
        assert!(store.get(0).unwrap().is_some());
    }
}
