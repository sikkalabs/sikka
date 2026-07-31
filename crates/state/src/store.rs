//! Persistent state: `redb` tables for accounts, validators and ledger meta.
//!
//! Three tables, no history. Storage grows with the number of accounts, not the
//! number of transactions, which is the whole point of the design: a ten-year-old
//! chain with ten million accounts is the same size as a one-day-old chain with
//! ten million accounts.

use std::path::Path;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};
use sikka_common::account::Account;
use sikka_common::bytes::{Address, Hash};
use sikka_common::codec::{Decode, Encode, Reader, Writer};
use sikka_common::error::{Error, Result};
use sikka_common::validator::Validator;

const ACCOUNTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("accounts");
const VALIDATORS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("validators");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

const META_KEY: &str = "ledger";

fn storage_error<E: std::fmt::Display>(e: E) -> Error {
    Error::Storage(e.to_string())
}

/// Everything about the chain that is not an account or a validator.
///
/// One record, written in the same transaction as the accounts it describes, so
/// the database can never claim a state root that its accounts do not produce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerMeta {
    pub chain_id: String,
    pub genesis_fingerprint: Hash,
    /// Transactions per checkpoint for this chain (10,000 on mainnet).
    pub checkpoint_tx_interval: u32,
    /// Height of the last finalized checkpoint.
    pub height: u64,
    pub last_checkpoint_hash: Hash,
    pub last_checkpoint_time: u64,
    pub state_root: Hash,
    pub validator_root: Hash,
    pub total_supply: u64,
    pub total_bonded: u64,
}

impl Encode for LedgerMeta {
    fn encode(&self, w: &mut Writer) {
        w.str(&self.chain_id)
            .raw(self.genesis_fingerprint.as_bytes())
            .u32(self.checkpoint_tx_interval)
            .u64(self.height)
            .raw(self.last_checkpoint_hash.as_bytes())
            .u64(self.last_checkpoint_time)
            .raw(self.state_root.as_bytes())
            .raw(self.validator_root.as_bytes())
            .u64(self.total_supply)
            .u64(self.total_bonded);
    }
}

impl Decode for LedgerMeta {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            chain_id: r.str()?,
            genesis_fingerprint: Hash::decode(r)?,
            checkpoint_tx_interval: r.u32()?,
            height: r.u64()?,
            last_checkpoint_hash: Hash::decode(r)?,
            last_checkpoint_time: r.u64()?,
            state_root: Hash::decode(r)?,
            validator_root: Hash::decode(r)?,
            total_supply: r.u64()?,
            total_bonded: r.u64()?,
        })
    }
}

/// A set of changes applied to the database in a single atomic transaction.
///
/// `None` deletes the record.
#[derive(Debug, Default, Clone)]
pub struct WriteBatch {
    pub accounts: Vec<(Address, Option<Account>)>,
    pub validators: Vec<(Address, Option<Validator>)>,
    pub meta: Option<LedgerMeta>,
}

impl WriteBatch {
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.validators.is_empty() && self.meta.is_none()
    }
}

/// The account and validator database.
pub struct StateStore {
    db: Database,
}

impl StateStore {
    /// Open (creating if needed) the state database at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let db = Database::create(path).map_err(storage_error)?;
        let store = Self { db };
        store.ensure_tables()?;
        Ok(store)
    }

    /// Create the tables so later read transactions never see a missing table.
    fn ensure_tables(&self) -> Result<()> {
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            write.open_table(ACCOUNTS).map_err(storage_error)?;
            write.open_table(VALIDATORS).map_err(storage_error)?;
            write.open_table(META).map_err(storage_error)?;
        }
        write.commit().map_err(storage_error)?;
        Ok(())
    }

    pub fn account(&self, address: &Address) -> Result<Option<Account>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(ACCOUNTS).map_err(storage_error)?;
        match table
            .get(address.as_bytes().as_slice())
            .map_err(storage_error)?
        {
            Some(bytes) => Ok(Some(Account::from_bytes(bytes.value())?)),
            None => Ok(None),
        }
    }

    pub fn account_count(&self) -> Result<u64> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(ACCOUNTS).map_err(storage_error)?;
        table.len().map_err(storage_error)
    }

    /// Every account, ascending by address.
    pub fn all_accounts(&self) -> Result<Vec<(Address, Account)>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(ACCOUNTS).map_err(storage_error)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(storage_error)? {
            let (key, value) = entry.map_err(storage_error)?;
            out.push((
                Address::from_slice(key.value())?,
                Account::from_bytes(value.value())?,
            ));
        }
        Ok(out)
    }

    pub fn validator(&self, address: &Address) -> Result<Option<Validator>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(VALIDATORS).map_err(storage_error)?;
        match table
            .get(address.as_bytes().as_slice())
            .map_err(storage_error)?
        {
            Some(bytes) => Ok(Some(Validator::from_bytes(bytes.value())?)),
            None => Ok(None),
        }
    }

    /// Every validator record, ascending by address.
    pub fn all_validators(&self) -> Result<Vec<Validator>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(VALIDATORS).map_err(storage_error)?;
        let mut out = Vec::new();
        for entry in table.iter().map_err(storage_error)? {
            let (_, value) = entry.map_err(storage_error)?;
            out.push(Validator::from_bytes(value.value())?);
        }
        Ok(out)
    }

    pub fn meta(&self) -> Result<Option<LedgerMeta>> {
        let read = self.db.begin_read().map_err(storage_error)?;
        let table = read.open_table(META).map_err(storage_error)?;
        match table.get(META_KEY).map_err(storage_error)? {
            Some(bytes) => Ok(Some(LedgerMeta::from_bytes(bytes.value())?)),
            None => Ok(None),
        }
    }

    /// Apply a batch atomically. Either everything lands or nothing does.
    pub fn write(&self, batch: &WriteBatch) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            let mut accounts = write.open_table(ACCOUNTS).map_err(storage_error)?;
            for (address, account) in &batch.accounts {
                match account {
                    Some(account) => {
                        accounts
                            .insert(address.as_bytes().as_slice(), account.to_bytes().as_slice())
                            .map_err(storage_error)?;
                    }
                    None => {
                        accounts
                            .remove(address.as_bytes().as_slice())
                            .map_err(storage_error)?;
                    }
                }
            }

            let mut validators = write.open_table(VALIDATORS).map_err(storage_error)?;
            for (address, validator) in &batch.validators {
                match validator {
                    Some(validator) => {
                        validators
                            .insert(
                                address.as_bytes().as_slice(),
                                validator.to_bytes().as_slice(),
                            )
                            .map_err(storage_error)?;
                    }
                    None => {
                        validators
                            .remove(address.as_bytes().as_slice())
                            .map_err(storage_error)?;
                    }
                }
            }

            if let Some(meta) = &batch.meta {
                let mut table = write.open_table(META).map_err(storage_error)?;
                table
                    .insert(META_KEY, meta.to_bytes().as_slice())
                    .map_err(storage_error)?;
            }
        }
        write.commit().map_err(storage_error)?;
        Ok(())
    }

    /// Replace the entire contents of the database in one transaction.
    ///
    /// Used by fast sync: a node that has fallen too far behind cannot replay
    /// its way forward (the transactions are gone by design), so it swaps its
    /// whole state for a verified snapshot instead.
    pub fn replace_all(
        &self,
        accounts: &[(Address, Account)],
        validators: &[Validator],
        meta: &LedgerMeta,
    ) -> Result<()> {
        let write = self.db.begin_write().map_err(storage_error)?;
        {
            let mut table = write.open_table(ACCOUNTS).map_err(storage_error)?;
            let existing: Vec<Vec<u8>> = table
                .iter()
                .map_err(storage_error)?
                .map(|entry| {
                    entry
                        .map(|(k, _)| k.value().to_vec())
                        .map_err(storage_error)
                })
                .collect::<Result<Vec<Vec<u8>>>>()?;
            for key in existing {
                table.remove(key.as_slice()).map_err(storage_error)?;
            }
            for (address, account) in accounts {
                table
                    .insert(address.as_bytes().as_slice(), account.to_bytes().as_slice())
                    .map_err(storage_error)?;
            }
        }
        {
            let mut table = write.open_table(VALIDATORS).map_err(storage_error)?;
            let existing: Vec<Vec<u8>> = table
                .iter()
                .map_err(storage_error)?
                .map(|entry| {
                    entry
                        .map(|(k, _)| k.value().to_vec())
                        .map_err(storage_error)
                })
                .collect::<Result<Vec<Vec<u8>>>>()?;
            for key in existing {
                table.remove(key.as_slice()).map_err(storage_error)?;
            }
            for validator in validators {
                table
                    .insert(
                        validator.address.as_bytes().as_slice(),
                        validator.to_bytes().as_slice(),
                    )
                    .map_err(storage_error)?;
            }
        }
        {
            let mut table = write.open_table(META).map_err(storage_error)?;
            table
                .insert(META_KEY, meta.to_bytes().as_slice())
                .map_err(storage_error)?;
        }
        write.commit().map_err(storage_error)?;
        Ok(())
    }

    /// Reclaim space after pruning.
    pub fn compact(&mut self) -> Result<()> {
        self.db.compact().map_err(storage_error)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::PublicKey;
    use sikka_crypto::PK_LEN;

    fn store() -> (StateStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = StateStore::open(dir.path().join("state.redb")).unwrap();
        (store, dir)
    }

    fn meta() -> LedgerMeta {
        LedgerMeta {
            chain_id: "sikka-test".into(),
            genesis_fingerprint: Hash([1u8; 32]),
            checkpoint_tx_interval: 4,
            height: 7,
            last_checkpoint_hash: Hash([2u8; 32]),
            last_checkpoint_time: 1_700_000_000,
            state_root: Hash([3u8; 32]),
            validator_root: Hash([4u8; 32]),
            total_supply: 21_000_000,
            total_bonded: 1_000,
        }
    }

    #[test]
    fn accounts_roundtrip() {
        let (store, _dir) = store();
        let address = Address([1u8; 32]);
        assert_eq!(store.account(&address).unwrap(), None);

        let account = Account {
            balance: 500,
            nonce: 2,
            credits: 90,
            last_regen_time: 123,
        };
        store
            .write(&WriteBatch {
                accounts: vec![(address, Some(account))],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(store.account(&address).unwrap(), Some(account));
        assert_eq!(store.account_count().unwrap(), 1);
    }

    #[test]
    fn deletion_removes_the_record() {
        let (store, _dir) = store();
        let address = Address([1u8; 32]);
        let account = Account {
            balance: 1,
            nonce: 0,
            credits: 0,
            last_regen_time: 0,
        };
        store
            .write(&WriteBatch {
                accounts: vec![(address, Some(account))],
                ..Default::default()
            })
            .unwrap();
        store
            .write(&WriteBatch {
                accounts: vec![(address, None)],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(store.account(&address).unwrap(), None);
        assert_eq!(store.account_count().unwrap(), 0);
    }

    #[test]
    fn accounts_iterate_in_address_order() {
        let (store, _dir) = store();
        let mut batch = WriteBatch::default();
        for i in [5u8, 1, 9, 3] {
            batch.accounts.push((
                Address([i; 32]),
                Some(Account {
                    balance: u64::from(i),
                    nonce: 0,
                    credits: 0,
                    last_regen_time: 0,
                }),
            ));
        }
        store.write(&batch).unwrap();

        let accounts = store.all_accounts().unwrap();
        let addresses: Vec<Address> = accounts.iter().map(|(a, _)| *a).collect();
        let mut sorted = addresses.clone();
        sorted.sort();
        assert_eq!(addresses, sorted);
        assert_eq!(accounts.len(), 4);
    }

    #[test]
    fn validators_roundtrip() {
        let (store, _dir) = store();
        let validator = Validator::new(PublicKey::new([7u8; PK_LEN]), 1_000, 1);
        store
            .write(&WriteBatch {
                validators: vec![(validator.address, Some(validator.clone()))],
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            store.validator(&validator.address).unwrap(),
            Some(validator.clone())
        );
        assert_eq!(store.all_validators().unwrap(), vec![validator]);
    }

    #[test]
    fn meta_roundtrips() {
        let (store, _dir) = store();
        assert_eq!(store.meta().unwrap(), None);
        let m = meta();
        store
            .write(&WriteBatch {
                meta: Some(m.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(store.meta().unwrap(), Some(m));
    }

    #[test]
    fn state_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.redb");
        let address = Address([8u8; 32]);
        let account = Account {
            balance: 42,
            nonce: 1,
            credits: 10,
            last_regen_time: 5,
        };
        {
            let store = StateStore::open(&path).unwrap();
            store
                .write(&WriteBatch {
                    accounts: vec![(address, Some(account))],
                    meta: Some(meta()),
                    ..Default::default()
                })
                .unwrap();
        }
        let store = StateStore::open(&path).unwrap();
        assert_eq!(store.account(&address).unwrap(), Some(account));
        assert_eq!(store.meta().unwrap(), Some(meta()));
    }

    #[test]
    fn meta_encoding_roundtrips() {
        let m = meta();
        assert_eq!(LedgerMeta::from_bytes(&m.to_bytes()).unwrap(), m);
    }
}
