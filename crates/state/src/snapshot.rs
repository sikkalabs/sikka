//! Chunked, compressed state snapshots.
//!
//! Snapshots are transferred as a small JSON manifest plus independently
//! compressed binary chunks. Chunks are content-checked before they are kept,
//! so interrupted downloads can resume without trusting partial files.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sikka_common::account::Account;
use sikka_common::bytes::{Address, Hash};
use sikka_common::checkpoint::Checkpoint;
use sikka_common::codec::{Decode, Encode, Reader, Writer};
use sikka_common::error::{Error, Result};
use sikka_common::validator::Validator;

use crate::ledger::StateSnapshot;

pub const SNAPSHOT_FORMAT_VERSION: u32 = 1;
pub const SNAPSHOT_CHUNK_TARGET_BYTES: usize = 4 * 1024 * 1024;
pub const SNAPSHOT_MAX_COMPRESSED_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const SNAPSHOT_MAX_UNCOMPRESSED_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const SNAPSHOT_MAX_MANIFEST_BYTES: usize = 32 * 1024 * 1024;
pub const SNAPSHOT_MAX_CHUNKS: usize = 65_536;
pub const SNAPSHOT_MAX_ACCOUNTS: u64 = 100_000_000;
pub const SNAPSHOT_MAX_VALIDATORS: u64 = 1_000_000;
pub const SNAPSHOT_MAX_UNCOMPRESSED_BYTES: u64 = 64 * 1024 * 1024 * 1024;

const SNAPSHOT_CHUNK_MAGIC: &[u8; 8] = b"SIKSNP01";
const SNAPSHOT_CHUNK_HASH_TAG: &[u8] = b"SIKKA/snapshot-chunk/v1";
const SNAPSHOT_COMPRESSION_LEVEL: i32 = 3;
const SNAPSHOT_ARCHIVES_RETAINED: usize = 2;

fn storage_error(action: &str, path: &Path, error: impl std::fmt::Display) -> Error {
    Error::Storage(format!("{action} {}: {error}", path.display()))
}

fn chunk_filename(index: u32) -> String {
    format!("chunk-{index:08}.zst")
}

fn id_dirname(id: &Hash) -> String {
    id.to_hex().trim_start_matches("0x").to_string()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotChunkKind {
    Accounts,
    Validators,
}

impl SnapshotChunkKind {
    fn tag(self) -> u8 {
        match self {
            Self::Accounts => 1,
            Self::Validators => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Accounts),
            2 => Ok(Self::Validators),
            tag => Err(Error::InvalidTag {
                kind: "snapshot chunk",
                tag,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotChunkMeta {
    pub index: u32,
    pub kind: SnapshotChunkKind,
    pub records: u32,
    pub compressed_bytes: u32,
    pub uncompressed_bytes: u32,
    pub hash: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    pub version: u32,
    pub snapshot_id: Hash,
    pub chain_id: String,
    pub genesis_fingerprint: Hash,
    pub checkpoint_tx_interval: u32,
    pub checkpoint: Checkpoint,
    pub account_count: u64,
    pub validator_count: u64,
    pub chunks: Vec<SnapshotChunkMeta>,
}

impl SnapshotManifest {
    pub fn validate(&self) -> Result<()> {
        if self.version != SNAPSHOT_FORMAT_VERSION {
            return Err(Error::Network(format!(
                "unsupported snapshot format version {}",
                self.version
            )));
        }
        if self.snapshot_id != self.checkpoint.hash() {
            return Err(Error::Network(
                "snapshot id does not match checkpoint hash".into(),
            ));
        }
        if self.chain_id.is_empty() || self.chain_id.len() > 128 {
            return Err(Error::Network("invalid snapshot chain id".into()));
        }
        if self.account_count > SNAPSHOT_MAX_ACCOUNTS {
            return Err(Error::Network(format!(
                "snapshot has too many accounts: {}",
                self.account_count
            )));
        }
        if self.validator_count > SNAPSHOT_MAX_VALIDATORS {
            return Err(Error::Network(format!(
                "snapshot has too many validators: {}",
                self.validator_count
            )));
        }
        if self.chunks.len() > SNAPSHOT_MAX_CHUNKS {
            return Err(Error::Network(format!(
                "snapshot has too many chunks: {}",
                self.chunks.len()
            )));
        }

        let mut accounts = 0u64;
        let mut validators = 0u64;
        let mut uncompressed = 0u64;
        let mut saw_validators = false;
        for (expected, chunk) in self.chunks.iter().enumerate() {
            if chunk.index as usize != expected {
                return Err(Error::Network(
                    "snapshot chunk indexes are not contiguous".into(),
                ));
            }
            if chunk.records == 0 {
                return Err(Error::Network(format!(
                    "snapshot chunk {} is empty",
                    chunk.index
                )));
            }
            let compressed = chunk.compressed_bytes as usize;
            let plain = chunk.uncompressed_bytes as usize;
            if compressed == 0 || compressed > SNAPSHOT_MAX_COMPRESSED_CHUNK_BYTES {
                return Err(Error::Network(format!(
                    "snapshot chunk {} has invalid compressed size",
                    chunk.index
                )));
            }
            if plain == 0 || plain > SNAPSHOT_MAX_UNCOMPRESSED_CHUNK_BYTES {
                return Err(Error::Network(format!(
                    "snapshot chunk {} has invalid uncompressed size",
                    chunk.index
                )));
            }
            uncompressed = uncompressed
                .checked_add(chunk.uncompressed_bytes as u64)
                .ok_or_else(|| Error::Network("snapshot size overflow".into()))?;
            match chunk.kind {
                SnapshotChunkKind::Accounts if saw_validators => {
                    return Err(Error::Network(
                        "account chunks follow validator chunks".into(),
                    ));
                }
                SnapshotChunkKind::Accounts => accounts += u64::from(chunk.records),
                SnapshotChunkKind::Validators => {
                    saw_validators = true;
                    validators += u64::from(chunk.records);
                }
            }
        }
        if accounts != self.account_count || validators != self.validator_count {
            return Err(Error::Network(
                "snapshot record counts do not match manifest".into(),
            ));
        }
        if uncompressed > SNAPSHOT_MAX_UNCOMPRESSED_BYTES {
            return Err(Error::Network(format!(
                "snapshot expands beyond {} bytes",
                SNAPSHOT_MAX_UNCOMPRESSED_BYTES
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotHeader {
    pub chain_id: String,
    pub genesis_fingerprint: Hash,
    pub checkpoint_tx_interval: u32,
    pub checkpoint: Checkpoint,
}

/// Incremental writer used while holding a consistent database read view.
pub struct SnapshotArchiveWriter {
    root: PathBuf,
    temp_dir: PathBuf,
    final_dir: PathBuf,
    header: SnapshotHeader,
    chunks: Vec<SnapshotChunkMeta>,
    records: Writer,
    record_count: u32,
    kind: Option<SnapshotChunkKind>,
    account_count: u64,
    validator_count: u64,
}

impl SnapshotArchiveWriter {
    pub fn create(root: impl AsRef<Path>, header: SnapshotHeader) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|e| storage_error("create", &root, e))?;
        let dirname = id_dirname(&header.checkpoint.hash());
        let final_dir = root.join(&dirname);
        let temp_dir = root.join(format!("{dirname}.building-{}", std::process::id()));
        if temp_dir.exists() {
            fs::remove_dir_all(&temp_dir)
                .map_err(|e| storage_error("remove stale", &temp_dir, e))?;
        }
        fs::create_dir_all(&temp_dir).map_err(|e| storage_error("create", &temp_dir, e))?;
        Ok(Self {
            root,
            temp_dir,
            final_dir,
            header,
            chunks: Vec::new(),
            records: Writer::with_capacity(SNAPSHOT_CHUNK_TARGET_BYTES),
            record_count: 0,
            kind: None,
            account_count: 0,
            validator_count: 0,
        })
    }

    pub fn push_account(&mut self, address: Address, account: Account) -> Result<()> {
        let mut record = Writer::with_capacity(60);
        address.encode(&mut record);
        account.encode(&mut record);
        self.push_record(SnapshotChunkKind::Accounts, record.as_slice())?;
        self.account_count = self
            .account_count
            .checked_add(1)
            .ok_or_else(|| Error::Other("snapshot account count overflow".into()))?;
        Ok(())
    }

    pub fn push_validator(&mut self, validator: &Validator) -> Result<()> {
        let record = validator.to_bytes();
        self.push_record(SnapshotChunkKind::Validators, &record)?;
        self.validator_count = self
            .validator_count
            .checked_add(1)
            .ok_or_else(|| Error::Other("snapshot validator count overflow".into()))?;
        Ok(())
    }

    fn push_record(&mut self, kind: SnapshotChunkKind, record: &[u8]) -> Result<()> {
        if self.kind.is_some_and(|current| current != kind)
            || (self.record_count > 0
                && self.records.as_slice().len() + record.len() > SNAPSHOT_CHUNK_TARGET_BYTES)
        {
            self.flush()?;
        }
        self.kind = Some(kind);
        self.records.raw(record);
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or_else(|| Error::Other("snapshot chunk record count overflow".into()))?;
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        if self.record_count == 0 {
            return Ok(());
        }
        if self.chunks.len() >= SNAPSHOT_MAX_CHUNKS {
            return Err(Error::Other("snapshot exceeds maximum chunk count".into()));
        }
        let index = self.chunks.len() as u32;
        let kind = self.kind.expect("records imply a chunk kind");
        let mut plain = Writer::with_capacity(self.records.as_slice().len() + 32);
        plain
            .raw(SNAPSHOT_CHUNK_MAGIC)
            .u32(SNAPSHOT_FORMAT_VERSION)
            .u8(kind.tag())
            .u32(index)
            .u32(self.record_count)
            .raw(self.records.as_slice());
        let plain = plain.finish();
        if plain.len() > SNAPSHOT_MAX_UNCOMPRESSED_CHUNK_BYTES {
            return Err(Error::Other(format!(
                "snapshot chunk {index} exceeds the uncompressed size limit"
            )));
        }
        let compressed = zstd::stream::encode_all(Cursor::new(&plain), SNAPSHOT_COMPRESSION_LEVEL)
            .map_err(|e| Error::Other(format!("compress snapshot chunk {index}: {e}")))?;
        if compressed.len() > SNAPSHOT_MAX_COMPRESSED_CHUNK_BYTES {
            return Err(Error::Other(format!(
                "snapshot chunk {index} exceeds the compressed size limit"
            )));
        }
        let hash = Hash::digest(&[SNAPSHOT_CHUNK_HASH_TAG, &compressed]);
        let path = self.temp_dir.join(chunk_filename(index));
        let mut file = fs::File::create(&path).map_err(|e| storage_error("create", &path, e))?;
        file.write_all(&compressed)
            .map_err(|e| storage_error("write", &path, e))?;
        file.sync_all()
            .map_err(|e| storage_error("sync", &path, e))?;
        self.chunks.push(SnapshotChunkMeta {
            index,
            kind,
            records: self.record_count,
            compressed_bytes: compressed.len() as u32,
            uncompressed_bytes: plain.len() as u32,
            hash,
        });
        self.records = Writer::with_capacity(SNAPSHOT_CHUNK_TARGET_BYTES);
        self.record_count = 0;
        self.kind = None;
        Ok(())
    }

    pub fn finish(mut self) -> Result<SnapshotManifest> {
        self.flush()?;
        let manifest = SnapshotManifest {
            version: SNAPSHOT_FORMAT_VERSION,
            snapshot_id: self.header.checkpoint.hash(),
            chain_id: self.header.chain_id,
            genesis_fingerprint: self.header.genesis_fingerprint,
            checkpoint_tx_interval: self.header.checkpoint_tx_interval,
            checkpoint: self.header.checkpoint,
            account_count: self.account_count,
            validator_count: self.validator_count,
            chunks: self.chunks,
        };
        manifest.validate()?;
        let manifest_path = self.temp_dir.join("manifest.json");
        let bytes = serde_json::to_vec(&manifest)?;
        let mut file = fs::File::create(&manifest_path)
            .map_err(|e| storage_error("create", &manifest_path, e))?;
        file.write_all(&bytes)
            .map_err(|e| storage_error("write", &manifest_path, e))?;
        file.sync_all()
            .map_err(|e| storage_error("sync", &manifest_path, e))?;

        if self.final_dir.exists() {
            fs::remove_dir_all(&self.temp_dir)
                .map_err(|e| storage_error("remove", &self.temp_dir, e))?;
            return SnapshotArchive::load(&self.root, &manifest.snapshot_id);
        }
        fs::rename(&self.temp_dir, &self.final_dir)
            .map_err(|e| storage_error("activate", &self.final_dir, e))?;
        prune_archives(&self.root, manifest.snapshot_id);
        Ok(manifest)
    }
}

pub struct SnapshotArchive;

impl SnapshotArchive {
    pub fn load(root: impl AsRef<Path>, id: &Hash) -> Result<SnapshotManifest> {
        let path = root.as_ref().join(id_dirname(id)).join("manifest.json");
        let bytes = fs::read(&path).map_err(|e| storage_error("read", &path, e))?;
        let manifest: SnapshotManifest = serde_json::from_slice(&bytes)?;
        manifest.validate()?;
        if &manifest.snapshot_id != id {
            return Err(Error::Storage(
                "snapshot cache directory does not match manifest".into(),
            ));
        }
        Ok(manifest)
    }

    pub fn load_if_present(root: impl AsRef<Path>, id: &Hash) -> Result<Option<SnapshotManifest>> {
        let root = root.as_ref();
        let archive = root.join(id_dirname(id));
        let path = archive.join("manifest.json");
        if !path.exists() {
            return Ok(None);
        }
        match Self::load(root, id) {
            Ok(manifest) => Ok(Some(manifest)),
            Err(_) => {
                fs::remove_dir_all(&archive)
                    .map_err(|e| storage_error("remove corrupt", &archive, e))?;
                Ok(None)
            }
        }
    }

    pub fn chunk_path(
        root: impl AsRef<Path>,
        id: &Hash,
        index: u32,
    ) -> Result<(SnapshotChunkMeta, PathBuf)> {
        let root = root.as_ref();
        let manifest = Self::load(root, id)?;
        let meta = manifest
            .chunks
            .get(index as usize)
            .filter(|chunk| chunk.index == index)
            .cloned()
            .ok_or_else(|| Error::Network(format!("snapshot chunk {index} does not exist")))?;
        let path = root.join(id_dirname(id)).join(chunk_filename(index));
        if !path.exists() {
            return Err(Error::Storage(format!(
                "snapshot chunk {} is missing",
                path.display()
            )));
        }
        Ok((meta, path))
    }
}

/// Persistent partial download. Valid chunks survive process restarts.
#[derive(Debug)]
pub struct SnapshotDownload {
    dir: PathBuf,
    manifest: SnapshotManifest,
}

impl SnapshotDownload {
    pub fn open(root: impl AsRef<Path>, manifest: SnapshotManifest) -> Result<Self> {
        manifest.validate()?;
        let root = root.as_ref();
        fs::create_dir_all(root).map_err(|e| storage_error("create", root, e))?;
        let dir = root.join(id_dirname(&manifest.snapshot_id));
        let manifest_path = dir.join("manifest.json");
        if manifest_path.exists() {
            let bytes =
                fs::read(&manifest_path).map_err(|e| storage_error("read", &manifest_path, e))?;
            let matches = serde_json::from_slice::<SnapshotManifest>(&bytes)
                .is_ok_and(|existing| existing == manifest);
            if !matches {
                fs::remove_dir_all(&dir).map_err(|e| storage_error("reset", &dir, e))?;
            }
        }
        fs::create_dir_all(&dir).map_err(|e| storage_error("create", &dir, e))?;
        if !manifest_path.exists() {
            let bytes = serde_json::to_vec(&manifest)?;
            fs::write(&manifest_path, bytes)
                .map_err(|e| storage_error("write", &manifest_path, e))?;
        }
        Ok(Self { dir, manifest })
    }

    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }

    pub fn has_chunk(&self, meta: &SnapshotChunkMeta) -> bool {
        let path = self.dir.join(chunk_filename(meta.index));
        verify_compressed_chunk(&path, meta).unwrap_or(false)
    }

    pub fn store_chunk(&self, meta: &SnapshotChunkMeta, bytes: &[u8]) -> Result<()> {
        verify_compressed_bytes(bytes, meta)?;
        let final_path = self.dir.join(chunk_filename(meta.index));
        let part_path = self
            .dir
            .join(format!("{}.part", chunk_filename(meta.index)));
        let mut file =
            fs::File::create(&part_path).map_err(|e| storage_error("create", &part_path, e))?;
        file.write_all(bytes)
            .map_err(|e| storage_error("write", &part_path, e))?;
        file.sync_all()
            .map_err(|e| storage_error("sync", &part_path, e))?;
        fs::rename(&part_path, &final_path)
            .map_err(|e| storage_error("activate", &final_path, e))?;
        Ok(())
    }

    pub fn decode(&self) -> Result<StateSnapshot> {
        self.manifest.validate()?;
        let mut accounts = Vec::new();
        let mut validators = Vec::new();
        for meta in &self.manifest.chunks {
            let path = self.dir.join(chunk_filename(meta.index));
            let compressed = fs::read(&path).map_err(|e| storage_error("read", &path, e))?;
            verify_compressed_bytes(&compressed, meta)?;
            let plain = decompress_bounded(&compressed, meta)?;
            decode_chunk(&plain, meta, &mut accounts, &mut validators)?;
        }
        if accounts.len() as u64 != self.manifest.account_count
            || validators.len() as u64 != self.manifest.validator_count
        {
            return Err(Error::Network(
                "decoded snapshot counts do not match manifest".into(),
            ));
        }
        Ok(StateSnapshot {
            chain_id: self.manifest.chain_id.clone(),
            genesis_fingerprint: self.manifest.genesis_fingerprint,
            checkpoint_tx_interval: self.manifest.checkpoint_tx_interval,
            checkpoint: self.manifest.checkpoint.clone(),
            accounts,
            validators,
        })
    }

    pub fn remove(self) -> Result<()> {
        Self::remove_for(
            self.dir
                .parent()
                .ok_or_else(|| Error::Storage("snapshot download has no parent".into()))?,
            &self.manifest.snapshot_id,
        )
    }

    pub fn remove_for(root: impl AsRef<Path>, snapshot_id: &Hash) -> Result<()> {
        let dir = root.as_ref().join(id_dirname(snapshot_id));
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|e| storage_error("remove", &dir, e))?;
        }
        Ok(())
    }
}

fn verify_compressed_chunk(path: &Path, meta: &SnapshotChunkMeta) -> Result<bool> {
    let file_meta = match fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(storage_error("inspect", path, error)),
    };
    if file_meta.len() != u64::from(meta.compressed_bytes) {
        return Ok(false);
    }
    let bytes = fs::read(path).map_err(|e| storage_error("read", path, e))?;
    Ok(verify_compressed_bytes(&bytes, meta).is_ok())
}

fn verify_compressed_bytes(bytes: &[u8], meta: &SnapshotChunkMeta) -> Result<()> {
    if bytes.len() != meta.compressed_bytes as usize {
        return Err(Error::Network(format!(
            "snapshot chunk {} size mismatch",
            meta.index
        )));
    }
    if bytes.len() > SNAPSHOT_MAX_COMPRESSED_CHUNK_BYTES {
        return Err(Error::Network(format!(
            "snapshot chunk {} exceeds compressed size limit",
            meta.index
        )));
    }
    let computed = Hash::digest(&[SNAPSHOT_CHUNK_HASH_TAG, bytes]);
    if computed != meta.hash {
        return Err(Error::Network(format!(
            "snapshot chunk {} hash mismatch",
            meta.index
        )));
    }
    Ok(())
}

fn decompress_bounded(bytes: &[u8], meta: &SnapshotChunkMeta) -> Result<Vec<u8>> {
    let decoder = zstd::stream::Decoder::new(Cursor::new(bytes))
        .map_err(|e| Error::Network(format!("open snapshot chunk {}: {e}", meta.index)))?;
    let mut limited = decoder.take(u64::from(meta.uncompressed_bytes) + 1);
    let mut plain = Vec::with_capacity(meta.uncompressed_bytes as usize);
    limited
        .read_to_end(&mut plain)
        .map_err(|e| Error::Network(format!("decompress snapshot chunk {}: {e}", meta.index)))?;
    if plain.len() != meta.uncompressed_bytes as usize {
        return Err(Error::Network(format!(
            "snapshot chunk {} uncompressed size mismatch",
            meta.index
        )));
    }
    Ok(plain)
}

fn decode_chunk(
    plain: &[u8],
    meta: &SnapshotChunkMeta,
    accounts: &mut Vec<(Address, Account)>,
    validators: &mut Vec<Validator>,
) -> Result<()> {
    let mut reader = Reader::new(plain);
    if &reader.array::<8>()? != SNAPSHOT_CHUNK_MAGIC {
        return Err(Error::Network(format!(
            "snapshot chunk {} has invalid magic",
            meta.index
        )));
    }
    let version = reader.u32()?;
    if version != SNAPSHOT_FORMAT_VERSION {
        return Err(Error::Network(format!(
            "snapshot chunk {} has unsupported version {version}",
            meta.index
        )));
    }
    let kind = SnapshotChunkKind::from_tag(reader.u8()?)?;
    let index = reader.u32()?;
    let records = reader.u32()?;
    if kind != meta.kind || index != meta.index || records != meta.records {
        return Err(Error::Network(format!(
            "snapshot chunk {} header does not match manifest",
            meta.index
        )));
    }
    match kind {
        SnapshotChunkKind::Accounts => {
            for _ in 0..records {
                accounts.push((Address::decode(&mut reader)?, Account::decode(&mut reader)?));
            }
        }
        SnapshotChunkKind::Validators => {
            for _ in 0..records {
                validators.push(Validator::decode(&mut reader)?);
            }
        }
    }
    reader.finish()
}

fn prune_archives(root: &Path, current: Hash) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let current = id_dirname(&current);
    let mut archives: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !entry.path().is_dir() || name.contains(".building-") {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((modified, entry.path()))
        })
        .collect();
    archives.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    let mut previous_retained = 0usize;
    for (_, path) in archives {
        let is_current = path
            .file_name()
            .is_some_and(|name| name == current.as_str());
        if is_current {
            continue;
        }
        if previous_retained < SNAPSHOT_ARCHIVES_RETAINED.saturating_sub(1) {
            previous_retained += 1;
            continue;
        }
        let _ = fs::remove_dir_all(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::PublicKey;
    use sikka_common::checkpoint::{Checkpoint, CheckpointHeader};
    use sikka_crypto::PK_LEN;

    fn checkpoint() -> Checkpoint {
        Checkpoint::new(CheckpointHeader {
            height: 7,
            prev_hash: Hash([1; 32]),
            state_root: Hash([2; 32]),
            validator_root: Hash([3; 32]),
            tx_root: Hash([4; 32]),
            tx_count: 1,
            timestamp: 1_700_000_000,
            proposer: Address([5; 32]),
            round: 0,
            total_supply: 100,
            total_bonded: 10,
        })
    }

    fn archive(root: &Path) -> SnapshotManifest {
        let mut writer = SnapshotArchiveWriter::create(
            root,
            SnapshotHeader {
                chain_id: "test".into(),
                genesis_fingerprint: Hash([9; 32]),
                checkpoint_tx_interval: 10,
                checkpoint: checkpoint(),
            },
        )
        .unwrap();
        writer
            .push_account(
                Address([7; 32]),
                Account {
                    balance: 90,
                    nonce: 2,
                    credits: 3,
                    last_regen_time: 4,
                },
            )
            .unwrap();
        writer
            .push_validator(&Validator::new(PublicKey::new([8; PK_LEN]), 10, 1))
            .unwrap();
        writer.finish().unwrap()
    }

    #[test]
    fn archive_roundtrips_through_resumable_download() {
        let served = tempfile::tempdir().unwrap();
        let downloaded = tempfile::tempdir().unwrap();
        let manifest = archive(served.path());
        assert_eq!(manifest.chunks.len(), 2);
        let download = SnapshotDownload::open(downloaded.path(), manifest.clone()).unwrap();
        for meta in &manifest.chunks {
            let (_, path) =
                SnapshotArchive::chunk_path(served.path(), &manifest.snapshot_id, meta.index)
                    .unwrap();
            download
                .store_chunk(meta, &fs::read(path).unwrap())
                .unwrap();
            assert!(download.has_chunk(meta));
        }
        let snapshot = download.decode().unwrap();
        assert_eq!(snapshot.accounts.len(), 1);
        assert_eq!(snapshot.validators.len(), 1);

        let resumed = SnapshotDownload::open(downloaded.path(), manifest).unwrap();
        assert!(resumed
            .manifest()
            .chunks
            .iter()
            .all(|chunk| resumed.has_chunk(chunk)));
    }

    #[test]
    fn corrupted_chunk_is_rejected_and_not_resumed() {
        let served = tempfile::tempdir().unwrap();
        let downloaded = tempfile::tempdir().unwrap();
        let manifest = archive(served.path());
        let download = SnapshotDownload::open(downloaded.path(), manifest.clone()).unwrap();
        let meta = &manifest.chunks[0];
        let (_, path) =
            SnapshotArchive::chunk_path(served.path(), &manifest.snapshot_id, meta.index).unwrap();
        let mut bytes = fs::read(path).unwrap();
        bytes[0] ^= 1;
        assert!(download.store_chunk(meta, &bytes).is_err());
        assert!(!download.has_chunk(meta));
    }

    #[test]
    fn manifest_rejects_non_contiguous_chunks() {
        let root = tempfile::tempdir().unwrap();
        let mut manifest = archive(root.path());
        manifest.chunks[0].index = 2;
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn large_account_sets_are_split_into_independent_chunks() {
        let served = tempfile::tempdir().unwrap();
        let downloaded = tempfile::tempdir().unwrap();
        let mut writer = SnapshotArchiveWriter::create(
            served.path(),
            SnapshotHeader {
                chain_id: "large-test".into(),
                genesis_fingerprint: Hash([9; 32]),
                checkpoint_tx_interval: 10,
                checkpoint: checkpoint(),
            },
        )
        .unwrap();
        for index in 0..70_000u64 {
            let mut address = [0u8; 32];
            address[..8].copy_from_slice(&index.to_be_bytes());
            writer
                .push_account(
                    Address(address),
                    Account {
                        balance: 1,
                        nonce: index,
                        credits: 1,
                        last_regen_time: 1_700_000_000,
                    },
                )
                .unwrap();
        }
        let manifest = writer.finish().unwrap();
        assert_eq!(manifest.account_count, 70_000);
        assert!(
            manifest
                .chunks
                .iter()
                .filter(|chunk| chunk.kind == SnapshotChunkKind::Accounts)
                .count()
                >= 2
        );

        let download = SnapshotDownload::open(downloaded.path(), manifest.clone()).unwrap();
        for meta in &manifest.chunks {
            let (_, path) =
                SnapshotArchive::chunk_path(served.path(), &manifest.snapshot_id, meta.index)
                    .unwrap();
            download
                .store_chunk(meta, &fs::read(path).unwrap())
                .unwrap();
        }
        assert_eq!(download.decode().unwrap().accounts.len(), 70_000);
    }

    #[test]
    fn decompression_cannot_exceed_manifest_limit() {
        let compressed = zstd::stream::encode_all(Cursor::new(vec![7u8; 1024]), 1).unwrap();
        let meta = SnapshotChunkMeta {
            index: 0,
            kind: SnapshotChunkKind::Accounts,
            records: 1,
            compressed_bytes: compressed.len() as u32,
            uncompressed_bytes: 10,
            hash: Hash::digest(&[SNAPSHOT_CHUNK_HASH_TAG, &compressed]),
        };
        assert!(decompress_bounded(&compressed, &meta).is_err());
    }

    #[test]
    #[ignore = "250 MiB Docker stress test"]
    fn snapshot_transport_roundtrips_250_mib() {
        const ACCOUNT_RECORD_BYTES: usize = 32 + 28;
        const RECORDS: u64 = (250 * 1024 * 1024 / ACCOUNT_RECORD_BYTES) as u64 + 1;

        let served = tempfile::tempdir().unwrap();
        let downloaded = tempfile::tempdir().unwrap();
        let mut writer = SnapshotArchiveWriter::create(
            served.path(),
            SnapshotHeader {
                chain_id: "large-test".into(),
                genesis_fingerprint: Hash([9; 32]),
                checkpoint_tx_interval: 10,
                checkpoint: checkpoint(),
            },
        )
        .unwrap();
        let mut random = 0x9e37_79b9_7f4a_7c15u64;
        for index in 0..RECORDS {
            let mut address = [0u8; 32];
            address[..8].copy_from_slice(&index.to_be_bytes());
            for word in address[8..].chunks_exact_mut(8) {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                word.copy_from_slice(&random.to_le_bytes());
            }
            writer
                .push_account(
                    Address(address),
                    Account {
                        balance: index + 1,
                        nonce: index,
                        credits: index as u32,
                        last_regen_time: 1_700_000_000 + index,
                    },
                )
                .unwrap();
        }
        let manifest = writer.finish().unwrap();
        assert!(manifest.chunks.len() >= 63);
        assert!(
            manifest
                .chunks
                .iter()
                .map(|chunk| u64::from(chunk.uncompressed_bytes))
                .sum::<u64>()
                >= 250 * 1024 * 1024
        );

        let download = SnapshotDownload::open(downloaded.path(), manifest.clone()).unwrap();
        for meta in &manifest.chunks {
            let (_, path) =
                SnapshotArchive::chunk_path(served.path(), &manifest.snapshot_id, meta.index)
                    .unwrap();
            download
                .store_chunk(meta, &fs::read(path).unwrap())
                .unwrap();
        }
        assert_eq!(download.decode().unwrap().accounts.len() as u64, RECORDS);
    }
}
