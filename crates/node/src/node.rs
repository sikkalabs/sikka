//! The node: everything that owns state, and the rules for changing it.
//!
//! All mutable state lives behind locks here, and every method in this file is
//! synchronous: a lock is never held across an `await`. Network I/O is the
//! caller's job — a handler or a background loop takes the [`Outbox`] a method
//! returns and sends it. That split keeps the consensus rules easy to test
//! (there is no runtime involved) and makes deadlock structurally impossible.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, MutexGuard};
use tracing::{debug, info, warn};

use sikka_checkpoint::{CheckpointStore, Commitment, CommitmentStore};
use sikka_common::account::Account;
use sikka_common::bytes::{Address, Hash, PublicKey, Signature};
use sikka_common::checkpoint::Checkpoint;
use sikka_common::constants::{quorum_bond, CHILLAR_PER_SIKKA};
use sikka_common::error::{Error, Result};
use sikka_common::genesis::GenesisConfig;
use sikka_common::time::now_secs;
use sikka_common::transaction::Transaction;
use sikka_common::validator::Validator;
use sikka_common::vote::{vote_from_checkpoint, Vote, VoteKind};
use sikka_consensus::equivocation::Equivocation;
use sikka_consensus::proposal::{
    build_proposal, verify_proposal, verify_proposal_with, Authority, CheckpointProposal,
    VerifiedProposal,
};
use sikka_consensus::votes::{VoteOutcome, VoteTracker};
use sikka_consensus::{proposer_for_round, round_at, PROPOSER_TIMEOUT_SECS};
use sikka_p2p::bloom::BloomFilter;
use sikka_p2p::mempool::{Admission, Mempool, DEFAULT_MAX_AGE_SECS};
use sikka_p2p::peers::{Peer, PeerAnnounce, PeerBook};
use sikka_p2p::wire::{Health, ProposalResponse};
use sikka_rpc::types::{
    AccountInfo, AccountProof, ChainInfo, MempoolInfo, TxStatus, ValidatorInfo,
};
use sikka_state::ledger::GenesisOutcome;
use sikka_state::{
    build_snapshot_archive, Ledger, SnapshotArchive, SnapshotChunkMeta, SnapshotManifest,
    StateSnapshot, StateStore,
};
use sikka_wallet::Keystore;

use crate::config::NodeConfig;

/// A finalized checkpoint and the transactions (plus slashing evidence) that
/// produced it.
///
/// The transactions and evidence travel with it so a peer that missed the
/// proposal can replay rather than fast-sync.
#[derive(Debug, Clone)]
pub struct Finalized {
    pub checkpoint: Checkpoint,
    pub transactions: Vec<Transaction>,
    pub evidence: Vec<Equivocation>,
}

/// Messages the caller should push to peers.
#[derive(Debug, Clone, Default)]
pub struct Outbox {
    pub transactions: Vec<Transaction>,
    pub votes: Vec<Vote>,
    pub proposals: Vec<CheckpointProposal>,
    pub finalized: Vec<Finalized>,
}

impl Outbox {
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
            && self.votes.is_empty()
            && self.proposals.is_empty()
            && self.finalized.is_empty()
    }
}

/// A proposal this node has replayed, signed, and is waiting on quorum for.
struct Pending {
    verified: VerifiedProposal,
    /// Kept whole so an abandoned round can be offered again byte for byte.
    proposal: CheckpointProposal,
    hash: Hash,
    height: u64,
    created_at: u64,
}

/// A checkpoint this node voted for and has not finalized.
///
/// The vote is durable and binds this node for as long as the height stays open:
/// it may not sign a rival, so this is the only checkpoint it can still help
/// commit there. Holding on to the proposal is what lets a later round offer it
/// again — without it the vote would outlive every trace of what it was for, and
/// the height could never close. It is stored next to the vote on disk, so a
/// restart mid-round recovers both.
struct Locked {
    proposal: CheckpointProposal,
    /// When it was last replayed and offered, to keep replay off the hot loop.
    /// `None` until it has been offered, so a round that has already waited out
    /// its timeout is retried at once.
    offered_at: Option<u64>,
}

/// Consensus state that must move together.
struct Chain {
    ledger: Ledger,
    checkpoints: CheckpointStore,
    /// At most one: a validator that has signed one checkpoint at a height must
    /// never sign another, or it slashes itself.
    pending: Option<Pending>,
    /// The checkpoint an abandoned round left this node committed to, if any.
    locked: Option<Locked>,
    /// Best (lowest-round) open proposal seen for the height still being decided.
    ///
    /// Later proposers adopt this instead of inventing a rival, which is what
    /// would lock two honest validators onto different hashes when a third is
    /// offline.
    known: Option<CheckpointProposal>,
    /// When the last checkpoint was finalized, for the idle-timer that lets a
    /// quiet chain make progress without a full batch.
    last_progress: u64,
}

pub struct Node {
    config: NodeConfig,
    keypair: sikka_crypto::Keypair,
    address: Address,
    public_key: PublicKey,
    chain: Mutex<Chain>,
    mempool: Mutex<Mempool>,
    votes: Mutex<VoteTracker>,
    /// Our own signed votes for unfinalized heights, each with the checkpoint it
    /// was cast over. Survives restarts so we can neither equivocate against
    /// ourselves after a reboot nor lose track of what we already signed.
    commitments: CommitmentStore,
    peers: Mutex<PeerBook>,
    /// Last time we ran bulk tx-signature verification for a (proposer, height).
    /// One expensive verify per scheduled proposal stops a key-holder from
    /// repeatedly forcing hundreds of MiB of ML-DSA work on the same turn.
    proposal_admit: Mutex<HashMap<(Address, u64), Instant>>,
    /// Cached funded-address list for `/api/address/random`, keyed by ledger height.
    funded_address_cache: Mutex<Option<(u64, Vec<FundedAddress>)>>,
    /// True while a background thread is building a snapshot archive.
    snapshot_building: Arc<AtomicBool>,
    started_at: u64,
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("address", &self.address)
            .field("advertise", &self.config.advertise)
            .finish()
    }
}

impl Node {
    /// Open (or create) everything a node needs to run.
    pub fn open(config: NodeConfig) -> Result<Arc<Self>> {
        std::fs::create_dir_all(&config.data_dir).map_err(|e| {
            Error::Other(format!("cannot create {}: {e}", config.data_dir.display()))
        })?;

        let genesis = load_genesis(&config)?;
        let keypair = load_keypair(&config)?;
        let mut config = config;
        let onion = sikka_onion::OnionIdentity::from_keypair(&keypair)
            .map_err(|e| Error::Other(format!("onion derivation failed: {e}")))?;
        if config.tor_socks.is_some() {
            config.advertise = onion.advertise_url();
            onion
                .write_ctor_dir(config.arti_ctor_path())
                .map_err(|e| Error::Other(format!("cannot write tor HS keys: {e}")))?;
            info!(
                onion = %onion.hostname,
                "advertising Tor v3 onion for peer mesh"
            );
        }
        let address = Address(keypair.address_bytes());
        let public_key = PublicKey::new(*keypair.public_bytes());

        let (ledger, outcome) = Ledger::open(config.state_path(), &genesis)?;
        let checkpoints = CheckpointStore::open(config.checkpoints_path())?;
        let commitments = CommitmentStore::open(config.commitments_path())?;

        match &outcome {
            GenesisOutcome::Initialized(checkpoint) => {
                checkpoints.put(checkpoint)?;
                info!(
                    chain_id = %genesis.chain_id,
                    supply = genesis.total_supply().unwrap_or(0),
                    validators = genesis.validators.len(),
                    "initialised chain from genesis"
                );
            }
            GenesisOutcome::Existing => {
                checkpoints.reconcile(ledger.height())?;
                info!(height = ledger.height(), "opened existing chain");
            }
        }

        // A vote already cast still binds this node at a height that is still
        // open, and the checkpoint it was cast over is the only one it may help
        // commit there. Both come back, so a restart mid-round can offer that
        // checkpoint again instead of stranding the height.
        let mut votes = VoteTracker::new(
            ledger.meta().chain_id.clone(),
            ledger.meta().genesis_fingerprint,
        );
        let mut locked = None;
        let mut known = None;
        for commitment in commitments.load_above(ledger.height())? {
            if commitment.height() == ledger.height() + 1 {
                known = Some(commitment.proposal.clone());
                // Only a precommit permanently locks the height. A restored
                // prevote is remembered as `known` so we can reoffer that round,
                // but a later round may still adopt a different proposal.
                if commitment.vote.kind == VoteKind::Precommit {
                    locked = Some(Locked {
                        proposal: commitment.proposal,
                        offered_at: None,
                    });
                }
            }
            votes.record(commitment.vote)?;
        }
        if votes.tracked_heights() > 0 {
            info!(
                heights = votes.tracked_heights(),
                can_reoffer = locked.is_some(),
                "restored our own votes from disk"
            );
        }

        let mut peers = PeerBook::new(address);
        let now = now_secs();
        for endpoint in &config.bootstrap {
            if endpoint != &config.advertise {
                peers.add_endpoint(endpoint, now);
            }
        }

        let mempool = Mempool::new(config.mempool_capacity, DEFAULT_MAX_AGE_SECS);
        let node = Arc::new(Self {
            keypair,
            address,
            public_key,
            chain: Mutex::new(Chain {
                ledger,
                checkpoints,
                pending: None,
                locked,
                known,
                last_progress: now,
            }),
            mempool: Mutex::new(mempool),
            votes: Mutex::new(votes),
            commitments,
            peers: Mutex::new(peers),
            proposal_admit: Mutex::new(HashMap::new()),
            funded_address_cache: Mutex::new(None),
            snapshot_building: Arc::new(AtomicBool::new(false)),
            started_at: now,
            config,
        });
        {
            let chain = node.chain.lock();
            let height = chain.ledger.height();
            if let Ok(Some(checkpoint)) = chain.checkpoints.get(height) {
                let store = chain.ledger.store_handle();
                let checkpoint = checkpoint.clone();
                drop(chain);
                node.schedule_snapshot_archive(checkpoint, store);
            }
        }
        Ok(node)
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn keypair(&self) -> &sikka_crypto::Keypair {
        &self.keypair
    }

    /// This node's public key, as it appears in votes and validator records.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn uptime(&self) -> u64 {
        now_secs().saturating_sub(self.started_at)
    }

    fn chain(&self) -> MutexGuard<'_, Chain> {
        self.chain.lock()
    }

    /// Whether this node's key belongs to a validator that can vote right now.
    pub fn is_active_validator(&self) -> bool {
        if !self.config.validator {
            return false;
        }
        let chain = self.chain();
        chain
            .ledger
            .validator(&self.address)
            .ok()
            .flatten()
            .is_some_and(|v| v.is_active_at(chain.ledger.height() + 1))
    }

    // ---- read paths ------------------------------------------------------

    pub fn health(&self) -> Health {
        let chain = self.chain();
        Health {
            chain_id: chain.ledger.meta().chain_id.clone(),
            height: chain.ledger.height(),
            state_root: chain.ledger.state_root(),
            mempool: self.mempool.lock().len(),
            peers: self.peers.lock().len(),
            validator: chain
                .ledger
                .validator(&self.address)
                .ok()
                .flatten()
                .is_some_and(|v| !v.slashed),
        }
    }

    pub fn chain_info(&self) -> Result<ChainInfo> {
        let chain = self.chain();
        let meta = chain.ledger.meta();
        Ok(ChainInfo {
            chain_id: meta.chain_id.clone(),
            genesis_fingerprint: meta.genesis_fingerprint,
            height: meta.height,
            state_root: meta.state_root,
            validator_root: meta.validator_root,
            last_checkpoint_hash: meta.last_checkpoint_hash,
            last_checkpoint_time: meta.last_checkpoint_time,
            total_supply: meta.total_supply,
            total_bonded: meta.total_bonded,
            accounts: chain.ledger.account_count()?,
            active_validators: chain.ledger.active_validators()?.len(),
            checkpoint_tx_interval: meta.checkpoint_tx_interval,
            mempool: self.mempool.lock().len(),
            peers: self.peers.lock().len(),
            node_address: self.address,
            validator: chain.ledger.validator(&self.address)?.is_some(),
        })
    }

    pub fn account(&self, address: &Address) -> Result<AccountInfo> {
        let now = now_secs();
        let chain = self.chain();
        let account = chain.ledger.account_opt(address)?;
        let committed = account.map(|a| a.nonce).unwrap_or(0);
        let next_nonce = self.mempool.lock().next_nonce(address, committed);
        let bond = chain.ledger.validator(address)?.map(|v| v.bond);
        Ok(AccountInfo::from_account(
            *address, account, now, next_nonce, bond,
        ))
    }

    /// An account plus the Merkle path and signed checkpoint that prove it.
    pub fn account_proof(&self, address: &Address) -> Result<AccountProof> {
        let chain = self.chain();
        let (account, proof) = chain.ledger.account_proof(address)?;
        let height = chain.ledger.height();
        let checkpoint = chain
            .checkpoints
            .get(height)?
            .ok_or(Error::CheckpointNotFound(height))?;
        Ok(AccountProof {
            address: *address,
            account,
            proof,
            state_root: chain.ledger.state_root(),
            checkpoint,
        })
    }

    pub fn validators(&self) -> Result<Vec<ValidatorInfo>> {
        let chain = self.chain();
        let height = chain.ledger.height() + 1;
        Ok(chain
            .ledger
            .validators()?
            .into_iter()
            .map(|v| ValidatorInfo {
                address: v.address,
                public_key: v.public_key.clone(),
                bond: v.bond,
                active_from: v.active_from,
                active: v.is_active_at(height),
                unbonding_since: v.unbonding_since,
                slashed: v.slashed,
                missed_proposer_slots: v.missed_proposer_slots,
            })
            .collect())
    }

    pub fn checkpoint(&self, height: u64) -> Result<Checkpoint> {
        let chain = self.chain();
        chain
            .checkpoints
            .get(height)?
            .ok_or(Error::CheckpointNotFound(height))
    }

    pub fn latest_checkpoint(&self) -> Result<Checkpoint> {
        let chain = self.chain();
        let height = chain.ledger.height();
        chain
            .checkpoints
            .get(height)?
            .ok_or(Error::CheckpointNotFound(height))
    }

    pub fn snapshot(&self) -> Result<StateSnapshot> {
        let chain = self.chain();
        let height = chain.ledger.height();
        let checkpoint = chain
            .checkpoints
            .get(height)?
            .ok_or(Error::CheckpointNotFound(height))?;
        chain.ledger.snapshot(checkpoint)
    }

    /// Build or load the current chunked snapshot manifest.
    pub fn snapshot_manifest(&self) -> Result<SnapshotManifest> {
        let checkpoint = {
            let chain = self.chain();
            let height = chain.ledger.height();
            chain
                .checkpoints
                .get(height)?
                .ok_or(Error::CheckpointNotFound(height))?
        };
        let snapshot_id = checkpoint.hash();
        if let Some(manifest) =
            SnapshotArchive::load_if_present(self.config.snapshot_cache_path(), &snapshot_id)?
        {
            return Ok(manifest);
        }
        let store = {
            let chain = self.chain();
            chain.ledger.store_handle()
        };
        self.schedule_snapshot_archive(checkpoint, store);
        Err(Error::Other("snapshot archive not ready".into()))
    }

    fn schedule_snapshot_archive(&self, checkpoint: Checkpoint, store: Arc<StateStore>) {
        if self
            .snapshot_building
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let cache_path = self.config.snapshot_cache_path();
        let building = Arc::clone(&self.snapshot_building);
        std::thread::spawn(move || {
            let result = build_snapshot_archive(&store, checkpoint, &cache_path);
            building.store(false, Ordering::Release);
            if let Err(error) = result {
                warn!(%error, "background snapshot archive build failed");
            }
        });
    }

    /// Resolve a cached chunk after validating its snapshot id and index.
    pub fn snapshot_chunk(
        &self,
        snapshot_id: &Hash,
        index: u32,
    ) -> Result<(SnapshotChunkMeta, PathBuf)> {
        SnapshotArchive::chunk_path(self.config.snapshot_cache_path(), snapshot_id, index)
    }

    pub fn height(&self) -> u64 {
        self.chain().ledger.height()
    }

    pub fn mempool_info(&self) -> MempoolInfo {
        let interval = u64::from(self.chain().ledger.checkpoint_tx_interval());
        let mempool = self.mempool.lock();
        MempoolInfo {
            pending: mempool.len(),
            capacity: mempool.capacity(),
            until_checkpoint: interval.saturating_sub(mempool.len() as u64),
        }
    }

    pub fn transaction_status(&self, id: &Hash) -> TxStatus {
        let mempool = self.mempool.lock();
        match mempool.get(id) {
            Some(tx) => TxStatus {
                id: *id,
                pending: true,
                transaction: Some(tx.clone()),
            },
            None => TxStatus {
                id: *id,
                pending: false,
                transaction: None,
            },
        }
    }

    pub fn peers(&self) -> Vec<Peer> {
        self.peers.lock().all()
    }

    pub fn peer_endpoints(&self) -> Vec<String> {
        self.peers.lock().endpoints_due(now_secs())
    }

    // ---- transactions ----------------------------------------------------

    /// Admit a transaction. The bool is false when it was already known, which
    /// is how gossip terminates instead of echoing forever.
    pub fn submit_transaction(&self, transaction: Transaction) -> Result<(Hash, bool)> {
        let id = transaction.id();
        let now = now_secs();
        // Chain first, then mempool: every path that holds both takes them in
        // this order, which is what keeps the pair deadlock-free.
        let chain = self.chain();
        let mut mempool = self.mempool.lock();
        if mempool.contains(&id) {
            return Ok((id, false));
        }
        let committed = chain.ledger.next_nonce(&transaction.from)?;

        // Can the sender afford this on top of what it already has queued? A
        // transaction it cannot pay for would be dropped by the checkpoint
        // anyway, so admitting one only lets a coinless address fill every
        // mempool on the network for free. Anything at or above this nonce is
        // replaced rather than queued behind, so it is not counted.
        let mut run = mempool.pending_run(&transaction.from, committed);
        run.retain(|t| t.nonce < transaction.nonce);
        run.push(transaction.clone());
        chain.ledger.would_apply(&run, now)?;
        transaction.check_chain_id(&chain.ledger.meta().chain_id)?;
        transaction.check_genesis_fingerprint(&chain.ledger.meta().genesis_fingerprint)?;

        let admission = mempool.insert(transaction, committed, now)?;
        Ok((id, admission == Admission::Accepted))
    }

    /// Take in transactions learned from a peer, returning how many were new.
    pub fn absorb_transactions(&self, transactions: Vec<Transaction>) -> usize {
        let mut accepted = 0;
        for transaction in transactions {
            match self.submit_transaction(transaction) {
                Ok((_, true)) => accepted += 1,
                Ok((_, false)) => {}
                Err(e) => debug!(error = %e, "peer offered a transaction we will not take"),
            }
        }
        accepted
    }

    /// Answer a peer's sync request: what it lacks, plus our own filter.
    pub fn sync_transactions(
        &self,
        filter: &BloomFilter,
        limit: usize,
    ) -> (Vec<Transaction>, BloomFilter) {
        let mempool = self.mempool.lock();
        (mempool.missing_from(filter, limit), mempool.bloom())
    }

    pub fn mempool_bloom(&self) -> BloomFilter {
        self.mempool.lock().bloom()
    }

    // ---- consensus -------------------------------------------------------

    /// Propose the next checkpoint, if it is our turn and there is work.
    ///
    /// Returns the proposal to broadcast together with our own vote for it.
    ///
    /// Later rounds adopt a known open proposal (or wait once any vote for the
    /// height exists) rather than inventing a rival. Two honest validators each
    /// inventing a different hash at the same height is a permanent deadlock
    /// under one-vote-per-height, which is exactly what happens when a third
    /// validator is offline and rounds advance.
    pub fn try_propose(&self) -> Result<Option<(CheckpointProposal, Vote)>> {
        if !self.config.validator {
            return Ok(None);
        }
        let now = now_secs();
        let mut chain = self.chain();

        if chain.pending.is_some() {
            return Ok(None);
        }

        let height = chain.ledger.height() + 1;
        let last_time = chain.ledger.meta().last_checkpoint_time;
        let timestamp = now.max(last_time + 1);
        let round = round_at(timestamp, last_time);

        // A precommit locks us for the height: only that checkpoint may be
        // offered again. A lone prevote does not lock — later rounds may adopt
        // a different proposal (Tendermint-style), which is what heals partitions.
        if let Some(lock) = self.votes.lock().precommit_lock(height, &self.address).cloned() {
            return Ok(self.reoffer_locked(chain, lock, now));
        }

        // Already prevoted this clock-round: restage that body (never invent a
        // rival at the same step). A later clock-round falls through and may
        // adopt a different known proposal.
        if let Some(prevote) = self
            .votes
            .lock()
            .vote_by(height, round, VoteKind::Prevote, &self.address)
            .cloned()
        {
            let body = chain
                .locked
                .as_ref()
                .map(|l| &l.proposal)
                .or(chain.known.as_ref())
                .filter(|p| p.hash() == prevote.checkpoint_hash)
                .cloned();
            if let Some(proposal) = body {
                if chain.locked.is_none() {
                    chain.locked = Some(Locked {
                        proposal: proposal.clone(),
                        offered_at: None,
                    });
                }
                return Ok(self.reoffer_locked(chain, prevote, now));
            }
            // Voted for a hash we no longer hold — wait for a peer reoffer.
            return Ok(None);
        }

        // Prefer an earlier proposal we already hold over inventing a new one —
        // but only if we are not precommit-locked elsewhere (checked above).
        if let Some(proposal) = chain.known.clone() {
            if proposal.height() == height {
                return self.adopt_proposal(chain, proposal, now);
            }
            chain.known = None;
        }

        let active = chain.ledger.active_validators_at(height)?;
        let Some(proposer) = proposer_for_round(height, round, &active) else {
            return Ok(None);
        };
        if proposer != self.address {
            return Ok(None);
        }

        let interval = chain.ledger.checkpoint_tx_interval() as usize;
        let evidence = self.collect_evidence(&chain);
        {
            let mut mempool = self.mempool.lock();
            mempool.purge_nonce_gaps(&|address| chain.ledger.next_nonce(address));
        }
        let pool_len = self.mempool.lock().len();
        let idle_deadline = self.config.max_checkpoint_delay.as_secs();
        let waited = now.saturating_sub(chain.last_progress);
        let due = pool_len >= interval
            || !evidence.is_empty()
            || (pool_len > 0 && idle_deadline > 0 && waited >= idle_deadline);
        if !due {
            return Ok(None);
        }

        let candidates = self.mempool.lock().batch(interval);
        if candidates.is_empty() && evidence.is_empty() {
            return Ok(None);
        }

        let (mut proposal, verified, drop_from_mempool) = build_proposal(
            &mut chain.ledger,
            candidates,
            evidence,
            timestamp,
            self.address,
            round,
        )?;
        let hash = verified.hash();
        let VerifiedProposal {
            checkpoint,
            staged,
        } = verified;
        let chain_id = chain.ledger.meta().chain_id.clone();
        let genesis_fingerprint = chain.ledger.meta().genesis_fingerprint;
        let guard = sikka_state::StageGuard::arm(&mut chain.ledger, staged);
        proposal.sign(&self.keypair)?;
        if !drop_from_mempool.is_empty() {
            self.mempool.lock().remove_all(&drop_from_mempool);
        }

        let vote = Vote::sign(
            &self.keypair,
            &chain_id,
            genesis_fingerprint,
            height,
            round,
            VoteKind::Prevote,
            hash,
        )?;
        // Disk before broadcast: a crash after signing must not let us sign again,
        // and must not lose the checkpoint the signature commits us to.
        self.commitments.put(&Commitment {
            vote: vote.clone(),
            proposal: proposal.clone(),
        })?;
        let staged = guard.disarm();
        remember_proposal(&mut chain.known, &proposal);
        chain.pending = Some(Pending {
            proposal: proposal.clone(),
            verified: VerifiedProposal { checkpoint, staged },
            hash,
            height,
            created_at: now,
        });
        drop(chain);

        self.votes.lock().record(vote.clone())?;
        info!(
            height,
            round,
            transactions = proposal.transactions.len(),
            evidence = proposal.evidence.len(),
            hash = %hash.short(),
            "proposing checkpoint"
        );
        Ok(Some((proposal, vote)))
    }

    /// Vote for an open proposal we already hold, instead of inventing a rival.
    fn adopt_proposal(
        &self,
        mut chain: MutexGuard<'_, Chain>,
        proposal: CheckpointProposal,
        now: u64,
    ) -> Result<Option<(CheckpointProposal, Vote)>> {
        let height = proposal.height();
        let round = proposal.header.round;
        if height != chain.ledger.height() + 1 {
            return Ok(None);
        }
        if let Some(lock) = self.votes.lock().precommit_lock(height, &self.address) {
            if lock.checkpoint_hash != proposal.hash() {
                return Ok(None);
            }
        }
        if self
            .votes
            .lock()
            .vote_by(height, round, VoteKind::Prevote, &self.address)
            .is_some()
        {
            return Ok(None);
        }
        // A prior round's pending prevote may be abandoned for a later-round
        // proposal — that is the partition heal. A precommit lock above already
        // refused rivals.
        if let Some(stale) = chain.pending.take() {
            if stale.proposal.header.round >= round {
                chain.pending = Some(stale);
                return Ok(None);
            }
            chain.ledger.rollback(stale.verified.staged);
        }

        let verified_ids: HashSet<Hash> = self.mempool.lock().verified_ids();
        let verified = match verify_proposal(&mut chain.ledger, &proposal, now, &verified_ids) {
            Ok(verified) => verified,
            Err(error) => {
                debug!(%error, height, "could not adopt the known open proposal");
                if chain.known.as_ref().is_some_and(|known| known.hash() == proposal.hash()) {
                    chain.known = None;
                }
                return Ok(None);
            }
        };

        let hash = verified.hash();
        let VerifiedProposal {
            checkpoint,
            staged,
        } = verified;
        let chain_id = chain.ledger.meta().chain_id.clone();
        let genesis_fingerprint = chain.ledger.meta().genesis_fingerprint;
        let guard = sikka_state::StageGuard::arm(&mut chain.ledger, staged);
        let vote = Vote::sign(
            &self.keypair,
            &chain_id,
            genesis_fingerprint,
            height,
            round,
            VoteKind::Prevote,
            hash,
        )?;
        self.commitments.put(&Commitment {
            vote: vote.clone(),
            proposal: proposal.clone(),
        })?;
        let staged = guard.disarm();
        remember_proposal(&mut chain.known, &proposal);
        chain.pending = Some(Pending {
            proposal: proposal.clone(),
            verified: VerifiedProposal { checkpoint, staged },
            hash,
            height,
            created_at: now,
        });
        drop(chain);

        self.votes.lock().record(vote.clone())?;
        info!(
            height,
            round,
            hash = %hash.short(),
            "adopting an open proposal instead of inventing a rival"
        );
        Ok(Some((proposal, vote)))
    }

    /// The proposal this node is currently trying to finalize, if any.
    ///
    /// Peers poll this before inventing a later-round checkpoint so they can
    /// adopt the same hash rather than locking onto a rival.
    pub fn open_proposal(&self) -> Option<CheckpointProposal> {
        let chain = self.chain();
        if let Some(pending) = &chain.pending {
            return Some(pending.proposal.clone());
        }
        if let Some(locked) = &chain.locked {
            return Some(locked.proposal.clone());
        }
        chain.known.clone()
    }

    /// Remember an open proposal from a peer without voting yet.
    ///
    /// The next [`Self::try_propose`] will adopt it (or [`Self::handle_proposal`]
    /// will vote immediately when called). Storing it first is what stops a
    /// later-round proposer inventing a rival while the body is in flight.
    pub fn note_open_proposal(&self, proposal: &CheckpointProposal) {
        let mut chain = self.chain();
        if proposal.height() == chain.ledger.height() + 1 {
            remember_proposal(&mut chain.known, proposal);
        }
    }

    /// Whether this node has already precommit-locked the height still open.
    pub fn has_voted_for_open_height(&self) -> bool {
        let height = self.height() + 1;
        self.votes
            .lock()
            .precommit_lock(height, &self.address)
            .is_some()
    }

    /// Offer the checkpoint an abandoned round left us committed to.
    ///
    /// Whose turn it was and whether the clock agreed were settled when this
    /// proposal was first signed, so neither is re-checked here: a header that
    /// has aged past the tolerance window is still the only checkpoint this node
    /// may help finalize, and refusing to replay it would strand the height for
    /// good. Only the state transition is re-derived, and it still has to
    /// reproduce the roots the header claims.
    ///
    /// A peer that already voted answers an identical proposal with the vote it
    /// cast, which is what completes a quorum whose first answer was lost or
    /// arrived after this node stopped waiting.
    fn reoffer_locked(
        &self,
        mut chain: MutexGuard<'_, Chain>,
        vote: Vote,
        now: u64,
    ) -> Option<(CheckpointProposal, Vote)> {
        let locked = chain.locked.as_mut()?;
        if locked
            .offered_at
            .is_some_and(|at| now.saturating_sub(at) < PROPOSER_TIMEOUT_SECS)
        {
            return None;
        }
        let proposal = locked.proposal.clone();
        if proposal.hash() != vote.checkpoint_hash {
            return None;
        }
        locked.offered_at = Some(now);

        let height = proposal.height();
        let verified_ids: HashSet<Hash> = self.mempool.lock().verified_ids();
        let verified = match verify_proposal_with(
            &mut chain.ledger,
            &proposal,
            now,
            &verified_ids,
            Authority::Finalized,
        ) {
            Ok(verified) => verified,
            Err(error) => {
                // Offer it anyway: a peer holding the matching staging can still
                // finalize it, and its signed form will come back to us.
                debug!(%error, height, "could not restage the checkpoint we voted for");
                return Some((proposal, vote));
            }
        };

        let hash = verified.hash();
        chain.pending = Some(Pending {
            proposal: proposal.clone(),
            verified,
            hash,
            height,
            created_at: now,
        });
        drop(chain);

        info!(
            height,
            hash = %hash.short(),
            "offering the checkpoint we voted for again"
        );
        Some((proposal, vote))
    }

    /// Evidence worth acting on: equivocation by validators still bonded.
    fn collect_evidence(&self, chain: &Chain) -> Vec<Equivocation> {
        let mut votes = self.votes.lock();
        if votes.equivocations().is_empty() {
            return Vec::new();
        }
        let drained = votes.drain_equivocations();
        drop(votes);
        drained
            .into_iter()
            .filter(
                |e| matches!(chain.ledger.validator(&e.validator), Ok(Some(v)) if v.is_slashable()),
            )
            .take(sikka_common::constants::MAX_EVIDENCE_PER_CHECKPOINT)
            .collect()
    }

    /// Replay a peer's proposal and prevote for it if we agree.
    pub fn handle_proposal(&self, proposal: &CheckpointProposal) -> Result<ProposalResponse> {
        if !self.config.validator {
            return Ok(refused("this node does not vote"));
        }
        let now = now_secs();
        let height = proposal.height();
        let round = proposal.header.round;
        let mut chain = self.chain();

        if height <= chain.ledger.height() {
            return Ok(refused(format!(
                "already at height {}",
                chain.ledger.height()
            )));
        }

        let hash = proposal.hash();
        // A precommit locks the height to one hash.
        if let Some(lock) = self.votes.lock().precommit_lock(height, &self.address) {
            if lock.checkpoint_hash == hash {
                remember_proposal(&mut chain.known, proposal);
                return Ok(ProposalResponse {
                    accepted: true,
                    vote: Some(lock.clone()),
                    reason: None,
                });
            }
            return Ok(refused(format!(
                "precommit-locked to {} at height {height}",
                lock.checkpoint_hash.short()
            )));
        }
        // Idempotent prevote for this round.
        if let Some(previous) = self
            .votes
            .lock()
            .vote_by(height, round, VoteKind::Prevote, &self.address)
            .cloned()
        {
            if previous.checkpoint_hash == hash {
                remember_proposal(&mut chain.known, proposal);
                // After a restart (or an expired round) we may still hold the
                // prevote without a staged body. Restage so we can precommit
                // once prevote quorum is visible again.
                if chain.pending.as_ref().is_none_or(|p| p.hash != hash) {
                    if let Some(stale) = chain.pending.take() {
                        chain.ledger.rollback(stale.verified.staged);
                    }
                    let verified_ids: HashSet<Hash> = self.mempool.lock().verified_ids();
                    match verify_proposal(&mut chain.ledger, proposal, now, &verified_ids) {
                        Ok(verified) => {
                            chain.pending = Some(Pending {
                                verified,
                                proposal: proposal.clone(),
                                hash,
                                height,
                                created_at: now,
                            });
                        }
                        Err(error) => {
                            debug!(%error, height, "could not restage a previously prevoted checkpoint");
                        }
                    }
                }
                return Ok(ProposalResponse {
                    accepted: true,
                    vote: Some(previous),
                    reason: None,
                });
            }
            return Ok(refused(format!(
                "already prevoted for {} at height {height} round {round}",
                previous.checkpoint_hash.short()
            )));
        }

        // Abandon an earlier-round pending prevote for a later-round proposal.
        if let Some(stale) = chain.pending.take() {
            if stale.hash == hash {
                chain.pending = Some(stale);
            } else if stale.proposal.header.round < round {
                chain.ledger.rollback(stale.verified.staged);
            } else {
                chain.pending = Some(stale);
                return Ok(refused("a checkpoint is already staged at this height"));
            }
        }

        // Proposer signature before any per-tx ML-DSA work, then admit at most
        // one expensive verify per proposer per timeout window.
        let active = chain.ledger.active_validators_at(height)?;
        let expected = proposer_for_round(height, round, &active).ok_or(Error::NoActiveValidators)?;
        if proposal.header.proposer != expected {
            return Err(Error::WrongProposer {
                expected,
                actual: proposal.header.proposer,
            });
        }
        let proposer_key = active
            .iter()
            .find(|v| v.address == expected)
            .map(|v| &v.public_key)
            .ok_or(Error::NoActiveValidators)?;
        proposal.verify_proposer_signature(proposer_key)?;
        if !self.admit_proposal_verify(expected, height) {
            return Ok(refused("proposal rate limited"));
        }

        let verified_ids: HashSet<Hash> = self.mempool.lock().verified_ids();
        let verified = if chain.pending.as_ref().is_some_and(|p| p.hash == hash) {
            // Already staged this body (e.g. we proposed it).
            let vote = Vote::sign(
                &self.keypair,
                &chain.ledger.meta().chain_id,
                chain.ledger.meta().genesis_fingerprint,
                height,
                round,
                VoteKind::Prevote,
                hash,
            )?;
            self.commitments.put(&Commitment {
                vote: vote.clone(),
                proposal: proposal.clone(),
            })?;
            remember_proposal(&mut chain.known, proposal);
            drop(chain);
            self.votes.lock().record(vote.clone())?;
            debug!(height, hash = %hash.short(), "prevoted for our own staged checkpoint");
            return Ok(ProposalResponse {
                accepted: true,
                vote: Some(vote),
                reason: None,
            });
        } else {
            verify_proposal(&mut chain.ledger, proposal, now, &verified_ids)?
        };
        let VerifiedProposal {
            checkpoint,
            staged,
        } = verified;
        let chain_id = chain.ledger.meta().chain_id.clone();
        let genesis_fingerprint = chain.ledger.meta().genesis_fingerprint;
        let guard = sikka_state::StageGuard::arm(&mut chain.ledger, staged);
        let vote = Vote::sign(
            &self.keypair,
            &chain_id,
            genesis_fingerprint,
            height,
            round,
            VoteKind::Prevote,
            hash,
        )?;
        self.commitments.put(&Commitment {
            vote: vote.clone(),
            proposal: proposal.clone(),
        })?;
        let staged = guard.disarm();

        remember_proposal(&mut chain.known, proposal);
        chain.pending = Some(Pending {
            verified: VerifiedProposal { checkpoint, staged },
            proposal: proposal.clone(),
            hash,
            height,
            created_at: now,
        });
        drop(chain);

        self.votes.lock().record(vote.clone())?;
        debug!(height, round, hash = %hash.short(), "prevoted for a peer's checkpoint");
        Ok(ProposalResponse {
            accepted: true,
            vote: Some(vote),
            reason: None,
        })
    }

    /// Admit one bulk proposal verification per (proposer, height) per timeout.
    fn admit_proposal_verify(&self, proposer: Address, height: u64) -> bool {
        let mut gate = self.proposal_admit.lock();
        let now = Instant::now();
        let window = Duration::from_secs(PROPOSER_TIMEOUT_SECS);
        gate.retain(|_, at| now.duration_since(*at) < window);
        let key = (proposer, height);
        match gate.get(&key) {
            Some(at) if now.duration_since(*at) < window => false,
            _ => {
                gate.insert(key, now);
                true
            }
        }
    }

    /// Record a vote. When prevotes reach quorum for our pending checkpoint we
    /// cast a precommit; when precommits reach quorum we finalize.
    ///
    /// Returns `(follow_up_vote, finalized)` so callers can gossip a precommit
    /// we just produced in reaction to inbound prevotes.
    pub fn handle_vote(&self, vote: Vote) -> Result<(Option<Vote>, Option<Finalized>)> {
        {
            let chain = self.chain();
            vote.verify(
                &chain.ledger.meta().chain_id,
                &chain.ledger.meta().genesis_fingerprint,
            )?;
            let height = chain.ledger.height();
            if vote.height <= height {
                return Ok((None, None));
            }
            if vote.height > height.saturating_add(sikka_common::constants::MAX_VOTE_HEIGHT_AHEAD)
            {
                return Err(Error::Other(format!(
                    "vote height {} is more than {} ahead of local tip {height}",
                    vote.height,
                    sikka_common::constants::MAX_VOTE_HEIGHT_AHEAD
                )));
            }
            // A vote also needs to be for a round that is plausibly due. Rounds
            // advance one per PROPOSER_TIMEOUT_SECS from the last checkpoint's
            // agreed timestamp, so without this a bonded key could plant votes
            // across ~2³² artificial rounds and grow both this tracker and this
            // node's ML-DSA verification work without bound.
            let due_round = round_at(now_secs(), chain.ledger.meta().last_checkpoint_time);
            if vote.round
                > due_round.saturating_add(sikka_common::constants::MAX_VOTE_ROUND_AHEAD)
            {
                return Err(Error::Other(format!(
                    "vote round {} is more than {} ahead of the round now due ({due_round})",
                    vote.round,
                    sikka_common::constants::MAX_VOTE_ROUND_AHEAD
                )));
            }
            let active = chain.ledger.active_validators_at(vote.height)?;
            if !active.iter().any(|v| v.address == vote.validator) {
                return Err(Error::UnknownVoter(vote.validator));
            }
            if !active
                .iter()
                .any(|v| v.address == vote.validator && v.public_key == vote.public_key)
            {
                return Err(Error::AddressKeyMismatch);
            }
        }

        let outcome = self.votes.lock().record(vote)?;
        if let VoteOutcome::Equivocated(evidence) = &outcome {
            warn!(
                validator = %evidence.validator,
                height = evidence.height,
                "equivocation detected; will be slashed in the next checkpoint we propose"
            );
        }
        let follow_up = self.maybe_precommit()?;
        let finalized = self.finalize_if_quorum()?;
        Ok((follow_up, finalized))
    }

    /// If our pending checkpoint has a prevote quorum and we have not
    /// precommitted yet, cast the precommit (the height lock).
    pub fn maybe_precommit(&self) -> Result<Option<Vote>> {
        if !self.config.validator {
            return Ok(None);
        }
        let chain = self.chain();
        let Some(pending) = &chain.pending else {
            return Ok(None);
        };
        let height = pending.height;
        let round = pending.proposal.header.round;
        let hash = pending.hash;
        let proposal = pending.proposal.clone();
        if self
            .votes
            .lock()
            .vote_by(height, round, VoteKind::Precommit, &self.address)
            .is_some()
        {
            return Ok(None);
        }
        let active = chain.ledger.active_validators_at(height)?;
        let authorized: Vec<(Address, u64)> =
            active.iter().map(|v| (v.address, v.bond)).collect();
        if !self.votes.lock().has_quorum(
            height,
            round,
            VoteKind::Prevote,
            &hash,
            &authorized,
        ) {
            return Ok(None);
        }
        let chain_id = chain.ledger.meta().chain_id.clone();
        let genesis_fingerprint = chain.ledger.meta().genesis_fingerprint;
        drop(chain);

        let vote = Vote::sign(
            &self.keypair,
            &chain_id,
            genesis_fingerprint,
            height,
            round,
            VoteKind::Precommit,
            hash,
        )?;
        self.commitments.put(&Commitment {
            vote: vote.clone(),
            proposal: proposal.clone(),
        })?;
        {
            let mut chain = self.chain();
            chain.locked = Some(Locked {
                proposal,
                offered_at: None,
            });
        }
        self.votes.lock().record(vote.clone())?;
        info!(height, round, hash = %hash.short(), "precommitting checkpoint");
        Ok(Some(vote))
    }

    /// Commit the pending checkpoint once ≥2/3 of the active bonded stake has
    /// precommitted it.
    ///
    /// Only the proposal's proposer assembles and commits the finalized
    /// artifact immediately. Everyone else applies that artifact via
    /// [`Self::handle_finalized`]. Rewards at the next height are paid to the
    /// whole active set (bond-weighted), so divergent signature subsets cannot
    /// fork state even if two certificates briefly coexist.
    ///
    /// If the proposer never seals (it died after votes arrived), any voter may
    /// finalize once a proposer timeout has passed, using the lexicographically
    /// first quorum of bonded stake so two late finalizers still agree when they
    /// share the same vote view.
    pub fn finalize_if_quorum(&self) -> Result<Option<Finalized>> {
        let now = now_secs();
        let mut chain = self.chain();
        let Some(pending) = &chain.pending else {
            return Ok(None);
        };
        let (height, hash) = (pending.height, pending.hash);
        let round = pending.proposal.header.round;
        let proposer = pending.proposal.header.proposer;
        let created_at = pending.created_at;
        let is_proposer = proposer == self.address;
        let proposer_missed = now.saturating_sub(created_at) >= PROPOSER_TIMEOUT_SECS;
        if !is_proposer && !proposer_missed {
            return Ok(None);
        }

        let active = chain.ledger.active_validators_at(height)?;
        let bonds: HashMap<Address, u64> = active.iter().map(|v| (v.address, v.bond)).collect();
        let addresses: Vec<Address> = active.iter().map(|v| v.address).collect();
        let total_bond: u64 = active.iter().map(|v| v.bond).sum();
        let needed = quorum_bond(total_bond);
        let mut signatures = self
            .votes
            .lock()
            .signatures(height, round, &hash, &addresses);
        let Some(take) = VoteTracker::quorum_prefix(&signatures, &bonds, needed) else {
            return Ok(None);
        };
        // Always seal with the lexicographically first quorum of bonded stake.
        signatures.truncate(take);

        let pending = chain.pending.take().expect("checked above");
        let evidence = pending.proposal.evidence.clone();
        let mut checkpoint = pending.verified.checkpoint.clone();
        for signature in signatures {
            checkpoint.add_signature(signature);
        }
        checkpoint.canonicalize();

        let transactions = pending.proposal.transactions;
        self.commit(&mut chain, pending.verified, &checkpoint, &transactions)?;
        info!(
            height,
            hash = %hash.short(),
            signatures = checkpoint.validator_signatures.len(),
            transactions = transactions.len(),
            "finalized checkpoint"
        );
        Ok(Some(Finalized {
            checkpoint,
            transactions,
            evidence,
        }))
    }

    /// Whether a far-ahead checkpoint is worth triggering a snapshot download.
    ///
    /// A node that is more than one checkpoint behind cannot verify the quorum
    /// of a future checkpoint (the validator set may have changed), but it can
    /// still demand that the checkpoint carry at least one signature that
    /// verifies against a validator it already trusts. Without a real validator
    /// key, no amount of crafted JSON passes this — which is the whole point:
    /// an anonymous sender must not be able to force a snapshot download.
    pub fn checkpoint_credible(&self, checkpoint: &Checkpoint) -> bool {
        let chain = self.chain();
        let Ok(active) = chain
            .ledger
            .active_validators_at(chain.ledger.height() + 1)
        else {
            return false;
        };
        let keys: HashMap<Address, PublicKey> =
            active.into_iter().map(|v| (v.address, v.public_key)).collect();
        let hash = checkpoint.hash();
        let payload = sikka_common::vote::vote_signing_bytes(
            &checkpoint.header.chain_id,
            &checkpoint.header.genesis_fingerprint,
            checkpoint.header.height,
            checkpoint.header.round,
            VoteKind::Precommit,
            &hash,
        );
        checkpoint.validator_signatures.iter().any(|sig| {
            keys.get(&sig.validator).is_some_and(|key| {
                key.as_slice() == sig.public_key.as_slice()
                    && sikka_crypto::verify(key.as_slice(), &payload, sig.signature.as_slice())
            })
        })
    }

    /// Apply a checkpoint another node finalized.
    ///
    /// Returns whether it moved us forward. A checkpoint we cannot apply from
    /// here — because it is more than one height ahead — is reported as
    /// [`Error::BadCheckpointHeight`], which is the signal to fast-sync.
    pub fn handle_finalized(
        &self,
        checkpoint: &Checkpoint,
        transactions: &[Transaction],
        evidence: &[Equivocation],
    ) -> Result<bool> {
        let now = now_secs();
        let mut chain = self.chain();
        let local = chain.ledger.height();
        let height = checkpoint.header.height;

        if height < local {
            return Ok(false);
        }
        if height == local {
            if let Some(existing) = chain.checkpoints.get(height)? {
                if existing.hash() == checkpoint.hash() {
                    if existing.validator_signatures != checkpoint.validator_signatures {
                        return Err(Error::Other(
                            "alternate signer set for an already-finalized checkpoint".into(),
                        ));
                    }
                    return Ok(false);
                }

                let active = chain.ledger.active_validators_at(height)?;
                let authorized: Vec<(Address, PublicKey, u64)> = active
                    .iter()
                    .map(|v| (v.address, v.public_key.clone(), v.bond))
                    .collect();
                checkpoint.verify_signatures(authorized.iter().map(|(a, k, b)| (a, k, *b)))?;

                let chain_id = chain.ledger.meta().chain_id.clone();
                let genesis_fingerprint = chain.ledger.meta().genesis_fingerprint;
                let existing_signers: HashSet<Address> = existing
                    .validator_signatures
                    .iter()
                    .map(|s| s.validator)
                    .collect();
                let incoming_signers: HashSet<Address> = checkpoint
                    .validator_signatures
                    .iter()
                    .map(|s| s.validator)
                    .collect();

                let mut noted = 0usize;
                for validator in existing_signers.intersection(&incoming_signers) {
                    let Some(existing_sig) = existing
                        .validator_signatures
                        .iter()
                        .find(|s| s.validator == *validator)
                    else {
                        continue;
                    };
                    let Some(incoming_sig) = checkpoint
                        .validator_signatures
                        .iter()
                        .find(|s| s.validator == *validator)
                    else {
                        continue;
                    };
                    let vote_a = vote_from_checkpoint(&existing, existing_sig);
                    let vote_b = vote_from_checkpoint(checkpoint, incoming_sig);
                    if let Ok(evidence) =
                        Equivocation::new(vote_a, vote_b, &chain_id, &genesis_fingerprint)
                    {
                        self.votes.lock().note_equivocation(evidence);
                        noted += 1;
                    }
                }
                if noted > 0 {
                    warn!(
                        height,
                        noted,
                        local_hash = %existing.hash().short(),
                        incoming_hash = %checkpoint.hash().short(),
                        "recorded partition-healed equivocation evidence"
                    );
                }
            }
            return Ok(false);
        }
        if height != local + 1 {
            return Err(Error::BadCheckpointHeight {
                expected: local + 1,
                actual: height,
            });
        }

        // Signatures first: a checkpoint that lacks quorum is not worth replaying.
        let active = chain.ledger.active_validators_at(height)?;
        let authorized: Vec<(Address, PublicKey, u64)> = active
            .iter()
            .map(|v| (v.address, v.public_key.clone(), v.bond))
            .collect();
        checkpoint.verify_signatures(authorized.iter().map(|(a, k, b)| (a, k, *b)))?;

        let hash = checkpoint.hash();
        let matches_pending = chain.pending.as_ref().is_some_and(|p| p.hash == hash);
        if matches_pending {
            let pending = chain.pending.take().expect("checked above");
            let transactions = pending.proposal.transactions;
            self.commit(&mut chain, pending.verified, checkpoint, &transactions)?;
            debug!(height, hash = %hash.short(), "adopted the finalized form of our pending checkpoint");
            return Ok(true);
        }

        // We voted for something else at this height (or nothing at all). The
        // signed checkpoint wins; drop ours and replay theirs.
        if let Some(stale) = chain.pending.take() {
            let outcome = chain.ledger.rollback(stale.verified.staged);
            debug!(
                height = stale.height,
                transactions = outcome.applied.len(),
                "rolled back our own pending checkpoint in favour of the finalized one"
            );
        }

        let proposal = CheckpointProposal {
            header: checkpoint.header.clone(),
            transactions: transactions.to_vec(),
            evidence: evidence.to_vec(),
            proposer_signature: Signature::default(),
        };
        let verified_ids: HashSet<Hash> = self.mempool.lock().verified_ids();
        let verified = match verify_proposal_with(
            &mut chain.ledger,
            &proposal,
            now,
            &verified_ids,
            Authority::Finalized,
        ) {
            Ok(verified) => verified,
            Err(e) if transactions.is_empty() => {
                // Nothing came with it to replay, so a snapshot is the only way
                // forward. The catch-up loop will fetch one.
                debug!(error = %e, "a finalized checkpoint arrived without its transactions");
                return Err(Error::Other(
                    "cannot replay a finalized checkpoint without its transactions".into(),
                ));
            }
            Err(e) => return Err(e),
        };
        self.commit(&mut chain, verified, checkpoint, transactions)?;
        info!(height, hash = %hash.short(), "replayed a checkpoint finalized by the network");
        Ok(true)
    }

    /// Persist a verified checkpoint and clean up everything it made obsolete.
    fn commit(
        &self,
        chain: &mut Chain,
        verified: VerifiedProposal,
        checkpoint: &Checkpoint,
        transactions: &[Transaction],
    ) -> Result<()> {
        let height = checkpoint.header.height;
        chain.checkpoints.put_unpruned(checkpoint)?;
        if let Err(error) = chain.ledger.commit(verified.staged, checkpoint) {
            if let Err(remove_error) = chain.checkpoints.remove(height) {
                warn!(
                    %remove_error,
                    height,
                    "could not remove uncommitted write-ahead checkpoint"
                );
            }
            return Err(error);
        }
        if let Err(error) = chain.checkpoints.prune_for_height(height) {
            warn!(%error, height, "could not prune checkpoint history");
        }
        chain.last_progress = now_secs();
        // The height is closed, so nothing here binds us any more.
        chain.locked = None;
        chain.known = None;

        let ids: Vec<Hash> = transactions.iter().map(|tx| tx.id()).collect();
        let senders: Vec<Address> = transactions.iter().map(|tx| tx.from).collect();
        let mut mempool = self.mempool.lock();
        mempool.remove_all(&ids);
        for sender in senders {
            if let Ok(nonce) = chain.ledger.next_nonce(&sender) {
                mempool.prune_stale_nonces(&sender, nonce);
            }
        }
        drop(mempool);

        self.votes.lock().prune_below(checkpoint.header.height + 1);
        self.commitments.prune_below(checkpoint.header.height + 1)?;
        let store = chain.ledger.store_handle();
        let checkpoint = checkpoint.clone();
        self.schedule_snapshot_archive(checkpoint, store);
        Ok(())
    }

    /// Give up on a pending checkpoint that has not reached quorum.
    ///
    /// Only the *staged state* is released, never the vote: the vote is a
    /// signed commitment, and forgetting it would let this node sign a second
    /// checkpoint at the same height and slash itself. Releasing the staging
    /// lets a later round be replayed and applied if it wins instead, and keeps
    /// the ledger's Merkle roots equal to the last committed checkpoint while
    /// the height stays open.
    ///
    /// The proposal is kept, because the vote by itself is a commitment with
    /// nothing left to commit: this node may not sign a rival, so unless it can
    /// offer this same checkpoint again the height can never close. See
    /// [`Self::reoffer_locked`].
    pub fn expire_pending(&self, timeout_secs: u64) -> bool {
        let now = now_secs();
        let mut chain = self.chain();
        let Some(pending) = &chain.pending else {
            return false;
        };
        if now.saturating_sub(pending.created_at) < timeout_secs {
            return false;
        }
        let pending = chain.pending.take().expect("checked above");
        let height = pending.height;
        let round = pending.proposal.header.round;
        let hash = pending.hash;
        chain.ledger.rollback(pending.verified.staged);
        remember_proposal(&mut chain.known, &pending.proposal);
        // Precommits lock the height; prevotes do not. Keeping a prevote-only
        // body as `locked` would force reoffering it forever and recreate the
        // one-phase deadlock after a partition heals.
        let precommit_locked = self
            .votes
            .lock()
            .vote_by(height, round, VoteKind::Precommit, &self.address)
            .is_some_and(|v| v.checkpoint_hash == hash);
        if precommit_locked {
            chain.locked = Some(Locked {
                proposal: pending.proposal,
                offered_at: None,
            });
        } else {
            chain.locked = None;
        }
        warn!(
            height,
            "pending checkpoint timed out without quorum; will offer it again"
        );
        true
    }

    // ---- peers -----------------------------------------------------------

    pub fn record_announce(&self, announce: &PeerAnnounce) -> Result<bool> {
        let chain = self.chain();
        let meta = chain.ledger.meta();
        self.peers.lock().record(
            announce,
            now_secs(),
            &meta.chain_id,
            &meta.genesis_fingerprint,
        )
    }

    pub fn add_peer_endpoint(&self, endpoint: &str) -> bool {
        self.peers.lock().add_endpoint(endpoint, now_secs())
    }

    pub fn record_peer_failure(&self, endpoint: &str) {
        self.peers.lock().record_failure(endpoint, now_secs());
    }

    pub fn record_peer_success(&self, endpoint: &str) {
        self.peers.lock().record_success(endpoint, now_secs());
    }

    pub fn own_announce(&self) -> Result<PeerAnnounce> {
        let chain = self.chain();
        let meta = chain.ledger.meta();
        PeerAnnounce::sign(
            &self.keypair,
            &self.config.advertise,
            now_secs(),
            &meta.chain_id,
            meta.genesis_fingerprint,
        )
    }

    // ---- maintenance and sync -------------------------------------------

    /// Drop transactions that can no longer be applied. Returns how many.
    pub fn prune_mempool(&self) -> usize {
        self.mempool.lock().prune_expired(now_secs())
    }

    fn validate_snapshot_target(
        &self,
        chain: &Chain,
        chain_id: &str,
        genesis_fingerprint: Hash,
        checkpoint: &Checkpoint,
    ) -> Result<bool> {
        let height = checkpoint.header.height;
        let local_height = chain.ledger.height();
        if height <= local_height {
            return Err(Error::Other(format!(
                "snapshot at height {height} is not ahead of local height {local_height}"
            )));
        }
        if genesis_fingerprint != chain.ledger.meta().genesis_fingerprint {
            return Err(Error::GenesisMismatch);
        }
        if chain_id != chain.ledger.meta().chain_id {
            return Err(Error::ChainIdMismatch {
                expected: chain.ledger.meta().chain_id.clone(),
                actual: chain_id.to_string(),
            });
        }

        let checkpoint_hash = checkpoint.hash();
        let pinned = match self.config.trusted_checkpoint {
            Some(anchor) if anchor.height == height => {
                if anchor.hash != checkpoint_hash {
                    return Err(Error::Other(format!(
                        "snapshot checkpoint {checkpoint_hash} does not match the trusted checkpoint {}",
                        anchor.hash
                    )));
                }
                true
            }
            _ => false,
        };
        let validators_changed = checkpoint.header.validator_root != chain.ledger.validator_root();
        let gap = height.saturating_sub(local_height);
        if gap > sikka_common::constants::WEAK_SUBJECTIVITY_GAP && !pinned {
            return Err(Error::Other(format!(
                "snapshot gap from {local_height} to {height} exceeds weak-subjectivity \
                 limit {}; set SIKKA_TRUSTED_CHECKPOINT={height}:{checkpoint_hash} after \
                 independently verifying that checkpoint{}",
                sikka_common::constants::WEAK_SUBJECTIVITY_GAP,
                if validators_changed {
                    " (validator set also changed)"
                } else {
                    ""
                }
            )));
        }
        Ok(pinned)
    }

    /// Validate a manifest's chain identity and trust anchor before downloading
    /// its potentially large chunk set.
    pub fn verify_snapshot_manifest(&self, manifest: &SnapshotManifest) -> Result<()> {
        manifest.validate()?;
        let chain = self.chain();
        let pinned = self.validate_snapshot_target(
            &chain,
            &manifest.chain_id,
            manifest.genesis_fingerprint,
            &manifest.checkpoint,
        )?;
        if pinned {
            return Ok(());
        }
        let height = manifest.checkpoint.header.height;
        let validators = chain.ledger.validators()?;
        let authorized: Vec<(Address, PublicKey, u64)> = validators
            .iter()
            .filter(|validator| validator.is_active_at(height))
            .map(|validator| (validator.address, validator.public_key.clone(), validator.bond))
            .collect();
        if authorized.is_empty() {
            return Err(Error::NoActiveValidators);
        }
        manifest
            .checkpoint
            .verify_signatures(authorized.iter().map(|(address, key, bond)| (address, key, *bond)))?;
        Ok(())
    }

    /// Replace local state with a snapshot from a peer.
    ///
    /// This is the only way to close a gap of more than one checkpoint: SIKKA
    /// keeps no transaction history, so there is nothing to replay. The snapshot
    /// is checked against its own checkpoint's signatures before it is trusted.
    pub fn apply_snapshot(&self, snapshot: &StateSnapshot) -> Result<u64> {
        let mut chain = self.chain();
        let height = snapshot.checkpoint.header.height;
        let pinned = self.validate_snapshot_target(
            &chain,
            &snapshot.chain_id,
            snapshot.genesis_fingerprint,
            &snapshot.checkpoint,
        )?;

        // A one-height transition is authorized by the locally known active
        // set. Larger gaps always need an operator-pinned trust anchor (see
        // WEAK_SUBJECTIVITY_GAP), even when validator_root is unchanged.
        let validators: Vec<Validator> = if pinned {
            snapshot.validators.clone()
        } else {
            chain.ledger.validators()?
        };
        let authorized: Vec<(Address, PublicKey, u64)> = validators
            .iter()
            .filter(|validator| validator.is_active_at(height))
            .map(|validator| (validator.address, validator.public_key.clone(), validator.bond))
            .collect();
        if authorized.is_empty() {
            return Err(Error::NoActiveValidators);
        }
        snapshot
            .checkpoint
            .verify_signatures(authorized.iter().map(|(a, k, b)| (a, k, *b)))?;

        if let Some(stale) = chain.pending.take() {
            chain.ledger.rollback(stale.verified.staged);
        }
        chain.locked = None;
        chain.known = None;
        chain.checkpoints.put_unpruned(&snapshot.checkpoint)?;
        if let Err(error) = chain.ledger.apply_snapshot(snapshot) {
            if let Err(remove_error) = chain.checkpoints.remove(height) {
                warn!(
                    %remove_error,
                    height,
                    "could not remove rejected write-ahead checkpoint"
                );
            }
            return Err(error);
        }
        if let Err(error) = chain.checkpoints.prune_for_height(height) {
            warn!(%error, height, "could not prune checkpoint history");
        }
        chain.last_progress = now_secs();
        let store = chain.ledger.store_handle();
        let checkpoint = snapshot.checkpoint.clone();
        drop(chain);

        self.votes.lock().prune_below(height + 1);
        self.commitments.prune_below(height + 1)?;
        self.schedule_snapshot_archive(checkpoint, store);
        info!(
            height,
            accounts = snapshot.accounts.len(),
            "fast-synced from a peer snapshot"
        );
        Ok(height)
    }

    /// Accounts in the current state, for diagnostics and tests.
    pub fn all_accounts(&self) -> Result<Vec<(Address, Account)>> {
        self.chain().ledger.all_accounts()
    }

    /// Pick a random address whose liquid balance plus bond is at least 1 SIKKA.
    ///
    /// Used by the public `/api/address/random` teaser so the landing page can
    /// link into a real holder without hard-coding addresses.
    pub fn random_funded_address(&self) -> Result<Option<FundedAddress>> {
        let chain = self.chain();
        let height = chain.ledger.height();
        drop(chain);

        let mut cache = self.funded_address_cache.lock();
        if cache.as_ref().is_none_or(|(cached_height, _)| *cached_height != height) {
            let chain = self.chain();
            let bonds: HashMap<Address, u64> = chain
                .ledger
                .validators()?
                .into_iter()
                .filter(|v| !v.slashed && v.bond > 0)
                .map(|v| (v.address, v.bond))
                .collect();

            let mut funded = Vec::new();
            for (address, account) in chain.ledger.all_accounts()? {
                let bond = bonds.get(&address).copied().unwrap_or(0);
                let total = account.balance.saturating_add(bond);
                if total >= CHILLAR_PER_SIKKA {
                    funded.push(FundedAddress {
                        address,
                        balance: account.balance,
                        bond,
                        total,
                    });
                }
            }
            *cache = Some((height, funded));
        }

        let funded = &mut cache.as_mut().unwrap().1;
        if funded.is_empty() {
            return Ok(None);
        }

        // Per-request counter mixed with tip height so consecutive loads rotate
        // holders without pulling in an RNG crate.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let mix = COUNTER
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .wrapping_mul(0x9E37_79B9)
            .wrapping_add(height.wrapping_mul(0x85EB_CA6B))
            .wrapping_add(now_secs());
        let index = (mix as usize) % funded.len();
        Ok(Some(funded.swap_remove(index)))
    }

    pub fn audit_supply(&self) -> Result<u64> {
        self.chain().ledger.audit_supply()
    }
}

/// A randomly selected account holding at least one SIKKA (liquid + bond).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FundedAddress {
    pub address: Address,
    pub balance: u64,
    pub bond: u64,
    pub total: u64,
}

fn refused(reason: impl Into<String>) -> ProposalResponse {
    ProposalResponse {
        accepted: false,
        vote: None,
        reason: Some(reason.into()),
    }
}

/// Keep the lowest-round open proposal for the height still being decided.
fn remember_proposal(known: &mut Option<CheckpointProposal>, proposal: &CheckpointProposal) {
    match known {
        Some(existing)
            if existing.height() == proposal.height()
                && existing.header.round <= proposal.header.round => {}
        _ => *known = Some(proposal.clone()),
    }
}

/// Load genesis from disk when present; otherwise use the baked-in SIKKA chain.
fn load_genesis(config: &NodeConfig) -> Result<GenesisConfig> {
    if config.genesis_path.exists() {
        let json = std::fs::read_to_string(&config.genesis_path).map_err(|e| {
            Error::Other(format!(
                "cannot read genesis {}: {e}",
                config.genesis_path.display()
            ))
        })?;
        return GenesisConfig::from_json(&json);
    }
    info!("no genesis file mounted; using baked-in SIKKA genesis");
    Ok(sikka_common::default_genesis())
}

/// Resolve the node's key: env hex wins, otherwise the on-disk keystore.
fn load_keypair(config: &NodeConfig) -> Result<sikka_crypto::Keypair> {
    if let Some(hex) = &config.private_key {
        let keypair = parse_private_key(hex)?;
        Keystore::from_keypair(&keypair).save(&config.key_path)?;
        return Ok(keypair);
    }
    Ok(Keystore::load_or_create(&config.key_path)?.keypair()?)
}

/// Accept a 32-byte seed or a full 4896-byte ML-DSA-87 secret, as hex.
fn parse_private_key(hex: &str) -> Result<sikka_crypto::Keypair> {
    let clean = hex.trim().strip_prefix("0x").unwrap_or(hex.trim());
    let bytes = ::hex::decode(clean).map_err(|_| Error::InvalidHex)?;
    match bytes.len() {
        32 => {
            let seed: [u8; 32] = bytes.try_into().expect("length checked");
            Ok(sikka_crypto::Keypair::from_seed(&seed)?)
        }
        sikka_crypto::SK_LEN => Ok(sikka_crypto::Keypair::from_private_bytes(&bytes)?),
        n => Err(Error::Other(format!(
            "SIKKA_PRIVATE_KEY must be a 32-byte seed or {}-byte secret, got {n} bytes",
            sikka_crypto::SK_LEN
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::constants::CHILLAR_PER_SIKKA;
    use sikka_common::genesis::{GenesisAllocation, GenesisValidator};

    struct Fixture {
        node: Arc<Node>,
        alice: sikka_crypto::Keypair,
        _dir: tempfile::TempDir,
    }

    impl Fixture {
        fn chain_id(&self) -> String {
            self.node.chain_info().unwrap().chain_id
        }

        fn genesis_fingerprint(&self) -> Hash {
            self.node.chain_info().unwrap().genesis_fingerprint
        }
    }

    /// A node that is the sole validator, so a single vote is a super-majority.
    fn solo_node() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let validator = sikka_crypto::Keypair::generate().unwrap();
        let alice = sikka_crypto::Keypair::generate().unwrap();

        let keystore = Keystore::from_keypair(&validator);
        keystore.save(dir.path().join("node_key.json")).unwrap();

        let genesis = GenesisConfig {
            chain_id: "sikka-test".into(),
            timestamp: now_secs() - 10,
            checkpoint_tx_interval: Some(2),
            max_missed_proposer_slots: None,
            allocations: vec![
                GenesisAllocation {
                    to: Address(validator.address_bytes()),
                    amount: 1_000_000 * CHILLAR_PER_SIKKA,
                },
                GenesisAllocation {
                    to: Address(alice.address_bytes()),
                    amount: 1_000 * CHILLAR_PER_SIKKA,
                },
            ],
            validators: vec![GenesisValidator {
                public_key: PublicKey::new(*validator.public_bytes()),
                bond: 500_000 * CHILLAR_PER_SIKKA,
                endpoint: None,
            }],
        };
        std::fs::write(dir.path().join("genesis.json"), genesis.to_json()).unwrap();

        let config = NodeConfig {
            data_dir: dir.path().to_path_buf(),
            genesis_path: dir.path().join("genesis.json"),
            key_path: dir.path().join("node_key.json"),
            bootstrap: Vec::new(),
            advertise: "http://127.0.0.1:8080".into(),
            tor_socks: None,
            ..NodeConfig::default()
        };

        let node = Node::open(config).unwrap();
        Fixture {
            node,
            alice,
            _dir: dir,
        }
    }

    struct Pair {
        nodes: Vec<Arc<Node>>,
        configs: Vec<NodeConfig>,
        alice: sikka_crypto::Keypair,
        _dirs: Vec<tempfile::TempDir>,
    }

    impl Pair {
        fn chain_id(&self) -> String {
            self.nodes[0].chain_info().unwrap().chain_id
        }

        fn genesis_fingerprint(&self) -> Hash {
            self.nodes[0].chain_info().unwrap().genesis_fingerprint
        }
    }

    /// Two validators on one genesis, wired by hand rather than over HTTP.
    ///
    /// Quorum is both of them, so no checkpoint closes without a round completing
    /// end to end — which is what makes an interrupted round observable.
    fn validator_pair() -> Pair {
        let alice = sikka_crypto::Keypair::generate().unwrap();
        let keys: Vec<sikka_crypto::Keypair> = (0..2)
            .map(|_| sikka_crypto::Keypair::generate().unwrap())
            .collect();

        let genesis = GenesisConfig {
            chain_id: "sikka-pair".into(),
            timestamp: now_secs() - 10,
            checkpoint_tx_interval: Some(2),
            max_missed_proposer_slots: None,
            allocations: keys
                .iter()
                .map(|kp| GenesisAllocation {
                    to: Address(kp.address_bytes()),
                    amount: 1_000_000 * CHILLAR_PER_SIKKA,
                })
                .chain(std::iter::once(GenesisAllocation {
                    to: Address(alice.address_bytes()),
                    amount: 1_000 * CHILLAR_PER_SIKKA,
                }))
                .collect(),
            validators: keys
                .iter()
                .map(|kp| GenesisValidator {
                    public_key: PublicKey::new(*kp.public_bytes()),
                    bond: 500_000 * CHILLAR_PER_SIKKA,
                    endpoint: None,
                })
                .collect(),
        };
        let json = genesis.to_json();

        let mut dirs = Vec::new();
        let mut configs = Vec::new();
        for (index, kp) in keys.iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            Keystore::from_keypair(kp)
                .save(dir.path().join("node_key.json"))
                .unwrap();
            std::fs::write(dir.path().join("genesis.json"), &json).unwrap();
            configs.push(NodeConfig {
                data_dir: dir.path().to_path_buf(),
                genesis_path: dir.path().join("genesis.json"),
                key_path: dir.path().join("node_key.json"),
                bootstrap: Vec::new(),
                advertise: format!("http://127.0.0.1:{}", 18080 + index),
                tor_socks: None,
                ..NodeConfig::default()
            });
            dirs.push(dir);
        }

        let nodes = configs
            .iter()
            .map(|config| Node::open(config.clone()).unwrap())
            .collect();
        Pair {
            nodes,
            configs,
            alice,
            _dirs: dirs,
        }
    }

    fn transfer(
        from: &sikka_crypto::Keypair,
        to: Address,
        amount: u64,
        nonce: u64,
        chain_id: &str,
        genesis_fingerprint: Hash,
    ) -> Transaction {
        Transaction::transfer(from, to, amount, nonce, now_secs(), chain_id, genesis_fingerprint).unwrap()
    }

    /// Drive prevotes → precommits → finalize for a solo validator.
    fn seal_solo(node: &Node, prevote: Vote) -> Finalized {
        let (follow_up, finalized) = node.handle_vote(prevote).unwrap();
        if let Some(done) = finalized {
            return done;
        }
        if let Some(precommit) = follow_up.or_else(|| node.maybe_precommit().unwrap()) {
            let (_, finalized) = node.handle_vote(precommit).unwrap();
            if let Some(done) = finalized {
                return done;
            }
        }
        node.finalize_if_quorum()
            .unwrap()
            .expect("solo precommit is a quorum of one")
    }

    /// Exchange votes between a proposer and one other validator until the height seals.
    fn seal_pair(
        proposer: &Node,
        voter: &Node,
        proposal: &CheckpointProposal,
        proposer_prevote: Vote,
    ) -> Finalized {
        let voter_prevote = voter
            .handle_proposal(proposal)
            .unwrap()
            .vote
            .expect("voter prevotes for a valid proposal");

        let (mut proposer_pre, finalized) = proposer.handle_vote(voter_prevote.clone()).unwrap();
        if let Some(done) = finalized {
            return done;
        }
        let (mut voter_pre, finalized) = voter.handle_vote(proposer_prevote).unwrap();
        if let Some(done) = finalized {
            return done;
        }

        if proposer_pre.is_none() {
            proposer_pre = proposer.maybe_precommit().unwrap();
        }
        if voter_pre.is_none() {
            voter_pre = voter.maybe_precommit().unwrap();
        }

        if let Some(pre) = voter_pre {
            let (_, finalized) = proposer.handle_vote(pre).unwrap();
            if let Some(done) = finalized {
                return done;
            }
        }
        if let Some(pre) = proposer_pre {
            let (_, finalized) = voter.handle_vote(pre).unwrap();
            if let Some(done) = finalized {
                return done;
            }
        }

        proposer
            .finalize_if_quorum()
            .unwrap()
            .or_else(|| voter.finalize_if_quorum().unwrap())
            .expect("two precommits are a quorum")
    }

    #[test]
    fn opens_a_chain_from_genesis_and_serves_it() {
        let f = solo_node();
        let info = f.node.chain_info().unwrap();
        assert_eq!(info.height, 0);
        assert_eq!(info.chain_id, "sikka-test");
        assert_eq!(info.accounts, 2);
        assert_eq!(info.active_validators, 1);
        assert_eq!(info.total_supply, 1_001_000 * CHILLAR_PER_SIKKA);
        assert!(f.node.is_active_validator());

        // The genesis checkpoint is stored, so proofs work from height zero.
        let proof = f
            .node
            .account_proof(&Address(f.alice.address_bytes()))
            .unwrap();
        assert_eq!(proof.checkpoint.header.height, 0);
        assert_eq!(proof.account.unwrap().balance, 1_000 * CHILLAR_PER_SIKKA);
    }

    #[test]
    fn reopening_keeps_the_chain() {
        let f = solo_node();
        let config = f.node.config().clone();
        let bob = Address([7u8; 32]);
        f.node
            .submit_transaction(transfer(&f.alice, bob, 500, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        f.node
            .submit_transaction(transfer(&f.alice, bob, 500, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let (_, vote) = f.node.try_propose().unwrap().unwrap();
        seal_solo(&f.node, vote);
        assert_eq!(f.node.height(), 1);
        drop(f.node);

        let reopened = Node::open(config).unwrap();
        assert_eq!(reopened.height(), 1);
        assert_eq!(reopened.account(&bob).unwrap().balance, 1_000);
    }

    #[test]
    fn a_solo_validator_finalizes_its_own_proposal() {
        let f = solo_node();
        let bob = Address([7u8; 32]);
        f.node
            .submit_transaction(transfer(&f.alice, bob, 700, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();

        // One transaction is short of the two-transaction interval.
        assert!(f.node.try_propose().unwrap().is_none());

        f.node
            .submit_transaction(transfer(&f.alice, bob, 300, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let (proposal, vote) = f.node.try_propose().unwrap().unwrap();
        assert_eq!(proposal.transactions.len(), 2);

        let finalized = seal_solo(&f.node, vote);
        assert_eq!(finalized.checkpoint.header.height, 1);
        assert_eq!(finalized.checkpoint.validator_signatures.len(), 1);

        assert_eq!(f.node.height(), 1);
        assert_eq!(f.node.account(&bob).unwrap().balance, 1_000);
        assert_eq!(
            f.node.mempool_info().pending,
            0,
            "applied transactions leave the pool"
        );

        // Inflation went somewhere, and nothing else was created or destroyed.
        let info = f.node.chain_info().unwrap();
        assert!(info.total_supply > 1_001_000 * CHILLAR_PER_SIKKA);
        assert_eq!(f.node.audit_supply().unwrap(), info.total_supply);
    }

    #[test]
    fn duplicate_submissions_are_reported_as_known() {
        let f = solo_node();
        let tx = transfer(&f.alice, Address([7u8; 32]), 1, 0, &f.chain_id(), f.genesis_fingerprint());
        assert!(f.node.submit_transaction(tx.clone()).unwrap().1);
        assert!(
            !f.node.submit_transaction(tx).unwrap().1,
            "gossip must not loop"
        );
    }

    #[test]
    fn a_non_validator_neither_proposes_nor_votes() {
        let f = solo_node();
        let mut config = f.node.config().clone();
        config.validator = false;
        let dir = tempfile::tempdir().unwrap();
        config.data_dir = dir.path().to_path_buf();
        config.key_path = dir.path().join("node_key.json");

        let observer = Node::open(config).unwrap();
        assert!(!observer.is_active_validator());
        assert!(observer.try_propose().unwrap().is_none());
    }

    #[test]
    fn a_pending_round_is_never_signed_twice() {
        let f = solo_node();
        let bob = Address([7u8; 32]);
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let (proposal, _) = f.node.try_propose().unwrap().unwrap();

        // The same proposal again gets the same vote back, not a second one.
        let response = f.node.handle_proposal(&proposal).unwrap();
        assert!(response.accepted);
        assert_eq!(response.vote.unwrap().checkpoint_hash, proposal.hash());

        // A different proposal at that height is refused.
        let mut conflicting = proposal.clone();
        conflicting.header.timestamp += 1;
        let response = f.node.handle_proposal(&conflicting).unwrap();
        assert!(!response.accepted);
        assert!(
            response.reason.unwrap().contains("prevoted"),
            "same-round rival must be refused"
        );

        // Proposing again while a round is open does nothing.
        assert!(f.node.try_propose().unwrap().is_none());
    }

    #[test]
    fn a_stalled_round_is_offered_again_rather_than_stranding_the_height() {
        let f = solo_node();
        let bob = Address([7u8; 32]);
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let root_before = f.node.chain_info().unwrap().state_root;

        let (first, first_vote) = f.node.try_propose().unwrap().unwrap();
        assert!(!f.node.expire_pending(600), "not yet due");
        assert!(f.node.expire_pending(0), "an overdue round is abandoned");

        assert_eq!(f.node.height(), 0);
        assert_eq!(
            f.node.chain_info().unwrap().state_root,
            root_before,
            "abandoning a round must leave state exactly as it was"
        );

        // The vote survives the abandoned staging and binds this node for as long
        // as the height is open, so the checkpoint it was cast for is offered
        // again — never a rival, and never nothing, which would leave a height
        // nobody can close while the vote sits on disk.
        let (again, again_vote) = f
            .node
            .try_propose()
            .unwrap()
            .expect("the checkpoint we voted for is offered again");
        assert_eq!(again.hash(), first.hash());
        assert_eq!(again_vote, first_vote);

        // A vote that turns up once the staging is back still closes the height
        // after prevotes reach quorum and we precommit.
        let finalized = seal_solo(&f.node, again_vote);
        assert_eq!(finalized.checkpoint.header.height, 1);
        assert_eq!(f.node.height(), 1);
    }

    #[test]
    fn a_node_will_not_sign_a_second_checkpoint_at_one_height() {
        let f = solo_node();
        let bob = Address([7u8; 32]);
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let (proposal, _) = f.node.try_propose().unwrap().unwrap();

        // Give up on the round, then offer a different checkpoint at that height:
        // signing it would be equivocation evidence against ourselves.
        assert!(f.node.expire_pending(0));
        let mut rival = proposal;
        rival.header.timestamp += 1;
        let response = f.node.handle_proposal(&rival).unwrap();
        assert!(!response.accepted);
        let reason = response.reason.unwrap();
        assert!(
            reason.contains("prevoted")
                || reason.contains("precommit")
                || reason.contains("voted"),
            "unexpected reason: {reason}"
        );
    }

    #[test]
    fn our_own_commitments_survive_restart_and_block_equivocation() {
        let f = solo_node();
        let bob = Address([7u8; 32]);
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let (proposal, original_vote) = f.node.try_propose().unwrap().unwrap();
        let height = proposal.height();
        let config = f.node.config().clone();
        let commitments_path = config.commitments_path();
        drop(f.node);

        assert_eq!(
            CommitmentStore::open(&commitments_path)
                .unwrap()
                .get(height)
                .unwrap(),
            Some(Commitment {
                vote: original_vote.clone(),
                proposal: proposal.clone(),
            }),
            "the vote and the checkpoint it commits us to must both survive exit"
        );

        let reopened = Node::open(config).unwrap();
        assert_eq!(reopened.height(), 0, "proposal was never finalized");

        // A rival at the same height must be refused — the vote came back from disk.
        let mut rival = proposal.clone();
        rival.header.timestamp += 1;
        let refused = reopened.handle_proposal(&rival).unwrap();
        assert!(!refused.accepted);
        assert!(
            refused.reason.unwrap().contains("prevoted"),
            "restored prevote must block a same-round rival"
        );

        // The checkpoint came back with the vote, so this node can offer it again
        // unaided. Were it restoring the vote alone it would be bound to a
        // checkpoint it could not name, and only a peer re-sending that exact
        // proposal could ever close the height.
        let (again, again_vote) = reopened
            .try_propose()
            .unwrap()
            .expect("the restored commitment is offered again");
        assert_eq!(again, proposal);
        assert_eq!(again_vote, original_vote);

        // The original hash is idempotent: re-send the same vote.
        let accepted = reopened.handle_proposal(&proposal).unwrap();
        assert!(accepted.accepted);
        let vote = accepted.vote.expect("same-hash retry returns the vote");
        assert_eq!(vote, original_vote);
        assert_eq!(vote.height, height);

        let finalized = seal_solo(&reopened, vote);
        assert_eq!(finalized.checkpoint, reopened.checkpoint(height).unwrap());
        assert_eq!(reopened.height(), height);
    }

    /// Every validator restarts mid-round, before any of them has quorum.
    ///
    /// Both have signed, so neither may sign anything else at this height: the
    /// checkpoint they signed is the only one that can ever close it. Restoring
    /// the votes without it would leave the whole set bound to a checkpoint none
    /// of them could name, and the chain would stop here for good.
    #[test]
    fn a_round_interrupted_by_restarting_every_validator_still_closes() {
        let pair = validator_pair();
        let bob = Address([7u8; 32]);
        for node in &pair.nodes {
            for nonce in 0..2 {
                node.submit_transaction(transfer(&pair.alice, bob, 1, nonce, &pair.chain_id(), pair.genesis_fingerprint()))
                    .unwrap();
            }
        }

        // Whoever's turn it is proposes; asking the other costs nothing.
        let (proposal, proposer_vote, proposer) = match pair.nodes[0].try_propose().unwrap() {
            Some((proposal, vote)) => (proposal, vote, 0),
            None => {
                let (proposal, vote) = pair.nodes[1]
                    .try_propose()
                    .unwrap()
                    .expect("one of the two holds the round");
                (proposal, vote, 1)
            }
        };
        let voter = 1 - proposer;
        let _ = pair.nodes[voter]
            .handle_proposal(&proposal)
            .unwrap()
            .vote
            .expect("the other validator agrees");

        // Both go down before either has seen the other's vote.
        drop(pair.nodes);
        let restarted: Vec<Arc<Node>> = pair
            .configs
            .iter()
            .map(|config| Node::open(config.clone()).unwrap())
            .collect();
        assert!(restarted.iter().all(|node| node.height() == 0));

        // The proposer offers what it signed, byte for byte, straight off disk.
        let (again, again_vote) = restarted[proposer]
            .try_propose()
            .unwrap()
            .expect("the restored commitment is offered again");
        assert_eq!(again, proposal);
        assert_eq!(again_vote, proposer_vote);

        let finalized = seal_pair(
            &restarted[proposer],
            &restarted[voter],
            &again,
            again_vote,
        );
        assert_eq!(finalized.checkpoint.header.height, 1);
        assert_eq!(finalized.checkpoint.hash(), proposal.hash());

        assert!(restarted[voter]
            .handle_finalized(
                &finalized.checkpoint,
                &finalized.transactions,
                &finalized.evidence,
            )
            .unwrap());
        assert!(restarted.iter().all(|node| node.height() == 1));
        assert!(restarted
            .iter()
            .all(|node| node.account(&bob).unwrap().balance == 2));
    }

    #[test]
    fn orphan_votes_alone_do_not_freeze_inventing() {
        // A vote without a body must not permanently block a later proposer —
        // that was a byzantine halt (cast a fake vote, freeze the height).
        // Honest adoption is via peer-fetch + note_open_proposal (covered below).
        let pair = validator_pair();
        let bob = Address([7u8; 32]);
        for node in &pair.nodes {
            for nonce in 0..2 {
                node.submit_transaction(transfer(&pair.alice, bob, 1, nonce, &pair.chain_id(), pair.genesis_fingerprint()))
                    .unwrap();
            }
        }

        let (proposal, vote, proposer) = match pair.nodes[0].try_propose().unwrap() {
            Some((proposal, vote)) => (proposal, vote, 0),
            None => {
                let (proposal, vote) = pair.nodes[1]
                    .try_propose()
                    .unwrap()
                    .expect("one of the two holds the round");
                (proposal, vote, 1)
            }
        };
        let other = 1 - proposer;

        pair.nodes[other].handle_vote(vote.clone()).unwrap();
        // Still the proposer's round: the other node is not due to invent yet.
        assert!(pair.nodes[other].try_propose().unwrap().is_none());

        let finalized = seal_pair(&pair.nodes[proposer], &pair.nodes[other], &proposal, vote);
        assert_eq!(finalized.checkpoint.hash(), proposal.hash());
    }

    #[test]
    fn a_known_open_proposal_is_adopted_instead_of_inventing_a_rival() {
        let pair = validator_pair();
        let bob = Address([7u8; 32]);
        for node in &pair.nodes {
            for nonce in 0..2 {
                node.submit_transaction(transfer(&pair.alice, bob, 1, nonce, &pair.chain_id(), pair.genesis_fingerprint()))
                    .unwrap();
            }
        }

        let (proposal, proposer_vote, proposer) = match pair.nodes[0].try_propose().unwrap() {
            Some((proposal, vote)) => (proposal, vote, 0),
            None => {
                let (proposal, vote) = pair.nodes[1]
                    .try_propose()
                    .unwrap()
                    .expect("one of the two holds the round");
                (proposal, vote, 1)
            }
        };
        let other = 1 - proposer;

        // Simulate learning the open proposal via peer fetch before our turn to
        // invent: remember it, then try_propose must adopt that hash.
        pair.nodes[other].note_open_proposal(&proposal);
        let (adopted, adopted_vote) = pair.nodes[other]
            .try_propose()
            .unwrap()
            .expect("the known proposal is adopted");
        assert_eq!(adopted.hash(), proposal.hash());
        assert_ne!(adopted_vote.validator, proposer_vote.validator);
        let _ = adopted_vote;

        let finalized = seal_pair(
            &pair.nodes[proposer],
            &pair.nodes[other],
            &proposal,
            proposer_vote,
        );
        assert_eq!(finalized.checkpoint.hash(), proposal.hash());
    }

    #[test]
    fn finalized_commitments_are_pruned() {
        let f = solo_node();
        let bob = Address([7u8; 32]);
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let (_, vote) = f.node.try_propose().unwrap().unwrap();
        let height = vote.height;
        let commitments_path = f.node.config().commitments_path();
        seal_solo(&f.node, vote);
        assert_eq!(f.node.height(), height);
        drop(f.node);

        let stored = CommitmentStore::open(commitments_path).unwrap();
        assert!(
            stored.get(height).unwrap().is_none(),
            "finalized heights must leave the durable commitment store"
        );
        assert!(stored.is_empty().unwrap());
    }

    #[test]
    fn a_transaction_the_sender_cannot_pay_for_is_never_admitted() {
        let f = solo_node();
        let bob = Address([7u8; 32]);

        // An address with no coins costs nothing to create, so if the mempool
        // took its transactions anyone could fill the network's pools for free.
        let pauper = sikka_crypto::Keypair::generate().unwrap();
        let error = f
            .node
            .submit_transaction(transfer(&pauper, bob, 1, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap_err();
        assert!(matches!(error, Error::InsufficientBalance { .. }));
        assert_eq!(f.node.mempool_info().pending, 0);

        // The same rule applies to a funded account spending more than it has,
        // counting what it already has queued rather than each transaction alone.
        let balance = f
            .node
            .account(&Address(f.alice.address_bytes()))
            .unwrap()
            .balance;
        f.node
            .submit_transaction(transfer(&f.alice, bob, balance - 1, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let error = f
            .node
            .submit_transaction(transfer(&f.alice, bob, balance - 1, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap_err();
        assert!(matches!(error, Error::InsufficientBalance { .. }));
        assert_eq!(f.node.mempool_info().pending, 1);

        // Replacing that queued transaction with an affordable one is fine: it
        // takes the nonce's place instead of queueing behind it.
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        assert_eq!(f.node.mempool_info().pending, 1);
    }

    #[test]
    fn votes_from_strangers_are_rejected() {
        let f = solo_node();
        let stranger = sikka_crypto::Keypair::generate().unwrap();
        let vote = Vote::sign(&stranger, &f.chain_id(), f.genesis_fingerprint(), 1, 0, VoteKind::Precommit, Hash([1u8; 32])).unwrap();
        assert!(matches!(
            f.node.handle_vote(vote),
            Err(Error::UnknownVoter(_))
        ));
    }

    #[test]
    fn stale_votes_are_ignored_rather_than_erroring() {
        let f = solo_node();
        let vote = Vote::sign(f.node.keypair(), &f.chain_id(), f.genesis_fingerprint(), 0, 0, VoteKind::Precommit, Hash([1u8; 32])).unwrap();
        assert!(f.node.handle_vote(vote).unwrap().1.is_none());
    }

    #[test]
    fn a_snapshot_carries_the_whole_state() {
        let f = solo_node();
        let bob = Address([7u8; 32]);
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1_000, 0, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        f.node
            .submit_transaction(transfer(&f.alice, bob, 1_000, 1, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap();
        let (_, vote) = f.node.try_propose().unwrap().unwrap();
        seal_solo(&f.node, vote);

        let snapshot = f.node.snapshot().unwrap();
        snapshot.verify().unwrap();
        assert_eq!(snapshot.checkpoint.header.height, 1);
        assert_eq!(snapshot.accounts.len(), 3);
        assert!(snapshot.encoded_size() > 0);
    }

    #[test]
    fn a_transaction_the_pool_cannot_use_is_refused() {
        let f = solo_node();
        let bob = Address([7u8; 32]);
        // Nonce 5 with nothing pending leaves a gap.
        let error = f
            .node
            .submit_transaction(transfer(&f.alice, bob, 1, 5, &f.chain_id(), f.genesis_fingerprint()))
            .unwrap_err();
        assert!(matches!(error, Error::BadNonce { .. }));
    }

    #[test]
    fn missing_genesis_falls_back_to_the_baked_in_chain() {
        let dir = tempfile::tempdir().unwrap();
        let config = NodeConfig {
            data_dir: dir.path().to_path_buf(),
            genesis_path: dir.path().join("genesis.json"),
            key_path: dir.path().join("node_key.json"),
            ..NodeConfig::default()
        };

        let node = Node::open(config).unwrap();
        assert_eq!(node.health().chain_id, "sikka");
        assert_eq!(
            node.account(&sikka_common::admin_address())
                .unwrap()
                .balance,
            sikka_common::admin_allocation_chillar()
        );
    }
}
