//! The ledger: current state plus the rules that move it forward.
//!
//! Execution is split into three explicit phases so a validator can check a
//! proposal without trusting it and without committing to it:
//!
//! 1. [`Ledger::execute`] runs transactions against a read-only overlay and
//!    reports what *would* change.
//! 2. [`Ledger::stage`] folds those changes into the Merkle trees and yields the
//!    resulting state root, keeping an undo log.
//! 3. [`Ledger::commit`] persists them, or [`Ledger::rollback`] discards them if
//!    the root does not match the proposal.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use sikka_common::account::Account;
use sikka_common::bytes::{Address, Hash};
use sikka_common::checkpoint::{Checkpoint, CheckpointHeader};
use sikka_common::constants::{min_bond, CREDIT_COST_PER_TX};
use sikka_common::error::{Error, Result};
use sikka_common::genesis::GenesisConfig;
use sikka_common::inflation::{checkpoint_inflation, distribute_rewards};
use sikka_common::transaction::{Transaction, TxKind};
use sikka_common::validator::Validator;
use sikka_common::DEFAULT_CHECKPOINT_TX_INTERVAL;

use crate::smt::{Proof, Smt, UndoLog};
use crate::snapshot::{SnapshotArchive, SnapshotArchiveWriter, SnapshotHeader, SnapshotManifest};
use crate::store::{LedgerMeta, StateStore, WriteBatch};

/// Addresses that signed `checkpoint`, in the order stored on it.
fn signers_of(checkpoint: &Checkpoint) -> Vec<Address> {
    checkpoint
        .validator_signatures
        .iter()
        .map(|signature| signature.validator)
        .collect()
}

/// Where a checkpoint is being built, and when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionContext {
    /// Height of the checkpoint under construction.
    pub height: u64,
    /// Checkpoint timestamp. This — not any node's wall clock — is the clock
    /// transactions are validated against, so replay is deterministic.
    pub timestamp: u64,
    /// Round-robin proposer for this height; receives the rounding remainder of
    /// the inflation payout.
    pub proposer: Address,
    /// Validators proven to have equivocated, whose bonds are burned here.
    pub slashings: Vec<Address>,
}

impl ExecutionContext {
    pub fn new(height: u64, timestamp: u64, proposer: Address) -> Self {
        Self {
            height,
            timestamp,
            proposer,
            slashings: Vec::new(),
        }
    }
}

/// The result of executing a batch: what changed, and what was rejected.
#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub context: ExecutionContext,
    /// Transactions that succeeded, in the order they were applied.
    pub applied: Vec<Transaction>,
    /// Transactions that failed, with the reason. A proposer drops these; a
    /// verifier treats any rejection as grounds to vote against the proposal.
    pub rejected: Vec<(Hash, Error)>,
    /// Final values of every touched account.
    pub accounts: BTreeMap<Address, Account>,
    /// Final values of every touched validator; `None` means the record is gone.
    pub validators: BTreeMap<Address, Option<Validator>>,
    pub total_supply: u64,
    pub total_bonded: u64,
    /// CHILLAR minted by this checkpoint's inflation.
    pub minted: u64,
    pub rewards: Vec<(Address, u64)>,
    /// Bonds whose cooldown elapsed and were returned to their owners.
    pub released: Vec<Address>,
    /// Bonds burned by slashing.
    pub burned: u64,
}

impl ExecutionOutcome {
    pub fn tx_ids(&self) -> Vec<Hash> {
        self.applied.iter().map(|tx| tx.id()).collect()
    }

    pub fn tx_root(&self) -> Hash {
        CheckpointHeader::compute_tx_root(&self.tx_ids())
    }
}

/// Changes folded into the Merkle trees but not yet persisted.
#[derive(Debug)]
pub struct Staged {
    pub state_root: Hash,
    pub validator_root: Hash,
    pub outcome: ExecutionOutcome,
    accounts_undo: UndoLog,
    validators_undo: UndoLog,
}

/// Outcome of opening a database against a genesis file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisOutcome {
    /// The database was empty and has been initialised from genesis.
    Initialized(Box<Checkpoint>),
    /// The database already matched this genesis.
    Existing,
}

/// Read-through overlay used during execution.
///
/// Nothing here touches the database or the Merkle trees, so a failed or
/// rejected batch costs nothing to abandon.
struct Overlay<'a> {
    ledger: &'a Ledger,
    accounts: HashMap<Address, Option<Account>>,
    validators: HashMap<Address, Option<Validator>>,
}

impl<'a> Overlay<'a> {
    fn new(ledger: &'a Ledger) -> Self {
        Self {
            ledger,
            accounts: HashMap::new(),
            validators: HashMap::new(),
        }
    }

    fn account(&mut self, address: &Address) -> Result<Option<Account>> {
        if let Some(cached) = self.accounts.get(address) {
            return Ok(*cached);
        }
        let loaded = self.ledger.store.account(address)?;
        self.accounts.insert(*address, loaded);
        Ok(loaded)
    }

    fn set_account(&mut self, address: Address, account: Account) {
        self.accounts.insert(address, Some(account));
    }

    fn validator(&mut self, address: &Address) -> Result<Option<Validator>> {
        if let Some(cached) = self.validators.get(address) {
            return Ok(cached.clone());
        }
        let loaded = self.ledger.store.validator(address)?;
        self.validators.insert(*address, loaded.clone());
        Ok(loaded)
    }

    fn set_validator(&mut self, validator: Validator) {
        self.validators.insert(validator.address, Some(validator));
    }

    fn remove_validator(&mut self, address: Address) {
        self.validators.insert(address, None);
    }

    /// Credit an account, creating it if it does not exist.
    ///
    /// A newly created account starts with zero credits anchored at `now`, so
    /// funding a fresh address does not hand the recipient a spam allowance.
    fn credit(&mut self, address: Address, amount: u64, now: u64) -> Result<()> {
        let account = match self.account(&address)? {
            Some(mut account) => {
                account.balance = account
                    .balance
                    .checked_add(amount)
                    .ok_or(Error::BalanceOverflow)?;
                account
            }
            None => Account::new_funded(amount, now),
        };
        self.set_account(address, account);
        Ok(())
    }

    /// Every validator record, with overlay changes applied.
    fn all_validators(&mut self) -> Result<Vec<Validator>> {
        let mut merged: BTreeMap<Address, Validator> = BTreeMap::new();
        for validator in self.ledger.store.all_validators()? {
            merged.insert(validator.address, validator);
        }
        for (address, validator) in &self.validators {
            match validator {
                Some(validator) => {
                    merged.insert(*address, validator.clone());
                }
                None => {
                    merged.remove(address);
                }
            }
        }
        Ok(merged.into_values().collect())
    }
}

/// Current state, the trees that commit to it, and the rules that change it.
pub struct Ledger {
    store: StateStore,
    accounts: Smt,
    validators: Smt,
    meta: LedgerMeta,
}

impl std::fmt::Debug for Ledger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ledger")
            .field("chain_id", &self.meta.chain_id)
            .field("height", &self.meta.height)
            .field("state_root", &self.meta.state_root)
            .field("accounts", &self.accounts.len())
            .field("validators", &self.validators.len())
            .finish()
    }
}

impl Ledger {
    /// Open the ledger at `path`, initialising it from `genesis` if empty.
    ///
    /// A database built from a different genesis is rejected rather than
    /// silently reused: continuing on the wrong chain is worse than refusing to
    /// start.
    pub fn open(path: impl AsRef<Path>, genesis: &GenesisConfig) -> Result<(Self, GenesisOutcome)> {
        genesis.validate()?;
        let store = StateStore::open(path)?;

        if let Some(meta) = store.meta()? {
            if meta.genesis_fingerprint != genesis.fingerprint() {
                return Err(Error::GenesisMismatch);
            }
            let accounts = Smt::from_leaves(
                store
                    .all_accounts()?
                    .into_iter()
                    .map(|(a, acc)| (a.to_array(), acc.leaf_hash(&a))),
            );
            let validators = Smt::from_leaves(
                store
                    .all_validators()?
                    .into_iter()
                    .map(|v| (v.address.to_array(), v.leaf_hash())),
            );
            if accounts.root() != meta.state_root {
                return Err(Error::Storage(format!(
                    "database state root {} does not match its accounts ({})",
                    meta.state_root,
                    accounts.root()
                )));
            }
            if validators.root() != meta.validator_root {
                return Err(Error::Storage(format!(
                    "database validator root {} does not match its validators ({})",
                    meta.validator_root,
                    validators.root()
                )));
            }
            let ledger = Self {
                store,
                accounts,
                validators,
                meta,
            };
            return Ok((ledger, GenesisOutcome::Existing));
        }

        let mut ledger = Self {
            store,
            accounts: Smt::new(),
            validators: Smt::new(),
            meta: LedgerMeta {
                chain_id: genesis.chain_id.clone(),
                genesis_fingerprint: genesis.fingerprint(),
                checkpoint_tx_interval: genesis
                    .checkpoint_tx_interval
                    .unwrap_or(DEFAULT_CHECKPOINT_TX_INTERVAL),
                height: 0,
                last_checkpoint_hash: Hash::ZERO,
                last_checkpoint_time: genesis.timestamp,
                state_root: Hash::ZERO,
                validator_root: Hash::ZERO,
                total_supply: 0,
                total_bonded: 0,
                last_signers: Vec::new(),
            },
        };
        let checkpoint = ledger.init_genesis(genesis)?;
        Ok((ledger, GenesisOutcome::Initialized(Box::new(checkpoint))))
    }

    fn init_genesis(&mut self, genesis: &GenesisConfig) -> Result<Checkpoint> {
        let mut batch = WriteBatch::default();
        let mut accounts: BTreeMap<Address, Account> = BTreeMap::new();

        for allocation in &genesis.allocations {
            accounts.insert(
                allocation.to,
                Account {
                    balance: allocation.amount,
                    nonce: 0,
                    credits: GenesisConfig::initial_credits(),
                    last_regen_time: genesis.timestamp,
                },
            );
        }

        let mut total_bonded: u64 = 0;
        let mut validators: Vec<Validator> = Vec::new();
        for genesis_validator in &genesis.validators {
            let address = genesis_validator.address();
            let account = accounts
                .get_mut(&address)
                .ok_or_else(|| Error::InvalidGenesis(format!("validator {address} unfunded")))?;
            account.balance = account
                .balance
                .checked_sub(genesis_validator.bond)
                .ok_or_else(|| Error::InvalidGenesis(format!("validator {address} underfunded")))?;
            total_bonded += genesis_validator.bond;
            // Genesis validators vote from the first checkpoint after genesis.
            validators.push(Validator::new(
                genesis_validator.public_key.clone(),
                genesis_validator.bond,
                1,
            ));
        }

        for (address, account) in &accounts {
            self.accounts
                .insert(address.to_array(), account.leaf_hash(address));
            batch.accounts.push((*address, Some(*account)));
        }
        for validator in &validators {
            self.validators
                .insert(validator.address.to_array(), validator.leaf_hash());
            batch
                .validators
                .push((validator.address, Some(validator.clone())));
        }

        self.meta.total_supply = genesis.total_supply()?;
        self.meta.total_bonded = total_bonded;
        self.meta.state_root = self.accounts.root();
        self.meta.validator_root = self.validators.root();

        let header = CheckpointHeader {
            height: 0,
            prev_hash: Hash::ZERO,
            state_root: self.meta.state_root,
            validator_root: self.meta.validator_root,
            tx_root: CheckpointHeader::compute_tx_root(&[]),
            tx_count: 0,
            timestamp: genesis.timestamp,
            proposer: Address::ZERO,
            round: 0,
            total_supply: self.meta.total_supply,
            total_bonded: self.meta.total_bonded,
        };
        // Genesis needs no signatures: every node derives it from the same file
        // and refuses to run against a database built from a different one.
        let checkpoint = Checkpoint::new(header);
        self.meta.last_checkpoint_hash = checkpoint.hash();

        batch.meta = Some(self.meta.clone());
        self.store.write(&batch)?;
        Ok(checkpoint)
    }

    // ---- read access ----------------------------------------------------

    pub fn meta(&self) -> &LedgerMeta {
        &self.meta
    }

    pub fn height(&self) -> u64 {
        self.meta.height
    }

    pub fn state_root(&self) -> Hash {
        self.accounts.root()
    }

    pub fn validator_root(&self) -> Hash {
        self.validators.root()
    }

    pub fn total_supply(&self) -> u64 {
        self.meta.total_supply
    }

    pub fn total_bonded(&self) -> u64 {
        self.meta.total_bonded
    }

    pub fn checkpoint_tx_interval(&self) -> u32 {
        self.meta.checkpoint_tx_interval
    }

    pub fn account_count(&self) -> Result<u64> {
        self.store.account_count()
    }

    /// Account state, or an all-zero account if the address is unknown.
    pub fn account(&self, address: &Address) -> Result<Account> {
        Ok(self.store.account(address)?.unwrap_or_default())
    }

    pub fn account_opt(&self, address: &Address) -> Result<Option<Account>> {
        self.store.account(address)
    }

    pub fn all_accounts(&self) -> Result<Vec<(Address, Account)>> {
        self.store.all_accounts()
    }

    /// The nonce the next transaction from `address` must use.
    pub fn next_nonce(&self, address: &Address) -> Result<u64> {
        Ok(self.store.account(address)?.map(|a| a.nonce).unwrap_or(0))
    }

    pub fn validator(&self, address: &Address) -> Result<Option<Validator>> {
        self.store.validator(address)
    }

    pub fn validators(&self) -> Result<Vec<Validator>> {
        self.store.all_validators()
    }

    /// Validators eligible to vote at `height`, ascending by address.
    ///
    /// Address order — not bond order — is what makes round-robin proposer
    /// selection identical on every node.
    pub fn active_validators_at(&self, height: u64) -> Result<Vec<Validator>> {
        let mut active: Vec<Validator> = self
            .store
            .all_validators()?
            .into_iter()
            .filter(|v| v.is_active_at(height))
            .collect();
        active.sort_by_key(|a| a.address);
        Ok(active)
    }

    /// Validators eligible to vote on the next checkpoint.
    pub fn active_validators(&self) -> Result<Vec<Validator>> {
        self.active_validators_at(self.meta.height + 1)
    }

    /// An account with a Merkle proof against the current state root.
    pub fn account_proof(&self, address: &Address) -> Result<(Option<Account>, Proof)> {
        let account = self.store.account(address)?;
        Ok((account, self.accounts.proof(&address.to_array())))
    }

    /// Sum of every balance and every bond.
    ///
    /// Should always equal `total_supply`; used as a self-check after genesis,
    /// snapshot restore and in tests.
    pub fn audit_supply(&self) -> Result<u64> {
        let mut total: u64 = 0;
        for (_, account) in self.store.all_accounts()? {
            total = total
                .checked_add(account.balance)
                .ok_or(Error::BalanceOverflow)?;
        }
        for validator in self.store.all_validators()? {
            total = total
                .checked_add(validator.bond)
                .ok_or(Error::BalanceOverflow)?;
        }
        Ok(total)
    }

    // ---- execution ------------------------------------------------------

    /// Would `transactions` all apply, in this order, against current state?
    ///
    /// This is admission control, not execution: nothing is written and the
    /// result is thrown away. A transaction that cannot be afforded now can
    /// never be afforded by the checkpoint that would carry it, since inflation
    /// pays validators rather than senders, so keeping it out of the mempool
    /// costs nothing and refusing to is a free way for anyone to fill every
    /// node's mempool — credits are only charged when a transaction executes.
    ///
    /// The rules come from `apply_transaction`, the same code a checkpoint runs,
    /// so admission cannot drift away from execution.
    pub fn would_apply(&self, transactions: &[Transaction], timestamp: u64) -> Result<()> {
        let mut overlay = Overlay::new(self);
        let context = ExecutionContext::new(self.meta.height + 1, timestamp, Address::default());
        for tx in transactions {
            Self::apply_transaction(&mut overlay, tx, &context, self.meta.total_supply)?;
        }
        Ok(())
    }

    /// Run `transactions` against an overlay of current state.
    ///
    /// Signatures are **not** re-checked here: they are verified once when a
    /// transaction enters the mempool or arrives inside a proposal. Verifying
    /// 10,000 ML-DSA-87 signatures twice per checkpoint would dominate the cost
    /// of everything else.
    pub fn execute(
        &self,
        transactions: &[Transaction],
        context: ExecutionContext,
    ) -> Result<ExecutionOutcome> {
        let mut overlay = Overlay::new(self);
        let mut outcome = ExecutionOutcome {
            context: context.clone(),
            applied: Vec::new(),
            rejected: Vec::new(),
            accounts: BTreeMap::new(),
            validators: BTreeMap::new(),
            total_supply: self.meta.total_supply,
            total_bonded: self.meta.total_bonded,
            minted: 0,
            rewards: Vec::new(),
            released: Vec::new(),
            burned: 0,
        };

        // 1. Slash equivocators before they can be paid.
        for address in &context.slashings {
            if let Some(mut validator) = overlay.validator(address)? {
                if validator.is_slashable() {
                    outcome.burned += validator.bond;
                    outcome.total_supply = outcome.total_supply.saturating_sub(validator.bond);
                    validator.bond = 0;
                    validator.slashed = true;
                    overlay.set_validator(validator);
                }
            }
        }

        // 2. Apply transactions in the order given.
        for tx in transactions {
            match Self::apply_transaction(&mut overlay, tx, &context, outcome.total_supply) {
                Ok(()) => outcome.applied.push(tx.clone()),
                Err(e) => outcome.rejected.push((tx.id(), e)),
            }
        }

        // 3. Return bonds whose cooldown has elapsed.
        for validator in overlay.all_validators()? {
            if validator.is_releasable(context.timestamp) {
                overlay.credit(validator.address, validator.bond, context.timestamp)?;
                overlay.remove_validator(validator.address);
                outcome.released.push(validator.address);
            }
        }

        // 4. Mint inflation for the elapsed period and pay validators that
        // signed the previous checkpoint (still active). Offline bonded stake
        // is not burned — it simply earns nothing this round. An empty signer
        // list (genesis) pays the whole active set; if every prior signer has
        // since left, fall back to the active set so inflation still lands.
        let elapsed = context
            .timestamp
            .saturating_sub(self.meta.last_checkpoint_time);
        let minted = checkpoint_inflation(outcome.total_supply, elapsed);
        let active: Vec<(Address, u64)> = overlay
            .all_validators()?
            .into_iter()
            .filter(|v| v.is_active_at(context.height))
            .map(|v| (v.address, v.bond))
            .collect();
        let eligible: Vec<(Address, u64)> = if self.meta.last_signers.is_empty() {
            active
        } else {
            let paid: std::collections::HashSet<Address> =
                self.meta.last_signers.iter().copied().collect();
            let filtered: Vec<(Address, u64)> = active
                .iter()
                .copied()
                .filter(|(address, _)| paid.contains(address))
                .collect();
            if filtered.is_empty() {
                active
            } else {
                filtered
            }
        };
        let rewards = distribute_rewards(minted, &eligible, &context.proposer);
        for (address, amount) in &rewards {
            overlay.credit(*address, *amount, context.timestamp)?;
        }
        let paid: u64 = rewards.iter().map(|(_, amount)| amount).sum();
        outcome.minted = paid;
        outcome.rewards = rewards;
        outcome.total_supply = outcome
            .total_supply
            .checked_add(paid)
            .ok_or(Error::BalanceOverflow)?;

        // 5. Collect final values.
        for (address, account) in overlay.accounts {
            if let Some(account) = account {
                outcome.accounts.insert(address, account);
            }
        }
        for (address, validator) in overlay.validators {
            outcome.validators.insert(address, validator);
        }
        outcome.total_bonded = {
            let mut bonded: u64 = 0;
            let changed: BTreeMap<&Address, &Option<Validator>> =
                outcome.validators.iter().collect();
            for validator in self.store.all_validators()? {
                if !changed.contains_key(&validator.address) {
                    bonded += validator.bond;
                }
            }
            for validator in outcome.validators.values().flatten() {
                bonded += validator.bond;
            }
            bonded
        };

        Ok(outcome)
    }

    fn apply_transaction(
        overlay: &mut Overlay<'_>,
        tx: &Transaction,
        context: &ExecutionContext,
        total_supply: u64,
    ) -> Result<()> {
        // The checkpoint timestamp is the clock: using each validator's wall
        // clock here would make execution non-deterministic.
        tx.check_static(context.timestamp)?;

        let mut sender = overlay
            .account(&tx.from)?
            .ok_or(Error::InsufficientBalance {
                address: tx.from,
                balance: 0,
                needed: tx.amount,
            })?;

        if sender.nonce != tx.nonce {
            return Err(Error::BadNonce {
                address: tx.from,
                expected: sender.nonce,
                actual: tx.nonce,
            });
        }

        // Credits regenerate from the transaction's own signed timestamp.
        sender.settle_credits(tx.timestamp);
        if sender.credits < CREDIT_COST_PER_TX {
            return Err(Error::InsufficientCredits {
                address: tx.from,
                credits: sender.credits,
                needed: CREDIT_COST_PER_TX,
            });
        }

        match tx.kind {
            TxKind::Transfer => {
                if sender.balance < tx.amount {
                    return Err(Error::InsufficientBalance {
                        address: tx.from,
                        balance: sender.balance,
                        needed: tx.amount,
                    });
                }
                sender.balance -= tx.amount;
            }
            TxKind::Bond => {
                if sender.balance < tx.amount {
                    return Err(Error::InsufficientBalance {
                        address: tx.from,
                        balance: sender.balance,
                        needed: tx.amount,
                    });
                }
                let existing = overlay.validator(&tx.from)?;
                let new_bond = existing
                    .as_ref()
                    .map(|v| v.bond)
                    .unwrap_or(0)
                    .checked_add(tx.amount)
                    .ok_or_else(|| Error::Other("bond overflow".into()))?;
                let minimum = min_bond(total_supply);
                if new_bond < minimum {
                    return Err(Error::BondTooSmall {
                        bond: new_bond,
                        minimum,
                    });
                }
                match existing {
                    Some(validator) if validator.slashed => {
                        return Err(Error::ValidatorSlashed(tx.from))
                    }
                    Some(validator) if validator.unbonding_since.is_some() => {
                        return Err(Error::AlreadyUnbonding(tx.from))
                    }
                    Some(mut validator) => {
                        validator.bond = new_bond;
                        overlay.set_validator(validator);
                    }
                    None => {
                        // A bond takes effect at the next checkpoint boundary,
                        // so the voting set for this height is already fixed.
                        overlay.set_validator(Validator::new(
                            tx.public_key.clone(),
                            new_bond,
                            context.height + 1,
                        ));
                    }
                }
                sender.balance -= tx.amount;
            }
            TxKind::Unbond => {
                let mut validator = overlay
                    .validator(&tx.from)?
                    .ok_or(Error::NotAValidator(tx.from))?;
                if validator.slashed {
                    return Err(Error::ValidatorSlashed(tx.from));
                }
                if validator.unbonding_since.is_some() {
                    return Err(Error::AlreadyUnbonding(tx.from));
                }
                validator.unbonding_since = Some(tx.timestamp);
                overlay.set_validator(validator);
            }
        }

        sender.nonce += 1;
        sender.credits -= CREDIT_COST_PER_TX;
        overlay.set_account(tx.from, sender);

        if tx.kind == TxKind::Transfer {
            overlay.credit(tx.to, tx.amount, tx.timestamp)?;
        }
        Ok(())
    }

    // ---- staging and commit ---------------------------------------------

    /// Fold an outcome into the Merkle trees and report the resulting roots.
    pub fn stage(&mut self, outcome: ExecutionOutcome) -> Staged {
        let account_updates: Vec<(crate::smt::Key, Option<Hash>)> = outcome
            .accounts
            .iter()
            .map(|(address, account)| (address.to_array(), Some(account.leaf_hash(address))))
            .collect();
        let validator_updates: Vec<(crate::smt::Key, Option<Hash>)> = outcome
            .validators
            .iter()
            .map(|(address, validator)| {
                (
                    address.to_array(),
                    validator.as_ref().map(|v| v.leaf_hash()),
                )
            })
            .collect();

        let accounts_undo = self.accounts.apply(&account_updates);
        let validators_undo = self.validators.apply(&validator_updates);

        Staged {
            state_root: self.accounts.root(),
            validator_root: self.validators.root(),
            outcome,
            accounts_undo,
            validators_undo,
        }
    }

    /// Undo a staged change, restoring the previous roots exactly.
    pub fn rollback(&mut self, staged: Staged) -> ExecutionOutcome {
        self.validators.revert(staged.validators_undo);
        self.accounts.revert(staged.accounts_undo);
        debug_assert_eq!(self.accounts.root(), self.meta.state_root);
        debug_assert_eq!(self.validators.root(), self.meta.validator_root);
        staged.outcome
    }

    /// Persist a staged change together with the checkpoint that finalizes it.
    ///
    /// The checkpoint must commit to exactly the staged roots; on any storage
    /// failure the Merkle trees are rolled back so memory and disk stay in step.
    pub fn commit(&mut self, staged: Staged, checkpoint: &Checkpoint) -> Result<()> {
        if checkpoint.header.state_root != staged.state_root {
            let expected = checkpoint.header.state_root;
            let computed = staged.state_root;
            self.rollback(staged);
            return Err(Error::StateRootMismatch { expected, computed });
        }
        if checkpoint.header.validator_root != staged.validator_root {
            let expected = checkpoint.header.validator_root;
            let computed = staged.validator_root;
            self.rollback(staged);
            return Err(Error::StateRootMismatch { expected, computed });
        }

        let mut batch = WriteBatch::default();
        for (address, account) in &staged.outcome.accounts {
            batch.accounts.push((*address, Some(*account)));
        }
        for (address, validator) in &staged.outcome.validators {
            batch.validators.push((*address, validator.clone()));
        }

        let meta = LedgerMeta {
            chain_id: self.meta.chain_id.clone(),
            genesis_fingerprint: self.meta.genesis_fingerprint,
            checkpoint_tx_interval: self.meta.checkpoint_tx_interval,
            height: checkpoint.header.height,
            last_checkpoint_hash: checkpoint.hash(),
            last_checkpoint_time: checkpoint.header.timestamp,
            state_root: staged.state_root,
            validator_root: staged.validator_root,
            total_supply: staged.outcome.total_supply,
            total_bonded: staged.outcome.total_bonded,
            last_signers: signers_of(checkpoint),
        };
        batch.meta = Some(meta.clone());

        match self.store.write(&batch) {
            Ok(()) => {
                self.meta = meta;
                Ok(())
            }
            Err(e) => {
                self.rollback(staged);
                Err(e)
            }
        }
    }

    /// Build the header for a checkpoint over `staged`.
    pub fn build_header(
        &self,
        staged: &Staged,
        prev_hash: Hash,
        proposer: Address,
        round: u32,
    ) -> CheckpointHeader {
        CheckpointHeader {
            height: staged.outcome.context.height,
            prev_hash,
            state_root: staged.state_root,
            validator_root: staged.validator_root,
            tx_root: staged.outcome.tx_root(),
            tx_count: staged.outcome.applied.len() as u32,
            timestamp: staged.outcome.context.timestamp,
            proposer,
            round,
            total_supply: staged.outcome.total_supply,
            total_bonded: staged.outcome.total_bonded,
        }
    }

    // ---- snapshots -------------------------------------------------------

    /// Materialize the current state as a cached chunked snapshot archive.
    ///
    /// Records are read and compressed incrementally, so archive generation
    /// never constructs the giant JSON value used by the old transport.
    pub fn snapshot_archive(
        &self,
        checkpoint: Checkpoint,
        root: impl AsRef<Path>,
    ) -> Result<SnapshotManifest> {
        if checkpoint.header.height != self.meta.height
            || checkpoint.header.state_root != self.meta.state_root
            || checkpoint.header.validator_root != self.meta.validator_root
        {
            return Err(Error::Other(
                "checkpoint does not describe the ledger being snapshotted".into(),
            ));
        }
        let root = root.as_ref();
        let snapshot_id = checkpoint.hash();
        if let Some(manifest) = SnapshotArchive::load_if_present(root, &snapshot_id)? {
            return Ok(manifest);
        }
        let mut writer = SnapshotArchiveWriter::create(
            root,
            SnapshotHeader {
                chain_id: self.meta.chain_id.clone(),
                genesis_fingerprint: self.meta.genesis_fingerprint,
                checkpoint_tx_interval: self.meta.checkpoint_tx_interval,
                checkpoint,
            },
        )?;
        self.store
            .visit_accounts(|address, account| writer.push_account(address, account))?;
        self.store
            .visit_validators(|validator| writer.push_validator(&validator))?;
        writer.finish()
    }

    /// Full state dump for fast sync.
    pub fn snapshot(&self, checkpoint: Checkpoint) -> Result<StateSnapshot> {
        Ok(StateSnapshot {
            chain_id: self.meta.chain_id.clone(),
            genesis_fingerprint: self.meta.genesis_fingerprint,
            checkpoint_tx_interval: self.meta.checkpoint_tx_interval,
            checkpoint,
            accounts: self.store.all_accounts()?,
            validators: self.store.all_validators()?,
        })
    }

    /// Create a ledger directly from a verified snapshot.
    ///
    /// The snapshot must already have been checked against a finalized
    /// checkpoint's signatures; [`StateSnapshot::verify`] checks the state it
    /// contains actually hashes to the root that checkpoint commits to.
    pub fn restore(path: impl AsRef<Path>, snapshot: &StateSnapshot) -> Result<Self> {
        snapshot.verify()?;
        let store = StateStore::open(path)?;
        if let Some(existing) = store.meta()? {
            if existing.genesis_fingerprint != snapshot.genesis_fingerprint {
                return Err(Error::GenesisMismatch);
            }
        }

        let mut batch = WriteBatch::default();
        let mut accounts = Smt::new();
        for (address, account) in &snapshot.accounts {
            accounts.insert(address.to_array(), account.leaf_hash(address));
            batch.accounts.push((*address, Some(*account)));
        }
        let mut validators = Smt::new();
        for validator in &snapshot.validators {
            validators.insert(validator.address.to_array(), validator.leaf_hash());
            batch
                .validators
                .push((validator.address, Some(validator.clone())));
        }

        let meta = LedgerMeta {
            chain_id: snapshot.chain_id.clone(),
            genesis_fingerprint: snapshot.genesis_fingerprint,
            checkpoint_tx_interval: snapshot.checkpoint_tx_interval,
            height: snapshot.checkpoint.header.height,
            last_checkpoint_hash: snapshot.checkpoint.hash(),
            last_checkpoint_time: snapshot.checkpoint.header.timestamp,
            state_root: snapshot.checkpoint.header.state_root,
            validator_root: snapshot.checkpoint.header.validator_root,
            total_supply: snapshot.checkpoint.header.total_supply,
            total_bonded: snapshot.checkpoint.header.total_bonded,
            last_signers: signers_of(&snapshot.checkpoint),
        };
        batch.meta = Some(meta.clone());
        store.write(&batch)?;

        Ok(Self {
            store,
            accounts,
            validators,
            meta,
        })
    }

    /// Replace this ledger's entire state with a verified snapshot.
    ///
    /// The in-place variant of [`Ledger::restore`], for a node that is already
    /// running and has fallen too far behind to catch up by replay. The
    /// database is rewritten in a single transaction, so a crash mid-sync
    /// leaves the old state intact rather than a half-applied mixture.
    pub fn apply_snapshot(&mut self, snapshot: &StateSnapshot) -> Result<()> {
        snapshot.verify()?;
        if snapshot.genesis_fingerprint != self.meta.genesis_fingerprint {
            return Err(Error::GenesisMismatch);
        }
        if snapshot.chain_id != self.meta.chain_id {
            return Err(Error::ChainIdMismatch {
                expected: self.meta.chain_id.clone(),
                actual: snapshot.chain_id.clone(),
            });
        }
        if snapshot.checkpoint.header.height <= self.meta.height {
            return Err(Error::Other(format!(
                "snapshot at height {} is not ahead of local height {}",
                snapshot.checkpoint.header.height, self.meta.height
            )));
        }

        let meta = LedgerMeta {
            chain_id: self.meta.chain_id.clone(),
            genesis_fingerprint: self.meta.genesis_fingerprint,
            checkpoint_tx_interval: snapshot.checkpoint_tx_interval,
            height: snapshot.checkpoint.header.height,
            last_checkpoint_hash: snapshot.checkpoint.hash(),
            last_checkpoint_time: snapshot.checkpoint.header.timestamp,
            state_root: snapshot.checkpoint.header.state_root,
            validator_root: snapshot.checkpoint.header.validator_root,
            total_supply: snapshot.checkpoint.header.total_supply,
            total_bonded: snapshot.checkpoint.header.total_bonded,
            last_signers: signers_of(&snapshot.checkpoint),
        };
        self.store
            .replace_all(&snapshot.accounts, &snapshot.validators, &meta)?;

        self.accounts = Smt::from_leaves(
            snapshot
                .accounts
                .iter()
                .map(|(a, acc)| (a.to_array(), acc.leaf_hash(a))),
        );
        self.validators = Smt::from_leaves(
            snapshot
                .validators
                .iter()
                .map(|v| (v.address.to_array(), v.leaf_hash())),
        );
        self.meta = meta;
        Ok(())
    }
}

/// A complete state dump plus the checkpoint that attests to it.
///
/// This is all a new node needs: no transaction history, no old checkpoints.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StateSnapshot {
    pub chain_id: String,
    pub genesis_fingerprint: Hash,
    pub checkpoint_tx_interval: u32,
    pub checkpoint: Checkpoint,
    pub accounts: Vec<(Address, Account)>,
    pub validators: Vec<Validator>,
}

impl StateSnapshot {
    /// Rebuild both Merkle trees and check them against the checkpoint.
    ///
    /// Also re-derives total supply from the dump, so a snapshot cannot smuggle
    /// in coins that the accounts do not account for.
    pub fn verify(&self) -> Result<()> {
        if self.accounts.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
            return Err(Error::Other(
                "snapshot accounts are not strictly ordered and unique".into(),
            ));
        }
        if self
            .validators
            .windows(2)
            .any(|pair| pair[0].address >= pair[1].address)
        {
            return Err(Error::Other(
                "snapshot validators are not strictly ordered and unique".into(),
            ));
        }
        let accounts = Smt::from_leaves(
            self.accounts
                .iter()
                .map(|(a, acc)| (a.to_array(), acc.leaf_hash(a))),
        );
        if accounts.root() != self.checkpoint.header.state_root {
            return Err(Error::StateRootMismatch {
                expected: self.checkpoint.header.state_root,
                computed: accounts.root(),
            });
        }

        let validators = Smt::from_leaves(
            self.validators
                .iter()
                .map(|v| (v.address.to_array(), v.leaf_hash())),
        );
        if validators.root() != self.checkpoint.header.validator_root {
            return Err(Error::StateRootMismatch {
                expected: self.checkpoint.header.validator_root,
                computed: validators.root(),
            });
        }

        let mut supply: u64 = 0;
        for (_, account) in &self.accounts {
            supply = supply
                .checked_add(account.balance)
                .ok_or(Error::BalanceOverflow)?;
        }
        let mut bonded: u64 = 0;
        for validator in &self.validators {
            supply = supply
                .checked_add(validator.bond)
                .ok_or(Error::BalanceOverflow)?;
            bonded = bonded
                .checked_add(validator.bond)
                .ok_or(Error::BalanceOverflow)?;
        }
        if supply != self.checkpoint.header.total_supply {
            return Err(Error::Other(format!(
                "snapshot balances sum to {supply} but the checkpoint claims {}",
                self.checkpoint.header.total_supply
            )));
        }
        if bonded != self.checkpoint.header.total_bonded {
            return Err(Error::Other(format!(
                "snapshot bonds sum to {bonded} but the checkpoint claims {}",
                self.checkpoint.header.total_bonded
            )));
        }
        Ok(())
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Approximate encoded size, for logging sync progress.
    pub fn encoded_size(&self) -> usize {
        self.accounts.len() * 60 + self.validators.len() * 2_700
    }
}
