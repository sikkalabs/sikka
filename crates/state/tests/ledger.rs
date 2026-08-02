//! Ledger execution tests: transfers, credits, bonding, inflation, snapshots.

use sikka_common::bytes::{Address, PublicKey};
use sikka_common::checkpoint::Checkpoint;
use sikka_common::constants::{MAX_CREDITS, UNBONDING_SECS};
use sikka_common::error::Error;
use sikka_common::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};
use sikka_common::transaction::Transaction;
use sikka_crypto::Keypair;
use sikka_state::ledger::{ExecutionContext, GenesisOutcome};
use sikka_state::{Ledger, StateSnapshot};

const GENESIS_TIME: u64 = 1_700_000_000;
const ALLOCATION: u64 = 10_000_000_000;
const BOND: u64 = 1_000_000_000;

struct Fixture {
    ledger: Ledger,
    genesis_checkpoint: Checkpoint,
    validator: Keypair,
    alice: Keypair,
    bob: Keypair,
    _dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let validator = Keypair::generate().unwrap();
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();

        let validator_pk = PublicKey::new(*validator.public_bytes());
        let genesis = GenesisConfig {
            chain_id: "sikka-test".into(),
            timestamp: GENESIS_TIME,
            allocations: vec![
                GenesisAllocation {
                    to: validator_pk.address(),
                    amount: ALLOCATION,
                },
                GenesisAllocation {
                    to: PublicKey::new(*alice.public_bytes()).address(),
                    amount: ALLOCATION,
                },
            ],
            validators: vec![GenesisValidator {
                public_key: validator_pk,
                bond: BOND,
                endpoint: None,
            }],
            checkpoint_tx_interval: Some(4),
        max_missed_proposer_slots: None,
        };

        let dir = tempfile::tempdir().unwrap();
        let (ledger, outcome) = Ledger::open(dir.path().join("state.redb"), &genesis).unwrap();
        let genesis_checkpoint = match outcome {
            GenesisOutcome::Initialized(cp) => *cp,
            GenesisOutcome::Existing => panic!("expected a fresh database"),
        };

        Self {
            ledger,
            genesis_checkpoint,
            validator,
            alice,
            bob,
            _dir: dir,
        }
    }

    fn address(kp: &Keypair) -> Address {
        PublicKey::new(*kp.public_bytes()).address()
    }

    fn chain_id(&self) -> &str {
        &self.ledger.meta().chain_id
    }

    /// Execute, stage, wrap in a checkpoint and commit — the happy path a
    /// proposer and every verifier follow.
    fn apply(&mut self, txs: &[Transaction], timestamp: u64) -> sikka_state::ExecutionOutcome {
        let height = self.ledger.height() + 1;
        let proposer = Self::address(&self.validator);
        let context = ExecutionContext::new(height, timestamp, proposer);
        let outcome = self.ledger.execute(txs, context).unwrap();
        let prev = self.ledger.meta().last_checkpoint_hash;
        let staged = self.ledger.stage(outcome);
        let header = self.ledger.build_header(&staged, prev, proposer, 0);
        let checkpoint = Checkpoint::new(header);
        let outcome = staged.outcome.clone();
        self.ledger.commit(staged, &checkpoint).unwrap();
        outcome
    }
}

#[test]
fn genesis_creates_the_committed_state() {
    let f = Fixture::new();
    let validator = Fixture::address(&f.validator);
    let alice = Fixture::address(&f.alice);

    assert_eq!(f.ledger.height(), 0);
    assert_eq!(f.ledger.total_supply(), ALLOCATION * 2);
    assert_eq!(f.ledger.total_bonded(), BOND);
    assert_eq!(f.ledger.audit_supply().unwrap(), ALLOCATION * 2);

    // The validator's bond is locked out of its allocation, not minted.
    assert_eq!(
        f.ledger.account(&validator).unwrap().balance,
        ALLOCATION - BOND
    );
    assert_eq!(f.ledger.account(&alice).unwrap().balance, ALLOCATION);
    assert_eq!(f.ledger.account(&alice).unwrap().credits, MAX_CREDITS);

    assert_eq!(
        f.genesis_checkpoint.header.state_root,
        f.ledger.state_root()
    );
    assert_eq!(f.genesis_checkpoint.header.total_supply, ALLOCATION * 2);
    assert_eq!(f.ledger.active_validators().unwrap().len(), 1);
}

#[test]
fn reopening_keeps_state_and_rejects_a_different_genesis() {
    let validator = Keypair::generate().unwrap();
    let validator_pk = PublicKey::new(*validator.public_bytes());
    let genesis = GenesisConfig {
        chain_id: "sikka-test".into(),
        timestamp: GENESIS_TIME,
        allocations: vec![GenesisAllocation {
            to: validator_pk.address(),
            amount: ALLOCATION,
        }],
        validators: vec![GenesisValidator {
            public_key: validator_pk.clone(),
            bond: BOND,
            endpoint: None,
        }],
        checkpoint_tx_interval: Some(4),
        max_missed_proposer_slots: None,
    };

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state.redb");
    {
        let (ledger, outcome) = Ledger::open(&path, &genesis).unwrap();
        assert!(matches!(outcome, GenesisOutcome::Initialized(_)));
        assert_eq!(ledger.total_supply(), ALLOCATION);
    }
    {
        let (ledger, outcome) = Ledger::open(&path, &genesis).unwrap();
        assert_eq!(outcome, GenesisOutcome::Existing);
        assert_eq!(ledger.total_supply(), ALLOCATION);
        assert_eq!(ledger.audit_supply().unwrap(), ALLOCATION);
    }

    let mut other = genesis.clone();
    other.timestamp += 1;
    assert_eq!(
        Ledger::open(&path, &other).unwrap_err(),
        Error::GenesisMismatch
    );
}

#[test]
fn transfer_moves_value_and_advances_nonce() {
    let mut f = Fixture::new();
    let alice = Fixture::address(&f.alice);
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;

    let tx = Transaction::transfer(&f.alice, bob, 5_000, 0, now, f.chain_id()).unwrap();
    let outcome = f.apply(&[tx], now);

    assert_eq!(outcome.applied.len(), 1);
    assert!(outcome.rejected.is_empty());
    assert_eq!(
        f.ledger.account(&alice).unwrap().balance,
        ALLOCATION - 5_000
    );
    assert_eq!(f.ledger.account(&alice).unwrap().nonce, 1);
    assert_eq!(f.ledger.account(&bob).unwrap().balance, 5_000);
    assert_eq!(f.ledger.height(), 1);

    // A brand new account starts with no spam allowance.
    assert_eq!(f.ledger.account(&bob).unwrap().credits, 0);
    assert_eq!(f.ledger.account(&bob).unwrap().last_regen_time, now);
}

#[test]
fn credits_are_spent_and_regenerate() {
    let mut f = Fixture::new();
    let alice = Fixture::address(&f.alice);
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;

    let txs: Vec<Transaction> = (0..3)
        .map(|nonce| Transaction::transfer(&f.alice, bob, 10, nonce, now, f.chain_id()).unwrap())
        .collect();
    f.apply(&txs, now);

    // Alice had a full quota at genesis and spent three credits.
    assert_eq!(f.ledger.account(&alice).unwrap().credits, MAX_CREDITS - 3);
    assert_eq!(f.ledger.account(&alice).unwrap().nonce, 3);

    // Ten minutes later ten credits have come back, capped at the maximum.
    let later = now + 60 * 10;
    assert_eq!(
        f.ledger.account(&alice).unwrap().credits_at(later),
        MAX_CREDITS
    );
}

#[test]
fn spending_more_than_the_credit_quota_is_rejected() {
    let mut f = Fixture::new();
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;

    // Bob receives funds, so he exists but has zero credits.
    f.apply(
        &[Transaction::transfer(&f.alice, bob, 1_000, 0, now, f.chain_id()).unwrap()],
        now,
    );

    let tx = Transaction::transfer(&f.bob, Address([7u8; 32]), 10, 0, now, f.chain_id()).unwrap();
    let height = f.ledger.height() + 1;
    let context = ExecutionContext::new(height, now, Fixture::address(&f.validator));
    let outcome = f.ledger.execute(&[tx], context).unwrap();

    assert!(outcome.applied.is_empty());
    assert!(matches!(
        outcome.rejected[0].1,
        Error::InsufficientCredits { .. }
    ));

    // One minute later Bob has exactly one credit and can spend.
    let later = now + 60;
    let tx = Transaction::transfer(&f.bob, Address([7u8; 32]), 10, 0, later, f.chain_id()).unwrap();
    let outcome = f.apply(&[tx], later);
    assert_eq!(outcome.applied.len(), 1);
}

#[test]
fn invalid_transactions_are_rejected_without_touching_state() {
    let f = Fixture::new();
    let alice = Fixture::address(&f.alice);
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;
    let before = f.ledger.state_root();

    let cases = vec![
        // Wrong nonce.
        Transaction::transfer(&f.alice, bob, 10, 5, now, f.chain_id()).unwrap(),
        // More than the balance.
        Transaction::transfer(&f.alice, bob, ALLOCATION * 2, 0, now, f.chain_id()).unwrap(),
        // Timestamp far outside the tolerance window.
        Transaction::transfer(&f.alice, bob, 10, 0, now + 3_600, f.chain_id()).unwrap(),
        // Unknown sender.
        Transaction::transfer(&f.bob, alice, 10, 0, now, f.chain_id()).unwrap(),
        // Unbond from a non-validator.
        Transaction::unbond(&f.alice, 0, now, f.chain_id()).unwrap(),
    ];

    for tx in cases {
        let context = ExecutionContext::new(1, now, Fixture::address(&f.validator));
        let outcome = f.ledger.execute(&[tx], context).unwrap();
        assert!(
            outcome.applied.is_empty(),
            "expected rejection: {:?}",
            outcome.rejected
        );
        assert_eq!(outcome.rejected.len(), 1);
    }
    assert_eq!(f.ledger.state_root(), before);
}

#[test]
fn a_rejected_transaction_does_not_stop_the_batch() {
    let mut f = Fixture::new();
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;

    let good = Transaction::transfer(&f.alice, bob, 100, 0, now, f.chain_id()).unwrap();
    let bad = Transaction::transfer(&f.alice, bob, 100, 9, now, f.chain_id()).unwrap();
    let also_good = Transaction::transfer(&f.alice, bob, 100, 1, now, f.chain_id()).unwrap();

    let outcome = f.apply(&[good, bad, also_good], now);
    assert_eq!(outcome.applied.len(), 2);
    assert_eq!(outcome.rejected.len(), 1);
    assert_eq!(f.ledger.account(&bob).unwrap().balance, 200);
}

#[test]
fn staging_is_reversible() {
    let mut f = Fixture::new();
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;
    let root_before = f.ledger.state_root();
    let validator_root_before = f.ledger.validator_root();

    let tx = Transaction::transfer(&f.alice, bob, 1_000, 0, now, f.chain_id()).unwrap();
    let context = ExecutionContext::new(1, now, Fixture::address(&f.validator));
    let outcome = f.ledger.execute(&[tx], context).unwrap();

    let staged = f.ledger.stage(outcome);
    assert_ne!(staged.state_root, root_before);

    f.ledger.rollback(staged);
    assert_eq!(f.ledger.state_root(), root_before);
    assert_eq!(f.ledger.validator_root(), validator_root_before);
    assert_eq!(f.ledger.account(&bob).unwrap().balance, 0);
}

#[test]
fn execution_is_deterministic_across_two_ledgers() {
    let mut a = Fixture::new();
    let now = GENESIS_TIME + 600;

    // Rebuild the same genesis on a second database.
    let genesis = GenesisConfig {
        chain_id: "sikka-test".into(),
        timestamp: GENESIS_TIME,
        allocations: vec![
            GenesisAllocation {
                to: PublicKey::new(*a.validator.public_bytes()).address(),
                amount: ALLOCATION,
            },
            GenesisAllocation {
                to: PublicKey::new(*a.alice.public_bytes()).address(),
                amount: ALLOCATION,
            },
        ],
        validators: vec![GenesisValidator {
            public_key: PublicKey::new(*a.validator.public_bytes()),
            bond: BOND,
            endpoint: None,
        }],
        checkpoint_tx_interval: Some(4),
        max_missed_proposer_slots: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let (mut b, _) = Ledger::open(dir.path().join("state.redb"), &genesis).unwrap();
    assert_eq!(a.ledger.state_root(), b.state_root());

    let bob = Fixture::address(&a.bob);
    let txs: Vec<Transaction> = (0..5)
        .map(|nonce| Transaction::transfer(&a.alice, bob, 100 + nonce, nonce, now, a.chain_id()).unwrap())
        .collect();

    let proposer = Fixture::address(&a.validator);
    a.apply(&txs, now);

    let context = ExecutionContext::new(1, now, proposer);
    let outcome = b.execute(&txs, context).unwrap();
    let prev = b.meta().last_checkpoint_hash;
    let staged = b.stage(outcome);
    let header = b.build_header(&staged, prev, proposer, 0);
    b.commit(staged, &Checkpoint::new(header)).unwrap();

    assert_eq!(a.ledger.state_root(), b.state_root());
    assert_eq!(a.ledger.validator_root(), b.validator_root());
    assert_eq!(a.ledger.total_supply(), b.total_supply());
    assert_eq!(
        a.ledger.meta().last_checkpoint_hash,
        b.meta().last_checkpoint_hash
    );
}

#[test]
fn bonding_makes_a_validator_at_the_next_boundary() {
    let mut f = Fixture::new();
    let alice = Fixture::address(&f.alice);
    let now = GENESIS_TIME + 600;

    let tx = Transaction::bond(&f.alice, BOND, 0, now, f.chain_id()).unwrap();
    f.apply(&[tx], now);

    let validator = f.ledger.validator(&alice).unwrap().unwrap();
    assert_eq!(validator.bond, BOND);
    assert_eq!(validator.active_from, 2);
    assert_eq!(f.ledger.account(&alice).unwrap().balance, ALLOCATION - BOND);

    // Not yet voting at height 1, but voting from height 2.
    assert!(!f
        .ledger
        .active_validators_at(1)
        .unwrap()
        .iter()
        .any(|v| v.address == alice));
    assert!(f
        .ledger
        .active_validators_at(2)
        .unwrap()
        .iter()
        .any(|v| v.address == alice));

    // Supply is unchanged: bonding locks coins, it does not destroy them.
    assert_eq!(f.ledger.audit_supply().unwrap(), f.ledger.total_supply());
}

#[test]
fn bond_below_the_minimum_is_rejected() {
    let mut f = Fixture::new();
    let now = GENESIS_TIME + 600;
    // Minimum is 0.001% of the 20 SIKKA supply = 200,000 CHILLAR.
    let minimum = f.ledger.total_supply() / 100_000;
    assert_eq!(minimum, 200_000);

    let tx = Transaction::bond(&f.alice, minimum - 1, 0, now, f.chain_id()).unwrap();
    let context = ExecutionContext::new(1, now, Fixture::address(&f.validator));
    let outcome = f.ledger.execute(&[tx], context).unwrap();
    assert!(matches!(outcome.rejected[0].1, Error::BondTooSmall { .. }));

    let tx = Transaction::bond(&f.alice, minimum, 0, now, f.chain_id()).unwrap();
    let outcome = f.apply(&[tx], now);
    assert_eq!(outcome.applied.len(), 1);
}

#[test]
fn unbonding_waits_out_the_cooldown_then_returns_the_bond() {
    let mut f = Fixture::new();
    let alice = Fixture::address(&f.alice);
    let now = GENESIS_TIME + 600;

    f.apply(&[Transaction::bond(&f.alice, BOND, 0, now, f.chain_id()).unwrap()], now);
    f.apply(
        &[Transaction::unbond(&f.alice, 1, now + 60, f.chain_id()).unwrap()],
        now + 60,
    );

    let validator = f.ledger.validator(&alice).unwrap().unwrap();
    assert_eq!(validator.unbonding_since, Some(now + 60));
    // Unbonding validators stop voting immediately.
    assert!(!f
        .ledger
        .active_validators_at(3)
        .unwrap()
        .iter()
        .any(|v| v.address == alice));

    // Just before the cooldown ends nothing is released.
    let almost = now + 60 + UNBONDING_SECS - 1;
    let outcome = f.apply(&[], almost);
    assert!(outcome.released.is_empty());
    assert!(f.ledger.validator(&alice).unwrap().is_some());

    // After it ends the bond returns to the balance and the record is gone.
    let after = now + 60 + UNBONDING_SECS;
    let outcome = f.apply(&[], after);
    assert_eq!(outcome.released, vec![alice]);
    assert!(f.ledger.validator(&alice).unwrap().is_none());
    assert!(f.ledger.account(&alice).unwrap().balance >= ALLOCATION);
    assert_eq!(f.ledger.audit_supply().unwrap(), f.ledger.total_supply());
}

#[test]
fn double_unbond_and_bond_while_unbonding_are_rejected() {
    let mut f = Fixture::new();
    let now = GENESIS_TIME + 600;
    f.apply(&[Transaction::bond(&f.alice, BOND, 0, now, f.chain_id()).unwrap()], now);
    f.apply(&[Transaction::unbond(&f.alice, 1, now, f.chain_id()).unwrap()], now);

    let context = ExecutionContext::new(3, now, Fixture::address(&f.validator));
    let outcome = f
        .ledger
        .execute(
            // Both carry the same nonce: the first is rejected, so the second
            // is still the next one Alice owes.
            &[
                Transaction::unbond(&f.alice, 2, now, f.chain_id()).unwrap(),
                Transaction::bond(&f.alice, BOND, 2, now, f.chain_id()).unwrap(),
            ],
            context,
        )
        .unwrap();
    assert!(outcome.applied.is_empty());
    assert!(matches!(outcome.rejected[0].1, Error::AlreadyUnbonding(_)));
    assert!(matches!(outcome.rejected[1].1, Error::AlreadyUnbonding(_)));
}

#[test]
fn inflation_pays_validators_and_grows_supply() {
    let mut f = Fixture::new();
    let validator = Fixture::address(&f.validator);
    let supply_before = f.ledger.total_supply();
    let balance_before = f.ledger.account(&validator).unwrap().balance;

    // A day of elapsed time on a 20 SIKKA supply.
    let now = GENESIS_TIME + 86_400;
    let outcome = f.apply(&[], now);

    assert!(outcome.minted > 0, "expected inflation to mint something");
    assert_eq!(f.ledger.total_supply(), supply_before + outcome.minted);
    assert_eq!(
        f.ledger.account(&validator).unwrap().balance,
        balance_before + outcome.minted,
        "the only validator receives the whole reward"
    );
    assert_eq!(f.ledger.audit_supply().unwrap(), f.ledger.total_supply());
}

#[test]
fn inflation_is_split_by_bond_share() {
    let mut f = Fixture::new();
    let alice = Fixture::address(&f.alice);
    let validator = Fixture::address(&f.validator);
    let now = GENESIS_TIME + 600;

    // Alice bonds three times the genesis validator's stake.
    f.apply(
        &[Transaction::bond(&f.alice, BOND * 3, 0, now, f.chain_id()).unwrap()],
        now,
    );

    let alice_before = f.ledger.account(&alice).unwrap().balance;
    let validator_before = f.ledger.account(&validator).unwrap().balance;

    // Alice is active from height 2, so let height 3 pay both.
    let later = now + 86_400;
    f.apply(&[], now + 10);
    let outcome = f.apply(&[], later);

    let alice_reward = f.ledger.account(&alice).unwrap().balance - alice_before;
    let validator_reward = f.ledger.account(&validator).unwrap().balance - validator_before;
    assert!(alice_reward > 0 && validator_reward > 0);
    // Rewards from the height-3 checkpoint account for all but the dust minted
    // by the (ten second) height-2 checkpoint.
    assert!(alice_reward + validator_reward >= outcome.minted);
    // Alice holds 3/4 of the stake, so she earns roughly three times as much.
    let ratio = alice_reward as f64 / validator_reward as f64;
    assert!((2.5..3.5).contains(&ratio), "reward ratio was {ratio}");
}

#[test]
fn inflation_pays_every_active_validator_not_just_prior_signers() {
    use sikka_common::vote::{Vote, VoteKind};

    let mut f = Fixture::new();
    let alice = Fixture::address(&f.alice);
    let validator = Fixture::address(&f.validator);
    let now = GENESIS_TIME + 600;

    // Both are active from the next height.
    f.apply(
        &[Transaction::bond(&f.alice, BOND, 0, now, f.chain_id()).unwrap()],
        now,
    );
    assert_eq!(f.ledger.active_validators_at(f.ledger.height() + 1).unwrap().len(), 2);

    // Finalize a checkpoint signed only by the genesis validator — Alice was
    // "offline" for that round. Rewards at the next height must still include
    // her: paying only `last_signers` would let two valid certificates for the
    // same header fork H+1.
    let height = f.ledger.height() + 1;
    let context = ExecutionContext::new(height, now + 10, validator);
    let outcome = f.ledger.execute(&[], context).unwrap();
    let prev = f.ledger.meta().last_checkpoint_hash;
    let staged = f.ledger.stage(outcome);
    let header = f.ledger.build_header(&staged, prev, validator, 0);
    let mut checkpoint = Checkpoint::new(header);
    let hash = checkpoint.hash();
    checkpoint.add_signature(
        Vote::sign(&f.validator, f.chain_id(), height, 0, VoteKind::Precommit, hash)
            .unwrap()
            .into_signature(),
    );
    f.ledger.commit(staged, &checkpoint).unwrap();
    assert_eq!(f.ledger.meta().last_signers, vec![validator]);

    let alice_before = f.ledger.account(&alice).unwrap().balance;
    let validator_before = f.ledger.account(&validator).unwrap().balance;

    let later = now + 86_400;
    let paid = f.apply(&[], later);

    let alice_after = f.ledger.account(&alice).unwrap().balance;
    let validator_after = f.ledger.account(&validator).unwrap().balance;
    assert!(alice_after > alice_before, "active alice still earns inflation");
    assert!(validator_after > validator_before);
    assert_eq!(
        (alice_after - alice_before) + (validator_after - validator_before),
        paid.minted
    );
    assert!(paid.minted > 0);
}

#[test]
fn slashing_burns_the_bond_and_removes_the_validator() {
    let mut f = Fixture::new();
    let alice = Fixture::address(&f.alice);
    let now = GENESIS_TIME + 600;
    f.apply(&[Transaction::bond(&f.alice, BOND, 0, now, f.chain_id()).unwrap()], now);

    let supply_before = f.ledger.total_supply();
    let height = f.ledger.height() + 1;
    let mut context = ExecutionContext::new(height, now + 10, Fixture::address(&f.validator));
    context.slashings = vec![alice];

    let outcome = f.ledger.execute(&[], context).unwrap();
    assert_eq!(outcome.burned, BOND);

    let prev = f.ledger.meta().last_checkpoint_hash;
    let proposer = Fixture::address(&f.validator);
    let staged = f.ledger.stage(outcome);
    let header = f.ledger.build_header(&staged, prev, proposer, 0);
    f.ledger.commit(staged, &Checkpoint::new(header)).unwrap();

    let slashed = f.ledger.validator(&alice).unwrap().unwrap();
    assert!(slashed.slashed);
    assert_eq!(slashed.bond, 0);
    assert!(f.ledger.total_supply() < supply_before);
    assert!(!f
        .ledger
        .active_validators_at(height + 1)
        .unwrap()
        .iter()
        .any(|v| v.address == alice));
    assert_eq!(f.ledger.audit_supply().unwrap(), f.ledger.total_supply());
}

#[test]
fn state_proofs_verify_against_the_committed_root() {
    let mut f = Fixture::new();
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;
    f.apply(
        &[Transaction::transfer(&f.alice, bob, 777, 0, now, f.chain_id()).unwrap()],
        now,
    );

    let root = f.ledger.state_root();
    let (account, proof) = f.ledger.account_proof(&bob).unwrap();
    let account = account.unwrap();
    assert_eq!(account.balance, 777);
    assert!(proof.verify(&root, &bob.to_array(), &account.leaf_hash(&bob)));

    // A wallet cannot be lied to about the balance.
    let mut lie = account;
    lie.balance = 999;
    assert!(!proof.verify(&root, &bob.to_array(), &lie.leaf_hash(&bob)));

    // Absence proofs work for accounts that were never funded.
    let stranger = Address([0x42u8; 32]);
    let (missing, proof) = f.ledger.account_proof(&stranger).unwrap();
    assert!(missing.is_none());
    assert!(proof.verify_absent(&root, &stranger.to_array()));
}

#[test]
fn snapshot_restores_an_identical_ledger() {
    let mut f = Fixture::new();
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;
    f.apply(
        &[Transaction::transfer(&f.alice, bob, 1_234, 0, now, f.chain_id()).unwrap()],
        now,
    );
    f.apply(
        &[Transaction::bond(&f.alice, BOND, 1, now + 60, f.chain_id()).unwrap()],
        now + 60,
    );

    // Rebuild the checkpoint the ledger last committed to.
    let header = sikka_common::checkpoint::CheckpointHeader {
        height: f.ledger.height(),
        prev_hash: sikka_common::bytes::Hash::ZERO,
        state_root: f.ledger.state_root(),
        validator_root: f.ledger.validator_root(),
        tx_root: sikka_common::checkpoint::CheckpointHeader::compute_tx_root(&[]),
        tx_count: 0,
        timestamp: f.ledger.meta().last_checkpoint_time,
        proposer: Fixture::address(&f.validator),
        round: 0,
        total_supply: f.ledger.total_supply(),
        total_bonded: f.ledger.total_bonded(),
        chain_id: f.chain_id().into(),
    };
    let snapshot = f.ledger.snapshot(Checkpoint::new(header)).unwrap();
    snapshot.verify().unwrap();

    let dir = tempfile::tempdir().unwrap();
    let restored = Ledger::restore(dir.path().join("state.redb"), &snapshot).unwrap();
    assert_eq!(restored.state_root(), f.ledger.state_root());
    assert_eq!(restored.validator_root(), f.ledger.validator_root());
    assert_eq!(restored.total_supply(), f.ledger.total_supply());
    assert_eq!(restored.height(), f.ledger.height());
    assert_eq!(restored.account(&bob).unwrap().balance, 1_234);
    assert_eq!(restored.audit_supply().unwrap(), restored.total_supply());
}

#[test]
fn tampered_snapshots_are_rejected() {
    let mut f = Fixture::new();
    let bob = Fixture::address(&f.bob);
    let now = GENESIS_TIME + 600;
    f.apply(
        &[Transaction::transfer(&f.alice, bob, 1_000, 0, now, f.chain_id()).unwrap()],
        now,
    );

    let header = sikka_common::checkpoint::CheckpointHeader {
        height: f.ledger.height(),
        prev_hash: sikka_common::bytes::Hash::ZERO,
        state_root: f.ledger.state_root(),
        validator_root: f.ledger.validator_root(),
        tx_root: sikka_common::checkpoint::CheckpointHeader::compute_tx_root(&[]),
        tx_count: 0,
        timestamp: now,
        proposer: Fixture::address(&f.validator),
        round: 0,
        total_supply: f.ledger.total_supply(),
        total_bonded: f.ledger.total_bonded(),
        chain_id: f.chain_id().into(),
    };
    let snapshot: StateSnapshot = f.ledger.snapshot(Checkpoint::new(header)).unwrap();

    let mut tampered = snapshot.clone();
    tampered.accounts[0].1.balance += 1;
    assert!(tampered.verify().is_err());

    let mut duplicate_account = snapshot.clone();
    let first_account = duplicate_account.accounts[0];
    duplicate_account.accounts.insert(1, first_account);
    assert!(duplicate_account.verify().is_err());

    let mut duplicate_validator = snapshot.clone();
    duplicate_validator
        .validators
        .push(duplicate_validator.validators[0].clone());
    assert!(duplicate_validator.verify().is_err());

    let mut inflated = snapshot;
    inflated.checkpoint.header.total_supply += 1;
    assert!(inflated.verify().is_err());
}

#[test]
fn many_accounts_stay_consistent() {
    let mut f = Fixture::new();
    let now = GENESIS_TIME + 600;

    // Fan out to 60 distinct addresses across several checkpoints.
    let mut nonce = 0u64;
    for round in 0..3u64 {
        let txs: Vec<Transaction> = (0..20u64)
            .map(|i| {
                let mut raw = [0u8; 32];
                raw[0] = (round * 20 + i) as u8;
                raw[1] = 0xaa;
                let tx = Transaction::transfer(&f.alice, Address(raw), 1_000, nonce, now, f.chain_id()).unwrap();
                nonce += 1;
                tx
            })
            .collect();
        let outcome = f.apply(&txs, now);
        assert_eq!(outcome.applied.len(), 20);
    }

    assert_eq!(f.ledger.account_count().unwrap(), 62);
    assert_eq!(f.ledger.audit_supply().unwrap(), f.ledger.total_supply());

    // The tree rebuilt from the database must produce the committed root.
    let rebuilt = sikka_state::Smt::from_leaves(
        f.ledger
            .all_accounts()
            .unwrap()
            .into_iter()
            .map(|(a, acc)| (a.to_array(), acc.leaf_hash(&a))),
    );
    assert_eq!(rebuilt.root(), f.ledger.state_root());
}

#[test]
fn repeated_full_batch_proposer_misses_force_unbond() {
    use sikka_common::validator::Validator;

    let alice_kp = Keypair::generate().unwrap();
    let bob_kp = Keypair::generate().unwrap();
    let alice_pk = PublicKey::new(*alice_kp.public_bytes());
    let bob_pk = PublicKey::new(*bob_kp.public_bytes());

    let genesis = GenesisConfig {
        chain_id: "sikka-miss-test".into(),
        timestamp: GENESIS_TIME,
        allocations: vec![
            GenesisAllocation {
                to: alice_pk.address(),
                amount: ALLOCATION,
            },
            GenesisAllocation {
                to: bob_pk.address(),
                amount: ALLOCATION,
            },
        ],
        validators: vec![
            GenesisValidator {
                public_key: alice_pk.clone(),
                bond: BOND,
                endpoint: None,
            },
            GenesisValidator {
                public_key: bob_pk.clone(),
                bond: BOND,
                endpoint: None,
            },
        ],
        checkpoint_tx_interval: Some(2),
        max_missed_proposer_slots: Some(2),
    };

    let dir = tempfile::tempdir().unwrap();
    let (mut ledger, _) = Ledger::open(dir.path().join("state.redb"), &genesis).unwrap();

    let mut active = ledger.active_validators_at(1).unwrap();
    active.sort_by_key(|v| v.address);
    let round0 = Validator::proposer_for_round(1, 0, &active).unwrap();
    let round1 = Validator::proposer_for_round(1, 1, &active).unwrap();
    assert_ne!(round0, round1);

    let payer = if round1 == alice_pk.address() {
        &alice_kp
    } else {
        &bob_kp
    };
    let now = GENESIS_TIME + 60;
    let txs = vec![
        Transaction::transfer(payer, Address([0x11; 32]), 1_000, 0, now, &genesis.chain_id)
            .unwrap(),
        Transaction::transfer(payer, Address([0x22; 32]), 1_000, 1, now, &genesis.chain_id)
            .unwrap(),
    ];
    let mut context = ExecutionContext::new(1, now, round1);
    context.round = 1;
    let outcome = ledger.execute(&txs, context).unwrap();
    assert!(outcome.forced_unbonds.is_empty());
    assert_eq!(
        outcome
            .validators
            .get(&round0)
            .and_then(|v| v.as_ref())
            .unwrap()
            .missed_proposer_slots,
        1
    );

    let prev = ledger.meta().last_checkpoint_hash;
    let staged = ledger.stage(outcome);
    let header = ledger.build_header(&staged, prev, round1, 1);
    ledger.commit(staged, &Checkpoint::new(header)).unwrap();
    assert_eq!(
        ledger.validator(&round0).unwrap().unwrap().missed_proposer_slots,
        1
    );

    let mut active = ledger.active_validators_at(2).unwrap();
    active.sort_by_key(|v| v.address);
    let (h, absentee, winner) = (2u64..50)
        .find_map(|h| {
            let a0 = Validator::proposer_for_round(h, 0, &active).unwrap();
            let a1 = Validator::proposer_for_round(h, 1, &active).unwrap();
            (a0 == round0).then_some((h, a0, a1))
        })
        .expect("round-robin eventually reselects the absentee");
    let payer = if winner == alice_pk.address() {
        &alice_kp
    } else {
        &bob_kp
    };
    let payer_addr = PublicKey::new(*payer.public_bytes()).address();
    let nonce = ledger.next_nonce(&payer_addr).unwrap();
    let later = now + 60;
    let txs = vec![
        Transaction::transfer(payer, Address([0x33; 32]), 1_000, nonce, later, &genesis.chain_id)
            .unwrap(),
        Transaction::transfer(
            payer,
            Address([0x44; 32]),
            1_000,
            nonce + 1,
            later,
            &genesis.chain_id,
        )
        .unwrap(),
    ];
    let mut context = ExecutionContext::new(h, later, winner);
    context.round = 1;
    let outcome = ledger.execute(&txs, context).unwrap();
    assert_eq!(outcome.forced_unbonds, vec![absentee]);
    let forced = outcome
        .validators
        .get(&absentee)
        .and_then(|v| v.as_ref())
        .unwrap();
    assert_eq!(forced.bond, BOND);
    assert!(forced.unbonding_since.is_some());

    let prev = ledger.meta().last_checkpoint_hash;
    let staged = ledger.stage(outcome);
    let header = ledger.build_header(&staged, prev, winner, 1);
    ledger.commit(staged, &Checkpoint::new(header)).unwrap();
    let record = ledger.validator(&absentee).unwrap().unwrap();
    assert!(record.unbonding_since.is_some());
    assert!(!record.is_active_at(h + 1));
    assert!(record.is_slashable());
}

#[test]
fn short_batch_delay_seals_do_not_charge_proposer_misses() {
    use sikka_common::validator::Validator;

    let alice_kp = Keypair::generate().unwrap();
    let bob_kp = Keypair::generate().unwrap();
    let alice_pk = PublicKey::new(*alice_kp.public_bytes());
    let bob_pk = PublicKey::new(*bob_kp.public_bytes());

    let genesis = GenesisConfig {
        chain_id: "sikka-miss-idle".into(),
        timestamp: GENESIS_TIME,
        allocations: vec![
            GenesisAllocation {
                to: alice_pk.address(),
                amount: ALLOCATION,
            },
            GenesisAllocation {
                to: bob_pk.address(),
                amount: ALLOCATION,
            },
        ],
        validators: vec![
            GenesisValidator {
                public_key: alice_pk.clone(),
                bond: BOND,
                endpoint: None,
            },
            GenesisValidator {
                public_key: bob_pk.clone(),
                bond: BOND,
                endpoint: None,
            },
        ],
        checkpoint_tx_interval: Some(4),
        max_missed_proposer_slots: Some(2),
    };

    let dir = tempfile::tempdir().unwrap();
    let (ledger, _) = Ledger::open(dir.path().join("state.redb"), &genesis).unwrap();
    let mut active = ledger.active_validators_at(1).unwrap();
    active.sort_by_key(|v| v.address);
    let round0 = Validator::proposer_for_round(1, 0, &active).unwrap();
    let round1 = Validator::proposer_for_round(1, 1, &active).unwrap();
    let payer = if round1 == alice_pk.address() {
        &alice_kp
    } else {
        &bob_kp
    };
    let now = GENESIS_TIME + 60;
    let txs = vec![Transaction::transfer(
        payer,
        Address([0x55; 32]),
        1_000,
        0,
        now,
        &genesis.chain_id,
    )
    .unwrap()];
    let mut context = ExecutionContext::new(1, now, round1);
    context.round = 1;
    let mut ledger = ledger;
    let outcome = ledger.execute(&txs, context).unwrap();
    assert!(outcome.forced_unbonds.is_empty());
    // Unchanged validators may be absent from the outcome map.
    let missed = outcome
        .validators
        .get(&round0)
        .and_then(|v| v.as_ref())
        .map(|v| v.missed_proposer_slots)
        .unwrap_or(0);
    assert_eq!(missed, 0);
}
