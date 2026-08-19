//! Consensus tests over a four-validator committee, without any networking.
//!
//! Each "node" is its own database and its own key. Proposals and votes are
//! passed between them by hand, which is exactly what the HTTP layer does later,
//! so a disagreement here is a consensus bug rather than a transport bug.

use std::collections::HashSet;

use sikka_common::bytes::{Address, Hash, PublicKey};
use sikka_common::constants::quorum_threshold;
use sikka_common::error::Error;
use sikka_common::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};
use sikka_common::transaction::Transaction;
use sikka_common::vote::{Vote, VoteKind};
use sikka_consensus::proposal::{build_proposal, verify_proposal, CheckpointProposal};
use sikka_consensus::{proposer_for, VoteOutcome, VoteTracker};
use sikka_crypto::Keypair;
use sikka_state::Ledger;

const ALLOCATION: u64 = 10_000_000_000;
const BOND: u64 = 1_000_000_000;
const VALIDATORS: usize = 4;

fn sign_as(node: &Node, mut proposal: CheckpointProposal) -> CheckpointProposal {
    proposal.sign(&node.key).unwrap();
    proposal
}

struct Node {
    ledger: Ledger,
    key: Keypair,
    address: Address,
    _dir: tempfile::TempDir,
}

/// Four bonded validators plus one plain full node ("alice").
///
/// Alice holds coins and follows consensus without voting, which is the majority
/// case on a real network — and she can bond later, which is how the committee
/// grows.
struct Testnet {
    nodes: Vec<Node>,
    genesis_time: u64,
    now: u64,
}

impl Testnet {
    fn chain_id(&self) -> &str {
        &self.nodes[0].ledger.meta().chain_id
    }

    fn genesis_fingerprint(&self) -> Hash {
        self.nodes[0].ledger.meta().genesis_fingerprint
    }

    fn new() -> Self {
        let now = sikka_common::now_secs();
        let genesis_time = now - 3_600;

        // The last key is alice: funded at genesis, but not a validator.
        let keys: Vec<Keypair> = (0..VALIDATORS + 1)
            .map(|_| Keypair::generate().unwrap())
            .collect();

        let allocations: Vec<GenesisAllocation> = keys
            .iter()
            .map(|k| GenesisAllocation {
                to: PublicKey::new(*k.public_bytes()).address(),
                amount: ALLOCATION,
            })
            .collect();

        let genesis = GenesisConfig {
            chain_id: "sikka-consensus-test".into(),
            timestamp: genesis_time,
            allocations,
            validators: keys[..VALIDATORS]
                .iter()
                .map(|k| GenesisValidator {
                    public_key: PublicKey::new(*k.public_bytes()),
                    bond: BOND,
                    endpoint: None,
                })
                .collect(),
            checkpoint_tx_interval: Some(4),
            max_missed_proposer_slots: None,
        };

        let nodes = keys
            .into_iter()
            .map(|key| {
                let dir = tempfile::tempdir().unwrap();
                let (ledger, _) = Ledger::open(dir.path().join("state.redb"), &genesis).unwrap();
                let address = PublicKey::new(*key.public_bytes()).address();
                Node {
                    ledger,
                    key,
                    address,
                    _dir: dir,
                }
            })
            .collect();

        Self {
            nodes,
            genesis_time,
            now,
        }
    }

    fn alice(&self) -> &Keypair {
        &self.nodes[VALIDATORS].key
    }

    fn alice_address(&self) -> Address {
        self.nodes[VALIDATORS].address
    }

    /// Index of the node that proposes at `height`.
    fn proposer_index(&self, height: u64) -> usize {
        let active = self.nodes[0].ledger.active_validators_at(height).unwrap();
        let proposer = proposer_for(height, &active).unwrap();
        self.nodes
            .iter()
            .position(|n| n.address == proposer)
            .unwrap()
    }

    /// Run one full checkpoint round: propose, replay everywhere, vote, commit.
    fn round(&mut self, transactions: Vec<Transaction>, timestamp: u64) -> Hash {
        let height = self.nodes[0].ledger.height() + 1;
        let index = self.proposer_index(height);
        let proposer = self.nodes[index].address;

        let mut verified: Vec<Option<sikka_consensus::VerifiedProposal>> =
            (0..self.nodes.len()).map(|_| None).collect();

        let proposal = {
            let node = &mut self.nodes[index];
            let (mut proposal, own, _) = build_proposal(
                &mut node.ledger,
                transactions,
                Vec::new(),
                timestamp,
                proposer,
                0,
            )
            .unwrap();
            proposal.sign(&node.key).unwrap();
            verified[index] = Some(own);
            proposal
        };

        // Every other validator replays the proposal independently.
        for (i, node) in self.nodes.iter_mut().enumerate() {
            if i == index {
                continue;
            }
            let v = verify_proposal(&mut node.ledger, &proposal, timestamp, &HashSet::new())
                .unwrap_or_else(|e| panic!("node {i} rejected a valid proposal: {e}"));
            assert_eq!(
                v.hash(),
                proposal.hash(),
                "node {i} computed a different checkpoint"
            );
            verified[i] = Some(v);
        }

        // Votes are collected by everyone; each node finalizes on its own.
        let hash = proposal.hash();
        let mut tracker = VoteTracker::new(self.chain_id(), self.genesis_fingerprint());
        for node in &self.nodes {
            tracker
                .record(Vote::sign(&node.key, self.chain_id(), self.genesis_fingerprint(), height, 0, VoteKind::Precommit, hash).unwrap())
                .unwrap();
        }
        let authorized: Vec<(Address, u64)> = self.nodes[0]
            .ledger
            .active_validators_at(height)
            .unwrap()
            .iter()
            .map(|v| (v.address, v.bond))
            .collect();
        assert!(tracker.has_quorum(height, 0, VoteKind::Precommit, &hash, &authorized));

        let addresses: Vec<Address> = authorized.iter().map(|(a, _)| *a).collect();
        let signatures = tracker.signatures(height, 0, &hash, &addresses);
        for (i, node) in self.nodes.iter_mut().enumerate() {
            let mut v = verified[i]
                .take()
                .expect("every node verified the proposal");
            v.checkpoint.validator_signatures = signatures.clone();
            v.checkpoint.canonicalize();

            // The signatures a node commits must be a genuine super-majority of
            // the bonded stake it believes is active.
            let authorized: Vec<(Address, PublicKey, u64)> = node
                .ledger
                .active_validators_at(height)
                .unwrap()
                .into_iter()
                .map(|v| (v.address, v.public_key, v.bond))
                .collect();
            let refs: Vec<(&Address, &PublicKey, u64)> =
                authorized.iter().map(|(a, k, b)| (a, k, *b)).collect();
            v.checkpoint.verify_signatures(refs).unwrap();

            node.ledger.commit(v.staged, &v.checkpoint).unwrap();
        }
        hash
    }
}

#[test]
fn all_nodes_agree_on_the_proposer_for_every_height() {
    let net = Testnet::new();
    for height in 1..20u64 {
        let expected = net.proposer_index(height);
        for node in &net.nodes {
            let active = node.ledger.active_validators_at(height).unwrap();
            let proposer = proposer_for(height, &active).unwrap();
            assert_eq!(proposer, net.nodes[expected].address);
        }
    }
}

#[test]
fn a_checkpoint_round_finalizes_identical_state_everywhere() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let now = net.now;

    let txs: Vec<Transaction> = (0..4)
        .map(|nonce| Transaction::transfer(net.alice(), bob, 1_000 + nonce, nonce, now, net.chain_id(), net.genesis_fingerprint()).unwrap())
        .collect();

    net.round(txs, now);

    let reference = &net.nodes[0].ledger;
    assert_eq!(reference.height(), 1);
    assert_eq!(
        reference.account(&bob).unwrap().balance,
        1_000 + 1_001 + 1_002 + 1_003
    );
    for node in &net.nodes[1..] {
        assert_eq!(node.ledger.state_root(), reference.state_root());
        assert_eq!(node.ledger.validator_root(), reference.validator_root());
        assert_eq!(node.ledger.total_supply(), reference.total_supply());
        assert_eq!(
            node.ledger.meta().last_checkpoint_hash,
            reference.meta().last_checkpoint_hash
        );
    }
}

#[test]
fn several_rounds_keep_the_committee_in_step() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let mut nonce = 0u64;

    for round in 0..4u64 {
        let timestamp = net.now + round * 30;
        let txs: Vec<Transaction> = (0..3)
            .map(|_| {
                let tx = Transaction::transfer(net.alice(), bob, 500, nonce, timestamp, net.chain_id(), net.genesis_fingerprint()).unwrap();
                nonce += 1;
                tx
            })
            .collect();
        net.round(txs, timestamp);
    }

    let reference = &net.nodes[0].ledger;
    assert_eq!(reference.height(), 4);
    assert_eq!(reference.account(&bob).unwrap().balance, 500 * 12);
    for node in &net.nodes[1..] {
        assert_eq!(node.ledger.state_root(), reference.state_root());
        assert_eq!(node.ledger.height(), 4);
    }
    // Inflation over four checkpoints has grown the supply.
    assert!(reference.total_supply() > ALLOCATION * 5);
    assert_eq!(reference.audit_supply().unwrap(), reference.total_supply());
}

#[test]
fn tampered_proposals_are_refused() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let now = net.now;
    let height = 1;
    let index = net.proposer_index(height);
    let proposer = net.nodes[index].address;

    let txs: Vec<Transaction> = (0..3)
        .map(|nonce| Transaction::transfer(net.alice(), bob, 1_000, nonce, now, net.chain_id(), net.genesis_fingerprint()).unwrap())
        .collect();

    let (proposal, verified) = {
        let node = &mut net.nodes[index];
        let (proposal, verified, _) =
            build_proposal(&mut node.ledger, txs, Vec::new(), now, proposer, 0).unwrap();
        (sign_as(node, proposal), verified)
    };
    // Give the proposer's ledger back its pre-proposal state.
    net.nodes[index].ledger.rollback(verified.staged);

    // A different state root than the transactions produce. Re-sign so the
    // failure is the state mismatch, not a missing proposer signature.
    let mut forged = proposal.clone();
    forged.header.state_root = Hash([0x11u8; 32]);
    forged = sign_as(&net.nodes[index], forged);

    let verifier = (index + 1) % net.nodes.len();
    let verifier_address = net.nodes[verifier].address;
    let ledger = &mut net.nodes[verifier].ledger;
    assert!(matches!(
        verify_proposal(ledger, &forged, now, &HashSet::new()),
        Err(Error::StateRootMismatch { .. })
    ));

    // Reordered transactions.
    let mut reordered = proposal.clone();
    reordered.transactions.reverse();
    assert!(verify_proposal(ledger, &reordered, now, &HashSet::new()).is_err());

    // A transaction dropped without updating the header.
    let mut truncated = proposal.clone();
    truncated.transactions.pop();
    assert!(verify_proposal(ledger, &truncated, now, &HashSet::new()).is_err());

    // Someone else's turn to propose.
    let mut usurped = proposal.clone();
    usurped.header.proposer = verifier_address;
    assert!(matches!(
        verify_proposal(ledger, &usurped, now, &HashSet::new()),
        Err(Error::WrongProposer { .. })
    ));

    // Wrong height and wrong parent.
    let mut skipped = proposal.clone();
    skipped.header.height = 5;
    assert!(matches!(
        verify_proposal(ledger, &skipped, now, &HashSet::new()),
        Err(Error::BadCheckpointHeight { .. })
    ));

    let mut orphan = proposal.clone();
    orphan.header.prev_hash = Hash([0x22u8; 32]);
    assert!(matches!(
        verify_proposal(ledger, &orphan, now, &HashSet::new()),
        Err(Error::BadCheckpointParent { .. })
    ));

    // A timestamp far from this node's clock.
    let mut stale = proposal.clone();
    stale.header.timestamp = now - 10_000;
    assert!(verify_proposal(ledger, &stale, now, &HashSet::new()).is_err());

    // A forged signature on an otherwise valid transaction.
    let mut unsigned = proposal.clone();
    unsigned.transactions[0].signature = sikka_common::bytes::Signature::default();
    assert!(verify_proposal(ledger, &unsigned, now, &HashSet::new()).is_err());

    // The untouched proposal still verifies, so the failures above were caused
    // by the tampering and not by a poisoned ledger.
    let good = verify_proposal(ledger, &proposal, now, &HashSet::new()).unwrap();
    assert_eq!(good.hash(), proposal.hash());
}

#[test]
fn an_absent_proposer_loses_its_turn_to_the_next_validator() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let height = 1;

    // Round 0's proposer never proposes. After one proposer timeout, the next
    // validator in line may take the turn instead.
    let absent = net.proposer_index(height);
    let active = net.nodes[0].ledger.active_validators_at(height).unwrap();
    let taker_address = sikka_consensus::proposer_for_round(height, 1, &active).unwrap();
    let taker = net
        .nodes
        .iter()
        .position(|n| n.address == taker_address)
        .unwrap();
    assert_ne!(taker, absent, "a takeover must move the turn");

    let last_time = net.nodes[0].ledger.meta().last_checkpoint_time;
    let timestamp = last_time + sikka_consensus::PROPOSER_TIMEOUT_SECS;
    let txs = vec![Transaction::transfer(net.alice(), bob, 1_000, 0, timestamp, net.chain_id(), net.genesis_fingerprint()).unwrap()];

    let (proposal, verified) = {
        let node = &mut net.nodes[taker];
        let (proposal, verified, _) = build_proposal(
            &mut node.ledger,
            txs,
            Vec::new(),
            timestamp,
            taker_address,
            1,
        )
        .unwrap();
        (sign_as(node, proposal), verified)
    };
    assert_eq!(proposal.header.round, 1);
    net.nodes[taker].ledger.rollback(verified.staged);

    // Everyone else accepts it, because the round is derivable from the previous
    // checkpoint's timestamp and needs no agreement of its own.
    for (index, node) in net.nodes.iter_mut().enumerate() {
        if index == taker {
            continue;
        }
        let v = verify_proposal(&mut node.ledger, &proposal, timestamp, &HashSet::new())
            .unwrap_or_else(|e| panic!("node {index} rejected a legitimate takeover: {e}"));
        assert_eq!(v.hash(), proposal.hash());
        node.ledger.rollback(v.staged);
    }
}

#[test]
fn a_validator_cannot_jump_the_queue_by_claiming_a_later_round() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let height = 1;
    let now = net.now;

    let active = net.nodes[0].ledger.active_validators_at(height).unwrap();
    let round_one = sikka_consensus::proposer_for_round(height, 1, &active).unwrap();
    let impatient = net
        .nodes
        .iter()
        .position(|n| n.address == round_one)
        .unwrap();

    // Round 1's proposer builds immediately, without waiting out round 0.
    let txs = vec![Transaction::transfer(net.alice(), bob, 1_000, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap()];
    let (proposal, verified) = {
        let node = &mut net.nodes[impatient];
        let (proposal, verified, _) =
            build_proposal(&mut node.ledger, txs, Vec::new(), now, round_one, 1).unwrap();
        (sign_as(node, proposal), verified)
    };
    net.nodes[impatient].ledger.rollback(verified.staged);

    // The previous checkpoint is an hour old here, so round 1 *is* due by the
    // clock; what must not be possible is claiming a round the clock cannot
    // support. Move the last checkpoint forward by pointing at a fresh chain.
    let verifier = (impatient + 1) % net.nodes.len();
    let verifier_address = net.nodes[verifier].address;
    let ledger = &mut net.nodes[verifier].ledger;
    let last_time = ledger.meta().last_checkpoint_time;
    let far_future_round = ((now - last_time) / sikka_consensus::PROPOSER_TIMEOUT_SECS + 10) as u32;

    let mut greedy = proposal.clone();
    greedy.header.round = far_future_round;
    greedy.header.proposer =
        sikka_consensus::proposer_for_round(height, far_future_round, &active).unwrap();
    let error = verify_proposal(ledger, &greedy, now, &HashSet::new()).unwrap_err();
    assert!(
        format!("{error}").contains("not due"),
        "a round that has not arrived must be refused, got: {error}"
    );

    // And claiming the right round with the wrong identity still fails.
    let mut usurped = proposal.clone();
    usurped.header.round = 1;
    usurped.header.proposer = verifier_address;
    assert!(matches!(
        verify_proposal(ledger, &usurped, now, &HashSet::new()),
        Err(Error::WrongProposer { .. })
    ));
}

#[test]
fn a_finalized_checkpoint_is_applied_without_re_arguing_whose_turn_it_was() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let height = 1;
    let now = net.now;
    let index = net.proposer_index(height);
    let proposer = net.nodes[index].address;

    let txs = vec![Transaction::transfer(net.alice(), bob, 2_000, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap()];
    let (proposal, verified) = {
        let node = &mut net.nodes[index];
        let (proposal, verified, _) =
            build_proposal(&mut node.ledger, txs, Vec::new(), now, proposer, 0).unwrap();
        (sign_as(node, proposal), verified)
    };
    net.nodes[index].ledger.rollback(verified.staged);

    // A verifier whose clock is far enough off to reject the proposal outright…
    let verifier = (index + 1) % net.nodes.len();
    let ledger = &mut net.nodes[verifier].ledger;
    let skewed = now + 3_600;
    assert!(matches!(
        verify_proposal(ledger, &proposal, skewed, &HashSet::new()),
        Err(Error::TimestampOutOfRange { .. })
    ));

    // …must still be able to apply it once a super-majority has signed it,
    // because otherwise a bad clock would fork the node off the network.
    let applied = sikka_consensus::proposal::verify_proposal_with(
        ledger,
        &proposal,
        skewed,
        &HashSet::new(),
        sikka_consensus::Authority::Finalized,
    )
    .unwrap();
    assert_eq!(applied.hash(), proposal.hash());
    ledger.rollback(applied.staged);
}

#[test]
fn a_proposal_that_double_spends_is_refused() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let now = net.now;

    // Two transactions with the same nonce: only one can apply.
    let a = Transaction::transfer(net.alice(), bob, 1_000, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap();
    let b = Transaction::transfer(net.alice(), bob, 2_000, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap();
    let mut transactions = vec![a, b];
    transactions.sort_by_key(|tx| tx.id());

    let index = net.proposer_index(1);
    let proposer = net.nodes[index].address;
    let ids: Vec<Hash> = transactions.iter().map(|tx| tx.id()).collect();

    // Hand-build a proposal claiming both applied.
    let header = sikka_common::checkpoint::CheckpointHeader {
        height: 1,
        prev_hash: net.nodes[index].ledger.meta().last_checkpoint_hash,
        state_root: Hash([1u8; 32]),
        validator_root: net.nodes[index].ledger.validator_root(),
        tx_root: sikka_common::checkpoint::CheckpointHeader::compute_tx_root(&ids),
        tx_count: 2,
        timestamp: now,
        proposer,
        round: 0,
        total_supply: net.nodes[index].ledger.total_supply(),
        total_bonded: net.nodes[index].ledger.total_bonded(),
        chain_id: net.chain_id().into(),
        genesis_fingerprint: net.genesis_fingerprint(),
    };
    let mut proposal = CheckpointProposal {
        header,
        transactions,
        evidence: Vec::new(),
        proposer_signature: Default::default(),
    };
    proposal = sign_as(&net.nodes[index], proposal);

    let verifier = (index + 1) % net.nodes.len();
    let error = verify_proposal(
        &mut net.nodes[verifier].ledger,
        &proposal,
        now,
        &HashSet::new(),
    )
    .unwrap_err();
    assert!(
        format!("{error}").contains("rejects"),
        "expected a rejected-transaction error, got: {error}"
    );
}

#[test]
fn quorum_is_two_thirds_and_a_stalled_vote_finalizes_nothing() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let now = net.now;
    let height = 1;
    let index = net.proposer_index(height);
    let proposer = net.nodes[index].address;

    let txs = vec![Transaction::transfer(net.alice(), bob, 1_000, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap()];
    let (proposal, verified) = {
        let node = &mut net.nodes[index];
        let (proposal, verified, _) =
            build_proposal(&mut node.ledger, txs, Vec::new(), now, proposer, 0).unwrap();
        (sign_as(node, proposal), verified)
    };
    let hash = proposal.hash();

    let authorized: Vec<(Address, u64)> = net.nodes[index]
        .ledger
        .active_validators_at(height)
        .unwrap()
        .iter()
        .map(|v| (v.address, v.bond))
        .collect();
    assert_eq!(authorized.len(), VALIDATORS);
    assert_eq!(quorum_threshold(authorized.len()), 3);

    let mut tracker = VoteTracker::new(net.chain_id(), net.genesis_fingerprint());
    tracker
        .record(Vote::sign(&net.nodes[0].key, net.chain_id(), net.genesis_fingerprint(), height, 0, VoteKind::Precommit, hash).unwrap())
        .unwrap();
    tracker
        .record(Vote::sign(&net.nodes[1].key, net.chain_id(), net.genesis_fingerprint(), height, 0, VoteKind::Precommit, hash).unwrap())
        .unwrap();
    assert!(
        !tracker.has_quorum(height, 0, VoteKind::Precommit, &hash, &authorized),
        "two of four must not finalize"
    );

    tracker
        .record(Vote::sign(&net.nodes[2].key, net.chain_id(), net.genesis_fingerprint(), height, 0, VoteKind::Precommit, hash).unwrap())
        .unwrap();
    assert!(tracker.has_quorum(height, 0, VoteKind::Precommit, &hash, &authorized));

    // Nothing was committed while quorum was short: rolling back leaves the
    // proposer exactly where it started.
    let root_before_rollback = net.nodes[index].ledger.state_root();
    net.nodes[index].ledger.rollback(verified.staged);
    assert_ne!(root_before_rollback, net.nodes[index].ledger.state_root());
    assert_eq!(net.nodes[index].ledger.height(), 0);
}

#[test]
fn equivocation_is_detected_and_slashed_in_the_next_checkpoint() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let now = net.now;

    // The cheat signs two different checkpoints at height 1.
    let cheat_index = 0;
    let cheat = net.nodes[cheat_index].address;
    let vote_a = Vote::sign(&net.nodes[cheat_index].key, net.chain_id(), net.genesis_fingerprint(), 1, 0, VoteKind::Precommit, Hash([1u8; 32])).unwrap();
    let vote_b = Vote::sign(&net.nodes[cheat_index].key, net.chain_id(), net.genesis_fingerprint(), 1, 0, VoteKind::Precommit, Hash([2u8; 32])).unwrap();

    let mut tracker = VoteTracker::new(net.chain_id(), net.genesis_fingerprint());
    tracker.record(vote_a).unwrap();
    let outcome = tracker.record(vote_b).unwrap();
    let VoteOutcome::Equivocated(evidence) = outcome else {
        panic!("expected equivocation");
    };
    let evidence = *evidence;
    evidence.verify(&net.chain_id(), &net.genesis_fingerprint()).unwrap();

    // An honest proposer includes the evidence in its checkpoint.
    let height = 1;
    let index = net.proposer_index(height);
    let proposer = net.nodes[index].address;
    let txs = vec![Transaction::transfer(net.alice(), bob, 1_000, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap()];

    let (proposal, verified) = {
        let node = &mut net.nodes[index];
        let (proposal, verified, _) = build_proposal(
            &mut node.ledger,
            txs,
            vec![evidence.clone()],
            now,
            proposer,
            0,
        )
        .unwrap();
        (sign_as(node, proposal), verified)
    };

    // Another node reaches the same conclusion from the same evidence.
    let verifier = net
        .nodes
        .iter()
        .position(|n| n.address != proposer)
        .unwrap();
    let mirrored = verify_proposal(
        &mut net.nodes[verifier].ledger,
        &proposal,
        now,
        &HashSet::new(),
    )
    .unwrap();
    assert_eq!(mirrored.hash(), proposal.hash());

    let supply_before = net.nodes[index].ledger.total_supply();
    let mut checkpoint = verified.checkpoint.clone();
    checkpoint.validator_signatures = Vec::new();
    net.nodes[index]
        .ledger
        .commit(verified.staged, &checkpoint)
        .unwrap();
    net.nodes[verifier]
        .ledger
        .commit(mirrored.staged, &checkpoint)
        .unwrap();

    for node in [&net.nodes[index], &net.nodes[verifier]] {
        let slashed = node.ledger.validator(&cheat).unwrap().unwrap();
        assert!(slashed.slashed);
        assert_eq!(slashed.bond, 0);
        // The burned bond leaves circulation.
        assert!(node.ledger.total_supply() < supply_before + BOND);
        assert_eq!(
            node.ledger.audit_supply().unwrap(),
            node.ledger.total_supply()
        );
        // And the cheat no longer votes.
        let active = node.ledger.active_validators_at(2).unwrap();
        assert_eq!(active.len(), VALIDATORS - 1);
        assert!(!active.iter().any(|v| v.address == cheat));
    }

    // With three validators left, quorum is now two.
    assert_eq!(quorum_threshold(VALIDATORS - 1), 2);
}

#[test]
fn bonding_a_new_validator_changes_the_committee() {
    let mut net = Testnet::new();
    let now = net.now;
    let alice = net.alice_address();

    net.round(
        vec![Transaction::bond(net.alice(), BOND, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap()],
        now,
    );

    for node in &net.nodes {
        // Alice votes from height 2 onwards, not at height 1.
        assert_eq!(
            node.ledger.active_validators_at(1).unwrap().len(),
            VALIDATORS
        );
        let active = node.ledger.active_validators_at(2).unwrap();
        assert_eq!(active.len(), VALIDATORS + 1);
        assert!(active.iter().any(|v| v.address == alice));
    }

    // Quorum grows with the set.
    assert_eq!(quorum_threshold(VALIDATORS + 1), 4);

    // And the next round still finalizes with the larger committee.
    let bob = Address([0xbbu8; 32]);
    net.round(
        vec![Transaction::transfer(net.alice(), bob, 1_000, 1, now + 10, net.chain_id(), net.genesis_fingerprint()).unwrap()],
        now + 10,
    );
    let reference = &net.nodes[0].ledger;
    assert_eq!(reference.height(), 2);
    for node in &net.nodes[1..] {
        assert_eq!(node.ledger.state_root(), reference.state_root());
    }
}

#[test]
fn genesis_is_identical_on_every_node() {
    let net = Testnet::new();
    let reference = &net.nodes[0].ledger;
    assert_eq!(reference.height(), 0);
    assert_eq!(
        reference.total_supply(),
        ALLOCATION * (VALIDATORS as u64 + 1)
    );
    assert_eq!(reference.total_bonded(), BOND * VALIDATORS as u64);
    for node in &net.nodes[1..] {
        assert_eq!(node.ledger.state_root(), reference.state_root());
        assert_eq!(
            node.ledger.meta().last_checkpoint_hash,
            reference.meta().last_checkpoint_hash
        );
        assert_eq!(
            node.ledger.meta().genesis_fingerprint,
            reference.meta().genesis_fingerprint
        );
    }
    assert!(net.genesis_time < net.now);
}

#[test]
fn a_failed_head_does_not_purge_the_nonce_tail() {
    let mut net = Testnet::new();
    let bob_key = Keypair::generate().unwrap();
    let bob = PublicKey::new(*bob_key.public_bytes()).address();
    let now = net.now;
    net.round(
        vec![Transaction::transfer(net.alice(), bob, 1_000, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap()],
        now,
    );

    let later = now + 1;
    let head = Transaction::transfer(&bob_key, Address([0x11; 32]), 10, 0, later, net.chain_id(), net.genesis_fingerprint()).unwrap();
    let tail = Transaction::transfer(&bob_key, Address([0x22; 32]), 10, 1, later, net.chain_id(), net.genesis_fingerprint()).unwrap();
    let filler = Transaction::transfer(net.alice(), Address([0x33; 32]), 1, 1, later, net.chain_id(), net.genesis_fingerprint()).unwrap();

    let height = net.nodes[0].ledger.height() + 1;
    let index = net.proposer_index(height);
    let proposer = net.nodes[index].address;
    let node = &mut net.nodes[index];
    let (proposal, verified, drops) = build_proposal(
        &mut node.ledger,
        vec![head.clone(), tail.clone(), filler.clone()],
        Vec::new(),
        later,
        proposer,
        0,
    )
    .unwrap();
    node.ledger.rollback(verified.staged);

    assert!(
        drops.is_empty(),
        "battery miss on nonce 0 must not BadNonce-purge nonce 1"
    );
    assert_eq!(proposal.transactions.len(), 1);
    assert_eq!(proposal.transactions[0].id(), filler.id());
}

#[test]
fn a_real_nonce_gap_is_still_dropped() {
    let mut net = Testnet::new();
    let bob = Address([0xbbu8; 32]);
    let now = net.now;
    let filler = Transaction::transfer(net.alice(), bob, 1, 0, now, net.chain_id(), net.genesis_fingerprint()).unwrap();
    let gap = Transaction::transfer(net.alice(), bob, 1, 5, now, net.chain_id(), net.genesis_fingerprint()).unwrap();

    let height = net.nodes[0].ledger.height() + 1;
    let index = net.proposer_index(height);
    let proposer = net.nodes[index].address;
    let node = &mut net.nodes[index];
    let (proposal, verified, drops) = build_proposal(
        &mut node.ledger,
        vec![filler.clone(), gap.clone()],
        Vec::new(),
        now,
        proposer,
        0,
    )
    .unwrap();
    node.ledger.rollback(verified.staged);

    assert_eq!(proposal.transactions.len(), 1);
    assert_eq!(proposal.transactions[0].id(), filler.id());
    assert_eq!(drops, vec![gap.id()]);
}
