//! Vote tallying.
//!
//! Finality requires ≥2/3 bonded stake of **precommits** for a checkpoint.
//! Precommits are only cast after the same stake threshold of **prevotes** in
//! that round — so a temporary partition cannot permanently lock honest
//! validators onto different hashes (they have only prevoted, and may prevote
//! again in a later round).

use std::collections::HashMap;

use sikka_common::bytes::{Address, Hash};
use sikka_common::checkpoint::ValidatorSignature;
use sikka_common::constants::{quorum_bond, MAX_VOTE_ROUND_AHEAD};
use sikka_common::error::{Error, Result};
use sikka_common::vote::{Vote, VoteKind};

use crate::equivocation::Equivocation;

/// What happened when a vote was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteOutcome {
    /// First vote from this validator at this height/round/kind.
    Accepted { checkpoint_hash: Hash, votes: usize },
    /// The same vote again; harmless when gossiped.
    Duplicate,
    /// Two different hashes for the same `(height, round, kind)`.
    Equivocated(Box<Equivocation>),
}

#[derive(Debug, Default)]
struct StepVotes {
    by_validator: HashMap<Address, Vote>,
}

/// Votes for checkpoints that are not yet final.
#[derive(Debug)]
pub struct VoteTracker {
    chain_id: String,
    genesis_fingerprint: Hash,
    heights: HashMap<u64, HeightVotes>,
    equivocations: Vec<Equivocation>,
}

#[derive(Debug, Default)]
struct HeightVotes {
    /// Keyed by `(round, kind)`.
    steps: HashMap<(u32, VoteKind), StepVotes>,
    /// Highest round seen at this height, for the future-round bound.
    max_round: Option<u32>,
}

impl VoteTracker {
    pub fn new(chain_id: impl Into<String>, genesis_fingerprint: Hash) -> Self {
        Self {
            chain_id: chain_id.into(),
            genesis_fingerprint,
            heights: HashMap::new(),
            equivocations: Vec::new(),
        }
    }

    /// Record a vote, verifying its signature first.
    pub fn record(&mut self, vote: Vote) -> Result<VoteOutcome> {
        vote.verify(&self.chain_id, &self.genesis_fingerprint)?;
        let height = self.heights.entry(vote.height).or_default();
        // Bound future rounds: tentative votes at an arbitrary round are the
        // one knob a bonded key can turn to fill this tracker (and this node's
        // ML-DSA budget) without bound. A round is a 10s proposer turn derived
        // from the last checkpoint, so anything well past the highest round
        // already seen here is never legitimate.
        if let Some(max_round) = height.max_round {
            if vote.round > max_round.saturating_add(MAX_VOTE_ROUND_AHEAD) {
                return Err(Error::Other(format!(
                    "vote round {} is more than {MAX_VOTE_ROUND_AHEAD} ahead of the highest \
                     tracked round {max_round}",
                    vote.round
                )));
            }
        }
        let step = height
            .steps
            .entry((vote.round, vote.kind))
            .or_default();
        height.max_round = Some(
            height
                .max_round
                .map_or(vote.round, |max| max.max(vote.round)),
        );

        if let Some(existing) = step.by_validator.get(&vote.validator) {
            if existing.checkpoint_hash == vote.checkpoint_hash {
                return Ok(VoteOutcome::Duplicate);
            }
            let evidence = Equivocation::new(
                existing.clone(),
                vote,
                &self.chain_id,
                &self.genesis_fingerprint,
            )?;
            self.equivocations.push(evidence.clone());
            return Ok(VoteOutcome::Equivocated(Box::new(evidence)));
        }

        let checkpoint_hash = vote.checkpoint_hash;
        let validator = vote.validator;
        step.by_validator.insert(validator, vote);
        let votes = step
            .by_validator
            .values()
            .filter(|v| v.checkpoint_hash == checkpoint_hash)
            .count();
        Ok(VoteOutcome::Accepted {
            checkpoint_hash,
            votes,
        })
    }

    /// Headcount of votes for a specific step and hash.
    pub fn tally(
        &self,
        height: u64,
        round: u32,
        kind: VoteKind,
        checkpoint_hash: &Hash,
    ) -> usize {
        self.step(height, round, kind)
            .map(|s| {
                s.by_validator
                    .values()
                    .filter(|v| &v.checkpoint_hash == checkpoint_hash)
                    .count()
            })
            .unwrap_or(0)
    }

    pub fn bond_among(
        &self,
        height: u64,
        round: u32,
        kind: VoteKind,
        checkpoint_hash: &Hash,
        authorized: &[(Address, u64)],
    ) -> u64 {
        let Some(step) = self.step(height, round, kind) else {
            return 0;
        };
        authorized
            .iter()
            .filter(|(address, _)| {
                step.by_validator
                    .get(address)
                    .is_some_and(|v| &v.checkpoint_hash == checkpoint_hash)
            })
            .map(|(_, bond)| *bond)
            .fold(0u64, |acc, bond| acc.saturating_add(bond))
    }

    pub fn has_quorum(
        &self,
        height: u64,
        round: u32,
        kind: VoteKind,
        checkpoint_hash: &Hash,
        authorized: &[(Address, u64)],
    ) -> bool {
        let total: u64 = authorized
            .iter()
            .map(|(_, bond)| *bond)
            .fold(0u64, |acc, bond| acc.saturating_add(bond));
        let needed = quorum_bond(total);
        needed > 0
            && self.bond_among(height, round, kind, checkpoint_hash, authorized) >= needed
    }

    /// Precommit signatures to embed, ordered by validator address.
    pub fn signatures(
        &self,
        height: u64,
        round: u32,
        checkpoint_hash: &Hash,
        authorized: &[Address],
    ) -> Vec<ValidatorSignature> {
        let Some(step) = self.step(height, round, VoteKind::Precommit) else {
            return Vec::new();
        };
        let mut signatures: Vec<ValidatorSignature> = authorized
            .iter()
            .filter_map(|address| step.by_validator.get(address))
            .filter(|vote| &vote.checkpoint_hash == checkpoint_hash)
            .cloned()
            .map(Vote::into_signature)
            .collect();
        signatures.sort_by_key(|a| a.validator);
        signatures
    }

    /// Lexicographically first prefix of `signatures` whose bonds sum to at
    /// least `needed`.
    pub fn quorum_prefix(
        signatures: &[ValidatorSignature],
        bonds: &HashMap<Address, u64>,
        needed: u64,
    ) -> Option<usize> {
        if needed == 0 {
            return None;
        }
        let mut bonded: u64 = 0;
        for (i, sig) in signatures.iter().enumerate() {
            bonded = bonded.saturating_add(*bonds.get(&sig.validator).unwrap_or(&0));
            if bonded >= needed {
                return Some(i + 1);
            }
        }
        None
    }

    /// A validator's vote at a specific step, if any.
    pub fn vote_by(
        &self,
        height: u64,
        round: u32,
        kind: VoteKind,
        validator: &Address,
    ) -> Option<&Vote> {
        self.step(height, round, kind)?.by_validator.get(validator)
    }

    /// This validator's precommit lock at `height`, if any (any round).
    ///
    /// Once a precommit exists, the node must not vote for a rival hash at this
    /// height.
    pub fn precommit_lock(&self, height: u64, validator: &Address) -> Option<&Vote> {
        let height_votes = self.heights.get(&height)?;
        let mut best: Option<&Vote> = None;
        for ((_, kind), step) in &height_votes.steps {
            if *kind != VoteKind::Precommit {
                continue;
            }
            if let Some(vote) = step.by_validator.get(validator) {
                if best.is_none_or(|b| vote.round >= b.round) {
                    best = Some(vote);
                }
            }
        }
        best
    }

    /// Whether this validator has cast any vote at `height` (any step).
    pub fn has_any_vote(&self, height: u64, validator: &Address) -> bool {
        let Some(height_votes) = self.heights.get(&height) else {
            return false;
        };
        height_votes
            .steps
            .values()
            .any(|s| s.by_validator.contains_key(validator))
    }

    /// Popular prevote hashes at a height/round.
    pub fn prevote_candidates(&self, height: u64, round: u32) -> Vec<(Hash, usize)> {
        self.candidates(height, round, VoteKind::Prevote)
    }

    pub fn candidates(&self, height: u64, round: u32, kind: VoteKind) -> Vec<(Hash, usize)> {
        let Some(step) = self.step(height, round, kind) else {
            return Vec::new();
        };
        let mut counts: HashMap<Hash, usize> = HashMap::new();
        for vote in step.by_validator.values() {
            *counts.entry(vote.checkpoint_hash).or_insert(0) += 1;
        }
        let mut out: Vec<(Hash, usize)> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }

    pub fn equivocations(&self) -> &[Equivocation] {
        &self.equivocations
    }

    pub fn drain_equivocations(&mut self) -> Vec<Equivocation> {
        std::mem::take(&mut self.equivocations)
    }

    /// Record partition-healed equivocation without requiring both votes locally.
    pub fn note_equivocation(&mut self, evidence: Equivocation) {
        let duplicate = self.equivocations.iter().any(|existing| {
            existing.validator == evidence.validator
                && existing.height == evidence.height
                && existing.first.checkpoint_hash == evidence.first.checkpoint_hash
                && existing.second.checkpoint_hash == evidence.second.checkpoint_hash
        });
        if !duplicate {
            self.equivocations.push(evidence);
        }
    }

    pub fn prune_below(&mut self, height: u64) {
        self.heights.retain(|h, _| *h >= height);
    }

    pub fn tracked_heights(&self) -> usize {
        self.heights.len()
    }

    fn step(&self, height: u64, round: u32, kind: VoteKind) -> Option<&StepVotes> {
        self.heights.get(&height)?.steps.get(&(round, kind))
    }
}

/// Verify that a vote comes from a validator in `authorized`.
pub fn check_voter_authorized(vote: &Vote, authorized: &[Address]) -> Result<()> {
    if !authorized.contains(&vote.validator) {
        return Err(Error::UnknownVoter(vote.validator));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::PublicKey;
    use sikka_crypto::Keypair;

    struct Committee {
        keys: Vec<Keypair>,
    }

    fn chain_id() -> &'static str {
        "sikka-test"
    }

    fn fingerprint() -> Hash {
        Hash([0xAA; 32])
    }

    impl Committee {
        fn new(size: usize) -> Self {
            Self {
                keys: (0..size).map(|_| Keypair::generate().unwrap()).collect(),
            }
        }

        fn addresses(&self) -> Vec<Address> {
            self.keys
                .iter()
                .map(|k| PublicKey::new(*k.public_bytes()).address())
                .collect()
        }

        fn bonds(&self) -> Vec<(Address, u64)> {
            self.addresses().into_iter().map(|a| (a, 1)).collect()
        }

        fn prevote(&self, index: usize, height: u64, round: u32, hash: Hash) -> Vote {
            Vote::sign(
                &self.keys[index],
                chain_id(),
                fingerprint(),
                height,
                round,
                VoteKind::Prevote,
                hash,
            )
            .unwrap()
        }

        fn precommit(&self, index: usize, height: u64, round: u32, hash: Hash) -> Vote {
            Vote::sign(
                &self.keys[index],
                chain_id(),
                fingerprint(),
                height,
                round,
                VoteKind::Precommit,
                hash,
            )
            .unwrap()
        }
    }

    #[test]
    fn precommits_need_two_thirds_to_finalize() {
        let committee = Committee::new(4);
        let authorized = committee.bonds();
        let addresses = committee.addresses();
        let hash = Hash([1u8; 32]);
        let mut tracker = VoteTracker::new(chain_id(), fingerprint());

        tracker
            .record(committee.precommit(0, 1, 0, hash))
            .unwrap();
        tracker
            .record(committee.precommit(1, 1, 0, hash))
            .unwrap();
        assert!(!tracker.has_quorum(1, 0, VoteKind::Precommit, &hash, &authorized));

        tracker
            .record(committee.precommit(2, 1, 0, hash))
            .unwrap();
        assert!(tracker.has_quorum(1, 0, VoteKind::Precommit, &hash, &authorized));
        assert_eq!(tracker.signatures(1, 0, &hash, &addresses).len(), 3);
    }

    #[test]
    fn different_rounds_may_prevote_different_hashes() {
        let committee = Committee::new(3);
        let mut tracker = VoteTracker::new(chain_id(), fingerprint());
        tracker
            .record(committee.prevote(0, 1, 0, Hash([1u8; 32])))
            .unwrap();
        // Same validator, later round, different hash — not equivocation.
        assert!(matches!(
            tracker
                .record(committee.prevote(0, 1, 1, Hash([2u8; 32])))
                .unwrap(),
            VoteOutcome::Accepted { .. }
        ));
    }

    #[test]
    fn same_round_conflicting_prevotes_are_equivocation() {
        let committee = Committee::new(3);
        let mut tracker = VoteTracker::new(chain_id(), fingerprint());
        tracker
            .record(committee.prevote(0, 1, 0, Hash([1u8; 32])))
            .unwrap();
        let outcome = tracker
            .record(committee.prevote(0, 1, 0, Hash([2u8; 32])))
            .unwrap();
        assert!(matches!(outcome, VoteOutcome::Equivocated(_)));
    }

    #[test]
    fn a_precommit_is_a_lock_at_the_height() {
        let committee = Committee::new(2);
        let mut tracker = VoteTracker::new(chain_id(), fingerprint());
        let hash = Hash([9u8; 32]);
        tracker
            .record(committee.precommit(0, 3, 2, hash))
            .unwrap();
        let lock = tracker
            .precommit_lock(3, &committee.addresses()[0])
            .unwrap();
        assert_eq!(lock.checkpoint_hash, hash);
        assert_eq!(lock.round, 2);
    }

    #[test]
    fn empty_validator_set_never_reaches_quorum() {
        let tracker = VoteTracker::new(chain_id(), fingerprint());
        assert!(!tracker.has_quorum(1, 0, VoteKind::Precommit, &Hash([1u8; 32]), &[]));
    }

    #[test]
    fn rounds_more_than_the_allowed_gap_ahead_are_rejected() {
        let committee = Committee::new(3);
        let mut tracker = VoteTracker::new(chain_id(), fingerprint());
        let round = MAX_VOTE_ROUND_AHEAD + 2;
        assert!(matches!(
            tracker.record(committee.prevote(0, 1, round, Hash([1u8; 32]))),
            Ok(VoteOutcome::Accepted { .. })
        ));
        // Far beyond the highest round already recorded at this height.
        match tracker.record(committee.prevote(0, 1, round + MAX_VOTE_ROUND_AHEAD + 1, Hash([2u8; 32])))
        {
            Err(Error::Other(_)) => {}
            other => panic!("expected the round gap to be rejected, got {other:?}"),
        }
        // A legitimate early-round vote for the same height is still accepted.
        assert!(matches!(
            tracker.record(committee.prevote(0, 1, 0, Hash([3u8; 32]))),
            Ok(VoteOutcome::Accepted { .. })
        ));
    }
}
