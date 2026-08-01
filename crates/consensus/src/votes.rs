//! Vote tallying.
//!
//! A checkpoint is final when ≥2/3 of the **bonded stake** of the active set has
//! signed it. The tracker keeps one vote per validator per height, so a
//! validator who tries to sign two different checkpoints at the same height is
//! not just ignored — the attempt produces [`Equivocation`] evidence that burns
//! their bond.

use std::collections::HashMap;

use sikka_common::bytes::{Address, Hash};
use sikka_common::checkpoint::ValidatorSignature;
use sikka_common::constants::quorum_bond;
use sikka_common::error::{Error, Result};
use sikka_common::vote::Vote;

use crate::equivocation::Equivocation;

/// What happened when a vote was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteOutcome {
    /// First vote from this validator at this height.
    Accepted { checkpoint_hash: Hash, votes: usize },
    /// The same vote again; harmless, and common when votes are gossiped.
    Duplicate,
    /// The validator already voted for a different checkpoint at this height.
    Equivocated(Box<Equivocation>),
}

#[derive(Debug, Default)]
struct HeightVotes {
    by_validator: HashMap<Address, Vote>,
}

/// Votes for checkpoints that are not yet final.
#[derive(Debug, Default)]
pub struct VoteTracker {
    heights: HashMap<u64, HeightVotes>,
    equivocations: Vec<Equivocation>,
}

impl VoteTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a vote, verifying its signature first.
    ///
    /// The caller decides whether the voter is in the active set; the tracker
    /// only cares that the signature is real, so votes can be gossiped and
    /// tallied before the relevant validator set is known.
    pub fn record(&mut self, vote: Vote) -> Result<VoteOutcome> {
        vote.verify()?;
        let height = self.heights.entry(vote.height).or_default();

        if let Some(existing) = height.by_validator.get(&vote.validator) {
            if existing.checkpoint_hash == vote.checkpoint_hash {
                return Ok(VoteOutcome::Duplicate);
            }
            let evidence = Equivocation::new(existing.clone(), vote)?;
            self.equivocations.push(evidence.clone());
            return Ok(VoteOutcome::Equivocated(Box::new(evidence)));
        }

        let checkpoint_hash = vote.checkpoint_hash;
        let validator = vote.validator;
        height.by_validator.insert(validator, vote);
        let votes = height
            .by_validator
            .values()
            .filter(|v| v.checkpoint_hash == checkpoint_hash)
            .count();
        Ok(VoteOutcome::Accepted {
            checkpoint_hash,
            votes,
        })
    }

    /// Number of votes for a specific checkpoint.
    pub fn tally(&self, height: u64, checkpoint_hash: &Hash) -> usize {
        self.heights
            .get(&height)
            .map(|h| {
                h.by_validator
                    .values()
                    .filter(|v| &v.checkpoint_hash == checkpoint_hash)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Headcount of votes for a checkpoint restricted to an authorized set.
    pub fn tally_among(
        &self,
        height: u64,
        checkpoint_hash: &Hash,
        authorized: &[Address],
    ) -> usize {
        self.heights
            .get(&height)
            .map(|h| {
                authorized
                    .iter()
                    .filter(|address| {
                        h.by_validator
                            .get(address)
                            .is_some_and(|v| &v.checkpoint_hash == checkpoint_hash)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    /// Bonded stake among `authorized` that has voted for `checkpoint_hash`.
    ///
    /// `authorized` is `(address, bond)` for each active validator.
    pub fn bond_among(
        &self,
        height: u64,
        checkpoint_hash: &Hash,
        authorized: &[(Address, u64)],
    ) -> u64 {
        let Some(votes) = self.heights.get(&height) else {
            return 0;
        };
        authorized
            .iter()
            .filter(|(address, _)| {
                votes
                    .by_validator
                    .get(address)
                    .is_some_and(|v| &v.checkpoint_hash == checkpoint_hash)
            })
            .map(|(_, bond)| *bond)
            .fold(0u64, |acc, bond| acc.saturating_add(bond))
    }

    /// Whether a checkpoint has reached ≥2/3 of the active bonded stake.
    pub fn has_quorum(
        &self,
        height: u64,
        checkpoint_hash: &Hash,
        authorized: &[(Address, u64)],
    ) -> bool {
        let total: u64 = authorized.iter().map(|(_, bond)| *bond).sum();
        let needed = quorum_bond(total);
        needed > 0 && self.bond_among(height, checkpoint_hash, authorized) >= needed
    }

    /// Signatures to embed in a finalized checkpoint, ordered by validator
    /// address so every node produces byte-identical checkpoints.
    pub fn signatures(
        &self,
        height: u64,
        checkpoint_hash: &Hash,
        authorized: &[Address],
    ) -> Vec<ValidatorSignature> {
        let Some(votes) = self.heights.get(&height) else {
            return Vec::new();
        };
        let mut signatures: Vec<ValidatorSignature> = authorized
            .iter()
            .filter_map(|address| votes.by_validator.get(address))
            .filter(|vote| &vote.checkpoint_hash == checkpoint_hash)
            .cloned()
            .map(Vote::into_signature)
            .collect();
        signatures.sort_by_key(|a| a.validator);
        signatures
    }

    /// Lexicographically first prefix of `signatures` whose bonds sum to at
    /// least `needed`. Returns `None` if the full set is still short.
    ///
    /// Used so a late fallback finalizer embeds the same `last_signers` the
    /// proposer would have, as long as both have seen those voters.
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

    /// A validator's vote at a height, if any. Used to build evidence when a
    /// conflicting vote shows up later.
    pub fn vote_by(&self, height: u64, validator: &Address) -> Option<&Vote> {
        self.heights.get(&height)?.by_validator.get(validator)
    }

    /// All checkpoint hashes seen at a height, with their vote counts.
    pub fn candidates(&self, height: u64) -> Vec<(Hash, usize)> {
        let Some(votes) = self.heights.get(&height) else {
            return Vec::new();
        };
        let mut counts: HashMap<Hash, usize> = HashMap::new();
        for vote in votes.by_validator.values() {
            *counts.entry(vote.checkpoint_hash).or_insert(0) += 1;
        }
        let mut out: Vec<(Hash, usize)> = counts.into_iter().collect();
        out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        out
    }

    pub fn equivocations(&self) -> &[Equivocation] {
        &self.equivocations
    }

    /// Take the accumulated evidence, for inclusion in the next checkpoint.
    pub fn drain_equivocations(&mut self) -> Vec<Equivocation> {
        std::mem::take(&mut self.equivocations)
    }

    /// Forget votes for heights that are already final.
    pub fn prune_below(&mut self, height: u64) {
        self.heights.retain(|h, _| *h >= height);
    }

    pub fn tracked_heights(&self) -> usize {
        self.heights.len()
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

        /// Equal unit bonds — recovers the old headcount quorum.
        fn bonds(&self) -> Vec<(Address, u64)> {
            self.addresses().into_iter().map(|a| (a, 1)).collect()
        }

        fn vote(&self, index: usize, height: u64, hash: Hash) -> Vote {
            Vote::sign(&self.keys[index], height, hash).unwrap()
        }
    }

    #[test]
    fn quorum_needs_two_thirds_of_the_active_bond() {
        let committee = Committee::new(4);
        let authorized = committee.bonds();
        let addresses = committee.addresses();
        let hash = Hash([1u8; 32]);
        let mut tracker = VoteTracker::new();

        assert!(!tracker.has_quorum(1, &hash, &authorized));

        tracker.record(committee.vote(0, 1, hash)).unwrap();
        tracker.record(committee.vote(1, 1, hash)).unwrap();
        assert_eq!(tracker.tally(1, &hash), 2);
        assert!(
            !tracker.has_quorum(1, &hash, &authorized),
            "2 of 4 equal bonds is not enough"
        );

        tracker.record(committee.vote(2, 1, hash)).unwrap();
        assert!(
            tracker.has_quorum(1, &hash, &authorized),
            "3 of 4 equal bonds is enough"
        );
        assert_eq!(tracker.signatures(1, &hash, &addresses).len(), 3);
    }

    #[test]
    fn a_majority_of_stake_finalizes_even_with_a_minority_of_validators() {
        let committee = Committee::new(3);
        let addrs = committee.addresses();
        // Whale holds 70%; two minnows hold 15% each. Quorum is ceil(2/3 * 100) = 67.
        let authorized = vec![(addrs[0], 70), (addrs[1], 15), (addrs[2], 15)];
        let hash = Hash([1u8; 32]);
        let mut tracker = VoteTracker::new();

        tracker.record(committee.vote(0, 1, hash)).unwrap();
        assert!(
            tracker.has_quorum(1, &hash, &authorized),
            "70 of 100 bonded stake is a two-thirds majority"
        );

        // Minnows alone cannot finalize against the full active bond.
        let mut without_whale = VoteTracker::new();
        without_whale.record(committee.vote(1, 1, hash)).unwrap();
        without_whale.record(committee.vote(2, 1, hash)).unwrap();
        assert!(
            !without_whale.has_quorum(1, &hash, &authorized),
            "30 of 100 bonded stake is not enough"
        );
    }

    #[test]
    fn duplicate_votes_are_idempotent() {
        let committee = Committee::new(3);
        let hash = Hash([1u8; 32]);
        let mut tracker = VoteTracker::new();

        let vote = committee.vote(0, 1, hash);
        assert!(matches!(
            tracker.record(vote.clone()).unwrap(),
            VoteOutcome::Accepted { votes: 1, .. }
        ));
        assert_eq!(tracker.record(vote).unwrap(), VoteOutcome::Duplicate);
        assert_eq!(tracker.tally(1, &hash), 1);
    }

    #[test]
    fn conflicting_votes_produce_evidence() {
        let committee = Committee::new(3);
        let mut tracker = VoteTracker::new();

        tracker
            .record(committee.vote(0, 1, Hash([1u8; 32])))
            .unwrap();
        let outcome = tracker
            .record(committee.vote(0, 1, Hash([2u8; 32])))
            .unwrap();

        let VoteOutcome::Equivocated(evidence) = outcome else {
            panic!("expected equivocation, got {outcome:?}");
        };
        evidence.verify().unwrap();
        assert_eq!(evidence.height, 1);
        assert_eq!(tracker.equivocations().len(), 1);

        // The original vote is kept; the conflicting one is not counted.
        assert_eq!(tracker.tally(1, &Hash([1u8; 32])), 1);
        assert_eq!(tracker.tally(1, &Hash([2u8; 32])), 0);

        assert_eq!(tracker.drain_equivocations().len(), 1);
        assert!(tracker.equivocations().is_empty());
    }

    #[test]
    fn votes_from_outsiders_do_not_count_towards_quorum() {
        let committee = Committee::new(3);
        let outsider = Keypair::generate().unwrap();
        let authorized = committee.bonds();
        let addresses = committee.addresses();
        let hash = Hash([1u8; 32]);

        let mut tracker = VoteTracker::new();
        tracker.record(committee.vote(0, 1, hash)).unwrap();
        tracker.record(committee.vote(1, 1, hash)).unwrap();
        tracker
            .record(Vote::sign(&outsider, 1, hash).unwrap())
            .unwrap();

        // Three votes recorded, but only two from the active set.
        assert_eq!(tracker.tally(1, &hash), 3);
        assert_eq!(tracker.tally_among(1, &hash, &addresses), 2);
        assert!(
            tracker.has_quorum(1, &hash, &authorized),
            "2 of 3 equal bonds is a two-thirds majority"
        );
        assert_eq!(tracker.signatures(1, &hash, &addresses).len(), 2);

        let outsider_vote = Vote::sign(&outsider, 1, hash).unwrap();
        assert!(check_voter_authorized(&outsider_vote, &addresses).is_err());
        assert!(check_voter_authorized(&committee.vote(0, 1, hash), &addresses).is_ok());
    }

    #[test]
    fn forged_votes_are_refused() {
        let committee = Committee::new(3);
        let mut tracker = VoteTracker::new();
        let mut vote = committee.vote(0, 1, Hash([1u8; 32]));
        vote.checkpoint_hash = Hash([9u8; 32]);
        assert_eq!(tracker.record(vote).unwrap_err(), Error::InvalidSignature);
        assert_eq!(tracker.tally(1, &Hash([9u8; 32])), 0);
    }

    #[test]
    fn split_votes_are_reported_by_popularity() {
        let committee = Committee::new(5);
        let mut tracker = VoteTracker::new();
        let a = Hash([1u8; 32]);
        let b = Hash([2u8; 32]);

        tracker.record(committee.vote(0, 1, a)).unwrap();
        tracker.record(committee.vote(1, 1, a)).unwrap();
        tracker.record(committee.vote(2, 1, a)).unwrap();
        tracker.record(committee.vote(3, 1, b)).unwrap();

        let candidates = tracker.candidates(1);
        assert_eq!(candidates, vec![(a, 3), (b, 1)]);

        // Neither reaches 4 of 5, so nothing finalizes: the chain stalls rather
        // than forking.
        let authorized = committee.bonds();
        assert!(!tracker.has_quorum(1, &a, &authorized));
        assert!(!tracker.has_quorum(1, &b, &authorized));
    }

    #[test]
    fn pruning_forgets_finalized_heights() {
        let committee = Committee::new(3);
        let mut tracker = VoteTracker::new();
        for height in 1..=5 {
            tracker
                .record(committee.vote(0, height, Hash([height as u8; 32])))
                .unwrap();
        }
        assert_eq!(tracker.tracked_heights(), 5);
        tracker.prune_below(4);
        assert_eq!(tracker.tracked_heights(), 2);
        assert_eq!(tracker.tally(3, &Hash([3u8; 32])), 0);
        assert_eq!(tracker.tally(4, &Hash([4u8; 32])), 1);
    }

    #[test]
    fn a_single_validator_chain_finalizes_alone() {
        let committee = Committee::new(1);
        let authorized = committee.bonds();
        let hash = Hash([1u8; 32]);
        let mut tracker = VoteTracker::new();
        tracker.record(committee.vote(0, 1, hash)).unwrap();
        assert!(tracker.has_quorum(1, &hash, &authorized));
    }

    #[test]
    fn empty_validator_set_never_reaches_quorum() {
        let tracker = VoteTracker::new();
        assert!(!tracker.has_quorum(1, &Hash([1u8; 32]), &[]));
    }

    #[test]
    fn vote_lookup_finds_a_validators_vote() {
        let committee = Committee::new(2);
        let mut tracker = VoteTracker::new();
        let vote = committee.vote(1, 3, Hash([7u8; 32]));
        tracker.record(vote.clone()).unwrap();
        assert_eq!(tracker.vote_by(3, &vote.validator), Some(&vote));
        assert_eq!(tracker.vote_by(4, &vote.validator), None);
    }

    #[test]
    fn quorum_prefix_is_lex_first_until_bond_met() {
        let committee = Committee::new(3);
        let hash = Hash([1u8; 32]);
        let mut tracker = VoteTracker::new();
        for i in 0..3 {
            tracker.record(committee.vote(i, 1, hash)).unwrap();
        }
        let addresses = committee.addresses();
        let sigs = tracker.signatures(1, &hash, &addresses);
        let bonds: HashMap<Address, u64> = addresses.iter().map(|a| (*a, 10)).collect();
        assert_eq!(VoteTracker::quorum_prefix(&sigs, &bonds, 20), Some(2));
        assert_eq!(VoteTracker::quorum_prefix(&sigs, &bonds, 30), Some(3));
        assert_eq!(VoteTracker::quorum_prefix(&sigs, &bonds, 31), None);
    }
}
