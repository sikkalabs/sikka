//! Checkpoint voting consensus.
//!
//! Consensus here is deliberately small. It does not order transactions, it does
//! not vote on them individually, and it has no Tendermint prevote/precommit
//! rounds. It answers one question: *does at least two thirds of the bonded
//! stake agree that this is the state?*
//!
//! Round-robin proposer takeover still exists: after [`PROPOSER_TIMEOUT_SECS`]
//! the next validator may act. A validator that has already signed at a height
//! must never sign a rival (equivocation), so later rounds **adopt** a known
//! open proposal rather than inventing a new one. Inventing rivals is what
//! deadlocks a 2-of-3 committee when one validator is offline.
//!
//! The pieces:
//!
//! * [`proposer_for`] — round-robin selection, so nobody has to agree on a
//!   leader election.
//! * [`CheckpointProposal`] — a header, the transactions that produced it, and
//!   any slashing evidence, all independently re-checkable.
//! * [`VoteTracker`] — tallies signatures and notices equivocation.
//! * [`Equivocation`] — the only slashable offence. Being offline does not burn
//!   stake; repeated full-batch proposer timeouts force a normal unbond instead.

pub mod equivocation;
pub mod proposal;
pub mod votes;

pub use equivocation::Equivocation;
pub use proposal::{verify_proposal, Authority, CheckpointProposal, VerifiedProposal};
pub use votes::{VoteOutcome, VoteTracker};

use sikka_common::bytes::Address;
use sikka_common::validator::Validator;

/// How long the validator whose turn it is has to produce a checkpoint before
/// the turn passes to the next one.
///
/// Short enough that a dead validator costs seconds rather than minutes; long
/// enough that a slow node (a Raspberry Pi, a busy VPS) is not skipped
/// merely for being slow.
pub const PROPOSER_TIMEOUT_SECS: u64 = 10;

/// The proposer for `height`, chosen round-robin from the active set.
///
/// `active` must be in a canonical order (the ledger returns validators sorted
/// by address). Selection is a pure function of height and set membership, so
/// every node reaches the same answer without any messages.
pub fn proposer_for(height: u64, active: &[Validator]) -> Option<Address> {
    proposer_for_round(height, 0, active)
}

/// The proposer for a given turn at `height`.
///
/// Round 0 is the normal case. Each further round hands the turn to the next
/// validator in line, which is what stops an absent proposer from halting the
/// chain: after [`PROPOSER_TIMEOUT_SECS`] with no checkpoint, the next validator
/// takes over, and the round it used is recorded in the header so every node can
/// check the takeover was legitimate.
pub fn proposer_for_round(height: u64, round: u32, active: &[Validator]) -> Option<Address> {
    Validator::proposer_for_round(height, round, active)
}

/// Which round is due, given how long the previous checkpoint has stood.
///
/// A round is a pure function of two agreed timestamps, so a proposer and its
/// verifiers reach the same conclusion about whose turn it is without
/// exchanging anything.
pub fn round_at(now: u64, last_checkpoint_time: u64) -> u32 {
    let elapsed = now.saturating_sub(last_checkpoint_time);
    u32::try_from(elapsed / PROPOSER_TIMEOUT_SECS).unwrap_or(u32::MAX)
}

/// Whether `candidate` is the proposer for `height` at `round`.
pub fn is_proposer(height: u64, round: u32, active: &[Validator], candidate: &Address) -> bool {
    proposer_for_round(height, round, active).is_some_and(|proposer| &proposer == candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::bytes::PublicKey;
    use sikka_crypto::PK_LEN;

    fn validators(count: u8) -> Vec<Validator> {
        let mut validators: Vec<Validator> = (0..count)
            .map(|i| Validator::new(PublicKey::new([i; PK_LEN]), 1_000, 0))
            .collect();
        validators.sort_by_key(|a| a.address);
        validators
    }

    #[test]
    fn no_validators_means_no_proposer() {
        assert_eq!(proposer_for(0, &[]), None);
    }

    #[test]
    fn selection_rotates_through_the_set() {
        let set = validators(4);
        let picks: Vec<Address> = (0..8).map(|h| proposer_for(h, &set).unwrap()).collect();
        assert_eq!(picks[0], set[0].address);
        assert_eq!(picks[1], set[1].address);
        assert_eq!(picks[2], set[2].address);
        assert_eq!(picks[3], set[3].address);
        // ...and wraps around.
        assert_eq!(picks[4], picks[0]);
        assert_eq!(picks[7], picks[3]);
    }

    #[test]
    fn every_validator_proposes_equally_often() {
        let set = validators(5);
        let mut counts = std::collections::HashMap::new();
        for height in 0..1_000u64 {
            *counts
                .entry(proposer_for(height, &set).unwrap())
                .or_insert(0) += 1;
        }
        assert_eq!(counts.len(), 5);
        for count in counts.values() {
            assert_eq!(*count, 200);
        }
    }

    #[test]
    fn is_proposer_agrees_with_selection() {
        let set = validators(3);
        let expected = proposer_for(7, &set).unwrap();
        assert!(is_proposer(7, 0, &set, &expected));
        let other = set.iter().find(|v| v.address != expected).unwrap();
        assert!(!is_proposer(7, 0, &set, &other.address));
        assert!(!is_proposer(7, 0, &[], &expected));
    }

    #[test]
    fn each_round_hands_the_turn_to_the_next_validator() {
        let set = validators(4);
        // Successive rounds at one height walk the set, so a run of absent
        // validators is worked through rather than stalling.
        let picks: Vec<Address> = (0..5)
            .map(|round| proposer_for_round(9, round, &set).unwrap())
            .collect();
        assert_eq!(picks[0], proposer_for(9, &set).unwrap());
        assert_eq!(picks[1], proposer_for(10, &set).unwrap());
        assert_eq!(
            picks[4], picks[0],
            "four rounds is a full cycle of four validators"
        );
        assert_eq!(
            picks.iter().collect::<std::collections::HashSet<_>>().len(),
            4
        );
    }

    #[test]
    fn rounds_advance_once_per_timeout() {
        let last = 1_700_000_000;
        assert_eq!(round_at(last, last), 0);
        assert_eq!(round_at(last + PROPOSER_TIMEOUT_SECS - 1, last), 0);
        assert_eq!(round_at(last + PROPOSER_TIMEOUT_SECS, last), 1);
        assert_eq!(round_at(last + 3 * PROPOSER_TIMEOUT_SECS + 5, last), 3);
        // A clock behind the last checkpoint must not underflow into a huge round.
        assert_eq!(round_at(last - 500, last), 0);
    }
}
