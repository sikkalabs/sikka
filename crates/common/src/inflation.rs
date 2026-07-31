//! The inflation schedule: 1.5% annually, forever, with no cap.
//!
//! Inflation is what lets SIKKA stay feeless — validators are paid by the
//! protocol instead of by transactors. Checkpoints fire on transaction count,
//! not on a clock, so the amount minted is a function of the *time elapsed*
//! since the previous checkpoint. An idle network mints nothing; a busy one
//! mints many small amounts. Either way the annual rate holds.
//!
//! Everything here is integer arithmetic. Floating point would be a consensus
//! bug waiting to happen: `powf` is not guaranteed to be bit-identical across
//! platforms, and validators must agree on the last CHILLAR.

use crate::bytes::Address;
use crate::constants::SECONDS_PER_YEAR;

/// Fixed-point scale for the rate computation (10^18).
const SCALE: u128 = 1_000_000_000_000_000_000;

/// `ln(1.015)` scaled by 10^18 = 0.014888612493750216…
///
/// Continuous compounding at this rate is exactly 1.5% per year, so
/// `exp(LN_RATE * dt / year) - 1` is the growth factor for any interval,
/// regardless of how checkpoints are spaced.
const LN_RATE: u128 = 14_888_612_493_750_216;

/// Upper bound on `x = LN_RATE * dt / year` (≈134 years) that keeps the series
/// terms inside `u128`.
const MAX_X: u128 = 2 * SCALE;

/// `exp(x) - 1` in fixed point, computed by summing the Maclaurin series with
/// truncating division.
///
/// Truncation makes the result a slight under-estimate, which is the safe
/// direction: the protocol never mints more than the schedule allows.
fn expm1_fixed(x: u128) -> u128 {
    let x = x.min(MAX_X);
    let mut term = x;
    let mut sum = x;
    let mut n: u128 = 2;
    while term > 0 && n < 40 {
        term = term.saturating_mul(x) / SCALE / n;
        sum = sum.saturating_add(term);
        n += 1;
    }
    sum
}

/// CHILLAR minted for a checkpoint covering `elapsed_secs` of wall time.
pub fn checkpoint_inflation(total_supply: u64, elapsed_secs: u64) -> u64 {
    if total_supply == 0 || elapsed_secs == 0 {
        return 0;
    }
    let x = LN_RATE.saturating_mul(u128::from(elapsed_secs)) / u128::from(SECONDS_PER_YEAR);
    let factor = expm1_fixed(x);
    let minted = u128::from(total_supply).saturating_mul(factor) / SCALE;
    u64::try_from(minted).unwrap_or(u64::MAX)
}

/// Split `amount` across validators in proportion to their bonds.
///
/// `validators` must be in a deterministic order (the ledger sorts by address).
/// Integer division leaves a remainder of at most `validators.len() - 1`
/// CHILLAR, which goes to the proposer — the node that did the work of building
/// the checkpoint — so no CHILLAR is ever created or lost by rounding.
pub fn distribute_rewards(
    amount: u64,
    validators: &[(Address, u64)],
    proposer: &Address,
) -> Vec<(Address, u64)> {
    let total_bonded: u128 = validators.iter().map(|(_, bond)| u128::from(*bond)).sum();
    if amount == 0 || total_bonded == 0 || validators.is_empty() {
        return Vec::new();
    }

    let mut payouts: Vec<(Address, u64)> = Vec::with_capacity(validators.len());
    let mut distributed: u64 = 0;
    for (address, bond) in validators {
        let share = u128::from(amount) * u128::from(*bond) / total_bonded;
        let share = u64::try_from(share).unwrap_or(u64::MAX);
        distributed += share;
        payouts.push((*address, share));
    }

    let remainder = amount - distributed;
    if remainder > 0 {
        // Prefer the proposer; fall back to the first validator if the proposer
        // is not in the set (it always is in practice).
        let index = payouts.iter().position(|(a, _)| a == proposer).unwrap_or(0);
        payouts[index].1 += remainder;
    }

    payouts.retain(|(_, amount)| *amount > 0);
    payouts
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUPPLY: u64 = 1_000_000_000_000_000; // 1M SIKKA in CHILLAR

    #[test]
    fn a_full_year_mints_one_and_a_half_percent() {
        let minted = checkpoint_inflation(SUPPLY, SECONDS_PER_YEAR);
        let expected = SUPPLY / 1000 * 15;
        let drift = minted.abs_diff(expected);
        assert!(
            drift * 1_000_000 < expected,
            "minted {minted}, expected ≈{expected}"
        );
    }

    #[test]
    fn idle_or_empty_chain_mints_nothing() {
        assert_eq!(checkpoint_inflation(SUPPLY, 0), 0);
        assert_eq!(checkpoint_inflation(0, SECONDS_PER_YEAR), 0);
    }

    #[test]
    fn many_small_checkpoints_match_one_large_one() {
        // The schedule must not depend on how often checkpoints fire.
        let step = SECONDS_PER_YEAR / 365;
        let mut supply = SUPPLY;
        for _ in 0..365 {
            supply += checkpoint_inflation(supply, step);
        }
        let one_shot = SUPPLY + checkpoint_inflation(SUPPLY, SECONDS_PER_YEAR);
        let drift = supply.abs_diff(one_shot);
        assert!(
            drift * 100_000 < one_shot,
            "compounded {supply} vs single {one_shot}"
        );
    }

    #[test]
    fn inflation_is_monotonic_in_time_and_supply() {
        let mut previous = 0;
        for days in 1..60u64 {
            let minted = checkpoint_inflation(SUPPLY, days * 86_400);
            assert!(minted >= previous);
            previous = minted;
        }
        assert!(checkpoint_inflation(SUPPLY * 2, 86_400) > checkpoint_inflation(SUPPLY, 86_400));
    }

    #[test]
    fn extreme_inputs_do_not_overflow() {
        assert!(checkpoint_inflation(u64::MAX, u64::MAX) > 0);
        assert!(checkpoint_inflation(u64::MAX, SECONDS_PER_YEAR * 1_000) > 0);
    }

    #[test]
    fn ten_second_checkpoint_mints_a_sane_amount() {
        // 1.5%/year on 1,000,000 SIKKA is 15,000 SIKKA a year, which is about
        // 475,646 CHILLAR a second.
        let minted = checkpoint_inflation(SUPPLY, 10);
        assert!((4_700_000..=4_800_000).contains(&minted), "minted {minted}");
    }

    #[test]
    fn rewards_are_proportional_to_bond() {
        let a = Address([1u8; 32]);
        let b = Address([2u8; 32]);
        let payouts = distribute_rewards(300, &[(a, 100), (b, 200)], &a);
        assert_eq!(payouts, vec![(a, 100), (b, 200)]);
    }

    #[test]
    fn remainder_goes_to_the_proposer_and_nothing_is_lost() {
        let a = Address([1u8; 32]);
        let b = Address([2u8; 32]);
        let c = Address([3u8; 32]);
        let validators = [(a, 1), (b, 1), (c, 1)];
        let payouts = distribute_rewards(100, &validators, &b);
        let total: u64 = payouts.iter().map(|(_, v)| v).sum();
        assert_eq!(total, 100);
        let to_b = payouts.iter().find(|(x, _)| *x == b).unwrap().1;
        assert_eq!(to_b, 34);
    }

    #[test]
    fn zero_amount_or_no_bonds_pays_nobody() {
        let a = Address([1u8; 32]);
        assert!(distribute_rewards(0, &[(a, 10)], &a).is_empty());
        assert!(distribute_rewards(10, &[(a, 0)], &a).is_empty());
        assert!(distribute_rewards(10, &[], &a).is_empty());
    }

    #[test]
    fn dust_rewards_still_conserve_the_total() {
        let a = Address([1u8; 32]);
        let b = Address([2u8; 32]);
        let payouts = distribute_rewards(1, &[(a, 500), (b, 500)], &a);
        let total: u64 = payouts.iter().map(|(_, v)| v).sum();
        assert_eq!(total, 1);
    }
}
