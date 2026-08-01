//! Protocol constants.

/// Smallest divisible unit per SIKKA: 1 SIKKA = 10^9 CHILLAR.
pub const CHILLAR_PER_SIKKA: u64 = 1_000_000_000;

/// Anti-spam quota ceiling per account.
pub const MAX_CREDITS: u32 = 100;

/// One credit regenerates every 60 seconds of signed transaction time.
pub const CREDIT_REGEN_SECS: u64 = 60;

/// Every transaction burns exactly one credit.
pub const CREDIT_COST_PER_TX: u32 = 1;

/// A checkpoint is produced every 10,000 confirmed transactions. There is no
/// time-based fallback: an idle network produces no checkpoints.
pub const DEFAULT_CHECKPOINT_TX_INTERVAL: u32 = 10_000;

/// Maximum HTTP request body on bulk federation endpoints (checkpoint
/// proposal/finalized, mempool sync).
///
/// ML-DSA-87 keys and signatures are hex on the wire (~15 KiB JSON per
/// transaction), so a full [`DEFAULT_CHECKPOINT_TX_INTERVAL`] batch is about
/// 150 MiB. 256 MiB leaves headroom for checkpoint metadata and evidence.
/// Smaller routes keep Axum's 2 MiB default.
pub const MAX_HTTP_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Outbound timeout for large peer transfers (proposals, finalized
/// checkpoints, mempool sync, snapshots). Short timeouts are fine for votes
/// and single transactions; bulk payloads over Tor need minutes.
pub const BULK_REQUEST_TIMEOUT_SECS: u64 = 300;

/// Transactions whose signed timestamp differs from a validator's wall clock by
/// more than five minutes are rejected.
pub const TX_TIME_TOLERANCE_SECS: u64 = 300;

/// Minimum validator bond is 0.001% of current total supply, i.e. supply/100000.
pub const MIN_BOND_SUPPLY_DIVISOR: u64 = 100_000;

/// Unbonding cooldown: seven days without rewards, still slashable.
pub const UNBONDING_SECS: u64 = 7 * 24 * 60 * 60;

/// Number of recent checkpoints retained; older ones are pruned.
pub const CHECKPOINT_HISTORY: u64 = 100;

/// Maximum height gap a node may fast-sync across without an independently
/// pinned trusted checkpoint.
///
/// A gap of one height can still be closed by replaying a finalized checkpoint.
/// Anything larger requires `SIKKA_TRUSTED_CHECKPOINT`, even when
/// `validator_root` is unchanged — otherwise a former ≥2/3 set can forge a
/// long-range fork that keeps the same root and trick a stale node.
pub const WEAK_SUBJECTIVITY_GAP: u64 = 1;

/// Votes more than this many heights ahead of the local tip are ignored.
///
/// Stops a bonded key from filling the vote tracker with arbitrary future
/// heights (memory + ML-DSA verification spam).
pub const MAX_VOTE_HEIGHT_AHEAD: u64 = 1;

/// Maximum equivocation proofs accepted in one checkpoint proposal.
pub const MAX_EVIDENCE_PER_CHECKPOINT: usize = 64;

/// Soft cap on JSON/text bodies for non-bulk peer responses (votes, health,
/// single-tx receipts). Bulk routes still use [`MAX_HTTP_BODY_BYTES`].
pub const MAX_RPC_BODY_BYTES: usize = 2 * 1024 * 1024;

/// Seconds in a protocol year (365 days) used by the inflation schedule.
pub const SECONDS_PER_YEAR: u64 = 31_536_000;

/// Fixed annual inflation, 1.5%, expressed in basis points. Never changes.
pub const ANNUAL_INFLATION_BPS: u64 = 150;

/// Port every node listens on.
pub const DEFAULT_PORT: u16 = 64552;

/// Default chain identifier, mixed into genesis.
pub const DEFAULT_CHAIN_ID: &str = "sikka";

/// Hardcoded bootstrap peers used when no override is supplied.
pub const BOOTSTRAP_NODES: &[&str] = &[
    "http://kkd45odg66a5nwubewg4fw5v5wsr6rzbwiclcp6xe3hgtw7q7rdwxuid.onion",
    "http://myqf24ywedvegns2ubwkrmo45zxlbhoo6ss3dbaz4x2flzghlmtq5byd.onion",
    "http://pmz6d5pq6haxc4nmuohhtr2jvvvl6j2lfiowszkxdpn52gokkq4yg5id.onion",
];

/// Bonded stake required to finalize a checkpoint: `ceil(2/3 * total_active_bond)`.
///
/// Quorum is stake-weighted: each active validator contributes its bond, not a
/// flat one-address-one-vote. Equal bonds recover the old headcount rule.
///
/// ```
/// use sikka_common::constants::quorum_bond;
/// assert_eq!(quorum_bond(30_000), 20_000);
/// assert_eq!(quorum_bond(4), 3);
/// assert_eq!(quorum_bond(1), 1);
/// ```
pub const fn quorum_bond(total_active_bond: u64) -> u64 {
    if total_active_bond == 0 {
        return 0;
    }
    (2 * total_active_bond).div_ceil(3)
}

/// Headcount form kept for tests that use equal bonds (identical to
/// [`quorum_bond`] when every validator has bond weight 1).
pub const fn quorum_threshold(validator_count: usize) -> usize {
    quorum_bond(validator_count as u64) as usize
}

/// Minimum bond for the given total supply.
pub const fn min_bond(total_supply: u64) -> u64 {
    let bond = total_supply / MIN_BOND_SUPPLY_DIVISOR;
    if bond == 0 {
        1
    } else {
        bond
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quorum_is_two_thirds_rounded_up() {
        assert_eq!(quorum_bond(0), 0);
        assert_eq!(quorum_bond(1), 1);
        assert_eq!(quorum_bond(2), 2);
        assert_eq!(quorum_bond(3), 2);
        assert_eq!(quorum_bond(4), 3);
        assert_eq!(quorum_bond(40_200), 26_800);
        assert_eq!(quorum_threshold(4), 3);
        assert_eq!(quorum_threshold(100), 67);
    }

    #[test]
    fn quorum_always_exceeds_two_thirds() {
        for n in 1..500u64 {
            let q = quorum_bond(n);
            assert!(q * 3 >= n * 2, "quorum {q} too small for {n}");
            assert!(
                (q - 1) * 3 < n * 2,
                "quorum {q} larger than necessary for {n}"
            );
        }
    }

    #[test]
    fn min_bond_is_one_thousandth_of_a_percent() {
        assert_eq!(min_bond(100_000_000), 1_000);
        assert_eq!(min_bond(0), 1);
    }

    #[test]
    fn http_body_budget_covers_a_full_json_checkpoint() {
        // ~15 KiB JSON per ML-DSA-87 transaction × 10_000 ≈ 150 MiB.
        let approx_full_batch = DEFAULT_CHECKPOINT_TX_INTERVAL as usize * 15 * 1024;
        assert!(MAX_HTTP_BODY_BYTES > approx_full_batch);
        assert_eq!(BULK_REQUEST_TIMEOUT_SECS, 300);
    }
}
