//! Wall-clock access.
//!
//! The wall clock is only ever used to *bound* a transaction's signed timestamp.
//! Execution itself uses the signed timestamp, so consensus never depends on
//! clock agreement beyond the ±5 minute window.

use std::time::{SystemTime, UNIX_EPOCH};

/// Current unix time in seconds.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_is_plausible() {
        // Later than 2024-01-01 and earlier than 2100.
        let now = now_secs();
        assert!(now > 1_704_067_200, "clock is before 2024: {now}");
        assert!(now < 4_102_444_800, "clock is after 2100: {now}");
    }
}
