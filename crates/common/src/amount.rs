//! Human-facing SIKKA ↔ CHILLAR conversion.
//!
//! Every internal amount is an integer count of CHILLAR; SIKKA is presentation
//! only. Floating point never touches a balance.

use crate::constants::CHILLAR_PER_SIKKA;
use crate::error::{Error, Result};

/// Render CHILLAR as SIKKA with up to nine decimal places, trailing zeros
/// trimmed.
pub fn format_sikka(chillar: u64) -> String {
    let whole = chillar / CHILLAR_PER_SIKKA;
    let frac = chillar % CHILLAR_PER_SIKKA;
    if frac == 0 {
        return whole.to_string();
    }
    let frac = format!("{frac:09}");
    format!("{whole}.{}", frac.trim_end_matches('0'))
}

/// Parse a decimal SIKKA amount into CHILLAR.
pub fn parse_sikka(input: &str) -> Result<u64> {
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::Other("empty amount".into()));
    }
    let (whole, frac) = match input.split_once('.') {
        Some((w, f)) => (w, f),
        None => (input, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return Err(Error::Other("empty amount".into()));
    }
    if frac.len() > 9 {
        return Err(Error::Other("SIKKA has at most 9 decimal places".into()));
    }
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::Other(format!("'{input}' is not a decimal amount")));
    }

    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().map_err(|_| Error::BalanceOverflow)?
    };
    let mut padded = frac.to_string();
    while padded.len() < 9 {
        padded.push('0');
    }
    let frac: u64 = if padded.is_empty() {
        0
    } else {
        padded.parse().map_err(|_| Error::BalanceOverflow)?
    };

    whole
        .checked_mul(CHILLAR_PER_SIKKA)
        .and_then(|c| c.checked_add(frac))
        .ok_or(Error::BalanceOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_whole_and_fractional_amounts() {
        assert_eq!(format_sikka(0), "0");
        assert_eq!(format_sikka(CHILLAR_PER_SIKKA), "1");
        assert_eq!(format_sikka(CHILLAR_PER_SIKKA * 120), "120");
        assert_eq!(format_sikka(1), "0.000000001");
        assert_eq!(format_sikka(CHILLAR_PER_SIKKA + 500_000_000), "1.5");
        assert_eq!(format_sikka(1_234_567_891), "1.234567891");
    }

    #[test]
    fn parses_decimal_amounts() {
        assert_eq!(parse_sikka("1").unwrap(), CHILLAR_PER_SIKKA);
        assert_eq!(parse_sikka("1.5").unwrap(), 1_500_000_000);
        assert_eq!(parse_sikka("0.000000001").unwrap(), 1);
        assert_eq!(parse_sikka(" 120 ").unwrap(), 120 * CHILLAR_PER_SIKKA);
        assert_eq!(parse_sikka(".5").unwrap(), 500_000_000);
        assert_eq!(parse_sikka("7.").unwrap(), 7 * CHILLAR_PER_SIKKA);
    }

    #[test]
    fn rejects_garbage_and_overflow() {
        assert!(parse_sikka("").is_err());
        assert!(parse_sikka("abc").is_err());
        assert!(parse_sikka("1.2.3").is_err());
        assert!(parse_sikka("-1").is_err());
        assert!(parse_sikka("1.0000000001").is_err());
        assert!(parse_sikka("99999999999999999999").is_err());
    }

    #[test]
    fn roundtrips() {
        for chillar in [0u64, 1, 999_999_999, 1_000_000_000, 123_456_789_012_345] {
            assert_eq!(parse_sikka(&format_sikka(chillar)).unwrap(), chillar);
        }
    }
}
