//! Account state: the only thing SIKKA stores forever.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash};
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::constants::{BATTERY_REGEN_SECS, MAX_BATTERY};
use crate::error::Result;

/// Domain tag for account leaves in the Sparse Merkle Tree.
pub const ACCOUNT_LEAF_TAG: &[u8] = b"SIKKA/account-leaf/v1";

/// The complete state of an account: 28 bytes encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Account {
    /// Spendable balance in CHILLAR.
    pub balance: u64,
    /// Next expected transaction nonce; replay protection.
    pub nonce: u64,
    /// Anti-spam battery as of `last_regen_time`.
    pub battery: u32,
    /// Timestamp the battery was last settled at.
    pub last_regen_time: u64,
}

impl Account {
    /// An account created as the recipient of a transfer.
    ///
    /// It starts with an empty battery and its regeneration clock anchored at
    /// the creating transaction's timestamp, so a freshly funded account cannot
    /// immediately spam: charge must accrue in real time first.
    pub fn new_funded(balance: u64, created_at: u64) -> Self {
        Self {
            balance,
            nonce: 0,
            battery: 0,
            last_regen_time: created_at,
        }
    }

    /// Battery available at time `now`, without mutating state.
    ///
    /// Answers "how many transactions could this account send right now".
    pub fn battery_at(&self, now: u64) -> u32 {
        let elapsed = now.saturating_sub(self.last_regen_time) / BATTERY_REGEN_SECS;
        let regenerated = u64::from(self.battery).saturating_add(elapsed);
        u32::try_from(regenerated.min(u64::from(MAX_BATTERY))).unwrap_or(MAX_BATTERY)
    }

    /// Settle battery regeneration up to `now`.
    ///
    /// `now` is always a transaction's signed timestamp during execution, never
    /// a validator's wall clock, so every node computes the same result.
    pub fn settle_battery(&mut self, now: u64) {
        if now <= self.last_regen_time {
            // Ignore non-monotonic timestamps rather than handing out charge.
            return;
        }
        self.battery = self.battery_at(now);
        self.last_regen_time = now;
    }

    /// Seconds until at least one battery unit is available, or `None` if one
    /// already is.
    pub fn seconds_until_battery(&self, now: u64) -> Option<u64> {
        if self.battery_at(now) > 0 {
            return None;
        }
        let elapsed = now.saturating_sub(self.last_regen_time) % BATTERY_REGEN_SECS;
        Some(BATTERY_REGEN_SECS - elapsed)
    }

    /// SMT leaf value: `SHA3-256(tag || address || balance || nonce || battery || last_regen_time)`.
    pub fn leaf_hash(&self, address: &Address) -> Hash {
        let mut w = Writer::with_capacity(64);
        w.raw(address.as_bytes());
        self.encode(&mut w);
        Hash::digest(&[ACCOUNT_LEAF_TAG, w.as_slice()])
    }

    pub fn is_empty(&self) -> bool {
        *self == Account::default()
    }
}

impl Encode for Account {
    fn encode(&self, w: &mut Writer) {
        w.u64(self.balance)
            .u64(self.nonce)
            .u32(self.battery)
            .u64(self.last_regen_time);
    }
}

impl Decode for Account {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            balance: r.u64()?,
            nonce: r.u64()?,
            battery: r.u32()?,
            last_regen_time: r.u64()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_is_fixed_size_and_roundtrips() {
        let a = Account {
            balance: 1_000,
            nonce: 5,
            battery: 92,
            last_regen_time: 1_700_000_000,
        };
        let bytes = a.to_bytes();
        assert_eq!(bytes.len(), 28);
        assert_eq!(Account::from_bytes(&bytes).unwrap(), a);
    }

    #[test]
    fn battery_regenerates_one_per_minute() {
        let a = Account {
            balance: 0,
            nonce: 0,
            battery: 3,
            last_regen_time: 1_000,
        };
        assert_eq!(a.battery_at(1_000), 3);
        assert_eq!(a.battery_at(1_059), 3);
        assert_eq!(a.battery_at(1_060), 4);
        assert_eq!(a.battery_at(1_000 + 60 * 5), 8);
    }

    #[test]
    fn battery_saturates_at_max() {
        let a = Account {
            balance: 0,
            nonce: 0,
            battery: MAX_BATTERY.saturating_sub(1),
            last_regen_time: 0,
        };
        assert_eq!(a.battery_at(60 * 1_000_000), MAX_BATTERY);
        assert_eq!(a.battery_at(u64::MAX), MAX_BATTERY);
    }

    #[test]
    fn battery_never_goes_backwards_in_time() {
        let mut a = Account {
            balance: 0,
            nonce: 0,
            battery: 5,
            last_regen_time: 10_000,
        };
        assert_eq!(a.battery_at(5_000), 5);
        a.settle_battery(5_000);
        assert_eq!(a.battery, 5);
        assert_eq!(a.last_regen_time, 10_000);
    }

    #[test]
    fn settle_advances_clock_and_quota() {
        let mut a = Account {
            balance: 0,
            nonce: 0,
            battery: 0,
            last_regen_time: 1_000,
        };
        a.settle_battery(1_000 + 3 * 60);
        assert_eq!(a.battery, 3);
        assert_eq!(a.last_regen_time, 1_180);
    }

    #[test]
    fn new_account_starts_with_empty_battery() {
        let a = Account::new_funded(500, 1_000);
        assert_eq!(a.battery_at(1_000), 0);
        assert_eq!(a.seconds_until_battery(1_000), Some(60));
        assert_eq!(a.battery_at(1_060), 1);
        assert_eq!(a.seconds_until_battery(1_060), None);
    }

    #[test]
    fn leaf_hash_binds_address_and_every_field() {
        let addr = Address([1u8; 32]);
        let other = Address([2u8; 32]);
        let a = Account {
            balance: 1,
            nonce: 2,
            battery: 3,
            last_regen_time: 4,
        };

        assert_ne!(a.leaf_hash(&addr), a.leaf_hash(&other));

        let mut b = a;
        b.balance += 1;
        assert_ne!(a.leaf_hash(&addr), b.leaf_hash(&addr));

        let mut c = a;
        c.nonce += 1;
        assert_ne!(a.leaf_hash(&addr), c.leaf_hash(&addr));

        let mut d = a;
        d.battery += 1;
        assert_ne!(a.leaf_hash(&addr), d.leaf_hash(&addr));

        let mut e = a;
        e.last_regen_time += 1;
        assert_ne!(a.leaf_hash(&addr), e.leaf_hash(&addr));

        assert_eq!(a.leaf_hash(&addr), a.leaf_hash(&addr));
    }
}
