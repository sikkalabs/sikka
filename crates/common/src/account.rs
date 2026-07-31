//! Account state: the only thing SIKKA stores forever.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash};
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::constants::{CREDIT_REGEN_SECS, MAX_CREDITS};
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
    /// Anti-spam quota as of `last_regen_time`.
    pub credits: u32,
    /// Timestamp the credit quota was last settled at.
    pub last_regen_time: u64,
}

impl Account {
    /// An account created as the recipient of a transfer.
    ///
    /// It starts with zero credits and its regeneration clock anchored at the
    /// creating transaction's timestamp, so a freshly funded account cannot
    /// immediately spam: credits must accrue in real time first.
    pub fn new_funded(balance: u64, created_at: u64) -> Self {
        Self {
            balance,
            nonce: 0,
            credits: 0,
            last_regen_time: created_at,
        }
    }

    /// Credits available at time `now`, without mutating state.
    ///
    /// This is also the read model behind the `getCredits` RPC: it answers "how
    /// many transactions could this account send right now".
    pub fn credits_at(&self, now: u64) -> u32 {
        let elapsed = now.saturating_sub(self.last_regen_time) / CREDIT_REGEN_SECS;
        let regenerated = u64::from(self.credits).saturating_add(elapsed);
        u32::try_from(regenerated.min(u64::from(MAX_CREDITS))).unwrap_or(MAX_CREDITS)
    }

    /// Settle credit regeneration up to `now`.
    ///
    /// `now` is always a transaction's signed timestamp during execution, never
    /// a validator's wall clock, so every node computes the same result.
    pub fn settle_credits(&mut self, now: u64) {
        if now <= self.last_regen_time {
            // Ignore non-monotonic timestamps rather than handing out credits.
            return;
        }
        self.credits = self.credits_at(now);
        self.last_regen_time = now;
    }

    /// Seconds until at least one credit is available, or `None` if one already
    /// is.
    pub fn seconds_until_credit(&self, now: u64) -> Option<u64> {
        if self.credits_at(now) > 0 {
            return None;
        }
        let elapsed = now.saturating_sub(self.last_regen_time) % CREDIT_REGEN_SECS;
        Some(CREDIT_REGEN_SECS - elapsed)
    }

    /// SMT leaf value: `SHA3-256(tag || address || balance || nonce || credits || last_regen_time)`.
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
            .u32(self.credits)
            .u64(self.last_regen_time);
    }
}

impl Decode for Account {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            balance: r.u64()?,
            nonce: r.u64()?,
            credits: r.u32()?,
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
            credits: 92,
            last_regen_time: 1_700_000_000,
        };
        let bytes = a.to_bytes();
        assert_eq!(bytes.len(), 28);
        assert_eq!(Account::from_bytes(&bytes).unwrap(), a);
    }

    #[test]
    fn credits_regenerate_one_per_minute() {
        let a = Account {
            balance: 0,
            nonce: 0,
            credits: 10,
            last_regen_time: 1_000,
        };
        assert_eq!(a.credits_at(1_000), 10);
        assert_eq!(a.credits_at(1_059), 10);
        assert_eq!(a.credits_at(1_060), 11);
        assert_eq!(a.credits_at(1_000 + 60 * 5), 15);
    }

    #[test]
    fn credits_saturate_at_max() {
        let a = Account {
            balance: 0,
            nonce: 0,
            credits: 99,
            last_regen_time: 0,
        };
        assert_eq!(a.credits_at(60 * 1_000_000), MAX_CREDITS);
        assert_eq!(a.credits_at(u64::MAX), MAX_CREDITS);
    }

    #[test]
    fn credits_never_go_backwards_in_time() {
        let mut a = Account {
            balance: 0,
            nonce: 0,
            credits: 5,
            last_regen_time: 10_000,
        };
        assert_eq!(a.credits_at(5_000), 5);
        a.settle_credits(5_000);
        assert_eq!(a.credits, 5);
        assert_eq!(a.last_regen_time, 10_000);
    }

    #[test]
    fn settle_advances_clock_and_quota() {
        let mut a = Account {
            balance: 0,
            nonce: 0,
            credits: 0,
            last_regen_time: 1_000,
        };
        a.settle_credits(1_000 + 3 * 60);
        assert_eq!(a.credits, 3);
        assert_eq!(a.last_regen_time, 1_180);
    }

    #[test]
    fn new_account_starts_with_no_credits() {
        let a = Account::new_funded(500, 1_000);
        assert_eq!(a.credits_at(1_000), 0);
        assert_eq!(a.seconds_until_credit(1_000), Some(60));
        assert_eq!(a.credits_at(1_060), 1);
        assert_eq!(a.seconds_until_credit(1_060), None);
    }

    #[test]
    fn leaf_hash_binds_address_and_every_field() {
        let addr = Address([1u8; 32]);
        let other = Address([2u8; 32]);
        let a = Account {
            balance: 1,
            nonce: 2,
            credits: 3,
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
        d.credits += 1;
        assert_ne!(a.leaf_hash(&addr), d.leaf_hash(&addr));

        let mut e = a;
        e.last_regen_time += 1;
        assert_ne!(a.leaf_hash(&addr), e.leaf_hash(&addr));

        assert_eq!(a.leaf_hash(&addr), a.leaf_hash(&addr));
    }
}
