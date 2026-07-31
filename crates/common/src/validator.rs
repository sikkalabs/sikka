//! Validator records.
//!
//! Validation is permissionless: lock a bond and you are in. There is no
//! delegation, so a validator record is exactly one account's stake.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash, PublicKey};
use crate::codec::{Decode, Encode, Reader, Writer};
use crate::constants::UNBONDING_SECS;
use crate::error::Result;

/// Domain tag for validator leaves in the validator Sparse Merkle Tree.
pub const VALIDATOR_LEAF_TAG: &[u8] = b"SIKKA/validator-leaf/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    pub address: Address,
    /// Needed to verify this validator's checkpoint votes.
    pub public_key: PublicKey,
    /// Locked stake in CHILLAR.
    pub bond: u64,
    /// First checkpoint height at which this validator votes.
    ///
    /// A bond submitted during checkpoint `h` takes effect at `h + 1`, so the
    /// validator set for a height is fixed before its checkpoint is proposed.
    pub active_from: u64,
    /// Timestamp the unbonding cooldown started, if it has.
    pub unbonding_since: Option<u64>,
    /// Set when the validator equivocated. Slashed validators never return.
    pub slashed: bool,
}

impl Validator {
    pub fn new(public_key: PublicKey, bond: u64, active_from: u64) -> Self {
        Self {
            address: public_key.address(),
            public_key,
            bond,
            active_from,
            unbonding_since: None,
            slashed: false,
        }
    }

    /// Whether this validator votes on checkpoints at `height`.
    ///
    /// Unbonding validators stop voting immediately (and stop earning), but
    /// remain slashable until their bond is released.
    pub fn is_active_at(&self, height: u64) -> bool {
        !self.slashed
            && self.unbonding_since.is_none()
            && self.bond > 0
            && self.active_from <= height
    }

    /// Whether the cooldown has elapsed and the bond can be returned.
    pub fn is_releasable(&self, now: u64) -> bool {
        match self.unbonding_since {
            Some(started) => !self.slashed && now >= started.saturating_add(UNBONDING_SECS),
            None => false,
        }
    }

    /// Whether an equivocation proof can still burn this bond.
    pub fn is_slashable(&self) -> bool {
        !self.slashed && self.bond > 0
    }

    pub fn leaf_hash(&self) -> Hash {
        Hash::digest(&[VALIDATOR_LEAF_TAG, &self.to_bytes()])
    }
}

impl Encode for Validator {
    fn encode(&self, w: &mut Writer) {
        w.raw(self.address.as_bytes())
            .raw(self.public_key.as_slice())
            .u64(self.bond)
            .u64(self.active_from)
            .opt_u64(self.unbonding_since)
            .bool(self.slashed);
    }
}

impl Decode for Validator {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            address: Address::decode(r)?,
            public_key: PublicKey::decode(r)?,
            bond: r.u64()?,
            active_from: r.u64()?,
            unbonding_since: r.opt_u64()?,
            slashed: r.bool()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_crypto::PK_LEN;

    fn validator() -> Validator {
        Validator::new(PublicKey::new([5u8; PK_LEN]), 1_000, 10)
    }

    #[test]
    fn address_is_derived_from_key() {
        let v = validator();
        assert_eq!(v.address, v.public_key.address());
    }

    #[test]
    fn bond_activates_at_the_next_boundary() {
        let v = validator();
        assert!(!v.is_active_at(9));
        assert!(v.is_active_at(10));
        assert!(v.is_active_at(11));
    }

    #[test]
    fn unbonding_stops_voting_but_stays_slashable() {
        let mut v = validator();
        v.unbonding_since = Some(1_000);
        assert!(!v.is_active_at(11));
        assert!(v.is_slashable());
        assert!(!v.is_releasable(1_000 + UNBONDING_SECS - 1));
        assert!(v.is_releasable(1_000 + UNBONDING_SECS));
    }

    #[test]
    fn slashed_validators_are_out_for_good() {
        let mut v = validator();
        v.slashed = true;
        assert!(!v.is_active_at(11));
        assert!(!v.is_slashable());
        v.unbonding_since = Some(0);
        assert!(!v.is_releasable(u64::MAX));
    }

    #[test]
    fn zero_bond_is_inactive() {
        let mut v = validator();
        v.bond = 0;
        assert!(!v.is_active_at(11));
    }

    #[test]
    fn roundtrips_and_leaf_hash_is_sensitive() {
        let v = validator();
        let bytes = v.to_bytes();
        assert_eq!(Validator::from_bytes(&bytes).unwrap(), v);

        let mut other = v.clone();
        other.bond += 1;
        assert_ne!(v.leaf_hash(), other.leaf_hash());

        let mut unbonding = v.clone();
        unbonding.unbonding_since = Some(5);
        assert_ne!(v.leaf_hash(), unbonding.leaf_hash());
    }
}
