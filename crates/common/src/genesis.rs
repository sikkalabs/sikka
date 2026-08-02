//! Genesis configuration.
//!
//! Every coin that will ever exist at height 0 is listed here, so no single
//! entity controls the supply at launch. The file is JSON because humans review
//! it; the state it produces is committed by the genesis checkpoint's state
//! root.

use serde::{Deserialize, Serialize};

use crate::bytes::{Address, Hash, PublicKey};
use crate::constants::{min_bond, DEFAULT_CHAIN_ID, MAX_CREDITS};
use crate::error::{Error, Result};

/// Domain tag for the genesis fingerprint.
pub const GENESIS_TAG: &[u8] = b"SIKKA/genesis/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAllocation {
    pub to: Address,
    /// Amount in CHILLAR.
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub public_key: PublicKey,
    /// Bond in CHILLAR, locked out of this validator's genesis allocation.
    pub bond: u64,
    /// Optional `http://host:port` used to seed the peer list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl GenesisValidator {
    pub fn address(&self) -> Address {
        self.public_key.address()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisConfig {
    #[serde(default = "default_chain_id")]
    pub chain_id: String,
    /// Genesis unix timestamp; also the credit clock anchor for allocations.
    pub timestamp: u64,
    pub allocations: Vec<GenesisAllocation>,
    pub validators: Vec<GenesisValidator>,
    /// Overrides the 10,000-transaction checkpoint interval. Test networks use
    /// a small value so checkpoints happen without generating 10,000 signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_tx_interval: Option<u32>,
    /// Overrides [`crate::constants::DEFAULT_MAX_MISSED_PROPOSER_SLOTS`]. Test
    /// networks use a small value so an offline validator is forced to unbond
    /// without waiting for a hundred missed turns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_missed_proposer_slots: Option<u32>,
}

fn default_chain_id() -> String {
    DEFAULT_CHAIN_ID.to_string()
}

impl GenesisConfig {
    /// Total supply at height 0: the sum of all allocations.
    ///
    /// Bonds are locked *out of* allocations, not minted on top of them, so
    /// they do not add to supply.
    pub fn total_supply(&self) -> Result<u64> {
        let mut total: u64 = 0;
        for alloc in &self.allocations {
            total = total
                .checked_add(alloc.amount)
                .ok_or(Error::BalanceOverflow)?;
        }
        Ok(total)
    }

    /// Credits every genesis account starts with.
    ///
    /// Allocations are chosen by the network rather than created by a
    /// transaction, so they start with a full quota; the "new accounts start at
    /// zero" rule exists to stop an attacker minting fresh spam identities,
    /// which genesis by definition cannot do.
    pub const fn initial_credits() -> u32 {
        MAX_CREDITS
    }

    /// A stable fingerprint of the genesis configuration.
    ///
    /// Nodes compare this on startup so a node can never silently continue on a
    /// database created from a different genesis.
    pub fn fingerprint(&self) -> Hash {
        let mut w = crate::codec::Writer::new();
        w.str(&self.chain_id).u64(self.timestamp);
        w.u32(self.allocations.len() as u32);
        for alloc in &self.allocations {
            w.raw(alloc.to.as_bytes()).u64(alloc.amount);
        }
        w.u32(self.validators.len() as u32);
        for v in &self.validators {
            w.raw(v.public_key.as_slice()).u64(v.bond);
        }
        w.opt_u64(self.checkpoint_tx_interval.map(u64::from));
        w.opt_u64(self.max_missed_proposer_slots.map(u64::from));
        Hash::digest(&[GENESIS_TAG, w.as_slice()])
    }

    /// Reject genesis files that could not produce a working chain.
    pub fn validate(&self) -> Result<()> {
        if self.chain_id.is_empty() {
            return Err(Error::InvalidGenesis("chain_id must not be empty".into()));
        }
        if self.allocations.is_empty() {
            return Err(Error::InvalidGenesis("no allocations".into()));
        }
        if self.validators.is_empty() {
            return Err(Error::InvalidGenesis("no genesis validators".into()));
        }
        if let Some(0) = self.checkpoint_tx_interval {
            return Err(Error::InvalidGenesis(
                "checkpoint_tx_interval must be > 0".into(),
            ));
        }
        if let Some(0) = self.max_missed_proposer_slots {
            return Err(Error::InvalidGenesis(
                "max_missed_proposer_slots must be > 0".into(),
            ));
        }

        let mut seen = std::collections::HashSet::new();
        for alloc in &self.allocations {
            if alloc.amount == 0 {
                return Err(Error::InvalidGenesis(format!(
                    "allocation to {} is zero",
                    alloc.to
                )));
            }
            if !seen.insert(alloc.to) {
                return Err(Error::InvalidGenesis(format!(
                    "duplicate allocation to {}",
                    alloc.to
                )));
            }
        }

        let supply = self.total_supply()?;
        let minimum = min_bond(supply);

        let mut validators = std::collections::HashSet::new();
        for v in &self.validators {
            let address = v.address();
            if !validators.insert(address) {
                return Err(Error::InvalidGenesis(format!(
                    "duplicate validator {address}"
                )));
            }
            if v.bond < minimum {
                return Err(Error::BondTooSmall {
                    bond: v.bond,
                    minimum,
                });
            }
            let allocated = self
                .allocations
                .iter()
                .find(|a| a.to == address)
                .map(|a| a.amount)
                .ok_or_else(|| {
                    Error::InvalidGenesis(format!("validator {address} has no allocation"))
                })?;
            if allocated < v.bond {
                return Err(Error::InvalidGenesis(format!(
                    "validator {address} bonds {} but is only allocated {allocated}",
                    v.bond
                )));
            }
        }
        Ok(())
    }

    pub fn from_json(json: &str) -> Result<Self> {
        let config: Self = serde_json::from_str(json)?;
        config.validate()?;
        Ok(config)
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("genesis config is serializable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_crypto::Keypair;

    fn genesis_with(bond: u64, allocation: u64) -> (GenesisConfig, Keypair) {
        let kp = Keypair::generate().unwrap();
        let pk = PublicKey::new(*kp.public_bytes());
        let config = GenesisConfig {
            chain_id: "sikka-test".into(),
            timestamp: 1_700_000_000,
            allocations: vec![
                GenesisAllocation {
                    to: pk.address(),
                    amount: allocation,
                },
                GenesisAllocation {
                    to: Address([9u8; 32]),
                    amount: 1_000_000,
                },
            ],
            validators: vec![GenesisValidator {
                public_key: pk,
                bond,
                endpoint: None,
            }],
            checkpoint_tx_interval: Some(4),
            max_missed_proposer_slots: None,
        };
        (config, kp)
    }

    #[test]
    fn valid_genesis_passes() {
        let (config, _) = genesis_with(1_000_000, 5_000_000);
        config.validate().unwrap();
        assert_eq!(config.total_supply().unwrap(), 6_000_000);
    }

    #[test]
    fn json_roundtrip_preserves_everything() {
        let (config, _) = genesis_with(1_000_000, 5_000_000);
        let parsed = GenesisConfig::from_json(&config.to_json()).unwrap();
        assert_eq!(parsed, config);
        assert_eq!(parsed.fingerprint(), config.fingerprint());
    }

    #[test]
    fn bond_below_minimum_is_rejected() {
        // Supply 1_000_060 → minimum bond 10.
        let (mut config, _) = genesis_with(9, 60);
        assert!(matches!(config.validate(), Err(Error::BondTooSmall { .. })));
        config.validators[0].bond = 60;
        config.validate().unwrap();
    }

    #[test]
    fn validator_must_be_funded_enough_to_bond() {
        let (mut config, _) = genesis_with(5_000_001, 5_000_000);
        assert!(matches!(config.validate(), Err(Error::InvalidGenesis(_))));
        config.validators[0].bond = 5_000_000;
        config.validate().unwrap();
    }

    #[test]
    fn validator_without_allocation_is_rejected() {
        let (mut config, _) = genesis_with(1_000, 5_000_000);
        let stranger = Keypair::generate().unwrap();
        config.validators[0].public_key = PublicKey::new(*stranger.public_bytes());
        assert!(matches!(config.validate(), Err(Error::InvalidGenesis(_))));
    }

    #[test]
    fn duplicate_and_zero_allocations_are_rejected() {
        let (mut config, _) = genesis_with(1_000, 5_000_000);
        let dup = config.allocations[0].clone();
        config.allocations.push(dup);
        assert!(matches!(config.validate(), Err(Error::InvalidGenesis(_))));

        let (mut config, _) = genesis_with(1_000, 5_000_000);
        config.allocations[1].amount = 0;
        assert!(matches!(config.validate(), Err(Error::InvalidGenesis(_))));
    }

    #[test]
    fn empty_sections_are_rejected() {
        let (mut config, _) = genesis_with(1_000, 5_000_000);
        config.validators.clear();
        assert!(config.validate().is_err());

        let (mut config, _) = genesis_with(1_000, 5_000_000);
        config.allocations.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn fingerprint_changes_with_any_field() {
        let (config, _) = genesis_with(1_000, 5_000_000);
        let base = config.fingerprint();

        let mut other = config.clone();
        other.timestamp += 1;
        assert_ne!(base, other.fingerprint());

        let mut other = config.clone();
        other.chain_id = "other".into();
        assert_ne!(base, other.fingerprint());

        let mut other = config.clone();
        other.allocations[0].amount += 1;
        assert_ne!(base, other.fingerprint());

        let mut other = config;
        other.checkpoint_tx_interval = Some(5);
        assert_ne!(base, other.fingerprint());

        let (config, _) = genesis_with(1_000, 5_000_000);
        let base = config.fingerprint();
        let mut other = config;
        other.max_missed_proposer_slots = Some(3);
        assert_ne!(base, other.fingerprint());
    }
}
