//! The baked-in genesis for the SIKKA network.
//!
//! A node with no `SIKKA_GENESIS` file starts from this document: the admin
//! address holds the liquid mint (cold treasury — not a validator), and three
//! operators are funded and bonded at height 0. Peers find each other via the
//! hardcoded Tor bootstrap list, so genesis validators carry no endpoints.
//! Tests and second networks still override it by mounting a different genesis
//! file.

use serde::Deserialize;

use crate::bytes::{Address, PublicKey};
use crate::constants::{min_bond, CHILLAR_PER_SIKKA, DEFAULT_CHAIN_ID};
use crate::error::Result;
use crate::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};

/// Admin public key (ML-DSA-87), hex, no `0x` prefix.
const ADMIN_PK_HEX: &str = include_str!("admin_pk.hex");

/// Genesis validator public keys (ML-DSA-87), see [`validators.json`](./validators.json).
const VALIDATORS_JSON: &str = include_str!("validators.json");

/// Total coins minted at height 0, in SIKKA.
pub const DEFAULT_GENESIS_SUPPLY_SIKKA: u64 = 19_960_907;

/// SIKKA allocated to each genesis validator (fully bonded).
pub const GENESIS_VALIDATOR_STAKE_SIKKA: u64 = 20_000;

/// Fixed genesis timestamp so every binary produces the same fingerprint.
const DEFAULT_GENESIS_TIMESTAMP: u64 = 1_720_000_000;

#[derive(Deserialize)]
struct ValidatorsFile {
    validators: Vec<ValidatorEntry>,
}

#[derive(Deserialize)]
struct ValidatorEntry {
    #[serde(default)]
    name: String,
    public_key: String,
}

/// Stake locked for each genesis validator, in CHILLAR.
pub fn default_genesis_bond_chillar() -> u64 {
    GENESIS_VALIDATOR_STAKE_SIKKA
        .checked_mul(CHILLAR_PER_SIKKA)
        .expect("genesis validator stake fits in u64")
}

/// [`default_genesis_bond_chillar`] expressed in SIKKA.
pub fn default_genesis_bond_sikka() -> u64 {
    GENESIS_VALIDATOR_STAKE_SIKKA
}

/// Liquid mint kept by the cold admin address after funding genesis validators.
pub fn admin_allocation_chillar() -> u64 {
    let supply = DEFAULT_GENESIS_SUPPLY_SIKKA
        .checked_mul(CHILLAR_PER_SIKKA)
        .expect("default supply fits in u64");
    let bonded = default_genesis_bond_chillar()
        .checked_mul(3)
        .expect("three genesis bonds fit in u64");
    supply
        .checked_sub(bonded)
        .expect("admin allocation non-negative")
}

/// The admin address: `SHA3-256` of [`admin_public_key`].
pub fn admin_address() -> Address {
    admin_public_key()
        .expect("baked-in admin public key is valid")
        .address()
}

/// Decode the baked-in admin public key.
pub fn admin_public_key() -> Result<PublicKey> {
    PublicKey::from_hex(ADMIN_PK_HEX.trim())
}

fn genesis_validators() -> Vec<(String, PublicKey)> {
    let file: ValidatorsFile =
        serde_json::from_str(VALIDATORS_JSON).expect("baked-in validators.json is valid JSON");
    assert_eq!(
        file.validators.len(),
        3,
        "baked-in genesis expects exactly three validators"
    );
    file.validators
        .into_iter()
        .map(|entry| {
            let public_key = PublicKey::from_hex(entry.public_key.trim())
                .unwrap_or_else(|e| panic!("invalid public key for {}: {e}", entry.name));
            (entry.name, public_key)
        })
        .collect()
}

/// Genesis used when no genesis file is mounted.
pub fn default_genesis() -> GenesisConfig {
    let admin = admin_public_key().expect("baked-in admin public key is valid");
    let admin_addr = admin.address();
    let bond = default_genesis_bond_chillar();
    let validators = genesis_validators();

    let mut allocations = vec![GenesisAllocation {
        to: admin_addr,
        amount: admin_allocation_chillar(),
    }];
    let mut genesis_validators = Vec::with_capacity(validators.len());
    for (_name, public_key) in validators {
        let address = public_key.address();
        assert_ne!(
            address, admin_addr,
            "genesis validators must not reuse the admin mint key"
        );
        allocations.push(GenesisAllocation {
            to: address,
            amount: bond,
        });
        genesis_validators.push(GenesisValidator {
            public_key,
            bond,
            endpoint: None,
        });
    }

    let genesis = GenesisConfig {
        chain_id: DEFAULT_CHAIN_ID.into(),
        timestamp: DEFAULT_GENESIS_TIMESTAMP,
        allocations,
        validators: genesis_validators,
        checkpoint_tx_interval: None,
    };
    genesis
        .validate()
        .expect("baked-in genesis is always valid");
    // Sanity: each bond still clears the protocol floor for this supply.
    let minimum = min_bond(genesis.total_supply().expect("supply"));
    assert!(bond >= minimum, "genesis bond {bond} below minimum {minimum}");
    genesis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_public_key_hashes_to_the_known_address() {
        assert_eq!(
            admin_address().to_string(),
            "0x994992556d62b895dd34da64f4389d16404c81d57a91c737ab641cf652f1c447"
        );
    }

    #[test]
    fn genesis_validator_stake_is_twenty_thousand_sikka() {
        assert_eq!(default_genesis_bond_sikka(), 20_000);
        assert_eq!(default_genesis_bond_chillar(), 20_000 * CHILLAR_PER_SIKKA);
        assert_eq!(
            admin_allocation_chillar(),
            (DEFAULT_GENESIS_SUPPLY_SIKKA - 60_000) * CHILLAR_PER_SIKKA
        );
    }

    #[test]
    fn baked_in_genesis_funds_three_bonded_validators_and_cold_admin() {
        let genesis = default_genesis();
        assert_eq!(genesis.chain_id, "sikka");
        assert_eq!(genesis.validators.len(), 3);
        assert_eq!(genesis.allocations.len(), 4);
        assert!(genesis.validators.iter().all(|v| v.endpoint.is_none()));
        assert!(genesis
            .validators
            .iter()
            .all(|v| v.bond == default_genesis_bond_chillar()));
        assert!(genesis
            .validators
            .iter()
            .all(|v| v.address() != admin_address()));

        let admin_alloc = genesis
            .allocations
            .iter()
            .find(|a| a.to == admin_address())
            .expect("admin allocation");
        assert_eq!(admin_alloc.amount, admin_allocation_chillar());

        assert_eq!(
            genesis.total_supply().unwrap(),
            DEFAULT_GENESIS_SUPPLY_SIKKA * CHILLAR_PER_SIKKA
        );

        let bonded: u64 = genesis.validators.iter().map(|v| v.bond).sum();
        assert_eq!(bonded, 60_000 * CHILLAR_PER_SIKKA);
        assert_eq!(
            admin_alloc.amount,
            genesis.total_supply().unwrap() - bonded
        );
    }
}
