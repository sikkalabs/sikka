//! The baked-in genesis for the SIKKA network.
//!
//! A node with no `SIKKA_GENESIS` file starts from this document: the admin
//! address holds the liquid mint (cold treasury — not a validator), and two
//! operators are funded and bonded at height 0. Peers find each other via the
//! hardcoded clearnet bootstrap list, so genesis validators carry no endpoints.
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

/// Extra liquid SIKKA each genesis validator keeps after bonding.
pub const GENESIS_VALIDATOR_LIQUID_SIKKA: u64 = 20_000;

/// Fixed genesis timestamp so every binary produces the same fingerprint.
const DEFAULT_GENESIS_TIMESTAMP: u64 = 1_720_000_000;

/// Expected baked-in committee size.
const GENESIS_VALIDATOR_COUNT: usize = 2;

#[derive(Deserialize)]
struct ValidatorsFile {
    validators: Vec<ValidatorEntry>,
}

#[derive(Deserialize)]
struct ValidatorEntry {
    #[serde(default)]
    name: String,
    bond_sikka: u64,
    public_key: String,
}

#[derive(Clone)]
struct GenesisValidatorSpec {
    bond_sikka: u64,
    public_key: PublicKey,
}

impl GenesisValidatorSpec {
    fn bond_chillar(&self) -> u64 {
        self.bond_sikka
            .checked_mul(CHILLAR_PER_SIKKA)
            .expect("genesis validator stake fits in u64")
    }

    fn allocation_sikka(&self) -> u64 {
        self.bond_sikka
            .checked_add(GENESIS_VALIDATOR_LIQUID_SIKKA)
            .expect("genesis validator allocation fits in u64")
    }

    fn allocation_chillar(&self) -> u64 {
        self.allocation_sikka()
            .checked_mul(CHILLAR_PER_SIKKA)
            .expect("genesis validator allocation fits in u64")
    }
}

/// Total SIKKA allocated across all genesis validators (bond + liquid).
pub fn genesis_validator_allocation_sikka() -> u64 {
    genesis_validator_specs()
        .into_iter()
        .map(|spec| spec.allocation_sikka())
        .try_fold(0u64, u64::checked_add)
        .expect("genesis validator allocations fit in u64")
}

/// Full genesis allocation across all validators, in CHILLAR.
pub fn genesis_validator_allocation_chillar() -> u64 {
    genesis_validator_allocation_sikka()
        .checked_mul(CHILLAR_PER_SIKKA)
        .expect("genesis validator allocation fits in u64")
}

/// Bond of the largest genesis validator, in CHILLAR.
///
/// Kept for callers that need a single representative bond size.
pub fn default_genesis_bond_chillar() -> u64 {
    genesis_validator_specs()
        .into_iter()
        .map(|spec| spec.bond_chillar())
        .max()
        .expect("baked-in genesis has validators")
}

/// [`default_genesis_bond_chillar`] expressed in SIKKA.
pub fn default_genesis_bond_sikka() -> u64 {
    default_genesis_bond_chillar() / CHILLAR_PER_SIKKA
}

/// Liquid mint kept by the cold admin address after funding genesis validators.
pub fn admin_allocation_chillar() -> u64 {
    let supply = DEFAULT_GENESIS_SUPPLY_SIKKA
        .checked_mul(CHILLAR_PER_SIKKA)
        .expect("default supply fits in u64");
    supply
        .checked_sub(genesis_validator_allocation_chillar())
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

fn genesis_validator_specs() -> Vec<GenesisValidatorSpec> {
    let file: ValidatorsFile =
        serde_json::from_str(VALIDATORS_JSON).expect("baked-in validators.json is valid JSON");
    assert_eq!(
        file.validators.len(),
        GENESIS_VALIDATOR_COUNT,
        "baked-in genesis expects exactly {GENESIS_VALIDATOR_COUNT} validators"
    );
    file.validators
        .into_iter()
        .map(|entry| {
            assert!(
                entry.bond_sikka > 0,
                "genesis validator {} must have a positive bond",
                entry.name
            );
            let public_key = PublicKey::from_hex(entry.public_key.trim())
                .unwrap_or_else(|e| panic!("invalid public key for {}: {e}", entry.name));
            GenesisValidatorSpec {
                bond_sikka: entry.bond_sikka,
                public_key,
            }
        })
        .collect()
}

/// Genesis used when no genesis file is mounted.
pub fn default_genesis() -> GenesisConfig {
    let admin = admin_public_key().expect("baked-in admin public key is valid");
    let admin_addr = admin.address();
    let validators = genesis_validator_specs();

    let mut allocations = vec![GenesisAllocation {
        to: admin_addr,
        amount: admin_allocation_chillar(),
    }];
    let mut genesis_validators = Vec::with_capacity(validators.len());
    for spec in validators {
        let address = spec.public_key.address();
        assert_ne!(
            address, admin_addr,
            "genesis validators must not reuse the admin mint key"
        );
        let bond = spec.bond_chillar();
        allocations.push(GenesisAllocation {
            to: address,
            amount: spec.allocation_chillar(),
        });
        genesis_validators.push(GenesisValidator {
            public_key: spec.public_key,
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
    assert!(
        genesis.validators.iter().all(|v| v.bond >= minimum),
        "a genesis bond is below minimum {minimum}"
    );
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
    fn genesis_validators_get_bond_plus_liquid() {
        let specs = genesis_validator_specs();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].bond_sikka, 10_000);
        assert_eq!(specs[1].bond_sikka, 4_000);
        assert_eq!(GENESIS_VALIDATOR_LIQUID_SIKKA, 20_000);
        // 10k+20k + 4k+20k = 54k
        assert_eq!(genesis_validator_allocation_sikka(), 54_000);
        assert_eq!(
            admin_allocation_chillar(),
            (DEFAULT_GENESIS_SUPPLY_SIKKA - 54_000) * CHILLAR_PER_SIKKA
        );
        assert_eq!(default_genesis_bond_sikka(), 10_000);
    }

    #[test]
    fn baked_in_genesis_funds_two_bonded_validators_and_cold_admin() {
        let genesis = default_genesis();
        assert_eq!(genesis.chain_id, "sikka");
        assert_eq!(genesis.validators.len(), 2);
        assert_eq!(genesis.allocations.len(), 3);
        assert!(genesis.validators.iter().all(|v| v.endpoint.is_none()));
        assert!(genesis
            .validators
            .iter()
            .all(|v| v.address() != admin_address()));

        let bonds: Vec<u64> = genesis
            .validators
            .iter()
            .map(|v| v.bond / CHILLAR_PER_SIKKA)
            .collect();
        assert_eq!(bonds, vec![10_000, 4_000]);

        let admin_alloc = genesis
            .allocations
            .iter()
            .find(|a| a.to == admin_address())
            .expect("admin allocation");
        assert_eq!(admin_alloc.amount, admin_allocation_chillar());

        for validator in &genesis.validators {
            let alloc = genesis
                .allocations
                .iter()
                .find(|a| a.to == validator.address())
                .expect("validator allocation");
            assert_eq!(
                alloc.amount - validator.bond,
                GENESIS_VALIDATOR_LIQUID_SIKKA * CHILLAR_PER_SIKKA
            );
        }

        assert_eq!(
            genesis.total_supply().unwrap(),
            DEFAULT_GENESIS_SUPPLY_SIKKA * CHILLAR_PER_SIKKA
        );

        let bonded: u64 = genesis.validators.iter().map(|v| v.bond).sum();
        assert_eq!(bonded, 14_000 * CHILLAR_PER_SIKKA);
        let validator_funded: u64 = genesis
            .allocations
            .iter()
            .filter(|a| a.to != admin_address())
            .map(|a| a.amount)
            .sum();
        assert_eq!(validator_funded, 54_000 * CHILLAR_PER_SIKKA);
        assert_eq!(
            admin_alloc.amount,
            genesis.total_supply().unwrap() - validator_funded
        );

        // Quorum is stake-weighted: ceil(2/3 * 14k) = 9334, so the 10k bond alone has quorum.
        assert!(10_000 * CHILLAR_PER_SIKKA >= crate::constants::quorum_bond(bonded));
        assert!(4_000 * CHILLAR_PER_SIKKA < crate::constants::quorum_bond(bonded));
    }
}
