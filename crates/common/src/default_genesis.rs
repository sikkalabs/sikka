//! The baked-in genesis for the SIKKA network.
//!
//! A node with no `SIKKA_GENESIS` file starts from this document: one admin
//! address holds the mint, that same identity is the sole genesis validator,
//! and its peer endpoint is `https://1.sikkalabs.com`. Tests and second
//! networks still override it by mounting a different genesis file.

use crate::bytes::{Address, PublicKey};
use crate::constants::{min_bond, CHILLAR_PER_SIKKA, DEFAULT_CHAIN_ID};
use crate::error::Result;
use crate::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};

/// Admin public key (ML-DSA-87), hex, no `0x` prefix.
const ADMIN_PK_HEX: &str = include_str!("admin_pk.hex");

/// Total coins minted at height 0, in SIKKA.
pub const DEFAULT_GENESIS_SUPPLY_SIKKA: u64 = 19_960_907;

/// Peer URL advertised for the genesis validator.
pub const DEFAULT_GENESIS_ENDPOINT: &str = "https://1.sikkalabs.com";

/// Fixed genesis timestamp so every binary produces the same fingerprint.
const DEFAULT_GENESIS_TIMESTAMP: u64 = 1_720_000_000;

/// Stake locked for the sole genesis validator, in CHILLAR.
///
/// One hundred times the protocol minimum: a solid genesis stake, most of the
/// mint still liquid so the admin can fund joiners.
pub fn default_genesis_bond_chillar() -> u64 {
    let supply = DEFAULT_GENESIS_SUPPLY_SIKKA
        .checked_mul(CHILLAR_PER_SIKKA)
        .expect("default supply fits in u64");
    min_bond(supply).saturating_mul(100)
}

/// [`default_genesis_bond_chillar`] expressed in SIKKA (for docs and assertions).
pub fn default_genesis_bond_sikka() -> u64 {
    default_genesis_bond_chillar() / CHILLAR_PER_SIKKA
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

/// Genesis used when no genesis file is mounted.
pub fn default_genesis() -> GenesisConfig {
    let public_key = admin_public_key().expect("baked-in admin public key is valid");
    let address = public_key.address();
    let supply = DEFAULT_GENESIS_SUPPLY_SIKKA
        .checked_mul(CHILLAR_PER_SIKKA)
        .expect("default supply fits in u64");
    let bond = default_genesis_bond_chillar();

    let genesis = GenesisConfig {
        chain_id: DEFAULT_CHAIN_ID.into(),
        timestamp: DEFAULT_GENESIS_TIMESTAMP,
        allocations: vec![GenesisAllocation {
            to: address,
            amount: supply,
        }],
        validators: vec![GenesisValidator {
            public_key,
            bond,
            endpoint: Some(DEFAULT_GENESIS_ENDPOINT.into()),
        }],
        checkpoint_tx_interval: None,
    };
    genesis
        .validate()
        .expect("baked-in genesis is always valid");
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
    fn genesis_bond_is_one_hundred_times_the_protocol_minimum() {
        let supply = DEFAULT_GENESIS_SUPPLY_SIKKA * CHILLAR_PER_SIKKA;
        assert_eq!(default_genesis_bond_chillar(), min_bond(supply) * 100);
        // 19_960_907 SIKKA → min bond ~199.609 SIKKA → genesis bond ~19_960.9 SIKKA.
        assert_eq!(default_genesis_bond_sikka(), 19_960);
        assert_eq!(
            default_genesis_bond_chillar(),
            19_960_907_000_000 // 19_960.907 SIKKA in CHILLAR
        );
    }

    #[test]
    fn baked_in_genesis_is_valid_and_single_validator() {
        let genesis = default_genesis();
        assert_eq!(genesis.chain_id, "sikka");
        assert_eq!(genesis.validators.len(), 1);
        assert_eq!(genesis.allocations.len(), 1);
        assert_eq!(genesis.validators[0].address(), admin_address());
        assert_eq!(genesis.validators[0].bond, default_genesis_bond_chillar());
        assert_eq!(
            genesis.validators[0].endpoint.as_deref(),
            Some(DEFAULT_GENESIS_ENDPOINT)
        );
        assert_eq!(
            genesis.total_supply().unwrap(),
            DEFAULT_GENESIS_SUPPLY_SIKKA * CHILLAR_PER_SIKKA
        );
        // Almost all of the mint stays liquid for the admin to spend.
        let liquid = supply_liquid(&genesis);
        assert!(liquid > genesis.total_supply().unwrap() * 99 / 100);
    }

    fn supply_liquid(genesis: &GenesisConfig) -> u64 {
        let bonded: u64 = genesis.validators.iter().map(|v| v.bond).sum();
        genesis.total_supply().unwrap() - bonded
    }
}
