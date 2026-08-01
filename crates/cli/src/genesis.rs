//! Building a genesis file.
//!
//! Genesis is the one thing that cannot be negotiated at runtime: every node
//! must start from a byte-identical document, since its fingerprint is what stops
//! two chains being mistaken for one. This command produces that document, and
//! (for a test network) the validator keys to go with it.

use std::path::{Path, PathBuf};

use clap::Args;

use sikka_common::amount::{format_sikka, parse_sikka};
use sikka_common::bytes::{Address, PublicKey};
use sikka_common::constants::{min_bond, DEFAULT_CHAIN_ID};
use sikka_common::error::{Error, Result};
use sikka_common::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};
use sikka_common::time::now_secs;
use sikka_wallet::Keystore;

#[derive(Args)]
pub struct GenesisArgs {
    /// Where to write the genesis document.
    #[arg(long, default_value = "genesis.json")]
    out: PathBuf,

    #[arg(long, default_value = DEFAULT_CHAIN_ID)]
    chain_id: String,

    /// Genesis timestamp; defaults to now.
    #[arg(long)]
    timestamp: Option<u64>,

    /// Generate this many validator keystores and include them.
    #[arg(long, default_value_t = 0)]
    validators: usize,

    /// Directory for generated keystores.
    #[arg(long, default_value = "keys")]
    keys_dir: PathBuf,

    /// Endpoint template for generated validators, with `{i}` replaced by the
    /// validator's 1-based index. Seeds the peer list.
    #[arg(long)]
    endpoint_template: Option<String>,

    /// Allocation in SIKKA for each generated validator.
    #[arg(long, default_value = "1000000")]
    validator_allocation: String,

    /// Bond in SIKKA for each generated validator.
    #[arg(long, default_value = "100000")]
    bond: String,

    /// An extra allocation, as `address=amount_in_sikka`. Repeatable.
    #[arg(long = "fund", value_name = "ADDRESS=SIKKA")]
    funds: Vec<String>,

    /// Transactions per checkpoint. Small values suit a test network.
    #[arg(long)]
    interval: Option<u32>,

    /// Overwrite an existing genesis file and keystores.
    #[arg(long)]
    force: bool,
}

pub fn run(args: &GenesisArgs, json: bool) -> Result<()> {
    if args.out.exists() && !args.force {
        return Err(Error::Other(format!(
            "{} already exists; pass --force to replace it",
            args.out.display()
        )));
    }

    let validator_allocation = parse_sikka(&args.validator_allocation)?;
    let bond = parse_sikka(&args.bond)?;

    let mut allocations: Vec<GenesisAllocation> = Vec::new();
    let mut validators: Vec<GenesisValidator> = Vec::new();
    let mut created: Vec<(PathBuf, Address)> = Vec::new();

    for index in 1..=args.validators {
        let path = args.keys_dir.join(format!("validator{index}.json"));
        if path.exists() && !args.force {
            return Err(Error::Other(format!(
                "{} already exists; pass --force to replace it",
                path.display()
            )));
        }
        let keystore = Keystore::create(&path)?;
        let public_key: PublicKey = keystore.public_key.clone();
        allocations.push(GenesisAllocation {
            to: keystore.address,
            amount: validator_allocation,
        });
        validators.push(GenesisValidator {
            public_key,
            bond,
            endpoint: args
                .endpoint_template
                .as_ref()
                .map(|template| template.replace("{i}", &index.to_string())),
        });
        created.push((path, keystore.address));
    }

    for entry in &args.funds {
        let (address, amount) = entry
            .split_once('=')
            .ok_or_else(|| Error::Other(format!("--fund expects address=amount, got '{entry}'")))?;
        allocations.push(GenesisAllocation {
            to: address.trim().parse()?,
            amount: parse_sikka(amount)?,
        });
    }

    if validators.is_empty() {
        return Err(Error::InvalidGenesis(
            "a chain needs at least one validator: pass --validators N".into(),
        ));
    }

    let genesis = GenesisConfig {
        chain_id: args.chain_id.clone(),
        timestamp: args.timestamp.unwrap_or_else(now_secs),
        allocations,
        validators,
        checkpoint_tx_interval: args.interval,
    };

    // Validate before writing: a genesis file that no node will accept is worse
    // than no file at all. This is where an under-sized bond is caught.
    genesis.validate()?;
    let supply = genesis.total_supply()?;
    let minimum = min_bond(supply);

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Other(format!("cannot create {}: {e}", parent.display())))?;
        }
    }
    std::fs::write(&args.out, genesis.to_json())
        .map_err(|e| Error::Other(format!("cannot write {}: {e}", args.out.display())))?;

    if json {
        crate::format::print_json(&serde_json::json!({
            "genesis": args.out,
            "chain_id": genesis.chain_id,
            "fingerprint": genesis.fingerprint(),
            "total_supply": supply,
            "validators": created.iter().map(|(path, address)| serde_json::json!({
                "keystore": path,
                "address": address,
            })).collect::<Vec<_>>(),
        }))?;
    } else {
        println!("wrote {}", args.out.display());
        println!("chain        {}", genesis.chain_id);
        println!("fingerprint  {}", genesis.fingerprint());
        println!("supply       {} SIKKA", format_sikka(supply));
        println!("min bond     {} SIKKA", format_sikka(minimum));
        for (path, address) in &created {
            println!("validator    {address}  ({})", path.display());
        }
    }
    Ok(())
}

/// The validator set from a genesis file, for use as a proof trust anchor.
///
/// Anchoring on genesis rather than on what a node claims is the difference
/// between verifying a balance and being told one.
pub fn validator_keys_from_genesis(path: &Path) -> Result<Vec<(Address, PublicKey, u64)>> {
    let json = std::fs::read_to_string(path)
        .map_err(|e| Error::Other(format!("cannot read {}: {e}", path.display())))?;
    let genesis = GenesisConfig::from_json(&json)?;
    Ok(genesis
        .validators
        .iter()
        .map(|v| (v.address(), v.public_key.clone(), v.bond))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_args(dir: &Path) -> GenesisArgs {
        GenesisArgs {
            out: dir.join("genesis.json"),
            chain_id: "sikka-test".into(),
            timestamp: Some(1_700_000_000),
            validators: 2,
            keys_dir: dir.join("keys"),
            endpoint_template: Some("http://node{i}:8080".into()),
            validator_allocation: "1000000".into(),
            bond: "100000".into(),
            funds: vec![format!("{}=250", Address([9u8; 32]))],
            interval: Some(4),
            force: false,
        }
    }

    #[test]
    fn writes_a_usable_genesis_and_keys() {
        let dir = tempfile::tempdir().unwrap();
        let args = sample_args(dir.path());
        run(&args, false).unwrap();

        let genesis =
            GenesisConfig::from_json(&std::fs::read_to_string(&args.out).unwrap()).unwrap();
        genesis.validate().unwrap();
        assert_eq!(genesis.validators.len(), 2);
        assert_eq!(genesis.allocations.len(), 3);
        assert_eq!(genesis.checkpoint_tx_interval, Some(4));
        assert_eq!(
            genesis.validators[0].endpoint.as_deref(),
            Some("http://node1:8080"),
            "the template must be expanded per validator"
        );

        // The keystores match the validators the genesis file names.
        for (index, validator) in genesis.validators.iter().enumerate() {
            let path = dir
                .path()
                .join("keys")
                .join(format!("validator{}.json", index + 1));
            let keystore = Keystore::load(&path).unwrap();
            assert_eq!(keystore.address, validator.address());
        }

        let anchors = validator_keys_from_genesis(&args.out).unwrap();
        assert_eq!(anchors.len(), 2);
    }

    #[test]
    fn refuses_to_clobber_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let args = sample_args(dir.path());
        run(&args, false).unwrap();
        assert!(run(&args, false).is_err());

        let forced = GenesisArgs {
            force: true,
            ..sample_args(dir.path())
        };
        run(&forced, false).unwrap();
    }

    #[test]
    fn a_chain_without_validators_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let args = GenesisArgs {
            validators: 0,
            ..sample_args(dir.path())
        };
        assert!(matches!(run(&args, false), Err(Error::InvalidGenesis(_))));
    }

    #[test]
    fn a_bond_below_the_network_minimum_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        // Two validators with 1,000,000 SIKKA each, so the minimum bond
        // (0.001% of a 2,000,000 SIKKA supply) is 20 SIKKA.
        let args = GenesisArgs {
            bond: "19".into(),
            ..sample_args(dir.path())
        };
        assert!(matches!(run(&args, false), Err(Error::BondTooSmall { .. })));
    }

    #[test]
    fn malformed_funding_is_reported() {
        let dir = tempfile::tempdir().unwrap();
        let args = GenesisArgs {
            funds: vec!["not-an-entry".into()],
            ..sample_args(dir.path())
        };
        assert!(run(&args, false).is_err());
    }
}
