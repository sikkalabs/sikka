//! `sikka` — wallet and chain inspector.
//!
//! The CLI is a client, never a peer: it holds a key, asks a node questions and
//! checks the answers. Anything that changes the chain is a signed transaction
//! submitted over JSON-RPC, so pointing the CLI at somebody else's node is safe.

mod format;
mod genesis;
mod tor_onion;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use sikka_common::amount::{format_sikka, parse_sikka};
use sikka_common::bytes::{Address, Hash};
use sikka_common::error::{Error, Result};
use sikka_common::time::now_secs;
use sikka_crypto::{Keypair, SK_LEN};
use sikka_rpc::RpcClient;
use sikka_wallet::{verify_account_proof, Keystore, Wallet};
use tor_onion::TorOnionId;

const DEFAULT_NODE: &str = "http://localhost:64552";
const DEFAULT_KEY: &str = "sikka_key.json";

#[derive(Parser)]
#[command(
    name = "sikka",
    version,
    about = "SIKKA wallet and chain inspector",
    long_about = "A stateless wallet. Balances can be verified against a signed checkpoint, \
                  so the node you query does not have to be trusted."
)]
struct Cli {
    /// Node JSON-RPC endpoint.
    #[arg(long, short = 'n', global = true, env = "SIKKA_NODE", default_value = DEFAULT_NODE)]
    node: String,

    /// Keystore file for commands that sign.
    #[arg(long, short = 'k', global = true, env = "SIKKA_KEYSTORE", default_value = DEFAULT_KEY)]
    key: PathBuf,

    /// Print raw JSON instead of a human summary.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new keystore.
    New {
        /// Overwrite an existing keystore.
        #[arg(long)]
        force: bool,
    },
    /// Show the address of a keystore.
    Address,
    /// Show an account's balance, nonce and spam credits.
    Balance {
        /// Address to look up; defaults to the keystore's own.
        address: Option<Address>,
        /// Verify the balance against a signed checkpoint before printing it.
        #[arg(long)]
        verify: bool,
        /// Trust anchor for `--verify`: the genesis file's validator set.
        #[arg(long)]
        genesis: Option<PathBuf>,
    },
    /// Send SIKKA.
    Send {
        to: Address,
        /// Amount in SIKKA, e.g. `12.5`.
        amount: String,
        /// Wait until the transfer is reflected in the recipient's balance.
        #[arg(long)]
        wait: bool,
    },
    /// Bond a stake and become a validator.
    Bond {
        /// Amount in SIKKA.
        amount: String,
    },
    /// Begin unbonding, releasing the stake after the unbonding period.
    Unbond,
    /// Chain summary.
    Info,
    /// The validator set.
    Validators,
    /// A checkpoint, latest by default.
    Checkpoint { height: Option<u64> },
    /// Pending transaction count.
    Mempool,
    /// Peers the node knows.
    Peers,
    /// Whether a transaction is still pending.
    Status { id: Hash },
    /// Create a genesis file, and optionally the validator keys for it.
    Genesis(genesis::GenesisArgs),
    /// Show the Tor v3 onion derived from this node's key.
    TorId,
    /// Write Tor hidden-service keys for this node (used by the container entrypoint).
    TorPrepare {
        /// HiddenServiceDir to populate (default: beside the keystore).
        #[arg(long, default_value = "/data/tor/hs")]
        dir: PathBuf,
    },
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<()> {
    match &cli.command {
        Command::New { force } => {
            if cli.key.exists() && !force {
                return Err(Error::Other(format!(
                    "{} already exists; pass --force to replace it (the old key is gone forever)",
                    cli.key.display()
                )));
            }
            let keystore = Keystore::create(&cli.key)?;
            if cli.json {
                format::print_json(&serde_json::json!({
                    "address": keystore.address,
                    "path": cli.key,
                }))?;
            } else {
                println!("created {}", cli.key.display());
                println!("address {}", keystore.address);
                println!("\nKeep this file safe. There is no recovery phrase and no way back.");
            }
            Ok(())
        }

        Command::Address => {
            let wallet = load_wallet(&cli.key)?;
            println!("{}", wallet.address());
            Ok(())
        }

        Command::Balance {
            address,
            verify,
            genesis,
        } => {
            let client = client(&cli)?;
            let address = match address {
                Some(address) => *address,
                None => load_wallet(&cli.key)?.address(),
            };

            if *verify {
                let proof = client.account_proof(&address).await?;
                let validators = match genesis {
                    Some(path) => genesis::validator_keys_from_genesis(path)?,
                    // Without a genesis file the node's own validator list is the
                    // only anchor available. It still cannot lie about the
                    // balance, only about who the validators are.
                    None => client
                        .validators()
                        .await?
                        .into_iter()
                        .filter(|v| v.active && !v.slashed)
                        .map(|v| (v.address, v.public_key, v.bond))
                        .collect(),
                };
                let verified = verify_account_proof(&proof, &validators)?;
                if cli.json {
                    format::print_json(&serde_json::json!({
                        "address": verified.address,
                        "balance": verified.balance(),
                        "nonce": verified.nonce(),
                        "height": verified.height,
                        "state_root": verified.state_root,
                        "signatures": verified.signatures,
                        "verified": true,
                    }))?;
                } else {
                    println!("{} SIKKA", format_sikka(verified.balance()));
                    println!(
                        "verified against checkpoint {} signed by {} validators",
                        verified.height, verified.signatures
                    );
                }
                return Ok(());
            }

            let info = client.account(&address).await?;
            if cli.json {
                format::print_json(&info)?;
            } else {
                format::print_account(&info);
            }
            Ok(())
        }

        Command::Send { to, amount, wait } => {
            let amount = parse_sikka(amount)?;
            let wallet = load_wallet(&cli.key)?;
            let client = client(&cli)?;
            let account = client.account(&wallet.address()).await?;
            let chain_id = client.chain_info().await?.chain_id;
            let transaction = wallet.transfer(*to, amount, account.next_nonce, now_secs(), &chain_id)?;
            let receipt = client.submit(&transaction).await?;

            if cli.json {
                format::print_json(&receipt)?;
            } else {
                println!("sent {} SIKKA to {}", format_sikka(amount), to);
                println!("transaction {}", receipt.id);
                if account.credits_now <= 1 {
                    println!(
                        "note: this account is out of spam credits; the next transaction has to wait"
                    );
                }
            }

            if *wait {
                let before = client.account(to).await?.balance;
                await_balance(&client, to, before + amount).await?;
                println!("confirmed at height {}", client.chain_info().await?.height);
            }
            Ok(())
        }

        Command::Bond { amount } => {
            let amount = parse_sikka(amount)?;
            let wallet = load_wallet(&cli.key)?;
            let client = client(&cli)?;
            let account = client.account(&wallet.address()).await?;
            let chain_id = client.chain_info().await?.chain_id;
            let transaction = wallet.bond(amount, account.next_nonce, now_secs(), &chain_id)?;
            let receipt = client.submit(&transaction).await?;
            if cli.json {
                format::print_json(&receipt)?;
            } else {
                println!("bonding {} SIKKA", format_sikka(amount));
                println!("transaction {}", receipt.id);
                println!("you become an active validator one checkpoint after this is final");
            }
            Ok(())
        }

        Command::Unbond => {
            let wallet = load_wallet(&cli.key)?;
            let client = client(&cli)?;
            let account = client.account(&wallet.address()).await?;
            let chain_id = client.chain_info().await?.chain_id;
            let transaction = wallet.unbond(account.next_nonce, now_secs(), &chain_id)?;
            let receipt = client.submit(&transaction).await?;
            if cli.json {
                format::print_json(&receipt)?;
            } else {
                println!("unbonding; transaction {}", receipt.id);
                println!("the stake is released after the unbonding period");
            }
            Ok(())
        }

        Command::Info => {
            let info = client(&cli)?.chain_info().await?;
            if cli.json {
                format::print_json(&info)?;
            } else {
                format::print_chain_info(&info);
            }
            Ok(())
        }

        Command::Validators => {
            let validators = client(&cli)?.validators().await?;
            if cli.json {
                format::print_json(&validators)?;
            } else {
                format::print_validators(&validators);
            }
            Ok(())
        }

        Command::Checkpoint { height } => {
            let checkpoint = client(&cli)?.checkpoint(*height).await?;
            if cli.json {
                format::print_json(&checkpoint)?;
            } else {
                format::print_checkpoint(&checkpoint);
            }
            Ok(())
        }

        Command::Mempool => {
            let info = client(&cli)?.mempool().await?;
            if cli.json {
                format::print_json(&info)?;
            } else {
                println!("{} pending of {} capacity", info.pending, info.capacity);
                println!(
                    "{} more before the next checkpoint seals",
                    info.until_checkpoint
                );
            }
            Ok(())
        }

        Command::Peers => {
            let peers = client(&cli)?.peers().await?;
            if cli.json {
                format::print_json(&peers)?;
            } else if peers.is_empty() {
                println!("no peers");
            } else {
                for peer in peers {
                    println!("{peer}");
                }
            }
            Ok(())
        }

        Command::Status { id } => {
            let status = client(&cli)?.transaction_status(id).await?;
            if cli.json {
                format::print_json(&status)?;
            } else if status.pending {
                println!("pending");
            } else {
                println!(
                    "not pending: either applied and forgotten, or never seen.\n\
                     SIKKA keeps no history; check the recipient's balance to confirm a payment."
                );
            }
            Ok(())
        }

        Command::Genesis(args) => genesis::run(args, cli.json),

        Command::TorId => {
            let keypair = resolve_keypair(&cli)?;
            let id = TorOnionId::from_keypair(&keypair);
            if cli.json {
                format::print_json(&serde_json::json!({
                    "hostname": id.hostname,
                    "advertise": id.advertise_url(),
                    "address": Address(keypair.address_bytes()),
                }))?;
            } else {
                println!("{}", id.hostname);
                println!("advertise {}", id.advertise_url());
            }
            Ok(())
        }

        Command::TorPrepare { dir } => {
            let keypair = resolve_keypair(&cli)?;
            let id = TorOnionId::from_keypair(&keypair);
            id.write_hidden_service_dir(dir)?;
            if cli.json {
                format::print_json(&serde_json::json!({
                    "hostname": id.hostname,
                    "advertise": id.advertise_url(),
                    "dir": dir,
                }))?;
            } else {
                println!("wrote Tor hidden service keys to {}", dir.display());
                println!("{}", id.hostname);
            }
            Ok(())
        }
    }
}

/// Prefer `SIKKA_PRIVATE_KEY`, otherwise load/create the keystore at `--key`.
fn resolve_keypair(cli: &Cli) -> Result<Keypair> {
    if let Ok(hex) = std::env::var("SIKKA_PRIVATE_KEY") {
        if !hex.trim().is_empty() {
            let keypair = parse_private_key(&hex)?;
            Keystore::from_keypair(&keypair).save(&cli.key)?;
            return Ok(keypair);
        }
    }
    Ok(Keystore::load_or_create(&cli.key)?.keypair()?)
}

fn parse_private_key(hex: &str) -> Result<Keypair> {
    let clean = hex.trim().strip_prefix("0x").unwrap_or(hex.trim());
    let bytes = ::hex::decode(clean).map_err(|_| Error::InvalidHex)?;
    match bytes.len() {
        32 => {
            let seed: [u8; 32] = bytes.try_into().expect("length checked");
            Ok(Keypair::from_seed(&seed)?)
        }
        SK_LEN => Ok(Keypair::from_private_bytes(&bytes)?),
        n => Err(Error::Other(format!(
            "SIKKA_PRIVATE_KEY must be a 32-byte seed or {SK_LEN}-byte secret, got {n} bytes"
        ))),
    }
}

fn client(cli: &Cli) -> Result<RpcClient> {
    RpcClient::new(cli.node.trim_end_matches('/'))
}

fn load_wallet(path: &PathBuf) -> Result<Wallet> {
    if !path.exists() {
        return Err(Error::Other(format!(
            "no keystore at {}; create one with `sikka new`",
            path.display()
        )));
    }
    Wallet::from_keystore(&Keystore::load(path)?)
}

/// Poll until an account reaches at least `target`, or give up.
async fn await_balance(client: &RpcClient, address: &Address, target: u64) -> Result<()> {
    for _ in 0..60 {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        if client.account(address).await?.balance >= target {
            return Ok(());
        }
    }
    Err(Error::Other(
        "the transfer has not been applied yet; the mempool may be waiting for a full checkpoint"
            .into(),
    ))
}
