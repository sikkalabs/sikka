//! An unsigned "finalized checkpoint" 2+ heights ahead must not be able to
//! trigger a snapshot download; only a checkpoint with a signature from an
//! already-known validator may.

use std::time::Duration;

use sikka_common::bytes::{Address, Hash, PublicKey};
use sikka_common::checkpoint::{Checkpoint, CheckpointHeader};
use sikka_common::constants::CHILLAR_PER_SIKKA;
use sikka_common::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};
use sikka_common::time::now_secs;
use sikka_common::vote::{Vote, VoteKind};
use sikka_crypto::Keypair;
use sikka_node::NodeConfig;
use sikka_wallet::Keystore;

async fn spawn_solo() -> (String, Keypair) {
    let dir = tempfile::tempdir().unwrap();
    let validator = Keypair::generate().unwrap();
    Keystore::from_keypair(&validator)
        .save(dir.path().join("node_key.json"))
        .unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let endpoint = format!("http://127.0.0.1:{port}");

    let genesis = GenesisConfig {
        chain_id: "sikka-sync-spam".into(),
        timestamp: now_secs() - 10,
        checkpoint_tx_interval: Some(2),
        max_missed_proposer_slots: None,
        allocations: vec![GenesisAllocation {
            to: Address(validator.address_bytes()),
            amount: 1_000_000 * CHILLAR_PER_SIKKA,
        }],
        validators: vec![GenesisValidator {
            public_key: PublicKey::new(*validator.public_bytes()),
            bond: 500_000 * CHILLAR_PER_SIKKA,
            endpoint: Some(endpoint.clone()),
        }],
    };
    std::fs::write(dir.path().join("genesis.json"), genesis.to_json()).unwrap();

    let config = NodeConfig {
        data_dir: dir.path().to_path_buf(),
        genesis_path: dir.path().join("genesis.json"),
        key_path: dir.path().join("node_key.json"),
        listen: format!("127.0.0.1:{port}").parse().unwrap(),
        advertise: endpoint.clone(),
        bootstrap: Vec::new(),
        request_timeout: Duration::from_secs(5),
        max_checkpoint_delay: Duration::from_secs(0),
        tor_socks: None,
        ..NodeConfig::default()
    };

    let running = sikka_node::start(config).await.unwrap();
    tokio::spawn(async move {
        let _ = running.serve_until(std::future::pending()).await;
    });

    let client = reqwest::Client::new();
    for _ in 0..50 {
        if client
            .get(format!("{endpoint}/api/health"))
            .send()
            .await
            .is_ok()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    (endpoint, validator)
}

fn fake_header(chain_id: &str, local_height: u64) -> CheckpointHeader {
    CheckpointHeader {
        height: local_height + 2,
        prev_hash: Hash([0u8; 32]),
        state_root: Hash([7u8; 32]),
        validator_root: Hash([8u8; 32]),
        tx_root: Hash([9u8; 32]),
        tx_count: 10_000,
        timestamp: now_secs(),
        proposer: Address([0u8; 32]),
        round: 0,
        total_supply: 1,
        total_bonded: 0,
        chain_id: chain_id.into(),
        genesis_fingerprint: Hash([0xAA; 32]),
    }
}

async fn post_finalized(endpoint: &str, checkpoint: &Checkpoint) -> serde_json::Value {
    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "checkpoint": checkpoint,
        "transactions": [],
        "evidence": [],
    });
    let response = client
        .post(format!("{endpoint}/api/checkpoint/finalized"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        reqwest::StatusCode::OK,
        "a far-ahead checkpoint must be answered, not 4xx/5xx"
    );
    response.json().await.unwrap()
}

async fn local_height(endpoint: &str) -> u64 {
    sikka_rpc::RpcClient::new(endpoint)
        .unwrap()
        .chain_info()
        .await
        .unwrap()
        .height
}

#[tokio::test]
async fn unsigned_far_ahead_checkpoint_does_not_trigger_sync() {
    let (endpoint, _) = spawn_solo().await;
    let local = local_height(&endpoint).await;

    let header = fake_header("sikka-sync-spam", local);
    let unsigned = Checkpoint::new(header);
    let answer = post_finalized(&endpoint, &unsigned).await;
    assert_eq!(
        answer["syncing"], false,
        "unsigned JSON must never ask the sync loop to download a snapshot: {answer}"
    );
}

#[tokio::test]
async fn signed_far_ahead_checkpoint_may_trigger_sync() {
    let (endpoint, validator) = spawn_solo().await;
    let local = local_height(&endpoint).await;

    let header = fake_header("sikka-sync-spam", local);
    let mut checkpoint = Checkpoint::new(header);
    let hash = checkpoint.hash();
    let vote = Vote::sign(
        &validator,
        &checkpoint.header.chain_id,
        checkpoint.header.genesis_fingerprint,
        checkpoint.header.height,
        checkpoint.header.round,
        VoteKind::Precommit,
        hash,
    )
    .unwrap();
    checkpoint.add_signature(vote.into_signature());
    checkpoint.canonicalize();

    let answer = post_finalized(&endpoint, &checkpoint).await;
    assert!(
        answer["syncing"].as_bool().unwrap_or(false)
            || answer["applied"].as_bool().unwrap_or(false),
        "a validator-signed checkpoint is credible; expected syncing to be allowed: {answer}"
    );
}