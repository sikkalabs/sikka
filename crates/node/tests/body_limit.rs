//! Body-limit split: bulk federation POSTs accept >2 MiB; other POSTs do not.

use std::time::Duration;

use sikka_common::constants::CHILLAR_PER_SIKKA;
use sikka_common::bytes::{Address, PublicKey};
use sikka_common::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};
use sikka_common::time::now_secs;
use sikka_crypto::Keypair;
use sikka_node::NodeConfig;
use sikka_wallet::Keystore;

fn over_two_mib() -> Vec<u8> {
    vec![b'x'; 2 * 1024 * 1024 + 1024]
}

async fn spawn_solo() -> (String, tempfile::TempDir) {
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
        chain_id: "sikka-body-limit".into(),
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

    (endpoint, dir)
}

#[tokio::test]
async fn bulk_federation_accepts_bodies_over_two_mib() {
    let (endpoint, _dir) = spawn_solo().await;
    let client = reqwest::Client::new();
    let body = over_two_mib();

    let proposal = client
        .post(format!("{endpoint}/api/checkpoint/proposal"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_ne!(
        proposal.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "proposal must clear Axum's 2 MiB default; got {}",
        proposal.status()
    );

    let finalized = client
        .post(format!("{endpoint}/api/checkpoint/finalized"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_ne!(
        finalized.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "finalized must clear Axum's 2 MiB default; got {}",
        finalized.status()
    );

    let sync = client
        .post(format!("{endpoint}/api/tx/sync"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_ne!(
        sync.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "tx sync must clear Axum's 2 MiB default; got {}",
        sync.status()
    );
}

#[tokio::test]
async fn ordinary_posts_keep_the_two_mib_cap() {
    let (endpoint, _dir) = spawn_solo().await;
    let client = reqwest::Client::new();
    let body = over_two_mib();

    let vote = client
        .post(format!("{endpoint}/api/vote"))
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(
        vote.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "vote should still reject oversized bodies"
    );

    let rpc = client
        .post(format!("{endpoint}/api/rpc"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(
        rpc.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "rpc should still reject oversized bodies"
    );
}
