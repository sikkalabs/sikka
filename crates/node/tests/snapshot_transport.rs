//! End-to-end coverage for the manifest/chunk snapshot transport.

use std::sync::Arc;
use std::time::Duration;

use sikka_common::bytes::{Address, PublicKey};
use sikka_common::constants::CHILLAR_PER_SIKKA;
use sikka_common::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};
use sikka_common::time::now_secs;
use sikka_crypto::Keypair;
use sikka_node::{Node, NodeConfig};
use sikka_p2p::client::{ClientConfig, PeerClient};
use sikka_wallet::Keystore;

async fn spawn_solo() -> (String, Arc<Node>, tempfile::TempDir) {
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
        chain_id: "sikka-snapshot-transport".into(),
        timestamp: now_secs() - 10,
        checkpoint_tx_interval: Some(2),
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
        bulk_request_timeout: Duration::from_secs(30),
        max_checkpoint_delay: Duration::from_secs(0),
        ..NodeConfig::default()
    };

    let running = sikka_node::start(config).await.unwrap();
    let node = running.node.clone();
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
    (endpoint, node, dir)
}

#[tokio::test]
async fn snapshot_download_uses_manifest_and_chunks() {
    let (endpoint, node, _dir) = spawn_solo().await;
    let downloads = tempfile::tempdir().unwrap();
    let client = PeerClient::new(&ClientConfig {
        timeout: Duration::from_secs(5),
        bulk_timeout: Duration::from_secs(30),
    })
    .unwrap();

    let downloaded = client.snapshot(&endpoint, downloads.path()).await.unwrap();
    downloaded.verify().unwrap();
    assert_eq!(downloaded, node.snapshot().unwrap());
    assert!(
        downloads.path().read_dir().unwrap().next().is_some(),
        "completed chunks remain available until state application succeeds"
    );
    sikka_state::SnapshotDownload::remove_for(downloads.path(), &downloaded.checkpoint.hash())
        .unwrap();
    assert!(
        downloads.path().read_dir().unwrap().next().is_none(),
        "successful application cleanup should remove completed chunks"
    );
}

#[tokio::test]
async fn giant_json_snapshot_endpoint_is_removed() {
    let (endpoint, _node, _dir) = spawn_solo().await;
    let response = reqwest::get(format!("{endpoint}/api/state/snapshot"))
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);

    let manifest = reqwest::get(format!("{endpoint}/api/state/snapshot/manifest"))
        .await
        .unwrap();
    assert!(manifest.status().is_success());
    assert_eq!(
        manifest
            .json::<sikka_state::SnapshotManifest>()
            .await
            .unwrap()
            .version,
        sikka_state::SNAPSHOT_FORMAT_VERSION
    );
}
