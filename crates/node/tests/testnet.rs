//! A real four-node testnet, over real HTTP.
//!
//! Everything here runs the production code paths: axum servers on loopback
//! ports, JSON federation between them, the background loops driving consensus,
//! and a JSON-RPC client standing in for a wallet. The properties being checked
//! are the ones that matter for a chain to be usable at all — that a payment
//! submitted to one node is finalized by all of them, that every node ends up
//! with byte-identical state, and that a node which has never seen the chain
//! before can join and catch up.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sikka_common::amount::format_sikka;
use sikka_common::bytes::{Address, PublicKey};
use sikka_common::constants::CHILLAR_PER_SIKKA;
use sikka_common::genesis::{GenesisAllocation, GenesisConfig, GenesisValidator};
use sikka_common::time::now_secs;
use sikka_crypto::Keypair;
use sikka_node::{Node, NodeConfig};
use sikka_rpc::RpcClient;
use sikka_wallet::{verify_account_proof, Keystore, Wallet};

/// One running node plus the handles needed to talk to and inspect it.
struct TestNode {
    node: Arc<Node>,
    endpoint: String,
    rpc: RpcClient,
    _dir: tempfile::TempDir,
}

impl TestNode {
    fn address(&self) -> Address {
        self.node.address()
    }
}

/// Reserve a loopback port. Nodes must know their own endpoint before they bind,
/// so the port is chosen up front rather than by the kernel at bind time.
fn reserve_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

struct Testnet {
    nodes: Vec<TestNode>,
    alice: Wallet,
    genesis_path: PathBuf,
    validator_keys: Vec<(Address, PublicKey)>,
}

impl Testnet {
    /// Start `count` validators that all know about each other.
    async fn start(count: usize, tx_interval: u32) -> Self {
        let alice = Wallet::generate().unwrap();
        let keys: Vec<Keypair> = (0..count).map(|_| Keypair::generate().unwrap()).collect();
        let ports: Vec<u16> = (0..count).map(|_| reserve_port()).collect();
        let endpoints: Vec<String> = ports
            .iter()
            .map(|port| format!("http://127.0.0.1:{port}"))
            .collect();

        let bond = 100_000 * CHILLAR_PER_SIKKA;
        let mut allocations = vec![GenesisAllocation {
            to: alice.address(),
            amount: 10_000 * CHILLAR_PER_SIKKA,
        }];
        let mut validators = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            allocations.push(GenesisAllocation {
                to: Address(key.address_bytes()),
                amount: 1_000_000 * CHILLAR_PER_SIKKA,
            });
            validators.push(GenesisValidator {
                public_key: PublicKey::new(*key.public_bytes()),
                bond,
                endpoint: Some(endpoints[index].clone()),
            });
        }

        let genesis = GenesisConfig {
            chain_id: "sikka-testnet".into(),
            timestamp: now_secs() - 5,
            allocations,
            validators,
            checkpoint_tx_interval: Some(tx_interval),
        };
        genesis.validate().unwrap();

        let shared = tempfile::tempdir().unwrap();
        let genesis_path = shared.path().join("genesis.json");
        std::fs::write(&genesis_path, genesis.to_json()).unwrap();
        // The genesis file has to outlive the temp dir guard for later joiners.
        let genesis_path = {
            let persisted =
                std::env::temp_dir().join(format!("sikka-genesis-{}.json", reserve_port()));
            std::fs::copy(&genesis_path, &persisted).unwrap();
            persisted
        };

        let mut nodes = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let bootstrap: Vec<String> = endpoints
                .iter()
                .enumerate()
                .filter(|(other, _)| *other != index)
                .map(|(_, endpoint)| endpoint.clone())
                .collect();
            nodes.push(spawn_node(&genesis_path, Some(key), ports[index], bootstrap, true).await);
        }

        let validator_keys = keys
            .iter()
            .map(|k| {
                (
                    Address(k.address_bytes()),
                    PublicKey::new(*k.public_bytes()),
                )
            })
            .collect();

        Self {
            nodes,
            alice,
            genesis_path,
            validator_keys,
        }
    }

    /// Add a node that is not a validator and has no state at all.
    async fn join_observer(&self) -> TestNode {
        let bootstrap: Vec<String> = self.nodes.iter().map(|n| n.endpoint.clone()).collect();
        spawn_node(&self.genesis_path, None, reserve_port(), bootstrap, false).await
    }

    fn rpc(&self, index: usize) -> &RpcClient {
        &self.nodes[index].rpc
    }

    fn heights(&self) -> Vec<u64> {
        self.nodes.iter().map(|n| n.node.height()).collect()
    }

    /// Wait until every node reaches `height`, or fail with what they did reach.
    async fn await_height(&self, height: u64, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            if self.heights().iter().all(|h| *h >= height) {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "timed out waiting for height {height}; nodes reached {:?}",
                    self.heights()
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Wait until peer discovery has connected everyone.
    async fn await_peers(&self, within: Duration) {
        let expected = self.nodes.len() - 1;
        let deadline = Instant::now() + within;
        loop {
            if self.nodes.iter().all(|n| n.node.peers().len() >= expected) {
                return;
            }
            if Instant::now() > deadline {
                let counts: Vec<usize> = self.nodes.iter().map(|n| n.node.peers().len()).collect();
                panic!("peers never converged; each node sees {counts:?} of {expected}");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Submit `count` transfers from Alice through a rotating set of nodes.
    ///
    /// A node refuses a nonce it has no predecessor for, so each hop waits for the
    /// previous transaction to have gossiped its way over. That wait is the point:
    /// it is a live check that mempool sync reaches every node.
    async fn alice_pays(&self, to: Address, amount: u64, count: u64, first_nonce: u64) {
        for index in 0..count {
            let nonce = first_nonce + index;
            let node = &self.nodes[(index as usize) % self.nodes.len()];
            self.await_ready_for_nonce(node, nonce, Duration::from_secs(20))
                .await;
            let transaction = self.alice.transfer(to, amount, nonce, now_secs()).unwrap();
            node.rpc.submit(&transaction).await.unwrap();
        }
    }

    /// Wait until `node` would accept `nonce` from Alice as the next in sequence.
    async fn await_ready_for_nonce(&self, node: &TestNode, nonce: u64, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            let account = node.rpc.account(&self.alice.address()).await.unwrap();
            if account.next_nonce >= nonce {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "{} never caught up to nonce {nonce}; it expects {}",
                    node.endpoint, account.next_nonce
                );
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn spawn_node(
    genesis: &Path,
    key: Option<&Keypair>,
    port: u16,
    bootstrap: Vec<String>,
    validator: bool,
) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("node_key.json");
    if let Some(key) = key {
        Keystore::from_keypair(key).save(&key_path).unwrap();
    }

    let endpoint = format!("http://127.0.0.1:{port}");
    let config = NodeConfig {
        data_dir: dir.path().to_path_buf(),
        genesis_path: genesis.to_path_buf(),
        key_path,
        listen: format!("127.0.0.1:{port}").parse().unwrap(),
        advertise: endpoint.clone(),
        bootstrap,
        validator,
        mempool_capacity: 10_000,
        // Brisk timers: the test should finish in seconds, not minutes.
        propose_interval: Duration::from_millis(100),
        gossip_interval: Duration::from_millis(200),
        discovery_interval: Duration::from_millis(500),
        request_timeout: Duration::from_secs(5),
        max_checkpoint_delay: Duration::from_secs(0),
        ..NodeConfig::default()
    };

    let running = sikka_node::start(config).await.unwrap();
    let node = running.node.clone();
    tokio::spawn(async move {
        let _ = running.serve_until(std::future::pending()).await;
    });

    let rpc = RpcClient::with_timeout(&endpoint, Duration::from_secs(5)).unwrap();
    // Wait for the listener to actually answer before handing the node over.
    for _ in 0..50 {
        if rpc.chain_info().await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    TestNode {
        node,
        endpoint,
        rpc,
        _dir: dir,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_payment_submitted_to_one_node_is_finalized_by_all_of_them() {
    let net = Testnet::start(4, 4).await;
    net.await_peers(Duration::from_secs(10)).await;

    let bob = Address([0xbb; 32]);
    net.alice_pays(bob, 250 * CHILLAR_PER_SIKKA, 4, 0).await;
    net.await_height(1, Duration::from_secs(30)).await;

    // Every node agrees on the balance, and on the state root that commits to it.
    let expected = 1_000 * CHILLAR_PER_SIKKA;
    let mut roots = Vec::new();
    for node in &net.nodes {
        let info = node.rpc.chain_info().await.unwrap();
        let account = node.rpc.account(&bob).await.unwrap();
        assert_eq!(
            account.balance,
            expected,
            "{} disagrees: {} SIKKA",
            node.endpoint,
            format_sikka(account.balance)
        );
        roots.push(info.state_root);
    }
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "state roots diverged: {roots:?}"
    );

    // The checkpoint carries a super-majority of signatures, and its hash chain
    // starts at genesis.
    let checkpoint = net.rpc(0).checkpoint(Some(1)).await.unwrap();
    assert!(
        checkpoint.validator_signatures.len() >= 3,
        "expected a 2/3 majority of 4, got {}",
        checkpoint.validator_signatures.len()
    );
    let genesis_checkpoint = net.rpc(0).checkpoint(Some(0)).await.unwrap();
    assert_eq!(checkpoint.header.prev_hash, genesis_checkpoint.hash());

    // Signatures verify against the genesis validator set, which is the anchor a
    // wallet actually trusts.
    let signers = checkpoint
        .verify_signatures(net.validator_keys.iter().map(|(a, k)| (a, k)))
        .unwrap();
    assert_eq!(signers, checkpoint.validator_signatures.len());

    // Alice paid nothing in fees; the only supply change is protocol inflation.
    let alice = net.rpc(0).account(&net.alice.address()).await.unwrap();
    assert_eq!(alice.balance, 10_000 * CHILLAR_PER_SIKKA - expected);
    assert_eq!(alice.nonce, 4);
    let info = net.rpc(0).chain_info().await.unwrap();
    assert!(
        info.total_supply > 4_010_000 * CHILLAR_PER_SIKKA,
        "inflation should have minted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wallet_can_verify_a_balance_without_trusting_the_node() {
    let net = Testnet::start(4, 2).await;
    net.await_peers(Duration::from_secs(10)).await;

    let bob = Address([0xcc; 32]);
    net.alice_pays(bob, 5 * CHILLAR_PER_SIKKA, 2, 0).await;
    net.await_height(1, Duration::from_secs(30)).await;

    // Ask any node for a proof and check it against the genesis validators.
    for node in &net.nodes {
        let proof = node.rpc.account_proof(&bob).await.unwrap();
        let verified = verify_account_proof(&proof, &net.validator_keys).unwrap();
        assert_eq!(verified.balance(), 10 * CHILLAR_PER_SIKKA);
        assert!(verified.signatures >= 3);
    }

    // A proof of absence is just as verifiable.
    let nobody = Address([0x77; 32]);
    let proof = net.rpc(0).account_proof(&nobody).await.unwrap();
    let verified = verify_account_proof(&proof, &net.validator_keys).unwrap();
    assert_eq!(verified.balance(), 0);
    assert!(verified.account.is_none());

    // And a node that lies about a balance cannot produce a passing proof.
    let mut tampered = net.rpc(0).account_proof(&bob).await.unwrap();
    tampered.account = Some(sikka_common::account::Account {
        balance: 1_000_000 * CHILLAR_PER_SIKKA,
        nonce: 0,
        credits: 0,
        last_regen_time: 0,
    });
    assert!(verify_account_proof(&tampered, &net.validator_keys).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_node_joins_and_fast_syncs_to_the_current_state() {
    let net = Testnet::start(4, 2).await;
    net.await_peers(Duration::from_secs(10)).await;

    // Build a few checkpoints of history first, so the joiner is well behind.
    let bob = Address([0xdd; 32]);
    for round in 0..3u64 {
        net.alice_pays(bob, CHILLAR_PER_SIKKA, 2, round * 2).await;
        net.await_height(round + 1, Duration::from_secs(30)).await;
    }
    let target = net.nodes[0].node.height();
    assert!(target >= 3);

    // A node with an empty database, no key and no stake joins the network.
    let joiner = net.join_observer().await;
    assert_eq!(joiner.node.height(), 0, "a joiner starts from genesis");

    let deadline = Instant::now() + Duration::from_secs(30);
    while joiner.node.height() < target {
        if Instant::now() > deadline {
            panic!(
                "joiner stuck at height {} of {target}",
                joiner.node.height()
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // It ends up with exactly the same state, not merely the same height.
    let theirs = joiner.rpc.chain_info().await.unwrap();
    let ours = net.rpc(0).chain_info().await.unwrap();
    assert_eq!(theirs.state_root, ours.state_root);
    assert_eq!(theirs.total_supply, ours.total_supply);
    assert_eq!(
        joiner.rpc.account(&bob).await.unwrap().balance,
        6 * CHILLAR_PER_SIKKA
    );

    // Being a non-validator, it never signs anything.
    assert!(!joiner.node.is_active_validator());
    assert_ne!(joiner.address(), net.nodes[0].address());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_chain_keeps_going_when_a_validator_disappears() {
    let mut net = Testnet::start(4, 2).await;
    net.await_peers(Duration::from_secs(10)).await;

    let bob = Address([0xee; 32]);
    net.alice_pays(bob, CHILLAR_PER_SIKKA, 2, 0).await;
    net.await_height(1, Duration::from_secs(30)).await;

    // Kill one of the four. Quorum of 4 is 3, so the rest must carry on — and
    // must keep doing so through the dead node's proposer slots.
    let dead = net.nodes.pop().unwrap();
    let dead_address = dead.address();
    drop(dead);

    let start = net.nodes[0].node.height();
    for round in 0..3u64 {
        net.alice_pays(bob, CHILLAR_PER_SIKKA, 2, 2 + round * 2)
            .await;
        net.await_height(start + round + 1, Duration::from_secs(60))
            .await;
    }

    let info = net.rpc(0).chain_info().await.unwrap();
    assert!(info.height >= start + 3);
    assert_eq!(
        net.rpc(0).account(&bob).await.unwrap().balance,
        8 * CHILLAR_PER_SIKKA
    );

    // The dead node is still a validator on paper: liveness failure is not
    // slashable, only equivocation is.
    let validators = net.rpc(0).validators().await.unwrap();
    let dead_record = validators
        .iter()
        .find(|v| v.address == dead_address)
        .unwrap();
    assert!(!dead_record.slashed);
    assert!(dead_record.active);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn double_spends_and_bad_transactions_never_reach_a_checkpoint() {
    // Interval 1: a single affordable payment is enough to seal. That keeps the
    // test about admission and application, not about filling a batch.
    let net = Testnet::start(4, 1).await;
    net.await_peers(Duration::from_secs(10)).await;

    let bob = Address([0x11; 32]);
    let carol = Address([0x22; 32]);

    // A forged transaction is refused before it ever reaches the pool.
    let mut forged = net
        .alice
        .transfer(bob, CHILLAR_PER_SIKKA, 0, now_secs())
        .unwrap();
    forged.amount = 9_000 * CHILLAR_PER_SIKKA;
    let error = net.rpc(0).submit(&forged).await.unwrap_err();
    assert!(
        format!("{error}").contains("signature"),
        "unexpected: {error}"
    );

    // Alice has 10,000 SIKKA and tries to spend 6,000 twice. Each is
    // well-formed on its own, but the second cannot be paid for once the first
    // is queued, and the node refuses it there rather than letting it occupy
    // every mempool on the network until a checkpoint drops it.
    let honest = net
        .alice
        .transfer(bob, 6_000 * CHILLAR_PER_SIKKA, 0, now_secs())
        .unwrap();
    let double_spend = net
        .alice
        .transfer(carol, 6_000 * CHILLAR_PER_SIKKA, 1, now_secs())
        .unwrap();
    net.rpc(0).submit(&honest).await.unwrap();
    let error = net.rpc(0).submit(&double_spend).await.unwrap_err();
    assert!(
        format!("{error}").contains("insufficient balance"),
        "unexpected: {error}"
    );

    // On a node that has not heard the first spend, nonce 1 leaves a gap and is
    // refused. If gossip already delivered the honest spend, the refusal is
    // instead "insufficient balance". Either way it never sits in the pool.
    let error = net.rpc(1).submit(&double_spend).await.unwrap_err();
    let message = format!("{error}");
    assert!(
        message.contains("insufficient balance")
            || message.contains("bad nonce")
            || message.contains("nonce"),
        "unexpected: {error}"
    );

    net.await_height(1, Duration::from_secs(30)).await;

    assert_eq!(
        net.rpc(0).account(&bob).await.unwrap().balance,
        6_000 * CHILLAR_PER_SIKKA
    );
    assert_eq!(
        net.rpc(0).account(&carol).await.unwrap().balance,
        0,
        "the second spend of the same coins must not apply"
    );

    let alice = net.rpc(0).account(&net.alice.address()).await.unwrap();
    assert_eq!(alice.balance, 4_000 * CHILLAR_PER_SIKKA);
    assert_eq!(
        alice.nonce, 1,
        "only the applied transaction advances the nonce"
    );

    // The checkpoint records only what was applied.
    let checkpoint = net.rpc(0).checkpoint(Some(1)).await.unwrap();
    assert_eq!(checkpoint.header.tx_count, 1);

    // Supply is still exactly what the ledger thinks it is.
    for node in &net.nodes {
        let info = node.rpc.chain_info().await.unwrap();
        assert_eq!(node.node.audit_supply().unwrap(), info.total_supply);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bonding_makes_a_new_validator_and_it_starts_proposing() {
    let net = Testnet::start(4, 2).await;
    net.await_peers(Duration::from_secs(10)).await;

    // Alice bonds enough to qualify (0.001% of ~4.01M SIKKA supply is ~40).
    let bond = 1_000 * CHILLAR_PER_SIKKA;
    let transaction = net.alice.bond(bond, 0, now_secs()).unwrap();
    net.rpc(0).submit(&transaction).await.unwrap();
    // A second transaction so the checkpoint interval is met.
    net.alice_pays(Address([0x33; 32]), CHILLAR_PER_SIKKA, 1, 1)
        .await;

    net.await_height(1, Duration::from_secs(30)).await;

    let validators = net.rpc(0).validators().await.unwrap();
    let alice_record = validators
        .iter()
        .find(|v| v.address == net.alice.address())
        .unwrap();
    assert_eq!(alice_record.bond, bond);
    assert!(!alice_record.slashed);
    assert_eq!(validators.len(), 5);

    // The bond left her spendable balance and is still counted in total supply.
    let account = net.rpc(0).account(&net.alice.address()).await.unwrap();
    assert_eq!(account.bond, Some(bond));
    assert!(account.balance < 10_000 * CHILLAR_PER_SIKKA - bond);

    let info = net.rpc(0).chain_info().await.unwrap();
    assert_eq!(info.total_bonded, 400_000 * CHILLAR_PER_SIKKA + bond);

    // Alice is now a validator on paper but runs no node, so one slot in five of
    // the round-robin belongs to a validator that will never propose. The chain
    // has to work through those slots by round, and quorum is now four of five.
    for round in 0..5u64 {
        net.alice_pays(Address([0x33; 32]), CHILLAR_PER_SIKKA, 2, 2 + round * 2)
            .await;
        net.await_height(2 + round, Duration::from_secs(90)).await;
    }
    let info = net.rpc(0).chain_info().await.unwrap();
    assert_eq!(info.active_validators, 5);
    assert!(
        info.height >= 6,
        "an absent proposer must not halt the chain"
    );
}
