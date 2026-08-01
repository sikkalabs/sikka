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
use sikka_node::{Node, NodeConfig, TrustedCheckpoint};
use sikka_rpc::RpcClient;
use sikka_wallet::{verify_account_proof, Keystore, Wallet};

/// One running node plus the handles needed to talk to and inspect it.
struct TestNode {
    node: Arc<Node>,
    endpoint: String,
    rpc: RpcClient,
    _dir: tempfile::TempDir,
    /// Dropping the node must stop its server and consensus loops; otherwise a
    /// "killed" validator keeps inventing checkpoints on loopback and the
    /// remaining committee deadlocks under one-vote-per-height.
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for TestNode {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            server.abort();
        }
    }
}

impl TestNode {
    fn address(&self) -> Address {
        self.node.address()
    }
}

/// Unused — tests bind on port 0 now. Kept so older snippets still compile if
/// revived.
#[allow(dead_code)]
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
    validator_keys: Vec<(Address, PublicKey, u64)>,
}

impl Testnet {
    /// Start `count` validators that all know about each other.
    async fn start(count: usize, tx_interval: u32) -> Self {
        Self::start_with_offline(count, 0, tx_interval).await
    }

    /// Start `validator_count - offline` nodes on a genesis that still lists
    /// every validator. Quorum is computed from the full set, so this is the
    /// live case of a bonded validator that is simply unreachable.
    async fn start_with_offline(validator_count: usize, offline: usize, tx_interval: u32) -> Self {
        assert!(offline < validator_count);
        let running = validator_count - offline;
        let alice = Wallet::generate().unwrap();
        let keys: Vec<Keypair> = (0..validator_count)
            .map(|_| Keypair::generate().unwrap())
            .collect();

        let bond = 100_000 * CHILLAR_PER_SIKKA;
        let mut allocations = vec![GenesisAllocation {
            to: alice.address(),
            amount: 10_000 * CHILLAR_PER_SIKKA,
        }];
        let mut validators = Vec::new();
        for key in &keys {
            allocations.push(GenesisAllocation {
                to: Address(key.address_bytes()),
                amount: 1_000_000 * CHILLAR_PER_SIKKA,
            });
            validators.push(GenesisValidator {
                public_key: PublicKey::new(*key.public_bytes()),
                bond,
                // Endpoints are learned over the test mesh, not baked into genesis.
                endpoint: None,
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
            let persisted = std::env::temp_dir().join(format!(
                "sikka-genesis-{}.json",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::copy(&genesis_path, &persisted).unwrap();
            persisted
        };

        // Bind on port 0 so each node gets a fresh kernel port — no race with
        // TIME_WAIT from a previous test's aborted listener.
        let mut nodes = Vec::new();
        for key in keys.iter().take(running) {
            nodes.push(spawn_node(&genesis_path, Some(key), Vec::new(), true, None).await);
        }
        for i in 0..nodes.len() {
            for j in 0..nodes.len() {
                if i != j {
                    nodes[i].node.add_peer_endpoint(&nodes[j].endpoint);
                }
            }
        }

        let validator_keys = keys
            .iter()
            .map(|k| {
                (
                    Address(k.address_bytes()),
                    PublicKey::new(*k.public_bytes()),
                    bond,
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
    ///
    /// `trusted` is required when the network tip is more than one height ahead
    /// of genesis (weak-subjectivity window).
    async fn join_observer(&self, trusted: Option<TrustedCheckpoint>) -> TestNode {
        let bootstrap: Vec<String> = self.nodes.iter().map(|n| n.endpoint.clone()).collect();
        spawn_node(&self.genesis_path, None, bootstrap, false, trusted).await
    }

    fn rpc(&self, index: usize) -> &RpcClient {
        &self.nodes[index].rpc
    }

    fn heights(&self) -> Vec<u64> {
        self.nodes.iter().map(|n| n.node.height()).collect()
    }

    /// Wait until every node reaches `height` with a shared state root.
    async fn await_height(&self, height: u64, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            let heights = self.heights();
            let roots: Vec<_> = self
                .nodes
                .iter()
                .map(|n| n.node.chain_info().unwrap().state_root)
                .collect();
            let same_root = roots.windows(2).all(|pair| pair[0] == pair[1]);
            if heights.iter().all(|h| *h >= height) && same_root {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "timed out waiting for height {height}; nodes reached {:?}; roots {:?}",
                    heights,
                    roots.iter().map(|r| r.short()).collect::<Vec<_>>()
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
    bootstrap: Vec<String>,
    validator: bool,
    trusted_checkpoint: Option<TrustedCheckpoint>,
) -> TestNode {
    let dir = tempfile::tempdir().unwrap();
    let key_path = dir.path().join("node_key.json");
    if let Some(key) = key {
        Keystore::from_keypair(key).save(&key_path).unwrap();
    }

    let config = NodeConfig {
        data_dir: dir.path().to_path_buf(),
        genesis_path: genesis.to_path_buf(),
        key_path,
        listen: "127.0.0.1:0".parse().unwrap(),
        advertise: "http://127.0.0.1:0".into(),
        bootstrap,
        validator,
        trusted_checkpoint,
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
    let endpoint = running.node.config().advertise.clone();
    let node = running.node.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let _ = running
            .serve_until(async move {
                let _ = shutdown_rx.await;
            })
            .await;
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
        shutdown: Some(shutdown_tx),
        server: Some(server),
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
        .verify_signatures(net.validator_keys.iter().map(|(a, k, b)| (a, k, *b)))
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
    let tip = net.nodes[0].node.checkpoint(target).unwrap();

    // A node with an empty database joins with an independently pinned tip —
    // multi-height snapshot sync always needs a weak-subjectivity checkpoint.
    let joiner = net
        .join_observer(Some(TrustedCheckpoint {
            height: tip.header.height,
            hash: tip.hash(),
        }))
        .await;
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
async fn validator_changing_gaps_require_a_pinned_checkpoint() {
    let net = Testnet::start(4, 2).await;
    net.await_peers(Duration::from_secs(10)).await;

    let bond = 1_000 * CHILLAR_PER_SIKKA;
    net.rpc(0)
        .submit(&net.alice.bond(bond, 0, now_secs()).unwrap())
        .await
        .unwrap();
    net.alice_pays(Address([0x44; 32]), CHILLAR_PER_SIKKA, 1, 1)
        .await;
    net.await_height(1, Duration::from_secs(30)).await;
    net.alice_pays(Address([0x55; 32]), CHILLAR_PER_SIKKA, 2, 2)
        .await;
    net.await_height(2, Duration::from_secs(90)).await;

    let snapshot = net.nodes[0].node.snapshot().unwrap();
    let manifest = net.nodes[0].node.snapshot_manifest().unwrap();
    let checkpoint_hash = snapshot.checkpoint.hash();
    let open_observer = |trusted_checkpoint| {
        let dir = tempfile::tempdir().unwrap();
        let config = NodeConfig {
            data_dir: dir.path().to_path_buf(),
            genesis_path: net.genesis_path.clone(),
            key_path: dir.path().join("node_key.json"),
            bootstrap: Vec::new(),
            validator: false,
            trusted_checkpoint,
            ..NodeConfig::default()
        };
        (Node::open(config).unwrap(), dir)
    };

    let (untrusted, _untrusted_dir) = open_observer(None);
    assert!(untrusted.verify_snapshot_manifest(&manifest).is_err());
    let error = untrusted.apply_snapshot(&snapshot).unwrap_err();
    assert!(
        error.to_string().contains("SIKKA_TRUSTED_CHECKPOINT"),
        "unexpected error: {error}"
    );
    assert_eq!(untrusted.height(), 0);

    let (trusted, _trusted_dir) = open_observer(Some(TrustedCheckpoint {
        height: snapshot.checkpoint.header.height,
        hash: checkpoint_hash,
    }));
    trusted.verify_snapshot_manifest(&manifest).unwrap();
    assert_eq!(
        trusted.apply_snapshot(&snapshot).unwrap(),
        snapshot.checkpoint.header.height
    );
    assert_eq!(
        trusted.chain_info().unwrap().state_root,
        snapshot.checkpoint.header.state_root
    );
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

/// Regression for the competing-round deadlock: with 3 bonded validators and
/// only 2 online, quorum is 2. If each online validator invents its own
/// checkpoint as rounds advance, they lock onto different hashes and the
/// height never closes. They must adopt one shared proposal instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_of_three_validators_finalize_while_one_stays_offline() {
    let net = Testnet::start_with_offline(3, 1, 2).await;
    net.await_peers(Duration::from_secs(10)).await;
    assert_eq!(net.nodes.len(), 2);
    assert_eq!(net.validator_keys.len(), 3);

    let bob = Address([0x2f; 32]);
    // Several heights, so proposer rounds rotate through the missing validator.
    for round in 0..4u64 {
        net.alice_pays(bob, CHILLAR_PER_SIKKA, 2, round * 2).await;
        net.await_height(round + 1, Duration::from_secs(90))
            .await;
    }

    assert_eq!(net.nodes[0].node.height(), net.nodes[1].node.height());
    assert!(net.nodes[0].node.height() >= 4);
    assert_eq!(
        net.rpc(0).account(&bob).await.unwrap().balance,
        8 * CHILLAR_PER_SIKKA
    );
    let root_a = net.rpc(0).chain_info().await.unwrap().state_root;
    let root_b = net.rpc(1).chain_info().await.unwrap().state_root;
    assert_eq!(root_a, root_b);
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
