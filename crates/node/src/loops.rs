//! Background loops.
//!
//! Each loop does one thing on a timer, and none of them holds state of its own:
//! they call into [`Node`], which is where the rules live. A crashed loop cannot
//! corrupt anything, and a loop can be dropped from a deployment (an observer
//! node runs no consensus loop) without touching the rest.

use std::sync::Arc;
use std::time::Duration;

use tokio::time::{interval, MissedTickBehavior};
use tracing::{debug, info, warn};

use sikka_p2p::client::PeerClient;

use crate::gossip::Gossip;
use crate::node::Node;
use crate::sync;

/// How long a staged checkpoint may sit without reaching quorum before its
/// staging is released.
///
/// A few proposer turns: by then the round-robin has moved on, and holding the
/// staging only stops this node from replaying whichever checkpoint does win.
/// The vote itself is never released, so nothing here risks equivocation, and
/// the proposal is kept so the round can be offered again.
const ROUND_TIMEOUT_SECS: u64 = 3 * sikka_consensus::PROPOSER_TIMEOUT_SECS;

/// Spawn every loop and return their handles.
pub fn spawn_all(
    node: Arc<Node>,
    gossip: Arc<Gossip>,
    client: PeerClient,
) -> Vec<tokio::task::JoinHandle<()>> {
    vec![
        tokio::spawn(consensus_loop(node.clone(), gossip.clone())),
        tokio::spawn(mempool_loop(node.clone(), client.clone())),
        tokio::spawn(discovery_loop(node.clone(), client.clone())),
        tokio::spawn(catchup_loop(node.clone(), gossip, client)),
        tokio::spawn(maintenance_loop(node)),
    ]
}

fn ticker(period: Duration) -> tokio::time::Interval {
    let mut ticker = interval(period);
    // If a tick is late (a long checkpoint, a slow disk) skip it rather than
    // firing a burst to "catch up".
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ticker
}

/// Propose when it is our turn, and give up on rounds that stall.
async fn consensus_loop(node: Arc<Node>, gossip: Arc<Gossip>) {
    let mut ticker = ticker(node.config().propose_interval);
    loop {
        ticker.tick().await;

        // A vote can arrive before the checkpoint it completes is staged — out of
        // order, or during a round this node had already given up on — so the
        // tally is worth re-checking even when nothing happened here.
        match node.finalize_if_quorum() {
            Ok(Some(finalized)) => {
                gossip.finalized(finalized);
                continue;
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "finalizing a staged checkpoint failed"),
        }

        if node.expire_pending(ROUND_TIMEOUT_SECS) {
            continue;
        }

        match node.try_propose() {
            Ok(Some((proposal, vote))) => {
                gossip.proposal(proposal);
                // A single-validator chain reaches quorum on its own vote, and
                // there is no peer to send it to; check locally either way.
                match node.finalize_if_quorum() {
                    Ok(Some(finalized)) => gossip.finalized(finalized),
                    Ok(None) => gossip.vote(vote),
                    Err(e) => warn!(error = %e, "finalizing our own proposal failed"),
                }
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, "proposing failed"),
        }
    }
}

/// Exchange pending transactions with peers.
async fn mempool_loop(node: Arc<Node>, client: PeerClient) {
    let mut ticker = ticker(node.config().gossip_interval);
    loop {
        ticker.tick().await;
        let accepted = sync::gossip_mempool(&node, &client).await;
        if accepted > 0 {
            debug!(accepted, "took in transactions from peers");
        }
    }
}

/// Announce ourselves and learn peers.
async fn discovery_loop(node: Arc<Node>, client: PeerClient) {
    // Announce immediately on startup so a fresh node joins in seconds, then
    // settle into the configured interval.
    sync::discover(&node, &client).await;
    let mut ticker = ticker(node.config().discovery_interval);
    loop {
        ticker.tick().await;
        sync::discover(&node, &client).await;
    }
}

/// Notice when the network has moved ahead of us and fetch a snapshot.
async fn catchup_loop(node: Arc<Node>, gossip: Arc<Gossip>, client: PeerClient) {
    // On startup, catch up before doing anything else useful.
    match sync::fast_sync(&node, &client).await {
        Ok(Some(height)) => info!(height, "synced at startup"),
        Ok(None) => debug!("already at the network's height"),
        Err(e) => debug!(error = %e, "nothing to sync from at startup"),
    }

    let mut ticker = ticker(Duration::from_secs(15));
    loop {
        ticker.tick().await;
        let local = node.height();
        let statuses = sync::survey(&node, &client).await;
        // One behind is normal: the finalized checkpoint carrying its own
        // transactions is on its way and can simply be replayed.
        if statuses.first().is_some_and(|best| best.height > local + 1) {
            info!(
                local,
                network = statuses[0].height,
                "falling behind; requesting a snapshot"
            );
            gossip.request_sync();
        }
    }
}

/// Housekeeping: drop transactions that can never be applied, and log a
/// heartbeat so an operator can see the chain moving.
async fn maintenance_loop(node: Arc<Node>) {
    let mut ticker = ticker(Duration::from_secs(60));
    loop {
        ticker.tick().await;
        let dropped = node.prune_mempool();
        if dropped > 0 {
            debug!(dropped, "pruned expired transactions");
        }
        let health = node.health();
        info!(
            height = health.height,
            mempool = health.mempool,
            peers = health.peers,
            validator = health.validator,
            uptime = node.uptime(),
            "status"
        );
    }
}
