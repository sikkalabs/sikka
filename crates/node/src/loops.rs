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
        tokio::spawn(consensus_loop(node.clone(), gossip.clone(), client.clone())),
        tokio::spawn(mempool_loop(node.clone(), client.clone())),
        tokio::spawn(discovery_loop(node.clone(), client.clone())),
        tokio::spawn(catchup_loop(node.clone(), gossip, client.clone())),
        tokio::spawn(tor_probe_loop(node.clone(), client)),
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
async fn consensus_loop(node: Arc<Node>, gossip: Arc<Gossip>, client: PeerClient) {
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

        if let Ok(Some(precommit)) = node.maybe_precommit() {
            gossip.vote(precommit);
            match node.finalize_if_quorum() {
                Ok(Some(finalized)) => {
                    gossip.finalized(finalized);
                    continue;
                }
                Ok(None) => {}
                Err(e) => warn!(error = %e, "finalizing after precommit failed"),
            }
        }

        if node.expire_pending(ROUND_TIMEOUT_SECS) {
            continue;
        }

        // Before inventing a later-round checkpoint, learn whether a peer already
        // holds one. Adopting that hash is what keeps 2-of-3 live when one
        // validator is offline; inventing a rival deadlocks the height.
        adopt_peer_proposals(&node, &gossip, &client).await;

        match node.try_propose() {
            Ok(Some((proposal, vote))) => {
                gossip.proposal(proposal);
                gossip.vote(vote);
                // Prevote may already be a quorum (single-validator or small
                // committee); advance to precommit/finalize locally either way.
                if let Ok(Some(precommit)) = node.maybe_precommit() {
                    gossip.vote(precommit);
                }
                match node.finalize_if_quorum() {
                    Ok(Some(finalized)) => gossip.finalized(finalized),
                    Ok(None) => {}
                    Err(e) => warn!(error = %e, "finalizing our own proposal failed"),
                }
            }
            Ok(None) => {
                if let Ok(Some(precommit)) = node.maybe_precommit() {
                    gossip.vote(precommit);
                }
                match node.finalize_if_quorum() {
                    Ok(Some(finalized)) => gossip.finalized(finalized),
                    Ok(None) => {}
                    Err(e) => warn!(error = %e, "finalizing a restaged checkpoint failed"),
                }
            }
            Err(e) => warn!(error = %e, "proposing failed"),
        }
    }
}

/// Pull any open proposal peers are already committed to and adopt it locally.
async fn adopt_peer_proposals(node: &Node, gossip: &Gossip, client: &PeerClient) {
    if !node.config().validator || node.has_voted_for_open_height() {
        return;
    }
    // Already holding a body for this height — try_propose will adopt or wait.
    if node.open_proposal().is_some() {
        return;
    }

    for endpoint in node.peer_endpoints() {
        match client.pending_proposal(&endpoint).await {
            Ok(Some(proposal)) => {
                node.note_open_proposal(&proposal);
                match node.handle_proposal(&proposal) {
                    Ok(response) => {
                        if let Some(vote) = response.vote {
                            node.record_peer_success(&endpoint);
                            gossip.proposal(proposal);
                            gossip.vote(vote);
                            if let Ok(Some(precommit)) = node.maybe_precommit() {
                                gossip.vote(precommit);
                            }
                            match node.finalize_if_quorum() {
                                Ok(Some(finalized)) => gossip.finalized(finalized),
                                Ok(None) => {}
                                Err(e) => {
                                    warn!(error = %e, "finalizing an adopted proposal failed")
                                }
                            }
                            return;
                        }
                        if let Some(reason) = response.reason {
                            debug!(peer = %endpoint, %reason, "peer open proposal not adopted");
                        }
                    }
                    Err(e) => {
                        debug!(peer = %endpoint, error = %e, "could not verify peer open proposal");
                    }
                }
            }
            Ok(None) => node.record_peer_success(&endpoint),
            Err(e) => {
                debug!(peer = %endpoint, error = %e, "pending-proposal fetch failed");
                node.record_peer_failure(&endpoint);
            }
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
        // Finalized gossip can miss a peer. A node that stayed one height behind
        // across this interval (or fell further) recovers from a snapshot rather
        // than waiting forever while reoffering a rival it locked onto.
        if statuses.first().is_some_and(|best| best.height > local) {
            info!(
                local,
                network = statuses[0].height,
                "falling behind; requesting a snapshot"
            );
            gossip.request_sync();
        }
    }
}

/// Probe this node's own onion via SOCKS so the landing page knows if Tor works.
async fn tor_probe_loop(node: Arc<Node>, client: PeerClient) {
    let advertise = node.config().advertise.clone();
    if node.config().tor_socks.is_none() || !sikka_p2p::is_onion_endpoint(&advertise) {
        node.set_tor_status("disabled", "Tor not required for this node");
        return;
    }

    node.set_tor_status("checking", "probing onion via SOCKS");
    let mut ticker = ticker(Duration::from_secs(30));
    loop {
        match client.health(&advertise).await {
            Ok(_) => {
                let prev = node.tor_status();
                node.set_tor_status("ok", "onion reachable via Tor");
                if prev.status != "ok" {
                    info!(%advertise, "Tor onion self-check succeeded");
                }
            }
            Err(e) => {
                let detail = format!("onion unreachable via Tor: {e}");
                let prev = node.tor_status();
                node.set_tor_status("down", detail.clone());
                if prev.status != "down" {
                    warn!(%advertise, error = %e, "Tor onion self-check failed");
                }
            }
        }
        ticker.tick().await;
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
