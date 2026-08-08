//! Catching up, and finding people to catch up from.
//!
//! There is no block-by-block sync in SIKKA, because there are no blocks: once a
//! checkpoint is final the transactions behind it are discarded. A node that is
//! one checkpoint behind catches up by replaying the transactions attached to a
//! finalized checkpoint; a node further behind than that downloads a state
//! snapshot and verifies it against the signatures on the checkpoint that
//! commits to it. Joining a year-old chain and restarting after a week offline
//! are the same operation, and both cost the size of the current state rather
//! than the size of all history.

use std::sync::Arc;

use tracing::{debug, info, warn};

use sikka_common::error::{Error, Result};
use sikka_p2p::client::PeerClient;
use sikka_state::{SnapshotDownload, SnapshotManifest};

use crate::node::Node;

/// A peer's self-reported position.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub endpoint: String,
    pub height: u64,
    pub chain_id: String,
}

/// Poll peers for their height, dropping the ones on a different chain.
pub async fn survey(node: &Arc<Node>, client: &PeerClient) -> Vec<PeerStatus> {
    let expected = node.health().chain_id;
    let mut statuses = Vec::new();
    for endpoint in node.peer_endpoints() {
        match client.health(&endpoint).await {
            Ok(health) => {
                if health.chain_id != expected {
                    warn!(
                        peer = %endpoint,
                        theirs = %health.chain_id,
                        ours = %expected,
                        "peer is on a different chain; ignoring it"
                    );
                    node.record_peer_failure(&endpoint);
                    continue;
                }
                node.record_peer_success(&endpoint);
                statuses.push(PeerStatus {
                    endpoint,
                    height: health.height,
                    chain_id: health.chain_id,
                });
            }
            Err(e) => {
                debug!(peer = %endpoint, error = %e, "health check failed");
                node.record_peer_failure(&endpoint);
            }
        }
    }
    statuses.sort_by_key(|s| std::cmp::Reverse(s.height));
    statuses
}

/// Bring this node up to the network's height using a snapshot.
///
/// Returns the height reached, or `None` if nobody is ahead of us.
pub async fn fast_sync(node: &Arc<Node>, client: &PeerClient) -> Result<Option<u64>> {
    let local = node.height();
    let statuses = survey(node, client).await;
    let Some(best) = statuses.first() else {
        return Ok(None);
    };
    if best.height <= local {
        return Ok(None);
    }

    info!(from = local, to = best.height, peer = %best.endpoint, "fast syncing");
    let mut last_error = None;
    // Peers are untrusted. Validate checkpoint trust from the small manifest
    // before spending bandwidth on chunks, then verify the reconstructed roots.
    for status in statuses.iter().filter(|s| s.height > local) {
        let manifest = match client.snapshot_manifest(&status.endpoint).await {
            Ok(manifest) => manifest,
            Err(e) => {
                debug!(peer = %status.endpoint, error = %e, "snapshot manifest download failed");
                node.record_peer_failure(&status.endpoint);
                last_error = Some(e);
                continue;
            }
        };
        if let Err(e) = node.verify_snapshot_manifest(&manifest) {
            warn!(peer = %status.endpoint, error = %e, "rejected a peer's snapshot manifest");
            node.record_peer_failure(&status.endpoint);
            last_error = Some(e);
            continue;
        }
        match client
            .snapshot_from_manifest(
                &status.endpoint,
                node.config().snapshot_download_path(),
                manifest.clone(),
            )
            .await
        {
            Ok(snapshot) => match node.apply_snapshot(&snapshot) {
                Ok(height) => {
                    if let Err(error) = SnapshotDownload::remove_for(
                        node.config().snapshot_download_path(),
                        &snapshot.checkpoint.hash(),
                    ) {
                        debug!(%error, "could not remove completed snapshot download");
                    }
                    return Ok(Some(height));
                }
                Err(e) => {
                    warn!(peer = %status.endpoint, error = %e, "rejected a peer's snapshot");
                    node.record_peer_failure(&status.endpoint);
                    cleanup_snapshot(node, &manifest);
                    last_error = Some(e);
                }
            },
            Err(e) => {
                debug!(peer = %status.endpoint, error = %e, "snapshot download failed");
                node.record_peer_failure(&status.endpoint);
                cleanup_snapshot(node, &manifest);
                last_error = Some(e);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| Error::Network("no peer could serve a snapshot".into())))
}

/// Discard a peer's failed snapshot download so failed syncs cannot stack up
/// on disk (the original reason the sync endpoint was a cheap DoS).
fn cleanup_snapshot(node: &Node, manifest: &SnapshotManifest) {
    if let Err(error) =
        SnapshotDownload::remove_for(node.config().snapshot_download_path(), &manifest.snapshot_id)
    {
        debug!(%error, snapshot = %manifest.snapshot_id, "could not clean up failed snapshot download");
    }
}

/// Announce ourselves to peers and adopt the peers they know.
///
/// Discovery is deliberately dumb: a signed claim of "I am reachable at this
/// endpoint", passed around until it stops being new. There is no DHT and no
/// rendezvous server, so there is nothing to seize.
pub async fn discover(node: &Arc<Node>, client: &PeerClient) -> usize {
    let announce = match node.own_announce() {
        Ok(announce) => announce,
        Err(e) => {
            warn!(error = %e, "could not sign our own announcement");
            return 0;
        }
    };

    let mut learned = 0;
    for endpoint in node.peer_endpoints() {
        match client.announce(&endpoint, Some(&announce)).await {
            Ok(peers) => {
                node.record_peer_success(&endpoint);
                for peer in peers {
                    if peer.endpoint == node.config().advertise {
                        continue;
                    }
                    if node.add_peer_endpoint(&peer.endpoint) {
                        learned += 1;
                    }
                }
            }
            Err(e) => {
                debug!(peer = %endpoint, error = %e, "announcement failed");
                node.record_peer_failure(&endpoint);
            }
        }
    }
    if learned > 0 {
        info!(learned, total = node.peers().len(), "learned new peers");
    }
    learned
}

/// Reconcile mempools with peers using bloom filters.
///
/// The filter is a few kilobytes and the reply contains only what we are missing,
/// so a node with a thousand pending transactions does not re-download them from
/// every peer on every tick.
pub async fn gossip_mempool(node: &Arc<Node>, client: &PeerClient) -> usize {
    let filter = node.mempool_bloom();
    let mut accepted = 0;
    for endpoint in node.peer_endpoints() {
        match client
            .sync_transactions(&endpoint, filter.clone(), 1_000)
            .await
        {
            Ok(response) => {
                node.record_peer_success(&endpoint);
                let count = response.transactions.len();
                let new = node.absorb_transactions(response.transactions);
                accepted += new;
                if count > 0 {
                    debug!(peer = %endpoint, offered = count, accepted = new, "synced mempool");
                }
            }
            Err(e) => {
                debug!(peer = %endpoint, error = %e, "mempool sync failed");
                node.record_peer_failure(&endpoint);
            }
        }
    }
    accepted
}
