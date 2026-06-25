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

use std::collections::HashSet;
use std::sync::Arc;

use tracing::{debug, info, warn};

use sikka_common::bytes::Hash;
use sikka_common::constants::WEAK_SUBJECTIVITY_GAP;
use sikka_common::error::{Error, Result};
use sikka_p2p::client::PeerClient;
use sikka_p2p::validate_endpoint_url;
use sikka_state::{SnapshotDownload, SnapshotManifest};

use crate::config::TrustedCheckpoint;
use crate::node::Node;

/// A peer's self-reported position.
#[derive(Debug, Clone)]
pub struct PeerStatus {
    pub endpoint: String,
    pub height: u64,
    pub chain_id: String,
}

/// A latest-checkpoint claim from a hardcoded bootstrap node.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapCandidate {
    height: u64,
    hash: Hash,
    locally_verifiable: bool,
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

/// Learn a weak-subjectivity pin from the hardcoded bootstrap list.
///
/// Discovered gossip peers never participate: a random onion in the peer book
/// must not choose the canonical hash. Bootstrap onions are already in the
/// binary as the discovery roots, so they are the social-consensus source for
/// "which finalized checkpoint is the live tip."
///
/// Same validator root as genesis (or our last known set): one bootstrap whose
/// checkpoint signatures verify is enough — forging that requires the live
/// ≥2/3 keys, which can already finalize the chain. Validator-set changes
/// cannot be checked locally, so those hashes need a 2/3 majority of the
/// *configured* bootstrap list to agree. Distinct hashes at the same height
/// are equivocation and refuse to guess.
async fn attest_from_bootstraps(
    node: &Arc<Node>,
    client: &PeerClient,
) -> Result<Option<TrustedCheckpoint>> {
    let bootstraps = node.config().bootstrap.clone();
    if bootstraps.is_empty() {
        return Ok(None);
    }
    let advertise = node.config().advertise.clone();
    let mut candidates = Vec::new();
    for endpoint in &bootstraps {
        if endpoint == &advertise {
            continue;
        }
        match client.latest_checkpoint(endpoint).await {
            Ok(checkpoint) => match node.evaluate_bootstrap_checkpoint(&checkpoint) {
                Ok(locally_verifiable) => {
                    candidates.push(BootstrapCandidate {
                        height: checkpoint.header.height,
                        hash: checkpoint.hash(),
                        locally_verifiable,
                    });
                }
                Err(e) => {
                    debug!(
                        peer = %endpoint,
                        error = %e,
                        "bootstrap checkpoint is not a usable trust anchor"
                    );
                }
            },
            Err(e) => {
                debug!(peer = %endpoint, error = %e, "bootstrap checkpoint fetch failed");
            }
        }
    }
    select_attested_checkpoint(&candidates, bootstraps.len())
}

fn select_attested_checkpoint(
    candidates: &[BootstrapCandidate],
    configured_bootstrap_count: usize,
) -> Result<Option<TrustedCheckpoint>> {
    if candidates.is_empty() {
        return Ok(None);
    }
    let max_height = candidates.iter().map(|c| c.height).max().unwrap();
    let at_tip: Vec<&BootstrapCandidate> = candidates
        .iter()
        .filter(|c| c.height == max_height)
        .collect();
    let mut hashes = HashSet::new();
    for candidate in &at_tip {
        hashes.insert(candidate.hash);
    }
    if hashes.len() > 1 {
        return Err(Error::Other(format!(
            "bootstrap nodes disagree on the checkpoint hash at height {max_height}; \
             set SIKKA_TRUSTED_CHECKPOINT after independently verifying the canonical tip"
        )));
    }
    let hash = at_tip[0].hash;
    let locally_verifiable = at_tip.iter().any(|c| c.locally_verifiable);
    if !locally_verifiable {
        let needed = (2 * configured_bootstrap_count).div_ceil(3).max(1);
        if at_tip.len() < needed {
            return Ok(None);
        }
    }
    Ok(Some(TrustedCheckpoint {
        height: max_height,
        hash,
    }))
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

    let gap = best.height.saturating_sub(local);
    if gap > WEAK_SUBJECTIVITY_GAP && node.config().trusted_checkpoint.is_none() {
        match attest_from_bootstraps(node, client).await {
            Ok(Some(pin)) => {
                node.set_attested_checkpoint(pin);
                info!(
                    height = pin.height,
                    hash = %pin.hash,
                    "bootstrap-attested weak-subjectivity pin"
                );
            }
            Ok(None) => {
                debug!("hardcoded bootstrap nodes did not attest a weak-subjectivity pin");
            }
            Err(e) => {
                warn!(error = %e, "bootstrap checkpoint attestation failed");
                return Err(e);
            }
        }
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
            // Policy rejects (weak-subjectivity, wrong hash) are not evidence
            // that the peer is unreachable — a lagging honest node still serves
            // a real snapshot of an older height.
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
    if let Err(error) = SnapshotDownload::remove_for(
        node.config().snapshot_download_path(),
        &manifest.snapshot_id,
    ) {
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
        if validate_endpoint_url(&endpoint).is_err() {
            debug!(peer = %endpoint, "skipping non-routable peer endpoint");
            continue;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(height: u64, byte: u8, locally_verifiable: bool) -> BootstrapCandidate {
        BootstrapCandidate {
            height,
            hash: Hash([byte; 32]),
            locally_verifiable,
        }
    }

    #[test]
    fn a_lagging_bootstrap_does_not_block_the_tip() {
        let pin = select_attested_checkpoint(&[cand(146, 1, true), cand(912, 2, true)], 2)
            .unwrap()
            .unwrap();
        assert_eq!(pin.height, 912);
        assert_eq!(pin.hash, Hash([2; 32]));
    }

    #[test]
    fn one_locally_verified_bootstrap_is_enough() {
        let pin = select_attested_checkpoint(&[cand(912, 7, true)], 2)
            .unwrap()
            .unwrap();
        assert_eq!(pin.height, 912);
        assert_eq!(pin.hash, Hash([7; 32]));
    }

    #[test]
    fn validator_set_change_needs_bootstrap_quorum() {
        assert!(select_attested_checkpoint(&[cand(50, 3, false)], 2)
            .unwrap()
            .is_none());
        let pin = select_attested_checkpoint(&[cand(50, 3, false), cand(50, 3, false)], 2)
            .unwrap()
            .unwrap();
        assert_eq!(pin.height, 50);
        assert_eq!(pin.hash, Hash([3; 32]));
    }

    #[test]
    fn equivocating_bootstraps_refuse_to_guess() {
        let error =
            select_attested_checkpoint(&[cand(912, 1, true), cand(912, 2, true)], 2).unwrap_err();
        assert!(
            error.to_string().contains("disagree"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn empty_candidates_mean_no_pin() {
        assert!(select_attested_checkpoint(&[], 2).unwrap().is_none());
    }
}
