//! Outbound relay.
//!
//! Handlers and loops hand work to [`Gossip`] and return immediately; a worker
//! task does the fanning out. Nothing here blocks a request on a peer being
//! reachable, so a slow or briefly unreachable peer cannot stall HTTP handlers.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use sikka_common::time::now_secs;
use sikka_common::transaction::Transaction;
use sikka_common::vote::Vote;
use sikka_consensus::proposal::CheckpointProposal;
use sikka_p2p::client::{ClientConfig, PeerClient};

use crate::node::{Finalized, Node};

/// Minimum wall-clock gap between sync *requests*. The in-flight guard only
/// stops concurrent downloads; this stops an attacker from queueing a fresh
/// snapshot download the moment the previous one finishes.
const SYNC_COOLDOWN_SECS: u64 = 30;

/// Maximum events queued before producers start dropping. One event fans out
/// to every peer, so the real memory ceiling is `QUEUE_CAP + RELAY_QUEUE_CAP`,
/// not an attacker-chosen function of the peer count.
const QUEUE_CAP: usize = 1024;

/// Cap on in-flight relay messages. Each of the [`RELAY_WORKERS`] consumers
/// holds at most one of these while talking to a peer, so this bounds both the
/// number of queued messages and the number of concurrent peer sockets.
const RELAY_QUEUE_CAP: usize = 256;

/// Number of tasks that actually deliver events to peers.
const RELAY_WORKERS: usize = 16;

/// A unit of outbound work.
#[derive(Debug, Clone)]
enum Job {
    Transaction(Box<Transaction>),
    Vote(Box<Vote>),
    Proposal(Box<CheckpointProposal>),
    Finalized(Box<Finalized>),
    /// Fetch a snapshot from the most advanced peer.
    Sync,
}

/// Handle for queueing outbound work.
pub struct Gossip {
    jobs: mpsc::Sender<Job>,
    /// Guards against queueing a dozen snapshot downloads because a dozen
    /// checkpoints arrived while we were behind.
    syncing: Arc<AtomicBool>,
    /// Unix seconds of the last accepted sync request, for the cooldown.
    last_sync_request: AtomicU64,
}

impl Gossip {
    /// Start the relay worker. The returned handle is cheap to clone into
    /// handlers.
    pub fn start(node: Arc<Node>) -> sikka_common::error::Result<(Arc<Self>, PeerClient)> {
        let client = PeerClient::new(&ClientConfig {
            timeout: node.config().request_timeout,
            bulk_timeout: node.config().bulk_request_timeout,
            socks_proxy: node.config().tor_socks.clone(),
        })?;
        let (jobs, receiver) = mpsc::channel(QUEUE_CAP);
        let syncing = Arc::new(AtomicBool::new(false));
        let gossip = Arc::new(Self {
            jobs,
            syncing: syncing.clone(),
            last_sync_request: AtomicU64::new(0),
        });

        tokio::spawn(worker(
            node,
            client.clone(),
            gossip.clone(),
            receiver,
            syncing,
        ));
        Ok((gossip, client))
    }

    /// A gossip handle that discards everything, for tests.
    pub fn disconnected() -> Arc<Self> {
        let (jobs, receiver) = mpsc::channel(QUEUE_CAP);
        drop(receiver);
        Arc::new(Self {
            jobs,
            syncing: Arc::new(AtomicBool::new(false)),
            last_sync_request: AtomicU64::new(0),
        })
    }

    pub fn transaction(&self, transaction: Transaction) {
        self.send(Job::Transaction(Box::new(transaction)));
    }

    pub fn vote(&self, vote: Vote) {
        self.send(Job::Vote(Box::new(vote)));
    }

    pub fn proposal(&self, proposal: CheckpointProposal) {
        self.send(Job::Proposal(Box::new(proposal)));
    }

    pub fn finalized(&self, finalized: Finalized) {
        self.send(Job::Finalized(Box::new(finalized)));
    }

    /// Ask the sync loop to fetch a snapshot, subject to a cooldown.
    ///
    /// Returns whether the request was actually queued. The in-flight guard
    /// only blocks *concurrent* syncs; the timestamp gate keeps one sender from
    /// repeatedly re-triggering a download the moment the other finishes.
    pub fn request_sync(&self) -> bool {
        if self.syncing.load(Ordering::Relaxed) {
            return false;
        }
        let now = now_secs();
        let last = self.last_sync_request.load(Ordering::Relaxed);
        if last > 0 && now < last + SYNC_COOLDOWN_SECS {
            return false;
        }
        if self
            .last_sync_request
            .compare_exchange(last, now, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        self.send(Job::Sync);
        true
    }

    fn send(&self, job: Job) {
        use mpsc::error::TrySendError;
        match self.jobs.try_send(job) {
            Ok(()) => {}
            // Full: the relay is saturated, drop rather than grow memory
            // without bound (an attacker sending events faster than the node
            // can relay them must be shed, not stored).
            Err(TrySendError::Full(_)) => debug!("gossip queue full; dropping an event"),
            // A closed channel means the node is shutting down; dropping the
            // message is the right thing to do.
            Err(TrySendError::Closed(_)) => {}
        }
    }
}

async fn worker(
    node: Arc<Node>,
    client: PeerClient,
    gossip: Arc<Gossip>,
    mut jobs: mpsc::Receiver<Job>,
    syncing: Arc<AtomicBool>,
) {
    // A small fixed pool of relay tasks, not a fresh spawned task per
    // (event × peer). Under a flood of events this stays bounded regardless of
    // how many peers a malicious node manages to seed into `peer_endpoints`.
    let mut relays = Vec::with_capacity(RELAY_WORKERS);
    for _ in 0..RELAY_WORKERS {
        let (tx, rx) = mpsc::channel(RELAY_QUEUE_CAP);
        relays.push(tx);
        let (node, client, gossip) = (node.clone(), client.clone(), gossip.clone());
        tokio::spawn(relay_worker(node, client, gossip, rx));
    }
    let mut round_robin = 0usize;

    while let Some(job) = jobs.recv().await {
        let endpoints = node.peer_endpoints();
        match job {
            Job::Transaction(_) | Job::Vote(_) | Job::Proposal(_) | Job::Finalized(_) => {
                for endpoint in endpoints {
                    use mpsc::error::TrySendError;
                    let relay = &relays[round_robin % relays.len()];
                    round_robin = round_robin.wrapping_add(1);
                    match relay.try_send((job.clone(), endpoint)) {
                        Ok(()) => {}
                        // Saturated: drop the fan-out rather than queue it. A
                        // peer that cannot keep up is exactly the one a flood
                        // attacker would point us at.
                        Err(TrySendError::Full(_)) => {
                            debug!("relay queue full; dropping outbound event")
                        }
                        Err(TrySendError::Closed(_)) => return,
                    }
                }
            }
            Job::Sync => {
                if syncing.swap(true, Ordering::SeqCst) {
                    continue;
                }
                let (node, client, syncing) = (node.clone(), client.clone(), syncing.clone());
                tokio::spawn(async move {
                    match crate::sync::fast_sync(&node, &client).await {
                        Ok(Some(height)) => info!(height, "caught up by fast sync"),
                        Ok(None) => debug!("no peer is ahead of us"),
                        Err(e) => warn!(error = %e, "fast sync failed"),
                    }
                    syncing.store(false, Ordering::SeqCst);
                });
            }
        }
    }
}

/// Deliver queued events to peers, one at a time.
async fn relay_worker(
    node: Arc<Node>,
    client: PeerClient,
    gossip: Arc<Gossip>,
    mut rx: mpsc::Receiver<(Job, String)>,
) {
    while let Some((job, endpoint)) = rx.recv().await {
        match job {
            Job::Transaction(transaction) => {
                match client.submit_transaction(&endpoint, &transaction).await {
                    Ok(_) => node.record_peer_success(&endpoint),
                    Err(e) => {
                        debug!(peer = %endpoint, error = %e, "transaction relay failed");
                        node.record_peer_failure(&endpoint);
                    }
                }
            }
            Job::Vote(vote) => {
                if let Err(e) = client.submit_vote(&endpoint, &vote).await {
                    debug!(peer = %endpoint, error = %e, "vote relay failed");
                    node.record_peer_failure(&endpoint);
                }
            }
            Job::Proposal(proposal) => {
                // Proposals are the one case where the reply matters: it carries
                // the peer's vote, which is what brings the checkpoint to quorum.
                match client.submit_proposal(&endpoint, &proposal).await {
                    Ok(response) => {
                        node.record_peer_success(&endpoint);
                        if let Some(vote) = response.vote {
                            collect_vote(&node, &gossip, vote);
                        } else if let Some(reason) = response.reason {
                            debug!(peer = %endpoint, %reason, "peer declined our proposal");
                        }
                    }
                    Err(e) => {
                        debug!(peer = %endpoint, error = %e, "proposal relay failed");
                        node.record_peer_failure(&endpoint);
                    }
                }
            }
            Job::Finalized(finalized) => {
                if let Err(e) = client
                    .submit_checkpoint(
                        &endpoint,
                        &finalized.checkpoint,
                        &finalized.transactions,
                        &finalized.evidence,
                    )
                    .await
                {
                    debug!(peer = %endpoint, error = %e, "checkpoint relay failed");
                    node.record_peer_failure(&endpoint);
                }
            }
            Job::Sync => {
                // Sync is handled by the worker directly; it never reaches the
                // relay queue.
                debug!("sync job reached the relay queue; dropping");
            }
        }
    }
}

/// Feed a vote we received in a proposal response back into consensus.
fn collect_vote(node: &Arc<Node>, gossip: &Arc<Gossip>, vote: Vote) {
    match node.handle_vote(vote) {
        Ok((follow_up, finalized)) => {
            if let Some(vote) = follow_up {
                gossip.vote(vote);
            }
            if let Some(finalized) = finalized {
                gossip.finalized(finalized);
            }
        }
        Err(e) => debug!(error = %e, "a peer's vote was not usable"),
    }
}
