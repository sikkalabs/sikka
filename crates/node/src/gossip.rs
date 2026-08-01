//! Outbound relay.
//!
//! Handlers and loops hand work to [`Gossip`] and return immediately; a worker
//! task does the fanning out. Nothing here blocks a request on a peer being
//! reachable, so a slow or briefly unreachable peer cannot stall HTTP handlers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use sikka_common::transaction::Transaction;
use sikka_common::vote::Vote;
use sikka_consensus::proposal::CheckpointProposal;
use sikka_p2p::client::{ClientConfig, PeerClient};

use crate::node::{Finalized, Node};

/// A unit of outbound work.
#[derive(Debug)]
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
    jobs: mpsc::UnboundedSender<Job>,
    /// Guards against queueing a dozen snapshot downloads because a dozen
    /// checkpoints arrived while we were behind.
    syncing: Arc<AtomicBool>,
}

impl Gossip {
    /// Start the relay worker. The returned handle is cheap to clone into
    /// handlers.
    pub fn start(node: Arc<Node>) -> sikka_common::error::Result<(Arc<Self>, PeerClient)> {
        let client = PeerClient::new(&ClientConfig {
            timeout: node.config().request_timeout,
            bulk_timeout: node.config().bulk_request_timeout,
        })?;
        let (jobs, receiver) = mpsc::unbounded_channel();
        let syncing = Arc::new(AtomicBool::new(false));
        let gossip = Arc::new(Self {
            jobs,
            syncing: syncing.clone(),
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
        let (jobs, receiver) = mpsc::unbounded_channel();
        drop(receiver);
        Arc::new(Self {
            jobs,
            syncing: Arc::new(AtomicBool::new(false)),
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

    pub fn request_sync(&self) {
        if self.syncing.load(Ordering::Relaxed) {
            return;
        }
        self.send(Job::Sync);
    }

    fn send(&self, job: Job) {
        // A closed channel means the node is shutting down; dropping the message
        // is the right thing to do.
        let _ = self.jobs.send(job);
    }
}

async fn worker(
    node: Arc<Node>,
    client: PeerClient,
    gossip: Arc<Gossip>,
    mut jobs: mpsc::UnboundedReceiver<Job>,
    syncing: Arc<AtomicBool>,
) {
    while let Some(job) = jobs.recv().await {
        let endpoints = node.peer_endpoints();
        match job {
            Job::Transaction(transaction) => {
                for endpoint in endpoints {
                    let (client, node, transaction) =
                        (client.clone(), node.clone(), transaction.clone());
                    tokio::spawn(async move {
                        match client.submit_transaction(&endpoint, &transaction).await {
                            Ok(_) => node.record_peer_success(&endpoint),
                            Err(e) => {
                                debug!(peer = %endpoint, error = %e, "transaction relay failed");
                                node.record_peer_failure(&endpoint);
                            }
                        }
                    });
                }
            }
            Job::Vote(vote) => {
                for endpoint in endpoints {
                    let (client, node, vote) = (client.clone(), node.clone(), vote.clone());
                    tokio::spawn(async move {
                        if let Err(e) = client.submit_vote(&endpoint, &vote).await {
                            debug!(peer = %endpoint, error = %e, "vote relay failed");
                            node.record_peer_failure(&endpoint);
                        }
                    });
                }
            }
            Job::Proposal(proposal) => {
                // Proposals are the one case where the reply matters: it carries
                // the peer's vote, which is what brings the checkpoint to quorum.
                for endpoint in endpoints {
                    let (client, node, gossip, proposal) = (
                        client.clone(),
                        node.clone(),
                        gossip.clone(),
                        proposal.clone(),
                    );
                    tokio::spawn(async move {
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
                    });
                }
            }
            Job::Finalized(finalized) => {
                for endpoint in endpoints {
                    let (client, node, finalized) =
                        (client.clone(), node.clone(), finalized.clone());
                    tokio::spawn(async move {
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
                    });
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
