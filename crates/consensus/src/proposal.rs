//! Checkpoint proposals.
//!
//! The proposer does no privileged work: it picks up confirmed transactions,
//! sorts them by hash, applies them, and publishes the resulting state root
//! along with the transactions themselves. Every other validator replays exactly
//! the same list in exactly the same order. If their root matches, they sign; if
//! it does not, they refuse — there is nothing to negotiate.
//!
//! Proposals carry the proposer's ML-DSA signature over the header hash so peers
//! can reject forgeries before verifying a bulk of transaction signatures.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use sikka_common::bytes::{Address, Hash, PublicKey, Signature};
use sikka_common::checkpoint::{Checkpoint, CheckpointHeader};
use sikka_common::codec::{Decode, Encode, Reader, Writer};
use sikka_common::constants::TX_TIME_TOLERANCE_SECS;
use sikka_common::error::{Error, Result};
use sikka_common::transaction::Transaction;
use sikka_state::ledger::{ExecutionContext, Staged};
use sikka_state::Ledger;

use crate::equivocation::Equivocation;
use crate::{proposer_for_round, PROPOSER_TIMEOUT_SECS};

/// Domain tag for the proposer's signature over a proposal.
pub const PROPOSAL_TAG: &[u8] = b"SIKKA/proposal/v1";

/// Bytes the proposer signs: domain tag + checkpoint header hash.
///
/// The header already commits to `tx_root`, evidence-affecting state roots, and
/// round/proposer, so one signature authenticates the whole body without hashing
/// every transaction again up front.
pub fn proposal_signing_bytes(header_hash: &Hash) -> Vec<u8> {
    let mut w = Writer::with_capacity(40);
    w.raw(PROPOSAL_TAG).raw(header_hash.as_bytes());
    w.finish()
}

/// A proposed checkpoint, with everything needed to check it independently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointProposal {
    pub header: CheckpointHeader,
    /// The transactions applied, in the canonical (hash-ascending) order.
    pub transactions: Vec<Transaction>,
    /// Equivocation proofs justifying any bonds burned by this checkpoint.
    #[serde(default)]
    pub evidence: Vec<Equivocation>,
    /// Proposer's signature over [`proposal_signing_bytes`] of the header hash.
    ///
    /// Checked before any per-transaction ML-DSA work when the proposal is
    /// still only a request to vote (`Authority::Proposed`).
    #[serde(default)]
    pub proposer_signature: Signature,
}

impl CheckpointProposal {
    pub fn height(&self) -> u64 {
        self.header.height
    }

    pub fn hash(&self) -> Hash {
        self.header.hash()
    }

    /// Sign this proposal as its header proposer.
    pub fn sign(&mut self, keypair: &sikka_crypto::Keypair) -> Result<()> {
        let public_key = PublicKey::new(*keypair.public_bytes());
        if public_key.address() != self.header.proposer {
            return Err(Error::WrongProposer {
                expected: self.header.proposer,
                actual: public_key.address(),
            });
        }
        self.proposer_signature = Signature::new(keypair.sign(&proposal_signing_bytes(&self.hash()))?);
        Ok(())
    }

    /// Verify the proposer's signature against their known public key.
    pub fn verify_proposer_signature(&self, public_key: &PublicKey) -> Result<()> {
        if public_key.address() != self.header.proposer {
            return Err(Error::AddressKeyMismatch);
        }
        let payload = proposal_signing_bytes(&self.hash());
        if !sikka_crypto::verify(
            public_key.as_slice(),
            &payload,
            self.proposer_signature.as_slice(),
        ) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

impl Encode for CheckpointProposal {
    fn encode(&self, w: &mut Writer) {
        self.header.encode(w);
        self.transactions.encode(w);
        self.evidence.encode(w);
        w.raw(self.proposer_signature.as_slice());
    }
}

impl Decode for CheckpointProposal {
    fn decode(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self {
            header: CheckpointHeader::decode(r)?,
            transactions: Vec::<Transaction>::decode(r)?,
            evidence: Vec::<Equivocation>::decode(r)?,
            proposer_signature: Signature::decode(r)?,
        })
    }
}

/// A proposal that has been replayed and agrees with local state.
#[derive(Debug)]
pub struct VerifiedProposal {
    /// The unsigned checkpoint to vote for.
    pub checkpoint: Checkpoint,
    /// Changes folded into the Merkle trees, awaiting quorum.
    pub staged: Staged,
}

impl VerifiedProposal {
    pub fn hash(&self) -> Hash {
        self.checkpoint.hash()
    }

    pub fn height(&self) -> u64 {
        self.checkpoint.header.height
    }
}

/// Sort key defining the canonical order of transactions inside a checkpoint.
///
/// Ordering is by `(sender, nonce, transaction id)`. It is a pure function of
/// the transaction set — never of arrival time — so every validator derives the
/// same order and no proposer can reorder, front-run or selectively censor
/// without the result being obvious.
///
/// The nonce is part of the key because a sender's transactions must stay in
/// nonce order: ordering purely by hash would shuffle them, and every one after
/// the first would fail its nonce check. That would cap an account at one
/// transaction per checkpoint.
pub fn order_key(tx: &Transaction) -> (Address, u64, Hash) {
    (tx.from, tx.nonce, tx.id())
}

/// Put transactions into canonical order, dropping exact duplicates.
pub fn canonical_order(mut transactions: Vec<Transaction>) -> Vec<Transaction> {
    transactions.sort_by_key(order_key);
    transactions.dedup_by_key(|tx| tx.id());
    transactions
}

/// Validate evidence and reduce it to the set of validators to slash.
fn slashings(ledger: &Ledger, evidence: &[Equivocation]) -> Result<Vec<Address>> {
    let mut out: Vec<Address> = Vec::new();
    for item in evidence {
        item.verify()?;
        // Only bonded validators can be slashed; evidence against anyone else is
        // noise, not an offence.
        match ledger.validator(&item.validator)? {
            Some(validator) if validator.is_slashable() => {
                if !out.contains(&item.validator) {
                    out.push(item.validator);
                }
            }
            Some(_) => {}
            None => return Err(Error::NotAValidator(item.validator)),
        }
    }
    out.sort();
    Ok(out)
}

/// Build a proposal for the next height from `candidates`.
///
/// Transactions that fail are silently dropped from the checkpoint: they were
/// invalid against the state at this height, and including them would make the
/// checkpoint unverifiable. Ids that failed with [`Error::BadNonce`] are
/// returned so the caller can purge them from the mempool — they can never
/// apply until the gap is filled, and re-batching them only wastes CPU.
///
/// The returned [`Staged`] must be committed once the checkpoint reaches quorum,
/// or rolled back.
pub fn build_proposal(
    ledger: &mut Ledger,
    candidates: Vec<Transaction>,
    evidence: Vec<Equivocation>,
    timestamp: u64,
    proposer: Address,
    round: u32,
) -> Result<(CheckpointProposal, VerifiedProposal, Vec<Hash>)> {
    let height = ledger.height() + 1;
    let mut context = ExecutionContext::new(height, timestamp, proposer);
    context.slashings = slashings(ledger, &evidence)?;

    let ordered = canonical_order(candidates);
    let outcome = ledger.execute(&ordered, context)?;
    let drop_from_mempool: Vec<Hash> = outcome
        .rejected
        .iter()
        .filter(|(_, err)| matches!(err, Error::BadNonce { .. }))
        .map(|(id, _)| *id)
        .collect();
    let applied = outcome.applied.clone();
    if applied.is_empty() && evidence.is_empty() {
        return Err(Error::Other(format!(
            "nothing to checkpoint: no transaction applied and no evidence to record ({} bad-nonce drop candidates)",
            drop_from_mempool.len()
        )));
    }

    let prev_hash = ledger.meta().last_checkpoint_hash;
    let staged = ledger.stage(outcome);
    let header = ledger.build_header(&staged, prev_hash, proposer, round);

    let proposal = CheckpointProposal {
        header: header.clone(),
        transactions: applied,
        evidence,
        proposer_signature: Signature::default(),
    };
    let verified = VerifiedProposal {
        checkpoint: Checkpoint::new(header),
        staged,
    };
    Ok((proposal, verified, drop_from_mempool))
}

/// What gives a header the right to exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// A proposal asking to be signed. Whose turn it is and whether the clock
    /// is plausible are both policy questions this node answers for itself.
    Proposed,
    /// A checkpoint a super-majority has already signed. Those signatures are
    /// the authority for who proposed it and when, so re-litigating the turn
    /// order would only let a node with a slightly wrong clock refuse final
    /// state. The state transition itself is still fully re-derived.
    Finalized,
}

/// Replay a proposal against local state and decide whether to sign it.
///
/// `verified_signatures` lists transaction ids whose ML-DSA-87 signatures this
/// node has already checked (everything in its mempool). Anything else in the
/// proposal is verified here, so a proposal can never smuggle in an unsigned
/// transaction, and a node never pays to verify the same signature twice.
pub fn verify_proposal(
    ledger: &mut Ledger,
    proposal: &CheckpointProposal,
    wall_clock: u64,
    verified_signatures: &HashSet<Hash>,
) -> Result<VerifiedProposal> {
    verify_proposal_with(
        ledger,
        proposal,
        wall_clock,
        verified_signatures,
        Authority::Proposed,
    )
}

/// [`verify_proposal`], with control over which policy checks apply.
pub fn verify_proposal_with(
    ledger: &mut Ledger,
    proposal: &CheckpointProposal,
    wall_clock: u64,
    verified_signatures: &HashSet<Hash>,
    authority: Authority,
) -> Result<VerifiedProposal> {
    let header = &proposal.header;

    let expected_height = ledger.height() + 1;
    if header.height != expected_height {
        return Err(Error::BadCheckpointHeight {
            expected: expected_height,
            actual: header.height,
        });
    }

    let expected_parent = ledger.meta().last_checkpoint_hash;
    if header.prev_hash != expected_parent {
        return Err(Error::BadCheckpointParent {
            expected: expected_parent,
            actual: header.prev_hash,
        });
    }

    // The header timestamp is the clock every transaction in this checkpoint is
    // judged against. That it advances is a property of the chain, checked
    // always; that it agrees with *this node's* clock is a policy question, and
    // only a proposal has to satisfy it. A finalized checkpoint carries a
    // super-majority's word on the time, and a node with a bad clock refusing
    // final state would fork itself off the network for no benefit.
    if header.timestamp <= ledger.meta().last_checkpoint_time {
        return Err(Error::Other(format!(
            "checkpoint timestamp {} does not advance past {}",
            header.timestamp,
            ledger.meta().last_checkpoint_time
        )));
    }

    let active = ledger.active_validators_at(header.height)?;
    if authority == Authority::Proposed {
        if header.timestamp.abs_diff(wall_clock) > TX_TIME_TOLERANCE_SECS {
            return Err(Error::TimestampOutOfRange {
                timestamp: header.timestamp,
                now: wall_clock,
                tolerance: TX_TIME_TOLERANCE_SECS,
            });
        }

        // A validator may only take a turn that is actually due. Rounds are
        // derived from the previous checkpoint's timestamp, which everyone
        // agrees on, and the header cannot claim a round the clock does not
        // support — otherwise a validator could skip the queue by dating its
        // proposal into the future.
        let earliest =
            ledger.meta().last_checkpoint_time + u64::from(header.round) * PROPOSER_TIMEOUT_SECS;
        if header.timestamp < earliest {
            return Err(Error::Other(format!(
                "round {} is not due until {earliest}, but the header is dated {}",
                header.round, header.timestamp
            )));
        }
        if header.round > 0 && wall_clock + PROPOSER_TIMEOUT_SECS < earliest {
            return Err(Error::Other(format!(
                "round {} is not due yet by this node's clock",
                header.round
            )));
        }

        let expected_proposer = proposer_for_round(header.height, header.round, &active)
            .ok_or(Error::NoActiveValidators)?;
        if header.proposer != expected_proposer {
            return Err(Error::WrongProposer {
                expected: expected_proposer,
                actual: header.proposer,
            });
        }

        // Authenticate the proposer before any per-transaction ML-DSA work.
        // Without this, anyone could POST a bulk of forged txs claiming the
        // current proposer's address and burn CPU on signature checks.
        let proposer_key = active
            .iter()
            .find(|v| v.address == expected_proposer)
            .map(|v| &v.public_key)
            .ok_or(Error::NoActiveValidators)?;
        proposal.verify_proposer_signature(proposer_key)?;
    }

    if proposal.transactions.is_empty() && proposal.evidence.is_empty() {
        return Err(Error::Other(
            "checkpoint carries neither transactions nor evidence".into(),
        ));
    }
    if header.tx_count as usize != proposal.transactions.len() {
        return Err(Error::Other(format!(
            "header claims {} transactions but carries {}",
            header.tx_count,
            proposal.transactions.len()
        )));
    }

    // Canonical ordering, checked rather than assumed.
    let keys: Vec<(Address, u64, Hash)> = proposal.transactions.iter().map(order_key).collect();
    if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(Error::Other(
            "transactions are not in canonical (sender, nonce, id) order, or contain duplicates"
                .into(),
        ));
    }
    let ids: Vec<Hash> = proposal.transactions.iter().map(|tx| tx.id()).collect();
    let tx_root = CheckpointHeader::compute_tx_root(&ids);
    if header.tx_root != tx_root {
        return Err(Error::Other(
            "transaction root does not match the transactions".into(),
        ));
    }

    for (tx, id) in proposal.transactions.iter().zip(&ids) {
        // Always bind address↔key, even when the id is already cached: a
        // proposer must not swap a different public key onto a mempool
        // transaction and skip verification.
        if tx.public_key.address() != tx.from {
            return Err(Error::AddressKeyMismatch);
        }
        if !verified_signatures.contains(id) {
            tx.verify_signature()?;
        }
    }

    let mut context = ExecutionContext::new(header.height, header.timestamp, header.proposer);
    context.slashings = slashings(ledger, &proposal.evidence)?;

    let outcome = ledger.execute(&proposal.transactions, context)?;
    if let Some((id, reason)) = outcome.rejected.first() {
        return Err(Error::Other(format!(
            "proposal contains a transaction this node rejects ({}): {reason}",
            id.short()
        )));
    }

    let staged = ledger.stage(outcome);
    let mismatch = if staged.state_root != header.state_root {
        Some(Error::StateRootMismatch {
            expected: header.state_root,
            computed: staged.state_root,
        })
    } else if staged.validator_root != header.validator_root {
        Some(Error::StateRootMismatch {
            expected: header.validator_root,
            computed: staged.validator_root,
        })
    } else if staged.outcome.total_supply != header.total_supply {
        Some(Error::Other(format!(
            "header claims a total supply of {} but replay produced {}",
            header.total_supply, staged.outcome.total_supply
        )))
    } else if staged.outcome.total_bonded != header.total_bonded {
        Some(Error::Other(format!(
            "header claims {} bonded but replay produced {}",
            header.total_bonded, staged.outcome.total_bonded
        )))
    } else {
        None
    };

    if let Some(error) = mismatch {
        ledger.rollback(staged);
        return Err(error);
    }

    Ok(VerifiedProposal {
        checkpoint: Checkpoint::new(header.clone()),
        staged,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::transaction::Transaction;
    use sikka_common::vote::{Vote, VoteKind};
    use sikka_crypto::Keypair;

    #[test]
    fn a_proposal_survives_a_codec_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let mut proposal = CheckpointProposal {
            header: CheckpointHeader {
                height: 9,
                prev_hash: Hash([1u8; 32]),
                state_root: Hash([2u8; 32]),
                validator_root: Hash([3u8; 32]),
                tx_root: Hash([4u8; 32]),
                tx_count: 2,
                timestamp: 1_700_000_000,
                proposer: PublicKey::new(*kp.public_bytes()).address(),
                round: 3,
                total_supply: 1_000_000,
                total_bonded: 1_000,
            },
            transactions: vec![
                Transaction::transfer(&kp, Address([6u8; 32]), 1, 0, 1_700_000_000).unwrap(),
                Transaction::transfer(&kp, Address([7u8; 32]), 2, 1, 1_700_000_000).unwrap(),
            ],
            evidence: vec![Equivocation::new(
                Vote::sign(&kp, 9, 0, VoteKind::Precommit, Hash([8u8; 32])).unwrap(),
                Vote::sign(&kp, 9, 0, VoteKind::Precommit, Hash([9u8; 32])).unwrap(),
            )
            .unwrap()],
            proposer_signature: Signature::default(),
        };
        proposal.sign(&kp).unwrap();

        let decoded = CheckpointProposal::from_bytes(&proposal.to_bytes()).unwrap();
        assert_eq!(decoded, proposal);
        assert_eq!(decoded.hash(), proposal.hash());
        decoded
            .verify_proposer_signature(&PublicKey::new(*kp.public_bytes()))
            .unwrap();
    }

    #[test]
    fn an_unsigned_proposal_is_rejected_before_tx_work() {
        // Covered structurally: verify_proposer_signature fails on a default
        // signature. The full verify_proposal path uses a live ledger in the
        // integration suite; this keeps the cheap check honest in unit tests.
        let kp = Keypair::generate().unwrap();
        let pk = PublicKey::new(*kp.public_bytes());
        let proposal = CheckpointProposal {
            header: CheckpointHeader {
                height: 1,
                prev_hash: Hash::ZERO,
                state_root: Hash([1u8; 32]),
                validator_root: Hash([2u8; 32]),
                tx_root: Hash([3u8; 32]),
                tx_count: 0,
                timestamp: 1,
                proposer: pk.address(),
                round: 0,
                total_supply: 1,
                total_bonded: 1,
            },
            transactions: Vec::new(),
            evidence: Vec::new(),
            proposer_signature: Signature::default(),
        };
        assert_eq!(
            proposal.verify_proposer_signature(&pk).unwrap_err(),
            Error::InvalidSignature
        );
    }

    #[test]
    fn canonical_order_sorts_and_deduplicates() {
        let kp = Keypair::generate().unwrap();
        let a = Transaction::transfer(&kp, Address([1u8; 32]), 1, 0, 1_000).unwrap();
        let b = Transaction::transfer(&kp, Address([2u8; 32]), 2, 1, 1_000).unwrap();
        let c = Transaction::transfer(&kp, Address([3u8; 32]), 3, 2, 1_000).unwrap();

        let ordered = canonical_order(vec![c.clone(), a.clone(), b.clone(), a.clone()]);
        assert_eq!(ordered.len(), 3, "the duplicate was dropped");

        // One sender's transactions come out in nonce order, whatever order they
        // arrived in.
        assert_eq!(
            ordered.iter().map(|tx| tx.nonce).collect::<Vec<u64>>(),
            vec![0, 1, 2]
        );

        // The order of the input does not affect the result.
        assert_eq!(canonical_order(vec![b, a, c]), ordered);
    }

    #[test]
    fn canonical_order_groups_senders_by_address() {
        let first = Keypair::generate().unwrap();
        let second = Keypair::generate().unwrap();
        let target = Address([1u8; 32]);

        let mut transactions = Vec::new();
        for kp in [&first, &second] {
            for nonce in 0..3 {
                transactions.push(Transaction::transfer(kp, target, 1, nonce, 1_000).unwrap());
            }
        }
        transactions.reverse();

        let ordered = canonical_order(transactions);
        let keys: Vec<(Address, u64, Hash)> = ordered.iter().map(order_key).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);

        // Each sender's own transactions remain in nonce order.
        for sender in [&first, &second] {
            let address = sikka_common::bytes::PublicKey::new(*sender.public_bytes()).address();
            let nonces: Vec<u64> = ordered
                .iter()
                .filter(|tx| tx.from == address)
                .map(|tx| tx.nonce)
                .collect();
            assert_eq!(nonces, vec![0, 1, 2]);
        }
    }
}
