//! The mempool: verified transactions waiting for a checkpoint.
//!
//! This is the only place SIKKA holds transactions at all, and it holds them
//! briefly. Once a checkpoint finalizes, the transactions that produced it are
//! dropped — the state root is the record. Nothing here is persisted, so a
//! restarting node simply refills from its peers.
//!
//! Every transaction is signature-verified on the way in, exactly once. That is
//! what lets checkpoint replay skip verification and stay fast.

use std::collections::{BTreeMap, HashMap, HashSet};

use sikka_common::bytes::{Address, Hash};
use sikka_common::error::{Error, Result};
use sikka_common::transaction::Transaction;

use crate::bloom::BloomFilter;

/// Default cap on pending transactions.
pub const DEFAULT_CAPACITY: usize = 100_000;
/// How long an unconfirmed transaction is kept before being dropped. Beyond the
/// ±5 minute timestamp tolerance it could never be applied anyway.
pub const DEFAULT_MAX_AGE_SECS: u64 = 600;

#[derive(Debug, Clone)]
struct Entry {
    transaction: Transaction,
    received_at: u64,
}

/// Why a transaction was accepted or turned away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// New and queued.
    Accepted,
    /// Already present; nothing to do.
    Known,
}

#[derive(Debug)]
pub struct Mempool {
    entries: HashMap<Hash, Entry>,
    /// Per sender, nonce → id. Ordered so the next nonce is cheap to find and a
    /// sender's transactions can be emitted in sequence.
    by_sender: HashMap<Address, BTreeMap<u64, Hash>>,
    capacity: usize,
    max_age: u64,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(DEFAULT_CAPACITY, DEFAULT_MAX_AGE_SECS)
    }
}

impl Mempool {
    pub fn new(capacity: usize, max_age: u64) -> Self {
        Self {
            entries: HashMap::new(),
            by_sender: HashMap::new(),
            capacity: capacity.max(1),
            max_age,
        }
    }

    /// Admit a transaction.
    ///
    /// `committed_nonce` is the sender's nonce in finalized state. A transaction
    /// may use that nonce or continue an unbroken run of pending nonces above it,
    /// so a wallet can send several payments without waiting for a checkpoint,
    /// while gaps — which could never be applied — are refused.
    pub fn insert(
        &mut self,
        transaction: Transaction,
        committed_nonce: u64,
        now: u64,
    ) -> Result<Admission> {
        let id = transaction.id();
        if self.entries.contains_key(&id) {
            return Ok(Admission::Known);
        }

        transaction.validate_stateless(now)?;

        if transaction.nonce < committed_nonce {
            return Err(Error::BadNonce {
                address: transaction.from,
                expected: committed_nonce,
                actual: transaction.nonce,
            });
        }
        let expected = self.next_nonce(&transaction.from, committed_nonce);
        if transaction.nonce > expected {
            return Err(Error::BadNonce {
                address: transaction.from,
                expected,
                actual: transaction.nonce,
            });
        }

        if self.entries.len() >= self.capacity {
            // Full: make room by dropping the oldest, so a burst cannot lock the
            // mempool permanently.
            if !self.evict_oldest() {
                return Err(Error::Other("mempool is full".into()));
            }
        }

        let sender = transaction.from;
        let nonce = transaction.nonce;
        // A replacement at the same nonce (different payload) supersedes the
        // pending one; keeping both would guarantee one of them fails.
        if let Some(existing) = self
            .by_sender
            .get(&sender)
            .and_then(|n| n.get(&nonce))
            .copied()
        {
            self.remove(&existing);
        }
        self.entries.insert(
            id,
            Entry {
                transaction,
                received_at: now,
            },
        );
        self.by_sender.entry(sender).or_default().insert(nonce, id);
        Ok(Admission::Accepted)
    }

    /// The nonce a new transaction from `sender` should carry.
    pub fn next_nonce(&self, sender: &Address, committed_nonce: u64) -> u64 {
        let Some(pending) = self.by_sender.get(sender) else {
            return committed_nonce;
        };
        let mut next = committed_nonce;
        while pending.contains_key(&next) {
            next += 1;
        }
        next
    }

    /// A sender's pending transactions, in nonce order, starting at
    /// `committed_nonce` and stopping at the first gap.
    ///
    /// This is the run a new transaction would queue behind, so it is what
    /// decides whether the sender can still afford one more.
    pub fn pending_run(&self, sender: &Address, committed_nonce: u64) -> Vec<Transaction> {
        let Some(nonces) = self.by_sender.get(sender) else {
            return Vec::new();
        };
        let mut run = Vec::new();
        let mut nonce = committed_nonce;
        while let Some(id) = nonces.get(&nonce) {
            match self.entries.get(id) {
                Some(entry) => run.push(entry.transaction.clone()),
                None => break,
            }
            nonce += 1;
        }
        run
    }

    pub fn contains(&self, id: &Hash) -> bool {
        self.entries.contains_key(id)
    }

    pub fn get(&self, id: &Hash) -> Option<&Transaction> {
        self.entries.get(id).map(|e| &e.transaction)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn ids(&self) -> Vec<Hash> {
        self.entries.keys().copied().collect()
    }

    /// Ids of everything in the pool, for skipping signature re-verification
    /// during checkpoint replay.
    pub fn verified_ids(&self) -> HashSet<Hash> {
        self.entries.keys().copied().collect()
    }

    /// Up to `limit` transactions in canonical checkpoint order.
    pub fn batch(&self, limit: usize) -> Vec<Transaction> {
        let mut transactions: Vec<Transaction> = self
            .entries
            .values()
            .map(|e| e.transaction.clone())
            .collect();
        transactions.sort_by_key(sikka_consensus::proposal::order_key);
        transactions.truncate(limit);
        transactions
    }

    pub fn remove(&mut self, id: &Hash) -> Option<Transaction> {
        let entry = self.entries.remove(id)?;
        let sender = entry.transaction.from;
        if let Some(nonces) = self.by_sender.get_mut(&sender) {
            nonces.remove(&entry.transaction.nonce);
            if nonces.is_empty() {
                self.by_sender.remove(&sender);
            }
        }
        Some(entry.transaction)
    }

    /// Drop transactions that made it into a checkpoint.
    pub fn remove_all(&mut self, ids: &[Hash]) {
        for id in ids {
            self.remove(id);
        }
    }

    /// Drop everything from `sender` with a nonce below `committed_nonce`.
    ///
    /// Called after a checkpoint so transactions invalidated by it (replaced, or
    /// simply superseded) do not linger.
    pub fn prune_stale_nonces(&mut self, sender: &Address, committed_nonce: u64) {
        let stale: Vec<Hash> = self
            .by_sender
            .get(sender)
            .map(|nonces| {
                nonces
                    .range(..committed_nonce)
                    .map(|(_, id)| *id)
                    .collect::<Vec<Hash>>()
            })
            .unwrap_or_default();
        for id in stale {
            self.remove(&id);
        }
    }

    /// Drop transactions older than the configured maximum age.
    pub fn prune_expired(&mut self, now: u64) -> usize {
        let expired: Vec<Hash> = self
            .entries
            .iter()
            .filter(|(_, e)| now.saturating_sub(e.received_at) > self.max_age)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.remove(id);
        }
        expired.len()
    }

    fn evict_oldest(&mut self) -> bool {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|(id, e)| (e.received_at, **id))
            .map(|(id, _)| *id);
        match oldest {
            Some(id) => {
                self.remove(&id);
                true
            }
            None => false,
        }
    }

    /// A filter summarising what this node already holds.
    pub fn bloom(&self) -> BloomFilter {
        BloomFilter::from_hashes(self.entries.keys())
    }

    /// Transactions a peer's filter does not cover, capped at `limit`.
    pub fn missing_from(&self, filter: &BloomFilter, limit: usize) -> Vec<Transaction> {
        let mut missing: Vec<Transaction> = self
            .entries
            .iter()
            .filter(|(id, _)| !filter.contains(id))
            .map(|(_, e)| e.transaction.clone())
            .collect();
        missing.sort_by_key(sikka_consensus::proposal::order_key);
        missing.truncate(limit);
        missing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_crypto::Keypair;

    const NOW: u64 = 1_700_000_000;

    fn transfer(kp: &Keypair, nonce: u64, amount: u64) -> Transaction {
        Transaction::transfer(kp, Address([9u8; 32]), amount, nonce, NOW).unwrap()
    }

    #[test]
    fn accepts_verifies_and_deduplicates() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::default();
        let tx = transfer(&kp, 0, 100);

        assert_eq!(
            pool.insert(tx.clone(), 0, NOW).unwrap(),
            Admission::Accepted
        );
        assert_eq!(pool.insert(tx.clone(), 0, NOW).unwrap(), Admission::Known);
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx.id()));
        assert_eq!(pool.get(&tx.id()), Some(&tx));
    }

    #[test]
    fn rejects_unsigned_and_stale_transactions() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::default();

        let mut forged = transfer(&kp, 0, 100);
        forged.amount = 200;
        assert_eq!(
            pool.insert(forged, 0, NOW).unwrap_err(),
            Error::InvalidSignature
        );

        let tx = transfer(&kp, 0, 100);
        assert!(matches!(
            pool.insert(tx, 0, NOW + 10_000).unwrap_err(),
            Error::TimestampOutOfRange { .. }
        ));
        assert!(pool.is_empty());
    }

    #[test]
    fn queues_a_run_of_nonces_but_refuses_gaps() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::default();

        pool.insert(transfer(&kp, 0, 1), 0, NOW).unwrap();
        pool.insert(transfer(&kp, 1, 1), 0, NOW).unwrap();
        pool.insert(transfer(&kp, 2, 1), 0, NOW).unwrap();
        assert_eq!(pool.len(), 3);

        // A gap can never be applied, so it is refused.
        assert!(matches!(
            pool.insert(transfer(&kp, 7, 1), 0, NOW).unwrap_err(),
            Error::BadNonce { .. }
        ));
        // A nonce already spent on chain is refused too (a different amount, so
        // this is a new transaction rather than one the pool already holds).
        assert!(matches!(
            pool.insert(transfer(&kp, 0, 99), 3, NOW).unwrap_err(),
            Error::BadNonce { .. }
        ));
    }

    #[test]
    fn next_nonce_follows_the_pending_run() {
        let kp = Keypair::generate().unwrap();
        let address = transfer(&kp, 0, 1).from;
        let mut pool = Mempool::default();

        assert_eq!(pool.next_nonce(&address, 5), 5);
        pool.insert(transfer(&kp, 5, 1), 5, NOW).unwrap();
        assert_eq!(pool.next_nonce(&address, 5), 6);
        pool.insert(transfer(&kp, 6, 1), 5, NOW).unwrap();
        assert_eq!(pool.next_nonce(&address, 5), 7);
    }

    #[test]
    fn a_replacement_supersedes_the_same_nonce() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::default();

        let first = transfer(&kp, 0, 100);
        let replacement = transfer(&kp, 0, 500);
        pool.insert(first.clone(), 0, NOW).unwrap();
        pool.insert(replacement.clone(), 0, NOW).unwrap();

        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&first.id()));
        assert!(pool.contains(&replacement.id()));
    }

    #[test]
    fn batch_is_in_canonical_order_and_bounded() {
        let a = Keypair::generate().unwrap();
        let b = Keypair::generate().unwrap();
        let mut pool = Mempool::default();

        // Interleave two senders so the batch has to sort across accounts.
        for nonce in 0..4 {
            pool.insert(transfer(&b, nonce, 10), 0, NOW).unwrap();
            pool.insert(transfer(&a, nonce, 10), 0, NOW).unwrap();
        }

        let batch = pool.batch(100);
        assert_eq!(batch.len(), 8);
        let keys: Vec<_> = batch
            .iter()
            .map(sikka_consensus::proposal::order_key)
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);

        assert_eq!(pool.batch(3).len(), 3);
    }

    #[test]
    fn removal_clears_the_sender_index() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::default();
        let tx = transfer(&kp, 0, 1);
        pool.insert(tx.clone(), 0, NOW).unwrap();

        pool.remove_all(&[tx.id()]);
        assert!(pool.is_empty());
        assert_eq!(pool.next_nonce(&tx.from, 0), 0);
        // The nonce slot is free again.
        pool.insert(transfer(&kp, 0, 2), 0, NOW).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn stale_nonces_are_pruned_after_a_checkpoint() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::default();
        for nonce in 0..4 {
            pool.insert(transfer(&kp, nonce, 1), 0, NOW).unwrap();
        }
        let address = transfer(&kp, 0, 1).from;

        // A checkpoint applied nonces 0 and 1.
        pool.prune_stale_nonces(&address, 2);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.next_nonce(&address, 2), 4);
    }

    #[test]
    fn expiry_drops_old_transactions() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::new(100, 600);
        pool.insert(transfer(&kp, 0, 1), 0, NOW).unwrap();

        assert_eq!(pool.prune_expired(NOW + 599), 0);
        assert_eq!(pool.prune_expired(NOW + 601), 1);
        assert!(pool.is_empty());
    }

    #[test]
    fn a_full_pool_evicts_the_oldest() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::new(2, 600);
        let first = transfer(&kp, 0, 1);
        pool.insert(first.clone(), 0, NOW).unwrap();
        pool.insert(transfer(&kp, 1, 1), 0, NOW + 1).unwrap();
        pool.insert(transfer(&kp, 2, 1), 0, NOW + 2).unwrap();

        assert_eq!(pool.len(), 2);
        assert!(!pool.contains(&first.id()), "the oldest entry made room");
    }

    #[test]
    fn sync_returns_only_what_the_peer_lacks() {
        let kp = Keypair::generate().unwrap();
        let mut mine = Mempool::default();
        let mut theirs = Mempool::default();

        for nonce in 0..6 {
            let tx = transfer(&kp, nonce, 10);
            mine.insert(tx.clone(), 0, NOW).unwrap();
            if nonce < 3 {
                theirs.insert(tx, 0, NOW).unwrap();
            }
        }

        let missing = mine.missing_from(&theirs.bloom(), 100);
        assert_eq!(missing.len(), 3);
        assert!(missing.iter().all(|tx| tx.nonce >= 3));

        // Once synced, there is nothing left to send.
        for tx in missing {
            theirs.insert(tx, 0, NOW).unwrap();
        }
        assert!(mine.missing_from(&theirs.bloom(), 100).is_empty());
        assert_eq!(theirs.len(), 6);
    }

    #[test]
    fn verified_ids_cover_the_pool() {
        let kp = Keypair::generate().unwrap();
        let mut pool = Mempool::default();
        let tx = transfer(&kp, 0, 1);
        pool.insert(tx.clone(), 0, NOW).unwrap();
        assert!(pool.verified_ids().contains(&tx.id()));
    }
}
