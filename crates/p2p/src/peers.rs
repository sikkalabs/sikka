//! Peer identity and discovery.
//!
//! A peer *is* an ML-DSA-87 key: its network identity and its account identity
//! are the same 32-byte address. Announcements are signed, so a node can never
//! be told that some other node lives at an attacker's endpoint, and there is
//! nothing to encrypt in transit — every message is authenticated at the
//! application layer, which is why plain HTTP(S) is enough.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use sikka_common::bytes::{Address, PublicKey, Signature};
use sikka_common::codec::Writer;
use sikka_common::constants::TX_TIME_TOLERANCE_SECS;
use sikka_common::error::{Error, Result};

/// Domain tag for signed peer announcements.
pub const ANNOUNCE_TAG: &[u8] = b"SIKKA/peer-announce/v3";

/// Maximum peers tracked, so discovery cannot exhaust memory.
pub const DEFAULT_MAX_PEERS: usize = 512;

/// Consecutive failures before a peer is dropped.
pub const MAX_FAILURES: u32 = 10;

/// A signed claim: "this key is reachable at this endpoint".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAnnounce {
    pub public_key: PublicKey,
    /// Base URL, e.g. `https://1.sikkalabs.com` or `http://node:64552`.
    pub endpoint: String,
    pub timestamp: u64,
    pub signature: Signature,
}

impl PeerAnnounce {
    pub fn signing_bytes(endpoint: &str, timestamp: u64, chain_id: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(ANNOUNCE_TAG)
            .str(chain_id)
            .str(endpoint)
            .u64(timestamp);
        w.finish()
    }

    pub fn sign(
        keypair: &sikka_crypto::Keypair,
        endpoint: &str,
        timestamp: u64,
        chain_id: &str,
    ) -> Result<Self> {
        let payload = Self::signing_bytes(endpoint, timestamp, chain_id);
        Ok(Self {
            public_key: PublicKey::new(*keypair.public_bytes()),
            endpoint: endpoint.to_string(),
            timestamp,
            signature: Signature::new(keypair.sign(&payload)?),
        })
    }

    pub fn address(&self) -> Address {
        self.public_key.address()
    }

    /// Verify the signature and freshness.
    ///
    /// Stale announcements are rejected so an old endpoint cannot be replayed
    /// after a node has moved.
    pub fn verify(&self, now: u64, chain_id: &str) -> Result<()> {
        if self.endpoint.is_empty() || self.endpoint.len() > 256 {
            return Err(Error::Network("implausible peer endpoint".into()));
        }
        if !self.endpoint.starts_with("http://") && !self.endpoint.starts_with("https://") {
            return Err(Error::Network(
                "peer endpoint must be an http(s) URL".into(),
            ));
        }
        if self.timestamp.abs_diff(now) > TX_TIME_TOLERANCE_SECS {
            return Err(Error::TimestampOutOfRange {
                timestamp: self.timestamp,
                now,
                tolerance: TX_TIME_TOLERANCE_SECS,
            });
        }
        let payload = Self::signing_bytes(&self.endpoint, self.timestamp, chain_id);
        if !sikka_crypto::verify(
            self.public_key.as_slice(),
            &payload,
            self.signature.as_slice(),
        ) {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

/// A known peer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub address: Address,
    pub endpoint: String,
    pub last_seen: u64,
    #[serde(default)]
    pub failures: u32,
}

/// The set of peers a node talks to.
#[derive(Debug)]
pub struct PeerBook {
    peers: HashMap<Address, Peer>,
    /// This node's own address, so it never adds itself.
    self_address: Address,
    max_peers: usize,
}

impl PeerBook {
    pub fn new(self_address: Address) -> Self {
        Self {
            peers: HashMap::new(),
            self_address,
            max_peers: DEFAULT_MAX_PEERS,
        }
    }

    pub fn with_max(self_address: Address, max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            self_address,
            max_peers: max_peers.max(1),
        }
    }

    /// Record a verified announcement.
    ///
    /// Returns `true` if this was a new peer or a changed endpoint.
    pub fn record(
        &mut self,
        announce: &PeerAnnounce,
        now: u64,
        chain_id: &str,
    ) -> Result<bool> {
        announce.verify(now, chain_id)?;
        let address = announce.address();
        if address == self.self_address {
            return Ok(false);
        }
        Ok(self.upsert(address, announce.endpoint.clone(), now))
    }

    /// Add a peer learned without a signature (a bootstrap entry or a referral
    /// from another node).
    ///
    /// Referrals only get a node as far as *trying* an endpoint; nothing is
    /// trusted until that endpoint answers with something signed.
    pub fn add_endpoint(&mut self, endpoint: &str, now: u64) -> bool {
        // Bootstrap entries have no address yet; key them by the hash of the
        // endpoint until the peer identifies itself.
        let placeholder = Address(sikka_crypto::sha3_256(endpoint.as_bytes()));
        if placeholder == self.self_address {
            return false;
        }
        if self.peers.values().any(|p| p.endpoint == endpoint) {
            return false;
        }
        self.upsert(placeholder, endpoint.to_string(), now)
    }

    fn upsert(&mut self, address: Address, endpoint: String, now: u64) -> bool {
        if let Some(existing) = self.peers.get_mut(&address) {
            let changed = existing.endpoint != endpoint;
            existing.endpoint = endpoint;
            existing.last_seen = now;
            existing.failures = 0;
            return changed;
        }
        if self.peers.len() >= self.max_peers {
            // Evict the peer we have heard from least recently.
            if let Some(stalest) = self
                .peers
                .iter()
                .min_by_key(|(a, p)| (p.last_seen, **a))
                .map(|(a, _)| *a)
            {
                self.peers.remove(&stalest);
            }
        }
        // Two identities claiming one endpoint means one of them moved on.
        let duplicates: Vec<Address> = self
            .peers
            .iter()
            .filter(|(_, p)| p.endpoint == endpoint)
            .map(|(a, _)| *a)
            .collect();
        for duplicate in duplicates {
            self.peers.remove(&duplicate);
        }
        self.peers.insert(
            address,
            Peer {
                address,
                endpoint,
                last_seen: now,
                failures: 0,
            },
        );
        true
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn contains(&self, address: &Address) -> bool {
        self.peers.contains_key(address)
    }

    /// Peers ordered by address, so behaviour does not depend on hash iteration
    /// order.
    pub fn all(&self) -> Vec<Peer> {
        let mut peers: Vec<Peer> = self.peers.values().cloned().collect();
        peers.sort_by_key(|a| a.address);
        peers
    }

    pub fn endpoints(&self) -> Vec<String> {
        self.all().into_iter().map(|p| p.endpoint).collect()
    }

    /// Note a failed request; the peer is dropped after too many.
    pub fn record_failure(&mut self, endpoint: &str) {
        let mut drop_address = None;
        for (address, peer) in self.peers.iter_mut() {
            if peer.endpoint == endpoint {
                peer.failures += 1;
                if peer.failures >= MAX_FAILURES {
                    drop_address = Some(*address);
                }
                break;
            }
        }
        if let Some(address) = drop_address {
            self.peers.remove(&address);
        }
    }

    pub fn record_success(&mut self, endpoint: &str, now: u64) {
        for peer in self.peers.values_mut() {
            if peer.endpoint == endpoint {
                peer.failures = 0;
                peer.last_seen = now;
                break;
            }
        }
    }

    pub fn remove(&mut self, address: &Address) -> Option<Peer> {
        self.peers.remove(address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_crypto::Keypair;

    const NOW: u64 = 1_700_000_000;

    fn chain_id() -> &'static str {
        "sikka-test"
    }

    fn announce(kp: &Keypair, endpoint: &str, timestamp: u64) -> PeerAnnounce {
        PeerAnnounce::sign(kp, endpoint, timestamp, chain_id()).unwrap()
    }

    #[test]
    fn signed_announcements_verify() {
        let kp = Keypair::generate().unwrap();
        let a = announce(&kp, "http://sikka-1:8080", NOW);
        a.verify(NOW, chain_id()).unwrap();
        assert_eq!(a.address(), PublicKey::new(*kp.public_bytes()).address());
    }

    #[test]
    fn tampering_with_the_endpoint_breaks_the_signature() {
        let kp = Keypair::generate().unwrap();
        let mut a = announce(&kp, "http://sikka-1:8080", NOW);
        a.endpoint = "http://attacker:8080".into();
        assert_eq!(a.verify(NOW, chain_id()).unwrap_err(), Error::InvalidSignature);
    }

    #[test]
    fn stale_and_malformed_announcements_are_rejected() {
        let kp = Keypair::generate().unwrap();
        let a = announce(&kp, "http://sikka-1:8080", NOW);
        assert!(matches!(
            a.verify(NOW + 10_000, chain_id()),
            Err(Error::TimestampOutOfRange { .. })
        ));

        let bad = announce(&kp, "sikka-1:8080", NOW);
        assert!(matches!(bad.verify(NOW, chain_id()), Err(Error::Network(_))));
    }

    #[test]
    fn book_records_and_updates_peers() {
        let me = Keypair::generate().unwrap();
        let peer = Keypair::generate().unwrap();
        let mut book = PeerBook::new(PublicKey::new(*me.public_bytes()).address());

        assert!(book
            .record(&announce(&peer, "http://a:8080", NOW), NOW, chain_id())
            .unwrap());
        assert_eq!(book.len(), 1);

        // Same endpoint again is not news.
        assert!(!book
            .record(&announce(&peer, "http://a:8080", NOW + 1), NOW + 1, chain_id())
            .unwrap());
        // A move is.
        assert!(book
            .record(&announce(&peer, "http://b:8080", NOW + 2), NOW + 2, chain_id())
            .unwrap());
        assert_eq!(book.len(), 1);
        assert_eq!(book.all()[0].endpoint, "http://b:8080");
    }

    #[test]
    fn a_node_never_adds_itself() {
        let me = Keypair::generate().unwrap();
        let address = PublicKey::new(*me.public_bytes()).address();
        let mut book = PeerBook::new(address);
        assert!(!book
            .record(&announce(&me, "http://me:8080", NOW), NOW, chain_id())
            .unwrap());
        assert!(book.is_empty());
    }

    #[test]
    fn bootstrap_endpoints_are_deduplicated() {
        let me = Keypair::generate().unwrap();
        let mut book = PeerBook::new(PublicKey::new(*me.public_bytes()).address());
        assert!(book.add_endpoint("http://boot:8080", NOW));
        assert!(!book.add_endpoint("http://boot:8080", NOW));
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn a_signed_announcement_replaces_its_bootstrap_placeholder() {
        let me = Keypair::generate().unwrap();
        let peer = Keypair::generate().unwrap();
        let mut book = PeerBook::new(PublicKey::new(*me.public_bytes()).address());

        book.add_endpoint("http://a:8080", NOW);
        book.record(&announce(&peer, "http://a:8080", NOW), NOW, chain_id())
            .unwrap();

        assert_eq!(book.len(), 1, "the placeholder must not linger");
        assert!(book.contains(&PublicKey::new(*peer.public_bytes()).address()));
    }

    #[test]
    fn failing_peers_are_eventually_dropped() {
        let me = Keypair::generate().unwrap();
        let peer = Keypair::generate().unwrap();
        let mut book = PeerBook::new(PublicKey::new(*me.public_bytes()).address());
        book.record(&announce(&peer, "http://a:8080", NOW), NOW, chain_id())
            .unwrap();

        for _ in 0..MAX_FAILURES - 1 {
            book.record_failure("http://a:8080");
        }
        assert_eq!(book.len(), 1);
        book.record_success("http://a:8080", NOW + 1);
        assert_eq!(book.all()[0].failures, 0);

        for _ in 0..MAX_FAILURES {
            book.record_failure("http://a:8080");
        }
        assert!(book.is_empty());
    }

    #[test]
    fn the_book_is_bounded() {
        let me = Keypair::generate().unwrap();
        let mut book = PeerBook::with_max(PublicKey::new(*me.public_bytes()).address(), 3);
        for i in 0..10 {
            book.add_endpoint(&format!("http://peer-{i}:8080"), NOW + i);
        }
        assert_eq!(book.len(), 3);
    }

}
