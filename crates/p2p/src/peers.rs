//! Peer identity and discovery.
//!
//! A peer *is* an ML-DSA-87 key: its network identity and its account identity
//! are the same 32-byte address. Announcements are signed, so a node can never
//! be told that some other node lives at an attacker's endpoint.
//!
//! Production peers advertise Tor v3 onions (`http://….onion`). Loopback HTTP
//! is allowed only so in-process unit tests can mesh without Tor. Clearnet
//! hosts are rejected — the peer mesh is Tor-only.

use std::collections::HashMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use sikka_common::bytes::{Address, Hash, PublicKey, Signature};
use sikka_common::codec::Writer;
use sikka_common::constants::TX_TIME_TOLERANCE_SECS;
use sikka_common::error::{Error, Result};

/// Domain tag for signed peer announcements.
pub const ANNOUNCE_TAG: &[u8] = b"SIKKA/peer-announce/v4";

/// Maximum peers tracked, so discovery cannot exhaust memory.
pub const DEFAULT_MAX_PEERS: usize = 512;

/// Consecutive failures before a peer may be dropped — and only when the book
/// is already at [`DEFAULT_MAX_PEERS`]. Below that, failed endpoints are kept
/// and retried with exponential backoff so a short outage cannot empty the mesh.
pub const MAX_FAILURES: u32 = 10;

/// Base delay (seconds) after the first failure: `base * 2^(failures-1)`.
pub const BACKOFF_BASE_SECS: u64 = 2;

/// Cap on per-peer dial backoff so a long outage still recovers within minutes.
pub const BACKOFF_MAX_SECS: u64 = 300;

/// Key bootstrap/referral entries before a peer identifies itself.
fn placeholder_for_endpoint(endpoint: &str) -> Address {
    Address(sikka_crypto::sha3_256(endpoint.as_bytes()))
}

fn is_placeholder_address(address: &Address, endpoint: &str) -> bool {
    *address == placeholder_for_endpoint(endpoint)
}

/// Reject peer endpoints that are not Tor onions (or loopback for local tests).
pub fn validate_endpoint_url(endpoint: &str) -> Result<()> {
    if endpoint.is_empty() || endpoint.len() > 256 {
        return Err(Error::Network("implausible peer endpoint".into()));
    }
    if endpoint.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(Error::Network("peer endpoint contains control characters".into()));
    }
    let Some(rest) = endpoint.strip_prefix("http://") else {
        return Err(Error::Network(
            "peer endpoint must be an http:// onion or loopback URL".into(),
        ));
    };
    if rest.is_empty() {
        return Err(Error::Network("peer endpoint has no host".into()));
    }

    let host = if rest.starts_with('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| Error::Network("malformed IPv6 peer endpoint".into()))?;
        &rest[1..end]
    } else {
        let end = rest.find([':', '/']).unwrap_or(rest.len());
        &rest[..end]
    };

    if host.is_empty() {
        return Err(Error::Network("peer endpoint has no host".into()));
    }
    if is_onion_host(host) || is_loopback_host(host) {
        return Ok(());
    }
    Err(Error::Network(
        "peer endpoint must be a .onion or loopback host".into(),
    ))
}

/// True when the URL host is a Tor v3 onion address.
pub fn is_onion_endpoint(endpoint: &str) -> bool {
    endpoint_host(endpoint).is_some_and(is_onion_host)
}

/// True when the URL host is loopback (unit-test meshes).
pub fn is_loopback_endpoint(endpoint: &str) -> bool {
    endpoint_host(endpoint).is_some_and(is_loopback_host)
}

fn endpoint_host(endpoint: &str) -> Option<&str> {
    let rest = endpoint.strip_prefix("http://")?;
    if rest.starts_with('[') {
        let end = rest.find(']')?;
        Some(&rest[1..end])
    } else {
        let end = rest.find([':', '/']).unwrap_or(rest.len());
        Some(&rest[..end])
    }
}

fn is_onion_host(host: &str) -> bool {
    let Some(label) = host.strip_suffix(".onion") else {
        return false;
    };
    // Tor v3: 56 chars of base32 (a-z2-7).
    label.len() == 56
        && label
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7'))
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let ip_host = host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host);
    ip_host
        .parse::<IpAddr>()
        .is_ok_and(|ip| match ip {
            IpAddr::V4(v4) => v4.is_loopback(),
            IpAddr::V6(v6) => v6.is_loopback(),
        })
}

enum UpsertPolicy {
    /// Signed announcement: may evict stalest peers and replace endpoint owners.
    Signed,
    /// Unsigned referral: never evict real-address peers.
    UnsignedReferral,
}

/// Seconds to wait before dialing again after `failures` consecutive errors.
pub fn backoff_secs(failures: u32) -> u64 {
    if failures == 0 {
        return 0;
    }
    let shift = (failures - 1).min(16);
    BACKOFF_BASE_SECS
        .saturating_mul(1u64 << shift)
        .min(BACKOFF_MAX_SECS)
}

/// A signed claim: "this key is reachable at this endpoint".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAnnounce {
    pub public_key: PublicKey,
    /// Base URL, e.g. `http://….onion` or `http://127.0.0.1:64552` in tests.
    pub endpoint: String,
    pub timestamp: u64,
    pub signature: Signature,
}

impl PeerAnnounce {
    pub fn signing_bytes(
        endpoint: &str,
        timestamp: u64,
        chain_id: &str,
        genesis_fingerprint: &Hash,
    ) -> Vec<u8> {
        let mut w = Writer::new();
        w.raw(ANNOUNCE_TAG)
            .str(chain_id)
            .raw(genesis_fingerprint.as_bytes())
            .str(endpoint)
            .u64(timestamp);
        w.finish()
    }

    pub fn sign(
        keypair: &sikka_crypto::Keypair,
        endpoint: &str,
        timestamp: u64,
        chain_id: &str,
        genesis_fingerprint: Hash,
    ) -> Result<Self> {
        let payload = Self::signing_bytes(endpoint, timestamp, chain_id, &genesis_fingerprint);
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
    pub fn verify(&self, now: u64, chain_id: &str, genesis_fingerprint: &Hash) -> Result<()> {
        validate_endpoint_url(&self.endpoint)?;
        if self.timestamp.abs_diff(now) > TX_TIME_TOLERANCE_SECS {
            return Err(Error::TimestampOutOfRange {
                timestamp: self.timestamp,
                now,
                tolerance: TX_TIME_TOLERANCE_SECS,
            });
        }
        let payload = Self::signing_bytes(&self.endpoint, self.timestamp, chain_id, genesis_fingerprint);
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
    /// Unix seconds; dials are skipped until this time while backing off.
    #[serde(default)]
    pub backoff_until: u64,
}

impl Peer {
    pub fn due(&self, now: u64) -> bool {
        self.backoff_until <= now
    }
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
        genesis_fingerprint: &Hash,
    ) -> Result<bool> {
        announce.verify(now, chain_id, genesis_fingerprint)?;
        let address = announce.address();
        if address == self.self_address {
            return Ok(false);
        }
        Ok(self.upsert(
            address,
            announce.endpoint.clone(),
            now,
            UpsertPolicy::Signed,
        ))
    }

    /// Add a peer learned without a signature (a bootstrap entry or a referral
    /// from another node).
    ///
    /// Referrals only get a node as far as *trying* an endpoint; nothing is
    /// trusted until that endpoint answers with something signed.
    pub fn add_endpoint(&mut self, endpoint: &str, now: u64) -> bool {
        if validate_endpoint_url(endpoint).is_err() {
            return false;
        }
        // Bootstrap entries have no address yet; key them by the hash of the
        // endpoint until the peer identifies itself.
        let placeholder = placeholder_for_endpoint(endpoint);
        if placeholder == self.self_address {
            return false;
        }
        if self.peers.values().any(|p| p.endpoint == endpoint) {
            return false;
        }
        self.upsert(
            placeholder,
            endpoint.to_string(),
            now,
            UpsertPolicy::UnsignedReferral,
        )
    }

    fn upsert(
        &mut self,
        address: Address,
        endpoint: String,
        now: u64,
        policy: UpsertPolicy,
    ) -> bool {
        if let Some(existing) = self.peers.get_mut(&address) {
            let changed = existing.endpoint != endpoint;
            existing.endpoint = endpoint;
            existing.last_seen = now;
            existing.failures = 0;
            existing.backoff_until = 0;
            return changed;
        }
        if self.peers.len() >= self.max_peers {
            let evict = match policy {
                UpsertPolicy::Signed => self
                    .peers
                    .iter()
                    .min_by_key(|(a, p)| (p.last_seen, **a))
                    .map(|(a, _)| *a),
                UpsertPolicy::UnsignedReferral => self
                    .peers
                    .iter()
                    .filter(|(_, p)| is_placeholder_address(&p.address, &p.endpoint))
                    .min_by_key(|(a, p)| (p.last_seen, **a))
                    .map(|(a, _)| *a),
            };
            if let Some(stalest) = evict {
                self.peers.remove(&stalest);
            } else if matches!(policy, UpsertPolicy::UnsignedReferral) {
                return false;
            }
        }
        // Two identities claiming one endpoint means one of them moved on.
        let duplicates: Vec<Address> = self
            .peers
            .iter()
            .filter(|(_, p)| {
                p.endpoint == endpoint
                    && (matches!(policy, UpsertPolicy::Signed)
                        || is_placeholder_address(&p.address, &p.endpoint))
            })
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
                backoff_until: 0,
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

    /// Endpoints that are not sitting out a backoff window.
    pub fn endpoints_due(&self, now: u64) -> Vec<String> {
        self.all()
            .into_iter()
            .filter(|p| p.due(now))
            .map(|p| p.endpoint)
            .collect()
    }

    /// Note a failed request.
    ///
    /// Below [`DEFAULT_MAX_PEERS`] the endpoint is kept and retried later with
    /// exponential backoff. Only a full book may drop a peer after
    /// [`MAX_FAILURES`] consecutive failures — otherwise a two-node mesh dies
    /// permanently after a brief outage.
    pub fn record_failure(&mut self, endpoint: &str, now: u64) {
        let mut drop_address = None;
        let at_capacity = self.peers.len() >= self.max_peers;
        for (address, peer) in self.peers.iter_mut() {
            if peer.endpoint == endpoint {
                peer.failures = peer.failures.saturating_add(1);
                peer.backoff_until = now.saturating_add(backoff_secs(peer.failures));
                if at_capacity && peer.failures >= MAX_FAILURES {
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
                peer.backoff_until = 0;
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

    fn fingerprint() -> Hash {
        Hash([0xAA; 32])
    }

    fn announce(kp: &Keypair, endpoint: &str, timestamp: u64) -> PeerAnnounce {
        PeerAnnounce::sign(kp, endpoint, timestamp, chain_id(), fingerprint()).unwrap()
    }

    #[test]
    fn signed_announcements_verify() {
        let kp = Keypair::generate().unwrap();
        let a = announce(&kp, "http://127.0.0.1:8080", NOW);
        a.verify(NOW, chain_id(), &fingerprint()).unwrap();
        assert_eq!(a.address(), PublicKey::new(*kp.public_bytes()).address());
    }

    #[test]
    fn tampering_with_the_endpoint_breaks_the_signature() {
        let kp = Keypair::generate().unwrap();
        let mut a = announce(&kp, "http://127.0.0.1:8080", NOW);
        a.endpoint = "http://127.0.0.1:9999".into();
        assert_eq!(a.verify(NOW, chain_id(), &fingerprint()).unwrap_err(), Error::InvalidSignature);
    }

    #[test]
    fn stale_and_malformed_announcements_are_rejected() {
        let kp = Keypair::generate().unwrap();
        let a = announce(&kp, "http://127.0.0.1:8080", NOW);
        assert!(matches!(
            a.verify(NOW + 10_000, chain_id(), &fingerprint()),
            Err(Error::TimestampOutOfRange { .. })
        ));

        let bad = announce(&kp, "not-a-url", NOW);
        assert!(matches!(bad.verify(NOW, chain_id(), &fingerprint()), Err(Error::Network(_))));
    }

    #[test]
    fn book_records_and_updates_peers() {
        let me = Keypair::generate().unwrap();
        let peer = Keypair::generate().unwrap();
        let mut book = PeerBook::new(PublicKey::new(*me.public_bytes()).address());

        assert!(book
            .record(&announce(&peer, "http://127.0.0.1:8081", NOW), NOW, chain_id(), &fingerprint())
            .unwrap());
        assert_eq!(book.len(), 1);

        // Same endpoint again is not news.
        assert!(!book
            .record(&announce(&peer, "http://127.0.0.1:8081", NOW + 1), NOW + 1, chain_id(), &fingerprint())
            .unwrap());
        // A move is.
        assert!(book
            .record(&announce(&peer, "http://127.0.0.1:8082", NOW + 2), NOW + 2, chain_id(), &fingerprint())
            .unwrap());
        assert_eq!(book.len(), 1);
        assert_eq!(book.all()[0].endpoint, "http://127.0.0.1:8082");
    }

    #[test]
    fn a_node_never_adds_itself() {
        let me = Keypair::generate().unwrap();
        let address = PublicKey::new(*me.public_bytes()).address();
        let mut book = PeerBook::new(address);
        assert!(!book
            .record(&announce(&me, "http://127.0.0.1:8083", NOW), NOW, chain_id(), &fingerprint())
            .unwrap());
        assert!(book.is_empty());
    }

    #[test]
    fn bootstrap_endpoints_are_deduplicated() {
        let me = Keypair::generate().unwrap();
        let mut book = PeerBook::new(PublicKey::new(*me.public_bytes()).address());
        assert!(book.add_endpoint("http://127.0.0.1:8084", NOW));
        assert!(!book.add_endpoint("http://127.0.0.1:8084", NOW));
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn a_signed_announcement_replaces_its_bootstrap_placeholder() {
        let me = Keypair::generate().unwrap();
        let peer = Keypair::generate().unwrap();
        let mut book = PeerBook::new(PublicKey::new(*me.public_bytes()).address());

        book.add_endpoint("http://127.0.0.1:8081", NOW);
        book.record(&announce(&peer, "http://127.0.0.1:8081", NOW), NOW, chain_id(), &fingerprint())
            .unwrap();

        assert_eq!(book.len(), 1, "the placeholder must not linger");
        assert!(book.contains(&PublicKey::new(*peer.public_bytes()).address()));
    }

    #[test]
    fn failing_peers_backoff_instead_of_dropping_a_small_book() {
        let me = Keypair::generate().unwrap();
        let peer = Keypair::generate().unwrap();
        let mut book = PeerBook::new(PublicKey::new(*me.public_bytes()).address());
        book.record(&announce(&peer, "http://127.0.0.1:8081", NOW), NOW, chain_id(), &fingerprint())
            .unwrap();

        for i in 1..=MAX_FAILURES {
            book.record_failure("http://127.0.0.1:8081", NOW + i as u64);
        }
        assert_eq!(book.len(), 1, "small books must keep failed endpoints");
        let kept = &book.all()[0];
        assert_eq!(kept.failures, MAX_FAILURES);
        assert_eq!(kept.backoff_until, NOW + MAX_FAILURES as u64 + backoff_secs(MAX_FAILURES));
        assert!(book.endpoints_due(NOW + MAX_FAILURES as u64).is_empty());
        assert_eq!(
            book.endpoints_due(kept.backoff_until),
            vec!["http://127.0.0.1:8081".to_string()]
        );

        book.record_success("http://127.0.0.1:8081", NOW + 100);
        assert_eq!(book.all()[0].failures, 0);
        assert_eq!(book.all()[0].backoff_until, 0);
    }

    #[test]
    fn full_books_may_drop_peers_after_max_failures() {
        let me = Keypair::generate().unwrap();
        let mut book = PeerBook::with_max(PublicKey::new(*me.public_bytes()).address(), 2);
        book.add_endpoint("http://127.0.0.1:8081", NOW);
        book.add_endpoint("http://127.0.0.1:8082", NOW);
        assert_eq!(book.len(), 2);

        for i in 1..=MAX_FAILURES {
            book.record_failure("http://127.0.0.1:8081", NOW + i as u64);
        }
        assert_eq!(book.len(), 1);
        assert_eq!(book.endpoints(), vec!["http://127.0.0.1:8082".to_string()]);
    }

    #[test]
    fn clearnet_urls_are_rejected_onion_and_loopback_ok() {
        for endpoint in [
            "http://10.0.0.1:8080",
            "http://192.168.1.1:8080",
            "http://169.254.169.254/",
            "http://sikka-1:8080",
            "https://1.sikkalabs.com",
            "http://example.com",
        ] {
            assert!(
                validate_endpoint_url(endpoint).is_err(),
                "expected {endpoint} to be rejected"
            );
        }
        for endpoint in [
            "http://127.0.0.1:8080",
            "http://localhost:8080",
            "http://[::1]:8080",
            "http://vgz5tb6cr3bewedb3zqhfrqgnfghrkvpjqguoeqragqyx247azeym7ad.onion",
        ] {
            validate_endpoint_url(endpoint).unwrap();
        }
    }


    #[test]
    fn unsigned_referral_cannot_evict_signed_peer() {
        let me = Keypair::generate().unwrap();
        let signed = Keypair::generate().unwrap();
        let signed_address = PublicKey::new(*signed.public_bytes()).address();
        let mut book = PeerBook::with_max(PublicKey::new(*me.public_bytes()).address(), 2);

        book.record(
            &announce(&signed, "http://127.0.0.1:8085", NOW),
            NOW,
            chain_id(),
            &fingerprint(),
        )
        .unwrap();
        book.add_endpoint("http://127.0.0.1:8084", NOW);
        assert_eq!(book.len(), 2);

        // May evict another placeholder, but never the signed peer.
        assert!(book.add_endpoint("http://127.0.0.1:8086", NOW));
        assert_eq!(book.len(), 2);
        assert!(book.contains(&signed_address));
        assert!(!book.endpoints().iter().any(|e| e == "http://127.0.0.1:8084"));
    }

    #[test]
    fn backoff_doubles_until_the_cap() {
        assert_eq!(backoff_secs(0), 0);
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(2), 4);
        assert_eq!(backoff_secs(3), 8);
        assert_eq!(backoff_secs(10), BACKOFF_MAX_SECS);
        assert_eq!(backoff_secs(20), BACKOFF_MAX_SECS);
    }

    #[test]
    fn the_book_is_bounded() {
        let me = Keypair::generate().unwrap();
        let mut book = PeerBook::with_max(PublicKey::new(*me.public_bytes()).address(), 3);
        for i in 0..10 {
            book.add_endpoint(&format!("http://127.0.0.1:{}", 9000 + i), NOW + i);
        }
        assert_eq!(book.len(), 3);
    }

}
