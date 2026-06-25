//! HTTP federation: the mempool, peer discovery and the client side of the
//! protocol.
//!
//! Nodes talk over signed JSON on plain HTTP. Production peers reach each other
//! only via Tor v3 onions (SOCKS5h). Application-layer ML-DSA-87 signatures make
//! transport TLS unnecessary. Loopback HTTP remains for in-process tests.

pub mod bloom;
pub mod client;
pub mod mempool;
pub mod peers;
pub mod wire;

pub use bloom::BloomFilter;
pub use client::{ClientConfig, PeerClient};
pub use mempool::{Admission, Mempool};
pub use peers::{
    backoff_secs, is_loopback_endpoint, is_onion_endpoint, validate_endpoint_url, Peer,
    PeerAnnounce, PeerBook, BACKOFF_BASE_SECS, BACKOFF_MAX_SECS, DEFAULT_MAX_PEERS, MAX_FAILURES,
};
pub use wire::MessageKind;
