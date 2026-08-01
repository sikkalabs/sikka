//! HTTP federation: the mempool, peer discovery and the client side of the
//! protocol.
//!
//! There is no bespoke networking here on purpose. Nodes talk to each other with
//! `POST`s and `GET`s of signed JSON, so:
//!
//! * a node can sit behind any reverse proxy or load balancer;
//! * there are no long-lived connections to manage or reconnect;
//! * transport encryption is unnecessary, because every message carries an
//!   ML-DSA-87 signature over its own contents.
//!
//! The server side lives in the `sikka-node` crate, which owns the state these
//! messages act on.

pub mod bloom;
pub mod client;
pub mod mempool;
pub mod peers;
pub mod wire;

pub use bloom::BloomFilter;
pub use client::{ClientConfig, PeerClient};
pub use mempool::{Admission, Mempool};
pub use peers::{Peer, PeerAnnounce, PeerBook};
pub use wire::MessageKind;
