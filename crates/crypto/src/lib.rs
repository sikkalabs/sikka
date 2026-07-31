//! Post-quantum cryptographic primitives for SIKKA.
//!
//! Two primitives, nothing else:
//!
//! * **ML-DSA-87** (FIPS 204, security category 5) for every signature in the
//!   system: transactions, checkpoint votes and peer announcements.
//! * **SHA3-256** for every hash: addresses, transaction ids, Merkle nodes.
//!
//! Classical signature schemes (ECDSA, Ed25519) are broken by a sufficiently
//! large quantum computer, so they are deliberately absent.

pub mod hash;
pub mod sign;

pub use hash::{sha3_256, sha3_256_parts, Hasher};
pub use sign::{
    derive_address_bytes, public_key_from_secret, sign, sign_deterministic, verify, CryptoError,
    Keypair, PK_LEN, SIG_LEN, SK_LEN,
};

/// Domain separation context mixed into every ML-DSA signature.
///
/// ML-DSA supports a native context string; using it prevents a signature
/// produced for one SIKKA message kind (or another protocol entirely) from
/// being replayed as another.
pub const SIGNING_CONTEXT: &[u8] = b"SIKKA-v1";
