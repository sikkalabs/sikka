//! ML-DSA-87 (FIPS 204) signing and verification.

use fips204::ml_dsa_87;
use fips204::traits::{KeyGen, SerDes, Signer, Verifier};

use crate::hash::sha3_256;
use crate::SIGNING_CONTEXT;

/// Length of an ML-DSA-87 public key in bytes (2592).
pub const PK_LEN: usize = ml_dsa_87::PK_LEN;
/// Length of an ML-DSA-87 private key in bytes (4896).
pub const SK_LEN: usize = ml_dsa_87::SK_LEN;
/// Length of an ML-DSA-87 signature in bytes (4627).
pub const SIG_LEN: usize = ml_dsa_87::SIG_LEN;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("key generation failed: {0}")]
    KeyGen(&'static str),
    #[error("signing failed: {0}")]
    Sign(&'static str),
    #[error("malformed private key")]
    InvalidPrivateKey,
    #[error("malformed public key")]
    InvalidPublicKey,
    #[error("expected {expected} bytes, got {actual}")]
    BadLength { expected: usize, actual: usize },
}

/// An ML-DSA-87 keypair.
///
/// The deserialised private key is kept alive because `fips204` precomputes
/// signing material on deserialisation; reusing it makes repeated signing
/// substantially cheaper.
pub struct Keypair {
    private: ml_dsa_87::PrivateKey,
    private_bytes: [u8; SK_LEN],
    public_bytes: [u8; PK_LEN],
}

impl Keypair {
    /// Generate a fresh keypair from the operating system CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let (public, private) = ml_dsa_87::try_keygen().map_err(CryptoError::KeyGen)?;
        let public_bytes = public.into_bytes();
        let private_bytes = private.clone().into_bytes();
        Ok(Self {
            private,
            private_bytes,
            public_bytes,
        })
    }

    /// Expand a 32-byte FIPS 204 seed ξ into a full keypair.
    ///
    /// This is what the browser wallet stores as the short private key: the same
    /// seed always produces the same ML-DSA-87 key, and the expanded secret is
    /// what the node and CLI keystores keep.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, CryptoError> {
        let (public, private) = ml_dsa_87::KG::keygen_from_seed(seed);
        let public_bytes = public.into_bytes();
        let private_bytes = private.clone().into_bytes();
        Ok(Self {
            private,
            private_bytes,
            public_bytes,
        })
    }

    /// Restore a keypair from serialised private key bytes.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let private_bytes: [u8; SK_LEN] = bytes.try_into().map_err(|_| CryptoError::BadLength {
            expected: SK_LEN,
            actual: bytes.len(),
        })?;
        let private = ml_dsa_87::PrivateKey::try_from_bytes(private_bytes)
            .map_err(|_| CryptoError::InvalidPrivateKey)?;
        let public_bytes = private.get_public_key().into_bytes();
        Ok(Self {
            private,
            private_bytes,
            public_bytes,
        })
    }

    pub fn public_bytes(&self) -> &[u8; PK_LEN] {
        &self.public_bytes
    }

    pub fn private_bytes(&self) -> &[u8; SK_LEN] {
        &self.private_bytes
    }

    /// SHA3-256 of the public key: the account address.
    pub fn address_bytes(&self) -> [u8; 32] {
        derive_address_bytes(&self.public_bytes)
    }

    /// Sign a message with fresh randomness (hedged signing, recommended).
    pub fn sign(&self, message: &[u8]) -> Result<[u8; SIG_LEN], CryptoError> {
        self.private
            .try_sign(message, SIGNING_CONTEXT)
            .map_err(CryptoError::Sign)
    }

    /// Sign a message deterministically from a caller-supplied seed.
    ///
    /// Useful for reproducible test vectors; hedged [`Keypair::sign`] is
    /// preferred in production.
    pub fn sign_deterministic(
        &self,
        seed: &[u8; 32],
        message: &[u8],
    ) -> Result<[u8; SIG_LEN], CryptoError> {
        self.private
            .try_sign_with_seed(seed, message, SIGNING_CONTEXT)
            .map_err(CryptoError::Sign)
    }
}

impl std::fmt::Debug for Keypair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keypair")
            .field("address", &hex::encode(self.address_bytes()))
            .field("private", &"<redacted>")
            .finish()
    }
}

/// Derive an address from a serialised public key: `SHA3-256(public_key)`.
pub fn derive_address_bytes(public_key: &[u8]) -> [u8; 32] {
    sha3_256(public_key)
}

/// Recover the public key bytes belonging to a serialised private key.
pub fn public_key_from_secret(private_bytes: &[u8]) -> Result<[u8; PK_LEN], CryptoError> {
    Ok(*Keypair::from_private_bytes(private_bytes)?.public_bytes())
}

/// Sign `message` with a serialised private key.
pub fn sign(private_bytes: &[u8], message: &[u8]) -> Result<[u8; SIG_LEN], CryptoError> {
    Keypair::from_private_bytes(private_bytes)?.sign(message)
}

/// Deterministically sign `message` with a serialised private key.
pub fn sign_deterministic(
    private_bytes: &[u8],
    seed: &[u8; 32],
    message: &[u8],
) -> Result<[u8; SIG_LEN], CryptoError> {
    Keypair::from_private_bytes(private_bytes)?.sign_deterministic(seed, message)
}

/// Verify an ML-DSA-87 signature.
///
/// Returns `false` for malformed keys or signatures rather than erroring: a
/// caller validating untrusted network data only cares whether the message is
/// authentic.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(pk_bytes) = <[u8; PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(sig_bytes) = <[u8; SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(pk) = ml_dsa_87::PublicKey::try_from_bytes(pk_bytes) else {
        return false;
    };
    pk.verify(message, &sig_bytes, SIGNING_CONTEXT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_always_expands_to_the_same_keypair() {
        let seed = [7u8; 32];
        let a = Keypair::from_seed(&seed).unwrap();
        let b = Keypair::from_seed(&seed).unwrap();
        assert_eq!(a.public_bytes(), b.public_bytes());
        assert_eq!(a.private_bytes(), b.private_bytes());
        assert_eq!(a.address_bytes(), derive_address_bytes(a.public_bytes()));
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign(b"pay alice 10 SIKKA").unwrap();
        assert!(verify(kp.public_bytes(), b"pay alice 10 SIKKA", &sig));
    }

    #[test]
    fn rejects_tampered_message() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign(b"pay alice 10 SIKKA").unwrap();
        assert!(!verify(kp.public_bytes(), b"pay alice 11 SIKKA", &sig));
    }

    #[test]
    fn rejects_wrong_key() {
        let a = Keypair::generate().unwrap();
        let b = Keypair::generate().unwrap();
        let sig = a.sign(b"msg").unwrap();
        assert!(!verify(b.public_bytes(), b"msg", &sig));
    }

    #[test]
    fn rejects_malformed_inputs() {
        let kp = Keypair::generate().unwrap();
        let sig = kp.sign(b"msg").unwrap();
        assert!(!verify(&[0u8; 8], b"msg", &sig));
        assert!(!verify(kp.public_bytes(), b"msg", &[0u8; 8]));
    }

    #[test]
    fn private_key_roundtrips_through_bytes() {
        let kp = Keypair::generate().unwrap();
        let restored = Keypair::from_private_bytes(kp.private_bytes()).unwrap();
        assert_eq!(kp.public_bytes(), restored.public_bytes());
        assert_eq!(kp.address_bytes(), restored.address_bytes());
        let sig = restored.sign(b"msg").unwrap();
        assert!(verify(kp.public_bytes(), b"msg", &sig));
    }

    #[test]
    fn deterministic_signing_is_reproducible() {
        let kp = Keypair::generate().unwrap();
        let seed = [7u8; 32];
        let a = kp.sign_deterministic(&seed, b"msg").unwrap();
        let b = kp.sign_deterministic(&seed, b"msg").unwrap();
        assert_eq!(a, b);
        assert!(verify(kp.public_bytes(), b"msg", &a));
    }

    #[test]
    fn expected_parameter_sizes() {
        assert_eq!(PK_LEN, 2592);
        assert_eq!(SK_LEN, 4896);
        assert_eq!(SIG_LEN, 4627);
    }

    #[test]
    fn address_is_sha3_of_public_key() {
        let kp = Keypair::generate().unwrap();
        assert_eq!(kp.address_bytes(), crate::sha3_256(kp.public_bytes()));
    }
}
