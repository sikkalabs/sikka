//! Fixed-size byte types: [`Address`], [`Hash`], [`PublicKey`], [`Signature`].
//!
//! All of them serialise as hex strings so that JSON payloads and log lines are
//! human readable, and all of them have a fixed binary encoding used for
//! hashing and signing.

use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sikka_crypto::{PK_LEN, SIG_LEN};

use crate::error::Error;

fn decode_hex(s: &str, expected: usize) -> Result<Vec<u8>, Error> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|_| Error::InvalidHex)?;
    if bytes.len() != expected {
        return Err(Error::InvalidLength {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

/// A 32-byte account address: `SHA3-256(ML-DSA-87 public key)`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Address(pub [u8; 32]);

/// A 32-byte SHA3-256 digest.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Hash(pub [u8; 32]);

macro_rules! impl_hex32 {
    ($ty:ident, $label:literal) => {
        impl $ty {
            pub const ZERO: Self = Self([0u8; 32]);

            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub const fn to_array(self) -> [u8; 32] {
                self.0
            }

            pub fn is_zero(&self) -> bool {
                self.0 == [0u8; 32]
            }

            /// Hex form with a `0x` prefix.
            pub fn to_hex(&self) -> String {
                format!("0x{}", hex::encode(self.0))
            }

            /// Parse from hex, with or without the `0x` prefix.
            pub fn from_hex(s: &str) -> Result<Self, Error> {
                let bytes = decode_hex(s, 32)?;
                let mut out = [0u8; 32];
                out.copy_from_slice(&bytes);
                Ok(Self(out))
            }

            pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
                let arr: [u8; 32] = bytes.try_into().map_err(|_| Error::InvalidLength {
                    expected: 32,
                    actual: bytes.len(),
                })?;
                Ok(Self(arr))
            }

            /// Bit `index` of the 256-bit value, index 0 being the most
            /// significant bit. Used to walk the Sparse Merkle Tree.
            pub fn bit(&self, index: usize) -> bool {
                debug_assert!(index < 256);
                (self.0[index / 8] >> (7 - (index % 8))) & 1 == 1
            }

            /// Short form for logs: first four bytes.
            pub fn short(&self) -> String {
                format!("0x{}", hex::encode(&self.0[..4]))
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.to_hex())
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($label, "({})"), self.to_hex())
            }
        }

        impl FromStr for $ty {
            type Err = Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_hex(s)
            }
        }

        impl From<[u8; 32]> for $ty {
            fn from(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }
        }

        impl AsRef<[u8]> for $ty {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl Serialize for $ty {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::from_hex(&s).map_err(D::Error::custom)
            }
        }
    };
}

impl_hex32!(Address, "Address");
impl_hex32!(Hash, "Hash");

impl Address {
    /// Derive an address from serialised ML-DSA-87 public key bytes.
    pub fn from_public_key_bytes(public_key: &[u8]) -> Self {
        Self(sikka_crypto::derive_address_bytes(public_key))
    }
}

impl Hash {
    /// SHA3-256 over a domain tag and payload parts.
    pub fn digest(parts: &[&[u8]]) -> Self {
        Self(sikka_crypto::sha3_256_parts(parts))
    }
}

/// A large fixed-size byte blob (public keys and signatures), hex-encoded on the
/// wire.
///
/// ML-DSA-87 keys are 2592 bytes and signatures 4627 bytes, well past the
/// 32-element limit of `serde`'s array impls, hence the dedicated type.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Bytes<const N: usize>([u8; N]);

impl<const N: usize> Bytes<N> {
    pub const LEN: usize = N;

    pub const fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let arr: [u8; N] = bytes.try_into().map_err(|_| Error::InvalidLength {
            expected: N,
            actual: bytes.len(),
        })?;
        Ok(Self(arr))
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self, Error> {
        let bytes = decode_hex(s, N)?;
        Self::from_slice(&bytes)
    }
}

impl<const N: usize> Default for Bytes<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> fmt::Debug for Bytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Full hex would be thousands of characters; show a stable prefix.
        write!(f, "Bytes<{}>({}…)", N, hex::encode(&self.0[..8.min(N)]))
    }
}

impl<const N: usize> fmt::Display for Bytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl<const N: usize> FromStr for Bytes<N> {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl<const N: usize> From<[u8; N]> for Bytes<N> {
    fn from(bytes: [u8; N]) -> Self {
        Self(bytes)
    }
}

impl<const N: usize> AsRef<[u8]> for Bytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Serialize for Bytes<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de, const N: usize> Deserialize<'de> for Bytes<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(D::Error::custom)
    }
}

/// An ML-DSA-87 public key (2592 bytes).
pub type PublicKey = Bytes<PK_LEN>;
/// An ML-DSA-87 signature (4627 bytes).
pub type Signature = Bytes<SIG_LEN>;

impl PublicKey {
    /// The address this key controls.
    pub fn address(&self) -> Address {
        Address::from_public_key_bytes(self.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_hex_roundtrip() {
        let a = Address([0xab; 32]);
        let s = a.to_hex();
        assert!(s.starts_with("0x"));
        assert_eq!(s.len(), 66);
        assert_eq!(Address::from_hex(&s).unwrap(), a);
        assert_eq!(Address::from_hex(&s[2..]).unwrap(), a);
    }

    #[test]
    fn rejects_wrong_length_and_bad_chars() {
        assert!(Address::from_hex("0x1234").is_err());
        assert!(Address::from_hex("0xzz").is_err());
    }

    #[test]
    fn bits_are_big_endian() {
        let mut raw = [0u8; 32];
        raw[0] = 0b1000_0001;
        raw[31] = 0b0000_0001;
        let a = Address(raw);
        assert!(a.bit(0));
        assert!(!a.bit(1));
        assert!(a.bit(7));
        assert!(a.bit(255));
        assert!(!a.bit(254));
    }

    #[test]
    fn address_matches_sha3_of_public_key() {
        let pk = PublicKey::new([3u8; PK_LEN]);
        assert_eq!(
            pk.address(),
            Address(sikka_crypto::sha3_256(&[3u8; PK_LEN]))
        );
    }

    #[test]
    fn json_uses_hex_strings() {
        let a = Address([1u8; 32]);
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, format!("\"{}\"", a.to_hex()));
        assert_eq!(serde_json::from_str::<Address>(&json).unwrap(), a);

        let sig = Signature::new([7u8; SIG_LEN]);
        let json = serde_json::to_string(&sig).unwrap();
        assert_eq!(serde_json::from_str::<Signature>(&json).unwrap(), sig);
    }

    #[test]
    fn zero_helpers() {
        assert!(Address::ZERO.is_zero());
        assert!(!Address([1u8; 32]).is_zero());
    }
}
