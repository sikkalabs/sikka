//! SHA3-256 hashing.

use sha3::{Digest, Sha3_256};

/// Hash a single byte slice with SHA3-256.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash the concatenation of several slices without allocating an intermediate
/// buffer. Used everywhere a domain prefix precedes the payload.
pub fn sha3_256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Incremental SHA3-256 hasher for streaming larger structures.
#[derive(Default, Clone)]
pub struct Hasher {
    inner: Sha3_256,
}

impl Hasher {
    pub fn new() -> Self {
        Self {
            inner: Sha3_256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.inner.update(data);
        self
    }

    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_nist_empty_vector() {
        // SHA3-256("") from the NIST test vectors.
        assert_eq!(
            hex::encode(sha3_256(b"")),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn matches_nist_abc_vector() {
        assert_eq!(
            hex::encode(sha3_256(b"abc")),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn parts_equal_concatenation() {
        assert_eq!(sha3_256_parts(&[b"ab", b"c"]), sha3_256(b"abc"));
    }

    #[test]
    fn streaming_equals_oneshot() {
        let mut h = Hasher::new();
        h.update(b"ab").update(b"c");
        assert_eq!(h.finalize(), sha3_256(b"abc"));
    }
}
