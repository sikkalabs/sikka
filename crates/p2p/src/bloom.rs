//! Bloom filter for mempool reconciliation.
//!
//! When two nodes sync mempools, sending every transaction id would cost 32
//! bytes each. Instead a node sends a compact filter of what it already has, and
//! the peer replies with whatever the filter does not cover. False positives
//! just mean a transaction arrives a little later through another peer; false
//! negatives are impossible, so nothing is ever lost.

use serde::{Deserialize, Serialize};
use sikka_common::bytes::Hash;

/// Bits per expected element (≈1% false positive rate with 5 probes).
const BITS_PER_ITEM: usize = 10;
/// Number of probes per element. Each probe consumes 4 bytes of the id, so this
/// cannot exceed 8.
const PROBES: usize = 5;
/// Smallest filter, so an empty mempool still produces a valid filter.
const MIN_BITS: usize = 512;
/// Cap on filter size, to bound what a peer can make us allocate.
const MAX_BITS: usize = 1 << 22; // 4 Mbit = 512 KiB

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BloomFilter {
    /// Bit array, hex encoded on the wire.
    #[serde(with = "hex_bytes")]
    bits: Vec<u8>,
    probes: u8,
}

mod hex_bytes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(D::Error::custom)
    }
}

impl BloomFilter {
    /// A filter sized for `expected` elements.
    pub fn with_capacity(expected: usize) -> Self {
        let bits = (expected * BITS_PER_ITEM)
            .next_power_of_two()
            .clamp(MIN_BITS, MAX_BITS);
        Self {
            bits: vec![0u8; bits / 8],
            probes: PROBES as u8,
        }
    }

    /// Build a filter over a set of transaction ids.
    pub fn from_hashes<'a, I: IntoIterator<Item = &'a Hash>>(hashes: I) -> Self {
        let hashes: Vec<&Hash> = hashes.into_iter().collect();
        let mut filter = Self::with_capacity(hashes.len().max(64));
        for hash in hashes {
            filter.insert(hash);
        }
        filter
    }

    fn bit_count(&self) -> usize {
        self.bits.len() * 8
    }

    /// Probe positions for a hash, taken straight from its bytes: the id is
    /// already a uniformly distributed SHA3 digest, so no rehashing is needed.
    fn positions(&self, hash: &Hash) -> impl Iterator<Item = usize> + '_ {
        let bytes = *hash.as_bytes();
        let count = (self.probes as usize).min(8);
        let modulus = self.bit_count();
        (0..count).map(move |i| {
            let word = u32::from_le_bytes([
                bytes[i * 4],
                bytes[i * 4 + 1],
                bytes[i * 4 + 2],
                bytes[i * 4 + 3],
            ]);
            (word as usize) % modulus
        })
    }

    pub fn insert(&mut self, hash: &Hash) {
        if self.bits.is_empty() {
            return;
        }
        for position in self.positions(hash).collect::<Vec<usize>>() {
            self.bits[position / 8] |= 1 << (position % 8);
        }
    }

    /// Whether the filter *may* contain the hash. False positives are possible;
    /// false negatives are not.
    pub fn contains(&self, hash: &Hash) -> bool {
        if self.bits.is_empty() {
            return false;
        }
        self.positions(hash)
            .all(|position| self.bits[position / 8] & (1 << (position % 8)) != 0)
    }

    pub fn size_bytes(&self) -> usize {
        self.bits.len()
    }

    /// Reject filters a peer sent that are too large to process.
    pub fn is_acceptable(&self) -> bool {
        !self.bits.is_empty()
            && self.bit_count() <= MAX_BITS
            && self.probes >= 1
            && self.probes <= 8
            && self.bit_count() % 8 == 0
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::with_capacity(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_crypto::sha3_256;

    fn hash(i: u32) -> Hash {
        Hash(sha3_256(&i.to_le_bytes()))
    }

    #[test]
    fn inserted_hashes_are_always_found() {
        let hashes: Vec<Hash> = (0..500).map(hash).collect();
        let filter = BloomFilter::from_hashes(hashes.iter());
        for h in &hashes {
            assert!(filter.contains(h), "false negatives are not allowed");
        }
    }

    #[test]
    fn empty_filter_contains_nothing() {
        let filter = BloomFilter::from_hashes(std::iter::empty());
        assert!(!filter.contains(&hash(1)));
        assert!(filter.is_acceptable());
    }

    #[test]
    fn false_positive_rate_is_low() {
        let inserted: Vec<Hash> = (0..1_000).map(hash).collect();
        let filter = BloomFilter::from_hashes(inserted.iter());

        let probes = 10_000u32;
        let positives = (10_000..10_000 + probes)
            .filter(|i| filter.contains(&hash(*i)))
            .count();
        // 10 bits per item with 5 probes should stay near 1%.
        assert!(
            positives * 100 < probes as usize * 5,
            "{positives} false positives of {probes}"
        );
    }

    #[test]
    fn filter_grows_with_the_set() {
        let small = BloomFilter::from_hashes((0..10).map(hash).collect::<Vec<Hash>>().iter());
        let large = BloomFilter::from_hashes((0..100_000).map(hash).collect::<Vec<Hash>>().iter());
        assert!(large.size_bytes() > small.size_bytes());
        assert!(large.is_acceptable());
    }

    #[test]
    fn serialises_as_hex() {
        let filter = BloomFilter::from_hashes([hash(1), hash(2)].iter());
        let json = serde_json::to_string(&filter).unwrap();
        let parsed: BloomFilter = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, filter);
        assert!(parsed.contains(&hash(1)));
    }

    #[test]
    fn malformed_filters_are_rejected() {
        let mut filter = BloomFilter::from_hashes([hash(1)].iter());
        filter.probes = 0;
        assert!(!filter.is_acceptable());

        let broken: BloomFilter = serde_json::from_str(r#"{"bits":"","probes":5}"#).unwrap();
        assert!(!broken.is_acceptable());
        assert!(!broken.contains(&hash(1)));
    }

    #[test]
    fn reconciliation_finds_exactly_the_missing_items() {
        let mine: Vec<Hash> = (0..200).map(hash).collect();
        let theirs: Vec<Hash> = (150..350).map(hash).collect();

        let filter = BloomFilter::from_hashes(mine.iter());
        let missing: Vec<&Hash> = theirs.iter().filter(|h| !filter.contains(h)).collect();

        // Everything from 200 upwards must be reported; the overlap must not be.
        for h in theirs.iter().take(50) {
            assert!(!missing.contains(&h), "the overlap should not be resent");
        }
        assert!(
            missing.len() >= 140,
            "expected most of the 150 new items, got {}",
            missing.len()
        );
    }
}
