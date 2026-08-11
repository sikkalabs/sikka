//! Deterministic Tor v3 onion addresses for the SIKKA peer mesh.
//!
//! Consensus identity stays ML-DSA-87. Tor gets a companion ed25519 key derived
//! from the node's ML-DSA secret so the same validator key always yields the
//! same `.onion` hostname. This material is transport-only — never used for
//! transactions, votes, or peer announcement signatures.

use std::fs;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};
use sha3::Sha3_256;
use sikka_crypto::Keypair;

type HmacSha3_256 = Hmac<Sha3_256>;

/// Domain tag mixed into the IKM before HKDF.
pub const ONION_IKM_TAG: &[u8] = b"SIKKA/tor-onion-v3/ikm/v1";

/// HKDF info string for the ed25519 seed.
pub const ONION_HKDF_INFO: &[u8] = b"SIKKA/tor-onion-v3/v1";

/// C Tor / Arti ctor secret-key file header (NUL-terminated).
pub const HS_SECRET_HEADER: &[u8] = b"== ed25519v1-secret: type0 ==\0";

/// C Tor / Arti ctor public-key file header (NUL-terminated).
pub const HS_PUBLIC_HEADER: &[u8] = b"== ed25519v1-public: type0 ==\0";

#[derive(Debug, thiserror::Error)]
pub enum OnionError {
    #[error("onion key derivation failed: {0}")]
    Derive(String),
    #[error("cannot write onion key material: {0}")]
    Io(#[from] std::io::Error),
}

/// Tor v3 onion identity derived from a SIKKA ML-DSA keypair.
#[derive(Debug, Clone)]
pub struct OnionIdentity {
    /// 32-byte ed25519 seed (RFC 8032).
    pub seed: [u8; 32],
    /// 64-byte expanded secret (SHA-512(seed) with clamping) for Tor key files.
    pub expanded_secret: [u8; 64],
    /// 32-byte ed25519 public key.
    pub public_key: [u8; 32],
    /// `<56chars>.onion` hostname (no scheme, no port).
    pub hostname: String,
}

impl OnionIdentity {
    /// Derive the companion Tor identity from an ML-DSA node keypair.
    pub fn from_keypair(keypair: &Keypair) -> Result<Self, OnionError> {
        let ikm = onion_ikm(keypair.private_bytes());
        let seed = hkdf_sha3_256(&ikm, ONION_HKDF_INFO)?;
        Self::from_ed25519_seed(seed)
    }

    /// Derive from a raw 32-byte ed25519 seed (tests / offline tooling).
    pub fn from_ed25519_seed(seed: [u8; 32]) -> Result<Self, OnionError> {
        let expanded_secret = expand_ed25519_secret(&seed);
        let signing = SigningKey::from_bytes(&seed);
        let verifying: VerifyingKey = signing.verifying_key();
        let public_key = verifying.to_bytes();
        let hostname = onion_v3_hostname(&public_key);
        Ok(Self {
            seed,
            expanded_secret,
            public_key,
            hostname,
        })
    }

    /// Advertise URL peers should dial (`http://<hostname>` — Tor HS has no port in the name).
    pub fn advertise_url(&self) -> String {
        format!("http://{}", self.hostname)
    }

    /// Write a C Tor–compatible HiddenServiceDir (also readable via Arti ctor keystore).
    ///
    /// Layout:
    /// ```text
    /// <dir>/hs_ed25519_secret_key
    /// <dir>/hs_ed25519_public_key
    /// <dir>/hostname
    /// ```
    pub fn write_ctor_dir(&self, dir: impl AsRef<Path>) -> Result<(), OnionError> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }

        let mut secret = Vec::with_capacity(HS_SECRET_HEADER.len() + 64);
        secret.extend_from_slice(HS_SECRET_HEADER);
        secret.extend_from_slice(&self.expanded_secret);
        write_exclusive(dir.join("hs_ed25519_secret_key"), &secret)?;

        let mut public = Vec::with_capacity(HS_PUBLIC_HEADER.len() + 32);
        public.extend_from_slice(HS_PUBLIC_HEADER);
        public.extend_from_slice(&self.public_key);
        write_exclusive(dir.join("hs_ed25519_public_key"), &public)?;

        let mut hostname = self.hostname.clone();
        hostname.push('\n');
        write_exclusive(dir.join("hostname"), hostname.as_bytes())?;

        // Empty authorized_clients dir keeps tor/arti happy if they expect it.
        let clients = dir.join("authorized_clients");
        fs::create_dir_all(&clients)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&clients, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
}

/// IKM: domain-tagged SHA3-256 of the ML-DSA secret (same for seed-expanded and loaded keys).
pub fn onion_ikm(private_bytes: &[u8]) -> [u8; 32] {
    sikka_crypto::sha3_256_parts(&[ONION_IKM_TAG, private_bytes])
}

fn hkdf_sha3_256(ikm: &[u8; 32], info: &[u8]) -> Result<[u8; 32], OnionError> {
    // HKDF-Extract with empty salt → HMAC(zeros, ikm)
    let mut extract = HmacSha3_256::new_from_slice(&[0u8; 32])
        .map_err(|e| OnionError::Derive(e.to_string()))?;
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    // HKDF-Expand for one block (L=32 ≤ HashLen)
    let mut expand = HmacSha3_256::new_from_slice(&prk)
        .map_err(|e| OnionError::Derive(e.to_string()))?;
    expand.update(info);
    expand.update(&[0x01]);
    let okm = expand.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&okm);
    Ok(out)
}

fn expand_ed25519_secret(seed: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha512::digest(seed);
    h[0] &= 248;
    h[31] &= 63;
    h[31] |= 64;
    h.into()
}

/// Tor v3 address: base32(pubkey \|\| checksum\|\| version) + ".onion"
fn onion_v3_hostname(pubkey: &[u8; 32]) -> String {
    let version = [0x03u8];
    let checksum = {
        let mut hasher = Sha3_256::new();
        hasher.update(b".onion checksum");
        hasher.update(pubkey);
        hasher.update(version);
        let dig = hasher.finalize();
        [dig[0], dig[1]]
    };
    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(pubkey);
    raw[32..34].copy_from_slice(&checksum);
    raw[34] = 0x03;
    format!("{}.onion", base32_nopad_lower(&raw))
}

fn base32_nopad_lower(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHABET[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

fn write_exclusive(path: impl AsRef<Path>, bytes: &[u8]) -> Result<(), OnionError> {
    let path = path.as_ref();
    let mut file = fs::File::create(path)?;
    file.write_all(bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_keypair_same_onion() {
        let seed = [9u8; 32];
        let kp = Keypair::from_seed(&seed).unwrap();
        let a = OnionIdentity::from_keypair(&kp).unwrap();
        let b = OnionIdentity::from_keypair(&kp).unwrap();
        assert_eq!(a.hostname, b.hostname);
        assert!(a.hostname.ends_with(".onion"));
        assert_eq!(a.hostname.len(), 56 + ".onion".len());
        assert_eq!(a.advertise_url(), format!("http://{}", a.hostname));
    }

    #[test]
    fn seed_and_expanded_secret_agree() {
        let seed = [3u8; 32];
        let from_seed = Keypair::from_seed(&seed).unwrap();
        let from_sk = Keypair::from_private_bytes(from_seed.private_bytes()).unwrap();
        let onion_a = OnionIdentity::from_keypair(&from_seed).unwrap();
        let onion_b = OnionIdentity::from_keypair(&from_sk).unwrap();
        assert_eq!(onion_a.hostname, onion_b.hostname);
    }

    #[test]
    fn hostname_length_and_suffix() {
        let onion = OnionIdentity::from_ed25519_seed([0x11; 32]).unwrap();
        assert!(onion.hostname.ends_with(".onion"));
        assert_eq!(onion.hostname.len(), 62); // 56 base32 + ".onion"
        assert!(onion
            .hostname
            .chars()
            .take(56)
            .all(|c| matches!(c, 'a'..='z' | '2'..='7')));
    }

    #[test]
    fn ctor_dir_roundtrip_files() {
        let dir = tempfile::tempdir().unwrap();
        let kp = Keypair::from_seed(&[7u8; 32]).unwrap();
        let onion = OnionIdentity::from_keypair(&kp).unwrap();
        onion.write_ctor_dir(dir.path()).unwrap();

        let secret = fs::read(dir.path().join("hs_ed25519_secret_key")).unwrap();
        assert!(secret.starts_with(HS_SECRET_HEADER));
        assert_eq!(secret.len(), HS_SECRET_HEADER.len() + 64);

        let public = fs::read(dir.path().join("hs_ed25519_public_key")).unwrap();
        assert!(public.starts_with(HS_PUBLIC_HEADER));
        assert_eq!(&public[HS_PUBLIC_HEADER.len()..], &onion.public_key);

        let hostname = fs::read_to_string(dir.path().join("hostname")).unwrap();
        assert_eq!(hostname.trim(), onion.hostname);
    }

    #[test]
    fn validator_env_seeds_produce_distinct_onions() {
        let v1 = hex::decode("8a553524df98f2f3cbf23fed86699b342ed7f428b27e1e1e88b9eefb910bf908").unwrap();
        let v2 = hex::decode("f8e5718302a0b32a3159c7a00a6a481c081d8f206081804dd3db7ad07e306f99").unwrap();
        let s1: [u8; 32] = v1.try_into().unwrap();
        let s2: [u8; 32] = v2.try_into().unwrap();
        let o1 = OnionIdentity::from_keypair(&Keypair::from_seed(&s1).unwrap()).unwrap();
        let o2 = OnionIdentity::from_keypair(&Keypair::from_seed(&s2).unwrap()).unwrap();
        assert_ne!(o1.hostname, o2.hostname);
        eprintln!("validator1 onion: {}", o1.advertise_url());
        eprintln!("validator2 onion: {}", o2.advertise_url());
    }
}
