//! Deterministic Tor v3 onion identity derived from a SIKKA key.
//!
//! Peer mesh traffic goes over Tor. The onion address is a stable function of
//! the node's ML-DSA secret (via SHA3-256 domain separation into an ed25519
//! seed), so reinstalling on a Pi with the same `SIKKA_PRIVATE_KEY` republishes
//! the same `.onion` without DNS.

use std::path::Path;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::Sha512;
use sha3::{Digest as Sha3Digest, Sha3_256};
use sikka_common::error::{Error, Result};
use sikka_crypto::Keypair;

/// Domain tag mixed into the KDF so Tor material is never the ML-DSA key.
pub const TOR_ONION_KDF_TAG: &[u8] = b"SIKKA/tor-onion/v1";

// Tor pads these tags to exactly 32 bytes with trailing NULs.
const HS_SECRET_PREFIX: &[u8] = b"== ed25519v1-secret: type0 ==\0\0\0";
const HS_PUBLIC_PREFIX: &[u8] = b"== ed25519v1-public: type0 ==\0\0\0";

/// Tor v3 onion identity for a SIKKA keypair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TorOnionId {
    /// 32-byte ed25519 seed (after KDF).
    pub seed: [u8; 32],
    /// 32-byte ed25519 public key.
    pub public_key: [u8; 32],
    /// 56-character `.onion` hostname without scheme.
    pub hostname: String,
}

impl TorOnionId {
    /// Derive a Tor v3 identity from a SIKKA keypair's secret bytes.
    pub fn from_keypair(keypair: &Keypair) -> Self {
        Self::from_secret_bytes(keypair.private_bytes())
    }

    /// KDF + ed25519 expand from arbitrary secret material (seed or full SK).
    pub fn from_secret_bytes(secret: &[u8]) -> Self {
        let seed = kdf_tor_seed(secret);
        let signing = SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key().to_bytes();
        let hostname = onion_hostname(&public_key);
        Self {
            seed,
            public_key,
            hostname,
        }
    }

    /// `http://<hostname>` — what peers should dial.
    pub fn advertise_url(&self) -> String {
        format!("http://{}", self.hostname)
    }

    /// Write Tor's `hs_ed25519_*` + `hostname` files into `dir` (HiddenServiceDir).
    pub fn write_hidden_service_dir(&self, dir: impl AsRef<Path>) -> Result<()> {
        let dir = dir.as_ref();
        std::fs::create_dir_all(dir).map_err(|e| {
            Error::Other(format!("cannot create Tor hidden service dir {}: {e}", dir.display()))
        })?;

        let expanded = expand_ed25519_secret(&self.seed);
        let mut secret_file = Vec::with_capacity(HS_SECRET_PREFIX.len() + 64);
        secret_file.extend_from_slice(HS_SECRET_PREFIX);
        secret_file.extend_from_slice(&expanded);

        let mut public_file = Vec::with_capacity(HS_PUBLIC_PREFIX.len() + 32);
        public_file.extend_from_slice(HS_PUBLIC_PREFIX);
        public_file.extend_from_slice(&self.public_key);

        write_file(dir.join("hs_ed25519_secret_key"), &secret_file, 0o600)?;
        write_file(dir.join("hs_ed25519_public_key"), &public_file, 0o644)?;
        write_file(
            dir.join("hostname"),
            format!("{}\n", self.hostname).as_bytes(),
            0o644,
        )?;

        // Tor also expects the verifying key object; public file is enough for
        // current Tor when secret is present.
        let _ = VerifyingKey::from_bytes(&self.public_key);
        Ok(())
    }
}

fn kdf_tor_seed(secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(TOR_ONION_KDF_TAG);
    hasher.update(secret);
    let digest = hasher.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&digest);
    seed
}

/// RFC 8032 expanded secret key (64 bytes) as Tor stores it.
fn expand_ed25519_secret(seed: &[u8; 32]) -> [u8; 64] {
    let mut h = Sha512::digest(seed);
    h[0] &= 248;
    h[31] &= 127;
    h[31] |= 64;
    let mut out = [0u8; 64];
    out.copy_from_slice(&h);
    out
}

fn onion_hostname(public_key: &[u8; 32]) -> String {
    let mut checksum_input = Vec::with_capacity(15 + 32 + 1);
    checksum_input.extend_from_slice(b".onion checksum");
    checksum_input.extend_from_slice(public_key);
    checksum_input.push(0x03);
    let checksum = Sha3_256::digest(&checksum_input);

    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(public_key);
    raw[32] = checksum[0];
    raw[33] = checksum[1];
    raw[34] = 0x03;

    let mut hostname = BASE32_NOPAD.encode(&raw);
    hostname.make_ascii_lowercase();
    format!("{hostname}.onion")
}

fn write_file(path: impl AsRef<Path>, bytes: &[u8], mode: u32) -> Result<()> {
    let path = path.as_ref();
    std::fs::write(path, bytes)
        .map_err(|e| Error::Other(format!("cannot write {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
    }
    let _ = mode;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_secret_yields_same_onion() {
        let kp = Keypair::from_seed(&[9u8; 32]).unwrap();
        let a = TorOnionId::from_keypair(&kp);
        let b = TorOnionId::from_keypair(&kp);
        assert_eq!(a.hostname, b.hostname);
        assert!(a.hostname.ends_with(".onion"));
        assert_eq!(a.hostname.len(), 56 + 6); // 56 base32 + ".onion"
    }

    #[test]
    fn different_secrets_yield_different_onions() {
        let a = TorOnionId::from_keypair(&Keypair::from_seed(&[1u8; 32]).unwrap());
        let b = TorOnionId::from_keypair(&Keypair::from_seed(&[2u8; 32]).unwrap());
        assert_ne!(a.hostname, b.hostname);
    }

    #[test]
    fn tor_key_prefixes_are_32_bytes() {
        assert_eq!(HS_SECRET_PREFIX.len(), 32);
        assert_eq!(HS_PUBLIC_PREFIX.len(), 32);
        assert_eq!(&HS_SECRET_PREFIX[29..], &[0, 0, 0]);
        assert_eq!(&HS_PUBLIC_PREFIX[29..], &[0, 0, 0]);
    }

    #[test]
    fn writes_hidden_service_dir() {
        let dir = tempfile::tempdir().unwrap();
        let id = TorOnionId::from_keypair(&Keypair::from_seed(&[3u8; 32]).unwrap());
        id.write_hidden_service_dir(dir.path()).unwrap();
        assert!(dir.path().join("hostname").exists());
        let secret = std::fs::read(dir.path().join("hs_ed25519_secret_key")).unwrap();
        let public = std::fs::read(dir.path().join("hs_ed25519_public_key")).unwrap();
        // Tor's on-disk format: 32-byte tag + 64-byte expanded secret / 32-byte pubkey.
        assert_eq!(secret.len(), 96);
        assert_eq!(public.len(), 64);
        assert_eq!(&secret[..32], HS_SECRET_PREFIX);
        assert_eq!(&public[..32], HS_PUBLIC_PREFIX);
        let hostname = std::fs::read_to_string(dir.path().join("hostname")).unwrap();
        assert_eq!(hostname.trim(), id.hostname);
    }
}
