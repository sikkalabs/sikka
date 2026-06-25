//! On-disk key storage.
//!
//! A keystore is a small JSON file holding one ML-DSA-87 private key. It is
//! written with `0600` permissions and is not encrypted: node validator keys have
//! to be readable unattended at startup, and pretending otherwise by shipping a
//! passphrase in an environment variable would be security theatre. Protect the
//! file with the filesystem, or a mounted secret.

use std::path::Path;

use serde::{Deserialize, Serialize};

use sikka_common::bytes::{Address, PublicKey};
use sikka_common::error::{Error, Result};
use sikka_crypto::{Keypair, SK_LEN};

/// Serialised keypair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keystore {
    /// Present for readability; always re-derived from the key on load.
    pub address: Address,
    pub public_key: PublicKey,
    /// Hex-encoded ML-DSA-87 private key.
    pub private_key: String,
    #[serde(default = "default_scheme")]
    pub scheme: String,
}

fn default_scheme() -> String {
    "ML-DSA-87".to_string()
}

impl Keystore {
    pub fn from_keypair(keypair: &Keypair) -> Self {
        Self {
            address: Address(keypair.address_bytes()),
            public_key: PublicKey::new(*keypair.public_bytes()),
            private_key: hex::encode(keypair.private_bytes()),
            scheme: default_scheme(),
        }
    }

    /// Generate and immediately persist a new key.
    pub fn create(path: impl AsRef<Path>) -> Result<Self> {
        let keystore = Self::from_keypair(&Keypair::generate()?);
        keystore.save(path)?;
        Ok(keystore)
    }

    /// Load a key, or create one if the file does not exist.
    ///
    /// This is what a node does on first boot: no manual key ceremony needed to
    /// stand up a peer.
    pub fn load_or_create(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            Self::load(path)
        } else {
            Self::create(path)
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let json = std::fs::read_to_string(path)
            .map_err(|e| Error::Other(format!("cannot read keystore {}: {e}", path.display())))?;
        let keystore: Self = serde_json::from_str(&json)?;
        keystore.validate()?;
        Ok(keystore)
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::Other(format!("cannot create {}: {e}", parent.display()))
                })?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)
            .map_err(|e| Error::Other(format!("cannot write keystore {}: {e}", path.display())))?;
        Self::restrict_permissions(path)?;
        Ok(())
    }

    #[cfg(unix)]
    fn restrict_permissions(path: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| Error::Other(format!("cannot secure {}: {e}", path.display())))
    }

    #[cfg(not(unix))]
    fn restrict_permissions(_path: &Path) -> Result<()> {
        Ok(())
    }

    /// Check the file's contents are internally consistent.
    pub fn validate(&self) -> Result<()> {
        if self.scheme != default_scheme() {
            return Err(Error::Other(format!(
                "unsupported signature scheme '{}'; SIKKA uses ML-DSA-87",
                self.scheme
            )));
        }
        let bytes = hex::decode(&self.private_key).map_err(|_| Error::InvalidHex)?;
        if bytes.len() != SK_LEN {
            return Err(Error::InvalidLength {
                expected: SK_LEN,
                actual: bytes.len(),
            });
        }
        let keypair = Keypair::from_private_bytes(&bytes)?;
        if keypair.public_bytes() != self.public_key.as_bytes() {
            return Err(Error::Other(
                "keystore public key does not match its private key".into(),
            ));
        }
        if Address(keypair.address_bytes()) != self.address {
            return Err(Error::AddressKeyMismatch);
        }
        Ok(())
    }

    pub fn keypair(&self) -> Result<Keypair> {
        let bytes = hex::decode(&self.private_key).map_err(|_| Error::InvalidHex)?;
        Ok(Keypair::from_private_bytes(&bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys").join("validator.json");

        let created = Keystore::create(&path).unwrap();
        let loaded = Keystore::load(&path).unwrap();
        assert_eq!(created, loaded);
        assert_eq!(loaded.scheme, "ML-DSA-87");
        assert_eq!(
            loaded.address,
            Address(loaded.keypair().unwrap().address_bytes())
        );
    }

    #[test]
    fn load_or_create_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        let first = Keystore::load_or_create(&path).unwrap();
        let second = Keystore::load_or_create(&path).unwrap();
        assert_eq!(first, second, "an existing key must not be replaced");
    }

    #[cfg(unix)]
    #[test]
    fn keystore_is_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        Keystore::create(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn inconsistent_keystores_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("node.json");
        let mut keystore = Keystore::create(&path).unwrap();

        let other = Keystore::from_keypair(&Keypair::generate().unwrap());
        keystore.address = other.address;
        assert!(keystore.validate().is_err());

        let mut keystore = Keystore::load(&path).unwrap();
        keystore.public_key = other.public_key.clone();
        assert!(keystore.validate().is_err());

        let mut keystore = Keystore::load(&path).unwrap();
        keystore.private_key = "not hex".into();
        assert_eq!(keystore.validate().unwrap_err(), Error::InvalidHex);

        let mut keystore = Keystore::load(&path).unwrap();
        keystore.private_key = hex::encode([0u8; 16]);
        assert!(matches!(
            keystore.validate(),
            Err(Error::InvalidLength { .. })
        ));

        let mut keystore = Keystore::load(&path).unwrap();
        keystore.scheme = "Ed25519".into();
        assert!(keystore.validate().is_err());
    }

    #[test]
    fn a_missing_file_is_a_clear_error() {
        let error = Keystore::load("/nonexistent/path/keys.json").unwrap_err();
        assert!(format!("{error}").contains("cannot read keystore"));
    }
}
