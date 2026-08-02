//! Stateless wallet.
//!
//! The wallet stores a key and nothing else. It holds no chain data, no
//! transaction history and no cache: it asks a node for a balance and, crucially,
//! can *check the answer* by verifying a Merkle proof against a checkpoint signed
//! by a super-majority of validators. That is what makes it safe to point a
//! wallet at somebody else's node.

pub mod keystore;
pub mod proof;

pub use keystore::Keystore;
pub use proof::{verify_account_proof, VerifiedBalance};

use sikka_common::bytes::Address;
use sikka_common::error::Result;
use sikka_common::transaction::{Transaction, TxKind};

/// A key plus the ability to sign transactions with it.
pub struct Wallet {
    keypair: sikka_crypto::Keypair,
    address: Address,
}

impl Wallet {
    pub fn new(keypair: sikka_crypto::Keypair) -> Self {
        let address = Address(keypair.address_bytes());
        Self { keypair, address }
    }

    /// Generate a fresh key.
    pub fn generate() -> Result<Self> {
        Ok(Self::new(sikka_crypto::Keypair::generate()?))
    }

    pub fn from_keystore(keystore: &Keystore) -> Result<Self> {
        Ok(Self::new(keystore.keypair()?))
    }

    pub fn address(&self) -> Address {
        self.address
    }

    pub fn keypair(&self) -> &sikka_crypto::Keypair {
        &self.keypair
    }

    pub fn to_keystore(&self) -> Keystore {
        Keystore::from_keypair(&self.keypair)
    }

    /// Sign a transfer.
    ///
    /// `timestamp` is signed and becomes the battery-regeneration clock for the
    /// sending account, so it must be the wallet's honest view of now: a node
    /// rejects anything more than five minutes from its own clock.
    ///
    /// `chain_id` binds the signature to one chain so the same key cannot reuse
    /// a payment across forks.
    pub fn transfer(
        &self,
        to: Address,
        amount: u64,
        nonce: u64,
        timestamp: u64,
        chain_id: &str,
    ) -> Result<Transaction> {
        Transaction::sign(
            &self.keypair,
            TxKind::Transfer,
            to,
            amount,
            nonce,
            timestamp,
            chain_id,
        )
    }

    pub fn bond(
        &self,
        amount: u64,
        nonce: u64,
        timestamp: u64,
        chain_id: &str,
    ) -> Result<Transaction> {
        Transaction::bond(&self.keypair, amount, nonce, timestamp, chain_id)
    }

    pub fn unbond(
        &self,
        nonce: u64,
        timestamp: u64,
        chain_id: &str,
    ) -> Result<Transaction> {
        Transaction::unbond(&self.keypair, nonce, timestamp, chain_id)
    }
}

impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("address", &self.address)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signs_transactions_it_can_verify() {
        let wallet = Wallet::generate().unwrap();
        let to = Address([9u8; 32]);
        let chain_id = "sikka-test";

        let transfer = wallet.transfer(to, 100, 0, 1_700_000_000, chain_id).unwrap();
        assert_eq!(transfer.from, wallet.address());
        transfer.verify_signature().unwrap();

        let bond = wallet.bond(1_000, 1, 1_700_000_000, chain_id).unwrap();
        assert_eq!(bond.kind, TxKind::Bond);
        bond.verify_signature().unwrap();

        let unbond = wallet.unbond(2, 1_700_000_000, chain_id).unwrap();
        assert_eq!(unbond.kind, TxKind::Unbond);
        assert_eq!(unbond.amount, 0);
        unbond.verify_signature().unwrap();
    }

    #[test]
    fn address_is_derived_from_the_key() {
        let wallet = Wallet::generate().unwrap();
        assert_eq!(
            wallet.address(),
            Address(sikka_crypto::sha3_256(wallet.keypair().public_bytes()))
        );
    }

    #[test]
    fn survives_a_keystore_roundtrip() {
        let wallet = Wallet::generate().unwrap();
        let restored = Wallet::from_keystore(&wallet.to_keystore()).unwrap();
        assert_eq!(restored.address(), wallet.address());
    }
}
