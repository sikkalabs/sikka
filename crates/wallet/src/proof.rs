//! State proof verification.
//!
//! This is the piece that makes a wallet trustless. A node answers "what is my
//! balance" with the account, a Merkle path, and the checkpoint whose state root
//! that path leads to. The wallet then checks:
//!
//! 1. the checkpoint carries signatures from ≥2/3 of the validators it knows;
//! 2. the Merkle path really produces that checkpoint's state root;
//! 3. the account in the path is the one it was handed.
//!
//! A lying node cannot pass all three, so a wallet never has to trust the node
//! it happens to be talking to.
//!
//! Verification fails closed: the caller must supply the trusted validator set
//! (normally read from the genesis file it pinned out-of-band). An empty set is
//! an error, never a silent skip — otherwise a handpicked "validator" list or a
//! forged quorum would pass without any real check.

use sikka_common::account::Account;
use sikka_common::bytes::{Address, Hash, PublicKey};
use sikka_common::checkpoint::Checkpoint;
use sikka_common::error::{Error, Result};
use sikka_rpc::types::AccountProof;

/// A balance that has been checked against a signed checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBalance {
    pub address: Address,
    /// `None` means the address provably holds nothing.
    pub account: Option<Account>,
    pub height: u64,
    pub state_root: Hash,
    /// How many validators signed the checkpoint the proof was checked against.
    pub signatures: usize,
}

impl VerifiedBalance {
    pub fn balance(&self) -> u64 {
        self.account.map(|a| a.balance).unwrap_or(0)
    }

    pub fn nonce(&self) -> u64 {
        self.account.map(|a| a.nonce).unwrap_or(0)
    }
}

/// Verify an account proof.
///
/// `validators` is the set the wallet trusts — the genesis validator set that
/// was pinned out-of-band, as `(address, public_key, bond)`. It must be
/// non-empty: with nobody to trust there is nothing to verify, so the call
/// fails closed rather than reporting a passed check. Never pass a validator
/// list obtained from the node answering the query itself — a malicious node
/// can fabricate keys, bonds and signatures together.
pub fn verify_account_proof(
    proof: &AccountProof,
    validators: &[(Address, PublicKey, u64)],
) -> Result<VerifiedBalance> {
    let checkpoint: &Checkpoint = &proof.checkpoint;

    if proof.state_root != checkpoint.header.state_root {
        return Err(Error::StateRootMismatch {
            expected: checkpoint.header.state_root,
            computed: proof.state_root,
        });
    }

    if validators.is_empty() {
        return Err(Error::QuorumNotReached { got: 0, needed: 1 });
    }
    let refs: Vec<(&Address, &PublicKey, u64)> =
        validators.iter().map(|(a, k, b)| (a, k, *b)).collect();
    let signatures = checkpoint.verify_signatures(refs)?;

    let key = proof.address.to_array();
    let verified = match &proof.account {
        Some(account) => {
            let leaf = account.leaf_hash(&proof.address);
            proof.proof.verify(&proof.state_root, &key, &leaf)
        }
        None => proof.proof.verify_absent(&proof.state_root, &key),
    };
    if !verified {
        return Err(Error::InvalidProof);
    }

    Ok(VerifiedBalance {
        address: proof.address,
        account: proof.account,
        height: checkpoint.header.height,
        state_root: proof.state_root,
        signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sikka_common::checkpoint::CheckpointHeader;
    use sikka_common::vote::{Vote, VoteKind};
    use sikka_crypto::Keypair;
    use sikka_state::smt::Smt;

    struct Fixture {
        proof: AccountProof,
        validators: Vec<(Address, PublicKey, u64)>,
        account: Account,
        address: Address,
    }

    /// A two-account tree, a checkpoint over it, and signatures from three of
    /// four validators.
    fn fixture() -> Fixture {
        let address = Address([0xaau8; 32]);
        let other = Address([0xbbu8; 32]);
        let account = Account {
            balance: 5_000,
            nonce: 2,
            battery: 40,
            last_regen_time: 1_000,
        };
        let other_account = Account {
            balance: 1,
            nonce: 0,
            battery: 0,
            last_regen_time: 1_000,
        };

        let mut smt = Smt::new();
        smt.insert(address.to_array(), account.leaf_hash(&address));
        smt.insert(other.to_array(), other_account.leaf_hash(&other));
        let state_root = smt.root();

        let keys: Vec<Keypair> = (0..4).map(|_| Keypair::generate().unwrap()).collect();
        let validators: Vec<(Address, PublicKey, u64)> = keys
            .iter()
            .map(|k| {
                let pk = PublicKey::new(*k.public_bytes());
                (pk.address(), pk, 1)
            })
            .collect();

        let header = CheckpointHeader {
            height: 42,
            prev_hash: Hash([1u8; 32]),
            state_root,
            validator_root: Hash([2u8; 32]),
            tx_root: Hash([3u8; 32]),
            tx_count: 10_000,
            timestamp: 1_700_000_000,
            proposer: validators[0].0,
            round: 0,
            total_supply: 5_001,
            total_bonded: 0,
            chain_id: "sikka-test".into(),
            genesis_fingerprint: Hash([0xAA; 32]),
        };
        let mut checkpoint = Checkpoint::new(header);
        let hash = checkpoint.hash();
        for key in keys.iter().take(3) {
            checkpoint.add_signature(Vote::sign(key, &checkpoint.header.chain_id, checkpoint.header.genesis_fingerprint, 42, 0, VoteKind::Precommit, hash).unwrap().into_signature());
        }
        checkpoint.canonicalize();

        Fixture {
            proof: AccountProof {
                address,
                account: Some(account),
                proof: smt.proof(&address.to_array()),
                state_root,
                checkpoint,
            },
            validators,
            account,
            address,
        }
    }

    #[test]
    fn a_valid_proof_verifies() {
        let f = fixture();
        let verified = verify_account_proof(&f.proof, &f.validators).unwrap();
        assert_eq!(verified.balance(), 5_000);
        assert_eq!(verified.nonce(), 2);
        assert_eq!(verified.height, 42);
        assert_eq!(verified.signatures, 3);
        assert_eq!(verified.account, Some(f.account));
    }

    #[test]
    fn a_lied_about_balance_is_caught() {
        let mut f = fixture();
        f.proof.account = Some(Account {
            balance: 999_999,
            nonce: 2,
            battery: 40,
            last_regen_time: 1_000,
        });
        assert_eq!(
            verify_account_proof(&f.proof, &f.validators).unwrap_err(),
            Error::InvalidProof
        );
    }

    #[test]
    fn a_proof_for_another_account_is_caught() {
        let mut f = fixture();
        f.proof.address = Address([0xccu8; 32]);
        assert_eq!(
            verify_account_proof(&f.proof, &f.validators).unwrap_err(),
            Error::InvalidProof
        );
    }

    #[test]
    fn a_state_root_that_the_checkpoint_does_not_commit_to_is_caught() {
        let mut f = fixture();
        f.proof.state_root = Hash([0x99u8; 32]);
        assert!(matches!(
            verify_account_proof(&f.proof, &f.validators),
            Err(Error::StateRootMismatch { .. })
        ));
    }

    #[test]
    fn a_checkpoint_short_of_quorum_is_rejected() {
        let mut f = fixture();
        f.proof.checkpoint.validator_signatures.truncate(2);
        assert!(matches!(
            verify_account_proof(&f.proof, &f.validators),
            Err(Error::QuorumNotReached { got: 2, needed: 3 })
        ));
    }

    #[test]
    fn signatures_from_unknown_validators_are_rejected() {
        let f = fixture();
        let strangers: Vec<(Address, PublicKey, u64)> = (0..4)
            .map(|_| {
                let pk = PublicKey::new(*Keypair::generate().unwrap().public_bytes());
                (pk.address(), pk, 1)
            })
            .collect();
        assert!(matches!(
            verify_account_proof(&f.proof, &strangers),
            Err(Error::UnknownVoter(_))
        ));
    }

    #[test]
    fn absence_is_provable() {
        let f = fixture();
        let missing = Address([0x11u8; 32]);

        let mut smt = Smt::new();
        smt.insert(f.address.to_array(), f.account.leaf_hash(&f.address));
        let other = Address([0xbbu8; 32]);
        let other_account = Account {
            balance: 1,
            nonce: 0,
            battery: 0,
            last_regen_time: 1_000,
        };
        smt.insert(other.to_array(), other_account.leaf_hash(&other));

        let proof = AccountProof {
            address: missing,
            account: None,
            proof: smt.proof(&missing.to_array()),
            state_root: smt.root(),
            checkpoint: f.proof.checkpoint.clone(),
        };
        let verified = verify_account_proof(&proof, &f.validators).unwrap();
        assert_eq!(verified.balance(), 0);
        assert!(verified.account.is_none());

        // Claiming a balance for a proof of absence must fail.
        let mut lying = proof;
        lying.account = Some(Account {
            balance: 1,
            nonce: 0,
            battery: 0,
            last_regen_time: 0,
        });
        assert_eq!(
            verify_account_proof(&lying, &f.validators).unwrap_err(),
            Error::InvalidProof
        );
    }

    #[test]
    fn an_empty_validator_set_fails_closed() {
        let f = fixture();
        // Even a valid proof with no trusted anchor must be rejected, not
        // reported as verified.
        assert!(matches!(
            verify_account_proof(&f.proof, &[]),
            Err(Error::QuorumNotReached { got: 0, needed: 1 })
        ));
    }
}
