//! State proofs for light client verification.
//!
//! Provides authenticated proofs of account state and storage values
//! against the global state root. Light clients can verify these proofs
//! without downloading the full state.
//!
//! ## Proof Types
//!
//! - **AccountProof**: Proves an account's state (or non-existence) against the global root.
//! - **StorageProof**: Proves a storage slot value, chained through the account proof
//!   to the global root.
//!
//! ## Verification Chain
//!
//! ```text
//! StorageProof:
//!   storage_smt_proof  (key → value in storage trie)
//!       ↓ verifies against
//!   account.storage_root
//!       ↓ embedded in
//!   account_proof.smt_proof  (address_hash → account_hash in account trie)
//!       ↓ verifies against
//!   global state_root
//! ```

use brrq_crypto::hash::Hash256;
use brrq_types::account::Account;
use brrq_types::address::Address;

use crate::smt::{SmtProof, SparseMerkleTree};

/// Proof of an account's state against the global state root.
///
/// Contains the SMT Merkle proof that the account's hash is (or is not)
/// present at the expected key in the account trie.
#[derive(Debug, Clone)]
pub struct AccountProof {
    /// The address being proved.
    pub address: Address,
    /// The account data, if it exists.
    pub account: Option<Account>,
    /// The SMT Merkle proof (address_hash → account_hash).
    pub smt_proof: SmtProof,
    /// The state root this proof is valid against.
    pub state_root: Hash256,
}

impl AccountProof {
    /// Verify this proof against an expected state root.
    ///
    /// Returns `true` if the SMT proof is valid against the given root.
    pub fn verify(&self, expected_root: &Hash256) -> bool {
        // The state root must match what we claim
        if self.state_root != *expected_root {
            return false;
        }
        // Bind account data hash to SMT proof value.
        if let Some(ref acct) = self.account {
            if acct.hash() != self.smt_proof.value {
                return false;
            }
        }
        SparseMerkleTree::verify_proof(&self.smt_proof, expected_root)
    }
}

/// Proof of a storage slot value, chained to the global state root.
///
/// Verification requires two steps:
/// 1. Verify the storage proof against the account's storage_root.
/// 2. Verify the account proof against the global state root.
#[derive(Debug, Clone)]
pub struct StorageProof {
    /// The account proof (proves the account in the global trie).
    pub account_proof: AccountProof,
    /// The storage key being proved.
    pub key: Hash256,
    /// The storage value, if it exists.
    pub value: Option<Hash256>,
    /// The SMT proof for the storage slot (key → value in storage trie).
    /// `None` if the account doesn't exist (no storage trie).
    pub storage_smt_proof: Option<SmtProof>,
    /// The storage root of the account's storage trie.
    pub storage_root: Hash256,
}

impl StorageProof {
    /// Verify the full proof chain: storage → account → global root.
    ///
    /// Returns `true` only if both the storage proof and account proof are valid.
    pub fn verify(&self, expected_root: &Hash256) -> bool {
        // Step 1: Verify the account proof against the global root.
        if !self.account_proof.verify(expected_root) {
            return false;
        }

        // Step 2: If the account doesn't exist, storage is implicitly empty.
        // The storage proof should be None and value should be None.
        if self.account_proof.account.is_none() {
            return self.storage_smt_proof.is_none() && self.value.is_none();
        }

        // Step 3: Check the account's storage_root.
        let account = self.account_proof.account.as_ref().unwrap();

        // If the account's storage_root is ZERO, it has never had storage written.
        // The proof value must be None — no storage exists.
        if account.storage_root == Hash256::ZERO {
            return self.value.is_none();
        }

        // Step 4: Verify the account's storage_root matches the proof's storage_root.
        if account.storage_root != self.storage_root {
            return false;
        }

        // Step 5: Verify the storage SMT proof against the storage root.
        match &self.storage_smt_proof {
            Some(proof) => {
                // Bind value to proof value.
                let proof_value = if proof.exists { Some(proof.value) } else { None };
                if self.value != proof_value {
                    return false;
                }
                SparseMerkleTree::verify_proof(proof, &self.storage_root)
            }
            None => false, // Account exists with storage but no proof provided
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world_state::WorldState;
    use brrq_crypto::hash::Hasher;

    fn addr(s: &str) -> Address {
        let hash = Hasher::hash(s.as_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Address::from_bytes(bytes)
    }

    #[test]
    fn test_account_proof_existing() {
        let mut ws = WorldState::new();
        let alice = addr("alice_proof_test");
        ws.get_or_create_account(alice).balance = 1000;
        ws.flush_account(&alice);

        let proof = ws.prove_account(&alice);
        let root = ws.state_root();

        // Proof should be for an existing account
        assert!(proof.account.is_some());
        assert_eq!(proof.account.as_ref().unwrap().balance, 1000);
        assert_eq!(proof.address, alice);
        assert_eq!(proof.state_root, root);

        // Verification should succeed
        assert!(proof.verify(&root));
    }

    #[test]
    fn test_account_proof_nonexistent() {
        let mut ws = WorldState::new();
        // Add one account so the tree is non-empty
        ws.get_or_create_account(addr("other")).balance = 100;
        ws.flush_account(&addr("other"));

        let bob = addr("bob_nonexistent");
        let proof = ws.prove_account(&bob);
        let root = ws.state_root();

        // Proof should be for a non-existent account
        assert!(proof.account.is_none());
        assert!(!proof.smt_proof.exists);

        // Non-membership proof should still verify
        assert!(proof.verify(&root));
    }

    #[test]
    fn test_account_proof_wrong_root_fails() {
        let mut ws = WorldState::new();
        let alice = addr("alice_wrong_root");
        ws.get_or_create_account(alice).balance = 500;
        ws.flush_account(&alice);

        let proof = ws.prove_account(&alice);
        let root = ws.state_root();

        // Correct root works
        assert!(proof.verify(&root));

        // Wrong root fails
        let wrong_root = Hasher::hash(b"wrong_root");
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn test_storage_proof_existing() {
        let mut ws = WorldState::new();
        let contract = addr("contract_storage_proof");
        ws.get_or_create_account(contract);

        let key = Hasher::hash(b"slot_42");
        let value = Hasher::hash(b"value_42");
        ws.storage_set(&contract, key, value);

        let proof = ws.prove_storage(&contract, &key);
        let root = ws.state_root();

        // Should have the correct value
        assert_eq!(proof.value, Some(value));
        assert!(proof.storage_smt_proof.is_some());

        // Full chain verification should succeed
        assert!(proof.verify(&root));
    }

    #[test]
    fn test_storage_proof_nonexistent() {
        let mut ws = WorldState::new();
        let contract = addr("contract_empty_storage");
        ws.get_or_create_account(contract);

        let key = Hasher::hash(b"missing_slot");
        let proof = ws.prove_storage(&contract, &key);
        let root = ws.state_root();

        // Value should be None (or Some(ZERO) depending on SMT)
        // The storage trie for this account is empty, so no storage SMT proof
        // The account exists but has no storage trie entries
        assert!(proof.verify(&root));
    }

    #[test]
    fn test_storage_proof_chained_verification() {
        let mut ws = WorldState::new();
        let contract = addr("contract_chained");
        ws.get_or_create_account(contract);

        // Set multiple storage slots
        for i in 0..5 {
            let key = Hasher::hash(format!("slot_{}", i).as_bytes());
            let val = Hasher::hash(format!("val_{}", i).as_bytes());
            ws.storage_set(&contract, key, val);
        }

        let root = ws.state_root();

        // Verify each slot
        for i in 0..5 {
            let key = Hasher::hash(format!("slot_{}", i).as_bytes());
            let expected_val = Hasher::hash(format!("val_{}", i).as_bytes());
            let proof = ws.prove_storage(&contract, &key);

            assert_eq!(proof.value, Some(expected_val));
            assert!(proof.verify(&root), "Storage proof failed for slot_{}", i);
        }

        // Verify a non-existent slot also passes
        let missing_key = Hasher::hash(b"slot_999");
        let proof = ws.prove_storage(&contract, &missing_key);
        assert!(proof.verify(&root));
    }
}
