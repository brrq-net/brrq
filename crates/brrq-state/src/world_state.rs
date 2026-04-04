//! World state management.
//!
//! The world state tracks all accounts, their balances, nonces,
//! and smart contract storage. It uses the Sparse Merkle Tree
//! for authenticated state commitments.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_types::account::Account;
use brrq_types::address::Address;

use crate::error::StateError;
use crate::proofs::{AccountProof, StorageProof};
use crate::smt::SparseMerkleTree;
use crate::state_db::StateDb;

use std::collections::HashMap;

/// A single state change recorded during execution.
///
/// Used for zero-knowledge proving and for undo-log rollback.
/// Each variant carries enough information to reverse the change.
#[derive(Debug, Clone)]
pub enum StateChange {
    /// Balance change.
    BalanceChange {
        address: Address,
        old_balance: u64,
        new_balance: u64,
    },
    /// Nonce increment.
    NonceChange {
        address: Address,
        old_nonce: u64,
        new_nonce: u64,
    },
    /// Storage slot update.
    StorageChange {
        address: Address,
        key: Hash256,
        old_value: Option<Hash256>,
        new_value: Hash256,
    },
    /// Contract deployment.
    CodeDeploy {
        address: Address,
        code_hash: Hash256,
    },
    /// Base fee burned (removed from circulating supply).
    FeeBurn {
        amount: u64,
    },
}

/// Maximum number of entries in the address hash cache before eviction.
/// When exceeded, the cache is cleared to bound memory usage.
const MAX_ADDRESS_CACHE_SIZE: usize = 100_000;

/// A lightweight zero-copy extraction of modified state data (O(Delta) size).
/// This is used to persist only exactly what changed to disk without cloning
/// the entire `WorldState` into background async threads, preventing Memory OOM.
#[derive(Debug, Clone)]
pub struct StateDiff {
    pub accounts: Vec<(Address, Account)>,
    pub storage: Vec<((Address, Hash256), Option<Hash256>)>,
    pub code: Vec<(Hash256, Vec<u8>)>,
    pub deleted_accounts: Vec<Address>,
}

/// The world state — top-level state management.
#[derive(Debug, Clone)]
pub struct WorldState {
    /// Account data indexed by address.
    accounts: HashMap<Address, Account>,
    /// Account state trie (address_hash → account_hash).
    account_trie: SparseMerkleTree,
    /// Per-contract storage tries.
    storage_tries: HashMap<Address, SparseMerkleTree>,
    /// Backing database.
    db: StateDb,
    /// Cache of address → SHA-256(address) to avoid rehashing.
    address_hash_cache: HashMap<Address, Hash256>,
    /// O(Delta) persistence: addresses of accounts that were modified
    pub dirty_accounts: std::collections::HashSet<Address>,
    /// O(Delta) persistence: set of (address, key) for modified storage slots
    pub dirty_storage: std::collections::HashSet<(Address, Hash256)>,
    /// O(Delta) persistence: addresses of deleted accounts
    pub deleted_accounts: std::collections::HashSet<Address>,
}

impl WorldState {
    /// Create a new empty world state.
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            account_trie: SparseMerkleTree::new(),
            storage_tries: HashMap::new(),
            db: StateDb::new(),
            address_hash_cache: HashMap::new(),
            dirty_accounts: std::collections::HashSet::new(),
            dirty_storage: std::collections::HashSet::new(),
            deleted_accounts: std::collections::HashSet::new(),
        }
    }

    /// Get the state root (commitment to entire world state).
    pub fn state_root(&self) -> Hash256 {
        self.account_trie.root()
    }

    /// Get a dual-hash state root for quantum-hedged commitment.
    ///
    /// Computes `DualHash(SHA-256(root) || Poseidon2(root))` so the state
    /// root remains secure even if SHA-256 or Poseidon2 is individually broken.
    pub fn dual_state_root(&self) -> brrq_crypto::hash::DualHash {
        let root = self.state_root();
        Hasher::dual_hash(root.as_bytes())
    }

    /// Get an account by address. Returns None if not found.
    pub fn get_account(&self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// Get or create an account (returns mutable reference).
    pub fn get_or_create_account(&mut self, address: Address) -> &mut Account {
        if let std::collections::hash_map::Entry::Vacant(e) = self.accounts.entry(address) {
            let account = Account::new_eoa(address, 0);
            e.insert(account);
            self.update_account_trie(&address);
        }
        self.accounts.get_mut(&address).unwrap()
    }

    /// Set/update an account.
    pub fn set_account(&mut self, account: Account) {
        let address = account.address;
        self.accounts.insert(address, account);
        self.update_account_trie(&address);
    }

    /// Check if an account exists.
    pub fn account_exists(&self, address: &Address) -> bool {
        self.accounts.contains_key(address)
    }

    /// Get the balance of an account (0 if not found).
    pub fn balance(&self, address: &Address) -> u64 {
        self.accounts.get(address).map(|a| a.balance).unwrap_or(0)
    }

    /// Get the nonce of an account (0 if not found).
    pub fn nonce(&self, address: &Address) -> u64 {
        self.accounts.get(address).map(|a| a.nonce).unwrap_or(0)
    }

    /// Transfer value between accounts.
    pub fn transfer(
        &mut self,
        from: &Address,
        to: &Address,
        amount: u64,
    ) -> Result<(), StateError> {
        // Self-transfer is a no-op.
        if from == to {
            return Ok(());
        }

        // Reject zero-value transfers to prevent state bloat.
        if amount == 0 {
            return Ok(());
        }

        // Check balance
        let from_balance = self.balance(from);
        if from_balance < amount {
            return Err(StateError::InsufficientBalance {
                have: from_balance,
                need: amount,
            });
        }

        // Pre-check: verify credit won't overflow BEFORE debiting.
        // This ensures atomicity — if the credit would fail, sender keeps their funds.
        let to_balance = self.balance(to);
        to_balance
            .checked_add(amount)
            .ok_or_else(|| StateError::BalanceOverflow {
                address: format!("{:?}", to),
            })?;

        // Debit (safe — we checked from_balance >= amount above)
        let from_account = self.get_or_create_account(*from);
        from_account.balance -= amount;
        let from_addr = from_account.address;
        self.update_account_trie(&from_addr);

        // Credit (safe — we checked no overflow above)
        let to_account = self.get_or_create_account(*to);
        to_account.balance += amount;
        let to_addr = to_account.address;
        self.update_account_trie(&to_addr);

        Ok(())
    }

    /// Increment an account's nonce.
    pub fn increment_nonce(&mut self, address: &Address) -> Result<u64, StateError> {
        let account =
            self.accounts
                .get_mut(address)
                .ok_or_else(|| StateError::AccountNotFound {
                    address: format!("{:?}", address),
                })?;
        account.nonce = account
            .nonce
            .checked_add(1)
            .ok_or_else(|| StateError::NonceOverflow {
                address: format!("{:?}", address),
            })?;
        let new_nonce = account.nonce;
        self.update_account_trie(address);
        Ok(new_nonce)
    }

    /// Store contract code and update account's code_hash.
    pub fn deploy_code(&mut self, address: &Address, code: &[u8]) -> Result<Hash256, StateError> {
        let code_hash = Hasher::hash(code);
        self.db.store_code(code_hash, code);

        let account =
            self.accounts
                .get_mut(address)
                .ok_or_else(|| StateError::AccountNotFound {
                    address: format!("{:?}", address),
                })?;
        account.code_hash = code_hash;
        self.update_account_trie(address);
        Ok(code_hash)
    }

    /// Get contract code by address.
    pub fn get_code(&self, address: &Address) -> Option<&[u8]> {
        let account = self.accounts.get(address)?;
        self.db.get_code(&account.code_hash)
    }

    /// Get a value from contract storage.
    pub fn storage_get(&self, address: &Address, key: &Hash256) -> Option<Hash256> {
        self.storage_tries.get(address)?.get(key)
    }

    /// Set a value in contract storage.
    pub fn storage_set(&mut self, address: &Address, key: Hash256, value: Hash256) {
        // Skip if no account exists to avoid creating an orphaned storage trie.
        if !self.accounts.contains_key(address) {
            return;
        }

        let trie = self.storage_tries.entry(*address).or_default();
        trie.insert(key, value);
        self.dirty_storage.insert((*address, key));

        // Update the account's storage_root
        if let Some(account) = self.accounts.get_mut(address) {
            account.storage_root = trie.root();
            self.update_account_trie(address);
        }
    }

    /// Remove a key from contract storage (proper SMT deletion).
    ///
    /// Unlike `storage_set(addr, key, ZERO)`, this actually removes the leaf
    /// from the Sparse Merkle Tree, preserving the correct state root.
    pub fn storage_remove(&mut self, address: &Address, key: &Hash256) {
        if let Some(trie) = self.storage_tries.get_mut(address) {
            trie.remove(key);
            self.dirty_storage.insert((*address, *key));
            // Update the account's storage_root
            if let Some(account) = self.accounts.get_mut(address) {
                account.storage_root = trie.root();
                self.update_account_trie(address);
            }
        }
    }

    /// Clone the storage trie for a contract address.
    ///
    /// Returns a cloned copy of the contract's SMT for safe reads
    /// during VM execution. Returns a default empty trie if no
    /// storage exists yet for this address.
    pub fn clone_storage_trie(&self, address: &Address) -> SparseMerkleTree {
        self.storage_tries.get(address).cloned().unwrap_or_default()
    }

    /// Get the storage root for a contract.
    pub fn storage_root(&self, address: &Address) -> Hash256 {
        self.storage_tries
            .get(address)
            .map(|t| t.root())
            .unwrap_or_else(|| SparseMerkleTree::new().root())
    }

    // ── State Proofs ──────────────────────────────────────────────────

    /// Generate a Merkle proof for an account against the current state root.
    ///
    /// Returns an `AccountProof` containing:
    /// - The SMT proof (address_hash key in the account trie)
    /// - The account data (if it exists)
    /// - The current state root
    ///
    /// Works for both existing accounts (membership proof) and
    /// non-existent accounts (non-membership proof).
    pub fn prove_account(&self, address: &Address) -> AccountProof {
        let address_hash = self
            .address_hash_cache
            .get(address)
            .copied()
            .unwrap_or_else(|| Hasher::hash(address.as_bytes()));

        let smt_proof = self.account_trie.prove(&address_hash);
        let account = self.accounts.get(address).cloned();
        let state_root = self.state_root();

        AccountProof {
            address: *address,
            account,
            smt_proof,
            state_root,
        }
    }

    /// Generate a storage proof for a key in a contract's storage trie.
    ///
    /// Returns a `StorageProof` containing:
    /// - The account proof (chained to the global state root)
    /// - The storage SMT proof (key in the contract's storage trie)
    /// - The storage value (if it exists)
    /// - The account's storage root
    ///
    /// For non-existent accounts, the storage proof will have no storage SMT proof
    /// and the value will be None.
    pub fn prove_storage(&self, address: &Address, key: &Hash256) -> StorageProof {
        let account_proof = self.prove_account(address);

        let (storage_smt_proof, value, storage_root) =
            if let Some(trie) = self.storage_tries.get(address) {
                let proof = trie.prove(key);
                let val = trie.get(key);
                let root = trie.root();
                (Some(proof), val, root)
            } else if account_proof.account.is_some() {
                // Account exists but has no storage trie — storage_root is ZERO.
                // No storage proof needed; verify will check storage_root == ZERO.
                (None, None, Hash256::ZERO)
            } else {
                // Account doesn't exist — no storage trie at all.
                (None, None, Hash256::ZERO)
            };

        StorageProof {
            account_proof,
            key: *key,
            value,
            storage_smt_proof,
            storage_root,
        }
    }

    /// Number of accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Iterate over all accounts (for persistence / serialization).
    pub fn accounts_iter(&self) -> impl Iterator<Item = (&Address, &Account)> {
        self.accounts.iter()
    }

    /// Iterate over all storage tries (for persistence).
    pub fn storage_tries_iter(&self) -> impl Iterator<Item = (&Address, &SparseMerkleTree)> {
        self.storage_tries.iter()
    }

    /// Store raw code in the backing database (used by persistent storage loader).
    pub fn store_code_raw(&mut self, code_hash: Hash256, code: &[u8]) {
        self.db.store_code(code_hash, code);
    }

    /// Create a snapshot of the current state (for rollback).
    pub fn snapshot(&self) -> WorldState {
        self.clone()
    }

    /// Flush the account trie entry after in-place mutation via `get_or_create_account()`.
    ///
    /// Call this after modifying an account's balance/nonce in-place to ensure
    /// the account trie reflects the updated state, without cloning the account.
    pub fn flush_account(&mut self, address: &Address) {
        self.update_account_trie(address);
    }

    /// Rollback state changes in reverse order (undo-log).
    ///
    /// Iterates through the given changes in **reverse** order and restores
    /// each field to its previous value. This is far cheaper than deep-cloning
    /// the entire `WorldState` via `snapshot()`.
    ///
    /// Note: `CodeDeploy` only resets the account's `code_hash` to `ZERO` but
    /// does NOT remove the bytecode from `StateDb`. The code store is
    /// content-addressed and may be shared across contracts.
    pub fn rollback_changes(&mut self, changes: &[StateChange]) {
        for change in changes.iter().rev() {
            match change {
                StateChange::BalanceChange {
                    address,
                    old_balance,
                    ..
                } => {
                    if let Some(acct) = self.accounts.get_mut(address) {
                        acct.balance = *old_balance;
                    }
                    self.update_account_trie(address);
                }
                StateChange::NonceChange {
                    address, old_nonce, ..
                } => {
                    if let Some(acct) = self.accounts.get_mut(address) {
                        acct.nonce = *old_nonce;
                    }
                    self.update_account_trie(address);
                }
                StateChange::StorageChange {
                    address,
                    key,
                    old_value,
                    ..
                } => {
                    match old_value {
                        Some(v) => self.storage_set(address, *key, *v),
                        None => {
                            // Key didn't exist before — properly remove it from the SMT.
                            // Using insert(ZERO) would create a leaf node distinct from
                            // an empty path, corrupting the state root.
                            self.storage_remove(address, key);
                        }
                    }
                }
                StateChange::CodeDeploy { address, .. } => {
                    if let Some(acct) = self.accounts.get_mut(address) {
                        acct.code_hash = Hash256::ZERO;
                    }
                    self.update_account_trie(address);
                }
                StateChange::FeeBurn { .. } => {
                    // FeeBurn is an accounting record only — no state to rollback.
                    // The actual balance deduction is already captured in BalanceChange entries.
                }
            }
        }
    }

    /// Clear dirty tracking sets after a successful disk flush.
    pub fn clear_dirty(&mut self) {
        self.dirty_accounts.clear();
        self.dirty_storage.clear();
        self.deleted_accounts.clear();
    }

    /// Extract the minimal dirty StateDiff and clear the tracking flags locally.
    /// This prevents OOM memory bloat by sending ONLY the changes to `spawn_blocking`.
    pub fn extract_diff(&mut self) -> StateDiff {
        let mut diff_accounts = Vec::with_capacity(self.dirty_accounts.len());
        let mut diff_code = Vec::new();
        for addr in &self.dirty_accounts {
            if let Some(account) = self.get_account(addr) {
                diff_accounts.push((*addr, account.clone()));
                if account.code_hash != Hash256::ZERO {
                    if let Some(code) = self.get_code(addr) {
                        diff_code.push((account.code_hash, code.to_vec()));
                    }
                }
            }
        }

        let mut diff_storage = Vec::with_capacity(self.dirty_storage.len());
        for (addr, slot_key) in &self.dirty_storage {
            diff_storage.push(((*addr, *slot_key), self.storage_get(addr, slot_key)));
        }

        let deleted: Vec<Address> = self.deleted_accounts.iter().copied().collect();
        self.clear_dirty();

        StateDiff {
            accounts: diff_accounts,
            storage: diff_storage,
            code: diff_code,
            deleted_accounts: deleted,
        }
    }

    // --- Internal ---

    /// Update the account trie entry for an address (uses cached address hash).
    fn update_account_trie(&mut self, address: &Address) {
        // Evict the entire cache when it grows too large to bound memory.
        // The cache is a pure optimization (rehashing is cheap), so clearing
        // is safe — entries will be repopulated on demand.
        if self.address_hash_cache.len() >= MAX_ADDRESS_CACHE_SIZE {
            self.address_hash_cache.clear();
        }
        let address_hash = *self
            .address_hash_cache
            .entry(*address)
            .or_insert_with(|| Hasher::hash(address.as_bytes()));
        if let Some(account) = self.accounts.get(address) {
            let account_hash = account.hash();
            self.account_trie.insert(address_hash, account_hash);
            self.dirty_accounts.insert(*address);
            self.deleted_accounts.remove(address);
        }
    }
}

impl Default for WorldState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> Address {
        let hash = Hasher::hash(s.as_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Address::from_bytes(bytes)
    }

    #[test]
    fn test_empty_world_state() {
        let ws = WorldState::new();
        assert_eq!(ws.account_count(), 0);
        assert_eq!(ws.balance(&addr("alice")), 0);
        assert_eq!(ws.nonce(&addr("alice")), 0);
    }

    #[test]
    fn test_create_account() {
        let mut ws = WorldState::new();
        let alice = addr("alice");
        let account = ws.get_or_create_account(alice);
        account.balance = 1000;
        assert_eq!(ws.balance(&alice), 1000);
        assert_eq!(ws.account_count(), 1);
    }

    #[test]
    fn test_transfer() {
        let mut ws = WorldState::new();
        let alice = addr("alice");
        let bob = addr("bob");

        // Fund alice
        ws.get_or_create_account(alice).balance = 1000;

        // Transfer
        ws.transfer(&alice, &bob, 300).unwrap();
        assert_eq!(ws.balance(&alice), 700);
        assert_eq!(ws.balance(&bob), 300);
    }

    // Self-transfer must be a no-op
    #[test]
    fn test_transfer_self_is_noop() {
        let mut ws = WorldState::new();
        let alice = addr("alice");
        ws.get_or_create_account(alice).balance = 1000;

        // Self-transfer should succeed and not change balance
        ws.transfer(&alice, &alice, 500).unwrap();
        assert_eq!(ws.balance(&alice), 1000);
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let mut ws = WorldState::new();
        let alice = addr("alice");
        let bob = addr("bob");
        ws.get_or_create_account(alice).balance = 100;

        let result = ws.transfer(&alice, &bob, 200);
        assert!(result.is_err());
    }

    #[test]
    fn test_ext5_zero_value_transfer_noop() {
        // Zero-value transfer must be a no-op to prevent state bloat.
        // Without this check, sending 0 sats to random addresses creates permanent
        // empty accounts in the state trie with no pruning mechanism.
        let mut ws = WorldState::new();
        let alice = addr("alice");
        let random = addr("random_target");
        ws.get_or_create_account(alice).balance = 1000;

        let accounts_before = ws.accounts.len();

        // Zero-value transfer should succeed but NOT create the target account
        ws.transfer(&alice, &random, 0).unwrap();

        assert_eq!(
            ws.accounts.len(),
            accounts_before,
            "zero-value transfer must not create new accounts"
        );
        assert_eq!(ws.balance(&alice), 1000, "sender balance unchanged");
        assert_eq!(ws.balance(&random), 0, "random target should not exist");
    }

    #[test]
    fn test_nonce_increment() {
        let mut ws = WorldState::new();
        let alice = addr("alice");
        ws.get_or_create_account(alice);

        assert_eq!(ws.nonce(&alice), 0);
        ws.increment_nonce(&alice).unwrap();
        assert_eq!(ws.nonce(&alice), 1);
        ws.increment_nonce(&alice).unwrap();
        assert_eq!(ws.nonce(&alice), 2);
    }

    #[test]
    fn test_state_root_changes() {
        let mut ws = WorldState::new();
        let root0 = ws.state_root();

        ws.get_or_create_account(addr("alice")).balance = 1000;
        let root1 = ws.state_root();
        assert_ne!(root0, root1);

        ws.get_or_create_account(addr("bob")).balance = 500;
        let root2 = ws.state_root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_state_root_deterministic() {
        let mut ws1 = WorldState::new();
        ws1.get_or_create_account(addr("alice")).balance = 1000;
        ws1.get_or_create_account(addr("bob")).balance = 500;

        let mut ws2 = WorldState::new();
        ws2.get_or_create_account(addr("alice")).balance = 1000;
        ws2.get_or_create_account(addr("bob")).balance = 500;

        assert_eq!(ws1.state_root(), ws2.state_root());
    }

    #[test]
    fn test_deploy_and_get_code() {
        let mut ws = WorldState::new();
        let addr = addr("contract");
        ws.get_or_create_account(addr);

        let code = vec![0x13, 0x00, 0x00, 0x00]; // NOP instruction
        let code_hash = ws.deploy_code(&addr, code.clone()).unwrap();

        assert_eq!(ws.get_code(&addr), Some(code.as_slice()));
        assert_eq!(ws.get_account(&addr).unwrap().code_hash, code_hash);
    }

    #[test]
    fn test_contract_storage() {
        let mut ws = WorldState::new();
        let contract = addr("contract");
        ws.get_or_create_account(contract);

        let key = Hasher::hash(b"slot_0");
        let value = Hasher::hash(b"value_0");

        ws.storage_set(&contract, key, value);
        assert_eq!(ws.storage_get(&contract, &key), Some(value));
    }

    #[test]
    fn test_storage_root_updates_account() {
        let mut ws = WorldState::new();
        let contract = addr("contract");
        ws.get_or_create_account(contract);
        let root_before = ws.state_root();

        let key = Hasher::hash(b"slot_0");
        let value = Hasher::hash(b"value_0");
        ws.storage_set(&contract, key, value);

        let root_after = ws.state_root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_snapshot_and_rollback() {
        let mut ws = WorldState::new();
        let alice = addr("alice");

        // Use set_account to ensure trie is updated with balance
        let mut account = Account::new_eoa(alice, 1000);
        ws.set_account(account.clone());
        let snapshot = ws.snapshot();
        let root_before = ws.state_root();

        // Modify state via set_account (properly updates trie)
        account.balance = 0;
        ws.set_account(account);
        assert_ne!(ws.state_root(), root_before);

        // Rollback
        ws = snapshot;
        assert_eq!(ws.state_root(), root_before);
        assert_eq!(ws.balance(&alice), 1000);
    }

    // ── Undo-log rollback tests ───────────────────────────────────────

    #[test]
    fn test_rollback_balance_change() {
        let mut ws = WorldState::new();
        let alice = addr("alice");
        ws.set_account(Account::new_eoa(alice, 1000));
        let root_before = ws.state_root();

        // Record a balance change and apply it
        let changes = vec![StateChange::BalanceChange {
            address: alice,
            old_balance: 1000,
            new_balance: 700,
        }];
        ws.get_or_create_account(alice).balance = 700;
        ws.flush_account(&alice);
        assert_eq!(ws.balance(&alice), 700);
        assert_ne!(ws.state_root(), root_before);

        // Rollback
        ws.rollback_changes(&changes);
        assert_eq!(ws.balance(&alice), 1000);
        assert_eq!(ws.state_root(), root_before);
    }

    #[test]
    fn test_rollback_nonce_change() {
        let mut ws = WorldState::new();
        let alice = addr("alice");
        ws.set_account(Account::new_eoa(alice, 1000));
        let root_before = ws.state_root();

        // Increment nonce
        ws.increment_nonce(&alice).unwrap();
        assert_eq!(ws.nonce(&alice), 1);

        let changes = vec![StateChange::NonceChange {
            address: alice,
            old_nonce: 0,
            new_nonce: 1,
        }];

        // Rollback
        ws.rollback_changes(&changes);
        assert_eq!(ws.nonce(&alice), 0);
        assert_eq!(ws.state_root(), root_before);
    }

    #[test]
    fn test_rollback_multiple_changes() {
        let mut ws = WorldState::new();
        let alice = addr("alice");
        let bob = addr("bob");
        ws.set_account(Account::new_eoa(alice, 1000));
        ws.set_account(Account::new_eoa(bob, 500));
        let root_before = ws.state_root();

        // Simulate transfer: alice -300, bob +300, alice nonce +1
        let mut changes = Vec::new();

        // Balance change for alice
        changes.push(StateChange::BalanceChange {
            address: alice,
            old_balance: 1000,
            new_balance: 700,
        });
        ws.get_or_create_account(alice).balance = 700;
        ws.flush_account(&alice);

        // Balance change for bob
        changes.push(StateChange::BalanceChange {
            address: bob,
            old_balance: 500,
            new_balance: 800,
        });
        ws.get_or_create_account(bob).balance = 800;
        ws.flush_account(&bob);

        // Nonce change for alice
        changes.push(StateChange::NonceChange {
            address: alice,
            old_nonce: 0,
            new_nonce: 1,
        });
        ws.increment_nonce(&alice).unwrap();

        assert_eq!(ws.balance(&alice), 700);
        assert_eq!(ws.balance(&bob), 800);
        assert_eq!(ws.nonce(&alice), 1);

        // Rollback ALL changes
        ws.rollback_changes(&changes);
        assert_eq!(ws.balance(&alice), 1000);
        assert_eq!(ws.balance(&bob), 500);
        assert_eq!(ws.nonce(&alice), 0);
        assert_eq!(ws.state_root(), root_before);
    }

    #[test]
    fn test_rollback_code_deploy() {
        let mut ws = WorldState::new();
        let contract = addr("contract_rollback");
        ws.get_or_create_account(contract);

        let code = vec![0x13, 0x00, 0x00, 0x00];
        let code_hash = ws.deploy_code(&contract, code).unwrap();
        assert_ne!(ws.get_account(&contract).unwrap().code_hash, Hash256::ZERO);

        let changes = vec![StateChange::CodeDeploy {
            address: contract,
            code_hash,
        }];

        // Rollback should reset code_hash to ZERO
        ws.rollback_changes(&changes);
        assert_eq!(ws.get_account(&contract).unwrap().code_hash, Hash256::ZERO);
    }

    #[test]
    fn test_rollback_storage_change() {
        let mut ws = WorldState::new();
        let contract = addr("contract_storage");
        ws.get_or_create_account(contract);

        let key = Hasher::hash(b"slot_0");
        let value = Hasher::hash(b"value_0");
        ws.storage_set(&contract, key, value);
        assert_eq!(ws.storage_get(&contract, &key), Some(value));

        let changes = vec![StateChange::StorageChange {
            address: contract,
            key,
            old_value: None, // Didn't exist before
            new_value: value,
        }];

        // Rollback removes the key (it didn't exist before)
        ws.rollback_changes(&changes);
        let result = ws.storage_get(&contract, &key);
        assert_eq!(result, None);
    }

    // ── clone_storage_trie tests ────────────────────────────────────

    #[test]
    fn test_clone_storage_trie() {
        let mut ws = WorldState::new();
        let contract = addr("clone_test_contract");
        ws.get_or_create_account(contract);

        let key = Hasher::hash(b"slot_0");
        let value = Hasher::hash(b"value_0");
        ws.storage_set(&contract, key, value);

        // Clone the trie and verify we can read the data
        let cloned = ws.clone_storage_trie(&contract);
        assert_eq!(cloned.get(&key), Some(value));

        // Verify the cloned trie root matches
        assert_eq!(cloned.root(), ws.storage_root(&contract));
    }

    #[test]
    fn test_clone_storage_trie_empty() {
        let ws = WorldState::new();
        let contract = addr("no_storage_contract");

        // Clone non-existent storage → default empty trie
        let cloned = ws.clone_storage_trie(&contract);
        let key = Hasher::hash(b"any_key");
        assert_eq!(cloned.get(&key), None);
    }
}
