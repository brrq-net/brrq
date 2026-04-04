//! Brrq account model (§4.3.1).
//!
//! Brrq uses an Account Model (not UTXO) for state management:
//! - Persistent state for smart contracts
//! - Simple balance tracking
//! - DeFi-friendly (DEX, lending, vaults)
//!
//! Each account has: balance + nonce + optional contract code/storage.

use brrq_crypto::hash::{Hash256, Hasher};
use serde::{Deserialize, Serialize};

use crate::address::Address;

/// A Brrq account.
///
/// ## Account Types
/// - **Externally Owned Account (EOA)**: User-controlled, has balance
/// - **Contract Account**: Has code + storage, controlled by contract logic
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Account {
    /// Account address.
    pub address: Address,
    /// Balance in satoshis (brqBTC, 1:1 with BTC).
    pub balance: u64,
    /// Transaction nonce (prevents replay attacks).
    pub nonce: u64,
    /// Contract code hash (Hash256::ZERO for EOAs).
    pub code_hash: Hash256,
    /// Storage root (Merkle root of contract storage, Hash256::ZERO for EOAs).
    pub storage_root: Hash256,
}

impl Account {
    /// Create a new externally owned account (EOA).
    pub fn new_eoa(address: Address, balance: u64) -> Self {
        Self {
            address,
            balance,
            nonce: 0,
            code_hash: Hash256::ZERO,
            storage_root: Hash256::ZERO,
        }
    }

    /// Create a new contract account.
    pub fn new_contract(address: Address, code_hash: Hash256) -> Self {
        Self {
            address,
            balance: 0,
            nonce: 0,
            code_hash,
            storage_root: Hash256::ZERO,
        }
    }

    /// Check if this is a contract account.
    pub fn is_contract(&self) -> bool {
        !self.code_hash.is_zero()
    }

    /// Check if this is an externally owned account.
    pub fn is_eoa(&self) -> bool {
        self.code_hash.is_zero()
    }

    /// Compute the account hash for Merkle tree inclusion.
    ///
    /// H("BRRQ_ACCOUNT_V1" || address || balance || nonce || code_hash || storage_root)
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::ACCOUNT_V1);
        hasher.update(self.address.as_bytes());
        hasher.update(&self.balance.to_le_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(self.code_hash.as_bytes());
        hasher.update(self.storage_root.as_bytes());
        hasher.finalize()
    }

    /// Check if the account has sufficient balance.
    pub fn has_balance(&self, amount: u64) -> bool {
        self.balance >= amount
    }

    /// Deduct balance (returns false if insufficient).
    pub fn debit(&mut self, amount: u64) -> bool {
        if self.balance < amount {
            return false;
        }
        self.balance -= amount;
        true
    }

    /// Add balance. Returns false if the credit would overflow u64.
    pub fn credit(&mut self, amount: u64) -> bool {
        match self.balance.checked_add(amount) {
            Some(new_balance) => {
                self.balance = new_balance;
                true
            }
            None => false,
        }
    }

    /// Increment nonce (after successful transaction).
    /// Returns false if nonce would overflow u64.
    pub fn increment_nonce(&mut self) -> bool {
        match self.nonce.checked_add(1) {
            Some(new_nonce) => {
                self.nonce = new_nonce;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_eoa() {
        let addr = Address::from_bytes([1u8; 20]);
        let account = Account::new_eoa(addr, 100_000);
        assert!(account.is_eoa());
        assert!(!account.is_contract());
        assert_eq!(account.balance, 100_000);
        assert_eq!(account.nonce, 0);
    }

    #[test]
    fn test_balance_operations() {
        let addr = Address::from_bytes([1u8; 20]);
        let mut account = Account::new_eoa(addr, 1000);

        assert!(account.has_balance(500));
        assert!(account.debit(500));
        assert_eq!(account.balance, 500);

        assert!(!account.debit(501)); // Insufficient
        assert_eq!(account.balance, 500); // Unchanged

        assert!(account.credit(200));
        assert_eq!(account.balance, 700);
    }

    #[test]
    fn test_nonce_increment() {
        let addr = Address::from_bytes([1u8; 20]);
        let mut account = Account::new_eoa(addr, 0);
        assert_eq!(account.nonce, 0);
        assert!(account.increment_nonce());
        assert_eq!(account.nonce, 1);
    }

    #[test]
    fn test_account_hash_deterministic() {
        let addr = Address::from_bytes([1u8; 20]);
        let a1 = Account::new_eoa(addr, 1000);
        let a2 = Account::new_eoa(addr, 1000);
        assert_eq!(a1.hash(), a2.hash());
    }

    #[test]
    fn test_different_balance_different_hash() {
        let addr = Address::from_bytes([1u8; 20]);
        let a1 = Account::new_eoa(addr, 1000);
        let a2 = Account::new_eoa(addr, 2000);
        assert_ne!(a1.hash(), a2.hash());
    }
}
