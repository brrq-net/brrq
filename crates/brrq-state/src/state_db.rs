//! In-memory state database.
//!
//! This provides a key-value store interface backed by a HashMap.
//! In production, this would be backed by RocksDB.
//! For MVP, the in-memory backend is sufficient and avoids
//! the LLVM/clang dependency on Windows.

use brrq_crypto::hash::Hash256;
use std::collections::HashMap;

/// In-memory state database.
///
/// Stores raw key-value pairs. Higher-level structures
/// (SMT, account storage) are built on top of this.
#[derive(Debug, Clone)]
pub struct StateDb {
    /// Key-value storage.
    store: HashMap<Hash256, Vec<u8>>,
    /// Code storage (code_hash → bytecode).
    code_store: HashMap<Hash256, Vec<u8>>,
}

impl StateDb {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self {
            store: HashMap::new(),
            code_store: HashMap::new(),
        }
    }

    /// Get a value by key.
    pub fn get(&self, key: &Hash256) -> Option<&[u8]> {
        self.store.get(key).map(|v| v.as_slice())
    }

    /// Set a value for a key.
    pub fn put(&mut self, key: Hash256, value: Vec<u8>) {
        self.store.insert(key, value);
    }

    /// Delete a key.
    pub fn delete(&mut self, key: &Hash256) -> bool {
        self.store.remove(key).is_some()
    }

    /// Check if a key exists.
    pub fn contains(&self, key: &Hash256) -> bool {
        self.store.contains_key(key)
    }

    /// Store contract bytecode.
    pub fn store_code(&mut self, code_hash: Hash256, code: &[u8]) {
        self.code_store.insert(code_hash, code.to_vec());
    }

    /// Retrieve contract bytecode by hash.
    pub fn get_code(&self, code_hash: &Hash256) -> Option<&[u8]> {
        self.code_store.get(code_hash).map(|v| v.as_slice())
    }

    /// Number of entries in the main store.
    pub fn len(&self) -> usize {
        self.store.len()
    }

    /// Check if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.store.is_empty()
    }

    /// Number of stored code entries.
    pub fn code_count(&self) -> usize {
        self.code_store.len()
    }
}

impl Default for StateDb {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;

    #[test]
    fn test_put_get() {
        let mut db = StateDb::new();
        let key = Hasher::hash(b"test_key");
        db.put(key, b"test_value".to_vec());
        assert_eq!(db.get(&key), Some(b"test_value".as_slice()));
    }

    #[test]
    fn test_get_missing() {
        let db = StateDb::new();
        let key = Hasher::hash(b"missing");
        assert_eq!(db.get(&key), None);
    }

    #[test]
    fn test_delete() {
        let mut db = StateDb::new();
        let key = Hasher::hash(b"to_delete");
        db.put(key, b"value".to_vec());
        assert!(db.delete(&key));
        assert_eq!(db.get(&key), None);
        assert!(!db.delete(&key)); // Already deleted
    }

    #[test]
    fn test_contains() {
        let mut db = StateDb::new();
        let key = Hasher::hash(b"exists");
        assert!(!db.contains(&key));
        db.put(key, b"value".to_vec());
        assert!(db.contains(&key));
    }

    #[test]
    fn test_code_store() {
        let mut db = StateDb::new();
        let code = vec![0x13, 0x00, 0x00, 0x00]; // NOP
        let code_hash = Hasher::hash(&code);
        db.store_code(code_hash, &code);
        assert_eq!(db.get_code(&code_hash), Some(code.as_slice()));
        assert_eq!(db.code_count(), 1);
    }

    #[test]
    fn test_len() {
        let mut db = StateDb::new();
        assert_eq!(db.len(), 0);
        assert!(db.is_empty());
        db.put(Hasher::hash(b"a"), b"1".to_vec());
        db.put(Hasher::hash(b"b"), b"2".to_vec());
        assert_eq!(db.len(), 2);
        assert!(!db.is_empty());
    }
}
