//! Portal state persistence — serialize/deserialize escrow and nullifier state.
//!
//! Provides binary serialization for Portal state that can be stored in
//! RocksDB or any other byte-oriented storage backend.
//!
//! ## Storage Layout
//!
//! Portal state is persisted as two independent blobs:
//! - **Escrow blob**: All active/settled/expired locks + balance tracking
//! - **Nullifier blob**: Set of consumed nullifier hashes
//!
//! Both are serialized with bincode and can be loaded atomically on startup.

use serde::{Deserialize, Serialize};
use brrq_crypto::hash::Hash256;

use crate::escrow::EscrowManager;
use crate::nullifier::NullifierSet;
use crate::types::PortalLock;

/// Current snapshot format version. Increment on any schema change.
/// Bumped to v2 to include permanent nullifier tracking.
pub const SNAPSHOT_VERSION: u32 = 2;

/// Serializable snapshot of the EscrowManager state.
#[derive(Serialize, Deserialize)]
pub struct EscrowSnapshot {
    /// Schema version — must match SNAPSHOT_VERSION on deserialization.
    pub version: u32,
    /// All locks (active, settled, expired, cancelled).
    pub locks: Vec<PortalLock>,
    /// Total amount currently held in escrow.
    pub total_escrowed: u64,
    /// Current lock nonce counter.
    pub lock_nonce: u64,
}

/// Serializable snapshot of the NullifierSet state.
#[derive(Serialize, Deserialize)]
pub struct NullifierSnapshot {
    /// Schema version — must match SNAPSHOT_VERSION on deserialization.
    pub version: u32,
    /// All consumed nullifier hashes.
    pub consumed: Vec<Hash256>,
    /// Nullifiers that are permanent (no expiry, must never be pruned).
    #[serde(default)]
    pub permanent: Vec<Hash256>,
}

impl EscrowManager {
    /// Serialize the escrow state to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let snapshot = self.to_snapshot();
        bincode::serialize(&snapshot).map_err(|e| format!("escrow serialize failed: {e}"))
    }

    /// Deserialize escrow state from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Limit deserialization to 64MB to prevent OOM from crafted payloads
        const MAX_BLOB_SIZE: u64 = 64 * 1024 * 1024;
        if bytes.len() as u64 > MAX_BLOB_SIZE {
            return Err(format!("escrow blob too large: {} bytes (max {})", bytes.len(), MAX_BLOB_SIZE));
        }
        let snapshot: EscrowSnapshot = bincode::deserialize(bytes)
            .map_err(|e| format!("escrow deserialize failed: {e}"))?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(format!(
                "escrow snapshot version mismatch: expected {}, got {}",
                SNAPSHOT_VERSION, snapshot.version
            ));
        }
        Ok(Self::from_snapshot(snapshot))
    }

    /// Create a serializable snapshot.
    pub fn to_snapshot(&self) -> EscrowSnapshot {
        EscrowSnapshot {
            version: SNAPSHOT_VERSION,
            locks: self.all_locks().cloned().collect(),
            total_escrowed: self.total_escrowed(),
            lock_nonce: self.lock_nonce(),
        }
    }

    /// Restore from a snapshot and verify integrity.
    pub fn from_snapshot(snapshot: EscrowSnapshot) -> Self {
        let mut escrow = Self::new();
        escrow.restore_locks(snapshot.locks, snapshot.total_escrowed, snapshot.lock_nonce);

        // Verify invariant: total_escrowed must match sum of active locks
        if !escrow.verify_invariant() {
            tracing::error!(
                "INTEGRITY VIOLATION: total_escrowed ({}) != sum of active locks. Recomputing.",
                escrow.total_escrowed()
            );
            // Self-heal: recompute from lock data by re-restoring
            let correct: u64 = escrow
                .all_locks()
                .filter(|l| l.status == crate::types::LockStatus::Active)
                .map(|l| l.amount)
                .sum();
            let locks: Vec<_> = escrow.all_locks().cloned().collect();
            let nonce = escrow.lock_nonce();
            escrow.restore_locks(Vec::new(), 0, 0); // clear
            escrow.restore_locks(locks, correct, nonce);
        }

        escrow
    }
}

impl NullifierSet {
    /// Serialize the nullifier set to bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        let snapshot = self.to_snapshot();
        bincode::serialize(&snapshot).map_err(|e| format!("nullifier serialize failed: {e}"))
    }

    /// Deserialize nullifier set from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        // Limit deserialization to 64MB to prevent OOM
        const MAX_BLOB_SIZE: u64 = 64 * 1024 * 1024;
        if bytes.len() as u64 > MAX_BLOB_SIZE {
            return Err(format!("nullifier blob too large: {} bytes (max {})", bytes.len(), MAX_BLOB_SIZE));
        }
        let snapshot: NullifierSnapshot = bincode::deserialize(bytes)
            .map_err(|e| format!("nullifier deserialize failed: {e}"))?;
        if snapshot.version != SNAPSHOT_VERSION {
            return Err(format!(
                "nullifier snapshot version mismatch: expected {}, got {}",
                SNAPSHOT_VERSION, snapshot.version
            ));
        }
        Ok(Self::from_snapshot(snapshot))
    }

    /// Create a serializable snapshot.
    pub fn to_snapshot(&self) -> NullifierSnapshot {
        NullifierSnapshot {
            version: SNAPSHOT_VERSION,
            consumed: self.all_consumed().cloned().collect(),
            permanent: self.all_permanent().cloned().collect(),
        }
    }

    /// Restore from a snapshot using bulk insert (avoids N individual consume() calls).
    pub fn from_snapshot(snapshot: NullifierSnapshot) -> Self {
        let set: std::collections::HashSet<brrq_crypto::hash::Hash256> =
            snapshot.consumed.into_iter().collect();
        let perm: std::collections::HashSet<brrq_crypto::hash::Hash256> =
            snapshot.permanent.into_iter().collect();
        Self::restore_bulk(set, perm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;
    use brrq_crypto::schnorr::SchnorrKeyPair;
    use brrq_types::Address;
    use crate::types::MIN_TIMEOUT_BLOCKS;

    #[test]
    fn test_escrow_roundtrip() {
        let kp = SchnorrKeyPair::generate();
        let addr = Address::from_public_key(kp.public_key().as_bytes());
        let mut escrow = EscrowManager::new();

        let cond = Hasher::hash(b"secret");
        let timeout = 100_000 + MIN_TIMEOUT_BLOCKS + 1_000;
        escrow.register_lock(
            addr, *kp.public_key(), 50_000, cond, Hash256::ZERO, timeout, 100_000,
        ).unwrap();

        let bytes = escrow.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        let restored = EscrowManager::from_bytes(&bytes).unwrap();
        assert_eq!(restored.total_escrowed(), escrow.total_escrowed());
        assert_eq!(restored.active_lock_count(), escrow.active_lock_count());
        assert!(restored.verify_invariant());
    }

    #[test]
    fn test_nullifier_roundtrip() {
        let mut nullifiers = NullifierSet::new();
        let n1 = Hasher::hash(b"null1");
        let n2 = Hasher::hash(b"null2");
        nullifiers.consume(&n1);
        nullifiers.consume(&n2);

        // Serialize
        let bytes = nullifiers.to_bytes().unwrap();
        assert!(!bytes.is_empty());

        // Deserialize
        let restored = NullifierSet::from_bytes(&bytes).unwrap();
        assert_eq!(restored.len(), 2);
        assert!(restored.is_consumed(&n1));
        assert!(restored.is_consumed(&n2));
        assert!(!restored.is_consumed(&Hasher::hash(b"null3")));
    }
}
