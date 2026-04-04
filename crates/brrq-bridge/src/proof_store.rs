//! Proof availability store for STARK and SNARK proofs.
//!
//! Stores full STARK proofs and their SNARK wrappers, indexed by L2 block
//! range. Provides lookup by block range or individual L2 height.
//!
//! ## MVP Design
//!
//! In the MVP, this is an in-memory store served via HTTP/RPC. Any full node
//! can serve proofs to light clients or challengers. In production, this
//! would be backed by a DA layer (Celestia, Arweave, or Bitcoin Inscriptions).
//!
//! ## Integrity
//!
//! Each stored proof includes a `stark_proof_hash` computed at storage time.
//! The `verify_proof_integrity()` method re-hashes and compares, detecting
//! accidental corruption or tampering.

use std::collections::BTreeMap;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_prover::snark_wrapper::WrappedSnarkProof;
use brrq_prover::types::{BatchProofRecord, StarkProof};
use serde::{Deserialize, Serialize};

// ── Types ───────────────────────────────────────────────────────────────────

/// A stored proof with both STARK and SNARK representations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProof {
    /// Block range this proof covers [start, end] inclusive.
    pub block_range: (u64, u64),
    /// Full STARK proof (for local verification).
    pub stark_proof: StarkProof,
    /// Wrapped SNARK proof (for L1 posting).
    pub snark_proof: WrappedSnarkProof,
    /// SHA-256 hash of the serialized STARK proof.
    pub stark_proof_hash: Hash256,
    /// State root before the first block in the batch.
    pub initial_state_root: Hash256,
    /// State root after the last block in the batch.
    pub final_state_root: Hash256,
    /// Timestamp when stored (UNIX epoch seconds).
    pub stored_at: u64,
    /// L1 anchor transaction ID (set when proof commitment is posted to L1).
    pub l1_anchor_tx: Option<[u8; 32]>,
}

// ── ProofStore ──────────────────────────────────────────────────────────────

/// Maximum proofs stored in memory.
///
/// Prevents unbounded growth. Once the cap is reached, new proofs are
/// rejected until old proofs are evicted (via `evict_oldest`).
const MAX_STORED_PROOFS: usize = 10_000;

/// Proof availability store.
///
/// Stores full STARK proofs and their SNARK wrappers, indexed by L2 block
/// range. In the MVP, this is an in-memory store served via HTTP/RPC.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProofStore {
    /// Proofs indexed by (start_height, end_height).
    proofs: BTreeMap<(u64, u64), StoredProof>,
}

impl ProofStore {
    /// Create a new empty proof store.
    pub fn new() -> Self {
        Self {
            proofs: BTreeMap::new(),
        }
    }

    /// Store a proof from a `BatchProofRecord`.
    ///
    /// Returns the `stark_proof_hash` on success, or an error if the record
    /// has no SNARK proof or a proof for this range already exists.
    pub fn store_proof(&mut self, record: &BatchProofRecord) -> Result<Hash256, String> {
        let range = record.block_range;

        // Validate range
        if range.1 < range.0 {
            return Err(format!(
                "invalid block range: end {} < start {}",
                range.1, range.0,
            ));
        }

        // Reject duplicates
        if self.proofs.contains_key(&range) {
            return Err(format!(
                "proof already stored for range [{}, {}]",
                range.0, range.1,
            ));
        }

        // Enforce capacity limit.
        if self.proofs.len() >= MAX_STORED_PROOFS {
            return Err(format!(
                "proof store at capacity ({}) — evict old proofs first",
                MAX_STORED_PROOFS,
            ));
        }

        // Reject overlapping ranges using BTreeMap range query.
        for (existing, _) in self.proofs.range(..=(range.1, u64::MAX)) {
            if existing.1 >= range.0 {
                return Err(format!(
                    "proof range [{}, {}] overlaps with existing [{}, {}]",
                    range.0, range.1, existing.0, existing.1,
                ));
            }
        }

        // Validate contiguity — new proof must connect to an
        // existing range (predecessor or successor) or start at block 0/1.
        // Gaps in provable history would allow a malicious prover to skip blocks.
        if !self.proofs.is_empty() {
            let connects_to_predecessor = self
                .proofs
                .keys()
                .any(|&(_, end)| end + 1 == range.0);
            let connects_to_successor = self
                .proofs
                .keys()
                .any(|&(start, _)| range.1 + 1 == start);
            let is_genesis = range.0 <= 1;

            if !connects_to_predecessor && !connects_to_successor && !is_genesis {
                return Err(format!(
                    "proof range [{}, {}] creates gap — must connect to an \
                     existing range or start at genesis. \
                     Gaps in proof coverage are not allowed",
                    range.0, range.1,
                ));
            }
        }

        // Reject synthetic proofs.
        // Synthetic proofs are generated by `prove_batch()` (deprecated) and
        // `aggregate_batch_proofs()` — they do NOT prove actual execution.
        // Only real execution proofs from `prove_batch_real()` are accepted.
        if record.is_synthetic {
            return Err(
                "REJECTED: synthetic proof — only real execution proofs are accepted. \
                 Synthetic proofs do not prove actual state transitions.".to_string()
            );
        }

        // Require SNARK wrapper
        let snark = record.snark_proof.as_ref().ok_or_else(|| {
            "BatchProofRecord has no SNARK wrapper — cannot store without SNARK".to_string()
        })?;

        // Compute STARK proof hash with domain separation.
        // Without the domain tag, this hash could collide with hashes of other
        // data structures that happen to have the same byte representation.
        let stark_bytes = record.proof.to_bytes()?;
        let mut hasher = Hasher::new();
        hasher.update(b"STARK_PROOF_V1:");
        hasher.update(&stark_bytes);
        let stark_proof_hash = hasher.finalize();

        // SystemTime is not monotonic — NTP adjustments can
        // cause out-of-order timestamps. For internal ordering, consider
        // using the L2 block height or a monotonic counter instead.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let stored = StoredProof {
            block_range: range,
            stark_proof: record.proof.clone(),
            snark_proof: snark.clone(),
            stark_proof_hash,
            initial_state_root: record.initial_state_root,
            final_state_root: record.final_state_root,
            stored_at: now,
            l1_anchor_tx: None,
        };

        self.proofs.insert(range, stored);
        Ok(stark_proof_hash)
    }

    /// Retrieve a proof by exact block range.
    pub fn get_proof(&self, block_range: (u64, u64)) -> Option<&StoredProof> {
        self.proofs.get(&block_range)
    }

    /// Find the proof covering a specific L2 height.
    ///
    /// Uses BTreeMap range query instead of linear scan.
    /// Only checks entries where start <= height, then verifies end >= height.
    pub fn find_proof_for_height(&self, height: u64) -> Option<&StoredProof> {
        // Look at entries where start <= height (using range up to (height, MAX))
        // and check if end >= height. Iterate in reverse to find the tightest match.
        self.proofs
            .range(..=(height, u64::MAX))
            .rev()
            .find(|(_, p)| height <= p.block_range.1)
            .map(|(_, p)| p)
    }

    /// Get all stored proofs as a slice-like iterator.
    pub fn all_proofs(&self) -> Vec<&StoredProof> {
        self.proofs.values().collect()
    }

    /// Mark a proof as anchored on L1 (after OP_RETURN posting).
    ///
    /// Returns `true` if the proof was found and updated.
    pub fn mark_anchored(&mut self, block_range: (u64, u64), l1_tx: [u8; 32]) -> bool {
        if let Some(proof) = self.proofs.get_mut(&block_range) {
            proof.l1_anchor_tx = Some(l1_tx);
            true
        } else {
            false
        }
    }

    /// Number of stored proofs.
    pub fn count(&self) -> usize {
        self.proofs.len()
    }

    /// Number of proofs anchored on L1.
    pub fn anchored_count(&self) -> usize {
        self.proofs
            .values()
            .filter(|p| p.l1_anchor_tx.is_some())
            .count()
    }

    /// Evict the oldest `count` proofs (by block range).
    ///
    /// Returns the number of proofs actually evicted. Only evicts proofs
    /// that have been anchored on L1 (confirmed safe to remove).
    pub fn evict_oldest_anchored(&mut self, count: usize) -> usize {
        let keys_to_remove: Vec<_> = self
            .proofs
            .iter()
            .filter(|(_, p)| p.l1_anchor_tx.is_some())
            .take(count)
            .map(|(k, _)| *k)
            .collect();
        let removed = keys_to_remove.len();
        for key in keys_to_remove {
            self.proofs.remove(&key);
        }
        removed
    }

    /// Evict unanchored proofs stored before `before_timestamp` (UNIX epoch seconds).
    ///
    /// Proofs that were never anchored on L1 and are older than the given
    /// timestamp are removed to prevent unbounded memory growth.
    pub fn evict_stale_unanchored(&mut self, before_timestamp: u64) -> usize {
        let before = self.proofs.len();
        self.proofs
            .retain(|_, p| p.l1_anchor_tx.is_some() || p.stored_at >= before_timestamp);
        before - self.proofs.len()
    }

    /// Serialize proof store to bytes for persistence.
    ///
    /// Callers should write the returned bytes to disk periodically.
    /// Future: replace with a DA layer backend (Celestia, Arweave, or Bitcoin Inscriptions).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("proof_store serialize: {e}"))
    }

    /// Deserialize proof store from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("proof_store deserialize: {e}"))
    }

    /// Verify that a stored proof is consistent with its commitment.
    ///
    /// Re-hashes the STARK proof bytes and compares with the stored
    /// `stark_proof_hash`. Detects corruption or tampering.
    pub fn verify_proof_integrity(&self, block_range: (u64, u64)) -> Result<bool, String> {
        let stored = self.proofs.get(&block_range).ok_or_else(|| {
            format!(
                "no proof stored for range [{}, {}]",
                block_range.0, block_range.1
            )
        })?;

        // Must use the same domain-separated hash as store_proof (GAP-6).
        let mut hasher = Hasher::new();
        hasher.update(b"STARK_PROOF_V1:");
        hasher.update(&stored.stark_proof.to_bytes()?);
        let recomputed = hasher.finalize();
        Ok(recomputed == stored.stark_proof_hash)
    }
}

impl Default for ProofStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_prover::batch::prove_batch;
    use brrq_prover::prover::StarkProver;

    fn make_record(start: u64, end: u64) -> BatchProofRecord {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([start as u8; 32]);
        let final_root = Hash256::from_bytes([end as u8; 32]);
        prove_batch(&prover, initial, final_root, (start, end), 50, 21_000).unwrap()
    }

    #[test]
    fn store_and_retrieve_proof() {
        let mut store = ProofStore::new();
        let record = make_record(1, 10);

        let hash = store.store_proof(&record).unwrap();
        assert_ne!(hash, Hash256::ZERO);
        assert_eq!(store.count(), 1);

        let stored = store.get_proof((1, 10)).unwrap();
        assert_eq!(stored.block_range, (1, 10));
        assert_eq!(stored.stark_proof_hash, hash);
        assert!(stored.l1_anchor_tx.is_none());
    }

    #[test]
    fn find_proof_for_height() {
        let mut store = ProofStore::new();
        store.store_proof(&make_record(1, 10)).unwrap();
        store.store_proof(&make_record(11, 20)).unwrap();

        // Height 5 should be in range [1, 10]
        let proof = store.find_proof_for_height(5).unwrap();
        assert_eq!(proof.block_range, (1, 10));

        // Height 15 should be in range [11, 20]
        let proof = store.find_proof_for_height(15).unwrap();
        assert_eq!(proof.block_range, (11, 20));

        // Height 25 should not exist
        assert!(store.find_proof_for_height(25).is_none());
    }

    #[test]
    fn mark_proof_anchored() {
        let mut store = ProofStore::new();
        store.store_proof(&make_record(1, 10)).unwrap();

        assert_eq!(store.anchored_count(), 0);

        let tx_id = [0xABu8; 32];
        assert!(store.mark_anchored((1, 10), tx_id));
        assert_eq!(store.anchored_count(), 1);

        let stored = store.get_proof((1, 10)).unwrap();
        assert_eq!(stored.l1_anchor_tx, Some(tx_id));

        // Non-existent range
        assert!(!store.mark_anchored((99, 100), tx_id));
    }

    #[test]
    fn proof_integrity_check() {
        let mut store = ProofStore::new();
        store.store_proof(&make_record(1, 10)).unwrap();

        // Should pass integrity check
        assert!(store.verify_proof_integrity((1, 10)).unwrap());

        // Non-existent range should error
        assert!(store.verify_proof_integrity((99, 100)).is_err());
    }

    #[test]
    fn store_duplicate_rejected() {
        let mut store = ProofStore::new();
        store.store_proof(&make_record(1, 10)).unwrap();

        // Second store for same range should fail
        let result = store.store_proof(&make_record(1, 10));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already stored"));
        assert_eq!(store.count(), 1);
    }

    #[test]
    fn all_proofs_ordered() {
        let mut store = ProofStore::new();
        store.store_proof(&make_record(11, 20)).unwrap();
        store.store_proof(&make_record(1, 10)).unwrap();
        store.store_proof(&make_record(21, 30)).unwrap();

        let all = store.all_proofs();
        assert_eq!(all.len(), 3);
        // BTreeMap orders by key, so (1,10) < (11,20) < (21,30)
        assert_eq!(all[0].block_range, (1, 10));
        assert_eq!(all[1].block_range, (11, 20));
        assert_eq!(all[2].block_range, (21, 30));
    }

    #[test]
    fn default_is_empty() {
        let store = ProofStore::default();
        assert_eq!(store.count(), 0);
        assert_eq!(store.anchored_count(), 0);
    }

    #[test]
    fn stored_proof_has_snark() {
        let mut store = ProofStore::new();
        store.store_proof(&make_record(1, 10)).unwrap();

        let stored = store.get_proof((1, 10)).unwrap();
        // SNARK should be valid
        assert!(stored.snark_proof.verify().is_ok());
        // SNARK public inputs should match state roots
        assert_eq!(
            stored.snark_proof.public_inputs.initial_state_root,
            stored.initial_state_root
        );
        assert_eq!(
            stored.snark_proof.public_inputs.final_state_root,
            stored.final_state_root
        );
    }

    #[test]
    fn test_gap6_domain_separated_proof_hash() {
        // GAP-6: The proof hash must include the "STARK_PROOF_V1:" domain tag.
        // Hashing with the tag must differ from hashing without it.
        use brrq_crypto::hash::Hasher;

        let mut store = ProofStore::new();
        let record = make_record(1, 10);
        let stark_bytes = record.proof.to_bytes().unwrap();

        // Hash WITHOUT domain tag (old, vulnerable approach)
        let plain_hash = Hasher::hash(&stark_bytes);

        // Store proof (uses domain-tagged hash internally)
        let tagged_hash = store.store_proof(&record).unwrap();

        // The domain-tagged hash must differ from the plain hash
        assert_ne!(
            tagged_hash, plain_hash,
            "GAP-6: domain-separated proof hash must differ from plain hash"
        );

        // Verify the stored hash matches expected domain-tagged computation
        let mut hasher = Hasher::new();
        hasher.update(b"STARK_PROOF_V1:");
        hasher.update(&stark_bytes);
        let expected = hasher.finalize();
        assert_eq!(
            tagged_hash, expected,
            "proof hash must use STARK_PROOF_V1: prefix"
        );
    }
}
