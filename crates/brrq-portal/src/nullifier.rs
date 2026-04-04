//! Nullifier Set — prevents double-spending of Portal Keys.
//!
//! Uses HashSet for O(1) lookup/consume. Merkle root is cached and
//! recomputed only when nullifiers change (once per block).
//!
//! ## Pruning
//!
//! Nullifiers are only needed while the original lock is still valid.
//! After `timeout_l2_block + SETTLEMENT_GRACE_BLOCKS`, the lock is expired
//! and pruned — any settlement attempt would fail regardless. Nullifiers
//! for expired locks are safe to remove.
//!
//! `consume_with_expiry()` records when each nullifier can be pruned.
//! `prune_expired()` removes nullifiers past their expiry, keeping the
//! set size bounded to ~active locks (not all-time history).

use std::collections::{BTreeMap, HashSet};

use brrq_crypto::hash::Hash256;
use brrq_crypto::merkle::compute_tx_root;
use tracing::warn;

/// Nullifier set with Merkle commitment and expiry-based pruning.
pub struct NullifierSet {
    /// All consumed nullifiers (O(1) lookup).
    consumed: HashSet<Hash256>,
    /// Cached Merkle root. Invalidated on consume/prune.
    merkle_root_cache: Option<Hash256>,
    /// Expiry index — maps block height → nullifiers that expire at that height.
    /// Used by `prune_expired()` to remove old nullifiers efficiently.
    expiry_index: BTreeMap<u64, Vec<Hash256>>,
    /// Nullifiers consumed without expiry (permanent, must never be pruned).
    /// Tracked so `backfill_expiry()` can skip them after restore.
    permanent: HashSet<Hash256>,
}

impl NullifierSet {
    /// Create a new empty nullifier set.
    pub fn new() -> Self {
        Self {
            consumed: HashSet::new(),
            merkle_root_cache: Some(Hash256::ZERO),
            expiry_index: BTreeMap::new(),
            permanent: HashSet::new(),
        }
    }

    /// Bulk-restore consumed nullifiers (used by persistence layer).
    ///
    /// NOTE: Expiry index is NOT persisted. After restart, previously consumed nullifiers
    /// remain in the set until they are eventually cleaned by a full rebuild.
    /// New nullifiers consumed after restart will have proper expiry tracking.
    pub(crate) fn restore_bulk(nullifiers: HashSet<Hash256>, permanent: HashSet<Hash256>) -> Self {
        let cache = if nullifiers.is_empty() {
            Some(Hash256::ZERO)
        } else {
            None
        };
        Self {
            consumed: nullifiers,
            merkle_root_cache: cache,
            expiry_index: BTreeMap::new(),
            permanent,
        }
    }

    /// Assign a default expiry to restored nullifiers that lack expiry tracking.
    ///
    /// Only assigns expiry to nullifiers that are NOT in the `permanent` set.
    /// Permanent nullifiers (consumed without expiry via `consume()`) must never be
    /// made pruneable — pruning them would re-enable double-spending.
    pub(crate) fn backfill_expiry(&mut self, default_expiry: u64) {
        let untracked: Vec<Hash256> = self.consumed.iter()
            .filter(|n| !self.permanent.contains(n))
            .filter(|n| !self.expiry_index.values().any(|bucket| bucket.contains(n)))
            .copied()
            .collect();
        if !untracked.is_empty() {
            self.expiry_index.entry(default_expiry).or_default().extend(untracked);
        }
    }

    /// Check if a nullifier has been consumed.
    pub fn is_consumed(&self, nullifier: &Hash256) -> bool {
        self.consumed.contains(nullifier)
    }

    /// Consume a nullifier, marking it as spent (no expiry — permanent).
    ///
    /// Use `consume_with_expiry()` when lock timeout is known for pruning support.
    pub(crate) fn consume(&mut self, nullifier: &Hash256) -> bool {
        let is_new = self.consumed.insert(*nullifier);
        if !is_new {
            warn!(nullifier = %nullifier, "double-spend attempt: nullifier already consumed");
        } else {
            self.merkle_root_cache = None;
            // Track as permanent so backfill_expiry() skips it after restore.
            self.permanent.insert(*nullifier);
        }
        is_new
    }

    /// Consume a nullifier with expiry tracking for future pruning.
    ///
    /// `expires_at` is the block height after which this nullifier can be safely
    /// removed (typically `lock.timeout_l2_block + SETTLEMENT_GRACE_BLOCKS`).
    pub fn consume_with_expiry(&mut self, nullifier: &Hash256, expires_at: u64) -> bool {
        let is_new = self.consumed.insert(*nullifier);
        if !is_new {
            warn!(nullifier = %nullifier, "double-spend attempt: nullifier already consumed");
        } else {
            self.merkle_root_cache = None;
            self.expiry_index
                .entry(expires_at)
                .or_default()
                .push(*nullifier);
        }
        is_new
    }

    /// Prune nullifiers that have expired (lock timeout + grace period passed).
    ///
    /// Returns the number of nullifiers pruned.
    /// Should be called periodically (e.g., once per block in maintenance).
    pub fn prune_expired(&mut self, current_height: u64) -> usize {
        let mut pruned = 0;
        // Collect all expiry heights <= current_height
        let expired_heights: Vec<u64> = self.expiry_index
            .range(..=current_height)
            .map(|(&h, _)| h)
            .collect();

        for height in expired_heights {
            if let Some(nullifiers) = self.expiry_index.remove(&height) {
                for n in &nullifiers {
                    self.consumed.remove(n);
                    pruned += 1;
                }
            }
        }

        if pruned > 0 {
            self.merkle_root_cache = None;
        }
        pruned
    }

    /// Compute the Merkle root of all consumed nullifiers.
    ///
    /// Cached — only recomputed when nullifiers change.
    /// Uses raw byte ordering for deterministic, portable results.
    pub fn merkle_root(&mut self) -> Hash256 {
        if let Some(cached) = self.merkle_root_cache {
            return cached;
        }
        let root = if self.consumed.is_empty() {
            Hash256::ZERO
        } else {
            let mut sorted: Vec<Hash256> = self.consumed.iter().copied().collect();
            sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            compute_tx_root(&sorted)
        };
        self.merkle_root_cache = Some(root);
        root
    }

    /// Number of consumed nullifiers.
    pub fn len(&self) -> usize {
        self.consumed.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.consumed.is_empty()
    }

    /// Iterator over all consumed nullifiers (for serialization).
    pub(crate) fn all_consumed(&self) -> impl Iterator<Item = &Hash256> {
        self.consumed.iter()
    }

    /// Iterator over permanent nullifiers (for serialization).
    pub(crate) fn all_permanent(&self) -> impl Iterator<Item = &Hash256> {
        self.permanent.iter()
    }

    /// Number of pending expiry entries (for monitoring).
    pub(crate) fn expiry_queue_len(&self) -> usize {
        self.expiry_index.values().map(|v| v.len()).sum()
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;

    #[test]
    fn test_nullifier_merkle_root_empty() {
        let mut ns = NullifierSet::new();
        assert_eq!(ns.merkle_root(), Hash256::ZERO);
    }

    #[test]
    fn test_nullifier_merkle_root_deterministic() {
        let mut ns = NullifierSet::new();
        ns.consume(&Hasher::hash(b"n1"));
        ns.consume(&Hasher::hash(b"n2"));
        ns.consume(&Hasher::hash(b"n3"));
        let root1 = ns.merkle_root();

        let mut ns2 = NullifierSet::new();
        ns2.consume(&Hasher::hash(b"n3"));
        ns2.consume(&Hasher::hash(b"n1"));
        ns2.consume(&Hasher::hash(b"n2"));
        let root2 = ns2.merkle_root();

        assert_eq!(root1, root2);
        assert!(!root1.is_zero());
    }

    #[test]
    fn test_nullifier_merkle_root_changes_on_consume() {
        let mut ns = NullifierSet::new();
        ns.consume(&Hasher::hash(b"n1"));
        let root1 = ns.merkle_root();
        ns.consume(&Hasher::hash(b"n2"));
        let root2 = ns.merkle_root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_nullifier_merkle_root_cached() {
        let mut ns = NullifierSet::new();
        ns.consume(&Hasher::hash(b"n1"));
        let root1 = ns.merkle_root();
        let root2 = ns.merkle_root();
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_bulk_restore() {
        let mut ns1 = NullifierSet::new();
        ns1.consume(&Hasher::hash(b"a"));
        ns1.consume(&Hasher::hash(b"b"));
        ns1.consume(&Hasher::hash(b"c"));
        let root1 = ns1.merkle_root();

        let set: HashSet<Hash256> = [
            Hasher::hash(b"c"),
            Hasher::hash(b"a"),
            Hasher::hash(b"b"),
        ].into_iter().collect();
        let mut ns2 = NullifierSet::restore_bulk(set, HashSet::new());
        let root2 = ns2.merkle_root();

        assert_eq!(root1, root2);
        assert_eq!(ns2.len(), 3);
        assert!(ns2.is_consumed(&Hasher::hash(b"a")));
    }

    // ── Pruning Tests ─────────────────────────────────────────────────

    #[test]
    fn test_consume_with_expiry_and_prune() {
        let mut ns = NullifierSet::new();
        let n1 = Hasher::hash(b"expires_early");
        let n2 = Hasher::hash(b"expires_late");
        let n3 = Hasher::hash(b"no_expiry");

        ns.consume_with_expiry(&n1, 100);  // Expires at block 100
        ns.consume_with_expiry(&n2, 200);  // Expires at block 200
        ns.consume(&n3);                    // No expiry — stays forever

        assert_eq!(ns.len(), 3);
        assert!(ns.is_consumed(&n1));

        // Prune at block 100 — n1 should be removed
        let pruned = ns.prune_expired(100);
        assert_eq!(pruned, 1);
        assert!(!ns.is_consumed(&n1));
        assert!(ns.is_consumed(&n2));
        assert!(ns.is_consumed(&n3));
        assert_eq!(ns.len(), 2);

        // Prune at block 200 — n2 should be removed
        let pruned = ns.prune_expired(200);
        assert_eq!(pruned, 1);
        assert!(!ns.is_consumed(&n2));
        assert!(ns.is_consumed(&n3)); // n3 has no expiry — stays
        assert_eq!(ns.len(), 1);
    }

    #[test]
    fn test_prune_invalidates_merkle_cache() {
        let mut ns = NullifierSet::new();
        let n1 = Hasher::hash(b"temp");
        ns.consume_with_expiry(&n1, 50);
        let root_before = ns.merkle_root();
        assert!(!root_before.is_zero());

        ns.prune_expired(50);
        let root_after = ns.merkle_root();
        assert_eq!(root_after, Hash256::ZERO); // Empty set → zero root
    }

    #[test]
    fn test_prune_no_effect_before_expiry() {
        let mut ns = NullifierSet::new();
        ns.consume_with_expiry(&Hasher::hash(b"a"), 100);
        assert_eq!(ns.prune_expired(50), 0); // Too early
        assert_eq!(ns.len(), 1);
    }

    #[test]
    fn test_expiry_queue_len() {
        let mut ns = NullifierSet::new();
        ns.consume_with_expiry(&Hasher::hash(b"a"), 100);
        ns.consume_with_expiry(&Hasher::hash(b"b"), 100);
        ns.consume_with_expiry(&Hasher::hash(b"c"), 200);
        assert_eq!(ns.expiry_queue_len(), 3);
        ns.prune_expired(100);
        assert_eq!(ns.expiry_queue_len(), 1);
    }

    // ── Fix Tests ──────────────────────────────────────────────

    #[test]
    fn test_backfill_expiry_skips_permanent_nullifiers() {
        let mut ns = NullifierSet::new();
        let permanent_n = Hasher::hash(b"permanent");
        let temporary_n = Hasher::hash(b"temporary");

        // Consume one permanent (no expiry) and one with expiry
        ns.consume(&permanent_n);
        ns.consume_with_expiry(&temporary_n, 100);

        // Simulate restore: create a new set with both nullifiers,
        // marking the permanent one in the permanent set.
        let consumed: HashSet<Hash256> = [permanent_n, temporary_n].into_iter().collect();
        let perm: HashSet<Hash256> = [permanent_n].into_iter().collect();
        let mut restored = NullifierSet::restore_bulk(consumed, perm);

        // Backfill should only assign expiry to the non-permanent nullifier
        restored.backfill_expiry(500);

        // Prune at block 500 — only the temporary one should be pruned
        let pruned = restored.prune_expired(500);
        assert_eq!(pruned, 1);
        assert!(restored.is_consumed(&permanent_n), "permanent nullifier must survive pruning");
        assert!(!restored.is_consumed(&temporary_n), "temporary nullifier should be pruned");
    }
}
