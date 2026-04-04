//! Chain synchronization protocol.
//!
//! Handles syncing a node to the latest chain state from peers.
//! Uses a simple request-response pattern for block ranges.

use crate::error::SyncError;
use brrq_crypto::hash::Hash256;

/// Sync state of the local node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncState {
    /// Fully synced with the network.
    Synced,
    /// Downloading blocks.
    Syncing {
        /// Current local height.
        current: u64,
        /// Target height (best known).
        target: u64,
    },
    /// Initial sync not yet started.
    NotStarted,
    /// Downloading state snapshot instead of blocks.
    /// Triggered when the gap to best_known_height > SNAPSHOT_SYNC_THRESHOLD.
    /// After snapshot is applied, switches to Syncing for remaining blocks.
    SnapshotSync {
        /// Height of the snapshot being downloaded.
        snapshot_height: u64,
        /// State root of the snapshot (for verification).
        snapshot_state_root: Hash256,
    },
}

impl SyncState {
    /// Progress as a percentage (0-100).
    pub fn progress(&self) -> f64 {
        match self {
            SyncState::Synced => 100.0,
            SyncState::NotStarted => 0.0,
            SyncState::Syncing { current, target } => {
                if *target == 0 {
                    return 0.0;
                }
                (*current as f64 / *target as f64) * 100.0
            }
            SyncState::SnapshotSync { .. } => 5.0, // Snapshot download = early phase
        }
    }
}

/// Sync manager coordinates block download from peers.
pub struct SyncManager {
    /// Current sync state.
    pub state: SyncState,
    /// Local chain height.
    pub local_height: u64,
    /// Best known height from peers.
    pub best_known_height: u64,
    /// Last block hash.
    pub last_block_hash: Hash256,
    /// Number of blocks per sync batch.
    pub batch_size: u64,
    /// Optional weak subjectivity checkpoint.
    /// When set, the sync manager will reject any chain that doesn't include
    /// this block hash at the specified height. Protects against long-range attacks.
    pub ws_checkpoint: Option<(u64, Hash256)>,
}

impl SyncManager {
    /// Create a new sync manager.
    pub fn new() -> Self {
        Self {
            state: SyncState::NotStarted,
            local_height: 0,
            best_known_height: 0,
            last_block_hash: Hash256::ZERO,
            batch_size: 100,
            ws_checkpoint: None,
        }
    }

    /// Update the best known height from peer information.
    pub fn update_target(&mut self, peer_height: u64) {
        if peer_height > self.best_known_height {
            self.best_known_height = peer_height;
            self.update_state();
        }
    }

    /// Record that a block has been processed.
    pub fn block_processed(&mut self, height: u64, hash: Hash256) {
        if height > self.local_height {
            self.local_height = height;
            self.last_block_hash = hash;
            self.update_state();
        }
    }

    /// Process a synced block with hash chain validation.
    ///
    /// Verifies that the block's parent hash matches our last known hash.
    /// This prevents attackers from injecting forged blocks during sync.
    ///
    /// Also enforces the V-05 weak subjectivity checkpoint when configured,
    /// rejecting any chain that presents the wrong hash at the checkpoint height.
    pub fn process_validated_block(
        &mut self,
        height: u64,
        hash: Hash256,
        parent_hash: Hash256,
    ) -> Result<(), SyncError> {
        // V-24: Validate hash chain continuity.
        // For blocks after genesis, the parent hash must match the last processed block.
        if height > 0 && parent_hash != self.last_block_hash {
            return Err(SyncError::InvalidParentHash {
                height,
                expected: self.last_block_hash,
                got: parent_hash,
            });
        }

        // V-05: Enforce weak subjectivity checkpoint.
        // If a checkpoint is configured and we're at that height, the hash must match.
        if let Some((cp_height, cp_hash)) = &self.ws_checkpoint
            && height == *cp_height
            && hash != *cp_hash
        {
            return Err(SyncError::WeakSubjectivityViolation {
                height: *cp_height,
                expected: *cp_hash,
                got: hash,
            });
        }

        // Use block_processed for heights > 0. For genesis (height 0),
        // block_processed won't update because local_height is already 0,
        // so we set last_block_hash directly.
        if height == 0 {
            self.last_block_hash = hash;
        } else {
            self.block_processed(height, hash);
        }
        Ok(())
    }

    /// If we're more than this many blocks behind,
    /// use snapshot sync instead of block-by-block download.
    /// After pruning at 10,000 blocks, peers can't serve blocks < (tip - 10,000).
    /// Threshold should be less than the prune window.
    pub const SNAPSHOT_SYNC_THRESHOLD: u64 = 5_000;

    /// Check if snapshot sync is needed (gap too large for block sync).
    /// Removed local_height == 0 restriction — nodes resuming far behind
    /// must also be able to snapshot sync when peers have pruned old blocks.
    pub fn needs_snapshot_sync(&self) -> bool {
        let gap = self.best_known_height.saturating_sub(self.local_height);
        gap > Self::SNAPSHOT_SYNC_THRESHOLD
    }

    /// Begin snapshot sync mode.
    pub fn begin_snapshot_sync(&mut self, snapshot_height: u64, state_root: Hash256) {
        self.state = SyncState::SnapshotSync {
            snapshot_height,
            snapshot_state_root: state_root,
        };
    }

    /// Complete snapshot sync — jump to snapshot height and switch to block sync.
    ///
    /// `block_hash` MUST be the actual block hash at `snapshot_height`, NOT the state root.
    /// Using the state root here would break the parent-hash chain validation.
    pub fn complete_snapshot_sync(&mut self, snapshot_height: u64, block_hash: Hash256) {
        self.local_height = snapshot_height;
        // Use block hash (not state root) to maintain valid parent-hash chain
        self.last_block_hash = block_hash;
        self.update_state();
    }

    /// Get the next batch of block heights to request.
    pub fn next_batch(&self) -> Option<(u64, u64)> {
        // Don't request blocks during snapshot sync
        if matches!(self.state, SyncState::SnapshotSync { .. }) {
            return None;
        }
        if self.local_height >= self.best_known_height {
            return None;
        }
        let from = self.local_height + 1;
        let to = (from + self.batch_size - 1).min(self.best_known_height);
        Some((from, to))
    }

    /// Check if we need to sync.
    pub fn needs_sync(&self) -> bool {
        self.local_height < self.best_known_height
    }

    /// Update the internal sync state.
    fn update_state(&mut self) {
        if self.local_height >= self.best_known_height && self.best_known_height > 0 {
            self.state = SyncState::Synced;
        } else if self.best_known_height > 0 {
            self.state = SyncState::Syncing {
                current: self.local_height,
                target: self.best_known_height,
            };
        }
    }
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_initial_state() {
        let sync = SyncManager::new();
        assert_eq!(sync.state, SyncState::NotStarted);
        assert!(!sync.needs_sync());
    }

    #[test]
    fn test_sync_needed() {
        let mut sync = SyncManager::new();
        sync.update_target(100);
        assert!(sync.needs_sync());
        assert_eq!(
            sync.state,
            SyncState::Syncing {
                current: 0,
                target: 100
            }
        );
    }

    #[test]
    fn test_block_processed() {
        let mut sync = SyncManager::new();
        sync.update_target(10);
        for h in 1..=10 {
            let mut hash = Hash256::ZERO;
            hash.0[0] = h as u8;
            sync.block_processed(h, hash);
        }
        assert_eq!(sync.state, SyncState::Synced);
        assert!(!sync.needs_sync());
    }

    #[test]
    fn test_next_batch() {
        let mut sync = SyncManager::new();
        sync.batch_size = 50;
        sync.update_target(200);

        let batch = sync.next_batch().unwrap();
        assert_eq!(batch, (1, 50));

        sync.local_height = 50;
        let batch = sync.next_batch().unwrap();
        assert_eq!(batch, (51, 100));
    }

    #[test]
    fn test_progress() {
        assert_eq!(SyncState::Synced.progress(), 100.0);
        assert_eq!(SyncState::NotStarted.progress(), 0.0);

        let syncing = SyncState::Syncing {
            current: 50,
            target: 100,
        };
        assert!((syncing.progress() - 50.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_no_batch_when_synced() {
        let mut sync = SyncManager::new();
        sync.local_height = 100;
        sync.best_known_height = 100;
        assert!(sync.next_batch().is_none());
    }

    // ── V-24: Block validation tests ─────────────────────────────────────────

    #[test]
    fn test_process_validated_block_genesis() {
        // Genesis block (height 0) should always succeed since there's no parent to check.
        let mut sync = SyncManager::new();
        sync.update_target(10);

        let hash = Hash256::from_bytes([1u8; 32]);
        let result = sync.process_validated_block(0, hash, Hash256::ZERO);
        assert!(result.is_ok());
        assert_eq!(sync.last_block_hash, hash);
    }

    #[test]
    fn test_process_validated_block_valid_chain() {
        // A valid sequence of blocks with correct parent hashes should succeed.
        let mut sync = SyncManager::new();
        sync.update_target(3);

        let hash0 = Hash256::from_bytes([1u8; 32]);
        sync.process_validated_block(0, hash0, Hash256::ZERO)
            .unwrap();

        let hash1 = Hash256::from_bytes([2u8; 32]);
        // parent_hash must equal hash0
        sync.process_validated_block(1, hash1, hash0).unwrap();
        assert_eq!(sync.local_height, 1);
        assert_eq!(sync.last_block_hash, hash1);

        let hash2 = Hash256::from_bytes([3u8; 32]);
        sync.process_validated_block(2, hash2, hash1).unwrap();
        assert_eq!(sync.local_height, 2);
        assert_eq!(sync.last_block_hash, hash2);
    }

    #[test]
    fn test_process_validated_block_invalid_parent_hash() {
        // A block with a wrong parent hash should be rejected.
        let mut sync = SyncManager::new();
        sync.update_target(10);

        let hash0 = Hash256::from_bytes([1u8; 32]);
        sync.process_validated_block(0, hash0, Hash256::ZERO)
            .unwrap();

        let hash1 = Hash256::from_bytes([2u8; 32]);
        let wrong_parent = Hash256::from_bytes([99u8; 32]);
        let result = sync.process_validated_block(1, hash1, wrong_parent);

        assert!(result.is_err());
        match result.unwrap_err() {
            SyncError::InvalidParentHash {
                height,
                expected,
                got,
            } => {
                assert_eq!(height, 1);
                assert_eq!(expected, hash0);
                assert_eq!(got, wrong_parent);
            }
            other => panic!("expected InvalidParentHash, got: {:?}", other),
        }
        // State must not have changed after a rejected block.
        assert_eq!(sync.local_height, 0);
        assert_eq!(sync.last_block_hash, hash0);
    }

    // ── V-05: Weak subjectivity checkpoint tests ─────────────────────────────

    #[test]
    fn test_ws_checkpoint_pass() {
        // Block at checkpoint height with the correct hash should be accepted.
        let mut sync = SyncManager::new();
        sync.update_target(10);

        let cp_hash = Hash256::from_bytes([5u8; 32]);
        sync.ws_checkpoint = Some((2, cp_hash));

        let hash0 = Hash256::from_bytes([1u8; 32]);
        sync.process_validated_block(0, hash0, Hash256::ZERO)
            .unwrap();

        let hash1 = Hash256::from_bytes([2u8; 32]);
        sync.process_validated_block(1, hash1, hash0).unwrap();

        // Height 2 with matching checkpoint hash should succeed.
        sync.process_validated_block(2, cp_hash, hash1).unwrap();
        assert_eq!(sync.local_height, 2);
        assert_eq!(sync.last_block_hash, cp_hash);
    }

    #[test]
    fn test_ws_checkpoint_violation() {
        // Block at checkpoint height with a WRONG hash should be rejected.
        let mut sync = SyncManager::new();
        sync.update_target(10);

        let cp_hash = Hash256::from_bytes([5u8; 32]);
        sync.ws_checkpoint = Some((2, cp_hash));

        let hash0 = Hash256::from_bytes([1u8; 32]);
        sync.process_validated_block(0, hash0, Hash256::ZERO)
            .unwrap();

        let hash1 = Hash256::from_bytes([2u8; 32]);
        sync.process_validated_block(1, hash1, hash0).unwrap();

        // Height 2 with a wrong hash should be rejected.
        let wrong_hash = Hash256::from_bytes([99u8; 32]);
        let result = sync.process_validated_block(2, wrong_hash, hash1);

        assert!(result.is_err());
        match result.unwrap_err() {
            SyncError::WeakSubjectivityViolation {
                height,
                expected,
                got,
            } => {
                assert_eq!(height, 2);
                assert_eq!(expected, cp_hash);
                assert_eq!(got, wrong_hash);
            }
            other => panic!("expected WeakSubjectivityViolation, got: {:?}", other),
        }
        // State must not have changed after a rejected block.
        assert_eq!(sync.local_height, 1);
        assert_eq!(sync.last_block_hash, hash1);
    }

    #[test]
    fn test_ws_checkpoint_irrelevant_height() {
        // Blocks at heights other than the checkpoint height should not be affected.
        let mut sync = SyncManager::new();
        sync.update_target(10);

        let cp_hash = Hash256::from_bytes([5u8; 32]);
        sync.ws_checkpoint = Some((5, cp_hash));

        let hash0 = Hash256::from_bytes([1u8; 32]);
        sync.process_validated_block(0, hash0, Hash256::ZERO)
            .unwrap();

        // Height 1 is not the checkpoint height, so any hash should be fine.
        let hash1 = Hash256::from_bytes([99u8; 32]);
        let result = sync.process_validated_block(1, hash1, hash0);
        assert!(result.is_ok());
    }
}
