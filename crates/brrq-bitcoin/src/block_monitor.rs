//! Bitcoin L1 block monitor — polls for new blocks and caches recent headers.
//!
//! ## Reorg Detection
//!
//! On each poll, if the chain height decreased or the hash at `known_height`
//! differs from the cached hash, a `ChainReorg` error is returned. The caller
//! must handle this by re-scanning deposits and re-validating anchors.
//!
//! ## Reorg Tracking
//!
//! The monitor maintains a chain structure (hash → header + height),
//! tracks `best_block_hash` and `best_block_height`, and identifies
//! transactions in orphaned blocks during reorganizations. Deposits from
//! orphaned blocks are marked unconfirmed and require re-confirmation.

use std::collections::{HashMap, HashSet, VecDeque};
use tracing::{debug, info, warn};

use crate::error::BitcoinError;
use crate::rpc_client::BitcoinRpc;
use crate::types::{L1BlockInfo, MAX_CATCHUP_BLOCKS, MAX_L1_BLOCK_CACHE};

// ── Reorg tracking constants and types ─────────────────────────────────────

/// Minimum number of confirmations before a deposit is
/// considered safe from reorganization. Blocks with fewer confirmations
/// are vulnerable to being orphaned.
pub const MIN_CONFIRMATIONS: u32 = 6;

/// Maximum number of entries to keep in the chain_index HashMap.
/// Set to two Bitcoin difficulty periods (2016 blocks each) to bound
/// memory usage while retaining enough history for reorg detection.
const MAX_CHAIN_INDEX_SIZE: usize = 2016;

/// A tracked entry in the chain structure, linking a block
/// hash to its header info and the transactions it contains.
#[derive(Debug, Clone)]
pub struct ChainEntry {
    /// Block header info (height, hash, timestamp).
    pub info: L1BlockInfo,
    /// Hash of the parent block (prev_blockhash).
    pub parent_hash: [u8; 32],
    /// Transaction IDs included in this block (tracked for reorg invalidation).
    pub tx_ids: Vec<[u8; 32]>,
}

/// Status of a tracked deposit with respect to chain reorganizations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepositConfirmationStatus {
    /// Deposit is confirmed in the canonical chain with sufficient depth.
    Confirmed,
    /// Deposit was in a block that was orphaned during a reorg.
    /// Requires re-confirmation in the new canonical chain.
    Unconfirmed,
    /// Deposit is confirmed but has fewer than MIN_CONFIRMATIONS.
    Pending,
}

/// Result of a chain reorganization, identifying affected transactions.
#[derive(Debug, Clone)]
pub struct ReorgResult {
    /// Block hashes that were orphaned (removed from the canonical chain).
    pub orphaned_blocks: Vec<[u8; 32]>,
    /// Transaction IDs from orphaned blocks that need re-confirmation.
    pub orphaned_tx_ids: Vec<[u8; 32]>,
    /// The new best block hash after the reorg.
    pub new_best_hash: [u8; 32],
    /// The new best block height after the reorg.
    pub new_best_height: u64,
}

/// Monitors Bitcoin L1 for new blocks.
///
/// On each `poll()`, fetches any blocks produced since the last known height
/// and maintains a small in-memory cache of recent block headers.
///
/// ## Reorg Safety
///
/// The monitor detects chain reorganizations by verifying the hash at
/// `known_height` has not changed. If a reorg is detected, it returns
/// `BitcoinError::ChainReorg` so the caller can take appropriate action
/// (e.g., re-scan deposits, invalidate anchors).
///
/// ## Chain Structure
///
/// The monitor tracks a full chain structure (hash → entry) with
/// parent links, enabling fork detection and transaction invalidation
/// during reorganizations.
#[derive(Clone)]
pub struct BlockMonitor {
    /// Last known Bitcoin block height.
    known_height: u64,
    /// Cache of recent L1 block headers (newest at back).
    recent_blocks: VecDeque<L1BlockInfo>,
    /// Maximum number of blocks to keep in cache.
    max_cache: usize,
    // ── Reorg tracking fields ──────────────────────────────────────
    /// Chain structure: block_hash → ChainEntry (header + parent + txs).
    chain_index: HashMap<[u8; 32], ChainEntry>,
    /// Hash of the current best (tip) block.
    best_block_hash: Option<[u8; 32]>,
    /// Height of the current best (tip) block.
    best_block_height: u64,
    /// Deposits that have been invalidated by reorgs and need re-confirmation.
    orphaned_deposits: HashSet<[u8; 32]>,
}

impl BlockMonitor {
    /// Create a new block monitor starting from height 0.
    ///
    /// **Warning:** On first poll, this will fetch up to `MAX_CATCHUP_BLOCKS`
    /// blocks. For a node that has never synced, use `with_height()` to start
    /// from a recent height, or let the first poll auto-clamp.
    pub fn new() -> Self {
        Self {
            known_height: 0,
            recent_blocks: VecDeque::new(),
            max_cache: MAX_L1_BLOCK_CACHE,
            chain_index: HashMap::new(),
            best_block_hash: None,
            best_block_height: 0,
            orphaned_deposits: HashSet::new(),
        }
    }

    /// Create a monitor starting from a known height (e.g., loaded from disk).
    ///
    /// This is the recommended constructor for production use. It avoids
    /// fetching the entire chain history on first poll.
    pub fn with_height(height: u64) -> Self {
        Self {
            known_height: height,
            recent_blocks: VecDeque::new(),
            max_cache: MAX_L1_BLOCK_CACHE,
            chain_index: HashMap::new(),
            best_block_hash: None,
            best_block_height: height,
            orphaned_deposits: HashSet::new(),
        }
    }

    /// Poll Bitcoin for new blocks since the last known height.
    ///
    /// Returns only *newly discovered* blocks (empty vec if no new blocks).
    ///
    /// ## Reorg Detection
    ///
    /// If the chain tip is lower than our known height, or the hash at our
    /// known height has changed, this returns `BitcoinError::ChainReorg`.
    /// The caller should then reset the monitor and re-scan.
    ///
    /// ## Catch-up Limit
    ///
    /// At most `MAX_CATCHUP_BLOCKS` (100) blocks are fetched per poll to
    /// prevent blocking the thread for minutes on first sync.
    pub fn poll(&mut self, rpc: &dyn BitcoinRpc) -> Result<Vec<L1BlockInfo>, BitcoinError> {
        let chain_height = rpc.get_block_count()?;

        // ── Reorg detection ──────────────────────────────────────────────
        if chain_height < self.known_height {
            warn!(
                "Chain reorg detected: chain_height={} < known_height={}",
                chain_height, self.known_height
            );
            return Err(BitcoinError::ChainReorg {
                expected: self.known_height,
                actual: chain_height,
            });
        }

        // Verify hash at known_height hasn't changed (deeper reorg check)
        if self.known_height > 0
            && let Some(cached) = self.recent_blocks.back()
            && cached.height == self.known_height
        {
            match rpc.get_block_hash(self.known_height) {
                Ok(current_hash) => {
                    if current_hash != cached.hash {
                        warn!(
                            "Chain reorg detected: hash mismatch at height {}",
                            self.known_height
                        );
                        return Err(BitcoinError::ChainReorg {
                            expected: self.known_height,
                            actual: chain_height,
                        });
                    }
                }
                Err(_) => {
                    // Block no longer exists at known_height → reorg
                    return Err(BitcoinError::ChainReorg {
                        expected: self.known_height,
                        actual: chain_height,
                    });
                }
            }
        }

        if chain_height == self.known_height {
            return Ok(vec![]);
        }

        // ── Catch-up with limit ──────────────────────────────────────────
        let start = self.known_height.saturating_add(1);
        let end = chain_height.min(start.saturating_add(MAX_CATCHUP_BLOCKS - 1));

        if chain_height > end {
            debug!(
                "L1 catch-up limited: fetching blocks {}-{} of {} total (will continue next poll)",
                start,
                end,
                chain_height - self.known_height,
            );
        }

        let mut new_blocks = Vec::new();

        // Fetch each new block header
        for h in start..=end {
            match rpc.get_block_info(h) {
                Ok(info) => {
                    self.recent_blocks.push_back(info.clone());
                    new_blocks.push(info);
                }
                Err(e) => {
                    // Stop at first failure — we'll retry on next poll
                    debug!("Failed to fetch L1 block {}: {}", h, e);
                    break;
                }
            }
        }

        // Trim cache to max size
        while self.recent_blocks.len() > self.max_cache {
            self.recent_blocks.pop_front();
        }

        // Update known height to the last successfully fetched block
        if let Some(last) = new_blocks.last() {
            self.known_height = last.height;
        }

        Ok(new_blocks)
    }

    /// Reset the monitor after a reorg is detected.
    ///
    /// Sets the known height to a safe point (e.g., `reorg_height - depth`)
    /// and clears the cache.
    pub fn reset_to(&mut self, height: u64) {
        self.known_height = height;
        self.recent_blocks.clear();
        // Prune chain_index entries above the reset height.
        self.chain_index
            .retain(|_, entry| entry.info.height <= height);
        self.best_block_height = height;
        // Try to find the best block hash at the reset height.
        self.best_block_hash = self
            .chain_index
            .iter()
            .find(|(_, entry)| entry.info.height == height)
            .map(|(hash, _)| *hash);
    }

    /// Current known Bitcoin block height.
    pub fn height(&self) -> u64 {
        self.known_height
    }

    /// Hash of the latest known Bitcoin block (if any).
    pub fn latest_hash(&self) -> Option<[u8; 32]> {
        self.recent_blocks.back().map(|b| b.hash)
    }

    /// Check if a specific block hash is in the recent cache.
    pub fn has_block(&self, hash: &[u8; 32]) -> bool {
        self.recent_blocks.iter().any(|b| &b.hash == hash)
    }

    /// Check if a block is in the canonical best chain.
    ///
    /// Walks backwards from `best_block_hash` through parent links to see
    /// if the given hash is an ancestor of the current tip.
    pub fn is_in_best_chain(&self, hash: &[u8; 32]) -> bool {
        // If it's in the recent_blocks cache, it's canonical.
        if self.has_block(hash) {
            return true;
        }
        // Walk the chain_index from the tip.
        let mut current = self.best_block_hash;
        while let Some(cur_hash) = current {
            if &cur_hash == hash {
                return true;
            }
            current = self
                .chain_index
                .get(&cur_hash)
                .map(|entry| entry.parent_hash);
        }
        false
    }

    /// Number of blocks currently in the cache.
    pub fn cache_len(&self) -> usize {
        self.recent_blocks.len()
    }

    // ── Reorg tracking methods ─────────────────────────────────────────

    /// Get the current best block hash.
    pub fn best_block_hash(&self) -> Option<[u8; 32]> {
        self.best_block_hash
    }

    /// Get the current best block height.
    pub fn best_block_height(&self) -> u64 {
        self.best_block_height
    }

    /// Register a new block header in the chain structure.
    ///
    /// Checks if the new header extends the current tip or creates a fork.
    /// If a fork becomes the longest chain (reorg), returns a `ReorgResult`
    /// identifying all transactions in orphaned blocks.
    ///
    /// `parent_hash` is the prev_blockhash from the Bitcoin block header.
    /// `tx_ids` are the transaction IDs included in this block.
    pub fn register_block(
        &mut self,
        info: L1BlockInfo,
        parent_hash: [u8; 32],
        tx_ids: Vec<[u8; 32]>,
    ) -> Option<ReorgResult> {
        let block_hash = info.hash;
        let block_height = info.height;

        let entry = ChainEntry {
            info: info.clone(),
            parent_hash,
            tx_ids,
        };

        // Insert into chain index.
        self.chain_index.insert(block_hash, entry);

        // Evict old entries if chain_index exceeds the maximum size.
        if self.chain_index.len() > MAX_CHAIN_INDEX_SIZE {
            let cutoff = self
                .best_block_height
                .saturating_sub(MAX_CHAIN_INDEX_SIZE as u64);
            self.chain_index.retain(|_, e| e.info.height >= cutoff);
        }

        // Case 1: No best block yet (first block registered).
        if self.best_block_hash.is_none() {
            self.best_block_hash = Some(block_hash);
            self.best_block_height = block_height;
            info!("M-08: Initial best block set to height {}", block_height);
            return None;
        }

        let current_best = self.best_block_hash.unwrap();

        // Case 2: Extends the current tip (normal case).
        if parent_hash == current_best {
            self.best_block_hash = Some(block_hash);
            self.best_block_height = block_height;
            return None;
        }

        // Case 3: Fork detected. Check if the new chain is longer.
        if block_height > self.best_block_height {
            // New chain is longer → reorganization.
            warn!(
                "M-08: Chain reorganization detected! Old tip at height {}, new tip at height {}",
                self.best_block_height, block_height
            );

            // Find the fork point by walking both chains back.
            let orphaned = self.find_orphaned_blocks(&current_best, &block_hash);
            let orphaned_tx_ids: Vec<[u8; 32]> = orphaned
                .iter()
                .flat_map(|hash| {
                    self.chain_index
                        .get(hash)
                        .map(|e| e.tx_ids.clone())
                        .unwrap_or_default()
                })
                .collect();

            // Mark affected deposits as orphaned.
            for tx_id in &orphaned_tx_ids {
                self.orphaned_deposits.insert(*tx_id);
            }

            let result = ReorgResult {
                orphaned_blocks: orphaned,
                orphaned_tx_ids,
                new_best_hash: block_hash,
                new_best_height: block_height,
            };

            // Update best block.
            self.best_block_hash = Some(block_hash);
            self.best_block_height = block_height;

            Some(result)
        } else {
            // Fork exists but is not longer — ignore it.
            debug!(
                "M-08: Fork block at height {} (tip is {}), ignoring shorter fork",
                block_height, self.best_block_height
            );
            None
        }
    }

    /// Find blocks that are in the old chain but not in the new chain.
    fn find_orphaned_blocks(&self, old_tip: &[u8; 32], new_tip: &[u8; 32]) -> Vec<[u8; 32]> {
        // Collect ancestors of the old tip.
        let mut old_chain = HashSet::new();
        let mut current = Some(*old_tip);
        while let Some(hash) = current {
            old_chain.insert(hash);
            current = self.chain_index.get(&hash).map(|e| e.parent_hash);
        }

        // Walk the new chain and find the fork point.
        let mut new_chain = HashSet::new();
        let mut current = Some(*new_tip);
        while let Some(hash) = current {
            new_chain.insert(hash);
            if old_chain.contains(&hash) {
                break; // Fork point found.
            }
            current = self.chain_index.get(&hash).map(|e| e.parent_hash);
        }

        // Orphaned = old_chain - new_chain (blocks only in old chain, above fork point).
        old_chain.difference(&new_chain).copied().collect()
    }

    /// Check the confirmation status of a deposit transaction.
    ///
    /// Returns:
    /// - `Unconfirmed` if the transaction's block was orphaned in a reorg.
    /// - `Pending` if confirmed but with fewer than `MIN_CONFIRMATIONS`.
    /// - `Confirmed` if confirmed with sufficient depth.
    pub fn deposit_status(
        &self,
        tx_id: &[u8; 32],
        block_hash: &[u8; 32],
    ) -> DepositConfirmationStatus {
        // Check if this tx was orphaned by a reorg.
        if self.orphaned_deposits.contains(tx_id) {
            return DepositConfirmationStatus::Unconfirmed;
        }

        // Check if the block is in the best chain.
        if !self.is_in_best_chain(block_hash) {
            return DepositConfirmationStatus::Unconfirmed;
        }

        // Check confirmation depth.
        if let Some(entry) = self.chain_index.get(block_hash) {
            let depth = self.best_block_height.saturating_sub(entry.info.height) + 1;
            if depth >= MIN_CONFIRMATIONS as u64 {
                DepositConfirmationStatus::Confirmed
            } else {
                DepositConfirmationStatus::Pending
            }
        } else {
            // Block not in our chain index — treat as unconfirmed.
            DepositConfirmationStatus::Unconfirmed
        }
    }

    /// Clear an orphaned deposit after it has been re-confirmed
    /// in the new canonical chain.
    pub fn clear_orphaned_deposit(&mut self, tx_id: &[u8; 32]) {
        self.orphaned_deposits.remove(tx_id);
    }

    /// Number of entries in the chain index.
    pub fn chain_index_len(&self) -> usize {
        self.chain_index.len()
    }
}

impl Default for BlockMonitor {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_monitor_starts_at_zero() {
        let monitor = BlockMonitor::new();
        assert_eq!(monitor.height(), 0);
        assert!(monitor.latest_hash().is_none());
        assert_eq!(monitor.cache_len(), 0);
    }

    #[test]
    fn with_height_starts_at_given() {
        let monitor = BlockMonitor::with_height(800_000);
        assert_eq!(monitor.height(), 800_000);
        assert!(monitor.latest_hash().is_none());
    }

    #[test]
    fn has_block_empty_cache() {
        let monitor = BlockMonitor::new();
        assert!(!monitor.has_block(&[0xFF; 32]));
    }

    #[test]
    fn default_creates_new() {
        let monitor = BlockMonitor::default();
        assert_eq!(monitor.height(), 0);
    }

    #[test]
    fn reset_to_clears_cache() {
        let mut monitor = BlockMonitor::with_height(100);
        monitor.recent_blocks.push_back(L1BlockInfo {
            height: 100,
            hash: [0xAA; 32],
            timestamp: 1_700_000_000,
        });
        assert_eq!(monitor.cache_len(), 1);

        monitor.reset_to(50);
        assert_eq!(monitor.height(), 50);
        assert_eq!(monitor.cache_len(), 0);
    }

    #[test]
    fn max_catchup_blocks_constant() {
        // Ensures the catch-up limit is reasonable
        assert!(MAX_CATCHUP_BLOCKS >= 10);
        assert!(MAX_CATCHUP_BLOCKS <= 1000);
    }

    // ── Reorg tracking tests ───────────────────────────────────────────

    fn block_info(height: u64, hash_byte: u8) -> L1BlockInfo {
        L1BlockInfo {
            height,
            hash: [hash_byte; 32],
            timestamp: 1_700_000_000 + height,
        }
    }

    #[test]
    fn m08_register_first_block_sets_best() {
        let mut monitor = BlockMonitor::new();
        let info = block_info(1, 0x01);
        let result = monitor.register_block(info, [0x00; 32], vec![]);
        assert!(result.is_none());
        assert_eq!(monitor.best_block_height(), 1);
        assert_eq!(monitor.best_block_hash(), Some([0x01; 32]));
    }

    #[test]
    fn m08_extending_tip_no_reorg() {
        let mut monitor = BlockMonitor::new();
        // Block 1
        monitor.register_block(block_info(1, 0x01), [0x00; 32], vec![]);
        // Block 2 extends block 1
        let result = monitor.register_block(block_info(2, 0x02), [0x01; 32], vec![]);
        assert!(result.is_none());
        assert_eq!(monitor.best_block_height(), 2);
        assert_eq!(monitor.best_block_hash(), Some([0x02; 32]));
    }

    #[test]
    fn m08_fork_shorter_chain_ignored() {
        let mut monitor = BlockMonitor::new();
        // Main chain: 1 → 2 → 3
        monitor.register_block(block_info(1, 0x01), [0x00; 32], vec![]);
        monitor.register_block(block_info(2, 0x02), [0x01; 32], vec![]);
        monitor.register_block(block_info(3, 0x03), [0x02; 32], vec![]);
        // Fork: 1 → 2' (height 2, shorter than main chain at 3)
        let result = monitor.register_block(block_info(2, 0xF2), [0x01; 32], vec![]);
        assert!(result.is_none()); // shorter fork ignored
        assert_eq!(monitor.best_block_height(), 3);
    }

    #[test]
    fn m08_fork_longer_chain_triggers_reorg() {
        let mut monitor = BlockMonitor::new();
        // Main chain: 1 → 2
        monitor.register_block(block_info(1, 0x01), [0x00; 32], vec![[0xAA; 32]]);
        monitor.register_block(
            block_info(2, 0x02),
            [0x01; 32],
            vec![[0xBB; 32]], // tx in block 2
        );
        // Fork chain: 1 → 2' → 3' (longer)
        monitor.register_block(block_info(2, 0xF2), [0x01; 32], vec![]);
        let result = monitor.register_block(block_info(3, 0xF3), [0xF2; 32], vec![]);
        assert!(result.is_some());
        let reorg = result.unwrap();
        assert_eq!(reorg.new_best_height, 3);
        assert_eq!(reorg.new_best_hash, [0xF3; 32]);
        // Block 2 (0x02) should be orphaned — its tx [0xBB] should be in orphaned list.
        assert!(reorg.orphaned_blocks.contains(&[0x02; 32]));
        assert!(reorg.orphaned_tx_ids.contains(&[0xBB; 32]));
    }

    #[test]
    fn m08_deposit_status_confirmed() {
        let mut monitor = BlockMonitor::new();
        // Build a chain of 7 blocks.
        let tx_id = [0xAA; 32];
        monitor.register_block(block_info(1, 0x01), [0x00; 32], vec![tx_id]);
        for i in 2..=7 {
            monitor.register_block(block_info(i, i as u8), [(i - 1) as u8; 32], vec![]);
        }
        // tx at height 1, tip at height 7 → depth = 7 >= MIN_CONFIRMATIONS (6)
        let status = monitor.deposit_status(&tx_id, &[0x01; 32]);
        assert_eq!(status, DepositConfirmationStatus::Confirmed);
    }

    #[test]
    fn m08_deposit_status_pending() {
        let mut monitor = BlockMonitor::new();
        let tx_id = [0xAA; 32];
        monitor.register_block(block_info(1, 0x01), [0x00; 32], vec![tx_id]);
        // Only 3 blocks total → depth = 3 < 6
        for i in 2..=3 {
            monitor.register_block(block_info(i, i as u8), [(i - 1) as u8; 32], vec![]);
        }
        let status = monitor.deposit_status(&tx_id, &[0x01; 32]);
        assert_eq!(status, DepositConfirmationStatus::Pending);
    }

    #[test]
    fn m08_deposit_status_unconfirmed_after_reorg() {
        let mut monitor = BlockMonitor::new();
        let tx_id = [0xBB; 32];
        // Main chain: 1 → 2 (tx in block 2)
        monitor.register_block(block_info(1, 0x01), [0x00; 32], vec![]);
        monitor.register_block(block_info(2, 0x02), [0x01; 32], vec![tx_id]);
        // Fork: 1 → 2' → 3' (reorg orphans block 2)
        monitor.register_block(block_info(2, 0xF2), [0x01; 32], vec![]);
        monitor.register_block(block_info(3, 0xF3), [0xF2; 32], vec![]);
        let status = monitor.deposit_status(&tx_id, &[0x02; 32]);
        assert_eq!(status, DepositConfirmationStatus::Unconfirmed);
    }

    #[test]
    fn m08_clear_orphaned_deposit() {
        let mut monitor = BlockMonitor::new();
        let tx_id = [0xBB; 32];
        monitor.register_block(block_info(1, 0x01), [0x00; 32], vec![]);
        monitor.register_block(block_info(2, 0x02), [0x01; 32], vec![tx_id]);
        monitor.register_block(block_info(2, 0xF2), [0x01; 32], vec![]);
        monitor.register_block(block_info(3, 0xF3), [0xF2; 32], vec![]);
        // Tx is orphaned.
        assert_eq!(
            monitor.deposit_status(&tx_id, &[0x02; 32]),
            DepositConfirmationStatus::Unconfirmed
        );
        // Clear the orphaned status after re-confirmation.
        monitor.clear_orphaned_deposit(&tx_id);
        // Now it should not be in the orphaned set, but block 0x02 is
        // still not in best chain → still Unconfirmed.
        assert_eq!(
            monitor.deposit_status(&tx_id, &[0x02; 32]),
            DepositConfirmationStatus::Unconfirmed
        );
    }

    #[test]
    fn m08_min_confirmations_constant() {
        assert_eq!(MIN_CONFIRMATIONS, 6);
    }

    #[test]
    fn m08_is_in_best_chain() {
        let mut monitor = BlockMonitor::new();
        monitor.register_block(block_info(1, 0x01), [0x00; 32], vec![]);
        monitor.register_block(block_info(2, 0x02), [0x01; 32], vec![]);
        monitor.register_block(block_info(3, 0x03), [0x02; 32], vec![]);

        assert!(monitor.is_in_best_chain(&[0x01; 32]));
        assert!(monitor.is_in_best_chain(&[0x02; 32]));
        assert!(monitor.is_in_best_chain(&[0x03; 32]));
        assert!(!monitor.is_in_best_chain(&[0xFF; 32]));
    }
}
