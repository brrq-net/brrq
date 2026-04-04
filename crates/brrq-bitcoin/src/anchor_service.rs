//! Anchor service — posts Brrq state commitments to Bitcoin via OP_RETURN.
//!
//! Each anchor contains:
//! - State root (32 bytes) — proves the entire L2 state at that height
//! - L2 height (8 bytes) — identifies which batch
//! - Proof hash (32 bytes) — links to the STARK batch proof
//!
//! Total: 76 bytes per anchor, well within the 80-byte OP_RETURN limit.
//!
//! ## Idempotency
//!
//! The service prevents posting duplicate anchors for the same L2 height.
//! If `post_anchor` is called for a height that was already posted, it
//! returns `BitcoinError::DuplicateAnchor`.

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use brrq_crypto::hash::Hash256;

use crate::error::BitcoinError;
use crate::rpc_client::BitcoinRpc;
use crate::types::{AnchorData, L1AnchorRecord};

/// Maximum anchor records kept in memory.
///
/// Only confirmed anchors at the front of the Vec are evicted.
/// This prevents unbounded growth on long-running nodes.
const MAX_ANCHOR_RECORDS: usize = 10_000;

/// Service for posting L2 state commitments to Bitcoin L1.
pub struct AnchorService {
    /// Posted anchor records (newest at end).
    posted_anchors: Vec<L1AnchorRecord>,
}

impl AnchorService {
    /// Create a new anchor service.
    pub fn new() -> Self {
        Self {
            posted_anchors: Vec::new(),
        }
    }

    /// Post a state commitment to Bitcoin L1 via OP_RETURN.
    ///
    /// Steps:
    /// 1. Check for duplicate (already posted for this L2 height)
    /// 2. Build the 76-byte anchor payload
    /// 3. Create a funded + signed OP_RETURN transaction via bitcoind wallet
    /// 4. Broadcast the transaction
    /// 5. Record the anchor
    ///
    /// Returns `BitcoinError::DuplicateAnchor` if an anchor was already posted
    /// for the given `l2_height`.
    pub fn post_anchor(
        &mut self,
        rpc: &dyn BitcoinRpc,
        state_root: Hash256,
        l2_height: u64,
        proof_hash: Hash256,
    ) -> Result<L1AnchorRecord, BitcoinError> {
        // ── Idempotency check ────────────────────────────────────────────
        if self.posted_anchors.iter().any(|a| a.l2_height == l2_height) {
            return Err(BitcoinError::DuplicateAnchor(l2_height));
        }

        let anchor_data = AnchorData {
            state_root,
            l2_height,
            proof_hash,
        };

        let payload = anchor_data.to_bytes();
        debug!(
            "Posting L1 anchor: l2_height={}, state_root=0x{}, payload={} bytes",
            l2_height,
            hex::encode(state_root.as_bytes()),
            payload.len(),
        );

        // Create and sign the OP_RETURN transaction via bitcoind's wallet
        let signed_hex = rpc.create_op_return_tx(&payload)?;

        // Broadcast
        let txid = rpc.send_signed_tx(&signed_hex)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|e| {
                warn!("System clock before Unix epoch: {}", e);
                std::time::Duration::ZERO
            })
            .as_secs();

        let record = L1AnchorRecord {
            l1_tx_id: txid,
            l1_height: 0, // Updated when tx confirms (see update_confirmation)
            l2_height,
            block_hash: [0u8; 32],
            state_root,
            proof_hash,
            timestamp: now,
        };

        info!(
            "L1 anchor posted: l2_height={}, l1_txid={}",
            l2_height,
            hex::encode(txid),
        );

        self.posted_anchors.push(record.clone());

        // Evict oldest confirmed anchors if over capacity.
        if self.posted_anchors.len() > MAX_ANCHOR_RECORDS {
            // Count how many confirmed records we can safely evict from the front.
            let evict_count = self
                .posted_anchors
                .iter()
                .take(self.posted_anchors.len() - MAX_ANCHOR_RECORDS)
                .filter(|a| a.l1_height > 0)
                .count();
            if evict_count > 0 {
                // Remove confirmed entries from the front
                let mut evicted = 0;
                self.posted_anchors.retain(|a| {
                    if evicted < evict_count && a.l1_height > 0 {
                        evicted += 1;
                        false
                    } else {
                        true
                    }
                });
                debug!(
                    "Evicted {} confirmed anchor records (cap={})",
                    evict_count, MAX_ANCHOR_RECORDS
                );
            }
        }

        Ok(record)
    }

    /// Update confirmation status for a posted anchor.
    ///
    /// Called when we detect the anchor transaction in a confirmed Bitcoin block.
    pub fn update_confirmation(&mut self, l2_height: u64, l1_block_height: u64) -> bool {
        for anchor in &mut self.posted_anchors {
            if anchor.l2_height == l2_height && anchor.l1_height == 0 {
                anchor.l1_height = l1_block_height;
                info!(
                    "L1 anchor confirmed: l2_height={}, l1_block_height={}",
                    l2_height, l1_block_height,
                );
                return true;
            }
        }
        false
    }

    /// Get all posted anchor records.
    pub fn anchors(&self) -> &[L1AnchorRecord] {
        &self.posted_anchors
    }

    /// Get the most recently posted anchor.
    pub fn latest_anchor(&self) -> Option<&L1AnchorRecord> {
        self.posted_anchors.last()
    }

    /// Number of anchors posted.
    pub fn anchor_count(&self) -> usize {
        self.posted_anchors.len()
    }

    /// Number of anchors that have been confirmed on L1.
    pub fn confirmed_anchor_count(&self) -> usize {
        self.posted_anchors
            .iter()
            .filter(|a| a.l1_height > 0)
            .count()
    }

    /// Number of anchors still pending confirmation.
    pub fn pending_anchor_count(&self) -> usize {
        self.posted_anchors
            .iter()
            .filter(|a| a.l1_height == 0)
            .count()
    }

    /// Check pending anchors for L1 confirmations via Bitcoin RPC.
    ///
    /// Queries `getrawtransaction` (verbose) for each unconfirmed anchor to see
    /// whether it has been included in a Bitcoin block. Returns the L2 heights
    /// of newly confirmed anchors.
    pub fn check_confirmations(&mut self, rpc: &dyn BitcoinRpc) -> Vec<u64> {
        let mut newly_confirmed = Vec::new();

        for anchor in &mut self.posted_anchors {
            // Skip already confirmed
            if anchor.l1_height > 0 {
                continue;
            }

            match rpc.get_tx_block_info(&anchor.l1_tx_id) {
                Ok(Some((_block_hash, block_height, _confirmations))) => {
                    anchor.l1_height = block_height;
                    info!(
                        "L1 anchor confirmed: l2_height={}, l1_block_height={}",
                        anchor.l2_height, block_height,
                    );
                    newly_confirmed.push(anchor.l2_height);
                }
                Ok(None) => {
                    // Still unconfirmed — normal for recent broadcasts
                    debug!(
                        "L1 anchor still pending: l2_height={}, l1_txid={}",
                        anchor.l2_height,
                        hex::encode(anchor.l1_tx_id),
                    );
                }
                Err(e) => {
                    warn!(
                        "Failed to check anchor confirmation for l2_height={}: {}",
                        anchor.l2_height, e,
                    );
                }
            }
        }

        newly_confirmed
    }

    /// Load anchor records from persistent storage (called at startup).
    ///
    /// **Note:** This replaces any in-memory records. Call this at startup
    /// before posting new anchors to avoid losing persisted data.
    pub fn load_anchors(&mut self, records: Vec<L1AnchorRecord>) {
        self.posted_anchors = records;
    }

    /// Add a single anchor record (e.g., loaded from sled).
    ///
    /// Skips duplicates (by L2 height) to prevent double-counting.
    pub fn add_anchor(&mut self, record: L1AnchorRecord) {
        if !self
            .posted_anchors
            .iter()
            .any(|a| a.l2_height == record.l2_height)
        {
            self.posted_anchors.push(record);
        }
    }
}

impl Default for AnchorService {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(l2_height: u64, confirmed: u64) -> L1AnchorRecord {
        L1AnchorRecord {
            l1_tx_id: [l2_height as u8; 32],
            l1_height: confirmed,
            l2_height,
            block_hash: [0u8; 32],
            state_root: Hash256::from_bytes([0xAA; 32]),
            proof_hash: Hash256::from_bytes([0xBB; 32]),
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn new_service_is_empty() {
        let service = AnchorService::new();
        assert_eq!(service.anchor_count(), 0);
        assert!(service.latest_anchor().is_none());
        assert!(service.anchors().is_empty());
    }

    #[test]
    fn load_anchors_from_storage() {
        let mut service = AnchorService::new();

        let records = vec![make_record(100, 800_000), make_record(200, 800_010)];

        service.load_anchors(records);
        assert_eq!(service.anchor_count(), 2);
        assert_eq!(service.latest_anchor().unwrap().l2_height, 200);
    }

    #[test]
    fn add_single_anchor() {
        let mut service = AnchorService::new();
        service.add_anchor(make_record(50, 0));
        assert_eq!(service.anchor_count(), 1);
        assert_eq!(service.latest_anchor().unwrap().l2_height, 50);
    }

    #[test]
    fn add_duplicate_anchor_is_skipped() {
        let mut service = AnchorService::new();
        service.add_anchor(make_record(50, 0));
        service.add_anchor(make_record(50, 0)); // duplicate
        assert_eq!(service.anchor_count(), 1);
    }

    #[test]
    fn default_creates_empty() {
        let service = AnchorService::default();
        assert_eq!(service.anchor_count(), 0);
    }

    #[test]
    fn update_confirmation_sets_block_height() {
        let mut service = AnchorService::new();
        service.add_anchor(make_record(100, 0)); // unconfirmed
        assert_eq!(service.pending_anchor_count(), 1);
        assert_eq!(service.confirmed_anchor_count(), 0);

        let updated = service.update_confirmation(100, 850_000);
        assert!(updated);
        assert_eq!(service.pending_anchor_count(), 0);
        assert_eq!(service.confirmed_anchor_count(), 1);
        assert_eq!(service.anchors()[0].l1_height, 850_000);
    }

    #[test]
    fn update_confirmation_not_found() {
        let mut service = AnchorService::new();
        let updated = service.update_confirmation(999, 850_000);
        assert!(!updated);
    }

    #[test]
    fn update_confirmation_already_confirmed_no_double_update() {
        let mut service = AnchorService::new();
        service.add_anchor(make_record(100, 800_000)); // already confirmed
        let updated = service.update_confirmation(100, 850_000); // should not update
        assert!(!updated);
        assert_eq!(service.anchors()[0].l1_height, 800_000); // unchanged
    }
}
