//! Shadow block processing — replay Bitcoin blocks through Brrq logic.

use crate::BitcoinError;
use crate::canary::readonly_client::ReadOnlyBitcoinClient;
use crate::types::L1BlockInfo;

/// Report from shadow processing a range of blocks.
#[derive(Debug, Clone)]
pub struct ShadowReport {
    /// First block height processed.
    pub from_height: u64,
    /// Last block height processed.
    pub to_height: u64,
    /// Number of blocks processed.
    pub blocks_processed: u64,
    /// Total deposits found in the range.
    pub deposits_found: u64,
    /// Total anchors verified in the range.
    pub anchors_verified: u64,
    /// Blocks that had processing errors.
    pub error_heights: Vec<u64>,
    /// Block info for all processed blocks.
    pub block_infos: Vec<L1BlockInfo>,
}

/// Shadow processor — processes mainnet Bitcoin blocks through Brrq logic
/// without writing anything to the chain.
pub struct ShadowProcessor {
    btc: ReadOnlyBitcoinClient,
    last_processed_height: u64,
}

impl ShadowProcessor {
    /// Create a new shadow processor.
    pub fn new(btc: ReadOnlyBitcoinClient) -> Self {
        Self {
            btc,
            last_processed_height: 0,
        }
    }

    /// Process a range of blocks.
    pub fn process_range(&mut self, from: u64, to: u64) -> Result<ShadowReport, BitcoinError> {
        let mut report = ShadowReport {
            from_height: from,
            to_height: to,
            blocks_processed: 0,
            deposits_found: 0,
            anchors_verified: 0,
            error_heights: Vec::new(),
            block_infos: Vec::new(),
        };

        for height in from..=to {
            match self.process_block(height) {
                Ok(info) => {
                    report.block_infos.push(info);
                    report.blocks_processed += 1;
                }
                Err(_) => {
                    report.error_heights.push(height);
                }
            }
        }

        self.last_processed_height = to;
        Ok(report)
    }

    /// Process a single block at the given height.
    fn process_block(&self, height: u64) -> Result<L1BlockInfo, BitcoinError> {
        let info = self.btc.get_block_info(height)?;
        // In a full implementation, this would:
        // 1. Scan for deposits to the bridge address
        // 2. Verify any Brrq anchors in the block
        // 3. Track state transitions
        // For now, we just fetch and validate block info
        Ok(info)
    }

    /// Get the last processed height.
    pub fn last_processed_height(&self) -> u64 {
        self.last_processed_height
    }

    /// Get the current chain tip height.
    pub fn tip_height(&self) -> Result<u64, BitcoinError> {
        self.btc.get_block_count()
    }
}
