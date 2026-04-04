//! Data models for indexed blockchain data.

use serde::{Deserialize, Serialize};

/// Indexed block record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedBlock {
    pub height: u64,
    pub hash: String,
    pub parent_hash: String,
    pub timestamp: u64,
    pub tx_count: usize,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub state_root: String,
    pub sequencer: String,
    pub epoch: u64,
    pub size_bytes: usize,
}

/// Indexed transaction record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedTransaction {
    pub hash: String,
    pub block_height: u64,
    pub tx_index: usize,
    pub from_addr: String,
    pub to_addr: Option<String>,
    pub amount: Option<u64>,
    pub tx_type: String,
    pub gas_used: Option<u64>,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub nonce: u64,
    pub success: bool,
    pub created_at: u64,
}
