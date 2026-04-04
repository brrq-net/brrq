//! L1-specific types for Bitcoin integration.

use brrq_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

/// Magic bytes at the start of every Brrq OP_RETURN payload.
pub const ANCHOR_MAGIC: [u8; 4] = *b"BRRQ";

/// Total size of the OP_RETURN anchor payload (76 bytes, fits in 80-byte limit).
///
/// Layout: `[magic:4][state_root:32][l2_height:8 LE][proof_hash:32]`
pub const ANCHOR_DATA_SIZE: usize = 76;

/// Default L2 blocks between L1 anchor postings.
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 100;

/// Default Bitcoin RPC poll interval in seconds.
pub const DEFAULT_POLL_INTERVAL_SECS: u64 = 30;

/// Maximum recent L1 blocks to cache in memory.
pub const MAX_L1_BLOCK_CACHE: usize = 10;

/// Minimum confirmations before a deposit is accepted.
/// Zero-confirmation deposits are a security risk (RBF/double-spend).
pub const MIN_DEPOSIT_CONFIRMATIONS: u32 = 6;

/// Maximum number of blocks to fetch in a single catch-up poll.
/// Prevents fetching 850,000+ blocks when starting from height 0 on mainnet.
pub const MAX_CATCHUP_BLOCKS: u64 = 100;

/// Maximum known deposits to track in memory before pruning oldest.
pub const MAX_KNOWN_DEPOSITS: usize = 100_000;

/// Minimum deposit amount in satoshis.
///
/// Deposits below this threshold are rejected to prevent:
/// - Dust attacks (spamming the bridge with uneconomical deposits)
/// - Gas-cost griefing (L2 minting tx costs more than the deposit value)
///
/// 10,000 sats ≈ 0.0001 BTC — above Bitcoin's dust limit and economically
/// meaningful for L2 operations.
pub const MIN_DEPOSIT_SATS: u64 = 10_000;

/// Maximum deposit amount per single UTXO in satoshis.
///
/// Sanity check to reject clearly invalid deposit values that could indicate
/// RPC data corruption or a malformed UTXO. Set to 21M BTC (total supply).
pub const MAX_DEPOSIT_SATS: u64 = 21_000_000 * 100_000_000; // 2.1 quadrillion sats

// ── L1 Block Info ────────────────────────────────────────────────────────────

/// Information about a Bitcoin L1 block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1BlockInfo {
    /// Block height.
    pub height: u64,
    /// Block hash (32 bytes, big-endian as Bitcoin uses internally).
    pub hash: [u8; 32],
    /// Block timestamp (Unix seconds, u32 in Bitcoin protocol, stored as u64).
    pub timestamp: u64,
}

// ── Anchor Data (OP_RETURN payload) ──────────────────────────────────────────

/// Data embedded in a Bitcoin OP_RETURN output to anchor Brrq state on L1.
///
/// This is the core L2→L1 commitment: anyone can verify that the Brrq chain
/// committed to a specific state root at a given height by reading this from
/// the Bitcoin blockchain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorData {
    /// Brrq L2 state root (SHA-256 SMT root) after the anchored batch.
    pub state_root: Hash256,
    /// L2 block height at the anchor point.
    pub l2_height: u64,
    /// SHA-256 hash of the STARK batch proof covering this state transition.
    pub proof_hash: Hash256,
}

impl AnchorData {
    /// Serialize to 76-byte OP_RETURN payload.
    ///
    /// Layout: `[BRRQ:4][state_root:32][l2_height:8 LE][proof_hash:32]`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ANCHOR_DATA_SIZE);
        buf.extend_from_slice(&ANCHOR_MAGIC);
        buf.extend_from_slice(self.state_root.as_bytes());
        buf.extend_from_slice(&self.l2_height.to_le_bytes());
        buf.extend_from_slice(self.proof_hash.as_bytes());
        assert_eq!(
            buf.len(),
            ANCHOR_DATA_SIZE,
            "BUG: anchor payload size mismatch"
        );
        buf
    }

    /// Deserialize from 76-byte OP_RETURN payload.
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::BitcoinError> {
        if data.len() != ANCHOR_DATA_SIZE {
            return Err(crate::BitcoinError::InvalidAnchorData(format!(
                "expected {} bytes, got {}",
                ANCHOR_DATA_SIZE,
                data.len()
            )));
        }
        if data[0..4] != ANCHOR_MAGIC {
            return Err(crate::BitcoinError::InvalidAnchorData(format!(
                "invalid magic: expected {:?}, got {:?}",
                ANCHOR_MAGIC,
                &data[0..4]
            )));
        }

        let mut sr = [0u8; 32];
        sr.copy_from_slice(&data[4..36]);

        let mut height_bytes = [0u8; 8];
        height_bytes.copy_from_slice(&data[36..44]);
        let l2_height = u64::from_le_bytes(height_bytes);

        let mut ph = [0u8; 32];
        ph.copy_from_slice(&data[44..76]);

        Ok(Self {
            state_root: Hash256::from_bytes(sr),
            l2_height,
            proof_hash: Hash256::from_bytes(ph),
        })
    }
}

// ── L1 Anchor Record (persisted) ─────────────────────────────────────────────

/// A record of a state commitment posted to Bitcoin L1.
///
/// Stored in the sled `l1_anchors` tree for persistence across restarts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1AnchorRecord {
    /// Bitcoin transaction ID containing the OP_RETURN.
    pub l1_tx_id: [u8; 32],
    /// Bitcoin block height where the tx was confirmed (0 if unconfirmed).
    pub l1_height: u64,
    /// L2 block height at the anchor point.
    pub l2_height: u64,
    /// Bitcoin block hash for SPV root checks.
    pub block_hash: [u8; 32],
    /// L2 state root committed.
    pub state_root: Hash256,
    /// Hash of the STARK proof.
    pub proof_hash: Hash256,
    /// Unix timestamp when the anchor was posted.
    pub timestamp: u64,
}

// ── Deposit Event (from L1 scanning) ─────────────────────────────────────────

/// A raw deposit event detected on Bitcoin L1.
///
/// The `DepositWatcher` produces these; the sync loop converts them into
/// `bridge.process_deposit()` calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositEvent {
    /// Bitcoin transaction ID (32 bytes).
    pub btc_tx_id: [u8; 32],
    /// Output index within the Bitcoin transaction.
    pub btc_vout: u32,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// scriptPubKey of the output (for recipient derivation).
    pub recipient_script: Vec<u8>,
    /// Current number of confirmations.
    pub confirmations: u32,
}

// ── L1 Status (for API responses) ────────────────────────────────────────────

/// Current Bitcoin L1 connection status, returned by API endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1Status {
    /// Whether the node is connected to a Bitcoin L1 node.
    pub connected: bool,
    /// Current Bitcoin block height (None if never connected).
    pub l1_height: u64,
    /// Latest Bitcoin block hash (hex, None if not connected).
    pub l1_hash: Option<String>,
    /// Bitcoin network name.
    pub network: String,
    /// Total number of anchors posted to L1 (u64 for cross-platform serialization).
    pub anchor_count: u64,
    /// L2 height of the most recent anchor.
    pub last_anchor_l2_height: Option<u64>,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_data_roundtrip() {
        let data = AnchorData {
            state_root: Hash256::from_bytes([0xAA; 32]),
            l2_height: 12345,
            proof_hash: Hash256::from_bytes([0xBB; 32]),
        };
        let bytes = data.to_bytes();
        assert_eq!(bytes.len(), ANCHOR_DATA_SIZE);
        assert_eq!(&bytes[0..4], b"BRRQ");

        let decoded = AnchorData::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn anchor_data_zero_height() {
        let data = AnchorData {
            state_root: Hash256::ZERO,
            l2_height: 0,
            proof_hash: Hash256::ZERO,
        };
        let bytes = data.to_bytes();
        let decoded = AnchorData::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.l2_height, 0);
    }

    #[test]
    fn anchor_data_max_height() {
        let data = AnchorData {
            state_root: Hash256::ZERO,
            l2_height: u64::MAX,
            proof_hash: Hash256::ZERO,
        };
        let bytes = data.to_bytes();
        let decoded = AnchorData::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.l2_height, u64::MAX);
    }

    #[test]
    fn anchor_data_invalid_magic() {
        let mut bytes = vec![0u8; ANCHOR_DATA_SIZE];
        bytes[0..4].copy_from_slice(b"FAKE");
        assert!(AnchorData::from_bytes(&bytes).is_err());
    }

    #[test]
    fn anchor_data_wrong_size_too_small() {
        assert!(AnchorData::from_bytes(&[0u8; 10]).is_err());
    }

    #[test]
    fn anchor_data_wrong_size_too_large() {
        assert!(AnchorData::from_bytes(&[0u8; 100]).is_err());
    }

    #[test]
    fn anchor_data_preserves_state_root_bytes() {
        let sr: [u8; 32] = core::array::from_fn(|i| i as u8);
        let data = AnchorData {
            state_root: Hash256::from_bytes(sr),
            l2_height: 42,
            proof_hash: Hash256::ZERO,
        };
        let bytes = data.to_bytes();
        assert_eq!(&bytes[4..36], &sr);
    }

    #[test]
    fn l1_block_info_creation() {
        let info = L1BlockInfo {
            height: 800_000,
            hash: [0xFF; 32],
            timestamp: 1_700_000_000,
        };
        assert_eq!(info.height, 800_000);
    }

    #[test]
    fn l1_status_defaults() {
        let status = L1Status {
            connected: false,
            l1_height: 0,
            l1_hash: None,
            network: "regtest".into(),
            anchor_count: 0,
            last_anchor_l2_height: None,
        };
        assert!(!status.connected);
        assert_eq!(status.network, "regtest");
    }

    #[test]
    fn l1_anchor_record_serialization() {
        let record = L1AnchorRecord {
            l1_tx_id: [0xAA; 32],
            l1_height: 800_000,
            block_hash: [0u8; 32],
            l2_height: 100,
            state_root: Hash256::from_bytes([0xBB; 32]),
            proof_hash: Hash256::from_bytes([0xCC; 32]),
            timestamp: 1_700_000_000,
        };
        let bytes = bincode::serialize(&record).unwrap();
        let decoded: L1AnchorRecord = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded.l2_height, 100);
        assert_eq!(decoded.l1_height, 800_000);
    }

    #[test]
    fn deposit_event_creation() {
        let event = DepositEvent {
            btc_tx_id: [0x11; 32],
            btc_vout: 0,
            amount_sats: 100_000_000, // 1 BTC
            recipient_script: vec![0x00, 0x14, 0xAB],
            confirmations: 6,
        };
        assert_eq!(event.amount_sats, 100_000_000);
        assert_eq!(event.confirmations, 6);
    }

    #[test]
    fn anchor_magic_is_brrq() {
        assert_eq!(&ANCHOR_MAGIC, b"BRRQ");
    }

    #[test]
    fn deposit_bounds_are_sane() {
        // Minimum must be above Bitcoin dust limit (~546 sats for P2PKH)
        assert!(MIN_DEPOSIT_SATS >= 546);
        // Maximum must not exceed total Bitcoin supply
        assert!(MAX_DEPOSIT_SATS <= 21_000_000 * 100_000_000);
        // Min must be less than max
        assert!(MIN_DEPOSIT_SATS < MAX_DEPOSIT_SATS);
    }

    #[test]
    fn anchor_data_size_fits_op_return() {
        // OP_RETURN max is 80 bytes; we use 76
        assert!(ANCHOR_DATA_SIZE <= 80);
        assert_eq!(ANCHOR_DATA_SIZE, 4 + 32 + 8 + 32);
    }

    /// Validates whitepaper §16.1: "DA on L1 per batch < 400 bytes"
    ///
    /// The full L1 DA footprint per batch is:
    ///   anchor payload (76 bytes) + OP_RETURN overhead (~11 bytes) +
    ///   Bitcoin tx overhead (~140 bytes for 1-in 1-out) ≈ 227 bytes.
    ///
    /// Even with a wrapped SNARK proof (~300 bytes) in a second OP_RETURN
    /// output, the total stays well under 400 bytes.
    #[test]
    fn anchor_da_under_whitepaper_limit() {
        let data = AnchorData {
            state_root: Hash256::from_bytes([0xFF; 32]),
            l2_height: u64::MAX,
            proof_hash: Hash256::from_bytes([0xEE; 32]),
        };
        let payload = data.to_bytes();

        // OP_RETURN script: OP_RETURN (1) + OP_PUSHDATA1 (1) + len (1) + data
        let op_return_script_size = 1 + 1 + 1 + payload.len(); // 79 bytes

        // Minimal Bitcoin tx: version(4) + flag(2) + vin_count(1) + vin(41) +
        // vout_count(1) + vout_value(8) + vout_scriptlen(1) + vout_script(~79) +
        // change_vout(~34) + locktime(4) ≈ 175 bytes
        let btc_tx_overhead = 175;
        let total_da = op_return_script_size + btc_tx_overhead;

        // Whitepaper §16.1 claims < 400 bytes per batch
        assert!(
            total_da < 400,
            "DA per batch = {} bytes, exceeds 400-byte whitepaper claim",
            total_da,
        );
    }
}
