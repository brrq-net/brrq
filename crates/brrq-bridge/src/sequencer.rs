//! §5.1–5.2: Sequencer, Data Availability, and MEV Protection.
//!
//! # Yellow Paper Alignment
//!
//! **§5.1 Sequencer:** The entity that collects user transactions, orders them
//! into L2 blocks, executes them on the RISC-V VM, and produces STARK proofs.
//!
//! **Fundamental distinction from the Committee:**
//! - Sequencer = Block Producer (produces state transitions)
//! - Committee = Validator (attests to state transition validity)
//! - No single entity performs both roles.
//!
//! **§5.2 Data Availability:** Block data is published via:
//! 1. OP_RETURN on L1 (block header + Merkle root commitment) — mandatory
//! 2. Brrq P2P network (full transaction data) — mandatory
//! 3. No external DA layer (sovereignty preserved)
//!
//! **§5.1 MEV Protection:** Commit-Reveal for transaction privacy:
//! - Commit: User submits encrypted transaction hash
//! - Reveal: User reveals transaction content after ordering is committed
//! - Sequencer cannot see content before committing to order

use brrq_crypto::hash::{Hash256, Hasher};
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// §5.1 Sequencer Configuration
// ═══════════════════════════════════════════════════════════════

/// Maximum L2 blocks a sequencer can produce before mandatory rotation.
///
/// Prevents a single sequencer from holding ordering power indefinitely.
/// After this many blocks, the next registered sequencer takes over.
pub const SEQUENCER_ROTATION_BLOCKS: u64 = 28_800; // ~24 hours at 3s/block

/// Minimum number of registered sequencers for rotation policy.
///
/// With fewer than this, a single sequencer operates (no rotation).
pub const MIN_SEQUENCERS_FOR_ROTATION: usize = 2;

/// Maximum time (in L2 blocks) a sequencer can hold a transaction
/// in the commit phase before it must be revealed or dropped.
pub const COMMIT_REVEAL_WINDOW: u64 = 200; // ~10 minutes at 3s/block

/// Minimum bond a sequencer must post to register (satoshis).
///
/// Without a minimum bond, sequencers have zero economic
/// disincentive against censorship or MEV extraction.
pub const MIN_SEQUENCER_BOND: u64 = 100_000_000; // 1 BTC

/// Sequencer registration and state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerInfo {
    /// Sequencer's L2 address (identity).
    pub address: brrq_types::Address,
    /// Human-readable label (max 128 bytes).
    pub label: String,
    /// L2 block height when this sequencer was registered.
    pub registered_at: u64,
    /// Whether this sequencer is currently active.
    pub active: bool,
    /// Bond posted by the sequencer (satoshis).
    /// Sequencers must post a bond to prevent censorship/MEV abuse.
    pub bond: u64,
    /// Total blocks produced by this sequencer.
    pub blocks_produced: u64,
}

/// Sequencer manager — tracks registered sequencers and rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerManager {
    /// Registered sequencers.
    sequencers: Vec<SequencerInfo>,
    /// Index of the current active sequencer in the rotation.
    current_sequencer_idx: usize,
    /// L2 block height when the current sequencer started its turn.
    rotation_started_at: u64,
}

impl SequencerManager {
    /// Create a new sequencer manager.
    pub fn new() -> Self {
        Self {
            sequencers: Vec::new(),
            current_sequencer_idx: 0,
            rotation_started_at: 0,
        }
    }

    /// Register a new sequencer.
    pub fn register(
        &mut self,
        address: brrq_types::Address,
        label: String,
        bond: u64,
        current_height: u64,
    ) -> Result<(), SequencerError> {
        if label.len() > 128 {
            return Err(SequencerError::LabelTooLong);
        }
        // Enforce minimum bond to ensure economic accountability.
        if bond < MIN_SEQUENCER_BOND {
            return Err(SequencerError::InsufficientBond {
                required: MIN_SEQUENCER_BOND,
                provided: bond,
            });
        }
        if self.sequencers.iter().any(|s| s.address == address) {
            return Err(SequencerError::AlreadyRegistered);
        }
        self.sequencers.push(SequencerInfo {
            address,
            label,
            registered_at: current_height,
            active: true,
            bond,
            blocks_produced: 0,
        });
        Ok(())
    }

    /// Get the current active sequencer (based on rotation).
    pub fn current_sequencer(&self, current_height: u64) -> Option<&SequencerInfo> {
        let active: Vec<&SequencerInfo> = self.sequencers.iter().filter(|s| s.active).collect();
        if active.is_empty() {
            return None;
        }
        if active.len() < MIN_SEQUENCERS_FOR_ROTATION {
            return active.first().copied();
        }
        // Rotation: switch every SEQUENCER_ROTATION_BLOCKS
        let elapsed = current_height.saturating_sub(self.rotation_started_at);
        let rotation_count = elapsed / SEQUENCER_ROTATION_BLOCKS;
        let idx = (self.current_sequencer_idx + rotation_count as usize) % active.len();
        active.get(idx).copied()
    }

    /// Check if a given address is the current valid sequencer.
    pub fn is_current_sequencer(
        &self,
        address: &brrq_types::Address,
        current_height: u64,
    ) -> bool {
        self.current_sequencer(current_height)
            .map_or(false, |s| s.address == *address)
    }

    /// Number of registered (active) sequencers.
    pub fn active_count(&self) -> usize {
        self.sequencers.iter().filter(|s| s.active).count()
    }

    /// Deactivate a sequencer.
    ///
    /// Reset rotation state when a sequencer is deactivated.
    /// Without this, the rotation index and `rotation_started_at` become
    /// stale — the `%` arithmetic in `current_sequencer()` silently
    /// shifts which sequencer is selected.
    pub fn deactivate(
        &mut self,
        address: &brrq_types::Address,
        current_height: u64,
    ) -> Result<(), SequencerError> {
        let seq = self
            .sequencers
            .iter_mut()
            .find(|s| s.address == *address)
            .ok_or(SequencerError::NotFound)?;
        seq.active = false;

        // Reset rotation anchor so the schedule is recomputed from
        // the new active set. Without this, elapsed time accumulates
        // against a set that no longer matches the index arithmetic.
        self.rotation_started_at = current_height;
        self.current_sequencer_idx = 0;

        Ok(())
    }

    /// Validate that a sequencer is authorized to produce a block.
    ///
    /// This is the ENFORCING gate — block validation MUST call this before
    /// accepting any block. `is_current_sequencer()` is advisory;
    /// this method returns an error that rejects the block.
    pub fn validate_block_producer(
        &mut self,
        producer: &brrq_types::Address,
        current_height: u64,
    ) -> Result<(), SequencerError> {
        // If no sequencers registered, reject all blocks.
        if self.active_count() == 0 {
            return Err(SequencerError::NotFound);
        }

        // If only one active sequencer, skip rotation check.
        if self.active_count() < MIN_SEQUENCERS_FOR_ROTATION {
            let sole = self
                .sequencers
                .iter()
                .find(|s| s.active)
                .ok_or(SequencerError::NotFound)?;
            if sole.address != *producer {
                return Err(SequencerError::NotCurrentSequencer);
            }
        } else if !self.is_current_sequencer(producer, current_height) {
            return Err(SequencerError::NotCurrentSequencer);
        }

        // Increment blocks_produced for the producing sequencer.
        if let Some(seq) = self.sequencers.iter_mut().find(|s| s.address == *producer) {
            seq.blocks_produced += 1;
        }

        Ok(())
    }
}

impl Default for SequencerManager {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════
// §5.2 Data Availability — OP_RETURN Commitment
// ═══════════════════════════════════════════════════════════════

/// Maximum OP_RETURN payload size in bytes.
///
/// Bitcoin consensus allows up to 80 bytes in OP_RETURN.
/// We use: 4 (magic) + 32 (block_hash) + 32 (tx_root) + 8 (height) = 76 bytes.
pub const DA_COMMITMENT_SIZE: usize = 76;

/// Magic bytes for Brrq DA commitment identification in OP_RETURN.
pub const DA_MAGIC: [u8; 4] = [0x42, 0x52, 0x52, 0x51]; // "BRRQ"

/// A commitment to L2 block data, published on L1 via OP_RETURN.
///
/// This anchors an immutable proof that the L2 block data existed at
/// the time of the L1 transaction. Any full node can verify the data
/// against this commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaCommitment {
    /// L2 block height this commitment covers.
    pub l2_height: u64,
    /// Hash of the L2 block header.
    pub block_hash: Hash256,
    /// Merkle root of all transactions in the L2 block.
    pub tx_merkle_root: Hash256,
    /// L1 transaction ID where this commitment was published (set after broadcast).
    pub l1_tx_id: Option<Hash256>,
    /// L1 block height where this commitment was confirmed (set after confirmation).
    pub l1_confirmed_at: Option<u64>,
}

impl DaCommitment {
    /// Create a new DA commitment for an L2 block.
    pub fn new(l2_height: u64, block_hash: Hash256, tx_merkle_root: Hash256) -> Self {
        Self {
            l2_height,
            block_hash,
            tx_merkle_root,
            l1_tx_id: None,
            l1_confirmed_at: None,
        }
    }

    /// Serialize to OP_RETURN payload format (76 bytes).
    ///
    /// Layout: [4: magic][32: block_hash][32: tx_merkle_root][8: l2_height_le]
    pub fn to_op_return_payload(&self) -> [u8; DA_COMMITMENT_SIZE] {
        let mut buf = [0u8; DA_COMMITMENT_SIZE];
        buf[0..4].copy_from_slice(&DA_MAGIC);
        buf[4..36].copy_from_slice(self.block_hash.as_bytes());
        buf[36..68].copy_from_slice(self.tx_merkle_root.as_bytes());
        buf[68..76].copy_from_slice(&self.l2_height.to_le_bytes());
        buf
    }

    /// Deserialize from OP_RETURN payload.
    pub fn from_op_return_payload(data: &[u8]) -> Result<Self, SequencerError> {
        if data.len() != DA_COMMITMENT_SIZE {
            return Err(SequencerError::InvalidDaPayloadSize {
                expected: DA_COMMITMENT_SIZE,
                actual: data.len(),
            });
        }
        if data[0..4] != DA_MAGIC {
            return Err(SequencerError::InvalidDaMagic);
        }
        let block_hash = Hash256::from_bytes(data[4..36].try_into().unwrap());
        let tx_merkle_root = Hash256::from_bytes(data[36..68].try_into().unwrap());
        let l2_height = u64::from_le_bytes(data[68..76].try_into().unwrap());

        Ok(Self {
            l2_height,
            block_hash,
            tx_merkle_root,
            l1_tx_id: None,
            l1_confirmed_at: None,
        })
    }

    /// Compute the commitment hash for verification.
    ///
    /// H("BRRQ_DA_COMMITMENT" || l2_height || block_hash || tx_merkle_root)
    pub fn commitment_hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(b"BRRQ_DA_COMMITMENT");
        hasher.update(&self.l2_height.to_le_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(self.tx_merkle_root.as_bytes());
        hasher.finalize()
    }
}

/// Minimum number of L2 blocks a full node must retain.
///
/// Yellow Paper §5.2: Full nodes retain at least 10,080 blocks (~1 week).
/// Archive nodes retain all history.
pub const MIN_RETENTION_BLOCKS: u64 = 10_080;

// ═══════════════════════════════════════════════════════════════
// §5.1 MEV Protection — Commit-Reveal
// ═══════════════════════════════════════════════════════════════

/// A committed (encrypted) transaction awaiting reveal.
///
/// Commit: User submits H(tx_content || blinding_factor).
/// Reveal: User reveals tx_content and blinding_factor.
///
/// The sequencer commits to the ordering BEFORE seeing tx content,
/// preventing front-running and sandwich attacks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedTransaction {
    /// Hash commitment: H("BRRQ_TX_COMMIT" || tx_content || blinding_factor)
    pub commitment: Hash256,
    /// L2 address that submitted the commitment.
    pub sender: brrq_types::Address,
    /// L2 block height when the commitment was submitted.
    pub committed_at: u64,
    /// Ordering position assigned by the sequencer (before reveal).
    pub ordering_index: u64,
    /// Whether this commitment has been revealed.
    pub revealed: bool,
}

impl CommittedTransaction {
    /// Compute a commitment hash from transaction content and blinding factor.
    pub fn compute_commitment(tx_content: &[u8], blinding_factor: &[u8; 32]) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(b"BRRQ_TX_COMMIT");
        hasher.update(tx_content);
        hasher.update(blinding_factor);
        hasher.finalize()
    }

    /// Verify that a reveal matches the original commitment.
    pub fn verify_reveal(&self, tx_content: &[u8], blinding_factor: &[u8; 32]) -> bool {
        let expected = Self::compute_commitment(tx_content, blinding_factor);
        expected == self.commitment
    }

    /// Check if this commitment has expired (past the reveal window).
    ///
    /// Expired commitments should be pruned to prevent memory exhaustion
    /// from malicious users who submit commitments without ever revealing.
    pub fn is_expired(&self, current_height: u64) -> bool {
        current_height > self.committed_at.saturating_add(COMMIT_REVEAL_WINDOW)
    }
}

// ═══════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════

/// Sequencer and DA errors.
#[derive(Debug, thiserror::Error)]
pub enum SequencerError {
    #[error("sequencer already registered")]
    AlreadyRegistered,

    #[error("sequencer not found")]
    NotFound,

    #[error("label too long (max 128 bytes)")]
    LabelTooLong,

    #[error("invalid DA payload size: expected {expected}, got {actual}")]
    InvalidDaPayloadSize { expected: usize, actual: usize },

    #[error("invalid DA magic bytes (expected BRRQ)")]
    InvalidDaMagic,

    #[error("commitment not found")]
    CommitmentNotFound,

    #[error("commitment already revealed")]
    AlreadyRevealed,

    #[error("reveal does not match commitment")]
    RevealMismatch,

    #[error("commit-reveal window expired: committed at {committed_at}, current {current}, window {window}")]
    CommitRevealExpired {
        committed_at: u64,
        current: u64,
        window: u64,
    },

    #[error("not the current sequencer")]
    NotCurrentSequencer,

    #[error("insufficient bond: required {required} sat, provided {provided} sat")]
    InsufficientBond { required: u64, provided: u64 },
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_types::Address;

    // ── Sequencer Tests ────────────────────────────────────────

    #[test]
    fn test_sequencer_register() {
        let mut mgr = SequencerManager::new();
        assert_eq!(mgr.active_count(), 0);

        mgr.register(Address::ZERO, "seq-0".into(), 100_000_000, 0)
            .unwrap();
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_sequencer_duplicate_rejected() {
        let mut mgr = SequencerManager::new();
        mgr.register(Address::ZERO, "seq-0".into(), 100_000_000, 0)
            .unwrap();
        let err = mgr
            .register(Address::ZERO, "seq-0-dup".into(), 100_000_000, 0)
            .unwrap_err();
        assert!(matches!(err, SequencerError::AlreadyRegistered));
    }

    #[test]
    fn test_sequencer_label_too_long() {
        let mut mgr = SequencerManager::new();
        let long_label = "x".repeat(129);
        let err = mgr
            .register(Address::ZERO, long_label, 100_000_000, 0)
            .unwrap_err();
        assert!(matches!(err, SequencerError::LabelTooLong));
    }

    #[test]
    fn test_sequencer_rotation() {
        let mut mgr = SequencerManager::new();
        let addr0 = Address::from_bytes([0u8; 20]);
        let addr1 = Address::from_bytes([1u8; 20]);

        mgr.register(addr0, "seq-0".into(), 100_000_000, 0)
            .unwrap();
        mgr.register(addr1, "seq-1".into(), 100_000_000, 0)
            .unwrap();

        // At height 0, first sequencer is active
        let current = mgr.current_sequencer(0).unwrap();
        assert_eq!(current.address, addr0);

        // After rotation period, second sequencer takes over
        let current = mgr.current_sequencer(SEQUENCER_ROTATION_BLOCKS).unwrap();
        assert_eq!(current.address, addr1);

        // After two rotations, back to first
        let current = mgr
            .current_sequencer(SEQUENCER_ROTATION_BLOCKS * 2)
            .unwrap();
        assert_eq!(current.address, addr0);
    }

    #[test]
    fn test_sequencer_single_no_rotation() {
        let mut mgr = SequencerManager::new();
        let addr0 = Address::from_bytes([0u8; 20]);
        mgr.register(addr0, "solo".into(), 100_000_000, 0)
            .unwrap();

        // Single sequencer — no rotation, always the same
        assert_eq!(mgr.current_sequencer(0).unwrap().address, addr0);
        assert_eq!(
            mgr.current_sequencer(SEQUENCER_ROTATION_BLOCKS * 10)
                .unwrap()
                .address,
            addr0
        );
    }

    #[test]
    fn test_sequencer_deactivate() {
        let mut mgr = SequencerManager::new();
        let addr = Address::from_bytes([0u8; 20]);
        mgr.register(addr, "seq".into(), 100_000_000, 0).unwrap();
        assert_eq!(mgr.active_count(), 1);
        mgr.deactivate(&addr, 0).unwrap();
        assert_eq!(mgr.active_count(), 0);
        assert!(mgr.current_sequencer(0).is_none());
    }

    #[test]
    fn test_sequencer_insufficient_bond() {
        let mut mgr = SequencerManager::new();
        let err = mgr
            .register(Address::ZERO, "cheap".into(), 0, 0)
            .unwrap_err();
        assert!(matches!(err, SequencerError::InsufficientBond { .. }));
    }

    #[test]
    fn test_arv1_deactivation_resets_rotation() {
        let mut mgr = SequencerManager::new();
        let a = Address::from_bytes([1u8; 20]);
        let b = Address::from_bytes([2u8; 20]);
        let c = Address::from_bytes([3u8; 20]);

        mgr.register(a, "a".into(), MIN_SEQUENCER_BOND, 0).unwrap();
        mgr.register(b, "b".into(), MIN_SEQUENCER_BOND, 0).unwrap();
        mgr.register(c, "c".into(), MIN_SEQUENCER_BOND, 0).unwrap();

        // At height 0: a is current (idx=0, 3 active)
        assert_eq!(mgr.current_sequencer(0).unwrap().address, a);

        // Deactivate b at height 100
        mgr.deactivate(&b, 100).unwrap();

        // After deactivation, rotation resets: active=[a,c], idx=0, started_at=100
        // At height 100: a is current
        assert_eq!(mgr.current_sequencer(100).unwrap().address, a);

        // At height 100 + ROTATION: next active (c)
        assert_eq!(
            mgr.current_sequencer(100 + SEQUENCER_ROTATION_BLOCKS)
                .unwrap()
                .address,
            c
        );
    }

    #[test]
    fn test_arv5_commitment_expiry() {
        let ctx = CommittedTransaction {
            commitment: Hash256::ZERO,
            sender: Address::ZERO,
            committed_at: 100,
            ordering_index: 0,
            revealed: false,
        };

        // Within window: not expired
        assert!(!ctx.is_expired(100 + COMMIT_REVEAL_WINDOW));

        // Past window: expired
        assert!(ctx.is_expired(100 + COMMIT_REVEAL_WINDOW + 1));
    }

    // ── DA Commitment Tests ────────────────────────────────────

    #[test]
    fn test_da_commitment_roundtrip() {
        let commitment = DaCommitment::new(42, Hash256::ZERO, Hash256::ZERO);
        let payload = commitment.to_op_return_payload();

        assert_eq!(payload.len(), DA_COMMITMENT_SIZE);
        assert_eq!(&payload[0..4], &DA_MAGIC);

        let parsed = DaCommitment::from_op_return_payload(&payload).unwrap();
        assert_eq!(parsed.l2_height, 42);
        assert_eq!(parsed.block_hash, Hash256::ZERO);
        assert_eq!(parsed.tx_merkle_root, Hash256::ZERO);
    }

    #[test]
    fn test_da_commitment_invalid_magic() {
        let mut payload = [0u8; DA_COMMITMENT_SIZE];
        payload[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        let err = DaCommitment::from_op_return_payload(&payload).unwrap_err();
        assert!(matches!(err, SequencerError::InvalidDaMagic));
    }

    #[test]
    fn test_da_commitment_invalid_size() {
        let payload = [0u8; 10];
        let err = DaCommitment::from_op_return_payload(&payload).unwrap_err();
        assert!(matches!(err, SequencerError::InvalidDaPayloadSize { .. }));
    }

    #[test]
    fn test_da_commitment_hash_deterministic() {
        let c1 = DaCommitment::new(100, Hash256::ZERO, Hash256::ZERO);
        let c2 = DaCommitment::new(100, Hash256::ZERO, Hash256::ZERO);
        assert_eq!(c1.commitment_hash(), c2.commitment_hash());

        // Different height → different hash
        let c3 = DaCommitment::new(101, Hash256::ZERO, Hash256::ZERO);
        assert_ne!(c1.commitment_hash(), c3.commitment_hash());
    }

    #[test]
    fn test_da_commitment_payload_fits_op_return() {
        // Bitcoin OP_RETURN allows up to 80 bytes
        assert!(DA_COMMITMENT_SIZE <= 80);
    }

    // ── Commit-Reveal MEV Tests ────────────────────────────────

    #[test]
    fn test_commit_reveal_valid() {
        let tx_content = b"transfer 1 BTC to Alice";
        let blinding = [0xABu8; 32];

        let commitment = CommittedTransaction::compute_commitment(tx_content, &blinding);
        let ctx = CommittedTransaction {
            commitment,
            sender: Address::ZERO,
            committed_at: 0,
            ordering_index: 0,
            revealed: false,
        };

        assert!(ctx.verify_reveal(tx_content, &blinding));
    }

    #[test]
    fn test_commit_reveal_wrong_content() {
        let tx_content = b"transfer 1 BTC to Alice";
        let blinding = [0xABu8; 32];

        let commitment = CommittedTransaction::compute_commitment(tx_content, &blinding);
        let ctx = CommittedTransaction {
            commitment,
            sender: Address::ZERO,
            committed_at: 0,
            ordering_index: 0,
            revealed: false,
        };

        // Wrong content → reveal fails
        assert!(!ctx.verify_reveal(b"transfer 100 BTC to Eve", &blinding));
    }

    #[test]
    fn test_commit_reveal_wrong_blinding() {
        let tx_content = b"transfer 1 BTC to Alice";
        let blinding = [0xABu8; 32];
        let wrong_blinding = [0xCDu8; 32];

        let commitment = CommittedTransaction::compute_commitment(tx_content, &blinding);
        let ctx = CommittedTransaction {
            commitment,
            sender: Address::ZERO,
            committed_at: 0,
            ordering_index: 0,
            revealed: false,
        };

        // Wrong blinding factor → reveal fails
        assert!(!ctx.verify_reveal(tx_content, &wrong_blinding));
    }

    #[test]
    fn test_commit_reveal_commitment_deterministic() {
        let tx = b"some transaction";
        let bf = [0x42u8; 32];

        let c1 = CommittedTransaction::compute_commitment(tx, &bf);
        let c2 = CommittedTransaction::compute_commitment(tx, &bf);
        assert_eq!(c1, c2);

        // Different blinding → different commitment
        let c3 = CommittedTransaction::compute_commitment(tx, &[0x43u8; 32]);
        assert_ne!(c1, c3);
    }
}
