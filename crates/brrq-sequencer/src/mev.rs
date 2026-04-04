//! MEV-aware mempool with commit-reveal phase management.
//!
//! ## Design (§4.7 — Commit-Reveal MEV Protection)
//!
//! The MEV mempool operates in three phases per block:
//!
//! 1. **Commit**: Accept encrypted transaction envelopes.
//!    The sequencer can see max_fee_per_gas, max_priority_fee_per_gas, nonce, sender - but NOT what the tx does.
//!
//! 2. **Ordering**: Lock the ordering. No new transactions accepted.
//!    The sequencer commits to a specific ordering of envelopes.
//!
//! 3. **Decrypt**: Decrypt envelopes in the committed order, producing
//!    plaintext transactions for execution.
//!
//! After execution, the mempool resets to Commit phase for the next block.

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap, HashSet};

use brrq_crypto::encryption::EpochKey;
use brrq_crypto::hash::{Hash256, Hasher};
use brrq_types::address::Address;
use brrq_types::mev::EncryptedEnvelope;
use brrq_types::transaction::Transaction;
use serde::{Deserialize, Serialize};

use crate::error::SequencerError;

/// Maximum number of encrypted envelopes in the MEV mempool.
const DEFAULT_MEV_MAX_SIZE: usize = 10_000;

/// Maximum byte budget for encrypted envelopes (50 MB).
const DEFAULT_MEV_MAX_BYTES: usize = 50 * 1024 * 1024;

/// Maximum envelopes per sender to prevent single-account spam.
/// Same limit as the regular Mempool's MAX_TXS_PER_ACCOUNT.
const MAX_ENVELOPES_PER_SENDER: usize = 64;

/// Maximum decrypt failures tolerated per batch before aborting.
/// Prevents attackers from filling the mempool with undecryptable envelopes
/// that waste sequencer time and block space.
const MAX_DECRYPT_FAILURES: usize = 50;

/// Minimum number of L2 blocks between `lock_ordering` and `decrypt_batch`.
///
/// Enforced at the consensus layer: a block containing MEV decrypted
/// transactions is only valid if ordering was locked at least this many
/// blocks earlier. This prevents a malicious sequencer from committing
/// an ordering and decrypting in the same block (H-1 in threat model).
/// Minimum reveal delay for commit-reveal security.
pub const MIN_REVEAL_DELAY_BLOCKS: u64 = 2;

// ═══════════════════════════════════════════════════════════════
// L1 Ordering Anchor
// ═══════════════════════════════════════════════════════════════

/// L1 ordering anchor — commits block ordering to Bitcoin via OP_RETURN.
///
/// When only a single sequencer produces blocks, there is no MEV protection
/// from the commit-reveal protocol alone. The L1 anchor provides accountability:
/// the sequencer must publish the ordering hash to L1 BEFORE decrypting,
/// creating an immutable record that can be audited for ordering manipulation.
///
/// Layout (72 bytes in OP_RETURN):
/// - bytes 0..32: ordering_commitment (SHA-256 of ordered envelope hashes)
/// - bytes 32..40: l2_block_height (u64 LE)
/// - bytes 40..72: sequencer_signature_hash (truncated signature commitment)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct L1OrderingAnchor {
    /// SHA-256 commitment to the ordered envelope hashes.
    pub ordering_commitment: Hash256,
    /// L2 block height this ordering applies to.
    pub l2_block_height: u64,
    /// Truncated hash of the sequencer's signature over the commitment.
    pub sequencer_sig_hash: Hash256,
    /// Bitcoin L1 transaction ID that published this anchor (set after broadcast).
    pub l1_tx_id: Option<Hash256>,
}

impl L1OrderingAnchor {
    /// Create a new L1 ordering anchor.
    pub fn new(
        ordering_commitment: Hash256,
        l2_block_height: u64,
        sequencer_sig_hash: Hash256,
    ) -> Self {
        Self {
            ordering_commitment,
            l2_block_height,
            sequencer_sig_hash,
            l1_tx_id: None,
        }
    }

    /// Serialize to 72-byte OP_RETURN payload.
    pub fn to_op_return(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];
        buf[0..32].copy_from_slice(self.ordering_commitment.as_bytes());
        buf[32..40].copy_from_slice(&self.l2_block_height.to_le_bytes());
        buf[40..72].copy_from_slice(self.sequencer_sig_hash.as_bytes());
        buf
    }

    /// Verify that this anchor matches a given ordering commitment.
    pub fn verify(&self, expected_commitment: &Hash256) -> bool {
        self.ordering_commitment == *expected_commitment
    }
}

/// The current phase of the MEV commit-reveal protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MevPhase {
    /// Accepting encrypted transaction envelopes.
    Commit,
    /// Ordering is locked — no new envelopes accepted.
    Ordering,
    /// Decrypting and executing committed transactions.
    Decrypt,
}

impl std::fmt::Display for MevPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MevPhase::Commit => write!(f, "Commit"),
            MevPhase::Ordering => write!(f, "Ordering"),
            MevPhase::Decrypt => write!(f, "Decrypt"),
        }
    }
}

/// MEV-protected mempool that enforces the commit-reveal protocol.
///
/// Unlike the standard [`Mempool`](crate::Mempool), this mempool stores
/// [`EncryptedEnvelope`]s instead of plaintext transactions. The sequencer
/// can order by max_fee_per_gas but cannot see transaction content.
#[derive(Debug, Clone)]
pub struct MevMempool {
    /// Encrypted envelopes keyed by envelope hash.
    envelopes: HashMap<Hash256, EncryptedEnvelope>,
    /// Priority queue: (max_fee_per_gas DESC, insertion_order ASC) → envelope hash.
    priority_queue: BTreeMap<(Reverse<u64>, u64), Hash256>,
    /// Known hashes for duplicate detection.
    known_hashes: HashSet<Hash256>,
    /// Per-sender envelope count to prevent single-account spam.
    sender_counts: HashMap<Address, usize>,
    /// Reverse index from envelope hash to priority queue key for O(log N) removal.
    hash_to_priority_key: HashMap<Hash256, (Reverse<u64>, u64)>,
    /// Insertion counter for stable ordering within same gas price.
    insertion_counter: u64,
    /// Current protocol phase.
    phase: MevPhase,
    /// Current epoch number.
    epoch: u64,
    /// Latest L1 ordering anchor (if published).
    pub l1_anchor: Option<L1OrderingAnchor>,
    /// Maximum number of envelopes.
    max_size: usize,
    /// Maximum total byte budget.
    max_bytes: usize,
    /// Current total byte usage.
    total_bytes: usize,
    /// L2 block height at which ordering was locked (for reveal delay enforcement).
    lock_height: Option<u64>,
    /// Whether the ordering commitment has been anchored on L1.
    ///
    /// This flag MUST be set to `true` (via `confirm_ordering_committed()`)
    /// before `decrypt_batch()` can be called. Without this, the sequencer
    /// could decrypt envelopes before the ordering is immutably committed,
    /// defeating MEV protection.
    ordering_committed: bool,
}

impl MevMempool {
    /// Create a new MEV mempool for the given epoch.
    pub fn new(epoch: u64) -> Self {
        Self {
            envelopes: HashMap::new(),
            priority_queue: BTreeMap::new(),
            known_hashes: HashSet::new(),
            sender_counts: HashMap::new(),
            hash_to_priority_key: HashMap::new(),
            insertion_counter: 0,
            phase: MevPhase::Commit,
            epoch,
            l1_anchor: None,
            max_size: DEFAULT_MEV_MAX_SIZE,
            max_bytes: DEFAULT_MEV_MAX_BYTES,
            total_bytes: 0,
            lock_height: None,
            ordering_committed: false,
        }
    }

    /// Create a MEV mempool with custom capacity limits.
    pub fn with_capacity(epoch: u64, max_size: usize, max_bytes: usize) -> Self {
        Self {
            max_size,
            max_bytes,
            ..Self::new(epoch)
        }
    }

    /// Submit an encrypted envelope during the Commit phase.
    ///
    /// Validates:
    /// - Correct phase (must be Commit)
    /// - No duplicates
    /// - Commitment integrity
    /// - Sender signature
    /// - Capacity limits
    pub fn submit(&mut self, envelope: EncryptedEnvelope) -> Result<Hash256, SequencerError> {
        // 1. Phase check
        if self.phase != MevPhase::Commit {
            return Err(SequencerError::InvalidTransaction {
                reason: format!(
                    "MEV mempool is in {} phase, not accepting new envelopes",
                    self.phase
                ),
            });
        }

        // 1b. Gas price must be non-zero (prevents spam with zero-fee envelopes)
        if envelope.metadata.max_fee_per_gas == 0 {
            return Err(SequencerError::InvalidTransaction {
                reason: "max_fee_per_gas must be > 0".into(),
            });
        }

        // 1b2. Sender must not be the zero address (H-2: prevents invalid envelopes)
        if envelope.metadata.sender == Address::ZERO {
            return Err(SequencerError::InvalidTransaction {
                reason: "sender must not be zero address".into(),
            });
        }

        // 1c. Commitment must be non-zero (zero commitment is always invalid)
        if envelope.commitment == Hash256::ZERO {
            return Err(SequencerError::InvalidTransaction {
                reason: "envelope commitment must be non-zero".into(),
            });
        }

        // 1d. Encrypted payload must be non-empty
        if envelope.encrypted_kind.is_empty() {
            return Err(SequencerError::InvalidTransaction {
                reason: "encrypted_kind must be non-empty".into(),
            });
        }

        // 2. Compute envelope hash
        let env_hash = envelope.hash();

        // 3. Duplicate check
        if self.known_hashes.contains(&env_hash) {
            return Err(SequencerError::DuplicateTransaction {
                tx_hash: format!("{:?}", env_hash),
            });
        }

        // 4. Verify commitment integrity (without decrypting)
        if !envelope.verify_commitment() {
            return Err(SequencerError::InvalidTransaction {
                reason: "envelope commitment integrity check failed".into(),
            });
        }

        // 5. Verify sender signature (pre-decryption authentication)
        envelope
            .verify_signature()
            .map_err(|e| SequencerError::InvalidTransaction {
                reason: format!("envelope signature invalid: {e}"),
            })?;

        // 6. Capacity check (count) — with fee-based eviction
        if self.envelopes.len() >= self.max_size {
            // Find lowest-fee envelope via priority queue (last entry = lowest fee due to Reverse ordering)
            let mut evicted = false;
            if let Some((&lowest_key, &lowest_hash)) = self.priority_queue.iter().next_back() {
                if let Some(lowest_env) = self.envelopes.get(&lowest_hash) {
                    if envelope.metadata.max_fee_per_gas > lowest_env.metadata.max_fee_per_gas {
                        // Evict lowest, insert new
                        let evict_hash = lowest_hash;
                        self.remove_envelope(&evict_hash, &lowest_key);
                        evicted = true;
                    }
                }
            }
            if !evicted {
                return Err(SequencerError::MempoolFull {
                    capacity: self.max_size,
                    current: self.envelopes.len(),
                });
            }
        }

        // 7. Capacity check (bytes) — H-3: use checked_add to prevent overflow
        //    Evict lowest-fee envelopes when byte budget is
        //    exceeded, instead of unconditionally rejecting. Without this, an
        //    attacker filling the pool with many tiny low-fee envelopes would
        //    prevent larger legitimate transactions from entering.
        let env_size = envelope.size();
        let mut current_total = self.total_bytes;
        loop {
            let new_total =
                current_total
                    .checked_add(env_size)
                    .ok_or(SequencerError::MempoolFull {
                        capacity: self.max_bytes,
                        current: self.total_bytes,
                    })?;
            if new_total <= self.max_bytes {
                break; // fits
            }
            // Try to evict the lowest-fee envelope to free bytes
            if let Some((&lowest_key, &lowest_hash)) = self.priority_queue.iter().next_back() {
                if let Some(lowest_env) = self.envelopes.get(&lowest_hash) {
                    if envelope.metadata.max_fee_per_gas > lowest_env.metadata.max_fee_per_gas {
                        let evict_hash = lowest_hash;
                        self.remove_envelope(&evict_hash, &lowest_key);
                        current_total = self.total_bytes;
                        continue; // re-check after eviction
                    }
                }
            }
            // Cannot evict anything — pool is full of higher-fee envelopes
            return Err(SequencerError::MempoolFull {
                capacity: self.max_bytes,
                current: self.total_bytes,
            });
        }

        // Per-sender limit to prevent single-account spam
        let sender = envelope.metadata.sender;
        let sender_count = self.sender_counts.get(&sender).copied().unwrap_or(0);
        if sender_count >= MAX_ENVELOPES_PER_SENDER {
            return Err(SequencerError::InvalidTransaction {
                reason: format!(
                    "sender has {} envelopes (max {})",
                    sender_count, MAX_ENVELOPES_PER_SENDER
                ),
            });
        }

        // 8. Insert into priority queue (ordered by max_fee_per_gas DESC)
        let max_fee_per_gas = envelope.metadata.max_fee_per_gas;
        let key = (Reverse(max_fee_per_gas), self.insertion_counter);
        self.insertion_counter += 1;
        self.priority_queue.insert(key, env_hash);
        self.hash_to_priority_key.insert(env_hash, key);

        // 9. Store
        self.known_hashes.insert(env_hash);
        self.total_bytes = new_total;
        *self.sender_counts.entry(sender).or_insert(0) += 1;
        self.envelopes.insert(env_hash, envelope);

        Ok(env_hash)
    }

    /// Lock the ordering — transition from Commit to Ordering phase.
    ///
    /// After this call, no new envelopes are accepted. The current ordering
    /// is frozen and the sequencer commits to it.
    ///
    /// `current_height` is the L2 block height at which ordering is locked.
    /// The sequencer must wait at least [`MIN_REVEAL_DELAY_BLOCKS`] before
    /// calling `decrypt_batch`.
    pub fn lock_ordering(&mut self, current_height: u64) -> Result<(), SequencerError> {
        // WI-5D: Only allow locking from Commit phase
        if self.phase != MevPhase::Commit && self.phase != MevPhase::Ordering {
            return Err(SequencerError::InvalidTransaction {
                reason: format!(
                    "cannot lock ordering in {} phase (must be Commit or Ordering)",
                    self.phase
                ),
            });
        }

        self.phase = MevPhase::Ordering;
        // Only record lock height on the first lock — prevents timer reset
        // by repeated calls with a later height.
        if self.lock_height.is_none() {
            self.lock_height = Some(current_height);
        }
        Ok(())
    }

    /// Compute a deterministic commitment to the current ordering.
    ///
    /// The ordering commitment is:
    /// `H(MEV_ORDERING_V1 ∥ height ∥ hash_1 ∥ hash_2 ∥ ... ∥ hash_n)`
    ///
    /// where hashes are in priority-queue order (max_fee_per_gas DESC, insertion ASC).
    /// This must be computed in the Ordering phase.
    pub fn compute_ordering_commitment(&self) -> Result<Hash256, SequencerError> {
        if self.phase != MevPhase::Ordering {
            return Err(SequencerError::InvalidTransaction {
                reason: format!(
                    "cannot compute ordering commitment in {} phase (must be Ordering)",
                    self.phase
                ),
            });
        }

        let height = self.lock_height.unwrap_or(0);
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::MEV_ORDERING_V1);
        hasher.update(&height.to_le_bytes());

        // Hash envelope hashes in priority order
        for env_hash in self.priority_queue.values() {
            hasher.update(env_hash.as_bytes());
        }

        Ok(hasher.finalize())
    }

    /// Confirm that the ordering commitment has been anchored on L1.
    ///
    /// This MUST be called after the L1 ordering anchor transaction has been
    /// confirmed (mined in a Bitcoin block). Only after this confirmation
    /// can `decrypt_batch()` proceed.
    ///
    /// The L1 anchor must match the ordering commitment computed by
    /// `compute_ordering_commitment()`.
    ///
    /// # Errors
    /// - Not in Ordering phase
    /// - No L1 anchor provided
    /// - L1 anchor commitment does not match the computed ordering commitment
    pub fn confirm_ordering_committed(
        &mut self,
        anchor: &L1OrderingAnchor,
    ) -> Result<(), SequencerError> {
        if self.phase != MevPhase::Ordering {
            return Err(SequencerError::InvalidTransaction {
                reason: format!(
                    "cannot confirm ordering in {} phase (must be Ordering)",
                    self.phase
                ),
            });
        }

        // Verify anchor matches the current ordering commitment
        let expected = self.compute_ordering_commitment()?;
        if !anchor.verify(&expected) {
            return Err(SequencerError::InvalidTransaction {
                reason: "L1 anchor ordering commitment does not match computed ordering".into(),
            });
        }

        self.ordering_committed = true;
        self.l1_anchor = Some(anchor.clone());
        Ok(())
    }

    /// Whether the ordering commitment has been confirmed on L1.
    pub fn is_ordering_committed(&self) -> bool {
        self.ordering_committed
    }

    /// Verify that a set of transaction hashes matches a previously computed
    /// ordering commitment.
    ///
    /// Used by validators to verify the sequencer's ordering commitment
    /// matches the actual transaction ordering in the decrypted block.
    pub fn verify_ordering(height: u64, commitment: &Hash256, tx_hashes: &[Hash256]) -> bool {
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::MEV_ORDERING_V1);
        hasher.update(&height.to_le_bytes());
        for h in tx_hashes {
            hasher.update(h.as_bytes());
        }
        &hasher.finalize() == commitment
    }

    /// Get ordered envelopes by gas price (highest first).
    ///
    /// Returns references to up to `max_count` envelopes in priority order.
    pub fn get_ordered(&self, max_count: usize) -> Vec<&EncryptedEnvelope> {
        self.priority_queue
            .iter()
            .take(max_count)
            .filter_map(|(_, hash)| self.envelopes.get(hash))
            .collect()
    }

    /// Decrypt all ordered envelopes into plaintext transactions.
    ///
    /// Transitions to Decrypt phase and decrypts envelopes in the committed
    /// ordering (max_fee_per_gas DESC). Any envelopes that fail to decrypt are
    /// skipped with a warning.
    ///
    /// `current_height` is the L2 block height at which decryption is attempted.
    /// The sequencer must have locked ordering at least [`MIN_REVEAL_DELAY_BLOCKS`]
    /// blocks earlier. This prevents the sequencer from seeing transaction content
    /// before committing to an ordering (H-1 mitigation).
    ///
    /// Returns the plaintext transactions ready for execution.
    pub fn decrypt_batch(
        &mut self,
        epoch_key: &EpochKey,
        max_count: usize,
        current_height: u64,
    ) -> Result<Vec<Transaction>, SequencerError> {
        if self.phase == MevPhase::Commit {
            return Err(SequencerError::InvalidTransaction {
                reason: "cannot decrypt: ordering has not been locked (still in Commit phase)"
                    .into(),
            });
        }

        // Enforce ordering commitment — the sequencer must have committed
        // the ordering on L1 before it can decrypt any envelopes.
        // This prevents the sequencer from decrypting envelopes, observing
        // their content, and then reordering for MEV extraction.
        if !self.ordering_committed {
            return Err(SequencerError::InvalidTransaction {
                reason: "must commit ordering on L1 before decryption (call confirm_ordering_committed first)".into(),
            });
        }

        // Enforce reveal delay: must wait MIN_REVEAL_DELAY_BLOCKS after lock.
        // Use checked_add: if lock_h is near u64::MAX and addition overflows,
        // no valid block height can satisfy the delay → always reject.
        if let Some(lock_h) = self.lock_height {
            match lock_h.checked_add(MIN_REVEAL_DELAY_BLOCKS) {
                Some(required_height) if current_height >= required_height => {
                    // Delay satisfied
                }
                _ => {
                    // Either current_height < required_height, or overflow (no valid height)
                    return Err(SequencerError::InvalidTransaction {
                        reason: format!(
                            "MEV reveal too early: locked at height {}, current {}, need >= {}",
                            lock_h,
                            current_height,
                            lock_h.saturating_add(MIN_REVEAL_DELAY_BLOCKS),
                        ),
                    });
                }
            }
        }

        self.phase = MevPhase::Decrypt;

        let mut transactions = Vec::new();
        let mut failures = 0usize;
        let mut failed_hashes = Vec::new();
        let ordered_hashes: Vec<Hash256> = self
            .priority_queue
            .iter()
            .take(max_count)
            .map(|(_, hash)| *hash)
            .collect();

        for hash in &ordered_hashes {
            if let Some(envelope) = self.envelopes.get(hash) {
                match envelope.decrypt(epoch_key) {
                    Ok(tx) => transactions.push(tx),
                    Err(e) => {
                        tracing::warn!(
                            "MEV envelope {:?} decryption failed: {}, evicting",
                            hash,
                            e
                        );
                        failed_hashes.push(*hash);
                        failures += 1;
                        // Abort early if too many failures — likely a DoS attempt
                        if failures >= MAX_DECRYPT_FAILURES {
                            tracing::error!(
                                "MEV decrypt: {} failures reached limit, aborting batch",
                                failures
                            );
                            break;
                        }
                    }
                }
            }
        }

        // Evict failed envelopes so they don't waste space in future batches
        self.remove_committed(&failed_hashes);

        Ok(transactions)
    }

    /// Decrypt a batch using threshold-reconstructed epoch key from Shamir shares.
    ///
    /// This is the preferred decryption method for production. Instead of
    /// receiving the epoch key directly, it reconstructs it from threshold
    /// shares collected from multiple sequencers.
    ///
    /// # Arguments
    /// - `shares`: Collected Shamir key shares (must be >= threshold)
    /// - `config`: Threshold encryption config (threshold, total_shares)
    /// - `anchor`: L1 anchor hash for key derivation verification
    /// - `epoch`: Epoch number for key derivation verification
    /// - `epoch_seed`: Revealed epoch seed
    /// - `max_count`: Maximum number of envelopes to decrypt
    /// - `current_height`: Current L2 block height
    pub fn decrypt_batch_threshold(
        &mut self,
        shares: &[brrq_crypto::encryption::KeyShare],
        config: &brrq_crypto::encryption::ThresholdEncryptionConfig,
        epoch_seed: &brrq_crypto::hash::Hash256,
        epoch: u64,
        anchor: &brrq_crypto::hash::Hash256,
        max_count: usize,
        current_height: u64,
    ) -> Result<Vec<Transaction>, SequencerError> {
        // Reconstruct the epoch key from shares
        let epoch_key = brrq_crypto::encryption::reconstruct_secret(shares, config)
            .map_err(|e| SequencerError::InvalidTransaction {
                reason: format!("threshold key reconstruction failed: {e}"),
            })?;

        // Verify the reconstructed key matches the expected derivation
        let expected_key = brrq_crypto::encryption::EpochKey::derive_with_anchor(
            epoch_seed, epoch, anchor,
        );
        if epoch_key.as_bytes() != expected_key.as_bytes() {
            return Err(SequencerError::InvalidTransaction {
                reason: "reconstructed epoch key does not match expected derivation".into(),
            });
        }

        // Delegate to the existing decrypt_batch with the verified key
        self.decrypt_batch(&epoch_key, max_count, current_height)
    }

    /// Remove a single envelope by hash and its known priority key.
    /// Used internally for eviction when the priority key is already known.
    fn remove_envelope(&mut self, hash: &Hash256, priority_key: &(Reverse<u64>, u64)) {
        if let Some(envelope) = self.envelopes.remove(hash) {
            self.total_bytes = self.total_bytes.saturating_sub(envelope.size());
            let sender = envelope.metadata.sender;
            if let Some(count) = self.sender_counts.get_mut(&sender) {
                *count = count.saturating_sub(1);
            }
        }
        self.priority_queue.remove(priority_key);
        self.hash_to_priority_key.remove(hash);
    }

    /// Remove committed envelopes after block inclusion.
    /// Uses reverse index for O(log N) removal from BTreeMap
    /// instead of O(N) retain().
    pub fn remove_committed(&mut self, hashes: &[Hash256]) {
        for hash in hashes {
            if let Some(envelope) = self.envelopes.remove(hash) {
                self.total_bytes = self.total_bytes.saturating_sub(envelope.size());
                // Decrement sender count to keep per-sender limit accurate
                let sender = envelope.metadata.sender;
                if let Some(count) = self.sender_counts.get_mut(&sender) {
                    *count = count.saturating_sub(1);
                }
            }
            // O(log N) removal via reverse index instead of O(N) retain
            if let Some(priority_key) = self.hash_to_priority_key.remove(hash) {
                self.priority_queue.remove(&priority_key);
            }
        }
    }

    /// Reset to Commit phase for the next block.
    ///
    /// Clears all envelopes and resets the phase state machine.
    /// Call this after a block has been produced and committed.
    pub fn reset_phase(&mut self) {
        self.envelopes.clear();
        self.priority_queue.clear();
        self.hash_to_priority_key.clear();
        self.known_hashes.clear();
        self.insertion_counter = 0;
        self.total_bytes = 0;
        self.phase = MevPhase::Commit;
        self.lock_height = None;
        self.l1_anchor = None;
        self.ordering_committed = false;
        self.sender_counts.clear();
    }

    /// Get the block height at which ordering was locked.
    pub fn lock_height(&self) -> Option<u64> {
        self.lock_height
    }

    /// Advance to the next epoch.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Number of envelopes in the mempool.
    pub fn len(&self) -> usize {
        self.envelopes.len()
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.envelopes.is_empty()
    }

    /// Get the current phase.
    pub fn phase(&self) -> &MevPhase {
        &self.phase
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Get estimated byte usage.
    pub fn byte_usage(&self) -> usize {
        self.total_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::encryption::EpochKey;
    use brrq_crypto::hash::Hash256;
    use brrq_crypto::schnorr::SchnorrKeyPair;
    use brrq_types::address::Address;
    use brrq_types::mev::EncryptedEnvelope;
    use brrq_types::signature::{PublicKey, Signature};
    use brrq_types::transaction::{Transaction, TransactionBody, TransactionKind, chain_id};

    fn test_epoch_key() -> EpochKey {
        let seed = Hash256::from_bytes([0xAA; 32]);
        EpochKey::derive(&seed, 1)
    }

    fn make_signed_envelope(
        keypair: &SchnorrKeyPair,
        nonce: u64,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
    ) -> EncryptedEnvelope {
        let from = Address::from_public_key(keypair.public_key().as_bytes());
        let to = Address::from_bytes([0xBB; 20]);
        let body = TransactionBody {
            from,
            kind: TransactionKind::Transfer { to, amount: 50_000 },
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            chain_id: chain_id::TESTNET,
        };
        let body_hash = body.hash();
        let sig = keypair.sign(&body_hash).unwrap();
        let tx = Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(*keypair.public_key()),
        };

        let epoch_key = test_epoch_key();
        EncryptedEnvelope::encrypt(&tx, &epoch_key, 1, keypair).unwrap()
    }

    /// Helper: lock ordering and confirm it committed on L1.
    /// This simulates the full commit flow required before decrypt_batch().
    fn lock_and_confirm_ordering(pool: &mut MevMempool, lock_height: u64) {
        pool.lock_ordering(lock_height).unwrap();
        let commitment = pool.compute_ordering_commitment().unwrap();
        let anchor = L1OrderingAnchor::new(
            commitment,
            lock_height,
            Hash256::from_bytes([0xFF; 32]),
        );
        pool.confirm_ordering_committed(&anchor).unwrap();
    }

    #[test]
    fn test_submit_and_len() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let env = make_signed_envelope(&keypair, 0, 100, 10);

        let hash = pool.submit(env).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_duplicate_rejection() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let env = make_signed_envelope(&keypair, 0, 100, 10);
        let env2 = env.clone();

        pool.submit(env).unwrap();
        let result = pool.submit(env2);
        assert!(result.is_err());
    }

    #[test]
    fn test_phase_enforcement() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        // Submit in Commit phase works
        let env1 = make_signed_envelope(&keypair, 0, 100, 10);
        pool.submit(env1).unwrap();

        // Lock ordering → Ordering phase
        pool.lock_ordering(100).unwrap();
        assert_eq!(*pool.phase(), MevPhase::Ordering);

        // Submit in Ordering phase fails
        let env2 = make_signed_envelope(&keypair, 1, 200, 10);
        let result = pool.submit(env2);
        assert!(result.is_err());
    }

    #[test]
    fn test_priority_ordering() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        // Submit 3 envelopes with different gas prices
        let env_low = make_signed_envelope(&keypair, 0, 10, 10);
        let env_high = make_signed_envelope(&keypair, 1, 100, 10);
        let env_mid = make_signed_envelope(&keypair, 2, 50, 10);

        pool.submit(env_low).unwrap();
        pool.submit(env_high).unwrap();
        pool.submit(env_mid).unwrap();

        let ordered = pool.get_ordered(10);
        assert_eq!(ordered.len(), 3);
        // Highest gas price first
        assert_eq!(ordered[0].metadata.max_fee_per_gas, 100);
        assert_eq!(ordered[1].metadata.max_fee_per_gas, 50);
        assert_eq!(ordered[2].metadata.max_fee_per_gas, 10);
    }

    #[test]
    fn test_decrypt_batch() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let epoch_key = test_epoch_key();

        let env1 = make_signed_envelope(&keypair, 0, 100, 10);
        let env2 = make_signed_envelope(&keypair, 1, 50, 10);
        pool.submit(env1).unwrap();
        pool.submit(env2).unwrap();

        // Lock ordering, confirm on L1, then decrypt after delay
        lock_and_confirm_ordering(&mut pool, 100);
        let txs = pool.decrypt_batch(&epoch_key, 10, 102).unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(*pool.phase(), MevPhase::Decrypt);

        // First tx should have higher max_fee_per_gas (priority ordering preserved)
        assert_eq!(txs[0].body.max_fee_per_gas, 100);
        assert_eq!(txs[1].body.max_fee_per_gas, 50);
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let env = make_signed_envelope(&keypair, 0, 100, 10);
        pool.submit(env).unwrap();

        // Wrong epoch key → decryption fails → skip
        lock_and_confirm_ordering(&mut pool, 100);
        let wrong_key = EpochKey::derive(&Hash256::from_bytes([0xBB; 32]), 99);
        let txs = pool.decrypt_batch(&wrong_key, 10, 102).unwrap();
        assert_eq!(txs.len(), 0); // All skipped
    }

    #[test]
    fn test_reset_phase() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        pool.lock_ordering(100).unwrap();
        assert_eq!(*pool.phase(), MevPhase::Ordering);

        pool.reset_phase();
        assert_eq!(*pool.phase(), MevPhase::Commit);
        assert!(pool.is_empty());
        assert_eq!(pool.byte_usage(), 0);
    }

    #[test]
    fn test_capacity_limit() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::with_capacity(1, 2, 50 * 1024 * 1024);

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        pool.submit(make_signed_envelope(&keypair, 1, 200, 10))
            .unwrap();

        // Third should fail (max_size = 2)
        let result = pool.submit(make_signed_envelope(&keypair, 2, 300, 10));
        assert!(result.is_err());
    }

    #[test]
    fn test_remove_committed() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let hash1 = pool
            .submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        let _hash2 = pool
            .submit(make_signed_envelope(&keypair, 1, 200, 10))
            .unwrap();
        assert_eq!(pool.len(), 2);

        pool.remove_committed(&[hash1]);
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_byte_tracking() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        let bytes1 = pool.byte_usage();
        assert!(bytes1 > 0, "first envelope must have non-zero byte size");

        pool.submit(make_signed_envelope(&keypair, 1, 200, 10))
            .unwrap();
        let bytes2 = pool.byte_usage();
        assert!(
            bytes2 > bytes1,
            "second envelope must increase total bytes: was {}, now {}",
            bytes1,
            bytes2
        );
        // Verify additive property: total = first + second
        let expected_second_size = bytes2 - bytes1;
        assert!(
            expected_second_size > 0,
            "second envelope must have non-zero individual size"
        );
    }

    #[test]
    fn test_full_lifecycle() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let epoch_key = test_epoch_key();

        // Step 1: Commit
        assert_eq!(*pool.phase(), MevPhase::Commit);
        let h1 = pool
            .submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        let h2 = pool
            .submit(make_signed_envelope(&keypair, 1, 50, 10))
            .unwrap();
        let h3 = pool
            .submit(make_signed_envelope(&keypair, 2, 200, 10))
            .unwrap();

        // Step 2: Lock ordering and confirm on L1
        lock_and_confirm_ordering(&mut pool, 100);

        // Check ordering (should be: 200, 100, 50)
        let ordered = pool.get_ordered(10);
        assert_eq!(ordered.len(), 3);
        assert_eq!(ordered[0].metadata.max_fee_per_gas, 200);

        // Step 3: Decrypt
        let txs = pool.decrypt_batch(&epoch_key, 10, 102).unwrap();
        assert_eq!(txs.len(), 3);
        assert_eq!(*pool.phase(), MevPhase::Decrypt);

        // Verify decrypted transactions are valid
        for tx in &txs {
            assert!(tx.is_structurally_valid());
        }

        // Cleanup: remove committed, reset for next block
        pool.remove_committed(&[h1, h2, h3]);
        pool.reset_phase();
        assert_eq!(*pool.phase(), MevPhase::Commit);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_set_epoch() {
        let mut pool = MevMempool::new(1);
        assert_eq!(pool.epoch(), 1);
        pool.set_epoch(5);
        assert_eq!(pool.epoch(), 5);
    }

    // ══════════════════════════════════════════════════════════════
    // Adversarial / Attack Vector Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_submit_during_decrypt_phase_fails() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let epoch_key = test_epoch_key();

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        lock_and_confirm_ordering(&mut pool, 100);
        pool.decrypt_batch(&epoch_key, 10, 102).unwrap();
        assert_eq!(*pool.phase(), MevPhase::Decrypt);

        // Submit during Decrypt phase must fail
        let env = make_signed_envelope(&keypair, 1, 200, 10);
        let result = pool.submit(env);
        assert!(
            result.is_err(),
            "Submit during Decrypt phase must be rejected"
        );
    }

    #[test]
    fn adversarial_max_max_fee_per_gas_priority() {
        // Attacker submits envelope with u64::MAX gas price to front-run
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let env_normal = make_signed_envelope(&keypair, 0, 100, 10);
        let env_maxgas = make_signed_envelope(&keypair, 1, u64::MAX, 10);
        let env_mid = make_signed_envelope(&keypair, 2, 50_000, 10);

        pool.submit(env_normal).unwrap();
        pool.submit(env_maxgas).unwrap();
        pool.submit(env_mid).unwrap();

        let ordered = pool.get_ordered(10);
        assert_eq!(
            ordered[0].metadata.max_fee_per_gas,
            u64::MAX,
            "Max gas price must be first"
        );
        assert_eq!(ordered[1].metadata.max_fee_per_gas, 50_000);
        assert_eq!(ordered[2].metadata.max_fee_per_gas, 100);
    }

    #[test]
    fn adversarial_double_remove_no_underflow() {
        // Double-removing the same hash must not underflow total_bytes
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let hash = pool
            .submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        let bytes_after_add = pool.byte_usage();
        assert!(
            bytes_after_add > 0,
            "submitted envelope must have non-zero byte size"
        );

        // Remove once — pool is now empty, bytes must be 0
        pool.remove_committed(&[hash]);
        assert_eq!(pool.len(), 0);
        assert_eq!(
            pool.byte_usage(),
            0,
            "removing only envelope must zero out byte usage"
        );

        // Remove same hash again — should NOT underflow, must stay at 0
        pool.remove_committed(&[hash]);
        assert_eq!(
            pool.byte_usage(),
            0,
            "double-remove must not underflow (saturating_sub)"
        );
    }

    #[test]
    fn adversarial_partial_decryption_failure() {
        // Some envelopes decrypt, some don't — ensure valid ones still work
        let keypair1 = SchnorrKeyPair::generate();
        let keypair2 = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let good_key = test_epoch_key();
        let bad_key = EpochKey::derive(&Hash256::from_bytes([0xCC; 32]), 99);

        // Good envelope (encrypted with test key)
        let env_good = make_signed_envelope(&keypair1, 0, 100, 10);
        pool.submit(env_good).unwrap();

        // Bad envelope (encrypted with wrong key, but valid commitment+sig)
        let from = Address::from_public_key(keypair2.public_key().as_bytes());
        let to = Address::from_bytes([0xBB; 20]);
        let body = TransactionBody {
            from,
            kind: TransactionKind::Transfer { to, amount: 50_000 },
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 200,
            max_priority_fee_per_gas: 10, // Higher priority
            chain_id: chain_id::TESTNET,
        };
        let body_hash = body.hash();
        let sig = keypair2.sign(&body_hash).unwrap();
        let tx = Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(*keypair2.public_key()),
        };
        let env_bad = EncryptedEnvelope::encrypt(&tx, &bad_key, 1, &keypair2).unwrap();
        pool.submit(env_bad).unwrap();

        assert_eq!(pool.len(), 2);

        // Lock ordering, confirm on L1, then decrypt after delay
        lock_and_confirm_ordering(&mut pool, 100);
        let txs = pool.decrypt_batch(&good_key, 10, 102).unwrap();
        assert_eq!(
            txs.len(),
            1,
            "Only the correctly-encrypted envelope should decrypt"
        );
        assert_eq!(txs[0].body.max_fee_per_gas, 100);
    }

    #[test]
    fn adversarial_tampered_commitment_rejected() {
        // Envelope with tampered commitment should be rejected at submit
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let mut env = make_signed_envelope(&keypair, 0, 100, 10);
        env.commitment.0[0] ^= 0xFF; // Tamper commitment

        let result = pool.submit(env);
        assert!(result.is_err(), "Tampered commitment must be rejected");
    }

    #[test]
    fn adversarial_tampered_signature_rejected() {
        // Envelope with tampered Schnorr signature should be rejected
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let mut env = make_signed_envelope(&keypair, 0, 100, 10);
        // Tamper signature bytes
        let mut sig_bytes = env.signature.as_bytes().to_vec();
        sig_bytes[0] ^= 0xFF;
        if let Ok(tampered) = brrq_crypto::schnorr::SchnorrSignature::from_slice(&sig_bytes) {
            env.signature = tampered;
        }

        let result = pool.submit(env);
        assert!(result.is_err(), "Tampered signature must be rejected");
    }

    #[test]
    fn adversarial_byte_budget_enforcement() {
        // Byte budget must prevent over-allocation
        let keypair = SchnorrKeyPair::generate();
        // Set very tight byte budget (500 bytes)
        let mut pool = MevMempool::with_capacity(1, 10_000, 500);

        // First envelope should fit
        let env1 = make_signed_envelope(&keypair, 0, 100, 10);
        let size1 = env1.size();
        pool.submit(env1).unwrap();

        // Keep adding until we exceed budget
        let mut nonce = 1;
        loop {
            let env = make_signed_envelope(&keypair, nonce, 100, 100);
            match pool.submit(env) {
                Ok(_) => {
                    nonce += 1;
                    if nonce > 100 {
                        panic!("Should have hit byte budget by now");
                    }
                }
                Err(_) => break,
            }
        }

        assert!(
            pool.byte_usage() <= 500,
            "Byte usage must not exceed budget"
        );
        assert!(pool.byte_usage() + size1 > 500, "Budget was actually hit");
    }

    #[test]
    fn adversarial_insertion_order_stability() {
        // Same max_fee_per_gas → insertion order determines priority (FIFO within same price tier)
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let env1 = make_signed_envelope(&keypair, 0, 100, 10);
        let env2 = make_signed_envelope(&keypair, 1, 100, 10);
        let env3 = make_signed_envelope(&keypair, 2, 100, 10);

        pool.submit(env1).unwrap();
        pool.submit(env2).unwrap();
        pool.submit(env3).unwrap();

        let ordered = pool.get_ordered(10);
        assert_eq!(ordered.len(), 3);
        // All same max_fee_per_gas → should maintain insertion order
        assert_eq!(ordered[0].metadata.nonce, 0);
        assert_eq!(ordered[1].metadata.nonce, 1);
        assert_eq!(ordered[2].metadata.nonce, 2);
    }

    #[test]
    fn adversarial_get_ordered_max_count_limit() {
        // get_ordered should respect max_count
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        for i in 0..5 {
            pool.submit(make_signed_envelope(&keypair, i, (i + 1) * 10, 1))
                .unwrap();
        }

        let ordered = pool.get_ordered(3);
        assert_eq!(ordered.len(), 3, "Must respect max_count");
        // Top 3 by max_fee_per_gas
        assert_eq!(ordered[0].metadata.max_fee_per_gas, 50);
        assert_eq!(ordered[1].metadata.max_fee_per_gas, 40);
        assert_eq!(ordered[2].metadata.max_fee_per_gas, 30);
    }

    #[test]
    fn adversarial_decrypt_batch_max_count_limit() {
        // decrypt_batch should respect max_count
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let epoch_key = test_epoch_key();

        for i in 0..5 {
            pool.submit(make_signed_envelope(&keypair, i, (i + 1) * 10, 1))
                .unwrap();
        }

        lock_and_confirm_ordering(&mut pool, 100);
        let txs = pool.decrypt_batch(&epoch_key, 2, 102).unwrap();
        assert_eq!(txs.len(), 2, "Must respect max_count in decrypt_batch");
        assert_eq!(txs[0].body.max_fee_per_gas, 50);
        assert_eq!(txs[1].body.max_fee_per_gas, 40);
    }

    #[test]
    fn adversarial_reset_clears_known_hashes() {
        // After reset, previously submitted envelopes should be acceptable again
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        let env = make_signed_envelope(&keypair, 0, 100, 10);
        let env_clone = env.clone();

        pool.submit(env).unwrap();
        // Duplicate rejected
        assert!(pool.submit(env_clone.clone()).is_err());

        // Reset
        pool.reset_phase();

        // Same envelope should now be acceptable
        pool.submit(env_clone).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_reveal_delay_enforcement() {
        // Decrypt in the same block as lock should fail (H-1 mitigation)
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let epoch_key = test_epoch_key();

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        lock_and_confirm_ordering(&mut pool, 50); // Lock at height 50

        // Decrypt at height 50 (same block) → must fail
        let result = pool.decrypt_batch(&epoch_key, 10, 50);
        assert!(result.is_err(), "Decrypt in same block as lock must fail");

        // Decrypt at height 52 (lock + MIN_REVEAL_DELAY_BLOCKS) → must succeed
        let txs = pool.decrypt_batch(&epoch_key, 10, 52).unwrap();
        assert_eq!(txs.len(), 1);
    }

    #[test]
    fn test_lock_height_cleared_on_reset() {
        let mut pool = MevMempool::new(1);
        pool.lock_ordering(42).unwrap();
        assert_eq!(pool.lock_height(), Some(42));
        pool.reset_phase();
        assert_eq!(pool.lock_height(), None);
    }

    #[test]
    fn test_reveal_delay_overflow_safe() {
        // lock_height at u64::MAX must NOT bypass the delay via overflow
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let epoch_key = test_epoch_key();

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        lock_and_confirm_ordering(&mut pool, u64::MAX);

        // Any current_height should fail (saturating_add prevents wrap to 0)
        let result = pool.decrypt_batch(&epoch_key, 10, u64::MAX);
        assert!(
            result.is_err(),
            "Overflow: lock at u64::MAX must not bypass delay"
        );
    }

    #[test]
    fn test_double_lock_preserves_original_height() {
        // Calling lock_ordering twice must not reset the timer
        let mut pool = MevMempool::new(1);

        pool.lock_ordering(100).unwrap();
        assert_eq!(pool.lock_height(), Some(100));

        // Second call with later height must NOT overwrite
        pool.lock_ordering(200).unwrap();
        assert_eq!(
            pool.lock_height(),
            Some(100),
            "Double lock must preserve original height"
        );
    }

    #[test]
    fn adversarial_lock_ordering_is_irreversible_without_reset() {
        // Once ordering is locked, only reset_phase can go back to Commit
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        pool.lock_ordering(100).unwrap();

        // Cannot submit after lock
        assert!(
            pool.submit(make_signed_envelope(&keypair, 1, 200, 10))
                .is_err()
        );

        // Lock again should not crash (idempotent)
        pool.lock_ordering(100).unwrap();
        assert_eq!(*pool.phase(), MevPhase::Ordering);
    }

    // ── WI-5D: Input validation tests ─────────────────────────────────

    #[test]
    fn test_decrypt_without_ordering_commitment_fails() {
        // Sequencer must confirm ordering on L1 before decrypting.
        // Attempting to decrypt without confirmation must fail.
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let epoch_key = test_epoch_key();

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        pool.lock_ordering(100).unwrap();
        // Do NOT call confirm_ordering_committed

        let result = pool.decrypt_batch(&epoch_key, 10, 102);
        assert!(
            result.is_err(),
            "decrypt_batch must fail without ordering commitment"
        );
        let err_msg = format!("{:?}", result.unwrap_err());
        assert!(
            err_msg.contains("commit ordering"),
            "error should mention ordering commitment requirement"
        );
    }

    #[test]
    fn test_confirm_ordering_wrong_commitment_fails() {
        // L1 anchor with wrong ordering commitment must be rejected.
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        pool.lock_ordering(100).unwrap();

        let wrong_anchor = L1OrderingAnchor::new(
            Hash256::from_bytes([0x11; 32]), // wrong commitment
            100,
            Hash256::from_bytes([0xFF; 32]),
        );
        let result = pool.confirm_ordering_committed(&wrong_anchor);
        assert!(
            result.is_err(),
            "confirm with wrong commitment must fail"
        );
    }

    #[test]
    fn test_ordering_committed_flag_cleared_on_reset() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);

        pool.submit(make_signed_envelope(&keypair, 0, 100, 10))
            .unwrap();
        lock_and_confirm_ordering(&mut pool, 100);
        assert!(pool.is_ordering_committed());

        pool.reset_phase();
        assert!(!pool.is_ordering_committed(), "ordering_committed must be cleared on reset");
    }

    #[test]
    fn test_wi5d_zero_max_fee_per_gas_rejected() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let env = make_signed_envelope(&keypair, 0, 0, 10); // max_fee_per_gas = 0

        let result = pool.submit(env);
        assert!(result.is_err(), "zero max_fee_per_gas must be rejected");
    }

    #[test]
    fn test_wi5d_zero_commitment_rejected() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let mut env = make_signed_envelope(&keypair, 0, 100, 10);
        env.commitment = Hash256::ZERO; // tamper commitment to zero

        let result = pool.submit(env);
        assert!(result.is_err(), "zero commitment must be rejected");
    }

    #[test]
    fn test_wi5d_empty_encrypted_kind_rejected() {
        let keypair = SchnorrKeyPair::generate();
        let mut pool = MevMempool::new(1);
        let mut env = make_signed_envelope(&keypair, 0, 100, 10);
        env.encrypted_kind = Vec::new(); // empty ciphertext

        let result = pool.submit(env);
        assert!(result.is_err(), "empty encrypted_kind must be rejected");
    }
}
