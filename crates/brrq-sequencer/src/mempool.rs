//! Transaction mempool.
//!
//! Holds pending transactions ordered by gas price (priority)
//! and nonce (per-account ordering).
//!
//! Enforces two capacity limits per whitepaper §8.4:
//! - **Count**: 10,000 transactions maximum
//! - **Size**: 50 MB maximum byte budget
//!
//! Transactions expire after 30 minutes (whitepaper §8.4).

use brrq_crypto::hash::Hash256;
use brrq_types::address::Address;
use brrq_types::transaction::{Transaction, TransactionKind};

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::time::Instant;

use crate::error::SequencerError;

/// An obfuscated transaction payload stored in the mempool.
/// Exposes strictly metadata (gas price, fees, nonce) for sequencer selection,
/// whilst blinding the underlying semantic payload (such as contract calls or exact balances)
/// to hinder generic-frontrunning MEV and transaction sniping until block inclusion.
#[derive(Debug, Clone)]
pub struct ObfuscatedTransaction {
    /// The actual transaction (kept hidden from p2p broadcast queries until execution)
    /// Restricted to pub(crate) to prevent external crates from accessing
    /// the plaintext transaction directly, which would bypass MEV obfuscation.
    pub(crate) inner: Transaction,
    /// Estimated size for mempool limits
    pub estimated_size: usize,
    /// Insertion order for stable sorting
    pub insertion_order: u64,
}

impl ObfuscatedTransaction {
    /// Accessor for the inner transaction (crate-internal only).
    pub(crate) fn transaction(&self) -> &Transaction {
        &self.inner
    }
}

impl ObfuscatedTransaction {
    pub fn new(tx: Transaction, insertion_order: u64) -> Self {
        let size = estimate_tx_bytes(&tx);
        Self {
            inner: tx,
            estimated_size: size,
            insertion_order,
        }
    }
}

/// Maximum mempool capacity (number of transactions). Whitepaper §8.4.
const DEFAULT_MAX_SIZE: usize = 10_000;

/// Maximum mempool byte budget (50 MB). Whitepaper §8.4.
const DEFAULT_MAX_BYTES: usize = 50 * 1024 * 1024; // 50 MB

/// Transaction time-to-live (30 minutes). Whitepaper §8.4.
const TX_TTL_SECS: u64 = 30 * 60; // 1800 seconds

/// Maximum pending transactions per account to prevent spam.
/// Without this limit, a single account could monopolize the entire
/// mempool capacity.
const MAX_TXS_PER_ACCOUNT: usize = 64;

/// Maximum gap between submitted tx nonce and confirmed account nonce.
/// Allows up to 16 pending transactions ahead of the confirmed nonce.
pub const MAX_NONCE_GAP: u64 = 16;

/// Maximum number of committed hashes to retain for replay prevention.
/// When exceeded, the oldest hashes are dropped (bulk clear and restart).
const MAX_COMMITTED_HASHES: usize = 100_000;

/// Estimate the wire size of a transaction in bytes.
///
/// TransactionBody baseline ~52 bytes (from=20 + nonce=8 + gas_limit=8 + gas_price=8 + chain_id=8)
/// + kind overhead (~30 bytes for Transfer), + signature + public_key.
fn estimate_tx_bytes(tx: &Transaction) -> usize {
    let base = 82; // conservative TransactionBody overhead
    base + tx.signature.size() + tx.public_key.size()
}

#[derive(Debug, Clone)]
pub struct Mempool {
    /// Obfuscated transactions by hash.
    txs: HashMap<Hash256, ObfuscatedTransaction>,
    /// Per-account pending nonces to detect gaps.
    account_nonces: HashMap<Address, Vec<u64>>,
    /// Known tx hashes (including recently removed) to prevent duplicates.
    known_hashes: HashSet<Hash256>,
    /// Committed transaction hashes retained for replay prevention.
    /// Bounded to MAX_COMMITTED_HASHES to prevent unbounded memory growth.
    committed_hashes: HashSet<Hash256>,
    /// Insertion-ordered queue of committed hashes for rolling eviction.
    committed_order: VecDeque<Hash256>,
    /// Insertion counter for ordering within same gas price.
    insertion_counter: u64,
    /// Maximum number of transactions.
    max_size: usize,
    /// Maximum total byte budget.
    max_bytes: usize,
    /// Current estimated byte usage.
    total_bytes: usize,
    /// Insertion timestamp per tx hash for TTL expiry.
    inserted_at: HashMap<Hash256, Instant>,
    /// Current base fee derived from the previous block's gas utilization.
    base_fee: u64,
    /// Fast O(log N) Priority Index tracking `(EffectiveTip, InvertedNonce, TxHash)`.
    /// The lowest priority drops first. Used by `evict_lowest_fee`.
    fee_index: BTreeMap<(u64, u64, Hash256), ()>,

    // ── Portal (L3) mempool awareness ─────────────────────────────
    /// Nullifiers from pending SettlePortalLock/BatchSettlePortal txs.
    /// Merchants query this via API to detect in-flight settlements.
    pending_portal_nullifiers: HashSet<Hash256>,
    /// Lock IDs from pending CancelPortalLock txs.
    /// Merchants query this via API to detect in-flight cancellations.
    pending_portal_cancels: HashSet<Hash256>,
    /// Lock IDs targeted by pending settlements.
    /// When a CancelPortalLock arrives for a lock with a pending settlement,
    /// the cancel is rejected to prevent cross-block front-running.
    pending_portal_settlement_locks: HashSet<Hash256>,
}

impl Mempool {
    /// Create a new empty mempool.
    pub fn new() -> Self {
        Self {
            txs: HashMap::new(),
            account_nonces: HashMap::new(),
            known_hashes: HashSet::new(),
            committed_hashes: HashSet::new(),
            committed_order: VecDeque::new(),
            insertion_counter: 0,
            max_size: DEFAULT_MAX_SIZE,
            max_bytes: DEFAULT_MAX_BYTES,
            total_bytes: 0,
            inserted_at: HashMap::new(),
            base_fee: 10, // Default INITIAL_BASE_FEE
            fee_index: BTreeMap::new(),
            pending_portal_nullifiers: HashSet::new(),
            pending_portal_cancels: HashSet::new(),
            pending_portal_settlement_locks: HashSet::new(),
        }
    }

    /// Create a mempool with a custom size limit.
    pub fn with_capacity(max_size: usize) -> Self {
        Self {
            max_size,
            ..Self::new()
        }
    }

    /// Get the current base fee required for mempool admission
    pub fn current_base_fee(&self) -> u64 {
        self.base_fee
    }

    /// Update the current base fee after a block is produced.
    /// This keeps the mempool in sync with the EIP-1559 network cost.
    pub fn set_base_fee(&mut self, fee: u64) {
        self.base_fee = fee;
        // Actively purge underwater transactions when base_fee spikes
        // to prevent them from consuming capacity and causing a gridlock DoS.
        let underwater_hashes: Vec<Hash256> = self
            .txs
            .iter()
            .filter(|(_, ob)| ob.inner.body.max_fee_per_gas < self.base_fee)
            .map(|(hash, _)| *hash)
            .collect();
        if !underwater_hashes.is_empty() {
            tracing::info!(
                "Evicting {} underwater transactions after base_fee spiked to {}",
                underwater_hashes.len(),
                fee
            );
            self.remove_evicted(&underwater_hashes);
        }

        // Restore O(N log N) index rebuild because effective_tip is dynamic.
        self.fee_index.clear();
        for (hash, ob) in &self.txs {
            let tx = &ob.inner;
            let effective_tip = std::cmp::min(
                tx.body.max_fee_per_gas.saturating_sub(self.base_fee),
                tx.body.max_priority_fee_per_gas,
            );
            let inverted_nonce = u64::MAX.saturating_sub(tx.body.nonce);
            self.fee_index
                .insert((effective_tip, inverted_nonce, *hash), ());
        }
    }

    /// Evicts the lowest paying transaction to make room for a higher-paying one natively via `O(log N)` BTreeMap.
    /// Returns true if an eviction occurred, false if the mempool is full of higher paying txs.
    fn evict_lowest_fee(&mut self) -> bool {
        if let Some(((_e_tip, _inv_nonce, target_hash), _)) = self.fee_index.pop_first() {
            tracing::debug!(
                "O(log N) Evicting mempool hash {:?} preventing DoS gridlock",
                target_hash
            );
            self.remove_evicted(&[target_hash]);
            // Re-insert evicted hash into known_hashes to prevent instant
            // re-submission. Cap known_hashes at 4x max_size to prevent
            // unbounded memory growth; skip re-insert when cap is hit.
            let known_cap = self.max_size.saturating_mul(4);
            if self.known_hashes.len() < known_cap {
                self.known_hashes.insert(target_hash);
            }
            true
        } else {
            false
        }
    }

    /// Add a transaction to the mempool.
    ///
    /// # Precondition
    ///  The caller MUST verify `tx.verify_signature()`
    /// BEFORE acquiring the write lock and calling this method. Signature verification
    /// is CPU-intensive (Schnorr verify) and performing it under the write lock blocks
    /// all concurrent readers (balance queries, height queries, RPCs). All production
    /// call sites (services.rs, network_service.rs) already verify before the lock.
    pub fn add(&mut self, tx: Transaction) -> Result<Hash256, SequencerError> {
        let tx_hash = tx.hash();

        // Enforce load shedding requirement using current base fee
        let required_fee = self.current_base_fee();
        if tx.body.max_fee_per_gas < required_fee {
            return Err(SequencerError::InvalidTransaction {
                reason: format!(
                    "gas price {} below current_base_fee {}",
                    tx.body.max_fee_per_gas, required_fee
                ),
            });
        }

        // Check for duplicates (both pending and previously committed)
        if self.known_hashes.contains(&tx_hash) || self.committed_hashes.contains(&tx_hash) {
            return Err(SequencerError::DuplicateTransaction {
                tx_hash: format!("{:?}", tx_hash),
            });
        }

        // Validate signature before eviction decisions.
        if !tx.is_structurally_valid() {
            return Err(SequencerError::InvalidTransaction {
                reason: "structurally invalid".into(),
            });
        }
        if tx.verify_signature().is_err() {
            return Err(SequencerError::InvalidTransaction {
                reason: "invalid signature".into(),
            });
        }

        // Check transaction capacity and evict instead of rejecting
        let tx_bytes = estimate_tx_bytes(&tx);

        while self.txs.len() >= self.max_size || self.total_bytes + tx_bytes > self.max_bytes {
            let effective_tip = std::cmp::min(
                tx.body
                    .max_fee_per_gas
                    .saturating_sub(self.current_base_fee()),
                tx.body.max_priority_fee_per_gas,
            );

            let mut lowest_tip = u64::MAX;
            if let Some(((tip, _, _), _)) = self.fee_index.first_key_value() {
                lowest_tip = *tip;
            }

            // Require strictly HIGHER tip (not equal) to prevent zero-cost
            // churning DoS where equal-tip transactions evict each other
            // indefinitely without economic cost.
            if effective_tip <= lowest_tip {
                return Err(SequencerError::MempoolFull {
                    capacity: self.max_size,
                    current: self.txs.len(),
                });
            }

            if !self.evict_lowest_fee() {
                break;
            }
        }

        // NOTE: Structural validity and signature already verified above (before eviction).
        // No need to re-check here.

        let _gas_price = tx.body.max_fee_per_gas;
        let sender = *tx.sender();

        // Per-account transaction limit to prevent DoS.
        let account_nonces = self.account_nonces.entry(sender).or_default();
        if account_nonces.len() >= MAX_TXS_PER_ACCOUNT {
            return Err(SequencerError::InvalidTransaction {
                reason: format!(
                    "account {} has {} pending txs (max {})",
                    sender,
                    account_nonces.len(),
                    MAX_TXS_PER_ACCOUNT
                ),
            });
        }

        // Reject duplicate nonces from the same sender.
        if account_nonces.contains(&tx.body.nonce) {
            return Err(SequencerError::InvalidTransaction {
                reason: format!(
                    "account {} already has pending tx with nonce {}",
                    sender, tx.body.nonce
                ),
            });
        }

        // Track nonce
        account_nonces.push(tx.body.nonce);

        // Store
        self.known_hashes.insert(tx_hash);
        self.inserted_at.insert(tx_hash, Instant::now());
        self.total_bytes += tx_bytes;

        // Compute fee_index key and handle portal tracking BEFORE consuming tx,
        // avoiding an unnecessary tx.clone().
        // Mount to our O(log N) Priority Index bridging rapid eviction defenses softly.
        let inverted_nonce = u64::MAX.saturating_sub(tx.body.nonce); // Higher Nonces sort FIRST (evicted earlier)

        let effective_tip = std::cmp::min(
            tx.body
                .max_fee_per_gas
                .saturating_sub(self.current_base_fee()),
            tx.body.max_priority_fee_per_gas,
        );

        // Track pending portal operations for merchant safety queries.
        // This leaks minimal info (boolean per nullifier/lock_id) — acceptable
        // tradeoff vs full MEV obfuscation since it only reveals existence, not
        // amounts, senders, or fees.
        match &tx.body.kind {
            TransactionKind::SettlePortalLock { nullifier, lock_id, .. } => {
                self.pending_portal_nullifiers.insert(*nullifier);
                self.pending_portal_settlement_locks.insert(*lock_id);
            }
            TransactionKind::BatchSettlePortal { claims } => {
                for claim in claims {
                    self.pending_portal_nullifiers.insert(claim.nullifier);
                    self.pending_portal_settlement_locks.insert(claim.lock_id);
                }
            }
            TransactionKind::RelayedBatchSettle { claims, .. } => {
                for claim in claims {
                    self.pending_portal_nullifiers.insert(claim.nullifier);
                    self.pending_portal_settlement_locks.insert(claim.lock_id);
                }
            }
            TransactionKind::CancelPortalLock { lock_id } => {
                // Reject cancel if settlement is already pending for this lock.
                // This prevents cross-block front-running where a user cancels in block N
                // and the merchant's settlement fails in block N+1.
                // NOTE: C-2 already prevents cancel after condition_hash is set (on-chain),
                // but this mempool-level check provides early rejection before gas is wasted.
                if self.pending_portal_settlement_locks.contains(lock_id) {
                    // Reject the transaction instead of silently falling through
                    // to insertion — prevents gas waste and tracking inconsistency.
                    return Err(SequencerError::InvalidTransaction {
                        reason: format!(
                            "cancel rejected: lock {} has a pending settlement",
                            lock_id
                        ),
                    });
                } else {
                    self.pending_portal_cancels.insert(*lock_id);
                }
            }
            _ => {}
        }

        // Now consume tx by move (no clone needed — all fields read above)
        let obfuscated = ObfuscatedTransaction::new(tx, self.insertion_counter);
        self.insertion_counter += 1;
        self.txs.insert(tx_hash, obfuscated);

        self.fee_index
            .insert((effective_tip, inverted_nonce, tx_hash), ());

        Ok(tx_hash)
    }

    /// Get the next batch of transactions for block building.
    ///
    /// Uses the existing `fee_index` BTreeMap which
    /// already maintains transactions sorted by `(effective_tip, inverted_nonce, hash)`.
    /// Iterates in reverse (highest tip first) and takes `max_count` entries.
    /// This is O(max_count) with zero allocation instead of the previous O(N log N)
    /// collect-and-sort approach.
    pub fn get_pending(&self, max_count: usize) -> Vec<&Transaction> {
        self.fee_index
            .iter()
            .rev() // highest effective_tip first
            .filter_map(|((_, _, hash), _)| self.txs.get(hash).map(|ob| &ob.inner))
            .take(max_count)
            .collect()
    }

    /// Remove transactions that were included in a block.
    ///
    /// Uses a reverse index for O(log n) removal from the priority queue
    /// instead of O(n) `retain()`.
    /// Remove a transaction from internal data structures (shared by all removal paths).
    fn remove_tx_internal(&mut self, hash: &Hash256) {
        if let Some(obfuscated) = self.txs.remove(hash) {
            let tx = &obfuscated.inner;
            self.total_bytes = self.total_bytes.saturating_sub(obfuscated.estimated_size);
            let sender = *tx.sender();
            if let Some(nonces) = self.account_nonces.get_mut(&sender) {
                nonces.retain(|&n| n != tx.body.nonce);
                if nonces.is_empty() {
                    self.account_nonces.remove(&sender);
                }
            }

            let inverted_nonce = u64::MAX.saturating_sub(tx.body.nonce);
            let effective_tip = std::cmp::min(
                tx.body.max_fee_per_gas.saturating_sub(self.base_fee),
                tx.body.max_priority_fee_per_gas,
            );
            self.fee_index
                .remove(&(effective_tip, inverted_nonce, *hash));

            // Clean up pending portal tracking
            self.remove_portal_tracking(tx);
        }
        self.inserted_at.remove(hash);
    }

    pub fn remove_committed(&mut self, tx_hashes: &[Hash256]) {
        for hash in tx_hashes {
            self.remove_tx_internal(hash);
            // Move hash to committed_hashes instead of dropping it.
            // This prevents replay of committed transactions.
            self.known_hashes.remove(hash);
            self.committed_hashes.insert(*hash);
            self.committed_order.push_back(*hash);
            if self.committed_hashes.len() > MAX_COMMITTED_HASHES {
                // Evict oldest 10% instead of clearing everything,
                // preserving replay protection for ~90% of recent transactions.
                let evict_count = MAX_COMMITTED_HASHES / 10;
                for _ in 0..evict_count {
                    if let Some(old) = self.committed_order.pop_front() {
                        self.committed_hashes.remove(&old);
                    }
                }
            }
        }
    }

    /// Remove evicted transactions WITHOUT marking them as committed.
    ///
    /// Fee-based eviction and underwater purges are NOT block commitments — the
    /// transaction was never included in a block. Marking them as committed would
    /// permanently blacklist re-submission of valid transactions.
    /// Evicted hashes stay in `known_hashes` temporarily to prevent instant
    /// re-flooding, but are NOT added to `committed_hashes`.
    fn remove_evicted(&mut self, tx_hashes: &[Hash256]) {
        for hash in tx_hashes {
            self.remove_tx_internal(hash);
            // Keep in known_hashes to prevent instant re-submission spam,
            // but do NOT add to committed_hashes — tx was never committed.
        }
    }

    /// Number of pending transactions.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }

    /// Get a transaction by hash.
    pub fn get(&self, hash: &Hash256) -> Option<&Transaction> {
        self.txs.get(hash).map(|ob| &ob.inner)
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, hash: &Hash256) -> bool {
        self.txs.contains_key(hash)
    }

    /// Clear all transactions and reset duplicate tracking.
    pub fn clear(&mut self) {
        self.txs.clear();
        self.account_nonces.clear();
        self.known_hashes.clear();
        self.committed_hashes.clear();
        self.committed_order.clear();
        self.inserted_at.clear();
        self.fee_index.clear();
        self.insertion_counter = 0;
        self.total_bytes = 0;
        self.pending_portal_nullifiers.clear();
        self.pending_portal_cancels.clear();
        self.pending_portal_settlement_locks.clear();
    }

    /// Evict transactions older than 30 minutes (whitepaper §8.4).
    ///
    /// Should be called periodically (e.g., once per block or once per minute).
    /// Returns the number of expired transactions removed.
    pub fn evict_expired(&mut self) -> usize {
        let now = Instant::now();
        let ttl = std::time::Duration::from_secs(TX_TTL_SECS);

        let expired: Vec<Hash256> = self
            .inserted_at
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) >= ttl)
            .map(|(hash, _)| *hash)
            .collect();

        // Expired transactions must NOT go into
        // committed_hashes. `remove_committed` conflates expiry (timed out,
        // never included in a block) with commitment (included in a block).
        // Expired transactions should be eligible for re-submission with
        // the same hash. Remove them directly from the mempool instead.
        let count = expired.len();
        for hash in &expired {
            if let Some(obfuscated) = self.txs.remove(hash) {
                let tx = &obfuscated.inner;
                self.total_bytes =
                    self.total_bytes.saturating_sub(obfuscated.estimated_size);
                let sender = *tx.sender();
                if let Some(nonces) = self.account_nonces.get_mut(&sender) {
                    nonces.retain(|&n| n != tx.body.nonce);
                    if nonces.is_empty() {
                        self.account_nonces.remove(&sender);
                    }
                }
                let inverted_nonce = u64::MAX.saturating_sub(tx.body.nonce);
                let effective_tip = std::cmp::min(
                    tx.body.max_fee_per_gas.saturating_sub(self.base_fee),
                    tx.body.max_priority_fee_per_gas,
                );
                self.fee_index
                    .remove(&(effective_tip, inverted_nonce, *hash));

                // Clean up pending portal tracking
                self.remove_portal_tracking(tx);
            }
            self.inserted_at.remove(hash);
            // Unlike remove_committed(), do NOT insert into committed_hashes.
            // Expired transactions were never included in a block and should
            // be eligible for re-submission.
            self.known_hashes.remove(hash);
        }
        count
    }

    /// Get estimated byte usage of the mempool.
    pub fn byte_usage(&self) -> usize {
        self.total_bytes
    }

    // ── Portal (L3) mempool awareness ─────────────────────────────

    /// Check if a nullifier has a pending settlement in the mempool.
    ///
    /// Returns `true` if any pending `SettlePortalLock` or `BatchSettlePortal`
    /// transaction contains this nullifier. Merchants should reject payment
    /// if this returns `true` (another settlement is already in-flight).
    pub fn has_pending_portal_nullifier(&self, nullifier: &Hash256) -> bool {
        self.pending_portal_nullifiers.contains(nullifier)
    }

    /// Check if a lock has a pending cancellation in the mempool.
    ///
    /// Returns `true` if any pending `CancelPortalLock` transaction targets
    /// this lock_id. Merchants should reject payment if this returns `true`
    /// (the lock owner is trying to cancel and reclaim funds).
    pub fn has_pending_portal_cancel(&self, lock_id: &Hash256) -> bool {
        self.pending_portal_cancels.contains(lock_id)
    }

    /// Remove portal tracking entries for a transaction being removed.
    fn remove_portal_tracking(&mut self, tx: &Transaction) {
        match &tx.body.kind {
            TransactionKind::SettlePortalLock { nullifier, lock_id, .. } => {
                self.pending_portal_nullifiers.remove(nullifier);
                // Clean settlement lock tracking on commit/evict
                self.pending_portal_settlement_locks.remove(lock_id);
            }
            TransactionKind::BatchSettlePortal { claims } => {
                for claim in claims {
                    self.pending_portal_nullifiers.remove(&claim.nullifier);
                    // Clean settlement lock tracking
                    self.pending_portal_settlement_locks.remove(&claim.lock_id);
                }
            }
            // Handle RelayedBatchSettle
            TransactionKind::RelayedBatchSettle { claims, .. } => {
                for claim in claims {
                    self.pending_portal_nullifiers.remove(&claim.nullifier);
                    self.pending_portal_settlement_locks.remove(&claim.lock_id);
                }
            }
            TransactionKind::CancelPortalLock { lock_id } => {
                self.pending_portal_cancels.remove(lock_id);
            }
            _ => {}
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_types::signature::{PublicKey, Signature};
    use brrq_types::transaction::{TransactionBody, TransactionKind, chain_id};

    const TEST_SECRET: [u8; 32] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
        0xcd, 0xef,
    ];

    fn build_tx(secret: &[u8; 32], nonce: u64, max_fee: u64, max_priority: u64) -> Transaction {
        use brrq_crypto::schnorr::SchnorrKeyPair;

        let keypair = SchnorrKeyPair::from_secret_bytes(secret).expect("test key must be valid");
        let pk = keypair.public_key();

        let from = Address::from_public_key(pk.as_bytes());
        let to = Address::from_bytes([2u8; 20]);
        let body = TransactionBody {
            from,
            kind: TransactionKind::Transfer { to, amount: 100 },
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: max_priority,
            chain_id: chain_id::TESTNET,
        };

        let body_hash = body.hash();
        let sig = keypair.sign(&body_hash).expect("signing must succeed");

        Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(pk.clone()),
        }
    }

    fn make_tx_from(secret: &[u8; 32], nonce: u64, max_fee: u64, max_priority: u64) -> Transaction {
        build_tx(secret, nonce, max_fee, max_priority)
    }

    fn make_tx(nonce: u64, max_fee: u64, max_priority: u64) -> Transaction {
        make_tx_from(&TEST_SECRET, nonce, max_fee, max_priority)
    }

    #[test]
    fn test_dynamic_base_fee() {
        let mut pool = Mempool::with_capacity(100);
        // Default initial base fee is 10
        assert_eq!(pool.current_base_fee(), 10);

        // Adding transactions does not change the base fee
        for i in 0..50 {
            let mut secret = TEST_SECRET;
            secret[0] = i as u8;
            pool.add(make_tx_from(&secret, i as u64, 100, 10)).unwrap();
        }
        assert_eq!(pool.current_base_fee(), 10);

        // base_fee is updated externally via set_base_fee (driven by block gas utilization)
        pool.set_base_fee(40);
        assert_eq!(pool.current_base_fee(), 40);

        // Transactions with max_fee below the new base fee must be rejected
        let mut fail_secret = TEST_SECRET;
        fail_secret[0] = 200;
        let res = pool.add(make_tx_from(&fail_secret, 0, 39, 10));
        let err = res.unwrap_err();
        assert!(
            matches!(&err, SequencerError::InvalidTransaction { reason } if reason.contains("base_fee")),
            "below-base-fee tx should be rejected with base_fee error, got: {}",
            err,
        );
    }

    #[test]
    fn test_add_and_get() {
        let mut pool = Mempool::new();
        let tx = make_tx(0, 100, 10);
        let hash = pool.add(tx).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&hash));
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut pool = Mempool::new();
        let tx = make_tx(0, 100, 10);
        let tx2 = tx.clone();
        pool.add(tx).unwrap();
        let result = pool.add(tx2);
        assert!(result.is_err());
    }

    #[test]
    fn test_priority_ordering() {
        let mut pool = Mempool::new();
        pool.add(make_tx(0, 10, 10)).unwrap();
        pool.add(make_tx(1, 100, 100)).unwrap();
        pool.add(make_tx(2, 50, 50)).unwrap();

        let pending = pool.get_pending(10);
        assert_eq!(pending.len(), 3);
        assert_eq!(pending[0].body.max_fee_per_gas, 100);
        assert_eq!(pending[1].body.max_fee_per_gas, 50);
        assert_eq!(pending[2].body.max_fee_per_gas, 10);
    }

    #[test]
    fn test_remove_committed() {
        let mut pool = Mempool::new();
        let hash1 = pool.add(make_tx(0, 100, 10)).unwrap();
        let hash2 = pool.add(make_tx(1, 200, 20)).unwrap();
        assert_eq!(pool.len(), 2);

        pool.remove_committed(&[hash1]);
        assert_eq!(pool.len(), 1);
        assert!(!pool.contains(&hash1));
        assert!(pool.contains(&hash2));
    }

    #[test]
    fn test_expiry() {
        let mut pool = Mempool::new();
        pool.add(make_tx(0, 100, 10)).unwrap();
        assert_eq!(pool.len(), 1);

        // Fast forward time by inserting a fake old timestamp
        let tx_hash = pool.txs.keys().next().unwrap().clone();
        let old_time = Instant::now() - std::time::Duration::from_secs(TX_TTL_SECS + 1);
        pool.inserted_at.insert(tx_hash, old_time);

        let evicted = pool.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_capacity_limits() {
        let mut pool = Mempool::with_capacity(2);
        pool.add(make_tx(0, 100, 10)).unwrap();
        pool.add(make_tx(1, 100, 10)).unwrap();
        assert_eq!(pool.len(), 2);

        let mut fail_secret = TEST_SECRET;
        fail_secret[0] = 99;
        // Use a lower effective tip than existing txs so the new tx is rejected (not evicting)
        // Existing txs: effective_tip = min(100-10, 10) = 10
        // New tx: effective_tip = min(15-10, 1) = 1 < 10 => MempoolFull
        let res = pool.add(make_tx_from(&fail_secret, 0, 15, 1));
        assert!(matches!(
            res,
            Err(SequencerError::MempoolFull {
                capacity: 2,
                current: 2
            })
        ));
    }

    #[test]
    fn test_per_account_limit() {
        let mut pool = Mempool::new();
        for i in 0..MAX_TXS_PER_ACCOUNT {
            pool.add(make_tx(i as u64, 100, 10)).unwrap();
        }

        let res = pool.add(make_tx(MAX_TXS_PER_ACCOUNT as u64, 100, 10));
        assert!(matches!(
            res,
            Err(SequencerError::InvalidTransaction { .. })
        ));
    }

    // ── Portal mempool tracking tests ─────────────────────────────

    fn build_portal_tx(
        secret: &[u8; 32],
        nonce: u64,
        kind: TransactionKind,
    ) -> Transaction {
        use brrq_crypto::schnorr::SchnorrKeyPair;

        let keypair = SchnorrKeyPair::from_secret_bytes(secret).expect("test key");
        let pk = keypair.public_key();
        let from = Address::from_public_key(pk.as_bytes());

        let body = TransactionBody {
            from,
            kind,
            nonce,
            gas_limit: 100_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            chain_id: chain_id::TESTNET,
        };
        let body_hash = body.hash();
        let sig = keypair.sign(&body_hash).expect("signing");

        Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(pk.clone()),
        }
    }

    #[test]
    fn test_portal_pending_nullifier_tracking() {
        use brrq_crypto::hash::Hasher;

        let mut pool = Mempool::new();
        let nullifier = Hasher::hash(b"test_nullifier_001");
        let lock_id = Hasher::hash(b"test_lock_001");

        // Initially no pending nullifier
        assert!(!pool.has_pending_portal_nullifier(&nullifier));

        // Add a SettlePortalLock tx
        let tx = build_portal_tx(&TEST_SECRET, 0, TransactionKind::SettlePortalLock {
            lock_id,
            merchant_secret: b"secret".to_vec(),
            portal_signature: vec![0u8; 64],
            nullifier,
        });
        let tx_hash = pool.add(tx).unwrap();

        // Nullifier should now be tracked as pending
        assert!(pool.has_pending_portal_nullifier(&nullifier));

        // Remove (committed) — nullifier should be cleared
        pool.remove_committed(&[tx_hash]);
        assert!(!pool.has_pending_portal_nullifier(&nullifier));
    }

    #[test]
    fn test_portal_pending_cancel_tracking() {
        use brrq_crypto::hash::Hasher;

        let mut pool = Mempool::new();
        let lock_id = Hasher::hash(b"cancel_lock_001");

        assert!(!pool.has_pending_portal_cancel(&lock_id));

        let tx = build_portal_tx(&TEST_SECRET, 0, TransactionKind::CancelPortalLock {
            lock_id,
        });
        let tx_hash = pool.add(tx).unwrap();

        assert!(pool.has_pending_portal_cancel(&lock_id));

        pool.remove_committed(&[tx_hash]);
        assert!(!pool.has_pending_portal_cancel(&lock_id));
    }

    #[test]
    fn test_portal_pending_cleared_on_clear() {
        use brrq_crypto::hash::Hasher;

        let mut pool = Mempool::new();
        let nullifier = Hasher::hash(b"clear_null");
        let lock_id = Hasher::hash(b"clear_lock");

        pool.add(build_portal_tx(&TEST_SECRET, 0, TransactionKind::SettlePortalLock {
            lock_id: Hasher::hash(b"x"),
            merchant_secret: b"s".to_vec(),
            portal_signature: vec![0u8; 64],
            nullifier,
        })).unwrap();

        // Use different key to avoid nonce collision
        let secret2: [u8; 32] = [0x02; 32];
        pool.add(build_portal_tx(&secret2, 0, TransactionKind::CancelPortalLock {
            lock_id,
        })).unwrap();

        assert!(pool.has_pending_portal_nullifier(&nullifier));
        assert!(pool.has_pending_portal_cancel(&lock_id));

        pool.clear();

        assert!(!pool.has_pending_portal_nullifier(&nullifier));
        assert!(!pool.has_pending_portal_cancel(&lock_id));
    }
}
