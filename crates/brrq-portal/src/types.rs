//! Core Portal types: PortalLock, PortalKey, SettlementClaim, BatchResult.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::{SchnorrPublicKey, SchnorrSignature};
use brrq_types::Address;
use serde::{Deserialize, Serialize};

/// Minimum timeout in L2 blocks (~24 hours at 3s/block = 28800, but using
/// the whitepaper's reference of 144 L1 blocks mapped to L2 blocks).
/// Prevents short-timeout griefing attacks.
pub const MIN_TIMEOUT_BLOCKS: u64 = 28_800;

/// Maximum timeout (~1 year at 3s/block = 10,512,000 blocks).
/// Prevents permanent state bloat from locks that can never expire.
pub const MAX_TIMEOUT_BLOCKS: u64 = 10_512_000;

/// Maximum claims per batch settlement.
pub const MAX_BATCH_SIZE: usize = 100;

/// Minimum lock amount in satoshis (base dust limit).
/// Set to Bitcoin dust limit (546 sats) to align with L1 economics.
pub const MIN_LOCK_AMOUNT: u64 = 546;

/// Cost per block of lock duration, in satoshis.
/// Makes long-lived locks proportionally more expensive.
///
/// A 1-day lock (~28,800 blocks) costs: 28,800 × 1 = 28,800 sats minimum.
/// A 1-year lock (~10.5M blocks) costs: 10,500,000 × 1 = 10.5M sats minimum.
///
/// This makes "million dust locks for a year" economically impossible:
/// 1M locks × 10.5M sats = 10.5T sats = 105,000 BTC required.
pub const STATE_COST_PER_BLOCK_SAT: u64 = 1;

/// Maximum active locks per address (prevents state bloat).
pub const MAX_LOCKS_PER_ADDRESS: usize = 1_000;

/// Maximum relay fee in basis points (1% = 100 bps).
pub const MAX_RELAY_FEE_BPS: u16 = 100;

/// Settlement grace period after timeout (in L2 blocks).
///
/// Allows merchants to settle locks that expired during sequencer downtime.
/// The lock owner cannot get a refund until timeout + GRACE_BLOCKS.
/// This creates a window where:
///   - Settlement is still accepted (merchant can claim)
///   - Expiry is delayed (user can't double-claim)
///
/// 2880 blocks ≈ 2.4 hours at 3s/block — sufficient for sequencer recovery.
pub const SETTLEMENT_GRACE_BLOCKS: u64 = 2_880;

/// Status of a Portal lock on L2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockStatus {
    /// Lock is active and can be settled.
    Active,
    /// Lock has been settled by a merchant.
    Settled,
    /// Lock has expired and funds returned to owner.
    Expired,
    /// Lock was cancelled by the owner before any Portal Key was issued.
    Cancelled,
}

/// A Portal lock on L2 — funds escrowed from user's balance.
///
/// Created via `create_lock` transaction. The amount is deducted from the
/// user's balance immediately and held in escrow until settlement or timeout.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortalLock {
    /// Unique lock identifier.
    /// Derived: SHA-256(PORTAL_LOCK_V1 || owner || amount || condition_hash || timeout || nonce)
    pub lock_id: Hash256,
    /// Account owner on L2 who created the lock.
    pub owner: Address,
    /// Owner's public key (for signature verification).
    pub owner_pubkey: SchnorrPublicKey,
    /// Amount locked in satoshis.
    pub amount: u64,
    /// H(merchant_secret) — the merchant's condition for settlement.
    pub condition_hash: Hash256,
    /// Pre-computed nullifier commitment (stored for verification).
    /// N = HMAC-SHA256(secret_key, lock_id || condition_hash)
    pub nullifier_hash: Hash256,
    /// L2 block height at which the lock expires.
    pub timeout_l2_block: u64,
    /// Current status of the lock.
    pub status: LockStatus,
    /// L2 block height when this lock was created.
    pub created_at_block: u64,
    /// Intended merchant address (set during UpdateLockCondition).
    /// If non-zero, settlement MUST credit this address.
    /// Prevents front-running attacks on RelayedBatchSettle.
    pub merchant_address: Address,
    /// Merchant's Schnorr public key for relay signature verification.
    /// Set during UpdateLockCondition alongside merchant_address.
    /// Prevents pubkey substitution attack where attacker creates a 1-sat lock
    /// and uses their own owner_pubkey to forge merchant_signature.
    pub merchant_pubkey: SchnorrPublicKey,
}

/// Compute a deterministic lock_id.
pub fn compute_lock_id(
    owner: &Address,
    amount: u64,
    condition_hash: &Hash256,
    timeout_l2_block: u64,
    nonce: u64,
) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(brrq_crypto::domain_tags::PORTAL_LOCK_V1);
    hasher.update(owner.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(condition_hash.as_bytes());
    hasher.update(&timeout_l2_block.to_le_bytes());
    hasher.update(&nonce.to_le_bytes());
    hasher.finalize()
}

/// Compute the extended deterministic nullifier.
///
/// N = HMAC-SHA256(secret_key, PORTAL_NULLIFIER_V1 || lock_id || condition_hash)
///
/// The condition_hash inclusion prevents sending the same nullifier to two
/// different merchants — each merchant gets a unique nullifier per lock.
pub fn compute_nullifier(
    secret_key: &[u8; 32],
    lock_id: &Hash256,
    condition_hash: &Hash256,
) -> Hash256 {
    // HMAC-SHA256(K, M) = SHA-256((K ^ opad) || SHA-256((K ^ ipad) || M))
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= secret_key[i];
        opad[i] ^= secret_key[i];
    }

    // Inner hash: SHA-256(ipad || domain_tag || lock_id || condition_hash)
    let mut inner = Hasher::new();
    inner.update(&ipad);
    inner.update(brrq_crypto::domain_tags::PORTAL_NULLIFIER_V1);
    inner.update(lock_id.as_bytes());
    inner.update(condition_hash.as_bytes());
    let inner_hash = inner.finalize();

    // Outer hash: SHA-256(opad || inner_hash)
    let mut outer = Hasher::new();
    outer.update(&opad);
    outer.update(inner_hash.as_bytes());
    let result = outer.finalize();

    // SEC: Zeroize key-derived material to prevent stack leakage.
    // Uses volatile write to prevent compiler from optimizing away the clear.
    for b in ipad.iter_mut() { unsafe { std::ptr::write_volatile(b, 0); } }
    for b in opad.iter_mut() { unsafe { std::ptr::write_volatile(b, 0); } }

    result
}

/// Compute the Portal Key signature payload.
///
/// payload = SHA-256(PORTAL_KEY_SIG_V1 || lock_id || condition_hash || timeout)
pub fn compute_portal_key_payload(
    lock_id: &Hash256,
    condition_hash: &Hash256,
    timeout_l2_block: u64,
) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(brrq_crypto::domain_tags::PORTAL_KEY_SIG_V1);
    hasher.update(lock_id.as_bytes());
    hasher.update(condition_hash.as_bytes());
    hasher.update(&timeout_l2_block.to_le_bytes());
    hasher.finalize()
}

/// The Portal Key — sent from user's wallet to the merchant.
///
/// Contains everything the merchant needs to:
/// 1. Verify the signature locally (mathematical verification, ~0.05ms)
/// 2. Query L2 for lock status (RPC call, ~50ms)
/// 3. Check the nullifier hasn't been consumed
/// 4. Settle later (asynchronously, possibly batched)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortalKey {
    /// Protocol version identifier.
    pub protocol: String,
    /// Schnorr signature over (lock_id || condition_hash || timeout).
    pub signature: SchnorrSignature,
    /// Extended deterministic nullifier.
    pub nullifier: Hash256,
    /// Reference to the lock on L2.
    pub lock_id: Hash256,
    /// Public inputs visible to the merchant.
    pub public_inputs: PortalKeyPublicInputs,
}

/// Public inputs embedded in a Portal Key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortalKeyPublicInputs {
    /// Lock owner's address on L2.
    pub owner: Address,
    /// Lock owner's public key.
    pub owner_pubkey: SchnorrPublicKey,
    /// Asset identifier (always "BTC" for now).
    pub asset_id: String,
    /// Amount in satoshis.
    pub amount: u64,
    /// The merchant's condition hash.
    pub condition_hash: Hash256,
    /// Lock expiry block height.
    pub timeout_l2_block: u64,
}

/// A claim submitted by a merchant to settle a Portal lock.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SettlementClaim {
    /// The lock to settle.
    pub lock_id: Hash256,
    /// The merchant's secret (preimage of condition_hash).
    pub merchant_secret: Vec<u8>,
    /// The Portal Key signature (for re-verification).
    pub signature: SchnorrSignature,
    /// The nullifier from the Portal Key.
    pub nullifier: Hash256,
    /// Merchant's L2 address to receive funds.
    pub merchant_address: Address,
}

/// Result of a batch settlement operation.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BatchResult {
    /// Number of successfully settled claims.
    pub succeeded: u64,
    /// Number of failed claims.
    pub failed: u64,
    /// Total amount settled across all successful claims (satoshis).
    /// Use this instead of reading lock amounts after settlement.
    pub total_settled_amount: u64,
    /// Per-claim settled amounts (index → amount) for successful claims.
    pub settled_amounts: Vec<(usize, u64)>,
    /// Indices and error descriptions of failed claims.
    pub failed_details: Vec<(usize, String)>,
    /// Indices of failed claims (legacy, kept for backward compat).
    pub failed_indices: Vec<usize>,
}

impl PortalKey {
    /// Protocol version string for v4.0.
    pub const PROTOCOL_V4: &str = "Brrq_L3_Portal_v4";
}
