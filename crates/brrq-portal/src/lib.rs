//! # brrq-portal
//!
//! L3 Pragmatic Portal: Account+Escrow model with Nullifiers and Batch Settlement.
//!
//! ## Overview (Whitepaper v4.0)
//!
//! The Portal is not a network — it's an **SDK/protocol layer** that achieves:
//! - **40-100x L2 load reduction** via Lock Pools + Batch Settlement
//! - **0ms merchant acceptance** via local Schnorr verification + L2 lock query
//! - **Trustless security** via on-chain escrow locks + deterministic nullifiers
//!
//! ## Architecture
//!
//! ```text
//! User Wallet                L2 Chain              Merchant
//!   │                          │                      │
//!   │ create_lock(amount)      │                      │
//!   │─────────────────────────→│                      │
//!   │  balance -= amount       │                      │
//!   │  escrow += amount        │                      │
//!   │ ← lock_id                │                      │
//!   │                          │                      │
//!   │ generate_portal_key()    │                      │
//!   │──────────────────────────────────────────────── →│
//!   │                          │  verify_signature ✓  │
//!   │                          │← get_lock(lock_id)   │
//!   │                          │  check_nullifier ✓   │
//!   │                          │                      │
//!   │                          │  settle (async)      │
//!   │                          │← batch_settle(...)   │
//! ```
//!
//! ## Security Model
//!
//! - **No double-spend**: Amount locked on L2 before Portal Key generation
//! - **No race condition**: Lock is a single L2 transaction
//! - **Extended nullifier**: HMAC-SHA256(sk, lock_id || condition_hash) — unique per merchant
//! - **Escape hatch**: Funds auto-return after timeout_l2_block

pub mod error;
pub mod escrow;
pub mod lock_pool;
pub mod maintenance;
pub mod nullifier;
pub mod persistence;
pub mod portal_key;
pub mod proof_of_purchase;
pub mod prepaid;
pub mod settlement;
pub mod session_key;
pub mod tee;
pub mod types;
pub mod uri;

pub use error::{PortalError, SettlementError};
pub use escrow::EscrowManager;
pub use nullifier::NullifierSet;
pub use portal_key::{generate_portal_key, verify_portal_key_full, verify_portal_key_signature};
pub use settlement::{batch_settle, compute_batch_merkle_root, settle_portal_key, settle_session_receipt};
pub use persistence::{EscrowSnapshot, NullifierSnapshot};
pub use maintenance::{MaintenanceResult, PendingRefund, PortalHealth, compute_health, prune_old_locks, scan_and_expire_locks};
pub use prepaid::{PaymentReceipt, PrepaidCard};
pub use lock_pool::{
    LockPool, PoolSlot, create_lock_pool, refill_pool, MAX_POOL_SLOTS,
};
pub use types::{
    BatchResult, LockStatus, PortalKey, PortalKeyPublicInputs, PortalLock, SettlementClaim,
    MAX_BATCH_SIZE, MIN_TIMEOUT_BLOCKS,
};
pub use uri::{BrrqChain, BrrqPaymentUri, UriError, URI_VERSION};
pub use proof_of_purchase::{ProofOfPurchase, BpopError, compute_bpop_payload};
pub use tee::{TeeKeyStore, TeeError, TeeAttestation, SoftwareKeyStore};

