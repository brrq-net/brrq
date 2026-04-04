//! Bitcoin L1 integration for Brrq.
//!
//! This crate provides everything needed to connect a Brrq node to Bitcoin L1:
//!
//! - **RPC Client**: Connect to bitcoind via JSON-RPC
//! - **Block Monitor**: Track new Bitcoin blocks and cache recent headers
//! - **Deposit Watcher**: Detect peg-in deposits to the bridge address
//! - **Anchor Service**: Post state commitments to Bitcoin via OP_RETURN
//!
//! All components are designed for **graceful degradation**: if the Bitcoin
//! connection is unavailable, the Brrq node continues operating as L2-only.

pub mod anchor_service;
pub mod block_monitor;
#[cfg(feature = "canary")]
pub mod canary;
pub mod deposit_watcher;
pub mod error;
pub mod rpc_client;
pub mod spv;
pub mod types;

// ── Re-exports ───────────────────────────────────────────────────────────────
pub use anchor_service::AnchorService;
pub use block_monitor::{
    BlockMonitor, ChainEntry, DepositConfirmationStatus, MIN_CONFIRMATIONS, ReorgResult,
};
pub use deposit_watcher::{DepositWatcher, ScriptType, detect_script_type};
pub use error::BitcoinError;
pub use rpc_client::{BitcoinRpc, BitcoinRpcClient};
pub use spv::{SpvProof, SpvVerifyResult, validate_pow};

// Types — explicit re-exports (no glob)
pub use types::{
    ANCHOR_DATA_SIZE, ANCHOR_MAGIC, AnchorData, DEFAULT_CHECKPOINT_INTERVAL,
    DEFAULT_POLL_INTERVAL_SECS, DepositEvent, L1AnchorRecord, L1BlockInfo, L1Status,
    MAX_CATCHUP_BLOCKS, MAX_DEPOSIT_SATS, MAX_KNOWN_DEPOSITS, MAX_L1_BLOCK_CACHE,
    MIN_DEPOSIT_CONFIRMATIONS, MIN_DEPOSIT_SATS,
};

#[cfg(feature = "canary")]
pub use canary::{
    AnchorVerifier, DepositValidator, ReadOnlyBitcoinClient, ShadowProcessor, ShadowReport,
};
