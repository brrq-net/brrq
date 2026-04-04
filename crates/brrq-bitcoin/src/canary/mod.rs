//! Canary — Read-only Bitcoin mainnet shadow processing.
//!
//! Provides safe, observation-only access to Bitcoin mainnet for validating
//! Brrq's L1 integration logic against real data. All write operations are
//! blocked at the type level.
//!
//! # Safety
//!
//! - [`ReadOnlyBitcoinClient`] exposes only read methods — write methods
//!   are absent from the API, not just gated by runtime checks.
//! - Runtime guard: `BRRQ_CANARY_MODE=readonly` must be set.
//! - Network assertion: refuses to operate if `network() != Bitcoin`.
//! - Rate limiting: 1 RPC call per second to avoid overloading mainnet nodes.

pub mod anchor_verifier;
pub mod deposit_validator;
pub mod readonly_client;
pub mod safety;
pub mod shadow_processor;

pub use anchor_verifier::{AnchorVerifier, AnchorVerifyResult};
pub use deposit_validator::{DepositDiscrepancy, DepositValidator, KnownDeposit};
pub use readonly_client::ReadOnlyBitcoinClient;
pub use safety::CanarySafetyGuard;
pub use shadow_processor::{ShadowProcessor, ShadowReport};
