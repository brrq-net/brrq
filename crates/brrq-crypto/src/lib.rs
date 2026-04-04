//! # brrq-crypto
//!
//! Core cryptographic primitives for the Brrq protocol.
//!
//! ## Hash-First Architecture (HFA)
//!
//! Every cryptographic operation is built on hash functions:
//! - **SHA-256**: External-facing state commitments, Merkle trees, SMT
//! - **Poseidon2**: Internal zkVM state (~138x more ZK-efficient than SHA-256)
//! - **SLH-DSA** (FIPS 205): Post-quantum signatures (full hypertree)
//! - **Schnorr** (BIP-340): Classical signatures (Bitcoin-compatible)
//! - **EOTS**: Extractable One-Time Signatures (slashing mechanism)
//!
//! ## Dual-Hash Architecture (§3.5)
//!
//! | Context          | Hash      | Rationale                    |
//! |------------------|-----------|------------------------------|
//! | External (L1)    | SHA-256   | Bitcoin compatibility + HW   |
//! | Internal (zkVM)  | Poseidon2 | ~138x fewer ZK constraints   |

pub mod domain_tags;
pub mod encryption;
pub mod eots;
pub mod error;
pub mod hash;
pub mod merkle;
pub mod musig2;
pub mod poseidon2;
pub mod scalar;
pub mod schnorr;
pub mod sha256;
pub mod slh_dsa;
pub mod vrf;
pub mod zeroize;

pub use encryption::{EpochKey, SealedData};
pub use error::PrimitiveError;
pub use hash::{Hash256, Hasher};
