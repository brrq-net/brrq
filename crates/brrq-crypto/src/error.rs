//! Centralized error types for brrq-crypto cryptographic primitives.
//!
//! Each sub-module retains its own domain-specific error enum for precise
//! error matching at call sites. `PrimitiveError` is the top-level umbrella
//! that unifies them for callers that don't need module-level granularity.
//!
//! Note: `encryption::CryptoError` is intentionally excluded — encryption
//! is a separate layer with distinct error semantics (authentication failure,
//! share reconstruction) unrelated to cryptographic primitive operations.

use thiserror::Error;

use crate::eots::EotsError;
use crate::merkle::MerkleError;
use crate::musig2::MuSig2Error;
use crate::schnorr::SchnorrError;
use crate::slh_dsa::SlhDsaError;
use crate::vrf::VrfError;

/// Umbrella error for cryptographic primitive operations in Brrq.
///
/// Covers: Schnorr, EOTS, SLH-DSA, Merkle, MuSig2, and VRF.
/// Does NOT cover: encryption (`encryption::CryptoError`) or
/// hardware key stores (`tpm2::KeyStoreError`) — those are separate concerns.
///
/// # `secp256k1::Error` ambiguity
///
/// Four variants (`Schnorr`, `Eots`, `MuSig2`, `Vrf`) each wrap a sub-error
/// that itself implements `From<secp256k1::Error>`. This means there is **no**
/// direct `From<secp256k1::Error> for PrimitiveError` — the compiler cannot
/// choose which path to take. Callers must convert explicitly:
///
/// ```ignore
/// // WON'T COMPILE: secp_result?  (ambiguous From path)
/// // DO THIS INSTEAD:
/// let key = secp256k1::PublicKey::from_slice(bytes)
///     .map_err(SchnorrError::from)?;  // explicit sub-error
/// ```
///
/// ```ignore
/// fn do_crypto() -> Result<(), PrimitiveError> {
///     let sig = schnorr::sign(&keypair, &msg)?;  // SchnorrError → PrimitiveError
///     let proof = vrf::prove(&sk, &input)?;       // VrfError → PrimitiveError
///     Ok(())
/// }
/// ```
#[derive(Debug, Error)]
pub enum PrimitiveError {
    #[error("schnorr: {0}")]
    Schnorr(#[from] SchnorrError),

    #[error("EOTS: {0}")]
    Eots(#[from] EotsError),

    #[error("SLH-DSA: {0}")]
    SlhDsa(#[from] SlhDsaError),

    #[error("merkle: {0}")]
    Merkle(#[from] MerkleError),

    #[error("MuSig2: {0}")]
    MuSig2(#[from] MuSig2Error),

    #[error("VRF: {0}")]
    Vrf(#[from] VrfError),
}
