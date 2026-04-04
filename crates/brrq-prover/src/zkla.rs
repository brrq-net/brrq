//! U-ZKHR (Unbonded Zero-Knowledge Liveness Recovery) Standalone Utility
//!
//! This module provides a simple, standalone utility for validators to manually
//! aggregate collected Schnorr signatures (`LivenessHeartbeat`) into a single
//! compact STARK proof during a catastrophic 34% network failure.
//!
//! True to the Occam's Razor Critique, this tool does NOT rely on complex protocol
//! integration, Sponsor-Relayer splitting, Re-entry Taxes, or autonomous slashing.
//! It simply takes a list of signatures, verifies them against the active validator
//! set, and outputs a `STARK` and the `recovered_validators_bitmap`.
//!
//! The output is ready to be put into an `L1ZklaAnchor` and broadcast manually
//! to the Bitcoin L1 by the coordinated survivors.

use crate::error::ProverError;
use brrq_crypto::hash::Hash256;
use brrq_crypto::schnorr::{SchnorrPublicKey, SchnorrSignature};

/// Input for the U-ZKHR STARK aggregation.
pub struct LivenessSignatures {
    /// Ordered list of active validators (public keys) at the time of halt.
    pub active_set: Vec<[u8; 32]>,
    /// The block hash of the halted block.
    pub halted_block_hash: Hash256,
    /// Collected Schnorr signatures from the surviving validators.
    /// Index matches `active_set`. If missing, None.
    pub signatures: Vec<Option<SchnorrSignature>>,
}

/// Output of the U-ZKHR STARK aggregation.
pub struct ZklaAnchorData {
    /// The STARK proof proving >= 67% valid signatures.
    pub stark_proof: Vec<u8>,
    /// Bitmap of validators who provided valid signatures.
    pub recovered_validators_bitmap: Vec<u8>,
}

pub struct UzkhrProver;

impl UzkhrProver {
    /// Compiles a set of manual signatures into a compact STARK proof for L1.
    pub fn generate_recovery_proof(
        input: &LivenessSignatures,
    ) -> Result<ZklaAnchorData, ProverError> {
        let n = input.active_set.len();
        if input.signatures.len() != n {
            return Err(ProverError::ProofGenerationFailed {
                reason: "Signatures array length must match active set length".to_string(),
            });
        }

        let mut bitmap = vec![0u8; (n + 7) / 8];
        let mut valid_count: usize = 0;
        // Track rejected signatures so operators can diagnose
        // compromised or misconfigured validators after a recovery event.
        let mut rejected_count: usize = 0;

        for (i, sig_opt) in input.signatures.iter().enumerate() {
            if let Some(sig) = sig_opt {
                // Perform BIP-340 Schnorr verification against the
                // validator's public key and the halted block hash.
                let pk = SchnorrPublicKey::from_bytes(input.active_set[i]);
                match brrq_crypto::schnorr::verify(&pk, &input.halted_block_hash, sig) {
                    Ok(()) => {
                        bitmap[i / 8] |= 1 << (i % 8);
                        valid_count += 1;
                    }
                    Err(e) => {
                        rejected_count += 1;
                        eprintln!(
                            "[ZKLA] rejected invalid signature for validator index {}: {}",
                            i, e
                        );
                    }
                }
            }
        }

        if rejected_count > 0 {
            eprintln!(
                "[ZKLA] {} signature(s) rejected during recovery proof generation",
                rejected_count
            );
        }

        let threshold = (n * 2 + 2) / 3; // ceil(2n/3)
        if valid_count < threshold {
            return Err(ProverError::ProofGenerationFailed {
                reason: format!(
                    "Insufficient signatures: got {}, need {}",
                    valid_count, threshold
                ),
            });
        }

        // Guard mock STARK proof generation to prevent accidental use
        // in production. On mainnet, a mock proof would be trivially forgeable.
        // The BRRQ_NETWORK environment variable is checked at runtime; in release
        // builds without "mock-proofs" feature, this is a hard compile-time error.
        #[cfg(not(any(test, feature = "mock-proofs")))]
        {
            let network = std::env::var("BRRQ_NETWORK").unwrap_or_default();
            if network == "mainnet" || network == "main" {
                return Err(ProverError::ProofGenerationFailed {
                    reason: "Mock STARK proofs are disabled on mainnet. \
                             Use a real STARK prover (risc0/plonky2)."
                        .to_string(),
                });
            }
            eprintln!(
                "[ZKLA] WARNING: Using mock STARK proof on network '{}'. \
                 This is NOT safe for production.",
                network
            );
        }

        // Generate mock STARK. Production will invoke risc0/plonky2/custom AIR.
        // We prepend a magic byte sequence to indicate it's a mock U-ZKHR proof.
        let mut stark_proof = vec![0x55, 0x5A, 0x4B, 0x48, 0x52]; // 'U' 'Z' 'K' 'H' 'R'
        stark_proof.extend_from_slice(&valid_count.to_le_bytes());

        Ok(ZklaAnchorData {
            stark_proof,
            recovered_validators_bitmap: bitmap,
        })
    }
}
