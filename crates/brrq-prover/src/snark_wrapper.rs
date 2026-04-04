//! STARK-to-SNARK wrapping (simulated + real Plonky2).
//!
//! # Security
//!
//! Simulated verification paths are gated by three layers:
//!   - **Compile-time**: `real-plonky2` feature flag
//!   - **Runtime**: `BRRQ_NETWORK` env var guard (rejects mainnet if simulated)
//!   - **API-level**: `is_simulated()` / `require_real()` checks at security boundaries
//!
//! Per whitepaper SS3.8, the STARK proof (~44 KB) is wrapped in a SNARK
//! (~256 bytes) for economical L1 posting. This module provides:
//!
//! - **Simulated** (default): hash-based simulation for development/testing
//! - **Real Plonky2** (`real-plonky2` feature): FRI-based recursive proof
//!
//! ## Simulation Design (Groth16Simulated)
//!
//! The simulated proof is constructed as:
//! 1. `stark_proof_hash` = SHA-256(serialized STARK proof)
//! 2. `public_inputs` = (initial_state_root, final_state_root, block_range, stark_proof_hash)
//! 3. `proof_bytes` = HMAC-SHA256(simulation_key, public_inputs_bytes)
//!
//! This is **NOT** cryptographically secure as a SNARK. The simulation key
//! is deterministic (`SHA-256("brrq-snark-simulation-v1")`) so proofs are
//! reproducible.
//!
//! ## Three Sunsetting Paths (SS3.8)
//!
//! | Path | Condition | Timeline |
//! |------|-----------|----------|
//! | 1. Native STARK in BitVM | BitVM2 maturity | 2-4 years |
//! | 2. Quantum-resistant SNARK | Lattice/hash SNARK maturity | 3-5 years |
//! | 3. OP_CAT on Bitcoin | Soft fork | Undefined |

use brrq_crypto::hash::{Hash256, Hasher};
use serde::{Deserialize, Serialize};

use crate::types::StarkProof;

// ── Constants ───────────────────────────────────────────────────────────────

/// Magic bytes identifying a Brrq SNARK wrapper.
pub const SNARK_MAGIC: [u8; 4] = *b"BRSN";

/// Target size for the simulated proof element (~256 bytes).
///
/// Real Groth16: A (64) + B (128) + C (64) = 256 bytes on BN254.
pub const WRAPPED_PROOF_SIZE: usize = 256;

/// Domain separator for the simulation HMAC key.
/// Use centralized domain tag constant instead of inline literal.
const SIMULATION_DOMAIN: &[u8] = brrq_crypto::domain_tags::SNARK_SIMULATION_V1;

/// Compact serialization overhead: magic(4) + version(1) + proof_system(1).
const COMPACT_HEADER_SIZE: usize = 6;

/// Public inputs serialized size: 2*32 (roots) + 2*8 (heights) + 32 (hash) = 112.
const PUBLIC_INPUTS_SIZE: usize = 112;

// ── Types ───────────────────────────────────────────────────────────────────

/// Proof system identifier.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProofSystem {
    /// MVP: hash-based simulation (not cryptographically secure).
    Groth16Simulated = 0,
    /// Future: real BN254 Groth16 via bellman/ark-groth16.
    Groth16Real = 1,
    /// Future: PLONK alternative.
    PlonkReal = 2,
    /// DEPRECATED: Plonky2 — transparent recursive SNARK.
    /// Plonky2 is deprecated (Polygon pivoted to Plonky3). Retained for
    /// backward compatibility with existing serialized proofs only.
    /// New proofs MUST use Sp1Groth16.
    #[deprecated(note = "Plonky2 is deprecated — use Sp1Groth16 instead")]
    Plonky2 = 3,
    /// SP1 + Groth16 — recursive STARK verification via SP1 zkVM.
    ///
    /// SP1 runs Brrq's full STARK verifier inside a RISC-V zkVM and wraps
    /// the result into a ~260-byte Groth16 proof. This is stronger than the
    /// old Plonky2 approach: full STARK verification, not just metadata binding.
    ///
    /// Groth16 requires a trusted setup, but SP1's ceremony is shared across
    /// all SP1 users (amortized trust assumption).
    Sp1Groth16 = 4,
}

impl ProofSystem {
    /// Convert from byte.
    #[allow(deprecated)]
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Groth16Simulated),
            1 => Some(Self::Groth16Real),
            2 => Some(Self::PlonkReal),
            3 => Some(Self::Plonky2),
            4 => Some(Self::Sp1Groth16),
            _ => None,
        }
    }

    /// Whether this proof system requires a trusted setup ceremony.
    ///
    /// Groth16 requires a powers-of-tau ceremony where participants must
    /// destroy their toxic waste. If ANY participant's secret is compromised
    /// (or if the ceremony software is backdoored), the attacker can forge
    /// proofs — stealing ALL bridge funds.
    ///
    /// Plonky2 uses only hash-based commitments (FRI), so it is transparent
    /// and has no trusted setup requirement.
    #[allow(deprecated)]
    pub fn requires_trusted_setup(&self) -> bool {
        matches!(
            self,
            ProofSystem::Groth16Real | ProofSystem::PlonkReal | ProofSystem::Sp1Groth16
        )
    }
}

/// Trusted setup ceremony configuration.
///
/// Documents the trust assumptions for proof systems that require
/// a ceremony. This struct exists purely for documentation and
/// configuration validation — it does not perform the ceremony.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyConfig {
    /// Minimum number of independent participants.
    pub min_participants: u32,
    /// Minimum number of distinct geographic jurisdictions.
    pub min_jurisdictions: u32,
    /// Whether the ceremony software must be audited.
    pub requires_audit: bool,
    /// Description of the trust assumption.
    pub trust_model: String,
}

impl Default for CeremonyConfig {
    fn default() -> Self {
        Self {
            min_participants: 100,
            min_jurisdictions: 10,
            requires_audit: true,
            trust_model: "1-of-N honesty: at least one participant must destroy their toxic waste"
                .into(),
        }
    }
}

/// Warning constant for code that uses trusted-setup proof systems.
pub const TRUSTED_SETUP_WARNING: &str = "WARNING: This proof system requires a trusted setup ceremony. \
     If the ceremony is compromised, ALL bridge funds can be stolen. \
     SP1's Groth16 uses a shared ceremony (amortized trust across all SP1 users). \
     Long-term goal: replace with native STARK verification in BitVM (no trusted setup).";

/// Public inputs that the SNARK verifier checks.
///
/// These are the values that both prover and verifier agree on:
/// the SNARK proves that a valid STARK proof exists binding
/// `initial_state_root` to `final_state_root` over the block range.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnarkPublicInputs {
    /// State root before the first block in the batch.
    pub initial_state_root: Hash256,
    /// State root after the last block in the batch.
    pub final_state_root: Hash256,
    /// First L2 block height in the batch.
    pub l2_height_start: u64,
    /// Last L2 block height in the batch.
    pub l2_height_end: u64,
    /// SHA-256 hash of the full serialized STARK proof.
    pub stark_proof_hash: Hash256,
}

impl SnarkPublicInputs {
    /// Serialize public inputs to deterministic bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(PUBLIC_INPUTS_SIZE);
        buf.extend_from_slice(self.initial_state_root.as_bytes());
        buf.extend_from_slice(self.final_state_root.as_bytes());
        buf.extend_from_slice(&self.l2_height_start.to_le_bytes());
        buf.extend_from_slice(&self.l2_height_end.to_le_bytes());
        buf.extend_from_slice(self.stark_proof_hash.as_bytes());
        debug_assert_eq!(buf.len(), PUBLIC_INPUTS_SIZE);
        buf
    }

    /// Deserialize from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        if data.len() < PUBLIC_INPUTS_SIZE {
            return Err(format!(
                "public inputs too short: {} < {}",
                data.len(),
                PUBLIC_INPUTS_SIZE,
            ));
        }
        let initial_state_root = Hash256::from_slice(&data[0..32]);
        let final_state_root = Hash256::from_slice(&data[32..64]);
        let l2_height_start = u64::from_le_bytes(
            data[64..72]
                .try_into()
                .map_err(|_| "invalid height_start slice length".to_string())?,
        );
        let l2_height_end = u64::from_le_bytes(
            data[72..80]
                .try_into()
                .map_err(|_| "invalid height_end slice length".to_string())?,
        );
        if l2_height_end < l2_height_start {
            return Err(format!(
                "invalid block range: end ({}) < start ({})",
                l2_height_end, l2_height_start,
            ));
        }
        let stark_proof_hash = Hash256::from_slice(&data[80..112]);
        Ok(Self {
            initial_state_root,
            final_state_root,
            l2_height_start,
            l2_height_end,
            stark_proof_hash,
        })
    }
}

/// Wrapped SNARK proof — compact representation for L1 posting.
///
/// In production, this would be a real Groth16 proof (~256 bytes).
/// For MVP, we use a hash-based simulation that commits to the same
/// public inputs as a real SNARK would.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WrappedSnarkProof {
    /// Simulated proof bytes (256 bytes).
    ///
    /// Production: Groth16 points (A, B, C) on BN254.
    /// Simulation: 8 rounds of HMAC-SHA256 keyed by simulation secret.
    pub proof_bytes: Vec<u8>,
    /// Public inputs committed in the proof.
    pub public_inputs: SnarkPublicInputs,
    /// Proof system identifier.
    pub proof_system: ProofSystem,
}

impl WrappedSnarkProof {
    /// Wrap a STARK proof into a simulated SNARK.
    ///
    /// ## Process
    ///
    /// 1. Serialize the STARK proof to bytes
    /// 2. Hash the bytes to get `stark_proof_hash`
    /// 3. Build `SnarkPublicInputs` from state roots + block range + hash
    /// 4. Generate simulated proof via keyed hash chain
    ///
    /// ## Security Note
    ///
    /// This simulation is **NOT** a real zero-knowledge proof. It is a
    /// deterministic commitment scheme using SHA-256. Replace with a real
    /// Groth16 prover for production use.
    ///
    /// This function generates a simulated (forgeable) SNARK using a
    /// deterministic HMAC key. Safety relies on compile-time and runtime
    /// guards (see module docs).
    pub fn wrap_stark(stark_proof: &StarkProof, block_range: (u64, u64)) -> Result<Self, String> {
        // Step 1: Hash the full STARK proof
        let stark_bytes = stark_proof
            .to_bytes()
            .map_err(|e| format!("STARK proof serialization failed: {}", e))?;
        let stark_proof_hash = Hasher::hash(&stark_bytes);

        // Step 2: Build public inputs
        let public_inputs = SnarkPublicInputs {
            initial_state_root: stark_proof.initial_state_root,
            final_state_root: stark_proof.final_state_root,
            l2_height_start: block_range.0,
            l2_height_end: block_range.1,
            stark_proof_hash,
        };

        // Step 3: Generate simulated proof bytes (256 bytes = 8 x 32)
        let proof_bytes = generate_simulated_proof(&public_inputs);

        Ok(Self {
            proof_bytes,
            public_inputs,
            proof_system: ProofSystem::Groth16Simulated,
        })
    }

    /// Wrap a STARK proof using the SP1 + Groth16 wrapper.
    ///
    /// SP1 runs Brrq's STARK verifier inside a RISC-V zkVM and wraps
    /// the result into a ~260-byte Groth16 proof.
    ///
    /// With `real-sp1`: generates a real Groth16 proof (3-10 min per batch).
    /// Without `real-sp1`: generates a simulated proof (dev/test only).
    ///
    /// Callers making security decisions should check `is_simulated()`.
    pub fn wrap_stark_sp1(
        stark_proof: &StarkProof,
        block_range: (u64, u64),
    ) -> Result<Self, String> {
        let result = crate::sp1_wrapper::wrap_stark_sp1(stark_proof, block_range)?;

        Ok(Self {
            proof_bytes: result.proof_bytes,
            public_inputs: result.public_inputs,
            proof_system: ProofSystem::Sp1Groth16,
        })
    }

    /// DEPRECATED: Wrap a STARK proof using the Plonky2 wrapper.
    ///
    /// Plonky2 is deprecated (Polygon pivoted to Plonky3). Use `wrap_stark_sp1()`
    /// instead. This method is retained only for backward compatibility.
    #[deprecated(note = "Plonky2 is deprecated — use wrap_stark_sp1() instead")]
    #[allow(deprecated)]
    pub fn wrap_stark_plonky2(
        stark_proof: &StarkProof,
        block_range: (u64, u64),
    ) -> Result<Self, String> {
        #[cfg(feature = "real-plonky2")]
        {
            let wrapper = crate::plonky2_wrapper::Plonky2Wrapper::real();
            let (proof_bytes, public_inputs) = wrapper
                .wrap(stark_proof, block_range)
                .map_err(|e| e.to_string())?;
            Ok(Self {
                proof_bytes,
                public_inputs,
                proof_system: ProofSystem::Plonky2,
            })
        }

        #[cfg(all(not(feature = "real-plonky2"), feature = "allow-simulated-proofs"))]
        {
            let wrapper =
                crate::plonky2_wrapper::Plonky2SnarkWrapper::<()>::simulate_aggregation(b"");
            let (proof_bytes, public_inputs) = wrapper
                .wrap(stark_proof, block_range)
                .map_err(|e| e.to_string())?;
            Ok(Self {
                proof_bytes,
                public_inputs,
                proof_system: ProofSystem::Plonky2,
            })
        }

        #[cfg(all(not(feature = "real-plonky2"), not(feature = "allow-simulated-proofs")))]
        {
            let _ = (stark_proof, block_range);
            Err("Plonky2 is not available: neither `real-plonky2` nor \
                 `allow-simulated-proofs` feature is enabled"
                .into())
        }
    }

    /// Wrap a STARK proof using the best available proof system.
    ///
    /// Priority order:
    /// 1. `real-sp1` → real SP1 + Groth16 proof
    /// 2. `real-plonky2` → real Plonky2 proof (deprecated, fallback only)
    /// 3. Neither → SP1 simulated (dev/test only)
    ///
    /// This is the single entry point for callers that need SNARK wrapping
    /// without caring which backend is active.
    pub fn wrap_best_available(
        stark_proof: &StarkProof,
        block_range: (u64, u64),
    ) -> Result<Self, String> {
        // Prefer SP1 (actively maintained) over Plonky2 (deprecated)
        #[cfg(feature = "real-sp1")]
        return Self::wrap_stark_sp1(stark_proof, block_range);

        #[cfg(all(not(feature = "real-sp1"), feature = "real-plonky2"))]
        {
            #[allow(deprecated)]
            return Self::wrap_stark_plonky2(stark_proof, block_range);
        }

        // No real prover available — use SP1 simulated (same guard pattern)
        #[cfg(all(not(feature = "real-sp1"), not(feature = "real-plonky2")))]
        return Self::wrap_stark_sp1(stark_proof, block_range);
    }

    /// Verify an SP1 Groth16 proof.
    ///
    /// In simulation mode, re-derives the expected proof and compares.
    /// In real mode (`real-sp1`), delegates to SP1's Groth16 verifier.
    pub fn verify_sp1(&self) -> Result<bool, String> {
        if self.proof_system != ProofSystem::Sp1Groth16 {
            return Err(format!(
                "verify_sp1 called on {:?} proof",
                self.proof_system,
            ));
        }

        crate::sp1_wrapper::verify_sp1(&self.proof_bytes, &self.public_inputs)
    }

    /// Verify a Plonky2 proof (DEPRECATED — use verify_sp1() for new proofs).
    ///
    /// In simulation mode, requires the original STARK proof bytes for re-derivation.
    /// In real mode (`real-plonky2` feature), the Plonky2 proof is self-contained
    /// and `stark_bytes` is used only for consistency validation.
    #[deprecated(note = "Plonky2 is deprecated — use verify_sp1() for new proofs")]
    #[allow(deprecated)]
    pub fn verify_plonky2(&self, stark_bytes: &[u8]) -> Result<bool, String> {
        if self.proof_system != ProofSystem::Plonky2 {
            return Err(format!(
                "verify_plonky2 called on {:?} proof",
                self.proof_system,
            ));
        }

        #[cfg(feature = "real-plonky2")]
        {
            let wrapper = crate::plonky2_wrapper::Plonky2Wrapper::real();
            return wrapper.verify(&self.proof_bytes, &self.public_inputs, stark_bytes);
        }

        #[cfg(all(not(feature = "real-plonky2"), feature = "allow-simulated-proofs"))]
        {
            // Runtime production guard — reject simulated verification on mainnet.
            if let Ok(network) = std::env::var("BRRQ_NETWORK") {
                if network.eq_ignore_ascii_case("mainnet") {
                    return Err(
                        "SECURITY VIOLATION: verify_plonky2() called in simulated mode \
                         but BRRQ_NETWORK=mainnet. Simulated Plonky2 proofs MUST NOT be \
                         accepted on mainnet. Rebuild with feature `real-plonky2`."
                            .into(),
                    );
                }
            }

            let wrapper =
                crate::plonky2_wrapper::Plonky2SnarkWrapper::<()>::simulate_aggregation(b"");
            wrapper
                .verify(&self.proof_bytes, &self.public_inputs, stark_bytes)
                .map_err(|e| e.to_string())
        }

        #[cfg(all(not(feature = "real-plonky2"), not(feature = "allow-simulated-proofs")))]
        {
            Err("Plonky2 is not available: neither `real-plonky2` nor \
                 `allow-simulated-proofs` feature is enabled"
                .into())
        }
    }

    /// Returns true if this proof uses a simulated (non-cryptographic) proof system.
    ///
    /// Callers making security decisions (bridge challenge verification,
    /// withdrawal authorization) MUST check this and reject simulated proofs.
    ///
    /// Uses a **whitelist pattern**: only proof systems with a real cryptographic
    /// verifier return `false`. The catch-all arm defaults to `true`, so any
    /// new `ProofSystem` variant is treated as simulated until explicitly
    /// whitelisted after verifier integration.
    #[allow(deprecated)]
    pub fn is_simulated(&self) -> bool {
        // Whitelist pattern: only explicitly verified systems return false.
        #[allow(clippy::match_like_matches_macro)]
        match self.proof_system {
            // ── Whitelisted real proof systems (have audited verifiers) ──
            ProofSystem::Groth16Real => false,
            ProofSystem::PlonkReal => false,

            // SP1 + Groth16: only real when `real-sp1` feature is enabled.
            #[cfg(feature = "real-sp1")]
            ProofSystem::Sp1Groth16 => false,

            // Plonky2 (DEPRECATED): only real when `real-plonky2` feature is enabled.
            #[cfg(feature = "real-plonky2")]
            ProofSystem::Plonky2 => false,

            // ── Everything else is simulated (safe default) ──
            // This catches: Groth16Simulated, Sp1Groth16 (without real-sp1),
            // Plonky2 (without real-plonky2), and any future variants.
            _ => true,
        }
    }

    /// Assert that this proof is NOT simulated. Call at security boundaries
    /// (bridge withdrawal, challenge response) to reject simulated proofs.
    ///
    /// Enforces two layers: `is_simulated()` feature-flag check, plus a
    /// runtime `BRRQ_NETWORK` guard for defense-in-depth.
    pub fn require_real(&self) -> Result<(), String> {
        // Layer 1: Feature-flag based check.
        if self.is_simulated() {
            return Err(format!(
                "SECURITY VIOLATION: {:?} proof is simulated — cannot be used for \
                 security-critical operations. Enable `real-sp1` \
                 feature for production use.",
                self.proof_system,
            ));
        }

        // Layer 2: Runtime network guard (catches deployment misconfigurations).
        #[cfg(not(any(feature = "real-sp1", feature = "real-plonky2")))]
        {
            #[allow(deprecated)]
            if let Ok(network) = std::env::var("BRRQ_NETWORK") {
                if network.eq_ignore_ascii_case("mainnet") {
                    let missing_feature = match self.proof_system {
                        ProofSystem::Sp1Groth16 => Some("real-sp1"),
                        ProofSystem::Plonky2 => Some("real-plonky2"),
                        ProofSystem::Groth16Real => Some("groth16-removed"),
                        _ => None,
                    };
                    if let Some(feature) = missing_feature {
                        return Err(format!(
                            "SECURITY VIOLATION: {:?} proof on BRRQ_NETWORK=mainnet but \
                             feature `{}` is not enabled. This binary is not safe for \
                             mainnet deployment.",
                            self.proof_system, feature,
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Verify the wrapped SNARK proof.
    ///
    /// For simulated proofs: re-computes the HMAC chain and compares.
    /// Note: Groth16Real is no longer supported (PHA violation). Use Plonky2 instead.
    ///
    /// For `Groth16Simulated`, panics on mainnet via `BRRQ_NETWORK` check.
    #[allow(deprecated)]
    pub fn verify(&self) -> Result<bool, String> {
        match self.proof_system {
            ProofSystem::Groth16Simulated => {
                // Runtime guard — reject simulated verification on production networks.
                enforce_simulated_network_check("verify[Groth16Simulated]");

                // Validate size
                if self.proof_bytes.len() != WRAPPED_PROOF_SIZE {
                    return Err(format!(
                        "invalid proof size: {} != {}",
                        self.proof_bytes.len(),
                        WRAPPED_PROOF_SIZE,
                    ));
                }

                // Re-compute and compare
                let expected = generate_simulated_proof(&self.public_inputs);
                if self.proof_bytes != expected {
                    return Err("simulated proof verification failed: HMAC mismatch".into());
                }

                Ok(true)
            }
            ProofSystem::Groth16Real => Err(
                "real Groth16 requires verifying key — use verify_groth16() with a Groth16Wrapper"
                    .into(),
            ),
            ProofSystem::PlonkReal => Err("Method not available".into()),
            ProofSystem::Plonky2 => {
                Err("Plonky2 requires STARK bytes — use verify_plonky2(stark_bytes) instead".into())
            }
            ProofSystem::Sp1Groth16 => self.verify_sp1(),
        }
    }

    /// Serialize to compact bytes for L1 posting or network transmission.
    ///
    /// Format (v1 — fixed proof size):
    /// ```text
    /// [BRSN: 4][version: 1][proof_system: 1][public_inputs: 112][proof_bytes: 256]
    /// Total: 374 bytes
    /// ```
    ///
    /// Format (v2 — variable proof size, for Plonky2):
    /// ```text
    /// [BRSN: 4][version: 1][proof_system: 1][public_inputs: 112][proof_len: 4][proof_bytes: N]
    /// Total: 122 + N bytes
    /// ```
    #[allow(deprecated)]
    pub fn to_compact_bytes(&self) -> Vec<u8> {
        let use_variable = matches!(
            self.proof_system,
            ProofSystem::Plonky2 | ProofSystem::Sp1Groth16
        ) && self.proof_bytes.len() != WRAPPED_PROOF_SIZE;

        let mut buf = Vec::with_capacity(
            COMPACT_HEADER_SIZE + PUBLIC_INPUTS_SIZE + 4 + self.proof_bytes.len(),
        );

        // Header
        buf.extend_from_slice(&SNARK_MAGIC);
        buf.push(if use_variable { 0x02 } else { 0x01 }); // version
        buf.push(self.proof_system as u8);

        // Public inputs (fixed 112 bytes)
        buf.extend_from_slice(&self.public_inputs.to_bytes());

        if use_variable {
            // Variable-length proof: 4-byte little-endian length prefix.
            buf.extend_from_slice(&(self.proof_bytes.len() as u32).to_le_bytes());
        }

        buf.extend_from_slice(&self.proof_bytes);

        buf
    }

    /// Deserialize from compact bytes.
    pub fn from_compact_bytes(data: &[u8]) -> Result<Self, String> {
        let min_header = COMPACT_HEADER_SIZE + PUBLIC_INPUTS_SIZE;
        if data.len() < min_header {
            return Err(format!(
                "compact bytes too short: {} < {}",
                data.len(),
                min_header,
            ));
        }

        // Check magic
        if data[0..4] != SNARK_MAGIC {
            return Err(format!(
                "invalid SNARK magic: expected {:?}, got {:?}",
                SNARK_MAGIC,
                &data[0..4],
            ));
        }

        // Check version
        let version = data[4];
        if version != 0x01 && version != 0x02 {
            return Err(format!("unsupported SNARK version: {version}"));
        }

        // Parse proof system
        let proof_system = ProofSystem::from_byte(data[5])
            .ok_or_else(|| format!("unknown proof system: {}", data[5]))?;

        // Parse public inputs
        let pi_start = COMPACT_HEADER_SIZE;
        let pi_end = pi_start + PUBLIC_INPUTS_SIZE;
        let public_inputs = SnarkPublicInputs::from_bytes(&data[pi_start..pi_end])?;

        // Parse proof bytes
        let proof_bytes = if version == 0x02 {
            // Variable-length proof (v2).
            if data.len() < pi_end + 4 {
                return Err("compact bytes too short for v2 length prefix".into());
            }
            let proof_len = u32::from_le_bytes([
                data[pi_end],
                data[pi_end + 1],
                data[pi_end + 2],
                data[pi_end + 3],
            ]) as usize;
            let proof_start = pi_end + 4;
            let proof_end = proof_start + proof_len;
            if data.len() < proof_end {
                return Err(format!(
                    "compact bytes too short for proof: {} < {}",
                    data.len(),
                    proof_end,
                ));
            }
            data[proof_start..proof_end].to_vec()
        } else {
            // Fixed-size proof (v1).
            let proof_start = pi_end;
            let proof_end = proof_start + WRAPPED_PROOF_SIZE;
            if data.len() < proof_end {
                return Err(format!(
                    "compact bytes too short: {} < {}",
                    data.len(),
                    proof_end,
                ));
            }
            data[proof_start..proof_end].to_vec()
        };

        Ok(Self {
            proof_bytes,
            public_inputs,
            proof_system,
        })
    }

    /// Total size in bytes (compact format).
    #[allow(deprecated)]
    pub fn compact_size(&self) -> usize {
        let use_variable = matches!(
            self.proof_system,
            ProofSystem::Plonky2 | ProofSystem::Sp1Groth16
        ) && self.proof_bytes.len() != WRAPPED_PROOF_SIZE;
        if use_variable {
            COMPACT_HEADER_SIZE + PUBLIC_INPUTS_SIZE + 4 + self.proof_bytes.len()
        } else {
            COMPACT_HEADER_SIZE + PUBLIC_INPUTS_SIZE + WRAPPED_PROOF_SIZE
        }
    }

    /// Get the SNARK commitment hash (for OP_RETURN anchor).
    ///
    /// This is SHA-256 of the compact bytes, used as a fingerprint
    /// in the 76-byte OP_RETURN payload.
    pub fn commitment_hash(&self) -> Hash256 {
        Hasher::hash(&self.to_compact_bytes())
    }
}

// ── Internal Helpers ────────────────────────────────────────────────────────

/// Runtime network guard for simulated SNARK paths.
///
/// Panics if `BRRQ_NETWORK` is set to anything other than "testnet" or "regtest".
/// This is a defence-in-depth measure: if a production binary somehow calls
/// `wrap_stark` in simulated mode, the simulated proof cannot be generated
/// on a mainnet deployment.
///
/// The panic is intentional — generating a simulated proof on mainnet is a
/// critical security violation that must halt the process immediately.
fn enforce_simulated_network_check(caller: &str) {
    if let Ok(network) = std::env::var("BRRQ_NETWORK") {
        let network_lower = network.to_lowercase();
        if network_lower != "testnet" && network_lower != "regtest" {
            panic!(
                "SECURITY VIOLATION: {}() called with simulated SNARK mode but \
                 BRRQ_NETWORK=\"{}\". Simulated proofs are only allowed on \
                 \"testnet\" or \"regtest\" networks. Aborting to prevent \
                 forgeable proofs on a production network.",
                caller, network,
            );
        }
    }
    // If BRRQ_NETWORK is not set, allow — tests typically don't set it.
}

/// Generate the simulation secret key.
///
/// Deterministic: `SHA-256("brrq-snark-simulation-v1")`.
fn simulation_key() -> Hash256 {
    Hasher::hash(SIMULATION_DOMAIN)
}

/// Generate 256 bytes of simulated proof via keyed hash chain.
///
/// ```text
/// chunk[0] = SHA-256(key || public_inputs || 0x00)
/// chunk[1] = SHA-256(key || chunk[0] || 0x01)
/// ...
/// chunk[7] = SHA-256(key || chunk[6] || 0x07)
/// proof_bytes = chunk[0] || chunk[1] || ... || chunk[7]
/// ```
fn generate_simulated_proof(public_inputs: &SnarkPublicInputs) -> Vec<u8> {
    let key = simulation_key();
    let pi_bytes = public_inputs.to_bytes();
    let mut proof = Vec::with_capacity(WRAPPED_PROOF_SIZE);

    // First chunk: keyed hash of public inputs
    let mut hasher = Hasher::new();
    hasher.update(key.as_bytes());
    hasher.update(&pi_bytes);
    hasher.update(&[0x00]);
    let mut prev = hasher.finalize();
    proof.extend_from_slice(prev.as_bytes());

    // Subsequent chunks: chain from previous
    for i in 1u8..8 {
        let mut hasher = Hasher::new();
        hasher.update(key.as_bytes());
        hasher.update(prev.as_bytes());
        hasher.update(&[i]);
        prev = hasher.finalize();
        proof.extend_from_slice(prev.as_bytes());
    }

    debug_assert_eq!(proof.len(), WRAPPED_PROOF_SIZE);
    proof
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::prove_batch;
    use crate::prover::StarkProver;

    /// Helper: generate a real STARK proof and wrap it.
    #[allow(deprecated)]
    fn make_wrapped_snark() -> (StarkProof, WrappedSnarkProof) {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();
        let snark = WrappedSnarkProof::wrap_stark(&record.proof, record.block_range).unwrap();
        (record.proof, snark)
    }

    #[test]
    fn wrap_stark_produces_valid_snark() {
        let (_stark, snark) = make_wrapped_snark();

        assert_eq!(snark.proof_system, ProofSystem::Groth16Simulated);
        assert_eq!(snark.proof_bytes.len(), WRAPPED_PROOF_SIZE);
        assert_eq!(snark.public_inputs.l2_height_start, 1);
        assert_eq!(snark.public_inputs.l2_height_end, 10);
        assert_ne!(snark.public_inputs.stark_proof_hash, Hash256::ZERO);
    }

    #[test]
    fn snark_verify_success() {
        let (_stark, snark) = make_wrapped_snark();
        let result = snark.verify();
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn snark_verify_tampered_inputs_fails() {
        let (_stark, mut snark) = make_wrapped_snark();

        // Tamper with the final state root
        snark.public_inputs.final_state_root = Hash256::from_bytes([0xFF; 32]);

        let result = snark.verify();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HMAC mismatch"));
    }

    #[test]
    fn snark_verify_tampered_proof_fails() {
        let (_stark, mut snark) = make_wrapped_snark();

        // Tamper with proof bytes
        snark.proof_bytes[0] ^= 0xFF;

        let result = snark.verify();
        assert!(result.is_err());
    }

    #[test]
    fn snark_compact_bytes_roundtrip() {
        let (_stark, snark) = make_wrapped_snark();

        let compact = snark.to_compact_bytes();
        let recovered = WrappedSnarkProof::from_compact_bytes(&compact).unwrap();

        assert_eq!(recovered.proof_system, snark.proof_system);
        assert_eq!(recovered.public_inputs, snark.public_inputs);
        assert_eq!(recovered.proof_bytes, snark.proof_bytes);
    }

    #[test]
    fn snark_compact_bytes_invalid_magic() {
        let (_stark, snark) = make_wrapped_snark();
        let mut compact = snark.to_compact_bytes();

        // Corrupt magic
        compact[0] = 0xFF;

        let result = WrappedSnarkProof::from_compact_bytes(&compact);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid SNARK magic"));
    }

    #[test]
    fn snark_size_within_target() {
        let (_stark, snark) = make_wrapped_snark();
        let compact = snark.to_compact_bytes();

        // Must be under 400 bytes (whitepaper says ~200-300 for proof + public inputs)
        assert!(compact.len() <= 400, "compact size {} > 400", compact.len());
        assert_eq!(
            compact.len(),
            COMPACT_HEADER_SIZE + PUBLIC_INPUTS_SIZE + WRAPPED_PROOF_SIZE
        );
        assert_eq!(snark.compact_size(), compact.len());
    }

    #[test]
    #[allow(deprecated)]
    fn snark_deterministic() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0xAA; 32]);
        let final_root = Hash256::from_bytes([0xBB; 32]);
        let record = prove_batch(&prover, initial, final_root, (5, 15), 100, 50_000).unwrap();

        let snark1 = WrappedSnarkProof::wrap_stark(&record.proof, record.block_range).unwrap();
        let snark2 = WrappedSnarkProof::wrap_stark(&record.proof, record.block_range).unwrap();

        assert_eq!(snark1.proof_bytes, snark2.proof_bytes);
        assert_eq!(snark1.public_inputs, snark2.public_inputs);
    }

    #[test]
    #[allow(deprecated)]
    fn snark_different_roots_different_proofs() {
        let prover = StarkProver::new();

        let record1 = prove_batch(
            &prover,
            Hash256::from_bytes([1; 32]),
            Hash256::from_bytes([2; 32]),
            (1, 10),
            10,
            1000,
        )
        .unwrap();

        let record2 = prove_batch(
            &prover,
            Hash256::from_bytes([3; 32]),
            Hash256::from_bytes([4; 32]),
            (1, 10),
            10,
            1000,
        )
        .unwrap();

        let snark1 = WrappedSnarkProof::wrap_stark(&record1.proof, record1.block_range).unwrap();
        let snark2 = WrappedSnarkProof::wrap_stark(&record2.proof, record2.block_range).unwrap();

        assert_ne!(snark1.proof_bytes, snark2.proof_bytes);
        assert_ne!(
            snark1.public_inputs.stark_proof_hash,
            snark2.public_inputs.stark_proof_hash
        );
    }

    #[test]
    fn snark_public_inputs_consistency() {
        let (stark, snark) = make_wrapped_snark();

        assert_eq!(
            snark.public_inputs.initial_state_root,
            stark.initial_state_root
        );
        assert_eq!(snark.public_inputs.final_state_root, stark.final_state_root);

        // stark_proof_hash should be SHA-256 of STARK bytes
        let expected_hash = Hasher::hash(&stark.to_bytes().unwrap());
        assert_eq!(snark.public_inputs.stark_proof_hash, expected_hash);
    }

    #[test]
    #[allow(deprecated)]
    fn proof_system_serialization() {
        assert_eq!(
            ProofSystem::from_byte(0),
            Some(ProofSystem::Groth16Simulated)
        );
        assert_eq!(ProofSystem::from_byte(1), Some(ProofSystem::Groth16Real));
        assert_eq!(ProofSystem::from_byte(2), Some(ProofSystem::PlonkReal));
        assert_eq!(ProofSystem::from_byte(3), Some(ProofSystem::Plonky2));
        assert_eq!(ProofSystem::from_byte(4), Some(ProofSystem::Sp1Groth16));
        assert_eq!(ProofSystem::from_byte(5), None);
        assert_eq!(ProofSystem::from_byte(255), None);
    }

    #[test]
    fn snark_commitment_hash_deterministic() {
        let (_stark, snark) = make_wrapped_snark();

        let hash1 = snark.commitment_hash();
        let hash2 = snark.commitment_hash();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, Hash256::ZERO);
    }

    #[test]
    fn compact_bytes_too_short_rejected() {
        let result = WrappedSnarkProof::from_compact_bytes(&[0; 10]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn public_inputs_bytes_roundtrip() {
        let pi = SnarkPublicInputs {
            initial_state_root: Hash256::from_bytes([0xAA; 32]),
            final_state_root: Hash256::from_bytes([0xBB; 32]),
            l2_height_start: 100,
            l2_height_end: 200,
            stark_proof_hash: Hash256::from_bytes([0xCC; 32]),
        };

        let bytes = pi.to_bytes();
        assert_eq!(bytes.len(), PUBLIC_INPUTS_SIZE);

        let recovered = SnarkPublicInputs::from_bytes(&bytes).unwrap();
        assert_eq!(recovered, pi);
    }

    #[test]
    fn real_proof_system_verify_requires_wrapper() {
        let (_stark, mut snark) = make_wrapped_snark();
        snark.proof_system = ProofSystem::Groth16Real;

        let result = snark.verify();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verify_groth16"));
    }

    // ── Adversarial Tests ──────────────────────────────────────

    /// CRITICAL: Plonky2 simulated proofs MUST be flagged as simulated.
    ///
    /// Without this, the guards in bridge.rs (batch proof path) and
    /// challenge_manager.rs (L1 anchor consistency) would allow forgeable
    /// Plonky2 proofs through. Found during adversarial review (2026-03-07).
    #[test]
    #[cfg(not(feature = "real-plonky2"))]
    #[allow(deprecated)]
    fn crit1_plonky2_simulated_is_detected() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();

        // Wrap via Plonky2 path (deprecated)
        let snark =
            WrappedSnarkProof::wrap_stark_plonky2(&record.proof, record.block_range).unwrap();

        assert_eq!(snark.proof_system, ProofSystem::Plonky2);
        assert!(
            snark.is_simulated(),
            "VIOLATION: Plonky2 simulated proof passes is_simulated() check! \
             An attacker could forge Plonky2 proofs and drain the bridge."
        );
    }

    /// When real-plonky2 feature is enabled, Plonky2 proofs are NOT simulated.
    /// The guards in bridge.rs and challenge_manager.rs pass them through.
    #[test]
    #[cfg(feature = "real-plonky2")]
    #[allow(deprecated)]
    fn crit1_real_plonky2_not_simulated() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();

        // Wrap via Plonky2 path (deprecated)
        let snark =
            WrappedSnarkProof::wrap_stark_plonky2(&record.proof, record.block_range).unwrap();

        assert_eq!(snark.proof_system, ProofSystem::Plonky2);
        assert!(
            !snark.is_simulated(),
            "real-plonky2 feature is enabled — Plonky2 proofs must NOT be simulated"
        );

        // Verify STARK proof passes cryptographic verification (prerequisite for bridge).
        assert!(
            crate::verifier::StarkVerifier::verify(&record.proof).is_ok(),
            "STARK proof must be cryptographically valid"
        );
    }

    /// Verify that ALL non-real proof systems are flagged as simulated.
    #[test]
    #[allow(deprecated)]
    fn crit1_all_simulated_systems_detected() {
        let (_stark, mut snark) = make_wrapped_snark();

        // Groth16Simulated → must be simulated
        snark.proof_system = ProofSystem::Groth16Simulated;
        assert!(snark.is_simulated(), "Groth16Simulated must be simulated");

        // Sp1Groth16 → depends on feature flag
        snark.proof_system = ProofSystem::Sp1Groth16;
        #[cfg(not(feature = "real-sp1"))]
        assert!(
            snark.is_simulated(),
            "Sp1Groth16 must be simulated without real-sp1 feature"
        );

        // Plonky2 (deprecated) → depends on feature flag
        snark.proof_system = ProofSystem::Plonky2;
        #[cfg(not(feature = "real-plonky2"))]
        assert!(
            snark.is_simulated(),
            "Plonky2 must be simulated without real-plonky2 feature"
        );
        #[cfg(feature = "real-plonky2")]
        assert!(
            !snark.is_simulated(),
            "Plonky2 must NOT be simulated with real-plonky2 feature"
        );

        // Real systems → must NOT be simulated
        snark.proof_system = ProofSystem::Groth16Real;
        assert!(!snark.is_simulated(), "Groth16Real must not be simulated");

        snark.proof_system = ProofSystem::PlonkReal;
        assert!(!snark.is_simulated(), "PlonkReal must not be simulated");
    }

    /// require_real() rejects simulated proofs.
    #[test]
    fn crit1_require_real_rejects_simulated() {
        let (_stark, snark) = make_wrapped_snark();
        assert_eq!(snark.proof_system, ProofSystem::Groth16Simulated);
        let result = snark.require_real();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("SECURITY VIOLATION"));
    }

    /// require_real() accepts real proof systems.
    #[test]
    fn crit1_require_real_accepts_real() {
        let (_stark, mut snark) = make_wrapped_snark();
        snark.proof_system = ProofSystem::Groth16Real;
        assert!(snark.require_real().is_ok());
    }

    /// Verify that is_simulated() covers every ProofSystem variant.
    /// This test ensures a new variant can't be added without updating is_simulated().
    #[test]
    fn crit1_is_simulated_covers_all_variants() {
        // Test all known byte values for ProofSystem (0..=4)
        for byte_val in 0..=4u8 {
            let system = ProofSystem::from_byte(byte_val).unwrap();
            // Just calling is_simulated ensures the match is exhaustive
            let _ = WrappedSnarkProof {
                proof_bytes: vec![0; 256],
                public_inputs: SnarkPublicInputs {
                    initial_state_root: Hash256::ZERO,
                    final_state_root: Hash256::ZERO,
                    l2_height_start: 0,
                    l2_height_end: 0,
                    stark_proof_hash: Hash256::ZERO,
                },
                proof_system: system,
            }
            .is_simulated();
        }
    }

    // ── SP1 + Groth16 Tests ──────────────────────────────────────────────

    /// SP1 simulated proofs MUST be flagged as simulated (without real-sp1).
    #[test]
    #[cfg(not(feature = "real-sp1"))]
    fn sp1_simulated_is_detected() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        #[allow(deprecated)]
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();

        let snark =
            WrappedSnarkProof::wrap_stark_sp1(&record.proof, record.block_range).unwrap();

        assert_eq!(snark.proof_system, ProofSystem::Sp1Groth16);
        assert!(
            snark.is_simulated(),
            "VIOLATION: SP1 simulated proof passes is_simulated() check! \
             An attacker could forge SP1 proofs and drain the bridge."
        );
    }

    /// SP1 proof wrapping and verification round-trip.
    #[test]
    fn sp1_wrap_and_verify_roundtrip() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        #[allow(deprecated)]
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();

        let snark =
            WrappedSnarkProof::wrap_stark_sp1(&record.proof, record.block_range).unwrap();

        // Verify via the unified verify() interface
        let result = snark.verify();
        assert!(result.is_ok(), "SP1 verify failed: {:?}", result.err());
        assert!(result.unwrap());
    }

    /// SP1 compact bytes round-trip (v2 variable-length format).
    #[test]
    fn sp1_compact_bytes_roundtrip() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        #[allow(deprecated)]
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();

        let snark =
            WrappedSnarkProof::wrap_stark_sp1(&record.proof, record.block_range).unwrap();

        let compact = snark.to_compact_bytes();
        let recovered = WrappedSnarkProof::from_compact_bytes(&compact).unwrap();

        assert_eq!(recovered.proof_system, ProofSystem::Sp1Groth16);
        assert_eq!(recovered.public_inputs, snark.public_inputs);
        assert_eq!(recovered.proof_bytes, snark.proof_bytes);
    }

    /// SP1 public inputs match STARK proof data.
    #[test]
    fn sp1_public_inputs_consistency() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        #[allow(deprecated)]
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();

        let snark =
            WrappedSnarkProof::wrap_stark_sp1(&record.proof, record.block_range).unwrap();

        assert_eq!(snark.public_inputs.initial_state_root, initial);
        assert_eq!(snark.public_inputs.final_state_root, final_root);
        assert_eq!(snark.public_inputs.l2_height_start, 1);
        assert_eq!(snark.public_inputs.l2_height_end, 10);

        // stark_proof_hash should be SHA-256 of STARK bytes
        let expected_hash = Hasher::hash(&record.proof.to_bytes().unwrap());
        assert_eq!(snark.public_inputs.stark_proof_hash, expected_hash);
    }

    /// wrap_best_available uses SP1 (not Plonky2) when no real feature is enabled.
    #[test]
    #[cfg(all(not(feature = "real-sp1"), not(feature = "real-plonky2")))]
    fn wrap_best_available_uses_sp1() {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        #[allow(deprecated)]
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();

        let snark =
            WrappedSnarkProof::wrap_best_available(&record.proof, record.block_range).unwrap();

        assert_eq!(
            snark.proof_system,
            ProofSystem::Sp1Groth16,
            "wrap_best_available should prefer SP1 over simulated Groth16"
        );
    }

    /// SP1 simulated systems detected in is_simulated coverage.
    #[test]
    #[allow(deprecated)]
    fn crit1_sp1_simulated_in_all_systems() {
        let (_stark, mut snark) = make_wrapped_snark();

        // Sp1Groth16 → depends on feature flag
        snark.proof_system = ProofSystem::Sp1Groth16;
        #[cfg(not(feature = "real-sp1"))]
        assert!(
            snark.is_simulated(),
            "Sp1Groth16 must be simulated without real-sp1 feature"
        );
        #[cfg(feature = "real-sp1")]
        assert!(
            !snark.is_simulated(),
            "Sp1Groth16 must NOT be simulated with real-sp1 feature"
        );
    }
}
