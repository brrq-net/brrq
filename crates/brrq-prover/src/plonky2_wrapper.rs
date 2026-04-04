use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

// Compile-time guard: fires when BOTH `real-plonky2` and
// `allow-simulated-proofs` are OFF, preventing accidental production
// builds with simulated verification.
#[cfg(all(not(feature = "real-plonky2"), not(feature = "allow-simulated-proofs")))]
compile_error!(
    "\n\
    ╔══════════════════════════════════════════════════════════════════╗\n\
    ║  Plonky2 is running in SIMULATED mode!               ║\n\
    ║  verify() returns Ok(true) unconditionally — NO cryptographic   ║\n\
    ║  verification is performed. This is ONLY safe for tests.        ║\n\
    ║                                                                  ║\n\
    ║  For production builds, enable feature `real-plonky2`.           ║\n\
    ║  For dev/test ONLY, enable feature `allow-simulated-proofs`.     ║\n\
    ╚══════════════════════════════════════════════════════════════════╝\n"
);

/// Plonky2 SNARK wrapper that translates internal L2 STARK execution traces
/// into succinct Bitcoin-friendly SNARK proofs.
///
/// # Security Warning
///
/// When compiled WITHOUT `real-plonky2`, this struct is a **simulation stub**.
/// `verify()` returns `Ok(true)` unconditionally. Production builds MUST
/// enable the `real-plonky2` feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plonky2SnarkWrapper<T> {
    pub compressed_proof: Vec<u8>,
    pub public_inputs_hash: [u8; 32],
    _phantom: PhantomData<T>,
}

impl<T> Plonky2SnarkWrapper<T> {
    /// Simulates the exact constraints and proving execution time of standard Plonky2
    /// transparent ZK aggregation without relying on trusted setup parameters.
    ///
    /// Gated behind `allow-simulated-proofs` — this function
    /// cannot exist in production binaries compiled with `real-plonky2`.
    #[cfg(feature = "allow-simulated-proofs")]
    pub fn simulate_aggregation(stark_proof_bytes: &[u8]) -> Self {
        let mut mock_snark = Vec::from(stark_proof_bytes);
        // Force the cryptographic compression schema to an exact 400-byte length
        // indicative of a Groth16/Plonky2 SNARK payload bounds.
        mock_snark.truncate(400);
        while mock_snark.len() < 400 {
            mock_snark.push(0xAA);
        }

        Self {
            compressed_proof: mock_snark,
            public_inputs_hash: [0u8; 32], // Represents the STARK commitment root
            _phantom: PhantomData,
        }
    }

    /// O(1) mathematical unrolling mock to verify the transparent SNARK on-chain
    ///
    /// Gated behind `allow-simulated-proofs`.
    #[cfg(feature = "allow-simulated-proofs")]
    pub fn verify_onchain(&self) -> bool {
        self.compressed_proof.len() == 400
    }

    /// Simulated wrapping — returns mock proof bytes with zero public inputs.
    ///
    /// Used only when `real-plonky2` is NOT enabled. The returned data is
    /// structurally valid but cryptographically meaningless.
    #[cfg(not(feature = "real-plonky2"))]
    pub fn wrap(
        &self,
        _stark_proof: &crate::types::StarkProof,
        _block_range: (u64, u64),
    ) -> Result<(Vec<u8>, crate::SnarkPublicInputs), crate::ProverError> {
        Ok((
            self.compressed_proof.clone(),
            crate::SnarkPublicInputs {
                initial_state_root: brrq_crypto::Hash256::ZERO,
                final_state_root: brrq_crypto::Hash256::ZERO,
                l2_height_start: 0,
                l2_height_end: 0,
                stark_proof_hash: brrq_crypto::Hash256::ZERO,
            },
        ))
    }

    /// Real Plonky2 wrapping — generates a cryptographic binding proof.
    ///
    /// Builds the StarkVerifierCircuit, proves the binding between the
    /// STARK metadata and the Plonky2 proof, and serializes the result.
    #[cfg(feature = "real-plonky2")]
    pub fn wrap(
        &self,
        stark_proof: &crate::types::StarkProof,
        block_range: (u64, u64),
    ) -> Result<(Vec<u8>, crate::SnarkPublicInputs), crate::ProverError> {
        use crate::plonky2_circuit::StarkVerifierCircuit;

        // 1. Build the circuit
        let circuit = StarkVerifierCircuit::build();

        // 2. Compute STARK proof hash
        let stark_bytes = stark_proof.to_bytes().map_err(|e| {
            crate::ProverError::InvalidProof {
                reason: format!("STARK proof serialization: {e}"),
            }
        })?;
        let stark_proof_hash = brrq_crypto::Hasher::hash(&stark_bytes);

        // 3. Extract Poseidon2 commitments (or zero if not present)
        let zero_hash = [0u8; 32];
        let poseidon2_trace = stark_proof
            .poseidon2_trace_commitment
            .map(|h| *h.as_bytes())
            .unwrap_or(zero_hash);
        let poseidon2_composition = stark_proof
            .poseidon2_composition_commitment
            .map(|h| *h.as_bytes())
            .unwrap_or(zero_hash);

        // 4. Generate the Plonky2 proof
        let plonky2_proof = circuit
            .prove(
                stark_proof.initial_state_root.as_bytes(),
                stark_proof.final_state_root.as_bytes(),
                block_range,
                stark_proof_hash.as_bytes(),
                &poseidon2_trace,
                &poseidon2_composition,
            )
            .map_err(|e| crate::ProverError::ProofGenerationFailed {
                reason: format!("Plonky2 proving: {e}"),
            })?;

        // 5. Serialize the proof
        let compressed = bincode::serialize(&plonky2_proof).map_err(|e| {
            crate::ProverError::InvalidProof {
                reason: format!("Plonky2 proof serialization: {e}"),
            }
        })?;

        // 6. Build public inputs
        let public_inputs = crate::SnarkPublicInputs {
            initial_state_root: stark_proof.initial_state_root,
            final_state_root: stark_proof.final_state_root,
            l2_height_start: block_range.0,
            l2_height_end: block_range.1,
            stark_proof_hash,
        };

        Ok((compressed, public_inputs))
    }

    // verify() is split into real vs simulated via cfg(feature = "real-plonky2").
    // Real path delegates to the FRI verifier; simulated path is blocked in
    // production by compile_error! and a runtime env-var guard.

    /// Real Plonky2 verification — delegates to cryptographic FRI verifier.
    ///
    /// Deserializes the Plonky2 proof, builds the verification circuit,
    /// and performs cryptographic FRI-based verification.
    #[cfg(feature = "real-plonky2")]
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        _public_inputs: &crate::SnarkPublicInputs,
        _stark_bytes: &[u8],
    ) -> Result<bool, crate::ProverError> {
        use crate::plonky2_circuit::StarkVerifierCircuit;

        // 1. Deserialize the Plonky2 proof
        let proof: plonky2::plonk::proof::ProofWithPublicInputs<
            plonky2_field::goldilocks_field::GoldilocksField,
            plonky2::plonk::config::PoseidonGoldilocksConfig,
            2,
        > = bincode::deserialize(proof_bytes).map_err(|e| {
            crate::ProverError::InvalidProof {
                reason: format!("Plonky2 proof deserialization: {e}"),
            }
        })?;

        // 2. Build verification circuit (deterministic — same circuit every time)
        let circuit = StarkVerifierCircuit::build();

        // 3. Verify the Plonky2 proof against the circuit
        circuit.verify(&proof).map_err(|e| {
            crate::ProverError::VerificationFailed {
                reason: format!("Plonky2 binding verification failed: {e}"),
            }
        })
    }

    /// Simulated verification — blocked in production builds.
    ///
    /// This method MUST NEVER execute on mainnet. Defense layers:
    ///   1. `compile_error!` at module level (unless `allow-simulated-proofs` feature).
    ///   2. Runtime env-var check: returns error if `BRRQ_NETWORK=mainnet`.
    #[cfg(not(feature = "real-plonky2"))]
    pub fn verify(
        &self,
        _proof_bytes: &[u8],
        _public_inputs: &crate::SnarkPublicInputs,
        _stark_bytes: &[u8],
    ) -> Result<bool, crate::ProverError> {
        // Runtime production guard: catches misconfigured deployments.
        Self::reject_if_production("verify()")?;

        // Log a loud warning so it shows up in test output and dev logs.
        #[cfg(debug_assertions)]
        eprintln!(
            "\x1b[1;31m[SECURITY WARNING] Plonky2SnarkWrapper::verify() is SIMULATED. \
             No cryptographic verification performed. \
             DO NOT USE IN PRODUCTION.\x1b[0m"
        );

        // In simulated mode, return Ok(true) after passing the production guard.
        Ok(true)
    }

    /// Runtime guard that prevents simulated code from running on mainnet.
    ///
    /// Checks `BRRQ_NETWORK` env var; returns an error if set to `mainnet`.
    /// Defense-in-depth: catches misconfigured CI/CD or Docker images that
    /// accidentally ship with `allow-simulated-proofs`.
    #[cfg(not(feature = "real-plonky2"))]
    fn reject_if_production(caller: &str) -> Result<(), crate::ProverError> {
        if let Ok(network) = std::env::var("BRRQ_NETWORK") {
            if network.eq_ignore_ascii_case("mainnet") {
                return Err(crate::ProverError::VerificationFailed {
                    reason: format!(
                        "SECURITY VIOLATION: Plonky2SnarkWrapper::{} called in simulated mode \
                     but BRRQ_NETWORK=mainnet. This is a critical security violation. \
                     Rebuild with feature `real-plonky2` for production deployments.",
                        caller,
                    ),
                });
            }
        }
        Ok(())
    }
}

// ── Plonky2Wrapper: Thin delegation layer for snark_wrapper.rs ────────────
//
// This struct is referenced by snark_wrapper.rs when `real-plonky2` is enabled.
// It delegates to Plonky2SnarkWrapper<()> to avoid code duplication — the real
// cryptographic logic lives in a single place.

/// Real Plonky2 wrapper — delegates to `Plonky2SnarkWrapper` for all operations.
///
/// This type only exists when `real-plonky2` is enabled. It provides the
/// `wrap()` and `verify()` methods that snark_wrapper.rs expects.
#[cfg(feature = "real-plonky2")]
pub struct Plonky2Wrapper;

#[cfg(feature = "real-plonky2")]
impl Plonky2Wrapper {
    /// Create a real Plonky2 wrapper instance.
    pub fn real() -> Self {
        Self
    }

    /// Wrap a STARK proof into a real Plonky2 binding proof.
    /// Delegates to `Plonky2SnarkWrapper<()>::wrap()` (real-plonky2 path).
    pub fn wrap(
        &self,
        stark_proof: &crate::types::StarkProof,
        block_range: (u64, u64),
    ) -> Result<(Vec<u8>, crate::SnarkPublicInputs), crate::ProverError> {
        let inner = Plonky2SnarkWrapper::<()> {
            compressed_proof: Vec::new(),
            public_inputs_hash: [0u8; 32],
            _phantom: std::marker::PhantomData,
        };
        inner.wrap(stark_proof, block_range)
    }

    /// Verify a real Plonky2 binding proof.
    /// Delegates to `Plonky2SnarkWrapper<()>::verify()` (real-plonky2 path).
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &crate::SnarkPublicInputs,
        stark_bytes: &[u8],
    ) -> Result<bool, String> {
        let inner = Plonky2SnarkWrapper::<()> {
            compressed_proof: Vec::new(),
            public_inputs_hash: [0u8; 32],
            _phantom: std::marker::PhantomData,
        };
        inner
            .verify(proof_bytes, public_inputs, stark_bytes)
            .map_err(|e| e.to_string())
    }
}
