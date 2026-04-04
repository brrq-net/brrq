//! SP1 + Groth16 STARK wrapping — replacement for deprecated Plonky2 wrapper.
//!
//! # Architecture
//!
//! SP1 (Succinct) is a RISC-V zkVM that can generate Groth16 proofs via
//! recursive proof composition:
//!
//! 1. The SP1 "program" runs Brrq's STARK verifier inside SP1's RISC-V VM
//! 2. SP1 generates an internal STARK proof that the verifier accepted
//! 3. SP1 wraps its internal STARK into a Groth16 proof (~260 bytes)
//!
//! This is **stronger** than the old Plonky2 approach: SP1 proves full STARK
//! verification was performed correctly, not just metadata binding.
//!
//! # Security
//!
//! Simulated paths follow the same three-layer guard pattern:
//!   - **Compile-time**: `real-sp1` feature flag
//!   - **Runtime**: `BRRQ_NETWORK` env var guard (rejects mainnet if simulated)
//!   - **API-level**: `is_simulated()` / `require_real()` checks
//!
//! # Why SP1 over Plonky2
//!
//! - Plonky2 is deprecated (Polygon pivoted to Plonky3)
//! - SP1 is actively maintained, audited, and industry-standard
//! - SP1 + Groth16 output is ~260 bytes (fits <400 byte L1 budget)
//! - SP1 eliminates the need for a custom verification circuit
//! - Groth16 requires a trusted setup, BUT SP1's ceremony is shared across
//!   all SP1 users (amortized trust) — unlike a Brrq-specific ceremony

// Compile-time guard: fires when BOTH `real-sp1` and
// `allow-simulated-proofs` are OFF, preventing accidental production
// builds with simulated verification.
#[cfg(all(not(feature = "real-sp1"), not(feature = "allow-simulated-proofs")))]
compile_error!(
    "\n\
    ╔══════════════════════════════════════════════════════════════════╗\n\
    ║  SP1 is running in SIMULATED mode!                   ║\n\
    ║  verify() returns Ok(true) unconditionally — NO cryptographic   ║\n\
    ║  verification is performed. This is ONLY safe for tests.        ║\n\
    ║                                                                  ║\n\
    ║  For production builds, enable feature `real-sp1`.               ║\n\
    ║  For dev/test ONLY, enable feature `allow-simulated-proofs`.     ║\n\
    ╚══════════════════════════════════════════════════════════════════╝\n"
);

use brrq_crypto::hash::{Hash256, Hasher};
use serde::{Deserialize, Serialize};

use crate::snark_wrapper::SnarkPublicInputs;
use crate::types::StarkProof;

// ── Constants ───────────────────────────────────────────────────────────────

/// Target Groth16 proof size from SP1 wrapping.
///
/// Standard BN254 Groth16: A (64B) + B (128B) + C (64B) = 256 bytes.
/// SP1 adds ~4 bytes of metadata. We allocate 260 bytes.
pub const SP1_GROTH16_PROOF_SIZE: usize = 260;

/// Domain separator for SP1 simulation HMAC key.
const SP1_SIMULATION_DOMAIN: &[u8] = b"brrq-sp1-groth16-simulation-v1";

// ── Types ───────────────────────────────────────────────────────────────────

/// SP1 wrapper configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sp1WrapperConfig {
    /// Path to the compiled SP1 ELF binary (STARK verifier program).
    pub elf_path: Option<String>,
    /// Whether to use GPU acceleration for SP1 proving.
    pub use_gpu: bool,
}

impl Default for Sp1WrapperConfig {
    fn default() -> Self {
        Self {
            elf_path: None,
            use_gpu: false,
        }
    }
}

/// Result of SP1 wrapping — proof bytes and public inputs.
pub struct Sp1WrapResult {
    /// Groth16 proof bytes (~260 bytes in production, 260 bytes simulated).
    pub proof_bytes: Vec<u8>,
    /// Public inputs that the Groth16 verifier checks.
    pub public_inputs: SnarkPublicInputs,
}

// ── Simulated SP1 Wrapper ───────────────────────────────────────────────────

/// Wrap a STARK proof using simulated SP1 + Groth16.
///
/// This produces a deterministic hash-based simulation that matches the
/// structure of a real SP1 Groth16 output but is NOT cryptographically
/// secure. Gated by `allow-simulated-proofs` feature flag.
///
/// The simulation:
/// 1. Serializes the STARK proof and computes `stark_proof_hash`
/// 2. Builds `SnarkPublicInputs` from state roots + block range + hash
/// 3. Generates 260 bytes of simulated proof via keyed hash chain
///
/// # Security Warning
///
/// The simulation key is deterministic — anyone can reproduce the proof.
/// This path is blocked on mainnet by runtime `BRRQ_NETWORK` check.
pub fn wrap_stark_sp1_simulated(
    stark_proof: &StarkProof,
    block_range: (u64, u64),
) -> Result<Sp1WrapResult, String> {
    // Runtime production guard
    reject_if_production("wrap_stark_sp1_simulated")?;

    // Step 1: Hash the full STARK proof
    let stark_bytes = stark_proof
        .to_bytes()
        .map_err(|e| format!("STARK proof serialization failed: {e}"))?;
    let stark_proof_hash = Hasher::hash(&stark_bytes);

    // Step 2: Build public inputs (same structure as real SP1)
    let public_inputs = SnarkPublicInputs {
        initial_state_root: stark_proof.initial_state_root,
        final_state_root: stark_proof.final_state_root,
        l2_height_start: block_range.0,
        l2_height_end: block_range.1,
        stark_proof_hash,
    };

    // Step 3: Generate simulated Groth16 proof bytes (260 bytes)
    let proof_bytes = generate_simulated_sp1_proof(&public_inputs);

    Ok(Sp1WrapResult {
        proof_bytes,
        public_inputs,
    })
}

/// Verify a simulated SP1 Groth16 proof.
///
/// Re-derives the expected proof bytes from public inputs and compares.
/// Gated by runtime `BRRQ_NETWORK` check.
pub fn verify_sp1_simulated(
    proof_bytes: &[u8],
    public_inputs: &SnarkPublicInputs,
) -> Result<bool, String> {
    reject_if_production("verify_sp1_simulated")?;

    if proof_bytes.len() != SP1_GROTH16_PROOF_SIZE {
        return Err(format!(
            "invalid SP1 proof size: {} != {}",
            proof_bytes.len(),
            SP1_GROTH16_PROOF_SIZE,
        ));
    }

    let expected = generate_simulated_sp1_proof(public_inputs);
    if proof_bytes != expected {
        return Err("SP1 simulated proof verification failed: HMAC mismatch".into());
    }

    Ok(true)
}

// ── Real SP1 Wrapper ────────────────────────────────────────────────────────

/// Wrap a STARK proof using real SP1 + Groth16.
///
/// This runs Brrq's STARK verifier inside SP1's RISC-V zkVM, generating
/// a real Groth16 proof that can be verified on Bitcoin L1 via BitVM2.
///
/// ## Process
///
/// 1. Load the SP1 STARK verifier ELF binary
/// 2. Serialize the STARK proof as SP1 program input
/// 3. SP1 executes the verifier → generates internal STARK
/// 4. SP1 wraps its STARK into Groth16 (~260 bytes)
/// 5. Extract public inputs and proof bytes
///
/// ## Performance
///
/// Expected proving time: 3-10 minutes per batch. This is acceptable
/// since batches are wrapped 1-3 times per hour (recursive aggregation).
#[cfg(feature = "real-sp1")]
pub fn wrap_stark_sp1_real(
    stark_proof: &StarkProof,
    block_range: (u64, u64),
    config: &Sp1WrapperConfig,
) -> Result<Sp1WrapResult, String> {
    use sp1_sdk::{ProverClient, SP1Stdin};

    // 1. Load the compiled STARK verifier ELF
    let elf_path = config
        .elf_path
        .as_deref()
        .unwrap_or("sp1-program/elf/stark-verifier");
    let elf = std::fs::read(elf_path)
        .map_err(|e| format!("failed to read SP1 ELF at {elf_path}: {e}"))?;

    // 2. Serialize STARK proof as SP1 stdin
    let stark_bytes = stark_proof
        .to_bytes()
        .map_err(|e| format!("STARK proof serialization failed: {e}"))?;

    let mut stdin = SP1Stdin::new();
    stdin.write(&stark_bytes);
    stdin.write(&stark_proof.initial_state_root.as_bytes().to_vec());
    stdin.write(&stark_proof.final_state_root.as_bytes().to_vec());
    stdin.write(&block_range.0.to_le_bytes().to_vec());
    stdin.write(&block_range.1.to_le_bytes().to_vec());

    // 3. Create SP1 prover client and generate Groth16 proof
    let client = ProverClient::new();
    let (pk, _vk) = client.setup(&elf);

    let proof = client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .map_err(|e| format!("SP1 Groth16 proving failed: {e}"))?;

    // 4. Extract proof bytes
    let proof_bytes = proof.bytes();

    // 5. Compute stark_proof_hash for public inputs
    let stark_proof_hash = Hasher::hash(&stark_bytes);

    let public_inputs = SnarkPublicInputs {
        initial_state_root: stark_proof.initial_state_root,
        final_state_root: stark_proof.final_state_root,
        l2_height_start: block_range.0,
        l2_height_end: block_range.1,
        stark_proof_hash,
    };

    Ok(Sp1WrapResult {
        proof_bytes,
        public_inputs,
    })
}

/// Verify a real SP1 Groth16 proof.
#[cfg(feature = "real-sp1")]
pub fn verify_sp1_real(
    proof_bytes: &[u8],
    public_inputs: &SnarkPublicInputs,
    config: &Sp1WrapperConfig,
) -> Result<bool, String> {
    use sp1_sdk::ProverClient;

    let elf_path = config
        .elf_path
        .as_deref()
        .unwrap_or("sp1-program/elf/stark-verifier");
    let elf = std::fs::read(elf_path)
        .map_err(|e| format!("failed to read SP1 ELF at {elf_path}: {e}"))?;

    let client = ProverClient::new();
    let (_pk, vk) = client.setup(&elf);

    // Reconstruct SP1 proof from bytes for verification
    let proof: sp1_sdk::SP1ProofWithPublicValues = bincode::deserialize(proof_bytes)
        .map_err(|e| format!("failed to deserialize SP1 proof: {e}"))?;

    client
        .verify(&proof, &vk)
        .map_err(|e| format!("SP1 Groth16 verification failed: {e}"))?;

    // Verify that the SP1 proof's committed public values match
    // the expected public_inputs. Without this, a valid SP1 proof from a different
    // block range or state transition would be accepted as valid.
    let expected_bytes = public_inputs.to_bytes();
    let committed = proof.public_values.as_slice();
    if committed.len() < expected_bytes.len()
        || committed[..expected_bytes.len()] != expected_bytes[..]
    {
        return Err(format!(
            "SP1 proof public values mismatch: expected {} bytes matching claimed inputs, got {} bytes",
            expected_bytes.len(),
            committed.len()
        ));
    }

    Ok(true)
}

// ── Unified Interface ───────────────────────────────────────────────────────

/// Wrap a STARK proof using the best available SP1 backend.
///
/// With `real-sp1`: generates a real Groth16 proof via SP1.
/// Without `real-sp1`: generates a simulated proof (dev/test only).
pub fn wrap_stark_sp1(
    stark_proof: &StarkProof,
    block_range: (u64, u64),
) -> Result<Sp1WrapResult, String> {
    #[cfg(feature = "real-sp1")]
    {
        let config = Sp1WrapperConfig::default();
        return wrap_stark_sp1_real(stark_proof, block_range, &config);
    }
    #[cfg(not(feature = "real-sp1"))]
    {
        return wrap_stark_sp1_simulated(stark_proof, block_range);
    }
}

/// Verify an SP1 Groth16 proof using the best available backend.
pub fn verify_sp1(
    proof_bytes: &[u8],
    public_inputs: &SnarkPublicInputs,
) -> Result<bool, String> {
    #[cfg(feature = "real-sp1")]
    {
        let config = Sp1WrapperConfig::default();
        return verify_sp1_real(proof_bytes, public_inputs, &config);
    }
    #[cfg(not(feature = "real-sp1"))]
    {
        return verify_sp1_simulated(proof_bytes, public_inputs);
    }
}

// ── Internal Helpers ────────────────────────────────────────────────────────

/// Runtime guard: reject simulated SP1 on production networks.
fn reject_if_production(caller: &str) -> Result<(), String> {
    if let Ok(network) = std::env::var("BRRQ_NETWORK") {
        if network.eq_ignore_ascii_case("mainnet") {
            return Err(format!(
                "SECURITY VIOLATION: {caller}() called in simulated mode but \
                 BRRQ_NETWORK=mainnet. Simulated SP1 proofs MUST NOT be used on \
                 mainnet. Rebuild with feature `real-sp1`.",
            ));
        }
    }
    Ok(())
}

/// Generate 260 bytes of simulated SP1 Groth16 proof via keyed hash chain.
///
/// ```text
/// key = SHA-256("brrq-sp1-groth16-simulation-v1")
/// chunk[0] = SHA-256(key || public_inputs_bytes || 0x00)
/// chunk[1] = SHA-256(key || chunk[0] || 0x01)
/// ...
/// chunk[7] = SHA-256(key || chunk[6] || 0x07)
/// proof = chunk[0..7] || chunk[7][0..4]    (8*32 + 4 = 260 bytes)
/// ```
fn generate_simulated_sp1_proof(public_inputs: &SnarkPublicInputs) -> Vec<u8> {
    let key = Hasher::hash(SP1_SIMULATION_DOMAIN);
    let pi_bytes = public_inputs.to_bytes();
    let mut proof = Vec::with_capacity(SP1_GROTH16_PROOF_SIZE);

    // First chunk
    let mut hasher = Hasher::new();
    hasher.update(key.as_bytes());
    hasher.update(&pi_bytes);
    hasher.update(&[0x00]);
    let mut prev = hasher.finalize();
    proof.extend_from_slice(prev.as_bytes());

    // Subsequent chunks (7 more = 8 total = 256 bytes)
    for i in 1u8..8 {
        let mut hasher = Hasher::new();
        hasher.update(key.as_bytes());
        hasher.update(prev.as_bytes());
        hasher.update(&[i]);
        prev = hasher.finalize();
        proof.extend_from_slice(prev.as_bytes());
    }

    // Add 4 more bytes to reach 260 (Groth16 metadata)
    let mut hasher = Hasher::new();
    hasher.update(key.as_bytes());
    hasher.update(prev.as_bytes());
    hasher.update(&[0xFF]); // metadata marker
    let final_hash = hasher.finalize();
    proof.extend_from_slice(&final_hash.as_bytes()[..4]);

    debug_assert_eq!(proof.len(), SP1_GROTH16_PROOF_SIZE);
    proof
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch::prove_batch;
    use crate::prover::StarkProver;

    fn make_stark_proof() -> (StarkProof, (u64, u64)) {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        #[allow(deprecated)]
        let record = prove_batch(&prover, initial, final_root, (1, 10), 50, 21_000).unwrap();
        (record.proof, record.block_range)
    }

    #[test]
    fn sp1_simulated_wrap_produces_valid_output() {
        let (proof, range) = make_stark_proof();
        let result = wrap_stark_sp1_simulated(&proof, range).unwrap();

        assert_eq!(result.proof_bytes.len(), SP1_GROTH16_PROOF_SIZE);
        assert_eq!(result.public_inputs.l2_height_start, 1);
        assert_eq!(result.public_inputs.l2_height_end, 10);
        assert_ne!(result.public_inputs.stark_proof_hash, Hash256::ZERO);
    }

    #[test]
    fn sp1_simulated_verify_success() {
        let (proof, range) = make_stark_proof();
        let result = wrap_stark_sp1_simulated(&proof, range).unwrap();
        assert!(verify_sp1_simulated(&result.proof_bytes, &result.public_inputs).unwrap());
    }

    #[test]
    fn sp1_simulated_verify_tampered_fails() {
        let (proof, range) = make_stark_proof();
        let result = wrap_stark_sp1_simulated(&proof, range).unwrap();

        // Tamper with proof bytes
        let mut tampered = result.proof_bytes.clone();
        tampered[0] ^= 0xFF;

        let verify = verify_sp1_simulated(&tampered, &result.public_inputs);
        assert!(verify.is_err());
        assert!(verify.unwrap_err().contains("HMAC mismatch"));
    }

    #[test]
    fn sp1_simulated_verify_tampered_inputs_fails() {
        let (proof, range) = make_stark_proof();
        let result = wrap_stark_sp1_simulated(&proof, range).unwrap();

        let mut tampered_inputs = result.public_inputs.clone();
        tampered_inputs.final_state_root = Hash256::from_bytes([0xFF; 32]);

        let verify = verify_sp1_simulated(&result.proof_bytes, &tampered_inputs);
        assert!(verify.is_err());
    }

    #[test]
    fn sp1_simulated_deterministic() {
        let (proof, range) = make_stark_proof();
        let r1 = wrap_stark_sp1_simulated(&proof, range).unwrap();
        let r2 = wrap_stark_sp1_simulated(&proof, range).unwrap();

        assert_eq!(r1.proof_bytes, r2.proof_bytes);
        assert_eq!(r1.public_inputs, r2.public_inputs);
    }

    #[test]
    fn sp1_simulated_different_roots_different_proofs() {
        let prover = StarkProver::new();

        #[allow(deprecated)]
        let record1 = prove_batch(
            &prover,
            Hash256::from_bytes([1; 32]),
            Hash256::from_bytes([2; 32]),
            (1, 10),
            10,
            1000,
        )
        .unwrap();
        #[allow(deprecated)]
        let record2 = prove_batch(
            &prover,
            Hash256::from_bytes([3; 32]),
            Hash256::from_bytes([4; 32]),
            (1, 10),
            10,
            1000,
        )
        .unwrap();

        let r1 = wrap_stark_sp1_simulated(&record1.proof, record1.block_range).unwrap();
        let r2 = wrap_stark_sp1_simulated(&record2.proof, record2.block_range).unwrap();

        assert_ne!(r1.proof_bytes, r2.proof_bytes);
    }

    #[test]
    fn sp1_proof_size_within_l1_budget() {
        let (proof, range) = make_stark_proof();
        let result = wrap_stark_sp1_simulated(&proof, range).unwrap();

        // Must fit within 400-byte L1 budget (proof only, without header/inputs)
        assert!(
            result.proof_bytes.len() <= 400,
            "SP1 proof {} bytes > 400 byte L1 budget",
            result.proof_bytes.len()
        );
    }

    #[test]
    fn sp1_wrong_size_rejected() {
        let pi = SnarkPublicInputs {
            initial_state_root: Hash256::ZERO,
            final_state_root: Hash256::ZERO,
            l2_height_start: 0,
            l2_height_end: 0,
            stark_proof_hash: Hash256::ZERO,
        };
        let result = verify_sp1_simulated(&[0u8; 100], &pi);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("invalid SP1 proof size"));
    }
}
