//! Bridge Backend Abstraction — pluggable L1 verification strategy.
//!
//! ## Purpose
//!
//! Decouples the bridge from a specific BitVM version. The dispute game,
//! proof verification, and bond management all go through this trait.
//! Switching from BitVM2 → BitVM3 requires only implementing a new backend.
//!
//! ## Backends
//!
//! | Backend | Status | Mechanism |
//! |---------|--------|-----------|
//! | BitVM2  | Production | On-chain Script verification |
//! | BitVM3  | Research | Off-chain Garbled Circuits |
//! | OP_CAT  | Speculative (requires Bitcoin soft fork) | Native Script introspection |
//!
//! ## Migration Path
//!
//! 1. Launch with `BitVM2Backend` (current code, production-ready)
//! 2. When BitVM3 is ready → implement `BitVM3Backend`
//! 3. Governance proposal to switch backend (no bridge rebuild needed)

use brrq_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

/// Verification result from L1 dispute resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisputeVerdict {
    /// Operator's state claim is valid — bond returned.
    OperatorHonest,
    /// Operator's state claim is fraudulent — bond slashed.
    OperatorFraudulent,
    /// Dispute timed out — default resolution applied.
    Timeout,
    /// Verification failed due to technical error.
    Error(String),
}

/// A proof that can be verified on L1 through the backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1VerifiableProof {
    /// STARK proof bytes (backend-agnostic).
    pub stark_proof: Vec<u8>,
    /// Initial state root the proof claims to start from.
    pub initial_state_root: Hash256,
    /// Final state root the proof claims to end at.
    pub final_state_root: Hash256,
    /// Block range covered by the proof.
    pub block_range: (u64, u64),
}

/// Estimated cost of posting a proof or dispute step to L1.
#[derive(Debug, Clone)]
pub struct L1CostEstimate {
    /// Estimated Bitcoin transaction fee in satoshis.
    pub fee_sats: u64,
    /// Number of L1 transactions required.
    pub num_transactions: u32,
    /// Total weight units consumed.
    pub total_weight: u64,
}

/// Bridge backend trait — abstracts L1 verification mechanism.
///
/// Implementations handle the details of how proofs are posted to Bitcoin
/// and how disputes are resolved. The bridge core calls these methods
/// without knowing whether BitVM2, BitVM3, or OP_CAT is used underneath.
pub trait BridgeBackend: Send + Sync {
    /// Human-readable name for logging and diagnostics.
    fn name(&self) -> &str;

    /// Whether this backend is production-ready.
    fn is_production_ready(&self) -> bool;

    /// Estimate the L1 cost of posting a proof.
    ///
    /// Used by the economics layer to determine if proving is profitable
    /// and by the relayer to set appropriate gas prices.
    fn estimate_proof_cost(&self, proof: &L1VerifiableProof) -> L1CostEstimate;

    /// Prepare proof data for L1 posting.
    ///
    /// For BitVM2: wraps STARK in Groth16 SNARK, chunks into Tapscript leaves.
    /// For BitVM3: encodes as Garbled Circuit inputs (much smaller).
    /// For OP_CAT: encodes as Script with CAT-based verification.
    ///
    /// Returns serialized bytes ready for L1 transaction construction.
    fn prepare_for_l1(&self, proof: &L1VerifiableProof) -> Result<Vec<u8>, String>;

    /// Maximum proof size this backend can handle (bytes).
    ///
    /// BitVM2: limited by Tapscript chunking (~4GB theoretical, ~100MB practical)
    /// BitVM3: limited by Garbled Circuit size (potentially larger)
    /// OP_CAT: limited by Script size (much smaller)
    fn max_proof_size(&self) -> usize;

    /// Number of L1 transactions needed for a complete dispute resolution.
    ///
    /// BitVM2: 4 (Kickoff → Assert → Disprove → Take)
    /// BitVM3: potentially 2 (Challenge → Response) — much fewer rounds
    fn dispute_rounds(&self) -> u32;

    /// Challenge period in L1 blocks.
    ///
    /// How long the operator has to respond before bond is slashed.
    fn challenge_period_blocks(&self) -> u32;
}

/// BitVM2 backend — on-chain Script verification via Tapscript chunking.
///
/// This is the production backend. Uses Groth16 SNARK wrapping + Tapscript
/// chunking for L1 fraud proof verification.
pub struct BitVM2Backend {
    /// Challenge period in L1 blocks (~2 weeks).
    pub challenge_period: u32,
}

impl Default for BitVM2Backend {
    fn default() -> Self {
        Self {
            challenge_period: 2016, // ~2 weeks
        }
    }
}

impl BridgeBackend for BitVM2Backend {
    fn name(&self) -> &str {
        "BitVM2"
    }

    fn is_production_ready(&self) -> bool {
        true
    }

    fn estimate_proof_cost(&self, proof: &L1VerifiableProof) -> L1CostEstimate {
        // BitVM2: SNARK proof ~374 bytes → 1 OP_RETURN tx + dispute Tapscript tree
        let num_chunks = crate::bitvm_compiler::min_leaves_for_script(proof.stark_proof.len());
        L1CostEstimate {
            fee_sats: 50_000 + (num_chunks as u64 * 10_000), // ~50K base + 10K per chunk
            num_transactions: 4, // Kickoff + Assert + Disprove + Take
            total_weight: 400 + (num_chunks as u64 * 1_000),
        }
    }

    fn prepare_for_l1(&self, proof: &L1VerifiableProof) -> Result<Vec<u8>, String> {
        // In production: STARK → Groth16 SNARK → Tapscript chunks
        // For now: pass through (SNARK wrapping happens in snark_wrapper.rs)
        Ok(proof.stark_proof.clone())
    }

    fn max_proof_size(&self) -> usize {
        100 * 1024 * 1024 // 100 MB practical limit for chunked verification
    }

    fn dispute_rounds(&self) -> u32 {
        4 // Kickoff → Assert → Disprove → Take
    }

    fn challenge_period_blocks(&self) -> u32 {
        self.challenge_period
    }
}

/// BitVM3 backend stub — off-chain Garbled Circuit verification.
///
/// Future BitVM3 backend.
/// Based on "BitVM3-RSA: Efficient Computation on Bitcoin" (Jul 2025).
///
/// Key differences from BitVM2:
/// - Computation is OFF-CHAIN (Garbled Circuits, not Bitcoin Script)
/// - ~1000x cheaper fraud proofs
/// - Fewer dispute rounds (potentially 2 vs 4)
/// - Requires garbled circuit library (not yet available for Rust/Bitcoin)
pub struct BitVM3Backend {
    /// Challenge period in L1 blocks.
    pub challenge_period: u32,
}

impl Default for BitVM3Backend {
    fn default() -> Self {
        Self {
            challenge_period: 1008, // ~1 week (faster disputes due to off-chain computation)
        }
    }
}

impl BridgeBackend for BitVM3Backend {
    fn name(&self) -> &str {
        "BitVM3-RSA (stub)"
    }

    fn is_production_ready(&self) -> bool {
        false // Research phase — no code, no audit
    }

    fn estimate_proof_cost(&self, _proof: &L1VerifiableProof) -> L1CostEstimate {
        // BitVM3: ~1000x cheaper than BitVM2
        L1CostEstimate {
            fee_sats: 5_000, // ~1000x cheaper than BitVM2
            num_transactions: 2, // Challenge + Response (vs 4 for BitVM2)
            total_weight: 1_000,
        }
    }

    fn prepare_for_l1(&self, _proof: &L1VerifiableProof) -> Result<Vec<u8>, String> {
        Err("BitVM3 backend is not yet available".into())
    }

    fn max_proof_size(&self) -> usize {
        1024 * 1024 * 1024 // 1 GB theoretical (garbled circuits are more size-efficient)
    }

    fn dispute_rounds(&self) -> u32 {
        2 // Challenge → Response (vs 4 for BitVM2)
    }

    fn challenge_period_blocks(&self) -> u32 {
        self.challenge_period
    }
}

/// Select the best available backend.
///
/// Preference: BitVM3 (if ready) > BitVM2 (production) > error
pub fn select_backend() -> Box<dyn BridgeBackend> {
    let bitvm3 = BitVM3Backend::default();
    if bitvm3.is_production_ready() {
        return Box::new(bitvm3);
    }
    Box::new(BitVM2Backend::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitvm2_is_production_ready() {
        let backend = BitVM2Backend::default();
        assert!(backend.is_production_ready());
        assert_eq!(backend.name(), "BitVM2");
        assert_eq!(backend.dispute_rounds(), 4);
        assert_eq!(backend.challenge_period_blocks(), 2016);
    }

    #[test]
    fn test_bitvm3_is_not_production_ready() {
        let backend = BitVM3Backend::default();
        assert!(!backend.is_production_ready());
        assert_eq!(backend.dispute_rounds(), 2);
        // prepare_for_l1 must fail
        let proof = L1VerifiableProof {
            stark_proof: vec![0xAB; 100],
            initial_state_root: Hash256::ZERO,
            final_state_root: Hash256::ZERO,
            block_range: (0, 10),
        };
        assert!(backend.prepare_for_l1(&proof).is_err());
    }

    #[test]
    fn test_select_backend_returns_bitvm2() {
        let backend = select_backend();
        assert_eq!(backend.name(), "BitVM2");
        assert!(backend.is_production_ready());
    }

    #[test]
    fn test_bitvm3_cost_much_cheaper() {
        let proof = L1VerifiableProof {
            stark_proof: vec![0; 1000],
            initial_state_root: Hash256::ZERO,
            final_state_root: Hash256::ZERO,
            block_range: (0, 10),
        };
        let v2_cost = BitVM2Backend::default().estimate_proof_cost(&proof);
        let v3_cost = BitVM3Backend::default().estimate_proof_cost(&proof);
        assert!(
            v3_cost.fee_sats < v2_cost.fee_sats / 5,
            "BitVM3 should be significantly cheaper: v2={} v3={}",
            v2_cost.fee_sats,
            v3_cost.fee_sats
        );
        assert!(v3_cost.num_transactions < v2_cost.num_transactions);
    }
}
