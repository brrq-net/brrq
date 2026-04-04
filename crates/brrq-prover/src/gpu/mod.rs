//! GPU acceleration for STARK proving operations.
//!
//! This module provides optional GPU acceleration for the prover's
//! most compute-intensive operations:
//!
//! 1. **NTT (Number Theoretic Transform)** — the dominant cost in STARK
//!    proof generation. On CPU, NTT takes ~60-70% of total prove time.
//!    GPU NTT provides 10-50x speedup depending on polynomial degree.
//!
//! 2. **Merkle tree hashing** — bulk SHA-256/Poseidon2 hashing of evaluation
//!    leaves. Embarrassingly parallel, but memory-bandwidth limited on CPU.
//!
//! 3. **FRI folding** — independent per-element operations across the
//!    evaluation domain. Maps naturally to GPU SIMT execution.
//!
//! ## Architecture
//!
//! GPU acceleration is trait-based via [`GpuBackend`]. Implementations:
//! - **CPU fallback** (`CpuBackend`): Always available, uses rayon.
//! - **CUDA** (`CudaBackend`): Behind `gpu-cuda` feature, requires NVIDIA GPU.
//!
//! The active backend is selected at startup via [`select_backend()`] and
//! stored in a global. All prover hot paths call through the backend trait.
//!
//! ## Feature flags
//!
//! - `gpu-cuda`: Enables CUDA backend via `cudarc` crate. Requires CUDA
//!   toolkit installed and NVIDIA GPU at runtime.

#[cfg(feature = "gpu-cuda")]
pub mod cuda_ntt;

use crate::field::Fp;
use std::sync::OnceLock;

/// GPU backend trait for accelerated STARK operations.
///
/// All methods have CPU fallback implementations. GPU backends override
/// only the operations they can accelerate.
pub trait GpuBackend: Send + Sync {
    /// Backend name for logging/diagnostics.
    fn name(&self) -> &str;

    /// Whether this backend is using actual GPU hardware.
    fn is_gpu(&self) -> bool;

    /// GPU NTT: in-place forward transform.
    ///
    /// Default: delegates to CPU NTT (`field::ntt`).
    fn ntt(&self, values: &mut [Fp], omega: Fp) {
        crate::field::ntt(values, omega);
    }

    /// GPU inverse NTT: in-place inverse transform.
    ///
    /// Default: delegates to CPU INTT (`field::intt`).
    fn intt(&self, values: &mut [Fp], omega: Fp) {
        crate::field::intt(values, omega);
    }

    /// Batch NTT: transform multiple polynomials in parallel.
    ///
    /// Default: sequential NTT on each polynomial.
    fn batch_ntt(&self, polys: &mut [Vec<Fp>], omega: Fp) {
        for poly in polys.iter_mut() {
            self.ntt(poly, omega);
        }
    }

    /// Bulk hash field elements into Merkle leaves (SHA-256).
    ///
    /// Default: delegates to rayon parallel map.
    fn hash_evaluations(&self, evals: &[Fp]) -> Vec<brrq_crypto::hash::Hash256> {
        use brrq_crypto::hash::Hasher;
        use rayon::prelude::*;
        evals
            .par_iter()
            .map(|e| Hasher::hash(&e.value().to_le_bytes()))
            .collect()
    }

    /// FRI fold: compute one folding round.
    ///
    /// Default: delegates to CPU implementation.
    fn fri_fold(
        &self,
        evals: &[Fp],
        alpha: Fp,
        domain_gen: Fp,
    ) -> Result<Vec<Fp>, crate::error::ProverError> {
        crate::fri::fri_fold(evals, alpha, domain_gen)
    }
}

/// CPU-only backend using rayon for parallelism.
pub struct CpuBackend;

impl GpuBackend for CpuBackend {
    fn name(&self) -> &str {
        "CPU (rayon)"
    }

    fn is_gpu(&self) -> bool {
        false
    }

    // All default implementations use the existing CPU code paths.
    // No overrides needed — the trait defaults already call into
    // field::ntt, field::intt, etc.
}

/// Global GPU backend instance.
static BACKEND: OnceLock<Box<dyn GpuBackend>> = OnceLock::new();

/// Select and initialize the GPU backend.
///
/// Tries GPU backends in order of preference, falling back to CPU.
/// This should be called once at prover initialization.
pub fn select_backend() -> &'static dyn GpuBackend {
    BACKEND
        .get_or_init(|| {
            // Try CUDA first if feature-enabled.
            #[cfg(feature = "gpu-cuda")]
            {
                match cuda_ntt::CudaBackend::try_init() {
                    Ok(backend) => {
                        tracing::info!(
                            "GPU acceleration: CUDA backend initialized ({})",
                            backend.device_name()
                        );
                        return Box::new(backend);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "CUDA backend failed to initialize: {}. Falling back to CPU.",
                            e
                        );
                    }
                }
            }

            tracing::info!("GPU acceleration: using CPU backend (rayon)");
            Box::new(CpuBackend)
        })
        .as_ref()
}

/// Get the active GPU backend (initializes on first call).
#[inline]
pub fn backend() -> &'static dyn GpuBackend {
    select_backend()
}
