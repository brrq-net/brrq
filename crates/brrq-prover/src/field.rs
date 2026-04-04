//! Field arithmetic and polynomial operations for the STARK prover.
//!
//! ## BabyBear Field (p = 15 × 2^27 + 1 = 2013265921)
//!
//! BabyBear is a 31-bit prime field chosen specifically for STARK proving:
//! - **Two-adicity 27**: The multiplicative group supports power-of-2 subgroups
//!   up to 2^27 = 134,217,728 elements, enabling efficient NTT and FRI folding.
//! - **Same bit-width as M31**: Fits in u32, minimizing memory overhead.
//! - **Battle-tested**: Used by RISC Zero for RISC-V ZK proving.
//!
//! ## Why not M31?
//!
//! M31 (p = 2^31 - 1) has two-adicity of only 1 (p-1 = 2 × odd). This means
//! the largest power-of-2 multiplicative subgroup has just 2 elements — making
//! standard FRI folding mathematically impossible for any practical trace size.
//! BabyBear solves this while keeping the same 32-bit field element size.
//!
//! ## M31 Compatibility
//!
//! M31 is still re-exported for Poseidon2 hash (brrq-crypto). The STARK prover
//! uses BabyBear exclusively for polynomial operations, FRI, and AIR constraints.

pub use brrq_crypto::poseidon2::{M31, M31_P};

use serde::{Deserialize, Serialize};

// ══════════════════════════════════════════════════════════════════════
// BabyBear Prime Field
// ══════════════════════════════════════════════════════════════════════

/// BabyBear prime: p = 15 × 2^27 + 1 = 2,013,265,921.
pub const BABYBEAR_P: u32 = 2_013_265_921;

/// BabyBear prime as u64 for intermediate computations.
const P64: u64 = BABYBEAR_P as u64;

/// Primitive root of the full multiplicative group Z_p^*.
/// 31 generates the group of order p-1 = 2,013,265,920.
pub const GENERATOR: u32 = 31;

/// Two-adicity: largest k such that 2^k divides p-1.
/// p-1 = 15 × 2^27, so TWO_ADICITY = 27.
pub const TWO_ADICITY: u32 = 27;

// ══════════════════════════════════════════════════════════════════════
// AirField Trait — Generic arithmetic for AIR constraint evaluation.
//
// AIR constraints must evaluate over both the base field (Fp)
// during LDE composition and the extension field (Fp4) at the OOD point.
// This trait provides a uniform interface for both, eliminating code
// duplication while maintaining full type safety.
// ══════════════════════════════════════════════════════════════════════

/// Arithmetic operations required by AIR constraint evaluation.
///
/// Both `Fp` (base field, LDE path) and `Fp4` (extension field, OOD path)
/// implement this trait, allowing a single generic AIR implementation to
/// serve both the prover's LDE composition and the verifier's OOD check.
///
/// # Determinism
///
/// All implementations must be fully deterministic: identical inputs produce
/// identical outputs on every platform.
pub trait AirField: Copy + PartialEq + Eq + std::fmt::Debug + Default {
    /// Additive identity.
    const ZERO: Self;
    /// Multiplicative identity.
    const ONE: Self;

    /// Embed a u32 constant into the field. Used for opcode values, selector
    /// indices, and small integer constants in AIR constraints.
    fn from_u32(val: u32) -> Self;

    /// Field addition.
    fn add(self, rhs: Self) -> Self;
    /// Field subtraction.
    fn sub(self, rhs: Self) -> Self;
    /// Field multiplication.
    fn mul(self, rhs: Self) -> Self;
}

impl AirField for Fp {
    const ZERO: Self = Fp::ZERO;
    const ONE: Self = Fp::ONE;

    #[inline]
    fn from_u32(val: u32) -> Self {
        Fp::new(val)
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        self.add(rhs)
    }

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        self.sub(rhs)
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        self.mul(rhs)
    }
}

/// A field element in BabyBear (p = 2,013,265,921).
///
/// Invariant: `self.0` is always in `[0, p)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash, Serialize, Deserialize)]
pub struct Fp(pub u32);

impl Fp {
    pub const ZERO: Self = Self(0);
    pub const ONE: Self = Self(1);
    pub const TWO: Self = Self(2);
    pub const MODULUS: u32 = BABYBEAR_P;

    /// Create from u32, reducing mod p.
    #[inline]
    pub fn new(val: u32) -> Self {
        Self(val % BABYBEAR_P)
    }

    /// Create from u64, reducing mod p.
    #[inline]
    pub fn from_u64(val: u64) -> Self {
        Self((val % P64) as u32)
    }

    /// Raw value in [0, p).
    #[inline]
    pub fn value(self) -> u32 {
        self.0
    }

    /// Field addition: (a + b) mod p.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, rhs: Self) -> Self {
        let sum = self.0 as u64 + rhs.0 as u64;
        if sum >= P64 {
            Self((sum - P64) as u32)
        } else {
            Self(sum as u32)
        }
    }

    /// Field subtraction: (a - b) mod p.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, rhs: Self) -> Self {
        if self.0 >= rhs.0 {
            Self(self.0 - rhs.0)
        } else {
            Self(BABYBEAR_P - rhs.0 + self.0)
        }
    }

    /// Field multiplication: (a × b) mod p.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn mul(self, rhs: Self) -> Self {
        Self::from_u64(self.0 as u64 * rhs.0 as u64)
    }

    /// Additive inverse: -a mod p.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn neg(self) -> Self {
        if self.0 == 0 {
            Self::ZERO
        } else {
            Self(BABYBEAR_P - self.0)
        }
    }

    /// Modular exponentiation via square-and-multiply.
    pub fn pow(self, mut exp: u64) -> Self {
        let mut base = self;
        let mut result = Self::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        result
    }

    /// Multiplicative inverse via Fermat's little theorem: a^(-1) = a^(p-2).
    ///
    /// Returns `None` if `self` is zero (division by zero).
    /// Prefer this over [`inv`] in production code paths that handle adversarial input.
    #[inline]
    pub fn try_inv(self) -> Option<Self> {
        if self.0 == 0 {
            None
        } else {
            Some(self.pow(P64 - 2))
        }
    }

    /// Multiplicative inverse via Fermat's little theorem: a^(-1) = a^(p-2).
    ///
    /// # Panics
    /// Panics if `self` is zero. Use [`try_inv`] for adversarial inputs.
    pub fn inv(self) -> Self {
        assert!(self.0 != 0, "BabyBear: division by zero");
        self.pow(P64 - 2)
    }

    /// Get the primitive 2^k-th root of unity in BabyBear (fallible).
    ///
    /// Returns `Err` if k > TWO_ADICITY (27).
    /// Prefer this over [`root_of_unity`] in production code paths.
    pub fn try_root_of_unity(k: u32) -> Result<Self, &'static str> {
        if k > TWO_ADICITY {
            return Err("BabyBear: k exceeds TWO_ADICITY (27)");
        }
        let exp = (P64 - 1) / (1u64 << k);
        Ok(Self::new(GENERATOR).pow(exp))
    }

    /// Get the primitive 2^k-th root of unity in BabyBear.
    ///
    /// ω_k = g^((p-1)/2^k) where g = 31 is the multiplicative generator.
    ///
    /// # Panics
    /// Panics if k > TWO_ADICITY (27). Use [`try_root_of_unity`] for adversarial inputs.
    pub fn root_of_unity(k: u32) -> Self {
        assert!(
            k <= TWO_ADICITY,
            "BabyBear: max two-adicity is {TWO_ADICITY}, got {k}"
        );
        let exp = (P64 - 1) / (1u64 << k);
        Self::new(GENERATOR).pow(exp)
    }
}

impl std::ops::Add for Fp {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Fp::add(self, rhs)
    }
}

impl std::ops::Sub for Fp {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Fp::sub(self, rhs)
    }
}

impl std::ops::Mul for Fp {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Fp::mul(self, rhs)
    }
}

impl std::ops::Neg for Fp {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Fp::neg(self)
    }
}

impl std::fmt::Display for Fp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ══════════════════════════════════════════════════════════════════════
// Multiplicative Domain
// ══════════════════════════════════════════════════════════════════════

/// A multiplicative domain {1, ω, ω², ..., ω^(n-1)} for polynomial evaluation.
///
/// The domain size is always a power of 2 (required for NTT and FRI).
#[derive(Clone, Debug)]
pub struct Domain {
    /// Primitive n-th root of unity (domain generator).
    pub generator: Fp,
    /// Domain size (always 2^log_size).
    pub size: usize,
    /// log₂(size).
    pub log_size: u32,
}

impl Domain {
    /// Create a domain of size 2^log_size (fallible).
    ///
    /// Returns `Err` if log_size > TWO_ADICITY (27).
    /// Prefer this over [`new`] in production code paths.
    pub fn try_new(log_size: u32) -> Result<Self, &'static str> {
        let generator = Fp::try_root_of_unity(log_size)?;
        let size = 1usize << log_size;
        Ok(Self {
            generator,
            size,
            log_size,
        })
    }

    /// Create a domain of size 2^log_size.
    ///
    /// # Panics
    /// Panics if log_size > TWO_ADICITY (27). Use [`try_new`] for adversarial inputs.
    pub fn new(log_size: u32) -> Self {
        let size = 1usize << log_size;
        let generator = Fp::root_of_unity(log_size);
        Self {
            generator,
            size,
            log_size,
        }
    }

    /// Create a shifted (coset) domain: {h, h·ω, h·ω², ..., h·ω^(n-1)}.
    /// Used for LDE domains that don't overlap with the trace domain.
    pub fn coset(&self, offset: Fp) -> Vec<Fp> {
        let mut points = Vec::with_capacity(self.size);
        let mut x = offset;
        for _ in 0..self.size {
            points.push(x);
            x = x.mul(self.generator);
        }
        points
    }

    /// Evaluate the vanishing polynomial Z_H(x) = x^n - 1.
    ///
    /// Z_H(ω^i) = 0 for all i in [0, n). This is the key algebraic property
    /// that links the domain to the constraint system.
    #[inline]
    pub fn vanishing_eval(&self, x: Fp) -> Fp {
        x.pow(self.size as u64).sub(Fp::ONE)
    }

    /// Evaluate the transition zerofier: Z_H(x) / (x - ω^(n-1)).
    ///
    /// This vanishes on all domain points EXCEPT the last one.
    /// Used for transition constraints that relate consecutive rows.
    ///
    /// Returns `None` if x = ω^(n-1) (division by zero).
    pub fn transition_zerofier_eval(&self, x: Fp) -> Option<Fp> {
        let last_point = self.generator.pow(self.size as u64 - 1);
        let denom = x.sub(last_point);
        if denom == Fp::ZERO {
            return None;
        }
        let z_h = self.vanishing_eval(x);
        Some(z_h.mul(denom.inv()))
    }

    /// Evaluate the boundary zerofier for the first row: Z_H(x) / (x - 1).
    ///
    /// This vanishes on all domain points EXCEPT x = 1 (the first row).
    ///
    /// Returns `None` if x = 1.
    pub fn boundary_zerofier_eval_first(&self, x: Fp) -> Option<Fp> {
        let denom = x.sub(Fp::ONE);
        if denom == Fp::ZERO {
            return None;
        }
        let z_h = self.vanishing_eval(x);
        Some(z_h.mul(denom.inv()))
    }
}

// ══════════════════════════════════════════════════════════════════════
// NTT — Number Theoretic Transform (FFT over finite fields)
// ══════════════════════════════════════════════════════════════════════

/// Bit-reverse an index within a log_n-bit number.
fn bit_reverse(mut x: usize, log_n: u32) -> usize {
    let mut result = 0;
    for _ in 0..log_n {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// In-place bit-reversal permutation.
fn bit_reverse_permutation(values: &mut [Fp], log_n: u32) {
    let n = values.len();
    for i in 0..n {
        let j = bit_reverse(i, log_n);
        if i < j {
            values.swap(i, j);
        }
    }
}

/// Fallible NTT — returns `Err` if length is not a power of 2.
///
/// Prefer this over [`ntt`] in production code paths that handle adversarial input.
pub fn try_ntt(values: &mut [Fp], omega: Fp) -> Result<(), &'static str> {
    let n = values.len();
    if n == 0 || !n.is_power_of_two() {
        return Err("NTT: length must be a non-zero power of 2");
    }
    ntt(values, omega);
    Ok(())
}

/// Number Theoretic Transform (Cooley-Tukey, Decimation-in-Time).
///
/// Transforms polynomial coefficients [a₀, a₁, ..., a_{n-1}] into
/// evaluations [P(1), P(ω), P(ω²), ..., P(ω^{n-1})] in natural order.
///
/// # Panics
/// Panics if `values.len()` is not a power of 2. Use [`try_ntt`] for adversarial inputs.
pub fn ntt(values: &mut [Fp], omega: Fp) {
    let n = values.len();
    assert!(n.is_power_of_two(), "NTT: length must be power of 2");
    if n <= 1 {
        return;
    }

    let log_n = n.trailing_zeros();
    bit_reverse_permutation(values, log_n);

    let mut len = 2;
    while len <= n {
        let half = len / 2;
        // Twiddle factor step: ω^(n/len) is the primitive len-th root of unity.
        let w = omega.pow((n / len) as u64);

        for start in (0..n).step_by(len) {
            let mut twiddle = Fp::ONE;
            for j in 0..half {
                let u = values[start + j];
                let v = values[start + j + half].mul(twiddle);
                values[start + j] = u.add(v);
                values[start + j + half] = u.sub(v);
                twiddle = twiddle.mul(w);
            }
        }
        len *= 2;
    }
}

/// Inverse NTT: evaluations → coefficients.
///
/// Transforms evaluations [P(1), P(ω), ..., P(ω^{n-1})] back to
/// polynomial coefficients [a₀, a₁, ..., a_{n-1}].
pub fn intt(values: &mut [Fp], omega: Fp) {
    let n = values.len();
    if n <= 1 {
        return;
    }
    // INTT = NTT with inverse root, then divide by n.
    let omega_inv = omega.inv();
    ntt(values, omega_inv);
    let n_inv = Fp::new(n as u32).inv();
    for v in values.iter_mut() {
        *v = v.mul(n_inv);
    }
}

// ── GPU-accelerated NTT dispatch ────────────────────────────────────

/// NTT dispatched through the GPU backend (if available).
///
/// Falls back to CPU NTT when no GPU is present. All prover hot paths
/// should prefer this over [`ntt`] directly.
pub fn gpu_ntt(values: &mut [Fp], omega: Fp) {
    crate::gpu::backend().ntt(values, omega);
}

/// Inverse NTT dispatched through the GPU backend (if available).
pub fn gpu_intt(values: &mut [Fp], omega: Fp) {
    crate::gpu::backend().intt(values, omega);
}

// ══════════════════════════════════════════════════════════════════════
// Polynomial Operations
// ══════════════════════════════════════════════════════════════════════

/// Evaluate polynomial at a single point using Horner's method.
///
/// P(x) = coeffs[0] + coeffs[1]·x + coeffs[2]·x² + ...
pub fn poly_eval(coeffs: &[Fp], x: Fp) -> Fp {
    let mut result = Fp::ZERO;
    for &c in coeffs.iter().rev() {
        result = result.mul(x).add(c);
    }
    result
}

/// Evaluate polynomial at all points in a domain using NTT.
///
/// Given coefficients, returns evaluations at {1, ω, ω², ..., ω^(n-1)}.
/// Pads with zeros if coefficients are shorter than domain size.
pub fn poly_eval_domain(coeffs: &[Fp], domain: &Domain) -> Vec<Fp> {
    let mut padded = vec![Fp::ZERO; domain.size];
    let copy_len = coeffs.len().min(domain.size);
    padded[..copy_len].copy_from_slice(&coeffs[..copy_len]);
    ntt(&mut padded, domain.generator);
    padded
}

/// Interpolate polynomial from evaluations on a domain using INTT.
///
/// Given evaluations at {1, ω, ω², ..., ω^(n-1)}, returns coefficients.
pub fn poly_interpolate(evals: &[Fp], domain: &Domain) -> Vec<Fp> {
    assert_eq!(
        evals.len(),
        domain.size,
        "evaluations must match domain size"
    );
    let mut coeffs = evals.to_vec();
    gpu_intt(&mut coeffs, domain.generator);
    coeffs
}

/// Evaluate polynomial on a coset domain: {h, h·ω, h·ω², ..., h·ω^(n-1)}.
///
/// Uses the shift property: P(h·ω^i) = NTT of [a₀, a₁·h, a₂·h², ...].
pub fn poly_eval_coset(coeffs: &[Fp], domain: &Domain, offset: Fp) -> Vec<Fp> {
    let mut shifted = vec![Fp::ZERO; domain.size];
    let mut h_power = Fp::ONE;
    for (i, shifted_val) in shifted.iter_mut().enumerate() {
        if i < coeffs.len() {
            *shifted_val = coeffs[i].mul(h_power);
        }
        h_power = h_power.mul(offset);
    }
    gpu_ntt(&mut shifted, domain.generator);
    shifted
}

/// Polynomial addition: result[i] = a[i] + b[i].
pub fn poly_add(a: &[Fp], b: &[Fp]) -> Vec<Fp> {
    let len = a.len().max(b.len());
    let mut result = vec![Fp::ZERO; len];
    for (i, val) in result.iter_mut().enumerate() {
        let av = if i < a.len() { a[i] } else { Fp::ZERO };
        let bv = if i < b.len() { b[i] } else { Fp::ZERO };
        *val = av.add(bv);
    }
    result
}

/// Polynomial subtraction: result[i] = a[i] - b[i].
pub fn poly_sub(a: &[Fp], b: &[Fp]) -> Vec<Fp> {
    let len = a.len().max(b.len());
    let mut result = vec![Fp::ZERO; len];
    for (i, val) in result.iter_mut().enumerate() {
        let av = if i < a.len() { a[i] } else { Fp::ZERO };
        let bv = if i < b.len() { b[i] } else { Fp::ZERO };
        *val = av.sub(bv);
    }
    result
}

/// Scale a polynomial by a scalar: result[i] = s · p[i].
pub fn poly_scale(p: &[Fp], s: Fp) -> Vec<Fp> {
    p.iter().map(|&c| c.mul(s)).collect()
}

/// Polynomial multiplication via NTT (O(n log n)).
///
/// Computes a(x) · b(x) using:
/// 1. Pad to 2^k ≥ deg(a) + deg(b) + 1
/// 2. NTT both
/// 3. Pointwise multiply
/// 4. INTT result
pub fn poly_mul(a: &[Fp], b: &[Fp]) -> Vec<Fp> {
    if a.is_empty() || b.is_empty() {
        return vec![];
    }
    let result_len = a.len() + b.len() - 1;
    let padded_len = result_len.next_power_of_two();
    let log_n = padded_len.trailing_zeros();
    let omega = Fp::root_of_unity(log_n);

    let mut a_padded = vec![Fp::ZERO; padded_len];
    let mut b_padded = vec![Fp::ZERO; padded_len];
    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);

    ntt(&mut a_padded, omega);
    ntt(&mut b_padded, omega);

    let mut result = vec![Fp::ZERO; padded_len];
    for i in 0..padded_len {
        result[i] = a_padded[i].mul(b_padded[i]);
    }

    intt(&mut result, omega);
    result.truncate(result_len);
    result
}

// ══════════════════════════════════════════════════════════════════════
// Legacy M31 compatibility (used by Poseidon2 and old interfaces)
// ══════════════════════════════════════════════════════════════════════

/// Find a subgroup generator for M31 (legacy, for backward compatibility).
pub fn find_subgroup_generator(domain_size: usize) -> M31 {
    let g = M31::new(3);
    let exp = (M31_P - 1) / domain_size as u32;
    g.pow(exp)
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── BabyBear arithmetic ──

    #[test]
    fn test_fp_basic_arithmetic() {
        let a = Fp::new(100);
        let b = Fp::new(200);
        assert_eq!(a.add(b).value(), 300);
        assert_eq!(b.sub(a).value(), 100);
        assert_eq!(a.mul(b).value(), 20_000);
    }

    #[test]
    fn test_fp_modular_reduction() {
        let a = Fp::new(BABYBEAR_P - 1);
        let b = Fp::new(2);
        // (p-1) + 2 = p+1 ≡ 1 (mod p)
        assert_eq!(a.add(b).value(), 1);
    }

    #[test]
    fn test_fp_subtraction_underflow() {
        let a = Fp::new(5);
        let b = Fp::new(10);
        // 5 - 10 ≡ p - 5 (mod p)
        assert_eq!(a.sub(b).value(), BABYBEAR_P - 5);
    }

    #[test]
    fn test_fp_negation() {
        let a = Fp::new(42);
        let neg_a = a.neg();
        assert_eq!(a.add(neg_a).value(), 0);
        assert_eq!(Fp::ZERO.neg().value(), 0);
    }

    #[test]
    fn test_fp_multiplication_overflow() {
        // Ensure u64 intermediate handles large values.
        let a = Fp::new(BABYBEAR_P - 1);
        let b = Fp::new(BABYBEAR_P - 1);
        // (p-1)^2 mod p = 1
        assert_eq!(a.mul(b).value(), 1);
    }

    #[test]
    fn test_fp_inverse() {
        let a = Fp::new(7);
        let a_inv = a.inv();
        assert_eq!(a.mul(a_inv).value(), 1);
    }

    #[test]
    fn test_fp_inverse_large() {
        let a = Fp::new(BABYBEAR_P - 1); // = -1
        let a_inv = a.inv();
        assert_eq!(a.mul(a_inv).value(), 1);
        // -1 * -1 = 1, so inv(-1) = -1
        assert_eq!(a_inv.value(), BABYBEAR_P - 1);
    }

    #[test]
    fn test_fp_pow() {
        let a = Fp::new(3);
        assert_eq!(a.pow(0).value(), 1);
        assert_eq!(a.pow(1).value(), 3);
        assert_eq!(a.pow(2).value(), 9);
        assert_eq!(a.pow(10).value(), 59049);
    }

    #[test]
    fn test_fp_fermats_little_theorem() {
        // a^(p-1) = 1 for any nonzero a.
        let a = Fp::new(42);
        assert_eq!(a.pow(P64 - 1).value(), 1);
    }

    // ── Root of unity ──

    #[test]
    fn test_root_of_unity_order() {
        for k in 1..=10 {
            let omega = Fp::root_of_unity(k);
            let n = 1u64 << k;
            // ω^n = 1
            assert_eq!(omega.pow(n).value(), 1, "ω^(2^{k}) should be 1");
            // ω^(n/2) ≠ 1 (primitive root)
            assert_ne!(omega.pow(n / 2).value(), 1, "ω^(2^{k}/2) should NOT be 1");
        }
    }

    #[test]
    fn test_root_of_unity_generates_domain() {
        let k = 3; // Domain of size 8.
        let omega = Fp::root_of_unity(k);
        let n = 1u64 << k;
        let mut seen = std::collections::HashSet::new();
        let mut x = Fp::ONE;
        for _ in 0..n {
            assert!(seen.insert(x.value()), "duplicate domain element");
            x = x.mul(omega);
        }
        assert_eq!(x.value(), 1, "should return to 1 after n steps");
    }

    // ── Domain ──

    #[test]
    fn test_domain_vanishing() {
        let domain = Domain::new(3); // size 8
        let omega = domain.generator;
        // Z_H(ω^i) = 0 for all i in [0, 8).
        let mut x = Fp::ONE;
        for i in 0..domain.size {
            assert_eq!(
                domain.vanishing_eval(x).value(),
                0,
                "Z_H should vanish at ω^{i}"
            );
            x = x.mul(omega);
        }
        // Z_H at a random point should NOT be zero.
        let random_point = Fp::new(42);
        assert_ne!(domain.vanishing_eval(random_point).value(), 0);
    }

    // ── NTT / INTT ──

    #[test]
    fn test_ntt_intt_roundtrip() {
        let log_n = 3u32;
        let n = 1usize << log_n;
        let omega = Fp::root_of_unity(log_n);

        let original: Vec<Fp> = (1..=n as u32).map(Fp::new).collect();
        let mut values = original.clone();

        ntt(&mut values, omega);
        // After NTT, values should be different (unless trivial).
        assert_ne!(values, original, "NTT should change values");

        intt(&mut values, omega);
        // After INTT, should recover original.
        assert_eq!(values, original, "INTT should recover original");
    }

    #[test]
    fn test_ntt_matches_naive_eval() {
        let log_n = 3u32;
        let n = 1usize << log_n;
        let omega = Fp::root_of_unity(log_n);

        let coeffs: Vec<Fp> = (1..=n as u32).map(Fp::new).collect();
        let mut ntt_result = coeffs.clone();
        ntt(&mut ntt_result, omega);

        // Compare with Horner evaluation at each domain point.
        let mut x = Fp::ONE;
        for i in 0..n {
            let expected = poly_eval(&coeffs, x);
            assert_eq!(
                ntt_result[i].value(),
                expected.value(),
                "NTT mismatch at index {i}: x = {x}"
            );
            x = x.mul(omega);
        }
    }

    #[test]
    fn test_ntt_size_1() {
        let mut values = vec![Fp::new(42)];
        ntt(&mut values, Fp::ONE);
        assert_eq!(values[0].value(), 42);
    }

    #[test]
    fn test_ntt_size_2() {
        let omega = Fp::root_of_unity(1); // ω² = 1, ω ≠ 1 → ω = p-1 = -1
        let mut values = vec![Fp::new(3), Fp::new(5)];
        ntt(&mut values, omega);
        // P(x) = 3 + 5x
        // P(1) = 8, P(-1) = 3 - 5 = p - 2
        assert_eq!(values[0].value(), 8);
        assert_eq!(values[1].value(), BABYBEAR_P - 2);
    }

    // ── Polynomial operations ──

    #[test]
    fn test_poly_eval_horner() {
        // P(x) = 1 + 2x + 3x²
        let coeffs = vec![Fp::new(1), Fp::new(2), Fp::new(3)];
        // P(10) = 1 + 20 + 300 = 321
        assert_eq!(poly_eval(&coeffs, Fp::new(10)).value(), 321);
    }

    #[test]
    fn test_poly_eval_domain_matches_ntt() {
        let domain = Domain::new(3);
        let coeffs: Vec<Fp> = (1..=5).map(|i| Fp::new(i)).collect();

        let evals = poly_eval_domain(&coeffs, &domain);

        // Verify against Horner at each point.
        let mut x = Fp::ONE;
        for (i, &eval) in evals.iter().enumerate() {
            let expected = poly_eval(&coeffs, x);
            assert_eq!(eval.value(), expected.value(), "mismatch at index {i}");
            x = x.mul(domain.generator);
        }
    }

    #[test]
    fn test_poly_interpolate_roundtrip() {
        let domain = Domain::new(3);
        let original: Vec<Fp> = vec![
            Fp::new(5),
            Fp::new(3),
            Fp::new(7),
            Fp::new(1),
            Fp::new(9),
            Fp::new(2),
            Fp::new(4),
            Fp::new(6),
        ];

        // Evaluate on domain.
        let evals = poly_eval_domain(&original, &domain);
        // Interpolate back.
        let recovered = poly_interpolate(&evals, &domain);

        // The recovered coefficients should be the original (padded to domain size).
        for (i, &coeff) in original.iter().enumerate() {
            assert_eq!(
                recovered[i].value(),
                coeff.value(),
                "coefficient mismatch at index {i}"
            );
        }
    }

    #[test]
    fn test_poly_eval_coset() {
        let domain = Domain::new(2); // size 4
        let coeffs = vec![Fp::new(1), Fp::new(2), Fp::new(3)];
        let offset = Fp::new(7);

        let coset_evals = poly_eval_coset(&coeffs, &domain, offset);

        // Verify against Horner at each coset point.
        let omega = domain.generator;
        let mut x = offset;
        for (i, &eval) in coset_evals.iter().enumerate() {
            let expected = poly_eval(&coeffs, x);
            assert_eq!(
                eval.value(),
                expected.value(),
                "coset mismatch at index {i}"
            );
            x = x.mul(omega);
        }
    }

    #[test]
    fn test_poly_mul() {
        // (1 + 2x) × (3 + 4x) = 3 + 10x + 8x²
        let a = vec![Fp::new(1), Fp::new(2)];
        let b = vec![Fp::new(3), Fp::new(4)];
        let result = poly_mul(&a, &b);

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].value(), 3);
        assert_eq!(result[1].value(), 10);
        assert_eq!(result[2].value(), 8);
    }

    #[test]
    fn test_poly_add_sub() {
        let a = vec![Fp::new(1), Fp::new(2), Fp::new(3)];
        let b = vec![Fp::new(10), Fp::new(20)];

        let sum = poly_add(&a, &b);
        assert_eq!(sum[0].value(), 11);
        assert_eq!(sum[1].value(), 22);
        assert_eq!(sum[2].value(), 3);

        let diff = poly_sub(&a, &b);
        assert_eq!(diff[0].value(), BABYBEAR_P - 9);
        assert_eq!(diff[1].value(), BABYBEAR_P - 18);
        assert_eq!(diff[2].value(), 3);
    }

    // ── Fallible APIs (WI-1A: adversarial hardening) ──

    #[test]
    fn test_try_inv_zero_returns_none() {
        assert!(Fp::ZERO.try_inv().is_none());
    }

    #[test]
    fn test_try_inv_nonzero_returns_some() {
        let a = Fp::new(7);
        let a_inv = a.try_inv().unwrap();
        assert_eq!(a.mul(a_inv).value(), 1);
    }

    #[test]
    fn test_try_root_of_unity_valid() {
        for k in 0..=TWO_ADICITY {
            assert!(Fp::try_root_of_unity(k).is_ok());
        }
    }

    #[test]
    fn test_try_root_of_unity_exceeds_two_adicity() {
        assert!(Fp::try_root_of_unity(TWO_ADICITY + 1).is_err());
        assert!(Fp::try_root_of_unity(28).is_err());
        assert!(Fp::try_root_of_unity(u32::MAX).is_err());
    }

    #[test]
    fn test_try_ntt_power_of_two() {
        let omega = Fp::root_of_unity(3);
        let mut values: Vec<Fp> = (1..=8).map(Fp::new).collect();
        assert!(try_ntt(&mut values, omega).is_ok());
    }

    #[test]
    fn test_try_ntt_non_power_of_two() {
        let mut values = vec![Fp::new(1), Fp::new(2), Fp::new(3)]; // len=3
        assert!(try_ntt(&mut values, Fp::ONE).is_err());
    }

    #[test]
    fn test_try_ntt_empty() {
        let mut values: Vec<Fp> = vec![];
        assert!(try_ntt(&mut values, Fp::ONE).is_err());
    }

    #[test]
    fn test_domain_try_new_valid() {
        for k in 0..=20 {
            assert!(Domain::try_new(k).is_ok());
        }
    }

    #[test]
    fn test_domain_try_new_exceeds_adicity() {
        assert!(Domain::try_new(28).is_err());
    }

    // ── Legacy M31 ──

    #[test]
    fn test_find_subgroup_generator_m31() {
        let domain_size = 2usize;
        let g = find_subgroup_generator(domain_size);
        let result = g.pow(domain_size as u32);
        assert_eq!(result.0, 1, "Generator^domain_size should be 1");
    }
}
