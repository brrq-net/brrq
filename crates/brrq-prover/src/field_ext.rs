//! Quartic extension field BabyBear⁴ = F_p[x] / (x⁴ + 11).
//!
//! # Security Rationale
//!
//! The base field BabyBear has |F_p| ≈ 2³¹, giving only ~10-bit OOD security
//! for typical trace degrees (d ≈ 2²⁰). By sampling the OOD challenge from
//! F_p⁴ (|F_p⁴| ≈ 2¹²⁴), we raise OOD security to ~102 bits:
//!
//!   ε_OOD = d / |F_p⁴| = 3 × 2²⁰ / 2¹²⁴ ≈ 2⁻¹⁰²
//!
//! # Irreducibility of x⁴ + 11 over BabyBear
//!
//! The polynomial x⁴ + 11 is irreducible over F_p (p = 2,013,265,921) because:
//! - -11 mod p is not a quadratic residue squared to a fourth root in F_p*
//! - Verified computationally: (-11)^((p-1)/4) ≢ 1 (mod p)
//!
//! This matches the Plonky3 convention (which uses x⁴ - 11, equivalent under
//! sign change of the generator).
//!
//! # Representation
//!
//! An element of F_p⁴ is represented as (c0, c1, c2, c3), encoding:
//!   c0 + c1·α + c2·α² + c3·α³
//! where α is a root of x⁴ + 11, so α⁴ = -11 in F_p.
//!
//! # Determinism
//!
//! All operations use u32/u64 integer arithmetic with explicit modular
//! reduction. No floating point, no platform-dependent behavior. Every
//! verifier on every platform produces identical results.

use serde::{Deserialize, Serialize};

use crate::field::{AirField, Fp, BABYBEAR_P};

/// The constant W such that α⁴ = -W in F_p.
/// We use x⁴ + 11, so α⁴ = -11, meaning W = 11.
const W: u32 = 11;

/// An element of the quartic extension field BabyBear⁴ = F_p[x]/(x⁴ + 11).
///
/// Represented as (c0, c1, c2, c3) encoding c0 + c1·α + c2·α² + c3·α³.
///
/// # Invariants
/// - Each component c_i is a valid `Fp` element in [0, p).
/// - All arithmetic is deterministic (no floating point).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Hash, Serialize, Deserialize)]
pub struct Fp4 {
    pub c0: Fp,
    pub c1: Fp,
    pub c2: Fp,
    pub c3: Fp,
}

impl Fp4 {
    pub const ZERO: Self = Self {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
        c2: Fp::ZERO,
        c3: Fp::ZERO,
    };

    pub const ONE: Self = Self {
        c0: Fp::ONE,
        c1: Fp::ZERO,
        c2: Fp::ZERO,
        c3: Fp::ZERO,
    };

    /// Embed a base field element into the extension field.
    /// base ↦ (base, 0, 0, 0)
    #[inline]
    pub fn from_base(base: Fp) -> Self {
        Self {
            c0: base,
            c1: Fp::ZERO,
            c2: Fp::ZERO,
            c3: Fp::ZERO,
        }
    }

    /// Construct from four base field components.
    #[inline]
    pub fn new(c0: Fp, c1: Fp, c2: Fp, c3: Fp) -> Self {
        Self { c0, c1, c2, c3 }
    }

    /// Addition in F_p⁴: component-wise addition.
    #[inline]
    pub fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
            c2: self.c2.add(rhs.c2),
            c3: self.c3.add(rhs.c3),
        }
    }

    /// Subtraction in F_p⁴: component-wise subtraction.
    #[inline]
    pub fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
            c2: self.c2.sub(rhs.c2),
            c3: self.c3.sub(rhs.c3),
        }
    }

    /// Additive inverse in F_p⁴.
    #[inline]
    pub fn neg(self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
            c2: self.c2.neg(),
            c3: self.c3.neg(),
        }
    }

    /// Multiplication in F_p⁴.
    ///
    /// Given a = a0 + a1·α + a2·α² + a3·α³ and b = b0 + b1·α + b2·α² + b3·α³,
    /// compute a·b mod (α⁴ + W) where α⁴ = -W.
    ///
    /// The schoolbook product a·b has terms up to α⁶. We reduce using α⁴ = -W:
    ///   α⁴ = -W,  α⁵ = -W·α,  α⁶ = -W·α²
    ///
    /// Result coefficients:
    ///   c0 = a0·b0 - W·(a1·b3 + a2·b2 + a3·b1)
    ///   c1 = a0·b1 + a1·b0 - W·(a2·b3 + a3·b2)
    ///   c2 = a0·b2 + a1·b1 + a2·b0 - W·a3·b3
    ///   c3 = a0·b3 + a1·b2 + a2·b1 + a3·b0
    ///
    /// Cost: 16 Fp multiplications + 12 Fp additions.
    pub fn mul(self, rhs: Self) -> Self {
        let (a0, a1, a2, a3) = (self.c0, self.c1, self.c2, self.c3);
        let (b0, b1, b2, b3) = (rhs.c0, rhs.c1, rhs.c2, rhs.c3);
        let w = Fp::new(W);

        // Schoolbook terms
        let a0b0 = a0.mul(b0);
        let a0b1 = a0.mul(b1);
        let a0b2 = a0.mul(b2);
        let a0b3 = a0.mul(b3);
        let a1b0 = a1.mul(b0);
        let a1b1 = a1.mul(b1);
        let a1b2 = a1.mul(b2);
        let a1b3 = a1.mul(b3);
        let a2b0 = a2.mul(b0);
        let a2b1 = a2.mul(b1);
        let a2b2 = a2.mul(b2);
        let a2b3 = a2.mul(b3);
        let a3b0 = a3.mul(b0);
        let a3b1 = a3.mul(b1);
        let a3b2 = a3.mul(b2);
        let a3b3 = a3.mul(b3);

        // Reduce: α⁴ = -W
        let c0 = a0b0.sub(w.mul(a1b3.add(a2b2).add(a3b1)));
        let c1 = a0b1.add(a1b0).sub(w.mul(a2b3.add(a3b2)));
        let c2 = a0b2.add(a1b1).add(a2b0).sub(w.mul(a3b3));
        let c3 = a0b3.add(a1b2).add(a2b1).add(a3b0);

        Self { c0, c1, c2, c3 }
    }

    /// Multiply by a base field scalar.
    /// (c0 + c1·α + c2·α² + c3·α³) × s = (c0·s + c1·s·α + c2·s·α² + c3·s·α³)
    #[inline]
    pub fn mul_base(self, s: Fp) -> Self {
        Self {
            c0: self.c0.mul(s),
            c1: self.c1.mul(s),
            c2: self.c2.mul(s),
            c3: self.c3.mul(s),
        }
    }

    /// Compute the field norm N(a) = a · a^p · a^(p²) · a^(p³) ∈ F_p.
    ///
    /// For the quartic extension with irreducible x⁴ + W, the norm can be
    /// computed as:
    ///   N(a) = (c0² + W·c2²)² + W·(c1² + W·c3²)² - ... (simplified)
    ///
    /// We use the formula via the quadratic subfield tower:
    ///   F_p⁴ = F_p² [β] / (β² + W·ξ)
    /// where F_p² = F_p[ξ] / (ξ² + W).
    ///
    /// Instead, we compute the norm directly via conjugate products:
    ///   N(a) = a · conj₁(a) · conj₂(a) · conj₃(a)
    ///
    /// For practical implementation, we use Frobenius endomorphisms.
    /// But the simplest correct approach: compute a^((p⁴-1)/(p-1)) and
    /// extract the constant term.
    ///
    /// For inversion, we use the identity: a⁻¹ = adj(a) / N(a),
    /// where adj(a) = a^(p + p² + p³) and N(a) = a^(1 + p + p² + p³).
    ///
    /// Efficient implementation: compute via the tower decomposition.
    fn norm(self) -> Fp {
        // Using the tower F_p → F_p² → F_p⁴:
        // Let α² = β where β² = -W (the intermediate extension).
        // Then a = (c0 + c2·β) + (c1 + c3·β)·α
        //        = A + B·α  where A = c0 + c2·β, B = c1 + c3·β
        //
        // N_{F_p⁴/F_p²}(a) = A² - B²·(-W) = A² + W·B²  (norm down to F_p²)
        // N_{F_p²/F_p}(x) = x₀² + W·x₁²  (norm down to F_p)
        //
        // Total norm = N_{F_p²/F_p}(A² + W·B²)

        let w = Fp::new(W);

        // A = c0 + c2·β → A₀ = c0, A₁ = c2
        // B = c1 + c3·β → B₀ = c1, B₁ = c3
        // A² = (A₀² - W·A₁²) + (2·A₀·A₁)·β
        let a_sq_0 = self.c0.mul(self.c0).sub(w.mul(self.c2.mul(self.c2)));
        let a_sq_1 = Fp::TWO.mul(self.c0.mul(self.c2));

        // B² = (B₀² - W·B₁²) + (2·B₀·B₁)·β
        let b_sq_0 = self.c1.mul(self.c1).sub(w.mul(self.c3.mul(self.c3)));
        let b_sq_1 = Fp::TWO.mul(self.c1.mul(self.c3));

        // A² - β·B² where β·B² = (-W·b_sq_1) + (b_sq_0)·β
        // So A² - β·B² = (a_sq_0 + W·b_sq_1) + (a_sq_1 - b_sq_0)·β
        let n_0 = a_sq_0.add(w.mul(b_sq_1));
        let n_1 = a_sq_1.sub(b_sq_0);

        // N_{F_p²/F_p}(n_0 + n_1·β) = n_0² + W·n_1²
        // (since β² = -W, the norm of x₀ + x₁·β is x₀² - (-W)·x₁² = x₀² + W·x₁²)
        n_0.mul(n_0).add(w.mul(n_1.mul(n_1)))
    }

    /// Multiplicative inverse via norm and adjugate.
    ///
    /// a⁻¹ = adj(a) / N(a)  where N(a) ∈ F_p and adj(a) ∈ F_p⁴.
    ///
    /// Returns `None` if `self` is zero.
    pub fn try_inv(self) -> Option<Self> {
        let n = self.norm();
        let n_inv = n.try_inv()?;

        // adj(a) = conj₁(a) · conj₂(a) · conj₃(a) = a^(p + p² + p³)
        // We compute adj(a) = a^(p-1) · a^(p²-1) · a^(p³-1) · a
        // But simpler: adj(a) = N(a) · a⁻¹, so a⁻¹ = adj(a) · N(a)⁻¹
        // Since we need adj(a), compute it as a^((p⁴-1)/(p-1) - 1)

        // Simpler approach: use the formula for the inverse in the tower.
        // a = A + B·α, a⁻¹ = (A - B·α) / (A² + W·B²)
        // where the denominator is in F_p² and can be inverted there.

        let w = Fp::new(W);

        // A = c0 + c2·β, B = c1 + c3·β (in F_p²)
        // A² + W·B² components (already computed in norm, but we need them here)
        let a_sq_0 = self.c0.mul(self.c0).sub(w.mul(self.c2.mul(self.c2)));
        let a_sq_1 = Fp::TWO.mul(self.c0.mul(self.c2));
        let b_sq_0 = self.c1.mul(self.c1).sub(w.mul(self.c3.mul(self.c3)));
        let b_sq_1 = Fp::TWO.mul(self.c1.mul(self.c3));

        // denom = A² - β·B² in F_p²
        // β·B² = (-W·b_sq_1) + (b_sq_0)·β
        // So A² - β·B² = (a_sq_0 + W·b_sq_1) + (a_sq_1 - b_sq_0)·β
        let d0 = a_sq_0.add(w.mul(b_sq_1));
        let d1 = a_sq_1.sub(b_sq_0);

        // Invert denom in F_p²: (d0 + d1·β)⁻¹ = (d0 - d1·β) / (d0² + W·d1²)
        // The scalar denominator is exactly N(a) which we already have.
        // So (d0 + d1·β)⁻¹ = (d0 · n⁻¹) + (-d1 · n⁻¹)·β
        let dinv_0 = d0.mul(n_inv);
        let dinv_1 = d1.neg().mul(n_inv);

        // a⁻¹ = (A·dinv - B·α·dinv) in tower form
        // = (A · dinv) + (-B · dinv) · α
        // where A, B, dinv are in F_p²

        // A · dinv (F_p² multiplication):
        // (c0 + c2·β)(dinv_0 + dinv_1·β) = (c0·dinv_0 - W·c2·dinv_1) + (c0·dinv_1 + c2·dinv_0)·β
        let r0 = self.c0.mul(dinv_0).sub(w.mul(self.c2.mul(dinv_1)));
        let r2 = self.c0.mul(dinv_1).add(self.c2.mul(dinv_0));

        // -B · dinv (F_p² multiplication, negated):
        // -(c1 + c3·β)(dinv_0 + dinv_1·β) = -(c1·dinv_0 - W·c3·dinv_1) + -(c1·dinv_1 + c3·dinv_0)·β
        let r1 = self.c1.mul(dinv_0).sub(w.mul(self.c3.mul(dinv_1))).neg();
        let r3 = self.c1.mul(dinv_1).add(self.c3.mul(dinv_0)).neg();

        Some(Self {
            c0: r0,
            c1: r1,
            c2: r2,
            c3: r3,
        })
    }

    /// Multiplicative inverse. Panics on zero.
    pub fn inv(self) -> Self {
        self.try_inv()
            .expect("Fp4::inv called on zero element")
    }

    /// Exponentiation by squaring.
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

    /// Check if this element is zero.
    #[inline]
    pub fn is_zero(self) -> bool {
        self.c0 == Fp::ZERO && self.c1 == Fp::ZERO && self.c2 == Fp::ZERO && self.c3 == Fp::ZERO
    }

    /// Serialize to 16 bytes (4 × u32 little-endian).
    pub fn to_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.c0.value().to_le_bytes());
        out[4..8].copy_from_slice(&self.c1.value().to_le_bytes());
        out[8..12].copy_from_slice(&self.c2.value().to_le_bytes());
        out[12..16].copy_from_slice(&self.c3.value().to_le_bytes());
        out
    }

    /// Deserialize from 16 bytes (4 × u32 little-endian).
    pub fn from_bytes(bytes: &[u8; 16]) -> Self {
        Self {
            c0: Fp::new(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])),
            c1: Fp::new(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])),
            c2: Fp::new(u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]])),
            c3: Fp::new(u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]])),
        }
    }
}

impl AirField for Fp4 {
    const ZERO: Self = Fp4::ZERO;
    const ONE: Self = Fp4::ONE;

    #[inline]
    fn from_u32(val: u32) -> Self {
        Fp4::from_base(Fp::new(val))
    }

    #[inline]
    fn add(self, rhs: Self) -> Self {
        Fp4::add(self, rhs)
    }

    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Fp4::sub(self, rhs)
    }

    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Fp4::mul(self, rhs)
    }
}

impl std::ops::Add for Fp4 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self {
        Fp4::add(self, rhs)
    }
}

impl std::ops::Sub for Fp4 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self {
        Fp4::sub(self, rhs)
    }
}

impl std::ops::Mul for Fp4 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        Fp4::mul(self, rhs)
    }
}

impl std::ops::Neg for Fp4 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        Fp4::neg(self)
    }
}

impl std::fmt::Display for Fp4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({} + {}·α + {}·α² + {}·α³)", self.c0, self.c1, self.c2, self.c3)
    }
}

// ══════════════════════════════════════════════════════════════════════
// Extension field polynomial evaluation
// ══════════════════════════════════════════════════════════════════════

/// Evaluate a polynomial with Fp coefficients at an Fp4 point via Horner's method.
///
/// Given P(x) = c₀ + c₁·x + c₂·x² + ... with cᵢ ∈ Fp,
/// computes P(z) ∈ Fp4 where z ∈ Fp4.
///
/// This is the key operation for OOD evaluation: trace polynomials have
/// base field coefficients, but the challenge point z is in the extension.
pub fn poly_eval_ext(coeffs: &[Fp], z: Fp4) -> Fp4 {
    let mut result = Fp4::ZERO;
    for &c in coeffs.iter().rev() {
        result = result.mul(z).add(Fp4::from_base(c));
    }
    result
}

/// Evaluate the vanishing polynomial Z_H(x) = x^n - 1 at an Fp4 point.
pub fn vanishing_eval_ext(z: Fp4, domain_size: u64) -> Fp4 {
    z.pow(domain_size).sub(Fp4::ONE)
}

/// Evaluate the transition zerofier Z_H(x)/(x - ω^(n-1)) at an Fp4 point.
///
/// Returns `None` if z = ω^(n-1) (division by zero).
pub fn transition_zerofier_eval_ext(
    z: Fp4,
    domain_size: u64,
    last_point: Fp,
) -> Option<Fp4> {
    let denom = z.sub(Fp4::from_base(last_point));
    if denom.is_zero() {
        return None;
    }
    let z_h = vanishing_eval_ext(z, domain_size);
    Some(z_h.mul(denom.inv()))
}

/// Evaluate the boundary zerofier Z_H(x)/(x - 1) at an Fp4 point.
///
/// Returns `None` if z = 1.
pub fn boundary_zerofier_eval_first_ext(z: Fp4, domain_size: u64) -> Option<Fp4> {
    let denom = z.sub(Fp4::ONE);
    if denom.is_zero() {
        return None;
    }
    let z_h = vanishing_eval_ext(z, domain_size);
    Some(z_h.mul(denom.inv()))
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fp4_add_sub() {
        let a = Fp4::new(Fp::new(1), Fp::new(2), Fp::new(3), Fp::new(4));
        let b = Fp4::new(Fp::new(10), Fp::new(20), Fp::new(30), Fp::new(40));

        let sum = a.add(b);
        assert_eq!(sum.c0.value(), 11);
        assert_eq!(sum.c1.value(), 22);
        assert_eq!(sum.c2.value(), 33);
        assert_eq!(sum.c3.value(), 44);

        let diff = sum.sub(b);
        assert_eq!(diff, a);
    }

    #[test]
    fn test_fp4_mul_by_base() {
        let a = Fp4::new(Fp::new(3), Fp::new(5), Fp::new(7), Fp::new(11));
        let s = Fp::new(10);

        let result = a.mul_base(s);
        assert_eq!(result.c0.value(), 30);
        assert_eq!(result.c1.value(), 50);
        assert_eq!(result.c2.value(), 70);
        assert_eq!(result.c3.value(), 110);
    }

    #[test]
    fn test_fp4_mul_identity() {
        let a = Fp4::new(Fp::new(7), Fp::new(13), Fp::new(19), Fp::new(23));
        let one = Fp4::ONE;

        assert_eq!(a.mul(one), a);
        assert_eq!(one.mul(a), a);
    }

    #[test]
    fn test_fp4_mul_base_elements() {
        // (3, 0, 0, 0) × (5, 0, 0, 0) = (15, 0, 0, 0)
        let a = Fp4::from_base(Fp::new(3));
        let b = Fp4::from_base(Fp::new(5));
        let result = a.mul(b);
        assert_eq!(result, Fp4::from_base(Fp::new(15)));
    }

    #[test]
    fn test_fp4_mul_alpha_squared() {
        // α × α = α²
        let alpha = Fp4::new(Fp::ZERO, Fp::ONE, Fp::ZERO, Fp::ZERO);
        let alpha_sq = alpha.mul(alpha);
        assert_eq!(alpha_sq, Fp4::new(Fp::ZERO, Fp::ZERO, Fp::ONE, Fp::ZERO));
    }

    #[test]
    fn test_fp4_mul_alpha_fourth() {
        // α⁴ = -11 (the defining relation)
        let alpha = Fp4::new(Fp::ZERO, Fp::ONE, Fp::ZERO, Fp::ZERO);
        let alpha_4 = alpha.pow(4);
        let neg_11 = Fp4::from_base(Fp::new(BABYBEAR_P - 11));
        assert_eq!(alpha_4, neg_11, "α⁴ must equal -11 in F_p");
    }

    #[test]
    fn test_fp4_inverse() {
        let a = Fp4::new(Fp::new(7), Fp::new(13), Fp::new(19), Fp::new(23));
        let a_inv = a.inv();
        let product = a.mul(a_inv);
        assert_eq!(product, Fp4::ONE, "a × a⁻¹ must be 1");
    }

    #[test]
    fn test_fp4_inverse_alpha() {
        let alpha = Fp4::new(Fp::ZERO, Fp::ONE, Fp::ZERO, Fp::ZERO);
        let alpha_inv = alpha.inv();
        let product = alpha.mul(alpha_inv);
        assert_eq!(product, Fp4::ONE, "α × α⁻¹ must be 1");
    }

    #[test]
    fn test_fp4_try_inv_zero() {
        assert!(Fp4::ZERO.try_inv().is_none());
    }

    #[test]
    fn test_fp4_inverse_random() {
        // Test several random-ish elements
        let elements = [
            Fp4::new(Fp::new(1), Fp::new(0), Fp::new(0), Fp::new(0)),
            Fp4::new(Fp::new(0), Fp::new(1), Fp::new(0), Fp::new(0)),
            Fp4::new(Fp::new(0), Fp::new(0), Fp::new(1), Fp::new(0)),
            Fp4::new(Fp::new(0), Fp::new(0), Fp::new(0), Fp::new(1)),
            Fp4::new(Fp::new(42), Fp::new(17), Fp::new(99), Fp::new(3)),
            Fp4::new(
                Fp::new(BABYBEAR_P - 1),
                Fp::new(BABYBEAR_P - 2),
                Fp::new(1000000),
                Fp::new(7),
            ),
        ];

        for a in &elements {
            let a_inv = a.inv();
            let product = a.mul(a_inv);
            assert_eq!(product, Fp4::ONE, "a × a⁻¹ must be 1 for a = {a}");
        }
    }

    #[test]
    fn test_fp4_pow() {
        let a = Fp4::new(Fp::new(3), Fp::new(5), Fp::new(7), Fp::new(11));
        assert_eq!(a.pow(0), Fp4::ONE);
        assert_eq!(a.pow(1), a);
        assert_eq!(a.pow(2), a.mul(a));
        assert_eq!(a.pow(3), a.mul(a).mul(a));
    }

    #[test]
    fn test_fp4_mul_commutativity() {
        let a = Fp4::new(Fp::new(7), Fp::new(13), Fp::new(19), Fp::new(23));
        let b = Fp4::new(Fp::new(31), Fp::new(37), Fp::new(41), Fp::new(43));
        assert_eq!(a.mul(b), b.mul(a), "multiplication must be commutative");
    }

    #[test]
    fn test_fp4_mul_associativity() {
        let a = Fp4::new(Fp::new(7), Fp::new(13), Fp::new(19), Fp::new(23));
        let b = Fp4::new(Fp::new(31), Fp::new(37), Fp::new(41), Fp::new(43));
        let c = Fp4::new(Fp::new(53), Fp::new(59), Fp::new(61), Fp::new(67));
        assert_eq!(
            a.mul(b).mul(c),
            a.mul(b.mul(c)),
            "multiplication must be associative"
        );
    }

    #[test]
    fn test_fp4_distributivity() {
        let a = Fp4::new(Fp::new(7), Fp::new(13), Fp::new(19), Fp::new(23));
        let b = Fp4::new(Fp::new(31), Fp::new(37), Fp::new(41), Fp::new(43));
        let c = Fp4::new(Fp::new(53), Fp::new(59), Fp::new(61), Fp::new(67));
        assert_eq!(
            a.mul(b.add(c)),
            a.mul(b).add(a.mul(c)),
            "a × (b + c) must equal a×b + a×c"
        );
    }

    #[test]
    fn test_fp4_serialization_roundtrip() {
        let a = Fp4::new(Fp::new(42), Fp::new(17), Fp::new(99), Fp::new(3));
        let bytes = a.to_bytes();
        let restored = Fp4::from_bytes(&bytes);
        assert_eq!(a, restored);
    }

    #[test]
    fn test_poly_eval_ext_matches_base() {
        // When z is a base field element, poly_eval_ext should match poly_eval
        let coeffs = vec![Fp::new(1), Fp::new(2), Fp::new(3)];
        let z_base = Fp::new(10);
        let z_ext = Fp4::from_base(z_base);

        let base_result = crate::field::poly_eval(&coeffs, z_base);
        let ext_result = poly_eval_ext(&coeffs, z_ext);

        assert_eq!(ext_result, Fp4::from_base(base_result));
    }

    #[test]
    fn test_poly_eval_ext_zero_poly() {
        let coeffs: Vec<Fp> = vec![];
        let z = Fp4::new(Fp::new(42), Fp::new(17), Fp::new(99), Fp::new(3));
        assert_eq!(poly_eval_ext(&coeffs, z), Fp4::ZERO);
    }

    #[test]
    fn test_vanishing_eval_ext_at_root_of_unity() {
        // Z_H(ω^i) = 0 for ω a root of unity of order n
        let n = 8u64;
        let omega = Fp::root_of_unity(3); // 8th root of unity
        let omega_ext = Fp4::from_base(omega);

        let z_h = vanishing_eval_ext(omega_ext, n);
        assert_eq!(z_h, Fp4::ZERO, "Z_H(ω) must be zero");
    }

    #[test]
    fn test_vanishing_eval_ext_at_random() {
        let z = Fp4::new(Fp::new(42), Fp::new(17), Fp::new(99), Fp::new(3));
        let z_h = vanishing_eval_ext(z, 8);
        assert_ne!(z_h, Fp4::ZERO, "Z_H(random) must be nonzero");
    }

    #[test]
    fn test_fp4_deterministic() {
        // The same operations must yield identical results across calls
        let a = Fp4::new(Fp::new(123456), Fp::new(789012), Fp::new(345678), Fp::new(901234));
        let b = Fp4::new(Fp::new(111111), Fp::new(222222), Fp::new(333333), Fp::new(444444));

        let r1 = a.mul(b).add(a).sub(b).mul(a.inv());
        let r2 = a.mul(b).add(a).sub(b).mul(a.inv());
        assert_eq!(r1, r2, "Fp4 arithmetic must be deterministic");
    }
}
