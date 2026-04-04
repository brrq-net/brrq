//! Fiat-Shamir transcript for non-interactive proofs.
//!
//! The transcript absorbs proof elements and produces deterministic
//! challenges, converting the interactive STARK protocol to
//! non-interactive (NARK → SNARK-like behavior).
//!
//! ## Security
//!
//! Uses SHA-256 based hashing for challenge generation. Each challenge
//! depends on ALL previously absorbed data, ensuring that any change
//! to the proof invalidates all subsequent challenges.

use crate::field::Fp;
use crate::field_ext::Fp4;
use brrq_crypto::hash::{Hash256, Hasher};

/// Fiat-Shamir transcript for challenge generation.
///
/// Absorbs commitments and data, produces field element challenges
/// using SHA-256 based hashing.
pub struct Transcript {
    state: Hash256,
}

impl Transcript {
    /// Create a new transcript with a domain separator.
    pub fn new(domain: &[u8]) -> Self {
        Self {
            state: Hasher::hash(domain),
        }
    }

    /// Absorb a hash commitment into the transcript.
    pub fn absorb_hash(&mut self, h: &Hash256) {
        let mut hasher = Hasher::new();
        hasher.update(self.state.as_bytes());
        hasher.update(h.as_bytes());
        self.state = hasher.finalize();
    }

    /// Absorb raw bytes into the transcript.
    pub fn absorb_bytes(&mut self, data: &[u8]) {
        let mut hasher = Hasher::new();
        hasher.update(self.state.as_bytes());
        hasher.update(data);
        self.state = hasher.finalize();
    }

    /// Absorb a u64 value.
    pub fn absorb_u64(&mut self, val: u64) {
        self.absorb_bytes(&val.to_le_bytes());
    }

    /// Absorb a BabyBear field element.
    pub fn absorb_fp(&mut self, val: Fp) {
        self.absorb_bytes(&val.value().to_le_bytes());
    }

    /// Squeeze a BabyBear field element challenge from the transcript.
    ///
    /// Each call produces a fresh challenge that depends on all
    /// previously absorbed data.
    ///
    /// Uses rejection sampling to eliminate modular reduction bias.
    /// Without this, values in `[0, 2^32 mod p)` are approximately 2x more
    /// likely than values in `[2^32 mod p, p)`, reducing soundness by a
    /// small factor. Rejection sampling ensures uniform distribution over
    /// the BabyBear field.
    pub fn challenge_field(&mut self) -> Fp {
        // max_unbiased is the largest multiple of MODULUS that fits
        // in u32, ensuring uniform sampling when we reject values above it.
        const MAX_UNBIASED: u32 = (u32::MAX / Fp::MODULUS) * Fp::MODULUS;

        loop {
            let mut hasher = Hasher::new();
            hasher.update(b"CHALLENGE");
            hasher.update(self.state.as_bytes());
            self.state = hasher.finalize();

            let bytes = self.state.as_bytes();
            let val = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

            // Reject values that would create bias via modular reduction
            if val < MAX_UNBIASED {
                return Fp::new(val);
            }
            // Rejected -- loop will hash again with the updated state
        }
    }

    /// Squeeze a usize index challenge in [0, bound).
    ///
    /// Uses rejection sampling to eliminate modular reduction bias when
    /// `bound` is not a power of 2. Without this, indices in
    /// `[0, 2^64 mod bound)` are slightly overrepresented.
    pub fn challenge_index(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "challenge_index: bound must be > 0");
        let bound_u64 = bound as u64;
        let max_unbiased = (u64::MAX / bound_u64) * bound_u64;

        loop {
            let mut hasher = Hasher::new();
            hasher.update(b"INDEX");
            hasher.update(self.state.as_bytes());
            self.state = hasher.finalize();

            let bytes = self.state.as_bytes();
            let val = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            if val < max_unbiased {
                return (val as usize) % bound;
            }
        }
    }

    // ══════════════════════════════════════════════════════════════
    // Extension field operations
    // ══════════════════════════════════════════════════════════════

    /// Squeeze an Fp4 extension field challenge from the transcript.
    ///
    /// Draws 4 independent Fp challenges and packs them into Fp4.
    /// Each component depends on all previously absorbed data plus
    /// the sequential draws, ensuring uniform distribution over Fp4.
    ///
    /// Security: |Fp4| ≈ 2^124, giving ~102-bit OOD security for
    /// trace degree d ≈ 2^20.
    pub fn challenge_ext_field(&mut self) -> Fp4 {
        Fp4::new(
            self.challenge_field(),
            self.challenge_field(),
            self.challenge_field(),
            self.challenge_field(),
        )
    }

    /// Absorb an Fp4 extension field element into the transcript.
    ///
    /// Absorbs all 4 components in order (c0, c1, c2, c3).
    pub fn absorb_fp4(&mut self, val: Fp4) {
        self.absorb_fp(val.c0);
        self.absorb_fp(val.c1);
        self.absorb_fp(val.c2);
        self.absorb_fp(val.c3);
    }

    /// Get the current transcript state (for inclusion in proofs).
    pub fn state(&self) -> Hash256 {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transcript_deterministic() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.absorb_hash(&Hash256::ZERO);
        t2.absorb_hash(&Hash256::ZERO);

        assert_eq!(t1.challenge_field().value(), t2.challenge_field().value());
    }

    #[test]
    fn test_transcript_different_domain() {
        let mut t1 = Transcript::new(b"domain_a");
        let mut t2 = Transcript::new(b"domain_b");

        assert_ne!(t1.challenge_field().value(), t2.challenge_field().value());
    }

    #[test]
    fn test_transcript_absorb_changes_state() {
        let mut t = Transcript::new(b"test");
        let c1 = t.challenge_field();
        t.absorb_u64(42);
        let c2 = t.challenge_field();
        assert_ne!(c1.value(), c2.value());
    }

    #[test]
    fn test_transcript_fp_absorb() {
        let mut t1 = Transcript::new(b"test");
        let mut t2 = Transcript::new(b"test");

        t1.absorb_fp(Fp::new(42));
        t2.absorb_fp(Fp::new(42));

        assert_eq!(t1.challenge_field().value(), t2.challenge_field().value());
    }

    #[test]
    fn test_transcript_challenge_range() {
        let mut t = Transcript::new(b"idx_test");
        for _ in 0..100 {
            let idx = t.challenge_index(10);
            assert!(idx < 10);
        }
    }

    // ── H-5 rejection sampling tests ──────────────────────────────────

    #[test]
    fn test_h5_challenge_field_in_range() {
        // All challenge values must be valid BabyBear field elements (< MODULUS)
        let mut t = Transcript::new(b"h5_range_test");
        for _ in 0..1000 {
            let c = t.challenge_field();
            assert!(
                c.value() < Fp::MODULUS,
                "challenge {} must be < MODULUS {}",
                c.value(),
                Fp::MODULUS,
            );
        }
    }

    #[test]
    fn test_h5_challenge_field_deterministic_after_fix() {
        // Rejection sampling must still be deterministic: same input -> same output
        let mut t1 = Transcript::new(b"h5_det");
        let mut t2 = Transcript::new(b"h5_det");

        t1.absorb_u64(123);
        t2.absorb_u64(123);

        for _ in 0..100 {
            assert_eq!(
                t1.challenge_field().value(),
                t2.challenge_field().value(),
                "rejection sampling must be deterministic"
            );
        }
    }
}
