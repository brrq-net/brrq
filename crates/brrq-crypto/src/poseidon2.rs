//! Poseidon2 — Algebraic hash function for internal zkVM state.
//!
//! ## Why Poseidon2?
//!
//! Per whitepaper §3.5, Brrq uses a dual-hash architecture:
//! - **External (L1-facing)**: SHA-256 — Bitcoin compatibility + hardware acceleration
//! - **Internal (zkVM)**: Poseidon2 — ~138x fewer ZK constraints than SHA-256
//!
//! ## Design: Poseidon2 over Mersenne-31 (M31)
//!
//! | Parameter    | Value           | Rationale                             |
//! |-------------|-----------------|---------------------------------------|
//! | Field       | M31 (p=2^31-1) | Stwo engine's native field            |
//! | State width | 16 elements     | Standard for 2:1 compression          |
//! | Rate        | 8 elements      | 8 input + 8 capacity                  |
//! | S-box       | x^5             | Lowest degree for M31 (gcd(5,p-1)=1)  |
//! | Full rounds | 8 (4+4)         | External rounds with full S-box layer  |
//! | Partial rds | 14              | Internal rounds with single S-box      |
//! | Output      | 8 elements      | 248 bits → padded to Hash256 (256 bit) |
//!
//! ## Security
//!
//! - 124-bit collision resistance (sponge capacity bound: 248/2)
//! - Grover's algorithm weakens to 124-bit quantum security
//! - Used only internally where ZK efficiency is critical
//! - SHA-256 remains for all L1-facing operations

use crate::hash::Hash256;

// ══════════════════════════════════════════════════════════════════════
// M31 Field Arithmetic — Mersenne-31 (p = 2^31 - 1)
// ══════════════════════════════════════════════════════════════════════

/// Mersenne-31 prime: p = 2^31 - 1 = 2,147,483,647.
pub const M31_P: u32 = (1u32 << 31) - 1;

/// A field element in the Mersenne-31 field.
/// Invariant: value is always in [0, M31_P).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct M31(pub u32);

impl M31 {
    pub const ZERO: M31 = M31(0);
    pub const ONE: M31 = M31(1);

    /// Create from u32, reducing modulo p.
    ///
    /// NOTE: This maps both 0 and M31_P (0x7FFFFFFF) to M31(0), and more
    /// generally `val` collides with `val + p` for any val where both are
    /// < 2^32. This is correct for field arithmetic but NOT injective over
    /// the full u32 range. Use `from_u32_injective()` when distinct u32
    /// values must map to distinct field elements (e.g., hash absorption).
    #[inline]
    pub fn new(val: u32) -> Self {
        Self(Self::reduce(val as u64))
    }

    /// Injective mapping from u32 to a pair of M31 elements.
    ///
    /// Standard `new()` reduces mod p, so distinct u32 values can collide
    /// (e.g., 0 and 0x7FFFFFFF both map to M31(0)). For hash absorption,
    /// we need injectivity: different byte inputs must produce different
    /// field element sequences.
    ///
    /// Encodes `val` as `(val mod p, val / p)` — a unique quotient-remainder
    /// pair since p = 2^31-1 and val < 2^32, giving quotient in {0, 1, 2}.
    /// Callers must absorb BOTH returned elements to preserve injectivity.
    #[inline]
    pub fn from_u32_injective(val: u32) -> (M31, M31) {
        let rem = Self::new(val);                                  // val mod p
        let quot = Self((val as u64 / M31_P as u64) as u32);      // val / p ∈ {0,1,2}
        (rem, quot)
    }

    /// Create from u64, reducing modulo p.
    ///
    /// `val % p` already guarantees `val < p`, so no further reduction needed.
    #[inline]
    pub fn from_u64(val: u64) -> Self {
        Self((val % M31_P as u64) as u32)
    }

    /// Branchless reduction modulo 2^31 - 1 using the Mersenne property.
    /// For x < 2^62: (x >> 31) + (x & p), then normalize without branching.
    #[inline]
    fn reduce(x: u64) -> u32 {
        let r = ((x >> 31) + (x & M31_P as u64)) as u32;
        // r is in [0, 2p]. Branchless conditional subtraction of p:
        // If r >= p: sub doesn't borrow (bit 31 = 0), we want sub.
        // If r < p:  sub borrows (bit 31 = 1), we want r = sub + p.
        let sub = r.wrapping_sub(M31_P);
        let borrow = sub >> 31; // 1 if r < p, 0 if r >= p
        sub.wrapping_add(borrow.wrapping_mul(M31_P))
    }

    /// Addition: (a + b) mod p.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn add(self, other: Self) -> Self {
        let sum = self.0 as u64 + other.0 as u64;
        Self(Self::reduce(sum))
    }

    /// Branchless subtraction: (a - b) mod p.
    ///
    /// Adds p before subtracting to guarantee no underflow, then reduces.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn sub(self, other: Self) -> Self {
        let diff = self.0 as u64 + M31_P as u64 - other.0 as u64;
        Self(Self::reduce(diff))
    }

    /// Multiplication: (a * b) mod p.
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn mul(self, other: Self) -> Self {
        let prod = self.0 as u64 * other.0 as u64;
        Self(Self::reduce(prod))
    }

    /// S-box: x^5 (standard for Poseidon2 over M31).
    #[inline]
    pub fn pow5(self) -> Self {
        let x2 = self.mul(self);
        let x4 = x2.mul(x2);
        x4.mul(self)
    }

    /// Modular exponentiation (used for inverse).
    pub fn pow(self, mut exp: u32) -> Self {
        let mut result = Self::ONE;
        let mut base = self;
        while exp > 0 {
            if exp & 1 == 1 {
                result = result.mul(base);
            }
            base = base.mul(base);
            exp >>= 1;
        }
        result
    }

    /// Multiplicative inverse: a^(p-2) mod p.
    pub fn inv(self) -> Self {
        self.pow(M31_P - 2)
    }
}

impl std::fmt::Display for M31 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ══════════════════════════════════════════════════════════════════════
// Poseidon2 Permutation Constants
// ══════════════════════════════════════════════════════════════════════

/// State width (number of M31 elements).
const WIDTH: usize = 16;
/// Rate (number of input elements per absorption).
const RATE: usize = 8;
/// Number of full (external) rounds at the start.
const FULL_ROUNDS_START: usize = 4;
/// Number of partial (internal) rounds.
const PARTIAL_ROUNDS: usize = 14;
/// Number of full (external) rounds at the end.
const FULL_ROUNDS_END: usize = 4;
/// Total rounds.
const TOTAL_ROUNDS: usize = FULL_ROUNDS_START + PARTIAL_ROUNDS + FULL_ROUNDS_END;

/// Round constants: deterministically generated from "Poseidon2_M31_w16".
/// Each round has WIDTH constants for full rounds, or 1 constant for partial rounds.
fn generate_round_constants() -> Vec<Vec<M31>> {
    use sha2::{Digest, Sha256};
    let mut constants = Vec::with_capacity(TOTAL_ROUNDS);
    let mut counter: u64 = 0;

    for round in 0..TOTAL_ROUNDS {
        let num_consts =
            if !(FULL_ROUNDS_START..FULL_ROUNDS_START + PARTIAL_ROUNDS).contains(&round) {
                WIDTH // Full round: one constant per element.
            } else {
                1 // Partial round: one constant for the S-box element.
            };

        let mut round_consts = Vec::with_capacity(num_consts);
        for _ in 0..num_consts {
            let mut h = Sha256::new();
            h.update(b"Poseidon2_M31_w16_rc");
            h.update(counter.to_le_bytes());
            let hash = h.finalize();
            let val = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
            round_consts.push(M31::new(val));
            counter += 1;
        }
        constants.push(round_consts);
    }
    constants
}

/// Diagonal elements for the internal (partial round) matrix M_I = I + diag(d).
/// Deterministically generated.
fn generate_internal_diag() -> [M31; WIDTH] {
    use sha2::{Digest, Sha256};
    let mut diag = [M31::ZERO; WIDTH];
    for (i, d) in diag.iter_mut().enumerate() {
        let mut h = Sha256::new();
        h.update(b"Poseidon2_M31_w16_diag");
        h.update((i as u64).to_le_bytes());
        let hash = h.finalize();
        let val = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        // Ensure non-zero to keep matrix invertible.
        *d = M31::new(val | 1);
    }
    diag
}

// ══════════════════════════════════════════════════════════════════════
// Poseidon2 Linear Layers
// ══════════════════════════════════════════════════════════════════════

/// Poseidon2 external (full round) linear layer.
/// Applies a 4x4 MDS matrix to each group of 4 elements, then mixes groups.
#[inline]
fn external_linear_layer(state: &mut [M31; WIDTH]) {
    // Step 1: Apply 4x4 circulant matrix to each group of 4.
    // M4 = circ(3, 2, 1, 1) — this is MDS over M31.
    // out[0] = 3a + 2b + c + d = (a+b+c+d) + 2a + b
    // out[1] = a + 3b + 2c + d = (a+b+c+d) + 2b + c
    // out[2] = a + b + 3c + 2d = (a+b+c+d) + 2c + d
    // out[3] = 2a + b + c + 3d = (a+b+c+d) + 2d + a
    for chunk_start in (0..WIDTH).step_by(4) {
        let a = state[chunk_start];
        let b = state[chunk_start + 1];
        let c = state[chunk_start + 2];
        let d = state[chunk_start + 3];

        let t = a.add(b).add(c).add(d);
        let a2 = a.add(a);
        let b2 = b.add(b);
        let c2 = c.add(c);
        let d2 = d.add(d);

        state[chunk_start] = t.add(a2).add(b);
        state[chunk_start + 1] = t.add(b2).add(c);
        state[chunk_start + 2] = t.add(c2).add(d);
        state[chunk_start + 3] = t.add(d2).add(a);
    }

    // Step 2: Mix across groups — add sum of all group heads.
    // This ensures full diffusion across all 16 elements.
    let mut group_sums = [M31::ZERO; 4];
    for i in 0..4 {
        for j in 0..4 {
            group_sums[i] = group_sums[i].add(state[j * 4 + i]);
        }
    }
    for i in 0..WIDTH {
        state[i] = state[i].add(group_sums[i % 4]);
    }
}

/// Poseidon2 internal (partial round) linear layer.
/// M_I = diag(d) + J (all-ones matrix): state[i] = d[i]*state[i] + sum(state).
#[inline]
fn internal_linear_layer(state: &mut [M31; WIDTH], diag: &[M31; WIDTH]) {
    // Sum of all elements.
    let mut sum = M31::ZERO;
    for &s in state.iter() {
        sum = sum.add(s);
    }
    // Each element: state[i] = state[i] * diag[i] + sum.
    for (s, &d) in state.iter_mut().zip(diag.iter()) {
        *s = s.mul(d).add(sum);
    }
}

// ══════════════════════════════════════════════════════════════════════
// Poseidon2 Permutation
// ══════════════════════════════════════════════════════════════════════

/// Cached round constants and diagonal elements.
/// Computed once on first use, then reused for all subsequent invocations.
static CACHED_ROUND_CONSTANTS: std::sync::LazyLock<Vec<Vec<M31>>> =
    std::sync::LazyLock::new(generate_round_constants);
static CACHED_INTERNAL_DIAG: std::sync::LazyLock<[M31; WIDTH]> =
    std::sync::LazyLock::new(generate_internal_diag);

/// Apply the full Poseidon2 permutation to a 16-element state.
#[inline]
pub fn poseidon2_permutation(state: &mut [M31; WIDTH]) {
    let rc = &*CACHED_ROUND_CONSTANTS;
    let diag = &*CACHED_INTERNAL_DIAG;
    let mut round = 0;

    // Initial external linear layer.
    external_linear_layer(state);

    // Full rounds (start).
    for _ in 0..FULL_ROUNDS_START {
        // Add round constants.
        for (s, c) in state.iter_mut().zip(rc[round].iter()) {
            *s = s.add(*c);
        }
        // S-box on all elements.
        for s in state.iter_mut() {
            *s = s.pow5();
        }
        // External linear layer.
        external_linear_layer(state);
        round += 1;
    }

    // Partial rounds.
    for _ in 0..PARTIAL_ROUNDS {
        // Add round constant to first element only.
        state[0] = state[0].add(rc[round][0]);
        // S-box on first element only.
        state[0] = state[0].pow5();
        // Internal linear layer.
        internal_linear_layer(state, diag);
        round += 1;
    }

    // Full rounds (end).
    for _ in 0..FULL_ROUNDS_END {
        for (s, c) in state.iter_mut().zip(rc[round].iter()) {
            *s = s.add(*c);
        }
        for s in state.iter_mut() {
            *s = s.pow5();
        }
        external_linear_layer(state);
        round += 1;
    }
}

// ══════════════════════════════════════════════════════════════════════
// Injective u32 → M31 absorption helper
// ══════════════════════════════════════════════════════════════════════

/// Absorb a u32 value into a rate element and accumulate the overflow
/// (quotient) into a capacity element, preserving injectivity.
///
/// `M31::new(val)` computes `val mod p`, which maps multiple distinct u32
/// values to the same field element (e.g., 0 and 0x7FFFFFFF both → M31(0),
/// 1 and 0x80000000 both → M31(1), etc.). For hash absorption this creates
/// collisions: different byte inputs can produce identical field-element states.
///
/// Fix: encode each u32 as `(val mod p, val / p)` — a unique quotient-remainder
/// pair. The remainder goes into the rate element; the quotient (0, 1, or 2)
/// is accumulated into `overflow_acc` which the caller must absorb into a
/// capacity element after processing all u32 values in a block.
#[inline]
fn absorb_u32(val: u32, rate_elem: &mut M31, overflow_acc: &mut u64) {
    *rate_elem = rate_elem.add(M31::new(val));
    // val / p: since val < 2^32 and p = 2^31-1, quotient is in {0, 1, 2}.
    // Accumulate quotients with positional encoding to distinguish which
    // element contributed which overflow.
    *overflow_acc = overflow_acc.wrapping_add(val as u64 / M31_P as u64);
    // Shift accumulator to create positional separation for the next u32.
    *overflow_acc = overflow_acc.wrapping_mul(3);
}

/// Absorb a data block into the sponge state's rate portion.
///
/// Processes up to RATE u32 values from `data[offset..]` into `state[0..RATE]`
/// using injective absorption, handles remaining bytes with 0x80 padding marker,
/// and mixes overflow bits into capacity elements. Returns the new offset.
#[inline]
fn absorb_block(state: &mut [M31; WIDTH], data: &[u8], offset: usize) -> usize {
    let chunk_end = (offset + RATE * 4).min(data.len());
    let mut elem_idx = 0;
    let mut overflow: u64 = 0;
    let mut pos = offset;

    // Map bytes to M31 elements and add into rate portion.
    while pos + 4 <= chunk_end && elem_idx < RATE {
        let val = u32::from_le_bytes([
            data[pos],
            data[pos + 1],
            data[pos + 2],
            data[pos + 3],
        ]);
        absorb_u32(val, &mut state[elem_idx], &mut overflow);
        pos += 4;
        elem_idx += 1;
    }

    // Handle remaining bytes (< 4).
    // Use 0x80 marker for padding to avoid collision with data bytes.
    if pos < chunk_end && elem_idx < RATE {
        let mut buf = [0u8; 4];
        let remaining = chunk_end - pos;
        buf[..remaining].copy_from_slice(&data[pos..chunk_end]);
        buf[remaining] = 0x80;
        let val = u32::from_le_bytes(buf);
        absorb_u32(val, &mut state[elem_idx], &mut overflow);
        pos = chunk_end;
    }

    // Mix overflow from this block into capacity elements.
    state[RATE + 4] = state[RATE + 4].add(M31::from_u64(overflow));
    state[RATE + 5] = state[RATE + 5].add(M31::from_u64(overflow >> 31));

    pos
}

/// Extract 8 output elements from the sponge state into a Hash256 (32 bytes).
#[inline]
fn squeeze_output(state: &[M31; WIDTH]) -> Hash256 {
    let mut output = [0u8; 32];
    for (i, s) in state.iter().enumerate().take(8) {
        let off = i * 4;
        output[off..off + 4].copy_from_slice(&s.0.to_le_bytes());
    }
    Hash256::from_bytes(output)
}

/// Encode the input data length into the sponge capacity elements.
///
/// Uses two capacity elements to prevent collisions for inputs
/// differing only in length > 2^31 bytes.
#[inline]
fn encode_length(state: &mut [M31; WIDTH], len: usize) {
    state[RATE] = state[RATE].add(M31::new((len & 0x7FFF_FFFF) as u32));
    state[RATE + 3] = state[RATE + 3].add(M31::new(((len >> 31) & 0x7FFF_FFFF) as u32));
}

/// Apply the finalization permutation after absorption.
///
/// Adds a domain flag to capacity and permutes once more, distinguishing
/// empty input (flag=1) from non-empty (flag=2) and separating the
/// absorption phase from the squeeze phase.
#[inline]
fn finalize_sponge(state: &mut [M31; WIDTH], is_empty: bool) {
    let flag = if is_empty { 1 } else { 2 };
    state[RATE + 1] = state[RATE + 1].add(M31::new(flag));
    poseidon2_permutation(state);
}

/// Load two Hash256 values into the 16-element state (8 elements each).
#[inline]
fn load_hash256_pair(state: &mut [M31; WIDTH], left: &Hash256, right: &Hash256) {
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();

    for (s, chunk) in state[..8].iter_mut().zip(left_bytes.chunks(4)) {
        let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        *s = M31::new(val);
    }
    for (s, chunk) in state[8..16].iter_mut().zip(right_bytes.chunks(4)) {
        let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        *s = M31::new(val);
    }
}

// ══════════════════════════════════════════════════════════════════════
// Poseidon2 Hash (Sponge Construction)
// ══════════════════════════════════════════════════════════════════════

/// Poseidon2 compression: hash two Hash256 values into one.
///
/// Maps 64 input bytes (two Hash256) to 16 M31 field elements,
/// applies Poseidon2 permutation, then converts 8 output elements
/// back to a Hash256 (256 bits).
///
/// This is the primary function for internal Merkle tree hashing.
pub fn poseidon2_compress(left: &Hash256, right: &Hash256) -> Hash256 {
    let mut state = [M31::ZERO; WIDTH];

    // Map 64 bytes (two Hash256) to 16 M31 elements.
    //
    // Inputs MUST be Poseidon2 outputs (all u32 < M31_P).
    // If a SHA-256 hash is accidentally passed, some u32 values may be >= M31_P,
    // causing M31::new() to reduce mod p → collision (distinct inputs map to
    // same field element). This is a defense-in-depth assertion.
    //
    // We check in all builds and panic on violation — this is a correctness
    // invariant, not a performance concern. M31::new() would reduce mod p with
    // no UB, but the result would be non-injective for values >= p (collisions).
    let left_bytes = left.as_bytes();
    let right_bytes = right.as_bytes();

    // Check in ALL builds (not just debug) to detect context leaks
    {
        let has_overflow = left_bytes.chunks(4).chain(right_bytes.chunks(4))
            .any(|chunk| {
                let val = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                val >= M31_P
            });
        if has_overflow {
            // This is a programming error: feeding raw SHA-256 bytes without
            // injective encoding causes non-injective mod-p reduction (collisions).
            // Panic in ALL builds — correctness invariant, not a performance concern.
            panic!(
                "poseidon2_compress: input contains u32 >= M31_P (0x{:08X}). \
                 This indicates a SHA-256 hash was passed to a Poseidon2 function. \
                 Use SHA-256 tree for external hashes, Poseidon2 tree for STARK proofs.",
                M31_P
            );
        }
    }

    load_hash256_pair(&mut state, left, right);

    // Apply Poseidon2 permutation.
    poseidon2_permutation(&mut state);

    // Extract 8 output elements → 32 bytes.
    squeeze_output(&state)
}

/// Poseidon2 hash of arbitrary data via sponge construction.
///
/// Absorbs data in RATE-sized chunks (32 bytes = 8 elements),
/// then squeezes 8 elements for 256-bit output.
///
/// ## Padding
///
/// Uses multi-rate padding to prevent collision between messages whose
/// lengths differ only by the padding pattern:
/// - Remaining bytes (< 4) are padded with `0x80` marker
/// - Input length is encoded into the capacity portion (`state[RATE]`)
/// - A finalization flag is added to `state[RATE+1]` after all data
///   is absorbed, distinguishing exact multiples of block size.
pub fn poseidon2_hash(data: &[u8]) -> Hash256 {
    let mut state = [M31::ZERO; WIDTH];

    // Encode full usize length using two capacity elements to prevent
    // collisions for inputs differing only in length > 2^31 bytes.
    encode_length(&mut state, data.len());

    // Absorb: process data in 32-byte (8-element) chunks.
    // Use absorb_u32() to prevent collisions from mod-p reduction:
    // overflow bits are accumulated per-block and mixed into capacity.
    let mut offset = 0;
    while offset < data.len() {
        offset = absorb_block(&mut state, data, offset);
        // Permute.
        poseidon2_permutation(&mut state);
    }

    // Finalization: add domain separation flag to capacity after all
    // data is absorbed. This distinguishes empty input from non-empty
    // input whose absorption happens to leave the state unchanged.
    finalize_sponge(&mut state, data.is_empty());

    // Squeeze: extract 8 elements → 32 bytes.
    squeeze_output(&state)
}

/// Poseidon2 domain-separated Merkle leaf hash.
///
/// Applies domain tag `M31(2)` to `state[0]` before permutation to distinguish
/// leaf hashes from internal node hashes (`M31(1)`) and plain compression (`M31(0)`).
/// This mirrors the SHA-256 pattern (0x00 prefix for leaves, 0x01 for nodes).
///
/// Uses a proper sponge loop to absorb data of arbitrary length, with
/// length encoding in the capacity portion to prevent padding collisions.
pub fn poseidon2_hash_leaf(data: &[u8]) -> Hash256 {
    let mut state = [M31::ZERO; WIDTH];

    // Encode full usize length (same two-element encoding as poseidon2_hash).
    encode_length(&mut state, data.len());

    // Domain separation for leaf (distinct from node = M31(1) and compress = M31(0)).
    // Applied before absorption so it's part of the initial state.
    state[RATE + 2] = state[RATE + 2].add(M31::new(2));

    // Absorb: process data in RATE-sized chunks (32 bytes).
    // Use absorb_u32() to prevent collisions from mod-p reduction.
    let mut offset = 0;
    while offset < data.len() {
        offset = absorb_block(&mut state, data, offset);
        poseidon2_permutation(&mut state);
    }

    // Finalization permutation — consistent with poseidon2_hash().
    // Separates the absorption phase from the squeeze phase, preventing an
    // attacker from controlling 8/16 state elements entering the squeeze.
    finalize_sponge(&mut state, data.is_empty());

    squeeze_output(&state)
}

/// Poseidon2 domain-separated Merkle node hash.
/// Equivalent to hash_node but using Poseidon2 internally.
pub fn poseidon2_hash_node(left: &Hash256, right: &Hash256) -> Hash256 {
    // Domain separation: add 0x01 to capacity element before compression.
    let mut state = [M31::ZERO; WIDTH];

    load_hash256_pair(&mut state, left, right);

    // Domain separation in capacity element (state[RATE+2]),
    // NOT in rate portion (state[0]). Placing it in state[0] creates an
    // algebraic relationship: hash_node(L,R) where L encodes M31(x)
    // equals compress(L',R) where L' encodes M31(x+1). Using capacity
    // avoids this (consistent with poseidon2_hash_leaf which uses state[RATE+2]).
    state[RATE + 2] = state[RATE + 2].add(M31::ONE);

    poseidon2_permutation(&mut state);

    squeeze_output(&state)
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ─── M31 Field Tests ───

    #[test]
    fn test_m31_basic_arithmetic() {
        let a = M31::new(100);
        let b = M31::new(200);
        assert_eq!(a.add(b).0, 300);
        assert_eq!(b.sub(a).0, 100);
        assert_eq!(a.mul(b).0, 20_000);
    }

    #[test]
    fn test_m31_reduction() {
        // p = 2^31 - 1 = 2147483647
        let a = M31::new(M31_P); // Should reduce to 0.
        assert_eq!(a.0, 0);

        let b = M31::new(M31_P + 1); // Should reduce to 1.
        assert_eq!(b.0, 1);
    }

    #[test]
    fn test_m31_inverse() {
        let a = M31::new(42);
        let inv = a.inv();
        let product = a.mul(inv);
        assert_eq!(product.0, 1);
    }

    #[test]
    fn test_m31_pow5() {
        let a = M31::new(3);
        let result = a.pow5();
        assert_eq!(result.0, 243); // 3^5 = 243
    }

    #[test]
    fn test_m31_subtraction_underflow() {
        let a = M31::new(5);
        let b = M31::new(10);
        let result = a.sub(b);
        // 5 - 10 mod p = p - 5
        assert_eq!(result.0, M31_P - 5);
    }

    // ─── Poseidon2 Permutation Tests ───

    #[test]
    fn test_poseidon2_permutation_deterministic() {
        let mut state1 = [M31::ZERO; WIDTH];
        state1[0] = M31::new(1);
        let mut state2 = state1;

        poseidon2_permutation(&mut state1);
        poseidon2_permutation(&mut state2);

        for i in 0..WIDTH {
            assert_eq!(state1[i], state2[i]);
        }
    }

    #[test]
    fn test_poseidon2_permutation_nonzero_output() {
        let mut state = [M31::ZERO; WIDTH];
        state[0] = M31::new(42);
        poseidon2_permutation(&mut state);

        // At least some outputs should be non-zero.
        let non_zero_count = state.iter().filter(|s| s.0 != 0).count();
        assert!(
            non_zero_count > WIDTH / 2,
            "Expected most outputs non-zero, got {}/{}",
            non_zero_count,
            WIDTH
        );
    }

    #[test]
    fn test_poseidon2_permutation_diffusion() {
        // Different inputs should produce different outputs.
        let mut state1 = [M31::ZERO; WIDTH];
        let mut state2 = [M31::ZERO; WIDTH];
        state1[0] = M31::new(1);
        state2[0] = M31::new(2);

        poseidon2_permutation(&mut state1);
        poseidon2_permutation(&mut state2);

        // Outputs should differ in most positions.
        let diff_count = state1
            .iter()
            .zip(state2.iter())
            .filter(|(a, b)| a != b)
            .count();
        assert!(
            diff_count > WIDTH / 2,
            "Expected high diffusion, got {}/{} differences",
            diff_count,
            WIDTH
        );
    }

    // ─── Poseidon2 Hash Tests ───

    #[test]
    fn test_poseidon2_compress_deterministic() {
        let a = Hash256::from_bytes([1u8; 32]);
        let b = Hash256::from_bytes([2u8; 32]);
        let h1 = poseidon2_compress(&a, &b);
        let h2 = poseidon2_compress(&a, &b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_poseidon2_compress_different_inputs() {
        let a = Hash256::from_bytes([1u8; 32]);
        let b = Hash256::from_bytes([2u8; 32]);
        let c = Hash256::from_bytes([3u8; 32]);
        let h1 = poseidon2_compress(&a, &b);
        let h2 = poseidon2_compress(&a, &c);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon2_compress_order_matters() {
        let a = Hash256::from_bytes([1u8; 32]);
        let b = Hash256::from_bytes([2u8; 32]);
        let h1 = poseidon2_compress(&a, &b);
        let h2 = poseidon2_compress(&b, &a);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon2_hash_basic() {
        let h1 = poseidon2_hash(b"hello");
        let h2 = poseidon2_hash(b"hello");
        assert_eq!(h1, h2);

        let h3 = poseidon2_hash(b"world");
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_poseidon2_hash_empty() {
        let h = poseidon2_hash(b"");
        assert!(!h.is_zero());
    }

    #[test]
    fn test_poseidon2_hash_leaf_deterministic() {
        let h1 = poseidon2_hash_leaf(b"test leaf data");
        let h2 = poseidon2_hash_leaf(b"test leaf data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_poseidon2_hash_leaf_domain_separation() {
        let data = [1u8; 32];
        let leaf = poseidon2_hash_leaf(&data);
        let plain = poseidon2_hash(&data);
        // Leaf hash must differ from plain hash due to domain tag.
        assert_ne!(leaf, plain);
    }

    #[test]
    fn test_poseidon2_leaf_vs_node_domain_separation() {
        // Leaf and node with same data must produce different hashes.
        let a = Hash256::from_bytes([1u8; 32]);
        let b = Hash256::from_bytes([2u8; 32]);
        let node = poseidon2_hash_node(&a, &b);

        // Construct equivalent leaf input (64 bytes = a || b).
        let mut leaf_data = [0u8; 64];
        leaf_data[..32].copy_from_slice(a.as_bytes());
        leaf_data[32..].copy_from_slice(b.as_bytes());
        let leaf = poseidon2_hash_leaf(&leaf_data);

        assert_ne!(leaf, node);
    }

    #[test]
    fn test_poseidon2_hash_node_domain_separation() {
        let a = Hash256::from_bytes([1u8; 32]);
        let b = Hash256::from_bytes([2u8; 32]);

        // poseidon2_compress and poseidon2_hash_node should differ
        // due to domain separation.
        let h1 = poseidon2_compress(&a, &b);
        let h2 = poseidon2_hash_node(&a, &b);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon2_hash_different_lengths() {
        let h1 = poseidon2_hash(b"abc");
        let h2 = poseidon2_hash(b"abcd");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_poseidon2_vs_sha256_different() {
        // Poseidon2 and SHA-256 should produce different outputs.
        let data = b"comparison test";
        let p2_hash = poseidon2_hash(data);
        let sha_hash = crate::hash::Hasher::hash(data);
        assert_ne!(p2_hash, sha_hash);
    }

    // ─── Padding collision regression tests ───

    #[test]
    fn test_poseidon2_no_padding_collision_3_vs_4_bytes() {
        // Ensure length-prefixed padding distinguishes b"abc" from b"abc\x01".
        let h1 = poseidon2_hash(b"abc");
        let h2 = poseidon2_hash(b"abc\x01");
        assert_ne!(
            h1, h2,
            "padding collision between 3 and 4 bytes"
        );
    }

    #[test]
    fn test_poseidon2_no_padding_collision_1_vs_2_bytes() {
        let h1 = poseidon2_hash(&[0x41]);
        let h2 = poseidon2_hash(&[0x41, 0x80]);
        assert_ne!(
            h1, h2,
            "padding collision between 1 and 2 bytes"
        );
    }

    #[test]
    fn test_poseidon2_no_padding_collision_2_vs_3_bytes() {
        let h1 = poseidon2_hash(&[0x41, 0x42]);
        let h2 = poseidon2_hash(&[0x41, 0x42, 0x80]);
        assert_ne!(
            h1, h2,
            "padding collision between 2 and 3 bytes"
        );
    }

    #[test]
    fn test_poseidon2_no_padding_collision_multiblock() {
        // 35-byte input vs 36-byte input where byte[35] matches old padding.
        let data35 = vec![0x42u8; 35];
        let mut data36 = vec![0x42u8; 36];
        data36[35] = 0x80;
        let h1 = poseidon2_hash(&data35);
        let h2 = poseidon2_hash(&data36);
        assert_ne!(h1, h2, "multiblock padding collision");
    }

    #[test]
    fn test_poseidon2_hash_leaf_no_padding_collision() {
        let h1 = poseidon2_hash_leaf(b"abc");
        let h2 = poseidon2_hash_leaf(b"abc\x80");
        assert_ne!(h1, h2, "leaf padding collision");
    }

    #[test]
    fn test_poseidon2_hash_leaf_handles_long_data() {
        // hash_leaf must absorb all data, not just the first 32 bytes.
        let data_a = vec![0x42u8; 64];
        let mut data_b = vec![0x42u8; 64];
        data_b[63] = 0x43; // differ only in last byte
        let h1 = poseidon2_hash_leaf(&data_a);
        let h2 = poseidon2_hash_leaf(&data_b);
        assert_ne!(
            h1, h2,
            "hash_leaf must process all bytes, not truncate at 32"
        );
    }

    // ─── M31 Edge Cases ───

    #[test]
    fn test_m31_zero_operations() {
        let z = M31::ZERO;
        let a = M31::new(42);
        assert_eq!(z.add(a).0, 42);
        assert_eq!(a.mul(z).0, 0);
        assert_eq!(z.pow5().0, 0);
    }

    #[test]
    fn test_m31_one_operations() {
        let one = M31::ONE;
        let a = M31::new(42);
        assert_eq!(a.mul(one).0, 42);
        assert_eq!(one.pow5().0, 1);
    }

    #[test]
    fn test_m31_large_multiplication() {
        // Test near-overflow: (p-1) * (p-1)
        let a = M31::new(M31_P - 1);
        let result = a.mul(a);
        // (p-1)^2 mod p = 1 (since p-1 ≡ -1 mod p, and (-1)^2 = 1)
        assert_eq!(result.0, 1);
    }

    #[test]
    fn test_m31_from_u32_injective() {
        // 0 and M31_P must produce different (rem, quot) pairs.
        let (r0, q0) = M31::from_u32_injective(0);
        let (rp, qp) = M31::from_u32_injective(M31_P);
        assert!(
            r0 != rp || q0 != qp,
            "from_u32_injective(0) and from_u32_injective(M31_P) must differ"
        );
        // 1 and M31_P+1 (= 0x80000000) must also differ.
        let (r1, q1) = M31::from_u32_injective(1);
        let (r1p, q1p) = M31::from_u32_injective(M31_P + 1);
        assert!(
            r1 != r1p || q1 != q1p,
            "from_u32_injective(1) and from_u32_injective(M31_P+1) must differ"
        );
    }

    #[test]
    fn test_poseidon2_hash_no_m31_collision() {
        // Two inputs that differ only in bytes that would collide under
        // naive mod-p reduction must produce different hashes.
        // 0x00000000 and 0xFFFFFF7F (little-endian for 0x7FFFFFFF = M31_P)
        // both map to M31(0) under M31::new().
        let mut input_a = [0u8; 4];
        let mut input_b = [0u8; 4];
        input_b.copy_from_slice(&M31_P.to_le_bytes()); // 0x7FFFFFFF in LE

        let h1 = poseidon2_hash(&input_a);
        let h2 = poseidon2_hash(&input_b);
        assert_ne!(h1, h2, "M31 reduction collision must be prevented by absorb_u32");

        // Also test with 1 vs 0x80000000 (= M31_P + 1, which reduces to 1)
        input_a.copy_from_slice(&1u32.to_le_bytes());
        input_b.copy_from_slice(&(M31_P + 1).to_le_bytes());
        let h3 = poseidon2_hash(&input_a);
        let h4 = poseidon2_hash(&input_b);
        assert_ne!(h3, h4, "M31 reduction collision for 1 vs M31_P+1");
    }
}
