//! 256-bit modular arithmetic on the secp256k1 scalar field.
//!
//! Operations are performed modulo the secp256k1 curve order `n`.
//! Scalars are represented as `[u64; 4]` in big-endian limb order
//! (limb 0 is the most significant).

/// Type alias for 256-bit scalar (big-endian limb order).
pub type U256 = [u64; 4];

/// The secp256k1 curve order n.
/// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
pub const SECP256K1_ORDER: U256 = [
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFE,
    0xBAAEDCE6AF48A03B,
    0xBFD25E8CD0364141,
];

/// Convert big-endian bytes to U256.
pub fn from_bytes(b: &[u8; 32]) -> U256 {
    // SAFETY: input is &[u8; 32], so each 8-byte slice is infallible.
    [
        u64::from_be_bytes(
            b[0..8]
                .try_into()
                .expect("infallible: 8-byte slice from [u8; 32]"),
        ),
        u64::from_be_bytes(
            b[8..16]
                .try_into()
                .expect("infallible: 8-byte slice from [u8; 32]"),
        ),
        u64::from_be_bytes(
            b[16..24]
                .try_into()
                .expect("infallible: 8-byte slice from [u8; 32]"),
        ),
        u64::from_be_bytes(
            b[24..32]
                .try_into()
                .expect("infallible: 8-byte slice from [u8; 32]"),
        ),
    ]
}

/// Convert U256 to big-endian bytes.
pub fn to_bytes(v: &U256) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&v[0].to_be_bytes());
    b[8..16].copy_from_slice(&v[1].to_be_bytes());
    b[16..24].copy_from_slice(&v[2].to_be_bytes());
    b[24..32].copy_from_slice(&v[3].to_be_bytes());
    b
}

/// Constant-time comparison of two U256 values.
///
/// Returns 1 if a >= b, 0 if a < b. Processes all 4 limbs regardless
/// of intermediate results to prevent timing side-channels.
fn ct_ge(a: &U256, b: &U256) -> u64 {
    // Walk from MSB to LSB. At each limb, determine if a>b, a<b, or a==b.
    // `gt` accumulates "a is greater at some higher limb" (and no lower limb has decided otherwise).
    // `lt` accumulates "a is less at some higher limb".
    // We use branchless arithmetic throughout.
    let mut gt: u64 = 0; // 1 if we've seen a[i] > b[i] at the most significant differing limb
    let mut lt: u64 = 0; // 1 if we've seen a[i] < b[i] at the most significant differing limb
    for i in 0..4 {
        // For each limb: is a[i] > b[i]? is a[i] < b[i]?
        let a_gt_b = ct_gt_u64(a[i], b[i]);
        let a_lt_b = ct_gt_u64(b[i], a[i]);
        // Only update if no prior limb has decided the comparison
        let undecided = 1 - (gt | lt);
        gt |= a_gt_b & undecided;
        lt |= a_lt_b & undecided;
    }
    // a >= b iff NOT (a < b)
    1 - lt
}

/// Constant-time: returns 1 if a > b, 0 otherwise. No branches.
#[inline]
fn ct_gt_u64(a: u64, b: u64) -> u64 {
    // (b - a) borrows iff a > b.
    let (_, borrow) = b.overflowing_sub(a);
    borrow as u64
}

/// Add two U256, returning (result, carry).
fn add_raw(a: &U256, b: &U256) -> (U256, bool) {
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in (0..4).rev() {
        let (sum, c1) = a[i].overflowing_add(b[i]);
        let (sum, c2) = sum.overflowing_add(carry);
        result[i] = sum;
        carry = (c1 as u64) + (c2 as u64);
    }
    (result, carry > 0)
}

/// Subtract two U256, returning (result, borrow).
fn sub_raw(a: &U256, b: &U256) -> (U256, bool) {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in (0..4).rev() {
        let (diff, b1) = a[i].overflowing_sub(b[i]);
        let (diff, b2) = diff.overflowing_sub(borrow);
        result[i] = diff;
        borrow = (b1 as u64) + (b2 as u64);
    }
    (result, borrow > 0)
}

/// Constant-time reduction modulo n (assumes value < 2n).
///
/// Always computes the subtraction, then uses ct_select to pick
/// the result without branching on the comparison.
fn reduce(v: &U256) -> U256 {
    let (subtracted, _) = sub_raw(v, &SECP256K1_ORDER);
    let ge = ct_ge(v, &SECP256K1_ORDER); // 1 if v >= n
    ct_select(v, &subtracted, ge)
}

/// Constant-time addition modulo n.
///
/// Reduces inputs first to handle values >= n (e.g., raw hash bytes).
/// Always computes both the sum and the reduced result, then
/// selects based on carry and comparison without branching.
pub fn add_mod(a: &U256, b: &U256) -> U256 {
    let a = reduce(a);
    let b = reduce(b);
    let (sum, carry) = add_raw(&a, &b);
    let (subtracted, _) = sub_raw(&sum, &SECP256K1_ORDER);
    // Need to subtract if carry occurred OR sum >= n
    let needs_sub = carry as u64 | ct_ge(&sum, &SECP256K1_ORDER);
    ct_select(&sum, &subtracted, needs_sub)
}

/// Constant-time subtraction modulo n.
///
/// Reduces inputs first to handle values >= n.
pub fn sub_mod(a: &U256, b: &U256) -> U256 {
    let a = reduce(a);
    let b = reduce(b);
    let (diff, borrow) = sub_raw(&a, &b);
    let (wrapped, _) = add_raw(&diff, &SECP256K1_ORDER);
    ct_select(&diff, &wrapped, borrow as u64)
}

/// Multiply two scalars modulo n.
///
/// Uses the double-and-add method with constant-time conditional selection
/// to avoid leaking bits of the multiplier via timing side channels.
pub fn mul_mod(a: &U256, b: &U256) -> U256 {
    let mut result = [0u64; 4];
    let mut current = reduce(a);
    let b_reduced = reduce(b);

    // Iterate over bits of b from LSB to MSB
    for word_idx in (0..4).rev() {
        for bit in 0..64 {
            // Always compute the addition, then conditionally select
            // to ensure constant-time execution regardless of bit value.
            let sum = add_mod(&result, &current);
            let flag = ((b_reduced[word_idx] >> bit) & 1) as u64;
            // Constant-time select: result = flag ? sum : result
            result = ct_select(&result, &sum, flag);
            current = add_mod(&current, &current); // double
        }
    }
    result
}

/// Modular exponentiation: base^exp mod n.
///
/// Uses square-and-multiply with constant-time conditional selection.
fn pow_mod(base: &U256, exp: &U256) -> U256 {
    let mut result: U256 = [0, 0, 0, 1]; // 1
    let mut current = reduce(base);

    for word_idx in (0..4).rev() {
        for bit in 0..64 {
            // Always compute the multiplication, then conditionally select.
            let product = mul_mod(&result, &current);
            let flag = (exp[word_idx] >> bit) & 1;
            result = ct_select(&result, &product, flag);
            current = mul_mod(&current, &current); // square
        }
    }
    result
}

/// Constant-time zero check: returns 1 if all limbs are zero, 0 otherwise.
/// Does not branch on the input value.
fn ct_is_zero(a: &U256) -> u64 {
    // OR all limbs together; result is 0 iff all limbs are 0
    let or = a[0] | a[1] | a[2] | a[3];
    // Convert nonzero → 0, zero → 1 without branching.
    // If or == 0, wrapping_sub(1) overflows to u64::MAX, right-shifting by 63 gives 0.
    // If or != 0, (or - 1) does NOT set the high bit (since or <= u64::MAX),
    // but we need a different approach: use the fact that (or | or.wrapping_neg()) >> 63
    // gives 1 when or != 0 and 0 when or == 0.
    let nonzero = (or | or.wrapping_neg()) >> 63; // 1 if nonzero, 0 if zero
    1 - nonzero
}

/// Constant-time conditional select: returns `b` if flag == 1, `a` if flag == 0.
/// `flag` must be 0 or 1. Does not branch on `flag`.
fn ct_select(a: &U256, b: &U256, flag: u64) -> U256 {
    let mask = flag.wrapping_neg(); // 0 → 0x0000..., 1 → 0xFFFF...
    [
        a[0] ^ (mask & (a[0] ^ b[0])),
        a[1] ^ (mask & (a[1] ^ b[1])),
        a[2] ^ (mask & (a[2] ^ b[2])),
        a[3] ^ (mask & (a[3] ^ b[3])),
    ]
}

/// Modular inverse: a^(-1) mod n.
///
/// Uses Fermat's little theorem: a^(-1) = a^(n-2) mod n.
/// Returns None if `a` is zero mod n.
pub fn inv_mod(a: &U256) -> Option<U256> {
    let a_reduced = reduce(a);

    // Constant-time zero check: always compute the inverse, then decide.
    // This prevents timing leakage of whether the input was zero.
    let is_zero = ct_is_zero(&a_reduced);

    // n - 2
    let n_minus_2 = {
        let two: U256 = [0, 0, 0, 2];
        let (result, _) = sub_raw(&SECP256K1_ORDER, &two);
        result
    };
    let result = pow_mod(&a_reduced, &n_minus_2);

    // Return None if input was zero, Some(result) otherwise.
    // The pow_mod computation runs regardless to maintain constant time.
    if is_zero == 1 { None } else { Some(result) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_mod_basic() {
        let a: U256 = [0, 0, 0, 100];
        let b: U256 = [0, 0, 0, 200];
        let result = add_mod(&a, &b);
        assert_eq!(result, [0, 0, 0, 300]);
    }

    #[test]
    fn test_sub_mod_basic() {
        let a: U256 = [0, 0, 0, 300];
        let b: U256 = [0, 0, 0, 100];
        let result = sub_mod(&a, &b);
        assert_eq!(result, [0, 0, 0, 200]);
    }

    #[test]
    fn test_sub_mod_underflow() {
        let a: U256 = [0, 0, 0, 1];
        let b: U256 = [0, 0, 0, 2];
        let result = sub_mod(&a, &b);
        // Should be n - 1
        let expected = sub_mod(&SECP256K1_ORDER, &[0, 0, 0, 1]);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_mul_mod_basic() {
        let a: U256 = [0, 0, 0, 7];
        let b: U256 = [0, 0, 0, 6];
        let result = mul_mod(&a, &b);
        assert_eq!(result, [0, 0, 0, 42]);
    }

    #[test]
    fn test_inverse() {
        // a * a^(-1) should equal 1
        let a: U256 = [0, 0, 0, 42];
        let a_inv = inv_mod(&a).unwrap();
        let product = mul_mod(&a, &a_inv);
        assert_eq!(product, [0, 0, 0, 1]);
    }

    #[test]
    fn test_inverse_large() {
        // Test with a larger value
        let a: U256 = [0x12345678, 0x9abcdef0, 0x11223344, 0x55667788];
        let a_inv = inv_mod(&a).unwrap();
        let product = mul_mod(&a, &a_inv);
        assert_eq!(product, [0, 0, 0, 1]);
    }

    #[test]
    fn test_inverse_zero() {
        let a: U256 = [0, 0, 0, 0];
        assert_eq!(inv_mod(&a), None);

        // n mod n is 0, so inv_mod(n) should also be None
        assert_eq!(inv_mod(&SECP256K1_ORDER), None);
    }

    #[test]
    fn test_roundtrip_bytes() {
        let bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let scalar = from_bytes(&bytes);
        let recovered = to_bytes(&scalar);
        assert_eq!(bytes, recovered);
    }

    #[test]
    fn test_add_mod_wraps() {
        // n-1 + 1 should be 0
        let n_minus_1 = sub_mod(&SECP256K1_ORDER, &[0, 0, 0, 1]);
        let one: U256 = [0, 0, 0, 1];
        let result = add_mod(&n_minus_1, &one);
        assert_eq!(result, [0, 0, 0, 0]);
    }
}
