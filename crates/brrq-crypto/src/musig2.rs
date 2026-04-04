//! MuSig2 — 2-round multi-party Schnorr signature aggregation on secp256k1.
//!
//! Follows the BIP-327 key aggregation scheme.
//!
//! ## Protocol overview
//!
//! **Key aggregation** (offline):
//! 1. Each signer provides their `SchnorrPublicKey` (x-only, 32 bytes).
//! 2. Keys are sorted lexicographically.
//! 3. A commitment `L = SHA-256("BRRQ_MUSIG2_KEYAGG_LIST" || pk1 || pk2 || ...)` is computed.
//! 4. Per-key coefficient: `a_i = SHA-256("BRRQ_MUSIG2_KEYAGG_COEF" || L || pk_i)`.
//! 5. Aggregate key: `Q = sum(a_i * P_i)`.
//!
//! **Round 1 — nonce generation**:
//! Each signer generates two secret nonces and publishes their public nonces.
//!
//! **Round 2 — partial signing**:
//! Each signer produces a partial signature using their secret nonce and the
//! aggregate nonce. The partial signatures are summed to form the final Schnorr sig.
//!
//! **Verification**:
//! The aggregated signature verifies against the aggregate key using standard BIP-340.
//!
//! Domain tags:
//! - `BRRQ_MUSIG2_KEYAGG_LIST` — key list commitment
//! - `BRRQ_MUSIG2_KEYAGG_COEF` — per-key coefficient
//! - `BRRQ_MUSIG2_NONCECOEF`   — nonce combination factor
//! - `BRRQ_MUSIG2_CHALLENGE`   — Schnorr challenge

use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use thiserror::Error;

use crate::hash::{Hash256, Hasher};
use crate::scalar;
use crate::schnorr::{SchnorrKeyPair, SchnorrPublicKey, SchnorrSignature};
use crate::sha256::tagged_hash;

// ── Domain tags ─────────────────────────────────────────────────────────────

const KEYAGG_LIST_TAG: &[u8] = crate::domain_tags::MUSIG2_KEYAGG_LIST;
const KEYAGG_COEF_TAG: &[u8] = crate::domain_tags::MUSIG2_KEYAGG_COEF;
const NONCE_COEF_TAG: &[u8] = crate::domain_tags::MUSIG2_NONCECOEF;
/// BIP-340 "BIP0340/challenge" tag used for the Schnorr challenge, so that
/// the final aggregated signature verifies under the standard BIP-340 verifier.
const BIP340_CHALLENGE_TAG: &str = "BIP0340/challenge";

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors from MuSig2 operations.
#[derive(Debug, Error)]
pub enum MuSig2Error {
    #[error("no public keys provided")]
    EmptyKeyList,
    #[error("duplicate public keys in the signer set")]
    DuplicateKeys,
    #[error("invalid or zero aggregate nonce")]
    InvalidNonce,
    #[error("invalid public key")]
    InvalidPublicKey,
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

// ── Public types ──────────────────────────────────────────────────────────────

/// Aggregate key produced by [`key_agg`].
///
/// Holds the aggregated x-only public key, per-signer coefficients, and
/// the sorted list of original signers (needed for coefficient lookup).
#[derive(Clone, Debug)]
pub struct AggregateKey {
    /// The aggregated x-only public key (Q).
    pub combined_key: SchnorrPublicKey,
    /// Per-signer coefficients `a_i`, parallel to `pubkeys`.
    pub key_agg_coefs: Vec<[u8; 32]>,
    /// Sorted original public keys.
    pub pubkeys: Vec<SchnorrPublicKey>,
}

/// A pair of secret nonces (consumed in Round 2 to prevent reuse).
///
/// Implements `Drop` with zeroization.
pub struct SecNonce {
    r1: [u8; 32],
    r2: [u8; 32],
}

impl Drop for SecNonce {
    fn drop(&mut self) {
        crate::zeroize::zeroize_bytes(&mut self.r1);
        crate::zeroize::zeroize_bytes(&mut self.r2);
    }
}

/// A pair of public nonces (`R1 = r1*G`, `R2 = r2*G`).
#[derive(Clone, Debug)]
pub struct PubNonce {
    /// 33-byte compressed point `r1 * G`.
    pub r1: [u8; 33],
    /// 33-byte compressed point `r2 * G`.
    pub r2: [u8; 33],
}

/// The aggregated nonce point `R` computed from all signers' public nonces.
#[derive(Clone, Debug)]
pub struct AggregateNonce {
    /// 33-byte compressed aggregate nonce point `R`.
    pub r: [u8; 33],
    /// The nonce combination factor `b` (needed by partial_sign).
    pub(crate) b: [u8; 32],
    /// `R1_agg` (33 bytes) — needed for b computation storage.
    #[allow(dead_code)]
    pub(crate) r1_agg: [u8; 33],
    /// `R2_agg` (33 bytes) — stored for partial signing.
    #[allow(dead_code)]
    pub(crate) r2_agg: [u8; 33],
}

/// A partial Schnorr signature from a single signer.
#[derive(Clone, Debug)]
pub struct PartialSignature {
    /// The partial s-value (32 bytes, big-endian).
    pub s: [u8; 32],
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Hash a list of 32-byte public keys with the key-list domain tag.
fn hash_key_list(sorted_keys: &[SchnorrPublicKey]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(KEYAGG_LIST_TAG);
    for pk in sorted_keys {
        hasher.update(pk.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// Compute the per-key coefficient: `a_i = SHA-256("BRRQ_MUSIG2_KEYAGG_COEF" || L || pk_i)`.
fn hash_key_coef(l: &[u8; 32], pk: &SchnorrPublicKey) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(KEYAGG_COEF_TAG);
    hasher.update(l);
    hasher.update(pk.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Sum secp256k1 points. Fails if the list is empty or all points cancel.
fn sum_points(
    _secp: &Secp256k1<secp256k1::All>,
    points: &[PublicKey],
) -> Result<PublicKey, MuSig2Error> {
    let refs: Vec<&PublicKey> = points.iter().collect();
    PublicKey::combine_keys(&refs).map_err(|_| MuSig2Error::InvalidNonce)
}

/// Multiply a full `PublicKey` by a scalar given as 32 big-endian bytes.
fn point_mul(
    secp: &Secp256k1<secp256k1::All>,
    point: &PublicKey,
    scalar_bytes: &[u8; 32],
) -> Result<PublicKey, MuSig2Error> {
    let scalar =
        secp256k1::Scalar::from_be_bytes(*scalar_bytes).map_err(|_| MuSig2Error::InvalidNonce)?;
    point
        .mul_tweak(secp, &scalar)
        .map_err(|_| MuSig2Error::InvalidNonce)
}

/// Generate a valid random 32-byte secret key scalar (nonzero and < n).
fn random_scalar() -> [u8; 32] {
    loop {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        if SecretKey::from_slice(&bytes).is_ok() {
            return bytes;
        }
    }
}

/// Compute the BIP-340 Schnorr challenge using the standard "BIP0340/challenge" tagged hash:
/// `e = tagged_hash("BIP0340/challenge", R_x(32) || Q_x(32) || msg(32))`
/// reduced mod n.
///
/// Using the BIP-340 tagged hash ensures the final aggregated signature verifies
/// under the standard `secp256k1::verify_schnorr` (and any BIP-340 verifier).
fn schnorr_challenge(r_x: &[u8; 32], q_x: &[u8; 32], msg: &Hash256) -> [u8; 32] {
    // BIP-340 challenge: tagged_hash("BIP0340/challenge", r_x || q_x || m)
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(r_x);
    data.extend_from_slice(q_x);
    data.extend_from_slice(msg.as_bytes());
    let digest = tagged_hash(BIP340_CHALLENGE_TAG, &data);
    let raw = scalar::from_bytes(digest.as_bytes());
    let reduced = scalar::add_mod(&raw, &[0u64; 4]);
    scalar::to_bytes(&reduced)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Aggregate public keys using BIP-327 key coefficients.
///
/// 1. Sort pubkeys lexicographically (byte order of the 32-byte x-only keys).
/// 2. `L = SHA-256("BRRQ_MUSIG2_KEYAGG_LIST" || pk1 || pk2 || ...)`.
/// 3. `a_i = SHA-256("BRRQ_MUSIG2_KEYAGG_COEF" || L || pk_i)` for each signer.
/// 4. `Q = sum(a_i * P_i)` using even-parity full public keys.
/// 5. Return x-only Q as `SchnorrPublicKey`.
pub fn key_agg(pubkeys: &[SchnorrPublicKey]) -> Result<AggregateKey, MuSig2Error> {
    if pubkeys.is_empty() {
        return Err(MuSig2Error::EmptyKeyList);
    }

    // Sort lexicographically
    let mut sorted = pubkeys.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    // Check for duplicates
    for i in 0..sorted.len().saturating_sub(1) {
        if sorted[i] == sorted[i + 1] {
            return Err(MuSig2Error::DuplicateKeys);
        }
    }

    let secp = Secp256k1::new();

    // L = hash of all sorted keys
    let l = hash_key_list(&sorted);

    // Compute coefficients and accumulate Q
    let mut coefs: Vec<[u8; 32]> = Vec::with_capacity(sorted.len());
    let mut weighted_points: Vec<PublicKey> = Vec::with_capacity(sorted.len());

    for pk in &sorted {
        let a = hash_key_coef(&l, pk);
        coefs.push(a);

        // Reconstruct full public key from x-only (try both parities)
        let xonly = secp256k1::XOnlyPublicKey::from_slice(pk.as_bytes())
            .map_err(|_| MuSig2Error::InvalidPublicKey)?;

        // Use even parity (BIP-340 convention for x-only keys)
        let pk_full = PublicKey::from_x_only_public_key(xonly, secp256k1::Parity::Even);

        // a_i * P_i
        let weighted = point_mul(&secp, &pk_full, &a)?;
        weighted_points.push(weighted);
    }

    // Q = sum of weighted points
    let q_point = sum_points(&secp, &weighted_points)?;

    // Convert to x-only
    let (q_xonly, _parity) = q_point.x_only_public_key();
    let combined_key = SchnorrPublicKey::from_bytes(q_xonly.serialize());

    Ok(AggregateKey {
        combined_key,
        key_agg_coefs: coefs,
        pubkeys: sorted,
    })
}

/// Generate a fresh nonce pair for Round 1.
///
/// Returns `(SecNonce, PubNonce)`. The `SecNonce` MUST be consumed in `partial_sign`
/// (it is moved in, preventing reuse).
///
/// `extra_input` can be the signer's index or any domain-specific randomness.
pub fn nonce_gen(
    keypair: &SchnorrKeyPair,
    msg: &Hash256,
    extra_input: &[u8],
) -> (SecNonce, PubNonce) {
    let secp = Secp256k1::new();

    // Mix RNG output with deterministic inputs (keypair, message, extra) for
    // hedged nonce generation. If the RNG fails, the secret key and message
    // still provide entropy. If the same (key, msg, extra) is re-used with
    // fresh RNG, a new nonce results — preventing catastrophic nonce reuse.
    let r1_bytes = {
        let mut hasher = Hasher::new();
        hasher.update(crate::domain_tags::MUSIG2_NONCE_GEN_R1);
        let mut rand_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rand_bytes);
        hasher.update(&rand_bytes);
        // Mix in secret key for deterministic backup
        let sk = keypair.secret_bytes();
        hasher.update(&*sk);
        // Mix in message for binding
        hasher.update(msg.as_bytes());
        hasher.update(extra_input);
        let digest = *hasher.finalize().as_bytes();
        // Reduce to a valid scalar
        if SecretKey::from_slice(&digest).is_ok() {
            digest
        } else {
            let fallback = Hasher::hash(&digest);
            if SecretKey::from_slice(fallback.as_bytes()).is_ok() {
                *fallback.as_bytes()
            } else {
                random_scalar()
            }
        }
    };

    let r2_bytes = {
        let mut hasher = Hasher::new();
        hasher.update(crate::domain_tags::MUSIG2_NONCE_GEN_R2);
        let mut rand_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rand_bytes);
        hasher.update(&rand_bytes);
        let sk = keypair.secret_bytes();
        hasher.update(&*sk);
        hasher.update(msg.as_bytes());
        hasher.update(extra_input);
        let digest = *hasher.finalize().as_bytes();
        if SecretKey::from_slice(&digest).is_ok() {
            digest
        } else {
            let fallback = Hasher::hash(&digest);
            if SecretKey::from_slice(fallback.as_bytes()).is_ok() {
                *fallback.as_bytes()
            } else {
                random_scalar()
            }
        }
    };

    let r1_sk =
        SecretKey::from_slice(&r1_bytes).expect("hedged nonce derivation returns valid key");
    let r2_sk =
        SecretKey::from_slice(&r2_bytes).expect("hedged nonce derivation returns valid key");

    let r1_pub = PublicKey::from_secret_key(&secp, &r1_sk).serialize();
    let r2_pub = PublicKey::from_secret_key(&secp, &r2_sk).serialize();

    (
        SecNonce {
            r1: r1_bytes,
            r2: r2_bytes,
        },
        PubNonce {
            r1: r1_pub,
            r2: r2_pub,
        },
    )
}

/// Aggregate all signers' public nonces.
///
/// Computes:
/// - `R1_agg = sum(R1_i)`, `R2_agg = sum(R2_i)`
/// - `b = SHA-256("BRRQ_MUSIG2_NONCECOEF" || R1_agg || R2_agg || Q_x || msg)` mod n
/// - `R = R1_agg + b * R2_agg`
///
/// The aggregate key `agg_key` and message `msg` are needed to bind the
/// nonce coefficient `b` to the signing session (prevents nonce malleation).
pub fn nonce_agg(
    pub_nonces: &[PubNonce],
    agg_key: &AggregateKey,
    msg: &Hash256,
) -> Result<AggregateNonce, MuSig2Error> {
    if pub_nonces.is_empty() {
        return Err(MuSig2Error::InvalidNonce);
    }

    let secp = Secp256k1::new();

    // Parse and sum R1 points
    let r1_points: Vec<PublicKey> = pub_nonces
        .iter()
        .map(|n| PublicKey::from_slice(&n.r1).map_err(|_| MuSig2Error::InvalidNonce))
        .collect::<Result<_, _>>()?;

    // Parse and sum R2 points
    let r2_points: Vec<PublicKey> = pub_nonces
        .iter()
        .map(|n| PublicKey::from_slice(&n.r2).map_err(|_| MuSig2Error::InvalidNonce))
        .collect::<Result<_, _>>()?;

    let r1_agg_point = sum_points(&secp, &r1_points)?;
    let r2_agg_point = sum_points(&secp, &r2_points)?;

    let r1_agg = r1_agg_point.serialize();
    let r2_agg = r2_agg_point.serialize();

    // b = SHA-256("BRRQ_MUSIG2_NONCECOEF" || R1_agg || R2_agg || Q_x || msg) mod n
    let b_bytes = {
        let mut hasher = Hasher::new();
        hasher.update(NONCE_COEF_TAG);
        hasher.update(&r1_agg);
        hasher.update(&r2_agg);
        hasher.update(agg_key.combined_key.as_bytes()); // Q_x (32 bytes)
        hasher.update(msg.as_bytes());
        let digest = hasher.finalize();
        let raw = scalar::from_bytes(digest.as_bytes());
        scalar::to_bytes(&scalar::add_mod(&raw, &[0u64; 4]))
    };

    // R = R1_agg + b * R2_agg
    let b_r2 = point_mul(&secp, &r2_agg_point, &b_bytes)?;
    let r_point = sum_points(&secp, &[r1_agg_point, b_r2])?;
    let r = r_point.serialize();

    Ok(AggregateNonce {
        r,
        b: b_bytes,
        r1_agg,
        r2_agg,
    })
}

/// Negate a scalar mod n: result = n - x.
fn negate_scalar(x: &scalar::U256) -> scalar::U256 {
    scalar::sub_mod(&scalar::SECP256K1_ORDER, x)
}

/// Check if a compressed 33-byte point has odd y-coordinate.
///
/// In compressed form: 0x02 = even y, 0x03 = odd y.
fn point_has_odd_y(compressed: &[u8; 33]) -> bool {
    compressed[0] == 0x03
}

/// Produce a partial signature (Round 2).
///
/// Consumes `sec_nonce` to prevent reuse (Rust move semantics).
///
/// Three BIP-340 parity adjustments are required for standard Schnorr verification:
///
/// 1. **Individual key parity**: Key aggregation uses even-parity public keys.
///    If signer i's actual pk has odd y, the aggregation used `-P_i = (-sk_i)*G`,
///    so signer i must use `-sk_i` in the signing equation.
///
/// 2. **Aggregate Q parity**: BIP-340 verifier reconstructs Q with even y.
///    If the true aggregate Q has odd y, it is stored as `-Q` with even y,
///    so all signers must negate their (already parity-adjusted) sk contributions.
///
/// 3. **Nonce R parity**: BIP-340 requires R to have even y at signing time.
///    If the aggregate R has odd y, all signers negate their nonce contributions.
///    The x-coordinate is unchanged (negating a point preserves x).
///
/// Partial signature: `s_i = r_eff_i + e * a_i * sk_eff_i  mod n`
pub fn partial_sign(
    keypair: &SchnorrKeyPair,
    sec_nonce: SecNonce, // consumed — prevents nonce reuse
    agg_nonce: &AggregateNonce,
    agg_key: &AggregateKey,
    msg: &Hash256,
) -> Result<PartialSignature, MuSig2Error> {
    let secp = Secp256k1::new();

    // Extract r1, r2 from sec_nonce (SecNonce's Drop impl zeroizes the original)
    let mut r1_bytes = sec_nonce.r1;
    let mut r2_bytes = sec_nonce.r2;

    // Combined nonce scalar: r = r1 + b * r2  mod n
    let r1_scalar = scalar::from_bytes(&r1_bytes);
    let r2_scalar = scalar::from_bytes(&r2_bytes);

    // Zeroize the local copies of secret nonce bytes immediately after use
    crate::zeroize::zeroize_bytes(&mut r1_bytes);
    crate::zeroize::zeroize_bytes(&mut r2_bytes);

    let b_scalar = scalar::from_bytes(&agg_nonce.b);
    let b_r2 = scalar::mul_mod(&b_scalar, &r2_scalar);
    let mut r_nonce_scalar = scalar::add_mod(&r1_scalar, &b_r2);

    // Parity fix 3: negate nonce scalar if R.y is odd.
    if point_has_odd_y(&agg_nonce.r) {
        r_nonce_scalar = negate_scalar(&r_nonce_scalar);
    }

    // e = BIP-340 challenge(R_x || Q_x || msg)
    // SAFETY: agg_nonce.r is [u8; 33], so r[1..] is always exactly 32 bytes.
    let r_x: [u8; 32] = agg_nonce.r[1..]
        .try_into()
        .expect("r is [u8;33]; r[1..] is 32");
    let q_x = agg_key.combined_key.0;
    let e_bytes = schnorr_challenge(&r_x, &q_x, msg);
    let e_scalar = scalar::from_bytes(&e_bytes);

    // Find this signer's coefficient a_i by matching x-only public key
    let my_pk = keypair.public_key();
    let coef_idx = agg_key
        .pubkeys
        .iter()
        .position(|pk| pk == my_pk)
        .ok_or(MuSig2Error::InvalidPublicKey)?;
    let a_bytes = agg_key.key_agg_coefs[coef_idx];
    let a_scalar = scalar::from_bytes(&a_bytes);

    // Get the raw secret key bytes and reconstruct the actual full public key
    let sk_secret = keypair.secret_bytes();
    let mut sk_scalar = scalar::from_bytes(&sk_secret);
    let sk_secp = SecretKey::from_slice(&*sk_secret).map_err(|_| MuSig2Error::InvalidPublicKey)?;
    let my_pk_full = PublicKey::from_secret_key(&secp, &sk_secp);
    let my_pk_full_bytes = my_pk_full.serialize();

    // Parity fix 1: negate sk if this signer's actual pk has odd y.
    // Key aggregation used P_i_even = -P_i_actual when P_i_actual.y is odd,
    // so the signer must use -sk to match.
    if point_has_odd_y(&my_pk_full_bytes) {
        sk_scalar = negate_scalar(&sk_scalar);
    }

    // Parity fix 2: negate sk if the true aggregate Q has odd y.
    // Re-sum all a_i * P_i_even to find the true Q with its actual parity.
    // The BIP-340 verifier uses Q_even (even y), so if Q.y is odd we need -sk.
    {
        let mut weighted: Vec<PublicKey> = Vec::with_capacity(agg_key.pubkeys.len());
        for (pk_sorted, coef) in agg_key.pubkeys.iter().zip(agg_key.key_agg_coefs.iter()) {
            let xonly = secp256k1::XOnlyPublicKey::from_slice(pk_sorted.as_bytes())
                .map_err(|_| MuSig2Error::InvalidPublicKey)?;
            let pk_full = PublicKey::from_x_only_public_key(xonly, secp256k1::Parity::Even);
            let c =
                secp256k1::Scalar::from_be_bytes(*coef).map_err(|_| MuSig2Error::InvalidNonce)?;
            let wp = pk_full
                .mul_tweak(&secp, &c)
                .map_err(|_| MuSig2Error::InvalidPublicKey)?;
            weighted.push(wp);
        }
        let refs: Vec<&PublicKey> = weighted.iter().collect();
        let q_true = PublicKey::combine_keys(&refs).map_err(|_| MuSig2Error::InvalidPublicKey)?;
        let q_true_bytes = q_true.serialize();
        if point_has_odd_y(&q_true_bytes) {
            sk_scalar = negate_scalar(&sk_scalar);
        }
    }

    // s_i = r_eff + e * a_i * sk_eff  mod n
    let e_a = scalar::mul_mod(&e_scalar, &a_scalar);
    let e_a_sk = scalar::mul_mod(&e_a, &sk_scalar);
    let s_scalar = scalar::add_mod(&r_nonce_scalar, &e_a_sk);
    let s_bytes = scalar::to_bytes(&s_scalar);

    Ok(PartialSignature { s: s_bytes })
}

/// Aggregate partial signatures into a final Schnorr signature.
///
/// `s = sum(s_i)  mod n`
/// The signature is `(R_x, s)` in BIP-340 format (64 bytes):
/// - first 32 bytes: x-coordinate of R
/// - last  32 bytes: s
pub fn partial_sig_agg(
    partial_sigs: &[PartialSignature],
    agg_nonce: &AggregateNonce,
) -> SchnorrSignature {
    // Sum all partial s-values mod n
    let mut s_sum = [0u64; 4];
    for ps in partial_sigs {
        let s = scalar::from_bytes(&ps.s);
        s_sum = scalar::add_mod(&s_sum, &s);
    }
    let s_bytes = scalar::to_bytes(&s_sum);

    // BIP-340 sig = R_x (32 bytes) || s (32 bytes)
    // SAFETY: agg_nonce.r is [u8; 33], so r[1..] is always exactly 32 bytes.
    let r_x: [u8; 32] = agg_nonce.r[1..]
        .try_into()
        .expect("r is [u8;33]; r[1..] is 32");
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_x);
    sig_bytes[32..].copy_from_slice(&s_bytes);

    SchnorrSignature::from_bytes(sig_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hasher;
    use crate::schnorr::{self, SchnorrKeyPair};

    fn make_keypair(seed: u8) -> SchnorrKeyPair {
        SchnorrKeyPair::from_secret_bytes(&[seed; 32]).unwrap()
    }

    fn test_msg() -> Hash256 {
        Hasher::hash(b"MuSig2 test message for brrq protocol")
    }

    fn musig2_sign(keypairs: &[SchnorrKeyPair], msg: &Hash256) -> (AggregateKey, SchnorrSignature) {
        let pubkeys: Vec<SchnorrPublicKey> = keypairs.iter().map(|kp| *kp.public_key()).collect();
        let agg_key = key_agg(&pubkeys).unwrap();

        // Round 1: each signer generates a nonce
        let nonce_pairs: Vec<(SecNonce, PubNonce)> =
            keypairs.iter().map(|kp| nonce_gen(kp, msg, b"")).collect();

        let pub_nonces: Vec<PubNonce> = nonce_pairs.iter().map(|(_, pn)| pn.clone()).collect();
        let sec_nonces: Vec<SecNonce> = nonce_pairs.into_iter().map(|(sn, _)| sn).collect();

        // Aggregate nonces
        let agg_nonce = nonce_agg(&pub_nonces, &agg_key, msg).unwrap();

        // Round 2: each signer produces a partial signature
        let partial_sigs: Vec<PartialSignature> = sec_nonces
            .into_iter()
            .zip(keypairs.iter())
            .map(|(sn, kp)| partial_sign(kp, sn, &agg_nonce, &agg_key, msg).unwrap())
            .collect();

        // Aggregate partial signatures
        let sig = partial_sig_agg(&partial_sigs, &agg_nonce);

        (agg_key, sig)
    }

    #[test]
    fn test_musig2_two_party_sign_verify() {
        let kp1 = make_keypair(0x01);
        let kp2 = make_keypair(0x02);
        let msg = test_msg();

        let (agg_key, sig) = musig2_sign(&[kp1, kp2], &msg);

        // The aggregated signature must verify under the aggregated key
        schnorr::verify(&agg_key.combined_key, &msg, &sig)
            .expect("2-party MuSig2 signature must verify");
    }

    #[test]
    fn test_musig2_three_party_sign_verify() {
        let kp1 = make_keypair(0x11);
        let kp2 = make_keypair(0x22);
        let kp3 = make_keypair(0x33);
        let msg = test_msg();

        let (agg_key, sig) = musig2_sign(&[kp1, kp2, kp3], &msg);

        schnorr::verify(&agg_key.combined_key, &msg, &sig)
            .expect("3-party MuSig2 signature must verify");
    }

    #[test]
    fn test_musig2_key_agg_deterministic() {
        let kp1 = make_keypair(0x01);
        let kp2 = make_keypair(0x02);
        let pubkeys = vec![*kp1.public_key(), *kp2.public_key()];

        let agg1 = key_agg(&pubkeys).unwrap();
        let agg2 = key_agg(&pubkeys).unwrap();

        assert_eq!(
            agg1.combined_key, agg2.combined_key,
            "key_agg must be deterministic"
        );
    }

    #[test]
    fn test_musig2_wrong_message_fails() {
        let kp1 = make_keypair(0x01);
        let kp2 = make_keypair(0x02);
        let msg = test_msg();
        let wrong_msg = Hasher::hash(b"wrong message");

        let (agg_key, sig) = musig2_sign(&[kp1, kp2], &msg);

        let result = schnorr::verify(&agg_key.combined_key, &wrong_msg, &sig);
        assert!(
            result.is_err(),
            "MuSig2 signature must not verify for wrong message"
        );
    }

    #[test]
    fn test_musig2_key_agg_order_independent() {
        let kp1 = make_keypair(0x01);
        let kp2 = make_keypair(0x02);
        let kp3 = make_keypair(0x03);

        let pk1 = *kp1.public_key();
        let pk2 = *kp2.public_key();
        let pk3 = *kp3.public_key();

        // Different orderings
        let agg_abc = key_agg(&[pk1, pk2, pk3]).unwrap();
        let agg_cba = key_agg(&[pk3, pk2, pk1]).unwrap();
        let agg_bca = key_agg(&[pk2, pk3, pk1]).unwrap();

        assert_eq!(
            agg_abc.combined_key, agg_cba.combined_key,
            "key_agg must be order-independent (abc vs cba)"
        );
        assert_eq!(
            agg_abc.combined_key, agg_bca.combined_key,
            "key_agg must be order-independent (abc vs bca)"
        );
    }

    #[test]
    fn test_musig2_empty_key_list_fails() {
        let result = key_agg(&[]);
        assert!(matches!(result, Err(MuSig2Error::EmptyKeyList)));
    }

    #[test]
    fn test_musig2_duplicate_keys_fail() {
        let kp = make_keypair(0x01);
        let pk = *kp.public_key();

        let result = key_agg(&[pk, pk]);
        assert!(matches!(result, Err(MuSig2Error::DuplicateKeys)));
    }

    #[test]
    fn test_musig2_single_signer_sign_verify() {
        // Single-signer MuSig2 degenerates to a scalar-weighted Schnorr sig.
        let kp = make_keypair(0x55);
        let msg = test_msg();

        let (agg_key, sig) = musig2_sign(&[kp], &msg);

        schnorr::verify(&agg_key.combined_key, &msg, &sig).expect("1-party MuSig2 must verify");
    }

    #[test]
    fn test_musig2_partial_sigs_are_different() {
        let kp1 = make_keypair(0x01);
        let kp2 = make_keypair(0x02);
        let msg = test_msg();
        let pubkeys = vec![*kp1.public_key(), *kp2.public_key()];
        let agg_key = key_agg(&pubkeys).unwrap();

        let (sn1, pn1) = nonce_gen(&kp1, &msg, b"");
        let (sn2, pn2) = nonce_gen(&kp2, &msg, b"");
        let agg_nonce = nonce_agg(&[pn1, pn2], &agg_key, &msg).unwrap();

        let ps1 = partial_sign(&kp1, sn1, &agg_nonce, &agg_key, &msg).unwrap();
        let ps2 = partial_sign(&kp2, sn2, &agg_nonce, &agg_key, &msg).unwrap();

        assert_ne!(
            ps1.s, ps2.s,
            "partial signatures from different signers must differ"
        );
    }
}
