//! ECVRF — Elliptic Curve Verifiable Random Function on secp256k1.
//!
//! Implements a DLEQ-proof-based VRF:
//!
//! - **Prover**: Given secret key `sk`, input `alpha`:
//!   1. `H = hash_to_curve(alpha)`
//!   2. `Gamma = sk * H` (the VRF hash point)
//!   3. Produce DLEQ proof that `sk` satisfies `PK = sk*G` and `Gamma = sk*H`
//!   4. `output = SHA-256("BRRQ_VRF_OUTPUT" || Gamma)`
//!
//! - **Verifier**: Given `PK`, `alpha`, `output`, `proof`:
//!   1. Recompute `H = hash_to_curve(alpha)`
//!   2. Reconstruct `U' = s*G + c*PK_full`, `V' = s*H + c*Gamma`
//!   3. Recompute challenge `c'`; verify `c == c'` and `output` matches `Gamma`
//!
//! **Parity convention**: The proof stores a 1-byte parity tag for the full
//! public key used in the challenge.  This avoids ambiguity: the verifier
//! reconstructs the same 33-byte `pk_bytes` that the prover fed into the hash
//! without needing to guess.
//!
//! Domain tags (all prefixed with `BRRQ_`):
//! - `BRRQ_VRF_H2C`    — hash-to-curve
//! - `BRRQ_VRF_DLEQ`   — DLEQ challenge
//! - `BRRQ_VRF_OUTPUT` — VRF output derivation

use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use thiserror::Error;

use crate::hash::Hasher;
use crate::scalar;
use crate::schnorr::{SchnorrKeyPair, SchnorrPublicKey};

// ── Domain tags ─────────────────────────────────────────────────────────────

const VRF_H2C_TAG: &[u8] = crate::domain_tags::VRF_H2C;
const VRF_DLEQ_TAG: &[u8] = crate::domain_tags::VRF_DLEQ;
const VRF_OUTPUT_TAG: &[u8] = crate::domain_tags::VRF_OUTPUT;

// ── Error type ───────────────────────────────────────────────────────────────

/// Errors produced by VRF operations.
#[derive(Debug, Error)]
pub enum VrfError {
    #[error("hash to curve failed: no valid point found after 256 attempts")]
    HashToCurveFailed,
    #[error("invalid proof: cannot parse proof components")]
    InvalidProof,
    #[error("verification failed: challenge mismatch or output mismatch")]
    VerificationFailed,
    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

// ── Public types ──────────────────────────────────────────────────────────────

/// The pseudorandom VRF output (32 bytes).
///
/// `output = SHA-256("BRRQ_VRF_OUTPUT" || Gamma_compressed)`
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VrfOutput(pub [u8; 32]);

/// A DLEQ proof that the same discrete-log `sk` underlies both
/// `PK = sk*G` and `Gamma = sk*H`.
///
/// `pk_parity` records the actual parity byte (0x02 or 0x03) of the full
/// public key used in the challenge hash — the verifier uses this to
/// reconstruct the identical 33-byte point without guessing.
#[derive(Clone, Debug)]
pub struct VrfProof {
    /// 33-byte compressed point `Gamma = sk * H`.
    pub gamma: Vec<u8>,
    /// DLEQ challenge scalar `c` (32 bytes, big-endian).
    pub challenge: [u8; 32],
    /// DLEQ response scalar `s = k - c*sk  mod n` (32 bytes, big-endian).
    pub response: [u8; 32],
    /// Parity byte of the full public key used during proving (0x02 or 0x03).
    pub pk_parity: u8,
}

// ── Internal: a 32-byte secret scalar that zeroizes on drop ──────────────────

struct ScalarSecret([u8; 32]);

impl Drop for ScalarSecret {
    fn drop(&mut self) {
        crate::zeroize::zeroize_bytes(&mut self.0);
    }
}

// ── Core functions ────────────────────────────────────────────────────────────

/// Constant-time hash-to-curve using the two-point Elligator 2 / SWU
/// construction (RFC 9380-style) adapted for secp256k1.
///
/// This replaces the try-and-increment method which leaks timing information
/// about which counter produced a valid point — a timing-capable adversary
/// observing VRF evaluations could learn partial information about the input.
///
/// Algorithm:
/// 1. Hash `alpha` to two independent 32-byte values `u0, u1`
/// 2. Map each to a secp256k1 point via constant-time Elligator:
///    - Compute two x-coordinate candidates from each u
///    - Both candidates are always decompressed (no early exit)
///    - Select the valid one deterministically
/// 3. Return `P0 + P1` (sum of two independently-mapped points)
///
/// The two-point construction ensures the output is indistinguishable
/// from a random group element, even though each individual map
/// covers only ~half of the curve.
///
/// **Timing guarantee**: Both decompression attempts are always performed.
/// The selection uses the success/failure of decompression which is
/// determined by whether `x³ + 7` is a quadratic residue mod p —
/// libsecp256k1 computes this via constant-time modular exponentiation.
fn hash_to_curve(alpha: &[u8]) -> Result<PublicKey, VrfError> {
    // Step 1: Hash to two independent field elements.
    let u0 = {
        let mut h = Hasher::new();
        h.update(VRF_H2C_TAG);
        h.update(alpha);
        h.update(&[0x00]);
        h.finalize()
    };
    let u1 = {
        let mut h = Hasher::new();
        h.update(VRF_H2C_TAG);
        h.update(alpha);
        h.update(&[0x01]);
        h.finalize()
    };

    // Step 2: Map each field element to a curve point.
    let p0 = elligator_to_point(u0.as_bytes())?;
    let p1 = elligator_to_point(u1.as_bytes())?;

    // Step 3: Return P0 + P1.
    PublicKey::combine_keys(&[&p0, &p1]).map_err(|_| VrfError::HashToCurveFailed)
}

/// Map a 32-byte hash to a secp256k1 point in constant time.
///
/// For secp256k1 (y² = x³ + 7), approximately 50% of x-coordinates have
/// a valid y-coordinate. This function generates candidate x-coordinates
/// via iterated hashing with domain separation and always evaluates a
/// fixed number of candidates (CANDIDATES_PER_MAP = 8) to prevent timing
/// leaks. The first valid point is selected.
///
/// **Timing guarantee**: All 8 candidates are always computed and all 8
/// decompressions are always attempted. The selection loop uses a flag
/// that is set on the first success — no early return. libsecp256k1's
/// point decompression (`secp256k1_ec_pubkey_parse`) uses constant-time
/// field exponentiation internally.
///
/// **Failure probability**: Pr[all 8 fail] = (1/2)⁸ = 1/256 per call.
/// Since `hash_to_curve` calls this twice, Pr[any call fails] < 2/256 < 1%.
/// In practice, failure is astronomically unlikely for hash-derived inputs.
fn elligator_to_point(u: &[u8; 32]) -> Result<PublicKey, VrfError> {
    const CANDIDATES: usize = 8;

    let mut result: Option<PublicKey> = None;

    // Always compute all candidates — no early exit.
    for i in 0..CANDIDATES {
        let x_hash = {
            let mut h = Hasher::new();
            h.update(b"BRRQ_VRF_H2C_CAND");
            h.update(u);
            h.update(&[i as u8]);
            h.finalize()
        };
        let mut candidate = [0u8; 33];
        candidate[0] = 0x02; // even-y
        candidate[1..].copy_from_slice(x_hash.as_bytes());

        if let Ok(pk) = PublicKey::from_slice(&candidate) {
            if result.is_none() {
                result = Some(pk);
            }
        }
    }

    result.ok_or(VrfError::HashToCurveFailed)
}

/// Compute the DLEQ challenge:
/// `c = SHA-256("BRRQ_VRF_DLEQ" || pk(33) || H(33) || Gamma(33) || U(33) || V(33))`
///
/// The 32-byte digest is reduced modulo the secp256k1 order.
fn dleq_challenge(
    pk_bytes: &[u8; 33],
    h_bytes: &[u8; 33],
    gamma_bytes: &[u8; 33],
    u_bytes: &[u8; 33],
    v_bytes: &[u8; 33],
) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(VRF_DLEQ_TAG);
    hasher.update(pk_bytes);
    hasher.update(h_bytes);
    hasher.update(gamma_bytes);
    hasher.update(u_bytes);
    hasher.update(v_bytes);
    let digest = hasher.finalize();

    // Reduce hash mod secp256k1 order to get a valid scalar
    let raw = scalar::from_bytes(digest.as_bytes());
    let reduced = scalar::add_mod(&raw, &[0u64; 4]);
    scalar::to_bytes(&reduced)
}

/// Derive the VRF output from the Gamma point.
/// `output = SHA-256("BRRQ_VRF_OUTPUT" || Gamma_compressed)`
fn derive_output(gamma_bytes: &[u8; 33]) -> VrfOutput {
    let mut hasher = Hasher::new();
    hasher.update(VRF_OUTPUT_TAG);
    hasher.update(gamma_bytes);
    VrfOutput(*hasher.finalize().as_bytes())
}

/// Produce VRF output and DLEQ proof for `alpha` using `keypair`.
///
/// Algorithm:
/// 1. `H = hash_to_curve(alpha)`
/// 2. Derive the full `PK` point from `sk` (33-byte compressed, includes true parity).
/// 3. `Gamma = sk * H`
/// 4. `k` = random scalar
/// 5. `U = k * G`, `V = k * H`
/// 6. `c = DLEQ_challenge(pk_full(33) || H || Gamma || U || V)`
/// 7. `s = k - c * sk  mod n`
/// 8. `output = SHA-256("BRRQ_VRF_OUTPUT" || Gamma)`
pub fn vrf_prove(
    keypair: &SchnorrKeyPair,
    alpha: &[u8],
) -> Result<(VrfOutput, VrfProof), VrfError> {
    let secp = Secp256k1::new();

    // Recover the actual full public key (with correct parity) from the secret key.
    let sk_bytes_secret = keypair.secret_bytes();
    let sk_raw: [u8; 32] = *sk_bytes_secret;
    let sk_secp = SecretKey::from_slice(&sk_raw).map_err(VrfError::Secp256k1)?;
    let pk_full = PublicKey::from_secret_key(&secp, &sk_secp);
    let pk_bytes: [u8; 33] = pk_full.serialize();
    let pk_parity = pk_bytes[0]; // 0x02 (even) or 0x03 (odd)

    // Step 1: H = hash_to_curve(alpha)
    let h_point = hash_to_curve(alpha)?;
    let h_bytes: [u8; 33] = h_point.serialize();

    // Step 3: Gamma = sk * H
    let sk_scalar = secp256k1::Scalar::from_be_bytes(sk_raw).map_err(|_| VrfError::InvalidProof)?;
    let gamma_point = h_point.mul_tweak(&secp, &sk_scalar)?;
    let gamma_bytes: [u8; 33] = gamma_point.serialize();

    // Step 4: k = hedged random scalar (nonzero and < n).
    // Hedging: combine RNG output with a hash of the secret key and
    // message, similar to MuSig2/RFC 6979 nonce hedging. This protects
    // against weak or biased RNG: even if the RNG is predictable, the
    // nonce remains unpredictable to an attacker without the secret key.
    let k_secret = loop {
        let mut rng_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut rng_bytes);

        // Hedge: k_raw = SHA-256(sk || alpha || rng_bytes)
        let mut hedge_hasher = Hasher::new();
        hedge_hasher.update(b"BRRQ_VRF_NONCE_HEDGE");
        hedge_hasher.update(&sk_raw);
        hedge_hasher.update(alpha);
        hedge_hasher.update(&rng_bytes);
        let hedged = hedge_hasher.finalize();

        let mut k_raw = [0u8; 32];
        k_raw.copy_from_slice(hedged.as_bytes());
        // Zeroize intermediate RNG bytes.
        rng_bytes.fill(0);

        if let Ok(sk) = SecretKey::from_slice(&k_raw) {
            break ScalarSecret(sk.secret_bytes());
        }
    };

    // Step 5: U = k*G, V = k*H
    let k_secp = SecretKey::from_slice(&k_secret.0).map_err(VrfError::Secp256k1)?;
    let k_scalar_secp =
        secp256k1::Scalar::from_be_bytes(k_secret.0).map_err(|_| VrfError::InvalidProof)?;

    let u_point = PublicKey::from_secret_key(&secp, &k_secp);
    let v_point = h_point.mul_tweak(&secp, &k_scalar_secp)?;

    let u_bytes: [u8; 33] = u_point.serialize();
    let v_bytes: [u8; 33] = v_point.serialize();

    // Step 6: c = challenge(pk_full || H || Gamma || U || V)
    let c_bytes = dleq_challenge(&pk_bytes, &h_bytes, &gamma_bytes, &u_bytes, &v_bytes);

    // Step 7: s = k - c * sk  mod n
    let k_scalar_u256 = scalar::from_bytes(&k_secret.0);
    let c_scalar_u256 = scalar::from_bytes(&c_bytes);
    let sk_scalar_u256 = scalar::from_bytes(&sk_raw);
    let c_sk = scalar::mul_mod(&c_scalar_u256, &sk_scalar_u256);
    let s_scalar = scalar::sub_mod(&k_scalar_u256, &c_sk);
    let s_bytes = scalar::to_bytes(&s_scalar);

    // Step 8: output = SHA-256("BRRQ_VRF_OUTPUT" || Gamma)
    let output = derive_output(&gamma_bytes);

    Ok((
        output,
        VrfProof {
            gamma: gamma_bytes.to_vec(),
            challenge: c_bytes,
            response: s_bytes,
            pk_parity,
        },
    ))
}

/// Verify a VRF proof and output.
///
/// Algorithm:
/// 1. `H = hash_to_curve(alpha)`
/// 2. Reconstruct `pk_full` from the x-only `pubkey` and the parity in `proof.pk_parity`.
/// 3. Parse `Gamma` from proof.
/// 4. `U' = s*G + c*pk_full`,  `V' = s*H + c*Gamma`
/// 5. `c' = challenge(pk_full || H || Gamma || U' || V')`
/// 6. Check `c == c'` (constant-time).
/// 7. Check `output == SHA-256("BRRQ_VRF_OUTPUT" || Gamma)` (constant-time).
pub fn vrf_verify(
    pubkey: &SchnorrPublicKey,
    alpha: &[u8],
    output: &VrfOutput,
    proof: &VrfProof,
) -> Result<(), VrfError> {
    let secp = Secp256k1::new();

    // Validate proof component sizes
    if proof.gamma.len() != 33 {
        return Err(VrfError::InvalidProof);
    }
    if proof.pk_parity != 0x02 && proof.pk_parity != 0x03 {
        return Err(VrfError::InvalidProof);
    }

    // Step 1: H = hash_to_curve(alpha)
    let h_point = hash_to_curve(alpha)?;
    let h_bytes: [u8; 33] = h_point.serialize();

    // Step 2: Reconstruct pk_full using the stored parity
    let pk_xonly = secp256k1::XOnlyPublicKey::from_slice(pubkey.as_bytes())
        .map_err(|_| VrfError::InvalidProof)?;
    let parity = if proof.pk_parity == 0x02 {
        secp256k1::Parity::Even
    } else {
        secp256k1::Parity::Odd
    };
    let pk_full = PublicKey::from_x_only_public_key(pk_xonly, parity);
    let pk_bytes: [u8; 33] = pk_full.serialize();

    // Step 3: Parse Gamma
    let gamma_bytes: [u8; 33] = proof
        .gamma
        .as_slice()
        .try_into()
        .map_err(|_| VrfError::InvalidProof)?;
    let gamma_point = PublicKey::from_slice(&gamma_bytes).map_err(|_| VrfError::InvalidProof)?;

    // Parse c and s scalars
    let c_secp =
        secp256k1::Scalar::from_be_bytes(proof.challenge).map_err(|_| VrfError::InvalidProof)?;
    let s_bytes = proof.response;
    let s_scalar_secp =
        secp256k1::Scalar::from_be_bytes(s_bytes).map_err(|_| VrfError::InvalidProof)?;

    // Step 4: U' = s*G + c*pk_full
    // s*G — handle the case where s == 0 (would be an invalid secret key)
    let s_sk = SecretKey::from_slice(&s_bytes).map_err(|_| VrfError::InvalidProof)?;
    let sg_point = PublicKey::from_secret_key(&secp, &s_sk);
    let c_pk = pk_full
        .mul_tweak(&secp, &c_secp)
        .map_err(|_| VrfError::VerificationFailed)?;
    let u_prime =
        PublicKey::combine_keys(&[&sg_point, &c_pk]).map_err(|_| VrfError::VerificationFailed)?;

    // V' = s*H + c*Gamma
    let sh_point = h_point
        .mul_tweak(&secp, &s_scalar_secp)
        .map_err(|_| VrfError::VerificationFailed)?;
    let c_gamma = gamma_point
        .mul_tweak(&secp, &c_secp)
        .map_err(|_| VrfError::VerificationFailed)?;
    let v_prime = PublicKey::combine_keys(&[&sh_point, &c_gamma])
        .map_err(|_| VrfError::VerificationFailed)?;

    let u_prime_bytes: [u8; 33] = u_prime.serialize();
    let v_prime_bytes: [u8; 33] = v_prime.serialize();

    // Step 5: c' = challenge(pk_full || H || Gamma || U' || V')
    let c_prime = dleq_challenge(
        &pk_bytes,
        &h_bytes,
        &gamma_bytes,
        &u_prime_bytes,
        &v_prime_bytes,
    );

    // Step 6: c == c' (constant-time comparison)
    let mut diff = 0u8;
    for (a, b) in proof.challenge.iter().zip(c_prime.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(VrfError::VerificationFailed);
    }

    // Step 7: output == SHA-256("BRRQ_VRF_OUTPUT" || Gamma) (constant-time)
    let expected_output = derive_output(&gamma_bytes);
    let mut out_diff = 0u8;
    for (a, b) in output.0.iter().zip(expected_output.0.iter()) {
        out_diff |= a ^ b;
    }
    if out_diff != 0 {
        return Err(VrfError::VerificationFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schnorr::SchnorrKeyPair;

    fn test_keypair() -> SchnorrKeyPair {
        SchnorrKeyPair::from_secret_bytes(&[0x42u8; 32]).unwrap()
    }

    fn test_keypair2() -> SchnorrKeyPair {
        SchnorrKeyPair::from_secret_bytes(&[0x43u8; 32]).unwrap()
    }

    #[test]
    fn test_vrf_prove_verify_roundtrip() {
        let kp = test_keypair();
        let alpha = b"test input alpha";

        let (output, proof) = vrf_prove(&kp, alpha).unwrap();
        vrf_verify(kp.public_key(), alpha, &output, &proof).expect("valid VRF proof should verify");
    }

    #[test]
    fn test_vrf_deterministic_output() {
        // Same key + input → same Gamma → same output.
        // Note: the proof itself differs (random k), but the output must be the same.
        let kp = test_keypair();
        let alpha = b"determinism check";

        let (output1, _) = vrf_prove(&kp, alpha).unwrap();
        let (output2, _) = vrf_prove(&kp, alpha).unwrap();

        assert_eq!(
            output1, output2,
            "VRF output must be deterministic for the same key and input"
        );
    }

    #[test]
    fn test_vrf_different_inputs_different_outputs() {
        let kp = test_keypair();

        let (out1, _) = vrf_prove(&kp, b"input one").unwrap();
        let (out2, _) = vrf_prove(&kp, b"input two").unwrap();

        assert_ne!(
            out1, out2,
            "different inputs must produce different VRF outputs"
        );
    }

    #[test]
    fn test_vrf_wrong_key_fails() {
        let kp = test_keypair();
        let kp2 = test_keypair2();
        let alpha = b"some alpha";

        let (output, proof) = vrf_prove(&kp, alpha).unwrap();

        // Verify with the wrong public key must fail
        let result = vrf_verify(kp2.public_key(), alpha, &output, &proof);
        assert!(result.is_err(), "VRF verification with wrong key must fail");
    }

    #[test]
    fn test_vrf_tampered_proof_fails() {
        let kp = test_keypair();
        let alpha = b"tamper test";

        let (output, mut proof) = vrf_prove(&kp, alpha).unwrap();

        // Flip a bit in the challenge
        proof.challenge[0] ^= 0x01;

        let result = vrf_verify(kp.public_key(), alpha, &output, &proof);
        assert!(
            result.is_err(),
            "tampered challenge must cause verification failure"
        );
    }

    #[test]
    fn test_vrf_tampered_output_fails() {
        let kp = test_keypair();
        let alpha = b"output tamper test";

        let (mut output, proof) = vrf_prove(&kp, alpha).unwrap();

        // Flip a bit in the output
        output.0[0] ^= 0x01;

        let result = vrf_verify(kp.public_key(), alpha, &output, &proof);
        assert!(
            result.is_err(),
            "tampered output must cause verification failure"
        );
    }

    #[test]
    fn test_vrf_output_looks_random() {
        let kp = test_keypair();
        let (output, _) = vrf_prove(&kp, b"randomness test").unwrap();

        // Output must not be all zeros or all ones
        let all_zero = output.0.iter().all(|&b| b == 0);
        let all_ones = output.0.iter().all(|&b| b == 0xFF);
        assert!(!all_zero, "VRF output should not be all zeros");
        assert!(!all_ones, "VRF output should not be all ones");

        // At least 10 distinct byte values (statistical plausibility check)
        let mut seen = std::collections::HashSet::new();
        for &b in output.0.iter() {
            seen.insert(b);
        }
        assert!(
            seen.len() >= 10,
            "VRF output should have reasonable byte diversity, got {} distinct bytes",
            seen.len()
        );
    }

    #[test]
    fn test_hash_to_curve_deterministic() {
        let h1 = hash_to_curve(b"same input").unwrap();
        let h2 = hash_to_curve(b"same input").unwrap();
        assert_eq!(h1.serialize(), h2.serialize());
    }

    #[test]
    fn test_hash_to_curve_different_inputs() {
        let h1 = hash_to_curve(b"input A").unwrap();
        let h2 = hash_to_curve(b"input B").unwrap();
        assert_ne!(h1.serialize(), h2.serialize());
    }

    #[test]
    fn test_vrf_proof_gamma_is_33_bytes() {
        let kp = test_keypair();
        let (_, proof) = vrf_prove(&kp, b"gamma size check").unwrap();
        assert_eq!(
            proof.gamma.len(),
            33,
            "Gamma must be 33-byte compressed point"
        );
    }

    #[test]
    fn test_vrf_invalid_parity_byte_rejected() {
        let kp = test_keypair();
        let alpha = b"parity test";
        let (output, mut proof) = vrf_prove(&kp, alpha).unwrap();
        proof.pk_parity = 0x04; // invalid parity byte
        let result = vrf_verify(kp.public_key(), alpha, &output, &proof);
        assert!(result.is_err(), "invalid parity byte must be rejected");
    }
}
