//! SLH-DSA (FIPS 205) — Stateless Hash-Based Digital Signature Algorithm.
//!
//! Full implementation following NIST FIPS 205 specification for SLH-DSA-SHA2-128s.
//!
//! ## Architecture: Hypertree = FORS + d layers of (WOTS+ inside XMSS)
//!
//! ```text
//!   Message
//!     |
//!     v
//!   H_msg() -> (FORS indices, tree_idx, leaf_idx)
//!     |
//!     v
//!   FORS: k=14 binary trees, each height a=12
//!     |  Reveals secret + auth path per tree
//!     v
//!   FORS Public Key (hash of k tree roots)
//!     |
//!     v
//!   HT: d=7 layers of XMSS trees (each height h'=9)
//!     Each XMSS leaf = WOTS+ public key
//!     WOTS+ uses w=16 Winternitz chains of length 15
//!     |
//!     v
//!   HT root = PK.root (32 bytes)
//! ```
//!
//! ## Parameters: SLH-DSA-SHA2-128s
//!
//! | Parameter | Value  | Description                         |
//! |-----------|--------|-------------------------------------|
//! | n         | 16     | Security parameter (bytes)          |
//! | w         | 16     | Winternitz parameter                |
//! | h         | 63     | Total tree height                   |
//! | d         | 7      | Hypertree layers                    |
//! | h'        | 9      | XMSS tree height (h/d)              |
//! | a         | 12     | FORS tree height                    |
//! | k         | 14     | Number of FORS trees                |
//! | len1      | 32     | WOTS+ message chains                |
//! | len2      | 3      | WOTS+ checksum chains               |
//! | len       | 35     | Total WOTS+ chains                  |
//!
//! ## Signature Layout (7,856 bytes)
//!
//! | Component  | Size (bytes) | Formula            |
//! |------------|-------------|---------------------|
//! | R          | 16          | n                   |
//! | FORS sig   | 2,912       | k * (a+1) * n       |
//! | HT sig     | 4,928       | d * (len + h') * n  |
//! | **Total**  | **7,856**   |                     |

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::hash::{Hash256, Hasher};

// ══════════════════════════════════════════════════════════════════════
// FIPS 205 Parameters — SLH-DSA-SHA2-128s
// ══════════════════════════════════════════════════════════════════════

/// Security parameter n (bytes).
const N: usize = 16;
/// Winternitz parameter w.
const W: u32 = 16;
/// log2(w).
const LG_W: u32 = 4;
/// Total hypertree height.
const H_TOTAL: usize = 63;
/// Number of hypertree layers.
const D: usize = 7;
/// XMSS tree height per layer (H_TOTAL / D).
const HP: usize = 9;
/// FORS tree height.
const A: usize = 12;
/// Number of FORS trees.
const K: usize = 14;
/// WOTS+ message chains: ceil(8*N / LG_W) = ceil(128/4) = 32.
const LEN1: usize = 32;
/// WOTS+ checksum chains: floor(log2(LEN1*(W-1)) / LG_W) + 1 = 3.
const LEN2: usize = 3;
/// Total WOTS+ chains: LEN1 + LEN2.
const LEN: usize = 35;

/// SLH-DSA signature size: R(n) + FORS(k*(a+1)*n) + HT(d*(len+h')*n).
pub const SLH_DSA_SIGNATURE_SIZE: usize = N + K * (A + 1) * N + D * (LEN + HP) * N;
// = 16 + 14*13*16 + 7*44*16 = 16 + 2912 + 4928 = 7856

/// SLH-DSA public key size: PK.seed(n) + PK.root(n) = 2n.
pub const SLH_DSA_PUBLIC_KEY_SIZE: usize = 2 * N;

/// SLH-DSA secret key size: SK.seed(n) + SK.prf(n) + PK.seed(n) + PK.root(n) = 4n.
pub const SLH_DSA_SECRET_KEY_SIZE: usize = 4 * N;

/// Size of one XMSS signature: WOTS+ sig (len*n) + auth path (h'*n).
const XMSS_SIG_SIZE: usize = (LEN + HP) * N;

/// Size of the FORS signature: k * (secret(n) + auth(a*n)).
const FORS_SIG_SIZE: usize = K * (1 + A) * N;

/// Number of bytes in H_msg output.
const H_MSG_LEN: usize = (K * A + H_TOTAL - HP + HP).div_ceil(8); // = 29

// Compile-time assertions
const _: () = assert!(SLH_DSA_SIGNATURE_SIZE == 7_856);
const _: () = assert!(SLH_DSA_PUBLIC_KEY_SIZE == 32);
const _: () = assert!(SLH_DSA_SECRET_KEY_SIZE == 64);
const _: () = assert!(HP * D == H_TOTAL);
const _: () = assert!(LEN1 + LEN2 == LEN);

// ══════════════════════════════════════════════════════════════════════
// ADRS — Address structure for domain separation (FIPS 205 §4.2)
// ══════════════════════════════════════════════════════════════════════

/// FIPS 205 address types.
const ADRS_WOTS_HASH: u32 = 0;
const ADRS_WOTS_PK: u32 = 1;
const ADRS_TREE: u32 = 2;
const ADRS_FORS_TREE: u32 = 3;
const ADRS_FORS_ROOTS: u32 = 4;
const ADRS_WOTS_PRF: u32 = 5;

/// 32-byte address structure providing domain separation for all hash calls.
#[derive(Clone, Copy, Default)]
struct Adrs {
    data: [u8; 32],
}

impl Adrs {
    fn set_layer(&mut self, layer: u32) {
        self.data[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    fn set_tree(&mut self, tree: u64) {
        // Tree address occupies bytes 4-15 (96 bits).
        // We store the low 64 bits in bytes 8-15.
        self.data[4..8].copy_from_slice(&[0u8; 4]);
        self.data[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    fn set_type_and_clear(&mut self, t: u32) {
        self.data[16..20].copy_from_slice(&t.to_be_bytes());
        // Clear type-specific fields (bytes 20-31).
        self.data[20..32].fill(0);
    }

    fn set_key_pair(&mut self, kp: u32) {
        self.data[20..24].copy_from_slice(&kp.to_be_bytes());
    }

    fn get_key_pair(&self) -> u32 {
        u32::from_be_bytes([self.data[20], self.data[21], self.data[22], self.data[23]])
    }

    fn set_chain(&mut self, chain: u32) {
        self.data[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    fn set_hash(&mut self, hash: u32) {
        self.data[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    fn set_tree_height(&mut self, h: u32) {
        self.data[24..28].copy_from_slice(&h.to_be_bytes());
    }

    fn set_tree_index(&mut self, idx: u32) {
        self.data[28..32].copy_from_slice(&idx.to_be_bytes());
    }

    /// Compress ADRS from 32 bytes to 22 bytes (FIPS 205 §10.1).
    ///
    /// ADRSc removes padding bytes that are always zero for our parameters:
    ///   ADRSc = ADRS[3]      (1B layer)
    ///        || ADRS[8..16]  (8B tree address, low 64 bits)
    ///        || ADRS[19]     (1B type)
    ///        || ADRS[20..32] (12B type-specific words)
    ///   Total: 1 + 8 + 1 + 12 = 22 bytes
    fn compress(&self) -> [u8; 22] {
        let mut c = [0u8; 22];
        c[0] = self.data[3]; // layer (low byte)
        c[1..9].copy_from_slice(&self.data[8..16]); // tree address (low 8 bytes)
        c[9] = self.data[19]; // type (low byte)
        c[10..22].copy_from_slice(&self.data[20..32]); // key_pair, chain/height, hash/index
        c
    }
}

// ══════════════════════════════════════════════════════════════════════
// Tweakable hash functions (FIPS 205 §7, SHA-256 instantiation)
// ══════════════════════════════════════════════════════════════════════

/// F(PK.seed, ADRS, M) — used in WOTS+ chains and FORS leaf hashing.
/// Returns n bytes.
///
/// FIPS 205 §10.1 SHA-256 instantiation:
///   F = Trunc_n(SHA-256(toByte(0, 64-n) || PK.seed || ADRSc || M))
///   Padding = 48 zero bytes (aligns PK.seed to SHA-256 block boundary).
///   ADRSc = 22-byte compressed address.
fn hash_f(pk_seed: &[u8; N], adrs: &Adrs, m: &[u8; N]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update([0u8; 64 - N]); // 48 zero bytes — FIPS 205 block alignment
    h.update(pk_seed);
    h.update(adrs.compress());
    h.update(m);
    let result = h.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result[..N]);
    out
}

/// H(PK.seed, ADRS, M) — used in Merkle tree internal nodes.
/// Input M is 2n bytes (left || right children). Returns n bytes.
///
/// FIPS 205 §10.1 — 48-byte padding + compressed ADRS.
fn hash_h(pk_seed: &[u8; N], adrs: &Adrs, m: &[u8]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update([0u8; 64 - N]); // 48 zero bytes
    h.update(pk_seed);
    h.update(adrs.compress());
    h.update(m);
    let result = h.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result[..N]);
    out
}

/// T_l(PK.seed, ADRS, M) — used in WOTS+ PK compression and FORS root.
/// Input M is l*n bytes. Returns n bytes.
///
/// FIPS 205 §10.1 — 48-byte padding + compressed ADRS.
fn hash_t(pk_seed: &[u8; N], adrs: &Adrs, m: &[u8]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update([0u8; 64 - N]); // 48 zero bytes
    h.update(pk_seed);
    h.update(adrs.compress());
    h.update(m);
    let result = h.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result[..N]);
    out
}

/// PRF(PK.seed, SK.seed, ADRS) — pseudorandom function for key derivation.
///
/// FIPS 205 §10.1 — 48-byte padding + compressed ADRS.
fn prf(pk_seed: &[u8; N], sk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
    let mut h = Sha256::new();
    h.update([0u8; 64 - N]); // 48 zero bytes
    h.update(pk_seed);
    h.update(adrs.compress());
    h.update(sk_seed);
    let result = h.finalize();
    let mut out = [0u8; N];
    out.copy_from_slice(&result[..N]);
    out
}

/// PRF_msg(SK.prf, OptRand, M) — randomized message PRF via HMAC-SHA-256.
fn prf_msg(sk_prf: &[u8; N], opt_rand: &[u8; N], msg: &[u8]) -> [u8; N] {
    // HMAC-SHA-256(key=sk_prf, data=opt_rand||msg), truncated to n bytes.
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..N {
        ipad[i] ^= sk_prf[i];
        opad[i] ^= sk_prf[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(opt_rand);
    inner.update(msg);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let result = outer.finalize();

    // Zeroize HMAC pads that contain key material (sk_prf XOR'd in).
    crate::zeroize::zeroize_bytes(&mut ipad);
    crate::zeroize::zeroize_bytes(&mut opad);

    let mut out = [0u8; N];
    out.copy_from_slice(&result[..N]);
    out
}

/// H_msg(R, PK.seed, PK.root, M) — message hash producing FORS indices + HT address.
/// Returns H_MSG_LEN bytes via MGF1-SHA-256.
fn h_msg(r: &[u8; N], pk_seed: &[u8; N], pk_root: &[u8; N], msg: &[u8]) -> [u8; H_MSG_LEN] {
    // Inner hash: SHA-256(R || PK.seed || PK.root || M)
    let mut inner = Sha256::new();
    inner.update(r);
    inner.update(pk_seed);
    inner.update(pk_root);
    inner.update(msg);
    let inner_hash = inner.finalize();

    // MGF1 seed: R || PK.seed || inner_hash
    let mut mgf_seed = Vec::with_capacity(N + N + 32);
    mgf_seed.extend_from_slice(r);
    mgf_seed.extend_from_slice(pk_seed);
    mgf_seed.extend_from_slice(&inner_hash);

    // MGF1-SHA-256: produce H_MSG_LEN bytes
    let mut out = [0u8; H_MSG_LEN];
    let mut offset = 0;
    let mut counter: u32 = 0;
    while offset < H_MSG_LEN {
        let mut h = Sha256::new();
        h.update(&mgf_seed);
        h.update(counter.to_be_bytes());
        let block = h.finalize();
        let to_copy = (H_MSG_LEN - offset).min(32);
        out[offset..offset + to_copy].copy_from_slice(&block[..to_copy]);
        offset += to_copy;
        counter += 1;
    }
    out
}

// ══════════════════════════════════════════════════════════════════════
// Message digest parsing (FIPS 205 §6)
// ══════════════════════════════════════════════════════════════════════

/// Parse H_msg output into (FORS indices, tree_address, leaf_index).
fn parse_msg_digest(digest: &[u8; H_MSG_LEN]) -> (Vec<u32>, u64, u32) {
    // FORS message: first K*A = 168 bits = 21 bytes, as k values of a bits.
    let mut fors_indices = Vec::with_capacity(K);
    let md_bits = K * A; // 168 bits

    for i in 0..K {
        let bit_start = i * A;
        let mut val: u32 = 0;
        for b in 0..A {
            let byte_idx = (bit_start + b) / 8;
            let bit_idx = 7 - ((bit_start + b) % 8);
            if byte_idx < digest.len() && (digest[byte_idx] >> bit_idx) & 1 == 1 {
                val |= 1 << (A - 1 - b);
            }
        }
        fors_indices.push(val);
    }

    // Tree address: next (H_TOTAL - HP) = 54 bits.
    let tree_bit_start = md_bits;
    let tree_bits = H_TOTAL - HP; // 54
    let mut idx_tree: u64 = 0;
    for b in 0..tree_bits {
        let bit_pos = tree_bit_start + b;
        let byte_idx = bit_pos / 8;
        let bit_idx = 7 - (bit_pos % 8);
        if byte_idx < digest.len() && (digest[byte_idx] >> bit_idx) & 1 == 1 {
            idx_tree |= 1u64 << (tree_bits - 1 - b);
        }
    }

    // Leaf index: next HP = 9 bits.
    let leaf_bit_start = tree_bit_start + tree_bits;
    let mut idx_leaf: u32 = 0;
    for b in 0..HP {
        let bit_pos = leaf_bit_start + b;
        let byte_idx = bit_pos / 8;
        let bit_idx = 7 - (bit_pos % 8);
        if byte_idx < digest.len() && (digest[byte_idx] >> bit_idx) & 1 == 1 {
            idx_leaf |= 1u32 << (HP - 1 - b);
        }
    }

    (fors_indices, idx_tree, idx_leaf)
}

// ══════════════════════════════════════════════════════════════════════
// WOTS+ (FIPS 205 §3.1–§4)
// ══════════════════════════════════════════════════════════════════════

/// Convert n-byte message to base-w digits (w=16: each byte → 2 nibbles).
fn base_w(input: &[u8], out_len: usize) -> Vec<u32> {
    let mut result = Vec::with_capacity(out_len);
    for &byte in input {
        result.push((byte >> 4) as u32);
        result.push((byte & 0x0F) as u32);
        if result.len() >= out_len {
            break;
        }
    }
    result.truncate(out_len);
    result
}

/// Apply `steps` hash chain iterations from position `start`.
/// chain(X, start, steps, pk_seed, adrs) = F(F(...F(X)...)) applied `steps` times.
fn wots_chain(x: &[u8; N], start: u32, steps: u32, pk_seed: &[u8; N], adrs: &mut Adrs) -> [u8; N] {
    let mut tmp = *x;
    for j in start..start + steps {
        adrs.set_hash(j);
        tmp = hash_f(pk_seed, adrs, &tmp);
    }
    tmp
}

/// Generate WOTS+ public key for key pair `kp` in the current ADRS context.
/// Returns n-byte compressed public key.
fn wots_pkgen(sk_seed: &[u8; N], pk_seed: &[u8; N], kp: u32, adrs: &Adrs) -> [u8; N] {
    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(ADRS_WOTS_PRF);
    sk_adrs.set_key_pair(kp);

    let mut chain_adrs = *adrs;
    chain_adrs.set_type_and_clear(ADRS_WOTS_HASH);
    chain_adrs.set_key_pair(kp);

    // Compute all chain tops: chain(PRF(sk), 0, w-1) for each chain.
    let mut chain_tops = vec![0u8; LEN * N];
    for i in 0..LEN {
        sk_adrs.set_chain(i as u32);
        let mut sk = prf(pk_seed, sk_seed, &sk_adrs);

        chain_adrs.set_chain(i as u32);
        let top = wots_chain(&sk, 0, W - 1, pk_seed, &mut chain_adrs);
        chain_tops[i * N..(i + 1) * N].copy_from_slice(&top);

        // Zeroize WOTS+ secret seed after use.
        crate::zeroize::zeroize_bytes(&mut sk);
    }

    // Compress chain tops into n-byte public key via T_len.
    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(ADRS_WOTS_PK);
    pk_adrs.set_key_pair(kp);
    hash_t(pk_seed, &pk_adrs, &chain_tops)
}

/// Compute WOTS+ message digits (base-w message + checksum).
fn wots_msg_digits(msg: &[u8; N]) -> Vec<u32> {
    let mut digits = base_w(msg, LEN1);

    // Checksum: sum of (w-1 - digit) for all message digits.
    let mut csum: u32 = 0;
    for &d in &digits {
        csum += W - 1 - d;
    }

    // Encode checksum as LEN2 base-w digits.
    // Shift left by (8 - (LEN2 * LG_W % 8)) % 8 = (8 - 12%8) % 8 = 4.
    let shift = (8 - ((LEN2 as u32 * LG_W) % 8)) % 8;
    csum <<= shift;
    let csum_bytes = [((csum >> 8) & 0xFF) as u8, (csum & 0xFF) as u8];
    digits.extend(base_w(&csum_bytes, LEN2));

    digits
}

/// WOTS+ sign: produce len chain values for message `msg`.
fn wots_sign(msg: &[u8; N], sk_seed: &[u8; N], pk_seed: &[u8; N], kp: u32, adrs: &Adrs) -> Vec<u8> {
    let digits = wots_msg_digits(msg);

    let mut sk_adrs = *adrs;
    sk_adrs.set_type_and_clear(ADRS_WOTS_PRF);
    sk_adrs.set_key_pair(kp);

    let mut chain_adrs = *adrs;
    chain_adrs.set_type_and_clear(ADRS_WOTS_HASH);
    chain_adrs.set_key_pair(kp);

    let mut sig = Vec::with_capacity(LEN * N);
    for (i, &digit) in digits.iter().enumerate().take(LEN) {
        sk_adrs.set_chain(i as u32);
        let mut sk = prf(pk_seed, sk_seed, &sk_adrs);

        chain_adrs.set_chain(i as u32);
        let val = wots_chain(&sk, 0, digit, pk_seed, &mut chain_adrs);
        sig.extend_from_slice(&val);

        // Zeroize WOTS+ secret seed after use.
        crate::zeroize::zeroize_bytes(&mut sk);
    }
    sig
}

/// WOTS+ PKFromSig: recover public key from signature + message.
fn wots_pk_from_sig(sig: &[u8], msg: &[u8; N], pk_seed: &[u8; N], kp: u32, adrs: &Adrs) -> [u8; N] {
    let digits = wots_msg_digits(msg);

    let mut chain_adrs = *adrs;
    chain_adrs.set_type_and_clear(ADRS_WOTS_HASH);
    chain_adrs.set_key_pair(kp);

    let mut chain_tops = vec![0u8; LEN * N];
    for i in 0..LEN {
        let mut val = [0u8; N];
        val.copy_from_slice(&sig[i * N..(i + 1) * N]);

        chain_adrs.set_chain(i as u32);
        let top = wots_chain(&val, digits[i], W - 1 - digits[i], pk_seed, &mut chain_adrs);
        chain_tops[i * N..(i + 1) * N].copy_from_slice(&top);
    }

    let mut pk_adrs = *adrs;
    pk_adrs.set_type_and_clear(ADRS_WOTS_PK);
    pk_adrs.set_key_pair(kp);
    hash_t(pk_seed, &pk_adrs, &chain_tops)
}

// ══════════════════════════════════════════════════════════════════════
// XMSS — eXtended Merkle Signature Scheme (FIPS 205 §5)
// ══════════════════════════════════════════════════════════════════════

/// Build a full XMSS tree bottom-up. Returns all tree levels.
/// Level 0 = WOTS+ public keys (2^HP leaves).
/// Level HP = root (1 node).
fn build_xmss_tree(sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &Adrs) -> Vec<Vec<[u8; N]>> {
    let num_leaves = 1usize << HP; // 512
    let mut levels: Vec<Vec<[u8; N]>> = Vec::with_capacity(HP + 1);

    // Level 0: compute all WOTS+ public keys.
    let mut leaves = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        leaves.push(wots_pkgen(sk_seed, pk_seed, i as u32, adrs));
    }
    levels.push(leaves);

    // Build Merkle tree upward.
    for h in 1..=HP {
        let prev = &levels[h - 1];
        let level_size = prev.len() / 2;
        let mut level = Vec::with_capacity(level_size);
        for j in 0..level_size {
            let mut tree_adrs = *adrs;
            tree_adrs.set_type_and_clear(ADRS_TREE);
            tree_adrs.set_tree_height(h as u32);
            tree_adrs.set_tree_index(j as u32);
            let mut concat = [0u8; 2 * N];
            concat[..N].copy_from_slice(&prev[2 * j]);
            concat[N..].copy_from_slice(&prev[2 * j + 1]);
            level.push(hash_h(pk_seed, &tree_adrs, &concat));
        }
        levels.push(level);
    }

    levels
}

/// XMSS sign: produce WOTS+ signature + authentication path at leaf `idx`.
fn xmss_sign(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    idx: u32,
    adrs: &Adrs,
) -> Vec<u8> {
    // Build the full XMSS tree.
    let tree = build_xmss_tree(sk_seed, pk_seed, adrs);

    // WOTS+ signature for the message at leaf `idx`.
    let sig = wots_sign(msg, sk_seed, pk_seed, idx, adrs);

    // Authentication path: h' sibling hashes.
    let mut auth = Vec::with_capacity(HP * N);
    let mut pos = idx as usize;
    for level in tree.iter().take(HP) {
        let sibling = pos ^ 1;
        auth.extend_from_slice(&level[sibling]);
        pos /= 2;
    }

    // XMSS signature = WOTS+ sig || auth path.
    let mut xmss_sig = sig;
    xmss_sig.extend_from_slice(&auth);
    xmss_sig
}

/// XMSS PKFromSig: recover XMSS root from signature.
fn xmss_pk_from_sig(
    sig: &[u8],
    msg: &[u8; N],
    pk_seed: &[u8; N],
    idx: u32,
    adrs: &Adrs,
) -> [u8; N] {
    // Split: WOTS+ sig (LEN*N bytes) || auth path (HP*N bytes).
    let wots_sig = &sig[..LEN * N];
    let auth = &sig[LEN * N..];

    // Recover WOTS+ public key.
    let mut node = wots_pk_from_sig(wots_sig, msg, pk_seed, idx, adrs);

    // Walk up the Merkle tree using auth path.
    let mut tree_adrs = *adrs;
    tree_adrs.set_type_and_clear(ADRS_TREE);
    let mut pos = idx;
    for h in 0..HP {
        tree_adrs.set_tree_height((h + 1) as u32);
        tree_adrs.set_tree_index(pos / 2);

        let mut concat = [0u8; 2 * N];
        let sibling = &auth[h * N..(h + 1) * N];
        if pos.is_multiple_of(2) {
            // Current is left child.
            concat[..N].copy_from_slice(&node);
            concat[N..].copy_from_slice(sibling);
        } else {
            // Current is right child.
            concat[..N].copy_from_slice(sibling);
            concat[N..].copy_from_slice(&node);
        }
        node = hash_h(pk_seed, &tree_adrs, &concat);
        pos /= 2;
    }

    node
}

// ══════════════════════════════════════════════════════════════════════
// HT — Hypertree (FIPS 205 §6)
// ══════════════════════════════════════════════════════════════════════

/// HT sign: produce d XMSS signatures authenticating message through hypertree.
fn ht_sign(
    msg: &[u8; N],
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    mut idx_tree: u64,
    mut idx_leaf: u32,
) -> Vec<u8> {
    let mut adrs = Adrs::default();
    adrs.set_tree(idx_tree);

    // Layer 0: sign the message.
    let sig_tmp = xmss_sign(msg, sk_seed, pk_seed, idx_leaf, &adrs);
    let mut ht_sig = sig_tmp.clone();

    // Compute root at layer 0 for chaining.
    let mut root = xmss_pk_from_sig(&sig_tmp, msg, pk_seed, idx_leaf, &adrs);

    // Layers 1 through d-1.
    for layer in 1..D {
        idx_leaf = (idx_tree & ((1u64 << HP) - 1)) as u32;
        idx_tree >>= HP;

        adrs.set_layer(layer as u32);
        adrs.set_tree(idx_tree);

        let sig_tmp = xmss_sign(&root, sk_seed, pk_seed, idx_leaf, &adrs);
        ht_sig.extend_from_slice(&sig_tmp);

        if layer < D - 1 {
            root = xmss_pk_from_sig(&sig_tmp, &root, pk_seed, idx_leaf, &adrs);
        }
    }

    ht_sig
}

/// HT verify: check d XMSS signatures chain to PK.root.
fn ht_verify(
    msg: &[u8; N],
    ht_sig: &[u8],
    pk_seed: &[u8; N],
    mut idx_tree: u64,
    mut idx_leaf: u32,
    pk_root: &[u8; N],
) -> bool {
    let mut adrs = Adrs::default();
    adrs.set_tree(idx_tree);

    // Layer 0.
    let sig_layer = &ht_sig[..XMSS_SIG_SIZE];
    let mut node = xmss_pk_from_sig(sig_layer, msg, pk_seed, idx_leaf, &adrs);

    // Layers 1 through d-1.
    for layer in 1..D {
        idx_leaf = (idx_tree & ((1u64 << HP) - 1)) as u32;
        idx_tree >>= HP;

        adrs.set_layer(layer as u32);
        adrs.set_tree(idx_tree);

        let offset = layer * XMSS_SIG_SIZE;
        let sig_layer = &ht_sig[offset..offset + XMSS_SIG_SIZE];
        node = xmss_pk_from_sig(sig_layer, &node, pk_seed, idx_leaf, &adrs);
    }

    // Constant-time comparison to prevent timing leaks.
    // Default `==` for arrays short-circuits, leaking how many leading
    // bytes of the recovered root match the real root.
    ct_eq_n(&node, pk_root)
}

/// Constant-time equality check for [u8; N] arrays.
/// Processes all N bytes regardless of content to prevent timing attacks.
#[inline]
fn ct_eq_n(a: &[u8; N], b: &[u8; N]) -> bool {
    let mut diff = 0u8;
    for i in 0..N {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ══════════════════════════════════════════════════════════════════════
// FORS — Forest of Random Subsets (FIPS 205 §7)
// ══════════════════════════════════════════════════════════════════════

/// Build a single FORS binary tree (one of k trees).
/// Returns all tree levels. Level 0 = 2^a leaf hashes.
fn build_fors_tree(
    sk_seed: &[u8; N],
    pk_seed: &[u8; N],
    tree_idx: usize,
    adrs: &Adrs,
) -> Vec<Vec<[u8; N]>> {
    let num_leaves = 1usize << A; // 4096
    let mut levels: Vec<Vec<[u8; N]>> = Vec::with_capacity(A + 1);

    // Level 0: leaf hashes = F(pk_seed, adrs, PRF(pk_seed, sk_seed, adrs)).
    let mut leaves = Vec::with_capacity(num_leaves);
    for j in 0..num_leaves {
        let global_idx = (tree_idx << A) | j;
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_tree_height(0);
        leaf_adrs.set_tree_index(global_idx as u32);
        let mut sk = prf(pk_seed, sk_seed, &leaf_adrs);
        leaves.push(hash_f(pk_seed, &leaf_adrs, &sk));

        // Zeroize FORS secret after hashing into leaf.
        crate::zeroize::zeroize_bytes(&mut sk);
    }
    levels.push(leaves);

    // Build Merkle tree upward.
    for h in 1..=A {
        let prev = &levels[h - 1];
        let level_size = prev.len() / 2;
        let mut level = Vec::with_capacity(level_size);
        for j in 0..level_size {
            let global_idx = (tree_idx << (A - h)) | j;
            let mut node_adrs = *adrs;
            node_adrs.set_tree_height(h as u32);
            node_adrs.set_tree_index(global_idx as u32);
            let mut concat = [0u8; 2 * N];
            concat[..N].copy_from_slice(&prev[2 * j]);
            concat[N..].copy_from_slice(&prev[2 * j + 1]);
            level.push(hash_h(pk_seed, &node_adrs, &concat));
        }
        levels.push(level);
    }

    levels
}

/// FORS sign: produce k (secret + auth_path) pairs.
fn fors_sign(fors_indices: &[u32], sk_seed: &[u8; N], pk_seed: &[u8; N], adrs: &Adrs) -> Vec<u8> {
    let mut sig = Vec::with_capacity(FORS_SIG_SIZE);

    for (i, &idx) in fors_indices.iter().enumerate() {
        // Build the full tree for FORS tree i.
        let tree = build_fors_tree(sk_seed, pk_seed, i, adrs);

        // Reveal secret value at leaf idx.
        let global_leaf = (i << A) | (idx as usize);
        let mut sk_adrs = *adrs;
        sk_adrs.set_tree_height(0);
        sk_adrs.set_tree_index(global_leaf as u32);
        let mut sk = prf(pk_seed, sk_seed, &sk_adrs);
        sig.extend_from_slice(&sk);

        // Zeroize FORS secret after copying into signature.
        crate::zeroize::zeroize_bytes(&mut sk);

        // Authentication path: a sibling hashes.
        let mut pos = idx as usize;
        for level in tree.iter().take(A) {
            let sibling = pos ^ 1;
            sig.extend_from_slice(&level[sibling]);
            pos /= 2;
        }
    }

    sig
}

/// FORS PKFromSig: recover FORS public key from signature + indices.
fn fors_pk_from_sig(sig: &[u8], fors_indices: &[u32], pk_seed: &[u8; N], adrs: &Adrs) -> [u8; N] {
    let mut roots = Vec::with_capacity(K * N);
    let entry_size = (1 + A) * N; // secret + a auth nodes

    for (i, &idx) in fors_indices.iter().enumerate() {
        let entry = &sig[i * entry_size..];

        // Recover leaf hash from secret.
        let mut sk = [0u8; N];
        sk.copy_from_slice(&entry[..N]);
        let global_leaf = (i << A) | (idx as usize);
        let mut leaf_adrs = *adrs;
        leaf_adrs.set_tree_height(0);
        leaf_adrs.set_tree_index(global_leaf as u32);
        let mut node = hash_f(pk_seed, &leaf_adrs, &sk);

        // Walk up using auth path.
        let auth = &entry[N..entry_size];
        let mut pos = idx;
        for h in 0..A {
            let global_idx = (i << (A - h - 1)) | ((pos / 2) as usize);
            let mut node_adrs = *adrs;
            node_adrs.set_tree_height((h + 1) as u32);
            node_adrs.set_tree_index(global_idx as u32);

            let sibling = &auth[h * N..(h + 1) * N];
            let mut concat = [0u8; 2 * N];
            if pos % 2 == 0 {
                concat[..N].copy_from_slice(&node);
                concat[N..].copy_from_slice(sibling);
            } else {
                concat[..N].copy_from_slice(sibling);
                concat[N..].copy_from_slice(&node);
            }
            node = hash_h(pk_seed, &node_adrs, &concat);
            pos /= 2;
        }

        roots.extend_from_slice(&node);
    }

    // Compress k tree roots into FORS public key.
    let mut fors_pk_adrs = *adrs;
    fors_pk_adrs.set_type_and_clear(ADRS_FORS_ROOTS);
    fors_pk_adrs.set_key_pair(adrs.get_key_pair());
    hash_t(pk_seed, &fors_pk_adrs, &roots)
}

// ══════════════════════════════════════════════════════════════════════
// Public API — Types
// ══════════════════════════════════════════════════════════════════════

/// Errors that can occur during SLH-DSA operations.
#[derive(Debug, Error)]
pub enum SlhDsaError {
    #[error("invalid secret key length: expected {expected}, got {got}")]
    InvalidSecretKeyLength { expected: usize, got: usize },
    #[error("invalid public key length: expected {expected}, got {got}")]
    InvalidPublicKeyLength { expected: usize, got: usize },
    #[error("invalid signature length: expected {expected}, got {got}")]
    InvalidSignatureLength { expected: usize, got: usize },
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("key generation failed")]
    KeyGenerationFailed,
    #[error("signing failed")]
    SigningFailed,
}

/// SLH-DSA public key (32 bytes = PK.seed || PK.root).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SlhDsaPublicKey(pub(crate) Vec<u8>);

impl SlhDsaPublicKey {
    /// Create from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SlhDsaError> {
        if bytes.len() != SLH_DSA_PUBLIC_KEY_SIZE {
            return Err(SlhDsaError::InvalidPublicKeyLength {
                expected: SLH_DSA_PUBLIC_KEY_SIZE,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Compute hash of the public key.
    pub fn to_hash(&self) -> Hash256 {
        Hasher::hash(&self.0)
    }

    fn pk_seed(&self) -> &[u8] {
        &self.0[..N]
    }

    fn pk_root(&self) -> &[u8] {
        &self.0[N..2 * N]
    }
}

impl std::fmt::Debug for SlhDsaPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SlhDsaPK({})",
            hex::encode(&self.0[..8.min(self.0.len())])
        )
    }
}

/// SLH-DSA secret key (64 bytes = SK.seed || SK.prf || PK.seed || PK.root).
pub struct SlhDsaSecretKey(Vec<u8>);

/// Securely zeroize the root secret key material on drop.
/// SK.seed is the root from which ALL WOTS+, FORS, and XMSS keys are derived.
impl Drop for SlhDsaSecretKey {
    fn drop(&mut self) {
        crate::zeroize::zeroize_bytes(&mut self.0);
    }
}

impl SlhDsaSecretKey {
    /// Access the internal bytes (non-public field, controlled access).
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Create from bytes.
    ///
    /// Validates length (must be exactly SLH_DSA_SECRET_KEY_SIZE = 64 bytes)
    /// to prevent panics from out-of-bounds indexing later.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SlhDsaError> {
        if bytes.len() != SLH_DSA_SECRET_KEY_SIZE {
            return Err(SlhDsaError::InvalidSecretKeyLength {
                expected: SLH_DSA_SECRET_KEY_SIZE,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }
}

/// SLH-DSA signature (7,856 bytes = R || FORS_SIG || HT_SIG).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlhDsaSignature(pub Vec<u8>);

impl SlhDsaSignature {
    /// Create from bytes.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, SlhDsaError> {
        if bytes.len() != SLH_DSA_SIGNATURE_SIZE {
            return Err(SlhDsaError::InvalidSignatureLength {
                expected: SLH_DSA_SIGNATURE_SIZE,
                got: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Size in bytes.
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Expected size for SLH-DSA-SHA2-128s.
    pub const EXPECTED_SIZE: usize = SLH_DSA_SIGNATURE_SIZE;
}

impl std::fmt::Debug for SlhDsaSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SlhDsaSig({}B, {}...)",
            self.0.len(),
            hex::encode(&self.0[..8.min(self.0.len())])
        )
    }
}

// ══════════════════════════════════════════════════════════════════════
// Public API — Key Generation, Signing, Verification
// ══════════════════════════════════════════════════════════════════════

/// SLH-DSA keypair for signing.
///
/// ## Security Properties
///
/// - **Stateless**: No nonce tracking needed (unlike XMSS)
/// - **Randomized**: Same message → different signatures (via randomizer R)
/// - **Hash-based**: Security rests entirely on SHA-256 (quantum-resistant)
///
/// ## FIPS 205 Architecture
///
/// The keypair generates a hypertree of d=7 XMSS layers, each containing
/// 2^h'=512 WOTS+ leaf keys. The FORS layer provides k=14 independent
/// binary trees for message authentication.
pub struct SlhDsaKeyPair {
    secret_key: SlhDsaSecretKey,
    public_key: SlhDsaPublicKey,
}

impl SlhDsaKeyPair {
    /// Generate a new random keypair.
    ///
    /// Derives PK.root by computing the root of the top-level XMSS tree
    /// (layer d-1, tree 0). This requires building 2^h' = 512 WOTS+ leaf
    /// keys and computing their Merkle root.
    pub fn generate() -> Result<Self, SlhDsaError> {
        let mut rng = rand::thread_rng();
        use rand::RngCore;

        let mut sk_seed = [0u8; N];
        let mut sk_prf = [0u8; N];
        let mut pk_seed = [0u8; N];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut sk_prf);
        rng.fill_bytes(&mut pk_seed);

        // Compute PK.root: root of the XMSS tree at layer d-1, tree 0.
        let mut adrs = Adrs::default();
        adrs.set_layer((D - 1) as u32);
        adrs.set_tree(0);

        let tree = build_xmss_tree(&sk_seed, &pk_seed, &adrs);
        let pk_root = tree[HP][0]; // Root is the single node at the top level.

        // Encode keys.
        let mut secret_key_bytes = Vec::with_capacity(SLH_DSA_SECRET_KEY_SIZE);
        secret_key_bytes.extend_from_slice(&sk_seed);
        secret_key_bytes.extend_from_slice(&sk_prf);
        secret_key_bytes.extend_from_slice(&pk_seed);
        secret_key_bytes.extend_from_slice(&pk_root);

        let mut public_key_bytes = Vec::with_capacity(SLH_DSA_PUBLIC_KEY_SIZE);
        public_key_bytes.extend_from_slice(&pk_seed);
        public_key_bytes.extend_from_slice(&pk_root);

        // Zeroize intermediate secret key material on the stack.
        crate::zeroize::zeroize_bytes(&mut sk_seed);
        crate::zeroize::zeroize_bytes(&mut sk_prf);

        Ok(Self {
            secret_key: SlhDsaSecretKey(secret_key_bytes),
            public_key: SlhDsaPublicKey(public_key_bytes),
        })
    }

    /// Generate a key pair deterministically from a 32-byte seed.
    ///
    /// Derives sk_seed, sk_prf, and pk_seed from the input seed via SHA-256,
    /// ensuring the same seed always produces the same key pair.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self, SlhDsaError> {
        use crate::hash::Hasher;

        // Use centralized domain_tags constants for domain separation.

        // Derive sk_seed
        let mut h = Hasher::new();
        h.update(crate::domain_tags::SLH_SK_SEED);
        h.update(seed);
        let hash = h.finalize();
        let mut sk_seed = [0u8; N];
        sk_seed.copy_from_slice(&hash.0[..N]);

        // Derive sk_prf
        let mut h = Hasher::new();
        h.update(crate::domain_tags::SLH_SK_PRF);
        h.update(seed);
        let hash = h.finalize();
        let mut sk_prf = [0u8; N];
        sk_prf.copy_from_slice(&hash.0[..N]);

        // Derive pk_seed
        let mut h = Hasher::new();
        h.update(crate::domain_tags::SLH_PK_SEED);
        h.update(seed);
        let hash = h.finalize();
        let mut pk_seed = [0u8; N];
        pk_seed.copy_from_slice(&hash.0[..N]);

        // Compute PK.root
        let mut adrs = Adrs::default();
        adrs.set_layer((D - 1) as u32);
        adrs.set_tree(0);

        let tree = build_xmss_tree(&sk_seed, &pk_seed, &adrs);
        let pk_root = tree[HP][0];

        let mut secret_key_bytes = Vec::with_capacity(SLH_DSA_SECRET_KEY_SIZE);
        secret_key_bytes.extend_from_slice(&sk_seed);
        secret_key_bytes.extend_from_slice(&sk_prf);
        secret_key_bytes.extend_from_slice(&pk_seed);
        secret_key_bytes.extend_from_slice(&pk_root);

        let mut public_key_bytes = Vec::with_capacity(SLH_DSA_PUBLIC_KEY_SIZE);
        public_key_bytes.extend_from_slice(&pk_seed);
        public_key_bytes.extend_from_slice(&pk_root);

        // Zeroize intermediate secret key material on the stack.
        crate::zeroize::zeroize_bytes(&mut sk_seed);
        crate::zeroize::zeroize_bytes(&mut sk_prf);

        Ok(Self {
            secret_key: SlhDsaSecretKey(secret_key_bytes),
            public_key: SlhDsaPublicKey(public_key_bytes),
        })
    }

    /// Get the public key.
    pub fn public_key(&self) -> &SlhDsaPublicKey {
        &self.public_key
    }

    /// Sign a message.
    ///
    /// Produces a 7,856-byte signature via the full FIPS 205 pipeline:
    /// 1. Randomize message hash → FORS indices + HT address
    /// 2. FORS sign → FORS signature (2,912 bytes)
    /// 3. HT sign → d=7 XMSS signatures (4,928 bytes)
    /// 4. Assemble: R (16) || FORS_SIG (2,912) || HT_SIG (4,928)
    pub fn sign(&self, message: &[u8]) -> Result<SlhDsaSignature, SlhDsaError> {
        let mut rng = rand::thread_rng();
        use rand::RngCore;

        let sk = &self.secret_key.0;
        if sk.len() != SLH_DSA_SECRET_KEY_SIZE {
            return Err(SlhDsaError::SigningFailed);
        }

        let sk_seed = array_ref(sk, 0);
        let sk_prf = array_ref(sk, N);
        let pk_seed = array_ref(sk, 2 * N);
        let pk_root = array_ref(sk, 3 * N);

        // Step 1: Generate randomizer R.
        let mut opt_rand = [0u8; N];
        rng.fill_bytes(&mut opt_rand);
        let mut r = prf_msg(sk_prf, &opt_rand, message);

        // Step 2: Hash message to get FORS indices and HT address.
        let digest = h_msg(&r, pk_seed, pk_root, message);
        let (fors_indices, idx_tree, idx_leaf) = parse_msg_digest(&digest);

        // Step 3: FORS signing.
        let mut fors_adrs = Adrs::default();
        fors_adrs.set_tree(idx_tree);
        fors_adrs.set_type_and_clear(ADRS_FORS_TREE);
        fors_adrs.set_key_pair(idx_leaf);
        let fors_sig = fors_sign(&fors_indices, sk_seed, pk_seed, &fors_adrs);

        // Recover FORS public key (to be signed by HT).
        let fors_pk = fors_pk_from_sig(&fors_sig, &fors_indices, pk_seed, &fors_adrs);

        // Step 4: HT signing.
        let ht_sig = ht_sign(&fors_pk, sk_seed, pk_seed, idx_tree, idx_leaf);

        // Step 5: Assemble signature.
        let mut signature = Vec::with_capacity(SLH_DSA_SIGNATURE_SIZE);
        signature.extend_from_slice(&r);
        signature.extend_from_slice(&fors_sig);
        signature.extend_from_slice(&ht_sig);

        // Zeroize intermediate secret values from signing process.
        crate::zeroize::zeroize_bytes(&mut opt_rand);
        crate::zeroize::zeroize_bytes(&mut r);

        debug_assert_eq!(signature.len(), SLH_DSA_SIGNATURE_SIZE);
        Ok(SlhDsaSignature(signature))
    }
}

/// Extract a fixed-size array reference from a slice at the given offset.
fn array_ref(data: &[u8], offset: usize) -> &[u8; N] {
    data[offset..offset + N]
        .try_into()
        .expect("caller must ensure data[offset..offset+N] is in bounds")
}

/// Verify an SLH-DSA signature.
///
/// Follows FIPS 205 verification:
/// 1. Parse signature → R, FORS_SIG, HT_SIG
/// 2. Recompute message hash → FORS indices + HT address
/// 3. Recover FORS public key from FORS signature
/// 4. Verify HT signature authenticates FORS PK against PK.root
pub fn verify(
    public_key: &SlhDsaPublicKey,
    message: &[u8],
    signature: &SlhDsaSignature,
) -> Result<(), SlhDsaError> {
    if signature.0.len() != SLH_DSA_SIGNATURE_SIZE {
        return Err(SlhDsaError::InvalidSignatureLength {
            expected: SLH_DSA_SIGNATURE_SIZE,
            got: signature.0.len(),
        });
    }
    if public_key.0.len() != SLH_DSA_PUBLIC_KEY_SIZE {
        return Err(SlhDsaError::InvalidPublicKeyLength {
            expected: SLH_DSA_PUBLIC_KEY_SIZE,
            got: public_key.0.len(),
        });
    }

    let pk_seed: &[u8; N] = public_key
        .pk_seed()
        .try_into()
        .expect("pk length validated above");
    let pk_root: &[u8; N] = public_key
        .pk_root()
        .try_into()
        .expect("pk length validated above");

    // Parse signature.
    let r: &[u8; N] = signature.0[..N]
        .try_into()
        .expect("sig length validated above");
    let fors_sig = &signature.0[N..N + FORS_SIG_SIZE];
    let ht_sig = &signature.0[N + FORS_SIG_SIZE..];

    // Recompute message hash.
    let digest = h_msg(r, pk_seed, pk_root, message);
    let (fors_indices, idx_tree, idx_leaf) = parse_msg_digest(&digest);

    // Recover FORS public key.
    let mut fors_adrs = Adrs::default();
    fors_adrs.set_tree(idx_tree);
    fors_adrs.set_type_and_clear(ADRS_FORS_TREE);
    fors_adrs.set_key_pair(idx_leaf);
    let fors_pk = fors_pk_from_sig(fors_sig, &fors_indices, pk_seed, &fors_adrs);

    // Verify HT signature.
    if ht_verify(&fors_pk, ht_sig, pk_seed, idx_tree, idx_leaf, pk_root) {
        Ok(())
    } else {
        Err(SlhDsaError::VerificationFailed)
    }
}

/// Check if two SLH-DSA signatures on different messages with the same
/// public key constitute equivocation proof.
///
/// This is the core of Brrq's hash-based fraud detection (Layer 4 of PHA).
///
/// ## Equivocation Detection
///
/// If a sequencer signs two different blocks at the same height:
/// - sig1 = SLH-DSA.Sign(sk, Block1 || height || epoch)
/// - sig2 = SLH-DSA.Sign(sk, Block2 || height || epoch)
/// - Block1 != Block2
///
/// Then (sig1, sig2, Block1, Block2, pk, height) constitutes
/// a mathematical proof of fraud — **using only hash functions**.
pub fn verify_equivocation(
    public_key: &SlhDsaPublicKey,
    message1: &[u8],
    signature1: &SlhDsaSignature,
    message2: &[u8],
    signature2: &SlhDsaSignature,
) -> Result<bool, SlhDsaError> {
    // Messages must be different (otherwise it's not equivocation).
    if message1 == message2 {
        return Ok(false);
    }

    // Both signatures must be valid under the same public key.
    verify(public_key, message1, signature1)?;
    verify(public_key, message2, signature2)?;

    // If both verify: this is equivocation proof.
    Ok(true)
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let kp = SlhDsaKeyPair::generate().unwrap();
        assert_eq!(kp.public_key().as_bytes().len(), SLH_DSA_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_produces_correct_size() {
        let kp = SlhDsaKeyPair::generate().unwrap();
        let sig = kp.sign(b"test message").unwrap();
        assert_eq!(sig.size(), SLH_DSA_SIGNATURE_SIZE);
    }

    #[test]
    fn test_sign_is_randomized() {
        let kp = SlhDsaKeyPair::generate().unwrap();
        let msg = b"same message";
        let sig1 = kp.sign(msg).unwrap();
        let sig2 = kp.sign(msg).unwrap();
        // Randomized signatures should differ.
        assert_ne!(sig1.0, sig2.0);
    }

    #[test]
    fn test_verify_valid_signature() {
        let kp = SlhDsaKeyPair::generate().unwrap();
        let msg = b"verify me";
        let sig = kp.sign(msg).unwrap();
        assert!(verify(kp.public_key(), msg, &sig).is_ok());
    }

    #[test]
    fn test_equivocation_detection() {
        let kp = SlhDsaKeyPair::generate().unwrap();
        let block1 = b"block data A || height=100 || epoch=5";
        let block2 = b"block data B || height=100 || epoch=5";
        let sig1 = kp.sign(block1).unwrap();
        let sig2 = kp.sign(block2).unwrap();

        let is_equivocation =
            verify_equivocation(kp.public_key(), block1, &sig1, block2, &sig2).unwrap();
        assert!(is_equivocation);
    }

    #[test]
    fn test_same_message_not_equivocation() {
        let kp = SlhDsaKeyPair::generate().unwrap();
        let msg = b"same block";
        let sig1 = kp.sign(msg).unwrap();
        let sig2 = kp.sign(msg).unwrap();

        let is_equivocation = verify_equivocation(kp.public_key(), msg, &sig1, msg, &sig2).unwrap();
        assert!(!is_equivocation);
    }

    #[test]
    fn test_signature_size_constant() {
        assert_eq!(SlhDsaSignature::EXPECTED_SIZE, 7_856);
    }

    #[test]
    fn test_verify_rejects_tampered_signature() {
        let kp = SlhDsaKeyPair::generate().unwrap();
        let msg = b"important message";
        let mut sig = kp.sign(msg).unwrap();
        // Tamper with a byte inside the FORS signature region.
        sig.0[N + 10] ^= 0xFF;
        assert!(verify(kp.public_key(), msg, &sig).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_message() {
        let kp = SlhDsaKeyPair::generate().unwrap();
        let sig = kp.sign(b"message A").unwrap();
        assert!(verify(kp.public_key(), b"message B", &sig).is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_public_key() {
        let kp1 = SlhDsaKeyPair::generate().unwrap();
        let kp2 = SlhDsaKeyPair::generate().unwrap();
        let msg = b"test";
        let sig = kp1.sign(msg).unwrap();
        assert!(verify(kp2.public_key(), msg, &sig).is_err());
    }

    // FIPS 205 structural tests

    #[test]
    fn test_base_w_conversion() {
        let input = [0xAB, 0xCD];
        let digits = base_w(&input, 4);
        assert_eq!(digits, vec![0xA, 0xB, 0xC, 0xD]);
    }

    #[test]
    fn test_wots_msg_digits_length() {
        let msg = [0u8; N];
        let digits = wots_msg_digits(&msg);
        assert_eq!(digits.len(), LEN); // 35 digits
    }

    #[test]
    fn test_wots_checksum_range() {
        // All-zero message: each digit = 0, checksum = 32 * 15 = 480.
        let msg = [0u8; N];
        let digits = wots_msg_digits(&msg);
        for &d in &digits {
            assert!(d < W, "digit {} >= w={}", d, W);
        }
    }

    #[test]
    fn test_fors_sign_verify_consistency() {
        let mut rng = rand::thread_rng();
        use rand::RngCore;
        let mut sk_seed = [0u8; N];
        let mut pk_seed = [0u8; N];
        rng.fill_bytes(&mut sk_seed);
        rng.fill_bytes(&mut pk_seed);

        let mut adrs = Adrs::default();
        adrs.set_type_and_clear(ADRS_FORS_TREE);
        adrs.set_key_pair(0);

        // Generate arbitrary FORS indices.
        let indices: Vec<u32> = (0..K as u32).map(|i| i % (1 << A) as u32).collect();

        let sig = fors_sign(&indices, &sk_seed, &pk_seed, &adrs);
        let pk1 = fors_pk_from_sig(&sig, &indices, &pk_seed, &adrs);

        // Sign again with same indices should produce same PK.
        let sig2 = fors_sign(&indices, &sk_seed, &pk_seed, &adrs);
        let pk2 = fors_pk_from_sig(&sig2, &indices, &pk_seed, &adrs);
        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_signature_layout_sizes() {
        // Verify the signature component sizes add up correctly.
        let r_size = N; // 16
        let fors_size = K * (1 + A) * N; // 14 * 13 * 16 = 2912
        let ht_size = D * (LEN + HP) * N; // 7 * 44 * 16 = 4928
        assert_eq!(r_size, 16);
        assert_eq!(fors_size, 2912);
        assert_eq!(ht_size, 4928);
        assert_eq!(r_size + fors_size + ht_size, SLH_DSA_SIGNATURE_SIZE);
    }

    #[test]
    fn test_h_msg_output_length() {
        let r = [0u8; N];
        let pk_seed = [1u8; N];
        let pk_root = [2u8; N];
        let digest = h_msg(&r, &pk_seed, &pk_root, b"test");
        assert_eq!(digest.len(), H_MSG_LEN);
    }

    #[test]
    fn test_deterministic_kat_from_fixed_seed() {
        // Deterministic KAT: generate from fixed seed, verify structural properties.
        // This catches regressions in the implementation across updates.
        let seed = [0x42u8; 32];
        let kp = SlhDsaKeyPair::from_seed(&seed).unwrap();
        let msg = b"BRRQ SLH-DSA KAT v1";

        let sig = kp.sign(msg).unwrap();

        // Structural invariants that must hold for any correct FIPS 205 implementation:
        assert_eq!(
            sig.size(),
            SLH_DSA_SIGNATURE_SIZE,
            "SLH-DSA-SHA2-128s signature must be {SLH_DSA_SIGNATURE_SIZE} bytes"
        );
        assert!(
            verify(kp.public_key(), msg, &sig).is_ok(),
            "Signature must verify against signing key"
        );
        assert!(
            verify(kp.public_key(), b"wrong message", &sig).is_err(),
            "Signature must NOT verify against wrong message"
        );

        // Verify public key size matches FIPS 205 SLH-DSA-SHA2-128s (PK.seed + PK.root = 2n)
        assert_eq!(
            kp.public_key().as_bytes().len(),
            SLH_DSA_PUBLIC_KEY_SIZE,
            "Public key must be {SLH_DSA_PUBLIC_KEY_SIZE} bytes"
        );

        // Deterministic seed must produce the same keypair every time
        let kp2 = SlhDsaKeyPair::from_seed(&seed).unwrap();
        assert_eq!(
            kp.public_key().as_bytes(),
            kp2.public_key().as_bytes(),
            "Same seed must produce identical public key"
        );
    }
}
