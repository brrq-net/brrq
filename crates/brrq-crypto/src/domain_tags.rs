//! Centralized domain separation constants for the Brrq protocol.
//!
//! Domain separation prevents cross-context hash collisions by ensuring
//! every hash computation includes a unique tag. All tags MUST be defined
//! here — never use inline string literals for domain separation.
//!
//! ## Naming Convention
//!
//! `BRRQ_{SUBSYSTEM}_{PURPOSE}[_VERSION]`
//!
//! ## Security Invariant
//!
//! No two tags may share a prefix. Tags are sorted alphabetically to make
//! it easy to verify this property by inspection.

// ── Account & Address ───────────────────────────────────────────────
pub const ACCOUNT_V1: &[u8] = b"BRRQ_ACCOUNT_V1";
pub const ADDR_V1: &[u8] = b"BRRQ_ADDR_V1";
/// Domain tag for address checksum computation.
/// Used in SHA-256("BRRQ_ADDR_CHECKSUM" || address_bytes)[0..4].
pub const ADDR_CHECKSUM: &[u8] = b"BRRQ_ADDR_CHECKSUM";

// ── Block ───────────────────────────────────────────────────────────
pub const BLOCK_HDR_V1: &[u8] = b"BRRQ_BLOCK_HDR_V1";

// ── Consensus & Epoch ───────────────────────────────────────────────
/// Epoch seed derivation via RANDAO.
pub const EPOCH_SEED_RANDAO: &[u8] = b"BRRQ_EPOCH_SEED_RANDAO";
/// RANDAO secret derivation (centralized from block_builder.rs/node.rs).
pub const RANDAO_SECRET_V1: &[u8] = b"BRRQ_RANDAO_SECRET_V1";
pub const RANDAO_COMMITMENT_V1: &[u8] = b"BRRQ_RANDAO_COMMITMENT_V1";
pub const RANDAO_REVEAL_V1: &[u8] = b"BRRQ_RANDAO_REVEAL_V1";
/// Centralized from inline `b"RANDAO_XOR_HASH"` in epoch.rs compute_randao_xor().
/// Used to hash the XOR of all RANDAO reveals for bias resistance.
pub const RANDAO_XOR_HASH: &[u8] = b"BRRQ_RANDAO_XOR_HASH";

// ── Cryptographic Keys ──────────────────────────────────────────────
pub const EOTS_BOND_KEY: &[u8] = b"BRRQ_EOTS_BOND_KEY";
pub const EOTS_EPOCH_KEY: &[u8] = b"BRRQ_EOTS_EPOCH_KEY";
pub const EOTS_CHALLENGE: &[u8] = b"BRRQ_EOTS/challenge";
/// EOTS deterministic nonce derivation (without chain binding).
pub const EOTS_NONCE: &[u8] = b"BRRQ_EOTS_NONCE";
/// EOTS deterministic nonce derivation with prev_block_hash binding.
pub const EOTS_NONCE_V2: &[u8] = b"BRRQ_EOTSv2_NONCE";
pub const SLH_DSA_KEY: &[u8] = b"BRRQ_SLH_DSA_KEY";
pub const SLH_SK_SEED: &[u8] = b"BRRQ_SLH_SK_SEED";
pub const SLH_SK_PRF: &[u8] = b"BRRQ_SLH_SK_PRF";
pub const SLH_PK_SEED: &[u8] = b"BRRQ_SLH_PK_SEED";

// ── Encryption ──────────────────────────────────────────────────────
/// CTR-mode keystream block derivation via tagged_hash.
/// Used in SHA-256 CTR stream cipher: keystream[i] = tagged_hash(tag, key || counter || nonce).
pub const CTR_KEYSTREAM_V1: &str = "BRRQ_CTR_KEYSTREAM_V1";
/// Epoch key derivation (used via tagged_hash, not byte literal).
pub const EPOCH_KEY: &str = "BRRQ_EPOCH_KEY";
/// L1-anchored epoch key derivation — includes L1 block hash to prevent
/// sequencer from deriving the key before committing ordering on-chain.
pub const EPOCH_ANCHORED_KEY: &str = "BRRQ_EPOCH_ANCHORED_KEY";
pub const ENC_SUBKEY: &[u8] = b"BRRQ_ENC_SUBKEY";
pub const MAC_SUBKEY: &[u8] = b"BRRQ_MAC_SUBKEY";

// ── MEV Protection ────────────────────────────────────────────────
pub const MEV_ENVELOPE_V1: &[u8] = b"BRRQ_MEV_ENVELOPE_V1";
/// MEV envelope signature domain tag.
pub const MEV_ENVELOPE_SIG_V1: &[u8] = b"BRRQ_MEVv1_ENVELOPE_SIG";
pub const MEV_META_V1: &[u8] = b"BRRQ_MEV_META_V1";
pub const MEV_ORDERING_V1: &[u8] = b"BRRQ_MEV_ORDERING_V1";
/// L1 ordering anchor domain tag.
/// Used to commit block ordering to Bitcoin L1 via OP_RETURN.
pub const MEV_L1_ANCHOR_V1: &[u8] = b"BRRQ_MEV_L1_ANCHOR_V1";

// ── Threshold Encryption ─────────────────────────────────────────
/// Domain tag for threshold key share derivation.
pub const THRESHOLD_SHARE_V1: &[u8] = b"BRRQ_THRESH_SHARE_V1";
/// Domain tag for threshold epoch key reconstruction.
pub const THRESHOLD_RECON_V1: &[u8] = b"BRRQ_THRESH_RECON_V1";

// ── Sequencer Rotation ────────────────────────────────────────────
pub const BLOCK_PROPOSAL_V1: &[u8] = b"BRRQ_BLOCK_PROPOSAL_V1";
pub const BLOCK_PREVOTE_V1: &[u8] = b"BRRQ_BLOCK_PREVOTE_V1";
pub const BLOCK_PRECOMMIT_V1: &[u8] = b"BRRQ_BLOCK_PRECOMMIT_V1";
pub const TIMEOUT_VOTE_V1: &[u8] = b"BRRQ_TIMEOUT_VOTE_V1";

// ── Dual-Hash ────────────────────────────────────────────────────
/// Domain tag for the combined DualHash commitment.
/// Used in SHA-256(DUAL_HASH_V1 || sha256 || poseidon2).
pub const DUAL_HASH_V1: &[u8] = b"BRRQ_DUAL_HASH";

/// Backward compatibility tag for serialized data.
#[deprecated(note = "Use dual_hash() directly.")]
pub const POSEIDON2_COMPAT_V1: &[u8] = b"BRRQ_POSEIDON2_COMPAT";

// ── Bridge (BitVM2 / Disputes / Emergency Exit) ────────────────────
/// Emergency exit domain tag (centralized from brrq-bridge).
pub const EMERGENCY_EXIT_V1: &[u8] = b"BRRQ_EMERGENCY_EXIT_V1";
/// Dispute game domain tag (centralized from brrq-bridge).
pub const DISPUTE_GAME_V1: &[u8] = b"BRRQ_DISPUTE_GAME_V1";
/// BitVM2 state domain tag (centralized from brrq-bridge).
pub const BITVM2_STATE_V1: &[u8] = b"BRRQ_BITVM2_STATE_V1";

// ── STARK Prover ────────────────────────────────────────────────────
pub const STARK_TRANSCRIPT_V2: &[u8] = b"BRRQ_STARK_v2";
/// SNARK simulation domain tag.
pub const SNARK_SIMULATION_V1: &[u8] = b"BRRQ_SNARK_SIMULATION_V1";
/// FRI commitment domain tag (centralized from brrq-prover).
pub const FRI_COMMIT: &[u8] = b"BRRQ_FRI_COMMIT";
/// Query proof domain tag (centralized from brrq-prover).
pub const QUERY_PROOF: &[u8] = b"BRRQ_QUERY_PROOF";
/// Circuit output domain tag (centralized from brrq-prover).
pub const CIRCUIT_OUT: &[u8] = b"BRRQ_CIRCUIT_OUT";

// ── Synthetic Deposits ──────────────────────────────────────────────
/// Domain tag for synthetic deposit transaction hashing.
pub const DEPOSIT_SYNTHETIC_V1: &[u8] = b"BRRQ_DEPOSIT_SYNTH_V1";

// ── API Request Signatures ─────────────────────────────────────────
/// Domain tag for API request signature verification.
/// Used in SHA-256(API_REQUEST_SIG_V1 || canonical_message) to produce
/// the message hash verified against the caller's Schnorr signature.
pub const API_REQUEST_SIG_V1: &[u8] = b"BRRQ_API_REQUEST_SIG_V1";

// ── Transaction ─────────────────────────────────────────────────────
pub const TX_BODY_V1: &[u8] = b"BRRQ_TX_BODY_V1";
pub const TX_LIGHT_V1: &[u8] = b"BRRQ_TX_LIGHT_V1";
pub const TX_FULL_V1: &[u8] = b"BRRQ_TX_FULL_V1";

// ── VRF (Verifiable Random Function) ──────────────────────────────
pub const VRF_H2C: &[u8] = b"BRRQ_VRF_H2C";
pub const VRF_DLEQ: &[u8] = b"BRRQ_VRF_DLEQ";
pub const VRF_OUTPUT: &[u8] = b"BRRQ_VRF_OUTPUT";

// ── Portal (L3 Pragmatic Portal) ──────────────────────────────────
/// Domain tag for Portal lock ID derivation.
/// lock_id = SHA-256(PORTAL_LOCK_V1 || owner || amount || condition_hash || timeout || nonce)
pub const PORTAL_LOCK_V1: &[u8] = b"BRRQ_PORTAL_LOCK_V1";
/// Domain tag for Portal nullifier computation.
/// nullifier = HMAC-SHA256(secret_key, PORTAL_NULLIFIER_V1 || lock_id || condition_hash)
pub const PORTAL_NULLIFIER_V1: &[u8] = b"BRRQ_PORTAL_NULLIFIER_V1";
/// Domain tag for Portal Key signature payload.
/// payload = SHA-256(PORTAL_KEY_SIG_V1 || lock_id || condition_hash || timeout)
pub const PORTAL_KEY_SIG_V1: &[u8] = b"BRRQ_PORTAL_KEY_SIG_V1";
/// Domain tag for Portal batch settlement Merkle root.
pub const PORTAL_BATCH_V1: &[u8] = b"BRRQ_PORTAL_BATCH_V1";
/// Lock Pool ID: SHA-256(PORTAL_POOL_V1 || owner || slot_amounts || timeout || nonce)
pub const PORTAL_POOL_V1: &[u8] = b"BRRQ_PORTAL_POOL_V1";
/// Prepaid card receipt signature payload tag.
pub const PORTAL_RECEIPT_V1: &[u8] = b"BRRQ_PORTAL_RECEIPT_V1";

// ── Merkle Tree (byte-valued domain prefixes) ───────────────────────
/// Merkle leaf prefix (0x00). Used in hash_leaf() to domain-separate
/// leaf hashes from internal node hashes, preventing second-preimage attacks.
pub const MERKLE_LEAF: &[u8] = &[0x00];
/// Merkle internal node prefix (0x01). Used in hash_node().
pub const MERKLE_NODE: &[u8] = &[0x01];

// ── MuSig2 (Aggregate Signatures) ─────────────────────────────────
pub const MUSIG2_KEYAGG_LIST: &[u8] = b"BRRQ_MUSIG2_KEYAGG_LIST";
pub const MUSIG2_KEYAGG_COEF: &[u8] = b"BRRQ_MUSIG2_KEYAGG_COEF";
pub const MUSIG2_NONCECOEF: &[u8] = b"BRRQ_MUSIG2_NONCECOEF";
/// MuSig2 hedged nonce generation — R1 component.
pub const MUSIG2_NONCE_GEN_R1: &[u8] = b"BRRQ_MUSIG2_NONCE_GEN_R1";
/// MuSig2 hedged nonce generation — R2 component.
pub const MUSIG2_NONCE_GEN_R2: &[u8] = b"BRRQ_MUSIG2_NONCE_GEN_R2";

#[cfg(test)]
mod tests {
    use super::*;

    /// All domain tags (both &[u8] and &str) for exhaustive testing.
    #[allow(deprecated)]
    fn all_tags() -> Vec<&'static [u8]> {
        vec![
            ACCOUNT_V1,
            ADDR_V1,
            ADDR_CHECKSUM,
            BLOCK_HDR_V1,
            EPOCH_SEED_RANDAO,
            RANDAO_SECRET_V1,
            RANDAO_COMMITMENT_V1,
            RANDAO_REVEAL_V1,
            RANDAO_XOR_HASH,
            EOTS_BOND_KEY,
            EOTS_EPOCH_KEY,
            EOTS_CHALLENGE,
            EOTS_NONCE,
            EOTS_NONCE_V2,
            SLH_DSA_KEY,
            SLH_SK_SEED,
            SLH_SK_PRF,
            SLH_PK_SEED,
            CTR_KEYSTREAM_V1.as_bytes(),
            EPOCH_KEY.as_bytes(),
            EPOCH_ANCHORED_KEY.as_bytes(),
            ENC_SUBKEY,
            MAC_SUBKEY,
            MEV_ENVELOPE_V1,
            MEV_ENVELOPE_SIG_V1,
            MEV_META_V1,
            MEV_ORDERING_V1,
            MEV_L1_ANCHOR_V1,
            THRESHOLD_SHARE_V1,
            THRESHOLD_RECON_V1,
            DUAL_HASH_V1,
            POSEIDON2_COMPAT_V1,
            BLOCK_PROPOSAL_V1,
            BLOCK_PREVOTE_V1,
            BLOCK_PRECOMMIT_V1,
            TIMEOUT_VOTE_V1,
            EMERGENCY_EXIT_V1,
            DISPUTE_GAME_V1,
            BITVM2_STATE_V1,
            STARK_TRANSCRIPT_V2,
            SNARK_SIMULATION_V1,
            FRI_COMMIT,
            QUERY_PROOF,
            CIRCUIT_OUT,
            DEPOSIT_SYNTHETIC_V1,
            API_REQUEST_SIG_V1,
            TX_BODY_V1,
            TX_LIGHT_V1,
            TX_FULL_V1,
            VRF_H2C,
            VRF_DLEQ,
            VRF_OUTPUT,
            PORTAL_LOCK_V1,
            PORTAL_NULLIFIER_V1,
            PORTAL_KEY_SIG_V1,
            PORTAL_BATCH_V1,
            PORTAL_POOL_V1,
            PORTAL_RECEIPT_V1,
            MUSIG2_KEYAGG_LIST,
            MUSIG2_KEYAGG_COEF,
            MUSIG2_NONCECOEF,
            MUSIG2_NONCE_GEN_R1,
            MUSIG2_NONCE_GEN_R2,
        ]
    }

    /// Verify all tags are unique (no duplicates).
    #[test]
    fn test_all_tags_unique() {
        let tags = all_tags();
        for i in 0..tags.len() {
            for j in (i + 1)..tags.len() {
                assert_ne!(
                    tags[i],
                    tags[j],
                    "duplicate domain tag: {:?}",
                    std::str::from_utf8(tags[i])
                );
            }
        }
    }

    /// Verify no tag is a prefix of another tag.
    ///
    /// This is the security invariant stated in the module doc:
    /// "No two tags may share a prefix."
    /// A prefix collision would allow an attacker to craft data that
    /// is valid under two different domain-separated hash contexts.
    #[test]
    fn test_no_prefix_collisions() {
        let tags = all_tags();
        for i in 0..tags.len() {
            for j in 0..tags.len() {
                if i != j && tags[j].starts_with(tags[i]) {
                    panic!(
                        "prefix collision: {:?} is a prefix of {:?}",
                        std::str::from_utf8(tags[i]).unwrap_or("<invalid>"),
                        std::str::from_utf8(tags[j]).unwrap_or("<invalid>"),
                    );
                }
            }
        }
    }

    /// Verify all tags follow the BRRQ_ prefix convention.
    #[test]
    fn test_all_tags_have_brrq_prefix() {
        let tags = all_tags();
        for tag in &tags {
            let s = std::str::from_utf8(tag).unwrap_or("<invalid>");
            assert!(
                s.starts_with("BRRQ_") || s.starts_with("brrq-"),
                "tag {:?} does not follow BRRQ_ prefix convention",
                s
            );
        }
    }
}
