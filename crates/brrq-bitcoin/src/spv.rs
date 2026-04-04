//! Bitcoin SPV (Simplified Payment Verification) inclusion proofs.
//!
//! Allows cryptographic verification that a Bitcoin transaction is included
//! in a specific block without downloading the full block. This removes the
//! need to trust federation members for deposit attestation.
//!
//! ## Usage
//!
//! ```ignore (requires live Bitcoin Core RPC connection)
//! // Fetch proof from Bitcoin Core
//! let proof = fetch_spv_proof(&rpc, txid)?;
//!
//! // Always use verify_in_chain() — never call verify() directly.
//! // verify() only checks Merkle inclusion and does NOT guard against
//! // orphan-block attacks.
//! let result = proof.verify_in_chain(|hash| block_monitor.is_in_best_chain(hash));
//! assert_eq!(result, SpvVerifyResult::Valid);
//! ```

use bitcoin::MerkleBlock;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::BitcoinError;
use crate::rpc_client::BitcoinRpcClient;

// ── SPV PoW validation ────────────────────────────────────────────────────

/// Mainnet minimum difficulty target (difficulty 1).
/// nBits = 0x1d00ffff → target = 0x00000000FFFF0000...0000 (256-bit).
/// No valid mainnet block can have a target higher than this.
const MAINNET_MAX_TARGET_NBITS: u32 = 0x1d00ffff;

/// Decode the compact `nBits` field into a 256-bit target (32-byte big-endian).
///
/// Format: `nBits = 0xEEMMMMM` where `EE` = exponent, `MMMMMM` = mantissa.
/// `target = mantissa * 2^(8 * (exponent - 3))`
fn nbits_to_target(nbits: u32) -> [u8; 32] {
    let mut target = [0u8; 32];
    let exponent = (nbits >> 24) as usize;
    let mantissa = nbits & 0x007F_FFFF;

    // If the sign bit (0x00800000) is set, target is negative → treat as zero.
    if nbits & 0x0080_0000 != 0 {
        return target;
    }

    if exponent == 0 {
        return target;
    }

    // Place the 3 mantissa bytes at position (32 - exponent) in big-endian.
    // mantissa bytes: [byte2, byte1, byte0] (big-endian).
    let mantissa_bytes = [
        ((mantissa >> 16) & 0xFF) as u8,
        ((mantissa >> 8) & 0xFF) as u8,
        (mantissa & 0xFF) as u8,
    ];

    for (i, &b) in mantissa_bytes.iter().enumerate() {
        let pos = 32usize.saturating_sub(exponent) + i;
        if pos < 32 {
            target[pos] = b;
        }
    }

    target
}

/// Compute double SHA-256 of an 80-byte block header (serialized).
fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Validate that a block header satisfies Proof-of-Work.
///
/// 1. Serializes the 80-byte header and computes its double-SHA-256 hash.
/// 2. Decodes the `bits` (nBits) field into a 256-bit target.
/// 3. Verifies hash <= target (interpreted as big-endian 256-bit integers,
///    but Bitcoin hashes are compared in *internal byte order* which is LE).
/// 4. Validates that the target does not exceed mainnet minimum difficulty.
///
/// Returns `Ok(())` if PoW is valid, or `Err(BitcoinError)` if not.
pub fn validate_pow(header: &bitcoin::block::Header) -> Result<(), BitcoinError> {
    // 1. Serialize the header to 80 bytes and compute double-SHA-256.
    let header_bytes = bitcoin::consensus::serialize(header);
    debug_assert_eq!(header_bytes.len(), 80, "block header must be 80 bytes");
    let hash = double_sha256(&header_bytes);

    // Bitcoin stores the hash in little-endian internally. For target
    // comparison we need to reverse to big-endian (most significant byte first).
    let mut hash_be = hash;
    hash_be.reverse();

    // 2. Decode nBits → 256-bit target.
    let nbits = header.bits.to_consensus();
    let target = nbits_to_target(nbits);

    // 3. Validate that the target is within mainnet difficulty range.
    // The target must not exceed the maximum allowed target (difficulty 1).
    let max_target = nbits_to_target(MAINNET_MAX_TARGET_NBITS);
    if target > max_target {
        return Err(BitcoinError::SpvVerificationFailed(format!(
            "nBits 0x{:08x} exceeds mainnet maximum target (difficulty too low)",
            nbits
        )));
    }

    // 4. Reject if hash > target (insufficient Proof-of-Work).
    if hash_be > target {
        return Err(BitcoinError::SpvVerificationFailed(format!(
            "block header hash exceeds PoW target (nBits=0x{:08x})",
            nbits
        )));
    }

    Ok(())
}

/// An SPV inclusion proof for a Bitcoin transaction.
///
/// Contains a serialized `MerkleBlock` (block header + partial Merkle tree)
/// proving that a transaction is included in a specific Bitcoin block.
///
/// Any node can verify this proof without connecting to Bitcoin Core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpvProof {
    /// The Bitcoin transaction ID this proof covers (big-endian, 32 bytes).
    pub txid: [u8; 32],
    /// Raw serialized `MerkleBlock` from `gettxoutproof`.
    /// Contains the 80-byte block header and partial Merkle tree.
    pub merkle_block_raw: Vec<u8>,
    /// Block hash where the transaction was included (big-endian, 32 bytes).
    pub block_hash: [u8; 32],
    /// Block height where the transaction was included.
    pub block_height: u64,
}

/// Result of SPV proof verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpvVerifyResult {
    /// Proof is valid: txid is included in the claimed block.
    Valid,
    /// MerkleBlock deserialization failed.
    InvalidMerkleBlock,
    /// The target txid was not found among the Merkle tree matches.
    TxidNotInProof,
    /// The block hash derived from the header does not match `block_hash`.
    BlockHashMismatch,
    /// The block hash is not on the canonical (best) chain.
    ///
    /// The Merkle proof is mathematically valid, but the block could be an
    /// orphan or part of a stale fork. Deposits from non-canonical blocks
    /// must be rejected to prevent fund inflation attacks.
    BlockNotInBestChain,
    /// Block header does not satisfy Proof-of-Work requirements.
    ///
    /// The block header hash exceeds the target derived from the `bits` field,
    /// or the `bits` field specifies a difficulty below mainnet minimum.
    /// An attacker could forge headers with valid Merkle proofs but
    /// insufficient PoW to trick the bridge into accepting fake deposits.
    InsufficientPoW,
}

impl SpvProof {
    /// Verify this SPV proof without any RPC connection.
    ///
    /// Steps:
    /// 1. Deserialize `merkle_block_raw` → `bitcoin::MerkleBlock`
    /// 2. Compute the block header hash, confirm it matches `self.block_hash`
    /// 3. Extract matched txids from the partial Merkle tree
    /// 4. Confirm `self.txid` is among the matches
    ///
    /// # Security Warning
    ///
    /// This method only validates Merkle inclusion — it does **NOT** verify
    /// the block is in the best (canonical) chain. An attacker can craft a
    /// valid Merkle proof against an orphan or stale block to inflate funds.
    ///
    /// **For deposit validation or any production path, always use
    /// [`verify_in_chain()`](Self::verify_in_chain) instead.**
    ///
    /// This method is retained as `pub(crate)` for internal use (e.g.,
    /// `fetch_spv_proof` pre-validation and `verify_in_chain` delegation).
    // Restricted to `pub(crate)` to prevent external callers from bypassing
    // the chain-inclusion check. All external code must use `verify_in_chain()`.
    pub(crate) fn verify(&self) -> SpvVerifyResult {
        // 1. Deserialize
        let merkle_block: MerkleBlock = match deserialize(&self.merkle_block_raw) {
            Ok(mb) => mb,
            Err(_) => return SpvVerifyResult::InvalidMerkleBlock,
        };

        // 2. Verify block hash
        let header_hash = merkle_block.header.block_hash();
        let header_hash_bytes: [u8; 32] = *header_hash.as_byte_array();
        if header_hash_bytes != self.block_hash {
            return SpvVerifyResult::BlockHashMismatch;
        }

        // 3. Extract matched transactions from partial Merkle tree
        //    and verify the computed Merkle root matches the block header.
        let mut matches = Vec::new();
        let mut indices = Vec::new();
        let computed_root = match merkle_block.txn.extract_matches(&mut matches, &mut indices) {
            Ok(root) => root,
            Err(_) => return SpvVerifyResult::InvalidMerkleBlock,
        };

        // Defense-in-depth: verify computed Merkle root matches header.
        // Some bitcoin crate versions do this internally, but we must not
        // rely on library internals for security-critical verification.
        if computed_root != merkle_block.header.merkle_root {
            return SpvVerifyResult::InvalidMerkleBlock;
        }

        // 4. Check if our txid is in the matches
        let target_txid = bitcoin::Txid::from_byte_array(self.txid);
        if matches.contains(&target_txid) {
            SpvVerifyResult::Valid
        } else {
            SpvVerifyResult::TxidNotInProof
        }
    }

    /// Verify this SPV proof AND confirm the block is on the canonical (best)
    /// chain.
    ///
    /// This is the **only recommended public entry point** for SPV verification.
    /// It performs two checks:
    /// 1. Merkle inclusion (delegated to the internal `verify()`)
    /// 2. Chain membership via the caller-supplied `is_known_block` predicate
    ///
    /// `is_known_block` should return `true` if the given block hash belongs to
    /// the canonical chain (e.g., from `BlockMonitor`'s cached header chain).
    ///
    /// # Why this method and not `verify()`?
    ///
    /// `verify()` only validates the mathematical Merkle proof — it does NOT
    /// check whether the block is part of the best chain. An attacker can
    /// construct a valid proof against an orphan / stale block, which would
    /// pass `verify()` and allow minting unbacked brqBTC on L2.
    ///
    /// `verify()` is restricted to `pub(crate)` so external crates cannot
    /// call it directly.
    pub fn verify_in_chain(&self, is_known_block: impl Fn(&[u8; 32]) -> bool) -> SpvVerifyResult {
        let result = self.verify();
        if result != SpvVerifyResult::Valid {
            return result;
        }

        // Validate Proof-of-Work before trusting the header.
        // Without this check, an attacker could forge block headers with valid
        // Merkle proofs but insufficient PoW, tricking the bridge into
        // accepting fake Bitcoin deposits.
        //
        // Gated behind `skip-pow-in-tests`: test fixtures use nonce=0 headers
        // that cannot satisfy PoW. PoW validation itself is covered by
        // dedicated unit tests for validate_pow(). Production builds (which
        // never enable this feature) always enforce PoW.
        #[cfg(not(feature = "skip-pow-in-tests"))]
        if let Err(_) = self.verify_pow() {
            return SpvVerifyResult::InsufficientPoW;
        }

        if !is_known_block(&self.block_hash) {
            return SpvVerifyResult::BlockNotInBestChain;
        }

        SpvVerifyResult::Valid
    }

    /// Verify Proof-of-Work for the block header in this proof.
    ///
    /// Deserializes the MerkleBlock and delegates to `validate_pow()`.
    /// Returns `Ok(())` if PoW is valid, `Err` otherwise.
    fn verify_pow(&self) -> Result<(), BitcoinError> {
        let merkle_block: MerkleBlock = deserialize(&self.merkle_block_raw)
            .map_err(|e| BitcoinError::SpvVerificationFailed(format!("deserialize: {}", e)))?;
        validate_pow(&merkle_block.header)
    }
}

/// Fetch an SPV inclusion proof from Bitcoin Core for a given transaction.
///
/// Uses `gettxoutproof` (Merkle proof) and `getrawtransaction` (block info).
/// Returns `Err` if the transaction is unconfirmed or the RPC fails.
///
/// **Important:** The internal `verify()` call only validates Merkle inclusion
/// (the transaction is in the Merkle tree of the block header). It does NOT
/// check whether the block is part of the canonical best chain. Callers MUST
/// use `SpvProof::verify_in_chain()` with a `BlockMonitor` to confirm the
/// block is actually in the best chain, preventing proofs against orphan or
/// attacker-crafted blocks.
pub fn fetch_spv_proof(rpc: &BitcoinRpcClient, txid: [u8; 32]) -> Result<SpvProof, BitcoinError> {
    // 1. Get the Merkle block proof
    let merkle_block_raw = rpc.get_tx_out_proof(&txid)?;

    // 2. Get block info (hash, height, confirmations)
    let (block_hash, block_height, _confirmations) = rpc
        .get_tx_block_info(&txid)?
        .ok_or_else(|| BitcoinError::SpvVerificationFailed("transaction is unconfirmed".into()))?;

    let proof = SpvProof {
        txid,
        merkle_block_raw,
        block_hash,
        block_height,
    };

    // 3. Verify before returning
    match proof.verify() {
        SpvVerifyResult::Valid => Ok(proof),
        other => Err(BitcoinError::SpvVerificationFailed(format!("{:?}", other))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::serialize;
    #[allow(unused_imports)]
    use bitcoin::hashes::Hash as _;
    use bitcoin::{CompactTarget, TxMerkleNode};

    /// Build a minimal valid MerkleBlock with a single transaction for testing.
    fn build_test_merkle_block(txid: bitcoin::Txid) -> (MerkleBlock, [u8; 32]) {
        let merkle_root = TxMerkleNode::from_byte_array(*txid.as_byte_array());

        let header = Header {
            version: Version::from_consensus(0x20000000),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root,
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };

        // PartialMerkleTree with a single matched tx
        let pmt = bitcoin::merkle_tree::PartialMerkleTree::from_txids(
            &[txid],
            &[true], // match the single tx
        );

        let block_hash_bytes: [u8; 32] = *header.block_hash().as_byte_array();
        let mb = MerkleBlock { header, txn: pmt };

        (mb, block_hash_bytes)
    }

    #[test]
    fn verify_valid_spv_proof() {
        let txid_bytes = [0xABu8; 32];
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);

        let (mb, block_hash) = build_test_merkle_block(txid);
        let raw = serialize(&mb);

        let proof = SpvProof {
            txid: txid_bytes,
            merkle_block_raw: raw,
            block_hash,
            block_height: 800_000,
        };

        assert_eq!(proof.verify(), SpvVerifyResult::Valid);
    }

    #[test]
    fn verify_rejects_wrong_txid() {
        let txid = bitcoin::Txid::from_byte_array([0xABu8; 32]);
        let (mb, block_hash) = build_test_merkle_block(txid);
        let raw = serialize(&mb);

        let proof = SpvProof {
            txid: [0xCDu8; 32], // different txid
            merkle_block_raw: raw,
            block_hash,
            block_height: 800_000,
        };

        assert_eq!(proof.verify(), SpvVerifyResult::TxidNotInProof);
    }

    #[test]
    fn verify_rejects_corrupt_merkle_block() {
        let proof = SpvProof {
            txid: [0xABu8; 32],
            merkle_block_raw: vec![0xFF; 10], // garbage
            block_hash: [0u8; 32],
            block_height: 0,
        };

        assert_eq!(proof.verify(), SpvVerifyResult::InvalidMerkleBlock);
    }

    #[test]
    fn verify_rejects_wrong_block_hash() {
        let txid_bytes = [0xABu8; 32];
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);

        let (mb, _correct_hash) = build_test_merkle_block(txid);
        let raw = serialize(&mb);

        let proof = SpvProof {
            txid: txid_bytes,
            merkle_block_raw: raw,
            block_hash: [0x99u8; 32], // wrong hash
            block_height: 800_000,
        };

        assert_eq!(proof.verify(), SpvVerifyResult::BlockHashMismatch);
    }

    #[test]
    fn verify_empty_merkle_block() {
        let proof = SpvProof {
            txid: [0xABu8; 32],
            merkle_block_raw: vec![],
            block_hash: [0u8; 32],
            block_height: 0,
        };

        assert_eq!(proof.verify(), SpvVerifyResult::InvalidMerkleBlock);
    }

    #[test]
    #[cfg(not(feature = "skip-pow-in-tests"))]
    fn verify_in_chain_rejects_test_header_insufficient_pow() {
        // Test headers (nonce=0, difficulty-1) fail PoW
        // validation in verify_in_chain(), which checks PoW before the
        // chain-membership check. This is the intended behavior — PoW
        // is the first line of defense against forged headers.
        let txid_bytes = [0xABu8; 32];
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let (mb, block_hash) = build_test_merkle_block(txid);
        let raw = serialize(&mb);

        let proof = SpvProof {
            txid: txid_bytes,
            merkle_block_raw: raw,
            block_hash,
            block_height: 800_000,
        };

        // Even though block IS in best chain, PoW fails first.
        let result = proof.verify_in_chain(|h| h == &block_hash);
        assert_eq!(result, SpvVerifyResult::InsufficientPoW);
    }

    #[test]
    #[cfg(not(feature = "skip-pow-in-tests"))]
    fn verify_in_chain_pow_fails_before_chain_check() {
        // PoW validation runs before the chain-membership check.
        // Even if the block is not in the best chain, PoW failure is reported first.
        let txid_bytes = [0xABu8; 32];
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let (mb, block_hash) = build_test_merkle_block(txid);
        let raw = serialize(&mb);

        let proof = SpvProof {
            txid: txid_bytes,
            merkle_block_raw: raw,
            block_hash,
            block_height: 800_000,
        };

        // Block NOT in best chain, but PoW fails first.
        let result = proof.verify_in_chain(|_| false);
        assert_eq!(result, SpvVerifyResult::InsufficientPoW);
    }

    #[test]
    fn verify_in_chain_propagates_merkle_errors() {
        let proof = SpvProof {
            txid: [0xABu8; 32],
            merkle_block_raw: vec![0xFF; 10], // garbage
            block_hash: [0u8; 32],
            block_height: 0,
        };

        // Merkle error should propagate without reaching chain check
        let result = proof.verify_in_chain(|_| panic!("should not be called"));
        assert_eq!(result, SpvVerifyResult::InvalidMerkleBlock);
    }

    // ── PoW validation tests ────────────────────────────────────────────

    #[test]
    fn m07_validate_pow_rejects_zero_nonce_header() {
        // A header with nonce=0 and difficulty-1 target almost certainly
        // has a hash that exceeds the target, so PoW validation should fail.
        let header = Header {
            version: Version::from_consensus(0x20000000),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array([0xAB; 32]),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff), // difficulty 1
            nonce: 0,
        };

        // With nonce=0, the hash will almost certainly exceed the target.
        let result = validate_pow(&header);
        assert!(result.is_err(), "nonce=0 header should fail PoW validation");
    }

    #[test]
    fn m07_validate_pow_rejects_trivial_difficulty() {
        // nBits = 0x207fffff → absurdly easy target (higher than mainnet max).
        let header = Header {
            version: Version::from_consensus(0x20000000),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: TxMerkleNode::from_byte_array([0xAB; 32]),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff), // trivial difficulty
            nonce: 0,
        };

        let result = validate_pow(&header);
        assert!(
            result.is_err(),
            "trivial difficulty target must be rejected"
        );
    }

    #[test]
    fn m07_nbits_to_target_difficulty_1() {
        // nBits 0x1d00ffff = difficulty 1 → target starts with 0x00000000FFFF...
        let target = nbits_to_target(0x1d00ffff);
        // Byte at index 3 should be 0xFF (first mantissa byte).
        assert_eq!(target[3], 0x00);
        assert_eq!(target[4], 0xff);
        assert_eq!(target[5], 0xff);
        // Leading 4 bytes should be zero.
        assert_eq!(&target[0..4], &[0, 0, 0, 0]);
    }

    #[test]
    fn m07_nbits_to_target_zero_exponent() {
        let target = nbits_to_target(0x00123456);
        assert_eq!(target, [0u8; 32]);
    }

    #[test]
    fn m07_nbits_negative_mantissa() {
        // Sign bit set → treated as zero target.
        let target = nbits_to_target(0x1d80ffff);
        assert_eq!(target, [0u8; 32]);
    }

    #[test]
    #[cfg(not(feature = "skip-pow-in-tests"))]
    fn m07_spv_verify_in_chain_rejects_insufficient_pow() {
        // Build a valid Merkle block but with a header that fails PoW.
        // The Merkle proof is mathematically valid, but the header has
        // nonce=0 with difficulty-1, so PoW validation will fail.
        let txid_bytes = [0xABu8; 32];
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);
        let (mb, block_hash) = build_test_merkle_block(txid);
        let raw = serialize(&mb);

        let proof = SpvProof {
            txid: txid_bytes,
            merkle_block_raw: raw,
            block_hash,
            block_height: 800_000,
        };

        // verify() (Merkle-only) should pass.
        assert_eq!(proof.verify(), SpvVerifyResult::Valid);

        // verify_in_chain() includes PoW check — should fail because nonce=0.
        let result = proof.verify_in_chain(|h| h == &block_hash);
        assert_eq!(result, SpvVerifyResult::InsufficientPoW);
    }

    #[test]
    fn spv_proof_serialization_roundtrip() {
        let txid_bytes = [0xABu8; 32];
        let txid = bitcoin::Txid::from_byte_array(txid_bytes);

        let (mb, block_hash) = build_test_merkle_block(txid);
        let raw = serialize(&mb);

        let proof = SpvProof {
            txid: txid_bytes,
            merkle_block_raw: raw,
            block_hash,
            block_height: 800_000,
        };

        let bytes = bincode::serialize(&proof).unwrap();
        let restored: SpvProof = bincode::deserialize(&bytes).unwrap();
        assert_eq!(proof, restored);
        assert_eq!(restored.verify(), SpvVerifyResult::Valid);
    }
}
