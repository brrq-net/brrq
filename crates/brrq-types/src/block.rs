//! Brrq block structure with dual signing (§3.6, §7.3).
//!
//! Each block is signed by the sequencer with TWO independent signatures:
//! 1. **Schnorr/EOTS**: For self-enforcing slashing (safety net)
//!    - EOTS key is **isolated** — controls only the Bond UTXO (33.33% of stake)
//!    - If sequencer equivocates, EOTS key is extractable → immediate slashing
//!    - EOTS key is **ephemeral** per epoch to limit damage window
//! 2. **SLH-DSA**: For hash-based fraud detection (future-proof, quantum-resistant)
//!
//! ## Key Isolation Design
//!
//! ```text
//! main_key (Schnorr)  → Main UTXO (66.67% of stake) — NOT used for block signing
//! eots_key (EOTS)     → Bond UTXO (33.33% of stake) — used for EOTS block signing
//! slh_dsa_key         → Equivocation detection — used for SLH-DSA block signing
//! ```
//!
//! This ensures that even if the EOTS key is extracted (quantum attack or equivocation),
//! only the Bond UTXO is at risk — the majority of stake remains safe.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::merkle::compute_tx_root;
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::transaction::Transaction;

/// Block header — the signed portion.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height (sequential, starts at 0).
    pub height: u64,
    /// Timestamp (Unix seconds).
    pub timestamp: u64,
    /// Hash of the previous block header.
    pub parent_hash: Hash256,
    /// Merkle root of all transactions in this block.
    pub transactions_root: Hash256,
    /// Merkle root of all signatures in this block (for Signature Aggregation proofs).
    pub signatures_root: Hash256,
    /// State root after executing all transactions.
    pub state_root: Hash256,
    /// Sequencer's address.
    pub sequencer: Address,
    /// Epoch number (for EOTS nonce binding).
    pub epoch: u64,
    /// Total gas used in this block.
    pub gas_used: u64,
    /// Gas limit for this block.
    pub gas_limit: u64,
    /// EIP-1559 Base fee per gas for this block.
    pub base_fee_per_gas: u64,
    /// Bitcoin L1 block height at time of L2 block production (None if L1 not connected).
    /// Note: `serde(default)` ensures backward-compat for JSON deserialization.
    /// We do NOT use `skip_serializing_if` because bincode is positional and
    /// skipping fields breaks deserialization alignment.
    #[serde(default)]
    pub l1_anchor_height: Option<u64>,
    /// Bitcoin L1 block hash at time of L2 block production (None if L1 not connected).
    #[serde(default)]
    pub l1_anchor_hash: Option<Hash256>,
    /// Merkle root of all consumed Portal nullifiers (for light-client verification).
    /// None when no Portal transactions exist in this block's history.
    #[serde(default)]
    pub portal_nullifier_root: Option<Hash256>,
    /// SHA-256 hash of the serialized Portal escrow blob (active locks state).
    /// Commits the sequencer to the exact escrow data published alongside this block.
    /// Full nodes verify: H(received_blob) == portal_escrow_blob_hash.
    /// None when no Portal state exists.
    #[serde(default)]
    pub portal_escrow_blob_hash: Option<Hash256>,
}

impl BlockHeader {
    /// Compute the block header hash.
    ///
    /// This is the message that gets dual-signed by the sequencer.
    ///
    /// # SECURITY NOTE
    ///
    /// The `l1_anchor_height` and `l1_anchor_hash` fields are **intentionally
    /// excluded** from the hash. They are informational metadata about which
    /// Bitcoin L1 block was known at the time of L2 block production.
    ///
    /// Rationale:
    /// - L1 anchor data is not part of L2 consensus (different nodes may have
    ///   different L1 views due to propagation delays)
    /// - Including them would make block hashes dependent on L1 state, breaking
    ///   L2-only operation when Bitcoin is unavailable
    /// - L1 anchoring is verified separately via the OP_RETURN data on Bitcoin
    ///
    /// If L1 anchor integrity is critical, validate `l1_anchor_hash` against
    /// a trusted Bitcoin source independently of the L2 block hash.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::BLOCK_HDR_V1);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.timestamp.to_le_bytes());
        hasher.update(self.parent_hash.as_bytes());
        hasher.update(self.transactions_root.as_bytes());
        hasher.update(self.signatures_root.as_bytes());
        hasher.update(self.state_root.as_bytes());
        hasher.update(self.sequencer.as_bytes());
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.gas_used.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.base_fee_per_gas.to_le_bytes());
        // Portal DA commitments — signed by sequencer to prevent data withholding.
        // Using 32 zero bytes as sentinel for None ensures hash stability across
        // blocks with and without Portal state (no length-ambiguity).
        match &self.portal_nullifier_root {
            Some(root) => { hasher.update(root.as_bytes()); }
            None => { hasher.update(&[0u8; 32]); }
        }
        match &self.portal_escrow_blob_hash {
            Some(h) => { hasher.update(h.as_bytes()); }
            None => { hasher.update(&[0u8; 32]); }
        }
        hasher.finalize()
    }
}

/// Dual signature over the block header (§3.6).
///
/// Each block is signed with TWO independent signatures:
/// 1. **EOTS** (Extractable One-Time Signature): Self-enforcing slashing
///    - Uses an **isolated** key controlling only the Bond UTXO (33.33%)
///    - If the same nonce signs two blocks → secret key extractable → immediate slash
/// 2. **SLH-DSA**: Hash-based equivocation detection (quantum-resistant)
///    - Provides long-term fraud proofs verifiable without curve assumptions
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DualSignature {
    /// EOTS signature (secp256k1 Schnorr-based, isolated key).
    pub eots: brrq_crypto::eots::EotsSignature,
    /// Post-quantum SLH-DSA signature.
    pub slh_dsa: brrq_crypto::slh_dsa::SlhDsaSignature,
}

impl DualSignature {
    /// Total size in bytes.
    pub fn size(&self) -> usize {
        // EOTS: 33 (nonce commitment) + 32 (s-value) = 65 bytes
        let eots_size = self.eots.nonce_commitment().as_bytes().len() + self.eots.s_value().len();
        eots_size + self.slh_dsa.size()
    }
}

/// The sequencer's public identity.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SequencerIdentity {
    /// Schnorr public key for EOTS verification (isolated Bond key).
    pub schnorr_pk: brrq_crypto::schnorr::SchnorrPublicKey,
    /// Post-quantum SLH-DSA public key.
    pub slh_dsa_pk: brrq_crypto::slh_dsa::SlhDsaPublicKey,
    /// The address derived from the network.
    pub address: Address,
}

/// A complete Brrq block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    /// Block header.
    pub header: BlockHeader,
    /// Signature from the sequencer.
    pub signature: DualSignature,
    /// Sequencer identity.
    pub sequencer_identity: SequencerIdentity,
    /// Transactions in this block.
    pub transactions: Vec<Transaction>,
}

/// A lightweight block optimized for Data Availability (Volition DA).
///
/// Contains the same header and block signatures, but excludes user
/// transaction signatures (SLH-DSA), reducing the size by ~98%.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightBlock {
    /// Block header.
    pub header: BlockHeader,
    /// Dual signature from the sequencer (EOTS + SLH-DSA).
    pub signature: DualSignature,
    /// Sequencer identity.
    pub sequencer_identity: SequencerIdentity,
    /// Lightweight transactions (no signatures).
    pub transactions: Vec<crate::transaction::LightTransaction>,
}

impl LightBlock {
    /// Get the block hash (header hash).
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    /// Get the block height.
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Get the number of transactions.
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Estimated total size in bytes for the data availability layer.
    pub fn size(&self) -> usize {
        // Fixed fields: height(8) + timestamp(8) + parent_hash(32) + tx_root(32) +
        //               sig_root(32) + state_root(32) + sequencer(20) + epoch(8) +
        //               gas_used(8) + gas_limit(8) = 188 bytes
        // Optional L1 fields: l1_anchor_height(Option<u64>=9) + l1_anchor_hash(Option<Hash256>=33) = 42 bytes max
        let header_size = 188 + 42; // 230 bytes (conservative estimate including L1 fields)
        let sig_size = self.signature.size();
        let tx_size: usize = self.transactions.iter().map(|tx| tx.size()).sum();

        header_size + sig_size + tx_size
    }
}

impl Block {
    /// Get the block hash (header hash).
    pub fn hash(&self) -> Hash256 {
        self.header.hash()
    }

    /// Compress this block into a lightweight representation for Data Availability (L1).
    pub fn compress_to_light(&self) -> LightBlock {
        // Here we extract the LightTransactions (dropping heavy signatures)
        let light_txs: Vec<crate::transaction::LightTransaction> =
            self.transactions.iter().map(|tx| tx.to_light()).collect();

        LightBlock {
            header: self.header.clone(),
            signature: self.signature.clone(),
            sequencer_identity: self.sequencer_identity.clone(),
            transactions: light_txs,
        }
    }

    /// Get the block height.
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Get the number of transactions.
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }

    /// Verify that the transactions root matches.
    pub fn verify_tx_root(&self) -> bool {
        let tx_hashes: Vec<Hash256> = self.transactions.iter().map(|tx| tx.hash()).collect();
        let computed_root = compute_tx_root(&tx_hashes);
        self.header.transactions_root == computed_root
    }

    /// Estimated total size in bytes.
    pub fn size(&self) -> usize {
        // Fixed header fields: 188 bytes + Optional L1 fields: up to 42 bytes = 230
        let header_size = 230;
        let sig_size = self.signature.size();
        let tx_size: usize = self.transactions.iter().map(|tx| tx.size()).sum();

        header_size + sig_size + tx_size
    }

    /// Check basic structural validity.
    pub fn is_structurally_valid(&self) -> bool {
        // Gas used must not exceed gas limit
        if self.header.gas_used > self.header.gas_limit {
            return false;
        }
        // Must have valid tx root
        self.verify_tx_root()
    }

    /// Verify the block's dual signature (EOTS + SLH-DSA).
    ///
    /// Returns `true` if both signatures are valid for the block header hash
    /// under the sequencer's claimed public keys.
    pub fn verify_signature(&self) -> bool {
        let header_hash = self.header.hash();

        // 1. Verify EOTS signature (secp256k1-based)
        let eots_ok = brrq_crypto::eots::verify(
            &self.sequencer_identity.schnorr_pk,
            &header_hash,
            &self.signature.eots,
        )
        .is_ok();

        // 2. Verify SLH-DSA signature (post-quantum)
        // The signing message is `height || header_hash` to prevent
        // cross-height equivocation proof attacks.
        let mut slh_msg = Vec::with_capacity(8 + 32);
        slh_msg.extend_from_slice(&self.header.height.to_le_bytes());
        slh_msg.extend_from_slice(header_hash.as_bytes());
        let slh_dsa_ok = brrq_crypto::slh_dsa::verify(
            &self.sequencer_identity.slh_dsa_pk,
            &slh_msg,
            &self.signature.slh_dsa,
        )
        .is_ok();

        eots_ok && slh_dsa_ok
    }
}

/// Genesis block configuration.
pub fn genesis_block(state_root: Hash256) -> BlockHeader {
    BlockHeader {
        height: 0,
        timestamp: 0,
        parent_hash: Hash256::ZERO,
        transactions_root: Hash256::ZERO,
        signatures_root: Hash256::ZERO,
        state_root,
        sequencer: Address::ZERO,
        epoch: 0,
        gas_used: 0,
        gas_limit: crate::gas::DEFAULT_BLOCK_GAS_LIMIT,
        base_fee_per_gas: 10, // INITIAL_BASE_FEE
        l1_anchor_height: None,
        l1_anchor_hash: None,
        portal_nullifier_root: None,
        portal_escrow_blob_hash: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_block() {
        let state_root = Hasher::hash(b"genesis state");
        let genesis = genesis_block(state_root);
        assert_eq!(genesis.height, 0);
        assert_eq!(genesis.parent_hash, Hash256::ZERO);
        assert_ne!(genesis.hash(), Hash256::ZERO);
    }

    #[test]
    fn test_header_hash_deterministic() {
        let h1 = BlockHeader {
            height: 1,
            timestamp: 1000,
            parent_hash: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            signatures_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            sequencer: Address::ZERO,
            epoch: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee_per_gas: 10,
            l1_anchor_height: None,
            l1_anchor_hash: None,
            portal_nullifier_root: None,
            portal_escrow_blob_hash: None,
        };
        let h2 = h1.clone();
        assert_eq!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_different_height_different_hash() {
        let h1 = BlockHeader {
            height: 1,
            timestamp: 1000,
            parent_hash: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            signatures_root: Hash256::ZERO,
            state_root: Hash256::ZERO,
            sequencer: Address::ZERO,
            epoch: 0,
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee_per_gas: 10,
            l1_anchor_height: None,
            l1_anchor_hash: None,
            portal_nullifier_root: None,
            portal_escrow_blob_hash: None,
        };
        let mut h2 = h1.clone();
        h2.height = 2;
        assert_ne!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_light_block_compression_size_difference() {
        use crate::signature::{PublicKey, Signature};
        use crate::transaction::{Transaction, TransactionBody, TransactionKind, chain_id};
        use brrq_crypto::eots::{EotsNonceCommitment, EotsSignature};
        use brrq_crypto::schnorr::SchnorrPublicKey;
        use brrq_crypto::slh_dsa::{SlhDsaPublicKey, SlhDsaSignature};

        // Mock a large SLH-DSA transaction
        let mut slh_dsa_sig_bytes = vec![0u8; 7856];
        slh_dsa_sig_bytes[0] = 1;

        let tx = Transaction {
            body: TransactionBody {
                from: Address::from_bytes([1u8; 20]),
                kind: TransactionKind::Transfer {
                    to: Address::from_bytes([2u8; 20]),
                    amount: 1000,
                },
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::SlhDsa(
                SlhDsaSignature::from_bytes(slh_dsa_sig_bytes.clone()).unwrap(),
            ),
            public_key: PublicKey::SlhDsa(SlhDsaPublicKey::from_bytes(vec![0u8; 32]).unwrap()),
        };

        let mock_eots = EotsSignature::new_unchecked(
            EotsNonceCommitment::from_bytes_unchecked(vec![0u8; 33]),
            vec![0u8; 32],
        );

        let header = genesis_block(Hash256::ZERO);
        let block = Block {
            header: header.clone(),
            signature: DualSignature {
                eots: mock_eots,
                slh_dsa: SlhDsaSignature::from_bytes(slh_dsa_sig_bytes.clone()).unwrap(),
            },
            sequencer_identity: SequencerIdentity {
                schnorr_pk: SchnorrPublicKey::from_bytes([0u8; 32]),
                slh_dsa_pk: SlhDsaPublicKey::from_bytes(vec![0u8; 32]).unwrap(),
                address: Address::ZERO,
            },
            transactions: vec![tx.clone(); 100], // 100 Heavy Txs
        };

        let full_size = block.size();

        // Compress for DA Data Availability
        let light_block = block.compress_to_light();
        let light_size = light_block.size();

        assert_eq!(light_block.transactions.len(), 100);
        assert_eq!(light_block.hash(), block.hash()); // Verification routing intact

        // Light block should be immensely smaller (full block handles ~7.8KB per tx + its own sig)
        // With 100 txs, ~800KB goes down to ~16KB.
        println!(
            "Light: {}, Full: {}, FullSigSize: {}",
            light_size,
            full_size,
            block.signature.size()
        );
        assert!(light_size < full_size / 40); // Assure massive compression
    }
}
