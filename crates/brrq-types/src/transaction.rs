//! Brrq transaction types.
//!
//! A transaction represents a signed state transition on the Brrq L2.
//! Supports both Schnorr (classical) and SLH-DSA (quantum-resistant) signatures.
//!
//! ## Transaction Flow (§4.6)
//! 1. User creates and signs transaction (Schnorr or SLH-DSA)
//! 2. Sequencer receives, validates signature, and orders
//! 3. zkVM executes the state transition with gas metering
//! 4. Prover generates STARK proof for the batch

use brrq_crypto::hash::{Hash256, Hasher};
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::signature::{PublicKey, Signature, SignatureType};

/// Transaction types supported by Brrq.
///
/// # Adding a new variant checklist
///
/// When adding a new `TransactionKind`, update **all** of these files:
///
/// - `brrq-types/src/transaction.rs`  — enum definition + hash type tag
/// - `brrq-types/src/gas.rs`          — intrinsic gas cost
/// - `brrq-sequencer/src/executor.rs` — execution match arm
/// - `brrq-sequencer/src/block_builder.rs` — block building
/// - `brrq-api/src/services.rs`       — `build_transaction`
/// - `brrq-network/src/message.rs`    — validation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransactionKind {
    /// Simple brqBTC transfer.
    Transfer {
        to: Address,
        /// Amount in satoshis.
        amount: u64,
    },
    /// Smart contract deployment.
    Deploy {
        /// Contract bytecode (RISC-V).
        code: Vec<u8>,
    },
    /// Smart contract call.
    ContractCall {
        /// Target contract address.
        to: Address,
        /// Calldata (ABI-encoded).
        data: Vec<u8>,
        /// BTC value to send with call (in satoshis).
        value: u64,
    },
    /// Register as a validator with an initial stake (§7.1).
    RegisterValidator {
        /// Initial stake in satoshis.
        stake: u64,
    },
    /// Add more stake to an existing validator (§7.1).
    AddStake {
        /// Additional stake in satoshis.
        amount: u64,
    },
    /// Begin the unbonding period to withdraw validator stake (§7.1).
    BeginUnbonding,
    /// Finish the unbonding period and refund the validator stake (§7.1).
    FinishUnbonding,
    /// Submit equivocation proof to slash a misbehaving validator (§7.3).
    SubmitEquivocationProof {
        /// The offending validator address.
        validator: Address,
        /// Block height where equivocation occurred.
        height: u64,
        /// First block hash signed.
        block_hash_a: Hash256,
        /// Second (conflicting) block hash signed.
        block_hash_b: Hash256,
        /// SLH-DSA signature on first block.
        signature_a: Vec<u8>,
        /// SLH-DSA signature on second block.
        signature_b: Vec<u8>,
        /// Validator's SLH-DSA public key.
        slh_dsa_pk: Vec<u8>,
    },
    /// Synthetic deposit from L1 Bitcoin bridge.
    ///
    /// Injected by the sequencer after SPV-verified peg-in deposits.
    /// Not signed by any user — the sequencer attests to L1 validity.
    /// Included in blocks so deposits are provable via STARK proofs.
    DepositSynthetic {
        /// L2 recipient address (derived from Bitcoin scriptPubKey).
        recipient: Address,
        /// Minted brqBTC amount in satoshis (after bridge fee deduction).
        amount: u64,
        /// Bitcoin transaction ID containing the deposit.
        btc_tx_id: Hash256,
        /// Output index within the Bitcoin transaction.
        btc_vout: u32,
        /// Bitcoin block hash where the transaction was included.
        block_hash: Hash256,
        /// Raw serialized `MerkleBlock` from `gettxoutproof`.
        merkle_block_raw: Vec<u8>,
    },
    /// Create a Portal escrow lock (L3 Portal Protocol v4).
    ///
    /// Deducts `amount` from sender's balance and locks it in escrow.
    /// The lock can be settled by a merchant with the correct secret,
    /// or auto-expires after `timeout_l2_block`.
    CreatePortalLock {
        /// Amount to lock in satoshis.
        amount: u64,
        /// H(merchant_secret) — settlement condition.
        condition_hash: Hash256,
        /// Pre-computed nullifier hash for double-spend prevention.
        nullifier_hash: Hash256,
        /// L2 block height at which the lock expires.
        timeout_l2_block: u64,
    },
    /// Settle a Portal lock — merchant claims escrowed funds.
    ///
    /// Reveals the merchant secret, consumes the nullifier, and transfers
    /// funds from escrow to the merchant's address.
    SettlePortalLock {
        /// The lock to settle.
        lock_id: Hash256,
        /// Merchant's secret (preimage of condition_hash).
        merchant_secret: Vec<u8>,
        /// Portal Key signature for re-verification.
        portal_signature: Vec<u8>,
        /// Nullifier from the Portal Key.
        nullifier: Hash256,
    },
    /// Batch settle multiple Portal locks in one transaction.
    ///
    /// Each claim is processed independently — failed claims don't
    /// affect others. Provides ~100x gas compression.
    BatchSettlePortal {
        /// Settlement claims to process.
        claims: Vec<PortalSettlementClaim>,
    },
    /// Cancel an active Portal lock (owner only, before any Portal Key usage).
    CancelPortalLock {
        /// The lock to cancel.
        lock_id: Hash256,
    },
    /// Create a Lock Pool — multiple denomination locks in a single transaction.
    ///
    /// Deducts the sum of all slot amounts from the sender's balance and creates
    /// one escrow lock per slot denomination. Reduces lock creation overhead by 5-10x.
    CreateLockPool {
        /// Denomination amounts for each slot (in satoshis).
        slot_amounts: Vec<u64>,
        /// L2 block height at which all locks in this pool expire.
        timeout_l2_block: u64,
    },
    /// Refill consumed slots in a Lock Pool — creates new locks for specified amounts.
    ///
    /// Works like CreateLockPool but for topping up an existing pool.
    /// Deducts the sum of slot_amounts from the sender's balance.
    RefillLockPool {
        /// Amounts for each slot to refill (in satoshis).
        slot_amounts: Vec<u64>,
        /// L2 block height at which the new locks expire.
        timeout_l2_block: u64,
    },
    /// Update the condition_hash and nullifier_hash on an existing Portal lock.
    ///
    /// Required for Lock Pool slots created with zero condition/nullifier.
    /// The wallet calls this before generating a Portal Key for a specific merchant.
    /// Only the lock owner can update (enforced by block builder).
    UpdateLockCondition {
        /// ID of the lock to update.
        lock_id: Hash256,
        /// New merchant-specific condition hash: H(merchant_secret).
        condition_hash: Hash256,
        /// New extended nullifier hash: HMAC-SHA256(sk, lock_id || condition_hash).
        nullifier_hash: Hash256,
        /// Merchant address that MUST receive funds on settlement.
        merchant_address: Address,
        /// Merchant's Schnorr public key for relay signature verification.
        merchant_pubkey: [u8; 32],
    },
    /// Gasless batch settlement submitted by a relayer on behalf of a merchant.
    ///
    /// The relayer pays gas fees and receives a fee from the settlement amount.
    /// The merchant signs the claims bundle off-chain; the relayer submits on-chain.
    /// Fee is capped at MAX_RELAY_FEE_BPS (100 bps = 1%).
    RelayedBatchSettle {
        /// Settlement claims (same as BatchSettlePortal).
        claims: Vec<PortalSettlementClaim>,
        /// Merchant's address (receives settlement minus relay fee).
        merchant_address: Address,
        /// Merchant's Schnorr signature over H(claims || merchant_address || relayer_address || relay_fee_bps).
        /// Including relayer_address in the signed payload prevents fee hijacking:
        /// a searcher cannot replace the relayer and steal the fee.
        merchant_signature: Vec<u8>,
        /// Relay fee in basis points (max 100 = 1%).
        relay_fee_bps: u16,
        /// Relayer's L2 address — MUST match tx.body.from (sender).
        /// Signed by the merchant to cryptographically bind the fee recipient.
        relayer_address: Address,
    },
    /// L1 Zero-Knowledge Liveness Anchor (U-ZKHR).
    ///
    /// Injected by the sequencer after SPV-verified recovery STARK is posted to L1.
    /// Not signed by any user - it is a protocol-level state transition.
    /// Includes the bitmap of validators who participated in the recovery.
    L1ZklaAnchor {
        /// The Bitcoin block hash where the STARK was included.
        btc_block_hash: Hash256,
        /// The transaction ID containing the STARK.
        btc_tx_id: Hash256,
        /// The STARK proof itself.
        stark_proof: Vec<u8>,
        /// Bitmap of validators who signed the liveness heartbeat.
        /// Position corresponds to their index in the active validator set.
        recovered_validators_bitmap: Vec<u8>,
    },
}

/// A settlement claim within a BatchSettlePortal transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortalSettlementClaim {
    /// The lock to settle.
    pub lock_id: Hash256,
    /// Merchant's secret (preimage of condition_hash).
    pub merchant_secret: Vec<u8>,
    /// Portal Key signature.
    pub portal_signature: Vec<u8>,
    /// Nullifier from the Portal Key.
    pub nullifier: Hash256,
}

impl PortalSettlementClaim {
    /// Feed all claim fields into `hasher` in canonical order.
    /// Used by `TransactionBody::hash()` for both `BatchSettlePortal` and
    /// `RelayedBatchSettle` to avoid duplicating the per-claim hash layout.
    fn hash_into(&self, hasher: &mut Hasher) {
        hasher.update(self.lock_id.as_bytes());
        hasher.update(&(self.merchant_secret.len() as u64).to_le_bytes());
        hasher.update(&self.merchant_secret);
        hasher.update(&(self.portal_signature.len() as u64).to_le_bytes());
        hasher.update(&self.portal_signature);
        hasher.update(self.nullifier.as_bytes());
    }

    /// Estimated serialized size in bytes.
    /// Used by both `Transaction::size()` and `LightTransaction::size()`.
    fn estimated_size(&self) -> usize {
        // lock_id(32) + len_prefix(8) + merchant_secret + len_prefix(8) + portal_signature + nullifier(32)
        32 + 8 + self.merchant_secret.len() + 8 + self.portal_signature.len() + 32
    }

    /// Basic structural validity: secret must be non-empty and signature must be 64 bytes.
    fn is_structurally_valid(&self) -> bool {
        !self.merchant_secret.is_empty() && self.portal_signature.len() == 64
    }
}

/// Validate slot_amounts for Lock Pool transactions (CreateLockPool / RefillLockPool).
/// Returns `true` if the slice is non-empty, at most 20 slots, and every amount > 0.
fn validate_slot_amounts(slot_amounts: &[u64]) -> bool {
    !slot_amounts.is_empty()
        && slot_amounts.len() <= 20
        && slot_amounts.iter().all(|&a| a > 0)
}

/// A Brrq transaction (unsigned).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransactionBody {
    /// Sender address.
    pub from: Address,
    /// Transaction kind (transfer, deploy, call).
    pub kind: TransactionKind,
    /// Sender's nonce (must match account nonce).
    pub nonce: u64,
    /// Gas limit for this transaction.
    pub gas_limit: u64,
    /// Maximum fee per gas unit the sender is willing to pay (EIP-1559).
    pub max_fee_per_gas: u64,
    /// Maximum priority fee per gas unit to tip the sequencer (EIP-1559).
    pub max_priority_fee_per_gas: u64,
    /// Chain ID (prevents cross-chain replay).
    pub chain_id: u64,
}

impl TransactionBody {
    /// Compute the hash of this transaction body (for signing).
    pub fn hash(&self) -> Hash256 {
        // Deterministic serialization for signing
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::TX_BODY_V1);
        hasher.update(self.from.as_bytes());
        hasher.update(&self.nonce.to_le_bytes());
        hasher.update(&self.gas_limit.to_le_bytes());
        hasher.update(&self.max_fee_per_gas.to_le_bytes());
        hasher.update(&self.max_priority_fee_per_gas.to_le_bytes());
        hasher.update(&self.chain_id.to_le_bytes());

        match &self.kind {
            TransactionKind::Transfer { to, amount } => {
                hasher.update(&[0x01]); // Type tag
                hasher.update(to.as_bytes());
                hasher.update(&amount.to_le_bytes());
            }
            TransactionKind::Deploy { code } => {
                hasher.update(&[0x02]); // Type tag
                hasher.update(&(code.len() as u64).to_le_bytes());
                hasher.update(code);
            }
            TransactionKind::ContractCall { to, data, value } => {
                hasher.update(&[0x03]); // Type tag
                hasher.update(to.as_bytes());
                hasher.update(&value.to_le_bytes());
                hasher.update(&(data.len() as u64).to_le_bytes());
                hasher.update(data);
            }
            TransactionKind::RegisterValidator { stake } => {
                hasher.update(&[0x04]); // Type tag
                hasher.update(&stake.to_le_bytes());
            }
            TransactionKind::AddStake { amount } => {
                hasher.update(&[0x05]); // Type tag
                hasher.update(&amount.to_le_bytes());
            }
            TransactionKind::BeginUnbonding => {
                hasher.update(&[0x06]); // Type tag
            }
            TransactionKind::FinishUnbonding => {
                hasher.update(&[0x09]); // Type tag
            }
            TransactionKind::SubmitEquivocationProof {
                validator,
                height,
                block_hash_a,
                block_hash_b,
                signature_a,
                signature_b,
                slh_dsa_pk,
            } => {
                hasher.update(&[0x07]); // Type tag
                hasher.update(validator.as_bytes());
                hasher.update(&height.to_le_bytes());
                hasher.update(block_hash_a.as_bytes());
                hasher.update(block_hash_b.as_bytes());
                hasher.update(&(signature_a.len() as u64).to_le_bytes());
                hasher.update(signature_a);
                hasher.update(&(signature_b.len() as u64).to_le_bytes());
                hasher.update(signature_b);
                hasher.update(&(slh_dsa_pk.len() as u64).to_le_bytes());
                hasher.update(slh_dsa_pk);
            }
            TransactionKind::DepositSynthetic {
                recipient,
                amount,
                btc_tx_id,
                btc_vout,
                block_hash,
                merkle_block_raw,
            } => {
                hasher.update(&[0x08]); // Type tag
                // Domain separation provided by TX_BODY_V1 + type tag.
                hasher.update(recipient.as_bytes());
                hasher.update(&amount.to_le_bytes());
                hasher.update(btc_tx_id.as_bytes());
                hasher.update(&btc_vout.to_le_bytes());
                hasher.update(block_hash.as_bytes());
                hasher.update(&(merkle_block_raw.len() as u64).to_le_bytes());
                hasher.update(merkle_block_raw);
            }
            TransactionKind::L1ZklaAnchor {
                btc_block_hash,
                btc_tx_id,
                stark_proof,
                recovered_validators_bitmap,
            } => {
                hasher.update(&[0x0A]); // Type tag
                hasher.update(btc_block_hash.as_bytes());
                hasher.update(btc_tx_id.as_bytes());
                hasher.update(&(stark_proof.len() as u64).to_le_bytes());
                hasher.update(stark_proof);
                hasher.update(&(recovered_validators_bitmap.len() as u64).to_le_bytes());
                hasher.update(recovered_validators_bitmap);
            }
            // ── Portal (L3) transaction types ─────────────────────────
            TransactionKind::CreatePortalLock {
                amount,
                condition_hash,
                nullifier_hash,
                timeout_l2_block,
            } => {
                hasher.update(&[0x10]); // Type tag (Portal range: 0x10+)
                hasher.update(&amount.to_le_bytes());
                hasher.update(condition_hash.as_bytes());
                hasher.update(nullifier_hash.as_bytes());
                hasher.update(&timeout_l2_block.to_le_bytes());
            }
            TransactionKind::SettlePortalLock {
                lock_id,
                merchant_secret,
                portal_signature,
                nullifier,
            } => {
                hasher.update(&[0x11]); // Type tag
                hasher.update(lock_id.as_bytes());
                hasher.update(&(merchant_secret.len() as u64).to_le_bytes());
                hasher.update(merchant_secret);
                hasher.update(&(portal_signature.len() as u64).to_le_bytes());
                hasher.update(portal_signature);
                hasher.update(nullifier.as_bytes());
            }
            TransactionKind::BatchSettlePortal { claims } => {
                hasher.update(&[0x12]); // Type tag
                hasher.update(&(claims.len() as u64).to_le_bytes());
                for claim in claims {
                    claim.hash_into(&mut hasher);
                }
            }
            TransactionKind::CancelPortalLock { lock_id } => {
                hasher.update(&[0x13]); // Type tag
                hasher.update(lock_id.as_bytes());
            }
            TransactionKind::CreateLockPool {
                slot_amounts,
                timeout_l2_block,
            } => {
                hasher.update(&[0x14]); // Type tag
                hasher.update(&(slot_amounts.len() as u64).to_le_bytes());
                for amount in slot_amounts {
                    hasher.update(&amount.to_le_bytes());
                }
                hasher.update(&timeout_l2_block.to_le_bytes());
            }
            TransactionKind::RefillLockPool { slot_amounts, timeout_l2_block } => {
                hasher.update(&[0x15]); // Type tag
                hasher.update(&(slot_amounts.len() as u64).to_le_bytes());
                for amount in slot_amounts {
                    hasher.update(&amount.to_le_bytes());
                }
                hasher.update(&timeout_l2_block.to_le_bytes());
            }
            TransactionKind::UpdateLockCondition { lock_id, condition_hash, nullifier_hash, merchant_address, merchant_pubkey } => {
                hasher.update(&[0x16]); // Type tag
                hasher.update(lock_id.as_bytes());
                hasher.update(condition_hash.as_bytes());
                hasher.update(merchant_address.as_bytes());
                hasher.update(nullifier_hash.as_bytes());
                hasher.update(merchant_pubkey);
            }
            TransactionKind::RelayedBatchSettle { claims, merchant_address, merchant_signature, relay_fee_bps, relayer_address } => {
                hasher.update(&[0x17]); // Type tag
                hasher.update(&(claims.len() as u64).to_le_bytes());
                // Hash ALL claim fields to prevent transaction malleability
                for claim in claims {
                    claim.hash_into(&mut hasher);
                }
                hasher.update(merchant_address.as_bytes());
                hasher.update(relayer_address.as_bytes());
                // Length-prefix merchant_signature to prevent boundary ambiguity
                hasher.update(&(merchant_signature.len() as u64).to_le_bytes());
                hasher.update(merchant_signature);
                hasher.update(&relay_fee_bps.to_le_bytes());
            }
        }

        hasher.finalize()
    }
}

/// A signed Brrq transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Transaction {
    /// The transaction body.
    pub body: TransactionBody,
    /// The signature (Schnorr or SLH-DSA).
    pub signature: Signature,
    /// The signer's public key.
    pub public_key: PublicKey,
}

/// A lightweight transaction for Volition Data Availability on L1.
/// Excludes the heavy signature and public key, retaining only the body
/// and the signature type (for verification routing).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LightTransaction {
    /// The transaction body.
    pub body: TransactionBody,
    /// The type of signature used to authorize this transaction.
    pub signature_type: SignatureType,
}

impl LightTransaction {
    /// Get the light transaction hash (body + signature type only).
    ///
    /// Note: this does NOT match `Transaction::hash()`, which also includes
    /// the full signature and public key bytes for malleability protection.
    pub fn hash(&self) -> Hash256 {
        let body_hash = self.body.hash();
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::TX_LIGHT_V1);
        hasher.update(body_hash.as_bytes());
        hasher.update(&[self.signature_type as u8]);
        hasher.finalize()
    }

    /// Estimated size in bytes for L1 posting.
    pub fn size(&self) -> usize {
        let base = 60; // address(20) + nonce(8) + gas_limit(8) + max_fee_per_gas(8) + max_priority(8) + chain_id(8)
        let kind_size = match &self.body.kind {
            TransactionKind::Transfer { .. } => 20 + 8,
            TransactionKind::Deploy { code } => code.len() + 8,
            TransactionKind::ContractCall { data, .. } => 20 + 8 + data.len() + 8,
            TransactionKind::RegisterValidator { .. } => 8,
            TransactionKind::AddStake { .. } => 8,
            TransactionKind::BeginUnbonding => 0,
            TransactionKind::FinishUnbonding => 0,
            TransactionKind::SubmitEquivocationProof {
                signature_a,
                signature_b,
                slh_dsa_pk,
                ..
            } => 20 + 8 + 32 + 32 + signature_a.len() + signature_b.len() + slh_dsa_pk.len(),
            TransactionKind::DepositSynthetic {
                merkle_block_raw, ..
            } => 20 + 8 + 32 + 4 + 32 + 8 + merkle_block_raw.len(),
            TransactionKind::L1ZklaAnchor {
                stark_proof,
                recovered_validators_bitmap,
                ..
            } => 32 + 32 + 8 + stark_proof.len() + 8 + recovered_validators_bitmap.len(),
            TransactionKind::CreatePortalLock { .. } => 8 + 32 + 32 + 8, // amount + cond_hash + null_hash + timeout
            TransactionKind::SettlePortalLock {
                merchant_secret,
                portal_signature,
                ..
            } => 32 + 8 + merchant_secret.len() + 8 + portal_signature.len() + 32,
            TransactionKind::BatchSettlePortal { claims } => {
                8 + claims.iter().map(|c| c.estimated_size()).sum::<usize>()
            }
            TransactionKind::CancelPortalLock { .. } => 32,
            TransactionKind::CreateLockPool { slot_amounts, .. } => 8 + (slot_amounts.len() * 8) + 8,
            TransactionKind::RefillLockPool { slot_amounts, .. } => 8 + (slot_amounts.len() * 8) + 8,
            TransactionKind::UpdateLockCondition { .. } => 32 + 32 + 32 + 20 + 32, // lock_id + cond + null + merchant_addr + merchant_pubkey
            TransactionKind::RelayedBatchSettle { claims, merchant_signature, .. } => {
                8 + claims.iter().map(|c| c.estimated_size()).sum::<usize>()
                + 20 + 20 + 8 + merchant_signature.len() + 2 // +20 for relayer_address
            }
        };
        // Just the body and 1 byte for signature type. NO PK or Sig bytes!
        base + kind_size + 1
    }
}

impl Transaction {
    /// Converts the full transaction into a lightweight transaction for L1 DA.
    pub fn into_light(self) -> LightTransaction {
        LightTransaction {
            body: self.body,
            signature_type: self.signature.signature_type(),
        }
    }

    /// Returns a lightweight representation without consuming the original.
    pub fn to_light(&self) -> LightTransaction {
        LightTransaction {
            body: self.body.clone(),
            signature_type: self.signature.signature_type(),
        }
    }
    /// Get the transaction hash (unique identifier).
    ///
    /// Includes signature bytes and public key to prevent transaction
    /// malleability — two transactions with the same body but different
    /// signatures will produce different hashes.
    pub fn hash(&self) -> Hash256 {
        let body_hash = self.body.hash();
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::TX_FULL_V1);
        hasher.update(body_hash.as_bytes());
        hasher.update(&[self.signature.signature_type() as u8]);
        hasher.update(self.signature.as_bytes());
        hasher.update(self.public_key.as_bytes());
        hasher.finalize()
    }

    /// Get the sender address.
    pub fn sender(&self) -> &Address {
        &self.body.from
    }

    /// Get the signature type used.
    pub fn signature_type(&self) -> SignatureType {
        self.signature.signature_type()
    }

    /// Estimated size in bytes.
    pub fn size(&self) -> usize {
        // Base: address(20) + nonce(8) + gas_limit(8) + max_fee(8) + max_priority(8) + chain_id(8)
        let base = 60;
        let kind_size = match &self.body.kind {
            TransactionKind::Transfer { .. } => 20 + 8, // to + amount
            TransactionKind::Deploy { code } => code.len() + 8,
            TransactionKind::ContractCall { data, .. } => 20 + 8 + data.len() + 8,
            TransactionKind::RegisterValidator { .. } => 8, // stake
            TransactionKind::AddStake { .. } => 8,          // amount
            TransactionKind::BeginUnbonding => 0,
            TransactionKind::FinishUnbonding => 0,
            TransactionKind::SubmitEquivocationProof {
                signature_a,
                signature_b,
                slh_dsa_pk,
                ..
            } => 20 + 8 + 32 + 32 + signature_a.len() + signature_b.len() + slh_dsa_pk.len(),
            // Include block_hash(32) + len_prefix(8) + merkle_block_raw
            TransactionKind::DepositSynthetic { merkle_block_raw, .. } => 20 + 8 + 32 + 4 + 32 + 8 + merkle_block_raw.len(),
            TransactionKind::L1ZklaAnchor {
                stark_proof,
                recovered_validators_bitmap,
                ..
            } => 32 + 32 + 8 + stark_proof.len() + 8 + recovered_validators_bitmap.len(),
            TransactionKind::CreatePortalLock { .. } => 8 + 32 + 32 + 8,
            TransactionKind::SettlePortalLock {
                merchant_secret,
                portal_signature,
                ..
            } => 32 + 8 + merchant_secret.len() + 8 + portal_signature.len() + 32,
            TransactionKind::BatchSettlePortal { claims } => {
                8 + claims.iter().map(|c| c.estimated_size()).sum::<usize>()
            }
            TransactionKind::CancelPortalLock { .. } => 32,
            TransactionKind::CreateLockPool { slot_amounts, .. } => 8 + (slot_amounts.len() * 8) + 8,
            TransactionKind::RefillLockPool { slot_amounts, .. } => 8 + (slot_amounts.len() * 8) + 8,
            TransactionKind::UpdateLockCondition { .. } => 32 + 32 + 32 + 20 + 32, // lock_id + cond + null + merchant_addr + merchant_pubkey
            TransactionKind::RelayedBatchSettle { claims, merchant_signature, .. } => {
                8 + claims.iter().map(|c| c.estimated_size()).sum::<usize>()
                + 20 + 20 + 8 + merchant_signature.len() + 2 // +20 for relayer_address
            }
        };
        let sig_size = self.signature.size();
        let pk_size = self.public_key.size();

        base + kind_size + sig_size + pk_size
    }

    /// Check basic structural validity (not full validation).
    pub fn is_structurally_valid(&self) -> bool {
        // Nonce must not be max (prevent overflow)
        if self.body.nonce == u64::MAX {
            return false;
        }
        // Gas limit must be reasonable
        if self.body.gas_limit == 0 {
            return false;
        }
        // Per-type gas cap: prevents declared-gas spam where attacker declares
        // huge gas_limit for trivial transactions, wasting block gas budget.
        const MAX_GAS_TRANSFER: u64 = 100_000;
        const MAX_GAS_DEPLOY: u64 = 10_000_000;
        const MAX_GAS_CONTRACT_CALL: u64 = 10_000_000;
        const MAX_GAS_STAKING: u64 = 200_000;
        const MAX_GAS_PORTAL: u64 = 500_000;
        const MAX_GAS_PORTAL_BATCH: u64 = 5_000_000;
        let max_gas_for_kind = match &self.body.kind {
            TransactionKind::Transfer { .. } => MAX_GAS_TRANSFER,
            TransactionKind::Deploy { .. } => MAX_GAS_DEPLOY,
            TransactionKind::ContractCall { .. } => MAX_GAS_CONTRACT_CALL,
            TransactionKind::RegisterValidator { .. }
            | TransactionKind::AddStake { .. }
            | TransactionKind::BeginUnbonding { .. }
            | TransactionKind::FinishUnbonding { .. }
            | TransactionKind::SubmitEquivocationProof { .. } => MAX_GAS_STAKING,
            TransactionKind::CreatePortalLock { .. }
            | TransactionKind::CancelPortalLock { .. }
            | TransactionKind::UpdateLockCondition { .. }
            | TransactionKind::CreateLockPool { .. }
            | TransactionKind::RefillLockPool { .. }
            | TransactionKind::SettlePortalLock { .. } => MAX_GAS_PORTAL,
            TransactionKind::BatchSettlePortal { .. }
            | TransactionKind::RelayedBatchSettle { .. } => MAX_GAS_PORTAL_BATCH,
            _ => 10_000_000, // Default cap for unknown types
        };
        if self.body.gas_limit > max_gas_for_kind {
            return false;
        }
        // gas_limit * max_fee_per_gas must not overflow u64 (fee calculation safety)
        if self
            .body
            .gas_limit
            .checked_mul(self.body.max_fee_per_gas)
            .is_none()
        {
            return false;
        }
        // Size limits for Vec<u8> fields (deserialization bomb protection).
        // Max contract code: 256 KB. Max calldata: 64 KB. Max equivocation sigs: 16 KB each.
        const MAX_CODE_SIZE: usize = 256 * 1024;
        const MAX_CALLDATA_SIZE: usize = 64 * 1024;
        const MAX_SIG_SIZE: usize = 16 * 1024;
        const MAX_PK_SIZE: usize = 4 * 1024;

        match &self.body.kind {
            // Reject empty code (nonsensical deploy) and oversized code.
            TransactionKind::Deploy { code } if code.is_empty() || code.len() > MAX_CODE_SIZE => {
                return false;
            }
            TransactionKind::ContractCall { data, .. } if data.len() > MAX_CALLDATA_SIZE => {
                return false;
            }
            TransactionKind::RegisterValidator { stake } if *stake == 0 => {
                return false;
            }
            TransactionKind::AddStake { amount } if *amount == 0 => {
                return false;
            }
            TransactionKind::SubmitEquivocationProof {
                block_hash_a,
                block_hash_b,
                signature_a,
                signature_b,
                slh_dsa_pk,
                ..
            } => {
                if block_hash_a == block_hash_b {
                    return false;
                }
                if signature_a.len() > MAX_SIG_SIZE
                    || signature_b.len() > MAX_SIG_SIZE
                    || slh_dsa_pk.len() > MAX_PK_SIZE
                {
                    return false;
                }
            }
            TransactionKind::DepositSynthetic {
                amount, recipient, merkle_block_raw, ..
            } if *amount == 0 || recipient.is_zero()
                // Reject empty merkle proofs (obviously invalid).
                || merkle_block_raw.is_empty()
                // Cap merkle proof to 64KB (reasonable for any Merkle tree depth)
                || merkle_block_raw.len() > 65_536 => {
                return false;
            }
            TransactionKind::L1ZklaAnchor { stark_proof, recovered_validators_bitmap, .. }
                // Reject empty proofs and empty bitmaps (obviously invalid).
                if stark_proof.is_empty()
                || recovered_validators_bitmap.is_empty()
                || stark_proof.len() > 1024 * 1024
                // Cap bitmap to 1KB (supports up to 8192 validators)
                || recovered_validators_bitmap.len() > 1024 =>
            {
                return false;
            }
            // Portal transaction validation
            TransactionKind::CreatePortalLock { amount, .. } if *amount == 0 => {
                return false;
            }
            TransactionKind::SettlePortalLock {
                merchant_secret,
                portal_signature,
                ..
            } => {
                if merchant_secret.is_empty() || portal_signature.len() != 64 {
                    return false;
                }
            }
            TransactionKind::BatchSettlePortal { claims } => {
                if claims.is_empty() || claims.len() > 100 {
                    return false;
                }
                if !claims.iter().all(|c| c.is_structurally_valid()) {
                    return false;
                }
            }
            TransactionKind::CreateLockPool { slot_amounts, .. } => {
                if !validate_slot_amounts(slot_amounts) {
                    return false;
                }
            }
            TransactionKind::UpdateLockCondition { lock_id, condition_hash, .. } => {
                if lock_id.is_zero() || condition_hash.is_zero() {
                    return false;
                }
            }
            TransactionKind::RelayedBatchSettle { claims, merchant_signature, relay_fee_bps, merchant_address, relayer_address } => {
                if claims.is_empty() || claims.len() > 100 {
                    return false;
                }
                if merchant_signature.len() != 64 {
                    return false;
                }
                if *relay_fee_bps > 100 { // Max 1%
                    return false;
                }
                if merchant_address.is_zero() || relayer_address.is_zero() {
                    return false;
                }
                if !claims.iter().all(|c| c.is_structurally_valid()) {
                    return false;
                }
            }
            // Validate remaining variants
            TransactionKind::RefillLockPool { slot_amounts, .. } => {
                if !validate_slot_amounts(slot_amounts) {
                    return false;
                }
            }
            TransactionKind::CancelPortalLock { lock_id } => {
                if lock_id.is_zero() {
                    return false;
                }
            }
            TransactionKind::Transfer { amount, .. } => {
                if *amount == 0 {
                    return false;
                }
            }
            // Explicit arms for all remaining variants instead of catch-all.
            // This ensures new TransactionKind variants get a compile error here,
            // forcing developers to add explicit validation.
            TransactionKind::Deploy { .. }
            | TransactionKind::ContractCall { .. }
            | TransactionKind::RegisterValidator { .. }
            | TransactionKind::AddStake { .. }
            | TransactionKind::BeginUnbonding
            | TransactionKind::FinishUnbonding
            | TransactionKind::SubmitEquivocationProof { .. }
            | TransactionKind::DepositSynthetic { .. }
            | TransactionKind::L1ZklaAnchor { .. }
            | TransactionKind::CreatePortalLock { .. }
            | TransactionKind::SettlePortalLock { .. }
            | TransactionKind::BatchSettlePortal { .. }
            | TransactionKind::CreateLockPool { .. }
            | TransactionKind::UpdateLockCondition { .. }
            | TransactionKind::RelayedBatchSettle { .. } => {}
        }
        // Signature type must match public key type
        self.signature.signature_type() == self.public_key.signature_type()
    }

    /// Verify the cryptographic signature and that the sender address matches the public key.
    ///
    /// Performs two checks:
    /// 1. `body.from == Address::from_public_key(public_key)` — the sender owns this key
    /// 2. The signature is valid over `body.hash()` — the key holder authorized this tx
    ///
    /// Returns `Ok(())` on success or a descriptive error message on failure.
    pub fn verify_signature(&self) -> Result<(), String> {
        // 1. Verify sender address matches the public key
        let expected_from = Address::from_public_key(self.public_key.as_bytes());
        if self.body.from != expected_from {
            return Err(format!(
                "sender address does not match public key: expected {}, got {}",
                expected_from, self.body.from
            ));
        }

        // 2. Verify the cryptographic signature over the body hash
        let body_hash = self.body.hash();

        match (&self.signature, &self.public_key) {
            (Signature::Schnorr(sig), PublicKey::Schnorr(pk)) => {
                brrq_crypto::schnorr::verify(pk, &body_hash, sig)
                    .map_err(|e| format!("Schnorr signature verification failed: {}", e))
            }
            (Signature::SlhDsa(sig), PublicKey::SlhDsa(pk)) => {
                brrq_crypto::slh_dsa::verify(pk, body_hash.as_bytes(), sig)
                    .map_err(|e| format!("SLH-DSA signature verification failed: {}", e))
            }
            _ => Err("signature type does not match public key type".into()),
        }
    }
}

/// A pending synthetic deposit from L1 Bitcoin.
///
/// Queued by the deposit watcher and consumed by the block builder.
/// Injected as `TransactionKind::DepositSynthetic` in the block.
#[derive(Debug, Clone)]
pub struct SyntheticDeposit {
    /// L2 recipient address.
    pub recipient: Address,
    /// Minted brqBTC amount in satoshis (after bridge fee).
    pub amount: u64,
    /// Bitcoin transaction ID.
    pub btc_tx_id: Hash256,
    /// Bitcoin output index.
    pub btc_vout: u32,
    /// Bitcoin block hash where the transaction was included.
    pub block_hash: Hash256,
    /// Raw serialized `MerkleBlock` from `gettxoutproof`.
    pub merkle_block_raw: Vec<u8>,
}

/// Brrq chain IDs.
pub mod chain_id {
    /// Mainnet (must match mainnet-genesis.toml chain_id = 3078357000).
    pub const MAINNET: u64 = 0xB77C_0008;
    /// Testnet.
    pub const TESTNET: u64 = 0xB77C_0001;
    /// Signet (development).
    pub const SIGNET: u64 = 0xB77C_0002;
    /// Local development.
    pub const LOCAL: u64 = 0xB77C_FFFF;
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::schnorr::{SchnorrKeyPair, SchnorrPublicKey, SchnorrSignature};

    fn mock_transfer_tx() -> Transaction {
        let from = Address::from_bytes([1u8; 20]);
        let to = Address::from_bytes([2u8; 20]);

        Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::Transfer {
                    to,
                    amount: 100_000,
                },
                nonce: 0,
                gas_limit: 21_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                chain_id: chain_id::LOCAL,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        }
    }

    /// Build a properly signed transfer transaction.
    fn make_signed_transfer(
        keys: &SchnorrKeyPair,
        to: Address,
        amount: u64,
        nonce: u64,
    ) -> Transaction {
        let from = Address::from_public_key(keys.public_key().as_bytes());
        let body = TransactionBody {
            from,
            kind: TransactionKind::Transfer { to, amount },
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            chain_id: chain_id::TESTNET,
        };
        let body_hash = body.hash();
        let sig = keys.sign(&body_hash).unwrap();

        Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(*keys.public_key()),
        }
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let tx1 = mock_transfer_tx();
        let tx2 = mock_transfer_tx();
        assert_eq!(tx1.hash(), tx2.hash());
    }

    #[test]
    fn test_tx_size() {
        let tx = mock_transfer_tx();
        let size = tx.size();
        // Schnorr: 52 + 28 + 64 + 32 = 176 bytes
        assert!(size > 100);
        assert!(size < 300); // Schnorr tx should be small
    }

    #[test]
    fn test_tx_structural_validity() {
        let tx = mock_transfer_tx();
        assert!(tx.is_structurally_valid());
    }

    #[test]
    fn test_chain_ids() {
        assert_ne!(chain_id::MAINNET, chain_id::TESTNET);
        assert_ne!(chain_id::TESTNET, chain_id::SIGNET);
    }

    // ── Signature verification tests ──────────────────────────────────

    #[test]
    fn test_verify_signature_valid() {
        let keys = SchnorrKeyPair::generate();
        let to = Address::from_bytes([0xBB; 20]);
        let tx = make_signed_transfer(&keys, to, 1_000, 0);
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn test_verify_signature_wrong_address() {
        let keys = SchnorrKeyPair::generate();
        let to = Address::from_bytes([0xBB; 20]);
        let mut tx = make_signed_transfer(&keys, to, 1_000, 0);
        // Tamper the from address
        tx.body.from = Address::from_bytes([0xFF; 20]);
        let result = tx.verify_signature();
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains("sender address does not match")
        );
    }

    #[test]
    fn test_verify_signature_tampered_body() {
        let keys = SchnorrKeyPair::generate();
        let to = Address::from_bytes([0xBB; 20]);
        let mut tx = make_signed_transfer(&keys, to, 1_000, 0);
        // Tamper the amount — body hash changes, signature becomes invalid
        tx.body.kind = TransactionKind::Transfer {
            to,
            amount: 999_999,
        };
        let result = tx.verify_signature();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("verification failed"));
    }

    #[test]
    fn test_verify_signature_wrong_key() {
        let keys1 = SchnorrKeyPair::generate();
        let keys2 = SchnorrKeyPair::generate();
        let to = Address::from_bytes([0xBB; 20]);
        let mut tx = make_signed_transfer(&keys1, to, 1_000, 0);
        // Replace public key with a different key — address won't match
        tx.public_key = PublicKey::Schnorr(*keys2.public_key());
        let result = tx.verify_signature();
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_signature_zero_sig_fails() {
        // The mock_transfer_tx has a zero signature — should fail verification
        let tx = mock_transfer_tx();
        let result = tx.verify_signature();
        assert!(result.is_err());
    }

    // ── Staking transaction tests ─────────────────────────────────────

    #[test]
    fn test_staking_tx_hash_deterministic() {
        let from = Address::from_bytes([1u8; 20]);
        let make_reg = || TransactionBody {
            from,
            kind: TransactionKind::RegisterValidator { stake: 1_000_000 },
            nonce: 0,
            gas_limit: 50_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            chain_id: chain_id::LOCAL,
        };
        assert_eq!(make_reg().hash(), make_reg().hash());

        // Different kind produces different hash
        let add_stake_body = TransactionBody {
            from,
            kind: TransactionKind::AddStake { amount: 1_000_000 },
            nonce: 0,
            gas_limit: 25_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            chain_id: chain_id::LOCAL,
        };
        assert_ne!(make_reg().hash(), add_stake_body.hash());

        // BeginUnbonding hash is stable
        let unbond_body = TransactionBody {
            from,
            kind: TransactionKind::BeginUnbonding,
            nonce: 0,
            gas_limit: 25_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            chain_id: chain_id::LOCAL,
        };
        assert_eq!(unbond_body.hash(), unbond_body.hash());
        assert_ne!(unbond_body.hash(), make_reg().hash());
    }

    #[test]
    fn test_register_validator_structural_validity() {
        let from = Address::from_bytes([1u8; 20]);
        // Valid: stake > 0
        let tx = Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::RegisterValidator { stake: 1_000_000 },
                nonce: 0,
                gas_limit: 50_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                chain_id: chain_id::LOCAL,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };
        assert!(tx.is_structurally_valid());

        // Invalid: stake == 0
        let tx_zero = Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::RegisterValidator { stake: 0 },
                nonce: 0,
                gas_limit: 50_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                chain_id: chain_id::LOCAL,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };
        assert!(!tx_zero.is_structurally_valid());
    }

    #[test]
    fn test_add_stake_structural_validity() {
        let from = Address::from_bytes([1u8; 20]);
        // Invalid: amount == 0
        let tx = Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::AddStake { amount: 0 },
                nonce: 0,
                gas_limit: 25_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                chain_id: chain_id::LOCAL,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };
        assert!(!tx.is_structurally_valid());
    }

    #[test]
    fn test_equivocation_proof_structural_validity() {
        let from = Address::from_bytes([1u8; 20]);
        let validator = Address::from_bytes([2u8; 20]);
        let hash_a = Hash256::ZERO;
        let mut hash_b = Hash256::ZERO;
        hash_b.0[0] = 1;

        // Valid: different hashes
        let tx_valid = Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::SubmitEquivocationProof {
                    validator,
                    height: 100,
                    block_hash_a: hash_a,
                    block_hash_b: hash_b,
                    signature_a: vec![0u8; 64],
                    signature_b: vec![0u8; 64],
                    slh_dsa_pk: vec![0u8; 32],
                },
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                chain_id: chain_id::LOCAL,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };
        assert!(tx_valid.is_structurally_valid());

        // Invalid: same hashes
        let tx_invalid = Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::SubmitEquivocationProof {
                    validator,
                    height: 100,
                    block_hash_a: Hash256::ZERO,
                    block_hash_b: Hash256::ZERO,
                    signature_a: vec![0u8; 64],
                    signature_b: vec![0u8; 64],
                    slh_dsa_pk: vec![0u8; 32],
                },
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 1,
                max_priority_fee_per_gas: 1,
                chain_id: chain_id::LOCAL,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };
        assert!(!tx_invalid.is_structurally_valid());
    }
}
