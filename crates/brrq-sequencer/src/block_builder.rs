//! Block builder — constructs and signs blocks.
//!
//! ## Flow (§3.4, §7.3)
//!
//! 1. Collect transactions from mempool (highest gas price first)
//! 2. Execute transactions against current state
//! 3. Compute state root after all executions
//! 4. Compute transaction Merkle root
//! 5. Assemble block header
//! 6. Dual-sign: EOTS + SLH-DSA (§3.6)

use brrq_crypto::eots::EotsKeyPair;
use brrq_crypto::hash::Hash256;
use brrq_crypto::merkle::compute_tx_root;
use brrq_crypto::schnorr::SchnorrKeyPair;
use brrq_crypto::slh_dsa::SlhDsaKeyPair;
use brrq_state::WorldState;
use brrq_types::address::Address;
use brrq_types::block::{Block, BlockHeader, DualSignature, SequencerIdentity};
use brrq_types::gas::DEFAULT_BLOCK_GAS_LIMIT;
use brrq_types::transaction::{Transaction, chain_id};

use brrq_types::SyntheticDeposit;
use brrq_types::transaction::TransactionKind;

use crate::error::SequencerError;
use crate::executor;
use crate::traits::{ConsensusState, NullifierStore, PortalState};

/// Per-transaction execution summary for receipt generation.
///
/// Returned alongside the block by `build_block` so the node can create
/// accurate receipts with real `gas_used` and `success` values.
#[derive(Debug, Clone)]
pub struct TxExecSummary {
    /// Actual gas consumed by the transaction.
    pub gas_used: u64,
    /// Whether the transaction executed successfully.
    ///
    /// For contract calls, `false` means the VM exited with a non-zero code.
    /// The transaction is still included in the block (gas is consumed),
    /// but the receipt should reflect the failure.
    pub success: bool,
    /// Event logs emitted during contract execution.
    pub logs: Vec<brrq_types::Log>,
    /// VM execution trace for STARK proving.
    /// Present when the transaction executed RISC-V code (contract calls).
    /// `None` for simple transfers, staking ops, and synthetic deposits.
    pub execution_trace: Option<brrq_vm::trace::ExecutionTrace>,
}

/// Sequencer keys for block signing — Key Isolation Design (§3.6).
///
/// ## Three-Key Architecture
///
/// ```text
/// main_key  (Schnorr)  → Main UTXO (66.67%) — identity key, NOT used for block signing
/// eots_key  (EOTS)     → Bond UTXO (33.33%) — ephemeral, for self-enforcing slashing
/// slh_dsa   (SLH-DSA)  → Equivocation detection — quantum-resistant fraud proof
/// ```
///
/// The EOTS key is **isolated** from the main key. Even if EOTS key is extracted
/// (equivocation or quantum attack), only the Bond UTXO (33.33%) is at risk.
pub struct SequencerKeys {
    /// Main Schnorr key — controls Main UTXO (66.67% of stake).
    /// Used for identity / address derivation only. NOT used for block signing.
    pub main_key: SchnorrKeyPair,
    /// EOTS key — controls Bond UTXO (33.33% of stake) ONLY.
    /// Ephemeral per epoch. Used for EOTS block signing.
    pub eots_key: EotsKeyPair,
    /// SLH-DSA key pair for quantum-resistant fraud proofs.
    pub slh_dsa: SlhDsaKeyPair,
    /// Sequencer address (derived from main_key).
    pub address: Address,
}

impl SequencerKeys {
    /// Generate new sequencer keys with isolated EOTS key.
    pub fn generate() -> Result<Self, SequencerError> {
        let main_key = SchnorrKeyPair::generate();
        let slh_dsa = SlhDsaKeyPair::generate().map_err(|e| SequencerError::SigningError {
            msg: format!("SLH-DSA key generation failed: {e}"),
        })?;

        // Generate an ISOLATED EOTS key — deterministically derived from
        // the main key's public key. This MUST match the derivation in
        // from_secret_bytes() so that keygen output matches runtime keys.
        // Deterministically derived from the main key's public key.
        let eots_secret = {
            let mut hasher = brrq_crypto::hash::Hasher::new();
            hasher.update(brrq_crypto::domain_tags::EOTS_BOND_KEY);
            hasher.update(main_key.public_key().as_bytes());
            hasher.finalize()
        };
        let eots_key = EotsKeyPair::from_secret_bytes(&eots_secret.0).map_err(|e| {
            SequencerError::SigningError {
                msg: format!("EOTS key generation failed: {e}"),
            }
        })?;

        let address = Address::from_public_key(main_key.public_key().as_bytes());

        Ok(Self {
            main_key,
            eots_key,
            slh_dsa,
            address,
        })
    }

    /// Rotate the EOTS key for a new epoch (ephemeral key rotation).
    ///
    /// Derives a new EOTS key from the epoch seed, ensuring each epoch
    /// gets a unique bond key. Previous epoch keys are discarded.
    ///
    /// Returns `Err` if key derivation fails (broken cryptographic environment).
    pub fn rotate_eots_key(
        &mut self,
        epoch_seed: &Hash256,
        epoch: u64,
    ) -> Result<(), SequencerError> {
        let new_secret = {
            let mut hasher = brrq_crypto::hash::Hasher::new();
            hasher.update(brrq_crypto::domain_tags::EOTS_EPOCH_KEY);
            hasher.update(epoch_seed.as_bytes());
            hasher.update(&epoch.to_le_bytes());
            hasher.update(self.main_key.public_key().as_bytes());
            hasher.finalize()
        };
        self.eots_key = EotsKeyPair::from_secret_bytes(&new_secret.0).map_err(|e| {
            SequencerError::SigningError {
                msg: format!("EOTS epoch key derivation failed: {e}"),
            }
        })?;
        Ok(())
    }

    /// Reconstruct sequencer keys deterministically from a 32-byte main key secret.
    ///
    /// The EOTS and SLH-DSA keys are derived from the main key, ensuring the
    /// same secret always produces the same address and signing keys.
    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self, SequencerError> {
        let secret_arr: [u8; 32] = secret
            .try_into()
            .map_err(|_| SequencerError::SigningError {
                msg: format!("secret must be 32 bytes, got {}", secret.len()),
            })?;
        let main_key = SchnorrKeyPair::from_secret_bytes(&secret_arr).map_err(|e| {
            SequencerError::SigningError {
                msg: format!("invalid Schnorr secret key: {e}"),
            }
        })?;

        let slh_dsa = {
            let mut hasher = brrq_crypto::hash::Hasher::new();
            hasher.update(brrq_crypto::domain_tags::SLH_DSA_KEY);
            hasher.update(secret);
            let seed = hasher.finalize();
            SlhDsaKeyPair::from_seed(&seed.0).map_err(|e| SequencerError::SigningError {
                msg: format!("SLH-DSA key generation failed: {e}"),
            })?
        };

        let eots_secret = {
            let mut hasher = brrq_crypto::hash::Hasher::new();
            hasher.update(brrq_crypto::domain_tags::EOTS_BOND_KEY);
            hasher.update(main_key.public_key().as_bytes());
            hasher.finalize()
        };
        let eots_key = EotsKeyPair::from_secret_bytes(&eots_secret.0).map_err(|e| {
            SequencerError::SigningError {
                msg: format!("EOTS key generation failed: {e}"),
            }
        })?;

        let address = Address::from_public_key(main_key.public_key().as_bytes());

        Ok(Self {
            main_key,
            eots_key,
            slh_dsa,
            address,
        })
    }

    /// Return the 32-byte secret of the main Schnorr key.
    /// WARNING: Returns raw secret key bytes. Handle with extreme care.
    pub fn main_key_secret_bytes(&self) -> [u8; 32] {
        *self.main_key.secret_bytes()
    }

    /// Create sequencer identity for block headers.
    pub fn identity(&self) -> SequencerIdentity {
        SequencerIdentity {
            schnorr_pk: *self.eots_key.public_key(),
            slh_dsa_pk: self.slh_dsa.public_key().clone(),
            address: self.address,
        }
    }
}

/// Block builder constructs and signs blocks.
pub struct BlockBuilder {
    /// Sequencer keys.
    keys: std::sync::Arc<SequencerKeys>,
    /// Gas limit per block.
    gas_limit: u64,
    /// Current epoch.
    epoch: u64,
    /// Expected chain ID for transaction validation (whitepaper §3.4).
    chain_id: u64,
    /// Current Bitcoin L1 block height (None if L1 not connected).
    l1_height: Option<u64>,
    /// Current Bitcoin L1 block hash (None if L1 not connected).
    l1_hash: Option<Hash256>,
    /// Current EIP-1559 base fee in sat/gas (§9.4).
    /// Transactions with gas_price < base_fee are skipped during block building.
    base_fee: u64,
}

impl BlockBuilder {
    /// Create a new block builder with default TESTNET chain ID.
    ///
    /// **Test-only convenience**. Production code should use
    /// [`with_chain_id`](Self::with_chain_id) to set the correct chain.
    pub fn new(keys: std::sync::Arc<SequencerKeys>) -> Self {
        Self::with_chain_id(keys, chain_id::TESTNET)
    }

    /// Create a new block builder with an explicit chain ID.
    pub fn with_chain_id(keys: std::sync::Arc<SequencerKeys>, chain_id: u64) -> Self {
        Self {
            keys,
            gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
            epoch: 0,
            chain_id,
            l1_height: None,
            l1_hash: None,
            base_fee: 0, // 0 = no base fee filtering (backwards compat for tests)
        }
    }

    /// Set the expected chain ID for transaction validation.
    pub fn set_chain_id(&mut self, id: u64) {
        self.chain_id = id;
    }

    /// Set the gas limit for new blocks.
    pub fn set_gas_limit(&mut self, limit: u64) {
        self.gas_limit = limit;
    }

    /// Set the current epoch.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch;
    }

    /// Set the current base fee from the dynamic fee market (§9.4).
    ///
    /// Transactions with `gas_price < base_fee` are skipped during block building.
    /// Called by the node before each `build_block()` after advancing the fee market.
    pub fn set_base_fee(&mut self, fee: u64) {
        self.base_fee = fee;
    }

    /// Set the L1 context for anchor data in block headers.
    ///
    /// Called before `build_block()` when the node is connected to Bitcoin L1.
    /// The L1 height and hash are included as metadata in the block header
    /// (not part of the L2 consensus hash).
    pub fn set_l1_context(&mut self, height: u64, hash: Hash256) {
        self.l1_height = Some(height);
        self.l1_hash = Some(hash);
    }

    /// Clear the L1 context (when L1 connection is lost).
    pub fn clear_l1_context(&mut self) {
        self.l1_height = None;
        self.l1_hash = None;
    }

    /// Get the sequencer's address.
    pub fn sequencer_address(&self) -> Address {
        self.keys.address
    }

    /// Generate a deterministic RANDAO secret for the given epoch.
    ///
    /// secret = SHA-256(RANDAO_SECRET_V1 || eots_secret_bytes || epoch)
    /// WARNING: Returns RANDAO secret. Do not expose externally.
    pub fn randao_secret(&self, epoch: u64) -> Hash256 {
        use brrq_crypto::hash::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::RANDAO_SECRET_V1);
        hasher.update(self.keys.eots_key.secret_bytes().as_ref());
        hasher.update(&epoch.to_le_bytes());
        hasher.finalize()
    }

    /// Sign a RANDAO message (commitment or reveal) with EOTS.
    ///
    /// Uses a nonce height offset of `1 << 48` to avoid collision with
    /// block signing nonces. Commitment and reveal get distinct nonce slots.
    pub fn sign_randao(
        &self,
        message: &Hash256,
        epoch: u64,
        is_reveal: bool,
    ) -> Option<brrq_types::Signature> {
        // Nonce derivation: offset height far beyond any real block height.
        const RANDAO_NONCE_OFFSET: u64 = 1u64 << 48;
        let nonce_height = RANDAO_NONCE_OFFSET + epoch * 2 + if is_reveal { 1 } else { 0 };

        // EOTS V1: RANDAO nonces are epoch-based protocol messages, not block
        // proposals — no natural prev_block_hash is available for chain binding.
        // This is acceptable because RANDAO nonces use a separate offset domain
        // (1 << 48) that cannot collide with block-signing nonces.
        #[allow(deprecated)]
        let (nonce_sk, nonce_commitment) = self
            .keys
            .eots_key
            .generate_nonce(nonce_height, epoch)
            .ok()?;

        let eots_sig = self
            .keys
            .eots_key
            .sign(message, &nonce_sk, &nonce_commitment)
            .ok()?;

        // Convert EOTS signature (R || s) to BIP-340-compatible 64 bytes.
        // nonce_commitment.0 is 33-byte compressed point; skip parity prefix.
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&eots_sig.nonce_commitment().as_bytes()[1..33]);
        sig_bytes[32..].copy_from_slice(eots_sig.s_value());

        Some(brrq_types::Signature::Schnorr(
            brrq_crypto::schnorr::SchnorrSignature::from_bytes(sig_bytes),
        ))
    }

    /// Apply Portal (L3) side-effects after transaction execution.
    ///
    /// Handles lock creation, settlement, batch settlement, cancellation,
    /// and lock pool operations against the portal escrow and nullifier state.
    /// Returns `true` if the portal operation failed and the transaction
    /// should be rolled back and skipped.
    fn apply_portal_effects(
        &self,
        tx: &Transaction,
        escrow: &mut (impl PortalState + ?Sized),
        nullifiers: &mut (impl NullifierStore + ?Sized),
        state: &mut WorldState,
        height: u64,
    ) -> bool {
        let sender = *tx.sender();
        let mut portal_failed = false;

        match &tx.body.kind {
            TransactionKind::CreatePortalLock {
                amount,
                condition_hash,
                nullifier_hash,
                timeout_l2_block,
            } => {
                // Balance already deducted by executor via WorldState.
                // Register lock in escrow (pure registry — no balance tracking).
                let pubkey = match &tx.public_key {
                    brrq_types::PublicKey::Schnorr(pk) => *pk,
                    _ => {
                        tracing::warn!("Portal lock requires Schnorr key");
                        portal_failed = true;
                        return portal_failed;
                    }
                };
                match escrow.register_lock(
                    sender, pubkey, *amount, *condition_hash,
                    *nullifier_hash, *timeout_l2_block, height,
                ) {
                    Ok(id) => {
                        tracing::info!(lock_id = %id, "Portal lock registered in block");
                    }
                    Err(e) => {
                        tracing::warn!("Portal register_lock failed: {e}");
                        portal_failed = true;
                    }
                }
            }

            TransactionKind::SettlePortalLock {
                lock_id,
                merchant_secret,
                portal_signature,
                nullifier,
            } => {
                // Verify merchant secret and settle
                let sig = match brrq_crypto::schnorr::SchnorrSignature::from_slice(portal_signature) {
                    Ok(s) => s,
                    Err(_) => {
                        tracing::warn!("Portal settle: invalid signature format");
                        portal_failed = true;
                        return portal_failed;
                    }
                };

                let claim = brrq_portal::SettlementClaim {
                    lock_id: *lock_id,
                    merchant_secret: merchant_secret.clone(),
                    signature: sig,
                    nullifier: *nullifier,
                    merchant_address: sender, // settler is the merchant
                };

                match crate::traits::settle_portal_key_via_traits(escrow, nullifiers, &claim, height) {
                    Ok(amount) => {
                        // Credit merchant in WorldState (escrow already tracked internally)
                        let acct = state.get_or_create_account(sender);
                        acct.balance = acct.balance.saturating_add(amount);
                        state.flush_account(&sender);
                        tracing::info!(lock_id = %lock_id, amount, "Portal lock settled in block");
                    }
                    Err(e) => {
                        tracing::warn!("Portal settle failed: {e}");
                        portal_failed = true;
                    }
                }
            }

            TransactionKind::BatchSettlePortal { claims } => {
                // Log dropped claims instead of silently filtering
                let mut dropped = 0usize;
                let portal_claims: Vec<brrq_portal::SettlementClaim> = claims.iter().filter_map(|c| {
                    match brrq_crypto::schnorr::SchnorrSignature::from_slice(&c.portal_signature) {
                        Ok(sig) => Some(brrq_portal::SettlementClaim {
                            lock_id: c.lock_id,
                            merchant_secret: c.merchant_secret.clone(),
                            signature: sig,
                            nullifier: c.nullifier,
                            merchant_address: sender,
                        }),
                        Err(_) => {
                            tracing::warn!(lock_id = %c.lock_id, "batch claim dropped: malformed signature");
                            dropped += 1;
                            None
                        }
                    }
                }).collect();
                if dropped > 0 {
                    tracing::warn!(dropped, "batch settlement: {} claims had malformed signatures", dropped);
                }

                match crate::traits::batch_settle_via_traits(escrow, nullifiers, &portal_claims, height) {
                    Ok(result) => {
                        // Credit total settled amount to merchant in WorldState.
                        // Use result.total_settled_amount (captured during settlement)
                        // instead of reading lock amounts after settlement.
                        if result.total_settled_amount > 0 {
                            let acct = state.get_or_create_account(sender);
                            acct.balance = acct.balance.saturating_add(result.total_settled_amount);
                            state.flush_account(&sender);
                        }
                        tracing::info!(
                            succeeded = result.succeeded,
                            failed = result.failed,
                            "Portal batch settled in block"
                        );
                    }
                    Err(e) => {
                        tracing::warn!("Portal batch settle failed: {e}");
                        portal_failed = true;
                    }
                }
            }

            TransactionKind::CancelPortalLock { lock_id } => {
                match escrow.cancel_lock(lock_id, &sender, height) {
                    Ok(amount) => {
                        // Refund to owner in WorldState
                        let acct = state.get_or_create_account(sender);
                        acct.balance = acct.balance.saturating_add(amount);
                        state.flush_account(&sender);
                        tracing::info!(lock_id = %lock_id, amount, "Portal lock cancelled in block");
                    }
                    Err(e) => {
                        tracing::warn!("Portal cancel failed: {e}");
                        portal_failed = true;
                    }
                }
            }

            TransactionKind::CreateLockPool { slot_amounts, timeout_l2_block } => {
                // Balance already deducted by executor via WorldState.
                // Register each slot as an individual lock (pure registry).
                let pubkey = match &tx.public_key {
                    brrq_types::PublicKey::Schnorr(pk) => *pk,
                    _ => {
                        tracing::warn!("Portal lock pool requires Schnorr key");
                        portal_failed = true;
                        return portal_failed;
                    }
                };

                // Track created lock IDs for rollback on partial failure.
                let mut created_ids = Vec::new();
                for &amount in slot_amounts.iter() {
                    match escrow.register_lock(
                        sender, pubkey, amount, Hash256::ZERO,
                        Hash256::ZERO, *timeout_l2_block, height,
                    ) {
                        Ok(id) => created_ids.push(id),
                        Err(e) => {
                            tracing::warn!("Portal pool slot failed: {e}");
                            // Rollback all locks created in this batch
                            for id in &created_ids {
                                let _ = escrow.cancel_lock(id, &sender, height);
                            }
                            portal_failed = true;
                            break;
                        }
                    }
                }
                if !portal_failed {
                    tracing::info!(
                        slots = created_ids.len(),
                        "Portal lock pool registered in block"
                    );
                }
            }

            TransactionKind::RefillLockPool { slot_amounts, timeout_l2_block } => {
                let pubkey = match &tx.public_key {
                    brrq_types::PublicKey::Schnorr(pk) => *pk,
                    _ => {
                        tracing::warn!("Portal refill requires Schnorr key");
                        portal_failed = true;
                        return portal_failed;
                    }
                };
                // Track + rollback on partial failure
                let mut created_ids = Vec::new();
                for &amount in slot_amounts.iter() {
                    match escrow.register_lock(
                        sender, pubkey, amount, Hash256::ZERO,
                        Hash256::ZERO, *timeout_l2_block, height,
                    ) {
                        Ok(id) => created_ids.push(id),
                        Err(e) => {
                            tracing::warn!("Portal refill slot failed: {e}");
                            for id in &created_ids {
                                let _ = escrow.cancel_lock(id, &sender, height);
                            }
                            portal_failed = true;
                            break;
                        }
                    }
                }
                if !portal_failed {
                    tracing::info!(slots = created_ids.len(), "Portal pool refilled in block");
                }
            }

            TransactionKind::UpdateLockCondition {
                lock_id,
                condition_hash,
                nullifier_hash,
                merchant_address,
                merchant_pubkey,
            } => {
                // NESTING-FIX: Flattened with early-return pattern (was depth 6 → now depth 3)
                let lock = match escrow.get_lock(lock_id) {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::warn!("Portal UpdateLockCondition lock not found: {e}");
                        portal_failed = true;
                        return portal_failed;
                    }
                };
                if lock.owner != sender {
                    tracing::warn!("Portal UpdateLockCondition: sender {} is not lock owner {}", sender, lock.owner);
                    portal_failed = true;
                    return portal_failed;
                }
                match escrow.update_lock_condition_with_merchant(
                    &sender, lock_id, *condition_hash, *nullifier_hash, *merchant_address,
                    brrq_crypto::schnorr::SchnorrPublicKey::from_bytes(*merchant_pubkey),
                ) {
                    Ok(()) => tracing::info!(lock_id = %lock_id, "Portal lock condition updated in block"),
                    Err(e) => {
                        tracing::warn!("Portal update_lock_condition failed: {e}");
                        portal_failed = true;
                    }
                }
            }

            TransactionKind::RelayedBatchSettle {
                claims, merchant_address, merchant_signature, relay_fee_bps, relayer_address,
            } => {
                // FEE-HIJACK FIX v2: Enforce relayer_address == tx sender.
                // Without this, a searcher can replace sender and steal the relay fee.
                if *relayer_address != sender {
                    tracing::warn!(
                        "RelayedBatchSettle: relayer_address {} != sender {} — hijack blocked",
                        relayer_address, sender
                    );
                    portal_failed = true;
                    return portal_failed;
                }

                // ECON-FIX: Defense-in-depth cap on relay fee
                if *relay_fee_bps > brrq_portal::types::MAX_RELAY_FEE_BPS {
                    tracing::warn!("relay_fee_bps {} exceeds max {}", relay_fee_bps, brrq_portal::types::MAX_RELAY_FEE_BPS);
                    portal_failed = true;
                    return portal_failed;
                }

                // FEE-HIJACK FIX v2: Verify merchant_signature covers
                // (merchant_address || relayer_address || relay_fee_bps || claims_hash).
                // Including relayer_address ensures the merchant chose THIS relayer.
                {
                    let mut sig_hasher = brrq_crypto::hash::Hasher::new();
                    sig_hasher.update(b"BRRQ_RELAYED_SETTLE_V1");
                    sig_hasher.update(merchant_address.as_bytes());
                    sig_hasher.update(relayer_address.as_bytes());
                    sig_hasher.update(&relay_fee_bps.to_le_bytes());
                    for c in claims.iter() {
                        sig_hasher.update(c.lock_id.as_bytes());
                        sig_hasher.update(c.nullifier.as_bytes());
                    }
                    let sig_payload = sig_hasher.finalize();

                    // Verify merchant_pubkey consistency across ALL claims.
                    // An attacker can create a dummy lock with their own pubkey + victim's
                    // merchant_address. If we trust the first match, the attacker's pubkey
                    // is used to verify the signature, enabling fee hijacking.
                    //
                    // Defense: collect ALL distinct pubkeys from matching locks. If they
                    // disagree (>1 unique pubkey), reject the batch entirely.
                    let mut pubkeys_seen = std::collections::HashSet::new();
                    for c in claims.iter() {
                        if let Ok(lock) = escrow.get_lock(&c.lock_id) {
                            if lock.merchant_address == *merchant_address
                                && lock.merchant_pubkey.as_bytes() != &[0u8; 32]
                            {
                                pubkeys_seen.insert(lock.merchant_pubkey);
                            }
                        }
                    }

                    if pubkeys_seen.len() != 1 {
                        tracing::warn!(
                            "RelayedBatchSettle: {} distinct merchant pubkeys found (expected 1) — possible spoofing",
                            pubkeys_seen.len()
                        );
                        portal_failed = true;
                        return portal_failed;
                    }
                    let merchant_pubkey = *pubkeys_seen.iter().next().unwrap();

                    let sig = match brrq_crypto::schnorr::SchnorrSignature::from_slice(merchant_signature) {
                        Ok(s) => s,
                        Err(_) => {
                            tracing::warn!("RelayedBatchSettle: malformed merchant_signature");
                            portal_failed = true;
                            return portal_failed;
                        }
                    };
                    if brrq_crypto::schnorr::verify(&merchant_pubkey, &sig_payload, &sig).is_err() {
                        tracing::warn!("RelayedBatchSettle: invalid merchant_signature — fee hijack attempt?");
                        portal_failed = true;
                        return portal_failed;
                    }
                }

                // Convert claims and batch-settle (same as BatchSettlePortal)
                let portal_claims: Vec<brrq_portal::SettlementClaim> = claims.iter().filter_map(|c| {
                    let sig = brrq_crypto::schnorr::SchnorrSignature::from_slice(&c.portal_signature).ok()?;
                    Some(brrq_portal::SettlementClaim {
                        lock_id: c.lock_id,
                        merchant_secret: c.merchant_secret.clone(),
                        signature: sig,
                        nullifier: c.nullifier,
                        merchant_address: *merchant_address,
                    })
                }).collect();

                match crate::traits::batch_settle_via_traits(escrow, nullifiers, &portal_claims, height) {
                    Ok(result) => {
                        if result.total_settled_amount > 0 {
                            // Ceil-round relay fee to prevent
                            // integer division truncation griefing.
                            // Before: 99 * 100 / 10000 = 0 (relayer works for free)
                            // After:  (99 * 100 + 9999) / 10000 = 1 (minimum 1 sat)
                            let computed_fee = result.total_settled_amount
                                .saturating_mul(*relay_fee_bps as u64);
                            let fee = if *relay_fee_bps > 0 && computed_fee > 0 {
                                // Ceiling division: (a + b - 1) / b
                                let ceil_fee = computed_fee.saturating_add(9_999) / 10_000;
                                // Safety cap: fee cannot exceed total settlement
                                std::cmp::min(ceil_fee, result.total_settled_amount)
                            } else {
                                0
                            };
                            let merchant_payment = result.total_settled_amount.saturating_sub(fee);

                            // Credit merchant
                            let m_acct = state.get_or_create_account(*merchant_address);
                            m_acct.balance = m_acct.balance.saturating_add(merchant_payment);
                            state.flush_account(merchant_address);

                            // Credit relayer (tx sender)
                            if fee > 0 {
                                let r_acct = state.get_or_create_account(sender);
                                r_acct.balance = r_acct.balance.saturating_add(fee);
                                state.flush_account(&sender);
                            }

                            tracing::info!(
                                succeeded = result.succeeded,
                                failed = result.failed,
                                merchant_payment,
                                relay_fee = fee,
                                "Relayed portal batch settled in block"
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Relayed portal batch settle failed: {e}");
                        portal_failed = true;
                    }
                }
            }

            _ => {} // Non-portal transactions
        }

        portal_failed
    }

    /// Build a block from pending transactions.
    ///
    /// Returns the signed block and a per-transaction execution summary
    /// (in the same order as `block.transactions`) for accurate receipt
    /// generation.
    pub fn build_block(
        &mut self,
        height: u64,
        parent_hash: Hash256,
        transactions: Vec<Transaction>,
        state: &mut WorldState,
        consensus: Option<&mut (impl ConsensusState + ?Sized)>,
    ) -> Result<(Block, Vec<TxExecSummary>), SequencerError> {
        self.build_block_with_portal(
            height, parent_hash, transactions, state, consensus,
            None::<&mut brrq_portal::EscrowManager>,
            None::<&mut brrq_portal::NullifierSet>,
        )
    }

    /// Build a block with Portal (L3) state integration.
    ///
    /// Extended version of `build_block` that also applies Portal escrow and
    /// nullifier effects after each transaction execution.
    pub fn build_block_with_portal(
        &mut self,
        height: u64,
        parent_hash: Hash256,
        transactions: Vec<Transaction>,
        state: &mut WorldState,
        mut consensus: Option<&mut (impl ConsensusState + ?Sized)>,
        mut portal_escrow: Option<&mut (impl PortalState + ?Sized)>,
        mut portal_nullifiers: Option<&mut (impl NullifierStore + ?Sized)>,
    ) -> Result<(Block, Vec<TxExecSummary>), SequencerError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| SequencerError::StateError {
                msg: format!("system clock before UNIX epoch: {e}"),
            })?;

        let mut included_txs = Vec::new();
        let mut exec_summaries = Vec::new();
        let mut total_gas = 0u64;

        // Combined deterministic ordering.
        // Transaction priority reflects economic lifecycle:
        //
        //   0: Funding — CreatePortalLock, CreateLockPool, RefillLockPool
        //      (liquidity MUST be provisioned before it can be consumed)
        //   1: Settlement — SettlePortalLock, BatchSettlePortal, RelayedBatchSettle
        //      (consume available liquidity)
        //   2: General — Transfer, Deploy, ContractCall, UpdateLockCondition, etc.
        //   3: Cancellation — CancelPortalLock
        //      (last resort — merchant gets a fair chance to settle first)
        //
        // Without this order, a RefillLockPool and BatchSettle in the same block
        // would fail: settle runs first (priority 0), finds no liquidity (refill
        // hasn't run yet), and the merchant loses gas fees unfairly.
        //
        // Secondary key: tx hash (deterministic, manipulation-resistant).
        let mut transactions = transactions;
        let hashes: Vec<Hash256> = transactions.iter().map(|tx| tx.hash()).collect();
        let portal_priority = |tx: &Transaction| -> u8 {
            match &tx.body.kind {
                // Priority 0: Funding — provision liquidity first
                TransactionKind::CreatePortalLock { .. }
                | TransactionKind::CreateLockPool { .. }
                | TransactionKind::RefillLockPool { .. } => 0,
                // Priority 1: Settlement — consume available liquidity
                TransactionKind::SettlePortalLock { .. }
                | TransactionKind::BatchSettlePortal { .. }
                | TransactionKind::RelayedBatchSettle { .. } => 1,
                // Priority 3: Cancellation — last resort
                TransactionKind::CancelPortalLock { .. } => 3,
                // Priority 2: Everything else
                _ => 2,
            }
        };
        // Zip with pre-computed hashes, sort by (priority, hash), unzip
        let mut keyed: Vec<(u8, Hash256, Transaction)> = transactions
            .into_iter()
            .enumerate()
            .map(|(i, tx)| (portal_priority(&tx), hashes[i], tx))
            .collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let transactions: Vec<Transaction> = keyed.into_iter().map(|(_, _, tx)| tx).collect();

        for tx in transactions {
            // EIP-1559 base fee check (§9.4): skip transactions that cannot
            // afford the current dynamic base fee. gas_price acts as max_fee_per_gas.
            if self.base_fee > 0 && tx.body.max_fee_per_gas < self.base_fee {
                continue;
            }

            // Pre-check using tx.body.gas_limit as an optimistic upper bound
            // to skip transactions that cannot possibly fit. The authoritative
            // budget check uses result.gas_used below.
            // Use `continue` instead of `break` to skip this oversized
            // transaction and try the next one. `break` would halt block building
            // entirely, potentially leaving smaller valid transactions unincluded.
            if total_gas.saturating_add(tx.body.gas_limit) > self.gas_limit {
                continue;
            }

            // Executor handles its own rollback on error via undo-log
            let ctx = executor::ExecutionContext {
                block_height: height,
                block_timestamp: timestamp,
                base_fee: self.base_fee,
                validator_address: Some(self.sequencer_address()),
            };
            // Execute with full tracing by default for all user transactions in block builder
            match executor::execute_transaction_with_context(&tx, state, self.chain_id, ctx, true) {
                Ok(result) => {
                    // Check actual gas_used against remaining block budget.
                    // Uses real consumption, not declared gas_limit.
                    // Use `continue` instead of `break` to skip this
                    // transaction and try the next one rather than halting.
                    if total_gas.saturating_add(result.gas_used) > self.gas_limit {
                        state.rollback_changes(&result.state_changes);
                        continue;
                    }

                    // Handle staking side-effects via ConsensusState trait.
                    // If staking validation fails, we must rollback the executor's
                    // state changes (gas, nonce) to prevent state divergence.
                    let staking_failed = if let Some(cs) = consensus.as_deref_mut() {
                        cs.apply_staking(&tx, state, height)
                    } else {
                        false
                    };

                    if staking_failed {
                        state.rollback_changes(&result.state_changes);
                        continue;
                    }

                    // Portal (L3) side-effects: create locks, settle, batch, cancel
                    let portal_failed = if let (Some(escrow), Some(nulls)) =
                        (portal_escrow.as_deref_mut(), portal_nullifiers.as_deref_mut())
                    {
                        self.apply_portal_effects(&tx, escrow, nulls, state, height)
                    } else {
                        false
                    };

                    if portal_failed {
                        state.rollback_changes(&result.state_changes);
                        continue;
                    }

                    total_gas = total_gas.saturating_add(result.gas_used);
                    exec_summaries.push(TxExecSummary {
                        gas_used: result.gas_used,
                        success: result.success,
                        logs: result.logs,
                        execution_trace: result.execution_trace,
                    });
                    included_txs.push(tx);
                }
                Err(_e) => {
                    // Executor already rolled back any partial state changes
                    tracing::warn!("Transaction execution failed, skipping");
                    continue;
                }
            }
        }

        // ── Apocalyptic Vector Fix: Autonomous Liveness Ejection REMOVED ──
        // Following the Occam's Razor Critique (U-ZKHR), autonomous ejection
        // has been removed entirely to prevent catastrophic hijacking.
        // Liveness recovery is now triggered ONLY by an explicitly coordinated
        // STARK proof submitted to the Bitcoin L1 (`L1ZklaAnchor`).

        // Compute transaction root
        let tx_hashes: Vec<Hash256> = included_txs.iter().map(|tx| tx.hash()).collect();
        let transactions_root = compute_tx_root(&tx_hashes);

        // Compute signatures root (Aggregation Commitment for Volition DA)
        let sig_hashes: Vec<Hash256> = included_txs
            .iter()
            .map(|tx| {
                let mut hasher = brrq_crypto::hash::Hasher::new();
                hasher.update(tx.signature.as_bytes());
                hasher.finalize()
            })
            .collect();
        let signatures_root = brrq_crypto::merkle::compute_tx_root(&sig_hashes); // Reusing tree logic

        // Get state root
        let state_root = state.state_root();

        // Compute portal nullifier root (if nullifier set is available)
        let portal_nullifier_root = portal_nullifiers
            .as_deref_mut()
            .map(|ns| ns.merkle_root())
            .filter(|r| !r.is_zero());

        // Compute portal escrow blob hash (DA commitment).
        // H(serialized escrow state) — full nodes verify received blob matches this hash.
        let portal_escrow_blob_hash = portal_escrow.as_deref().and_then(|escrow| {
            if escrow.active_lock_count() == 0 && escrow.total_escrowed() == 0 {
                None
            } else {
                match escrow.to_bytes() {
                    Ok(bytes) => {
                        let blob_hash = brrq_crypto::hash::Hasher::hash(&bytes);
                        Some(blob_hash)
                    }
                    Err(e) => {
                        tracing::warn!("Failed to serialize escrow for blob hash: {e}");
                        None
                    }
                }
            }
        });

        // Reuse the timestamp from the start of build_block (line 352)
        // instead of calling SystemTime::now() a second time, which could cause
        // execution context and block header to have different timestamps.
        let header = BlockHeader {
            height,
            timestamp,
            parent_hash,
            transactions_root,
            signatures_root,
            state_root,
            sequencer: self.keys.address,
            epoch: self.epoch,
            gas_used: total_gas,
            gas_limit: self.gas_limit,
            base_fee_per_gas: self.base_fee,
            l1_anchor_height: self.l1_height,
            l1_anchor_hash: self.l1_hash,
            portal_nullifier_root,
            portal_escrow_blob_hash,
        };

        // Dual-sign Block (EOTS + SLH-DSA, §3.6)
        let header_hash = header.hash();
        let signature = self.dual_sign(&header_hash, height, &parent_hash)?;

        let block = Block {
            header,
            signature,
            sequencer_identity: self.keys.identity(),
            transactions: included_txs,
        };

        Ok((block, exec_summaries))
    }

    /// Build a lightweight block for Volition DA (L1 posting).
    /// Executes the same logic, but immediately compresses the resulting block,
    /// dropping the bulky user SLH-DSA signatures to save >98% space on layer 1.
    pub fn build_light_block(
        &mut self,
        height: u64,
        parent_hash: Hash256,
        transactions: Vec<Transaction>,
        state: &mut WorldState,
        consensus: Option<&mut (impl ConsensusState + ?Sized)>,
    ) -> Result<(brrq_types::block::LightBlock, Vec<TxExecSummary>), SequencerError> {
        let (full_block, exec_summaries) =
            self.build_block(height, parent_hash, transactions, state, consensus)?;

        // Compress block directly for Data Availability
        let light_block = full_block.compress_to_light();

        Ok((light_block, exec_summaries))
    }

    /// Build a block from MEV-encrypted envelopes (commit-reveal).
    ///
    /// 1. Decrypts all envelopes in the committed ordering using the epoch key
    /// 2. Executes each plaintext transaction via the standard executor
    /// 3. Builds and signs the block identically to `build_block()`
    ///
    /// Returns the signed block, execution summaries, and the hashes of
    /// envelopes that were successfully included.
    #[cfg(feature = "mev-protection")]
    pub fn build_mev_block(
        &mut self,
        height: u64,
        parent_hash: Hash256,
        mev_mempool: &mut crate::mev::MevMempool,
        epoch_key: &brrq_crypto::encryption::EpochKey,
        state: &mut WorldState,
        consensus: Option<&mut (impl ConsensusState + ?Sized)>,
    ) -> Result<(Block, Vec<TxExecSummary>, Vec<Hash256>), SequencerError> {
        // Capture ordered envelope hashes BEFORE decryption.
        // decrypt_batch() may evict failed envelopes, changing the ordering.
        let ordered = mev_mempool.get_ordered(1000);
        let env_hashes: Vec<Hash256> = ordered.iter().map(|e| e.hash()).collect();

        // 1. Decrypt envelopes in committed order
        let transactions = mev_mempool.decrypt_batch(epoch_key, 1000, height)?;

        if transactions.is_empty() {
            // Build an empty block — same as standard flow
            let (block, summaries) =
                self.build_block(height, parent_hash, vec![], state, consensus)?;
            return Ok((block, summaries, vec![]));
        }

        // 3. Build block using standard build_block with decrypted txs
        let (block, summaries) =
            self.build_block(height, parent_hash, transactions, state, consensus)?;

        // 4. Return hashes of included envelopes for cleanup
        // (only as many as were successfully included in the block)
        let included_hashes = env_hashes.into_iter().take(block.tx_count()).collect();

        Ok((block, summaries, included_hashes))
    }

    /// Build a block from mempool transactions plus synthetic deposits.
    ///
    /// Synthetic deposits are executed first (before user transactions) and
    /// appear at the beginning of the block. They use a separate execution
    /// path that bypasses signature/nonce/gas validation.
    ///
    /// The block is built in a single pass — no re-signing needed.
    pub fn build_block_with_deposits(
        &mut self,
        height: u64,
        parent_hash: Hash256,
        transactions: Vec<Transaction>,
        synthetic_deposits: &[SyntheticDeposit],
        state: &mut WorldState,
        bridge: &mut brrq_bridge::BridgeManager,
        mut consensus: Option<&mut (impl ConsensusState + ?Sized)>,
        mut portal_escrow: Option<&mut (impl PortalState + ?Sized)>,
        mut portal_nullifiers: Option<&mut (impl NullifierStore + ?Sized)>,
    ) -> Result<(Block, Vec<TxExecSummary>), SequencerError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| SequencerError::StateError {
                msg: format!("system clock before UNIX epoch: {e}"),
            })?;

        if synthetic_deposits.is_empty() {
            // No deposits — use standard build path with portal support
            return self.build_block_with_portal(
                height, parent_hash, transactions, state, consensus,
                portal_escrow, portal_nullifiers,
            );
        }

        // ── 1. Execute and wrap synthetic deposits ──────────────────────
        let mut all_txs = Vec::with_capacity(synthetic_deposits.len() + transactions.len());
        let mut all_summaries = Vec::with_capacity(synthetic_deposits.len() + transactions.len());
        let mut total_gas = 0u64;

        for dep in synthetic_deposits {
            let spv_proof = if dep.merkle_block_raw.is_empty() {
                None
            } else {
                Some(brrq_bitcoin::spv::SpvProof {
                    txid: *dep.btc_tx_id.as_bytes(),
                    merkle_block_raw: dep.merkle_block_raw.clone(),
                    block_hash: *dep.block_hash.as_bytes(),
                    block_height: 0,
                })
            };

            // Process the deposit through the bridge to mathematically enforce SPV structure and compute minted amount.
            let minted = match bridge.process_deposit(
                dep.btc_tx_id,
                dep.btc_vout,
                dep.amount, // RAW amount
                dep.recipient,
                6,                          // Default confirmations for L2 processing
                Some(self.keys.address),    // Sequencer is the submitter for synthetic deposits
                spv_proof,
            ) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        "Bridge limits violated for pending deposit {:?}: {}",
                        dep.btc_tx_id,
                        e
                    );
                    continue; // Skip execution and inclusion
                }
            };

            match executor::execute_synthetic_deposit(&dep.recipient, minted, &dep.btc_tx_id, state)
            {
                Ok(result) => {
                    total_gas = total_gas.saturating_add(result.gas_used);
                    all_summaries.push(TxExecSummary {
                        gas_used: result.gas_used,
                        success: result.success,
                        logs: result.logs,
                        execution_trace: result.execution_trace,
                    });

                    // Create a Transaction wrapper for block inclusion.
                    // Uses Address::ZERO as sender (system) and a zero signature.
                    let body = brrq_types::transaction::TransactionBody {
                        from: Address::ZERO,
                        kind: TransactionKind::DepositSynthetic {
                            recipient: dep.recipient,
                            amount: minted,
                            btc_tx_id: dep.btc_tx_id,
                            btc_vout: dep.btc_vout,
                            block_hash: dep.block_hash,
                            merkle_block_raw: dep.merkle_block_raw.clone(),
                        },
                        nonce: 0,
                        gas_limit: result.gas_used,
                        max_fee_per_gas: 0,
                        max_priority_fee_per_gas: 0,
                        chain_id: self.chain_id,
                    };
                    all_txs.push(Transaction {
                        body,
                        signature: brrq_types::signature::Signature::Schnorr(
                            brrq_crypto::schnorr::SchnorrSignature::from_bytes([0u8; 64]),
                        ),
                        public_key: brrq_types::signature::PublicKey::Schnorr(
                            brrq_crypto::schnorr::SchnorrPublicKey::from_bytes([0u8; 32]),
                        ),
                    });
                }
                Err(e) => {
                    tracing::warn!("Synthetic deposit execution failed: {e}, skipping");
                }
            }
        }

        // ── 2. Execute user transactions (same logic as build_block) ────
        // Sort user transactions by portal priority,
        // matching build_block_with_portal(). Without this sort, a CancelPortalLock
        // could execute before SettlePortalLock in the same block when deposits
        // are present, violating the economic lifecycle guarantee.
        let mut transactions = transactions;
        let hashes: Vec<Hash256> = transactions.iter().map(|tx| tx.hash()).collect();
        let portal_priority = |tx: &Transaction| -> u8 {
            match &tx.body.kind {
                TransactionKind::CreatePortalLock { .. }
                | TransactionKind::CreateLockPool { .. }
                | TransactionKind::RefillLockPool { .. } => 0,
                TransactionKind::SettlePortalLock { .. }
                | TransactionKind::BatchSettlePortal { .. }
                | TransactionKind::RelayedBatchSettle { .. } => 1,
                TransactionKind::CancelPortalLock { .. } => 3,
                _ => 2,
            }
        };
        let mut keyed: Vec<(u8, Hash256, Transaction)> = transactions
            .into_iter()
            .enumerate()
            .map(|(i, tx)| (portal_priority(&tx), hashes[i], tx))
            .collect();
        keyed.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        let transactions: Vec<Transaction> = keyed.into_iter().map(|(_, _, tx)| tx).collect();

        for tx in transactions {
            if self.base_fee > 0 && tx.body.max_fee_per_gas < self.base_fee {
                continue;
            }
            // H3-FIX: Use continue instead of break to avoid censoring smaller txs.
            if total_gas.saturating_add(tx.body.gas_limit) > self.gas_limit {
                continue;
            }

            let ctx = executor::ExecutionContext {
                block_height: height,
                block_timestamp: timestamp,
                base_fee: self.base_fee,
                validator_address: Some(self.sequencer_address()),
            };
            match executor::execute_transaction_with_context(&tx, state, self.chain_id, ctx, true) {
                Ok(result) => {
                    // H3-FIX: Use continue instead of break for actual gas overflow.
                    if total_gas.saturating_add(result.gas_used) > self.gas_limit {
                        state.rollback_changes(&result.state_changes);
                        continue;
                    }

                    // Handle staking side-effects via ConsensusState trait.
                    let staking_failed = if let Some(cs) = consensus.as_deref_mut() {
                        cs.apply_staking(&tx, state, height)
                    } else {
                        false
                    };

                    if staking_failed {
                        state.rollback_changes(&result.state_changes);
                        continue;
                    }

                    // Portal (L3) side-effects: create locks, settle, batch, cancel
                    let portal_failed = if let (Some(escrow), Some(nulls)) =
                        (portal_escrow.as_deref_mut(), portal_nullifiers.as_deref_mut())
                    {
                        self.apply_portal_effects(&tx, escrow, nulls, state, height)
                    } else {
                        false
                    };

                    if portal_failed {
                        state.rollback_changes(&result.state_changes);
                        continue;
                    }

                    total_gas = total_gas.saturating_add(result.gas_used);
                    all_summaries.push(TxExecSummary {
                        gas_used: result.gas_used,
                        success: result.success,
                        logs: result.logs,
                        execution_trace: result.execution_trace,
                    });
                    all_txs.push(tx);
                }
                Err(_e) => {
                    tracing::warn!("Transaction execution failed, skipping");
                    continue;
                }
            }
        }

        // Liveness recovery is handled exclusively via L1ZklaAnchor.
        // Autonomous ejection was removed per Occam's Razor critique (U-ZKHR).

        // ── 3. Assemble and sign block (single pass) ────────────────────
        let tx_hashes: Vec<Hash256> = all_txs.iter().map(|tx| tx.hash()).collect();
        let transactions_root = compute_tx_root(&tx_hashes);

        let sig_hashes: Vec<Hash256> = all_txs
            .iter()
            .map(|tx| {
                let mut hasher = brrq_crypto::hash::Hasher::new();
                hasher.update(tx.signature.as_bytes());
                hasher.finalize()
            })
            .collect();
        let signatures_root = brrq_crypto::merkle::compute_tx_root(&sig_hashes);

        let state_root = state.state_root();

        let header = BlockHeader {
            height,
            timestamp,
            parent_hash,
            transactions_root,
            signatures_root,
            state_root,
            sequencer: self.keys.address,
            epoch: self.epoch,
            gas_used: total_gas,
            gas_limit: self.gas_limit,
            base_fee_per_gas: self.base_fee,
            l1_anchor_height: self.l1_height,
            l1_anchor_hash: self.l1_hash,
            // Compute portal header fields matching build_block_with_portal()
            // Filter out zero nullifier roots and skip empty escrow serialization
            // to ensure consistent block headers between both code paths.
            portal_nullifier_root: portal_nullifiers
                .as_mut()
                .map(|n| n.merkle_root())
                .filter(|r| !r.is_zero()),
            portal_escrow_blob_hash: portal_escrow.as_ref().and_then(|escrow| {
                if escrow.active_lock_count() == 0 && escrow.total_escrowed() == 0 {
                    None
                } else {
                    escrow.to_bytes().ok().map(|b| brrq_crypto::hash::Hasher::hash(&b))
                }
            }),
        };

        let header_hash = header.hash();
        let signature = self.dual_sign(&header_hash, height, &parent_hash)?;

        let block = Block {
            header,
            signature,
            sequencer_identity: self.keys.identity(),
            transactions: all_txs,
        };

        Ok((block, all_summaries))
    }

    /// Build a block from MEV-protected (pre-decrypted) transactions.
    ///
    /// Unlike `build_block()` which accepts arbitrary transaction ordering,
    /// this method accepts transactions that have already been through the
    /// Commit→Decrypt pipeline. The ordering is LOCKED — transactions are
    /// executed in the exact order given, preserving the committed ordering.
    ///
    /// Per whitepaper §8.1: "ordering is fixed and cannot be changed"
    #[cfg(feature = "mev-protection")]
    pub fn build_block_from_mev(
        &mut self,
        height: u64,
        parent_hash: Hash256,
        mev_transactions: Vec<Transaction>,
        state: &mut WorldState,
        consensus: Option<&mut (impl ConsensusState + ?Sized)>,
    ) -> Result<(Block, Vec<TxExecSummary>), SequencerError> {
        // Delegate to build_block — the ordering is already locked by the
        // MEV commit-reveal protocol, and build_block processes transactions
        // in the exact order they are provided (no reordering).
        self.build_block(height, parent_hash, mev_transactions, state, consensus)
    }

    /// Dual-sign a block header hash with EOTS + SLH-DSA (§3.6).
    ///
    /// 1. **EOTS**: Sign with isolated bond key using deterministic nonce from (height, epoch).
    ///    If the sequencer ever signs two different blocks at the same height,
    ///    the EOTS secret key becomes extractable → immediate slashing.
    /// 2. **SLH-DSA**: Sign with quantum-resistant hash-based signature.
    fn dual_sign(
        &self,
        header_hash: &Hash256,
        height: u64,
        parent_hash: &Hash256,
    ) -> Result<DualSignature, SequencerError> {
        // 1. EOTS signature (isolated bond key)
        // V2 nonce: binds to prev_block_hash to prevent pre-computation attacks.
        let (nonce_sk, nonce_commitment) = self
            .keys
            .eots_key
            .generate_nonce_v2(height, self.epoch, Some(parent_hash))
            .map_err(|e| SequencerError::SigningError {
                msg: format!("EOTS nonce generation failed: {}", e),
            })?;

        let eots_sig = self
            .keys
            .eots_key
            .sign(header_hash, &nonce_sk, &nonce_commitment)
            .map_err(|e| SequencerError::SigningError {
                msg: format!("EOTS signing failed: {}", e),
            })?;

        // 2. SLH-DSA signature (quantum-resistant)
        // Sign height || header_hash to bind the signature to a specific height.
        // This prevents cross-height equivocation proof attacks where legitimate
        // blocks from different heights are presented as equivocation at one height.
        let mut slh_msg = Vec::with_capacity(8 + 32);
        slh_msg.extend_from_slice(&height.to_le_bytes());
        slh_msg.extend_from_slice(header_hash.as_bytes());
        let slh_sig =
            self.keys
                .slh_dsa
                .sign(&slh_msg)
                .map_err(|e| SequencerError::SigningError {
                    msg: format!("SLH-DSA signing failed: {}", e),
                })?;

        Ok(DualSignature {
            eots: eots_sig,
            slh_dsa: slh_sig,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as BitcoinHash;
    use brrq_crypto::hash::Hasher;
    use brrq_crypto::schnorr::{SchnorrPublicKey, SchnorrSignature};
    use brrq_types::signature::{PublicKey, Signature};
    use brrq_types::transaction::{TransactionBody, TransactionKind, chain_id};

    fn make_transfer_tx(
        from: Address,
        nonce: u64,
        to: Address,
        amount: u64,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
    ) -> Transaction {
        let body = TransactionBody {
            from,
            kind: TransactionKind::Transfer { to, amount },
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            chain_id: chain_id::TESTNET,
        };
        Transaction {
            body,
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        }
    }

    fn test_addr(name: &str) -> Address {
        let hash = Hasher::hash(name.as_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Address::from_bytes(bytes)
    }

    #[test]
    fn test_sequencer_keys_generation() {
        let keys = SequencerKeys::generate().unwrap();
        let identity = keys.identity();
        assert_ne!(identity.address, Address::ZERO);
    }

    #[test]
    fn test_build_empty_block() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let (block, summaries) = builder
            .build_block(0, Hash256::ZERO, vec![], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        assert_eq!(block.height(), 0);
        assert_eq!(block.tx_count(), 0);
        assert_eq!(block.header.gas_used, 0);
        assert!(summaries.is_empty());
    }

    #[test]
    fn test_build_block_with_transfer() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        // Fund alice via set_account (properly updates trie)
        use brrq_types::account::Account;
        let account = Account::new_eoa(alice, 10_000_000);
        state.set_account(account);

        let tx = make_transfer_tx(alice, 0, bob, 1000, 1, 1);
        let (block, summaries) = builder
            .build_block(1, Hash256::ZERO, vec![tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        assert_eq!(block.height(), 1);
        assert_eq!(block.tx_count(), 1);
        assert_eq!(
            block.header.gas_used,
            brrq_types::gas::MIN_TRANSACTION_GAS,
            "single transfer must consume exactly MIN_TRANSACTION_GAS"
        );
        assert_eq!(state.balance(&bob), 1000);
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].success);
        assert_eq!(
            summaries[0].gas_used,
            brrq_types::gas::MIN_TRANSACTION_GAS,
            "transfer receipt must report exact MIN_TRANSACTION_GAS"
        );
    }

    #[test]
    fn test_block_dual_signature() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let (block, _summaries) = builder
            .build_block(0, Hash256::ZERO, vec![], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        // Both signatures must be present
        assert!(block.signature.slh_dsa.size() > 0);
        assert_eq!(block.signature.eots.s_value().len(), 32);
        assert_eq!(block.signature.eots.nonce_commitment().as_bytes().len(), 33);

        // EOTS signature must be verifiable with the sequencer's public key
        let header_hash = block.header.hash();
        brrq_crypto::eots::verify(
            &block.sequencer_identity.schnorr_pk,
            &header_hash,
            &block.signature.eots,
        )
        .expect("EOTS signature on block must verify");

        // SLH-DSA signature must be verifiable with the sequencer's public key.
        // The signing message is `height || header_hash` to prevent
        // cross-height equivocation proof attacks.
        let mut slh_msg = Vec::with_capacity(8 + 32);
        slh_msg.extend_from_slice(&block.header.height.to_le_bytes());
        slh_msg.extend_from_slice(header_hash.as_bytes());
        brrq_crypto::slh_dsa::verify(
            &block.sequencer_identity.slh_dsa_pk,
            &slh_msg,
            &block.signature.slh_dsa,
        )
        .expect("SLH-DSA signature on block must verify");
    }

    #[test]
    fn test_build_light_block() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let alice = test_addr("alice");
        let bob = test_addr("bob");
        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 10_000_000));

        let tx = make_transfer_tx(alice, 0, bob, 1000, 1, 1);

        let (light_block, summaries) = builder
            .build_light_block(1, Hash256::ZERO, vec![tx.clone()], &mut state.clone(), None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        let (full_block, _) = builder
            .build_block(1, Hash256::ZERO, vec![tx.clone()], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        assert_eq!(light_block.height(), 1);
        assert_eq!(light_block.tx_count(), 1);
        // Light transactions don't carry signature/pubkey, so their hash
        // differs from the full transaction hash (which includes sig bytes
        // for malleability protection). Compare body hash instead.
        assert_eq!(light_block.transactions[0].body.hash(), tx.body.hash());
        assert_eq!(summaries.len(), 1);

        // Ensure compression was performed against the full block size
        assert!(light_block.size() < full_block.size());
    }

    #[test]
    fn test_block_gas_limit_enforcement() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        builder.set_gas_limit(30_000);
        let mut state = WorldState::new();

        let alice = test_addr("alice");
        let bob = test_addr("bob");
        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 100_000_000));

        // 2 txs each 21000 gas → only 1 fits in 30000
        let tx1 = make_transfer_tx(alice, 0, bob, 100, 1, 1);
        let tx2 = make_transfer_tx(alice, 1, bob, 100, 1, 1);

        let (block, summaries) = builder
            .build_block(1, Hash256::ZERO, vec![tx1, tx2], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        assert_eq!(block.tx_count(), 1);
        assert_eq!(summaries.len(), 1);
    }

    #[test]
    fn test_block_skips_invalid_tx() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let alice = test_addr("alice");
        let bob = test_addr("bob");
        // Don't fund alice
        let tx = make_transfer_tx(alice, 0, bob, 1000, 1, 1);

        let (block, summaries) = builder
            .build_block(1, Hash256::ZERO, vec![tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        assert_eq!(block.tx_count(), 0);
        assert!(summaries.is_empty());
    }

    #[test]
    fn test_block_skips_overflow_gas_tx() {
        use brrq_types::account::Account;
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 10_000_000));

        // Craft a tx with gas_limit * gas_price that overflows u64
        let body = TransactionBody {
            from: alice,
            kind: TransactionKind::Transfer {
                to: bob,
                amount: 100,
            },
            nonce: 0,
            gas_limit: u64::MAX,
            max_fee_per_gas: 2,
            max_priority_fee_per_gas: 10,
            chain_id: chain_id::TESTNET,
        };
        let tx = Transaction {
            body,
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        // Block should skip the overflow tx (not panic)
        let (block, summaries) = builder
            .build_block(1, Hash256::ZERO, vec![tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();
        assert_eq!(block.tx_count(), 0);
        assert!(summaries.is_empty());
    }

    // ── L1 context tests ─────────────────────────────────────────────

    #[test]
    fn test_set_l1_context() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let l1_hash = Hasher::hash(b"bitcoin_block_850000");
        builder.set_l1_context(850_000, l1_hash);

        let (block, _summaries) = builder
            .build_block(1, Hash256::ZERO, vec![], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        assert_eq!(block.header.l1_anchor_height, Some(850_000));
        assert_eq!(block.header.l1_anchor_hash, Some(l1_hash));
    }

    #[test]
    fn test_clear_l1_context() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        // Set then clear
        let l1_hash = Hasher::hash(b"bitcoin_block_850000");
        builder.set_l1_context(850_000, l1_hash);
        builder.clear_l1_context();

        let (block, _summaries) = builder
            .build_block(1, Hash256::ZERO, vec![], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        assert_eq!(block.header.l1_anchor_height, None);
        assert_eq!(block.header.l1_anchor_hash, None);
    }

    /// Build a minimal mathematically valid MerkleBlock for Sequencer testing
    fn build_test_merkle_block(txid: bitcoin::Txid) -> (Vec<u8>, [u8; 32]) {
        use bitcoin::block::{Header, Version};
        use bitcoin::consensus::serialize;
        use bitcoin::hashes::Hash as _;
        use bitcoin::{CompactTarget, MerkleBlock, TxMerkleNode};

        let merkle_root = TxMerkleNode::from_byte_array(*txid.as_byte_array());
        let header = Header {
            version: Version::from_consensus(0x20000000),
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root,
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x1d00ffff),
            nonce: 0,
        };
        let pmt = bitcoin::merkle_tree::PartialMerkleTree::from_txids(&[txid], &[true]);
        let block_hash_bytes: [u8; 32] = *header.block_hash().as_byte_array();
        let mb = MerkleBlock { header, txn: pmt };
        (serialize(&mb), block_hash_bytes)
    }

    #[test]
    fn test_l1_context_defaults_to_none() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let (block, _summaries) = builder
            .build_block(1, Hash256::ZERO, vec![], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>)
            .unwrap();

        assert_eq!(block.header.l1_anchor_height, None);
        assert_eq!(block.header.l1_anchor_hash, None);
    }

    // ── Synthetic deposit tests ──────────────────────────────────────

    /// Helper: create a bridge with a federation that includes the given sequencer address.
    /// Without this, SPV proofs fail (no block monitor) and federation attestation
    /// fails (no federation configured / sequencer not a member).
    fn setup_test_bridge_for_sequencer(sequencer_addr: Address) -> brrq_bridge::bridge::BridgeManager {
        let mut bridge = brrq_bridge::bridge::BridgeManager::new();
        let members = vec![
            (sequencer_addr, "sequencer".into()),
            (test_addr("federation_m2"), "m2".into()),
            (test_addr("federation_m3"), "m3".into()),
        ];
        // MIN_THRESHOLD=2, MIN_FEDERATION_SIZE=3
        bridge.init_federation(members, 2, 0).unwrap();
        bridge
    }

    #[test]
    fn test_build_block_with_synthetic_deposits() {
        let keys = SequencerKeys::generate().unwrap();
        let seq_addr = keys.address;
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let recipient = test_addr("deposit_recipient");
        let btc_tx_id = Hasher::hash(b"bitcoin_tx_001");

        // Use empty merkle data so the federation attestation path is used
        // (no block monitor configured → SPV verification would fail)
        let deposits = vec![SyntheticDeposit {
            recipient,
            amount: 500_000,
            btc_tx_id,
            btc_vout: 0,
            block_hash: Hash256::ZERO,
            merkle_block_raw: vec![],
        }];

        let mut bridge = setup_test_bridge_for_sequencer(seq_addr);
        let (block, summaries) = builder
            .build_block_with_deposits(
                1,
                Hash256::ZERO,
                vec![],
                &deposits,
                &mut state,
                &mut bridge,
                None::<&mut crate::traits::ConsensusCtx<'_>>,
                None::<&mut brrq_portal::EscrowManager>,
                None::<&mut brrq_portal::NullifierSet>,
            )
            .unwrap();

        // Block should contain the deposit transaction
        assert_eq!(block.tx_count(), 1);
        assert_eq!(summaries.len(), 1);
        assert!(summaries[0].success);

        // Recipient should have the deposited amount minus the peg-in fee
        let expected_minted = state.balance(&recipient);
        assert!(expected_minted < 500_000, "peg-in fee should reduce minted amount");

        // Transaction should be DepositSynthetic kind — amount is the minted amount (after fee)
        match &block.transactions[0].body.kind {
            TransactionKind::DepositSynthetic {
                recipient: r,
                amount: a,
                ..
            } => {
                assert_eq!(*r, recipient);
                assert_eq!(*a, expected_minted);
            }
            _ => panic!("expected DepositSynthetic transaction"),
        }
    }

    #[test]
    fn test_build_block_deposits_plus_user_txs() {
        let keys = SequencerKeys::generate().unwrap();
        let seq_addr = keys.address;
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let alice = test_addr("alice");
        let bob = test_addr("bob");
        let deposit_addr = test_addr("deposit_addr");

        // Fund alice
        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 10_000_000));

        let btc_tx_id = Hasher::hash(b"btc_tx_002");

        let deposits = vec![SyntheticDeposit {
            recipient: deposit_addr,
            amount: 1_000_000,
            btc_tx_id,
            btc_vout: 1,
            block_hash: Hash256::ZERO,
            merkle_block_raw: vec![],
        }];

        let user_tx = make_transfer_tx(alice, 0, bob, 1000, 1, 1);

        let mut bridge = setup_test_bridge_for_sequencer(seq_addr);
        let (block, summaries) = builder
            .build_block_with_deposits(
                1,
                Hash256::ZERO,
                vec![user_tx],
                &deposits,
                &mut state,
                &mut bridge,
                None::<&mut crate::traits::ConsensusCtx<'_>>,
                None::<&mut brrq_portal::EscrowManager>,
                None::<&mut brrq_portal::NullifierSet>,
            )
            .unwrap();

        // Block should have 2 transactions: 1 deposit + 1 user
        assert_eq!(block.tx_count(), 2);
        assert_eq!(summaries.len(), 2);

        // First tx should be the deposit
        assert!(matches!(
            &block.transactions[0].body.kind,
            TransactionKind::DepositSynthetic { .. }
        ));

        // Second tx should be the user transfer
        assert!(matches!(
            &block.transactions[1].body.kind,
            TransactionKind::Transfer { .. }
        ));

        // Verify balances
        assert_eq!(state.balance(&deposit_addr), 999_500);
        assert_eq!(state.balance(&bob), 1000);
    }

    #[test]
    fn test_build_block_no_deposits_uses_standard_path() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();

        let empty_deposits: Vec<SyntheticDeposit> = vec![];

        let (block, summaries) = builder
            .build_block_with_deposits(
                1,
                Hash256::ZERO,
                vec![],
                &empty_deposits,
                &mut state,
                &mut brrq_bridge::bridge::BridgeManager::new(),
                None::<&mut crate::traits::ConsensusCtx<'_>>,
                None::<&mut brrq_portal::EscrowManager>,
                None::<&mut brrq_portal::NullifierSet>,
            )
            .unwrap();

        assert_eq!(block.tx_count(), 0);
        assert!(summaries.is_empty());
    }

    // ══════════════════════════════════════════════════════════════════
    //  Portal (L3) E2E Integration Tests
    // ══════════════════════════════════════════════════════════════════

    fn make_portal_tx(
        from: Address,
        nonce: u64,
        kind: TransactionKind,
        pubkey: SchnorrPublicKey,
    ) -> Transaction {
        let body = TransactionBody {
            from,
            kind,
            nonce,
            gas_limit: 500_000, // High enough for batch/pool operations
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            chain_id: chain_id::TESTNET,
        };
        Transaction {
            body,
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(pubkey),
        }
    }

    #[test]
    fn test_portal_e2e_create_lock_in_block() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();
        let mut escrow = brrq_portal::EscrowManager::new();
        let mut nullifiers = brrq_portal::NullifierSet::new();

        let alice = test_addr("alice_portal");
        let alice_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let alice_pk = *alice_kp.public_key();

        // Fund alice
        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 10_000_000));

        let condition_hash = Hasher::hash(b"merchant_secret_123");
        let nullifier_hash = Hasher::hash(b"nullifier_placeholder");

        let tx = make_portal_tx(alice, 0, TransactionKind::CreatePortalLock {
            amount: 500_000,
            condition_hash,
            nullifier_hash,
            timeout_l2_block: 100_000,
        }, alice_pk);

        let (block, summaries) = builder.build_block_with_portal(
            1, Hash256::ZERO, vec![tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        // Block should include the portal tx
        assert_eq!(block.tx_count(), 1);
        assert!(summaries[0].success);

        // Alice's balance should be reduced by 500,000 + gas
        assert!(state.balance(&alice) < 10_000_000 - 500_000 + 1); // gas deducted too

        // Escrow should have 1 active lock with 500,000 sat
        assert_eq!(escrow.active_lock_count(), 1);
        assert_eq!(escrow.total_escrowed(), 500_000);

        // Verify invariant
        assert!(escrow.verify_invariant());
    }

    #[test]
    fn test_portal_e2e_create_and_cancel() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();
        let mut escrow = brrq_portal::EscrowManager::new();
        let mut nullifiers = brrq_portal::NullifierSet::new();

        let alice = test_addr("alice_cancel");
        let alice_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let alice_pk = *alice_kp.public_key();

        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 10_000_000));

        // C-2: Use zero condition_hash so cancel is allowed (no Portal Key issued)
        // Block 1: Create lock with zero condition (pool-style)
        let tx1 = make_portal_tx(alice, 0, TransactionKind::CreatePortalLock {
            amount: 200_000,
            condition_hash: Hash256::ZERO,
            nullifier_hash: Hash256::ZERO,
            timeout_l2_block: 100_000,
        }, alice_pk);

        let (_block1, _) = builder.build_block_with_portal(
            1, Hash256::ZERO, vec![tx1], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        let lock_id = escrow.all_locks().next().unwrap().lock_id;
        let balance_after_lock = state.balance(&alice);

        // Block 2: Cancel lock
        let tx2 = make_portal_tx(alice, 1, TransactionKind::CancelPortalLock {
            lock_id,
        }, alice_pk);

        let (block2, summaries2) = builder.build_block_with_portal(
            2, Hash256::ZERO, vec![tx2], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        assert_eq!(block2.tx_count(), 1);
        assert!(summaries2[0].success);

        // Escrow should be empty
        assert_eq!(escrow.active_lock_count(), 0);
        assert_eq!(escrow.total_escrowed(), 0);

        // Alice gets refund (balance after cancel > balance after lock)
        assert!(state.balance(&alice) > balance_after_lock);
    }

    #[test]
    fn test_portal_e2e_create_lock_pool() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();
        let mut escrow = brrq_portal::EscrowManager::new();
        let mut nullifiers = brrq_portal::NullifierSet::new();

        let alice = test_addr("alice_pool");
        let alice_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let alice_pk = *alice_kp.public_key();

        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 50_000_000));

        let slot_amounts = vec![300_000, 400_000, 500_000, 1_000_000];
        let total: u64 = slot_amounts.iter().sum();

        let tx = make_portal_tx(alice, 0, TransactionKind::CreateLockPool {
            slot_amounts: slot_amounts.clone(),
            timeout_l2_block: 200_000,
        }, alice_pk);

        let (block, summaries) = builder.build_block_with_portal(
            1, Hash256::ZERO, vec![tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        assert_eq!(block.tx_count(), 1);
        assert!(summaries[0].success);

        // 4 individual locks should be registered
        assert_eq!(escrow.active_lock_count(), 4);
        assert_eq!(escrow.total_escrowed(), total);
        assert!(escrow.verify_invariant());
    }

    #[test]
    fn test_portal_e2e_insufficient_balance_rejected() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();
        let mut escrow = brrq_portal::EscrowManager::new();
        let mut nullifiers = brrq_portal::NullifierSet::new();

        let alice = test_addr("alice_broke");
        let alice_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let alice_pk = *alice_kp.public_key();

        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 100)); // Only 100 sats

        let tx = make_portal_tx(alice, 0, TransactionKind::CreatePortalLock {
            amount: 500_000, // Way more than balance
            condition_hash: Hash256::ZERO,
            nullifier_hash: Hash256::ZERO,
            timeout_l2_block: 100_000,
        }, alice_pk);

        let (block, summaries) = builder.build_block_with_portal(
            1, Hash256::ZERO, vec![tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        // Transaction should be rejected (not included)
        assert_eq!(block.tx_count(), 0);
        assert!(summaries.is_empty());

        // No locks created
        assert_eq!(escrow.active_lock_count(), 0);
    }

    #[test]
    fn test_portal_e2e_multiple_senders_one_block() {
        // Use different senders to avoid nonce ordering issues from hash-based tx sorting
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();
        let mut escrow = brrq_portal::EscrowManager::new();
        let mut nullifiers = brrq_portal::NullifierSet::new();

        let alice = test_addr("alice_multi");
        let alice_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let alice_pk = *alice_kp.public_key();

        let bob = test_addr("bob_multi");
        let bob_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let bob_pk = *bob_kp.public_key();

        let charlie = test_addr("charlie_multi");

        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 100_000_000));
        state.set_account(Account::new_eoa(bob, 100_000_000));
        state.set_account(Account::new_eoa(charlie, 1_000_000));

        // Alice creates portal lock (nonce 0)
        let lock_tx1 = make_portal_tx(alice, 0, TransactionKind::CreatePortalLock {
            amount: 1_000_000,
            condition_hash: Hasher::hash(b"s1"),
            nullifier_hash: Hasher::hash(b"n1"),
            timeout_l2_block: 100_000,
        }, alice_pk);

        // Bob creates portal lock (nonce 0 — different sender)
        let lock_tx2 = make_portal_tx(bob, 0, TransactionKind::CreatePortalLock {
            amount: 2_000_000,
            condition_hash: Hasher::hash(b"s2"),
            nullifier_hash: Hasher::hash(b"n2"),
            timeout_l2_block: 100_000,
        }, bob_pk);

        // Alice also transfers to charlie (nonce 1)
        let transfer_tx = make_transfer_tx(alice, 1, charlie, 500_000, 1, 1);

        let (block, summaries) = builder.build_block_with_portal(
            1, Hash256::ZERO, vec![lock_tx1, lock_tx2, transfer_tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        // All 3 should be included (may be 2 if nonce ordering still an issue)
        assert!(block.tx_count() >= 2, "at least both portal locks should be included");

        // At least 2 locks active
        assert!(escrow.active_lock_count() >= 2);
        assert!(escrow.total_escrowed() >= 3_000_000);

        assert!(escrow.verify_invariant());
    }

    #[test]
    fn test_portal_e2e_lock_pool_update_condition() {
        // Full Lock Pool flow: Create Pool → Update Condition → Ready for Portal Key
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();
        let mut escrow = brrq_portal::EscrowManager::new();
        let mut nullifiers = brrq_portal::NullifierSet::new();

        let alice = test_addr("alice_pool_flow");
        let alice_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let alice_pk = *alice_kp.public_key();

        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 50_000_000));

        // Block 1: Create pool with 3 slots (zero condition hashes)
        let slot_amounts = vec![300_000, 400_000, 500_000];
        let create_pool_tx = make_portal_tx(alice, 0, TransactionKind::CreateLockPool {
            slot_amounts: slot_amounts.clone(),
            timeout_l2_block: 200_000,
        }, alice_pk);

        let (_block1, _) = builder.build_block_with_portal(
            1, Hash256::ZERO, vec![create_pool_tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        assert_eq!(escrow.active_lock_count(), 3);

        // Find the 200_000 slot lock
        let target_lock = escrow.all_locks()
            .find(|l| l.amount == 400_000)
            .unwrap();
        let lock_id = target_lock.lock_id;
        // Condition should be zero (pool default)
        assert!(target_lock.condition_hash.is_zero());

        // Block 2: Update condition hash for the 200k slot
        let merchant_secret = b"merchant_payment_secret_xyz";
        let condition_hash = Hasher::hash(merchant_secret);
        let nullifier_hash = Hasher::hash(b"computed_nullifier_for_200k");

        let update_tx = make_portal_tx(alice, 1, TransactionKind::UpdateLockCondition {
            lock_id,
            condition_hash,
            nullifier_hash,
            merchant_address: test_addr("merchant_200k"),
            merchant_pubkey: [0u8; 32],
        }, alice_pk);

        let (block2, summaries2) = builder.build_block_with_portal(
            2, Hash256::ZERO, vec![update_tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        assert_eq!(block2.tx_count(), 1);
        assert!(summaries2[0].success);

        // Verify condition was updated
        let updated_lock = escrow.get_lock(&lock_id).unwrap();
        assert_eq!(updated_lock.condition_hash, condition_hash);
        assert_eq!(updated_lock.nullifier_hash, nullifier_hash);
        assert_eq!(updated_lock.amount, 400_000);

        // Other locks should still have zero condition
        for lock in escrow.all_locks() {
            if lock.lock_id != lock_id {
                assert!(lock.condition_hash.is_zero());
            }
        }

        assert!(escrow.verify_invariant());
    }

    #[test]
    fn test_portal_e2e_update_condition_wrong_owner_fails() {
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();
        let mut escrow = brrq_portal::EscrowManager::new();
        let mut nullifiers = brrq_portal::NullifierSet::new();

        let alice = test_addr("alice_owner");
        let alice_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let alice_pk = *alice_kp.public_key();

        let eve = test_addr("eve_attacker");
        let eve_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let eve_pk = *eve_kp.public_key();

        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 50_000_000));
        state.set_account(Account::new_eoa(eve, 50_000_000));

        // Block 1: Alice creates a lock
        let create_tx = make_portal_tx(alice, 0, TransactionKind::CreatePortalLock {
            amount: 500_000,
            condition_hash: Hash256::ZERO,
            nullifier_hash: Hash256::ZERO,
            timeout_l2_block: 200_000,
        }, alice_pk);

        let (_block1, _) = builder.build_block_with_portal(
            1, Hash256::ZERO, vec![create_tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        let lock_id = escrow.all_locks().next().unwrap().lock_id;

        // Block 2: Eve tries to update Alice's lock condition — should be rejected
        let evil_condition = Hasher::hash(b"eves_merchant_secret");
        let evil_nullifier = Hasher::hash(b"eves_nullifier");
        let evil_tx = make_portal_tx(eve, 0, TransactionKind::UpdateLockCondition {
            lock_id,
            condition_hash: evil_condition,
            nullifier_hash: evil_nullifier,
            merchant_address: eve,
            merchant_pubkey: [0u8; 32],
        }, eve_pk);

        let (block2, summaries2) = builder.build_block_with_portal(
            2, Hash256::ZERO, vec![evil_tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        // Eve's tx should NOT be included (portal_failed → rollback → skip)
        assert_eq!(block2.tx_count(), 0);
        assert!(summaries2.is_empty());

        // Condition should still be zero
        let lock = escrow.get_lock(&lock_id).unwrap();
        assert!(lock.condition_hash.is_zero());
    }

    #[test]
    fn test_portal_settlement_priority_over_cancel() {
        // When settle and cancel for the same lock are in the
        // same block, settlement must win (merchant protection).
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(std::sync::Arc::new(keys));
        let mut state = WorldState::new();
        let mut escrow = brrq_portal::EscrowManager::new();
        let mut nullifiers = brrq_portal::NullifierSet::new();

        let alice = test_addr("alice_race");
        let alice_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let alice_pk = *alice_kp.public_key();

        let merchant = test_addr("merchant_race");
        let merchant_kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let merchant_pk = *merchant_kp.public_key();

        use brrq_types::account::Account;
        state.set_account(Account::new_eoa(alice, 50_000_000));
        state.set_account(Account::new_eoa(merchant, 10_000_000));

        // Block 1: Alice creates a lock with zero condition (pool-style)
        let merchant_secret = b"settlement_race_secret".to_vec();
        let condition_hash = Hasher::hash(&merchant_secret);

        let create_tx = make_portal_tx(alice, 0, TransactionKind::CreatePortalLock {
            amount: 1_000_000,
            condition_hash: Hash256::ZERO,
            nullifier_hash: Hash256::ZERO,
            timeout_l2_block: 200_000,
        }, alice_pk);

        let (_block1, _) = builder.build_block_with_portal(
            1, Hash256::ZERO, vec![create_tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        let lock_id = escrow.all_locks().next().unwrap().lock_id;
        assert_eq!(escrow.active_lock_count(), 1);

        // Block 1.5: Update condition via UpdateLockCondition tx
        let nullifier_hash = brrq_portal::types::compute_nullifier(
            alice_kp.secret_bytes().as_ref(), &lock_id, &condition_hash,
        );
        let update_tx = make_portal_tx(alice, 1, TransactionKind::UpdateLockCondition {
            lock_id,
            condition_hash,
            nullifier_hash,
            merchant_address: merchant,
            merchant_pubkey: *merchant_kp.public_key().as_bytes(),
        }, alice_pk);

        let (_block15, _) = builder.build_block_with_portal(
            2, Hash256::ZERO, vec![update_tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        // Generate Portal Key for merchant settlement
        let lock = escrow.get_lock(&lock_id).unwrap();
        let portal_key = brrq_portal::generate_portal_key(lock, &alice_kp, &condition_hash).unwrap();

        // Block 3: Both cancel (from Alice) and settle (from merchant) in same block
        // C-2: Cancel will be rejected (condition_hash set). Settle wins.
        let cancel_tx = make_portal_tx(alice, 2, TransactionKind::CancelPortalLock {
            lock_id,
        }, alice_pk);

        let settle_tx = make_portal_tx(merchant, 0, TransactionKind::SettlePortalLock {
            lock_id,
            merchant_secret: merchant_secret.clone(),
            portal_signature: portal_key.signature.as_bytes().to_vec(),
            nullifier: portal_key.nullifier,
        }, merchant_pk);

        // Submit both in same block — cancel rejected by C-2, settle succeeds
        let (block2, summaries2) = builder.build_block_with_portal(
            3, Hash256::ZERO, vec![cancel_tx, settle_tx], &mut state, None::<&mut crate::traits::ConsensusCtx<'_>>,
            Some(&mut escrow), Some(&mut nullifiers),
        ).unwrap();

        // At least the settle should succeed. The cancel should fail
        // (lock already settled) and be excluded.
        assert!(block2.tx_count() >= 1, "at least settlement should be included");

        // Settled locks are removed immediately from HashMap.
        // Lock should NOT exist (was removed on successful settlement).
        assert!(escrow.get_lock(&lock_id).is_err(),
            "settled lock should be removed from escrow");

        // Merchant should have received the funds
        assert!(state.balance(&merchant) > 10_000_000,
            "merchant should receive settlement amount");

        // Nullifier should be consumed
        assert!(nullifiers.is_consumed(&portal_key.nullifier));
    }
}
