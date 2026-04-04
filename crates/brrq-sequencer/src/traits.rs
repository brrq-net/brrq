//! Dependency decoupling traits for block_builder.
//!
//! ## Design
//!
//! These traits abstract the concrete portal, nullifier, and consensus
//! types so that block_builder depends on interfaces, not implementations.
//!
//! - [`PortalState`] — escrow lock management (wraps `EscrowManager`)
//! - [`NullifierStore`] — nullifier consumption tracking (wraps `NullifierSet`)
//! - [`ConsensusState`] — staking + slashing (wraps `StakingState` + `SlashingEngine`)

use brrq_consensus::slashing::{EquivocationProof, SlashResult, SlashingEngine, SlashingReason};
use brrq_consensus::staking::StakingState;
use brrq_crypto::hash::Hash256;
use brrq_crypto::schnorr::SchnorrPublicKey;
use brrq_portal::error::PortalError;
use brrq_portal::types::PortalLock;
use brrq_state::WorldState;
use brrq_types::address::Address;
use brrq_types::transaction::{Transaction, TransactionKind};

// ── PortalState ─────────────────────────────────────────────────────

/// Abstraction over portal escrow state.
///
/// Decouples block_builder from `brrq_portal::EscrowManager`.
pub trait PortalState {
    fn register_lock(
        &mut self,
        owner: Address,
        owner_pubkey: SchnorrPublicKey,
        amount: u64,
        condition_hash: Hash256,
        nullifier_hash: Hash256,
        timeout_l2_block: u64,
        current_block: u64,
    ) -> Result<Hash256, PortalError>;

    fn settle_lock(&mut self, lock_id: &Hash256) -> Result<u64, PortalError>;

    fn cancel_lock(&mut self, lock_id: &Hash256, sender: &Address, current_block: u64) -> Result<u64, PortalError>;

    fn get_lock(&self, lock_id: &Hash256) -> Result<&PortalLock, PortalError>;

    fn update_lock_condition_with_merchant(
        &mut self,
        caller: &Address,
        lock_id: &Hash256,
        condition_hash: Hash256,
        nullifier_hash: Hash256,
        merchant_address: Address,
        merchant_pubkey: SchnorrPublicKey,
    ) -> Result<(), PortalError>;

    fn active_lock_count(&self) -> usize;

    fn total_escrowed(&self) -> u64;

    fn to_bytes(&self) -> Result<Vec<u8>, String>;
}

impl PortalState for brrq_portal::EscrowManager {
    fn register_lock(
        &mut self,
        owner: Address,
        owner_pubkey: SchnorrPublicKey,
        amount: u64,
        condition_hash: Hash256,
        nullifier_hash: Hash256,
        timeout_l2_block: u64,
        current_block: u64,
    ) -> Result<Hash256, PortalError> {
        brrq_portal::EscrowManager::register_lock(
            self, owner, owner_pubkey, amount, condition_hash,
            nullifier_hash, timeout_l2_block, current_block,
        )
    }

    fn settle_lock(&mut self, lock_id: &Hash256) -> Result<u64, PortalError> {
        brrq_portal::EscrowManager::settle_lock(self, lock_id)
    }

    fn cancel_lock(&mut self, lock_id: &Hash256, sender: &Address, current_block: u64) -> Result<u64, PortalError> {
        brrq_portal::EscrowManager::cancel_lock(self, lock_id, sender, current_block)
    }

    fn get_lock(&self, lock_id: &Hash256) -> Result<&PortalLock, PortalError> {
        brrq_portal::EscrowManager::get_lock(self, lock_id)
    }

    fn update_lock_condition_with_merchant(
        &mut self,
        caller: &Address,
        lock_id: &Hash256,
        condition_hash: Hash256,
        nullifier_hash: Hash256,
        merchant_address: Address,
        merchant_pubkey: SchnorrPublicKey,
    ) -> Result<(), PortalError> {
        brrq_portal::EscrowManager::update_lock_condition_with_merchant(
            self, caller, lock_id, condition_hash, nullifier_hash, merchant_address, merchant_pubkey,
        )
    }

    fn active_lock_count(&self) -> usize {
        brrq_portal::EscrowManager::active_lock_count(self)
    }

    fn total_escrowed(&self) -> u64 {
        brrq_portal::EscrowManager::total_escrowed(self)
    }

    fn to_bytes(&self) -> Result<Vec<u8>, String> {
        brrq_portal::EscrowManager::to_bytes(self)
    }
}

// ── NullifierStore ──────────────────────────────────────────────────

/// Abstraction over nullifier set operations.
///
/// Decouples block_builder from `brrq_portal::NullifierSet`.
pub trait NullifierStore {
    fn is_consumed(&self, nullifier: &Hash256) -> bool;

    fn consume_with_expiry(&mut self, nullifier: &Hash256, expires_at: u64) -> bool;

    fn prune_expired(&mut self, current_height: u64) -> usize;

    fn merkle_root(&mut self) -> Hash256;
}

impl NullifierStore for brrq_portal::NullifierSet {
    fn is_consumed(&self, nullifier: &Hash256) -> bool {
        brrq_portal::NullifierSet::is_consumed(self, nullifier)
    }

    fn consume_with_expiry(&mut self, nullifier: &Hash256, expires_at: u64) -> bool {
        brrq_portal::NullifierSet::consume_with_expiry(self, nullifier, expires_at)
    }

    fn prune_expired(&mut self, current_height: u64) -> usize {
        brrq_portal::NullifierSet::prune_expired(self, current_height)
    }

    fn merkle_root(&mut self) -> Hash256 {
        brrq_portal::NullifierSet::merkle_root(self)
    }
}

// ── ConsensusState ──────────────────────────────────────────────────

/// Abstraction over staking and slashing operations.
///
/// Decouples block_builder from `StakingState` + `SlashingEngine`.
pub trait ConsensusState {
    /// Apply staking-related side effects for a transaction.
    /// Returns `true` if the staking operation failed and the tx should be rolled back.
    fn apply_staking(
        &mut self,
        tx: &Transaction,
        state: &mut WorldState,
        height: u64,
    ) -> bool;

    /// Execute slashing for a specific validator and reason.
    fn check_slashing(
        &mut self,
        validator: &Address,
        reason: SlashingReason,
        offense_context: &[u8],
        current_height: u64,
        evidence_height: u64,
    ) -> Result<SlashResult, brrq_consensus::ConsensusError>;
}

/// Concrete implementation wrapping `StakingState` + `SlashingEngine`.
///
/// Created at the call site (node.rs, sim_node.rs) from destructured fields
/// to satisfy the borrow checker.
pub struct ConsensusCtx<'a> {
    pub staking: &'a mut StakingState,
    pub slashing: &'a mut SlashingEngine,
}

impl<'a> ConsensusCtx<'a> {
    pub fn new(staking: &'a mut StakingState, slashing: &'a mut SlashingEngine) -> Self {
        Self { staking, slashing }
    }
}

impl ConsensusState for ConsensusCtx<'_> {
    fn apply_staking(
        &mut self,
        tx: &Transaction,
        state: &mut WorldState,
        height: u64,
    ) -> bool {
        let mut failed = false;
        match &tx.body.kind {
            TransactionKind::RegisterValidator { stake } => {
                if let Err(e) = self.staking.register_validator(*tx.sender(), *stake) {
                    tracing::warn!("Staking register failed: {e}, skipping tx");
                    failed = true;
                }
            }
            TransactionKind::AddStake { amount } => {
                if let Err(e) = self.staking.add_stake(tx.sender(), *amount) {
                    tracing::warn!("Staking add_stake failed: {e}, skipping tx");
                    failed = true;
                }
            }
            TransactionKind::BeginUnbonding => {
                if let Err(e) = self.staking.begin_unbonding(tx.sender(), height) {
                    tracing::warn!("Staking begin_unbonding failed: {e}, skipping tx");
                    failed = true;
                }
            }
            TransactionKind::FinishUnbonding => {
                match self.staking.finish_unbonding(tx.sender(), height) {
                    Ok(refund_amount) => {
                        let acct = state.get_or_create_account(*tx.sender());
                        acct.balance = acct.balance.saturating_add(refund_amount);
                        // flush account to persist unbonding refund
                        state.flush_account(tx.sender());
                    }
                    Err(e) => {
                        tracing::warn!("Staking finish_unbonding failed: {e}, skipping tx");
                        failed = true;
                    }
                }
            }
            TransactionKind::SubmitEquivocationProof {
                validator,
                height: proof_height,
                block_hash_a,
                block_hash_b,
                signature_a,
                signature_b,
                slh_dsa_pk,
            } => {
                let proof = EquivocationProof {
                    validator: *validator,
                    height: *proof_height,
                    block_hash_a: *block_hash_a,
                    block_hash_b: *block_hash_b,
                    signature_a: signature_a.clone(),
                    signature_b: signature_b.clone(),
                    slh_dsa_pk: slh_dsa_pk.clone(),
                };
                match SlashingEngine::verify_equivocation(&proof) {
                    Ok(true) => {
                        let mut offense_ctx = Vec::with_capacity(8 + 32 + 32);
                        offense_ctx.extend_from_slice(&proof_height.to_le_bytes());
                        offense_ctx.extend_from_slice(block_hash_a.as_bytes());
                        offense_ctx.extend_from_slice(block_hash_b.as_bytes());
                        match self.slashing.slash(
                            self.staking,
                            validator,
                            SlashingReason::Equivocation,
                            &offense_ctx,
                            height,
                            *proof_height,
                        ) {
                            Ok(slash_result) => {
                                let challenger = tx.sender();
                                let reward = slash_result.challenger_reward;
                                // Don't panic — log and skip if distribution is wrong
                                if reward + slash_result.burned + slash_result.community_fund
                                    != slash_result.total_slashed
                                {
                                    tracing::error!(
                                        "Slash distribution mismatch: {} + {} + {} != {}",
                                        reward, slash_result.burned, slash_result.community_fund,
                                        slash_result.total_slashed,
                                    );
                                    failed = true;
                                } else {
                                    let acct = state.get_or_create_account(*challenger);
                                    acct.balance = acct.balance.saturating_add(reward);
                                    state.flush_account(challenger);
                                    tracing::info!(
                                        "Equivocation slash: {} lost {}, challenger rewarded {}",
                                        validator,
                                        slash_result.total_slashed,
                                        reward
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Slash failed: {e}, skipping tx");
                                failed = true;
                            }
                        }
                    }
                    Ok(false) => {
                        tracing::warn!("Equivocation proof invalid, skipping tx");
                        failed = true;
                    }
                    Err(e) => {
                        tracing::warn!("Equivocation verification error: {e}, skipping tx");
                        failed = true;
                    }
                }
            }
            TransactionKind::L1ZklaAnchor {
                btc_block_hash: _,
                btc_tx_id,
                stark_proof,
                recovered_validators_bitmap,
            } => {
                tracing::info!(
                    "Processing U-ZKHR STARK recovery anchor from L1 tx {}",
                    btc_tx_id
                );
                if stark_proof.is_empty() {
                    tracing::warn!("L1ZklaAnchor STARK proof is empty, skipping");
                    failed = true;
                } else if let Ok(proof) =
                    brrq_prover::types::StarkProof::from_bytes(stark_proof)
                {
                    let current_root = state.state_root();
                    let proof_initial_root = proof.initial_state_root;

                    if proof_initial_root != current_root {
                        tracing::error!(
                            proof_root = %proof_initial_root,
                            current_root = %current_root,
                            "L1ZklaAnchor proof initial_state_root does not match \
                             current state — stale or replayed proof rejected"
                        );
                        failed = true;
                    }

                    if !failed {
                        match brrq_prover::verifier::StarkVerifier::verify(&proof) {
                            Ok(true) => {
                                tracing::info!(
                                    "L1ZklaAnchor STARK proof verified (root-fresh + crypto-valid)"
                                );
                            }
                            Ok(false) => {
                                tracing::error!("L1ZklaAnchor STARK proof verification FAILED — rejecting anchor");
                                failed = true;
                            }
                            Err(e) => {
                                tracing::error!(%e, "L1ZklaAnchor STARK proof verification error — rejecting anchor");
                                failed = true;
                            }
                        }
                    }
                } else {
                    tracing::error!(
                        "L1ZklaAnchor STARK proof deserialization failed — rejecting anchor"
                    );
                    failed = true;
                }
                if !failed {
                    let mut to_unbond = Vec::new();
                    for (i, (addr, validator)) in
                        self.staking.validators.iter().enumerate()
                    {
                        if validator.status
                            == brrq_consensus::validator::ValidatorStatus::Active
                            || validator.status
                                == brrq_consensus::validator::ValidatorStatus::Suspended
                        {
                            let byte_idx = i / 8;
                            let bit_idx = i % 8;
                            let is_recovered = recovered_validators_bitmap
                                .get(byte_idx)
                                .map(|b| b & (1 << bit_idx) != 0)
                                .unwrap_or(false);

                            if !is_recovered {
                                to_unbond.push(*addr);
                            }
                        }
                    }

                    for addr in to_unbond {
                        if let Some(v) = self.staking.validators.get_mut(&addr) {
                            v.force_unbond(height);
                            tracing::warn!(
                                "U-ZKHR: Forcibly unbonding offline validator {} to restore BFT quorum",
                                addr
                            );
                        }
                    }
                }
            }
            _ => {} // Non-staking transactions
        }
        failed
    }

    fn check_slashing(
        &mut self,
        validator: &Address,
        reason: SlashingReason,
        offense_context: &[u8],
        current_height: u64,
        evidence_height: u64,
    ) -> Result<SlashResult, brrq_consensus::ConsensusError> {
        self.slashing.slash(
            self.staking,
            validator,
            reason,
            offense_context,
            current_height,
            evidence_height,
        )
    }
}

// ── Settlement helpers (trait-based) ────────────────────────────────

/// Settle a single Portal Key using trait abstractions.
///
/// Mirrors `brrq_portal::settle_portal_key` but operates through traits
/// so block_builder doesn't depend on concrete portal types.
pub fn settle_portal_key_via_traits(
    escrow: &mut (impl PortalState + ?Sized),
    nullifiers: &mut (impl NullifierStore + ?Sized),
    claim: &brrq_portal::SettlementClaim,
    current_block: u64,
) -> Result<u64, brrq_portal::SettlementError> {
    let lock = escrow
        .get_lock(&claim.lock_id)
        .map_err(brrq_portal::SettlementError::Portal)?;

    // 1. Check expiration (with grace period)
    let effective_deadline = lock.timeout_l2_block.saturating_add(brrq_portal::types::SETTLEMENT_GRACE_BLOCKS);
    if current_block > effective_deadline {
        return Err(brrq_portal::SettlementError::Expired {
            timeout: lock.timeout_l2_block,
            current: current_block,
        });
    }

    // Enforce merchant_address binding
    if !lock.merchant_address.is_zero() && claim.merchant_address != lock.merchant_address {
        return Err(brrq_portal::SettlementError::Portal(
            PortalError::OwnerMismatch {
                lock_owner: format!("{}", lock.merchant_address),
                key_owner: format!("{}", claim.merchant_address),
            },
        ));
    }

    // Reject empty merchant secret
    if claim.merchant_secret.is_empty() {
        return Err(brrq_portal::SettlementError::InvalidSecret);
    }
    // Cap merchant_secret to 1KB
    if claim.merchant_secret.len() > 1024 {
        return Err(brrq_portal::SettlementError::InvalidSecret);
    }

    // Reject settlement if lock has no nullifier commitment
    if lock.nullifier_hash.is_zero() {
        return Err(brrq_portal::SettlementError::Portal(
            PortalError::LockNotActive(claim.lock_id)
        ));
    }

    // 2. Verify merchant secret: sha256(secret) must equal condition_hash
    let computed_condition = brrq_crypto::hash::Hasher::hash(&claim.merchant_secret);
    if computed_condition != lock.condition_hash {
        return Err(brrq_portal::SettlementError::InvalidSecret);
    }

    // 3. Verify signature over (lock_id || condition_hash || timeout)
    let payload = brrq_portal::types::compute_portal_key_payload(
        &lock.lock_id,
        &lock.condition_hash,
        lock.timeout_l2_block,
    );
    brrq_crypto::schnorr::verify(&lock.owner_pubkey, &payload, &claim.signature)
        .map_err(|_| brrq_portal::SettlementError::InvalidSignature)?;

    // 4. Verify nullifier matches lock's stored nullifier_hash
    if !lock.nullifier_hash.is_zero() && claim.nullifier != lock.nullifier_hash {
        return Err(brrq_portal::SettlementError::DoubleSpend);
    }

    // 5. Check nullifier not already consumed (read-only check first).
    if nullifiers.is_consumed(&claim.nullifier) {
        return Err(brrq_portal::SettlementError::DoubleSpend);
    }

    // 6. Settle lock BEFORE consuming nullifier.
    //    If settle_lock fails, nullifier remains unconsumed — no permanent damage.
    //    If settle_lock succeeds but consume fails (should never happen after is_consumed
    //    check above), the lock is settled but nullifier is not consumed — a benign state
    //    that the next settlement attempt will catch via "lock not Active".
    let amount = escrow
        .settle_lock(&claim.lock_id)
        .map_err(brrq_portal::SettlementError::Portal)?;

    // 7. Consume nullifier AFTER successful settlement.
    if !nullifiers.consume_with_expiry(&claim.nullifier, effective_deadline) {
        // Lock already settled above — this is a double-spend race that arrived
        // between is_consumed check and here. Lock settlement is idempotent
        // (already removed from registry), so this is safe.
        return Err(brrq_portal::SettlementError::DoubleSpend);
    }

    tracing::info!(
        lock_id = %claim.lock_id,
        merchant = %claim.merchant_address,
        amount = amount,
        "settlement completed (via traits)"
    );

    Ok(amount)
}

/// Batch settlement using trait abstractions.
///
/// Mirrors `brrq_portal::batch_settle` but operates through traits.
pub fn batch_settle_via_traits(
    escrow: &mut (impl PortalState + ?Sized),
    nullifiers: &mut (impl NullifierStore + ?Sized),
    claims: &[brrq_portal::SettlementClaim],
    current_block: u64,
) -> Result<brrq_portal::BatchResult, brrq_portal::SettlementError> {
    if claims.is_empty() {
        return Err(brrq_portal::SettlementError::Portal(PortalError::EmptyBatch));
    }
    if claims.len() > brrq_portal::MAX_BATCH_SIZE {
        return Err(brrq_portal::SettlementError::Portal(
            PortalError::BatchTooLarge {
                size: claims.len(),
                max: brrq_portal::MAX_BATCH_SIZE,
            },
        ));
    }

    let mut result = brrq_portal::BatchResult::default();

    for (i, claim) in claims.iter().enumerate() {
        match settle_portal_key_via_traits(escrow, nullifiers, claim, current_block) {
            Ok(amount) => {
                result.succeeded += 1;
                result.total_settled_amount = result.total_settled_amount.saturating_add(amount);
                result.settled_amounts.push((i, amount));
            }
            Err(e) => {
                let err_msg = e.to_string();
                tracing::warn!(
                    index = i,
                    lock_id = %claim.lock_id,
                    error = %err_msg,
                    "batch settlement: claim failed"
                );
                result.failed += 1;
                result.failed_indices.push(i);
                result.failed_details.push((i, err_msg));
            }
        }
    }

    tracing::info!(
        succeeded = result.succeeded,
        failed = result.failed,
        total = claims.len(),
        "batch settlement completed (via traits)"
    );

    Ok(result)
}
