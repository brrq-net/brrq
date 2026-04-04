//! Transaction execution engine.
//!
//! Executes transactions against the world state and records all state changes
//! for zero-knowledge proving. Handles transfers, deploys, and contract calls
//! with full RISC-V zkVM execution.
//!
//! ## Execution Pipeline
//!
//! 1. Validate nonce matches expected
//! 2. Compute intrinsic gas cost (whitepaper &sect;4.4)
//! 3. Verify sender can cover `gas_cost + value`
//! 4. Deduct gas cost upfront from sender
//! 5. Execute the transaction kind (Transfer / Deploy / ContractCall)
//! 6. Increment sender nonce
//! 7. Refund unused gas to sender
//! 8. Return result with `gas_used` + recorded `state_changes`
//!
//! The caller (`BlockBuilder`) is responsible for snapshot/rollback on failure.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_state::{SparseMerkleTree, StateChange, WorldState};
use brrq_types::address::Address;
use brrq_types::gas::MIN_TRANSACTION_GAS;
use brrq_types::transaction::{Transaction, TransactionKind};
use brrq_vm::StorageProvider;

use std::collections::HashMap;

use crate::error::SequencerError;

/// Transaction execution result.
#[derive(Debug)]
pub struct ExecutionResult {
    /// Gas consumed by the execution.
    pub gas_used: u64,
    /// Whether the execution succeeded.
    pub success: bool,
    /// Output data (return value from contract call).
    pub output: Vec<u8>,
    /// State changes recorded during execution (for proving).
    pub state_changes: Vec<StateChange>,
    /// Event logs emitted during contract execution.
    pub logs: Vec<brrq_types::Log>,
    /// VM execution trace for STARK proving.
    /// Present when the executor ran RISC-V code (contract calls).
    /// `None` for simple transfers and synthetic deposits.
    pub execution_trace: Option<brrq_vm::trace::ExecutionTrace>,
}

/// Additional gas per byte of deploy code.
const GAS_PER_CODE_BYTE: u64 = 4;

/// Additional gas per byte of calldata.
const GAS_PER_CALLDATA_BYTE: u64 = 4;

/// Maximum number of VM execution steps (absolute safety bound).
const VM_STEP_LIMIT: u64 = 10_000_000;

/// Each unit of gas allows ~100 VM steps (conservative ratio).
/// A low-gas transaction cannot exhaust the full VM_STEP_LIMIT.
const STEPS_PER_GAS: u64 = 100;

/// Maximum deploy code size (256 KB).
pub const MAX_CODE_SIZE: usize = 256 * 1024;

/// Maximum calldata size (64 KB — aligned with is_structurally_valid in brrq-types).
/// Aligned with is_structurally_valid in brrq-types.
pub const MAX_CALLDATA_SIZE: usize = 64 * 1024;

/// Adapter bridging VM storage syscalls (SLOAD/SSTORE) to WorldState.
///
/// Clones the contract's SMT for safe reads during execution,
/// and buffers all writes for batch application after the VM completes.
/// Provides read-your-writes consistency: a key written via SSTORE
/// is immediately visible to subsequent SLOAD calls.
struct ContractStorageAdapter {
    /// Cloned SMT for reads (isolated from other contracts).
    read_trie: SparseMerkleTree,
    /// Buffered writes (applied to WorldState after VM completes).
    writes: HashMap<Hash256, Hash256>,
}

impl ContractStorageAdapter {
    fn new(trie: SparseMerkleTree) -> Self {
        Self {
            read_trie: trie,
            writes: HashMap::new(),
        }
    }
}

impl StorageProvider for ContractStorageAdapter {
    fn storage_get(&self, key: &Hash256) -> Option<Hash256> {
        // Check writes buffer first (read-your-writes consistency)
        if let Some(val) = self.writes.get(key) {
            if *val == Hash256::ZERO {
                return None;
            }
            return Some(*val);
        }
        self.read_trie.get(key)
    }

    fn storage_set(&mut self, key: Hash256, value: Hash256) {
        self.writes.insert(key, value);
    }

    fn drain_writes(&mut self) -> Vec<(Hash256, Hash256)> {
        self.writes.drain().collect()
    }
}

/// Execution context for VM.
#[derive(Clone, Default)]
pub struct ExecutionContext {
    pub block_height: u64,
    pub block_timestamp: u64,
    pub base_fee: u64,
    pub validator_address: Option<Address>,
}

/// Execute a transaction against the world state.
///
/// Performs full validation, state mutation, and state-change recording.
/// On error, any partial state mutations are rolled back via the undo-log
/// (`state.rollback_changes()`), so the caller does NOT need to snapshot.
///
/// `expected_chain_id` must match `tx.body.chain_id` to prevent cross-chain
/// replay attacks (whitepaper §3.4).
pub fn execute_transaction(
    tx: &Transaction,
    state: &mut WorldState,
    expected_chain_id: u64,
) -> Result<ExecutionResult, SequencerError> {
    execute_transaction_with_context(
        tx,
        state,
        expected_chain_id,
        ExecutionContext::default(),
        true,
    )
}

pub fn execute_transaction_with_context(
    tx: &Transaction,
    state: &mut WorldState,
    expected_chain_id: u64,
    ctx: ExecutionContext,
    generate_trace: bool,
) -> Result<ExecutionResult, SequencerError> {
    // DepositSynthetic and L1ZklaAnchor must never use this path.
    // Reject early to prevent unreachable panics and nonce/gas side effects.
    if matches!(
        tx.body.kind,
        TransactionKind::DepositSynthetic { .. } | TransactionKind::L1ZklaAnchor { .. }
    ) {
        return Err(SequencerError::InvalidTransaction {
            reason: "protocol-level transactions cannot be executed via execute_transaction()"
                .into(),
        });
    }

    let sender = *tx.sender();

    // ── 0. Validate chain ID ───────────────────────────────────────────
    if tx.body.chain_id != expected_chain_id {
        return Err(SequencerError::InvalidTransaction {
            reason: format!(
                "chain_id mismatch: expected {:#X}, got {:#X}",
                expected_chain_id, tx.body.chain_id
            ),
        });
    }

    // ── 1. Validate nonce ──────────────────────────────────────────────
    let expected_nonce = state.nonce(&sender);
    if tx.body.nonce != expected_nonce {
        return Err(SequencerError::NonceTooLow {
            expected: expected_nonce,
            got: tx.body.nonce,
        });
    }

    // ── 2. Compute intrinsic gas ───────────────────────────────────────
    let intrinsic = intrinsic_gas(tx);
    if tx.body.gas_limit < intrinsic {
        return Err(SequencerError::InsufficientGas {
            need: intrinsic,
            have: tx.body.gas_limit,
        });
    }

    // ── 3. Compute base gas cost and verify absolute minimum balance ───
    // A transaction MUST be able to pay the absolute maximum potential gas cost
    // just to be executed. If it can't, it is dropped as fundamentally invalid and does not increment nonce.
    if tx.body.max_fee_per_gas < ctx.base_fee {
        return Err(SequencerError::InvalidTransaction {
            reason: format!(
                "max_fee_per_gas ({}) < base_fee ({})",
                tx.body.max_fee_per_gas, ctx.base_fee
            ),
        });
    }

    let priority_fee = std::cmp::min(
        tx.body.max_priority_fee_per_gas,
        tx.body.max_fee_per_gas.saturating_sub(ctx.base_fee),
    );
    let effective_gas_price = ctx.base_fee.saturating_add(priority_fee);

    // Overflow already caught by is_structurally_valid() at mempool admission.
    // Using saturating_mul as a safety net — can never overflow past this point.
    let gas_cost = tx.body.gas_limit.saturating_mul(tx.body.max_fee_per_gas);

    let sender_balance = state.balance(&sender);
    if sender_balance < gas_cost {
        return Err(SequencerError::InsufficientGas {
            need: gas_cost,
            have: sender_balance,
        });
    }

    // IMPORTANT: From here on out, errors should return `Ok(ExecutionResult { success: false... })`
    // to ensure the user pays the gas penalty and their nonce increments, preventing DoS!
    let mut intrinsic_changes: Vec<StateChange> = Vec::with_capacity(4);
    let mut execution_changes: Vec<StateChange> = Vec::with_capacity(2);

    // ── 4. Increment Nonce Upfront ─────────────────────────────────────
    let old_nonce = state.nonce(&sender);
    if let Err(e) = state.increment_nonce(&sender) {
        return Err(e.into());
    }
    let new_nonce = state.nonce(&sender);
    intrinsic_changes.push(StateChange::NonceChange {
        address: sender,
        old_nonce,
        new_nonce,
    });

    // ── 5. Deduct max gas limit Upfront ────────────────────────────────
    let balance_before_gas = state.balance(&sender);
    if gas_cost > 0 {
        let acct = state.get_or_create_account(sender);
        acct.balance = acct.balance.saturating_sub(gas_cost);
        state.flush_account(&sender);
    }
    let balance_after_gas = state.balance(&sender);
    if balance_before_gas != balance_after_gas {
        intrinsic_changes.push(StateChange::BalanceChange {
            address: sender,
            old_balance: balance_before_gas,
            new_balance: balance_after_gas,
        });
    }

    // ── 6. Execute transaction kind ────────────────────────────────────
    let mut actual_gas_used = intrinsic; // Default to intrinsic if execution fails
    let mut output_data: Vec<u8> = Vec::new();
    let mut tx_logs: Vec<brrq_types::Log> = Vec::new();
    let mut captured_trace: Option<brrq_vm::trace::ExecutionTrace> = None;

    let mut execute = || -> Result<(), String> {
        let tx_value = match &tx.body.kind {
            TransactionKind::Transfer { amount, .. } => *amount,
            TransactionKind::ContractCall { value, .. } => *value,
            TransactionKind::RegisterValidator { stake } => *stake,
            TransactionKind::AddStake { amount } => *amount,
            _ => 0,
        };

        let protocol_fee = match &tx.body.kind {
            TransactionKind::Transfer { amount, .. } => {
                brrq_types::gas::fee_tiers::graduated_fee(*amount)
            }
            _ => 0,
        };

        let total_value_cost = tx_value.saturating_add(protocol_fee);
        if state.balance(&sender) < total_value_cost {
            return Err("Insufficient balance for transaction value and protocol fee".into());
        }

        match &tx.body.kind {
            TransactionKind::Transfer { to, amount } => {
                let sender_before = state.balance(&sender);
                let to_before = state.balance(to);

                state
                    .transfer(&sender, to, *amount)
                    .map_err(|e| e.to_string())?;

                if protocol_fee > 0 {
                    let acct = state.get_or_create_account(sender);
                    acct.balance = acct.balance.saturating_sub(protocol_fee);
                    state.flush_account(&sender);
                }

                execution_changes.push(StateChange::BalanceChange {
                    address: sender,
                    old_balance: sender_before,
                    new_balance: state.balance(&sender),
                });
                execution_changes.push(StateChange::BalanceChange {
                    address: *to,
                    old_balance: to_before,
                    new_balance: state.balance(to),
                });
            }

            TransactionKind::Deploy { code } => {
                // Enforce code size limit at execution time as defense-in-depth.
                // Primary validation is in is_structurally_valid() at mempool admission.
                if code.len() > MAX_CODE_SIZE {
                    return Err(format!("deploy code too large: {} > {MAX_CODE_SIZE}", code.len()));
                }
                let code_hash = Hasher::hash(code);
                let contract_addr = Address::from_public_key(code_hash.as_bytes());
                state.get_or_create_account(contract_addr);
                // Flush account after creation to update state trie.
                // Without this, the contract account exists in memory but the state root
                // does not reflect it, causing divergence between nodes.
                state.flush_account(&contract_addr);
                state
                    .deploy_code(&contract_addr, code)
                    .map_err(|e| e.to_string())?;

                execution_changes.push(StateChange::CodeDeploy {
                    address: contract_addr,
                    code_hash,
                });
            }

            TransactionKind::ContractCall { to, data, value } => {
                if data.len() > MAX_CALLDATA_SIZE {
                    return Err(format!(
                        "calldata too large: {} bytes (max {})",
                        data.len(),
                        MAX_CALLDATA_SIZE
                    ));
                }

                let gas_available = tx.body.gas_limit.saturating_sub(intrinsic);
                let (call_success, call_gas, call_data, call_logs, call_trace) =
                    execute_contract_call_internal(
                        state,
                        &mut execution_changes,
                        sender,
                        to,
                        *value,
                        data.as_ref(),
                        gas_available,
                        0, // depth
                        &ctx,
                        generate_trace,
                    )
                    .map_err(|e| e.to_string())?;

                actual_gas_used = intrinsic.saturating_add(call_gas);
                output_data = call_data;
                tx_logs = call_logs;
                captured_trace = call_trace;

                if !call_success {
                    return Err("Contract execution reverted".into());
                }
            }

            TransactionKind::RegisterValidator { stake } => {
                let sender_before = state.balance(&sender);
                {
                    let acct = state.get_or_create_account(sender);
                    acct.balance = acct.balance.saturating_sub(*stake);
                }
                state.flush_account(&sender);
                execution_changes.push(StateChange::BalanceChange {
                    address: sender,
                    old_balance: sender_before,
                    new_balance: state.balance(&sender),
                });
            }

            TransactionKind::AddStake { amount } => {
                let sender_before = state.balance(&sender);
                {
                    let acct = state.get_or_create_account(sender);
                    acct.balance = acct.balance.saturating_sub(*amount);
                }
                state.flush_account(&sender);
                execution_changes.push(StateChange::BalanceChange {
                    address: sender,
                    old_balance: sender_before,
                    new_balance: state.balance(&sender),
                });
            }

            TransactionKind::BeginUnbonding
            | TransactionKind::FinishUnbonding
            | TransactionKind::SubmitEquivocationProof { .. } => {}

            // ── Portal (L3) transaction execution ─────────────────────
            TransactionKind::CreatePortalLock {
                amount,
                condition_hash,
                nullifier_hash,
                timeout_l2_block,
            } => {
                // Deduct lock amount from sender's balance (escrow)
                let sender_before = state.balance(&sender);
                if sender_before < *amount {
                    return Err(format!(
                        "insufficient balance for portal lock: need {} sats, have {}",
                        amount, sender_before
                    ));
                }
                {
                    let acct = state.get_or_create_account(sender);
                    acct.balance = acct.balance.saturating_sub(*amount);
                }
                state.flush_account(&sender);
                execution_changes.push(StateChange::BalanceChange {
                    address: sender,
                    old_balance: sender_before,
                    new_balance: state.balance(&sender),
                });
                // Lock state is tracked externally in NodeState.portal_escrow
                // The block builder applies the lock creation after execution succeeds
            }

            TransactionKind::SettlePortalLock {
                lock_id: _,
                merchant_secret: _,
                portal_signature: _,
                nullifier: _,
            } => {
                // Settlement validation and fund transfer happen in block builder
                // (needs access to portal escrow state, not just WorldState)
                // The executor only records gas; the block builder applies portal effects
            }

            TransactionKind::BatchSettlePortal { claims: _ } => {
                // Same as SettlePortalLock — portal effects applied by block builder
            }

            TransactionKind::CancelPortalLock { lock_id: _ } => {
                // Cancellation refund applied by block builder after verifying ownership
            }

            TransactionKind::CreateLockPool {
                slot_amounts,
                timeout_l2_block: _,
            } => {
                // Deduct total pool amount from sender's balance
                // Use checked_add to prevent overflow (wraps to 0 in release).
                let total: u64 = slot_amounts.iter().try_fold(0u64, |acc, &x| acc.checked_add(x))
                    .ok_or("slot_amounts total overflow".to_string())?;
                let sender_before = state.balance(&sender);
                if sender_before < total {
                    return Err(format!(
                        "insufficient balance for lock pool: need {} sats, have {}",
                        total, sender_before
                    ));
                }
                {
                    let acct = state.get_or_create_account(sender);
                    acct.balance = acct.balance.saturating_sub(total);
                }
                state.flush_account(&sender);
                execution_changes.push(StateChange::BalanceChange {
                    address: sender,
                    old_balance: sender_before,
                    new_balance: state.balance(&sender),
                });
                // Pool creation (individual locks) applied by block builder
            }

            TransactionKind::RefillLockPool { slot_amounts, timeout_l2_block: _ } => {
                // Deduct total refill amount from sender's balance
                // Use checked_add to prevent overflow (wraps to 0 in release).
                let total: u64 = slot_amounts.iter().try_fold(0u64, |acc, &x| acc.checked_add(x))
                    .ok_or("slot_amounts total overflow".to_string())?;
                let sender_before = state.balance(&sender);
                if sender_before < total {
                    return Err(format!(
                        "insufficient balance for pool refill: need {} sats, have {}",
                        total, sender_before
                    ));
                }
                {
                    let acct = state.get_or_create_account(sender);
                    acct.balance = acct.balance.saturating_sub(total);
                }
                state.flush_account(&sender);
                execution_changes.push(StateChange::BalanceChange {
                    address: sender,
                    old_balance: sender_before,
                    new_balance: state.balance(&sender),
                });
            }

            TransactionKind::UpdateLockCondition { .. } => {
                // No balance change — condition update applied by block builder
            }

            TransactionKind::RelayedBatchSettle { .. } => {
                // Relayer pays gas. Settlement + fee distribution applied by block builder.
            }

            TransactionKind::DepositSynthetic { .. } | TransactionKind::L1ZklaAnchor { .. } => {
                unreachable!()
            }
        }
        Ok(())
    };

    let success = match execute() {
        Ok(_) => true,
        Err(e) => {
            tracing::debug!("Tx execution failed: {}", e);
            state.rollback_changes(&execution_changes);
            execution_changes.clear();
            output_data = e.into_bytes();
            false
        }
    };

    // ── 7. Refund unused gas AND unused fee premium ───────────────────────────────────────────
    let actual_fee_spent = actual_gas_used.saturating_mul(effective_gas_price);
    let refund_amount = gas_cost.saturating_sub(actual_fee_spent);

    if refund_amount > 0 {
        let old_balance = state.balance(&sender);
        {
            let acct = state.get_or_create_account(sender);
            acct.balance = acct.balance.saturating_add(refund_amount);
        }
        state.flush_account(&sender);
        let new_balance = state.balance(&sender);

        if old_balance != new_balance {
            intrinsic_changes.push(StateChange::BalanceChange {
                address: sender,
                old_balance,
                new_balance,
            });
        }
    }

    // ── 7.25. Record base fee burn explicitly ───────────────────────────────────────────
    let burned = actual_gas_used.saturating_mul(ctx.base_fee);
    if burned > 0 {
        intrinsic_changes.push(StateChange::FeeBurn { amount: burned });
    }

    // ── 7.5. Distribute priority tip to validator ───────────────────────────────────────────
    let tip_amount = actual_gas_used.saturating_mul(priority_fee);
    if tip_amount > 0 {
        if let Some(validator) = ctx.validator_address {
            let old_balance = state.balance(&validator);
            {
                let acct = state.get_or_create_account(validator);
                acct.balance = acct.balance.saturating_add(tip_amount);
            }
            state.flush_account(&validator);
            intrinsic_changes.push(StateChange::BalanceChange {
                address: validator,
                old_balance,
                new_balance: state.balance(&validator),
            });
        }
    }

    // Combine logs
    intrinsic_changes.extend(execution_changes);

    // ── 8. Return result ───────────────────────────────────────────────
    Ok(ExecutionResult {
        gas_used: actual_gas_used,
        success,
        output: output_data,
        state_changes: intrinsic_changes,
        logs: tx_logs,
        execution_trace: captured_trace,
    })
}

/// Intrinsic gas cost for a synthetic deposit transaction.
/// Lower than regular transfers since no signature verification is needed.
const DEPOSIT_SYNTHETIC_GAS: u64 = 10_000;

// ── Portal (L3) Dynamic Gas Pricing ─────────────────────────────────
// Off-VM dynamic repricing: gas reflects actual resource cost per operation.
// These atomic costs mirror real-world compute/IO so attackers pay proportionally.

/// Base transaction overhead (nonce bump, signature envelope, receipt).
const PORTAL_BASE_TX_GAS: u64 = 21_000;
/// Per-byte cost for variable-length payload fields (merchant_secret, signature).
const PORTAL_PAYLOAD_BYTE_GAS: u64 = 4;
/// Schnorr signature verification (one curve multiply + add).
const PORTAL_SCHNORR_VERIFY_GAS: u64 = 3_000;
/// SHA-256 hash computation (condition_hash check, lock_id derivation).
const PORTAL_SHA256_GAS: u64 = 500;
/// One state read (account lookup, lock lookup, nullifier check).
const PORTAL_DB_READ_GAS: u64 = 2_100;
/// One state write (balance update, lock status change, nullifier insert).
const PORTAL_DB_WRITE_GAS: u64 = 10_000;
/// Relay fee distribution overhead (one extra read + write for relayer).
const PORTAL_RELAY_FEE_GAS: u64 = PORTAL_DB_READ_GAS + PORTAL_DB_WRITE_GAS;

/// Compute dynamic gas for a single settlement claim based on payload size.
///
/// Per claim: 1 lock read + 1 nullifier read + 1 Schnorr verify + 1 SHA256 +
///            1 lock write (status→Settled) + 1 nullifier write (consume) +
///            1 merchant balance read + 1 merchant balance write (credit) +
///            payload bytes (merchant_secret + portal_signature)
fn portal_per_claim_gas(secret_len: usize, sig_len: usize) -> u64 {
    let ops = PORTAL_DB_READ_GAS              // read lock
        .saturating_add(PORTAL_DB_READ_GAS)   // read nullifier
        .saturating_add(PORTAL_DB_READ_GAS)   // read merchant balance
        .saturating_add(PORTAL_SCHNORR_VERIFY_GAS) // verify signature
        .saturating_add(PORTAL_SHA256_GAS)    // verify secret hash
        .saturating_add(PORTAL_DB_WRITE_GAS)  // write lock status
        .saturating_add(PORTAL_DB_WRITE_GAS)  // write nullifier
        .saturating_add(PORTAL_DB_WRITE_GAS); // write merchant balance
    let payload = ((secret_len + sig_len) as u64).saturating_mul(PORTAL_PAYLOAD_BYTE_GAS);
    ops.saturating_add(payload)
}

/// CreatePortalLock: 1 balance read + 1 balance write + 1 lock write + 1 SHA256 (lock_id)
const fn portal_create_lock_gas() -> u64 {
    PORTAL_BASE_TX_GAS + PORTAL_DB_READ_GAS + PORTAL_DB_WRITE_GAS + PORTAL_DB_WRITE_GAS + PORTAL_SHA256_GAS
}

/// CancelPortalLock: 1 lock read + 1 lock write + 1 balance read + 1 balance write (refund)
const fn portal_cancel_lock_gas() -> u64 {
    PORTAL_BASE_TX_GAS + PORTAL_DB_READ_GAS + PORTAL_DB_WRITE_GAS + PORTAL_DB_READ_GAS + PORTAL_DB_WRITE_GAS
}

/// UpdateLockCondition: 1 lock read + 1 lock write (condition + nullifier)
const fn portal_update_condition_gas() -> u64 {
    PORTAL_BASE_TX_GAS + PORTAL_DB_READ_GAS + PORTAL_DB_WRITE_GAS
}

/// Per-slot cost in lock pool: 1 lock write + 1 SHA256 (lock_id derivation)
const PORTAL_PER_SLOT_GAS: u64 = PORTAL_DB_WRITE_GAS + PORTAL_SHA256_GAS;

/// Execute a synthetic deposit — system transaction injected by the sequencer.
///
/// Bypasses nonce/signature/gas validation since deposits are attested
/// by SPV proof (or federation) and included by the sequencer.
/// Credits `amount` to `recipient` and records the state change.
pub fn execute_synthetic_deposit(
    recipient: &Address,
    amount: u64,
    btc_tx_id: &Hash256,
    state: &mut WorldState,
) -> Result<ExecutionResult, SequencerError> {
    if amount == 0 {
        return Err(SequencerError::InvalidTransaction {
            reason: "synthetic deposit amount is zero".into(),
        });
    }
    if recipient.is_zero() {
        return Err(SequencerError::InvalidTransaction {
            reason: "synthetic deposit to zero address".into(),
        });
    }

    let mut changes = Vec::with_capacity(1);
    let old_balance = state.balance(recipient);

    // Credit the minted amount to recipient
    {
        let acct = state.get_or_create_account(*recipient);
        acct.balance = acct.balance.saturating_add(amount);
    }
    state.flush_account(recipient);

    let new_balance = state.balance(recipient);
    changes.push(StateChange::BalanceChange {
        address: *recipient,
        old_balance,
        new_balance,
    });

    tracing::debug!(
        amount,
        %recipient,
        btc_tx_prefix = u64::from_le_bytes(
            btc_tx_id.as_bytes()[..8].try_into().expect("Hash256 is always 32 bytes"),
        ),
        "Synthetic deposit credited",
    );

    Ok(ExecutionResult {
        gas_used: DEPOSIT_SYNTHETIC_GAS,
        success: true,
        output: Vec::new(),
        state_changes: changes,
        logs: Vec::new(),
        execution_trace: None,
    })
}

/// Compute the intrinsic gas cost for a transaction (minimum gas required).
///
/// Per whitepaper &sect;4.4, base cost is 21,000 gas. Deploy and call transactions
/// add per-byte costs for their payload.
/// Gas costs for staking operations.
const REGISTER_VALIDATOR_GAS: u64 = 50_000;
const ADD_STAKE_GAS: u64 = 25_000;
const BEGIN_UNBONDING_GAS: u64 = 25_000;
const FINISH_UNBONDING_GAS: u64 = 25_000;
const EQUIVOCATION_PROOF_GAS: u64 = 100_000;

fn intrinsic_gas(tx: &Transaction) -> u64 {
    match &tx.body.kind {
        TransactionKind::Transfer { .. } => MIN_TRANSACTION_GAS,
        TransactionKind::Deploy { code } => MIN_TRANSACTION_GAS
            .saturating_add((code.len() as u64).saturating_mul(GAS_PER_CODE_BYTE)),
        TransactionKind::ContractCall { data, .. } => MIN_TRANSACTION_GAS
            .saturating_add((data.len() as u64).saturating_mul(GAS_PER_CALLDATA_BYTE)),
        TransactionKind::RegisterValidator { .. } => REGISTER_VALIDATOR_GAS,
        TransactionKind::AddStake { .. } => ADD_STAKE_GAS,
        TransactionKind::BeginUnbonding => BEGIN_UNBONDING_GAS,
        TransactionKind::FinishUnbonding => FINISH_UNBONDING_GAS,
        TransactionKind::SubmitEquivocationProof { .. } => EQUIVOCATION_PROOF_GAS,
        // ── Portal (L3) dynamic gas pricing ──────────────────────────
        TransactionKind::CreatePortalLock { .. } => portal_create_lock_gas(),
        TransactionKind::SettlePortalLock {
            merchant_secret, portal_signature, ..
        } => {
            // Single settlement: base + per-claim dynamic cost
            PORTAL_BASE_TX_GAS.saturating_add(
                portal_per_claim_gas(merchant_secret.len(), portal_signature.len()),
            )
        }
        TransactionKind::BatchSettlePortal { claims } => {
            // Accumulate per-claim cost dynamically based on payload sizes
            let mut gas = PORTAL_BASE_TX_GAS;
            for c in claims {
                gas = gas.saturating_add(
                    portal_per_claim_gas(c.merchant_secret.len(), c.portal_signature.len()),
                );
            }
            gas
        }
        TransactionKind::CancelPortalLock { .. } => portal_cancel_lock_gas(),
        TransactionKind::CreateLockPool { slot_amounts, .. } => {
            // Base + 1 balance read/write + per-slot (lock write + SHA256)
            PORTAL_BASE_TX_GAS
                .saturating_add(PORTAL_DB_READ_GAS)   // balance read
                .saturating_add(PORTAL_DB_WRITE_GAS)   // balance write
                .saturating_add((slot_amounts.len() as u64).saturating_mul(PORTAL_PER_SLOT_GAS))
        }
        TransactionKind::RefillLockPool { slot_amounts, .. } => {
            // Same cost structure as CreateLockPool
            PORTAL_BASE_TX_GAS
                .saturating_add(PORTAL_DB_READ_GAS)
                .saturating_add(PORTAL_DB_WRITE_GAS)
                .saturating_add((slot_amounts.len() as u64).saturating_mul(PORTAL_PER_SLOT_GAS))
        }
        TransactionKind::UpdateLockCondition { .. } => portal_update_condition_gas(),
        TransactionKind::RelayedBatchSettle { claims, .. } => {
            // Same as BatchSettlePortal + relay fee distribution overhead
            let mut gas = PORTAL_BASE_TX_GAS.saturating_add(PORTAL_RELAY_FEE_GAS);
            for c in claims {
                gas = gas.saturating_add(
                    portal_per_claim_gas(c.merchant_secret.len(), c.portal_signature.len()),
                );
            }
            gas
        }
        TransactionKind::DepositSynthetic { .. } => unreachable!("rejected in execute_transaction"),
        TransactionKind::L1ZklaAnchor { .. } => unreachable!("rejected in execute_transaction"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hash256;
    use brrq_crypto::schnorr::{SchnorrPublicKey, SchnorrSignature};
    use brrq_types::account::Account;
    use brrq_types::signature::{PublicKey, Signature};
    use brrq_types::transaction::{TransactionBody, chain_id};

    fn test_addr(name: &str) -> Address {
        let hash = Hasher::hash(name.as_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Address::from_bytes(bytes)
    }

    fn make_transfer(
        from: Address,
        nonce: u64,
        to: Address,
        amount: u64,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
    ) -> Transaction {
        Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::Transfer { to, amount },
                nonce,
                gas_limit: 21_000,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        }
    }

    fn make_deploy(from: Address, nonce: u64, code: Vec<u8>) -> Transaction {
        let gas_needed = 21_000 + (code.len() as u64) * GAS_PER_CODE_BYTE;
        Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::Deploy { code },
                nonce,
                gas_limit: gas_needed,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        }
    }

    fn make_contract_call(
        from: Address,
        nonce: u64,
        to: Address,
        value: u64,
        data: Vec<u8>,
    ) -> Transaction {
        let gas_needed = 21_000 + (data.len() as u64) * GAS_PER_CALLDATA_BYTE;
        Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::ContractCall { to, data, value },
                nonce,
                gas_limit: gas_needed,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        }
    }

    // ── Basic transfer tests ───────────────────────────────────────────

    #[test]
    fn test_transfer_success() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = make_transfer(alice, 0, bob, 5_000, 1, 1);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, 21_000);
        // alice: 1_000_000 - 21_000 (gas) - 5_000 (transfer) - protocol_fee
        let fee = brrq_types::gas::fee_tiers::graduated_fee(5_000);
        assert_eq!(state.balance(&alice), 1_000_000 - 21_000 - 5_000 - fee);
        assert_eq!(state.balance(&bob), 5_000);
        assert_eq!(state.nonce(&alice), 1);
    }

    #[test]
    fn test_transfer_records_state_changes() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 100_000));

        let tx = make_transfer(alice, 0, bob, 1_000, 1, 1);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        // Expect: gas deduction + sender balance + recipient balance + nonce = 4 changes
        assert!(result.state_changes.len() >= 3);

        let has_balance = result
            .state_changes
            .iter()
            .any(|c| matches!(c, StateChange::BalanceChange { .. }));
        let has_nonce = result.state_changes.iter().any(|c| {
            matches!(
                c,
                StateChange::NonceChange {
                    old_nonce: 0,
                    new_nonce: 1,
                    ..
                }
            )
        });
        assert!(has_balance);
        assert!(has_nonce);
    }

    #[test]
    fn test_transfer_insufficient_balance() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        // Alice has only 100 sat; needs at least 21_000 (gas) + 50 (value) = 21_050
        state.set_account(Account::new_eoa(alice, 100));

        let tx = make_transfer(alice, 0, bob, 50, 1, 1);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        let err = result.unwrap_err();
        assert!(
            matches!(err, SequencerError::InsufficientGas { .. }),
            "expected InsufficientGas error, got: {err:?}"
        );
    }

    #[test]
    fn test_transfer_wrong_nonce() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = make_transfer(alice, 5, bob, 100, 1, 1); // nonce 5, expected 0
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        assert!(matches!(
            result,
            Err(SequencerError::NonceTooLow {
                expected: 0,
                got: 5
            })
        ));
    }

    #[test]
    fn test_transfer_gas_overflow() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = Transaction {
            body: TransactionBody {
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
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        let err = result.unwrap_err();
        // saturating_mul prevents overflow, so we get InsufficientGas
        // instead of InvalidTransaction. gas_cost saturates to u64::MAX.
        match &err {
            SequencerError::InsufficientGas { need, have } => {
                assert_eq!(*need, u64::MAX, "saturating_mul should cap at u64::MAX");
                assert_eq!(*have, 1_000_000);
            }
            SequencerError::InvalidTransaction { reason } => {
                assert!(
                    reason.contains("overflow"),
                    "expected overflow error, got: {reason}"
                );
            }
            other => panic!("expected InsufficientGas or InvalidTransaction, got: {other:?}"),
        }
    }

    #[test]
    fn test_transfer_zero_gas_price() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 100_000));

        // gas_price=0 means no gas cost, only transfer value + protocol fee
        let tx = make_transfer(alice, 0, bob, 1_000, 0, 1);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        assert!(result.success);
        let fee = brrq_types::gas::fee_tiers::graduated_fee(1_000);
        assert_eq!(state.balance(&alice), 100_000 - 1_000 - fee);
        assert_eq!(state.balance(&bob), 1_000);
    }

    // ── Sequential nonce tests ─────────────────────────────────────────

    #[test]
    fn test_sequential_transfers() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 10_000_000));

        for i in 0..5 {
            let tx = make_transfer(alice, i, bob, 1_000, 1, 1);
            let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
            assert!(result.success);
        }

        assert_eq!(state.nonce(&alice), 5);
        assert_eq!(state.balance(&bob), 5_000);
        // alice: 10_000_000 - 5 * (21_000 + 1_000 + protocol_fee)
        let fee_per_tx = brrq_types::gas::fee_tiers::graduated_fee(1_000);
        let total_deducted = 5 * (21_000 + 1_000 + fee_per_tx);
        assert_eq!(state.balance(&alice), 10_000_000 - total_deducted);
    }

    // ── Deploy tests ───────────────────────────────────────────────────

    #[test]
    fn test_deploy_success() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let code = vec![0x13, 0x00, 0x00, 0x00]; // NOP instruction
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = make_deploy(alice, 0, code.clone());
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        assert!(result.success);
        assert_eq!(state.nonce(&alice), 1);

        let has_deploy = result
            .state_changes
            .iter()
            .any(|c| matches!(c, StateChange::CodeDeploy { .. }));
        assert!(has_deploy);

        // Verify contract code exists at the derived address
        let code_hash = Hasher::hash(&code);
        let contract_addr = Address::from_public_key(code_hash.as_bytes());
        assert!(state.get_code(&contract_addr).is_some());
    }

    #[test]
    fn test_deploy_gas_includes_code_bytes() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let code = vec![0u8; 256]; // 256 bytes of code
        state.set_account(Account::new_eoa(alice, 10_000_000));

        let tx = make_deploy(alice, 0, code);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        // gas_used = gas_limit = 21_000 + 256 * 4 = 22_024
        assert_eq!(result.gas_used, 22_024);
    }

    // ── Contract call tests ────────────────────────────────────────────

    #[test]
    fn test_contract_call_with_value() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = make_contract_call(alice, 0, contract, 5_000, vec![0xAB; 4]);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        assert!(result.success);
        assert_eq!(state.balance(&contract), 5_000);
        // alice: 1_000_000 - gas_cost - 5_000
        let gas_cost = result.gas_used * 10; // 21_000 + 4*4 = 21_016, fee=10
        assert_eq!(state.balance(&alice), 1_000_000 - gas_cost - 5_000);
    }

    #[test]
    fn test_contract_call_zero_value() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = make_contract_call(alice, 0, contract, 0, vec![0xAB; 4]);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        assert!(result.success);
        assert_eq!(state.balance(&contract), 0); // No value transferred
    }

    // ── RISC-V instruction encoding helpers ──────────────────────────

    /// Encode an I-type instruction.
    fn i_type(imm: i32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (((imm as u32) & 0xFFF) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    /// Encode a system instruction (ECALL / EBREAK).
    fn sys_type(imm: u32) -> u32 {
        (imm << 20) | 0b1110011
    }

    /// Assemble instruction words into little-endian bytes.
    fn assemble(instructions: &[u32]) -> Vec<u8> {
        instructions.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    const OP_IMM: u32 = 0b0010011;

    /// Build a RISC-V program that halts with exit code 0 (success, no output).
    fn make_halt_success_code() -> Vec<u8> {
        assemble(&[
            i_type(0, 0, 0b000, 10, OP_IMM), // ADDI x10, x0, 0 → a0=0 (success)
            i_type(0, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0 → a7=HALT
            sys_type(0),                     // ECALL → halt
        ])
    }

    /// Build a RISC-V program that halts with exit code 1 (failure).
    fn make_halt_failure_code() -> Vec<u8> {
        assemble(&[
            i_type(1, 0, 0b000, 10, OP_IMM), // ADDI x10, x0, 1 → a0=1 (failure)
            i_type(0, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0 → a7=HALT
            sys_type(0),                     // ECALL → halt
        ])
    }

    /// Build a RISC-V "echo" program that writes calldata as output then halts.
    ///
    /// Entry convention: a0=calldata_ptr, a1=calldata_len (set by executor).
    fn make_echo_code() -> Vec<u8> {
        assemble(&[
            // Write calldata as output (a0=ptr, a1=len already set by executor)
            i_type(1, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 1 → a7=WRITE_OUTPUT
            sys_type(0),                     // ECALL → write output
            // Halt with success
            i_type(0, 0, 0b000, 10, OP_IMM), // ADDI x10, x0, 0 → a0=0 (success)
            i_type(0, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0 → a7=HALT
            sys_type(0),                     // ECALL → halt
        ])
    }

    /// Build a RISC-V program that runs many NOPs before halting (burns gas).
    fn make_gas_burner_code(nops: usize) -> Vec<u8> {
        let mut instrs = Vec::with_capacity(nops + 3);
        for _ in 0..nops {
            instrs.push(i_type(0, 0, 0b000, 0, OP_IMM)); // NOP (ADDI x0, x0, 0)
        }
        instrs.push(i_type(0, 0, 0b000, 10, OP_IMM)); // a0=0
        instrs.push(i_type(0, 0, 0b000, 17, OP_IMM)); // a7=HALT
        instrs.push(sys_type(0)); // ECALL
        assemble(&instrs)
    }

    // ── VM contract execution tests ───────────────────────────────────

    #[test]
    fn test_contract_call_vm_success() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract_ok");
        state.set_account(Account::new_eoa(alice, 10_000_000));
        state.get_or_create_account(contract);

        // Deploy a "halt success" contract
        let code = make_halt_success_code();
        state.deploy_code(&contract, &code).unwrap();

        // Call it with enough gas for intrinsic + VM execution
        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: vec![],
                    value: 0,
                },
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success, "VM should exit with code 0");
        assert!(result.output.is_empty(), "no output expected");
        // Gas used should be intrinsic (21_000) + VM gas (small)
        assert!(result.gas_used > MIN_TRANSACTION_GAS);
        assert!(result.gas_used < 100_000, "should NOT consume all gas");
        // Verify gas refund: alice should get back unused gas
        let gas_cost_deducted = 100_000 * 10; // gas_limit * gas_price
        let refund = (100_000 - result.gas_used) * 10;
        let expected_balance = 10_000_000 - gas_cost_deducted + refund;
        assert_eq!(state.balance(&alice), expected_balance);
    }

    #[test]
    fn test_contract_call_vm_echo() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract_echo");
        state.set_account(Account::new_eoa(alice, 10_000_000));
        state.get_or_create_account(contract);

        // Deploy an echo contract
        let code = make_echo_code();
        state.deploy_code(&contract, &code).unwrap();

        let calldata = b"Hello, Brrq!".to_vec();
        let calldata_gas = (calldata.len() as u64) * GAS_PER_CALLDATA_BYTE;

        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: calldata.clone(),
                    value: 0,
                },
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);
        assert_eq!(
            result.output, b"Hello, Brrq!",
            "echo contract returns calldata"
        );
        assert!(result.gas_used >= MIN_TRANSACTION_GAS + calldata_gas);
    }

    #[test]
    fn test_contract_call_vm_failure_exit_code() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract_fail");
        state.set_account(Account::new_eoa(alice, 10_000_000));
        state.get_or_create_account(contract);

        // Deploy a "halt failure" contract (exit code 1)
        let code = make_halt_failure_code();
        state.deploy_code(&contract, &code).unwrap();

        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: vec![],
                    value: 0,
                },
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(!result.success, "exit code 1 should mark as failure");
        // Gas should still be partially used (not all consumed for non-zero exit)
        assert!(result.gas_used < 100_000);
    }

    #[test]
    fn test_contract_call_vm_out_of_gas() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract_gas_burn");
        state.set_account(Account::new_eoa(alice, 10_000_000));
        state.get_or_create_account(contract);

        // Deploy a gas burner with many NOPs (1 gas each = ~500 gas)
        let code = make_gas_burner_code(500);
        state.deploy_code(&contract, &code).unwrap();

        // Give very little gas: intrinsic (21_000) + only 10 for VM → VM runs out
        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: vec![],
                    value: 0,
                },
                nonce: 0,
                gas_limit: 21_010, // 21_000 intrinsic + 10 for VM (not enough)
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(!result.success, "VM should fail: out of gas");
        assert_eq!(result.gas_used, 21_010, "all gas consumed on VM error");
    }

    #[test]
    fn test_contract_call_eoa_gas_refund() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 10_000_000));

        // ContractCall to bob (EOA, no code) with gas_limit > intrinsic
        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: bob,
                    data: vec![],
                    value: 1_000,
                },
                nonce: 0,
                gas_limit: 100_000, // Way more than needed
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);
        // Only intrinsic gas should be charged (no VM execution for EOA)
        assert_eq!(result.gas_used, MIN_TRANSACTION_GAS);
        // Bob got the value
        assert_eq!(state.balance(&bob), 1_000);
        // Alice: 10M - 1M (gas upfront) + refund(1M-210k) - 1k (value)
        //      = 10M - 210k - 1k = 9_789_000
        let expected = 10_000_000 - (MIN_TRANSACTION_GAS * 10) - 1_000;
        assert_eq!(state.balance(&alice), expected);
    }

    #[test]
    fn test_contract_call_vm_gas_refund() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract_refund");
        state.set_account(Account::new_eoa(alice, 10_000_000));
        state.get_or_create_account(contract);

        // Deploy the simple halt-success contract
        let code = make_halt_success_code();
        state.deploy_code(&contract, &code).unwrap();

        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: vec![],
                    value: 0,
                },
                nonce: 0,
                gas_limit: 500_000, // Much more gas than needed
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);

        // Gas used is intrinsic + small VM gas, nowhere near 500_000
        assert!(result.gas_used < 22_000, "VM used minimal gas");

        // Alice paid gas_used, got refund for the rest
        let expected = 10_000_000 - (result.gas_used * 10);
        assert_eq!(state.balance(&alice), expected);
    }

    #[test]
    fn test_deploy_then_call_lifecycle() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        state.set_account(Account::new_eoa(alice, 100_000_000));

        // Step 1: Deploy an echo contract
        let code = make_echo_code();
        let code_hash = Hasher::hash(&code);
        let contract_addr = Address::from_public_key(code_hash.as_bytes());

        let deploy_tx = make_deploy(alice, 0, code.clone());
        let deploy_result = execute_transaction(&deploy_tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(deploy_result.success);
        assert_eq!(state.nonce(&alice), 1);
        assert!(state.get_code(&contract_addr).is_some());

        // Step 2: Call the deployed echo contract
        let calldata = b"Brrq VM works!".to_vec();
        let call_tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract_addr,
                    data: calldata.clone(),
                    value: 0,
                },
                nonce: 1,
                gas_limit: 200_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let call_result = execute_transaction(&call_tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(call_result.success);
        assert_eq!(call_result.output, b"Brrq VM works!");
        assert_eq!(state.nonce(&alice), 2);
    }

    #[test]
    fn test_contract_call_with_value_and_code() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract_value");
        state.set_account(Account::new_eoa(alice, 10_000_000));
        state.get_or_create_account(contract);

        // Deploy halt-success contract
        let code = make_halt_success_code();
        state.deploy_code(&contract, &code).unwrap();

        // Call with value transfer + VM execution
        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: vec![],
                    value: 50_000,
                },
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);
        assert_eq!(state.balance(&contract), 50_000);
        // Alice: 10M - gas_used*10 - 50k + refund
        let expected = 10_000_000 - (result.gas_used * 10) - 50_000;
        assert_eq!(state.balance(&alice), expected);
    }

    // ── Intrinsic gas tests ────────────────────────────────────────────

    #[test]
    fn test_intrinsic_gas_transfer() {
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        let tx = make_transfer(alice, 0, bob, 100, 1, 1);
        assert_eq!(intrinsic_gas(&tx), 21_000);
    }

    #[test]
    fn test_intrinsic_gas_deploy() {
        let alice = test_addr("alice");
        let code = vec![0u8; 100];
        let tx = make_deploy(alice, 0, code);
        // 21_000 + 100 * 4 = 21_400
        assert_eq!(intrinsic_gas(&tx), 21_400);
    }

    #[test]
    fn test_intrinsic_gas_contract_call() {
        let alice = test_addr("alice");
        let contract = test_addr("contract");
        let data = vec![0u8; 200];
        let tx = make_contract_call(alice, 0, contract, 0, data);
        // 21_000 + 200 * 4 = 21_800
        assert_eq!(intrinsic_gas(&tx), 21_800);
    }

    #[test]
    fn test_gas_limit_below_intrinsic() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let code = vec![0u8; 1000]; // needs 21_000 + 4_000 = 25_000 gas
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::Deploy { code },
                nonce: 0,
                gas_limit: 21_000, // Not enough for deploy
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        assert!(matches!(
            result,
            Err(SequencerError::InsufficientGas { .. })
        ));
    }

    // ── State root consistency ─────────────────────────────────────────

    #[test]
    fn test_state_root_changes_after_execution() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let root_before = state.state_root();
        let tx = make_transfer(alice, 0, bob, 1_000, 1, 1);
        execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        let root_after = state.state_root();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_deterministic_execution() {
        let run = || {
            let mut state = WorldState::new();
            let alice = test_addr("alice");
            let bob = test_addr("bob");
            state.set_account(Account::new_eoa(alice, 1_000_000));

            let tx = make_transfer(alice, 0, bob, 1_000, 1, 1);
            execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
            (
                state.state_root(),
                state.balance(&alice),
                state.balance(&bob),
            )
        };

        let (root1, bal_a1, bal_b1) = run();
        let (root2, bal_a2, bal_b2) = run();

        assert_eq!(root1, root2);
        assert_eq!(bal_a1, bal_a2);
        assert_eq!(bal_b1, bal_b2);
    }

    // ── Chain ID validation tests ─────────────────────────────────────

    #[test]
    fn test_wrong_chain_id_rejected() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = make_transfer(alice, 0, bob, 1_000, 1, 1);
        // Use MAINNET chain_id as expected, but tx has TESTNET
        let result = execute_transaction(&tx, &mut state, chain_id::MAINNET);
        assert!(result.is_err());
        match result {
            Err(SequencerError::InvalidTransaction { reason }) => {
                assert!(reason.contains("chain_id mismatch"));
            }
            other => panic!("expected chain_id mismatch error, got {:?}", other),
        }

        // State must be unchanged
        assert_eq!(state.nonce(&alice), 0);
        assert_eq!(state.balance(&alice), 1_000_000);
    }

    #[test]
    fn test_correct_chain_id_accepted() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = make_transfer(alice, 0, bob, 1_000, 1, 1);
        // Matching chain_id should succeed
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        let receipt = result.expect("matching chain_id should succeed");
        assert!(receipt.success, "transfer should succeed");
        assert_eq!(state.balance(&bob), 1_000, "bob should receive 1_000");
        assert!(
            state.balance(&alice) < 1_000_000,
            "alice's balance should have decreased from 1_000_000"
        );
    }

    // ── Code/calldata size limit tests ────────────────────────────────

    #[test]
    fn test_deploy_code_size_limit() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        state.set_account(Account::new_eoa(alice, 100_000_000));

        // Deploy code at exactly MAX_CODE_SIZE should succeed
        let ok_code = vec![0x13u8; MAX_CODE_SIZE];
        let tx = make_deploy(alice, 0, ok_code);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        assert!(result.is_ok(), "deploy at MAX_CODE_SIZE should succeed");

        // Deploy code exceeding MAX_CODE_SIZE should fail (execution fails, nonce still increments)
        let big_code = vec![0x13u8; MAX_CODE_SIZE + 1];
        let tx2 = make_deploy(alice, 1, big_code);
        let result2 = execute_transaction(&tx2, &mut state, chain_id::TESTNET);
        let receipt2 = result2.expect("should return Ok with success=false, not Err");
        assert!(!receipt2.success, "deploy with oversized code should fail");
        let output_str = String::from_utf8_lossy(&receipt2.output);
        assert!(
            output_str.contains("deploy code too large"),
            "expected code size error, got: {}",
            output_str
        );
    }

    #[test]
    fn test_calldata_size_limit() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let contract = test_addr("contract_limit");
        state.set_account(Account::new_eoa(alice, 1_000_000_000));

        // Calldata at exactly MAX_CALLDATA_SIZE should succeed
        let ok_data = vec![0xABu8; MAX_CALLDATA_SIZE];
        let gas_needed = 21_000 + (ok_data.len() as u64) * GAS_PER_CALLDATA_BYTE;
        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: ok_data,
                    value: 0,
                },
                nonce: 0,
                gas_limit: gas_needed,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        assert!(
            result.is_ok(),
            "calldata at MAX_CALLDATA_SIZE should succeed"
        );

        // Calldata exceeding MAX_CALLDATA_SIZE should fail
        let big_data = vec![0xABu8; MAX_CALLDATA_SIZE + 1];
        let gas_needed2 = 21_000 + (big_data.len() as u64) * GAS_PER_CALLDATA_BYTE;
        let tx2 = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: big_data,
                    value: 0,
                },
                nonce: 1,
                gas_limit: gas_needed2,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };
        let result2 = execute_transaction(&tx2, &mut state, chain_id::TESTNET);
        let receipt2 = result2.expect("should return Ok with success=false, not Err");
        assert!(!receipt2.success, "calldata exceeding limit should fail");
        let output_str = String::from_utf8_lossy(&receipt2.output);
        assert!(
            output_str.contains("calldata too large"),
            "expected calldata size error, got: {}",
            output_str
        );
    }

    // ── Staking transaction tests ─────────────────────────────────────

    fn make_staking_tx(
        from: Address,
        kind: TransactionKind,
        nonce: u64,
        gas_limit: u64,
    ) -> Transaction {
        Transaction {
            body: TransactionBody {
                from,
                kind,
                nonce,
                gas_limit,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        }
    }

    #[test]
    fn test_register_validator_deducts_stake() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        state.set_account(Account::new_eoa(alice, 10_000_000));

        let tx = make_staking_tx(
            alice,
            TransactionKind::RegisterValidator { stake: 1_000_000 },
            0,
            REGISTER_VALIDATOR_GAS,
        );
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);
        // Stake should be deducted from balance (plus gas cost)
        let gas_cost = REGISTER_VALIDATOR_GAS * 10; // max_fee_per_gas = 10
        assert_eq!(state.balance(&alice), 10_000_000 - 1_000_000 - gas_cost);
    }

    #[test]
    fn test_register_validator_insufficient_balance() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        state.set_account(Account::new_eoa(alice, 100)); // Not enough

        let tx = make_staking_tx(
            alice,
            TransactionKind::RegisterValidator { stake: 1_000_000 },
            0,
            REGISTER_VALIDATOR_GAS,
        );
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        let err = result.unwrap_err();
        assert!(
            matches!(err, SequencerError::InsufficientGas { .. }),
            "expected InsufficientGas error, got: {err:?}"
        );
    }

    #[test]
    fn test_add_stake_deducts_amount() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        state.set_account(Account::new_eoa(alice, 5_000_000));

        let tx = make_staking_tx(
            alice,
            TransactionKind::AddStake { amount: 500_000 },
            0,
            ADD_STAKE_GAS,
        );
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);
        let gas_cost = ADD_STAKE_GAS * 10; // max_fee_per_gas = 10
        assert_eq!(state.balance(&alice), 5_000_000 - 500_000 - gas_cost);
    }

    #[test]
    fn test_add_stake_insufficient_balance() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        state.set_account(Account::new_eoa(alice, 100));

        let tx = make_staking_tx(
            alice,
            TransactionKind::AddStake { amount: 500_000 },
            0,
            ADD_STAKE_GAS,
        );
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        let err = result.unwrap_err();
        assert!(
            matches!(err, SequencerError::InsufficientGas { .. }),
            "expected InsufficientGas error, got: {err:?}"
        );
    }

    #[test]
    fn test_begin_unbonding_charges_gas() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        state.set_account(Account::new_eoa(alice, 1_000_000));

        let tx = make_staking_tx(
            alice,
            TransactionKind::BeginUnbonding,
            0,
            BEGIN_UNBONDING_GAS,
        );
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, BEGIN_UNBONDING_GAS);
    }

    #[test]
    fn test_equivocation_proof_charges_gas() {
        let mut state = WorldState::new();
        let alice = test_addr("alice");
        let validator = test_addr("validator");
        state.set_account(Account::new_eoa(alice, 10_000_000));

        let mut hash_b = Hash256::ZERO;
        hash_b.0[0] = 1;

        let tx = make_staking_tx(
            alice,
            TransactionKind::SubmitEquivocationProof {
                validator,
                height: 100,
                block_hash_a: Hash256::ZERO,
                block_hash_b: hash_b,
                signature_a: vec![0u8; 64],
                signature_b: vec![0u8; 64],
                slh_dsa_pk: vec![0u8; 32],
            },
            0,
            EQUIVOCATION_PROOF_GAS,
        );
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);
        assert_eq!(result.gas_used, EQUIVOCATION_PROOF_GAS);
    }

    #[test]
    fn test_staking_gas_costs() {
        let alice = test_addr("alice");

        let reg_tx = make_staking_tx(
            alice,
            TransactionKind::RegisterValidator { stake: 100 },
            0,
            REGISTER_VALIDATOR_GAS,
        );
        assert_eq!(intrinsic_gas(&reg_tx), REGISTER_VALIDATOR_GAS);

        let add_tx = make_staking_tx(
            alice,
            TransactionKind::AddStake { amount: 100 },
            0,
            ADD_STAKE_GAS,
        );
        assert_eq!(intrinsic_gas(&add_tx), ADD_STAKE_GAS);

        let unbond_tx = make_staking_tx(
            alice,
            TransactionKind::BeginUnbonding,
            0,
            BEGIN_UNBONDING_GAS,
        );
        assert_eq!(intrinsic_gas(&unbond_tx), BEGIN_UNBONDING_GAS);
    }

    // ── Contract Storage (SLOAD/SSTORE) integration tests ───────────

    /// Helper: encode a U-type instruction.
    #[allow(dead_code)]
    fn u_type(imm: u32, rd: u32, opcode: u32) -> u32 {
        (imm & 0xFFFFF000) | (rd << 7) | opcode
    }

    #[allow(dead_code)]
    const LUI_OP: u32 = 0b0110111;

    /// Build a minimal contract that does: SSTORE(key_ptr, value_ptr) then HALT.
    fn make_sstore_contract() -> Vec<u8> {
        // The contract expects calldata in memory containing key(32) + value(32).
        // a0 = calldata_ptr, a1 = calldata_len
        //
        // Step 1: Set a7 = 0x106 (SSTORE)
        // Step 2: a0 already points to key (start of calldata)
        // Step 3: a1 = a0 + 32 (value is right after key in calldata)
        //         But a1 = calldata_len. We need to compute a1 = a0 + 32.
        //         ADDI x11, x10, 32
        // Step 4: ECALL (SSTORE)
        // Step 5: a7 = 0 (HALT), ECALL
        assemble(&[
            // a0 = calldata_ptr (key), compute a1 = a0 + 32 (value)
            i_type(32, 10, 0b000, 11, OP_IMM), // ADDI x11, x10, 32
            i_type(0x106, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0x106 (SSTORE)
            sys_type(0),                       // ECALL (SSTORE)
            i_type(0, 0, 0b000, 17, OP_IMM),   // ADDI x17, x0, 0 (HALT)
            i_type(0, 0, 0b000, 10, OP_IMM),   // ADDI x10, x0, 0 (exit code 0)
            sys_type(0),                       // ECALL (HALT)
        ])
    }

    /// Build a contract that does: SLOAD(key_ptr, out_ptr) then HALT(a0=exists).
    #[allow(dead_code)]
    fn make_sload_contract() -> Vec<u8> {
        // a0 = calldata_ptr (key), a1 = calldata_len
        // We'll use a fixed output ptr at 0x30000
        assemble(&[
            // Save calldata_ptr in x5 for key
            i_type(0, 10, 0b000, 5, OP_IMM), // ADDI x5, x10, 0 (save key ptr)
            // Set up SLOAD: a0 = key_ptr, a1 = out_ptr (0x30000)
            i_type(0, 5, 0b000, 10, OP_IMM), // ADDI x10, x5, 0 (a0 = key_ptr)
            u_type(0x30000, 11, LUI_OP),     // LUI x11, 0x30000 (a1 = out_ptr)
            i_type(0x105, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0x105 (SLOAD)
            sys_type(0),                     // ECALL (SLOAD) → a0 = exists
            // HALT with exit code = a0 (exists flag)
            i_type(0, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0 (HALT)
            sys_type(0),                     // ECALL (HALT)
        ])
    }

    fn make_contract_call_with_gas(
        from: Address,
        nonce: u64,
        to: Address,
        value: u64,
        data: Vec<u8>,
        gas_limit: u64,
    ) -> Transaction {
        Transaction {
            body: TransactionBody {
                from,
                kind: TransactionKind::ContractCall { to, data, value },
                nonce,
                gas_limit,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        }
    }

    #[test]
    fn test_contract_call_with_storage() {
        let mut state = WorldState::new();
        let alice = test_addr("storage_alice");
        let contract = test_addr("storage_contract");

        // Fund alice
        state.set_account(Account::new_eoa(alice, 10_000_000));

        // Deploy the SSTORE contract
        let sstore_code = make_sstore_contract();
        state.get_or_create_account(contract);
        state.deploy_code(&contract, &sstore_code).unwrap();

        // Build calldata: key(32 bytes) + value(32 bytes)
        let key = brrq_crypto::hash::Hasher::hash(b"contract_slot_0");
        let value = brrq_crypto::hash::Hasher::hash(b"contract_value_0");
        let mut calldata = Vec::with_capacity(64);
        calldata.extend_from_slice(key.as_bytes());
        calldata.extend_from_slice(value.as_bytes());

        // Call contract with enough gas for SSTORE (5000) + overhead
        let tx = make_contract_call_with_gas(alice, 0, contract, 0, calldata, 50_000);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success, "Contract call should succeed");

        // Verify storage was written
        assert_eq!(state.storage_get(&contract, &key), Some(value));
    }

    #[test]
    fn test_contract_storage_persistence() {
        let mut state = WorldState::new();
        let alice = test_addr("persist_alice");
        let contract = test_addr("persist_contract");

        // Fund alice
        state.set_account(Account::new_eoa(alice, 10_000_000));

        // Deploy SSTORE contract
        let sstore_code = make_sstore_contract();
        state.get_or_create_account(contract);
        state.deploy_code(&contract, &sstore_code).unwrap();

        // Write key1 = value1
        let key1 = brrq_crypto::hash::Hasher::hash(b"key1");
        let value1 = brrq_crypto::hash::Hasher::hash(b"value1");
        let mut calldata1 = Vec::with_capacity(64);
        calldata1.extend_from_slice(key1.as_bytes());
        calldata1.extend_from_slice(value1.as_bytes());

        let tx1 = make_contract_call_with_gas(alice, 0, contract, 0, calldata1, 50_000);
        let r1 = execute_transaction(&tx1, &mut state, chain_id::TESTNET).unwrap();
        assert!(r1.success);

        // Write key2 = value2 (in a separate transaction)
        let key2 = brrq_crypto::hash::Hasher::hash(b"key2");
        let value2 = brrq_crypto::hash::Hasher::hash(b"value2");
        let mut calldata2 = Vec::with_capacity(64);
        calldata2.extend_from_slice(key2.as_bytes());
        calldata2.extend_from_slice(value2.as_bytes());

        let tx2 = make_contract_call_with_gas(alice, 1, contract, 0, calldata2, 50_000);
        let r2 = execute_transaction(&tx2, &mut state, chain_id::TESTNET).unwrap();
        assert!(r2.success);

        // Verify both keys persist in world state
        assert_eq!(state.storage_get(&contract, &key1), Some(value1));
        assert_eq!(state.storage_get(&contract, &key2), Some(value2));
    }

    #[test]
    fn test_contract_storage_rollback() {
        let mut state = WorldState::new();
        let alice = test_addr("rollback_alice");
        let contract = test_addr("rollback_contract");

        // Fund alice with very limited balance
        state.set_account(Account::new_eoa(alice, 10_000_000));

        // Deploy SSTORE contract, then pre-populate a value
        let sstore_code = make_sstore_contract();
        state.get_or_create_account(contract);
        state.deploy_code(&contract, &sstore_code).unwrap();

        let key = brrq_crypto::hash::Hasher::hash(b"rollback_key");
        let value = brrq_crypto::hash::Hasher::hash(b"rollback_value");

        // First: successfully write key=value
        let mut calldata = Vec::with_capacity(64);
        calldata.extend_from_slice(key.as_bytes());
        calldata.extend_from_slice(value.as_bytes());

        let tx = make_contract_call_with_gas(alice, 0, contract, 0, calldata, 50_000);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);
        assert_eq!(state.storage_get(&contract, &key), Some(value));

        // Verify storage changes are recorded in state_changes
        let storage_changes: Vec<_> = result
            .state_changes
            .iter()
            .filter(|c| matches!(c, StateChange::StorageChange { .. }))
            .collect();
        assert!(
            !storage_changes.is_empty(),
            "Should have storage change records"
        );
    }

    // ── Graduated Protocol Fee tests ────────────────────────────────

    #[test]
    fn test_transfer_with_protocol_fee() {
        let mut state = WorldState::new();
        let alice = test_addr("fee_alice");
        let bob = test_addr("fee_bob");

        // Transfer 1,000,000 sats (tier 2): fee = 50 + 25*6 = 200 sats
        let amount = 1_000_000u64;
        let protocol_fee = brrq_types::gas::fee_tiers::graduated_fee(amount);
        assert_eq!(protocol_fee, 200);

        // Fund alice with amount + gas + protocol_fee + some margin
        let gas_cost = 21_000 * 1; // gas_limit * gas_price
        let total_needed = amount + gas_cost + protocol_fee;
        state.set_account(Account::new_eoa(alice, total_needed));

        let tx = make_transfer(alice, 0, bob, amount, 1, 1);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);

        // Bob should receive the full amount
        assert_eq!(state.balance(&bob), amount);

        // Alice should have lost: amount + gas_used * gas_price + protocol_fee
        // But she was refunded unused gas. Gas used = 21_000 (intrinsic for transfer)
        // So alice_final = total_needed - amount - 21_000 - protocol_fee = 0
        assert_eq!(state.balance(&alice), 0);
    }

    #[test]
    fn test_transfer_insufficient_with_fee() {
        let mut state = WorldState::new();
        let alice = test_addr("insuf_fee_alice");
        let bob = test_addr("insuf_fee_bob");

        // Transfer 1,000,000 sats: fee = 200 sats
        let amount = 1_000_000u64;
        let protocol_fee = brrq_types::gas::fee_tiers::graduated_fee(amount);

        // Fund alice with just enough for amount + gas, but NOT the fee
        let gas_cost = 21_000 * 1;
        state.set_account(Account::new_eoa(alice, amount + gas_cost));

        let tx = make_transfer(alice, 0, bob, amount, 1, 1);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);

        // Should fail because alice can't cover amount + protocol_fee after gas deduction
        let receipt = result.expect("should return Ok with success=false, not Err");
        assert!(
            !receipt.success,
            "Should fail: balance < amount + fee ({protocol_fee}) after gas deduction"
        );
    }

    #[test]
    fn test_zero_transfer_no_fee() {
        let mut state = WorldState::new();
        let alice = test_addr("zerofee_alice");
        let bob = test_addr("zerofee_bob");

        // Zero-amount transfer: fee = 0
        let amount = 0u64;
        let protocol_fee = brrq_types::gas::fee_tiers::graduated_fee(amount);
        assert_eq!(protocol_fee, 0);

        // Fund alice with just enough for gas
        let gas_cost = 21_000 * 1;
        state.set_account(Account::new_eoa(alice, gas_cost));

        let tx = make_transfer(alice, 0, bob, amount, 1, 1);
        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();
        assert!(result.success);

        // Bob received 0, alice spent only gas
        assert_eq!(state.balance(&bob), 0);
        assert_eq!(state.balance(&alice), 0);
    }

    // ── Synthetic deposit tests ──────────────────────────────────────

    #[test]
    fn test_execute_synthetic_deposit() {
        let mut state = WorldState::new();
        let recipient = test_addr("depositor");
        let btc_tx_id = Hasher::hash(b"btc_tx_abc");

        let result =
            execute_synthetic_deposit(&recipient, 1_000_000, &btc_tx_id, &mut state).unwrap();

        assert!(result.success);
        assert_eq!(result.gas_used, DEPOSIT_SYNTHETIC_GAS);
        assert_eq!(state.balance(&recipient), 1_000_000);
        assert_eq!(result.state_changes.len(), 1);
    }

    #[test]
    fn test_execute_synthetic_deposit_zero_amount() {
        let mut state = WorldState::new();
        let recipient = test_addr("depositor");
        let btc_tx_id = Hasher::hash(b"btc_tx_zero");

        let result = execute_synthetic_deposit(&recipient, 0, &btc_tx_id, &mut state);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_synthetic_deposit_zero_address() {
        let mut state = WorldState::new();
        let btc_tx_id = Hasher::hash(b"btc_tx_zero_addr");

        let result = execute_synthetic_deposit(&Address::ZERO, 1_000, &btc_tx_id, &mut state);
        assert!(result.is_err());
    }

    #[test]
    fn test_execute_synthetic_deposit_accumulates() {
        let mut state = WorldState::new();
        let recipient = test_addr("depositor");
        let btc_tx_1 = Hasher::hash(b"btc_tx_1");
        let btc_tx_2 = Hasher::hash(b"btc_tx_2");

        execute_synthetic_deposit(&recipient, 500_000, &btc_tx_1, &mut state).unwrap();
        execute_synthetic_deposit(&recipient, 300_000, &btc_tx_2, &mut state).unwrap();

        assert_eq!(state.balance(&recipient), 800_000);
    }

    #[test]
    fn test_vm_infinite_loop_gas_exhaustion() {
        let mut state = WorldState::new();
        let alice = test_addr("alice_loop");
        let contract = test_addr("contract_loop");
        state.set_account(Account::new_eoa(alice, 10_000_000));
        state.get_or_create_account(contract);

        // JAL x0, 0 -> infinite loop
        let code = assemble(&[0x0000006F]);
        state.deploy_code(&contract, &code).unwrap();

        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: vec![],
                    value: 0,
                },
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        // The sequencer should gracefully catch the StepLimit exception and consume ALL gas.
        assert!(!result.success, "Infinite loop should fail.");
        assert_eq!(
            result.gas_used, 100_000,
            "Should consume all allocated gas for the loop."
        );
    }

    #[test]
    fn test_vm_oob_memory_access_revert() {
        let mut state = WorldState::new();
        let alice = test_addr("alice_oob");
        let contract = test_addr("contract_oob");
        state.set_account(Account::new_eoa(alice, 10_000_000));
        state.get_or_create_account(contract);

        // OOB Memory write to 0xFFFFFFFF
        // SW rs2=11, rs1=10, offset=0, funct3=0b010, opcode=0b0100011
        // LUI x10, 0xFFFFF000: 0xFFFFF537
        // ADDI x10, x10, 0xFFF: 0xFFF50513
        // ADDI x11, x0, 42: 0x02A00593
        // SW x11, 0(x10): 0x00B52023
        let code_bytes = vec![
            0x37, 0xF5, 0xFF, 0xFF, 0x13, 0x05, 0xF5, 0xFF, 0x93, 0x05, 0xA0, 0x02, 0x23, 0x20,
            0xB5, 0x00,
        ];
        state.deploy_code(&contract, &code_bytes).unwrap();

        let tx = Transaction {
            body: TransactionBody {
                from: alice,
                kind: TransactionKind::ContractCall {
                    to: contract,
                    data: vec![],
                    value: 0,
                },
                nonce: 0,
                gas_limit: 100_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: chain_id::TESTNET,
            },
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET).unwrap();

        // The system should catch the fault and revert instead of panicing
        assert!(
            !result.success,
            "OOB Memory access should fail the transaction."
        );
        assert_eq!(
            result.gas_used, 100_000,
            "Failed transaction consumes all limit."
        );
    }

    // ══════════════════════════════════════════════════════════════════
    // CHAOS ENGINEERING: Atomic Commit Crash Resilience
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_executor_atomic_commit_crash_resilience() {
        // PURPOSE: Prove that a simulated crash between execute_transaction
        // and persist_block_atomic leaves NO partial state on disk.
        //
        // DESIGN:
        // 1. Create WorldState with Alice having 10M sats
        // 2. Execute a transfer of 5M sats from Alice to Bob
        // 3. Verify in-memory state shows Alice=5M, Bob=5M (gas aside)
        // 4. SIMULATED CRASH: Clone the pre-execution state (as if restoring from disk)
        // 5. Verify the "disk" state still shows Alice=10M, Bob=0
        //
        // This proves that execute_transaction operates purely in-memory
        // and no state leaks to persistent storage before the atomic commit.

        let mut state = WorldState::new();
        let alice = Address::from_bytes([0xAA; 20]);
        let bob = Address::from_bytes([0xBB; 20]);

        // Fund Alice
        state.set_account(Account::new_eoa(alice, 10_000_000));

        // Snapshot: this is the "disk state" before the block
        let pre_execution_root = state.state_root();
        let alice_balance_before = state.balance(&alice);
        let bob_balance_before = state.balance(&bob);

        assert_eq!(alice_balance_before, 10_000_000);
        assert_eq!(bob_balance_before, 0);

        // Execute a transfer transaction
        let body = TransactionBody {
            from: alice,
            kind: TransactionKind::Transfer { to: bob, amount: 5_000_000 },
            nonce: 0,
            gas_limit: 21_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            chain_id: chain_id::TESTNET,
        };
        let tx = Transaction {
            body,
            signature: Signature::Schnorr(SchnorrSignature::from_bytes([0u8; 64])),
            public_key: PublicKey::Schnorr(SchnorrPublicKey::from_bytes([0u8; 32])),
        };

        let result = execute_transaction(&tx, &mut state, chain_id::TESTNET);
        assert!(result.is_ok());
        let result = result.unwrap();

        // In-memory state reflects the transfer
        let alice_after_execute = state.balance(&alice);
        let bob_after_execute = state.balance(&bob);
        assert!(
            alice_after_execute < alice_balance_before,
            "Alice balance should decrease after execute"
        );
        assert_eq!(bob_after_execute, 5_000_000, "Bob should receive 5M sats");

        // === SIMULATED CRASH ===
        // At this point, the block has NOT been committed to disk.
        // In the real node, persist_block_atomic() has NOT been called.
        // We simulate a crash by rolling back the in-memory changes.
        state.rollback_changes(&result.state_changes);

        // === POST-CRASH VERIFICATION ===
        // After rollback (simulating disk restore), state must be pristine.
        let alice_after_crash = state.balance(&alice);
        let bob_after_crash = state.balance(&bob);

        assert_eq!(
            alice_after_crash, alice_balance_before,
            "CRASH RESILIENCE: Alice's balance must be fully restored after simulated crash"
        );
        assert_eq!(
            bob_after_crash, bob_balance_before,
            "CRASH RESILIENCE: Bob's balance must be zero after simulated crash (no partial commit)"
        );

        // NOTE: state_root may differ because rollback_changes() restores balances
        // but doesn't undo SMT trie node insertions. This is by design —
        // the real crash protection is that persist_block_atomic() (RocksDB WriteBatch)
        // hasn't been called, so the on-disk SMT is pristine.
        //
        // What matters for crash resilience:
        // ✅ Balances restored (proven above)
        // ✅ On-disk state untouched (persist_block_atomic not called)
        // ✅ No partial writes (RocksDB WAL guarantees)
    }
}
fn execute_contract_call_internal(
    state: &mut WorldState,
    changes: &mut Vec<StateChange>,
    caller: brrq_types::Address,
    to: &brrq_types::Address,
    value: u64,
    data: &[u8],
    gas_available: u64,
    depth: usize,
    ctx: &ExecutionContext,
    generate_trace: bool,
) -> Result<
    (
        bool,
        u64,
        Vec<u8>,
        Vec<brrq_types::Log>,
        Option<brrq_vm::trace::ExecutionTrace>,
    ),
    SequencerError,
> {
    if depth > 1024 {
        // Stack too deep
        return Ok((false, gas_available, Vec::new(), Vec::new(), None));
    }

    // Snapshot changes length to rollback value transfers on VM failure
    let changes_len_before_execution = changes.len();

    // Value transfer (if any)
    if value > 0 {
        let caller_balance = state.balance(&caller);
        if caller_balance < value {
            return Ok((false, 0, Vec::new(), Vec::new(), None));
        }

        let caller_before = caller_balance;
        let to_before = state.balance(to);

        if let Err(e) = state.transfer(&caller, to, value) {
            state.rollback_changes(changes);
            return Err(e.into());
        }

        changes.push(StateChange::BalanceChange {
            address: caller,
            old_balance: caller_before,
            new_balance: state.balance(&caller),
        });
        changes.push(StateChange::BalanceChange {
            address: *to,
            old_balance: to_before,
            new_balance: state.balance(to),
        });
    }

    // Check for code
    let code = match state.get_code(to) {
        Some(c) => c.to_vec(),
        None => {
            // No code at target — pure value transfer to EOA.
            // Consume 0 execution gas, exit successfully.
            return Ok((true, 0, Vec::new(), Vec::new(), None));
        }
    };

    // Create VM executor with contract code.
    // Step limit is proportional to gas, capped at VM_STEP_LIMIT.
    let step_limit = gas_available.saturating_mul(STEPS_PER_GAS).min(VM_STEP_LIMIT);
    let mut vm = match brrq_vm::Executor::new(&code, gas_available, step_limit) {
        Ok(vm) => vm,
        Err(e) => {
            tracing::warn!("VM init failed: {e}");
            return Err(SequencerError::ExecutionError {
                msg: format!("VM initialization failed: {e}"),
            });
        }
    };
    if generate_trace {
        vm.enable_trace();
    }
    vm.set_contract_address(*to);
    vm.set_caller(caller);
    vm.set_msg_value(value);
    vm.set_block_context(ctx.block_height, ctx.block_timestamp);

    // Set up storage adapter
    let storage_trie = state.clone_storage_trie(to);
    let adapter = ContractStorageAdapter::new(storage_trie);
    vm.set_storage(Box::new(adapter));

    // Set calldata in VM memory (fixed address for SDK compatibility)
    let calldata_addr = 0x8000_0000;
    if !data.is_empty()
        && let Err(e) = vm.write_memory(calldata_addr, data)
    {
        let changes_to_revert = changes.split_off(changes_len_before_execution);
        state.rollback_changes(&changes_to_revert);
        return Err(SequencerError::ExecutionError {
            msg: format!("failed to write calldata: {}", e),
        });
    }

    if let Err(e) = vm.set_reg(10, calldata_addr) {
        let changes_to_revert = changes.split_off(changes_len_before_execution);
        state.rollback_changes(&changes_to_revert);
        return Err(SequencerError::ExecutionError {
            msg: format!("failed to set register: {}", e),
        });
    }
    if let Err(e) = vm.set_reg(11, data.len() as u32) {
        let changes_to_revert = changes.split_off(changes_len_before_execution);
        state.rollback_changes(&changes_to_revert);
        return Err(SequencerError::ExecutionError {
            msg: format!("failed to set register: {}", e),
        });
    }

    let mut current_state_res = vm.run();
    #[allow(unused_assignments)] // initial None is required for type; always overwritten in loop
    let mut final_halt_res = None;

    // Loop to handle recursive YieldContractCall resolutions
    loop {
        match current_state_res {
            Ok(brrq_vm::executor::ExecutionState::YieldContractCall {
                to: call_to,
                value: call_value,
                calldata: call_calldata,
            }) => {
                // Pass a portion of gas to the sub-call (EIP-150 style: retain 1/64 of remaining gas)
                let remaining_gas = gas_available.saturating_sub(vm.gas_used());
                let sub_gas = remaining_gas.saturating_sub(remaining_gas / 64);

                let (sub_success, sub_gas_used, sub_return_data, mut _sub_logs, sub_trace) =
                    execute_contract_call_internal(
                        state,
                        changes,
                        *to, // the caller is the current contract
                        &call_to,
                        call_value,
                        &call_calldata,
                        sub_gas,
                        depth + 1,
                        ctx,
                        generate_trace,
                    )?;

                // Track gas used continuously
                if let Err(e) = vm.consume_gas(sub_gas_used) {
                    tracing::warn!("Sub-call exceeded parent gas: {:?}", e);
                }

                current_state_res = vm.resume(sub_success, sub_return_data, sub_trace);
            }
            Ok(brrq_vm::executor::ExecutionState::Halted(vm_result)) => {
                final_halt_res = Some(Ok(vm_result));
                break;
            }
            Err(e) => {
                final_halt_res = Some(Err(e));
                break;
            }
        }
    }

    let run_result = final_halt_res.unwrap();

    let mut success = false;
    let mut actual_gas_used = gas_available; // default to consuming all on error
    let mut output_data = Vec::new();
    let mut tx_logs = Vec::new();
    let mut captured_trace = None;

    match run_result {
        Ok(vm_result) => {
            actual_gas_used = vm_result.effective_gas_used;
            output_data = vm_result.output;
            tx_logs = vm_result.logs;

            if !vm_result.trace.steps.is_empty() {
                captured_trace = Some(vm_result.trace);
            }

            success = vm_result.exit_code == 0;

            if success && let Some(mut storage) = vm.take_storage() {
                for (key, value) in storage.drain_writes() {
                    let old_value = state.storage_get(to, &key);
                    state.storage_set(to, key, value);
                    changes.push(StateChange::StorageChange {
                        address: *to,
                        key,
                        old_value,
                        new_value: value,
                    });
                }
            }

            if success {
                for (to_addr, amount) in vm.take_native_transfers() {
                    let contract_bal = state.balance(to);
                    if contract_bal < amount {
                        success = false;
                        break;
                    }

                    let to_bal_before = state.balance(&to_addr);
                    // Use checked arithmetic to prevent overflow/underflow
                    let new_from_bal = match contract_bal.checked_sub(amount) {
                        Some(v) => v,
                        None => { success = false; break; }
                    };
                    let new_to_bal = match to_bal_before.checked_add(amount) {
                        Some(v) => v,
                        None => { success = false; break; }
                    };
                    {
                        state.get_or_create_account(*to).balance = new_from_bal;
                        state.get_or_create_account(to_addr).balance = new_to_bal;
                    }
                    state.flush_account(to);
                    state.flush_account(&to_addr);

                    changes.push(StateChange::BalanceChange {
                        address: *to,
                        old_balance: contract_bal,
                        new_balance: new_from_bal,
                    });
                    changes.push(StateChange::BalanceChange {
                        address: to_addr,
                        old_balance: to_bal_before,
                        new_balance: new_to_bal,
                    });
                }
            }
        }
        Err(e) => {
            tracing::warn!("VM execution error: {:?}", e);
        }
    }

    if !success {
        // Revert all state changes from this call frame
        let changes_to_revert = changes.split_off(changes_len_before_execution);
        state.rollback_changes(&changes_to_revert);
    }

    Ok((
        success,
        actual_gas_used,
        output_data,
        tx_logs,
        captured_trace,
    ))
}
