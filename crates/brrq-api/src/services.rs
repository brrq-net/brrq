//! Shared service layer — domain logic used by both REST and JSON-RPC handlers.
//!
//! Every function in this module takes `&NodeState` (read) or `&mut NodeState`
//! (write) and returns a `Result<serde_json::Value, ServiceError>`.  The
//! transport layer (REST / JSON-RPC) is responsible for acquiring the lock and
//! converting `ServiceError` into the appropriate HTTP / RPC error response.

use std::time::Instant;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_sequencer::executor::{MAX_CALLDATA_SIZE, MAX_CODE_SIZE};
use brrq_types::address::Address;
use brrq_types::signature::{PublicKey, Signature};
use brrq_types::transaction::{PortalSettlementClaim, Transaction, TransactionBody, TransactionKind};
use serde_json::json;

use crate::jsonrpc::{
    SendTxParams, parse_address, parse_hash, parse_schnorr_pubkey, parse_schnorr_signature,
};
use crate::state::NodeState;

// ── Service Error ──────────────────────────────────────────────────────────

/// Unified error type for service-layer operations.
///
/// The transport layer converts this to `ApiError` (REST) or `RpcResponse::error` (JSON-RPC).
#[derive(Debug)]
pub enum ServiceError {
    /// Client-supplied input was invalid (bad address, missing field, etc.).
    BadRequest(String),
    /// Request failed signature verification or authorization check.
    Unauthorized(String),
    /// Requested resource was not found.
    NotFound(String),
    /// Server-side error (faucet depleted, bridge failure, etc.).
    ServerError(String),
}

impl ServiceError {
    /// Convert to a JSON-RPC error code.
    pub fn rpc_code(&self) -> i32 {
        match self {
            ServiceError::BadRequest(_) => -32602,
            ServiceError::Unauthorized(_) => crate::error::RPC_UNAUTHORIZED,
            ServiceError::NotFound(_) => -32000,
            ServiceError::ServerError(_) => -32000,
        }
    }

    pub fn message(&self) -> &str {
        match self {
            ServiceError::BadRequest(m) => m,
            ServiceError::Unauthorized(m) => m,
            ServiceError::NotFound(m) => m,
            ServiceError::ServerError(m) => m,
        }
    }
}

impl From<ServiceError> for crate::error::ApiError {
    fn from(e: ServiceError) -> Self {
        match e {
            ServiceError::BadRequest(m) => crate::error::ApiError::BadRequest(m),
            ServiceError::Unauthorized(m) => crate::error::ApiError::Unauthorized(m),
            ServiceError::NotFound(m) => crate::error::ApiError::NotFound(m),
            ServiceError::ServerError(m) => crate::error::ApiError::Internal(m),
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn addr_hex(addr: &Address) -> String {
    format!("0x{}", hex::encode(addr.as_bytes()))
}

fn hash_hex(h: &Hash256) -> String {
    format!("0x{}", hex::encode(h.as_bytes()))
}

/// Convert a transaction to a JSON value with full details (used by REST).
pub fn tx_to_json(tx: &Transaction, block_height: Option<u64>) -> serde_json::Value {
    let (to, amount, kind) = match &tx.body.kind {
        TransactionKind::Transfer { to, amount } => (Some(addr_hex(to)), Some(*amount), "transfer"),
        TransactionKind::Deploy { .. } => (None, None, "deploy"),
        TransactionKind::ContractCall { to, value, .. } => {
            (Some(addr_hex(to)), Some(*value), "contract_call")
        }
        _ => (None, None, "other"),
    };
    json!({
        "hash": hash_hex(&tx.hash()),
        "from": addr_hex(&tx.body.from),
        "to": to,
        "amount": amount,
        "kind": kind,
        "nonce": tx.body.nonce,
        "gas_limit": tx.body.gas_limit,
        "gas_price": tx.body.max_fee_per_gas,
        "block_height": block_height,
    })
}

/// Return the string label for a transaction kind.
fn tx_kind_str(kind: &TransactionKind) -> &'static str {
    match kind {
        TransactionKind::Transfer { .. } => "transfer",
        TransactionKind::Deploy { .. } => "deploy",
        TransactionKind::ContractCall { .. } => "contract_call",
        _ => "other",
    }
}

// ── Request Signature Verification ────────────────────────────────────────

/// Verify a Schnorr signature over an API request body.
///
/// This is the shared verification routine for all state-mutating API endpoints
/// (governance, staking, bridge, etc.).  The caller must supply:
///
/// * `address`       — the claimed sender address (20 bytes).
/// * `public_key_hex` — hex-encoded 32-byte Schnorr public key.
/// * `signature_hex`  — hex-encoded 64-byte Schnorr signature.
/// * `canonical_msg`  — the canonical byte representation of the request body
///                      (all fields **except** `signature` and `public_key`,
///                       concatenated in a deterministic order).
///
/// Verification steps:
/// 1. Parse public key and signature from hex.
/// 2. Derive the expected address from the public key and compare.
/// 3. Hash `canonical_msg` with the `API_REQUEST_SIG_V1` domain tag.
/// 4. Verify the Schnorr signature over the resulting hash.
pub fn verify_request_signature(
    address: &Address,
    public_key_hex: &str,
    signature_hex: &str,
    canonical_msg: &[u8],
) -> Result<(), ServiceError> {
    // 1. Parse the public key.
    let pubkey = parse_schnorr_pubkey(public_key_hex).ok_or_else(|| {
        ServiceError::BadRequest("Invalid public_key (expected 32 hex bytes)".into())
    })?;

    // 2. Parse the signature.
    let signature = parse_schnorr_signature(signature_hex).ok_or_else(|| {
        ServiceError::BadRequest("Invalid signature (expected 64 hex bytes)".into())
    })?;

    // 3. Verify that the public key corresponds to the claimed address.
    let derived_address = Address::from_public_key(pubkey.as_bytes());
    if *address != derived_address {
        tracing::debug!(
            "Address mismatch: claimed {} but public key derives {}",
            address,
            derived_address,
        );
        return Err(ServiceError::Unauthorized(
            "Public key does not match claimed address".into(),
        ));
    }

    // 4. Domain-separated hash of the canonical message.
    let mut hasher = Hasher::new();
    hasher.update(brrq_crypto::domain_tags::API_REQUEST_SIG_V1);
    hasher.update(canonical_msg);
    let msg_hash = hasher.finalize();

    // 5. Verify the Schnorr signature.
    if let Err(e) = brrq_crypto::schnorr::verify(&pubkey, &msg_hash, &signature) {
        tracing::debug!("API request signature verification failed: {}", e);
        return Err(ServiceError::Unauthorized(
            "Signature verification failed".into(),
        ));
    }

    Ok(())
}

/// Build the canonical message bytes for a JSON request body.
///
/// Extracts all string keys from the JSON object except `signature` and
/// `public_key`, sorts them alphabetically, and concatenates
/// `key=value` pairs separated by `&`.  This gives a deterministic byte
/// representation that both client and server can reproduce.
pub fn canonical_message(body: &serde_json::Value) -> Vec<u8> {
    let obj = match body.as_object() {
        Some(o) => o,
        None => return Vec::new(),
    };
    let mut pairs: Vec<(&str, String)> = obj
        .iter()
        .filter(|(k, _)| *k != "signature" && *k != "public_key")
        .map(|(k, v)| {
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            (k.as_str(), val)
        })
        .collect();
    pairs.sort_by_key(|(k, _)| *k);

    let mut buf = Vec::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            buf.push(b'&');
        }
        buf.extend_from_slice(k.as_bytes());
        buf.push(b'=');
        buf.extend_from_slice(v.as_bytes());
    }
    buf
}

/// Extract and verify the signature fields from a JSON request body for
/// a given address field.  This is a convenience wrapper around
/// `verify_request_signature` + `canonical_message` for REST/RPC handlers.
pub fn verify_body_signature(
    body: &serde_json::Value,
    address: &Address,
) -> Result<(), ServiceError> {
    let sig_hex = body["signature"]
        .as_str()
        .ok_or_else(|| ServiceError::BadRequest("missing 'signature' field".into()))?;
    let pk_hex = body["public_key"]
        .as_str()
        .ok_or_else(|| ServiceError::BadRequest("missing 'public_key' field".into()))?;

    let canonical = canonical_message(body);
    verify_request_signature(address, pk_hex, sig_hex, &canonical)
}

// ── Transaction Building ───────────────────────────────────────────────────

/// Extract a required hash field from `SendTxParams`, returning a `ServiceError`
/// on missing or invalid values.
fn require_hash_field(hex: Option<&str>, field: &str) -> Result<Hash256, ServiceError> {
    let s = hex.ok_or_else(|| ServiceError::BadRequest(format!("Missing '{field}'")))?;
    parse_hash(s).ok_or_else(|| ServiceError::BadRequest(format!("Invalid '{field}'")))
}

/// Extract a required string field from `SendTxParams`, returning a `ServiceError`
/// on missing values.
fn require_str_field<'a>(val: Option<&'a str>, field: &str) -> Result<&'a str, ServiceError> {
    val.ok_or_else(|| ServiceError::BadRequest(format!("Missing '{field}'")))
}

/// Parse a `create_portal_lock` transaction kind from params.
fn parse_create_portal_lock(params: &SendTxParams) -> Result<TransactionKind, ServiceError> {
    let cond = params.condition_hash.as_deref()
        .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
    let null = params.nullifier_hash.as_deref()
        .unwrap_or("0x0000000000000000000000000000000000000000000000000000000000000000");
    let timeout = params.timeout_l2_block.ok_or_else(|| {
        ServiceError::BadRequest("Missing 'timeout_l2_block' for create_portal_lock".into())
    })?;
    let condition_hash = parse_hash(cond).ok_or_else(|| {
        ServiceError::BadRequest("Invalid 'condition_hash'".into())
    })?;
    let nullifier_hash = parse_hash(null).ok_or_else(|| {
        ServiceError::BadRequest("Invalid 'nullifier_hash'".into())
    })?;
    Ok(TransactionKind::CreatePortalLock {
        amount: params.amount,
        condition_hash,
        nullifier_hash,
        timeout_l2_block: timeout,
    })
}

/// Parse an `update_lock_condition` transaction kind from params.
fn parse_update_lock_condition(params: &SendTxParams, from: Address) -> Result<TransactionKind, ServiceError> {
    let lock_id = require_hash_field(params.lock_id.as_deref(), "lock_id")?;
    let condition_hash = require_hash_field(params.condition_hash.as_deref(), "condition_hash")?;
    let nullifier_hash = require_hash_field(params.nullifier_hash.as_deref(), "nullifier_hash")?;
    let merchant_addr = params.merchant_address.as_deref()
        .and_then(parse_address)
        .unwrap_or(from); // Default: sender is the one updating
    let merchant_pk = crate::jsonrpc::parse_schnorr_pubkey(&params.public_key)
        .map(|pk| *pk.as_bytes())
        .unwrap_or([0u8; 32]);
    Ok(TransactionKind::UpdateLockCondition {
        lock_id,
        condition_hash,
        nullifier_hash,
        merchant_address: merchant_addr,
        merchant_pubkey: merchant_pk,
    })
}

/// Parse a `settle_portal_lock` transaction kind from params.
fn parse_settle_portal_lock(params: &SendTxParams) -> Result<TransactionKind, ServiceError> {
    let lock_id = require_hash_field(params.lock_id.as_deref(), "lock_id")?;
    let secret_hex = require_str_field(params.merchant_secret.as_deref(), "merchant_secret")?;
    let secret_hex = secret_hex.strip_prefix("0x").unwrap_or(secret_hex);
    let merchant_secret = hex::decode(secret_hex).map_err(|e| {
        ServiceError::BadRequest(format!("Invalid 'merchant_secret' hex: {e}"))
    })?;
    let sig_hex = require_str_field(params.portal_signature.as_deref(), "portal_signature")?;
    let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
    let portal_signature = hex::decode(sig_hex).map_err(|e| {
        ServiceError::BadRequest(format!("Invalid 'portal_signature' hex: {e}"))
    })?;
    let nullifier = require_hash_field(params.nullifier.as_deref(), "nullifier")?;
    Ok(TransactionKind::SettlePortalLock {
        lock_id,
        merchant_secret,
        portal_signature,
        nullifier,
    })
}

/// Parse a `cancel_portal_lock` transaction kind from params.
fn parse_cancel_portal_lock(params: &SendTxParams) -> Result<TransactionKind, ServiceError> {
    let lock_id = require_hash_field(params.lock_id.as_deref(), "lock_id")?;
    Ok(TransactionKind::CancelPortalLock { lock_id })
}

/// Parse a `create_lock_pool` transaction kind from params.
fn parse_create_lock_pool(params: &SendTxParams) -> Result<TransactionKind, ServiceError> {
    let slot_amounts = params
        .slot_amounts
        .as_ref()
        .ok_or_else(|| ServiceError::BadRequest("Missing 'slot_amounts' for create_lock_pool".into()))?;
    if slot_amounts.is_empty() {
        return Err(ServiceError::BadRequest("'slot_amounts' must not be empty".into()));
    }
    let timeout = params.timeout_l2_block.ok_or_else(|| {
        ServiceError::BadRequest("Missing 'timeout_l2_block' for create_lock_pool".into())
    })?;
    Ok(TransactionKind::CreateLockPool {
        slot_amounts: slot_amounts.clone(),
        timeout_l2_block: timeout,
    })
}

/// Parse a `batch_settle_portal` transaction kind from params.
fn parse_batch_settle_portal(params: &SendTxParams) -> Result<TransactionKind, ServiceError> {
    let raw_claims = params
        .claims
        .as_ref()
        .ok_or_else(|| ServiceError::BadRequest("Missing 'claims' for batch_settle_portal".into()))?;
    if raw_claims.is_empty() {
        return Err(ServiceError::BadRequest("'claims' must not be empty".into()));
    }
    let mut claims = Vec::with_capacity(raw_claims.len());
    for (i, c) in raw_claims.iter().enumerate() {
        let lock_id_hex = c["lock_id"].as_str().ok_or_else(|| {
            ServiceError::BadRequest(format!("Missing 'lock_id' in claim[{i}]"))
        })?;
        let lock_id = parse_hash(lock_id_hex).ok_or_else(|| {
            ServiceError::BadRequest(format!("Invalid 'lock_id' in claim[{i}]"))
        })?;
        let secret_hex = c["merchant_secret"].as_str().ok_or_else(|| {
            ServiceError::BadRequest(format!("Missing 'merchant_secret' in claim[{i}]"))
        })?;
        let secret_hex = secret_hex.strip_prefix("0x").unwrap_or(secret_hex);
        let merchant_secret = hex::decode(secret_hex).map_err(|e| {
            ServiceError::BadRequest(format!("Invalid 'merchant_secret' hex in claim[{i}]: {e}"))
        })?;
        let sig_hex = c["portal_signature"].as_str().ok_or_else(|| {
            ServiceError::BadRequest(format!("Missing 'portal_signature' in claim[{i}]"))
        })?;
        let sig_hex = sig_hex.strip_prefix("0x").unwrap_or(sig_hex);
        let portal_signature = hex::decode(sig_hex).map_err(|e| {
            ServiceError::BadRequest(format!("Invalid 'portal_signature' hex in claim[{i}]: {e}"))
        })?;
        let nullifier_hex = c["nullifier"].as_str().ok_or_else(|| {
            ServiceError::BadRequest(format!("Missing 'nullifier' in claim[{i}]"))
        })?;
        let nullifier = parse_hash(nullifier_hex).ok_or_else(|| {
            ServiceError::BadRequest(format!("Invalid 'nullifier' in claim[{i}]"))
        })?;
        claims.push(PortalSettlementClaim {
            lock_id,
            merchant_secret,
            portal_signature,
            nullifier,
        });
    }
    Ok(TransactionKind::BatchSettlePortal { claims })
}

/// Build, validate, and return a signed `Transaction` from the user-supplied
/// `SendTxParams`.  Does NOT add to mempool — caller does that.
pub fn build_transaction(params: &SendTxParams) -> Result<Transaction, ServiceError> {
    let from = parse_address(&params.from)
        .ok_or_else(|| ServiceError::BadRequest("Invalid 'from' address".into()))?;

    let signature = parse_schnorr_signature(&params.signature)
        .map(Signature::Schnorr)
        .ok_or_else(|| {
            ServiceError::BadRequest("Invalid signature (expected 64 hex bytes)".into())
        })?;

    let public_key = parse_schnorr_pubkey(&params.public_key)
        .map(PublicKey::Schnorr)
        .ok_or_else(|| {
            ServiceError::BadRequest("Invalid public_key (expected 32 hex bytes)".into())
        })?;

    let chain_id = params
        .chain_id
        .unwrap_or(brrq_types::transaction::chain_id::TESTNET);

    let kind = match params.tx_type.as_str() {
        "transfer" => {
            let to = parse_address(&params.to).ok_or_else(|| {
                ServiceError::BadRequest("Invalid 'to' address for transfer".into())
            })?;
            TransactionKind::Transfer {
                to,
                amount: params.amount,
            }
        }
        "deploy" => {
            let code_hex = params
                .code
                .as_deref()
                .ok_or_else(|| ServiceError::BadRequest("Missing 'code' for deploy".into()))?;
            let code_hex = code_hex.strip_prefix("0x").unwrap_or(code_hex);
            let code = hex::decode(code_hex)
                .map_err(|e| ServiceError::BadRequest(format!("Invalid code hex: {}", e)))?;
            if code.len() > MAX_CODE_SIZE {
                return Err(ServiceError::BadRequest(format!(
                    "Code too large: {} > {}",
                    code.len(),
                    MAX_CODE_SIZE
                )));
            }
            TransactionKind::Deploy { code }
        }
        "contract_call" => {
            let to = parse_address(&params.to).ok_or_else(|| {
                ServiceError::BadRequest("Invalid 'to' address for contract_call".into())
            })?;
            let call_data = match &params.call_data {
                Some(cd) => {
                    let cd_hex = cd.strip_prefix("0x").unwrap_or(cd);
                    hex::decode(cd_hex).map_err(|e| {
                        ServiceError::BadRequest(format!("Invalid call_data hex: {}", e))
                    })?
                }
                None => Vec::new(),
            };
            if call_data.len() > MAX_CALLDATA_SIZE {
                return Err(ServiceError::BadRequest(format!(
                    "Calldata too large: {} > {}",
                    call_data.len(),
                    MAX_CALLDATA_SIZE
                )));
            }
            TransactionKind::ContractCall {
                to,
                data: call_data,
                value: params.value,
            }
        }
        "create_portal_lock" => parse_create_portal_lock(params)?,
        "update_lock_condition" => parse_update_lock_condition(params, from)?,
        "settle_portal_lock" => parse_settle_portal_lock(params)?,
        "cancel_portal_lock" => parse_cancel_portal_lock(params)?,
        "create_lock_pool" => parse_create_lock_pool(params)?,
        "batch_settle_portal" => parse_batch_settle_portal(params)?,
        other => {
            return Err(ServiceError::BadRequest(format!(
                "Unknown tx_type: {}",
                other
            )));
        }
    };

    let body = TransactionBody {
        from,
        kind,
        nonce: params.nonce,
        gas_limit: params.gas_limit,
        max_fee_per_gas: params.max_fee_per_gas,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas,
        chain_id,
    };
    let tx = Transaction {
        body,
        signature,
        public_key,
    };

    if let Err(e) = tx.verify_signature() {
        // Don't leak crypto error details to client.
        tracing::debug!("Signature verification failed: {}", e);
        return Err(ServiceError::BadRequest(
            "Signature verification failed".into(),
        ));
    }

    Ok(tx)
}

/// Add a transaction to the mempool and emit a pending-tx event.
///
/// Returns the transaction hash hex string.
pub fn submit_to_mempool(ns: &mut NodeState, tx: Transaction) -> Result<String, ServiceError> {
    let tx_hash = tx.hash();
    if let Err(e) = ns.mempool.add(tx.clone()) {
        return Err(ServiceError::BadRequest(format!("Mempool rejected: {}", e)));
    }
    // Emit pending tx event
    if let Some(etx) = &ns.event_tx {
        let kind_str = tx_kind_str(&tx.body.kind);
        let _ = etx.send(crate::events::NodeEvent::PendingTransaction {
            hash: hash_hex(&tx_hash),
            from: addr_hex(&tx.body.from),
            kind: kind_str.to_string(),
        });
    }
    Ok(hash_hex(&tx_hash))
}

// ── Read-only Queries ──────────────────────────────────────────────────────

/// Get the balance for an address.
pub fn get_balance(ns: &NodeState, address: &Address) -> serde_json::Value {
    json!({ "balance": ns.state.balance(address) })
}

/// Get full account details.
pub fn get_account(ns: &NodeState, address: &Address) -> serde_json::Value {
    match ns.state.get_account(address) {
        Some(acc) => json!({
            "address": addr_hex(address),
            "balance": acc.balance,
            "nonce": acc.nonce,
            "code_hash": hash_hex(&acc.code_hash),
            "storage_root": hash_hex(&acc.storage_root),
        }),
        None => json!({
            "address": addr_hex(address),
            "balance": 0,
            "nonce": 0,
        }),
    }
}

/// Reconstruct approximate historical account state at a given block height.
pub fn get_account_at_height(
    ns: &NodeState,
    address: &Address,
    height: u64,
) -> Result<serde_json::Value, ServiceError> {
    if height > ns.height {
        return Err(ServiceError::BadRequest(format!(
            "Requested height {} exceeds current height {}",
            height, ns.height
        )));
    }
    let block = ns.get_block(height).ok_or_else(|| {
        ServiceError::NotFound(format!(
            "Block {} not available (only recent {} blocks in memory)",
            height,
            crate::state::MAX_RECENT_BLOCKS
        ))
    })?;

    let current_balance = ns.state.balance(address);
    let current_nonce = ns.state.get_account(address).map_or(0, |a| a.nonce);

    // Compute net balance delta from blocks after `height` to reconstruct.
    let mut delta: i128 = 0;
    for b in ns.blocks.iter().rev() {
        if b.header.height <= height {
            break;
        }
        for tx in &b.transactions {
            if tx.body.from == *address {
                if let TransactionKind::Transfer { amount, .. } = &tx.body.kind {
                    delta += *amount as i128;
                }
            }
            match &tx.body.kind {
                TransactionKind::Transfer { to, amount } if *to == *address => {
                    delta -= *amount as i128;
                }
                TransactionKind::ContractCall { to, value, .. } if *to == *address => {
                    delta -= *value as i128;
                }
                _ => {}
            }
        }
    }
    let historical_balance = (current_balance as i128 + delta).max(0) as u64;

    Ok(json!({
        "address": addr_hex(address),
        "height": height,
        "block_hash": hash_hex(&block.hash()),
        "balance": historical_balance,
        "current_nonce": current_nonce,
        "note": "Historical balance is approximate (reconstructed from transaction deltas; does not account for gas costs or contract interactions)",
    }))
}

/// Get network statistics.
pub fn get_stats(ns: &NodeState) -> serde_json::Value {
    json!({
        "block_height": ns.height,
        "tx_count": ns.tx_total,
        "block_count": ns.height,
        "validator_count": ns.staking.validators.len(),
        "total_stake": ns.staking.validators.values().map(|v| v.total_stake()).sum::<u64>(),
        "mempool_size": ns.mempool.len(),
        "proof_count": ns.proof_records.len(),
    })
}

/// Get epoch information.
pub fn get_epoch_info(ns: &NodeState) -> serde_json::Value {
    json!({
        "current_epoch": ns.epoch.current_epoch,
        "epoch_start_height": ns.epoch.epoch_start_height,
        "epoch_length": ns.epoch.epoch_length,
    })
}

/// Get validators with pagination.
pub fn get_validators(ns: &NodeState, limit: usize, offset: usize) -> serde_json::Value {
    let total = ns.staking.validators.len();
    let limit = limit.min(200);
    let offset = offset.min(total);
    let validators: Vec<serde_json::Value> = ns
        .staking
        .validators
        .values()
        .skip(offset)
        .take(limit)
        .map(|v| {
            json!({
                "address": addr_hex(&v.address),
                "stake": v.stake,
                "total_stake": v.total_stake(),
                "status": format!("{:?}", v.status),
            })
        })
        .collect();
    json!({
        "validators": validators,
        "total": total,
        "limit": limit,
        "offset": offset,
    })
}

/// Get bridge status.
pub fn get_bridge_status(ns: &NodeState) -> serde_json::Value {
    let status = ns.bridge.status();
    json!({
        "total_locked": status.total_locked,
        "total_minted": status.total_minted,
        "pending_deposits": status.pending_deposits,
        "pending_withdrawals": status.pending_withdrawals,
        "paused": status.paused,
    })
}

/// Get the latest STARK proof record.
pub fn get_latest_proof(ns: &NodeState) -> serde_json::Value {
    match ns.proof_records.last() {
        Some(record) => json!({
            "block_range_start": record.block_range.0,
            "block_range_end": record.block_range.1,
            "verified": record.verified,
        }),
        None => serde_json::Value::Null,
    }
}

/// Get L1 status.
pub fn get_l1_status(ns: &NodeState) -> serde_json::Value {
    let last_anchor_l2_height = ns.l1_anchors.last().map(|a| a.l2_height);
    json!({
        "connected": ns.l1_connected,
        "l1_height": ns.l1_height,
        "network": ns.l1_network.as_deref().unwrap_or("none"),
        "anchor_count": ns.l1_anchors.len() as u64,
        "last_anchor_l2_height": last_anchor_l2_height,
    })
}

/// Get L1 anchors with pagination.
pub fn get_l1_anchors(ns: &NodeState, limit: usize, offset: usize) -> serde_json::Value {
    let total = ns.l1_anchors.len();
    let limit = limit.min(100);
    let start = offset.min(total);
    let end = (start + limit).min(total);

    let anchors: Vec<serde_json::Value> = ns.l1_anchors[start..end]
        .iter()
        .map(|a| anchor_to_json(a))
        .collect();

    json!({
        "anchors": anchors,
        "total": total,
        "limit": limit,
        "offset": offset,
    })
}

/// Get a specific anchor by L2 height.
pub fn get_l1_anchor_by_height(
    ns: &NodeState,
    height: u64,
) -> Result<serde_json::Value, ServiceError> {
    ns.l1_anchors
        .iter()
        .find(|a| a.l2_height == height)
        .map(|a| anchor_to_json(a))
        .ok_or_else(|| ServiceError::NotFound(format!("Anchor at L2 height {} not found", height)))
}

fn anchor_to_json(a: &brrq_bitcoin::L1AnchorRecord) -> serde_json::Value {
    json!({
        "l1_tx_id": hex::encode(a.l1_tx_id),
        "l1_height": a.l1_height,
        "l2_height": a.l2_height,
        "state_root": hash_hex(&a.state_root),
        "proof_hash": hash_hex(&a.proof_hash),
        "timestamp": a.timestamp,
    })
}

/// List all stored proofs.
pub fn list_proofs(ns: &NodeState, limit: usize, offset: usize) -> serde_json::Value {
    let limit = limit.min(1000);
    let all = ns.bridge.proof_store.all_proofs();
    let total = all.len();
    let proofs: Vec<serde_json::Value> = all
        .iter()
        .skip(offset)
        .take(limit)
        .map(|p| proof_record_to_json(p))
        .collect();
    json!({
        "proofs": proofs,
        "total": total,
        "limit": limit,
        "offset": offset,
    })
}

/// Get proof covering a specific L2 height.
pub fn get_proof_by_height(ns: &NodeState, height: u64) -> Result<serde_json::Value, ServiceError> {
    ns.bridge
        .proof_store
        .find_proof_for_height(height)
        .map(|p| proof_record_to_json(p))
        .ok_or_else(|| ServiceError::NotFound(format!("No proof found covering height {}", height)))
}

fn proof_record_to_json(p: &brrq_bridge::StoredProof) -> serde_json::Value {
    json!({
        "block_range_start": p.block_range.0,
        "block_range_end": p.block_range.1,
        "stark_proof_hash": hash_hex(&p.stark_proof_hash),
        "initial_state_root": hash_hex(&p.initial_state_root),
        "final_state_root": hash_hex(&p.final_state_root),
        "stored_at": p.stored_at,
        "l1_anchored": p.l1_anchor_tx.is_some(),
    })
}

/// List all challenges.
pub fn list_challenges(ns: &NodeState, limit: usize, offset: usize) -> serde_json::Value {
    let limit = limit.min(1000);
    let all = ns.bridge.challenge_manager.all_challenges();
    let challenges: Vec<serde_json::Value> = all
        .iter()
        .skip(offset)
        .take(limit)
        .map(|c| {
            json!({
                "challenge_id": hash_hex(&c.challenge_id),
                "challenger": addr_hex(&c.challenger),
                "status": format!("{:?}", c.status),
                "submitted_at_height": c.submitted_at_height,
            })
        })
        .collect();
    let stats = ns.bridge.challenge_manager.stats();
    json!({
        "challenges": challenges,
        "total": stats.total,
        "limit": limit,
        "offset": offset,
        "pending": stats.pending,
        "proven": stats.proven,
        "dismissed": stats.dismissed,
        "expired": stats.expired,
    })
}

/// List all registered operators.
pub fn list_operators(ns: &NodeState, limit: usize, offset: usize) -> serde_json::Value {
    let limit = limit.min(1000);
    let all = ns.bridge.operator_manager.all_operators();
    let total = all.len();
    let operators: Vec<serde_json::Value> = all
        .iter()
        .skip(offset)
        .take(limit)
        .map(|op| {
            json!({
                "address": addr_hex(&op.address),
                "total_fronted": op.total_fronted,
                "total_reimbursed": op.total_reimbursed,
                "active_withdrawals": op.active_withdrawals.len(),
                "registered_at": op.registered_at,
            })
        })
        .collect();
    json!({
        "operators": operators,
        "total": total,
        "limit": limit,
        "offset": offset,
    })
}

// ── Challenge Submission ───────────────────────────────────────────────────

/// Parse challenge type from JSON body fields.
pub fn parse_challenge_type(
    body: &serde_json::Value,
) -> Result<(brrq_bridge::ChallengeType, &str), ServiceError> {
    let ct_str = body
        .get("challenge_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let challenge_type = match ct_str {
        "InvalidStateRoot" => {
            let claimed = body
                .get("claimed_state_root")
                .and_then(|v| v.as_str())
                .and_then(parse_hash)
                .ok_or_else(|| ServiceError::BadRequest("invalid claimed_state_root".into()))?;
            let actual = body
                .get("actual_state_root")
                .and_then(|v| v.as_str())
                .and_then(parse_hash)
                .ok_or_else(|| ServiceError::BadRequest("invalid actual_state_root".into()))?;
            let l2_height = body
                .get("l2_height")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| ServiceError::BadRequest("missing l2_height".into()))?;
            brrq_bridge::ChallengeType::InvalidStateRoot {
                claimed_state_root: claimed,
                actual_state_root: actual,
                l2_height,
            }
        }
        _ => {
            return Err(ServiceError::BadRequest(format!(
                "unsupported challenge_type: '{}' (supported: InvalidStateRoot)",
                ct_str,
            )));
        }
    };
    Ok((challenge_type, ct_str))
}

/// Submit a challenge. Returns `(challenge_id_hex, "Pending")`.
pub fn submit_challenge(
    ns: &mut NodeState,
    challenger: Address,
    challenger_hex: &str,
    challenge_type: brrq_bridge::ChallengeType,
    ct_str: &str,
) -> Result<serde_json::Value, ServiceError> {
    // Challenge bond is required. For API calls, use the minimum bond.
    // In production, the bond amount should come from the API request payload.
    match ns.bridge.submit_challenge(challenger, challenge_type, brrq_bridge::challenge::CHALLENGE_BOND) {
        Ok(id) => {
            if let Some(ref event_tx) = ns.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::ChallengeSubmitted {
                    challenge_id: hash_hex(&id),
                    challenge_type: ct_str.to_string(),
                    challenger: challenger_hex.to_string(),
                });
            }
            Ok(json!({
                "challenge_id": hash_hex(&id),
                "status": "Pending",
            }))
        }
        Err(e) => Err(ServiceError::ServerError(format!(
            "challenge submission failed: {e}"
        ))),
    }
}

/// Respond to a challenge (operator defense).
pub fn respond_to_challenge(
    ns: &mut NodeState,
    challenge_id: &Hash256,
    proof_hash: Hash256,
    correct_state_root: Hash256,
    responder: Address,
    proof_hex: &str,
) -> Result<serde_json::Value, ServiceError> {
    let proof_bytes = hex::decode(proof_hex.strip_prefix("0x").unwrap_or(proof_hex))
        .map_err(|_| ServiceError::BadRequest("invalid proof_hex encoding".into()))?;

    let proof = brrq_prover::types::StarkProof::from_bytes(&proof_bytes)
        .map_err(|e| ServiceError::BadRequest(format!("invalid proof: {e}")))?;

    let response = brrq_bridge::ChallengeResponse {
        proof_hash,
        correct_state_root,
        responder,
    };

    match ns.bridge.respond_to_challenge(challenge_id, response, &proof) {
        Ok(status) => {
            let status_str = format!("{status:?}");
            Ok(json!({
                "challenge_id": hash_hex(challenge_id),
                "status": status_str,
            }))
        }
        Err(e) => Err(ServiceError::ServerError(format!(
            "challenge response failed: {e}"
        ))),
    }
}

// ── MEV ────────────────────────────────────────────────────────────────────

/// Submit an encrypted MEV envelope.
#[cfg(feature = "mev-protection")]
pub fn submit_mev_envelope(
    ns: &mut NodeState,
    envelope_hex: &str,
) -> Result<serde_json::Value, ServiceError> {
    // Reject oversized hex input before allocation (max 1 MB decoded).
    const MAX_ENVELOPE_HEX_LEN: usize = 2 * 1024 * 1024;
    if envelope_hex.len() > MAX_ENVELOPE_HEX_LEN {
        return Err(ServiceError::BadRequest("envelope_hex too large".into()));
    }

    let envelope_bytes = hex::decode(envelope_hex.strip_prefix("0x").unwrap_or(envelope_hex))
        .map_err(|_| ServiceError::BadRequest("invalid hex encoding".into()))?;
    let envelope: brrq_types::mev::EncryptedEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|_| ServiceError::BadRequest("invalid envelope format".into()))?;

    if ns.mev_mode == crate::state::MevActivationMode::Disabled {
        return Err(ServiceError::ServerError(
            "MEV protection is not enabled".into(),
        ));
    }

    match ns.mev_mempool.submit(envelope) {
        Ok(hash) => {
            let phase = format!("{}", ns.mev_mempool.phase());
            Ok(json!({
                "hash": hash_hex(&hash),
                "phase": phase,
            }))
        }
        Err(e) => Err(ServiceError::ServerError(format!("envelope rejected: {e}"))),
    }
}

/// Get MEV mempool status.
#[cfg(feature = "mev-protection")]
pub fn get_mev_status(ns: &NodeState) -> serde_json::Value {
    json!({
        "mode": format!("{:?}", ns.mev_mode),
        "phase": format!("{}", ns.mev_mempool.phase()),
        "pending_count": ns.mev_mempool.len(),
        "byte_usage": ns.mev_mempool.byte_usage(),
        "epoch": ns.mev_mempool.epoch(),
    })
}

/// Get the current epoch encryption key.
/// Epoch key is not exposed. Returns only epoch number and key commitment.
pub fn get_mev_epoch_key(ns: &NodeState) -> serde_json::Value {
    // Only expose the commitment (hash of key), not the key itself.
    // This allows clients to verify they have the right epoch but not decrypt.
    // Use L1-anchored derivation when available
    let epoch_key = if let Some(l1_hash) = ns.l1_block_hash {
        let anchor = brrq_crypto::hash::Hash256::from_bytes(l1_hash);
        brrq_crypto::encryption::EpochKey::derive_with_anchor(&ns.epoch.epoch_seed, ns.epoch.current_epoch, &anchor)
    } else {
        // Fallback: inline the derivation logic (derive() is now pub(crate) in brrq-crypto)
        let mut hasher = brrq_crypto::hash::Hasher::new();
        hasher.update(ns.epoch.epoch_seed.as_bytes());
        hasher.update(&ns.epoch.current_epoch.to_le_bytes());
        let hash = hasher.finalize();
        brrq_crypto::encryption::EpochKey::from_bytes(*hash.as_bytes())
    };
    let commitment = brrq_crypto::hash::Hasher::hash(epoch_key.as_bytes());
    json!({
        "epoch": ns.epoch.current_epoch,
        "key_commitment": format!("0x{}", hex::encode(commitment.as_bytes())),
        "note": "Epoch key is threshold-distributed. Use brrq_getMevKeyShare to request your share."
    })
}

// ── Governance ─────────────────────────────────────────────────────────────

/// Governance string field length limits .
const MAX_DESCRIPTION_LEN: usize = 5000;
const MAX_PARAMETER_LEN: usize = 100;
const MAX_AMENDMENT_LEN: usize = 10_000;

/// Parse a proposal type from JSON fields.
pub fn parse_proposal_type(
    body: &serde_json::Value,
) -> Result<(brrq_consensus::governance::ProposalType, &str), ServiceError> {
    let pt = body
        .get("proposal_type")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let proposal_type = match pt {
        "TechnicalUpdate" => {
            let desc = body
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if desc.len() > MAX_DESCRIPTION_LEN {
                return Err(ServiceError::BadRequest(format!(
                    "description too long (max {} chars)",
                    MAX_DESCRIPTION_LEN
                )));
            }
            brrq_consensus::governance::ProposalType::TechnicalUpdate {
                description: desc.to_string(),
            }
        }
        "FeeChange" => {
            let param = body.get("parameter").and_then(|v| v.as_str()).unwrap_or("");
            if param.len() > MAX_PARAMETER_LEN {
                return Err(ServiceError::BadRequest(format!(
                    "parameter name too long (max {} chars)",
                    MAX_PARAMETER_LEN
                )));
            }
            let old_val = body.get("old_value").and_then(|v| v.as_u64()).unwrap_or(0);
            let new_val = body.get("new_value").and_then(|v| v.as_u64()).unwrap_or(0);
            brrq_consensus::governance::ProposalType::FeeChange {
                parameter: param.to_string(),
                old_value: old_val,
                new_value: new_val,
            }
        }
        "SlashingChange" => {
            let reason = body.get("reason").and_then(|v| v.as_str()).unwrap_or("");
            if reason.len() > MAX_DESCRIPTION_LEN {
                return Err(ServiceError::BadRequest(format!(
                    "reason too long (max {} chars)",
                    MAX_DESCRIPTION_LEN
                )));
            }
            let old_bp = body.get("old_bp").and_then(|v| v.as_u64()).unwrap_or(0);
            let new_bp = body.get("new_bp").and_then(|v| v.as_u64()).unwrap_or(0);
            brrq_consensus::governance::ProposalType::SlashingChange {
                reason: reason.to_string(),
                old_bp,
                new_bp,
            }
        }
        "Constitutional" => {
            let amendment = body.get("amendment").and_then(|v| v.as_str()).unwrap_or("");
            if amendment.len() > MAX_AMENDMENT_LEN {
                return Err(ServiceError::BadRequest(format!(
                    "amendment too long (max {} chars)",
                    MAX_AMENDMENT_LEN
                )));
            }
            brrq_consensus::governance::ProposalType::Constitutional {
                amendment: amendment.to_string(),
            }
        }
        _ => {
            return Err(ServiceError::BadRequest(format!(
                "unsupported proposal_type: '{}' (supported: TechnicalUpdate, FeeChange, SlashingChange, Constitutional)",
                pt,
            )));
        }
    };
    Ok((proposal_type, pt))
}

/// Submit a governance proposal. Returns `{ proposal_id, status }`.
pub fn submit_proposal(
    ns: &mut NodeState,
    proposer: Address,
    proposer_hex: &str,
    proposal_type: brrq_consensus::governance::ProposalType,
    pt_str: &str,
) -> Result<serde_json::Value, ServiceError> {
    let height = ns.height;
    let ns_ref = &mut *ns;
    match ns_ref
        .governance
        .submit_proposal(proposer, proposal_type, height, &ns_ref.staking)
    {
        Ok(id) => {
            if let Some(ref event_tx) = ns_ref.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::GovernanceProposalSubmitted {
                    proposal_id: hash_hex(&id),
                    proposer: proposer_hex.to_string(),
                    proposal_type: pt_str.to_string(),
                });
            }
            Ok(json!({
                "proposal_id": hash_hex(&id),
                "status": "Active",
            }))
        }
        Err(e) => Err(ServiceError::ServerError(format!("proposal failed: {e}"))),
    }
}

/// Parse vote string into Vote enum.
pub fn parse_vote(vote_str: &str) -> Result<brrq_consensus::governance::Vote, ServiceError> {
    match vote_str {
        "Yes" => Ok(brrq_consensus::governance::Vote::Yes),
        "No" => Ok(brrq_consensus::governance::Vote::No),
        "Abstain" => Ok(brrq_consensus::governance::Vote::Abstain),
        _ => Err(ServiceError::BadRequest(format!(
            "invalid vote: {}",
            vote_str
        ))),
    }
}

/// Vote on a governance proposal.
pub fn vote_on_proposal(
    ns: &mut NodeState,
    proposal_id: &Hash256,
    voter: Address,
    voter_hex: &str,
    vote: brrq_consensus::governance::Vote,
    vote_str: &str,
    chamber: &str,
) -> Result<serde_json::Value, ServiceError> {
    let height = ns.height;
    let ns_ref = &mut *ns;
    let result = match chamber {
        "sequencer" => {
            ns_ref
                .governance
                .vote_sequencer(proposal_id, voter, vote, &ns_ref.staking, height)
        }
        _ => ns_ref
            .governance
            .vote_user(proposal_id, voter, vote, height),
    };

    match result {
        Ok(()) => {
            if let Some(ref event_tx) = ns_ref.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::GovernanceVoteCast {
                    proposal_id: hash_hex(proposal_id),
                    voter: voter_hex.to_string(),
                    chamber: chamber.to_string(),
                    vote: vote_str.to_string(),
                });
            }
            Ok(json!({ "status": "vote_recorded" }))
        }
        Err(e) => Err(ServiceError::ServerError(format!("vote failed: {e}"))),
    }
}

/// List all governance proposals.
pub fn list_proposals(ns: &NodeState) -> serde_json::Value {
    let proposals: Vec<serde_json::Value> = ns
        .governance
        .all_proposals()
        .iter()
        .map(|p| {
            json!({
                "id": hash_hex(&p.id),
                "proposer": addr_hex(&p.proposer),
                "status": format!("{:?}", p.status),
                "submitted_at": p.submitted_at,
                "voting_ends_at": p.voting_ends_at,
                "sequencer_yes_stake": p.sequencer_yes_stake,
                "sequencer_no_stake": p.sequencer_no_stake,
                "user_yes_power": p.user_yes_power,
                "user_no_power": p.user_no_power,
            })
        })
        .collect();
    json!({ "proposals": proposals })
}

/// Get governance statistics.
pub fn get_governance_stats(ns: &NodeState) -> serde_json::Value {
    let stats = ns.governance.stats();
    json!({
        "total_proposals": stats.total_proposals,
        "active_proposals": stats.active_proposals,
        "passed_proposals": stats.passed_proposals,
        "failed_proposals": stats.failed_proposals,
        "executed_proposals": stats.executed_proposals,
        "total_unique_voters": stats.total_unique_voters,
    })
}

// ── Sequencer Registration ─────────────────────────────────────────────────

/// Parse a region string into a `Region` enum.
#[cfg(feature = "sequencer-rotation")]
pub fn parse_region(region_str: &str) -> brrq_consensus::registration::Region {
    match region_str {
        "NorthAmerica" => brrq_consensus::registration::Region::NorthAmerica,
        "SouthAmerica" => brrq_consensus::registration::Region::SouthAmerica,
        "Europe" => brrq_consensus::registration::Region::Europe,
        "Africa" => brrq_consensus::registration::Region::Africa,
        "MiddleEast" => brrq_consensus::registration::Region::MiddleEast,
        "Asia" => brrq_consensus::registration::Region::Asia,
        "Oceania" => brrq_consensus::registration::Region::Oceania,
        _ => brrq_consensus::registration::Region::Unknown,
    }
}

/// Register a new sequencer.
#[cfg(feature = "sequencer-rotation")]
pub fn register_sequencer(
    ns: &mut NodeState,
    address: Address,
    addr_hex_str: &str,
    self_stake: u64,
    region: brrq_consensus::registration::Region,
    region_str: &str,
    commission_bp: u64,
) -> Result<serde_json::Value, ServiceError> {
    let request = brrq_consensus::registration::RegistrationRequest {
        address,
        self_stake,
        region,
        commission_bp,
        eots_pubkey: None,
    };

    let height = ns.height;
    let ns_ref = &mut *ns;
    match ns_ref
        .registration
        .register(request, &mut ns_ref.staking, height)
    {
        Ok(()) => {
            if let Some(ref event_tx) = ns_ref.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::SequencerRegistered {
                    address: addr_hex_str.to_string(),
                    stake: self_stake,
                    region: region_str.to_string(),
                });
            }
            Ok(json!({ "status": "registered" }))
        }
        Err(e) => Err(ServiceError::ServerError(format!(
            "registration failed: {e}"
        ))),
    }
}

/// List all registered sequencers.
#[cfg(feature = "sequencer-rotation")]
pub fn list_sequencers(ns: &NodeState) -> serde_json::Value {
    let sequencers: Vec<serde_json::Value> = ns
        .registration
        .all_sequencers()
        .iter()
        .map(|s| {
            json!({
                "address": addr_hex(&s.address),
                "self_stake": s.self_stake,
                "region": format!("{:?}", s.region),
                "blocks_produced": s.blocks_produced,
                "blocks_missed": s.blocks_missed,
                "total_delegated": s.total_delegated,
                "commission_bp": s.commission_bp,
                "accepting_delegations": s.accepting_delegations,
            })
        })
        .collect();
    json!({
        "sequencers": sequencers,
        "total": sequencers.len(),
    })
}

/// Delegate stake to a sequencer.
#[cfg(feature = "sequencer-rotation")]
pub fn delegate_stake(
    ns: &mut NodeState,
    delegator: Address,
    delegator_hex: &str,
    sequencer: Address,
    seq_hex: &str,
    amount: u64,
) -> Result<serde_json::Value, ServiceError> {
    let request = brrq_consensus::registration::DelegationRequest {
        delegator,
        sequencer,
        amount,
    };
    let height = ns.height;
    let ns_ref = &mut *ns;
    match ns_ref
        .registration
        .delegate(request, &mut ns_ref.staking, height)
    {
        Ok(()) => {
            if let Some(ref event_tx) = ns_ref.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::StakeDelegated {
                    delegator: delegator_hex.to_string(),
                    sequencer: seq_hex.to_string(),
                    amount,
                });
            }
            Ok(json!({ "status": "delegated" }))
        }
        Err(e) => Err(ServiceError::ServerError(format!("delegation failed: {e}"))),
    }
}

/// Undelegate stake from a sequencer.
#[cfg(feature = "sequencer-rotation")]
pub fn undelegate_stake(
    ns: &mut NodeState,
    delegator: Address,
    sequencer: Address,
) -> Result<serde_json::Value, ServiceError> {
    let current_height = ns.height;
    let ns_ref = &mut *ns;
    match ns_ref
        .registration
        .undelegate(delegator, sequencer, &mut ns_ref.staking, current_height)
    {
        Ok(amount) => {
            if let Some(ref event_tx) = ns_ref.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::StakeUndelegated {
                    delegator: addr_hex(&delegator),
                    sequencer: addr_hex(&sequencer),
                    amount,
                });
            }
            Ok(json!({
                "status": "undelegated",
                "amount": amount,
            }))
        }
        Err(e) => Err(ServiceError::ServerError(format!(
            "undelegation failed: {e}"
        ))),
    }
}

/// Get sequencer region distribution.
#[cfg(feature = "sequencer-rotation")]
pub fn get_sequencer_regions(ns: &NodeState) -> serde_json::Value {
    let regions = ns.registration.region_stats();
    let region_data: Vec<serde_json::Value> = regions
        .iter()
        .map(|(r, count)| {
            json!({
                "region": format!("{:?}", r),
                "count": count,
                "has_capacity": ns.registration.region_has_capacity(r),
            })
        })
        .collect();
    json!({
        "regions": region_data,
        "total_sequencers": ns.registration.count(),
    })
}

// ── Prover Pools ───────────────────────────────────────────────────────────

/// Create a prover pool.
#[cfg(feature = "prover-pools")]
pub fn create_prover_pool(
    ns: &mut NodeState,
    coordinator: Address,
    coord_hex: &str,
    name: String,
    fee_bp: u64,
) -> Result<serde_json::Value, ServiceError> {
    let height = ns.height;
    let pool_name = name.clone();
    match ns
        .prover_pools
        .create_pool(coordinator, name, fee_bp, height)
    {
        Ok(pool_id) => {
            if let Some(ref event_tx) = ns.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::ProverPoolCreated {
                    pool_id: hash_hex(&pool_id),
                    coordinator: coord_hex.to_string(),
                    name: pool_name,
                });
            }
            Ok(json!({
                "pool_id": hash_hex(&pool_id),
                "status": "created",
            }))
        }
        Err(e) => Err(ServiceError::ServerError(format!(
            "pool creation failed: {e}"
        ))),
    }
}

/// Join a prover pool.
#[cfg(feature = "prover-pools")]
pub fn join_prover_pool(
    ns: &mut NodeState,
    pool_id: Hash256,
    member: Address,
    member_hex: &str,
    weight: u64,
) -> Result<serde_json::Value, ServiceError> {
    let height = ns.height;
    match ns.prover_pools.join_pool(pool_id, member, weight, height) {
        Ok(()) => {
            if let Some(ref event_tx) = ns.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::ProverPoolJoined {
                    pool_id: hash_hex(&pool_id),
                    member: member_hex.to_string(),
                });
            }
            Ok(json!({ "status": "joined" }))
        }
        Err(e) => Err(ServiceError::ServerError(format!("join failed: {e}"))),
    }
}

/// List all prover pools.
#[cfg(feature = "prover-pools")]
pub fn list_prover_pools(ns: &NodeState) -> serde_json::Value {
    let pools: Vec<serde_json::Value> = ns
        .prover_pools
        .all_pools()
        .iter()
        .map(|p| {
            json!({
                "pool_id": hash_hex(&p.pool_id),
                "coordinator": addr_hex(&p.coordinator),
                "name": p.name,
                "member_count": p.members.len(),
                "proofs_generated": p.proofs_generated,
                "total_reward": p.total_reward,
                "coordinator_fee_bp": p.coordinator_fee_bp,
                "open": p.open,
            })
        })
        .collect();
    json!({
        "pools": pools,
        "total": pools.len(),
    })
}

/// Get prover pool statistics.
#[cfg(feature = "prover-pools")]
pub fn get_prover_pool_stats(ns: &NodeState) -> serde_json::Value {
    let stats = ns.prover_pools.stats();
    json!({
        "total_pools": stats.total_pools,
        "total_members": stats.total_members,
        "total_proofs": stats.total_proofs,
        "total_rewards": stats.total_rewards,
        "pending_tasks": stats.pending_tasks,
    })
}

// ── Faucet ─────────────────────────────────────────────────────────────────

/// Execute a faucet drip to the given recipient.
pub fn faucet_drip(
    ns: &mut NodeState,
    recipient: Address,
) -> Result<serde_json::Value, ServiceError> {
    let faucet_addr = match &ns.faucet_address {
        Some(addr) => *addr,
        None => return Err(ServiceError::BadRequest("Faucet not configured".into())),
    };

    // Check cooldown
    let cooldown_secs = ns.faucet_cooldown_secs;
    if let Some(last) = ns.faucet_cooldowns.get(&recipient) {
        let elapsed = last.elapsed().as_secs();
        if elapsed < cooldown_secs {
            let remaining = cooldown_secs - elapsed;
            return Err(ServiceError::BadRequest(format!(
                "Cooldown active — try again in {} seconds",
                remaining
            )));
        }
    }

    // Prune expired cooldowns periodically (prevent unbounded HashMap growth)
    if ns.faucet_cooldowns.len() > 10_000 {
        let cooldown_dur = std::time::Duration::from_secs(cooldown_secs);
        ns.faucet_cooldowns
            .retain(|_, last| last.elapsed() < cooldown_dur);
    }

    let drip = ns.faucet_drip_amount;
    let faucet_balance = ns.state.balance(&faucet_addr);
    if faucet_balance < drip {
        return Err(ServiceError::BadRequest("Faucet depleted".into()));
    }

    // P2P-FIX: Faucet creates a signed Transfer transaction that enters the
    // mempool and gets included in the next block. This ensures ALL nodes
    // (sequencer + followers) execute the same transaction and compute the
    // same state root. Direct state modification caused state root divergence.
    let faucet_kp = ns.faucet_keypair.as_ref().ok_or_else(|| {
        ServiceError::ServerError(
            "Faucet keypair not configured. Ensure genesis faucet address matches node key.".into()
        )
    })?.clone();

    let faucet_nonce = ns.state.nonce(&faucet_addr);
    let chain_id = ns.chain_id;

    let body = brrq_types::transaction::TransactionBody {
        from: faucet_addr,
        kind: brrq_types::transaction::TransactionKind::Transfer {
            to: recipient,
            amount: drip,
        },
        nonce: faucet_nonce,
        gas_limit: 21_000,
        max_fee_per_gas: 100, // High enough for any base_fee on testnet
        max_priority_fee_per_gas: 1,
        chain_id,
    };

    let body_hash = body.hash();
    let sig = faucet_kp
        .sign(&body_hash)
        .map_err(|e| ServiceError::ServerError(format!("Faucet sign failed: {e}")))?;

    let tx = brrq_types::transaction::Transaction {
        body,
        signature: brrq_types::signature::Signature::Schnorr(sig),
        public_key: brrq_types::signature::PublicKey::Schnorr(*faucet_kp.public_key()),
    };

    let tx_hash = tx.hash();

    // Submit to mempool — will be included in next block
    submit_to_mempool(ns, tx)
        .map_err(|e| ServiceError::ServerError(format!("Faucet mempool submit: {:?}", e)))?;

    // Record cooldown
    ns.faucet_cooldowns.insert(recipient, Instant::now());

    Ok(json!({
        "tx_hash": format!("0x{}", hex::encode(tx_hash.as_bytes())),
        "amount": drip,
        "recipient": addr_hex(&recipient),
    }))
}
