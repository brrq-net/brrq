//! JSON-RPC 2.0 handler — backward compatible with existing brrq clients.
//!
//! Handlers in this module are thin transport wrappers around shared service
//! functions in [`crate::services`].  Business logic lives in services.rs.

use axum::Json;
use axum::extract::{ConnectInfo, State};
use axum::Extension;
use serde::{Deserialize, Serialize};

use brrq_crypto::hash::Hash256;
use brrq_crypto::schnorr::{SchnorrPublicKey, SchnorrSignature};
use brrq_types::address::Address;
use brrq_types::transaction::TransactionKind;

use crate::middleware::EndpointRateLimiter;
use crate::services;
use crate::services::ServiceError;
use crate::state::AppState;
use crate::state::SharedState;

/// JSON-RPC 2.0 request.
#[derive(Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
    pub id: serde_json::Value,
}

/// JSON-RPC 2.0 response.
#[derive(Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: serde_json::Value,
}

/// JSON-RPC error object.
#[derive(Debug, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

impl RpcResponse {
    pub fn success(id: serde_json::Value, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: Some(result),
            error: None,
            id,
        }
    }
    pub fn error(id: serde_json::Value, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            result: None,
            error: Some(RpcError { code, message }),
            id,
        }
    }
}

/// Convert a `ServiceError` into an `RpcResponse`.
///
/// `ServerError` details are logged server-side but never exposed to
/// the client — the response carries only a generic message to prevent
/// information leakage (stack traces, internal paths, DB errors, etc.).
fn service_err(id: serde_json::Value, e: ServiceError) -> RpcResponse {
    match &e {
        ServiceError::ServerError(detail) => {
            // Log the real detail for operators, return opaque message to client.
            tracing::error!("JSON-RPC internal error: {}", detail);
            RpcResponse::error(id, e.rpc_code(), "Internal server error".to_string())
        }
        _ => RpcResponse::error(id, e.rpc_code(), e.message().to_string()),
    }
}

/// Maximum number of requests allowed in a JSON-RPC batch.
const MAX_BATCH_SIZE: usize = 50;

/// Classify JSON-RPC methods into rate-limiting tiers.
///
/// - **Strict**: resource-intensive or write methods (faucet, sendTransaction, bridge ops)
/// - **Relaxed**: read-only queries (getBalance, blockHeight, chainId)
/// - **Standard**: everything else (default)
fn method_rate_tier(method: &str) -> RateTier {
    match method {
        // Strict: write/expensive operations
        "brrq_faucetDrip"
        | "brrq_sendTransaction"
        | "brrq_bridgeDeposit"
        | "brrq_bridgeWithdraw"
        | "brrq_submitProof"
        | "brrq_submitChallenge"
        | "brrq_submitProposal"
        | "brrq_voteOnProposal"
        | "brrq_permissionlessWithdraw"
        | "brrq_sendEncryptedTx"
        | "brrq_initFederation" => RateTier::Strict,
        // Relaxed: cheap read-only queries
        "brrq_getBalance"
        | "brrq_getNonce"
        | "brrq_blockHeight"
        | "brrq_chainId"
        | "brrq_getStateRoot"
        | "brrq_getEpochInfo"
        | "brrq_bridgeStatus"
        | "brrq_getL1Status" => RateTier::Relaxed,
        // Standard: everything else
        _ => RateTier::Standard,
    }
}

#[derive(Clone, Copy)]
enum RateTier {
    Strict,
    Standard,
    Relaxed,
}

/// Handle a JSON-RPC 2.0 POST request (single or batch).
pub async fn handle_jsonrpc(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Extension(endpoint_limiter): Extension<EndpointRateLimiter>,
    State(app): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    // JSON-RPC 2.0 batch: array of requests
    if let Some(arr) = req.as_array() {
        if arr.is_empty() {
            return Json(
                serde_json::to_value(RpcResponse::error(
                    serde_json::Value::Null,
                    -32600,
                    "Invalid Request: empty batch".into(),
                ))
                // SAFETY: RpcResponse contains only String/Value/i32 fields —
                // serde_json serialization to Value cannot fail for these types.
                .expect("RpcResponse serialization is infallible"),
            );
        }
        if arr.len() > MAX_BATCH_SIZE {
            return Json(
                serde_json::to_value(RpcResponse::error(
                    serde_json::Value::Null,
                    -32600,
                    format!(
                        "Batch too large: {} requests (max {})",
                        arr.len(),
                        MAX_BATCH_SIZE
                    ),
                ))
                .expect("RpcResponse serialization is infallible"),
            );
        }
        let mut responses = Vec::with_capacity(arr.len());
        for item in arr {
            let resp = dispatch_single(item.clone(), &app, addr.ip(), &endpoint_limiter).await;
            responses
                .push(serde_json::to_value(resp).expect("RpcResponse serialization is infallible"));
        }
        return Json(serde_json::Value::Array(responses));
    }

    // Single request
    let resp = dispatch_single(req, &app, addr.ip(), &endpoint_limiter).await;
    Json(serde_json::to_value(resp).expect("RpcResponse serialization is infallible"))
}

/// Parse and dispatch a single JSON-RPC request.
async fn dispatch_single(
    req: serde_json::Value,
    app: &AppState,
    caller_ip: std::net::IpAddr,
    endpoint_limiter: &EndpointRateLimiter,
) -> RpcResponse {
    let rpc_req: RpcRequest = match serde_json::from_value(req) {
        Ok(r) => r,
        Err(e) => {
            // Log serde details server-side, return generic error to client.
            tracing::debug!("JSON-RPC parse error: {}", e);
            return RpcResponse::error(
                serde_json::Value::Null,
                -32700,
                "Parse error: invalid JSON-RPC request".into(),
            );
        }
    };

    if rpc_req.jsonrpc != "2.0" {
        return RpcResponse::error(
            rpc_req.id,
            -32600,
            "Invalid Request: expected jsonrpc 2.0".into(),
        );
    }

    // Reject params that are not an array or null.
    // JSON-RPC 2.0 spec allows both array (positional) and object (named) params,
    // but Brrq methods use positional params exclusively. Accepting objects would
    // bypass per-index validation in handlers and could allow smuggling unexpected
    // fields. Strict array-only policy eliminates this attack surface.
    if !rpc_req.params.is_array() && !rpc_req.params.is_null() {
        return RpcResponse::error(
            rpc_req.id,
            -32602,
            "Invalid params: must be an array or omitted".into(),
        );
    }

    // Per-method rate limiting.
    // The global rate limiter (middleware layer) applies to all requests uniformly.
    // This per-method check enforces tighter limits on write/expensive methods
    // (brrq_faucetDrip, brrq_sendTransaction, etc.) and looser limits on cheap reads.
    let limiter = match method_rate_tier(&rpc_req.method) {
        RateTier::Strict => &endpoint_limiter.strict,
        RateTier::Standard => &endpoint_limiter.standard,
        RateTier::Relaxed => &endpoint_limiter.relaxed,
    };
    if let Err(retry_after) = limiter.check(caller_ip).await {
        let secs = retry_after.as_secs().max(1);
        tracing::warn!(
            ip = %caller_ip,
            method = %rpc_req.method,
            retry_after_secs = secs,
            "JSON-RPC per-method rate limit exceeded"
        );
        return RpcResponse::error(
            rpc_req.id,
            -32005, // Custom: rate limited
            format!("Rate limit exceeded for method {}. Retry after {} seconds.", rpc_req.method, secs),
        );
    }

    dispatch(rpc_req, app).await
}

/// Dispatch a JSON-RPC request to the appropriate handler.
async fn dispatch(req: RpcRequest, app: &AppState) -> RpcResponse {
    let shared = &app.node;
    match req.method.as_str() {
        "brrq_sendTransaction" => handle_send_tx(req.id, req.params, shared).await,
        "brrq_getBalance" => handle_get_balance(req.id, req.params, shared).await,
        "brrq_getNonce" => handle_get_nonce(req.id, req.params, shared).await,
        "brrq_blockHeight" => handle_block_height(req.id, shared).await,
        "brrq_getReceipt" => handle_get_receipt(req.id, req.params, shared).await,
        "brrq_getBlock" => handle_get_block(req.id, req.params, shared).await,
        "brrq_getBlockByHash" => handle_get_block_by_hash(req.id, req.params, shared).await,
        "brrq_getTransaction" => handle_get_transaction(req.id, req.params, shared).await,
        "brrq_getTransactionsByAddress" => {
            handle_get_txs_by_address(req.id, req.params, shared).await
        }
        "brrq_getCode" => handle_get_code(req.id, req.params, shared).await,
        "brrq_getStorageAt" => handle_get_storage_at(req.id, req.params, shared).await,
        "brrq_getStateRoot" => handle_get_state_root(req.id, shared).await,
        "brrq_getAccount" => handle_get_account(req.id, req.params, shared).await,
        "brrq_getAccountAtHeight" => handle_get_account_at_height(req.id, req.params, shared).await,
        "brrq_getValidators" => handle_get_validators(req.id, req.params, shared).await,
        "brrq_getEpochInfo" => handle_get_epoch_info(req.id, shared).await,
        "brrq_getStakingInfo" => handle_get_staking_info(req.id, req.params, shared).await,
        "brrq_chainId" => handle_chain_id(req.id, shared).await,
        "brrq_bridgeDeposit" => handle_bridge_deposit(req.id, req.params, shared).await,
        "brrq_bridgeWithdraw" => handle_bridge_withdraw(req.id, req.params, shared).await,
        "brrq_bridgeVerifyWithdrawal" => handle_bridge_verify(req.id, req.params, shared).await,
        "brrq_bridgeCompleteWithdrawal" => handle_bridge_complete(req.id, req.params, shared).await,
        "brrq_bridgeStatus" => handle_bridge_status(req.id, shared).await,
        "brrq_submitProof" => handle_submit_proof(req.id).await,
        "brrq_getProof" => handle_get_proof(req.id, req.params, shared).await,
        "brrq_getLatestProof" => handle_get_latest_proof(req.id, shared).await,
        "brrq_getProofCount" => handle_get_proof_count(req.id, shared).await,
        "brrq_getAccountProof" => handle_get_account_proof(req.id, req.params, shared).await,
        "brrq_getStorageProof" => handle_get_storage_proof(req.id, req.params, shared).await,
        "brrq_verifyProof" => handle_verify_proof(req.id).await,
        "brrq_getLogs" => handle_get_logs(req.id, req.params, shared).await,
        "brrq_sendEncryptedTx" => handle_send_encrypted_tx(req.id).await,
        "brrq_faucetDrip" => handle_faucet_drip(req.id, req.params, shared).await,
        "brrq_getL1Status" => handle_get_l1_status(req.id, shared).await,
        "brrq_getL1Anchors" => handle_get_l1_anchors(req.id, req.params, shared).await,
        "brrq_getProofs" => handle_get_proofs(req.id, req.params, shared).await,
        "brrq_getProofByHeight" => handle_get_proof_by_height(req.id, req.params, shared).await,
        "brrq_getChallenges" => handle_get_challenges(req.id, req.params, shared).await,
        "brrq_submitChallenge" => handle_submit_challenge(req.id, req.params, shared).await,
        "brrq_permissionlessWithdraw" => {
            handle_permissionless_withdraw(req.id, req.params, shared).await
        }
        // ── MEV Protection ──────────────────────────────────────
        #[cfg(feature = "mev-protection")]
        "brrq_submitMevTransaction" => handle_submit_mev_tx(req.id, req.params, shared).await,
        #[cfg(feature = "mev-protection")]
        "brrq_getMevStatus" => handle_get_mev_status(req.id, shared).await,
        "brrq_getMevEpochKey" => handle_get_mev_epoch_key(req.id, shared).await,
        // ── Governance ────────────────────────────────────────────
        "brrq_submitProposal" => handle_submit_proposal(req.id, req.params, shared).await,
        "brrq_voteOnProposal" => handle_vote_on_proposal(req.id, req.params, shared).await,
        "brrq_getProposals" => handle_get_proposals(req.id, shared).await,
        "brrq_getGovernanceStats" => handle_get_governance_stats(req.id, shared).await,
        // ── Sequencer Registration ────────────────────────────────
        #[cfg(feature = "sequencer-rotation")]
        "brrq_registerSequencer" => handle_register_sequencer(req.id, req.params, shared).await,
        #[cfg(feature = "sequencer-rotation")]
        "brrq_getSequencers" => handle_get_sequencers(req.id, shared).await,
        #[cfg(feature = "sequencer-rotation")]
        "brrq_delegateStake" => handle_delegate_stake(req.id, req.params, shared).await,
        #[cfg(feature = "sequencer-rotation")]
        "brrq_undelegateStake" => handle_undelegate_stake(req.id, req.params, shared).await,
        // ── Prover Pools ──────────────────────────────────────────
        #[cfg(feature = "prover-pools")]
        "brrq_createProverPool" => handle_create_prover_pool(req.id, req.params, shared).await,
        #[cfg(feature = "prover-pools")]
        "brrq_joinProverPool" => handle_join_prover_pool(req.id, req.params, shared).await,
        #[cfg(feature = "prover-pools")]
        "brrq_getProverPools" => handle_get_prover_pools(req.id, shared).await,
        // SIM: Initialize federation for bridge simulation
        "brrq_initFederation" => handle_init_federation(req.id, req.params, shared).await,
        // ── Portal (L3) ────────────────────────────────────────────
        "brrq_getPortalLock" => handle_get_portal_lock(req.id, req.params, shared).await,
        "brrq_checkNullifier" => handle_check_nullifier(req.id, req.params, shared).await,
        "brrq_checkPortalSafety" => handle_check_portal_safety(req.id, req.params, shared).await,
        "brrq_getPortalStats" => handle_get_portal_stats(req.id, shared).await,
        _ => RpcResponse::error(req.id, -32601, format!("Method not found: {}", req.method)),
    }
}

// -- Param extraction helpers -------------------------------------------------
//
// These reduce the repeated `match params.get(N).and_then(…)` + early-return
// boilerplate in every JSON-RPC handler to a single `?`-able call.

/// Extract a required `&str` at positional index `idx` from the JSON-RPC params array.
fn require_str_param<'a>(
    params: &'a serde_json::Value,
    idx: usize,
    id: &serde_json::Value,
    field_name: &str,
) -> Result<&'a str, RpcResponse> {
    params
        .get(idx)
        .and_then(|v| v.as_str())
        .ok_or_else(|| RpcResponse::error(id.clone(), -32602, format!("Missing {field_name}")))
}

/// Extract and parse a required `Address` from a positional string param.
fn require_address_param(
    params: &serde_json::Value,
    idx: usize,
    id: &serde_json::Value,
    field_name: &str,
) -> Result<Address, RpcResponse> {
    let s = require_str_param(params, idx, id, field_name)?;
    parse_address(s)
        .ok_or_else(|| RpcResponse::error(id.clone(), -32602, format!("Invalid {field_name}")))
}

/// Extract and parse a required `Hash256` from a positional string param.
fn require_hash_param(
    params: &serde_json::Value,
    idx: usize,
    id: &serde_json::Value,
    field_name: &str,
) -> Result<Hash256, RpcResponse> {
    let s = require_str_param(params, idx, id, field_name)?;
    parse_hash(s)
        .ok_or_else(|| RpcResponse::error(id.clone(), -32602, format!("Invalid {field_name}")))
}

/// Extract a required JSON object at `params[0]`.
fn require_object_param<'a>(
    params: &'a serde_json::Value,
    id: &serde_json::Value,
    field_name: &str,
) -> Result<&'a serde_json::Value, RpcResponse> {
    params
        .get(0)
        .ok_or_else(|| RpcResponse::error(id.clone(), -32602, format!("Missing {field_name}")))
}

// -- Helper functions ---------------------------------------------------------

/// Maximum hex input length before attempting decode.
/// Prevents excessive allocation from massive hex strings.
/// 42 = "0x" + 40 hex chars (20 bytes) for address; 66 = "0x" + 64; 130 = "0x" + 128.
const MAX_HEX_INPUT_LEN: usize = 256;

pub fn parse_address(hex_str: &str) -> Option<Address> {
    // Reject oversized input before hex::decode to prevent allocation abuse.
    if hex_str.len() > MAX_HEX_INPUT_LEN {
        return None;
    }
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Some(Address::from_bytes(arr))
}

pub fn parse_hash(hex_str: &str) -> Option<Hash256> {
    if hex_str.len() > MAX_HEX_INPUT_LEN {
        return None;
    }
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    Some(Hash256::from_bytes(
        bytes.try_into().expect("length validated as 32"),
    ))
}

pub fn parse_schnorr_signature(hex_str: &str) -> Option<SchnorrSignature> {
    if hex_str.len() > MAX_HEX_INPUT_LEN {
        return None;
    }
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 64 {
        return None;
    }
    SchnorrSignature::from_slice(&bytes).ok()
}

pub fn parse_schnorr_pubkey(hex_str: &str) -> Option<SchnorrPublicKey> {
    if hex_str.len() > MAX_HEX_INPUT_LEN {
        return None;
    }
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(SchnorrPublicKey::from_bytes(arr))
}

pub fn block_to_json(block: &brrq_types::block::Block) -> serde_json::Value {
    serde_json::json!({
        "height": block.header.height,
        "timestamp": block.header.timestamp,
        "parent_hash": format!("0x{}", hex::encode(block.header.parent_hash.as_bytes())),
        "transactions_root": format!("0x{}", hex::encode(block.header.transactions_root.as_bytes())),
        "state_root": format!("0x{}", hex::encode(block.header.state_root.as_bytes())),
        "sequencer": format!("0x{}", hex::encode(block.header.sequencer.as_bytes())),
        "epoch": block.header.epoch,
        "gas_used": block.header.gas_used,
        "gas_limit": block.header.gas_limit,
        "hash": format!("0x{}", hex::encode(block.hash().as_bytes())),
        "tx_count": block.transactions.len(),
        "l1_anchor_height": block.header.l1_anchor_height,
        "l1_anchor_hash": block.header.l1_anchor_hash.map(|h| format!("0x{}", hex::encode(h.as_bytes()))),
    })
}

// -- JSON-RPC Handlers --------------------------------------------------------

// Default transaction type.
pub fn default_tx_type() -> String {
    "transfer".into()
}

#[derive(Deserialize)]
pub struct SendTxParams {
    pub from: String,
    #[serde(default)]
    pub to: String,
    #[serde(default)]
    pub amount: u64,
    pub nonce: u64,
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub signature: String,
    pub public_key: String,
    #[serde(default)]
    pub chain_id: Option<u64>,
    #[serde(default = "default_tx_type")]
    pub tx_type: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub call_data: Option<String>,
    #[serde(default)]
    pub value: u64,
    // ── Portal fields ──
    #[serde(default)]
    pub condition_hash: Option<String>,
    #[serde(default)]
    pub nullifier_hash: Option<String>,
    #[serde(default)]
    pub timeout_l2_block: Option<u64>,
    #[serde(default)]
    pub lock_id: Option<String>,
    #[serde(default)]
    pub merchant_secret: Option<String>,
    #[serde(default)]
    pub portal_signature: Option<String>,
    #[serde(default)]
    pub nullifier: Option<String>,
    #[serde(default)]
    pub merchant_address: Option<String>,
    // ── Lock Pool / Batch fields ──
    #[serde(default)]
    pub slot_amounts: Option<Vec<u64>>,
    #[serde(default)]
    pub claims: Option<Vec<serde_json::Value>>,
}

async fn handle_send_tx(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let tx_params: SendTxParams = match params.get(0) {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(p) => p,
            Err(e) => {
                // Log serde details server-side only.
                tracing::debug!("SendTx param parse error: {}", e);
                return RpcResponse::error(id, -32602, "Invalid transaction parameters".into());
            }
        },
        None => return RpcResponse::error(id, -32602, "Missing transaction parameter".into()),
    };

    let tx = match services::build_transaction(&tx_params) {
        Ok(t) => t,
        Err(e) => return service_err(id, e),
    };

    let mut ns = shared.write().await;
    match services::submit_to_mempool(&mut ns, tx) {
        Ok(hash_hex) => RpcResponse::success(id, serde_json::json!(hash_hex)),
        Err(e) => service_err(id, e),
    }
}

async fn handle_get_balance(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    RpcResponse::success(id, serde_json::json!(ns.state.balance(&address)))
}

async fn handle_get_nonce(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    RpcResponse::success(id, serde_json::json!(ns.state.nonce(&address)))
}

async fn handle_block_height(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, serde_json::json!(ns.height))
}

async fn handle_get_receipt(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let hash = match require_hash_param(&params, 0, &id, "tx hash") {
        Ok(h) => h,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    // Try in-memory first (recent receipts)
    if let Some(r) = ns.receipts.get(&hash) {
        return RpcResponse::success(
            id,
            serde_json::json!({
                "block_height": r.block_height,
                "gas_used": r.gas_used,
                "success": r.success,
                "block_hash": format!("0x{}", hex::encode(r.block_hash.as_bytes())),
            }),
        );
    }
    // Fall back to persistent store for pruned receipts
    if let Some(store) = &ns.store {
        if let Ok(Some(r)) = store.load_receipt(&hash) {
            return RpcResponse::success(
                id,
                serde_json::json!({
                    "block_height": r.block_height,
                    "gas_used": r.gas_used,
                    "success": r.success,
                    "block_hash": format!("0x{}", hex::encode(r.block_hash.as_bytes())),
                }),
            );
        }
    }
    RpcResponse::success(id, serde_json::Value::Null)
}

async fn handle_get_block(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let ns = shared.read().await;
    let height = if let Some(v) = params.get(0) {
        if v.is_string() && v.as_str() == Some("latest") {
            if ns.height == 0 {
                return RpcResponse::success(id, serde_json::Value::Null);
            }
            ns.height
        } else {
            match v.as_u64() {
                Some(h) => h,
                None => return RpcResponse::error(id, -32602, "Invalid height".into()),
            }
        }
    } else {
        return RpcResponse::error(id, -32602, "Missing height parameter".into());
    };
    match ns.get_block(height) {
        Some(block) => RpcResponse::success(id, block_to_json(&block)),
        None => RpcResponse::success(id, serde_json::Value::Null),
    }
}

async fn handle_get_block_by_hash(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let hash = match require_hash_param(&params, 0, &id, "block hash") {
        Ok(h) => h,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    match ns.get_block_by_hash(&hash) {
        Some(block) => RpcResponse::success(id, block_to_json(&block)),
        None => RpcResponse::success(id, serde_json::Value::Null),
    }
}

async fn handle_get_transaction(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let hash = match require_hash_param(&params, 0, &id, "tx hash") {
        Ok(h) => h,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    // Use tx_block_heights index to only scan blocks that contain transactions.
    // Falls back to PersistentStore for evicted blocks via get_block().
    for &h in &ns.tx_block_heights {
        if let Some(block) = ns.get_block(h) {
            for tx in &block.transactions {
                if tx.hash() == hash {
                    return RpcResponse::success(
                        id,
                        serde_json::json!({
                            "hash": format!("0x{}", hex::encode(tx.hash().as_bytes())),
                            "from": format!("0x{}", hex::encode(tx.body.from.as_bytes())),
                            "nonce": tx.body.nonce,
                            "gas_limit": tx.body.gas_limit,
                            "gas_price": tx.body.max_fee_per_gas,
                            "block_height": block.header.height,
                        }),
                    );
                }
            }
        }
    }
    RpcResponse::success(id, serde_json::Value::Null)
}

async fn handle_get_code(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    match ns.state.get_code(&address) {
        Some(code) => {
            RpcResponse::success(id, serde_json::json!(format!("0x{}", hex::encode(code))))
        }
        None => RpcResponse::success(id, serde_json::Value::Null),
    }
}

async fn handle_get_storage_at(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let key = match require_hash_param(&params, 1, &id, "storage key") {
        Ok(h) => h,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    let value = ns
        .state
        .storage_get(&address, &key)
        .unwrap_or(Hash256::ZERO);
    RpcResponse::success(
        id,
        serde_json::json!(format!("0x{}", hex::encode(value.as_bytes()))),
    )
}

async fn handle_get_state_root(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    let root = ns.state.state_root();
    RpcResponse::success(
        id,
        serde_json::json!(format!("0x{}", hex::encode(root.as_bytes()))),
    )
}

async fn handle_get_account(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    let result = services::get_account(&ns, &address);
    // If nonce is absent in the JSON, it means account was not found — return null for RPC compat.
    if result.get("code_hash").is_none() {
        return RpcResponse::success(id, serde_json::Value::Null);
    }
    RpcResponse::success(id, result)
}

/// Get account state at a specific block height (approximate reconstruction).
async fn handle_get_account_at_height(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let height = match params.get(1).and_then(|v| v.as_u64()) {
        Some(h) => h,
        None => return RpcResponse::error(id, -32602, "Missing block height".into()),
    };
    let ns = shared.read().await;
    match services::get_account_at_height(&ns, &address, height) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

/// Get transactions by address (sender or recipient) from recent blocks.
async fn handle_get_txs_by_address(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let limit = params
        .get(1)
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_u64())
        .unwrap_or(20)
        .min(100) as usize;
    let offset = params
        .get(1)
        .and_then(|v| v.get("offset"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;

    let ns = shared.read().await;
    let mut matched = Vec::new();
    for block in ns.blocks.iter().rev() {
        for tx in &block.transactions {
            let is_match = tx.body.from == address
                || match &tx.body.kind {
                    TransactionKind::Transfer { to, .. } => *to == address,
                    TransactionKind::ContractCall { to, .. } => *to == address,
                    _ => false,
                };
            if is_match {
                matched.push(serde_json::json!({
                    "hash": format!("0x{}", hex::encode(tx.hash().as_bytes())),
                    "from": format!("0x{}", hex::encode(tx.body.from.as_bytes())),
                    "nonce": tx.body.nonce,
                    "block_height": block.header.height,
                    "kind": match &tx.body.kind {
                        TransactionKind::Transfer { .. } => "transfer",
                        TransactionKind::Deploy { .. } => "deploy",
                        TransactionKind::ContractCall { .. } => "contract_call",
                        _ => "other",
                    },
                }));
            }
            if matched.len() >= offset + limit {
                break;
            }
        }
        if matched.len() >= offset + limit {
            break;
        }
    }
    let result: Vec<_> = matched.into_iter().skip(offset).collect();
    RpcResponse::success(
        id,
        serde_json::json!({
            "address": format!("0x{}", hex::encode(address.as_bytes())),
            "transactions": result,
            "limit": limit,
            "offset": offset,
        }),
    )
}

async fn handle_get_validators(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let limit = params
        .get(0)
        .and_then(|v| v.get("limit"))
        .and_then(|v| v.as_u64())
        .unwrap_or(100) as usize;
    let offset = params
        .get(0)
        .and_then(|v| v.get("offset"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0) as usize;
    let ns = shared.read().await;
    RpcResponse::success(id, services::get_validators(&ns, limit, offset))
}

async fn handle_get_epoch_info(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::get_epoch_info(&ns))
}

async fn handle_get_staking_info(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let ns = shared.read().await;
    if let Some(addr_str) = params.get(0).and_then(|v| v.as_str()) {
        let address = match parse_address(addr_str) {
            Some(a) => a,
            None => return RpcResponse::error(id, -32602, "Invalid address".into()),
        };
        match ns.staking.validators.get(&address) {
            Some(v) => RpcResponse::success(
                id,
                serde_json::json!({
                    "address": format!("0x{}", hex::encode(v.address.as_bytes())),
                    "stake": v.stake,
                    "total_stake": v.total_stake(),
                    "status": format!("{:?}", v.status),
                }),
            ),
            None => RpcResponse::success(id, serde_json::Value::Null),
        }
    } else {
        let total_stake: u64 = ns
            .staking
            .validators
            .values()
            .map(|v| v.total_stake())
            .sum();
        let info = serde_json::json!({
            "total_stake": total_stake,
            "validator_count": ns.staking.validators.len(),
            "stake_cap": ns.staking.stake_cap,
        });
        RpcResponse::success(id, info)
    }
}

async fn handle_chain_id(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, serde_json::json!({ "chain_id": ns.chain_id }))
}

// -- Bridge handlers ----------------------------------------------------------

async fn handle_bridge_deposit(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing deposit params".into()),
    };
    let btc_tx_id_hex = p.get("btc_tx_id").and_then(|v| v.as_str()).unwrap_or("");
    let vout = p.get("vout").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let amount = match p.get("amount").and_then(|v| v.as_u64()) {
        Some(a) if a > 0 => a,
        Some(0) => return RpcResponse::error(id, -32602, "Deposit amount must be > 0".into()),
        _ => return RpcResponse::error(id, -32602, "Missing or invalid 'amount'".into()),
    };
    let recipient_str = p.get("recipient").and_then(|v| v.as_str()).unwrap_or("");
    let confirmations = p.get("confirmations").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let submitter = p
        .get("submitter")
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    let btc_tx_id = match parse_hash(btc_tx_id_hex) {
        Some(h) => h,
        None => return RpcResponse::error(id, -32602, "Invalid btc_tx_id".into()),
    };
    let recipient = match parse_address(recipient_str) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid recipient address".into()),
    };

    // Verify Schnorr signature: submitter is REQUIRED for authenticated deposits.
    let submitter_addr = match submitter {
        Some(ref addr) => addr,
        None => {
            return RpcResponse::error(
                id,
                -32602,
                "Missing submitter — authenticated deposit requires a submitter address and signature".into(),
            );
        }
    };
    if let Err(e) = services::verify_body_signature(p, submitter_addr) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    // L1 transaction verification — parse SPV proof from request and
    // ensure the bridge's BlockMonitor is current before processing the deposit.
    //
    // process_deposit() enforces: either a valid SPV proof verified against the
    // canonical chain (via BlockMonitor), OR federation member attestation. We
    // parse the SPV proof here and sync the bridge's block_monitor from the
    // node-level l1_monitor so the verification can succeed.

    // Parse the optional SPV proof from the deposit request.
    let spv_proof: Option<brrq_bitcoin::spv::SpvProof> = p
        .get("spv_proof")
        .and_then(|v| serde_json::from_value(v.clone()).ok());

    let mut ns = shared.write().await;

    // Sync the bridge's BlockMonitor from the node-level L1 monitor so that
    // SPV proofs can be verified against the canonical Bitcoin chain.
    // Clone the monitor first to avoid overlapping borrows on `ns`.
    if let Some(monitor) = ns.l1_monitor.clone() {
        ns.bridge.set_block_monitor(monitor);
    }

    // Hard rejection on mainnet: if no L1 verification method is available
    // (no SPV proof AND no federation configured on the bridge), reject
    // outright. On testnet/local we allow federation-attested deposits to
    // proceed without SPV (process_deposit will still require federation
    // membership).
    let is_mainnet = ns.chain_id == brrq_types::transaction::chain_id::MAINNET;
    if is_mainnet && spv_proof.is_none() && ns.l1_monitor.is_none() {
        return RpcResponse::error(
            id,
            -32603,
            "Mainnet bridge deposits require L1 transaction verification \
             (SPV proof or connected Bitcoin node). No verification method \
             is available."
                .into(),
        );
    }

    match ns.bridge.process_deposit(
        btc_tx_id,
        vout,
        amount,
        recipient,
        confirmations,
        submitter,
        spv_proof,
    ) {
        Ok(minted) => RpcResponse::success(
            id,
            serde_json::json!({
                "minted": minted,
                "status": if confirmations >= 6 { "confirmed" } else { "pending" },
                "btc_tx_id": btc_tx_id_hex,
                "amount": amount,
            }),
        ),
        Err(e) => RpcResponse::error(id, -32602, format!("Bridge deposit failed: {:?}", e)),
    }
}

async fn handle_bridge_withdraw(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing withdraw params".into()),
    };
    let sender_str = p.get("sender").and_then(|v| v.as_str()).unwrap_or("");
    let amount = p.get("amount").and_then(|v| v.as_u64()).unwrap_or(0);
    let btc_dest = p
        .get("btc_destination")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let sender = match parse_address(sender_str) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid sender address".into()),
    };

    if amount == 0 {
        return RpcResponse::error(id, -32602, "Withdrawal amount must be > 0".into());
    }

    // Verify Schnorr signature from the sender to authorize the withdrawal.
    if let Err(e) = services::verify_body_signature(p, &sender) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let mut ns = shared.write().await;

    // HIGH: Deduct balance FIRST (safe ordering) to prevent double-spend via
    // TOCTOU between balance check and bridge call.
    let account = ns.state.get_or_create_account(sender);
    let prev_balance = account.balance;
    account.balance = match prev_balance.checked_sub(amount) {
        Some(b) => b,
        None => {
            return RpcResponse::error(
                id,
                -32000,
                format!(
                    "Insufficient balance: have {}, need {}",
                    prev_balance, amount
                ),
            );
        }
    };
    ns.state.flush_account(&sender);

    // Try bridge — if it fails, restore balance.
    match ns
        .bridge
        .request_withdrawal(sender, amount, btc_dest.to_string())
    {
        Ok(wid) => RpcResponse::success(
            id,
            serde_json::json!({
                "withdrawal_id": format!("0x{}", hex::encode(wid.as_bytes())),
                "amount": amount,
                "status": "initiated",
            }),
        ),
        Err(e) => {
            // Restore balance on bridge failure.
            let account = ns.state.get_or_create_account(sender);
            account.balance = account.balance.saturating_add(amount);
            ns.state.flush_account(&sender);
            RpcResponse::error(id, -32602, format!("Bridge withdrawal failed: {:?}", e))
        }
    }
}

async fn handle_bridge_verify(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing verify params".into()),
    };

    let wid_hex = p
        .get("withdrawal_id")
        .and_then(|v| v.as_str())
        .unwrap_or(params.get(0).and_then(|v| v.as_str()).unwrap_or(""));
    let wid = match parse_hash(wid_hex) {
        Some(h) => h,
        None => return RpcResponse::error(id, -32602, "Invalid withdrawal hash".into()),
    };

    // Verify Schnorr signature from the submitter to authorize verification.
    if let Some(submitter_hex) = p.get("submitter").and_then(|v| v.as_str()) {
        if let Some(submitter_addr) = parse_address(submitter_hex) {
            if let Err(e) = services::verify_body_signature(p, &submitter_addr) {
                return RpcResponse::error(id, -32603, e.message().to_string());
            }
        }
    }

    // Check if proof_payload is provided (raw bytes path)
    if let Some(proof_hex) = p.get("proof_payload").and_then(|v| v.as_str()) {
        let proof_bytes = match hex::decode(proof_hex.trim_start_matches("0x")) {
            Ok(b) => b,
            Err(_) => return RpcResponse::error(id, -32602, "Invalid proof format".into()),
        };
        let mut ns = shared.write().await;
        match ns.bridge.verify_withdrawal_proof(&wid, &proof_bytes) {
            Ok(status) => RpcResponse::success(
                id,
                serde_json::json!({
                    "status": format!("{:?}", status),
                    "verified": true,
                }),
            ),
            Err(e) => RpcResponse::error(
                id,
                -32602,
                format!("Bridge proof verification failed: {:?}", e),
            ),
        }
    } else {
        // No proof provided -- report status
        let ns = shared.read().await;
        match ns.bridge.withdrawals.get(&wid) {
            Some(w) => RpcResponse::success(
                id,
                serde_json::json!({
                    "verified": w.is_verified,
                    "status": format!("{:?}", w.status),
                }),
            ),
            None => RpcResponse::error(id, -32602, "Withdrawal not found".into()),
        }
    }
}

async fn handle_bridge_complete(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let hash_str = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            // Try object form
            match params
                .get(0)
                .and_then(|v| v.get("withdrawal_id"))
                .and_then(|v| v.as_str())
            {
                Some(s) => s,
                None => return RpcResponse::error(id, -32602, "Missing withdrawal hash".into()),
            }
        }
    };
    let hash = match parse_hash(hash_str) {
        Some(h) => h,
        None => return RpcResponse::error(id, -32602, "Invalid withdrawal hash".into()),
    };
    // Parse submitter address for access control
    let submitter = params
        .get(0)
        .and_then(|v| v.get("submitter"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);

    // Verify Schnorr signature from the submitter to authorize completion.
    if let Some(ref submitter_addr) = submitter {
        let p = params.get(0).unwrap();
        if let Err(e) = services::verify_body_signature(p, submitter_addr) {
            return RpcResponse::error(id, -32603, e.message().to_string());
        }
    }

    let mut ns = shared.write().await;
    match ns.bridge.complete_withdrawal(&hash, submitter) {
        Ok(payout) => RpcResponse::success(
            id,
            serde_json::json!({ "status": "completed", "payout": payout }),
        ),
        Err(e) => RpcResponse::error(id, -32602, format!("Bridge completion failed: {:?}", e)),
    }
}

async fn handle_bridge_status(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::get_bridge_status(&ns))
}

// -- Federation init (for simulation/testing) ---------------------------------

/// Handle `brrq_initFederation`.
///
/// Params: `[{ "members": [{"address": "0x...", "name": "m1"}, ...], "threshold": 3,
///             "admin": "0x...", "signature": "0x...", "public_key": "0x..." }]`
///
/// This is an admin-only endpoint. The `admin` address must match a
/// pre-configured admin address and the request must be signed.
async fn handle_init_federation(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };

    // Admin-only authorization check.
    let admin_hex = match p.get("admin").and_then(|v| v.as_str()) {
        Some(a) => a,
        None => {
            return RpcResponse::error(
                id,
                -32602,
                "Missing 'admin' field — federation init requires admin authorization".into(),
            );
        }
    };
    let admin_addr = match parse_address(admin_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid admin address".into()),
    };

    // Verify the admin's Schnorr signature over the request.
    if let Err(e) = services::verify_body_signature(p, &admin_addr) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    // Verify that the signing address is actually an admin.
    {
        let ns = shared.read().await;
        if !ns.is_admin(&admin_addr) {
            return RpcResponse::error(
                id,
                -32603,
                "Unauthorized: address is not a configured admin".into(),
            );
        }
    }

    let members_arr = match p.get("members").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Missing 'members' array".into()),
    };

    let threshold = p.get("threshold").and_then(|v| v.as_u64()).unwrap_or(3) as usize;

    let mut members = Vec::new();
    for m in members_arr {
        let addr_str = m.get("address").and_then(|v| v.as_str()).unwrap_or("");
        let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
        match parse_address(addr_str) {
            Some(a) => members.push((a, name.to_string())),
            None => {
                return RpcResponse::error(
                    id,
                    -32602,
                    format!("Invalid member address: {}", addr_str),
                );
            }
        }
    }

    let mut ns = shared.write().await;
    match ns.bridge.init_federation(members.clone(), threshold, 0) {
        Ok(()) => RpcResponse::success(
            id,
            serde_json::json!({
                "status": "federation_initialized",
                "members": members.len(),
                "threshold": threshold,
            }),
        ),
        Err(e) => RpcResponse::error(id, -32000, format!("Federation init failed: {:?}", e)),
    }
}

// -- Proof handlers -----------------------------------------------------------

async fn handle_submit_proof(id: serde_json::Value) -> RpcResponse {
    RpcResponse::error(
        id,
        -32601,
        "Method not available".into(),
    )
}

async fn handle_get_proof(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let hash = match require_hash_param(&params, 0, &id, "proof hash") {
        Ok(h) => h,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    // Search proof_records by trace_commitment (hash-based lookup, not just latest).
    if let Some(record) = ns
        .proof_records
        .iter()
        .find(|r| r.proof.trace_commitment == hash)
    {
        RpcResponse::success(
            id,
            serde_json::json!({
                "block_range_start": record.block_range.0,
                "block_range_end": record.block_range.1,
                "verified": record.verified,
                "trace_commitment": format!("0x{}", hex::encode(record.proof.trace_commitment.as_bytes())),
                "generation_time_ms": record.generation_time_ms,
                "tx_count": record.tx_count,
                "total_gas": record.total_gas,
            }),
        )
    } else {
        RpcResponse::success(id, serde_json::Value::Null)
    }
}

async fn handle_get_latest_proof(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::get_latest_proof(&ns))
}

async fn handle_get_proof_count(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, serde_json::json!(ns.proof_records.len()))
}

// -- State proof handlers -----------------------------------------------------

async fn handle_get_account_proof(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    let proof = ns.state.prove_account(&address);
    let siblings: Vec<String> = proof
        .smt_proof
        .siblings
        .iter()
        .map(|s| format!("0x{}", hex::encode(s.as_bytes())))
        .collect();
    let state_root = format!("0x{}", hex::encode(ns.state.state_root().as_bytes()));
    RpcResponse::success(
        id,
        serde_json::json!({
            "address": format!("0x{}", hex::encode(address.as_bytes())),
            "exists": proof.smt_proof.exists,
            "state_root": state_root,
            "account": ns.state.get_account(&address).map(|a| serde_json::json!({
                "balance": a.balance,
                "nonce": a.nonce,
                "code_hash": format!("0x{}", hex::encode(a.code_hash.as_bytes())),
                "storage_root": format!("0x{}", hex::encode(a.storage_root.as_bytes())),
            })),
            "proof": {
                "key": format!("0x{}", hex::encode(proof.smt_proof.key.as_bytes())),
                "value": format!("0x{}", hex::encode(proof.smt_proof.value.as_bytes())),
                "siblings": siblings,
                "root": state_root,
            },
        }),
    )
}

async fn handle_get_storage_proof(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let address = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };
    let key = match require_hash_param(&params, 1, &id, "storage key") {
        Ok(h) => h,
        Err(e) => return e,
    };
    let ns = shared.read().await;
    let proof = ns.state.prove_storage(&address, &key);
    let account_siblings: Vec<String> = proof
        .account_proof
        .smt_proof
        .siblings
        .iter()
        .map(|s| format!("0x{}", hex::encode(s.as_bytes())))
        .collect();
    let storage_siblings: Vec<String> = proof
        .storage_smt_proof
        .iter()
        .flat_map(|p| &p.siblings)
        .map(|s| format!("0x{}", hex::encode(s.as_bytes())))
        .collect();
    let value = ns
        .state
        .storage_get(&address, &key)
        .unwrap_or(Hash256::ZERO);
    let state_root = format!("0x{}", hex::encode(ns.state.state_root().as_bytes()));
    RpcResponse::success(
        id,
        serde_json::json!({
            "address": format!("0x{}", hex::encode(address.as_bytes())),
            "key": format!("0x{}", hex::encode(key.as_bytes())),
            "value": format!("0x{}", hex::encode(value.as_bytes())),
            "exists": proof.account_proof.smt_proof.exists,
            "state_root": state_root,
            "account_proof": {
                "key": format!("0x{}", hex::encode(proof.account_proof.smt_proof.key.as_bytes())),
                "value": format!("0x{}", hex::encode(proof.account_proof.smt_proof.value.as_bytes())),
                "siblings": account_siblings,
            },
            "storage_proof": {
                "siblings": storage_siblings,
            },
        }),
    )
}

async fn handle_verify_proof(id: serde_json::Value) -> RpcResponse {
    RpcResponse::error(
        id,
        -32601,
        "Method not available".into(),
    )
}

// -- Event log handler --------------------------------------------------------

async fn handle_get_logs(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let ns = shared.read().await;
    let from_block = params
        .get(0)
        .and_then(|v| v.get("fromBlock"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let to_block = params
        .get(0)
        .and_then(|v| v.get("toBlock"))
        .and_then(|v| v.as_u64())
        .unwrap_or(ns.height);

    // Enforce maximum block range to prevent DoS (10,000 blocks max)
    const MAX_LOG_RANGE: u64 = 10_000;
    if to_block.saturating_sub(from_block) > MAX_LOG_RANGE {
        return RpcResponse::error(
            id,
            -32602,
            format!(
                "Block range too large: {} blocks (max {}). Use smaller ranges.",
                to_block.saturating_sub(from_block),
                MAX_LOG_RANGE
            ),
        );
    }

    // Optional filters: address (contract), topics (indexed event params).
    let filter_address: Option<Address> = params
        .get(0)
        .and_then(|v| v.get("address"))
        .and_then(|v| v.as_str())
        .and_then(parse_address);
    let filter_topics: Vec<Option<Hash256>> = params
        .get(0)
        .and_then(|v| v.get("topics"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .take(4) // Max 4 indexed topics
                .map(|t| t.as_str().and_then(parse_hash))
                .collect()
        })
        .unwrap_or_default();

    let mut all_logs = Vec::new();
    const MAX_LOGS_RETURNED: usize = 10_000;
    for height in from_block..=to_block {
        if let Some(logs) = ns.block_logs.get(&height) {
            for log in logs {
                // Filter by contract address if specified.
                if let Some(ref addr) = filter_address {
                    if log.address != *addr {
                        continue;
                    }
                }
                // Filter by topics: each non-null entry must match the log's topic at that position.
                let topics_match = filter_topics.iter().enumerate().all(|(i, ft)| {
                    match ft {
                        None => true, // null = wildcard
                        Some(expected) => log.topics.get(i).map_or(false, |t| t == expected),
                    }
                });
                if !topics_match {
                    continue;
                }
                all_logs.push(serde_json::json!({
                    "block_height": height,
                    "address": format!("0x{}", hex::encode(log.address.as_bytes())),
                    "data": format!("0x{}", hex::encode(&log.data)),
                    "topics": log.topics.iter().map(|t| format!("0x{}", hex::encode(t.as_bytes()))).collect::<Vec<_>>(),
                }));
                if all_logs.len() >= MAX_LOGS_RETURNED {
                    break;
                }
            }
        }
        if all_logs.len() >= MAX_LOGS_RETURNED {
            break;
        }
    }
    RpcResponse::success(id, serde_json::json!(all_logs))
}

// -- MEV handler --------------------------------------------------------------

async fn handle_send_encrypted_tx(id: serde_json::Value) -> RpcResponse {
    RpcResponse::error(
        id,
        -32601,
        "brrq_sendEncryptedTx is deprecated — use brrq_submitMevTransaction instead".into(),
    )
}

// -- Faucet handler -----------------------------------------------------------

async fn handle_faucet_drip(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let recipient = match require_address_param(&params, 0, &id, "address") {
        Ok(a) => a,
        Err(e) => return e,
    };

    let mut ns = shared.write().await;
    match services::faucet_drip(&mut ns, recipient) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

/// Get Bitcoin L1 status.
async fn handle_get_l1_status(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::get_l1_status(&ns))
}

// -- Trustless Bridge handlers --------------------------------------------------

/// Get all stored proofs summary.
async fn handle_get_proofs(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let limit = params.get(0).and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let ns = shared.read().await;
    RpcResponse::success(id, services::list_proofs(&ns, limit, offset))
}

/// Get proof covering a specific L2 height.
async fn handle_get_proof_by_height(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let height = match params.get(0).and_then(|v| v.as_u64()) {
        Some(h) => h,
        None => return RpcResponse::error(id, -32602, "Missing height parameter".into()),
    };
    let ns = shared.read().await;
    match services::get_proof_by_height(&ns, height) {
        Ok(result) => RpcResponse::success(id, result),
        Err(_) => RpcResponse::success(id, serde_json::Value::Null),
    }
}

/// Get all challenges with statistics.
async fn handle_get_challenges(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let limit = params.get(0).and_then(|v| v.as_u64()).unwrap_or(100) as usize;
    let offset = params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    let ns = shared.read().await;
    RpcResponse::success(id, services::list_challenges(&ns, limit, offset))
}

/// Submit a challenge against an invalid state transition.
///
/// Params: `[{ "challenger": "0x...", "challenge_type": "InvalidStateRoot",
///             "claimed_state_root": "0x...", "actual_state_root": "0x...", "l2_height": 100 }]`
async fn handle_submit_challenge(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match require_object_param(&params, &id, "params") {
        Ok(v) => v,
        Err(e) => return e,
    };

    let challenger_hex = match p.get("challenger").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing challenger".into()),
    };
    let challenger = match parse_address(challenger_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid challenger address".into()),
    };

    // Verify Schnorr signature from the challenger.
    if let Err(e) = services::verify_body_signature(p, &challenger) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let (challenge_type, ct_str) = match services::parse_challenge_type(p) {
        Ok(v) => v,
        Err(e) => return service_err(id, e),
    };

    let mut ns = shared.write().await;
    match services::submit_challenge(&mut ns, challenger, challenger_hex, challenge_type, ct_str) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

/// Permissionless withdrawal with STARK proof.
///
/// Params: `[{ "withdrawal_id": "0x...", "proof_payload": "0x..." }]`
async fn handle_permissionless_withdraw(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match require_object_param(&params, &id, "params") {
        Ok(v) => v,
        Err(e) => return e,
    };

    let wid_hex = match p.get("withdrawal_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing withdrawal_id".into()),
    };
    let wid = match parse_hash(wid_hex) {
        Some(h) => h,
        None => return RpcResponse::error(id, -32602, "Invalid withdrawal_id".into()),
    };

    let proof_hex = match p.get("proof_payload").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing proof_payload".into()),
    };
    let proof_bytes = match hex::decode(proof_hex.trim_start_matches("0x")) {
        Ok(b) => b,
        Err(_) => return RpcResponse::error(id, -32602, "Invalid proof_payload hex".into()),
    };

    // Deserialize the STARK proof
    let proof = match brrq_prover::types::StarkProof::from_bytes(&proof_bytes) {
        Ok(p) => p,
        Err(e) => {
            return RpcResponse::error(id, -32602, format!("Proof deserialization failed: {}", e));
        }
    };

    let mut ns = shared.write().await;
    let current_l2_height = ns.height;
    match ns
        .bridge
        .permissionless_complete(&wid, &proof, current_l2_height)
    {
        Ok(payout) => {
            // Get withdrawal info for event
            let (amount, btc_dest) = ns
                .bridge
                .withdrawals
                .get(&wid)
                .map(|w| (w.amount, w.btc_destination.clone()))
                .unwrap_or((payout, String::new()));

            // Emit WithdrawalCompleted event
            if let Some(ref event_tx) = ns.event_tx {
                let _ = event_tx.send(crate::events::NodeEvent::WithdrawalCompleted {
                    withdrawal_id: format!("0x{}", hex::encode(wid.as_bytes())),
                    amount,
                    btc_destination: btc_dest,
                    permissionless: true,
                });
            }

            RpcResponse::success(
                id,
                serde_json::json!({
                    "status": "completed",
                    "payout": payout,
                    "permissionless": true,
                }),
            )
        }
        Err(e) => RpcResponse::error(
            id,
            -32602,
            format!("Permissionless withdrawal failed: {:?}", e),
        ),
    }
}

/// Get L1 anchors list.
///
/// Positional params: `[limit?, offset?]` (consistent with other JSON-RPC methods).
async fn handle_get_l1_anchors(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let ns = shared.read().await;
    let limit = params.get(0).and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let offset = params.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as usize;
    RpcResponse::success(id, services::get_l1_anchors(&ns, limit, offset))
}

// ══════════════════════════════════════════════════════════════════
// MEV Protection JSON-RPC handlers
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "mev-protection")]
async fn handle_submit_mev_tx(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };
    let envelope_hex = match p.get("envelope_hex").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing envelope_hex".into()),
    };

    let mut ns = shared.write().await;
    match services::submit_mev_envelope(&mut ns, envelope_hex) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

#[cfg(feature = "mev-protection")]
async fn handle_get_mev_status(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::get_mev_status(&ns))
}

async fn handle_get_mev_epoch_key(id: serde_json::Value, _shared: &SharedState) -> RpcResponse {
    // Epoch key is not exposed via RPC. Only epoch number and key commitment are returned.
    RpcResponse::error(id, -32601, "brrq_getMevEpochKey removed — epoch keys are threshold-distributed".into())
}

// ══════════════════════════════════════════════════════════════════
// Governance JSON-RPC handlers
// ══════════════════════════════════════════════════════════════════

async fn handle_submit_proposal(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };
    let proposer_hex = match p.get("proposer").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing proposer".into()),
    };
    let proposer = match parse_address(proposer_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid proposer address".into()),
    };

    // Verify Schnorr signature from the proposer.
    if let Err(e) = services::verify_body_signature(p, &proposer) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let (proposal_type, pt_str) = match services::parse_proposal_type(p) {
        Ok(v) => v,
        Err(e) => return service_err(id, e),
    };

    let mut ns = shared.write().await;
    match services::submit_proposal(&mut ns, proposer, proposer_hex, proposal_type, pt_str) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

async fn handle_vote_on_proposal(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };
    let pid_hex = match p.get("proposal_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing proposal_id".into()),
    };
    let proposal_id = match parse_hash(pid_hex) {
        Some(h) => h,
        None => return RpcResponse::error(id, -32602, "Invalid proposal_id".into()),
    };
    let voter_hex = match p.get("voter").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing voter".into()),
    };
    let voter = match parse_address(voter_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid voter address".into()),
    };
    let vote_str = match p.get("vote").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "missing or invalid vote".into()),
    };
    let vote = match services::parse_vote(vote_str) {
        Ok(v) => v,
        Err(e) => return service_err(id, e),
    };
    let chamber = p.get("chamber").and_then(|v| v.as_str()).unwrap_or("user");

    // Verify Schnorr signature from the voter.
    if let Err(e) = services::verify_body_signature(p, &voter) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let mut ns = shared.write().await;
    match services::vote_on_proposal(
        &mut ns,
        &proposal_id,
        voter,
        voter_hex,
        vote,
        vote_str,
        chamber,
    ) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

async fn handle_get_proposals(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::list_proposals(&ns))
}

async fn handle_get_governance_stats(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::get_governance_stats(&ns))
}

// ══════════════════════════════════════════════════════════════════
// Sequencer Registration JSON-RPC handlers
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "sequencer-rotation")]
async fn handle_register_sequencer(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };
    let addr_hex_str = match p.get("address").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing address".into()),
    };
    let address = match parse_address(addr_hex_str) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid address".into()),
    };
    let self_stake = match p.get("self_stake").and_then(|v| v.as_u64()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "missing or invalid self_stake".into()),
    };
    let region_str = p
        .get("region")
        .and_then(|v| v.as_str())
        .unwrap_or("Unknown");
    let region = services::parse_region(region_str);
    let commission_bp = p.get("commission_bp").and_then(|v| v.as_u64()).unwrap_or(0);

    // Verify Schnorr signature from the registering sequencer.
    if let Err(e) = services::verify_body_signature(p, &address) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let mut ns = shared.write().await;
    match services::register_sequencer(
        &mut ns,
        address,
        addr_hex_str,
        self_stake,
        region,
        region_str,
        commission_bp,
    ) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

#[cfg(feature = "sequencer-rotation")]
async fn handle_get_sequencers(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::list_sequencers(&ns))
}

#[cfg(feature = "sequencer-rotation")]
async fn handle_delegate_stake(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };
    let delegator_hex = match p.get("delegator").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Invalid delegator".into()),
    };
    let delegator = match parse_address(delegator_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid delegator".into()),
    };
    let seq_hex = match p.get("sequencer").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Invalid sequencer".into()),
    };
    let sequencer = match parse_address(seq_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid sequencer".into()),
    };
    let amount = match p.get("amount").and_then(|v| v.as_u64()) {
        Some(a) if a > 0 => a,
        _ => return RpcResponse::error(id, -32602, "missing or invalid amount".into()),
    };

    // Verify Schnorr signature from the delegator.
    if let Err(e) = services::verify_body_signature(p, &delegator) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let mut ns = shared.write().await;
    match services::delegate_stake(
        &mut ns,
        delegator,
        delegator_hex,
        sequencer,
        seq_hex,
        amount,
    ) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

#[cfg(feature = "sequencer-rotation")]
async fn handle_undelegate_stake(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };
    let delegator_hex = match p.get("delegator").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Invalid delegator".into()),
    };
    let delegator = match parse_address(delegator_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid delegator address".into()),
    };
    let sequencer = match p
        .get("sequencer")
        .and_then(|v| v.as_str())
        .and_then(parse_address)
    {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid sequencer".into()),
    };

    // Verify Schnorr signature from the delegator.
    if let Err(e) = services::verify_body_signature(p, &delegator) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let mut ns = shared.write().await;
    match services::undelegate_stake(&mut ns, delegator, sequencer) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

// ══════════════════════════════════════════════════════════════════
// Prover Pool JSON-RPC handlers
// ══════════════════════════════════════════════════════════════════

#[cfg(feature = "prover-pools")]
async fn handle_create_prover_pool(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };
    let coord_hex = match p.get("coordinator").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing coordinator".into()),
    };
    let coordinator = match parse_address(coord_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid coordinator address".into()),
    };
    let name = p
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("unnamed")
        .to_string();
    let fee_bp = p.get("fee_bp").and_then(|v| v.as_u64()).unwrap_or(0);

    // Verify Schnorr signature from the coordinator to authorize pool creation.
    if let Err(e) = services::verify_body_signature(p, &coordinator) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let mut ns = shared.write().await;
    match services::create_prover_pool(&mut ns, coordinator, coord_hex, name, fee_bp) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

#[cfg(feature = "prover-pools")]
async fn handle_join_prover_pool(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let p = match params.get(0) {
        Some(v) => v,
        None => return RpcResponse::error(id, -32602, "Missing params".into()),
    };
    let pool_id_hex = match p.get("pool_id").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing pool_id".into()),
    };
    let pool_id = match parse_hash(pool_id_hex) {
        Some(h) => h,
        None => return RpcResponse::error(id, -32602, "Invalid pool_id".into()),
    };
    let member_hex = match p.get("member").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "Missing member".into()),
    };
    let member = match parse_address(member_hex) {
        Some(a) => a,
        None => return RpcResponse::error(id, -32602, "Invalid member address".into()),
    };
    let weight = p.get("weight").and_then(|v| v.as_u64()).unwrap_or(50);

    // Verify Schnorr signature from the member to authorize pool join.
    if let Err(e) = services::verify_body_signature(p, &member) {
        return RpcResponse::error(id, -32603, e.message().to_string());
    }

    let mut ns = shared.write().await;
    match services::join_prover_pool(&mut ns, pool_id, member, member_hex, weight) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

#[cfg(feature = "prover-pools")]
async fn handle_get_prover_pools(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    RpcResponse::success(id, services::list_prover_pools(&ns))
}

// ── Portal (L3) JSON-RPC handlers ──────────────────────────────────

async fn handle_get_portal_lock(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let lock_id = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "missing lock_id parameter".into()),
    };
    let ns = shared.read().await;
    match crate::portal::get_portal_lock(&ns, lock_id) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

async fn handle_check_nullifier(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let nullifier = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "missing nullifier parameter".into()),
    };
    let ns = shared.read().await;
    match crate::portal::check_nullifier(&ns, nullifier) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

async fn handle_check_portal_safety(
    id: serde_json::Value,
    params: serde_json::Value,
    shared: &SharedState,
) -> RpcResponse {
    let lock_id = match params.get(0).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "missing lock_id parameter".into()),
    };
    let nullifier = match params.get(1).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return RpcResponse::error(id, -32602, "missing nullifier parameter".into()),
    };
    let ns = shared.read().await;
    let current_block = ns.height;
    match crate::portal::check_portal_safety(&ns, lock_id, nullifier, current_block) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

async fn handle_get_portal_stats(id: serde_json::Value, shared: &SharedState) -> RpcResponse {
    let ns = shared.read().await;
    match crate::portal::get_portal_stats(&ns) {
        Ok(result) => RpcResponse::success(id, result),
        Err(e) => service_err(id, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::NodeState;

    #[test]
    fn test_parse_address_valid() {
        let addr = parse_address("0x0000000000000000000000000000000000000001");
        assert!(addr.is_some());
    }

    #[test]
    fn test_parse_address_no_prefix() {
        let addr = parse_address("0000000000000000000000000000000000000001");
        assert!(addr.is_some());
    }

    #[test]
    fn test_parse_address_invalid() {
        let addr = parse_address("0xinvalid");
        assert!(addr.is_none());
    }

    #[test]
    fn test_rpc_response_success() {
        let resp = RpcResponse::success(serde_json::json!(1), serde_json::json!(42));
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_rpc_response_error() {
        let resp = RpcResponse::error(serde_json::json!(1), -32601, "Not found".into());
        assert!(resp.result.is_none());
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_dispatch_block_height() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_blockHeight".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));
    }

    #[tokio::test]
    async fn test_dispatch_get_balance_zero() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getBalance".into(),
            params: serde_json::json!(["0x0000000000000000000000000000000000000001"]),
            id: serde_json::json!(2),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));
    }

    #[tokio::test]
    async fn test_dispatch_unknown_method() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "unknown_method".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(3),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
    }

    #[tokio::test]
    async fn test_dispatch_chain_id() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_chainId".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(4),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
    }

    // ══════════════════════════════════════════════════════════════════
    // JSON-RPC Faucet Tests
    // ══════════════════════════════════════════════════════════════════

    fn make_app_with_faucet(faucet_balance: u64) -> AppState {
        let mut state = NodeState::new();
        let faucet_addr_bytes = [0u8; 20];
        let mut faucet_bytes = faucet_addr_bytes;
        faucet_bytes[19] = 0xFA;
        let faucet_addr = brrq_types::address::Address::from_bytes(faucet_bytes);
        state.faucet_address = Some(faucet_addr);
        state.faucet_drip_amount = 100_000_000;
        state.faucet_cooldown_secs = 3600;
        state
            .state
            .set_account(brrq_types::account::Account::new_eoa(
                faucet_addr,
                faucet_balance,
            ));
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        AppState::new(shared, event_tx)
    }

    #[tokio::test]
    async fn test_faucet_drip_success() {
        let app = make_app_with_faucet(1_000_000_000);
        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_faucetDrip".into(),
            params: serde_json::json!(["0x0000000000000000000000000000000000000001"]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some(), "faucet should succeed");
        let result = resp.result.unwrap();
        assert_eq!(result["amount"], 100_000_000);

        // Verify recipient got funds
        let ns = app.node.read().await;
        let recipient = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(ns.state.balance(&recipient), 100_000_000);
    }

    #[tokio::test]
    async fn test_faucet_drip_not_configured() {
        // No faucet address set
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_faucetDrip".into(),
            params: serde_json::json!(["0x0000000000000000000000000000000000000001"]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("not configured"));
    }

    #[tokio::test]
    async fn test_faucet_drip_missing_address() {
        let app = make_app_with_faucet(1_000_000_000);
        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_faucetDrip".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_faucet_drip_invalid_address() {
        let app = make_app_with_faucet(1_000_000_000);
        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_faucetDrip".into(),
            params: serde_json::json!(["0xINVALID"]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_faucet_drip_depleted() {
        // Faucet has 50 satoshis but drip is 100M
        let app = make_app_with_faucet(50);
        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_faucetDrip".into(),
            params: serde_json::json!(["0x0000000000000000000000000000000000000001"]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.error.is_some());
        assert!(resp.error.unwrap().message.contains("depleted"));
    }

    #[tokio::test]
    async fn test_faucet_drip_cooldown() {
        let app = make_app_with_faucet(10_000_000_000);
        let addr = "0x0000000000000000000000000000000000000001";

        // First drip should succeed
        let req1 = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_faucetDrip".into(),
            params: serde_json::json!([addr]),
            id: serde_json::json!(1),
        };
        let resp1 = dispatch(req1, &app).await;
        assert!(resp1.result.is_some(), "first drip should succeed");

        // Second drip should fail (cooldown)
        let req2 = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_faucetDrip".into(),
            params: serde_json::json!([addr]),
            id: serde_json::json!(2),
        };
        let resp2 = dispatch(req2, &app).await;
        assert!(resp2.error.is_some(), "second drip should fail (cooldown)");
        assert!(resp2.error.unwrap().message.contains("Cooldown"));
    }

    #[tokio::test]
    async fn test_faucet_multiple_recipients() {
        let app = make_app_with_faucet(10_000_000_000);

        // Three different addresses should all succeed
        for i in 1..=3 {
            let addr = format!("0x{:040x}", i);
            let req = RpcRequest {
                jsonrpc: "2.0".into(),
                method: "brrq_faucetDrip".into(),
                params: serde_json::json!([addr]),
                id: serde_json::json!(i),
            };
            let resp = dispatch(req, &app).await;
            assert!(resp.result.is_some(), "drip {} should succeed", i);
        }

        // Verify total deducted from faucet
        let ns = app.node.read().await;
        let mut faucet_bytes = [0u8; 20];
        faucet_bytes[19] = 0xFA;
        let faucet_addr = brrq_types::address::Address::from_bytes(faucet_bytes);
        assert_eq!(ns.state.balance(&faucet_addr), 10_000_000_000 - 300_000_000);
    }

    // ══════════════════════════════════════════════════════════════════
    // Additional JSON-RPC Method Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_dispatch_get_nonce() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getNonce".into(),
            params: serde_json::json!(["0x0000000000000000000000000000000000000001"]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));
    }

    #[tokio::test]
    async fn test_dispatch_get_balance_with_funds() {
        let mut state = NodeState::new();
        let addr = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        state
            .state
            .set_account(brrq_types::account::Account::new_eoa(addr, 42_000));
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getBalance".into(),
            params: serde_json::json!(["0x0000000000000000000000000000000000000001"]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert_eq!(resp.result.unwrap(), serde_json::json!(42_000));
    }

    #[tokio::test]
    async fn test_dispatch_block_height_with_height() {
        let mut state = NodeState::new();
        state.height = 99;
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_blockHeight".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert_eq!(resp.result.unwrap(), serde_json::json!(99));
    }

    #[tokio::test]
    async fn test_dispatch_get_state_root() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getStateRoot".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some(), "getStateRoot should return a value");
        let result = resp.result.unwrap();
        assert!(
            result.as_str().unwrap().starts_with("0x"),
            "state root should be hex"
        );
    }

    #[tokio::test]
    async fn test_dispatch_get_validators() {
        let mut state = NodeState::new();
        let addr = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        state.staking.register_validator(addr, 100_000_000).unwrap();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getValidators".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        let validators = result["validators"].as_array().unwrap();
        assert_eq!(validators.len(), 1);
        assert_eq!(result["total"], 1);
    }

    #[tokio::test]
    async fn test_dispatch_bridge_status() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_bridgeStatus".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some(), "bridgeStatus should return a value");
        let result = resp.result.unwrap();
        assert_eq!(result["paused"], false);
    }

    #[tokio::test]
    async fn test_dispatch_get_proof_count() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getProofCount".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap(), serde_json::json!(0));
    }

    #[tokio::test]
    async fn test_dispatch_get_epoch_info() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getEpochInfo".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["current_epoch"], 0);
        assert!(result["epoch_length"].as_u64().unwrap() > 0);
    }

    // ══════════════════════════════════════════════════════════════════
    // Parsing Edge Cases
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn test_parse_address_uppercase() {
        let addr = parse_address("0xAABBCCDDEE00112233445566778899AABBCCDDEE");
        assert!(addr.is_some());
    }

    #[test]
    fn test_parse_address_mixed_case() {
        let addr = parse_address("0xaAbBcCdDeE00112233445566778899AaBbCcDdEe");
        assert!(addr.is_some());
    }

    #[test]
    fn test_parse_hash_valid() {
        let hash = parse_hash(&format!("0x{}", "ab".repeat(32)));
        assert!(hash.is_some());
    }

    #[test]
    fn test_parse_hash_invalid() {
        let hash = parse_hash("0xtooshort");
        assert!(hash.is_none());
    }

    #[test]
    fn test_parse_hash_wrong_length() {
        // 31 bytes instead of 32
        let hash = parse_hash(&format!("0x{}", "ab".repeat(31)));
        assert!(hash.is_none());
    }

    // ══════════════════════════════════════════════════════════════════
    // Bitcoin L1 Integration Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_l1_status_disconnected() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getL1Status".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["connected"], false);
    }

    #[tokio::test]
    async fn test_get_l1_status_connected() {
        let mut state = NodeState::new();
        state.l1_connected = true;
        state.l1_height = 850_000;
        state.l1_network = Some("mainnet".into());
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getL1Status".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["connected"], true);
        assert_eq!(result["l1_height"], 850_000);
        assert_eq!(result["network"], "mainnet");
    }

    #[tokio::test]
    async fn test_get_l1_anchors_empty() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getL1Anchors".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        let anchors = result["anchors"].as_array().unwrap();
        assert!(anchors.is_empty());
    }

    #[tokio::test]
    async fn test_get_l1_anchors_with_data() {
        let mut state = NodeState::new();
        state.l1_anchors.push(brrq_bitcoin::L1AnchorRecord {
            l1_tx_id: [42u8; 32],
            l1_height: 850_000,
            block_hash: [0u8; 32],
            l2_height: 1000,
            state_root: brrq_crypto::hash::Hash256::ZERO,
            proof_hash: brrq_crypto::hash::Hash256::ZERO,
            timestamp: 1_700_000_000,
        });
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getL1Anchors".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        let anchors = result["anchors"].as_array().unwrap();
        assert_eq!(anchors.len(), 1);
        assert_eq!(anchors[0]["l1_height"], 850_000);
        assert_eq!(anchors[0]["l2_height"], 1000);
        assert_eq!(anchors[0]["timestamp"], 1_700_000_000);
        assert_eq!(result["total"], 1);
    }

    // ══════════════════════════════════════════════════════════════════
    // Trustless Bridge JSON-RPC Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_proofs_empty() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getProofs".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["total"], 0);
        assert!(result["proofs"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_proof_by_height_not_found() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getProofByHeight".into(),
            params: serde_json::json!([100]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        assert_eq!(resp.result.unwrap(), serde_json::Value::Null);
    }

    #[tokio::test]
    async fn test_get_proof_by_height_missing_param() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getProofByHeight".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_get_challenges_empty() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_getChallenges".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["total"], 0);
        assert_eq!(result["pending"], 0);
        assert!(result["challenges"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_permissionless_withdraw_missing_params() {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        let app = AppState::new(shared, event_tx);

        let req = RpcRequest {
            jsonrpc: "2.0".into(),
            method: "brrq_permissionlessWithdraw".into(),
            params: serde_json::json!([]),
            id: serde_json::json!(1),
        };
        let resp = dispatch(req, &app).await;
        assert!(resp.error.is_some());
    }

    // ── Params Validation Tests ────────────────────────────────────────

    fn make_app() -> AppState {
        let state = NodeState::new();
        let shared: SharedState = std::sync::Arc::new(tokio::sync::RwLock::new(state));
        let (event_tx, _) = crate::events::create_event_channel();
        AppState::new(shared, event_tx)
    }

    #[tokio::test]
    async fn test_params_array_accepted() {
        let app = make_app();
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "brrq_blockHeight",
            "params": [],
            "id": 1
        });
        let resp = dispatch_single(req, &app, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), &crate::middleware::EndpointRateLimiter::new()).await;
        assert!(resp.error.is_none(), "Array params should be accepted");
    }

    #[tokio::test]
    async fn test_params_null_accepted() {
        let app = make_app();
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "brrq_blockHeight",
            "id": 1
        });
        let resp = dispatch_single(req, &app, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), &crate::middleware::EndpointRateLimiter::new()).await;
        assert!(
            resp.error.is_none(),
            "Null/omitted params should be accepted"
        );
    }

    #[tokio::test]
    async fn test_params_object_rejected() {
        let app = make_app();
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "brrq_blockHeight",
            "params": {"key": "value"},
            "id": 1
        });
        let resp = dispatch_single(req, &app, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), &crate::middleware::EndpointRateLimiter::new()).await;
        assert!(resp.error.is_some(), "Object params must be rejected");
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_params_string_rejected() {
        let app = make_app();
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "brrq_blockHeight",
            "params": "not an array",
            "id": 1
        });
        let resp = dispatch_single(req, &app, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), &crate::middleware::EndpointRateLimiter::new()).await;
        assert!(resp.error.is_some(), "String params must be rejected");
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    #[tokio::test]
    async fn test_params_number_rejected() {
        let app = make_app();
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "brrq_blockHeight",
            "params": 42,
            "id": 1
        });
        let resp = dispatch_single(req, &app, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), &crate::middleware::EndpointRateLimiter::new()).await;
        assert!(resp.error.is_some(), "Number params must be rejected");
        assert_eq!(resp.error.as_ref().unwrap().code, -32602);
    }

    // ── Batch Size Limit Tests ───────────────────────────────────────────────

    #[tokio::test]
    async fn test_batch_within_limit() {
        let app = make_app();
        // 5 requests — well within MAX_BATCH_SIZE(50)
        let batch: Vec<serde_json::Value> = (0..5)
            .map(|i| {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "brrq_blockHeight",
                    "params": [],
                    "id": i
                })
            })
            .collect();
        let req = serde_json::Value::Array(batch);
        let resp = handle_jsonrpc(
                axum::extract::ConnectInfo(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)),
                axum::Extension(crate::middleware::EndpointRateLimiter::new()),
                axum::extract::State(app),
                Json(req),
            ).await;
        let arr = resp.0.as_array().unwrap();
        assert_eq!(arr.len(), 5);
    }

    #[tokio::test]
    async fn test_batch_over_limit_rejected() {
        let app = make_app();
        // 51 requests — exceeds MAX_BATCH_SIZE(50)
        let batch: Vec<serde_json::Value> = (0..51)
            .map(|i| {
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": "brrq_blockHeight",
                    "params": [],
                    "id": i
                })
            })
            .collect();
        let req = serde_json::Value::Array(batch);
        let resp = handle_jsonrpc(
                axum::extract::ConnectInfo(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)),
                axum::Extension(crate::middleware::EndpointRateLimiter::new()),
                axum::extract::State(app),
                Json(req),
            ).await;
        // Should return single error, not array
        let error = resp.0.get("error").expect("Should have error");
        assert_eq!(error["code"], -32600);
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("Batch too large")
        );
    }

    #[tokio::test]
    async fn test_batch_empty_rejected() {
        let app = make_app();
        let req = serde_json::Value::Array(vec![]);
        let resp = handle_jsonrpc(
                axum::extract::ConnectInfo(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0)),
                axum::Extension(crate::middleware::EndpointRateLimiter::new()),
                axum::extract::State(app),
                Json(req),
            ).await;
        let error = resp.0.get("error").expect("Should have error");
        assert_eq!(error["code"], -32600);
        assert!(error["message"].as_str().unwrap().contains("empty batch"));
    }

    // ── Oversized Hex Input Rejection Tests ──────────────────────────────────

    #[test]
    fn test_parse_address_oversized_rejected() {
        // 300 char hex string — exceeds MAX_HEX_INPUT_LEN(256)
        let oversized = "0x".to_string() + &"a".repeat(300);
        assert!(
            parse_address(&oversized).is_none(),
            "Oversized hex address must be rejected"
        );
    }

    #[test]
    fn test_parse_hash_oversized_rejected() {
        let oversized = "0x".to_string() + &"b".repeat(300);
        assert!(
            parse_hash(&oversized).is_none(),
            "Oversized hex hash must be rejected"
        );
    }

    #[test]
    fn test_parse_address_at_max_length() {
        // Exactly 256 chars (MAX_HEX_INPUT_LEN) — should be processed (may fail on length check, but not on size guard)
        let max_len = "0x".to_string() + &"a".repeat(254);
        // This will return None because 127 bytes != 20 bytes for address, but
        // the important thing is it doesn't panic or allocate excessively.
        let _ = parse_address(&max_len);
    }
}
