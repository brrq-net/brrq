//! REST API endpoints — for web frontends and block explorers.
//!
//! Handlers in this module are thin transport wrappers around shared service
//! functions in [`crate::services`].  Business logic lives in services.rs.

use std::sync::atomic::Ordering;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::IntoResponse,
    routing::{get, post},
};
use serde::Deserialize;

use brrq_types::transaction::TransactionKind;

use crate::error::ApiError;
use crate::jsonrpc::{SendTxParams, block_to_json, parse_address, parse_hash};
use crate::services;
use crate::state::AppState;

/// Pagination query parameters.
#[derive(Deserialize)]
pub struct PaginationParams {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    20
}

/// Create REST API routes.
pub fn routes() -> Router<AppState> {
    let router = Router::new()
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/blocks", get(list_blocks))
        .route("/blocks/{height}", get(get_block))
        .route("/transactions", post(submit_transaction))
        .route("/transactions/{hash}", get(get_transaction))
        .route("/accounts/{address}", get(get_account))
        .route("/accounts/{address}/balance", get(get_balance))
        .route(
            "/accounts/{address}/transactions",
            get(get_account_transactions),
        )
        .route(
            "/accounts/{address}/state/{height}",
            get(get_account_at_height),
        )
        .route("/validators", get(get_validators))
        .route("/epoch", get(get_epoch))
        .route("/bridge/status", get(get_bridge_status))
        .route("/proofs/latest", get(get_latest_proof))
        .route("/faucet", post(faucet_drip))
        .route("/l1/status", get(l1_status))
        .route("/l1/anchors", get(l1_anchors))
        .route("/l1/anchors/{height}", get(l1_anchor_by_height))
        .route("/proofs", get(list_proofs))
        .route("/proofs/height/{height}", get(get_proof_by_height))
        .route("/bridge/challenges", get(list_challenges))
        .route("/bridge/challenges/submit", post(submit_challenge))
        .route("/bridge/challenges/respond", post(respond_challenge))
        .route("/bridge/operators", get(list_operators))
        .route("/mev/epoch_key", get(mev_epoch_key))
        // ── Governance ────────────────────────────────────────────
        .route(
            "/governance/proposals",
            get(list_governance_proposals).post(submit_governance_proposal),
        )
        .route(
            "/governance/proposals/{id}/vote",
            post(vote_governance_proposal),
        )
        .route("/governance/stats", get(governance_stats))
        // ── Portal (L3) ───────────────────────────────────────────
        .route("/portal/locks/{lock_id}", get(get_portal_lock))
        .route("/portal/nullifiers/{nullifier}", get(check_portal_nullifier))
        .route("/portal/safety/{lock_id}/{nullifier}", get(check_portal_safety))
        .route("/portal/stats", get(portal_stats));

    // ── MEV Protection (conditional) ─────────────────────────────
    #[cfg(feature = "mev-protection")]
    let router = router
        .route("/mev/submit", post(mev_submit))
        .route("/mev/status", get(mev_status));

    // ── Sequencer Registration (conditional) ─────────────────────
    #[cfg(feature = "sequencer-rotation")]
    let router = router
        .route("/sequencers/register", post(register_sequencer))
        .route("/sequencers", get(list_sequencers))
        .route("/sequencers/delegate", post(delegate_stake))
        .route("/sequencers/undelegate", post(undelegate_stake))
        .route("/sequencers/regions", get(sequencer_regions));

    // ── Prover Pools (conditional) ────────────────────────────────
    #[cfg(feature = "prover-pools")]
    let router = router
        .route("/prover-pools/create", post(create_prover_pool))
        .route("/prover-pools/{id}/join", post(join_prover_pool))
        .route("/prover-pools", get(list_prover_pools))
        .route("/prover-pools/stats", get(prover_pool_stats));

    router
}

/// Prometheus-compatible metrics endpoint (mounted at /metrics, outside /api/v1).
pub fn metrics_routes() -> Router<AppState> {
    Router::new().route("/metrics", get(prometheus_metrics))
}

/// Enhanced health check with dynamic node status.
async fn health(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    let challenge_stats = ns.bridge.challenge_manager.stats();
    let ws_count = crate::websocket::active_ws_connections();

    // Dynamic health status based on node conditions.
    let status = if ns.height == 0 && ns.blocks.is_empty() {
        "initializing"
    } else if !ns.l1_connected && ns.l1_network.is_some() {
        "degraded" // L1 configured but disconnected
    } else {
        "ok"
    };

    // Syncing heuristic: if we have peers and recent blocks are old,
    // or if height is 0 but we're supposed to be running.
    let syncing = ns.height == 0 && ns.l1_connected;

    #[allow(unused_mut)]
    let mut health_json = serde_json::json!({
        "status": status,
        "version": env!("CARGO_PKG_VERSION"),
        "height": ns.height,
        "epoch": ns.epoch.current_epoch,
        "validator_count": ns.staking.validators.len(),
        "mempool_size": ns.mempool.len(),
        "syncing": syncing,
        "l1_connected": ns.l1_connected,
        "l1_height": ns.l1_height,
        "peer_count": ns.peer_count,
        "ws_connections": ws_count,
        "challenges_active": challenge_stats.pending,
        "proofs_stored": ns.bridge.proof_store.count(),
        "operators_registered": ns.bridge.operator_manager.operator_count(),
        "governance_active_proposals": ns.governance.stats().active_proposals,
        "mev_mode": format!("{:?}", ns.mev_mode),
    });
    #[cfg(feature = "sequencer-rotation")]
    {
        health_json["registered_sequencers"] = serde_json::json!(ns.registration.count());
    }
    #[cfg(feature = "prover-pools")]
    {
        health_json["prover_pools"] = serde_json::json!(ns.prover_pools.stats().total_pools);
    }
    Json(health_json)
}

/// Network statistics.
async fn stats(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_stats(&ns))
}

/// List blocks with pagination.
async fn list_blocks(
    State(app): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    let total = ns.height as usize;
    let limit = params.limit.min(100); // cap at 100
    // Return latest blocks first (height is 1-indexed)
    let top = total.saturating_sub(params.offset);
    let bottom = top.saturating_sub(limit);

    let mut blocks = Vec::new();
    // Iterate from top down to bottom (latest first)
    for h in (bottom..top).rev() {
        if let Some(block) = ns.get_block((h + 1) as u64) {
            blocks.push(block_to_json(&block));
        }
    }

    Json(serde_json::json!({
        "blocks": blocks,
        "total": total,
        "limit": limit,
        "offset": params.offset,
    }))
}

/// Get block by height.
async fn get_block(
    State(app): State<AppState>,
    Path(height): Path<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ns = app.node.read().await;
    match ns.get_block(height) {
        Some(block) => {
            let mut json = block_to_json(&block);
            // Add transactions array with full details
            let txs: Vec<serde_json::Value> = block
                .transactions
                .iter()
                .map(|tx| tx_to_rest_json(tx, Some(block.header.height)))
                .collect();
            json.as_object_mut()
                .unwrap()
                .insert("transactions".to_string(), serde_json::Value::Array(txs));
            Ok(Json(json))
        }
        None => Err(ApiError::NotFound(format!("Block {} not found", height))),
    }
}

/// Get transaction by hash.
async fn get_transaction(
    State(app): State<AppState>,
    Path(hash_str): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let hash = parse_hash(&hash_str).ok_or_else(|| ApiError::BadRequest("Invalid hash".into()))?;
    let ns = app.node.read().await;
    // Search recent in-memory blocks for the transaction
    for block in &ns.blocks {
        for tx in &block.transactions {
            if tx.hash() == hash {
                return Ok(Json(tx_to_rest_json(tx, Some(block.header.height))));
            }
        }
    }
    // Also check receipts for block height, then fetch from store
    if let Some(receipt) = ns.receipts.get(&hash)
        && let Some(block) = ns.get_block(receipt.block_height)
    {
        for tx in &block.transactions {
            if tx.hash() == hash {
                return Ok(Json(tx_to_rest_json(tx, Some(block.header.height))));
            }
        }
    }
    Err(ApiError::NotFound("Transaction not found".into()))
}

/// Get account details.
async fn get_account(
    State(app): State<AppState>,
    Path(addr_str): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let address =
        parse_address(&addr_str).ok_or_else(|| ApiError::BadRequest("Invalid address".into()))?;
    let ns = app.node.read().await;
    Ok(Json(services::get_account(&ns, &address)))
}

/// Get balance only.
async fn get_balance(
    State(app): State<AppState>,
    Path(addr_str): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let address =
        parse_address(&addr_str).ok_or_else(|| ApiError::BadRequest("Invalid address".into()))?;
    let ns = app.node.read().await;
    Ok(Json(services::get_balance(&ns, &address)))
}

/// Get account state at a specific block height.
///
/// Replays balance changes from blocks to reconstruct the account state
/// at the requested height. Only works for heights within in-memory blocks.
async fn get_account_at_height(
    State(app): State<AppState>,
    Path((addr_str, height)): Path<(String, u64)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let address =
        parse_address(&addr_str).ok_or_else(|| ApiError::BadRequest("Invalid address".into()))?;
    let ns = app.node.read().await;
    let result = services::get_account_at_height(&ns, &address, height)?;
    Ok(Json(result))
}

/// Get transactions by address with pagination.
///
/// Scans recent in-memory blocks for transactions where the address is
/// sender (`from`) or recipient (`to`). Returns latest-first.
async fn get_account_transactions(
    State(app): State<AppState>,
    Path(addr_str): Path<String>,
    Query(params): Query<PaginationParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let address =
        parse_address(&addr_str).ok_or_else(|| ApiError::BadRequest("Invalid address".into()))?;
    let ns = app.node.read().await;
    let limit = params.limit.min(100);
    let mut txs: Vec<serde_json::Value> = Vec::new();
    // Scan blocks newest-first for efficiency.
    'outer: for block in ns.blocks.iter().rev() {
        for tx in &block.transactions {
            let is_sender = tx.body.from == address;
            let is_recipient = match &tx.body.kind {
                TransactionKind::Transfer { to, .. } => *to == address,
                TransactionKind::ContractCall { to, .. } => *to == address,
                _ => false,
            };
            if is_sender || is_recipient {
                if params.offset > 0 && txs.len() < params.offset {
                    // skip for offset (reuse counter)
                    txs.push(serde_json::Value::Null); // placeholder
                    continue;
                }
                if txs.len() >= params.offset + limit {
                    break 'outer;
                }
                txs.push(tx_to_rest_json(tx, Some(block.header.height)));
            }
        }
    }
    // Remove offset placeholders.
    let result: Vec<serde_json::Value> = txs.into_iter().skip(params.offset).collect();
    Ok(Json(serde_json::json!({
        "address": format!("0x{}", hex::encode(address.as_bytes())),
        "transactions": result,
        "limit": limit,
        "offset": params.offset,
    })))
}

/// Get validators with pagination (default 100, max 200).
async fn get_validators(
    State(app): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_validators(&ns, params.limit, params.offset))
}

/// Get epoch info.
async fn get_epoch(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_epoch_info(&ns))
}

/// Get bridge status.
async fn get_bridge_status(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_bridge_status(&ns))
}

/// Get latest STARK proof.
async fn get_latest_proof(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_latest_proof(&ns))
}

/// Convert a transaction to a JSON value with full details.
fn tx_to_rest_json(
    tx: &brrq_types::transaction::Transaction,
    block_height: Option<u64>,
) -> serde_json::Value {
    services::tx_to_json(tx, block_height)
}

/// Submit a new transaction (POST /api/v1/transactions).
async fn submit_transaction(
    State(app): State<AppState>,
    Json(tx_params): Json<SendTxParams>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let tx = services::build_transaction(&tx_params)?;
    let mut ns = app.node.write().await;
    let hash_hex = services::submit_to_mempool(&mut ns, tx)?;
    Ok(Json(serde_json::json!({ "hash": hash_hex })))
}

/// Faucet request body.
#[derive(Deserialize)]
struct FaucetRequest {
    address: String,
}

/// Testnet faucet — distributes tokens to requesting addresses.
async fn faucet_drip(
    State(app): State<AppState>,
    Json(req): Json<FaucetRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let recipient = parse_address(&req.address)
        .ok_or_else(|| ApiError::BadRequest("Invalid address".into()))?;
    let mut ns = app.node.write().await;
    let result = services::faucet_drip(&mut ns, recipient)?;
    Ok(Json(result))
}

/// Get Bitcoin L1 connection status.
async fn l1_status(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_l1_status(&ns))
}

/// List L1 anchors with pagination.
async fn l1_anchors(
    State(app): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_l1_anchors(&ns, params.limit, params.offset))
}

/// Get a specific anchor by L2 height.
///
/// NOTE: Uses linear search over in-memory anchors. This is acceptable
/// because the anchor list grows slowly (one per checkpoint_interval L2
/// blocks). If the list grows large, consider a HashMap<u64, usize> index.
async fn l1_anchor_by_height(
    State(app): State<AppState>,
    Path(height): Path<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ns = app.node.read().await;
    let result = services::get_l1_anchor_by_height(&ns, height)?;
    Ok(Json(result))
}

/// List all stored proofs.
async fn list_proofs(
    State(app): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::list_proofs(&ns, params.limit, params.offset))
}

/// Get proof covering a specific L2 height.
async fn get_proof_by_height(
    State(app): State<AppState>,
    Path(height): Path<u64>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ns = app.node.read().await;
    let result = services::get_proof_by_height(&ns, height)?;
    Ok(Json(result))
}

/// List all challenges.
async fn list_challenges(
    State(app): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::list_challenges(&ns, params.limit, params.offset))
}

/// List all registered operators.
async fn list_operators(
    State(app): State<AppState>,
    Query(params): Query<PaginationParams>,
) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::list_operators(&ns, params.limit, params.offset))
}

/// Submit a challenge.
///
/// Body: `{ "challenger": "0x...", "challenge_type": "InvalidStateRoot",
///          "claimed_state_root": "0x...", "actual_state_root": "0x...", "l2_height": 100,
///          "signature": "0x...", "public_key": "0x..." }`
async fn submit_challenge(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let challenger_hex = body["challenger"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing challenger".into()))?;
    let challenger = parse_address(challenger_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid challenger address".into()))?;

    // Verify Schnorr signature from the challenger.
    services::verify_body_signature(&body, &challenger)?;

    let (challenge_type, ct_str) = services::parse_challenge_type(&body)?;

    let mut ns = app.node.write().await;
    let result =
        services::submit_challenge(&mut ns, challenger, challenger_hex, challenge_type, ct_str)?;
    Ok(Json(result))
}

/// Respond to a challenge (operator defense).
///
/// Body: `{ "challenge_id": "0x...", "proof_hash": "0x...",
///          "correct_state_root": "0x...", "responder": "0x...", "proof_hex": "..." }`
async fn respond_challenge(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let challenge_id_hex = body["challenge_id"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing challenge_id".into()))?;
    let challenge_id = parse_hash(challenge_id_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid challenge_id".into()))?;

    let proof_hash_hex = body["proof_hash"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing proof_hash".into()))?;
    let proof_hash = parse_hash(proof_hash_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid proof_hash".into()))?;

    let state_root_hex = body["correct_state_root"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing correct_state_root".into()))?;
    let correct_state_root = parse_hash(state_root_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid correct_state_root".into()))?;

    let responder_hex = body["responder"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing responder".into()))?;
    let responder = parse_address(responder_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid responder address".into()))?;

    let proof_hex = body["proof_hex"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing proof_hex".into()))?;

    // Verify Schnorr signature from the responder.
    services::verify_body_signature(&body, &responder)
        .map_err(|e| ApiError::Unauthorized(e.message().to_string()))?;

    let mut ns = app.node.write().await;
    let result = services::respond_to_challenge(
        &mut ns,
        &challenge_id,
        proof_hash,
        correct_state_root,
        responder,
        proof_hex,
    )?;
    Ok(Json(result))
}

// ══════════════════════════════════════════════════════════════════
// MEV Protection endpoints
// ══════════════════════════════════════════════════════════════════

/// Submit an encrypted transaction envelope for MEV-protected inclusion.
///
/// Body: `{ "envelope_hex": "..." }` — hex-encoded EncryptedEnvelope.
#[cfg(feature = "mev-protection")]
async fn mev_submit(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let envelope_hex = body["envelope_hex"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing envelope_hex".into()))?;
    let mut ns = app.node.write().await;
    let result = services::submit_mev_envelope(&mut ns, envelope_hex)?;
    Ok(Json(result))
}

/// Get current MEV mempool status.
#[cfg(feature = "mev-protection")]
async fn mev_status(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_mev_status(&ns))
}

/// Get the current epoch encryption key (public info for envelope creation).
async fn mev_epoch_key(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_mev_epoch_key(&ns))
}

// ══════════════════════════════════════════════════════════════════
// Governance endpoints
// ══════════════════════════════════════════════════════════════════

/// List governance proposals.
async fn list_governance_proposals(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::list_proposals(&ns))
}

/// Submit a governance proposal.
///
/// Body: `{ "proposer": "0x...", "proposal_type": "FeeChange",
///          "parameter": "gas_limit", "old_value": 30000000, "new_value": 50000000,
///          "signature": "0x...", "public_key": "0x..." }`
async fn submit_governance_proposal(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let proposer_hex = body["proposer"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing proposer".into()))?;
    let proposer = parse_address(proposer_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid proposer address".into()))?;
    if proposer.is_zero() {
        return Err(ApiError::BadRequest(
            "proposer address must not be zero".into(),
        ));
    }

    // Verify Schnorr signature from the proposer.
    services::verify_body_signature(&body, &proposer)?;

    let (proposal_type, pt_str) = services::parse_proposal_type(&body)?;

    let mut ns = app.node.write().await;
    let result = services::submit_proposal(&mut ns, proposer, proposer_hex, proposal_type, pt_str)?;
    Ok(Json(result))
}

/// Vote on a governance proposal.
///
/// Body: `{ "voter": "0x...", "vote": "Yes", "chamber": "sequencer",
///          "signature": "0x...", "public_key": "0x..." }`
async fn vote_governance_proposal(
    State(app): State<AppState>,
    Path(id_hex): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let proposal_id =
        parse_hash(&id_hex).ok_or_else(|| ApiError::BadRequest("invalid proposal ID".into()))?;
    let voter_hex = body["voter"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing voter".into()))?;
    let voter = parse_address(voter_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid voter address".into()))?;
    if voter.is_zero() {
        return Err(ApiError::BadRequest(
            "voter address must not be zero".into(),
        ));
    }

    // Verify Schnorr signature from the voter.
    services::verify_body_signature(&body, &voter)?;

    let vote_str = body["vote"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing or invalid vote".into()))?;
    let vote = services::parse_vote(vote_str)?;
    let chamber = body["chamber"].as_str().unwrap_or("user");

    let mut ns = app.node.write().await;
    let result = services::vote_on_proposal(
        &mut ns,
        &proposal_id,
        voter,
        voter_hex,
        vote,
        vote_str,
        chamber,
    )?;
    Ok(Json(result))
}

/// Governance statistics.
async fn governance_stats(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_governance_stats(&ns))
}

// ══════════════════════════════════════════════════════════════════
// Sequencer Registration endpoints
// ══════════════════════════════════════════════════════════════════

/// Register a new sequencer.
///
/// Body: `{ "address": "0x...", "self_stake": 100000000, "region": "Asia", "commission_bp": 500,
///          "signature": "0x...", "public_key": "0x..." }`
#[cfg(feature = "sequencer-rotation")]
async fn register_sequencer(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let addr_hex = body["address"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing address".into()))?;
    let address =
        parse_address(addr_hex).ok_or_else(|| ApiError::BadRequest("invalid address".into()))?;
    if address.is_zero() {
        return Err(ApiError::BadRequest("address must not be zero".into()));
    }

    // Verify Schnorr signature from the registering sequencer.
    services::verify_body_signature(&body, &address)?;

    let self_stake = body["self_stake"]
        .as_u64()
        .ok_or_else(|| ApiError::BadRequest("missing self_stake".into()))?;
    let region_str = body["region"].as_str().unwrap_or("Unknown");
    let region = services::parse_region(region_str);
    let commission_bp = body["commission_bp"].as_u64().unwrap_or(0);

    let mut ns = app.node.write().await;
    let result = services::register_sequencer(
        &mut ns,
        address,
        addr_hex,
        self_stake,
        region,
        region_str,
        commission_bp,
    )?;
    Ok(Json(result))
}

/// List all registered sequencers.
#[cfg(feature = "sequencer-rotation")]
async fn list_sequencers(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::list_sequencers(&ns))
}

/// Delegate stake to a sequencer.
///
/// Body: `{ "delegator": "0x...", "sequencer": "0x...", "amount": 100000,
///          "signature": "0x...", "public_key": "0x..." }`
#[cfg(feature = "sequencer-rotation")]
async fn delegate_stake(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let delegator_hex = body["delegator"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing delegator".into()))?;
    let delegator = parse_address(delegator_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid delegator address".into()))?;
    if delegator.is_zero() {
        return Err(ApiError::BadRequest(
            "delegator address must not be zero".into(),
        ));
    }

    // Verify Schnorr signature from the delegator.
    services::verify_body_signature(&body, &delegator)?;

    let seq_hex = body["sequencer"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing sequencer".into()))?;
    let sequencer = parse_address(seq_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid sequencer address".into()))?;
    let amount = body["amount"]
        .as_u64()
        .ok_or_else(|| ApiError::BadRequest("missing amount".into()))?;

    let mut ns = app.node.write().await;
    let result = services::delegate_stake(
        &mut ns,
        delegator,
        delegator_hex,
        sequencer,
        seq_hex,
        amount,
    )?;
    Ok(Json(result))
}

/// Undelegate stake from a sequencer.
///
/// Body: `{ "delegator": "0x...", "sequencer": "0x...",
///          "signature": "0x...", "public_key": "0x..." }`
#[cfg(feature = "sequencer-rotation")]
async fn undelegate_stake(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let delegator = parse_address(body["delegator"].as_str().unwrap_or(""))
        .ok_or_else(|| ApiError::BadRequest("invalid delegator address".into()))?;
    let sequencer = parse_address(body["sequencer"].as_str().unwrap_or(""))
        .ok_or_else(|| ApiError::BadRequest("invalid sequencer address".into()))?;
    if delegator.is_zero() {
        return Err(ApiError::BadRequest(
            "delegator address must not be zero".into(),
        ));
    }

    // Verify Schnorr signature from the delegator.
    services::verify_body_signature(&body, &delegator)?;

    let mut ns = app.node.write().await;
    let result = services::undelegate_stake(&mut ns, delegator, sequencer)?;
    Ok(Json(result))
}

/// Sequencer geographic region distribution.
#[cfg(feature = "sequencer-rotation")]
async fn sequencer_regions(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_sequencer_regions(&ns))
}

// ══════════════════════════════════════════════════════════════════
// Prover Pool endpoints
// ══════════════════════════════════════════════════════════════════

/// Create a prover pool.
///
/// Body: `{ "coordinator": "0x...", "name": "Pool Alpha", "fee_bp": 500 }`
#[cfg(feature = "prover-pools")]
async fn create_prover_pool(
    State(app): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let coord_hex = body["coordinator"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing coordinator".into()))?;
    let coordinator = parse_address(coord_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid coordinator address".into()))?;
    let name = body["name"].as_str().unwrap_or("unnamed").to_string();
    let fee_bp = body["fee_bp"].as_u64().unwrap_or(0);

    let mut ns = app.node.write().await;
    let result = services::create_prover_pool(&mut ns, coordinator, coord_hex, name, fee_bp)?;
    Ok(Json(result))
}

/// Join a prover pool.
///
/// Body: `{ "member": "0x...", "weight": 50 }`
#[cfg(feature = "prover-pools")]
async fn join_prover_pool(
    State(app): State<AppState>,
    Path(id_hex): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let pool_id =
        parse_hash(&id_hex).ok_or_else(|| ApiError::BadRequest("invalid pool ID".into()))?;
    let member_hex = body["member"]
        .as_str()
        .ok_or_else(|| ApiError::BadRequest("missing member".into()))?;
    let member = parse_address(member_hex)
        .ok_or_else(|| ApiError::BadRequest("invalid member address".into()))?;
    let weight = body["weight"].as_u64().unwrap_or(50);

    let mut ns = app.node.write().await;
    let result = services::join_prover_pool(&mut ns, pool_id, member, member_hex, weight)?;
    Ok(Json(result))
}

/// List all prover pools.
#[cfg(feature = "prover-pools")]
async fn list_prover_pools(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::list_prover_pools(&ns))
}

/// Prover pool statistics.
#[cfg(feature = "prover-pools")]
async fn prover_pool_stats(State(app): State<AppState>) -> Json<serde_json::Value> {
    let ns = app.node.read().await;
    Json(services::get_prover_pool_stats(&ns))
}

/// Prometheus-format metrics (plain text).
///
/// Counter metrics (blocks_produced, tx_total, peer_count) are read from
/// lock-free `AtomicU64` counters to reduce read-lock contention on NodeState.
/// Security defense counters are also lock-free AtomicU64.
/// Other metrics still require the read lock.
///
/// Metrics expose internal node state (block height, peer count,
/// security counters). Require API key when auth is enabled to prevent
/// reconnaissance by unauthenticated attackers.
async fn prometheus_metrics(
    headers: axum::http::HeaderMap,
    State(app): State<AppState>,
) -> impl IntoResponse {
    // Require API key for metrics when auth is globally enabled.
    if crate::middleware::is_metrics_auth_required() {
        let authorized = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(|token| crate::middleware::verify_api_key(token))
            .unwrap_or(false);
        if !authorized {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                "Metrics require API key (Authorization: Bearer <key>)\n".to_string(),
            )
                .into_response();
        }
    }
    // Read counter metrics from lock-free atomics (no RwLock needed).
    let blocks_produced = app.metrics.blocks_produced.load(Ordering::Relaxed);
    let tx_total = app.metrics.tx_processed.load(Ordering::Relaxed);
    let peer_count = app.metrics.peer_count.load(Ordering::Relaxed);

    // Read security defense counters (lock-free).
    let rate_limited = app.security.rate_limited_total.load(Ordering::Relaxed);
    let header_oversized = app.security.header_oversized_total.load(Ordering::Relaxed);
    let conn_rejected = app
        .security
        .connection_rejected_total
        .load(Ordering::Relaxed);
    let auth_failed = app.security.auth_failed_total.load(Ordering::Relaxed);
    let request_timeout = app.security.request_timeout_total.load(Ordering::Relaxed);

    // Other metrics still require the read lock.
    let ns = app.node.read().await;
    let lines = format!(
        "# HELP brrq_block_height Current block height.\n\
         # TYPE brrq_block_height gauge\n\
         brrq_block_height {}\n\
         # HELP brrq_peer_count Number of connected peers.\n\
         # TYPE brrq_peer_count gauge\n\
         brrq_peer_count {}\n\
         # HELP brrq_mempool_size Transactions in mempool.\n\
         # TYPE brrq_mempool_size gauge\n\
         brrq_mempool_size {}\n\
         # HELP brrq_validator_count Active validators.\n\
         # TYPE brrq_validator_count gauge\n\
         brrq_validator_count {}\n\
         # HELP brrq_epoch Current epoch number.\n\
         # TYPE brrq_epoch gauge\n\
         brrq_epoch {}\n\
         # HELP brrq_blocks_produced_total Total blocks produced by this node.\n\
         # TYPE brrq_blocks_produced_total counter\n\
         brrq_blocks_produced_total {}\n\
         # HELP brrq_tx_total Total transactions processed.\n\
         # TYPE brrq_tx_total counter\n\
         brrq_tx_total {}\n\
         # HELP brrq_l1_connected Bitcoin L1 connection status.\n\
         # TYPE brrq_l1_connected gauge\n\
         brrq_l1_connected {}\n\
         # HELP brrq_l1_height Current Bitcoin L1 block height.\n\
         # TYPE brrq_l1_height gauge\n\
         brrq_l1_height {}\n\
         # HELP brrq_l1_anchor_count Total L1 anchors posted.\n\
         # TYPE brrq_l1_anchor_count counter\n\
         brrq_l1_anchor_count {}\n\
         # HELP brrq_rate_limited_total Requests rejected by rate limiter (429).\n\
         # TYPE brrq_rate_limited_total counter\n\
         brrq_rate_limited_total {}\n\
         # HELP brrq_header_oversized_total Requests rejected by header size check (431).\n\
         # TYPE brrq_header_oversized_total counter\n\
         brrq_header_oversized_total {}\n\
         # HELP brrq_connection_rejected_total TCP connections rejected by per-IP limit.\n\
         # TYPE brrq_connection_rejected_total counter\n\
         brrq_connection_rejected_total {}\n\
         # HELP brrq_auth_failed_total Requests with invalid API key (401).\n\
         # TYPE brrq_auth_failed_total counter\n\
         brrq_auth_failed_total {}\n\
         # HELP brrq_request_timeout_total Requests killed by timeout (408).\n\
         # TYPE brrq_request_timeout_total counter\n\
         brrq_request_timeout_total {}\n",
        ns.height,
        peer_count,
        ns.mempool.len(),
        ns.staking.validators.len(),
        ns.epoch.current_epoch,
        blocks_produced,
        tx_total,
        ns.l1_connected as u8,
        ns.l1_height,
        ns.l1_anchors.len() as u64,
        rate_limited,
        header_oversized,
        conn_rejected,
        auth_failed,
        request_timeout,
    );
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        lines,
    )
        .into_response()
}

// ── Portal (L3) REST handlers ──────────────────────────────────────

/// GET /api/v1/portal/locks/{lock_id}
async fn get_portal_lock(
    State(app): State<AppState>,
    Path(lock_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ns = app.node.read().await;
    let result = crate::portal::get_portal_lock(&ns, &lock_id)?;
    Ok(Json(result))
}

/// GET /api/v1/portal/nullifiers/{nullifier}
async fn check_portal_nullifier(
    State(app): State<AppState>,
    Path(nullifier): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ns = app.node.read().await;
    let result = crate::portal::check_nullifier(&ns, &nullifier)?;
    Ok(Json(result))
}

/// GET /api/v1/portal/safety/{lock_id}/{nullifier}
///
/// Atomic safety check for merchants. Combines all Portal safety checks
/// (lock status, nullifier, mempool awareness) into a single query.
async fn check_portal_safety(
    State(app): State<AppState>,
    Path((lock_id, nullifier)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ns = app.node.read().await;
    let current_block = ns.height;
    let result = crate::portal::check_portal_safety(&ns, &lock_id, &nullifier, current_block)?;
    Ok(Json(result))
}

/// GET /api/v1/portal/stats
async fn portal_stats(
    State(app): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let ns = app.node.read().await;
    let result = crate::portal::get_portal_stats(&ns)?;
    Ok(Json(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::create_event_channel;
    use crate::state::{NodeState, SharedState};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use brrq_crypto::eots::{EotsNonceCommitment, EotsSignature};
    use brrq_crypto::hash::Hash256;
    use brrq_crypto::schnorr::SchnorrPublicKey;
    use brrq_crypto::slh_dsa::{SlhDsaPublicKey, SlhDsaSignature};
    use brrq_types::account::Account;
    use brrq_types::address::Address;
    use brrq_types::block::{Block, BlockHeader, DualSignature, SequencerIdentity};
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::ServiceExt; // for `oneshot`

    fn test_addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from_bytes(bytes)
    }

    fn mock_dual_sig() -> DualSignature {
        DualSignature {
            eots: EotsSignature::new_unchecked(
                EotsNonceCommitment::from_bytes_unchecked(vec![0u8; 33]),
                vec![0u8; 32],
            ),
            slh_dsa: SlhDsaSignature::from_bytes(vec![0u8; 7856]).unwrap(),
        }
    }

    fn mock_identity() -> SequencerIdentity {
        SequencerIdentity {
            schnorr_pk: SchnorrPublicKey::from_bytes([0u8; 32]),
            slh_dsa_pk: SlhDsaPublicKey::from_bytes(vec![0u8; 32]).unwrap(),
            address: Address::ZERO,
        }
    }

    fn make_block(height: u64) -> Block {
        let header = BlockHeader {
            height,
            parent_hash: Hash256::ZERO,
            state_root: Hash256::ZERO,
            transactions_root: Hash256::ZERO,
            signatures_root: Hash256::ZERO,
            timestamp: height * 3,
            sequencer: test_addr(1),
            gas_used: 0,
            gas_limit: 30_000_000,
            base_fee_per_gas: 10,
            epoch: 0,
            l1_anchor_height: None,
            l1_anchor_hash: None,
            portal_nullifier_root: None,
            portal_escrow_blob_hash: None,
        };
        Block {
            header,
            transactions: Vec::new(),
            signature: mock_dual_sig(),
            sequencer_identity: mock_identity(),
        }
    }

    fn make_app_state() -> AppState {
        let state = NodeState::new();
        let shared: SharedState = Arc::new(RwLock::new(state));
        let (event_tx, _) = create_event_channel();
        AppState::new(shared, event_tx)
    }

    fn make_app(state: AppState) -> Router {
        Router::new()
            .nest("/api/v1", routes())
            .merge(metrics_routes())
            .with_state(state)
    }

    async fn get_json(app: &Router, path: &str) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or(serde_json::json!(null));
        (status, json)
    }

    async fn post_json(
        app: &Router,
        path: &str,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value) {
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = resp.status();
        let body_bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value =
            serde_json::from_slice(&body_bytes).unwrap_or(serde_json::json!(null));
        (status, json)
    }

    async fn get_text(app: &Router, path: &str) -> (StatusCode, String) {
        let resp = app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[test]
    fn test_default_pagination() {
        let params: PaginationParams = serde_json::from_str("{}").unwrap();
        assert_eq!(params.limit, 20);
        assert_eq!(params.offset, 0);
    }

    #[test]
    fn test_custom_pagination() {
        let params: PaginationParams = serde_json::from_str(r#"{"limit":50,"offset":10}"#).unwrap();
        assert_eq!(params.limit, 50);
        assert_eq!(params.offset, 10);
    }

    // ══════════════════════════════════════════════════════════════════
    // Health Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_health_endpoint() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "initializing"); // height=0, empty blocks
        assert_eq!(json["height"], 0);
        assert_eq!(json["epoch"], 0);
        assert_eq!(json["mempool_size"], 0);
        assert_eq!(json["syncing"], false);
        assert!(json["version"].is_string());
        assert!(json["validator_count"].is_number());
        assert!(json["peer_count"].is_number());
        assert!(json["ws_connections"].is_number());
    }

    #[tokio::test]
    async fn test_health_reflects_height() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.height = 42;
        }
        let app = make_app(app_state);
        let (_, json) = get_json(&app, "/api/v1/health").await;
        assert_eq!(json["height"], 42);
    }

    // ══════════════════════════════════════════════════════════════════
    // Stats Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_stats_endpoint() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/stats").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["block_height"], 0);
        assert_eq!(json["tx_count"], 0);
        assert_eq!(json["block_count"], 0);
        assert_eq!(json["mempool_size"], 0);
    }

    #[tokio::test]
    async fn test_stats_with_blocks() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.height = 5;
            for i in 1..=5 {
                ns.push_block(make_block(i));
            }
        }
        let app = make_app(app_state);
        let (_, json) = get_json(&app, "/api/v1/stats").await;
        assert_eq!(json["block_height"], 5);
        assert_eq!(json["block_count"], 5);
    }

    // ══════════════════════════════════════════════════════════════════
    // Prometheus Metrics Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, text) = get_text(&app, "/metrics").await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("brrq_block_height 0"));
        assert!(text.contains("brrq_peer_count 0"));
        assert!(text.contains("brrq_mempool_size 0"));
        assert!(text.contains("brrq_epoch 0"));
        assert!(text.contains("brrq_blocks_produced_total 0"));
        assert!(text.contains("brrq_tx_total 0"));
    }

    #[tokio::test]
    async fn test_metrics_reflects_state() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.height = 100;
            ns.blocks_produced_total = 100;
            ns.tx_total = 500;
        }
        // Also update lock-free counters (prometheus_metrics reads from atomics).
        app_state
            .metrics
            .blocks_produced
            .store(100, std::sync::atomic::Ordering::Relaxed);
        app_state
            .metrics
            .tx_processed
            .store(500, std::sync::atomic::Ordering::Relaxed);
        let app = make_app(app_state);
        let (_, text) = get_text(&app, "/metrics").await;
        assert!(text.contains("brrq_block_height 100"));
        assert!(text.contains("brrq_blocks_produced_total 100"));
        assert!(text.contains("brrq_tx_total 500"));
    }

    #[tokio::test]
    async fn test_metrics_contains_help_and_type() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (_, text) = get_text(&app, "/metrics").await;
        assert!(text.contains("# HELP brrq_block_height"));
        assert!(text.contains("# TYPE brrq_block_height gauge"));
        assert!(text.contains("# HELP brrq_blocks_produced_total"));
        assert!(text.contains("# TYPE brrq_blocks_produced_total counter"));
        assert!(text.contains("# HELP brrq_tx_total"));
        assert!(text.contains("# TYPE brrq_tx_total counter"));
    }

    // ══════════════════════════════════════════════════════════════════
    // Faucet Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_faucet_not_configured() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = post_json(
            &app,
            "/api/v1/faucet",
            serde_json::json!({"address": "0x0000000000000000000000000000000000000001"}),
        )
        .await;
        // Faucet address is None → should fail with 400
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json.to_string().contains("not configured"));
    }

    #[tokio::test]
    async fn test_faucet_success() {
        let app_state = make_app_state();
        let faucet_addr = test_addr(0xFA);
        let recipient_addr = test_addr(0x01);
        {
            let mut ns = app_state.node.write().await;
            ns.faucet_address = Some(faucet_addr);
            ns.faucet_drip_amount = 1_000_000;
            ns.faucet_cooldown_secs = 3600;
            // Fund the faucet
            ns.state
                .set_account(Account::new_eoa(faucet_addr, 100_000_000));
        }
        let app = make_app(app_state.clone());
        let addr_hex = format!("0x{}", hex::encode(recipient_addr.as_bytes()));
        let (status, json) = post_json(
            &app,
            "/api/v1/faucet",
            serde_json::json!({"address": addr_hex}),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["amount"], 1_000_000);
        assert_eq!(json["tx_hash"], "faucet_direct_credit");

        // Verify balances
        let ns = app_state.node.read().await;
        assert_eq!(ns.state.balance(&recipient_addr), 1_000_000);
        assert_eq!(ns.state.balance(&faucet_addr), 99_000_000);
    }

    #[tokio::test]
    async fn test_faucet_cooldown() {
        let app_state = make_app_state();
        let faucet_addr = test_addr(0xFA);
        let recipient_addr = test_addr(0x01);
        {
            let mut ns = app_state.node.write().await;
            ns.faucet_address = Some(faucet_addr);
            ns.faucet_drip_amount = 1_000;
            ns.faucet_cooldown_secs = 3600;
            ns.state
                .set_account(Account::new_eoa(faucet_addr, 100_000_000));
        }
        let addr_hex = format!("0x{}", hex::encode(recipient_addr.as_bytes()));

        // First request should succeed
        let app = make_app(app_state.clone());
        let (status1, json1) = post_json(
            &app,
            "/api/v1/faucet",
            serde_json::json!({"address": &addr_hex}),
        )
        .await;
        assert_eq!(status1, StatusCode::OK);
        assert_eq!(json1["amount"], 1_000);
        assert_eq!(json1["tx_hash"], "faucet_direct_credit");

        // Second request should fail (cooldown active)
        let app = make_app(app_state.clone());
        let (status2, json2) = post_json(
            &app,
            "/api/v1/faucet",
            serde_json::json!({"address": &addr_hex}),
        )
        .await;
        assert_eq!(status2, StatusCode::BAD_REQUEST);
        assert!(json2.to_string().contains("Cooldown"));
    }

    #[tokio::test]
    async fn test_faucet_different_addresses_no_cooldown() {
        let app_state = make_app_state();
        let faucet_addr = test_addr(0xFA);
        {
            let mut ns = app_state.node.write().await;
            ns.faucet_address = Some(faucet_addr);
            ns.faucet_drip_amount = 1_000;
            ns.faucet_cooldown_secs = 3600;
            ns.state
                .set_account(Account::new_eoa(faucet_addr, 100_000_000));
        }

        // Two different addresses should both succeed
        let addr1_hex = format!("0x{}", hex::encode(test_addr(0x01).as_bytes()));
        let addr2_hex = format!("0x{}", hex::encode(test_addr(0x02).as_bytes()));

        let app = make_app(app_state.clone());
        let (s1, json1) = post_json(
            &app,
            "/api/v1/faucet",
            serde_json::json!({"address": &addr1_hex}),
        )
        .await;
        assert_eq!(s1, StatusCode::OK);
        assert_eq!(json1["amount"], 1_000);
        assert_eq!(json1["tx_hash"], "faucet_direct_credit");

        let app = make_app(app_state.clone());
        let (s2, json2) = post_json(
            &app,
            "/api/v1/faucet",
            serde_json::json!({"address": &addr2_hex}),
        )
        .await;
        assert_eq!(s2, StatusCode::OK);
        assert_eq!(json2["amount"], 1_000);
        assert_eq!(json2["tx_hash"], "faucet_direct_credit");

        // Verify both recipients received funds in node state
        let ns = app_state.node.read().await;
        assert_eq!(ns.state.balance(&test_addr(0x01)), 1_000);
        assert_eq!(ns.state.balance(&test_addr(0x02)), 1_000);
    }

    #[tokio::test]
    async fn test_faucet_depleted() {
        let app_state = make_app_state();
        let faucet_addr = test_addr(0xFA);
        {
            let mut ns = app_state.node.write().await;
            ns.faucet_address = Some(faucet_addr);
            ns.faucet_drip_amount = 1_000_000;
            ns.faucet_cooldown_secs = 0; // No cooldown
            // Faucet has less than drip amount
            ns.state.set_account(Account::new_eoa(faucet_addr, 500));
        }
        let app = make_app(app_state);
        let addr_hex = format!("0x{}", hex::encode(test_addr(0x01).as_bytes()));
        let (status, json) = post_json(
            &app,
            "/api/v1/faucet",
            serde_json::json!({"address": &addr_hex}),
        )
        .await;
        // Faucet balance insufficient → should fail with 400
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json.to_string().contains("depleted"));
    }

    #[tokio::test]
    async fn test_faucet_invalid_address() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.faucet_address = Some(test_addr(0xFA));
        }
        let app = make_app(app_state);
        let (status, json) = post_json(
            &app,
            "/api/v1/faucet",
            serde_json::json!({"address": "invalid_address"}),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json.to_string().contains("Invalid address"));
    }

    // ══════════════════════════════════════════════════════════════════
    // Block Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_block_success() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.height = 1;
            ns.push_block(make_block(1));
        }
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/blocks/1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["height"], 1);
    }

    #[tokio::test]
    async fn test_get_block_not_found() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, _) = get_json(&app, "/api/v1/blocks/999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_list_blocks_empty() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/blocks").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 0);
        assert!(json["blocks"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_list_blocks_with_data() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            for i in 1..=5 {
                ns.push_block(make_block(i));
            }
            ns.height = 5;
        }
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/blocks?limit=3").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 5);
        assert_eq!(json["limit"], 3);
        let blocks = json["blocks"].as_array().unwrap();
        assert_eq!(blocks.len(), 3);
    }

    // ══════════════════════════════════════════════════════════════════
    // Balance Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_balance_zero() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let addr_hex = format!("0x{}", hex::encode(test_addr(0x01).as_bytes()));
        let (status, json) =
            get_json(&app, &format!("/api/v1/accounts/{}/balance", addr_hex)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["balance"], 0);
    }

    #[tokio::test]
    async fn test_get_balance_with_funds() {
        let app_state = make_app_state();
        let addr = test_addr(0x01);
        {
            let mut ns = app_state.node.write().await;
            ns.state.set_account(Account::new_eoa(addr, 42_000));
        }
        let app = make_app(app_state);
        let addr_hex = format!("0x{}", hex::encode(addr.as_bytes()));
        let (_, json) = get_json(&app, &format!("/api/v1/accounts/{}/balance", addr_hex)).await;
        assert_eq!(json["balance"], 42_000);
    }

    // ══════════════════════════════════════════════════════════════════
    // Validators Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_validators_empty() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/validators").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json["validators"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_validators_with_data() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            let addr = test_addr(0x01);
            ns.staking.register_validator(addr, 100_000_000).unwrap();
        }
        let app = make_app(app_state);
        let (_, json) = get_json(&app, "/api/v1/validators").await;
        let validators = json["validators"].as_array().unwrap();
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0]["stake"], 100_000_000);
    }

    // ══════════════════════════════════════════════════════════════════
    // Epoch Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_epoch() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/epoch").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["current_epoch"], 0);
        assert!(json["epoch_length"].is_number());
    }

    // ══════════════════════════════════════════════════════════════════
    // Bridge Status Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_bridge_status() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/bridge/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total_locked"], 0);
        assert_eq!(json["paused"], false);
    }

    // ══════════════════════════════════════════════════════════════════
    // Account Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_account_nonexistent() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let addr_hex = format!("0x{}", hex::encode(test_addr(0x99).as_bytes()));
        let (status, json) = get_json(&app, &format!("/api/v1/accounts/{}", addr_hex)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["balance"], 0);
        assert_eq!(json["nonce"], 0);
    }

    #[tokio::test]
    async fn test_get_account_existing() {
        let app_state = make_app_state();
        let addr = test_addr(0x01);
        {
            let mut ns = app_state.node.write().await;
            let mut account = Account::new_eoa(addr, 50_000);
            account.nonce = 5;
            ns.state.set_account(account);
        }
        let app = make_app(app_state);
        let addr_hex = format!("0x{}", hex::encode(addr.as_bytes()));
        let (_, json) = get_json(&app, &format!("/api/v1/accounts/{}", addr_hex)).await;
        assert_eq!(json["balance"], 50_000);
        assert_eq!(json["nonce"], 5);
    }

    // ══════════════════════════════════════════════════════════════════
    // Latest Proof Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_latest_proof_none() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/proofs/latest").await;
        assert_eq!(status, StatusCode::OK);
        assert!(json.is_null());
    }

    // ── L1 API tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_l1_status_disconnected() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/l1/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["connected"], false);
        assert_eq!(json["l1_height"], 0);
        assert_eq!(json["anchor_count"], 0);
    }

    #[tokio::test]
    async fn test_l1_status_connected() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.l1_connected = true;
            ns.l1_height = 850_000;
            ns.l1_network = Some("mainnet".to_string());
        }
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/l1/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["connected"], true);
        assert_eq!(json["l1_height"], 850_000);
        assert_eq!(json["network"], "mainnet");
    }

    #[tokio::test]
    async fn test_l1_anchors_empty() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/l1/anchors").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 0);
        assert!(json["anchors"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_l1_anchors_with_data() {
        use brrq_bitcoin::L1AnchorRecord;
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.l1_anchors.push(L1AnchorRecord {
                l1_tx_id: [1u8; 32],
                l1_height: 850_000,
                block_hash: [0u8; 32],
                l2_height: 100,
                state_root: Hash256::ZERO,
                proof_hash: Hash256::ZERO,
                timestamp: 1_700_000_000,
            });
            ns.l1_anchors.push(L1AnchorRecord {
                l1_tx_id: [2u8; 32],
                l1_height: 850_100,
                block_hash: [0u8; 32],
                l2_height: 200,
                state_root: Hash256::ZERO,
                proof_hash: Hash256::ZERO,
                timestamp: 1_700_001_000,
            });
        }
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/l1/anchors").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 2);
        assert_eq!(json["anchors"].as_array().unwrap().len(), 2);
        assert_eq!(json["anchors"][0]["l2_height"], 100);
        assert_eq!(json["anchors"][1]["l2_height"], 200);
    }

    #[tokio::test]
    async fn test_l1_anchor_by_height_found() {
        use brrq_bitcoin::L1AnchorRecord;
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.l1_anchors.push(L1AnchorRecord {
                l1_tx_id: [99u8; 32],
                l1_height: 850_500,
                block_hash: [0u8; 32],
                l2_height: 500,
                state_root: Hash256::ZERO,
                proof_hash: Hash256::ZERO,
                timestamp: 1_700_005_000,
            });
        }
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/l1/anchors/500").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["l2_height"], 500);
        assert_eq!(json["l1_height"], 850_500);
    }

    #[tokio::test]
    async fn test_l1_anchor_by_height_not_found() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, _) = get_json(&app, "/api/v1/l1/anchors/999").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_health_includes_l1_fields() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.l1_connected = true;
            ns.l1_height = 123_456;
        }
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["l1_connected"], true);
        assert_eq!(json["l1_height"], 123_456);
    }

    #[tokio::test]
    async fn test_metrics_includes_l1() {
        let app_state = make_app_state();
        {
            let mut ns = app_state.node.write().await;
            ns.l1_connected = true;
            ns.l1_height = 100;
        }
        let app = make_app(app_state);
        let (status, text) = get_text(&app, "/metrics").await;
        assert_eq!(status, StatusCode::OK);
        assert!(text.contains("brrq_l1_connected 1"));
        assert!(text.contains("brrq_l1_height 100"));
        assert!(text.contains("brrq_l1_anchor_count 0"));
    }

    // ══════════════════════════════════════════════════════════════════
    // Proof Store Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_list_proofs_empty() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/proofs").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 0);
        assert!(json["proofs"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_proof_by_height_not_found() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, _) = get_json(&app, "/api/v1/proofs/height/100").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    // ══════════════════════════════════════════════════════════════════
    // Challenge Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_list_challenges_empty() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/bridge/challenges").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 0);
        assert_eq!(json["pending"], 0);
        assert!(json["challenges"].as_array().unwrap().is_empty());
    }

    // ══════════════════════════════════════════════════════════════════
    // Operator Endpoint Tests
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_list_operators_empty() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/bridge/operators").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["total"], 0);
        assert!(json["operators"].as_array().unwrap().is_empty());
    }

    // ══════════════════════════════════════════════════════════════════
    // Health Endpoint includes bridge fields
    // ══════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_health_includes_phase7_fields() {
        let app_state = make_app_state();
        let app = make_app(app_state);
        let (status, json) = get_json(&app, "/api/v1/health").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["challenges_active"], 0);
        assert_eq!(json["proofs_stored"], 0);
        assert_eq!(json["operators_registered"], 0);
    }
}
