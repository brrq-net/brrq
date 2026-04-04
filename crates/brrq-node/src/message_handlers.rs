//! Per-message handlers extracted from `network_service::handle_connection`.
//!
//! Dependency Decoupling.
//!
//! Each handler returns `false` to continue processing or `true` to disconnect the peer.

use std::sync::Arc;

use bincode::Options;
use tokio::sync::RwLock;

use brrq_network::{GossipEngine, Message, PeerManager, SyncManager};
use brrq_network::message::{
    BlockAnnounce, BlocksResponse, GetBlocksRequest, HelloMessage,
    SlashingEvidenceMessage, TransactionAnnounce,
};
use brrq_types::block::Block;
use brrq_types::transaction::Transaction;

use crate::node::{apply_block, SharedState};

/// Result of handling a Hello message.
pub(crate) enum HelloResult {
    /// Peer accepted — continue processing messages.
    Continue,
    /// Peer rejected — gracefully close connection (break loop).
    Disconnect,
}

/// Handle a NewTransaction message from a peer.
///
/// Validates fee, balance, signature, then adds to mempool with Dandelion++ relay.
/// Returns `true` if the peer should be disconnected (banned).
pub(crate) async fn handle_new_transaction(
    tx_announce: &TransactionAnnounce,
    peer_id: &str,
    shared: &SharedState,
    peers: &Arc<RwLock<PeerManager>>,
    gossip: &Arc<GossipEngine>,
    msg: Message,
) -> bool {
    // Header-First Mempool pre-validation
    let min_fee = {
        let ns = shared.read().await;
        ns.mempool.current_base_fee()
    };

    if tx_announce.max_fee_per_gas < min_fee {
        tracing::debug!(
            "Rejected network tx before deserialization from {}: gas_price {} < current_base_fee {}",
            peer_id,
            tx_announce.max_fee_per_gas,
            min_fee
        );
        if let Some(pi) = peers.write().await.get_peer_mut(peer_id) {
            if pi.adjust_reputation(-5) {
                tracing::warn!("Banning peer {} for spamming low-fee txs", peer_id);
                return true; // disconnect
            }
        }
        return false; // skip tx, continue processing
    }

    // Deserialize transaction
    let des_res: Result<Transaction, _> = bincode::options()
        .with_limit(10 * 1024 * 1024)
        .deserialize(&tx_announce.data);
    match des_res {
        Ok(tx) => {
            // Balance pre-check BEFORE signature verification.
            {
                let ns = shared.read().await;
                let sender = tx.body.from;
                let sender_balance = ns.state.balance(&sender);
                let min_required = (tx.body.gas_limit as u128)
                    .saturating_mul(tx.body.max_fee_per_gas as u128);
                if min_required > u64::MAX as u128
                    || sender_balance < min_required as u64
                {
                    tracing::debug!(
                        "DOS-SHIELD: Rejected tx from {} — balance {} < required {} (gas_limit={} × max_fee={})",
                        sender, sender_balance, min_required,
                        tx.body.gas_limit, tx.body.max_fee_per_gas,
                    );
                    if let Some(pi) = peers.write().await.get_peer_mut(peer_id) {
                        if pi.adjust_reputation(-10) {
                            tracing::warn!(
                                "Banning peer {} for sending unfunded spam txs",
                                peer_id
                            );
                            return true;
                        }
                    }
                    return false;
                }
            }

            // Verify signature BEFORE mempool admission.
            if let Err(e) = tx.verify_signature() {
                tracing::debug!(
                    "Rejected network tx with invalid signature from {}: {}",
                    peer_id, e
                );
                if let Some(pi) = peers.write().await.get_peer_mut(peer_id) {
                    if pi.adjust_reputation(-20) {
                        tracing::warn!("Banning peer {} for forged signatures", peer_id);
                        return true;
                    }
                }
                return false;
            }

            let mut ns = shared.write().await;
            match ns.mempool.add(tx) {
                Ok(hash) => {
                    tracing::debug!("Added tx {:?} from network to mempool", hash);
                    gossip.dandelion_relay(msg, 1);
                }
                Err(e) => {
                    tracing::debug!("Rejected network tx: {}", e);
                }
            }
        }
        Err(e) => {
            tracing::debug!("Invalid tx data from {}: {}", peer_id, e);
        }
    }
    false
}

/// Handle a Blocks (sync response) message from a peer.
///
/// Deserializes and applies each block to local state.
/// Returns `true` if the peer should be disconnected (banned).
pub(crate) async fn handle_blocks_response(
    resp: &BlocksResponse,
    peer_id: &str,
    shared: &SharedState,
    peers: &Arc<RwLock<PeerManager>>,
    sync_mgr: &Arc<RwLock<SyncManager>>,
) -> bool {
    tracing::info!(
        "Received {} blocks from {} for sync",
        resp.blocks.len(),
        peer_id,
    );

    let mut applied = 0u64;
    let mut failed = 0u64;
    for block_data in &resp.blocks {
        let des_res: Result<Block, _> = bincode::options()
            .with_limit(32 * 1024 * 1024)
            .deserialize(block_data);
        match des_res {
            Ok(block) => {
                let block_height = block.header.height;

                // Acquire permit BEFORE RwLock to prevent global deadlock
                let disk_semaphore = shared.read().await.disk_semaphore.clone();
                let permit = disk_semaphore.acquire_owned().await.ok();

                let mut ns = shared.write().await;

                // Skip blocks we already have
                if block_height <= ns.height {
                    drop(ns);
                    tracing::debug!(
                        "Skipping already-applied block #{} from {}",
                        block_height, peer_id,
                    );
                    continue;
                }

                let store_ref = ns.store.clone();
                match apply_block(&mut ns, block.clone()) {
                    Ok(exec_result) => {
                        crate::node::finalize_block(
                            &mut ns, block.clone(), exec_result, store_ref, permit,
                        );
                        let hash = ns.parent_hash;
                        let height = ns.height;
                        drop(ns);
                        // Use process_validated_block instead of
                        // block_processed to maintain SyncManager's parent-hash chain.
                        // block_processed only updates height/hash without verifying
                        // chain continuity, leaving the SyncManager blind to forked
                        // blocks that happened to pass apply_block individually.
                        if let Err(e) = sync_mgr.write().await.process_validated_block(
                            height, hash, block.header.parent_hash,
                        ) {
                            tracing::warn!(
                                "SyncManager chain validation failed for block #{}: {}",
                                block_height, e,
                            );
                        }
                        applied += 1;
                        tracing::debug!("Applied synced block #{}", block_height);
                    }
                    Err(e) => {
                        drop(ns);
                        failed += 1;
                        tracing::warn!(
                            "Failed to apply block #{} from {}: {}",
                            block_height, peer_id, e,
                        );
                        let should_ban = {
                            let mut pm = peers.write().await;
                            pm.get_peer_mut(peer_id)
                                .map(|p| p.adjust_reputation(-50))
                                .unwrap_or(false)
                        };
                        if should_ban {
                            tracing::warn!(
                                "Banning peer {} for sending invalid blocks",
                                peer_id,
                            );
                            return true;
                        }
                        break;
                    }
                }
            }
            Err(e) => {
                failed += 1;
                tracing::warn!(
                    "Failed to deserialize block from {}: {}", peer_id, e,
                );
                {
                    let mut pm = peers.write().await;
                    if let Some(p) = pm.get_peer_mut(peer_id) {
                        if p.adjust_reputation(-50) {
                            tracing::warn!(
                                "Banning peer {} for invalid block data",
                                peer_id,
                            );
                            return true;
                        }
                    }
                }
                break;
            }
        }
    }

    if applied > 0 {
        tracing::info!(
            "Sync: applied {} blocks from {} ({} failed)",
            applied, peer_id, failed,
        );
    }
    false
}

/// Handle a RANDAO commitment message from a peer.
///
/// Verifies EOTS signature and submits commitment to epoch manager.
#[cfg(feature = "sequencer-rotation")]
pub(crate) async fn handle_randao_commitment(
    randao_msg: &brrq_network::message::RandaoCommitmentMessage,
    peer_id: &str,
    shared: &SharedState,
) {
    let mut ns = shared.write().await;
    // Reject RANDAO from validators without registered EOTS pubkey
    let Some(pubkey) = ns.registration.get_eots_pubkey(&randao_msg.validator) else {
        tracing::warn!("RANDAO commitment from {peer_id}: validator {} has no EOTS pubkey, rejecting", randao_msg.validator);
        return;
    };
    let msg_hash = {
        use brrq_crypto::hash::Hasher;
        let mut h = Hasher::new();
        h.update(brrq_crypto::domain_tags::RANDAO_COMMITMENT_V1);
        h.update(&randao_msg.epoch.to_le_bytes());
        h.update(randao_msg.commitment.as_bytes());
        h.finalize()
    };
    if !crate::network_service::verify_randao_eots_sig(pubkey, &msg_hash, &randao_msg.eots_signature, peer_id, "commitment") {
        return;
    }
    if let Err(e) = ns
        .epoch
        .submit_randao_commitment(randao_msg.validator, randao_msg.commitment)
    {
        tracing::warn!("RANDAO commitment from {peer_id} rejected: {e}");
    }
}

/// Handle a RANDAO reveal message from a peer.
///
/// Verifies EOTS signature and submits reveal to epoch manager.
#[cfg(feature = "sequencer-rotation")]
pub(crate) async fn handle_randao_reveal(
    reveal_msg: &brrq_network::message::RandaoRevealMessage,
    peer_id: &str,
    shared: &SharedState,
) {
    let mut ns = shared.write().await;
    // Reject RANDAO from validators without registered EOTS pubkey
    let Some(pubkey) = ns.registration.get_eots_pubkey(&reveal_msg.validator) else {
        tracing::warn!("RANDAO reveal from {peer_id}: validator {} has no EOTS pubkey, rejecting", reveal_msg.validator);
        return;
    };
    let msg_hash = {
        use brrq_crypto::hash::Hasher;
        let mut h = Hasher::new();
        h.update(brrq_crypto::domain_tags::RANDAO_REVEAL_V1);
        h.update(&reveal_msg.epoch.to_le_bytes());
        h.update(reveal_msg.secret.as_bytes());
        h.finalize()
    };
    if !crate::network_service::verify_randao_eots_sig(pubkey, &msg_hash, &reveal_msg.eots_signature, peer_id, "reveal") {
        return;
    }
    let current_height = ns.height;
    ns.epoch.submit_randao_reveal(
        reveal_msg.validator,
        reveal_msg.secret,
        current_height,
    );
}

/// Handle a NewBlock announcement from a peer.
///
/// Updates the sync target, requests missing blocks if behind, and re-broadcasts.
/// Returns `true` if the peer should be disconnected (banned).
pub(crate) async fn handle_new_block(
    block_announce: &BlockAnnounce,
    peer_id: &str,
    shared: &SharedState,
    sync_mgr: &Arc<RwLock<SyncManager>>,
    gossip: &Arc<GossipEngine>,
    egress_tx: &tokio::sync::mpsc::Sender<Arc<Vec<u8>>>,
    msg: Message,
) -> bool {
    tracing::info!(
        "New block #{} from peer {}",
        block_announce.height,
        peer_id
    );
    sync_mgr.write().await.update_target(block_announce.height);

    // If this block is exactly our next expected, request it
    let local_height = shared.read().await.height;
    if block_announce.height == local_height + 1 {
        let req = Message::GetBlocks(GetBlocksRequest {
            from_height: local_height + 1,
            to_height: block_announce.height,
        });
        if let Ok(raw) = bincode::options()
            .with_limit(32 * 1024 * 1024)
            .serialize(&req)
        {
            if let Err(e) = egress_tx.try_send(Arc::new(raw)) {
                tracing::debug!(
                    "Failed to request block #{} from {}: {}",
                    block_announce.height,
                    peer_id,
                    e,
                );
            }
        }
    } else if block_announce.height > local_height + 1 {
        // We're behind — request the full range
        let req = Message::GetBlocks(GetBlocksRequest {
            from_height: local_height + 1,
            to_height: block_announce.height,
        });
        if let Ok(raw) = bincode::options()
            .with_limit(32 * 1024 * 1024)
            .serialize(&req)
        {
            if let Err(e) = egress_tx.try_send(Arc::new(raw)) {
                tracing::debug!(
                    "Failed to request blocks {}-{} from {}: {}",
                    local_height + 1,
                    block_announce.height,
                    peer_id,
                    e,
                );
            }
        }
    }

    // Re-broadcast
    gossip.broadcast(msg);
    false
}

/// Handle slashing evidence submitted by a peer.
///
/// Verifies the offense type, applies the slashing penalty via the SlashingEngine,
/// and credits the challenger reward.
/// Returns `true` if the peer should be disconnected (banned).
pub(crate) async fn handle_slashing_evidence(
    evidence: &SlashingEvidenceMessage,
    peer_id: &str,
    shared: &SharedState,
) -> bool {
    let mut ns = shared.write().await;
    tracing::info!(
        "Received slashing evidence from {peer_id}: offender={}, type={}, height={}",
        evidence.offender,
        evidence.offense_type,
        evidence.height,
    );
    // Verify and apply the slashing penalty.
    // The SlashingEngine prevents double-slashing via offense ID dedup.
    let reason = match evidence.offense_type.as_str() {
        "equivocation" | "dual_proposal" => {
            brrq_consensus::SlashingReason::Equivocation
        }
        "randao_non_reveal" => brrq_consensus::SlashingReason::RandaoNonReveal,
        _ => {
            tracing::warn!(
                "Unknown slashing offense type: {}",
                evidence.offense_type,
            );
            return false;
        }
    };
    let context = evidence.evidence_hash_a;
    let current_height = ns.height;
    let ns_ref = &mut *ns;
    match ns_ref.slashing.slash(
        &mut ns_ref.staking,
        &evidence.offender,
        reason,
        &context.0,
        current_height,
        evidence.height,
    ) {
        Ok(result) => {
            tracing::warn!(
                "Slashed {} for {:?}: total={}, burned={}, challenger_reward={}",
                result.validator,
                result.reason,
                result.total_slashed,
                result.burned,
                result.challenger_reward,
            );
            // Do NOT credit challenger reward via P2P message.
            // The `challenger` field in SlashingEvidenceMessage is unauthenticated —
            // any node can copy the evidence and replace `challenger` with their own address.
            // Rewards are only credited via signed SubmitEquivocationProof transactions,
            // where the Transaction signature proves the challenger's identity.
            if result.challenger_reward > 0 {
                tracing::info!(
                    reward = result.challenger_reward,
                    "Slashing reward available — challenger must submit SubmitEquivocationProof tx to claim"
                );
            }
        }
        Err(e) => {
            tracing::debug!("Slashing skipped: {e}");
        }
    }
    false
}

/// Handle a Hello message from a peer.
///
/// Validates network membership, verifies signature, checks validator proof,
/// negotiates protocol version, registers peer, and requests sync if needed.
pub(crate) async fn handle_hello(
    hello: &HelloMessage,
    peer_id: &str,
    shared: &SharedState,
    peers: &Arc<RwLock<PeerManager>>,
    sync_mgr: &Arc<RwLock<SyncManager>>,
    egress_tx: &tokio::sync::mpsc::Sender<Arc<Vec<u8>>>,
    config_network: &str,
    sequencer_address: Option<brrq_types::Address>,
    requires_validator_proof: bool,
) -> HelloResult {
    // Reject peers from different networks.
    if hello.network.is_empty()
        || config_network.is_empty()
        || hello.network != config_network
    {
        tracing::warn!(
            "Rejecting peer {}: network mismatch (ours={}, theirs={})",
            peer_id, config_network, hello.network,
        );
        peers.write().await.remove_peer(peer_id);
        return HelloResult::Disconnect;
    }

    // Verify Hello signature (proves peer controls the claimed identity key).
    let peer_ip = peer_id.split('_').nth(1).unwrap_or(peer_id);
    let authenticated = crate::network_service::verify_hello_signature(
        &hello.node_id,
        hello.nonce,
        &hello.network,
        hello.version,
        peer_ip,
        &hello.signature,
    );
    if !authenticated && !hello.signature.is_empty() {
        tracing::warn!(
            "Disconnecting peer {} — invalid Hello signature (forged identity)",
            peer_id,
        );
        if let Some(pi) = peers.write().await.get_peer_mut(peer_id) {
            pi.adjust_reputation(-100);
        }
        return HelloResult::Disconnect;
    }
    if authenticated {
        tracing::debug!("Peer {} authenticated via Hello signature", peer_id);

        if requires_validator_proof {
            let is_validator = {
                let ns = shared.read().await;
                let addr = brrq_types::Address::from_public_key(
                    hex::decode(&hello.node_id).unwrap_or_default().as_slice(),
                );
                ns.staking.validators.contains_key(&addr)
            };

            if !is_validator {
                tracing::warn!(
                    "Disconnecting peer {} — soft limit reached and peer is not an active validator",
                    peer_id
                );
                if let Some(pi) = peers.write().await.get_peer_mut(peer_id) {
                    pi.adjust_reputation(-100);
                }
                return HelloResult::Disconnect;
            } else {
                tracing::info!(
                    "Peer {} utilized a reserved Validator connection slot!",
                    peer_id
                );
            }
        }
    } else {
        tracing::debug!("Peer {} unauthenticated (legacy)", peer_id);
        if requires_validator_proof {
            tracing::warn!(
                "Disconnecting peer {} — soft limit reached and peer failed validator authentication",
                peer_id
            );
            if let Some(pi) = peers.write().await.get_peer_mut(peer_id) {
                pi.adjust_reputation(-100);
            }
            return HelloResult::Disconnect;
        }
    }

    // ── Version negotiation ──
    const MIN_PROTOCOL_VERSION: u32 = 1;
    const MAX_PROTOCOL_VERSION: u32 = 1;

    if hello.version < MIN_PROTOCOL_VERSION || hello.version > MAX_PROTOCOL_VERSION {
        tracing::warn!(
            peer = %peer_id,
            their_version = hello.version,
            our_min = MIN_PROTOCOL_VERSION,
            our_max = MAX_PROTOCOL_VERSION,
            "Rejecting peer: incompatible protocol version"
        );
        peers.write().await.remove_peer(peer_id);
        return HelloResult::Disconnect;
    }

    peers
        .write()
        .await
        .mark_connected(peer_id, hello.version, hello.best_height)
        .ok();
    sync_mgr.write().await.update_target(hello.best_height);
    tracing::debug!(
        "Hello from {}: height={}, version={}",
        peer_id, hello.best_height, hello.version
    );

    // If the peer is ahead, request blocks to catch up
    let local_height = shared.read().await.height;
    if hello.best_height > local_height {
        let req = Message::GetBlocks(GetBlocksRequest {
            from_height: local_height + 1,
            to_height: hello.best_height,
        });
        if let Ok(raw) = bincode::options()
            .with_limit(32 * 1024 * 1024)
            .serialize(&req)
        {
            if let Err(e) = egress_tx.try_send(Arc::new(raw)) {
                tracing::debug!(
                    "Failed to request sync blocks from {}: {}",
                    peer_id, e,
                );
            } else {
                tracing::info!(
                    "Requested blocks {}-{} from {}",
                    local_height + 1, hello.best_height, peer_id,
                );
            }
        }
    }
    HelloResult::Continue
}

/// Handle a GetBlocks request from a peer.
///
/// Retrieves blocks from local state (capped at 100) and sends response.
pub(crate) async fn handle_get_blocks(
    req: &GetBlocksRequest,
    peer_id: &str,
    shared: &SharedState,
    egress_tx: &tokio::sync::mpsc::Sender<Arc<Vec<u8>>>,
) {
    const MAX_BLOCKS_PER_REQUEST: u64 = 100;
    let capped_to = req
        .from_height
        .saturating_add(MAX_BLOCKS_PER_REQUEST - 1)
        .min(req.to_height);

    let ns = shared.read().await;
    let mut block_data = Vec::new();
    for h in req.from_height..=capped_to {
        if let Some(block) = ns.get_block(h) {
            if let Ok(data) = bincode::options()
                .with_limit(32 * 1024 * 1024)
                .serialize(&block)
            {
                block_data.push(data);
            }
        }
    }
    let resp = Message::Blocks(BlocksResponse { blocks: block_data });
    drop(ns);
    if let Ok(raw) = bincode::options()
        .with_limit(32 * 1024 * 1024)
        .serialize(&resp)
    {
        if let Err(e) = egress_tx.try_send(Arc::new(raw)) {
            tracing::debug!("Failed to send blocks to {}: {}", peer_id, e);
        }
    }
}
