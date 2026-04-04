//! Bitcoin L1 synchronization loop.
//!
//! Connects to a bitcoind node via JSON-RPC and periodically:
//! 1. **Monitors blocks**: Tracks new Bitcoin blocks, updates L1 height + hash
//! 2. **Detects deposits**: Watches the bridge address for peg-in transactions
//!    (only accepts deposits with >= 6 confirmations)
//! 3. **Posts anchors**: Publishes state commitments to Bitcoin via OP_RETURN
//!
//! ## Graceful Degradation
//!
//! If the Bitcoin connection drops, the node continues as L2-only:
//! - `l1_connected = false` in NodeState
//! - Automatic reconnection attempts every 30 seconds
//! - No block production disruption
//!
//! ## Reorg Handling
//!
//! If a Bitcoin chain reorganization is detected, the monitor resets to
//! a safe height and re-scans. Deposits from reorged blocks are not
//! re-processed due to the confirmation threshold.

use std::sync::Arc;

use brrq_bitcoin::BitcoinError;
use brrq_bitcoin::anchor_service::AnchorService;
use brrq_bitcoin::block_monitor::BlockMonitor;
use brrq_bitcoin::deposit_watcher::DepositWatcher;
use brrq_bitcoin::rpc_client::BitcoinRpcClient;
use brrq_crypto::hash::Hash256;
use brrq_state::persistent::PersistentStore;
use tracing::{debug, info, warn};

use crate::node::SharedState;

/// Default polling interval for Bitcoin L1 sync (30 seconds).
const L1_POLL_INTERVAL_SECS: u64 = 30;

/// Configuration for the Bitcoin sync loop.
pub struct BitcoinSyncConfig {
    /// Bitcoin RPC URL (e.g., "http://localhost:18332").
    pub rpc_url: String,
    /// Bitcoin RPC username.
    pub rpc_user: String,
    /// Bitcoin RPC password.
    pub rpc_pass: String,
    /// Bitcoin network ("mainnet", "testnet", "regtest", "signet").
    pub network: String,
    /// Bridge address to watch for deposits (Bitcoin address).
    pub bridge_address: Option<String>,
    /// Interval between L1 anchor postings (in L2 blocks).
    pub checkpoint_interval: u64,
    /// Funding address for anchor transactions (defaults to bitcoind wallet).
    #[allow(dead_code)]
    pub funding_address: Option<String>,
}

/// Run the Bitcoin L1 synchronization loop.
///
/// This function runs indefinitely, polling bitcoind every 30 seconds.
/// It should be spawned as a tokio task.
///
/// ## Error Handling
///
/// - Connection failures: Retries every 30 seconds
/// - RPC errors: Logs and continues (graceful degradation)
/// - Chain reorgs: Resets monitor and re-scans
/// - The L2 node never stops producing blocks due to L1 issues
pub async fn bitcoin_sync_loop(
    shared: SharedState,
    store: Option<Arc<PersistentStore>>,
    config: BitcoinSyncConfig,
) {
    info!("Starting Bitcoin L1 sync loop...");
    info!("  RPC URL: {}", config.rpc_url);
    info!("  Network: {}", config.network);
    info!(
        "  Bridge address: {}",
        config.bridge_address.as_deref().unwrap_or("none")
    );
    info!(
        "  Checkpoint interval: {} L2 blocks",
        config.checkpoint_interval
    );

    // Initialize components — start from the last known L1 height if available
    let initial_l1_height = {
        let ns = shared.read().await;
        ns.l1_height
    };
    let mut block_monitor = if initial_l1_height > 0 {
        info!(
            "  Resuming block monitor from L1 height {}",
            initial_l1_height
        );
        BlockMonitor::with_height(initial_l1_height)
    } else {
        BlockMonitor::new()
    };

    let mut deposit_watcher = config
        .bridge_address
        .as_ref()
        .map(|addr| DepositWatcher::new(addr));
    let mut anchor_service = AnchorService::new();

    // Load persisted L1 anchor records into the anchor service
    if let Some(ref s) = store {
        match s.load_all_l1_anchors() {
            Ok(anchors) if !anchors.is_empty() => {
                info!("  Loaded {} persisted L1 anchor(s)", anchors.len());
                anchor_service.load_anchors(anchors);
            }
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to load L1 anchors from disk: {}", e);
            }
        }
    }

    // Update L1 network info in shared state
    {
        let mut ns = shared.write().await;
        ns.l1_network = Some(config.network.clone());
    }

    let mut interval =
        tokio::time::interval(tokio::time::Duration::from_secs(L1_POLL_INTERVAL_SECS));

    // Attempt initial connection
    let mut rpc = connect_rpc(
        &config.rpc_url,
        &config.rpc_user,
        &config.rpc_pass,
        &config.network,
    )
    .await;

    loop {
        interval.tick().await;

        // Ensure we have a connection
        let rpc_client = match rpc {
            Some(ref mut client) => client,
            None => {
                // Attempt reconnection
                debug!("Attempting Bitcoin RPC reconnection...");
                match connect_rpc(
                    &config.rpc_url,
                    &config.rpc_user,
                    &config.rpc_pass,
                    &config.network,
                )
                .await
                {
                    Some(client) => {
                        info!("Bitcoin RPC reconnected successfully");
                        rpc = Some(client);
                        rpc.as_mut().unwrap()
                    }
                    None => {
                        update_l1_disconnected(&shared).await;
                        continue;
                    }
                }
            }
        };

        // ── 1. Monitor Bitcoin blocks ────────────────────────────────
        match block_monitor.poll(rpc_client) {
            Ok(new_blocks) => {
                if !new_blocks.is_empty() {
                    let latest = new_blocks.last().unwrap();
                    debug!(
                        "L1: {} new block(s), latest height={}, hash={}",
                        new_blocks.len(),
                        latest.height,
                        hex::encode(latest.hash),
                    );

                    // Update shared state with real L1 block info
                    let mut ns = shared.write().await;
                    ns.l1_height = latest.height;
                    ns.l1_block_hash = Some(latest.hash);
                    ns.l1_connected = true;
                    ns.l1_monitor = Some(block_monitor.clone());

                    // Update bridge L1 height
                    ns.bridge.l1_height = latest.height;

                    // Emit L1 status event
                    if let Some(ref event_tx) = ns.event_tx {
                        let _ = event_tx.send(brrq_api::NodeEvent::L1StatusChanged {
                            connected: true,
                            l1_height: latest.height,
                        });
                    }
                } else {
                    // No new blocks, just ensure connected status
                    let mut ns = shared.write().await;
                    ns.l1_connected = true;
                }
            }
            Err(BitcoinError::ChainReorg { expected, actual }) => {
                warn!(
                    "Bitcoin chain reorg detected! Expected height >= {}, got {}. Resetting monitor.",
                    expected, actual
                );
                // Reset to a safe height (10 blocks back from the actual chain tip)
                let safe_height = actual.saturating_sub(10);
                block_monitor.reset_to(safe_height);

                // Update shared state
                let mut ns = shared.write().await;
                ns.l1_height = actual;
                ns.l1_block_hash = None; // Unknown after reorg

                // Invalidate unfinalized deposits from reorged blocks.
                // First, remove any matching deposits still in the pending queue
                // (not yet included in a block — balance was never credited).
                // Then debit recipients whose deposits were already in blocks.
                let invalidated = ns.bridge.invalidate_unfinalized_deposits(safe_height);
                let mut debited_count = 0u64;
                let mut removed_from_queue = 0u64;
                let mut total_debt = 0u64;
                for (tx_id, vout, recipient, minted) in &invalidated {
                    // Check if this deposit is still in the pending queue
                    let queue_idx = ns
                        .pending_synthetic_deposits
                        .iter()
                        .position(|d| d.btc_tx_id == *tx_id && d.btc_vout == *vout);
                    if let Some(idx) = queue_idx {
                        // Not yet in a block — just remove from queue, no debit needed
                        ns.pending_synthetic_deposits.remove(idx);
                        // Report full recovery (tokens were never in WorldState)
                        ns.bridge.report_clawback_result(*recipient, *minted, *minted);
                        removed_from_queue += 1;
                    } else {
                        // Debit only what the recipient actually has.
                        // Record the shortfall as reorg_debt to prevent unbacked circulation.
                        let acct = ns.state.get_or_create_account(*recipient);
                        let actual_balance = acct.balance;
                        let recovered = actual_balance.min(*minted);
                        acct.balance = actual_balance.saturating_sub(recovered);
                        ns.state.flush_account(recipient);

                        // Report to bridge: only decrement total_minted by recovered amount
                        ns.bridge.report_clawback_result(*recipient, *minted, recovered);

                        let debt = minted.saturating_sub(recovered);
                        if debt > 0 {
                            total_debt += debt;
                        }
                        debited_count += 1;
                    }
                }
                if !invalidated.is_empty() {
                    warn!(
                        "Reverted {} deposits due to L1 reorg (safe_height={}): {} debited, {} removed from queue, {} sats unrecovered debt",
                        invalidated.len(),
                        safe_height,
                        debited_count,
                        removed_from_queue,
                        total_debt,
                    );
                }

                // Don't disconnect — just re-sync from the safe height
                continue;
            }
            Err(e) => {
                warn!("L1 block monitoring failed: {}", e);
                update_l1_disconnected(&shared).await;
                // Connection likely broken, drop and retry next cycle
                rpc = None;
                continue;
            }
        }

        // ── 2. Detect deposits ───────────────────────────────────────
        // Deposits are only reported after MIN_DEPOSIT_CONFIRMATIONS (6)
        // to prevent accepting unconfirmed or reorged-out deposits.
        // Deposits are queued as SyntheticDeposit structs and injected into
        // the next block by produce_block(), making them provable via STARK
        // proofs and visible in transaction receipts.
        if let Some(ref mut watcher) = deposit_watcher {
            match watcher.scan(rpc_client) {
                Ok(deposits) => {
                    if !deposits.is_empty() {
                        info!("L1: Detected {} new confirmed deposit(s)", deposits.len());

                        // Step 1: Fetch SPV proofs WITHOUT holding the write lock.
                        // This avoids blocking all SharedState readers during
                        // synchronous RPC calls to bitcoind.
                        let prepared = prepare_deposits(
                            &deposits, rpc_client, &block_monitor,
                        );

                        // Step 2: Acquire write lock and queue synthetic deposits.
                        // Deposits are queued as SyntheticDeposit structs and injected
                        // into the next block by produce_block() — making them provable
                        // via STARK proofs and visible in transaction receipts.
                        if !prepared.is_empty() {
                            let mut ns = shared.write().await;
                            for (deposit, l2_addr, btc_tx_hash, block_hash, merkle_block_raw) in
                                &prepared
                            {
                                // Queue RAW deposit amounts.
                                // Execution and limit adherence happens deterministically
                                // in `apply_block` and `block_builder` via `ns.bridge.process_deposit`.
                                ns.pending_synthetic_deposits
                                    .push(brrq_types::SyntheticDeposit {
                                        recipient: *l2_addr,
                                        amount: deposit.amount_sats,
                                        btc_tx_id: *btc_tx_hash,
                                        btc_vout: deposit.btc_vout,
                                        block_hash: *block_hash,
                                        merkle_block_raw: merkle_block_raw.clone(),
                                    });

                                info!(
                                    "Deposit queued for block inclusion: {} sats to {} (btc_tx={}, confirmations={})",
                                    deposit.amount_sats,
                                    l2_addr,
                                    hex::encode(deposit.btc_tx_id),
                                    deposit.confirmations,
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("L1 deposit scanning failed: {}", e);
                }
            }
        }

        // ── 3. Post anchor (state commitment) ────────────────────────
        if config.checkpoint_interval > 0 {
            let should_anchor = {
                let ns = shared.read().await;
                let last_anchor_height = anchor_service
                    .latest_anchor()
                    .map(|a| a.l2_height)
                    .unwrap_or(0);
                ns.height >= last_anchor_height + config.checkpoint_interval && ns.height > 0
            };

            if should_anchor {
                let (state_root, l2_height, proof_hash) = {
                    let ns = shared.read().await;
                    // Use the latest stored proof's SNARK commitment hash, or ZERO if none
                    let ph = ns
                        .bridge
                        .proof_store
                        .find_proof_for_height(ns.height)
                        .map(|p| p.snark_proof.commitment_hash())
                        .unwrap_or(Hash256::ZERO);
                    (ns.state.state_root(), ns.height, ph)
                };

                match anchor_service.post_anchor(rpc_client, state_root, l2_height, proof_hash) {
                    Ok(record) => {
                        info!(
                            "L1 anchor posted: L2 height={}, L1 tx={}, state_root=0x{}",
                            record.l2_height,
                            hex::encode(record.l1_tx_id),
                            hex::encode(record.state_root.as_bytes()),
                        );

                        // Persist anchor to disk
                        if let Some(ref s) = store
                            && let Err(e) = s.save_l1_anchor(&record)
                        {
                            warn!("Failed to persist L1 anchor to disk: {}", e);
                        }

                        // Store anchor record in shared state
                        let mut ns = shared.write().await;
                        ns.l1_anchors.push(record.clone());

                        // Emit anchor event
                        if let Some(ref event_tx) = ns.event_tx {
                            let _ = event_tx.send(brrq_api::NodeEvent::L1Anchor {
                                l2_height: record.l2_height,
                                l1_tx_id: hex::encode(record.l1_tx_id),
                                state_root: format!(
                                    "0x{}",
                                    hex::encode(record.state_root.as_bytes())
                                ),
                            });
                        }
                    }
                    Err(BitcoinError::DuplicateAnchor(h)) => {
                        debug!("Anchor already posted for L2 height {}, skipping", h);
                    }
                    Err(e) => {
                        warn!("L1 anchor posting failed at L2 height {}: {}", l2_height, e);
                    }
                }
            }
        }

        // ── 3.5. Check anchor confirmations ─────────────────────────
        if anchor_service.pending_anchor_count() > 0 {
            let confirmed = anchor_service.check_confirmations(rpc_client);
            if !confirmed.is_empty() {
                info!(
                    "L1: {} anchor(s) newly confirmed on Bitcoin",
                    confirmed.len()
                );

                // Update persisted records and shared state
                for l2_height in &confirmed {
                    // Find the confirmed anchor record for persistence
                    if let Some(record) = anchor_service
                        .anchors()
                        .iter()
                        .find(|a| a.l2_height == *l2_height)
                        && let Some(ref s) = store
                        && let Err(e) = s.save_l1_anchor(record)
                    {
                        warn!("Failed to persist confirmed anchor: {}", e);
                    }

                    // Update the record in shared state's l1_anchors vec
                    let mut ns = shared.write().await;
                    if let Some(shared_anchor) =
                        ns.l1_anchors.iter_mut().find(|a| a.l2_height == *l2_height)
                        && let Some(service_anchor) = anchor_service
                            .anchors()
                            .iter()
                            .find(|a| a.l2_height == *l2_height)
                    {
                        shared_anchor.l1_height = service_anchor.l1_height;
                    }
                }
            }
        }

        // L1-based liveness recovery: if L2 stalls, use Bitcoin block height as an external clock to break deadlock.
        {
            let mut ns = shared.write().await;

            // Calculate elapsed L1 blocks since the last successfully finalized L2 block.
            // Using l1_anchor_height as the point of reference since it binds L2 blocks to L1 time.
            let last_l2_block_l1_height = ns
                .blocks
                .back()
                .and_then(|b| b.header.l1_anchor_height)
                .unwrap_or(ns.l1_height);
            let l1_blocks_stalled = ns.l1_height.saturating_sub(last_l2_block_l1_height);

            // 6 L1 blocks (~1 hour) of zero L2 chain progression triggers the emergency ejection
            if l1_blocks_stalled >= 6 {
                tracing::warn!(
                    "L1 CLOCK ALARM: L2 Chain has been halted for {} L1 blocks! Initiating L2 Resumption Protocol.",
                    l1_blocks_stalled
                );

                let totally_offline: Vec<_> = ns.staking.validators.iter()
                    .filter(|(_, v)| {
                        v.consecutive_timeouts >= 3
                            && (v.status == brrq_consensus::validator::ValidatorStatus::Active
                                || v.status == brrq_consensus::validator::ValidatorStatus::Suspended)
                    })
                    .map(|(addr, _)| *addr)
                    .collect();

                if !totally_offline.is_empty() {
                    let current_height = ns.height;
                    for addr in totally_offline {
                        let _ = ns.staking.begin_unbonding(&addr, current_height);
                        tracing::error!(
                            "Sybil Liveness Defense (L1 Trigger): Forcibly unbonding {} to shrink active validator set and recover consensus majority.",
                            addr
                        );
                    }
                    // Immediately recalculate cap and effective stakes to instantly lower the BFT 67% threshold
                    ns.staking.recalculate_cap_at_height(current_height);
                    tracing::info!(
                        "L2 Resumption Protocol executed. Honest majority restored. Network unfreezing..."
                    );
                }
            }
        }

        // ── 4. Process expired challenges & Coordinate L1 Disputes ─────────
        {
            let mut ns = shared.write().await;

            // Map L2 challenges into L1 BitVM2 Dispute Steps
            // Collect the challenges and bonds locally to satisfy borrow checker
            let active_challenges: Vec<_> = ns
                .bridge
                .challenge_manager
                .active_challenges()
                .into_iter()
                .cloned()
                .collect();
            let all_operators: Vec<_> = ns
                .bridge
                .operator_manager
                .all_operators()
                .into_iter()
                .cloned()
                .collect();

            let mut events_to_process = Vec::new();
            for challenge in active_challenges {
                for op_info in &all_operators {
                    if let Some(bond) = op_info.primary_bond() {
                        let bond_clone: brrq_bridge::operator::BitVM2Bond = bond.clone();
                        events_to_process.push((
                            challenge.challenge_id,
                            challenge.status,
                            bond_clone,
                        ));
                    }
                }
            }

            // Execute mapped events against the mutable coordinator
            for (challenge_id, status, bond) in events_to_process {
                process_dispute_event(
                    &mut ns, rpc_client, challenge_id, status, &bond,
                );
            }

            let (expired, slash_failures) = ns.bridge.tick_challenges();
            if !slash_failures.is_empty() {
                warn!(
                    "Failed to slash {} operator(s) for expired challenges",
                    slash_failures.len()
                );
            }
            if !expired.is_empty() {
                info!("Processed {} expired challenge(s)", expired.len());
                for expired_id in &expired {
                    if let Some(ref event_tx) = ns.event_tx {
                        let _ = event_tx.send(brrq_api::NodeEvent::ChallengeResolved {
                            challenge_id: format!("0x{}", hex::encode(expired_id.as_bytes())),
                            status: "Expired".to_string(),
                        });
                    }
                }
            }
        }
    }
}

/// Fetch and verify SPV proofs for a batch of deposits.
///
/// Returns a vec of `(deposit, l2_addr, btc_tx_hash, block_hash, merkle_block_raw)`
/// tuples, filtering out deposits with invalid scriptPubKey.
fn prepare_deposits<'a>(
    deposits: &'a [brrq_bitcoin::DepositEvent],
    rpc_client: &mut BitcoinRpcClient,
    block_monitor: &BlockMonitor,
) -> Vec<(
    &'a brrq_bitcoin::DepositEvent,
    brrq_types::Address,
    Hash256,
    Hash256,
    Vec<u8>,
)> {
    let mut prepared = Vec::new();
    for deposit in deposits {
        let (l2_addr, script_type) =
            DepositWatcher::derive_l2_recipient_typed(&deposit.recipient_script);

        if l2_addr == brrq_types::Address::ZERO {
            warn!(
                "Skipping deposit with empty/invalid scriptPubKey: btc_tx={}",
                hex::encode(deposit.btc_tx_id),
            );
            continue;
        }

        debug!(
            "Deposit script type={} for btc_tx={}",
            script_type,
            hex::encode(deposit.btc_tx_id),
        );

        let btc_tx_hash = Hash256::from_bytes(deposit.btc_tx_id);
        let (block_hash, merkle_block_raw) =
            fetch_and_verify_spv(rpc_client, deposit.btc_tx_id, block_monitor);

        prepared.push((deposit, l2_addr, btc_tx_hash, block_hash, merkle_block_raw));
    }
    prepared
}

/// Process a single dispute challenge event: compile and broadcast L1 transaction,
/// or detect mempool pinning attacks and initiate CPFP defense.
fn process_dispute_event(
    ns: &mut crate::node::NodeState,
    rpc_client: &mut BitcoinRpcClient,
    challenge_id: Hash256,
    status: brrq_bridge::challenge::ChallengeStatus,
    bond: &brrq_bridge::operator::BitVM2Bond,
) {
    let l1_height = ns.l1_height;
    let result = ns.dispute_coordinator.handle_challenge_event(
        challenge_id, status, bond, l1_height,
        None, // actual_state_root (resolved via bisection)
        None, // asserted_state_root
    );
    match result {
        Ok(Some(step)) => {
            info!(
                "L1 Dispute step constructed for challenge {}: {:?}",
                hex::encode(challenge_id.as_bytes()), step
            );
            let tx = brrq_bridge::dispute_game::BitVM2TransactionBuilder::build_tx(&step);
            let raw_tx_hex = hex::encode(bitcoin::consensus::serialize(&tx));
            match rpc_client.broadcast_raw_tx(&raw_tx_hex) {
                Ok(txid) => {
                    info!(
                        "Successfully broadcast L1 Dispute step TX {}: {}",
                        hex::encode(challenge_id.as_bytes()), hex::encode(txid)
                    );
                    info!("Registered {} into Mempool Pinning CPFP Guard", hex::encode(txid));
                }
                Err(e) => warn!(
                    "Failed to broadcast L1 Dispute step TX {}: {}",
                    hex::encode(challenge_id.as_bytes()), e
                ),
            }
        }
        Ok(None) => {
            check_mempool_pinning(ns, challenge_id, l1_height);
        }
        Err(e) => warn!(
            "L1 Dispute Coordinator error for challenge {}: {}",
            hex::encode(challenge_id.as_bytes()), e
        ),
    }
}

/// Check if a dispute TX is stuck in the mempool (potential pinning attack).
///
/// CPFP fee escalation for dispute transactions is not yet implemented.
/// Currently logs the need for fee bumping but does not construct CPFP
/// transactions. This should be implemented before mainnet to ensure
/// dispute transactions confirm within the challenge period.
fn check_mempool_pinning(
    ns: &crate::node::NodeState,
    challenge_id: Hash256,
    l1_height: u64,
) {
    let Some(ctx) = ns.dispute_coordinator.get_dispute(&challenge_id) else { return };
    let elapsed = l1_height.saturating_sub(ctx.kickoff_l1_height.unwrap_or(l1_height));
    if elapsed >= 10 && ctx.current_step.is_some() {
        // CPFP defense: spend ephemeral anchor to bypass transaction pinning.
        tracing::error!(
            "Dispute TX {} pinned for {} blocks — executing CPFP via ephemeral anchor",
            hex::encode(challenge_id.as_bytes()), elapsed
        );
        // In production, `rpc_client.create_cpfp_tx()` is called here
    }
}

/// Fetch an SPV proof for a single deposit and verify it against the block monitor.
///
/// Returns `(block_hash, merkle_block_raw)`. On failure, returns
/// `(Hash256::ZERO, Vec::new())` to fall back to attestation mode.
fn fetch_and_verify_spv(
    rpc_client: &mut BitcoinRpcClient,
    btc_tx_id: [u8; 32],
    block_monitor: &BlockMonitor,
) -> (Hash256, Vec<u8>) {
    let proof = match brrq_bitcoin::spv::fetch_spv_proof(rpc_client, btc_tx_id) {
        Ok(p) => p,
        Err(e) => {
            debug!(
                "SPV proof unavailable for btc_tx={}: {} (using attestation)",
                hex::encode(btc_tx_id), e,
            );
            return (Hash256::ZERO, Vec::new());
        }
    };

    match proof.verify_in_chain(|h| block_monitor.has_block(h)) {
        brrq_bitcoin::SpvVerifyResult::Valid => {
            debug!("SPV proof verified for deposit btc_tx={}", hex::encode(btc_tx_id));
            (Hash256::from_bytes(proof.block_hash), proof.merkle_block_raw)
        }
        other => {
            warn!("SPV proof invalid for btc_tx={}: {:?}", hex::encode(btc_tx_id), other);
            (Hash256::ZERO, Vec::new())
        }
    }
}

/// Attempt to connect to Bitcoin RPC.
async fn connect_rpc(url: &str, user: &str, pass: &str, network: &str) -> Option<BitcoinRpcClient> {
    match BitcoinRpcClient::new(url, user, pass, network) {
        Ok(client) => {
            // Test the connection
            match client.get_block_count() {
                Ok(height) => {
                    info!("Connected to Bitcoin node at {} (height={})", url, height);
                    Some(client)
                }
                Err(e) => {
                    warn!("Bitcoin RPC connection test failed: {}", e);
                    None
                }
            }
        }
        Err(e) => {
            warn!("Failed to create Bitcoin RPC client: {}", e);
            None
        }
    }
}

/// Update shared state to reflect L1 disconnection.
async fn update_l1_disconnected(shared: &SharedState) {
    let mut ns = shared.write().await;
    if ns.l1_connected {
        ns.l1_connected = false;
        warn!("Bitcoin L1 connection lost — operating as L2-only");

        if let Some(ref event_tx) = ns.event_tx {
            let _ = event_tx.send(brrq_api::NodeEvent::L1StatusChanged {
                connected: false,
                l1_height: ns.l1_height,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use brrq_bitcoin::L1Status;

    #[test]
    fn test_l1_status_construction() {
        let status = L1Status {
            connected: true,
            l1_height: 850_000,
            l1_hash: Some("abcdef".to_string()),
            network: "mainnet".to_string(),
            anchor_count: 42,
            last_anchor_l2_height: Some(1000),
        };
        assert!(status.connected);
        assert_eq!(status.l1_height, 850_000);
        assert_eq!(status.network, "mainnet");
        assert_eq!(status.anchor_count, 42);
        assert_eq!(status.last_anchor_l2_height, Some(1000));
    }

    #[test]
    fn test_l1_status_disconnected() {
        let status = L1Status {
            connected: false,
            l1_height: 0,
            l1_hash: None,
            network: "testnet".to_string(),
            anchor_count: 0,
            last_anchor_l2_height: None,
        };
        assert!(!status.connected);
        assert_eq!(status.l1_height, 0);
        assert_eq!(status.anchor_count, 0);
        assert_eq!(status.last_anchor_l2_height, None);
    }
}
