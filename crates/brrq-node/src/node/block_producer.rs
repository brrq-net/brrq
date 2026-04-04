//! Block producer — production loop, key management, and block production/validation.
//!
//! Handles the block production entry point, key management, and block validation.
//!
//! Contains the block production entry point (`block_production_loop`),
//! key management (`load_or_generate_keys`), and core block production,
//! validation, and application functions.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use brrq_consensus::{FeeMarket, LeaderElection, StakingState};
use brrq_crypto::hash::Hash256;
use brrq_sequencer::block_builder::{BlockBuilder, SequencerKeys};
use brrq_state::persistent::PersistentStore;
use brrq_types::block::Block;
use brrq_types::transaction::{Transaction, TransactionKind};

use super::{NodeEvent, NodeState, SharedState, TxReceipt};

/// Default validator self-stake (1 BTC in satoshis).
const DEFAULT_VALIDATOR_STAKE: u64 = 100_000_000;

/// Start the block production loop.
///
/// This function runs forever, producing a block every `block_time_secs`.
/// It should be spawned as a tokio task.
///
/// ## Consensus Integration
///
/// **Single-sequencer mode** (rotation_enabled = false):
/// Sleep-based loop producing a block every interval.
///
/// **Multi-sequencer mode** (rotation_enabled = true):
/// Event-driven loop with 500ms tick checking the rotation state machine:
/// 1. `WaitingForProposal`: If I'm the leader → produce + broadcast proposal.
///    Otherwise, check_timeout → broadcast TimeoutVote.
/// 2. `Voting`: Votes arrive via network → at 2/3 quorum → Finalize.
/// 3. `Finalized`: Apply block → advance to next height.
pub async fn block_production_loop(
    shared: SharedState,
    store: Option<Arc<PersistentStore>>,
    block_time_secs: u64,
    key_path: &str,
    da_client: Box<dyn brrq_types::DaSubmit>,
) {
    let keys = std::sync::Arc::new(load_or_generate_keys(Path::new(key_path)));
    let mut builder = BlockBuilder::new(keys.clone());

    // Register this sequencer as a validator in the consensus layer
    {
        let mut ns = shared.write().await;
        let addr = builder.sequencer_address();
        if let Err(e) = ns.staking.register_validator(addr, DEFAULT_VALIDATOR_STAKE) {
            tracing::warn!("Validator registration failed (may already exist): {}", e);
        } else {
            tracing::info!("Sequencer registered as validator: {}", addr);
        }

        // Initialize bridge federation with the sequencer as sole member.
        // In dev-mode, 1-of-1 federation is allowed for testnet.
        // In production, MIN_FEDERATION_SIZE=3 enforces real multi-party setup.
        if ns.bridge.federation.is_none() {
            let members = vec![(addr, "sequencer".to_string())];
            if let Err(e) = ns.bridge.init_federation(members, 1, 0) {
                tracing::warn!("Bridge federation init failed: {}", e);
            } else {
                tracing::info!("Bridge federation initialized: sequencer as sole member");
            }
        }
    }

    // Check if rotation is enabled
    #[cfg(feature = "sequencer-rotation")]
    let rotation_enabled = {
        let ns = shared.read().await;
        ns.rotation_enabled
    };
    #[cfg(not(feature = "sequencer-rotation"))]
    let rotation_enabled = false;

    if rotation_enabled {
        #[cfg(feature = "sequencer-rotation")]
        {
            tracing::info!(
                "Block production started in ROTATION mode (tick = {}ms, persistent = {})",
                super::consensus_handler::ROTATION_TICK_MS,
                store.is_some(),
            );
            super::consensus_handler::rotation_production_loop(&mut builder, &shared, store, block_time_secs, &*da_client)
                .await;
        }
    } else {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(block_time_secs));
        tracing::info!(
            "Block production started (interval = {}s, persistent = {})",
            block_time_secs,
            store.is_some(),
        );
        loop {
            interval.tick().await;
            produce_block(&mut builder, &shared, store.clone(), &*da_client).await;
        }
    }
}

/// Load or generate sequencer keys.
///
/// If a key file exists at `path`, loads keys from it. Otherwise generates new
/// keys and saves them to the file for persistence across restarts.
pub(crate) fn load_or_generate_keys(path: &Path) -> SequencerKeys {
    if let Some(keys) = try_load_keys(path) {
        return keys;
    }

    // Generate new keys
    let keys =
        SequencerKeys::generate().expect("cryptographic key generation failed — cannot start node");

    if let Err(e) = save_keys_to_file(path, &keys) {
        tracing::error!("Failed to save validator keys to {:?}: {}", path, e);
    }

    tracing::info!("Generated new validator keys, address={}", keys.address);
    keys
}

/// Attempt to load sequencer keys from an existing key file.
/// Returns `None` if the file does not exist, is malformed, or derivation fails.
fn try_load_keys(path: &Path) -> Option<SequencerKeys> {
    if !path.exists() {
        return None;
    }

    let json = match std::fs::read_to_string(path) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("Failed to read key file {:?}: {}, generating new keys", path, e);
            return None;
        }
    };

    let val = match serde_json::from_str::<serde_json::Value>(&json) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("Failed to parse key file {:?}: {}, generating new keys", path, e);
            return None;
        }
    };

    let secret_hex = val.get("main_key_secret").and_then(|v| v.as_str())?;
    let secret_bytes = match hex::decode(secret_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            tracing::warn!("Invalid key file format at {:?}, generating new keys", path);
            return None;
        }
    };

    match SequencerKeys::from_secret_bytes(&secret_bytes) {
        Ok(keys) => {
            tracing::info!("Loaded validator keys from {:?}, address={}", path, keys.address);
            Some(keys)
        }
        Err(e) => {
            tracing::warn!(
                "Failed to derive keys from secret at {:?}: {}, generating new keys",
                path, e
            );
            None
        }
    }
}

/// Save sequencer keys to a file and restrict permissions.
fn save_keys_to_file(path: &Path, keys: &SequencerKeys) -> Result<(), std::io::Error> {
    let secret_hex = hex::encode(keys.main_key_secret_bytes());
    let key_data = serde_json::json!({
        "main_key_secret": secret_hex,
        "address": format!("{}", keys.address),
    });
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&key_data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(path, &json)?;

    restrict_key_file_permissions(path);
    tracing::info!("Saved validator keys to {:?}", path);
    Ok(())
}

/// Restrict key file permissions to owner-only on all platforms.
fn restrict_key_file_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        if let Err(e) = std::fs::set_permissions(path, perms) {
            tracing::warn!("Failed to set key file permissions to 0600: {}", e);
        }
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        let path_str = path.to_string_lossy();
        let username = std::env::var("USERNAME").unwrap_or_else(|_| "".to_string());
        if !username.is_empty() {
            let _ = Command::new("icacls")
                .args([path_str.as_ref(), "/inheritance:r"])
                .output();
            let grant_arg = format!("{}:F", username);
            if let Err(e) = Command::new("icacls")
                .args([path_str.as_ref(), "/grant:r", &grant_arg])
                .output()
            {
                tracing::warn!(
                    "Failed to set Windows ACL on key file {:?}: {}",
                    path, e
                );
            }
        } else {
            tracing::warn!(
                "Could not determine USERNAME for Windows ACL on key file {:?}",
                path
            );
        }
    }
}

// ══════════════════════════════════════════════════════════════════════
// Functions moved from mod.rs
// ══════════════════════════════════════════════════════════════════════

/// Produce a single block from the current mempool.
///
/// Integrates consensus layer:
/// 1. Epoch boundary check → transition (cap recalc, timeout resets)
/// 2. Leader election → only elected leader produces
/// 3. Block production → execute txs + dual-sign
/// 4. Validator tracking → record block produced / timeout
///
/// If `store` is `Some`, persists the new state to disk after the block is committed.
pub(crate) async fn produce_block(
    builder: &mut BlockBuilder,
    shared: &SharedState,
    store: Option<Arc<PersistentStore>>,
    da_client: &dyn brrq_types::DaSubmit,
) {
    let mut ns = shared.write().await;

    // Drain pending transactions (up to 1000 per block)
    let txs: Vec<Transaction> = ns.mempool.get_pending(1000).into_iter().cloned().collect();
    // Pre-compute all tx hashes for failed-tx eviction after block build.
    let all_pending_hashes: Vec<Hash256> = txs.iter().map(|tx| tx.hash()).collect();

    // Allow empty blocks in testnet to keep the chain advancing.
    // In production, you may want: if txs.is_empty() { return; }

    // Checked addition to prevent height overflow at u64::MAX
    let height = match ns.height.checked_add(1) {
        Some(h) => h,
        None => {
            tracing::error!("Block height overflow at u64::MAX — halting block production");
            return;
        }
    };
    let parent_hash = ns.parent_hash;
    let has_validators = !ns.staking.validators.is_empty();

    // ── Epoch transition ───────────────────────────────────────────
    if has_validators && ns.epoch.is_epoch_boundary(height) {
        // Split the borrow: epoch, staking, and slashing are disjoint fields of NodeState.
        let ns_ref = &mut *ns;
        let non_revealers = ns_ref.epoch.transition(
            height,
            &mut ns_ref.staking,
            &parent_hash,
            &mut ns_ref.slashing,
        );
        builder.set_epoch(ns_ref.epoch.current_epoch);
        for nr in &non_revealers {
            if let Some(v) = ns_ref.staking.validators.get_mut(nr) {
                v.adjust_reputation_penalty();
                tracing::warn!("Validator {} failed to reveal RANDAO secret", nr);
            }
        }
        tracing::info!(
            "Epoch transition → epoch {}, seed={:?}, validators={}, non_revealers={}",
            ns_ref.epoch.current_epoch,
            ns_ref.epoch.epoch_seed,
            ns_ref.epoch.validator_set.len(),
            non_revealers.len(),
        );
    }

    // ── RANDAO participation (§5) ──────────────────────────────────
    if has_validators {
        super::consensus_handler::participate_in_randao(&mut ns, builder, height);
    }

    // ── Dynamic Fee Market (§9.4) ──────────────────────────────────
    // Advance the EIP-1559-style base fee using the previous block's gas usage.
    // Only active when fee_market is Some (explicitly enabled).
    {
        let prev_gas = ns
            .blocks
            .back()
            .map(|b| (b.header.gas_used, b.header.gas_limit))
            .unwrap_or((0, 0));
        if prev_gas.1 > 0 {
            ns.fee_market.advance(prev_gas.0, prev_gas.1);
        }
        let new_base_fee = ns.fee_market.base_fee;
        builder.set_base_fee(new_base_fee);
        ns.mempool.set_base_fee(new_base_fee);
    }

    // ── Leader election ────────────────────────────────────────────
    // Use the rotation round (if active) instead of hardcoded 0.
    // When rotation_production_loop advances rounds via timeout, produce_block
    // must use the same round for leader election consistency.
    if has_validators {
        #[cfg(feature = "sequencer-rotation")]
        let election_round = ns.rotation.as_ref().map(|r| r.round()).unwrap_or(0);
        #[cfg(not(feature = "sequencer-rotation"))]
        let election_round = 0u32;
        match LeaderElection::elect(
            &ns.staking,
            &parent_hash,
            height,
            election_round,
            &ns.epoch.epoch_seed,
        ) {
            Ok(leader) => {
                let my_addr = builder.sequencer_address();
                if leader != my_addr {
                    // Not elected — record timeout for the expected leader
                    if let Some(v) = ns.staking.validators.get_mut(&leader) {
                        let new_status = v.record_timeout(height);
                        tracing::debug!(
                            "Leader {} missed block #{}, status={:?}",
                            leader,
                            height,
                            new_status,
                        );
                    }
                    return; // Skip block production
                }
                tracing::debug!("Elected as leader for block #{}", height);
            }
            Err(e) => {
                tracing::warn!("Leader election failed: {}, skipping block production", e);
                return;
            }
        }
    }

    // ── Set L1 context (if connected to Bitcoin) ───────────────────
    if ns.l1_connected && ns.l1_height > 0 {
        // Use the real Bitcoin block hash from the sync loop.
        // If the hash is not available (e.g., after reorg), use a hash of the height as fallback.
        let l1_hash = match ns.l1_block_hash {
            Some(hash_bytes) => Hash256::from_bytes(hash_bytes),
            None => {
                tracing::debug!(
                    "L1 block hash not available, using height-derived hash as fallback"
                );
                brrq_crypto::hash::Hasher::hash(&ns.l1_height.to_le_bytes())
            }
        };
        builder.set_l1_context(ns.l1_height, l1_hash);
    } else {
        builder.clear_l1_context();
    }

    // ── MEV-Protected Path (§8.1) ─────────────────────────────────
    #[cfg(feature = "mev-protection")]
    let (txs, _from_mev) = select_transactions_for_block(&mut ns, txs, height);
    #[cfg(not(feature = "mev-protection"))]
    let _from_mev = false;

    // ── Drain pending synthetic deposits ─────────────────────────
    // Deposits detected by bitcoin_sync are queued as SyntheticDeposit
    // structs. We drain them here and pass to build_block() for inclusion.
    let pending_deposits: Vec<brrq_types::SyntheticDeposit> =
        ns.pending_synthetic_deposits.drain(..).collect();

    // ── L1 monitoring: prover-strike detection + federation sunset ──
    super::bridge_monitor::run_l1_checks(&mut *ns, height);

    // ── Portal maintenance: expire locks past timeout ──────────────
    // Must match producer ordering (produce_block runs maintenance before build_block).
    super::portal_maintenance::run_portal_maintenance(&mut *ns, height);

    // ── Build block ────────────────────────────────────────────────
    // Both MEV and standard paths use build_block_with_deposits() to ensure
    // pending synthetic deposits are always included. The MEV ordering of
    // user transactions is preserved — deposits are prepended before them.
    // Scope the field destructuring so borrows are released before using `ns` below.
    let build_result = {
        let NodeState {
            ref mut state,
            ref mut bridge,
            ref mut staking,
            ref mut slashing,
            ref mut portal_escrow,
            ref mut portal_nullifiers,
            ..
        } = *ns;
        let mut consensus = brrq_sequencer::ConsensusCtx::new(staking, slashing);
        builder.build_block_with_deposits(
            height,
            parent_hash,
            txs,
            &pending_deposits,
            state,
            bridge,
            Some(&mut consensus),
            Some(portal_escrow),
            Some(portal_nullifiers),
        )
    };
    let (block, exec_summaries) = match build_result {
        Ok(result) => result,
        Err(e) => {
            // If MEV path was used and block build failed, reset the MEV phase
            // but do NOT remove envelopes — they can be retried next round.
            #[cfg(feature = "mev-protection")]
            if _from_mev {
                ns.mev_mempool.reset_phase();
                tracing::warn!("MEV block build failed; envelopes preserved for retry");
            }
            tracing::error!("Block production failed at height {}: {}", height, e);
            return;
        }
    };

    let block_hash = block.header.hash();
    let tx_count = block.tx_count();
    let gas_used = block.header.gas_used;

    // Record receipts and collect committed tx hashes
    let (new_receipts, committed_hashes) =
        collect_receipts_and_logs(&mut ns, &block, &exec_summaries, height, block_hash);

    // ── Fee distribution (§9.4) ───────────────────────────────────
    let per_tx_gas: Vec<u64> = exec_summaries.iter().map(|s| s.gas_used).collect();
    let mut dummy_undo_logs = Vec::new();
    distribute_fees(
        &mut ns,
        &block.transactions,
        &per_tx_gas,
        gas_used,
        builder.sequencer_address(),
        height,
        &mut dummy_undo_logs,
    );

    // Remove committed txs from mempool (reuse already-computed hashes)
    ns.mempool.remove_committed(&committed_hashes);
    ns.mempool.evict_expired();

    // Remove failed txs (submitted but not included) to prevent infinite retries.
    // A tx that fails execution (nonce mismatch, insufficient balance, contract
    // revert) should not block the mempool forever.
    if !all_pending_hashes.is_empty() {
        let committed_set: std::collections::HashSet<Hash256> =
            committed_hashes.iter().copied().collect();
        let failed_hashes: Vec<Hash256> = all_pending_hashes
            .iter()
            .filter(|h| !committed_set.contains(h))
            .copied()
            .collect();
        if !failed_hashes.is_empty() {
            ns.mempool.remove_committed(&failed_hashes);
            tracing::debug!(
                count = failed_hashes.len(),
                "Evicted failed transactions from mempool"
            );
        }
    }

    // ── Deferred MEV cleanup (only after successful block build) ──
    #[cfg(feature = "mev-protection")]
    if _from_mev {
        let ordered = ns.mev_mempool.get_ordered(1000);
        let env_hashes: Vec<Hash256> = ordered.iter().map(|e| e.hash()).collect();
        ns.mev_mempool.remove_committed(&env_hashes);
        ns.mev_mempool.reset_phase();
    }

    // Record successful block production for consensus tracking
    if has_validators {
        let my_addr = builder.sequencer_address();
        if let Some(v) = ns.staking.validators.get_mut(&my_addr) {
            v.record_block_produced();
        }
    }

    // ── Registration layer: process unbonding + feed tx data ──
    #[cfg(feature = "sequencer-rotation")]
    {
        let ns_ref = &mut *ns;
        let released = ns_ref.registration.process_unbonding(height);
        for (delegator, amount) in &released {
            let acct = ns_ref.state.get_or_create_account(*delegator);
            acct.balance = acct.balance.saturating_add(*amount);
            ns_ref.state.flush_account(delegator);
            tracing::debug!("Unbonding released: {} receives {} sats", delegator, amount,);
        }
    }

    // ── DA-Finality: await DA confirmation BEFORE advancing chain ──
    // A true rollup MUST guarantee DA availability before
    // committing locally. If DA submission fails, we must NOT advance
    // the chain — doing so would allow DA withholding attacks where
    // the sequencer commits state that peers cannot verify.
    let da_ok = da_client
        .submit_awaitable(block.compress_to_light())
        .await
        .is_ok();
    if !da_ok {
        tracing::error!(
            height,
            "DA submission failed — block NOT committed. Will retry on next tick.",
        );
        return;
    }

    // Persist Portal state BEFORE chain advance (crash safety).
    // If portal save fails, block is NOT committed — prevents state divergence.
    if let Some(ref s) = store {
        if let Err(e) = persist_portal_state(&ns, s) {
            tracing::error!("CRITICAL: Portal persistence failed: {e}. Block NOT committed.");
            return;
        }
    }

    // Advance chain state and persist
    let committed_root = advance_chain_state(&mut ns, height, block_hash, exec_summaries.len());
    ns.push_block(block.clone());

    // MPSC Zero-Copy Disk Pipeline offloading I/O sequentially natively
    if store.is_some() {
        enqueue_block_persistence(&mut ns, &new_receipts, &block, committed_root);
    }

    // Emit events for WebSocket subscribers
    emit_block_events(&ns, &block, height, block_hash, tx_count, gas_used);
    emit_portal_events(&ns, &block);

    // Queue P2P block announcement only if DA submission succeeded.
    // Without DA confirmation, broadcasting would allow DA withholding attacks.
    if da_ok {
        ns.pending_block_announcements
            .push((block_hash, height, builder.sequencer_address()));
    }

    tracing::info!(
        "Block #{} produced (epoch {}): {} tx(s), gas={}, base_fee={}, hash={:?}",
        height,
        ns.epoch.current_epoch,
        tx_count,
        gas_used,
        ns.fee_market.base_fee,
        block_hash,
    );

    // Accumulate execution traces for STARK batch proving.
    // Traces from TxExecSummary are extended into the running batch accumulator.
    for summary in &exec_summaries {
        if let Some(ref trace) = summary.execution_trace {
            ns.batch_traces.extend(trace);
        }
    }

    // Check if we should generate a batch STARK proof
    let batch_size = ns.batch_proof_config.batch_size;
    if batch_size > 0 && height >= ns.last_proved_height + batch_size {
        let shared_clone = shared.clone();
        drop(ns);
        tokio::spawn(async move {
            generate_batch_proof(shared_clone).await;
        });
    }
}

// ── Sub-Functions ────────────────────────────────────────────────────

/// Collect receipts, committed hashes, and block logs from execution summaries.
fn collect_receipts_and_logs(
    ns: &mut NodeState,
    block: &Block,
    exec_summaries: &[brrq_sequencer::block_builder::TxExecSummary],
    height: u64,
    block_hash: Hash256,
) -> (Vec<(Hash256, TxReceipt)>, Vec<Hash256>) {
    let mut new_receipts = Vec::with_capacity(block.transactions.len());
    let mut committed_hashes = Vec::with_capacity(block.transactions.len());
    let mut all_block_logs: Vec<brrq_types::Log> = Vec::new();
    for (i, tx) in block.transactions.iter().enumerate() {
        let summary = &exec_summaries[i];
        all_block_logs.extend(summary.logs.iter().cloned());
        let receipt = TxReceipt {
            block_height: height,
            gas_used: summary.gas_used,
            success: summary.success,
            block_hash,
            logs: summary.logs.clone(),
        };
        let tx_hash = tx.hash();
        committed_hashes.push(tx_hash);
        ns.receipts.insert(tx_hash, receipt.clone());
        new_receipts.push((tx_hash, receipt));
    }
    // Store block logs for getLogs queries
    if !all_block_logs.is_empty() {
        ns.block_logs.insert(height, all_block_logs);
    }
    (new_receipts, committed_hashes)
}

/// Advance chain height, parent hash, bridge state, and metrics counters.
/// Returns the committed state root.
fn advance_chain_state(
    ns: &mut NodeState,
    height: u64,
    block_hash: Hash256,
    tx_count: usize,
) -> Hash256 {
    ns.height = height;
    ns.parent_hash = block_hash;
    ns.bridge.l2_height = height;
    let committed_root = ns.state.state_root();
    ns.bridge.commit_state_root(height, committed_root);
    ns.blocks_produced_total += 1;
    ns.tx_total += tx_count as u64;
    if let Some(ref m) = ns.metrics {
        m.blocks_produced.fetch_add(1, Ordering::Relaxed);
        m.tx_processed
            .fetch_add(tx_count as u64, Ordering::Relaxed);
    }
    committed_root
}

/// Enqueue a block for async persistence via the MPSC pipeline.
fn enqueue_block_persistence(
    ns: &mut NodeState,
    new_receipts: &[(Hash256, TxReceipt)],
    block: &Block,
    committed_root: Hash256,
) {
    let diff = ns.state.extract_diff();
    let receipt_data: Vec<(
        brrq_crypto::hash::Hash256,
        brrq_state::persistent::ReceiptData,
    )> = new_receipts
        .iter()
        .map(|(h, r)| {
            (
                *h,
                brrq_state::persistent::ReceiptData {
                    block_height: r.block_height,
                    gas_used: r.gas_used,
                    success: r.success,
                    block_hash: r.block_hash,
                },
            )
        })
        .collect();
    // Serialize bridge state for atomic persistence.
    let bridge_state_blob = ns.bridge.to_bytes().ok();

    if let Some(tx) = ns.persistence_tx.clone() {
        if let Err(e) = tx.try_send(brrq_api::state::PersistenceTask::PersistBlock {
            diff,
            height: ns.height,
            parent_hash: ns.parent_hash,
            block: block.clone(),
            receipts: receipt_data,
            state_root: committed_root,
            bridge_state_blob,
            permit: None,
        }) {
            tracing::error!("MPSC pipeline dropped block {}: {}", ns.height, e);
        }
    }
}

/// Persist Portal escrow and nullifier state to disk.
fn persist_portal_state(
    ns: &NodeState,
    store: &PersistentStore,
) -> Result<(), String> {
    let escrow_bytes = ns.portal_escrow.to_bytes().map_err(|e| format!("serialize escrow: {e}"))?;
    store.save_portal_state_blob(&escrow_bytes).map_err(|e| format!("save escrow: {e}"))?;
    let null_bytes = ns.portal_nullifiers.to_bytes().map_err(|e| format!("serialize nullifiers: {e}"))?;
    store.save_portal_nullifiers_blob(&null_bytes).map_err(|e| format!("save nullifiers: {e}"))?;
    Ok(())
}

/// Emit NewBlock event for WebSocket subscribers.
fn emit_block_events(
    ns: &NodeState,
    block: &Block,
    height: u64,
    block_hash: Hash256,
    tx_count: usize,
    gas_used: u64,
) {
    let Some(ref event_tx) = ns.event_tx else { return };
    let _ = event_tx.send(NodeEvent::NewBlock {
        height,
        hash: format!("{:?}", block_hash),
        tx_count,
        timestamp: ns.blocks.back().map(|b| b.header.timestamp).unwrap_or(0),
        gas_used,
    });
}

/// Emit Portal transaction events for WebSocket subscribers.
/// S4/S5 FIX: Use actual amounts from escrow state, not hardcoded zeros
fn emit_portal_events(ns: &NodeState, block: &Block) {
    let Some(ref event_tx) = ns.event_tx else { return };
    for tx in &block.transactions {
        match &tx.body.kind {
            brrq_types::TransactionKind::CreatePortalLock {
                amount,
                timeout_l2_block,
                ..
            } => {
                let _ = event_tx.send(NodeEvent::PortalLockCreated {
                    lock_id: format!("{:?}", tx.hash()),
                    owner: tx.body.from.to_brrq_hex(),
                    amount: *amount,
                    timeout_l2_block: *timeout_l2_block,
                });
            }
            brrq_types::TransactionKind::SettlePortalLock { lock_id, .. } => {
                // Read actual amount from escrow (lock may be Settled now)
                let settled_amount = ns.portal_escrow
                    .get_lock(lock_id)
                    .map(|l| l.amount)
                    .unwrap_or(0);
                let _ = event_tx.send(NodeEvent::PortalLockSettled {
                    lock_id: lock_id.to_hex(),
                    merchant: tx.body.from.to_brrq_hex(),
                    amount: settled_amount,
                });
            }
            brrq_types::TransactionKind::BatchSettlePortal { claims } => {
                // S5 FIX: Report actual success/fail from exec summary
                // We can't know exact counts here without storing batch result,
                // so report claims submitted (total) — actual result was logged
                let _ = event_tx.send(NodeEvent::PortalBatchSettled {
                    succeeded: 0, // Actual count unknown at event emission
                    failed: 0,
                    total: claims.len() as u64,
                });
            }
            brrq_types::TransactionKind::CancelPortalLock { lock_id } => {
                let cancelled_amount = ns.portal_escrow
                    .get_lock(lock_id)
                    .map(|l| l.amount)
                    .unwrap_or(0);
                let _ = event_tx.send(NodeEvent::PortalLockCancelled {
                    lock_id: lock_id.to_hex(),
                    owner: tx.body.from.to_brrq_hex(),
                    amount: cancelled_amount,
                });
            }
            _ => {}
        }
    }
}

/// Select transactions for the next block, handling MEV protection.
///
/// Returns (transactions, from_mev_flag).
#[cfg(feature = "mev-protection")]
fn select_transactions_for_block(
    ns: &mut NodeState,
    standard_txs: Vec<Transaction>,
    height: u64,
) -> (Vec<Transaction>, bool) {
    let mev_active = ns.mev_mode != brrq_api::state::MevActivationMode::Disabled;
    let is_decentralized = ns.mev_mode == brrq_api::state::MevActivationMode::Decentralized;

    if !mev_active || ns.mev_mempool.is_empty() {
        return (standard_txs, false);
    }

    if is_decentralized {
        // Decentralized two-block split
        match ns.mev_ordering_locked_at {
            None => {
                // Lock ordering and broadcast commitment.
                if let Err(e) = ns.mev_mempool.lock_ordering(height) {
                    tracing::warn!(
                        "MEV lock_ordering failed: {e}, falling back to standard mempool"
                    );
                } else {
                    ns.mev_ordering_locked_at = Some(height);
                    tracing::info!(
                        "MEV ordering locked at height={}, decrypt in next block",
                        height
                    );
                }
                (standard_txs, false)
            }
            Some(locked_height) => {
                // Decrypt using locked ordering.
                // Use L1-anchored key derivation when anchor is available.
                //
                // Future: Replace with decrypt_batch_threshold() using Shamir shares
                // collected from committee members via P2P protocol. This requires:
                // 1. Share collection protocol (P2P messages between committee members)
                // 2. Share validation per member
                // 3. Timeout + fallback for offline members
                // For testnet, single-sequencer derivation is acceptable.
                let epoch_key = if let Some(ref anchor) = ns.l1_block_hash {
                    brrq_crypto::encryption::EpochKey::derive_with_anchor(
                        &ns.epoch.epoch_seed, ns.epoch.current_epoch, anchor,
                    )
                } else {
                    brrq_crypto::encryption::EpochKey::derive(
                        &ns.epoch.epoch_seed, ns.epoch.current_epoch,
                    )
                };
                match ns.mev_mempool.decrypt_batch(&epoch_key, 1000, height) {
                    Ok(decrypted) => {
                        tracing::info!(
                            "MEV decrypted {} txs (locked at height={})",
                            decrypted.len(),
                            locked_height,
                        );
                        ns.mev_ordering_locked_at = None;
                        (decrypted, true)
                    }
                    Err(e) => {
                        tracing::warn!("MEV decrypt failed: {e}, falling back to standard mempool");
                        ns.mev_mempool.reset_phase();
                        ns.mev_ordering_locked_at = None;
                        let fallback: Vec<Transaction> =
                            ns.mempool.get_pending(1000).into_iter().cloned().collect();
                        (fallback, false)
                    }
                }
            }
        }
    } else {
        // Centralized bypass: lock and decrypt in same block.
        if let Err(e) = ns.mev_mempool.lock_ordering(height) {
            tracing::warn!("MEV lock_ordering failed: {e}, falling back to standard mempool");
        }
        // Use L1-anchored derivation when available.
        let epoch_key = if let Some(ref anchor) = ns.l1_block_hash {
            brrq_crypto::encryption::EpochKey::derive_with_anchor(
                &ns.epoch.epoch_seed, ns.epoch.current_epoch, anchor,
            )
        } else {
            brrq_crypto::encryption::EpochKey::derive(&ns.epoch.epoch_seed, ns.epoch.current_epoch)
        };
        match ns
            .mev_mempool
            .decrypt_batch(&epoch_key, 1000, height.saturating_add(1))
        {
            Ok(decrypted) => (decrypted, true),
            Err(e) => {
                tracing::warn!("MEV decrypt failed: {e}, falling back to standard mempool");
                ns.mev_mempool.reset_phase();
                let fallback: Vec<Transaction> =
                    ns.mempool.get_pending(1000).into_iter().cloned().collect();
                (fallback, false)
            }
        }
    }
}

// ── Shared Fee Distribution ──────────────────────────────────────────

/// Compute total gas revenue from transactions and their actual gas usage.
///
/// Uses `effective_gas_price` (EIP-1559) = `min(max_fee, base_fee + priority)`,
/// NOT `max_fee_per_gas`. Using `max_fee_per_gas` would inflate revenue beyond
/// what was actually collected from users, causing phantom money creation when
/// `distribute_fees` splits the revenue into sequencer/treasury/burn shares.
///
/// This function is the SINGLE source of truth for gas revenue calculation.
/// Both `produce_block` and `apply_block` MUST use this function to prevent
/// consensus divergence between block producers and syncing nodes.
fn compute_gas_revenue(txs: &[Transaction], per_tx_gas: &[u64], base_fee: u64) -> u64 {
    txs.iter()
        .zip(per_tx_gas.iter())
        .map(|(tx, &gas_used)| {
            let priority_fee = std::cmp::min(
                tx.body.max_priority_fee_per_gas,
                tx.body.max_fee_per_gas.saturating_sub(base_fee),
            );
            let effective_gas_price = base_fee.saturating_add(priority_fee);
            (effective_gas_price as u128)
                .saturating_mul(gas_used as u128)
                .min(u64::MAX as u128) as u64
        })
        .fold(0u64, |acc, x| acc.saturating_add(x))
}

/// Distribute block fees to protocol participants.
///
/// Apply Portal side-effects during block re-execution on follower nodes.
///
/// Extracted from duplicated logic in produce_block and apply_block.
/// Any change to fee distribution MUST be made here — never in the callers.
///
/// Returns total gas revenue for logging purposes.
fn distribute_fees(
    ns: &mut NodeState,
    txs: &[Transaction],
    per_tx_gas: &[u64],
    gas_used: u64,
    sequencer_addr: brrq_types::Address,
    block_height: u64,
    undo_logs: &mut Vec<brrq_state::StateChange>,
) -> u64 {
    let total_gas_revenue = if gas_used > 0 {
        compute_gas_revenue(txs, per_tx_gas, ns.fee_market.base_fee)
    } else {
        0
    };

    // Fee market mode: split per whitepaper §9.4
    let fee_market = &ns.fee_market;
    let base_fee_burned = if gas_used > 0 {
        (fee_market.base_fee as u128)
            .saturating_mul(gas_used as u128)
            .min(u64::MAX as u128) as u64
    } else {
        0
    };

    let total_priority_fees = total_gas_revenue.saturating_sub(base_fee_burned);
    // Graduated fees and burn cap integration pending economic specification finalization
    let total_graduated_fees: u64 = 0;
    // Burn cap redirection requires fee_market.apply_burn_cap() with actual supply values
    let treasury_redirected_from_burn: u64 = 0;
    let dist = FeeMarket::distribute_block_fees_at_height(
        total_priority_fees,
        total_graduated_fees,
        base_fee_burned,
        treasury_redirected_from_burn,
        block_height,
    );

    let mut actual_bootstrap_payout = 0;

    // Helper for safe balance tracking for undo_logs
    let mut mutate_acct =
        |ns_mut: &mut NodeState, addr: brrq_types::Address, amount: u64, subtract: bool| {
            let old_balance = ns_mut.state.balance(&addr);
            let acct = ns_mut.state.get_or_create_account(addr);
            if subtract {
                if acct.balance >= amount {
                    acct.balance -= amount;
                } else {
                    tracing::error!(
                        "CRITICAL: Protocol treasury depleted! Cannot fully pay bootstrap reward."
                    );
                    acct.balance = 0;
                }
            } else {
                acct.balance = acct.balance.saturating_add(amount);
            }
            ns_mut.state.flush_account(&addr);
            let new_balance = ns_mut.state.balance(&addr);
            if old_balance != new_balance {
                undo_logs.push(brrq_state::StateChange::BalanceChange {
                    address: addr,
                    old_balance,
                    new_balance,
                });
            }
            new_balance // Return new balance
        };

    // 1. Handle Protocol Treasury (Receives 10% fee, Pays bootstrap reward)
    if dist.protocol_treasury > 0 || dist.bootstrap_reward > 0 {
        if let Some(treasury_addr) = ns.protocol_treasury_address {
            // Add incoming protocol fee share
            mutate_acct(ns, treasury_addr, dist.protocol_treasury, false);

            // Deduct bootstrap reward
            let before = ns.state.balance(&treasury_addr);
            let subtracted = std::cmp::min(before, dist.bootstrap_reward);
            actual_bootstrap_payout = subtracted;
            mutate_acct(ns, treasury_addr, subtracted, true);
        }
    }

    // 2. Credit sequencer (30% priority + actual_bootstrap_payout)
    if (dist.sequencer_reward > 0 || actual_bootstrap_payout > 0)
        && sequencer_addr != brrq_types::Address::ZERO
    {
        let total_sequencer = dist
            .sequencer_reward
            .saturating_add(actual_bootstrap_payout);
        mutate_acct(ns, sequencer_addr, total_sequencer, false);
    }

    // Credit prover pool (40% of priority fees)
    if dist.prover_reward > 0 {
        if let Some(prover_addr) = ns.prover_pool_address {
            mutate_acct(ns, prover_addr, dist.prover_reward, false);
        }
    }

    // Credit DA reserve (20% of priority fees)
    if dist.da_reserve > 0 {
        if let Some(da_addr) = ns.da_reserve_address {
            mutate_acct(ns, da_addr, dist.da_reserve, false);
        }
    }

    tracing::debug!(
        "Fee distribution: burned={}, sequencer={}, bootstrap={}, prover={}, da={}, treasury={}",
        dist.burned,
        dist.sequencer_reward,
        dist.bootstrap_reward,
        dist.prover_reward,
        dist.da_reserve,
        dist.protocol_treasury,
    );

    total_gas_revenue
}

// ── Batch Proof Generation ──────────────────────────────────────────

/// Generate a batch STARK proof for the latest unprovable block range.
///
/// Runs asynchronously after block production when the batch size threshold
/// is reached. Acquires locks only when reading state and storing results.
async fn generate_batch_proof(shared: SharedState) {
    // Read batch parameters and take accumulated traces from shared state
    let (initial_root, final_root, block_range, tx_count, total_gas, event_tx, batch_trace) = {
        let mut ns = shared.write().await;
        let batch_size = ns.batch_proof_config.batch_size;
        let start = ns.last_proved_height + 1;
        let end = ns.last_proved_height + batch_size;

        if end > ns.height {
            return; // Not enough blocks yet
        }

        // Compute state roots for the batch range.
        let initial_root = if start > 1 {
            ns.get_block(start - 1)
                .map(|b| b.header.state_root)
                .unwrap_or(Hash256::ZERO)
        } else {
            Hash256::ZERO
        };

        let final_root = ns
            .get_block(end)
            .map(|b| b.header.state_root)
            .unwrap_or(ns.state.state_root());

        // Count transactions and gas in the range
        let mut tx_count = 0usize;
        let mut total_gas = 0u64;
        for h in start..=end {
            if let Some(block) = ns.get_block(h) {
                tx_count += block.tx_count();
                total_gas += block.header.gas_used;
            }
        }

        // Skip empty batches: no transactions means no state transition to prove.
        if tx_count == 0 {
            tracing::info!(
                "Skipping proof for empty batch blocks {}-{} (0 transactions)",
                start, end,
            );
            ns.last_proved_height = end;
            return;
        }

        // Take the accumulated traces collected by produce_block and reset.
        let batch_trace = std::mem::replace(
            &mut ns.batch_traces,
            brrq_vm::trace::ExecutionTrace::new(),
        );

        // Verify trace register continuity before attempting proof.
        // Catches VM trace recording bugs early with actionable diagnostics.
        if !batch_trace.steps.is_empty() && !batch_trace.verify_consistency() {
            for window in batch_trace.steps.windows(2) {
                let prev = &window[0];
                let next = &window[1];
                if prev.regs_after != next.regs_before {
                    for r in 0..32 {
                        if prev.regs_after[r] != next.regs_before[r] {
                            tracing::error!(
                                "TRACE BUG: step {} regs_after[x{}]={:#x} != step {} regs_before[x{}]={:#x} (pc={:#x} → {:#x})",
                                prev.step, r, prev.regs_after[r],
                                next.step, r, next.regs_before[r],
                                prev.pc, next.pc,
                            );
                        }
                    }
                    break;
                }
            }
        }

        // If blocks have transactions but no traces were collected (e.g., blocks
        // produced before trace collection was wired up, or after a node restart),
        // skip this batch rather than failing repeatedly.
        if batch_trace.steps.is_empty() {
            tracing::warn!(
                "Skipping proof for blocks {}-{}: {} txs but no execution traces collected. \
                 Traces are only available for blocks produced after node start.",
                start, end, tx_count,
            );
            ns.last_proved_height = end;
            return;
        }

        (
            initial_root,
            final_root,
            (start, end),
            tx_count,
            total_gas,
            ns.event_tx.clone(),
            batch_trace,
        )
    };

    // Generate the proof (CPU-intensive, outside any lock).
    // Use real trace when available, falls back to synthetic internally.
    let prover = brrq_prover::StarkProver::new();
    match brrq_prover::batch::prove_batch_real(
        &prover,
        &batch_trace,
        initial_root,
        final_root,
        block_range,
        tx_count,
        total_gas,
    ) {
        Ok(record) => {
            let verified = record.verified;
            let gen_time = record.generation_time_ms;

            // Store the proof in shared state
            let mut ns = shared.write().await;
            ns.last_proved_height = block_range.1;

            // Store in bridge proof store
            let proof_stored_hash = match ns.bridge.store_batch_proof(&record) {
                Ok(hash) => Some(hash),
                Err(e) => {
                    tracing::warn!("Failed to store batch proof in bridge proof store: {}", e,);
                    None
                }
            };

            ns.proof_records.push(record);

            // Emit NewProof event for WebSocket subscribers
            if let Some(ref event_tx) = event_tx {
                let _ = event_tx.send(NodeEvent::NewProof {
                    block_range_start: block_range.0,
                    block_range_end: block_range.1,
                    verified,
                    generation_time_ms: gen_time,
                });

                // Emit ProofStored event
                if let Some(hash) = proof_stored_hash {
                    let _ = event_tx.send(NodeEvent::ProofStored {
                        block_range_start: block_range.0,
                        block_range_end: block_range.1,
                        stark_proof_hash: format!("0x{}", hex::encode(hash.as_bytes())),
                    });
                }
            }

            tracing::info!(
                "Batch STARK proof generated for blocks {}-{} (verified={}, {}ms)",
                block_range.0,
                block_range.1,
                verified,
                gen_time,
            );
        }
        Err(e) => {
            tracing::error!(
                "Batch proof generation failed for blocks {}-{}: {}",
                block_range.0,
                block_range.1,
                e,
            );
        }
    }
}

// ── Block Validation & Sync ──────────────────────────────────────────

/// Errors during block validation.
#[derive(Debug)]
pub enum ValidationError {
    /// Block height doesn't match expected.
    WrongHeight { expected: u64, got: u64 },
    /// Block parent hash doesn't match.
    WrongParentHash,
    /// Block failed structural validation (gas, tx_root).
    StructurallyInvalid,
    /// Block producer is not a registered validator.
    UnknownProducer(brrq_types::address::Address),
    /// Block timestamp is not advancing.
    TimestampNotAdvancing,
    /// Block timestamp is too far in the future (Time-Drift attack prevention).
    TimestampTooFarInFuture,
    /// Transaction execution produced different state.
    StateRootMismatch,
    /// General error.
    Other(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongHeight { expected, got } => {
                write!(f, "wrong height: expected {expected}, got {got}")
            }
            Self::WrongParentHash => write!(f, "parent hash mismatch"),
            Self::StructurallyInvalid => write!(f, "block is structurally invalid"),
            Self::UnknownProducer(addr) => write!(f, "unknown producer: {addr}"),
            Self::TimestampNotAdvancing => write!(f, "timestamp not advancing"),
            Self::TimestampTooFarInFuture => write!(f, "timestamp is too far in the future"),
            Self::StateRootMismatch => write!(f, "state root mismatch after re-execution"),
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

/// Validate a received block against expected chain state.
///
/// Checks structural validity, height continuity, parent hash chain,
/// timestamp monotonicity, and producer legitimacy.
pub fn validate_block(
    block: &Block,
    parent_hash: &Hash256,
    expected_height: u64,
    staking: &StakingState,
    prev_timestamp: u64,
    mtp: u64,
    l1_monitor: Option<&brrq_bitcoin::block_monitor::BlockMonitor>,
) -> Result<(), ValidationError> {
    // 1. Height must be next expected
    if block.header.height != expected_height {
        return Err(ValidationError::WrongHeight {
            expected: expected_height,
            got: block.header.height,
        });
    }

    // 2. Parent hash must match
    if block.header.parent_hash != *parent_hash {
        return Err(ValidationError::WrongParentHash);
    }

    // 3. Structural validity (gas + tx_root)
    if !block.is_structurally_valid() {
        return Err(ValidationError::StructurallyInvalid);
    }

    // 4. Timestamp must advance (or equal) relative to previous block.
    // Skip for first block (height 1) where prev_timestamp is 0 (genesis).
    if prev_timestamp > 0 && block.header.timestamp < prev_timestamp {
        return Err(ValidationError::TimestampNotAdvancing);
    }

    // 4.5. Bounded Deterministic Consensus Time.
    // 1. Lower Bound: Timestamp MUST be strictly greater than the Median Time Past (MTP) of the previous 11 blocks.
    #[cfg(not(test))]
    {
        if block.header.height > 0 && block.header.timestamp <= mtp {
            return Err(ValidationError::TimestampNotAdvancing);
        }
    }

    // 2. Upper Bound: Timestamp cannot be arbitrarily infinite (u64::MAX).
    // To maintain strict State Machine Replication determinism across validators,
    // we CANNOT use `SystemTime::now()` because local NTP clocks inevitably drift.
    // Instead, we mathematically bound maximum forward drift relative to the Median Time Past.
    #[cfg(not(test))]
    {
        const MAX_ALLOWED_BFT_DRIFT: u64 = 7200; // 2 hours
        if block.header.height > 0 && block.header.timestamp > mtp + MAX_ALLOWED_BFT_DRIFT {
            return Err(ValidationError::TimestampTooFarInFuture);
        }
    }

    // 5. Producer must be a registered validator (if validators exist).
    // When staking is empty (follower with no genesis validators), skip this
    // check — the caller (apply_block) will auto-register the sequencer.
    if !staking.validators.is_empty() && !staking.validators.contains_key(&block.header.sequencer) {
        return Err(ValidationError::UnknownProducer(block.header.sequencer));
    }

    // 6. Verify block dual signature (EOTS + SLH-DSA).
    // Skip for genesis block (height 0) which has no real signature.
    if block.header.height > 0 && !block.verify_signature() {
        return Err(ValidationError::StructurallyInvalid);
    }

    // 7. Sovereign Anchor Gatekeeping
    // We MUST verify that if the sequencer claims an L1 anchor, we have actually
    // seen this L1 block. If we haven't, we reject the block so the sequencer
    // cannot forge Bitcoin history.
    if let Some(anchor_hash) = block.header.l1_anchor_hash {
        if let Some(monitor) = l1_monitor {
            if !monitor.has_block(anchor_hash.as_bytes()) {
                // If the block is not in our local monitor, it means either:
                // 1) The sequencer is forging L1 history (Fraud).
                // 2) The sequencer is synced faster than this validator (Asynchrony).
                // In either case, stalling/rejecting the L2 block ensures safety without
                // breaking SMR determinism (since this check is OUTSIDE `apply_block`).
                return Err(ValidationError::Other(format!(
                    "l1_anchor_hash {} not recognized by local Bitcoin node",
                    anchor_hash
                )));
            }
        }
    }

    Ok(())
}

/// Apply a validated block to the node's state.
///
/// Re-executes all transactions to verify the state transition,
/// then commits the block to the chain.
///
/// Also runs consensus state updates (epoch transition,
/// fee market advance, staking tracking, registration unbonding, bridge
/// state root, counters) so that synced nodes stay consistent with producers.
pub fn apply_block(
    ns: &mut NodeState,
    block: Block,
) -> Result<brrq_api::state::BlockExecutionResult, ValidationError> {
    let expected_height = ns.height + 1;
    let mut undo_logs = Vec::new();
    let mut new_receipts = std::collections::HashMap::new();
    let mut new_block_logs = Vec::new();
    let mut committed_hashes = Vec::new();

    // Get previous block timestamp for monotonicity check
    let prev_timestamp = ns.blocks.back().map(|b| b.header.timestamp).unwrap_or(0);

    // Get Median Time Past for deterministic validation
    let mtp = ns.median_time_past();

    // Validate the block
    validate_block(
        &block,
        &ns.parent_hash,
        expected_height,
        &ns.staking,
        prev_timestamp,
        mtp,
        ns.l1_monitor.as_ref(),
    )?;

    let block_height = block.header.height;

    // Auto-register the block's sequencer as a validator if no validators
    // are known. This handles followers syncing from scratch when the
    // genesis has no pre-registered validators (sequencer registers
    // itself dynamically at startup, which is not encoded in blocks).
    if ns.staking.validators.is_empty()
        && block.header.sequencer != brrq_types::Address::ZERO
    {
        let _ = ns.staking.register_validator(block.header.sequencer, DEFAULT_VALIDATOR_STAKE);
        tracing::info!(
            "Auto-registered sequencer {} as validator from block {}",
            block.header.sequencer, block_height,
        );
    }

    let has_validators = !ns.staking.validators.is_empty();

    // ── Epoch transition (mirrors produce_block logic) ─────────────────
    if has_validators && ns.epoch.is_epoch_boundary(block_height) {
        let parent_hash = ns.parent_hash;
        let ns_ref = &mut *ns;
        let non_revealers = ns_ref.epoch.transition(
            block_height,
            &mut ns_ref.staking,
            &parent_hash,
            &mut ns_ref.slashing,
        );
        for nr in &non_revealers {
            if let Some(v) = ns_ref.staking.validators.get_mut(nr) {
                v.adjust_reputation_penalty();
            }
        }
        tracing::debug!(
            "apply_block: epoch transition at height {}, non_revealers={}",
            block_height,
            non_revealers.len(),
        );
    }

    // ── Dynamic fee market advance ─────────────────────────────────────
    {
        let prev_gas = ns
            .blocks
            .back()
            .map(|b| (b.header.gas_used, b.header.gas_limit))
            .unwrap_or((0, 0));
        if prev_gas.1 > 0 {
            ns.fee_market.advance(prev_gas.0, prev_gas.1);
        }
    }

    // Portal maintenance BEFORE transaction re-execution.
    // Must match producer ordering (produce_block runs maintenance before build_block).
    super::portal_maintenance::run_portal_maintenance(ns, block_height);

    // Re-execute transactions to verify state transition.
    // DepositSynthetic transactions use a separate execution path that
    // bypasses nonce/signature/gas validation (they are system transactions
    // injected by the sequencer, not user-signed).
    let chain_id = ns.chain_id;
    let mut total_gas_used = 0u64;
    let mut per_tx_gas_used: Vec<u64> = Vec::with_capacity(block.transactions.len());
    let mut block_trace = brrq_vm::trace::ExecutionTrace::with_capacity(0);
    for tx in &block.transactions {
        let exec_result = match &tx.body.kind {
            TransactionKind::DepositSynthetic {
                recipient,
                amount,
                btc_tx_id,
                btc_vout,
                block_hash,
                merkle_block_raw,
            } => {
                re_execute_synthetic_deposit(
                    ns, recipient, amount, btc_tx_id, btc_vout, block_hash, merkle_block_raw,
                )?
            }
            _ => brrq_sequencer::executor::execute_transaction_with_context(
                tx,
                &mut ns.state,
                chain_id,
                brrq_sequencer::executor::ExecutionContext {
                    base_fee: block.header.base_fee_per_gas,
                    block_height: block.header.height,
                    block_timestamp: block.header.timestamp,
                    validator_address: Some(block.header.sequencer),
                },
                false,
            ),
        };
        match exec_result {
            Ok(result) => {
                // Accumulate VM trace for STARK batch proving
                if let Some(ref trace) = result.execution_trace {
                    block_trace.extend(trace);
                }

                // ── Portal (L3) side-effects for follower nodes ──────────
                // Mirror the producer's apply_portal_effects logic so
                // follower portal state stays in sync with the sequencer.
                super::portal_maintenance::apply_portal_effects_follower(tx, &mut ns.portal_escrow, &mut ns.portal_nullifiers, &mut ns.state, block_height);

                let tx_hash = tx.hash();
                let block_hash = block.header.hash();
                total_gas_used = total_gas_used.saturating_add(result.gas_used);
                per_tx_gas_used.push(result.gas_used);
                undo_logs.extend(result.state_changes);
                committed_hashes.push(tx_hash);
                new_block_logs.extend(result.logs.clone());
                new_receipts.insert(
                    tx_hash,
                    TxReceipt {
                        block_height: block.header.height,
                        gas_used: result.gas_used,
                        success: result.success,
                        block_hash,
                        logs: result.logs,
                    },
                );
            }
            Err(e) => {
                tracing::warn!("Tx re-execution failed during block apply: {e}");
                per_tx_gas_used.push(0);
            }
        }
    }

    // ── State root verification ─────────────────────────────────────
    // Verify state root BEFORE fee distribution (matches produce_block order:
    // build_block computes state_root after tx execution but before fees).
    // State root verification required for all blocks except genesis.
    let computed_root = ns.state.state_root();
    let is_genesis = block_height <= 1;
    if !(is_genesis && block.header.state_root == brrq_crypto::hash::Hash256::ZERO)
        && computed_root != block.header.state_root
    {
        tracing::error!(
            "State root mismatch at height {}: computed={:?}, block={:?}",
            block_height,
            computed_root,
            block.header.state_root,
        );
        return Err(ValidationError::StateRootMismatch);
    }

    // ── Fee distribution ──────────────────────────────────────────
    // Applied AFTER state root check (fees are post-block-header operations).
    distribute_fees(
        ns,
        &block.transactions,
        &per_tx_gas_used,
        total_gas_used,
        block.header.sequencer,
        block_height,
        &mut undo_logs,
    );

    // ── Registration unbonding ─────────────────────────────────────────
    #[cfg(feature = "sequencer-rotation")]
    {
        let ns_ref = &mut *ns;
        let released = ns_ref.registration.process_unbonding(block_height);
        for (delegator, amount) in &released {
            let old_balance = ns_ref.state.balance(delegator);
            let acct = ns_ref.state.get_or_create_account(*delegator);
            acct.balance = acct.balance.saturating_add(*amount);
            ns_ref.state.flush_account(delegator);
            let new_balance = ns_ref.state.balance(delegator);
            undo_logs.push(brrq_state::StateChange::BalanceChange {
                address: *delegator,
                old_balance,
                new_balance,
            });
        }
    }

    // Update bridge state root (mirrors produce_block)
    ns.bridge.l2_height = block_height;
    let committed_root = ns.state.state_root();
    ns.bridge.commit_state_root(block_height, committed_root);

    // Sovereign Anchor: Deterministically record the L1 anchor in State
    if let Some(anchor) = block.header.l1_anchor_hash {
        let crypto_hash = brrq_crypto::hash::Hash256::from_bytes(*anchor.as_bytes());
        ns.push_l1_anchor(crypto_hash, block_height);
    }

    Ok(brrq_api::state::BlockExecutionResult {
        undo_logs,
        new_receipts,
        new_block_logs,
        committed_hashes,
    })
}

/// Re-execute a synthetic deposit transaction during block validation.
///
/// Sovereign SPV Execution: verifies SPV root against deterministic
/// L1 Anchors in NodeState before processing the deposit through the bridge.
fn re_execute_synthetic_deposit(
    ns: &mut NodeState,
    recipient: &brrq_types::Address,
    amount: &u64,
    btc_tx_id: &Hash256,
    btc_vout: &u32,
    block_hash: &Hash256,
    merkle_block_raw: &[u8],
) -> Result<
    Result<brrq_sequencer::executor::ExecutionResult, brrq_sequencer::SequencerError>,
    ValidationError,
> {
    // 1. Verify SPV root against deterministic L1 Anchors in NodeState.
    // NO external calls to l1_monitor here to ensure STARK provability.
    if !merkle_block_raw.is_empty() && !ns.has_l1_anchor(block_hash.as_bytes()) {
        tracing::error!("Fraudulent deposit: SPV root not in deterministic SMR anchors");
        return Err(ValidationError::Other(
            "Fraudulent synthetic deposit: SPV root not in state anchors".into(),
        ));
    }

    let spv_proof = if merkle_block_raw.is_empty() {
        None
    } else {
        Some(brrq_bitcoin::spv::SpvProof {
            txid: *btc_tx_id.as_bytes(),
            merkle_block_raw: merkle_block_raw.to_vec(),
            block_hash: *block_hash.as_bytes(),
            block_height: 0, // Not used strictly in L2 execution SPV checking
        })
    };

    // 2. Enforce bridge accounting limits and mathematically verify SPV paths before execution!
    let exec_result = match ns.bridge.process_deposit(
        *btc_tx_id, *btc_vout, *amount, *recipient, 6, None, spv_proof,
    ) {
        Ok(minted_amount) => brrq_sequencer::executor::execute_synthetic_deposit(
            recipient,
            minted_amount,
            btc_tx_id,
            &mut ns.state,
        ),
        Err(e) => {
            tracing::error!(
                "Bridge limits or SPV cryptography violated by Sequencer deposit: {e}"
            );
            Err(brrq_sequencer::SequencerError::InvalidTransaction {
                reason: "fraudulent deposit".into(),
            })
        }
    };
    Ok(exec_result)
}

/// Permanently commit an executed block, its metrics and logs avoiding unneeded clones.
pub fn finalize_block(
    ns: &mut NodeState,
    block: Block,
    exec_result: brrq_api::state::BlockExecutionResult,
    store: Option<Arc<PersistentStore>>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
) {
    ns.height = block.header.height;
    ns.parent_hash = block.header.hash();
    ns.receipts.extend(exec_result.new_receipts.clone());
    ns.block_logs
        .insert(block.header.height, exec_result.new_block_logs.clone());
    ns.blocks_produced_total += 1;
    ns.tx_total += exec_result.committed_hashes.len() as u64;

    if let Some(ref m) = ns.metrics {
        m.blocks_produced
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        m.tx_processed.fetch_add(
            exec_result.committed_hashes.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    let block_hash = block.header.hash();
    let tx_count = block.tx_count();
    let block_timestamp = block.header.timestamp;
    let block_gas_used = block.header.gas_used;

    let receipts_to_save: Vec<_> = exec_result
        .new_receipts
        .into_iter()
        .map(|(h, r)| {
            (
                h,
                brrq_state::persistent::ReceiptData {
                    block_height: r.block_height,
                    gas_used: r.gas_used,
                    success: r.success,
                    block_hash: r.block_hash,
                },
            )
        })
        .collect();

    ns.push_block(block.clone());

    if let Some(_store) = store {
        let finalized_root = ns.state.state_root();
        let diff = ns.state.extract_diff();
        // Serialize bridge state for atomic persistence.
        let bridge_state_blob = ns.bridge.to_bytes().ok();
        if let Some(tx) = ns.persistence_tx.clone() {
            if let Err(e) = tx.try_send(brrq_api::state::PersistenceTask::PersistBlock {
                diff,
                height: ns.height,
                parent_hash: ns.parent_hash,
                block: block.clone(),
                receipts: receipts_to_save,
                state_root: finalized_root,
                bridge_state_blob,
                permit,
            }) {
                tracing::error!("MPSC pipeline dropped synced block {}: {}", ns.height, e);
            }
        }
    }

    if let Some(ref event_tx) = ns.event_tx {
        let _ = event_tx.send(NodeEvent::NewBlock {
            height: ns.height,
            hash: format!("{:?}", block_hash),
            tx_count,
            timestamp: block_timestamp,
            gas_used: block_gas_used,
        });
    }
}
