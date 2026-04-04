//! Brrq full node binary.
//!
//! Assembles all Brrq subsystems into a running node with:
//! - Block production loop (every 3 seconds)
//! - JSON-RPC + REST HTTP server via Axum (brrq-api)
//! - WebSocket subscriptions (integrated in brrq-api at /ws)
//! - Persistent state storage (automatic save/load)
//! - SQLite blockchain indexer (brrq-indexer)

mod bitcoin_sync;
pub mod da;
mod genesis;
mod message_handlers;
mod network_service;
mod node;
pub mod platform;

#[cfg(test)]
mod multi_sequencer;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use brrq_api::{AppState, create_event_channel};
use brrq_crypto::hash::Hash256;
use brrq_state::persistent::PersistentStore;
use clap::Parser;
use tokio_util::sync::CancellationToken;
use tracing::info;

/// Build a receipt map from NodeState for the indexer.
/// Maps tx_hash → (gas_used, success).
fn build_receipt_map(ns: &node::NodeState) -> HashMap<Hash256, (u64, bool)> {
    ns.receipts
        .iter()
        .map(|(hash, r)| (*hash, (r.gas_used, r.success)))
        .collect()
}

/// Flush the MPSC persistence pipeline, waiting up to 5 seconds.
async fn flush_persistence_pipeline(
    tx: &tokio::sync::mpsc::Sender<brrq_api::state::PersistenceTask>,
) {
    let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
    if let Err(e) = tx.try_send(brrq_api::state::PersistenceTask::Flush(flush_tx)) {
        tracing::error!("Failed to send Flush to persistence pipeline: {}", e);
        return;
    }
    match tokio::time::timeout(tokio::time::Duration::from_secs(5), flush_rx).await {
        Ok(Ok(())) => {
            info!("Persistence pipeline flushed successfully.");
        }
        Ok(Err(_)) => {
            tracing::error!("Persistence flush: oneshot sender dropped.");
        }
        Err(_) => {
            tracing::error!("Persistence flush timed out after 5s — potential data loss.");
        }
    }
}

/// Prune historical blocks older than `PRUNE_HISTORY_DEPTH` after a successful persist.
fn persist_prune_old_blocks(store: &PersistentStore, height: u64) {
    const PRUNE_HISTORY_DEPTH: u64 = 10_000;
    let prune_height = height.saturating_sub(PRUNE_HISTORY_DEPTH);
    if prune_height > 0 {
        if let Err(e) = store.prune_blocks_prior_to_height(prune_height) {
            tracing::error!(
                "MPSC Failed to prune historical blocks prior to {}: {}",
                prune_height,
                e
            );
        }
    }
}

/// Load the faucet keypair from the validator key file.
///
/// Returns `Some(keypair)` if the key file exists and contains a valid
/// 32-byte `main_key_secret` field. Returns `None` on any I/O or
/// parsing error (callers log diagnostics separately).
fn load_faucet_keypair(key_path: &str) -> Option<brrq_crypto::schnorr::SchnorrKeyPair> {
    let key_file = std::path::Path::new(key_path);
    if !key_file.exists() {
        return None;
    }
    let json_str = std::fs::read_to_string(key_file).ok()?;
    let val: serde_json::Value = serde_json::from_str(&json_str).ok()?;
    let secret_hex = val.get("main_key_secret")?.as_str()?;
    let secret_bytes = hex::decode(secret_hex).ok()?;
    if secret_bytes.len() != 32 {
        return None;
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&secret_bytes);
    brrq_crypto::schnorr::SchnorrKeyPair::from_secret_bytes(&sk).ok()
}

/// Brrq full node CLI.
#[derive(Parser)]
#[command(name = "brrq-node", version, about = "Brrq L2 full node")]
struct Cli {
    /// Network to connect to.
    #[arg(long, default_value = "testnet")]
    network: String,

    /// Port for P2P connections.
    #[arg(long, default_value_t = 30303)]
    p2p_port: u16,

    /// Port for JSON-RPC + REST API.
    #[arg(long, default_value_t = 8545)]
    rpc_port: u16,

    /// Data directory.
    #[arg(long, default_value = "./brrq-data")]
    datadir: String,

    /// Enable sequencer mode (produces blocks).
    #[arg(long)]
    sequencer: bool,

    /// Enable prover mode.
    #[arg(long)]
    prover: bool,

    /// Number of blocks per STARK proof batch (0 = disabled).
    #[arg(long, default_value_t = 10)]
    batch_size: u64,

    /// Log level.
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Path to genesis configuration file.
    #[arg(long, default_value = "testnet-genesis.toml")]
    genesis: String,

    /// Comma-separated bootstrap node addresses (e.g., "seed1:30303,seed2:30303").
    #[arg(long, value_delimiter = ',')]
    bootstrap: Vec<String>,

    /// Path to validator key file (auto-generated if missing).
    #[arg(long)]
    validator_key: Option<String>,

    // ── Bitcoin L1 Integration ──────────────────────────────────────
    /// Bitcoin RPC URL (e.g., http://localhost:18332). Enables L1 integration.
    #[arg(long)]
    l1_rpc_url: Option<String>,

    /// Bitcoin RPC username. Prefer BRQ_L1_RPC_USER env var to avoid exposure in process listing.
    #[arg(long, env = "BRQ_L1_RPC_USER")]
    l1_rpc_user: Option<String>,

    /// Bitcoin RPC password. DEPRECATED as CLI flag — use BRQ_L1_RPC_PASS env var instead
    /// to avoid exposing credentials in process arguments (visible via `ps` / /proc).
    #[arg(long, env = "BRQ_L1_RPC_PASS", hide = true)]
    l1_rpc_pass: Option<String>,

    /// Bitcoin bridge address for deposit watching (Taproot/P2TR).
    #[arg(long)]
    bridge_address: Option<String>,

    // ── MEV Protection ───────────────────────────────────────────
    /// MEV protection mode (overrides genesis). Values: disabled, centralized_bypass, decentralized.
    #[arg(long)]
    mev_mode: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(&cli.log_level)
        .init();

    // Load genesis configuration
    let genesis_path = std::path::Path::new(&cli.genesis);
    let genesis_config = if genesis_path.exists() {
        match genesis::GenesisConfig::load(genesis_path) {
            Ok(g) => {
                info!("Loaded genesis from {}", cli.genesis);
                Some(g)
            }
            Err(e) => {
                tracing::error!("Failed to load genesis file: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        tracing::warn!("Genesis file not found at {}, using defaults", cli.genesis);
        None
    };

    let block_time = genesis_config
        .as_ref()
        .map(|g| g.chain.block_time_secs)
        .unwrap_or(3);

    info!("=================================================");
    info!("  Brrq Node v{}", env!("CARGO_PKG_VERSION"));
    info!("  Network: {}", cli.network);
    info!("  Genesis: {}", cli.genesis);
    info!("  P2P Port: {}", cli.p2p_port);
    info!("  RPC Port: {}", cli.rpc_port);
    info!("  Data Dir: {}", cli.datadir);
    info!("  Block Time: {}s", block_time);
    info!("  Sequencer: {}", cli.sequencer);
    info!("  Prover: {}", cli.prover);
    if let Some(ref url) = cli.l1_rpc_url {
        info!("  L1 RPC: {}", url);
        info!(
            "  Bridge Address: {}",
            cli.bridge_address.as_deref().unwrap_or("none")
        );
    } else {
        info!("  L1 Integration: disabled (no --l1-rpc-url)");
    }
    info!("=================================================");

    // Open persistent storage
    let db_path = format!("{}/state", cli.datadir);
    let store = match PersistentStore::open(&db_path) {
        Ok(s) => {
            info!("Persistent storage opened at {}", db_path);
            Arc::new(s)
        }
        Err(e) => {
            tracing::error!("Failed to open persistent storage at {}: {}", db_path, e);
            std::process::exit(1);
        }
    };

    // Load state from disk (or start fresh with genesis)
    let node_state = match node::NodeState::load_from_disk(&store) {
        Ok(mut ns) if ns.height > 0 => {
            info!(
                "Restored state: height={}, accounts={}",
                ns.height,
                ns.state.account_count()
            );
            // Replay genesis to rebuild staking/epoch state,
            // then replay all stored blocks to rebuild full consensus state.
            // Staking and epoch are not serialized to disk, so they must be
            // reconstructed from the block history on every restart.
            if let Some(ref genesis) = genesis_config {
                // Re-apply genesis staking/epoch config (without re-setting accounts)
                ns.staking = brrq_consensus::StakingState::new(genesis.chain.initial_stake_cap);
                ns.epoch = brrq_consensus::EpochState::new(genesis.chain.epoch_length);
                ns.chain_id = genesis.chain.chain_id;
                // Re-register genesis validators
                let mut validators: Vec<(brrq_types::Address, u64)> = genesis
                    .validators
                    .iter()
                    .filter_map(|v| {
                        genesis::parse_address_pub(&v.address)
                            .ok()
                            .map(|addr| (addr, v.stake))
                    })
                    .collect();
                validators.sort_by_key(|(addr, _)| *addr);
                for (addr, stake) in &validators {
                    let _ = ns.staking.register_validator(*addr, *stake);
                }
                info!(
                    "Rebuilt consensus state from genesis: {} validators, epoch_length={}",
                    validators.len(),
                    genesis.chain.epoch_length,
                );

                // Reconstruct dynamic validator registrations from block history.
                // The sequencer self-registers at startup (in-memory only), so this
                // registration is NOT encoded in blocks. Followers and restarted nodes
                // must discover validators by scanning block headers for unique
                // sequencer addresses and registering them.
                let mut discovered: std::collections::HashSet<brrq_types::Address> =
                    validators.iter().map(|(addr, _)| *addr).collect();
                for block in &ns.blocks {
                    let seq = block.header.sequencer;
                    if seq != brrq_types::Address::ZERO && !discovered.contains(&seq) {
                        discovered.insert(seq);
                        let _ = ns.staking.register_validator(seq, genesis.chain.initial_stake_cap.min(100_000_000));
                        info!("Discovered validator from block history: {}", seq);
                    }
                }
                // Also check PersistentStore for blocks evicted from memory
                {
                    let evicted_end = ns.height.saturating_sub(ns.blocks.len() as u64);
                    for h in 1..=evicted_end {
                        if let Ok(Some(block)) = store.load_block(h) {
                            let seq = block.header.sequencer;
                            if seq != brrq_types::Address::ZERO && !discovered.contains(&seq) {
                                discovered.insert(seq);
                                let _ = ns.staking.register_validator(seq, genesis.chain.initial_stake_cap.min(100_000_000));
                                info!("Discovered validator from stored block {}: {}", h, seq);
                            }
                        }
                    }
                }
                if discovered.len() > validators.len() {
                    info!(
                        "Total validators after block history scan: {} ({} from genesis, {} discovered)",
                        discovered.len(),
                        validators.len(),
                        discovered.len() - validators.len(),
                    );
                }
            }
            ns
        }
        Ok(mut ns) => {
            // height == 0: fresh store, apply genesis
            info!("Fresh store (height=0), applying genesis...");
            if let Some(ref genesis) = genesis_config
                && let Err(e) = genesis.apply(&mut ns)
            {
                tracing::error!("Failed to apply genesis: {}", e);
                std::process::exit(1);
            }
            ns
        }
        Err(e) => {
            tracing::warn!(
                "State payload corruption detected ({}), wiping persistent store to self-heal.",
                e
            );

            // On mainnet, attempt replay-from-stored-blocks recovery
            // instead of refusing to start. This rebuilds WorldState from genesis
            // by re-executing all stored blocks.
            if cli.network.contains("mainnet") {
                tracing::warn!(
                    "State corruption detected on mainnet. Attempting replay recovery \
                     from stored blocks (this may take a while)..."
                );

                // Create fresh NodeState with genesis
                let mut recovery_ns = node::NodeState::new();
                if let Some(ref genesis) = genesis_config {
                    if let Err(e) = genesis.apply(&mut recovery_ns) {
                        tracing::error!("Recovery failed: cannot apply genesis: {}", e);
                        std::process::exit(1);
                    }
                }

                // Load chain height from DB
                let (chain_height, _) = match store.load_chain_meta() {
                    Ok(meta) => meta,
                    Err(e) => {
                        tracing::error!("Recovery failed: cannot read chain meta: {}", e);
                        std::process::exit(1);
                    }
                };

                // Replay all stored blocks from 1 to chain_height
                let mut replayed = 0u64;
                for h in 1..=chain_height {
                    match store.load_block(h) {
                        Ok(Some(block)) => {
                            match crate::node::block_producer::apply_block(&mut recovery_ns, block) {
                                Ok(_) => {
                                    replayed += 1;
                                    if replayed % 1000 == 0 {
                                        tracing::info!("Recovery progress: {}/{} blocks replayed", replayed, chain_height);
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Recovery failed at block {}: {}. \
                                         State is consistent up to block {}.",
                                        h, e, h - 1
                                    );
                                    break;
                                }
                            }
                        }
                        Ok(None) => {
                            tracing::warn!("Recovery: block {} not found in store. Stopping at {}.", h, h - 1);
                            break;
                        }
                        Err(e) => {
                            tracing::error!("Recovery: failed to load block {}: {}. Stopping.", h, e);
                            break;
                        }
                    }
                }

                tracing::info!(
                    "Recovery complete: {} blocks replayed. State rebuilt to height {}.",
                    replayed, recovery_ns.height
                );
                recovery_ns
            } else {

            // Back up corrupted database before wiping
            let backup_dir = format!(
                "{}_backup_{}",
                db_path,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
            );
            tracing::warn!("Backing up corrupted database to {}", backup_dir);
            if let Err(backup_err) = std::fs::rename(&db_path, &backup_dir) {
                tracing::error!("Failed to backup corrupted database: {}", backup_err);
            }

            if let Err(clear_err) = store.clear_all() {
                tracing::error!(
                    "Self-healing failed to drop corrupted state DB: {}",
                    clear_err
                );
            }
            let mut ns = node::NodeState::new();
            // Apply genesis configuration on fresh start
            if let Some(ref genesis) = genesis_config
                && let Err(e) = genesis.apply(&mut ns)
            {
                tracing::error!("Failed to apply genesis: {}", e);
                std::process::exit(1);
            }
            ns
            } // close else (testnet path)
        }
    };

    let shared: node::SharedState = Arc::new(RwLock::new(node_state));

    // Create event broadcast channel for WebSocket subscriptions
    let (event_tx, _event_rx) = create_event_channel();

    // Spawn the strictly ordered Background Persistence Thread protecting Sled from OS Thread deadlocks natively
    let (persistence_tx, mut persistence_rx) =
        tokio::sync::mpsc::channel::<brrq_api::state::PersistenceTask>(1000);
    let store_persistence_clone = store.clone();

    // Background Persistence Loop
    tokio::task::spawn_blocking(move || {
        tracing::info!("Background MPSC Persistence Pipeline mounted securely.");
        while let Some(task) = persistence_rx.blocking_recv() {
            match task {
                brrq_api::state::PersistenceTask::PersistBlock {
                    diff,
                    height,
                    parent_hash,
                    block,
                    receipts,
                    state_root,
                    bridge_state_blob,
                    permit: _,
                } => {
                    // Bridge state is included in the same
                    // atomic WriteBatch to prevent unbacked brqBTC on crash.
                    if let Err(e) = store_persistence_clone.persist_block_atomic_with_portal(
                        &diff,
                        height,
                        &parent_hash,
                        Some(&block),
                        None,
                        &state_root,
                        None, // portal_escrow_blob
                        None, // portal_nullifiers_blob
                        bridge_state_blob.as_deref(),
                    ) {
                        tracing::error!(
                            "MPSC Failed to persist block #{} atomically: {}",
                            height,
                            e
                        );
                    } else {
                        persist_prune_old_blocks(&store_persistence_clone, height);
                    }

                    if let Err(e) = store_persistence_clone.save_receipts(&receipts) {
                        tracing::error!("MPSC Failed to persist block receipts: {e}");
                    }
                }
                brrq_api::state::PersistenceTask::Flush(sender) => {
                    // Test-only flush mechanism confirming buffer drains securely sync without fallback hacks natively.
                    tracing::info!("Test Harness Flush Signal received. Bridging disk barriers.");
                    let _ = sender.send(());
                }
            }
        }
        tracing::info!("Background MPSC Persistence Pipeline gracefully terminated.");
    });

    // Store event_tx, batch config, persistent store, and faucet config in shared state
    {
        let mut ns = shared.write().await;
        ns.persistence_tx = Some(persistence_tx);
        ns.event_tx = Some(event_tx.clone());
        ns.batch_proof_config.batch_size = cli.batch_size;
        ns.store = Some(store.clone());
        // Configure faucet from genesis
        if let Some(ref genesis) = genesis_config
            && let Some(ref faucet) = genesis.faucet
            && let Ok(addr) = genesis::parse_address_pub(&faucet.address)
        {
            ns.faucet_address = Some(addr);
            ns.faucet_drip_amount = faucet.drip_amount;
            ns.faucet_cooldown_secs = faucet.cooldown_secs;

            tracing::info!(
                "Faucet configured: address=0x{}, drip={}",
                hex::encode(addr.as_bytes()),
                faucet.drip_amount
            );
        }
        // CLI --mev-mode overrides genesis config
        if let Some(ref mode) = cli.mev_mode {
            ns.mev_mode = match mode.as_str() {
                "centralized_bypass" => brrq_api::MevActivationMode::CentralizedBypass,
                "decentralized" => brrq_api::MevActivationMode::Decentralized,
                _ => brrq_api::MevActivationMode::Disabled,
            };
            info!("MEV mode overridden by CLI: {:?}", ns.mev_mode);
        }
        info!("MEV protection: {:?}", ns.mev_mode);
    }

    info!("All subsystems initialized.");

    // Coordinated shutdown token — clones are passed to all spawned tasks
    let shutdown_token = CancellationToken::new();

    // Resolve sequencer address early (if sequencer mode) for P2P identity
    let key_path = cli
        .validator_key
        .clone()
        .unwrap_or_else(|| format!("{}/validator-keys.json", cli.datadir));
    let sequencer_address = if cli.sequencer {
        // Peek at the key file to derive the address without consuming the keys.
        // The block_production_loop will load them again independently.
        let key_file = std::path::Path::new(&key_path);
        if key_file.exists() {
            std::fs::read_to_string(key_file)
                .ok()
                .and_then(|json| serde_json::from_str::<serde_json::Value>(&json).ok())
                .and_then(|val| val.get("address")?.as_str().map(String::from))
                .and_then(|hex_str| genesis::parse_address_pub(&hex_str).ok())
        } else {
            None
        }
    } else {
        None
    };

    // Spawn P2P network service (if port configured)
    if cli.p2p_port > 0 {
        info!("Starting P2P network service on port {}...", cli.p2p_port);

        // Merge bootstrap nodes from genesis + CLI
        let mut bootstrap_nodes: Vec<String> = genesis_config
            .as_ref()
            .map(|g| g.bootstrap_nodes.clone())
            .unwrap_or_default();
        for node_addr in &cli.bootstrap {
            if !bootstrap_nodes.contains(node_addr) {
                bootstrap_nodes.push(node_addr.clone());
            }
        }
        if !bootstrap_nodes.is_empty() {
            info!("Bootstrap nodes: {:?}", bootstrap_nodes);
        }

        // Load or generate persistent P2P identity key.
        let (node_id, node_secret_key) = {
            let mut node_sk: Option<[u8; 32]> = None;
            match store.load_node_key() {
                Ok(Some(sk)) => {
                    node_sk = Some(sk);
                }
                Ok(None) => {
                    // Generate new identity key and persist.
                    let kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
                    let sb = kp.secret_bytes();
                    let mut sk = [0u8; 32];
                    sk.copy_from_slice(sb.as_ref());
                    if let Err(e) = store.save_node_key(&sk) {
                        tracing::warn!("Failed to persist node key: {}", e);
                    }
                    node_sk = Some(sk);
                }
                Err(e) => {
                    tracing::warn!("Failed to load node key: {}", e);
                }
            }

            let id = if let Some(ref sk) = node_sk {
                match brrq_crypto::schnorr::SchnorrKeyPair::from_secret_bytes(sk) {
                    Ok(kp) => hex::encode(kp.public_key().as_bytes()),
                    Err(_) => format!("brrq_{}", rand::random::<u32>()),
                }
            } else {
                format!("brrq_{}", rand::random::<u32>())
            };
            (id, node_sk)
        };

        info!(
            "P2P node identity: {}",
            &node_id[..std::cmp::min(16, node_id.len())]
        );

        // P2P-FIX: Set faucet keypair from VALIDATOR key (not node P2P key).
        // The validator key signs blocks and matches the sequencer address.
        // The faucet address in genesis must match the sequencer address.
        if let Some(kp) = load_faucet_keypair(&key_path) {
            let mut ns = shared.write().await;
            if let Some(faucet_addr) = ns.faucet_address {
                let derived_addr = brrq_types::Address::from_public_key(kp.public_key().as_bytes());
                if derived_addr == faucet_addr {
                    ns.faucet_keypair = Some(kp);
                    tracing::info!("Faucet keypair loaded from validator key (matches faucet address)");
                } else {
                    tracing::warn!(
                        "Faucet address mismatch: genesis=0x{} validator=0x{}",
                        hex::encode(faucet_addr.as_bytes()),
                        hex::encode(derived_addr.as_bytes()),
                    );
                }
            }
        }

        let net_config = network_service::NetworkConfig {
            p2p_port: cli.p2p_port,
            node_id,
            network: cli.network.clone(),
            bootstrap_nodes,
            sequencer_address,
            node_secret_key,
        };
        let net_service = network_service::NetworkService::new(net_config);
        let shared_clone = shared.clone();
        let shutdown_clone = shutdown_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = net_service.run(shared_clone) => {}
                _ = shutdown_clone.cancelled() => {
                    info!("P2P network service shutting down...");
                }
            }
        });
    }

    // Spawn block production (only in sequencer mode)
    if cli.sequencer {
        info!("Sequencer mode — starting block production loop...");
        let shared_clone = shared.clone();
        let store_clone = store.clone();
        let key_path_clone = key_path.clone();

        // Initialize DA Client — use NoopDaClient when no DA endpoint configured
        let da_client: Box<dyn brrq_types::DaSubmit> = if cli.l1_rpc_url.is_some() {
            let da_config = da::DaConfig::default();
            Box::new(da::HttpDaClient::new(da_config))
        } else {
            info!("No DA endpoint configured — using NoopDaClient (blocks commit without DA)");
            Box::new(da::NoopDaClient)
        };

        let shutdown_clone = shutdown_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = node::block_production_loop(
                    shared_clone,
                    Some(store_clone),
                    block_time,
                    &key_path_clone,
                    da_client,
                ) => {}
                _ = shutdown_clone.cancelled() => {
                    info!("Block production loop shutting down...");
                }
            }
        });
    }

    // Spawn SQLite indexer
    {
        let indexer_path = format!("{}/indexer.db", cli.datadir);
        match brrq_indexer::Database::open(&indexer_path) {
            Ok(db) => {
                info!("Indexer database opened at {}", indexer_path);
                let indexer = brrq_indexer::Indexer::new(db);
                let shared_clone = shared.clone();
                let event_tx_clone = event_tx.clone();
                let shutdown_clone = shutdown_token.clone();
                tokio::spawn(async move {
                    // Subscribe BEFORE indexing historical blocks to avoid
                    // a race condition where blocks produced between the end of the
                    // initial index scan and the subscribe() call would be lost.
                    // The broadcast channel buffers events, so we won't miss any
                    // blocks that arrive while we're catching up below.
                    let mut rx = event_tx_clone.subscribe();

                    // Index existing blocks on startup
                    let ns = shared_clone.read().await;
                    let receipt_map = build_receipt_map(&ns);
                    let indexed_count = ns.blocks.len();
                    // Record the latest height we indexed so we can detect
                    // gaps when processing events from the subscription.
                    let mut last_indexed_height: Option<u64> =
                        ns.blocks.back().map(|b| b.header.height);
                    for block in &ns.blocks {
                        if let Err(e) = indexer.index_block(block, &receipt_map) {
                            tracing::error!("Failed to index block: {}", e);
                        }
                    }
                    drop(ns);
                    if indexed_count > 0 {
                        tracing::info!("Indexed {} existing blocks", indexed_count);
                    }

                    // Process new block events from the subscription
                    loop {
                        let event = tokio::select! {
                            result = rx.recv() => result,
                            _ = shutdown_clone.cancelled() => {
                                info!("Indexer shutting down...");
                                break;
                            }
                        };
                        match event {
                            Ok(brrq_api::NodeEvent::NewBlock { height, .. }) => {
                                // If there is a gap between what we last
                                // indexed and this event, re-index the missing range
                                // to guarantee no blocks are skipped.
                                let expected = last_indexed_height.map(|h| h + 1).unwrap_or(0);
                                if height > expected {
                                    tracing::warn!(
                                        "Indexer detected gap: expected height {}, got {}. \
                                         Re-indexing blocks {}..{}",
                                        expected,
                                        height,
                                        expected,
                                        height - 1
                                    );
                                    let ns = shared_clone.read().await;
                                    let receipt_map = build_receipt_map(&ns);
                                    for gap_h in expected..height {
                                        let Some(block) = ns.get_block(gap_h) else { continue };
                                        if let Err(e) = indexer.index_block(&block, &receipt_map) {
                                            tracing::error!("Failed to re-index block {}: {}", gap_h, e);
                                        }
                                    }
                                    drop(ns);
                                }

                                let ns = shared_clone.read().await;
                                let receipt_map = build_receipt_map(&ns);
                                if let Some(block) = ns.get_block(height)
                                    && let Err(e) = indexer.index_block(&block, &receipt_map)
                                {
                                    tracing::error!("Failed to index block: {}", e);
                                }
                                drop(ns);
                                last_indexed_height = Some(height);
                            }
                            Ok(_) => {} // Ignore non-block events
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                // When the receiver lags, the broadcast
                                // channel drops the oldest messages. Re-index all
                                // blocks from the last known height to catch up.
                                tracing::warn!(
                                    "Indexer lagged by {} events, re-indexing from height {:?}",
                                    n,
                                    last_indexed_height
                                );
                                let ns = shared_clone.read().await;
                                let receipt_map = build_receipt_map(&ns);
                                let start = last_indexed_height.map(|h| h + 1).unwrap_or(0);
                                let end = ns.blocks.back().map(|b| b.header.height).unwrap_or(0);
                                for h in start..=end {
                                    let Some(block) = ns.get_block(h) else { continue };
                                    if let Err(e) = indexer.index_block(&block, &receipt_map) {
                                        tracing::error!("Failed to re-index block {}: {}", h, e);
                                    } else {
                                        last_indexed_height = Some(h);
                                    }
                                }
                                drop(ns);
                                tracing::info!(
                                    "Lag recovery complete, last indexed height: {:?}",
                                    last_indexed_height
                                );
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                tracing::info!("Event channel closed, indexer stopping");
                                break;
                            }
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!("Failed to open indexer database: {}, indexing disabled", e);
            }
        }
    }

    // Spawn Bitcoin L1 sync loop (if configured)
    if let Some(ref l1_rpc_url) = cli.l1_rpc_url {
        info!("Starting Bitcoin L1 sync loop...");

        // Warn if credentials are incomplete
        if cli.l1_rpc_user.is_none() || cli.l1_rpc_pass.is_none() {
            tracing::warn!(
                "Bitcoin RPC credentials incomplete — connection may fail. \
                 Set BRQ_L1_RPC_USER and BRQ_L1_RPC_PASS environment variables."
            );
        }

        // SEC: Warn if password was provided via CLI (visible in /proc/*/cmdline)
        if std::env::args().any(|a| a.starts_with("--l1-rpc-pass")) {
            tracing::warn!(
                "SECURITY: --l1-rpc-pass is deprecated. Bitcoin RPC password is visible in \
                 process arguments. Use BRQ_L1_RPC_PASS environment variable instead."
            );
        }

        let l1_network = genesis_config
            .as_ref()
            .and_then(|g| g.chain.l1_network.clone())
            .unwrap_or_else(|| {
                tracing::warn!("No l1_network in genesis config, defaulting to 'regtest'");
                "regtest".to_string()
            });
        let checkpoint_interval = genesis_config
            .as_ref()
            .map(|g| g.chain.l1_checkpoint_interval)
            .unwrap_or(100);

        // Credentials are resolved by clap from CLI args or env vars
        // (BRQ_L1_RPC_USER, BRQ_L1_RPC_PASS). Prefer env vars to avoid
        // exposing secrets in process argument lists.
        let rpc_user = cli.l1_rpc_user.clone().unwrap_or_default();
        let rpc_pass = cli.l1_rpc_pass.clone().unwrap_or_default();

        let sync_config = bitcoin_sync::BitcoinSyncConfig {
            rpc_url: l1_rpc_url.clone(),
            rpc_user,
            rpc_pass,
            network: l1_network,
            bridge_address: cli.bridge_address.clone().or_else(|| {
                genesis_config
                    .as_ref()
                    .and_then(|g| g.chain.bridge_address.clone())
            }),
            checkpoint_interval,
            funding_address: None,
        };
        let shared_clone = shared.clone();
        let store_clone = store.clone();
        let shutdown_clone = shutdown_token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = bitcoin_sync::bitcoin_sync_loop(shared_clone, Some(store_clone), sync_config) => {}
                _ = shutdown_clone.cancelled() => {
                    info!("Bitcoin L1 sync loop shutting down...");
                }
            }
        });
    }

    // Build Axum AppState and start API server
    let app_state = AppState::new(shared.clone(), event_tx.clone());
    // Wire lock-free metrics counters into NodeState so produce_block/apply_block
    // and the network service can increment them alongside the u64 fields.
    {
        let mut ns = shared.write().await;
        ns.metrics = Some(app_state.metrics.clone());
    }
    info!(
        "Starting API server on port {} (JSON-RPC + REST + WebSocket)...",
        cli.rpc_port
    );

    // ── Apply OS-level sandbox ────────────────────────────────────────
    // All file I/O (genesis, keys, DB) and network listeners are initialized.
    // From this point forward, restrict the process:
    // - Filesystem: only datadir (RW) + system paths (RO)
    // - Syscalls: deny execve, fork, ptrace, mount, privilege escalation
    crate::platform::apply_sandbox(&crate::platform::SandboxConfig {
        datadir: cli.datadir.clone(),
        genesis_path: cli.genesis.clone(),
        is_sequencer: cli.sequencer,
        validator_key_path: key_path.clone(),
    });

    // Run API server alongside shutdown signal for graceful termination
    let api_future = brrq_api::start_server(cli.rpc_port, app_state);
    let shutdown_future = tokio::signal::ctrl_c();

    tokio::select! {
        result = api_future => {
            if let Err(e) = result {
                tracing::error!("API server failed: {}", e);
            }
        }
        _ = shutdown_future => {
            info!("Shutdown signal received — initiating graceful shutdown...");

            // Flush the MPSC persistence pipeline before saving final state.
            // Without this, in-flight PersistBlock tasks could be lost on shutdown,
            // causing data loss (receipts, block diffs) for recently produced blocks.
            {
                let ns = shared.read().await;
                let flush_tx_opt = ns.persistence_tx.clone();
                drop(ns);
                if let Some(tx) = flush_tx_opt {
                    flush_persistence_pipeline(&tx).await;
                }
            }

            // 1. Save world state (accounts, code, storage)
            {
                let mut ns = shared.write().await;
                if let Some(s) = ns.store.clone() {
                    let height = ns.height;
                    let parent_hash = ns.parent_hash;
                    let root = ns.state.state_root();
                    let diff = ns.state.extract_diff();
                    if let Err(e) = s.persist_block_atomic(&diff, height, &parent_hash, None, None, &root) {
                        tracing::error!("FATAL: Failed to flush state atomically on shutdown: {}", e);
                    } else {
                        info!(
                            "State flushed: height={}, accounts={}",
                            ns.height,
                            ns.state.account_count(),
                        );
                    }
                }
            }

            // 2. Signal all spawned tasks to stop via the cancellation token
            shutdown_token.cancel();

            // 3. Allow a brief grace period for spawned tasks to complete
            // current operations before the runtime drops them.
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

            info!("Brrq node shut down gracefully.");
        }
    }
}
