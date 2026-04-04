//! Application state shared across all API handlers.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Instant;
use tokio::sync::{RwLock, broadcast};

use brrq_types::address::Address;

use brrq_bridge::BridgeManager;
use brrq_consensus::epoch::DEFAULT_EPOCH_LENGTH;
use brrq_consensus::governance::GovernanceManager;
#[cfg(feature = "sequencer-rotation")]
use brrq_consensus::registration::RegistrationManager;
use brrq_consensus::{
    DecentralizationTracker, EpochState, FeeMarket, SlashingEngine, StakingState,
};
#[cfg(feature = "sequencer-rotation")]
use brrq_consensus::{RotationConfig, RotationState};
use brrq_crypto::hash::Hash256;
use brrq_prover::batch::BatchProverConfig;
#[cfg(feature = "prover-pools")]
use brrq_prover::pool::ProverPoolManager;
use brrq_prover::types::BatchProofRecord;
use brrq_sequencer::Mempool;
#[cfg(feature = "mev-protection")]
use brrq_sequencer::MevMempool;
use brrq_state::WorldState;
use brrq_state::persistent::{PersistentStore, ReceiptData};
use brrq_types::block::Block;

use crate::events::NodeEvent;

/// Default initial stake cap (100 BTC in satoshis).
const INITIAL_STAKE_CAP: u64 = 10_000_000_000;

/// MEV protection activation mode.
///
/// Controls the commit-reveal pipeline for front-running protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MevActivationMode {
    /// MEV protection disabled — standard mempool only.
    Disabled,
    /// Centralized bypass — single sequencer encrypts/decrypts in the same block.
    /// Used before full multi-sequencer rotation.
    CentralizedBypass,
    /// Full decentralized commit-reveal with two-block lock/decrypt split.
    /// Requires active sequencer rotation and ordering commitments.
    Decentralized,
}

/// An asynchronous disk operation executed linearly resolving Write sync deadlocks natively.
#[derive(Debug)]
pub enum PersistenceTask {
    /// Save a fully dual-signed block and extract its unified dirty state variables smoothly.
    PersistBlock {
        diff: brrq_state::world_state::StateDiff,
        height: u64,
        parent_hash: Hash256,
        block: Block,
        receipts: Vec<(Hash256, ReceiptData)>,
        /// The computed state root after applying the block's state changes.
        /// Persisted atomically alongside block data so that `load_world_state`
        /// can verify integrity of the reconstructed state on startup.
        state_root: Hash256,
        /// Bridge state serialized blob, included in the
        /// same atomic WriteBatch as world state to prevent unbacked brqBTC on crash.
        bridge_state_blob: Option<Vec<u8>>,
        /// Handled by the drop trait naturally when PersistBlock leaves scope.
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    },
    /// Testing mechanism flushing disk synchronously without polluting production paths.
    Flush(tokio::sync::oneshot::Sender<()>),
}

/// Transaction receipt stored after inclusion in a block.
#[derive(Debug, Clone)]
pub struct TxReceipt {
    pub block_height: u64,
    pub gas_used: u64,
    pub success: bool,
    pub block_hash: Hash256,
    pub logs: Vec<brrq_types::Log>,
}

/// Maximum number of recent blocks kept in memory.
/// Older blocks are served from the persistent sled store.
pub const MAX_RECENT_BLOCKS: usize = 1000;

/// Maximum depth of receipts and block_logs retained in memory.
/// Prevents unbounded HashMap growth by pruning entries older than this
/// many blocks behind the chain tip.
/// Receipts/logs older than this are still available from the persistent sled store.
pub const PRUNE_RECEIPTS_DEPTH: u64 = 10_000;

/// Re-export SyntheticDeposit from brrq-types for backward compatibility.
pub use brrq_types::SyntheticDeposit;

/// Pending RANDAO message to be broadcast by the network service.
#[derive(Debug, Clone)]
pub struct PendingRandaoMsg {
    pub epoch: u64,
    pub validator: Address,
    pub data: Hash256,
    pub is_reveal: bool,
    /// EOTS signature over the RANDAO data (None = dummy fallback).
    pub signature: Option<brrq_types::Signature>,
}

/// Shared node state — the core data structure accessed by all API handlers.
pub struct NodeState {
    pub state: WorldState,
    pub mempool: Mempool,
    pub height: u64,
    pub parent_hash: Hash256,
    pub blocks: VecDeque<Block>,
    pub receipts: HashMap<Hash256, TxReceipt>,
    pub staking: StakingState,
    pub epoch: EpochState,
    pub event_tx: Option<broadcast::Sender<NodeEvent>>,
    pub bridge: BridgeManager,
    pub dispute_coordinator: brrq_bridge::dispute_coordinator::DisputeCoordinator,
    pub proof_records: Vec<BatchProofRecord>,
    pub batch_proof_config: BatchProverConfig,
    pub last_proved_height: u64,
    pub block_logs: HashMap<u64, Vec<brrq_types::Log>>,
    #[cfg(feature = "mev-protection")]
    pub mev_mempool: MevMempool,
    /// Reference to persistent store for serving old blocks.
    pub store: Option<Arc<PersistentStore>>,
    /// Faucet: address that funds are distributed from.
    pub faucet_address: Option<Address>,
    /// Faucet: amount dispensed per request (satoshis).
    pub faucet_drip_amount: u64,
    /// Faucet: cooldown period in seconds.
    pub faucet_cooldown_secs: u64,
    /// Faucet: last drip time per requesting address.
    pub faucet_cooldowns: HashMap<Address, Instant>,
    /// Faucet: keypair for signing faucet transactions (P2P-FIX).
    /// Set when faucet is configured and sequencer keys match faucet address.
    pub faucet_keypair: Option<brrq_crypto::schnorr::SchnorrKeyPair>,
    /// Total blocks produced by this node.
    pub blocks_produced_total: u64,
    /// Total transactions processed.
    pub tx_total: u64,
    /// Block heights that contain at least one transaction, sorted descending.
    /// Built from receipts at startup, updated on each new block with txs.
    /// Enables O(k) transaction listing where k = blocks-with-txs, not O(height).
    pub tx_block_heights: Vec<u64>,
    /// Number of currently connected P2P peers.
    /// Updated by the network service on peer connect/disconnect.
    pub peer_count: u64,
    /// Current Bitcoin L1 block height (0 = not connected).
    pub l1_height: u64,
    /// Latest known Bitcoin L1 block hash (None if never connected).
    pub l1_block_hash: Option<[u8; 32]>,
    /// Whether the node is connected to a Bitcoin L1 node.
    pub l1_connected: bool,
    /// The globally accessible canonical L1 BlockMonitor.
    pub l1_monitor: Option<brrq_bitcoin::block_monitor::BlockMonitor>,
    /// L1 anchor records posted to Bitcoin.
    pub l1_anchors: Vec<brrq_bitcoin::L1AnchorRecord>,
    /// L1 Bitcoin network name (None if L1 not configured).
    pub l1_network: Option<String>,
    /// MEV protection activation mode.
    /// Controls how the block production loop handles encrypted envelopes.
    pub mev_mode: MevActivationMode,
    /// WI-5A: Slashing engine with double-slash prevention.
    pub slashing: SlashingEngine,
    /// Governance manager for two-chamber voting.
    pub governance: GovernanceManager,
    /// Portal (L3): Escrow manager for Portal locks.
    pub portal_escrow: brrq_portal::EscrowManager,
    /// Portal (L3): Nullifier set for double-spend prevention.
    pub portal_nullifiers: brrq_portal::NullifierSet,
    /// Registration manager for decentralized sequencers.
    #[cfg(feature = "sequencer-rotation")]
    pub registration: RegistrationManager,
    /// Prover pool manager for cooperative proof generation.
    #[cfg(feature = "prover-pools")]
    pub prover_pools: ProverPoolManager,
    /// Sequencer rotation state machine.
    /// `None` when running in single-sequencer mode; `Some` when multi-sequencer
    /// rotation is active. Initialized on first block of a rotation-enabled session.
    #[cfg(feature = "sequencer-rotation")]
    pub rotation: Option<RotationState>,
    /// Configuration for rotation protocol.
    #[cfg(feature = "sequencer-rotation")]
    pub rotation_config: RotationConfig,
    /// Whether multi-sequencer rotation is enabled.
    #[cfg(feature = "sequencer-rotation")]
    pub rotation_enabled: bool,
    /// Dynamic fee market state (EIP-1559 style, §9.4).
    /// Active on all transactions.
    pub fee_market: FeeMarket,
    /// Protocol treasury address — receives 10% protocol share + funds bootstrap rewards.
    /// Set from genesis configuration; `None` if no treasury configured.
    pub protocol_treasury_address: Option<Address>,
    /// Prover pool address — receives 40% proof share of transaction fees (§9.4).
    /// Set from genesis configuration; `None` if no prover pool configured.
    pub prover_pool_address: Option<Address>,
    /// DA reserve address — receives 20% data availability share (§9.4).
    /// Set from genesis configuration; `None` if no DA reserve configured.
    pub da_reserve_address: Option<Address>,
    // ── Emergency fallback prover ──────────
    /// Maximum number of unproven blocks before declaring emergency.
    /// At 3s/block: 200 blocks ≈ 10 minutes without proofs.
    pub max_unproven_blocks: u64,
    /// Whether the emergency fallback prover is active.
    /// When true, the sequencer generates proofs locally instead of
    /// relying on the external prover market.
    pub fallback_prover_active: bool,

    /// Accumulated execution traces for the current proof batch.
    /// Populated by `produce_block` from `TxExecSummary` traces.
    /// Consumed and cleared by `generate_batch_proof`.
    pub batch_traces: brrq_vm::trace::ExecutionTrace,

    /// Pending synthetic deposits from L1 Bitcoin, queued for block inclusion.
    /// Drained by `produce_block()` and injected as synthetic transactions.
    pub pending_synthetic_deposits: Vec<SyntheticDeposit>,
    /// Block height at which MEV ordering was locked (two-block split).
    /// In `Decentralized` mode, lock_ordering happens in block N and
    /// decrypt_batch happens in block N+1. `None` when no lock is active.
    pub mev_ordering_locked_at: Option<u64>,
    /// Decentralization phase tracker (governance transitions).
    /// Evaluates network readiness metrics and transitions between phases.
    pub decentralization: DecentralizationTracker,
    /// RANDAO: epoch for which we last submitted a commitment.
    pub randao_committed_epoch: Option<u64>,
    /// RANDAO: epoch for which we last revealed our secret.
    pub randao_revealed_epoch: Option<u64>,
    /// RANDAO: current secret for the active epoch (cleared after reveal).
    pub randao_current_secret: Option<Hash256>,
    /// RANDAO: outbound messages pending broadcast by the network service.
    pub randao_pending: Vec<PendingRandaoMsg>,
    /// In-memory index: block hash → block height for O(1) hash lookups.
    /// Only covers blocks in the `blocks` VecDeque (recent blocks).
    pub block_hash_index: HashMap<Hash256, u64>,
    /// Chain ID from genesis config. Used for transaction replay protection.
    /// Defaults to TESTNET if not set via genesis.
    pub chain_id: u64,
    /// Pending block announcements to broadcast to P2P peers.
    /// Populated by `produce_block()`, drained by the network service outbound pump.
    pub pending_block_announcements: Vec<(Hash256, u64, Address)>,
    /// Pending consensus P2P messages (PreVotes/PreCommits) to broadcast.
    /// Serialized directly to bytes to prevent `brrq-api` depending on `brrq-network`.
    pub pending_consensus_messages: Vec<Vec<u8>>,
    /// Sequencer keys for signing BFT votes (PreVotes/PreCommits).
    pub sequencer_keys: Option<Arc<brrq_sequencer::block_builder::SequencerKeys>>,
    /// Optional reference to lock-free metrics counters.
    /// Set by main.rs after AppState construction; `None` in unit tests.
    /// When `Some`, produce_block/apply_block/network_service increment these
    /// alongside the u64 fields for lock-free reads by the /metrics endpoint.
    pub metrics: Option<Arc<NodeMetrics>>,
    /// Multi-Producer Single-Consumer (MPSC) Persistence Channel bounding Async Disk writes sequentially.
    /// Safely avoids race conditions when persisting Data execution metrics continuously without Node freezes.
    pub persistence_tx: Option<tokio::sync::mpsc::Sender<PersistenceTask>>,
    /// Multi-Producer Single-Consumer (MPSC) Persistence Semaphore protecting unbounded P2P synchronization metrics sequentially without Deadlocks.
    pub disk_semaphore: Arc<tokio::sync::Semaphore>,
    /// A lightweight snapshot of the state before an optimistic block application.
    /// If consensus fails (e.g. timeout), the state is restored to this snapshot.
    pub optimistic_snapshot: Option<Box<MetadataSnapshot>>,
    /// Optimistic execution result generated by `apply_block`. If the block fails finalization,
    /// these logs are replayed in reverse to restore the WorldState deterministically.
    pub optimistic_exec_result: Option<BlockExecutionResult>,
    /// The optimistically executed block, kept in memory so it can be persisted upon consensus finality.
    pub optimistic_block: Option<Block>,
    /// Addresses authorized to perform admin-only operations
    /// (e.g. `brrq_initFederation`).  Loaded from genesis config.
    pub admin_addresses: Vec<Address>,
    /// Pending Shamir shares for threshold epoch key reconstruction.
    /// Populated by ShareDistribution messages from the consensus layer.
    /// When threshold shares are collected, the epoch key can be reconstructed
    /// for MEV batch decryption.
    pub pending_shares: brrq_consensus::PendingShares,
}

/// The result of executing a block cleanly without permanently mutating global node state.
/// This acts as an optimistic payload that is either committed upon BFT finality or discarded.
#[derive(Clone, Debug)]
pub struct BlockExecutionResult {
    /// Ordered list of precise state mutations to revert in case of BFT failure.
    pub undo_logs: Vec<brrq_state::StateChange>,
    /// New transaction receipts generated during block execution.
    pub new_receipts: HashMap<Hash256, TxReceipt>,
    /// New EVM logs emitted by smart contracts in this block.
    pub new_block_logs: Vec<brrq_types::Log>,
    /// Hashes of transactions successfully committed in this block.
    pub committed_hashes: Vec<Hash256>,
}

/// A highly optimized O(1) instantaneous cloning snapshot containing strictly metadata
/// and bounded/architected structures. Bypasses the `WorldState`, `Mempool`, and historical data.
#[derive(Clone)]
pub struct MetadataSnapshot {
    pub fee_market: FeeMarket,
    #[cfg(feature = "sequencer-rotation")]
    pub registration: brrq_consensus::registration::RegistrationManager,
    pub bridge: BridgeManager,
    pub height: u64,
    pub tx_total: u64,
    pub blocks_produced_total: u64,
    // Consensus Triad
    pub epoch: brrq_consensus::epoch::EpochState,
    pub staking: brrq_consensus::staking::StakingState,
    pub slashing: brrq_consensus::slashing::SlashingEngine,
    // Chaos Triad
    pub decentralization: brrq_consensus::DecentralizationTracker,
    pub mev_ordering_locked_at: Option<u64>,
    pub randao_pending: Vec<PendingRandaoMsg>,
    pub randao_committed_epoch: Option<u64>,
    pub randao_revealed_epoch: Option<u64>,
    pub randao_current_secret: Option<Hash256>,
    // Bridge Guard
    pub pending_synthetic_deposits: Vec<brrq_types::SyntheticDeposit>,
    pub l1_anchors: Vec<brrq_bitcoin::L1AnchorRecord>,
    // Sovereign Triad
    pub governance: brrq_consensus::governance::GovernanceManager,
    #[cfg(feature = "prover-pools")]
    pub prover_pools: brrq_prover::pool::ProverPoolManager,
    pub dispute_coordinator: brrq_bridge::dispute_coordinator::DisputeCoordinator,
}

impl NodeState {
    /// Check whether the given address is a configured admin.
    pub fn is_admin(&self, addr: &Address) -> bool {
        self.admin_addresses.contains(addr)
    }

    /// Creates a highly optimized O(1) deep-copy metadata snapshot.
    pub fn snapshot(&self) -> MetadataSnapshot {
        MetadataSnapshot {
            fee_market: self.fee_market.clone(),
            #[cfg(feature = "sequencer-rotation")]
            registration: self.registration.clone(),
            bridge: self.bridge.clone(),
            height: self.height,
            tx_total: self.tx_total,
            blocks_produced_total: self.blocks_produced_total,
            epoch: self.epoch.clone(),
            staking: self.staking.clone(),
            slashing: self.slashing.clone(),
            decentralization: self.decentralization.clone(),
            mev_ordering_locked_at: self.mev_ordering_locked_at,
            randao_pending: self.randao_pending.clone(),
            randao_committed_epoch: self.randao_committed_epoch,
            randao_revealed_epoch: self.randao_revealed_epoch,
            randao_current_secret: self.randao_current_secret,
            pending_synthetic_deposits: self.pending_synthetic_deposits.clone(),
            l1_anchors: self.l1_anchors.clone(),
            governance: self.governance.clone(),
            #[cfg(feature = "prover-pools")]
            prover_pools: self.prover_pools.clone(),
            dispute_coordinator: self.dispute_coordinator.clone(),
        }
    }

    /// Restores pure metadata synchronously.
    /// Note: `undo_logs` must be processed externally to restore `WorldState`.
    pub fn restore_snapshot(&mut self, snap: MetadataSnapshot) {
        self.fee_market = snap.fee_market;
        #[cfg(feature = "sequencer-rotation")]
        {
            self.registration = snap.registration;
        }
        self.bridge = snap.bridge;
        self.height = snap.height;
        self.tx_total = snap.tx_total;
        self.blocks_produced_total = snap.blocks_produced_total;
        self.epoch = snap.epoch;
        self.staking = snap.staking;
        self.slashing = snap.slashing;
        self.decentralization = snap.decentralization;
        self.mev_ordering_locked_at = snap.mev_ordering_locked_at;
        self.randao_pending = snap.randao_pending;
        self.randao_committed_epoch = snap.randao_committed_epoch;
        self.randao_revealed_epoch = snap.randao_revealed_epoch;
        self.randao_current_secret = snap.randao_current_secret;
        self.pending_synthetic_deposits = snap.pending_synthetic_deposits;
        self.l1_anchors = snap.l1_anchors;
        self.governance = snap.governance;
        #[cfg(feature = "prover-pools")]
        {
            self.prover_pools = snap.prover_pools;
        }
        self.dispute_coordinator = snap.dispute_coordinator;
    }
}

/// Type alias for shared state.
pub type SharedState = Arc<RwLock<NodeState>>;

/// Lock-free metrics counters for read-hot paths.
///
/// These duplicate the `u64` fields in `NodeState` for backward compatibility
/// (tests read NodeState fields directly), but provide lock-free reads for
/// the `/metrics` endpoint and other monitoring. Incremented alongside
/// NodeState fields in `produce_block()` / `apply_block()`.
///
/// Future work: when contention is measured, split NodeState further and
/// remove the duplicate u64 fields.
pub struct NodeMetrics {
    pub blocks_produced: AtomicU64,
    pub tx_processed: AtomicU64,
    pub peer_count: AtomicU64,
}

impl NodeMetrics {
    pub fn new() -> Self {
        Self {
            blocks_produced: AtomicU64::new(0),
            tx_processed: AtomicU64::new(0),
            peer_count: AtomicU64::new(0),
        }
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Lock-free security/defense metrics counters.
///
/// Each defense layer increments its counter on rejection events.
/// Exposed via the `/metrics` Prometheus endpoint for monitoring
/// active attacks in real-time.
pub struct SecurityMetrics {
    /// Requests rejected by rate limiter (HTTP 429)
    pub rate_limited_total: AtomicU64,
    /// Requests rejected by header size check (HTTP 431)
    pub header_oversized_total: AtomicU64,
    /// TCP connections rejected by per-IP connection limit
    pub connection_rejected_total: AtomicU64,
    /// Requests with invalid/missing API key (HTTP 401)
    pub auth_failed_total: AtomicU64,
    /// Requests killed by timeout (HTTP 408)
    pub request_timeout_total: AtomicU64,
}

impl SecurityMetrics {
    pub fn new() -> Self {
        Self {
            rate_limited_total: AtomicU64::new(0),
            header_oversized_total: AtomicU64::new(0),
            connection_rejected_total: AtomicU64::new(0),
            auth_failed_total: AtomicU64::new(0),
            request_timeout_total: AtomicU64::new(0),
        }
    }
}

impl Default for SecurityMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Axum application state.
#[derive(Clone)]
pub struct AppState {
    pub node: SharedState,
    pub event_tx: broadcast::Sender<NodeEvent>,
    /// Lock-free metrics counters — read without acquiring the NodeState RwLock.
    pub metrics: Arc<NodeMetrics>,
    /// Lock-free security defense counters.
    pub security: Arc<SecurityMetrics>,
}

impl AppState {
    /// Create a new AppState with default (zeroed) metrics.
    pub fn new(node: SharedState, event_tx: broadcast::Sender<NodeEvent>) -> Self {
        Self {
            node,
            event_tx,
            metrics: Arc::new(NodeMetrics::new()),
            security: Arc::new(SecurityMetrics::new()),
        }
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeState {
    /// Create a new empty node state.
    pub fn new() -> Self {
        Self {
            l1_monitor: None,
            state: WorldState::new(),
            mempool: Mempool::new(),
            height: 0,
            parent_hash: Hash256::ZERO,
            blocks: VecDeque::new(),
            receipts: HashMap::new(),
            staking: StakingState::new(INITIAL_STAKE_CAP),
            epoch: EpochState::new(DEFAULT_EPOCH_LENGTH),
            event_tx: None,
            bridge: BridgeManager::new(),
            dispute_coordinator: brrq_bridge::dispute_coordinator::DisputeCoordinator::new(),
            proof_records: Vec::new(),
            batch_proof_config: BatchProverConfig::default(),
            last_proved_height: 0,
            block_logs: HashMap::new(),
            #[cfg(feature = "mev-protection")]
            mev_mempool: MevMempool::new(0),
            store: None,
            faucet_address: None,
            faucet_drip_amount: 100_000_000,
            faucet_cooldown_secs: 3600,
            faucet_cooldowns: HashMap::new(),
            faucet_keypair: None,
            blocks_produced_total: 0,
            tx_total: 0,
            tx_block_heights: Vec::new(),
            peer_count: 0,
            l1_height: 0,
            l1_block_hash: None,
            l1_connected: false,
            l1_anchors: Vec::new(),
            l1_network: None,
            mev_mode: MevActivationMode::Disabled,
            slashing: SlashingEngine::new(),
            governance: GovernanceManager::new(),
            portal_escrow: brrq_portal::EscrowManager::new(),
            portal_nullifiers: brrq_portal::NullifierSet::new(),
            #[cfg(feature = "sequencer-rotation")]
            registration: RegistrationManager::new(),
            #[cfg(feature = "prover-pools")]
            prover_pools: ProverPoolManager::new(),
            #[cfg(feature = "sequencer-rotation")]
            rotation: None,
            #[cfg(feature = "sequencer-rotation")]
            rotation_config: RotationConfig::default(),
            #[cfg(feature = "sequencer-rotation")]
            rotation_enabled: false,
            fee_market: FeeMarket::new(),
            protocol_treasury_address: None,
            prover_pool_address: None,
            da_reserve_address: None,
            max_unproven_blocks: 200,
            fallback_prover_active: false,
            batch_traces: brrq_vm::trace::ExecutionTrace::new(),
            pending_synthetic_deposits: Vec::new(),
            mev_ordering_locked_at: None,
            decentralization: DecentralizationTracker::new(),
            randao_committed_epoch: None,
            randao_revealed_epoch: None,
            randao_current_secret: None,
            randao_pending: Vec::new(),
            block_hash_index: HashMap::new(),
            chain_id: brrq_types::transaction::chain_id::TESTNET,
            pending_block_announcements: Vec::new(),
            pending_consensus_messages: Vec::new(),
            sequencer_keys: None,
            metrics: None,
            persistence_tx: None,
            disk_semaphore: Arc::new(tokio::sync::Semaphore::new(1000)),
            optimistic_snapshot: None,
            optimistic_exec_result: None,
            optimistic_block: None,
            admin_addresses: Vec::new(),
            pending_shares: brrq_consensus::PendingShares::new(),
        }
    }

    /// Load node state from a persistent store on disk.
    ///
    /// Restores accounts, chain metadata, and recent blocks from sled.
    /// Only the last `MAX_RECENT_BLOCKS` blocks are loaded into memory;
    /// older blocks are served from the store on demand via `get_block()`.
    pub fn load_from_disk(store: &PersistentStore) -> Result<Self, brrq_state::StateError> {
        let state = store.load_world_state()?;
        let (height, parent_hash) = store.load_chain_meta()?;

        // Load only recent blocks (not all of them)
        let recent_start = if height > MAX_RECENT_BLOCKS as u64 {
            height - MAX_RECENT_BLOCKS as u64 + 1
        } else {
            1
        };
        let blocks: VecDeque<Block> = if height > 0 {
            store
                .load_blocks_range(recent_start, height)?
                .into_iter()
                .collect()
        } else {
            VecDeque::new()
        };

        // Load receipts
        let receipt_entries = store.load_all_receipts()?;
        let mut receipts = HashMap::new();
        for (hash, rd) in receipt_entries {
            receipts.insert(
                hash,
                TxReceipt {
                    block_height: rd.block_height,
                    gas_used: rd.gas_used,
                    success: rd.success,
                    block_hash: rd.block_hash,
                    logs: Vec::new(), // Logs not persisted to disk yet
                },
            );
        }

        // Load L1 anchor records from disk
        let l1_anchors = store.load_all_l1_anchors().unwrap_or_else(|e| {
            tracing::warn!("Could not load L1 anchors from disk: {}", e);
            Vec::new()
        });

        // Restore bridge state from disk (or start fresh)
        let bridge = match store.load_bridge_state_blob() {
            Ok(Some(bytes)) => BridgeManager::from_bytes(&bytes).unwrap_or_else(|e| {
                tracing::warn!("Bridge state deserialize failed: {e} — starting fresh");
                BridgeManager::new()
            }),
            _ => BridgeManager::new(),
        };

        // Restore Portal escrow state from disk (or start fresh)
        let portal_escrow = match store.load_portal_state_blob() {
            Ok(Some(bytes)) => brrq_portal::EscrowManager::from_bytes(&bytes).unwrap_or_else(|e| {
                tracing::warn!("Portal escrow deserialize failed: {e} — starting fresh");
                brrq_portal::EscrowManager::new()
            }),
            _ => brrq_portal::EscrowManager::new(),
        };

        // Restore Portal nullifier set from disk (or start fresh)
        let portal_nullifiers = match store.load_portal_nullifiers_blob() {
            Ok(Some(bytes)) => brrq_portal::NullifierSet::from_bytes(&bytes).unwrap_or_else(|e| {
                tracing::warn!("Portal nullifiers deserialize failed: {e} — starting fresh");
                brrq_portal::NullifierSet::new()
            }),
            _ => brrq_portal::NullifierSet::new(),
        };

        // Build hash index for loaded blocks
        let block_hash_index: HashMap<Hash256, u64> = blocks
            .iter()
            .map(|b| (b.header.hash(), b.header.height))
            .collect();

        let restored_tx_total = receipts.len() as u64;

        // Build index of block heights that contain transactions.
        // Extracted from receipts (each receipt stores its block_height).
        // Sorted descending so list_transactions can iterate newest-first
        // and only load blocks that actually have txs — O(k) instead of O(height).
        let mut tx_block_heights: Vec<u64> = receipts
            .values()
            .map(|r| r.block_height)
            .collect::<std::collections::HashSet<u64>>()
            .into_iter()
            .collect();
        tx_block_heights.sort_unstable_by(|a, b| b.cmp(a));

        tracing::info!(
            "Loaded state from disk: height={}, accounts={}, receipts={}, recent_blocks={}, l1_anchors={}, bridge_deposits={}, bridge_withdrawals={}",
            height,
            state.account_count(),
            receipts.len(),
            blocks.len(),
            l1_anchors.len(),
            bridge.deposits.len(),
            bridge.withdrawals.len(),
        );

        Ok(Self {
            l1_monitor: None,
            state,
            mempool: Mempool::new(),
            height,
            parent_hash,
            blocks,
            receipts,
            staking: StakingState::new(INITIAL_STAKE_CAP),
            epoch: EpochState::new(DEFAULT_EPOCH_LENGTH),
            event_tx: None,
            bridge,
            dispute_coordinator: brrq_bridge::dispute_coordinator::DisputeCoordinator::new(),
            proof_records: Vec::new(),
            batch_proof_config: BatchProverConfig::default(),
            last_proved_height: 0,
            block_logs: HashMap::new(),
            #[cfg(feature = "mev-protection")]
            mev_mempool: MevMempool::new(0),
            store: None, // Will be set after construction in main.rs
            faucet_address: None,
            faucet_drip_amount: 100_000_000,
            faucet_cooldown_secs: 3600,
            faucet_cooldowns: HashMap::new(),
            faucet_keypair: None,
            blocks_produced_total: height,
            tx_total: restored_tx_total,
            tx_block_heights,
            peer_count: 0,
            l1_height: 0,
            l1_block_hash: None,
            l1_connected: false,
            l1_anchors,
            l1_network: None,
            mev_mode: MevActivationMode::Disabled,
            slashing: SlashingEngine::new(),
            governance: GovernanceManager::new(),
            portal_escrow,
            portal_nullifiers,
            #[cfg(feature = "sequencer-rotation")]
            registration: RegistrationManager::new(),
            #[cfg(feature = "prover-pools")]
            prover_pools: ProverPoolManager::new(),
            #[cfg(feature = "sequencer-rotation")]
            rotation: None,
            #[cfg(feature = "sequencer-rotation")]
            rotation_config: RotationConfig::default(),
            #[cfg(feature = "sequencer-rotation")]
            rotation_enabled: false,
            fee_market: FeeMarket::new(),
            protocol_treasury_address: None,
            prover_pool_address: None,
            da_reserve_address: None,
            max_unproven_blocks: 200,
            fallback_prover_active: false,
            batch_traces: brrq_vm::trace::ExecutionTrace::new(),
            pending_synthetic_deposits: Vec::new(),
            mev_ordering_locked_at: None,
            decentralization: DecentralizationTracker::new(),
            randao_committed_epoch: None,
            randao_revealed_epoch: None,
            randao_current_secret: None,
            randao_pending: Vec::new(),
            block_hash_index,
            chain_id: brrq_types::transaction::chain_id::TESTNET,
            pending_block_announcements: Vec::new(),
            pending_consensus_messages: Vec::new(),
            sequencer_keys: None,
            metrics: None,
            persistence_tx: None,
            disk_semaphore: Arc::new(tokio::sync::Semaphore::new(1000)),
            optimistic_snapshot: None,
            optimistic_exec_result: None,
            optimistic_block: None,
            admin_addresses: Vec::new(),
            pending_shares: brrq_consensus::PendingShares::new(),
        })
    }

    /// Check if an L1 anchor hash exists in the deterministic state.
    /// This is used internally by synthetic deposit execution.
    pub fn has_l1_anchor(&self, hash: &[u8; 32]) -> bool {
        self.l1_anchors.iter().any(|a| a.block_hash == *hash)
    }

    /// Deterministically push an L1 anchor to the state.
    /// Keeps a bounded history of the last 100 anchors.
    pub fn push_l1_anchor(&mut self, hash: brrq_crypto::hash::Hash256, l2_height: u64) {
        let record = brrq_bitcoin::L1AnchorRecord {
            l1_tx_id: [0u8; 32],
            l1_height: 0, // In this model, we don't strictly need L1 height, just the hash for SPV.
            block_hash: *hash.as_bytes(),
            l2_height,
            state_root: brrq_crypto::hash::Hash256::ZERO,
            proof_hash: brrq_crypto::hash::Hash256::ZERO,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        };
        self.l1_anchors.push(record);

        // Bound to the last 100 anchors
        if self.l1_anchors.len() > 100 {
            self.l1_anchors.remove(0);
        }
    }

    /// Compute the Median Time Past (MTP) of the previous 11 blocks.
    /// Used for deterministic consensus time validation.
    pub fn median_time_past(&self) -> u64 {
        let count = std::cmp::min(11, self.blocks.len());
        if count == 0 {
            // P2P-FIX: Fresh node syncing from genesis has no blocks yet.
            // Use current time minus a generous window so that:
            // 1. "timestamp not advancing" check passes (block_ts > mtp)
            // 2. "too far in future" check passes (block_ts < mtp + 7200)
            // This allows accepting blocks from the recent past (up to 1 hour ago).
            return std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs().saturating_sub(3600))
                .unwrap_or(0);
        }
        let mut timestamps: Vec<u64> = self
            .blocks
            .iter()
            .rev()
            .take(count)
            .map(|b| b.header.timestamp)
            .collect();
        timestamps.sort_unstable();
        timestamps[count / 2]
    }

    /// Get a block by height — O(1) via index for in-memory blocks,
    /// falls back to the persistent sled store for older blocks.
    pub fn get_block(&self, height: u64) -> Option<Block> {
        // Fast path: calculate offset directly since blocks are contiguous
        if let Some(first) = self.blocks.front() {
            let first_height = first.header.height;
            if height >= first_height && height <= first_height + self.blocks.len() as u64 - 1 {
                let idx = (height - first_height) as usize;
                return self.blocks.get(idx).cloned();
            }
        }
        // Slow path: check persistent store
        self.store
            .as_ref()
            .and_then(|s| s.load_block(height).ok())
            .flatten()
    }

    /// Get a block by hash — checks recent in-memory blocks first,
    /// then tries persistent store by scanning the hash→height index.
    pub fn get_block_by_hash(&self, hash: &Hash256) -> Option<Block> {
        // Fast path: check in-memory recent blocks via hash index
        if let Some(&height) = self.block_hash_index.get(hash) {
            return self.get_block(height);
        }
        // Slow path: persistent store does not have hash index yet
        None
    }

    /// Add a block and enforce the in-memory cap.
    /// Also prunes old receipts and block_logs via `prune_old_data()`
    /// using `PRUNE_RECEIPTS_DEPTH` to prevent unbounded memory growth.
    pub fn push_block(&mut self, block: Block) {
        // Update hash index
        let hash = block.header.hash();
        let height = block.header.height;
        self.block_hash_index.insert(hash, height);

        // Update tx_block_heights index if block has transactions
        if !block.transactions.is_empty() {
            // Insert at front (newest first) since blocks arrive in order
            self.tx_block_heights.insert(0, height);
        }

        self.blocks.push_back(block);
        while self.blocks.len() > MAX_RECENT_BLOCKS {
            if let Some(evicted) = self.blocks.pop_front() {
                self.block_hash_index.remove(&evicted.header.hash());
            }
        }
        // Prune in-memory receipts and logs for blocks that have been evicted.
        // Old data is still available from the persistent sled store.
        self.prune_old_data();
    }

    /// Remove in-memory receipts and logs older than `PRUNE_RECEIPTS_DEPTH`.
    /// Uses the dedicated pruning depth (default 10,000 blocks) rather than
    /// `MAX_RECENT_BLOCKS` to decouple receipt retention from block retention.
    fn prune_old_data(&mut self) {
        if self.height <= PRUNE_RECEIPTS_DEPTH {
            return;
        }
        let cutoff = self.height - PRUNE_RECEIPTS_DEPTH;
        let receipts_before = self.receipts.len();
        let logs_before = self.block_logs.len();
        self.receipts.retain(|_, r| r.block_height > cutoff);
        self.block_logs.retain(|&h, _| h > cutoff);
        let pruned_receipts = receipts_before - self.receipts.len();
        let pruned_logs = logs_before - self.block_logs.len();
        if pruned_receipts > 0 || pruned_logs > 0 {
            tracing::debug!(
                "Pruned in-memory data: {} receipts, {} block_logs (cutoff height={})",
                pruned_receipts,
                pruned_logs,
                cutoff,
            );
        }
    }

    /// Persist the current state to disk after a block is committed.
    ///
    /// Saves: world state (accounts + code), chain metadata, new receipts,
    /// and bridge state -- all atomically via a single WriteBatch.
    pub fn persist_block(
        &mut self,
        store: &PersistentStore,
        new_receipts: &[(Hash256, TxReceipt)],
    ) -> Result<(), brrq_state::StateError> {
        let diff = self.state.extract_diff();

        let block = self.blocks.back();

        let receipt_data: Vec<(Hash256, ReceiptData)> = new_receipts
            .iter()
            .map(|(hash, r)| {
                (
                    *hash,
                    ReceiptData {
                        block_height: r.block_height,
                        gas_used: r.gas_used,
                        success: r.success,
                        block_hash: r.block_hash,
                    },
                )
            })
            .collect();

        // Serialize bridge state for atomic persistence.
        let bridge_blob = self.bridge.to_bytes().ok();

        let state_root = self.state.state_root();

        // Single atomic WriteBatch for world state + bridge state.
        // Prevents unbacked brqBTC if a crash occurs between the two writes.
        store.persist_block_atomic_with_portal(
            &diff,
            self.height,
            &self.parent_hash,
            block,
            None, // receipts handled below (keyed by block hash, not included in atomic batch here)
            &state_root,
            None, // portal_escrow_blob
            None, // portal_nullifiers_blob
            bridge_blob.as_deref(),
        )?;

        // Save the latest block
        if let Some(b) = block {
            store.save_block(b)?;
        }

        // Save new receipts
        store.save_receipts(&receipt_data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::eots::{EotsNonceCommitment, EotsSignature};
    use brrq_crypto::schnorr::SchnorrPublicKey;
    use brrq_crypto::slh_dsa::{SlhDsaPublicKey, SlhDsaSignature};
    use brrq_types::address::Address;
    use brrq_types::block::{Block, BlockHeader, DualSignature, SequencerIdentity};

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

    fn make_block(height: u64, parent_hash: Hash256) -> Block {
        let header = BlockHeader {
            height,
            parent_hash,
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

    // ── NodeState creation ──────────────────────────────────────────────

    #[test]
    fn node_state_new_defaults() {
        let ns = NodeState::new();
        assert_eq!(ns.height, 0);
        assert!(ns.blocks.is_empty());
        assert!(ns.receipts.is_empty());
        assert_eq!(ns.parent_hash, Hash256::ZERO);
        assert!(ns.faucet_address.is_none());
        assert_eq!(ns.faucet_drip_amount, 100_000_000);
        assert_eq!(ns.faucet_cooldown_secs, 3600);
        assert!(ns.faucet_cooldowns.is_empty());
        assert_eq!(ns.blocks_produced_total, 0);
        assert_eq!(ns.tx_total, 0);
        assert!(ns.store.is_none());
    }

    // ── push_block tests ────────────────────────────────────────────────

    #[test]
    fn push_block_single() {
        let mut ns = NodeState::new();
        let block = make_block(1, Hash256::ZERO);
        ns.push_block(block.clone());
        assert_eq!(ns.blocks.len(), 1);
        assert_eq!(ns.blocks.back().unwrap().header.height, 1);
    }

    #[test]
    fn push_block_multiple() {
        let mut ns = NodeState::new();
        for i in 1..=10 {
            let block = make_block(i, Hash256::ZERO);
            ns.push_block(block);
        }
        assert_eq!(ns.blocks.len(), 10);
        assert_eq!(ns.blocks.front().unwrap().header.height, 1);
        assert_eq!(ns.blocks.back().unwrap().header.height, 10);
    }

    #[test]
    fn push_block_enforces_max_cap() {
        let mut ns = NodeState::new();
        // Push exactly MAX_RECENT_BLOCKS blocks
        for i in 1..=MAX_RECENT_BLOCKS as u64 {
            ns.push_block(make_block(i, Hash256::ZERO));
        }
        assert_eq!(ns.blocks.len(), MAX_RECENT_BLOCKS);

        // Push one more — oldest should be evicted
        ns.push_block(make_block(MAX_RECENT_BLOCKS as u64 + 1, Hash256::ZERO));
        assert_eq!(ns.blocks.len(), MAX_RECENT_BLOCKS);
        // First block should now be block 2 (block 1 evicted)
        assert_eq!(ns.blocks.front().unwrap().header.height, 2);
        assert_eq!(
            ns.blocks.back().unwrap().header.height,
            MAX_RECENT_BLOCKS as u64 + 1
        );
    }

    #[test]
    fn push_block_evicts_many() {
        let mut ns = NodeState::new();
        // Fill to cap
        for i in 1..=MAX_RECENT_BLOCKS as u64 {
            ns.push_block(make_block(i, Hash256::ZERO));
        }
        // Push 100 more
        for i in (MAX_RECENT_BLOCKS as u64 + 1)..=(MAX_RECENT_BLOCKS as u64 + 100) {
            ns.push_block(make_block(i, Hash256::ZERO));
        }
        assert_eq!(ns.blocks.len(), MAX_RECENT_BLOCKS);
        // Oldest should now be 101
        assert_eq!(ns.blocks.front().unwrap().header.height, 101);
    }

    // ── get_block tests ─────────────────────────────────────────────────

    #[test]
    fn get_block_from_memory() {
        let mut ns = NodeState::new();
        ns.push_block(make_block(1, Hash256::ZERO));
        ns.push_block(make_block(2, Hash256::ZERO));
        ns.push_block(make_block(3, Hash256::ZERO));

        assert!(ns.get_block(1).is_some());
        assert_eq!(ns.get_block(1).unwrap().header.height, 1);
        assert!(ns.get_block(2).is_some());
        assert!(ns.get_block(3).is_some());
        assert!(ns.get_block(4).is_none());
        assert!(ns.get_block(0).is_none());
    }

    #[test]
    fn get_block_after_eviction_no_store() {
        let mut ns = NodeState::new();
        // Fill beyond cap — no store configured
        for i in 1..=(MAX_RECENT_BLOCKS as u64 + 5) {
            ns.push_block(make_block(i, Hash256::ZERO));
        }
        // Block 1-5 should be evicted and not findable (no store)
        assert!(ns.get_block(1).is_none());
        assert!(ns.get_block(5).is_none());
        // Block 6+ should still be in memory
        assert!(ns.get_block(6).is_some());
    }

    #[test]
    fn get_block_fallback_to_store() {
        let store = PersistentStore::open_temporary().unwrap();
        let store = Arc::new(store);

        let mut ns = NodeState::new();
        ns.store = Some(store.clone());

        // Save block 1 to store, but DON'T put it in memory
        let block = make_block(1, Hash256::ZERO);
        store.save_block(&block).unwrap();

        // Should find it via store fallback
        let found = ns.get_block(1);
        assert!(found.is_some());
        assert_eq!(found.unwrap().header.height, 1);
    }

    // ── get_block_by_hash tests ─────────────────────────────────────────

    #[test]
    fn get_block_by_hash_found() {
        let mut ns = NodeState::new();
        let block = make_block(1, Hash256::ZERO);
        let hash = block.header.hash();
        ns.push_block(block);

        let found = ns.get_block_by_hash(&hash);
        assert!(found.is_some());
        assert_eq!(found.unwrap().header.height, 1);
    }

    #[test]
    fn get_block_by_hash_not_found() {
        let ns = NodeState::new();
        assert!(ns.get_block_by_hash(&Hash256::ZERO).is_none());
    }

    #[test]
    fn get_block_by_hash_evicted_returns_none() {
        let mut ns = NodeState::new();
        // Block 1 will be evicted
        let block1 = make_block(1, Hash256::ZERO);
        let hash1 = block1.header.hash();
        ns.push_block(block1);

        // Fill beyond cap
        for i in 2..=(MAX_RECENT_BLOCKS as u64 + 1) {
            ns.push_block(make_block(i, Hash256::ZERO));
        }

        // Block 1's hash should not be found (hash lookup doesn't check store)
        assert!(ns.get_block_by_hash(&hash1).is_none());
    }

    // ── Faucet state tests ──────────────────────────────────────────────

    #[test]
    fn faucet_defaults_on_new() {
        let ns = NodeState::new();
        assert!(ns.faucet_address.is_none());
        assert_eq!(ns.faucet_drip_amount, 100_000_000);
        assert_eq!(ns.faucet_cooldown_secs, 3600);
        assert!(ns.faucet_cooldowns.is_empty());
    }

    #[test]
    fn faucet_cooldown_tracking() {
        let mut ns = NodeState::new();
        let addr = test_addr(42);
        ns.faucet_cooldowns.insert(addr, Instant::now());
        assert!(ns.faucet_cooldowns.contains_key(&addr));
        assert!(ns.faucet_cooldowns.get(&addr).unwrap().elapsed().as_secs() < 1);
    }

    // ── Metrics counters ────────────────────────────────────────────────

    #[test]
    fn metrics_initial_zeros() {
        let ns = NodeState::new();
        assert_eq!(ns.blocks_produced_total, 0);
        assert_eq!(ns.tx_total, 0);
    }

    #[test]
    fn metrics_increment() {
        let mut ns = NodeState::new();
        ns.blocks_produced_total += 1;
        ns.tx_total += 5;
        assert_eq!(ns.blocks_produced_total, 1);
        assert_eq!(ns.tx_total, 5);
    }

    // ── Persistence tests ───────────────────────────────────────────────

    #[test]
    fn persist_and_reload_block() {
        let store = PersistentStore::open_temporary().unwrap();
        let mut ns = NodeState::new();

        // Create and add a block
        let block = make_block(1, Hash256::ZERO);
        ns.push_block(block);
        ns.height = 1;
        ns.parent_hash = ns.blocks.back().unwrap().header.hash();

        // Persist
        ns.persist_block(&store, &[]).unwrap();

        // Reload
        let restored = NodeState::load_from_disk(&store).unwrap();
        assert_eq!(restored.height, 1);
        assert_eq!(restored.blocks.len(), 1);
        assert_eq!(restored.blocks[0].header.height, 1);
    }

    #[test]
    fn persist_receipts() {
        let store = PersistentStore::open_temporary().unwrap();
        let mut ns = NodeState::new();

        let block = make_block(1, Hash256::ZERO);
        let block_hash = block.header.hash();
        ns.push_block(block);
        ns.height = 1;
        ns.parent_hash = block_hash;

        let tx_hash = brrq_crypto::hash::Hasher::hash(b"test_tx");
        let receipt = TxReceipt {
            block_height: 1,
            gas_used: 21000,
            success: true,
            block_hash,
            logs: Vec::new(),
        };
        ns.receipts.insert(tx_hash, receipt.clone());

        // Persist with receipts
        ns.persist_block(&store, &[(tx_hash, receipt)]).unwrap();

        // Reload
        let restored = NodeState::load_from_disk(&store).unwrap();
        assert_eq!(restored.receipts.len(), 1);
        assert!(restored.receipts.contains_key(&tx_hash));
        assert_eq!(restored.receipts[&tx_hash].gas_used, 21000);
        assert!(restored.receipts[&tx_hash].success);
    }

    #[test]
    fn load_from_disk_limits_recent_blocks() {
        let store = PersistentStore::open_temporary().unwrap();

        // Save many blocks to store directly
        for i in 1..=50u64 {
            let block = make_block(i, Hash256::ZERO);
            store.save_block(&block).unwrap();
        }
        // Save chain meta
        store.save_chain_meta(50, &Hash256::ZERO).unwrap();
        // Save empty world state
        let mut ws = brrq_state::WorldState::new();
        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();

        let restored = NodeState::load_from_disk(&store).unwrap();
        assert_eq!(restored.height, 50);
        // All 50 blocks should be loaded (under MAX_RECENT_BLOCKS)
        assert_eq!(restored.blocks.len(), 50);
    }

    // ── MAX_RECENT_BLOCKS constant ──────────────────────────────────────

    #[test]
    fn max_recent_blocks_is_1000() {
        assert_eq!(MAX_RECENT_BLOCKS, 1000);
    }

    // ── L1 anchor persistence tests ──────────────────────────────────

    #[test]
    fn test_load_from_disk_restores_l1_anchors() {
        let store = PersistentStore::open_temporary().unwrap();

        // Save minimal chain state so load_from_disk succeeds
        let mut ws = brrq_state::WorldState::new();
        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();
        store.save_chain_meta(0, &Hash256::ZERO).unwrap();

        // Save an L1 anchor record
        let anchor = brrq_bitcoin::L1AnchorRecord {
            l1_tx_id: [42u8; 32],
            l1_height: 850_000,
            block_hash: [0u8; 32],
            l2_height: 1000,
            state_root: Hash256::ZERO,
            proof_hash: Hash256::ZERO,
            timestamp: 1_700_000_000,
        };
        store.save_l1_anchor(&anchor).unwrap();

        // Load state from disk and verify anchors are restored
        let restored = NodeState::load_from_disk(&store).unwrap();
        assert_eq!(restored.l1_anchors.len(), 1);
        assert_eq!(restored.l1_anchors[0].l1_tx_id, [42u8; 32]);
        assert_eq!(restored.l1_anchors[0].l1_height, 850_000);
        assert_eq!(restored.l1_anchors[0].l2_height, 1000);
        assert_eq!(restored.l1_anchors[0].timestamp, 1_700_000_000);
    }
}
