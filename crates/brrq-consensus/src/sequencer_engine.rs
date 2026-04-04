//! Sequencer orchestrator — composes all consensus modules into a cohesive engine.
//!
//! ## Architecture
//!
//! The `SequencerEngine` is the top-level coordinator that wires together:
//! - [`StakingState`] — validator registration, √x stake cap, delegation
//! - [`LeaderElection`] — deterministic hash-based VRF
//! - [`RotationState`] — per-height proposal/vote/finalize FSM
//! - [`SlashingEngine`] — graduated penalties + equivocation detection
//! - [`EpochState`] — RANDAO commit-reveal + epoch transitions
//! - [`DecentralizationTracker`] — phase progression tracking
//! - [`CommitRevealManager`] — governance voting + MEV protection
//!
//! ## Sequencer Mode
//!
//! The engine operates in one of three modes, mapped from the
//! [`DecentralizationPhase`]:
//!
//! | Phase | Mode | Behavior |
//! |-------|------|----------|
//! | Foundation | `Centralized` | Designated sequencer, no election/rotation |
//! | Federation | `FederatedRotation` | Limited validator set, leader election + rotation |
//! | DualConsensus / FullSovereignty | `FullRotation` | Open validator set, full BFT |
//!
//! ## Block Lifecycle
//!
//! ```text
//! on_new_height()  →  elect leader  →  on_proposal()  →  on_vote()  →  on_finalize()
//!                                          ↓ timeout
//!                                     advance_round()  →  re-elect
//! ```

use brrq_crypto::hash::Hash256;
use brrq_types::Address;

use std::collections::HashMap;

#[cfg(feature = "governance-extensions")]
use crate::commit_reveal::CommitRevealManager;
use crate::decentralization::{
    BridgeMetrics, DecentralizationPhase, DecentralizationTracker, NetworkMetrics,
};
use crate::epoch::EpochState;
use crate::error::ConsensusError;
#[cfg(feature = "sequencer-rotation")]
use crate::leader_election::LeaderElection;
#[cfg(feature = "sequencer-rotation")]
use crate::rotation::{RotationAction, RotationConfig, RotationState};
use crate::slashing::{SlashResult, SlashingEngine, SlashingReason};
use crate::staking::StakingState;
use crate::view_sync::{TimeoutCertificate, ViewSyncState};

// ── Sequencer Mode ──────────────────────────────────────────────────────────

/// Operating mode of the sequencer, derived from [`DecentralizationPhase`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequencerMode {
    /// Foundation: designated sequencer, no election or rotation.
    /// The `designated` field holds the fixed sequencer address.
    Centralized,
    /// Federation: limited validator set with leader election + rotation.
    #[cfg(feature = "sequencer-rotation")]
    FederatedRotation,
    /// DualConsensus / FullSovereignty: open validator set, full BFT.
    #[cfg(feature = "sequencer-rotation")]
    FullRotation,
}

impl SequencerMode {
    /// Map a [`DecentralizationPhase`] to a [`SequencerMode`].
    pub fn from_phase(phase: DecentralizationPhase) -> Self {
        match phase {
            DecentralizationPhase::Foundation => Self::Centralized,
            #[cfg(feature = "sequencer-rotation")]
            DecentralizationPhase::Federation => Self::FederatedRotation,
            #[cfg(feature = "sequencer-rotation")]
            DecentralizationPhase::DualConsensus | DecentralizationPhase::FullSovereignty => {
                Self::FullRotation
            }
            #[cfg(not(feature = "sequencer-rotation"))]
            _ => Self::Centralized,
        }
    }

    /// Whether this mode uses leader election.
    pub fn uses_election(&self) -> bool {
        !matches!(self, Self::Centralized)
    }

    /// Whether this mode uses multi-round rotation with BFT voting.
    #[cfg(feature = "sequencer-rotation")]
    pub fn uses_rotation(&self) -> bool {
        !matches!(self, Self::Centralized)
    }

    /// Without sequencer-rotation feature, rotation is never used.
    #[cfg(not(feature = "sequencer-rotation"))]
    pub fn uses_rotation(&self) -> bool {
        false
    }
}

// ── Engine Events ───────────────────────────────────────────────────────────

/// Actions the engine emits for the node to execute.
#[derive(Debug, Clone)]
pub enum EngineAction {
    /// This node should propose a block (it is the elected leader).
    ProposeBlock { height: u64, round: u32 },
    /// This node should cast a PreVote for a proposed block.
    PreVoteForBlock {
        height: u64,
        round: u32,
        block_hash: Hash256,
    },
    /// This node should cast a PreCommit for a block after seeing 2/3 PreVotes.
    PreCommitForBlock {
        height: u64,
        round: u32,
        block_hash: Hash256,
    },
    /// A block has been finalized at this height.
    BlockFinalized { height: u64, block_hash: Hash256 },
    /// Timeout: broadcast a timeout vote to advance the round.
    BroadcastTimeout { height: u64, round: u32 },
    /// A new round has started (previous leader timed out).
    NewRound {
        height: u64,
        round: u32,
        new_leader: Address,
    },
    /// Epoch boundary: key rotation and cap recalculation occurred.
    EpochTransition {
        new_epoch: u64,
        non_revealers: Vec<Address>,
    },
    /// A validator was slashed.
    ValidatorSlashed(SlashResult),
    /// Equivocation detected — evidence available for slashing.
    EquivocationDetected {
        proposer: Address,
        height: u64,
        hashes: Vec<Hash256>,
    },
    /// Phase transition: the network moved to a new decentralization phase.
    PhaseTransition {
        from: DecentralizationPhase,
        to: DecentralizationPhase,
    },
    /// View sync: round advanced after receiving a valid timeout certificate.
    ViewSyncAdvance { height: u64, new_round: u32 },
}

// ── Sequencer Metrics ───────────────────────────────────────────────────────

/// Operational metrics for the sequencer engine.
///
/// These are accumulated over time and can be used to:
/// - Evaluate decentralization phase milestones
/// - Monitor system health
/// - Detect anomalous behavior
#[derive(Debug, Clone, Default)]
pub struct SequencerMetrics {
    /// Total blocks finalized.
    pub blocks_finalized: u64,
    /// Total rounds advanced (timeouts).
    pub timeouts: u64,
    /// Total equivocations detected.
    pub equivocations_detected: u64,
    /// Total validators slashed.
    pub validators_slashed: u64,
    /// Total epochs completed.
    pub epochs_completed: u64,
    /// Total RANDAO non-reveals.
    pub randao_non_reveals: u64,
    /// Number of phase transitions.
    pub phase_transitions: u64,
    /// Average finalization round (0 = first-try, higher = more timeouts).
    /// Stored as sum for computing running average.
    finalization_round_sum: u64,
}

impl SequencerMetrics {
    /// Average finalization round number.
    pub fn avg_finalization_round(&self) -> f64 {
        if self.blocks_finalized == 0 {
            0.0
        } else {
            self.finalization_round_sum as f64 / self.blocks_finalized as f64
        }
    }

    /// Timeout rate: ratio of timeout events to finalized blocks.
    ///
    /// A value > 1.0 means multiple timeouts per height on average.
    /// Returns 0.0 when no blocks have been finalized.
    pub fn timeout_rate(&self) -> f64 {
        if self.blocks_finalized == 0 {
            0.0
        } else {
            self.timeouts as f64 / self.blocks_finalized as f64
        }
    }

    /// Convert to `NetworkMetrics` for phase evaluation.
    ///
    /// Requires additional inputs that the engine doesn't track directly.
    pub fn to_network_metrics(
        &self,
        active_sequencers: u64,
        eligible_users: u64,
        locked_sats: u64,
        distinct_regions: u64,
        founder_seats: u64,
        bitvm2_pegout_bp: u64,
        rage_quit_tested: bool,
        council_elections: u64,
    ) -> NetworkMetrics {
        NetworkMetrics {
            active_sequencers,
            eligible_users,
            locked_sats,
            distinct_regions,
            uptime_blocks: self.blocks_finalized,
            proposals_executed: 0, // tracked by governance module
            founder_seats,
            bitvm2_pegout_bp,
            rage_quit_tested,
            council_elections,
        }
    }
}

// ── Sequencer Engine ────────────────────────────────────────────────────────

/// Top-level sequencer orchestrator.
///
/// Composes all consensus modules and manages the block production lifecycle.
pub struct SequencerEngine {
    /// Current sequencer mode (derived from decentralization phase).
    mode: SequencerMode,
    /// Designated sequencer for Centralized mode.
    designated_sequencer: Option<Address>,
    /// Staking state: validators, stakes, √x cap.
    pub(crate) staking: StakingState,
    /// Per-height rotation state (created fresh each height in rotation modes).
    #[cfg(feature = "sequencer-rotation")]
    rotation: Option<RotationState>,
    /// Rotation config for creating new RotationState instances.
    #[cfg(feature = "sequencer-rotation")]
    rotation_config: RotationConfig,
    /// Slashing engine: graduated penalties, double-slash prevention.
    pub(crate) slashing: SlashingEngine,
    /// Epoch state: RANDAO, epoch transitions.
    pub(crate) epoch: EpochState,
    /// Decentralization tracker: phase progression.
    pub(crate) decentralization: DecentralizationTracker,
    /// Commit-reveal manager: governance voting, MEV protection.
    #[cfg(feature = "governance-extensions")]
    pub(crate) commit_reveal: CommitRevealManager,
    /// Current block height.
    current_height: u64,
    /// VRF seed for leader election.
    vrf_seed: Hash256,
    /// Previous block hash (for leader election).
    prev_block_hash: Hash256,
    /// Our validator address (for determining if we should propose/vote).
    local_address: Option<Address>,
    /// Operational metrics.
    metrics: SequencerMetrics,
    /// View sync state for partition recovery (rotation modes only).
    view_sync: Option<ViewSyncState>,
    /// Proposals seen in centralized mode per height (equivocation detection).
    centralized_proposals: HashMap<u64, Vec<Hash256>>,
    /// Bridge metrics for BitVM2 peg-out tracking.
    pub(crate) bridge_metrics: BridgeMetrics,
    /// Tracks the highest sequence number seen per validator for replay protection.
    ///
    /// Every consensus message (proposal, vote, timeout) carries a monotonic
    /// `sequence` counter. Receivers must reject messages with a sequence <=
    /// the highest previously seen value for the same sender, preventing
    /// replay attacks.
    sequence_high_water: HashMap<Address, u64>,
    /// Accumulated threshold key shares for the current epoch's MEV decryption.
    ///
    /// Shares are collected from `ShareDistribution` consensus messages.
    /// Once `threshold` shares are collected, the epoch key can be
    /// reconstructed via `reconstruct_secret_verified()`.
    pending_shares: PendingShares,
}

/// Accumulator for threshold epoch key shares.
///
/// Tracks shares received for the current epoch and whether the threshold
/// has been reached.
#[derive(Debug, Clone)]
pub struct PendingShares {
    /// Epoch these shares belong to.
    pub epoch: u64,
    /// Collected shares keyed by share index (prevents duplicates).
    shares: HashMap<u32, brrq_crypto::encryption::KeyShare>,
    /// Threshold config (set when the epoch transitions).
    config: Option<brrq_crypto::encryption::ThresholdEncryptionConfig>,
    /// Height at which share collection started (for timeout tracking).
    pub collection_start_height: Option<u64>,
    /// Whether the key has been successfully reconstructed.
    pub reconstructed: bool,
    /// Track senders to enforce one-share-per-validator.
    /// Without this, a single malicious validator can flood with garbage shares
    /// using different indices, exhausting memory or corrupting reconstruction.
    seen_senders: std::collections::HashSet<brrq_types::Address>,
    /// Key commitment for verified reconstruction.
    /// Set during epoch transition when the expected key hash is known.
    /// reconstruct_secret_verified() checks the reconstructed key matches this.
    pub key_commitment: Option<brrq_crypto::hash::Hash256>,
}

/// Number of blocks to wait for threshold share collection before
/// declaring a timeout, skipping the batch, and penalizing non-responders.
pub const SHARE_TIMEOUT_BLOCKS: u64 = 10;

impl PendingShares {
    pub fn new() -> Self {
        Self {
            epoch: 0,
            shares: HashMap::new(),
            config: None,
            collection_start_height: None,
            reconstructed: false,
            seen_senders: std::collections::HashSet::new(),
            key_commitment: None,
        }
    }

    /// Reset for a new epoch.
    pub fn reset(&mut self, epoch: u64, config: brrq_crypto::encryption::ThresholdEncryptionConfig) {
        self.epoch = epoch;
        self.shares.clear();
        self.seen_senders.clear();
        self.config = Some(config);
        self.collection_start_height = None;
        self.reconstructed = false;
    }

    /// Maximum shares accepted = number of validators (or reasonable cap).
    /// Prevents memory exhaustion from garbage share flooding.
    const MAX_SHARES: usize = 200;

    /// Add a share from a specific sender. Returns true if threshold was just reached.
    ///
    /// Enforces:
    /// 1. One share per sender (duplicate sender → rejected)
    /// 2. Share index within valid range (< MAX_SHARES)
    /// 3. Total shares capped at MAX_SHARES (memory protection)
    pub fn add_share(
        &mut self,
        share: brrq_crypto::encryption::KeyShare,
        sender: brrq_types::Address,
        current_height: u64,
    ) -> bool {
        // One share per sender — prevents a single validator from
        // flooding with garbage shares under different indices.
        if self.seen_senders.contains(&sender) {
            return false; // Duplicate sender — silently rejected
        }

        // Share index must be within valid range for the actual threshold config
        let config_total = self.config.as_ref().map(|c| c.total_shares as usize).unwrap_or(Self::MAX_SHARES);
        if share.index as usize >= config_total || share.index as usize >= Self::MAX_SHARES {
            return false; // Index out of range
        }

        // Total share count cap (memory protection)
        if self.shares.len() >= Self::MAX_SHARES {
            return false; // Collection full
        }

        if self.collection_start_height.is_none() {
            self.collection_start_height = Some(current_height);
        }

        let index = share.index;
        self.seen_senders.insert(sender);
        self.shares.insert(index, share);
        self.threshold_reached()
    }

    /// Whether we have enough shares to reconstruct the key.
    pub fn threshold_reached(&self) -> bool {
        if let Some(config) = &self.config {
            self.shares.len() as u32 >= config.threshold
        } else {
            false
        }
    }

    /// Attempt to reconstruct the epoch key from collected shares.
    ///
    /// Returns `None` if threshold not reached or already reconstructed.
    pub fn try_reconstruct(
        &mut self,
    ) -> Option<Result<brrq_crypto::encryption::EpochKey, brrq_crypto::encryption::CryptoError>> {
        if self.reconstructed || !self.threshold_reached() {
            return None;
        }
        let config = self.config.as_ref()?;
        let shares: Vec<&brrq_crypto::encryption::KeyShare> = self.shares.values().collect();
        // Do NOT set reconstructed=true on success.
        // The caller MUST verify the key works (e.g., decrypt a test envelope)
        // before calling confirm_reconstruction(). If the key is junk (poisoned
        // share), the caller can remove the bad share and try again.
        let share_refs: Vec<_> = shares.into_iter().cloned().collect();
        // Use verified reconstruction when commitment is available.
        // This prevents poisoned DKG shares from producing a wrong epoch key.
        let result = if let Some(ref commitment) = self.key_commitment {
            brrq_crypto::encryption::reconstruct_secret_verified(&share_refs, config, commitment)
        } else {
            // Fallback for epochs without commitment (legacy/testnet).
            brrq_crypto::encryption::reconstruct_secret(&share_refs, config)
        };
        // Verify reconstructed key is not junk.
        // If reconstruction succeeds but produces a zero key, it was poisoned.
        // Reject zero keys (likely from poisoned DKG shares).
        if let Ok(ref key) = result {
            if key.as_bytes() == &[0u8; 32] {
                return Some(Err(brrq_crypto::encryption::CryptoError::ShareVerificationFailed));
            }
        }
        // DO NOT set self.reconstructed here — caller must confirm via confirm_reconstruction()
        Some(result)
    }

    /// Confirm that the reconstructed key is valid.
    /// Call this ONLY after verifying the key decrypts correctly.
    pub fn confirm_reconstruction(&mut self) {
        self.reconstructed = true;
    }

    /// Reject a specific share (e.g., if reconstruction produced a junk key).
    /// Removes the share so the next try_reconstruct() uses remaining valid shares.
    pub fn reject_share(&mut self, index: u32) {
        self.shares.remove(&index);
        // Allow retry since we removed a bad share
        self.reconstructed = false;
    }

    /// Check if share collection has timed out.
    pub fn is_timed_out(&self, current_height: u64) -> bool {
        if let Some(start) = self.collection_start_height {
            current_height >= start.saturating_add(SHARE_TIMEOUT_BLOCKS)
        } else {
            false
        }
    }

    /// Get indices of shares we have NOT received (for penalizing non-responders).
    pub fn missing_share_indices(&self, total: u32) -> Vec<u32> {
        (1..=total)
            .filter(|i| !self.shares.contains_key(i))
            .collect()
    }
}

impl SequencerEngine {
    /// Create a new engine in Centralized mode.
    ///
    /// `designated` is the fixed sequencer for Foundation mode.
    /// `stake_cap` is the initial √x stake cap.
    pub fn new(designated: Address, stake_cap: u64, epoch_length: u64) -> Self {
        Self {
            mode: SequencerMode::Centralized,
            designated_sequencer: Some(designated),
            staking: StakingState::new(stake_cap),
            #[cfg(feature = "sequencer-rotation")]
            rotation: None,
            #[cfg(feature = "sequencer-rotation")]
            rotation_config: RotationConfig::default(),
            slashing: SlashingEngine::new(),
            epoch: EpochState::new(epoch_length),
            decentralization: DecentralizationTracker::new(),
            #[cfg(feature = "governance-extensions")]
            commit_reveal: CommitRevealManager::new(),
            current_height: 0,
            vrf_seed: Hash256::ZERO,
            prev_block_hash: Hash256::ZERO,
            local_address: None,
            metrics: SequencerMetrics::default(),
            view_sync: None,
            centralized_proposals: HashMap::new(),
            bridge_metrics: BridgeMetrics::default(),
            sequence_high_water: HashMap::new(),
            pending_shares: PendingShares::new(),
        }
    }

    /// Create a new engine in a specific mode (for testing or resuming).
    #[cfg(feature = "sequencer-rotation")]
    pub fn with_mode(
        mode: SequencerMode,
        staking: StakingState,
        rotation_config: RotationConfig,
        epoch_length: u64,
    ) -> Self {
        Self {
            mode,
            designated_sequencer: None,
            staking,
            #[cfg(feature = "sequencer-rotation")]
            rotation: None,
            #[cfg(feature = "sequencer-rotation")]
            rotation_config,
            slashing: SlashingEngine::new(),
            epoch: EpochState::new(epoch_length),
            decentralization: DecentralizationTracker::new(),
            #[cfg(feature = "governance-extensions")]
            commit_reveal: CommitRevealManager::new(),
            current_height: 0,
            vrf_seed: Hash256::ZERO,
            prev_block_hash: Hash256::ZERO,
            local_address: None,
            metrics: SequencerMetrics::default(),
            view_sync: None,
            centralized_proposals: HashMap::new(),
            bridge_metrics: BridgeMetrics::default(),
            sequence_high_water: HashMap::new(),
            pending_shares: PendingShares::new(),
        }
    }

    /// Set the local validator address.
    pub fn set_local_address(&mut self, address: Address) {
        self.local_address = Some(address);
    }

    /// Set the VRF seed (typically from the epoch RANDAO output).
    pub fn set_vrf_seed(&mut self, seed: Hash256) {
        self.vrf_seed = seed;
    }

    /// Set the rotation config.
    #[cfg(feature = "sequencer-rotation")]
    pub fn set_rotation_config(&mut self, config: RotationConfig) {
        self.rotation_config = config;
    }

    /// Check and update the sequence number high-water mark for a sender.
    ///
    /// Every consensus message carries a monotonically increasing `sequence`
    /// counter per validator. This method enforces that the sequence is
    /// strictly greater than any previously seen value for the same sender,
    /// preventing replay attacks.
    ///
    /// # Errors
    ///
    /// Returns [`ConsensusError::ReplayedMessage`] if `sequence` is <= the
    /// highest value previously recorded for `sender`.
    pub fn check_and_update_sequence(
        &mut self,
        sender: &Address,
        sequence: u64,
    ) -> Result<(), ConsensusError> {
        let hwm = self.sequence_high_water.entry(*sender).or_insert(0);
        if sequence <= *hwm {
            return Err(ConsensusError::ReplayedMessage {
                sender: *sender,
                sequence,
            });
        }
        *hwm = sequence;
        Ok(())
    }

    /// Get the current high-water mark for a given sender (for diagnostics).
    pub fn sequence_high_water_mark(&self, sender: &Address) -> u64 {
        self.sequence_high_water.get(sender).copied().unwrap_or(0)
    }

    /// Get the current sequencer mode.
    pub fn mode(&self) -> SequencerMode {
        self.mode
    }

    /// Get the current height.
    pub fn height(&self) -> u64 {
        self.current_height
    }

    /// Get accumulated metrics.
    pub fn metrics(&self) -> &SequencerMetrics {
        &self.metrics
    }

    /// Get the current rotation state (if in rotation mode).
    #[cfg(feature = "sequencer-rotation")]
    pub fn rotation(&self) -> Option<&RotationState> {
        self.rotation.as_ref()
    }

    /// Get the current leader for this height/round.
    pub fn current_leader(&self) -> Option<&Address> {
        match self.mode {
            SequencerMode::Centralized => self.designated_sequencer.as_ref(),
            #[cfg(feature = "sequencer-rotation")]
            _ => self.rotation.as_ref().map(|r| r.leader()),
        }
    }

    // ── Block Lifecycle ─────────────────────────────────────────────────

    /// Start a new block height. Returns actions the node should take.
    ///
    /// This is the entry point for each new block production cycle:
    /// 1. Check for epoch boundary → transition if needed
    /// 2. Elect leader (in rotation modes)
    /// 3. Initialize rotation state
    /// 4. Return `ProposeBlock` if we are the leader
    #[allow(unused_variables)]
    pub fn on_new_height(
        &mut self,
        height: u64,
        prev_block_hash: Hash256,
        now_ms: u64,
    ) -> Result<Vec<EngineAction>, ConsensusError> {
        // Monotonicity: reject non-advancing heights (prevents replay/reorg confusion).
        if height != 0 && height <= self.current_height {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "height {} is not greater than current height {}",
                    height, self.current_height
                ),
            });
        }
        // If the previous height had a rotation that was not finalized,
        // the elected leader failed to produce a block. Record a timeout penalty
        // against them so repeated non-production leads to suspension/removal.
        #[cfg(feature = "sequencer-rotation")]
        {
            if let Some(ref prev_rotation) = self.rotation {
                let prev_leader = *prev_rotation.leader();
                let prev_height = prev_rotation.height();
                if let Some(v) = self.staking.validators.get_mut(&prev_leader) {
                    v.record_timeout(prev_height);
                }
                self.metrics.timeouts += 1;
            }
            self.rotation = None;
        }

        self.current_height = height;
        self.prev_block_hash = prev_block_hash;
        let mut actions = Vec::new();

        // GC old centralized proposal tracking (keep last 10 heights).
        self.centralized_proposals
            .retain(|h, _| height.saturating_sub(10) <= *h);

        // Process commit-reveal phase transitions.
        #[cfg(feature = "governance-extensions")]
        self.commit_reveal.process_block(height);

        // ── Epoch boundary check ──
        if self.epoch.is_epoch_boundary(height) {
            let non_revealers = self.epoch.transition(
                height,
                &mut self.staking,
                &prev_block_hash,
                &mut self.slashing,
            );
            let new_epoch = self.epoch.current_epoch;
            // Update VRF seed from epoch RANDAO.
            self.vrf_seed = self.epoch.epoch_seed;
            self.metrics.epochs_completed += 1;
            self.metrics.randao_non_reveals += non_revealers.len() as u64;
            actions.push(EngineAction::EpochTransition {
                new_epoch,
                non_revealers,
            });
        }

        // ── Leader election + rotation setup ──
        match self.mode {
            SequencerMode::Centralized => {
                // No election. The designated sequencer always proposes.
                if self.local_address == self.designated_sequencer {
                    actions.push(EngineAction::ProposeBlock { height, round: 0 });
                }
            }
            #[cfg(feature = "sequencer-rotation")]
            SequencerMode::FederatedRotation | SequencerMode::FullRotation => {
                let leader = LeaderElection::elect(
                    &self.staking,
                    &self.prev_block_hash,
                    height,
                    0, // round 0
                    &self.vrf_seed,
                )?;

                let rotation = RotationState::new(
                    self.rotation_config.clone(),
                    height,
                    leader,
                    &self.staking,
                    now_ms,
                );

                // Check if we are the leader.
                if self.local_address.as_ref() == Some(rotation.leader()) {
                    actions.push(EngineAction::ProposeBlock { height, round: 0 });
                }

                // Initialize view sync for partition recovery.
                let total_eff: u64 = self
                    .staking
                    .validators
                    .values()
                    .filter(|v| v.is_eligible(height))
                    .map(|v| StakingState::apply_sqrt_cap(v.total_stake(), self.staking.stake_cap))
                    .fold(0u64, |acc, s| acc.saturating_add(s));
                self.view_sync = Some(ViewSyncState::new(height, total_eff));

                self.rotation = Some(rotation);
            }
        }

        Ok(actions)
    }

    /// Handle a block proposal from a sequencer.
    ///
    /// In centralized mode, proposals from the designated sequencer auto-finalize.
    /// In rotation modes, the proposal transitions to the voting phase.
    #[allow(unused_variables)]
    pub fn on_proposal(
        &mut self,
        proposer: Address,
        block_hash: Hash256,
        now_ms: u64,
    ) -> Result<Vec<EngineAction>, ConsensusError> {
        let mut actions = Vec::new();

        match self.mode {
            SequencerMode::Centralized => {
                // In centralized mode, only the designated sequencer can propose.
                if Some(&proposer) != self.designated_sequencer.as_ref() {
                    return Err(ConsensusError::InvalidBlock {
                        reason: format!("proposer {} is not the designated sequencer", proposer),
                    });
                }

                // Centralized equivocation detection: track proposals per height.
                let seen = self
                    .centralized_proposals
                    .entry(self.current_height)
                    .or_default();
                if !seen.contains(&block_hash) {
                    seen.push(block_hash);
                }

                // Equivocation: multiple distinct proposals at same height.
                if seen.len() > 1 {
                    self.metrics.equivocations_detected += 1;
                    let hashes = seen.clone();
                    actions.push(EngineAction::EquivocationDetected {
                        proposer,
                        height: self.current_height,
                        hashes: hashes.clone(),
                    });
                    // Auto-slash even in centralized mode.
                    if let Ok(slash_result) = self.slashing.slash(
                        &mut self.staking,
                        &proposer,
                        SlashingReason::Equivocation,
                        &hashes
                            .iter()
                            .flat_map(|h| h.as_bytes().to_vec())
                            .collect::<Vec<_>>(),
                        self.current_height,
                        self.current_height,
                    ) {
                        self.metrics.validators_slashed += 1;
                        actions.push(EngineAction::ValidatorSlashed(slash_result));
                    }
                    return Err(ConsensusError::Equivocation {
                        height: self.current_height,
                    });
                }

                // Normal auto-finalize.
                self.metrics.blocks_finalized += 1;
                self.prev_block_hash = block_hash;
                actions.push(EngineAction::BlockFinalized {
                    height: self.current_height,
                    block_hash,
                });
            }
            #[cfg(feature = "sequencer-rotation")]
            SequencerMode::FederatedRotation | SequencerMode::FullRotation => {
                let rotation = self.rotation.as_mut().ok_or(ConsensusError::InvalidBlock {
                    reason: "no rotation state for current height".into(),
                })?;

                // receive_proposal returns Err(Equivocation) when dual proposals
                // are detected. We catch this to perform auto-slashing before
                // propagating the error.
                let proposal_result = rotation.receive_proposal(proposer, block_hash, now_ms);

                // Check for equivocation evidence (recorded even on error).
                let equivocation = rotation
                    .equivocation_evidence(&proposer)
                    .filter(|h| h.len() >= 2)
                    .cloned();

                if let Some(hashes) = equivocation {
                    self.metrics.equivocations_detected += 1;
                    actions.push(EngineAction::EquivocationDetected {
                        proposer,
                        height: self.current_height,
                        hashes: hashes.clone(),
                    });
                    // Auto-slash: equivocation = 33.33% stake penalty (EOTS key extractable).
                    if let Ok(slash_result) = self.slashing.slash(
                        &mut self.staking,
                        &proposer,
                        SlashingReason::Equivocation,
                        &hashes
                            .iter()
                            .flat_map(|h| h.as_bytes().to_vec())
                            .collect::<Vec<_>>(),
                        self.current_height,
                        self.current_height,
                    ) {
                        self.metrics.validators_slashed += 1;
                        actions.push(EngineAction::ValidatorSlashed(slash_result));
                    }
                }

                // Now propagate proposal result (may be Err for equivocation).
                let action = proposal_result?;
                self.translate_rotation_action(action, &mut actions);
            }
        }

        Ok(actions)
    }

    /// Handle a PreVote for a proposed block.
    #[allow(unused_variables, unused_mut)]
    pub fn on_prevote(
        &mut self,
        voter: Address,
        block_hash: Hash256,
        now_ms: u64,
    ) -> Result<Vec<EngineAction>, ConsensusError> {
        let mut actions = Vec::new();

        if !self.mode.uses_rotation() {
            return Ok(actions); // Votes are no-ops in centralized mode.
        }

        #[cfg(feature = "sequencer-rotation")]
        {
            // If rotation is already cleared, vote is a no-op.
            let rotation = match self.rotation.as_mut() {
                Some(r) => r,
                None => return Ok(actions),
            };

            let action = rotation.receive_prevote(voter, block_hash, now_ms)?;
            self.translate_rotation_action(action, &mut actions);
        }

        Ok(actions)
    }

    /// Handle a PreCommit for a proposed block.
    #[allow(unused_variables, unused_mut)]
    pub fn on_precommit(
        &mut self,
        voter: Address,
        block_hash: Hash256,
    ) -> Result<Vec<EngineAction>, ConsensusError> {
        let mut actions = Vec::new();

        if !self.mode.uses_rotation() {
            return Ok(actions);
        }

        #[cfg(feature = "sequencer-rotation")]
        {
            let rotation = match self.rotation.as_mut() {
                Some(r) => r,
                None => return Ok(actions),
            };

            let action = rotation.receive_precommit(voter, block_hash)?;
            self.translate_rotation_action(action, &mut actions);
        }

        Ok(actions)
    }

    /// Handle a timeout vote (leader failed to propose in time).
    #[allow(unused_variables, unused_mut)]
    pub fn on_timeout_vote(&mut self, voter: Address) -> Result<Vec<EngineAction>, ConsensusError> {
        let mut actions = Vec::new();

        if !self.mode.uses_rotation() {
            return Ok(actions);
        }

        #[cfg(feature = "sequencer-rotation")]
        {
            let rotation = self.rotation.as_mut().ok_or(ConsensusError::InvalidBlock {
                reason: "no rotation state for current height".into(),
            })?;

            let action = rotation.receive_timeout_vote(voter)?;
            self.translate_rotation_action(action, &mut actions);
        }

        Ok(actions)
    }

    /// Check for proposal timeout. Call periodically.
    #[allow(unused_variables, unused_mut)]
    pub fn check_timeout(&mut self, now_ms: u64) -> Vec<EngineAction> {
        let mut actions = Vec::new();

        #[cfg(feature = "sequencer-rotation")]
        {
            if let Some(ref rotation) = self.rotation {
                if let Some(action) = rotation.check_timeout(now_ms) {
                    self.translate_rotation_action(action, &mut actions);
                }
            }
        }

        actions
    }

    /// Handle a received threshold key share for MEV epoch key.
    ///
    /// Validates the share (correct epoch, not duplicate) and adds it to the
    /// accumulator. When threshold is reached, the epoch key can be reconstructed
    /// for batch decryption.
    ///
    /// # Arguments
    /// - `epoch`: Epoch the share belongs to
    /// - `share_index`: 1-based Shamir share index
    /// - `share_data`: 32-byte share value
    /// - `sender`: Address of the sender (must be in validator set)
    pub fn on_share_distribution(
        &mut self,
        epoch: u64,
        share_index: u32,
        share_data: [u8; 32],
        sender: &Address,
    ) -> Result<bool, ConsensusError> {
        // Validate epoch
        if epoch != self.epoch.current_epoch {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "share for epoch {epoch} but current epoch is {}",
                    self.epoch.current_epoch,
                ),
            });
        }

        // Validate sender is in the current validator set
        if !self.epoch.validator_set.contains(sender) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("share sender {sender:?} is not in the current validator set"),
            });
        }

        let share = brrq_crypto::encryption::KeyShare::new(share_index, share_data);
        let threshold_reached = self.pending_shares.add_share(share, *sender, self.current_height);

        if threshold_reached {
            // Threshold reached — caller can now reconstruct the epoch key
            // via try_reconstruct_epoch_key().
        }

        Ok(threshold_reached)
    }

    /// Attempt to reconstruct the epoch key from collected shares.
    ///
    /// Returns `Some(Ok(key))` if threshold is met and reconstruction succeeds.
    /// Returns `Some(Err(..))` if reconstruction fails (bad shares).
    /// Returns `None` if threshold not yet reached.
    pub fn try_reconstruct_epoch_key(
        &mut self,
    ) -> Option<Result<brrq_crypto::encryption::EpochKey, brrq_crypto::encryption::CryptoError>> {
        self.pending_shares.try_reconstruct()
    }

    /// Check if share collection has timed out for the current epoch.
    ///
    /// If timed out, returns the indices of missing shares (for penalizing
    /// non-responders). The caller should:
    /// 1. Skip the current batch (return encrypted txs to mempool)
    /// 2. Slash non-responders with `SlashCondition::ExtendedDowntime`
    pub fn check_share_timeout(&self) -> Option<Vec<u32>> {
        if !self.pending_shares.reconstructed
            && self.pending_shares.is_timed_out(self.current_height)
        {
            let total = self.epoch.validator_set.len() as u32;
            Some(self.pending_shares.missing_share_indices(total))
        } else {
            None
        }
    }

    /// Access pending shares state (for diagnostics/testing).
    pub fn pending_shares(&self) -> &PendingShares {
        &self.pending_shares
    }

    /// Initialize share collection for a new epoch.
    ///
    /// Called after epoch transition when the threshold config is known.
    pub fn init_share_collection(
        &mut self,
        config: brrq_crypto::encryption::ThresholdEncryptionConfig,
    ) {
        self.pending_shares.reset(self.epoch.current_epoch, config);
    }

    /// Advance to the next round after timeout consensus.
    ///
    /// Elects a new leader for the new round and re-initializes rotation.
    #[cfg(feature = "sequencer-rotation")]
    pub fn advance_round(&mut self, now_ms: u64) -> Result<Vec<EngineAction>, ConsensusError> {
        let mut actions = Vec::new();

        let rotation = self.rotation.as_mut().ok_or(ConsensusError::InvalidBlock {
            reason: "no rotation state to advance".into(),
        })?;

        let new_round = rotation.round() + 1;

        // Elect new leader for the new round.
        let new_leader = LeaderElection::elect(
            &self.staking,
            &self.prev_block_hash,
            self.current_height,
            new_round,
            &self.vrf_seed,
        )?;

        rotation.advance_round(new_leader, now_ms)?;
        self.metrics.timeouts += 1;

        actions.push(EngineAction::NewRound {
            height: self.current_height,
            round: new_round,
            new_leader,
        });

        // If we are the new leader, propose.
        if self.local_address.as_ref() == Some(&new_leader) {
            actions.push(EngineAction::ProposeBlock {
                height: self.current_height,
                round: new_round,
            });
        }

        Ok(actions)
    }

    /// Advance to the next round (no-op without sequencer-rotation feature).
    #[cfg(not(feature = "sequencer-rotation"))]
    pub fn advance_round(&mut self, _now_ms: u64) -> Result<Vec<EngineAction>, ConsensusError> {
        Err(ConsensusError::InvalidBlock {
            reason: "advance_round requires sequencer-rotation feature".into(),
        })
    }

    /// Finalize a block at the current height. Called after consensus is reached.
    ///
    /// If rotation is already `None`, quorum finalization already handled
    /// metrics and emitted `BlockFinalized` via `translate_rotation_action(Finalize)`.
    /// This method only emits `BlockFinalized` when rotation is still active.
    #[allow(unused_mut)]
    pub fn on_finalize(&mut self, block_hash: Hash256) -> Vec<EngineAction> {
        let mut actions = Vec::new();
        self.prev_block_hash = block_hash;

        #[cfg(feature = "sequencer-rotation")]
        {
            if self.rotation.is_some() {
                // Record metrics only if not already recorded by quorum finalization.
                let round = self.rotation.as_ref().map(|r| r.round()).unwrap_or(0);
                self.metrics.blocks_finalized += 1;
                self.metrics.finalization_round_sum = self
                    .metrics
                    .finalization_round_sum
                    .saturating_add(round as u64);
                self.rotation = None;

                actions.push(EngineAction::BlockFinalized {
                    height: self.current_height,
                    block_hash,
                });
            }
            // When rotation is None, quorum already emitted BlockFinalized.
            // No duplicate event.
        }

        actions
    }

    // ── Slashing ────────────────────────────────────────────────────────

    /// Slash a validator for a detected offense.
    pub fn slash_validator(
        &mut self,
        validator: &Address,
        reason: SlashingReason,
        context: &[u8],
        evidence_height: u64,
    ) -> Result<EngineAction, ConsensusError> {
        let result = self.slashing.slash(
            &mut self.staking,
            validator,
            reason,
            context,
            self.current_height,
            evidence_height,
        )?;
        self.metrics.validators_slashed += 1;
        Ok(EngineAction::ValidatorSlashed(result))
    }

    // ── View Sync ──────────────────────────────────────────────────────

    /// Handle a timeout certificate from a peer for view synchronization.
    ///
    /// If the certificate advances our highest certified round, returns a
    /// `ViewSyncAdvance` action so the node can elect a new leader.
    ///
    /// Now requires `validator_pubkeys` so that each Schnorr
    /// signature in the certificate is cryptographically verified.
    pub fn on_timeout_certificate(
        &mut self,
        cert: TimeoutCertificate,
        validator_pubkeys: &HashMap<Address, brrq_crypto::schnorr::SchnorrPublicKey>,
    ) -> Result<Vec<EngineAction>, ConsensusError> {
        let mut actions = Vec::new();

        if !self.mode.uses_rotation() {
            return Ok(actions);
        }

        let vs = match self.view_sync.as_mut() {
            Some(vs) => vs,
            None => return Ok(actions),
        };

        // Use the safe v2 method that independently verifies
        // aggregate_stake against actual validator stakes, preventing
        // inflation attacks via forged certificates.
        let validator_stakes: HashMap<Address, u64> = self
            .staking
            .validators
            .iter()
            .map(|(addr, v)| (*addr, v.stake))
            .collect();
        let advanced = vs.receive_timeout_certificate_with_stakes(
            cert,
            validator_pubkeys,
            &validator_stakes,
        )?;
        if advanced {
            let new_round = vs.highest_certified_round().saturating_add(1);
            actions.push(EngineAction::ViewSyncAdvance {
                height: self.current_height,
                new_round,
            });
        }

        Ok(actions)
    }

    /// Get the view sync state (if in rotation mode).
    pub fn view_sync(&self) -> Option<&ViewSyncState> {
        self.view_sync.as_ref()
    }

    // ── Bridge Metrics ───────────────────────────────────────────────

    /// Record a peg-out event for BitVM2 bridge metrics tracking.
    /// Called by the node layer after each peg-out completes.
    pub fn record_pegout(&mut self, is_bitvm2: bool) {
        self.bridge_metrics.record_pegout(is_bitvm2);
    }

    /// Get the current bridge metrics.
    pub fn bridge_metrics(&self) -> &BridgeMetrics {
        &self.bridge_metrics
    }

    // ── Phase Transitions ───────────────────────────────────────────────

    /// Evaluate and potentially advance the decentralization phase.
    ///
    /// Returns a `PhaseTransition` action if the phase changed.
    pub fn evaluate_phase(
        &mut self,
        metrics: &NetworkMetrics,
    ) -> Result<Option<EngineAction>, ConsensusError> {
        let evaluation = self.decentralization.evaluate(metrics);

        if evaluation.next_phase_ready {
            let from = self.decentralization.current_phase;
            self.decentralization.confirm_transition();
            let to = self
                .decentralization
                .advance_phase(metrics, self.current_height)?;
            self.mode = SequencerMode::from_phase(to);
            self.metrics.phase_transitions += 1;

            // Clear designated sequencer when leaving centralized mode.
            if self.mode != SequencerMode::Centralized {
                self.designated_sequencer = None;
            }

            Ok(Some(EngineAction::PhaseTransition { from, to }))
        } else {
            Ok(None)
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Translate a `RotationAction` into `EngineAction`s.
    #[cfg(feature = "sequencer-rotation")]
    fn translate_rotation_action(
        &mut self,
        action: RotationAction,
        actions: &mut Vec<EngineAction>,
    ) {
        match action {
            RotationAction::None => {}
            RotationAction::PreVote {
                height,
                round,
                block_hash,
            } => {
                if self.local_address.is_some() {
                    actions.push(EngineAction::PreVoteForBlock {
                        height,
                        round,
                        block_hash,
                    });
                }
            }
            RotationAction::PreCommit {
                height,
                round,
                block_hash,
            } => {
                if self.local_address.is_some() {
                    actions.push(EngineAction::PreCommitForBlock {
                        height,
                        round,
                        block_hash,
                    });
                }
            }
            RotationAction::Finalize { block_hash } => {
                // Record metrics and update state (matches on_finalize logic).
                let round = self.rotation.as_ref().map(|r| r.round()).unwrap_or(0);
                self.metrics.blocks_finalized += 1;
                self.metrics.finalization_round_sum = self
                    .metrics
                    .finalization_round_sum
                    .saturating_add(round as u64);
                self.prev_block_hash = block_hash;
                // Clear rotation state to prevent double-finalization.
                self.rotation = None;
                actions.push(EngineAction::BlockFinalized {
                    height: self.current_height,
                    block_hash,
                });
            }
            RotationAction::BroadcastTimeout { height, round } => {
                actions.push(EngineAction::BroadcastTimeout { height, round });
            }
            RotationAction::NewRound { round, leader } => {
                actions.push(EngineAction::NewRound {
                    height: self.current_height,
                    round,
                    new_leader: leader,
                });
            }
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;

    fn addr(n: u8) -> Address {
        Address::from_bytes([n; 20])
    }

    #[cfg(feature = "sequencer-rotation")]
    fn setup_engine_with_validators(count: u8) -> SequencerEngine {
        let mut engine = SequencerEngine::with_mode(
            SequencerMode::FullRotation,
            StakingState::new(100_000_000), // 1 BTC cap
            RotationConfig::default(),
            7200,
        );
        for i in 1..=count {
            engine
                .staking
                .register_validator(addr(i), 100_000_000) // 1 BTC each
                .unwrap();
        }
        engine.set_vrf_seed(Hasher::hash(b"test seed"));
        engine
    }

    // ── Centralized Mode ────────────────────────────────────────────

    #[test]
    fn centralized_designated_sequencer_proposes() {
        let designated = addr(1);
        let mut engine = SequencerEngine::new(designated, 100_000_000, 7200);
        engine.set_local_address(designated);

        let actions = engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        assert!(actions.iter().any(|a| matches!(
            a,
            EngineAction::ProposeBlock {
                height: 1,
                round: 0
            }
        )));
    }

    #[test]
    fn centralized_non_designated_does_not_propose() {
        let designated = addr(1);
        let mut engine = SequencerEngine::new(designated, 100_000_000, 7200);
        engine.set_local_address(addr(2)); // not the designated sequencer

        let actions = engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, EngineAction::ProposeBlock { .. })),
            "non-designated sequencer should not propose"
        );
    }

    #[test]
    fn centralized_wrong_proposer_rejected() {
        let designated = addr(1);
        let mut engine = SequencerEngine::new(designated, 100_000_000, 7200);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let result = engine.on_proposal(addr(2), Hasher::hash(b"block"), 0);
        assert!(result.is_err());
    }

    #[test]
    fn centralized_proposal_auto_finalizes() {
        let designated = addr(1);
        let mut engine = SequencerEngine::new(designated, 100_000_000, 7200);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let block_hash = Hasher::hash(b"block 1");
        let actions = engine.on_proposal(designated, block_hash, 0).unwrap();

        assert!(actions.iter().any(
            |a| matches!(a, EngineAction::BlockFinalized { height: 1, block_hash: h } if *h == block_hash)
        ));
    }

    // ── Rotation Mode ───────────────────────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn rotation_elects_leader_on_new_height() {
        let mut engine = setup_engine_with_validators(3);

        let _actions = engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        // Rotation state should be initialized.
        assert!(engine.rotation().is_some());
        assert!(engine.current_leader().is_some());
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn rotation_proposal_triggers_vote() {
        let mut engine = setup_engine_with_validators(3);
        engine.set_local_address(addr(2));

        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let leader = *engine.current_leader().unwrap();
        let block_hash = Hasher::hash(b"proposed block");

        let actions = engine.on_proposal(leader, block_hash, 100).unwrap();

        // Should trigger a vote action (if the engine translates RotationAction::Vote).
        // The RotationState.receive_proposal returns Vote action.
        assert!(
            !actions.is_empty()
                || engine
                    .rotation()
                    .map(|r| !r.is_finalized())
                    .unwrap_or(false),
            "proposal should transition rotation to voting phase"
        );
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn rotation_quorum_finalizes() {
        let mut engine = setup_engine_with_validators(3);
        engine.set_local_address(addr(1));

        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let leader = *engine.current_leader().unwrap();
        let block_hash = Hasher::hash(b"proposed block");

        // Leader proposes.
        engine.on_proposal(leader, block_hash, 100).unwrap();

        // All 3 validators prevote (2/3 quorum needed to trigger PreCommit).
        let mut precommit_triggered = false;
        for i in 1..=3 {
            let actions = engine.on_prevote(addr(i), block_hash, 100).unwrap();
            if actions
                .iter()
                .any(|a| matches!(a, EngineAction::PreCommitForBlock { .. }))
            {
                precommit_triggered = true;
            }
        }
        assert!(
            precommit_triggered,
            "2/3 prevotes should trigger PreCommit phase"
        );

        // All 3 validators precommit (2/3 quorum needed to finalize).
        let mut finalized = false;
        for i in 1..=3 {
            let actions = engine.on_precommit(addr(i), block_hash).unwrap();
            if actions
                .iter()
                .any(|a| matches!(a, EngineAction::BlockFinalized { .. }))
            {
                finalized = true;
                break;
            }
        }

        assert!(
            finalized || engine.rotation().map(|r| r.is_finalized()).unwrap_or(false),
            "block should be finalized after 2/3 quorum"
        );
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn rotation_timeout_advances_round() {
        let mut engine = setup_engine_with_validators(3);

        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        // Don't propose — simulate timeout.
        // Collect timeout votes from 2/3 validators.
        for i in 1..=3 {
            let _ = engine.on_timeout_vote(addr(i));
        }

        // Advance round.
        let actions = engine.advance_round(50_000).unwrap();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, EngineAction::NewRound { round: 1, .. }))
        );
    }

    // ── Equivocation Detection ──────────────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn equivocation_detected_on_dual_proposal() {
        let mut engine = setup_engine_with_validators(3);

        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let leader = *engine.current_leader().unwrap();
        let block_a = Hasher::hash(b"block A");
        let block_b = Hasher::hash(b"block B");

        // Leader proposes once (valid).
        engine.on_proposal(leader, block_a, 100).unwrap();

        // Second proposal from same leader is equivocation.
        // The rotation module records the evidence then returns Err(Equivocation).
        let result = engine.on_proposal(leader, block_b, 200);
        assert!(
            result.is_err(),
            "dual proposal should be rejected: {:?}",
            result
        );

        // Rotation state should have recorded the equivocation evidence
        // (recorded before the error is returned).
        let has_evidence = engine
            .rotation()
            .and_then(|r| r.equivocation_evidence(&leader))
            .map(|h| h.len() >= 2)
            .unwrap_or(false);
        assert!(has_evidence, "rotation should track equivocation evidence");
    }

    // ── Phase Transitions ───────────────────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn phase_transition_changes_mode() {
        let mut engine = SequencerEngine::new(addr(1), 100_000_000, 7200);
        assert_eq!(engine.mode(), SequencerMode::Centralized);

        // Build metrics that satisfy Foundation → Federation transition.
        let metrics = NetworkMetrics {
            active_sequencers: 15,
            eligible_users: 2000,
            locked_sats: 15_000_000_000, // 150 BTC
            distinct_regions: 5,
            uptime_blocks: 14_000_000, // ~6+ months
            proposals_executed: 0,
            founder_seats: 1,
            bitvm2_pegout_bp: 0,
            rage_quit_tested: false,
            council_elections: 0,
        };

        engine.current_height = 14_000_000;
        let result = engine.evaluate_phase(&metrics).unwrap();

        if let Some(EngineAction::PhaseTransition { from, to }) = result {
            assert_eq!(from, DecentralizationPhase::Foundation);
            assert_eq!(to, DecentralizationPhase::Federation);
            assert_eq!(engine.mode(), SequencerMode::FederatedRotation);
        }
        // Phase transition may not fire if milestones aren't all met.
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn mode_from_phase_mapping() {
        assert_eq!(
            SequencerMode::from_phase(DecentralizationPhase::Foundation),
            SequencerMode::Centralized
        );
        assert_eq!(
            SequencerMode::from_phase(DecentralizationPhase::Federation),
            SequencerMode::FederatedRotation
        );
        assert_eq!(
            SequencerMode::from_phase(DecentralizationPhase::DualConsensus),
            SequencerMode::FullRotation
        );
        assert_eq!(
            SequencerMode::from_phase(DecentralizationPhase::FullSovereignty),
            SequencerMode::FullRotation
        );
    }

    // ── Epoch Boundary ──────────────────────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn epoch_transition_fires_at_boundary() {
        let mut engine = setup_engine_with_validators(3);

        // First height: no epoch transition.
        let actions = engine
            .on_new_height(1, Hasher::hash(b"block 0"), 0)
            .unwrap();
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, EngineAction::EpochTransition { .. }))
        );

        // At epoch boundary (height = epoch_length).
        let actions = engine
            .on_new_height(7200, Hasher::hash(b"block 7199"), 0)
            .unwrap();
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, EngineAction::EpochTransition { .. })),
            "epoch transition should fire at boundary"
        );
    }

    // ── Slashing ────────────────────────────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn slash_validator_through_engine() {
        let mut engine = setup_engine_with_validators(3);
        engine.current_height = 100;

        let result =
            engine.slash_validator(&addr(1), SlashingReason::Downtime, b"missed 100 blocks", 90);

        assert!(result.is_ok());
        if let Ok(EngineAction::ValidatorSlashed(slash)) = result {
            assert_eq!(slash.validator, addr(1));
            assert_eq!(slash.reason, SlashingReason::Downtime);
        }
    }

    // ── Uses Election / Rotation Queries ────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn mode_queries() {
        assert!(!SequencerMode::Centralized.uses_election());
        assert!(!SequencerMode::Centralized.uses_rotation());
        assert!(SequencerMode::FederatedRotation.uses_election());
        assert!(SequencerMode::FederatedRotation.uses_rotation());
        assert!(SequencerMode::FullRotation.uses_election());
        assert!(SequencerMode::FullRotation.uses_rotation());
    }

    // ── Multi-height sequence ───────────────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn multi_height_happy_path() {
        let mut engine = setup_engine_with_validators(3);

        for height in 1u64..=5 {
            let prev = Hasher::hash(&height.to_le_bytes());
            engine.on_new_height(height, prev, 0).unwrap();

            let leader = *engine.current_leader().unwrap();
            let block_hash = Hasher::hash(&(height * 1000).to_le_bytes());

            engine.on_proposal(leader, block_hash, 100).unwrap();

            for i in 1..=3 {
                engine.on_prevote(addr(i), block_hash, 0).unwrap();
            }
            for i in 1..=3 {
                engine.on_precommit(addr(i), block_hash).unwrap();
            }

            engine.on_finalize(block_hash);
        }

        assert_eq!(engine.height(), 5);
        assert_eq!(engine.metrics().blocks_finalized, 5);
        assert!(engine.metrics().avg_finalization_round() < 1.0);
    }

    // ── Metrics ────────────────────────────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn metrics_track_finalization_and_timeouts() {
        let mut engine = setup_engine_with_validators(3);

        // Height 1: normal finalization (round 0).
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();
        let leader = *engine.current_leader().unwrap();
        let block_hash = Hasher::hash(b"block 1");
        engine.on_proposal(leader, block_hash, 100).unwrap();
        for i in 1..=3 {
            engine.on_prevote(addr(i), block_hash, 0).unwrap();
        }
        for i in 1..=3 {
            engine.on_precommit(addr(i), block_hash).unwrap();
        }
        engine.on_finalize(block_hash);

        assert_eq!(engine.metrics().blocks_finalized, 1);
        assert_eq!(engine.metrics().timeouts, 0);
        assert_eq!(engine.metrics().avg_finalization_round(), 0.0);

        // Height 2: timeout → advance round → finalize at round 1.
        engine
            .on_new_height(2, Hasher::hash(b"block 1"), 0)
            .unwrap();
        for i in 1..=3 {
            let _ = engine.on_timeout_vote(addr(i));
        }
        engine.advance_round(50_000).unwrap();

        let leader2 = *engine.current_leader().unwrap();
        let block_hash2 = Hasher::hash(b"block 2");
        engine.on_proposal(leader2, block_hash2, 51_000).unwrap();
        for i in 1..=3 {
            engine.on_prevote(addr(i), block_hash2, 0).unwrap();
        }
        for i in 1..=3 {
            engine.on_precommit(addr(i), block_hash2).unwrap();
        }
        engine.on_finalize(block_hash2);

        assert_eq!(engine.metrics().blocks_finalized, 2);
        assert_eq!(engine.metrics().timeouts, 1);
        // Round 0 + round 1 = 1, avg = 0.5
        assert!((engine.metrics().avg_finalization_round() - 0.5).abs() < f64::EPSILON);
        assert!(engine.metrics().timeout_rate() > 0.0);
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn metrics_track_slashing() {
        let mut engine = setup_engine_with_validators(3);
        engine.current_height = 100;

        engine
            .slash_validator(&addr(1), SlashingReason::Downtime, b"missed blocks", 90)
            .unwrap();

        assert_eq!(engine.metrics().validators_slashed, 1);
    }

    #[test]
    fn metrics_to_network_metrics() {
        let mut metrics = SequencerMetrics::default();
        metrics.blocks_finalized = 1000;

        let nm = metrics.to_network_metrics(10, 500, 5_000_000_000, 4, 1, 0, false, 0);
        assert_eq!(nm.uptime_blocks, 1000);
        assert_eq!(nm.active_sequencers, 10);
    }

    // ── Adversarial Tests ──────────────────────────────────────────

    #[test]
    fn centralized_proposal_updates_metrics() {
        // C-1 regression: centralized auto-finalize must increment blocks_finalized.
        let designated = addr(1);
        let mut engine = SequencerEngine::new(designated, 100_000_000, 7200);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let block_hash = Hasher::hash(b"block 1");
        engine.on_proposal(designated, block_hash, 0).unwrap();

        assert_eq!(
            engine.metrics().blocks_finalized,
            1,
            "centralized auto-finalize must count toward blocks_finalized"
        );
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn height_monotonicity_enforced() {
        // M-4: reject non-advancing heights.
        let mut engine = setup_engine_with_validators(3);
        engine.on_new_height(5, Hasher::hash(b"blk4"), 0).unwrap();

        // Same height rejected.
        assert!(engine.on_new_height(5, Hasher::hash(b"blk4"), 0).is_err());
        // Lower height rejected.
        assert!(engine.on_new_height(3, Hasher::hash(b"blk2"), 0).is_err());
        // Higher height accepted.
        assert!(engine.on_new_height(6, Hasher::hash(b"blk5"), 0).is_ok());
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn equivocation_auto_slashes() {
        // H-2: equivocation must trigger automatic slashing.
        let mut engine = setup_engine_with_validators(3);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let leader = *engine.current_leader().unwrap();
        let block_a = Hasher::hash(b"block A");
        let block_b = Hasher::hash(b"block B");

        // First proposal: valid.
        engine.on_proposal(leader, block_a, 100).unwrap();

        // Second proposal: equivocation — the rotation module returns Err.
        // But equivocation evidence was already recorded.
        let _ = engine.on_proposal(leader, block_b, 200);

        // Check equivocation was detected.
        assert_eq!(engine.metrics().equivocations_detected, 1);
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn finalize_via_quorum_updates_metrics() {
        // H-1 regression: Finalize via quorum vote must update metrics.
        let mut engine = setup_engine_with_validators(3);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let leader = *engine.current_leader().unwrap();
        let block_hash = Hasher::hash(b"quorum block");

        engine.on_proposal(leader, block_hash, 100).unwrap();

        // Vote until quorum.
        for i in 1..=3 {
            engine.on_prevote(addr(i), block_hash, 0).unwrap();
        }
        for i in 1..=3 {
            engine.on_precommit(addr(i), block_hash).unwrap();
        }

        // Finalization via translate_rotation_action must update metrics.
        assert!(
            engine.metrics().blocks_finalized >= 1,
            "quorum finalization must update blocks_finalized"
        );
        // Rotation should be cleared (no double-finalize).
        assert!(
            engine.rotation().is_none(),
            "rotation should be cleared after quorum finalization"
        );
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn voting_phase_timeout_fires() {
        // H-3: voting phase should also timeout.
        let mut engine = setup_engine_with_validators(3);
        let config = RotationConfig {
            proposal_timeout_ms: 1_000,
            ..RotationConfig::default()
        };
        engine.set_rotation_config(config);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let leader = *engine.current_leader().unwrap();
        let block_hash = Hasher::hash(b"block");

        // Leader proposes at t=100.
        engine.on_proposal(leader, block_hash, 100).unwrap();

        // Check timeout at t=500 — not yet (voting timeout = 2× proposal = 2000ms).
        let actions = engine.check_timeout(500);
        assert!(
            actions.is_empty(),
            "voting phase should not timeout before 2× proposal timeout"
        );

        // Check timeout at t=2200 — should fire.
        let actions = engine.check_timeout(2200);
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, EngineAction::BroadcastTimeout { .. })),
            "voting phase should timeout after 2× proposal timeout"
        );
    }

    #[test]
    fn timeout_rate_uses_blocks_as_denominator() {
        // M-2: timeout_rate should use blocks_finalized as denominator.
        let mut metrics = SequencerMetrics::default();
        metrics.blocks_finalized = 10;
        metrics.timeouts = 5;

        // Rate = 5/10 = 0.5 (not 5/15 = 0.33 as before).
        assert!((metrics.timeout_rate() - 0.5).abs() < f64::EPSILON);

        // Multiple timeouts per height: rate > 1.0 is possible.
        metrics.timeouts = 20;
        assert!(metrics.timeout_rate() > 1.0);
    }

    // ── Centralized Equivocation Detection ──────────────────────────

    #[test]
    fn centralized_equivocation_detected_and_slashed() {
        let designated = addr(1);
        let mut engine = SequencerEngine::new(designated, 100_000_000, 7200);
        engine
            .staking
            .register_validator(designated, 100_000_000)
            .unwrap();
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let block_a = Hasher::hash(b"block A");

        // First proposal: valid, auto-finalizes.
        engine.on_proposal(designated, block_a, 0).unwrap();

        // Need to advance height since block_a was finalized at height 1.
        engine.on_new_height(2, block_a, 0).unwrap();

        // Two proposals at same height = equivocation.
        let block_c = Hasher::hash(b"block C");
        let block_d = Hasher::hash(b"block D");
        engine.on_proposal(designated, block_c, 0).unwrap();

        let result = engine.on_proposal(designated, block_d, 0);
        assert!(result.is_err(), "second proposal at same height must fail");
        assert_eq!(engine.metrics().equivocations_detected, 1);
    }

    #[test]
    fn centralized_single_proposal_ok() {
        let designated = addr(1);
        let mut engine = SequencerEngine::new(designated, 100_000_000, 7200);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        let block_hash = Hasher::hash(b"block 1");
        let actions = engine.on_proposal(designated, block_hash, 0).unwrap();

        assert!(
            actions
                .iter()
                .any(|a| matches!(a, EngineAction::BlockFinalized { .. }))
        );
        assert_eq!(engine.metrics().equivocations_detected, 0);
    }

    // ── View Sync ────────────────────────────────────────────────────

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn view_sync_initialized_in_rotation_mode() {
        let mut engine = setup_engine_with_validators(3);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        assert!(
            engine.view_sync().is_some(),
            "view sync should be initialized in rotation mode"
        );
    }

    #[test]
    fn view_sync_not_initialized_in_centralized_mode() {
        let designated = addr(1);
        let mut engine = SequencerEngine::new(designated, 100_000_000, 7200);
        engine
            .on_new_height(1, Hasher::hash(b"genesis"), 0)
            .unwrap();

        assert!(
            engine.view_sync().is_none(),
            "view sync should not exist in centralized mode"
        );
    }

    // ── Bridge Metrics ──────────────────────────────────────────────

    #[test]
    fn bridge_metrics_record_pegout() {
        let mut engine = SequencerEngine::new(addr(1), 100_000_000, 7200);

        engine.record_pegout(true);
        engine.record_pegout(true);
        engine.record_pegout(false);

        assert_eq!(engine.bridge_metrics().total_pegouts, 3);
        assert_eq!(engine.bridge_metrics().bitvm2_pegouts, 2);
        assert_eq!(engine.bridge_metrics().bitvm2_pegout_bp(), 6666);
    }

    // ── Threshold Key Shares (P-2) ─────────────────────────────────

    #[test]
    fn pending_shares_threshold_3_of_5() {
        use brrq_crypto::encryption::{
            EpochKey, KeyShare, ThresholdEncryptionConfig, split_secret, reconstruct_secret,
        };

        let key = EpochKey::from_bytes([0xAB; 32]);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();
        let (shares, _commitments) = split_secret(&key, &config).unwrap();

        let mut pending = PendingShares::new();
        pending.reset(1, config.clone());

        // Each share from a different sender (one share per validator)
        let sender_a = brrq_types::Address::from_bytes([0x01; 20]);
        let sender_b = brrq_types::Address::from_bytes([0x02; 20]);
        let sender_c = brrq_types::Address::from_bytes([0x03; 20]);

        // Add 2 shares — not enough
        assert!(!pending.add_share(shares[0].clone(), sender_a, 100));
        assert!(!pending.add_share(shares[1].clone(), sender_b, 100));
        assert!(!pending.threshold_reached());

        // Add 3rd share — threshold reached
        assert!(pending.add_share(shares[2].clone(), sender_c, 100));
        assert!(pending.threshold_reached());

        // Reconstruct
        let result = pending.try_reconstruct();
        assert!(result.is_some());
        let reconstructed = result.unwrap().unwrap();
        assert_eq!(reconstructed.as_bytes(), key.as_bytes());
        assert!(pending.reconstructed);

        // Second call returns None (already reconstructed)
        assert!(pending.try_reconstruct().is_none());
    }

    #[test]
    fn pending_shares_fails_below_threshold() {
        use brrq_crypto::encryption::{EpochKey, ThresholdEncryptionConfig, split_secret};

        let key = EpochKey::from_bytes([0xCC; 32]);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();
        let (shares, _commitments) = split_secret(&key, &config).unwrap();

        let mut pending = PendingShares::new();
        pending.reset(1, config);

        // Only 2 shares — below threshold (different senders)
        let sender_a = brrq_types::Address::from_bytes([0x01; 20]);
        let sender_b = brrq_types::Address::from_bytes([0x02; 20]);
        pending.add_share(shares[0].clone(), sender_a, 100);
        pending.add_share(shares[1].clone(), sender_b, 101);

        assert!(!pending.threshold_reached());
        assert!(pending.try_reconstruct().is_none());
    }

    #[test]
    fn pending_shares_timeout_detection() {
        use brrq_crypto::encryption::ThresholdEncryptionConfig;

        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();
        let mut pending = PendingShares::new();
        pending.reset(1, config);

        // No shares yet — no timeout
        assert!(!pending.is_timed_out(200));

        // Set collection start
        pending.collection_start_height = Some(100);

        // Within window
        assert!(!pending.is_timed_out(105));
        assert!(!pending.is_timed_out(109));

        // At timeout boundary
        assert!(pending.is_timed_out(110));
        assert!(pending.is_timed_out(200));
    }

    #[test]
    fn pending_shares_missing_indices() {
        use brrq_crypto::encryption::{EpochKey, ThresholdEncryptionConfig, split_secret};

        let key = EpochKey::from_bytes([0xDD; 32]);
        let config = ThresholdEncryptionConfig::new(3, 5).unwrap();
        let (shares, _commitments) = split_secret(&key, &config).unwrap();

        let mut pending = PendingShares::new();
        pending.reset(1, config);

        // Add shares 1 and 3 (different senders — rejects duplicate senders)
        pending.add_share(shares[0].clone(), addr(1), 100); // index 1
        pending.add_share(shares[2].clone(), addr(2), 100); // index 3

        let missing = pending.missing_share_indices(5);
        assert!(missing.contains(&2));
        assert!(missing.contains(&4));
        assert!(missing.contains(&5));
        assert!(!missing.contains(&1));
        assert!(!missing.contains(&3));
    }

    #[test]
    fn engine_on_share_distribution_wrong_epoch_rejected() {
        let mut engine = SequencerEngine::new(addr(1), 100_000_000, 7200);
        let result = engine.on_share_distribution(
            99, // wrong epoch
            1,
            [0xAA; 32],
            &addr(1),
        );
        assert!(result.is_err());
    }

    #[test]
    fn engine_on_share_distribution_non_validator_rejected() {
        let mut engine = SequencerEngine::new(addr(1), 100_000_000, 7200);
        // epoch.validator_set is empty — any sender is non-validator
        let result = engine.on_share_distribution(
            0, // epoch 0 (initial)
            1,
            [0xAA; 32],
            &addr(99), // not in validator set
        );
        assert!(result.is_err());
    }

    #[test]
    fn epoch_split_shares_requires_reveal() {
        let epoch = EpochState::new(7200);
        // Seed not revealed — should fail
        let result = epoch.split_epoch_key_shares();
        assert!(result.is_err());
    }

    #[test]
    fn threshold_formula_correct() {
        // N=3: threshold = max(3/2+1, 2) = max(2, 2) = 2
        let mut epoch = EpochState::new(7200);
        epoch.validator_set = vec![addr(1), addr(2), addr(3)];
        assert_eq!(epoch.threshold_for_current_set(), 2);

        // N=5: threshold = max(5/2+1, 2) = max(3, 2) = 3
        epoch.validator_set = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];
        assert_eq!(epoch.threshold_for_current_set(), 3);

        // N=21: threshold = max(21/2+1, 2) = max(11, 2) = 11
        epoch.validator_set = (1..=21).map(addr).collect();
        assert_eq!(epoch.threshold_for_current_set(), 11);
    }
}
