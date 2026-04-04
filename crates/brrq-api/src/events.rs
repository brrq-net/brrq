//! Node events for WebSocket subscriptions and indexer.

use serde::{Deserialize, Serialize};

/// Events that can be pushed to WebSocket subscribers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum NodeEvent {
    /// A new block was produced or applied.
    NewBlock {
        height: u64,
        hash: String,
        tx_count: usize,
        timestamp: u64,
        gas_used: u64,
    },
    /// A new transaction entered the mempool.
    PendingTransaction {
        hash: String,
        from: String,
        kind: String,
    },
    /// A new batch STARK proof was generated.
    NewProof {
        block_range_start: u64,
        block_range_end: u64,
        verified: bool,
        generation_time_ms: u64,
    },
    /// A state anchor was posted to Bitcoin L1.
    L1Anchor {
        l2_height: u64,
        l1_tx_id: String,
        /// Hex-formatted state root (e.g., "0xabcd...") for consistent JSON serialization.
        state_root: String,
    },
    /// Bitcoin L1 connection status changed.
    L1StatusChanged { connected: bool, l1_height: u64 },
    /// A challenge was submitted against a withdrawal or anchor.
    ChallengeSubmitted {
        challenge_id: String,
        challenge_type: String,
        challenger: String,
    },
    /// A challenge was resolved.
    ChallengeResolved {
        challenge_id: String,
        status: String,
    },
    /// A withdrawal was completed.
    WithdrawalCompleted {
        withdrawal_id: String,
        amount: u64,
        btc_destination: String,
        permissionless: bool,
    },
    /// A batch proof was stored in the proof store.
    ProofStored {
        block_range_start: u64,
        block_range_end: u64,
        stark_proof_hash: String,
    },
    /// A governance proposal was submitted.
    GovernanceProposalSubmitted {
        proposal_id: String,
        proposer: String,
        proposal_type: String,
    },
    /// A vote was cast on a governance proposal.
    GovernanceVoteCast {
        proposal_id: String,
        voter: String,
        chamber: String,
        vote: String,
    },
    /// A governance proposal was finalized.
    GovernanceProposalFinalized { proposal_id: String, status: String },
    /// A new sequencer was registered.
    SequencerRegistered {
        address: String,
        stake: u64,
        region: String,
    },
    /// MEV protection phase changed.
    MevPhaseChanged { phase: String, epoch: u64 },
    /// Stake was delegated to a sequencer.
    StakeDelegated {
        delegator: String,
        sequencer: String,
        amount: u64,
    },
    /// Stake was undelegated from a sequencer.
    StakeUndelegated {
        delegator: String,
        sequencer: String,
        amount: u64,
    },
    /// A prover pool was created.
    #[cfg(feature = "prover-pools")]
    ProverPoolCreated {
        pool_id: String,
        coordinator: String,
        name: String,
    },
    /// A member joined a prover pool.
    #[cfg(feature = "prover-pools")]
    ProverPoolJoined { pool_id: String, member: String },
    // ── Portal (L3) Events ────────────────────────────────────────
    /// A Portal escrow lock was created.
    PortalLockCreated {
        lock_id: String,
        owner: String,
        amount: u64,
        timeout_l2_block: u64,
    },
    /// A Portal lock was settled (funds transferred to merchant).
    PortalLockSettled {
        lock_id: String,
        merchant: String,
        amount: u64,
    },
    /// A Portal lock expired (funds returned to owner).
    PortalLockExpired {
        lock_id: String,
        owner: String,
        amount: u64,
    },
    /// A batch of Portal locks was settled.
    PortalBatchSettled {
        succeeded: u64,
        failed: u64,
        total: u64,
    },
    /// A Portal lock was cancelled by the owner.
    PortalLockCancelled {
        lock_id: String,
        owner: String,
        amount: u64,
    },
    /// Proof gap detected — fallback prover activated.
    ProverStrikeDetected {
        proof_gap: u64,
        last_proved_height: u64,
        current_height: u64,
    },
}

/// Subscription topics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SubscriptionTopic {
    #[serde(rename = "newBlocks")]
    NewBlocks,
    #[serde(rename = "pendingTxs")]
    PendingTxs,
    #[serde(rename = "newProofs")]
    NewProofs,
    #[serde(rename = "l1Events")]
    L1Events,
    #[serde(rename = "bridgeEvents")]
    BridgeEvents,
    #[serde(rename = "governance")]
    Governance,
    #[serde(rename = "mevEvents")]
    MevEvents,
    #[serde(rename = "portalEvents")]
    PortalEvents,
}

/// Create a broadcast channel for node events.
pub fn create_event_channel() -> (
    tokio::sync::broadcast::Sender<NodeEvent>,
    tokio::sync::broadcast::Receiver<NodeEvent>,
) {
    tokio::sync::broadcast::channel(1024)
}
