//! Brrq consensus — PoS with √x effective stake cap.
//!
//! ## Architecture (§9)
//!
//! - **Staking**: Validators lock BTC in Taproot contracts on L1
//! - **√x Cap**: `EffectiveStake = min(stake, Cap + √(stake - Cap))`
//!   prevents wealth-based monopoly
//! - **Leader Election**: Deterministic hash-based VRF proportional to effective stake
//! - **Slashing**: Graduated penalties (5% downtime, 15% delay, 33.33% equivocation)
//! - **Epochs**: Periodic key rotation, cap recalculation, timeout resets
//! - **View Sync**: Partition recovery via timeout certificates
//!
//! ## Finality
//!
//! After 2/3 quorum finalizes a block, it is considered settled after
//! `finality_depth` subsequent blocks (default: 1). Quorum calculations
//! use a validator-set snapshot taken at rotation start, ensuring that
//! mid-round stake changes (e.g., slashing) cannot retroactively
//! invalidate finality decisions.
//!
//! ## Dual Signing (§3.6)
//!
//! Every block is signed with:
//! 1. **EOTS** (Schnorr/nonce-based) — immediate self-enforcing slashing
//! 2. **SLH-DSA** — quantum-resistant fraud proof
//!
//! ## Launch Phases — Module Activation Plan
//!
//! ### Foundation Launch — REQUIRED at genesis:
//! - `staking` — Validator registration + √x cap
//! - `epoch` — RANDAO commit-reveal + key rotation
//! - `leader_election` — Deterministic block producer selection
//! - `slashing` — Equivocation detection + graduated penalties
//! - `fee_market` — EIP-1559 dynamic base fee + distribution
//! - `governance` — Basic proposal submission + voting (limited)
//! - `emergency` — Pause/freeze capability for critical incidents
//! - `validator` — Validator state + reputation tracking
//!
//! ### Governance Extensions (governance-extensions feature) — Activated after milestones:
//! - `technical_council` — 7-member security veto + reports
//! - `vote_escrow` — Flash-loan protection for governance
//! - `commit_reveal` — Anti-Dark-DAO encrypted voting
//! - `doctrine_firewall` — Three Immutable Laws enforcement
//! - `timelock` — Execution delay for passed proposals
//! - `fork_logic` — Soft/hard fork signaling + activation
//! - `decentralization` — Phase transition tracking
//! - `deprecation` — EOTS deprecation gate

// ── Governance extensions (behind `governance-extensions` feature) ───────────
#[cfg(feature = "governance-extensions")]
pub mod commit_reveal;
#[cfg(feature = "governance-extensions")]
pub mod deprecation;
#[cfg(feature = "governance-extensions")]
pub mod doctrine_firewall;
#[cfg(feature = "governance-extensions")]
pub mod fork_logic;
#[cfg(feature = "governance-extensions")]
pub mod technical_council;
#[cfg(feature = "governance-extensions")]
pub mod timelock;
#[cfg(feature = "governance-extensions")]
pub mod vote_escrow;

// ── Core consensus (always compiled) ─────────────────────────────────────────
pub mod decentralization;
pub mod emergency;
pub mod epoch;
pub mod error;
pub mod fee_market;
pub mod governance;
pub mod leader_election;
pub mod params;
#[cfg(feature = "sequencer-rotation")]
pub mod registration;
#[cfg(feature = "sequencer-rotation")]
pub mod rotation;
pub mod sequencer_engine;
pub mod slashing;
pub mod staking;
pub mod validator;
pub mod view_sync;
pub mod wire;

// ── Re-exports: core ────────────────────────────────────────────────────────
pub use emergency::{EmergencyLevel, EmergencyManager};
pub use epoch::EpochState;
pub use error::ConsensusError;
pub use fee_market::{BlockFeeDistribution, FeeMarket, TransactionFeeBreakdown};
pub use governance::{
    GOVERNANCE_STAKE_COOLDOWN_BLOCKS, GovernanceManager, GovernanceVote,
    calculate_governance_voting_power,
};
pub use leader_election::{LeaderElection, VrfOutput, elect_leader, verify_leader_vrf};
pub use params::ConsensusParams;
#[cfg(feature = "sequencer-rotation")]
pub use registration::{Region, RegistrationManager, SequencerRegistration};
#[cfg(feature = "sequencer-rotation")]
pub use rotation::{RotationAction, RotationConfig, RotationPhase, RotationState};
pub use sequencer_engine::{
    EngineAction, PendingShares, SequencerEngine, SequencerMode, SHARE_TIMEOUT_BLOCKS,
};
pub use slashing::{SlashResult, SlashingEngine, SlashingReason};
pub use staking::{StakingState, graduated_min_stake};
pub use validator::{Validator, ValidatorStatus};
pub use view_sync::{TimeoutCertificate, ViewSyncState, timeout_vote_signing_message};
pub use wire::{ConsensusMessage, ShareDistributionMessage};

pub use decentralization::{BridgeMetrics, DecentralizationPhase, DecentralizationTracker};

// ── Re-exports: governance-extensions ───────────────────────────────────────
#[cfg(feature = "governance-extensions")]
pub use commit_reveal::{CommitRevealEvent, CommitRevealManager};
#[cfg(feature = "governance-extensions")]
pub use doctrine_firewall::{DoctrineCheckResult, DoctrineFirewall};
#[cfg(feature = "governance-extensions")]
pub use fork_logic::{ForkManager, ForkState, ForkType};
#[cfg(feature = "governance-extensions")]
pub use technical_council::TechnicalCouncil;
#[cfg(feature = "governance-extensions")]
pub use timelock::{TimeLockEvent, TimeLockManager};
#[cfg(feature = "governance-extensions")]
pub use vote_escrow::VoteEscrowManager;
