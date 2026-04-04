//! Two-chamber governance system (whitepaper section 14.2).
//!
//! ## Architecture
//!
//! Brrq governance uses a bicameral (two-chamber) system:
//!
//! 1. **Sequencer Chamber**: Validators vote weighted by effective stake
//! 2. **User Chamber**: Eligible users vote with equal weight (1 person = 1 vote)
//!
//! ## Sybil Protection (3-Layer)
//!
//! Users must satisfy ALL of:
//! - Minimum 10 transactions in the last 90 days
//! - Minimum balance of 0.01 BTC (1,000,000 satoshis)
//! - Account age >= 60 days (1,728,000 blocks at 3s/block)
//!
//! ## Approval Thresholds
//!
//! | Proposal Type     | Sequencer Threshold | User Threshold |
//! |-------------------|---------------------|----------------|
//! | TechnicalUpdate   | 67%                 | —              |
//! | FeeChange         | 67%                 | 51%            |
//! | SlashingChange    | 67%                 | 75%            |
//! | Constitutional    | 90%                 | 90%            |

use imbl::HashMap;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_types::Address;
use serde::{Deserialize, Serialize};

use crate::ConsensusError;
#[cfg(feature = "governance-extensions")]
use crate::doctrine_firewall::{DoctrineCheckResult, DoctrineFirewall, ProposalDoctrineCheck};
use crate::params::ConsensusParams;
use crate::staking::StakingState;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Sequencer chamber approval threshold: 67% (in basis points).
pub const SEQUENCER_THRESHOLD_BP: u64 = 6700;

/// User chamber approval threshold: 51% (in basis points).
pub const USER_THRESHOLD_BP: u64 = 5100;

/// Super-majority threshold: 75% (in basis points).
pub const SUPER_MAJORITY_BP: u64 = 7500;

/// Constitutional amendment threshold: 90% (in basis points).
pub const CONSTITUTIONAL_BP: u64 = 9000;

/// Minimum number of transactions in the last 90 days for voting eligibility.
pub const MIN_TX_FOR_VOTING: u64 = 10;

/// Minimum balance in satoshis for voting eligibility (0.01 BTC).
/// Set at 1,000,000 sats to increase the cost of Sybil vote-buying
/// attacks under quadratic voting.
pub const MIN_BALANCE_FOR_VOTING: u64 = 1_000_000;

/// Minimum account age in blocks for voting eligibility (~60 days at 3s/block).
pub const MIN_ACCOUNT_AGE_BLOCKS: u64 = 1_728_000;

/// Voting period duration in blocks (~7 days at 3s/block).
pub const VOTING_PERIOD_BLOCKS: u64 = 201_600;

/// Cooldown between proposals from the same address in blocks (~24 hours).
pub const PROPOSAL_COOLDOWN_BLOCKS: u64 = 28_800;

/// Minimum number of user-chamber voters required for quorum.
pub const MIN_USER_QUORUM: u64 = 10;

/// Minimum effective stake required to submit a governance proposal (0.1 BTC).
///
/// To prevent proposal spam, a proposer must hold at least this stake
/// multiplied by `(active_proposals_by_proposer + 1)`. This ensures that
/// creating many simultaneous proposals requires proportionally more stake.
pub const MIN_PROPOSAL_STAKE: u64 = 10_000_000;

/// Execution window: number of blocks after a proposal passes during which
/// it must be executed. After this window, execution is rejected.
/// ~1 day at 3s/block.
pub const EXECUTION_WINDOW_BLOCKS: u64 = 28_800;

// ═══════════════════════════════════════════════════════════════
// Time-Locked Governance with Community Veto
// ═══════════════════════════════════════════════════════════════
//
// Problem: Foundation governance allows the founding team to execute
// protocol upgrades unilaterally immediately after a vote passes.
// This eliminates the community's ability to react to malicious
// or poorly-considered changes.
//
// Solution: Mandatory time-lock between vote passage and execution,
// during which validators/community can veto the proposal. The team
// cannot bypass the time-lock under any circumstances.

/// Time-lock duration for TechnicalUpdate proposals (~3 days at 3s/block).
///
/// This is the minimum waiting period between a proposal passing and
/// being executable. During this window, validators can submit vetoes.
pub const TIMELOCK_TECHNICAL_BLOCKS: u64 = 86_400;

/// Time-lock duration for FeeChange proposals (~5 days).
pub const TIMELOCK_FEE_BLOCKS: u64 = 144_000;

/// Time-lock duration for SlashingChange proposals (~7 days).
pub const TIMELOCK_SLASHING_BLOCKS: u64 = 201_600;

/// Time-lock duration for Constitutional amendments (~14 days).
pub const TIMELOCK_CONSTITUTIONAL_BLOCKS: u64 = 403_200;

/// Veto threshold: percentage of total effective stake required to veto
/// a time-locked proposal (in basis points). 33.33% = 3333bp.
///
/// This is a deliberately low threshold because vetoes are a defensive
/// mechanism — a minority should be able to block potentially harmful
/// changes. The supermajority already voted Yes; the veto is a safety
/// valve for the minority that voted No or didn't participate.
pub const VETO_THRESHOLD_BP: u64 = 3333;

/// User-chamber veto threshold: percentage of participating user vote
/// power required to veto (in basis points). 25% = 2500bp.
///
/// Even lower than the sequencer threshold because users have less
/// coordination ability and the veto is a protective mechanism.
pub const USER_VETO_THRESHOLD_BP: u64 = 2500;

/// Minimum number of distinct veto voters required for a valid veto.
/// Prevents a single whale from unilaterally vetoing everything.
pub const MIN_VETO_VOTERS: u64 = 3;

// ═══════════════════════════════════════════════════════════════
// Anti-Sybil Governance — Stake Cooldown
// ═══════════════════════════════════════════════════════════════

/// Cooldown period in blocks before newly staked funds gain governance
/// voting power (~1 day at 3s/block).
///
/// This prevents "vote-and-dump" attacks where an attacker:
/// 1. Stakes tokens just before a vote
/// 2. Votes with the freshly staked weight
/// 3. Immediately unbonds after voting
///
/// During the cooldown window, the stake exists for consensus purposes
/// (block production, slashing) but carries ZERO governance voting power.
pub const GOVERNANCE_STAKE_COOLDOWN_BLOCKS: u64 = 28_800;

/// Calculate governance voting power for a validator.
///
/// Voting power is proportional to staked amount (effective stake),
/// but ONLY if the stake has been locked for at least
/// `GOVERNANCE_STAKE_COOLDOWN_BLOCKS`.
///
/// This function is the core anti-Sybil mechanism for the sequencer chamber:
/// - 1000 accounts with 1 BRQ each == 1 account with 1000 BRQ
///   (stake-weighted, not identity-weighted)
/// - Newly staked funds have 0 voting power during cooldown
///
/// # Arguments
///
/// * `effective_stake` - The validator's effective stake (after √x cap).
/// * `stake_registered_at` - Block height when the validator registered
///   (or last increased stake).
/// * `current_block` - Current chain tip block height.
///
/// # Returns
///
/// The governance voting power: `effective_stake` if cooldown has passed,
/// `0` otherwise.
pub fn calculate_governance_voting_power(
    effective_stake: u64,
    stake_registered_at: u64,
    current_block: u64,
) -> u64 {
    // Zero voting power during cooldown period
    // Note: If stake_registered_at is near u64::MAX, the saturating_add
    // will cap at u64::MAX, permanently denying voting power. This is
    // fail-safe (denies rather than grants) and is acceptable since such
    // values indicate corrupted or malicious registration data.
    if current_block < stake_registered_at.saturating_add(GOVERNANCE_STAKE_COOLDOWN_BLOCKS) {
        return 0;
    }
    effective_stake
}

// ═══════════════════════════════════════════════════════════════
// Quadratic Vote Power
// ═══════════════════════════════════════════════════════════════

/// Vote power computed as sqrt(balance_in_satoshis).
///
/// Quadratic voting prevents plutocratic capture: buying 2x the influence
/// requires 4x the capital. Combined with the raised MIN_BALANCE_FOR_VOTING,
/// this makes Sybil vote-buying exponentially more expensive.
///
/// Example: 1 BTC (100M sat) → vote power = √100M = 10,000
///          4 BTC (400M sat) → vote power = √400M = 20,000 (only 2x, not 4x)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VotePower(pub u64);

impl VotePower {
    /// Compute vote power from a balance in satoshis.
    /// `VotePower = floor(√balance)`
    pub fn from_balance(balance_sat: u64) -> Self {
        VotePower(integer_sqrt_gov(balance_sat))
    }

    /// Get the raw vote power value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Uses shared integer_sqrt from staking module.
use crate::staking::integer_sqrt as integer_sqrt_gov;

/// Maximum number of active governance proposals to prevent unbounded
/// storage growth from spam proposal creation.
pub const MAX_ACTIVE_PROPOSALS: u64 = 128;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// The type of governance proposal, which determines the required approval level.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalType {
    /// Technical protocol update (sequencer-only vote).
    TechnicalUpdate {
        /// Description of the technical change.
        description: String,
    },
    /// Change to fee parameters (both chambers required).
    FeeChange {
        /// Name of the fee parameter being changed.
        parameter: String,
        /// Current value.
        old_value: u64,
        /// Proposed new value.
        new_value: u64,
    },
    /// Change to slashing parameters (super-majority required).
    SlashingChange {
        /// Reason / description of the slashing parameter being changed.
        reason: String,
        /// Current penalty in basis points.
        old_bp: u64,
        /// Proposed new penalty in basis points.
        new_bp: u64,
    },
    /// Constitutional amendment (90% both chambers).
    Constitutional {
        /// Text of the constitutional amendment.
        amendment: String,
    },
}

/// Required approval level for a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequiredApproval {
    /// Only the sequencer chamber needs to approve (67%).
    SequencersOnly,
    /// Both chambers: sequencers at 67%, users at 51%.
    BothChambers,
    /// Both chambers with super-majority: sequencers at 67%, users at 75%.
    BothSuperMajority,
    /// Constitutional: both chambers at 90%.
    Constitutional,
}

/// A single vote cast by a participant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Vote {
    /// In favor of the proposal.
    Yes,
    /// Against the proposal.
    No,
    /// Present but abstaining.
    Abstain,
}

/// Current status of a governance proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Voting is open.
    Active,
    /// Voting concluded; proposal approved. Enters time-lock period.
    Passed,
    /// Voting concluded; proposal rejected.
    Failed,
    /// Proposal has been executed on-chain.
    Executed,
    /// Proposal was cancelled by its proposer.
    Cancelled,
    /// Proposal was vetoed during the time-lock period.
    /// This is a terminal state — the proposal cannot be re-submitted
    /// without a new proposal cycle.
    Vetoed,
}

/// A structured governance vote record.
///
/// Captures all metadata for a single vote, including stake-weighted
/// voting power and the block at which the voter's stake was locked.
/// This enables post-hoc auditing of governance decisions and ensures
/// that stake cooldown rules were enforced at vote time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceVote {
    /// The voter's address.
    pub voter: Address,
    /// The proposal being voted on.
    pub proposal_id: Hash256,
    /// The vote choice.
    pub vote: Vote,
    /// Stake-weighted voting power at time of vote.
    /// For sequencer chamber: effective_stake (after √x cap).
    /// For user chamber: sqrt(balance) (quadratic voting).
    pub stake_weight: u64,
    /// Block height when the voter's stake was locked/registered.
    /// Used to verify that GOVERNANCE_STAKE_COOLDOWN_BLOCKS has elapsed.
    pub stake_lock_block: u64,
}

/// Cached voter eligibility data used for Sybil protection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoterEligibility {
    /// The voter's address.
    pub address: Address,
    /// Number of transactions in the last 90 days.
    pub tx_count_90d: u64,
    /// Current balance in satoshis.
    pub balance: u64,
    /// Block height of the voter's first transaction.
    pub first_tx_height: u64,
}

/// A governance proposal with votes from both chambers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique proposal identifier (hash of proposer + height + type).
    pub id: Hash256,
    /// Address of the account that submitted this proposal.
    pub proposer: Address,
    /// The type and content of the proposal.
    pub proposal_type: ProposalType,
    /// The required approval level.
    pub required_approval: RequiredApproval,
    /// Block height at which the proposal was submitted.
    pub submitted_at: u64,
    /// Block height at which voting ends.
    pub voting_ends_at: u64,
    /// Current status of the proposal.
    pub status: ProposalStatus,
    /// Sequencer votes: address -> (vote, stake weight).
    pub sequencer_votes: HashMap<Address, (Vote, u64)>,
    /// User votes: address -> (vote, vote_power).
    /// Vote power is sqrt(balance) under quadratic voting.
    pub user_votes: HashMap<Address, (Vote, u64)>,
    /// Total effective stake that voted Yes in the sequencer chamber.
    pub sequencer_yes_stake: u64,
    /// Total effective stake that voted No in the sequencer chamber.
    pub sequencer_no_stake: u64,
    /// Total user Yes vote power (quadratic-weighted).
    pub user_yes_power: u64,
    /// Total user No vote power (quadratic-weighted).
    pub user_no_power: u64,
    /// Total user Abstain vote power (quadratic-weighted).
    pub user_abstain_power: u64,
    /// Execution deadline: block height by which the proposal must be executed.
    /// Set when the proposal transitions to Passed. None while Active/Failed.
    pub execution_deadline: Option<u64>,
    /// Snapshot of total effective stake at proposal submission time.
    /// Used at finalization to prevent vote-then-unbond attacks where validators
    /// vote and then unbond to artificially inflate their percentage.
    pub snapshot_total_effective_stake: u64,
    /// Block height at which the time-lock expires and the proposal
    /// becomes executable. Set when the proposal transitions to Passed.
    /// During the time-lock, validators/community can submit vetoes.
    pub timelock_expires_at: Option<u64>,
    /// Whether the proposal has been vetoed during the time-lock period.
    pub vetoed: bool,
    /// Veto votes from validators (stake-weighted).
    pub veto_sequencer_stake: u64,
    /// Veto votes from users (quadratic-weighted).
    pub veto_user_power: u64,
    /// Set of addresses that have submitted veto votes.
    pub veto_voters: std::collections::HashSet<Address>,
}

/// Aggregate governance statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GovernanceStats {
    /// Total proposals ever submitted.
    pub total_proposals: u64,
    /// Currently active proposals (voting open).
    pub active_proposals: u64,
    /// Proposals that passed.
    pub passed_proposals: u64,
    /// Proposals that failed.
    pub failed_proposals: u64,
    /// Proposals that have been executed.
    pub executed_proposals: u64,
    /// Number of unique addresses that have ever voted.
    pub total_unique_voters: u64,
}

// ═══════════════════════════════════════════════════════════════
// GovernanceManager
// ═══════════════════════════════════════════════════════════════

/// Manages the two-chamber governance system.
///
/// Tracks proposals, votes, voter eligibility, and governance statistics.
#[derive(Debug, Clone)]
pub struct GovernanceManager {
    /// All proposals keyed by their unique ID.
    pub proposals: HashMap<Hash256, Proposal>,
    /// Cached voter eligibility data.
    pub voter_eligibility: HashMap<Address, VoterEligibility>,
    /// Aggregate statistics.
    pub stats: GovernanceStats,
    /// Tracks the last proposal submission height per address (cooldown enforcement).
    pub last_proposal: HashMap<Address, u64>,
    /// Set of all unique voter addresses (for stats tracking).
    unique_voters: std::collections::HashSet<Address>,
    /// Optional runtime-configurable consensus parameters.
    /// When `None`, governance constants fall back to module-level `const` values.
    /// Future governance proposals can update these at runtime.
    params: Option<ConsensusParams>,
}

impl Default for GovernanceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl GovernanceManager {
    /// Create a new, empty governance manager.
    pub fn new() -> Self {
        Self {
            proposals: HashMap::new(),
            voter_eligibility: HashMap::new(),
            stats: GovernanceStats::default(),
            last_proposal: HashMap::new(),
            unique_voters: std::collections::HashSet::new(),
            params: None,
        }
    }

    /// Set runtime-configurable consensus parameters.
    ///
    /// When set, governance uses these values instead of module-level constants.
    pub fn set_params(&mut self, params: ConsensusParams) {
        self.params = Some(params);
    }

    fn voting_period(&self) -> u64 {
        self.params
            .as_ref()
            .map_or(VOTING_PERIOD_BLOCKS, |p| p.voting_period_blocks)
    }

    fn proposal_cooldown(&self) -> u64 {
        self.params
            .as_ref()
            .map_or(PROPOSAL_COOLDOWN_BLOCKS, |p| p.proposal_cooldown_blocks)
    }

    fn min_proposal_stake(&self) -> u64 {
        self.params
            .as_ref()
            .map_or(MIN_PROPOSAL_STAKE, |p| p.min_proposal_stake)
    }

    fn min_user_quorum(&self) -> u64 {
        self.params
            .as_ref()
            .map_or(MIN_USER_QUORUM, |p| p.min_user_quorum)
    }

    fn execution_window(&self) -> u64 {
        self.params
            .as_ref()
            .map_or(EXECUTION_WINDOW_BLOCKS, |p| p.execution_window_blocks)
    }

    /// Check that a proposal exists, is Active, and the voting period has not ended.
    /// Returns a reference to the proposal on success.
    fn check_proposal_votable<'a>(
        proposals: &'a HashMap<Hash256, Proposal>,
        proposal_id: &Hash256,
        current_height: u64,
    ) -> Result<&'a Proposal, ConsensusError> {
        let proposal =
            proposals
                .get(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("proposal not found: {}", proposal_id),
                })?;

        if proposal.status != ProposalStatus::Active {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("proposal {} is not active", proposal_id),
            });
        }

        if current_height >= proposal.voting_ends_at {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "voting period ended for proposal {} at block {}",
                    proposal_id, proposal.voting_ends_at,
                ),
            });
        }

        Ok(proposal)
    }

    /// Submit a new governance proposal.
    ///
    /// # Rules
    /// - `ProposalType` determines the `RequiredApproval` level.
    /// - A 24-hour cooldown is enforced between proposals from the same address.
    /// - `TechnicalUpdate` proposals require the proposer to be a registered validator.
    ///
    /// # Errors
    /// Returns `ConsensusError::InvalidBlock` if any precondition fails.
    pub fn submit_proposal(
        &mut self,
        proposer: Address,
        proposal_type: ProposalType,
        current_height: u64,
        staking: &StakingState,
    ) -> Result<Hash256, ConsensusError> {
        // Enforce cooldown: 24h between proposals per address
        let cooldown = self.proposal_cooldown();
        if let Some(&last_height) = self.last_proposal.get(&proposer)
            && current_height < last_height.saturating_add(cooldown)
        {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "proposal cooldown: address {} must wait until block {} (current: {})",
                    proposer,
                    last_height.saturating_add(cooldown),
                    current_height,
                ),
            });
        }

        // Limit active proposals to prevent unbounded storage growth.
        if self.stats.active_proposals >= MAX_ACTIVE_PROPOSALS {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "maximum active proposals reached ({}/{})",
                    self.stats.active_proposals, MAX_ACTIVE_PROPOSALS,
                ),
            });
        }

        // Sybil protection: proposer must hold sufficient effective stake.
        // Required stake scales with the number of active proposals by this address.
        if let Ok(proposer_stake) = staking.effective_stake(&proposer) {
            let active_by_proposer = self
                .proposals
                .values()
                .filter(|p| p.proposer == proposer && p.status == ProposalStatus::Active)
                .count() as u64;
            let required = self
                .min_proposal_stake()
                .saturating_mul(active_by_proposer.saturating_add(1));
            if proposer_stake < required {
                return Err(ConsensusError::InsufficientStake {
                    required,
                    actual: proposer_stake,
                });
            }
        }
        // If proposer is not a validator, the TechnicalUpdate check below
        // will catch it. Non-validator proposers for other types are allowed
        // without the stake check (they use the user chamber).

        // TechnicalUpdate requires the proposer to be a registered validator
        if matches!(proposal_type, ProposalType::TechnicalUpdate { .. })
            && !staking.validators.contains_key(&proposer)
        {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "technical update proposals require a registered validator: {}",
                    proposer,
                ),
            });
        }

        // Doctrine firewall: reject proposals that violate immutable laws
        #[cfg(feature = "governance-extensions")]
        {
            let doctrine_check = proposal_to_doctrine_check(&proposal_type);
            if let DoctrineCheckResult::Rejected {
                law_number, reason, ..
            } = DoctrineFirewall::validate(&doctrine_check)
            {
                return Err(ConsensusError::DoctrineViolation { law_number, reason });
            }
        }

        // Determine required approval level
        let required_approval = required_approval_for(&proposal_type);

        // Compute deterministic proposal ID
        let id = compute_proposal_id(&proposer, current_height, &proposal_type);

        let proposal = Proposal {
            id,
            proposer,
            proposal_type,
            required_approval,
            submitted_at: current_height,
            voting_ends_at: current_height.saturating_add(self.voting_period()),
            status: ProposalStatus::Active,
            sequencer_votes: HashMap::new(),
            user_votes: HashMap::new(),
            sequencer_yes_stake: 0,
            sequencer_no_stake: 0,
            user_yes_power: 0,
            user_no_power: 0,
            user_abstain_power: 0,
            execution_deadline: None,
            snapshot_total_effective_stake: staking.total_effective_stake(),
            timelock_expires_at: None,
            vetoed: false,
            veto_sequencer_stake: 0,
            veto_user_power: 0,
            veto_voters: std::collections::HashSet::new(),
        };

        if self.proposals.contains_key(&id) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("proposal with this ID already exists: {}", id),
            });
        }

        self.proposals.insert(id, proposal);
        self.last_proposal.insert(proposer, current_height);
        self.stats.total_proposals += 1;
        self.stats.active_proposals += 1;

        Ok(id)
    }

    /// Cast a vote in the sequencer (validator) chamber.
    ///
    /// The vote weight equals the voter's effective stake in the staking system.
    ///
    /// # Rules
    /// - Voter must be a registered validator.
    /// - No double voting.
    /// - Voting period must still be active.
    ///
    /// # Errors
    /// Returns `ConsensusError::InvalidBlock` if any precondition fails.
    pub fn vote_sequencer(
        &mut self,
        proposal_id: &Hash256,
        voter: Address,
        vote: Vote,
        staking: &StakingState,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let proposal = Self::check_proposal_votable(&self.proposals, proposal_id, current_height)?;

        // Voter must be a registered validator
        let validator =
            staking
                .validators
                .get(&voter)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("sequencer voter is not a registered validator: {}", voter),
                })?;

        // Voter must be in Active status (not Suspended, Unbonding, or Removed)
        if validator.status != crate::validator::ValidatorStatus::Active {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "sequencer voter {} is not active (status: {:?})",
                    voter, validator.status,
                ),
            });
        }

        // No double voting
        if proposal.sequencer_votes.contains_key(&voter) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "sequencer {} has already voted on proposal {}",
                    voter, proposal_id,
                ),
            });
        }

        // Reject if voter already voted in the user chamber.
        if proposal.user_votes.contains_key(&voter) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "sequencer {} already voted as user on proposal {}",
                    voter, proposal_id,
                ),
            });
        }

        // Get effective stake for vote weight
        let raw_stake = staking.effective_stake(&voter)?;

        // Apply governance stake cooldown.
        // Newly staked funds have zero voting power until GOVERNANCE_STAKE_COOLDOWN_BLOCKS
        // have elapsed since registration. This prevents vote-and-dump Sybil attacks.
        //
        // We derive the registration height from cap_eligible_height, which is set to
        // registration_height + NEW_VALIDATOR_CAP_COOLDOWN at validator creation time.
        let registration_height = validator
            .cap_eligible_height
            .saturating_sub(crate::staking::NEW_VALIDATOR_CAP_COOLDOWN);
        let stake =
            calculate_governance_voting_power(raw_stake, registration_height, current_height);
        if stake == 0 {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "M-11: sequencer {} stake is in cooldown (registered at block {}, \
                     cooldown ends at block {})",
                    voter,
                    registration_height,
                    registration_height.saturating_add(GOVERNANCE_STAKE_COOLDOWN_BLOCKS),
                ),
            });
        }

        // Record the vote (re-borrow mutably)
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| ConsensusError::ProposalNotFound { id: *proposal_id })?;
        proposal.sequencer_votes.insert(voter, (vote, stake));

        match vote {
            Vote::Yes => {
                proposal.sequencer_yes_stake = proposal.sequencer_yes_stake.saturating_add(stake);
            }
            Vote::No => {
                proposal.sequencer_no_stake = proposal.sequencer_no_stake.saturating_add(stake);
            }
            Vote::Abstain => {} // Counted as participation but not for/against
        }

        // Track unique voters
        if self.unique_voters.insert(voter) {
            self.stats.total_unique_voters += 1;
        }

        Ok(())
    }

    /// Cast a vote in the user chamber.
    ///
    /// Each eligible user gets exactly one vote (equal weight).
    ///
    /// # Rules
    /// - Voter must pass 3-layer Sybil check.
    /// - No double voting.
    /// - Voting period must still be active.
    ///
    /// # Errors
    /// Returns `ConsensusError::InvalidBlock` if any precondition fails.
    pub fn vote_user(
        &mut self,
        proposal_id: &Hash256,
        voter: Address,
        vote: Vote,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // Check voter eligibility (3-layer Sybil protection)
        if !self.is_eligible_voter(&voter, current_height) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("voter not eligible: {}", voter),
            });
        }

        let proposal = Self::check_proposal_votable(&self.proposals, proposal_id, current_height)?;

        // No double voting
        if proposal.user_votes.contains_key(&voter) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "user {} has already voted on proposal {}",
                    voter, proposal_id,
                ),
            });
        }

        // Reject if voter already voted in the sequencer chamber. Without
        // this check, a validator who is also an eligible user could vote in
        // both chambers, double-counting their influence.
        if proposal.sequencer_votes.contains_key(&voter) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "user {} already voted as sequencer on proposal {}",
                    voter, proposal_id,
                ),
            });
        }

        // Compute quadratic vote power = sqrt(balance)
        let balance = self
            .voter_eligibility
            .get(&voter)
            .map(|e| e.balance)
            .unwrap_or(0);
        let vote_power = VotePower::from_balance(balance).value();

        // Record the vote with vote power (re-borrow mutably)
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| ConsensusError::ProposalNotFound { id: *proposal_id })?;
        proposal.user_votes.insert(voter, (vote, vote_power));

        match vote {
            Vote::Yes => {
                proposal.user_yes_power = proposal.user_yes_power.saturating_add(vote_power)
            }
            Vote::No => proposal.user_no_power = proposal.user_no_power.saturating_add(vote_power),
            Vote::Abstain => {
                proposal.user_abstain_power = proposal.user_abstain_power.saturating_add(vote_power)
            }
        }

        // Track unique voters
        if self.unique_voters.insert(voter) {
            self.stats.total_unique_voters += 1;
        }

        Ok(())
    }

    /// Update the cached voter eligibility data for an address.
    ///
    /// This should be called periodically by the state sync layer to keep
    /// eligibility information up-to-date.
    pub fn update_voter_eligibility(
        &mut self,
        address: Address,
        balance: u64,
        first_tx_height: u64,
        tx_count_90d: u64,
    ) {
        self.voter_eligibility.insert(
            address,
            VoterEligibility {
                address,
                tx_count_90d,
                balance,
                first_tx_height,
            },
        );
    }

    /// Check if an address is eligible to vote in the user chamber.
    ///
    /// ## 3-Layer Sybil Protection
    ///
    /// 1. **Activity**: At least 10 transactions in the last 90 days.
    /// 2. **Balance**: At least 0.01 BTC (1,000,000 satoshis).
    /// 3. **Account Age**: Account must be at least 60 days old (1,728,000 blocks).
    pub fn is_eligible_voter(&self, address: &Address, current_height: u64) -> bool {
        let Some(eligibility) = self.voter_eligibility.get(address) else {
            return false;
        };

        // Layer 1: Activity check
        if eligibility.tx_count_90d < MIN_TX_FOR_VOTING {
            return false;
        }

        // Layer 2: Balance check
        if eligibility.balance < MIN_BALANCE_FOR_VOTING {
            return false;
        }

        // Layer 3: Account age check (use saturating_add to prevent overflow)
        if current_height
            < eligibility
                .first_tx_height
                .saturating_add(MIN_ACCOUNT_AGE_BLOCKS)
        {
            return false;
        }

        true
    }

    /// Finalize all proposals whose voting period has ended.
    ///
    /// For each active proposal where `voting_ends_at <= current_height`, tallies
    /// votes and determines whether the proposal passed or failed based on the
    /// required approval level and the total effective stake in the system.
    ///
    /// ## Abstention Semantics
    ///
    /// **Sequencer Chamber**: The threshold is compared against
    /// `snapshot_total_effective_stake` (the entire validator set at submission
    /// time), NOT against the sum of actual votes. Abstaining has NO effect on
    /// the outcome — it is equivalent to not voting at all. A proposal needs
    /// a fixed amount of Yes stake regardless of how many abstain.
    ///
    /// **User Chamber**: The threshold is compared against
    /// `user_yes_power + user_no_power + user_abstain_power` (the total
    /// quadratic vote power of all who participated). Abstaining *inflates the
    /// denominator* without adding to the numerator, making it harder for the
    /// proposal to pass. This incentivises active engagement — a voter who
    /// shows up but abstains is implicitly saying "I don't think this has
    /// enough support" by raising the bar for approval.
    ///
    /// Returns a list of (proposal_id, new_status) for each finalized proposal.
    pub fn finalize_proposals(
        &mut self,
        current_height: u64,
        _staking: &StakingState,
    ) -> Vec<(Hash256, ProposalStatus)> {
        // Collect IDs of proposals that need finalization
        let to_finalize: Vec<Hash256> = self
            .proposals
            .iter()
            .filter(|(_, p)| {
                p.status == ProposalStatus::Active && current_height >= p.voting_ends_at
            })
            .map(|(id, _)| *id)
            .collect();

        let mut results = Vec::new();
        let min_quorum = self.min_user_quorum();

        for id in to_finalize {
            let proposal = match self.proposals.get_mut(&id) {
                Some(p) => p,
                None => continue, // proposal removed between collect and iteration
            };

            // Use the snapshot taken at submission time, not the live value.
            // This prevents vote-then-unbond attacks where a validator votes
            // and then unbonds to reduce total_effective_stake, artificially
            // inflating their vote percentage.
            let total_effective_stake = proposal.snapshot_total_effective_stake;
            let sequencer_yes = proposal.sequencer_yes_stake;
            // Use quadratic vote power instead of equal-weight count
            let user_yes = proposal.user_yes_power;
            let user_total_power = proposal
                .user_yes_power
                .saturating_add(proposal.user_no_power)
                .saturating_add(proposal.user_abstain_power);
            let user_voter_count = proposal.user_votes.len() as u64;
            let required_approval = proposal.required_approval;

            // Determine thresholds from the required approval level
            let (seq_threshold, user_threshold) = match required_approval {
                RequiredApproval::SequencersOnly => (SEQUENCER_THRESHOLD_BP, 0),
                RequiredApproval::BothChambers => (SEQUENCER_THRESHOLD_BP, USER_THRESHOLD_BP),
                RequiredApproval::BothSuperMajority => (SEQUENCER_THRESHOLD_BP, SUPER_MAJORITY_BP),
                RequiredApproval::Constitutional => (CONSTITUTIONAL_BP, CONSTITUTIONAL_BP),
            };

            let seq_pass = meets_threshold(sequencer_yes, total_effective_stake, seq_threshold);
            let user_pass = required_approval == RequiredApproval::SequencersOnly
                || user_chamber_passes(
                    user_yes,
                    user_total_power,
                    user_voter_count,
                    min_quorum,
                    user_threshold,
                );

            let new_status = if seq_pass && user_pass {
                ProposalStatus::Passed
            } else {
                ProposalStatus::Failed
            };

            // Double firewall: re-check doctrine before allowing Passed status.
            // Even if a malicious node skipped the pre-vote check, honest nodes
            // will reject doctrine-violating proposals at finalization.
            #[cfg(feature = "governance-extensions")]
            let final_status = if new_status == ProposalStatus::Passed {
                let doctrine_check = proposal_to_doctrine_check(&proposal.proposal_type);
                if let DoctrineCheckResult::Rejected { .. } =
                    DoctrineFirewall::validate(&doctrine_check)
                {
                    ProposalStatus::Failed
                } else {
                    ProposalStatus::Passed
                }
            } else {
                new_status
            };
            #[cfg(not(feature = "governance-extensions"))]
            let final_status = new_status;

            // Update proposal status and stats
            proposal.status = final_status;
            self.stats.active_proposals = self.stats.active_proposals.saturating_sub(1);

            match final_status {
                ProposalStatus::Passed => {
                    self.stats.passed_proposals += 1;
                    // Set time-lock instead of immediate execution deadline.
                    // The execution deadline is set AFTER the time-lock expires
                    // (via `process_timelocks()`).
                    let timelock_duration = Self::timelock_for(&proposal.required_approval);
                    proposal.timelock_expires_at =
                        Some(current_height.saturating_add(timelock_duration));
                    // execution_deadline is NOT set here — it's set when the timelock expires
                }
                ProposalStatus::Failed => self.stats.failed_proposals += 1,
                _ => {}
            }

            results.push((id, final_status));
        }

        results
    }

    /// Get a reference to a proposal by its ID.
    pub fn get_proposal(&self, id: &Hash256) -> Option<&Proposal> {
        self.proposals.get(id)
    }

    /// Get all currently active proposals.
    pub fn active_proposals(&self) -> Vec<&Proposal> {
        self.proposals
            .values()
            .filter(|p| p.status == ProposalStatus::Active)
            .collect()
    }

    /// Get all proposals (any status).
    pub fn all_proposals(&self) -> Vec<&Proposal> {
        self.proposals.values().collect()
    }

    /// Get a reference to the governance statistics.
    pub fn stats(&self) -> &GovernanceStats {
        &self.stats
    }

    /// Get the time-lock duration for a given approval level.
    fn timelock_for(required: &RequiredApproval) -> u64 {
        match required {
            RequiredApproval::SequencersOnly => TIMELOCK_TECHNICAL_BLOCKS,
            RequiredApproval::BothChambers => TIMELOCK_FEE_BLOCKS,
            RequiredApproval::BothSuperMajority => TIMELOCK_SLASHING_BLOCKS,
            RequiredApproval::Constitutional => TIMELOCK_CONSTITUTIONAL_BLOCKS,
        }
    }

    /// Submit a veto vote against a time-locked proposal.
    ///
    /// Validators and eligible users can veto during the time-lock period.
    /// If the veto threshold is reached (33.33% of sequencer stake OR 25%
    /// of user vote power, with at least MIN_VETO_VOTERS distinct voters),
    /// the proposal transitions to `Vetoed` status.
    ///
    /// # Rules
    /// - Proposal must be in `Passed` status with an active time-lock.
    /// - Voter must not have already vetoed.
    /// - Time-lock must not have expired.
    pub fn submit_veto(
        &mut self,
        proposal_id: &Hash256,
        voter: Address,
        staking: &StakingState,
        current_height: u64,
    ) -> Result<bool, ConsensusError> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or_else(|| ConsensusError::InvalidBlock {
                reason: format!("proposal not found: {}", proposal_id),
            })?;

        if proposal.status != ProposalStatus::Passed {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("cannot veto proposal {}: status is {:?}", proposal_id, proposal.status),
            });
        }

        // Must be within the time-lock period
        let timelock_end = proposal.timelock_expires_at.ok_or_else(|| {
            ConsensusError::InvalidBlock {
                reason: format!("proposal {} has no time-lock set", proposal_id),
            }
        })?;

        if current_height >= timelock_end {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "time-lock for proposal {} has expired at block {}",
                    proposal_id, timelock_end,
                ),
            });
        }

        // No double veto
        if proposal.veto_voters.contains(&voter) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("voter {} has already vetoed proposal {}", voter, proposal_id),
            });
        }

        // Compute veto weight — validator stake or user vote power
        let mut seq_weight = 0u64;
        let mut user_weight = 0u64;
        if let Some(validator) = staking.validators.get(&voter) {
            if validator.status == crate::validator::ValidatorStatus::Active {
                seq_weight = staking.effective_stake(&voter).unwrap_or(0);
            }
        }
        if self.is_eligible_voter(&voter, current_height) {
            let balance = self
                .voter_eligibility
                .get(&voter)
                .map(|e| e.balance)
                .unwrap_or(0);
            user_weight = VotePower::from_balance(balance).value();
        }

        if seq_weight == 0 && user_weight == 0 {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("voter {} has no veto power (not a validator or eligible user)", voter),
            });
        }

        // Record the veto (re-borrow mutably)
        let total_stake = proposal.snapshot_total_effective_stake;
        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or_else(|| ConsensusError::ProposalNotFound { id: *proposal_id })?;

        proposal.veto_voters.insert(voter);
        proposal.veto_sequencer_stake = proposal.veto_sequencer_stake.saturating_add(seq_weight);
        proposal.veto_user_power = proposal.veto_user_power.saturating_add(user_weight);

        // Check if veto threshold is reached
        let veto_count = proposal.veto_voters.len() as u64;
        let seq_veto_reached = veto_count >= MIN_VETO_VOTERS
            && meets_threshold(proposal.veto_sequencer_stake, total_stake, VETO_THRESHOLD_BP);

        // For user veto, use the total participating user power from the original vote
        let user_total = proposal
            .user_yes_power
            .saturating_add(proposal.user_no_power)
            .saturating_add(proposal.user_abstain_power);
        let user_veto_reached = veto_count >= MIN_VETO_VOTERS
            && meets_threshold(proposal.veto_user_power, user_total, USER_VETO_THRESHOLD_BP);

        if seq_veto_reached || user_veto_reached {
            proposal.status = ProposalStatus::Vetoed;
            proposal.vetoed = true;
            self.stats.passed_proposals = self.stats.passed_proposals.saturating_sub(1);
            return Ok(true);
        }

        Ok(false)
    }

    /// Process time-locks for all passed proposals.
    ///
    /// For proposals whose time-lock has expired without being vetoed,
    /// this sets the execution deadline (beginning the execution window).
    /// Call this at each block processing step.
    ///
    /// Returns a list of proposal IDs that became executable.
    pub fn process_timelocks(&mut self, current_height: u64) -> Vec<Hash256> {
        let exec_window = self.execution_window();
        let mut newly_executable = Vec::new();

        let to_process: Vec<Hash256> = self
            .proposals
            .iter()
            .filter(|(_, p)| {
                p.status == ProposalStatus::Passed
                    && p.execution_deadline.is_none()
                    && p.timelock_expires_at
                        .is_some_and(|t| current_height >= t)
            })
            .map(|(id, _)| *id)
            .collect();

        for id in to_process {
            if let Some(proposal) = self.proposals.get_mut(&id) {
                proposal.execution_deadline =
                    Some(current_height.saturating_add(exec_window));
                newly_executable.push(id);
            }
        }

        newly_executable
    }

    /// Check if a proposal is currently in its time-lock period.
    pub fn is_in_timelock(&self, proposal_id: &Hash256, current_height: u64) -> bool {
        self.proposals.get(proposal_id).is_some_and(|p| {
            p.status == ProposalStatus::Passed
                && p.timelock_expires_at
                    .is_some_and(|t| current_height < t)
        })
    }

    /// Mark a passed proposal as executed.
    ///
    /// # Errors
    /// Returns an error if the proposal is not found, is not in `Passed` status,
    /// or the execution window has expired.
    pub fn mark_executed(
        &mut self,
        id: &Hash256,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let proposal = self
            .proposals
            .get_mut(id)
            .ok_or_else(|| ConsensusError::InvalidBlock {
                reason: format!("proposal not found: {}", id),
            })?;

        if proposal.status != ProposalStatus::Passed {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "cannot execute proposal {}: status is {:?}, expected Passed",
                    id, proposal.status,
                ),
            });
        }

        // Cannot execute during time-lock period
        if let Some(timelock_end) = proposal.timelock_expires_at
            && current_height < timelock_end
        {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "proposal {} is in time-lock until block {} (current: {})",
                    id, timelock_end, current_height,
                ),
            });
        }

        // Cannot execute a vetoed proposal
        if proposal.vetoed {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "proposal {} has been vetoed and cannot be executed",
                    id,
                ),
            });
        }

        // Check execution window (must be set by process_timelocks first)
        if proposal.execution_deadline.is_none() {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "proposal {} time-lock has not been processed yet (call process_timelocks first)",
                    id,
                ),
            });
        }

        if let Some(deadline) = proposal.execution_deadline
            && current_height > deadline
        {
            return Err(ConsensusError::ExecutionWindowExpired { deadline });
        }

        proposal.status = ProposalStatus::Executed;
        self.stats.passed_proposals = self.stats.passed_proposals.saturating_sub(1);
        self.stats.executed_proposals += 1;

        Ok(())
    }

    /// Reset the execution deadline for a passed proposal.
    ///
    /// Call this after a timelock expires to begin the execution window
    /// from the timelock's end height rather than the finalization height.
    pub fn begin_execution_window(
        &mut self,
        id: &Hash256,
        start_height: u64,
    ) -> Result<(), ConsensusError> {
        let proposal = self
            .proposals
            .get_mut(id)
            .ok_or_else(|| ConsensusError::InvalidBlock {
                reason: format!("proposal not found: {}", id),
            })?;
        if proposal.status != ProposalStatus::Passed {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "cannot begin execution window for {}: status is {:?}",
                    id, proposal.status,
                ),
            });
        }
        proposal.execution_deadline = Some(start_height.saturating_add(EXECUTION_WINDOW_BLOCKS));
        Ok(())
    }

    /// Cancel a proposal. Only the original proposer may cancel.
    ///
    /// # Errors
    /// Returns an error if the proposal is not found, is not active, or the
    /// canceller is not the original proposer.
    pub fn cancel_proposal(
        &mut self,
        id: &Hash256,
        canceller: Address,
    ) -> Result<(), ConsensusError> {
        let proposal = self
            .proposals
            .get(id)
            .ok_or_else(|| ConsensusError::InvalidBlock {
                reason: format!("proposal not found: {}", id),
            })?;

        if proposal.status != ProposalStatus::Active {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "cannot cancel proposal {}: status is {:?}, expected Active",
                    id, proposal.status,
                ),
            });
        }

        if proposal.proposer != canceller {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "only the proposer {} can cancel proposal {}, not {}",
                    proposal.proposer, id, canceller,
                ),
            });
        }

        let proposal = self
            .proposals
            .get_mut(id)
            .ok_or_else(|| ConsensusError::ProposalNotFound { id: *id })?;
        proposal.status = ProposalStatus::Cancelled;
        self.stats.active_proposals = self.stats.active_proposals.saturating_sub(1);

        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════

/// Map a proposal type to its required approval level.
fn required_approval_for(proposal_type: &ProposalType) -> RequiredApproval {
    match proposal_type {
        ProposalType::TechnicalUpdate { .. } => RequiredApproval::SequencersOnly,
        ProposalType::FeeChange { .. } => RequiredApproval::BothChambers,
        ProposalType::SlashingChange { .. } => RequiredApproval::BothSuperMajority,
        ProposalType::Constitutional { .. } => RequiredApproval::Constitutional,
    }
}

/// Check if a vote meets a threshold using u128 arithmetic.
///
/// Returns true when `yes_votes * 10_000 >= threshold_bp * total_votes` AND `total_votes > 0`.
/// Uses u128 intermediate to prevent overflow.
fn meets_threshold(yes_votes: u64, total_votes: u64, threshold_bp: u64) -> bool {
    total_votes > 0
        && (yes_votes as u128) * 10_000 >= (threshold_bp as u128) * (total_votes as u128)
}

/// Check if the user chamber passes with quorum + threshold.
fn user_chamber_passes(
    user_yes: u64,
    user_total_power: u64,
    user_voter_count: u64,
    min_quorum: u64,
    threshold_bp: u64,
) -> bool {
    user_voter_count >= min_quorum && meets_threshold(user_yes, user_total_power, threshold_bp)
}

/// Map a `ProposalType` to a `ProposalDoctrineCheck` for firewall validation.
#[cfg(feature = "governance-extensions")]
fn proposal_to_doctrine_check(pt: &ProposalType) -> ProposalDoctrineCheck {
    match pt {
        ProposalType::TechnicalUpdate { description } => ProposalDoctrineCheck::TechnicalUpdate {
            description: description.clone(),
        },
        ProposalType::FeeChange { parameter, new_value, .. } => ProposalDoctrineCheck::FeeChange {
            description: parameter.clone(),
            new_value: *new_value,
        },
        ProposalType::SlashingChange { reason, .. } => ProposalDoctrineCheck::SlashingChange {
            reason: reason.clone(),
        },
        ProposalType::Constitutional { amendment } => ProposalDoctrineCheck::Constitutional {
            amendment: amendment.clone(),
        },
    }
}

/// Compute a deterministic proposal ID from proposer, height, and proposal type.
fn compute_proposal_id(proposer: &Address, height: u64, proposal_type: &ProposalType) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(proposer.as_bytes());
    hasher.update(&height.to_le_bytes());

    // Serialize the proposal type for hashing
    match proposal_type {
        ProposalType::TechnicalUpdate { description } => {
            hasher.update(b"TechnicalUpdate");
            hasher.update(description.as_bytes());
        }
        ProposalType::FeeChange {
            parameter,
            old_value,
            new_value,
        } => {
            hasher.update(b"FeeChange");
            hasher.update(parameter.as_bytes());
            hasher.update(&old_value.to_le_bytes());
            hasher.update(&new_value.to_le_bytes());
        }
        ProposalType::SlashingChange {
            reason,
            old_bp,
            new_bp,
        } => {
            hasher.update(b"SlashingChange");
            hasher.update(reason.as_bytes());
            hasher.update(&old_bp.to_le_bytes());
            hasher.update(&new_bp.to_le_bytes());
        }
        ProposalType::Constitutional { amendment } => {
            hasher.update(b"Constitutional");
            hasher.update(amendment.as_bytes());
        }
    }

    hasher.finalize()
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::ValidatorStatus;

    /// Create a test address from a single byte.
    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address(bytes)
    }

    /// Create a StakingState with registered validators.
    /// Returns (staking, list_of_addresses).
    fn setup_staking(stakes: &[(u8, u64)]) -> StakingState {
        let mut staking = StakingState::new(100_000_000_000); // 1000 BTC cap (high, no capping)
        staking.min_validator_stake = 0; // Allow small stakes in tests
        for &(id, stake) in stakes {
            staking
                .register_validator(addr(id), stake)
                .expect("register should succeed");
        }
        staking
    }

    /// Register a user as eligible for voting in the user chamber.
    fn make_eligible(gov: &mut GovernanceManager, id: u8) {
        gov.update_voter_eligibility(
            addr(id),
            1_000_000, // 0.01 BTC (above MIN_BALANCE_FOR_VOTING)
            0,         // first tx at block 0 (old account)
            100,       // 100 txs in 90 days (above MIN_TX_FOR_VOTING)
        );
    }

    // ───────────────────────────────────────────────────────────
    // Proposal Submission Tests
    // ───────────────────────────────────────────────────────────

    #[test]
    fn submit_proposal_technical_update() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);
        let proposer = addr(1);

        let result = gov.submit_proposal(
            proposer,
            ProposalType::TechnicalUpdate {
                description: "Upgrade VM gas table".into(),
            },
            2_000_000, // current height (well past any cooldown)
            &staking,
        );

        assert!(result.is_ok());
        let id = result.unwrap();
        let proposal = gov.get_proposal(&id).unwrap();
        assert_eq!(proposal.proposer, proposer);
        assert_eq!(proposal.required_approval, RequiredApproval::SequencersOnly);
        assert_eq!(proposal.status, ProposalStatus::Active);
        assert_eq!(proposal.voting_ends_at, 2_000_000 + VOTING_PERIOD_BLOCKS);
    }

    #[test]
    fn submit_proposal_fee_change() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[]);

        let result = gov.submit_proposal(
            addr(10),
            ProposalType::FeeChange {
                parameter: "base_fee".into(),
                old_value: 100,
                new_value: 200,
            },
            5_000_000,
            &staking,
        );

        assert!(result.is_ok());
        let id = result.unwrap();
        let proposal = gov.get_proposal(&id).unwrap();
        assert_eq!(proposal.required_approval, RequiredApproval::BothChambers);
    }

    #[test]
    fn submit_proposal_slashing_change() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[]);

        let result = gov.submit_proposal(
            addr(20),
            ProposalType::SlashingChange {
                reason: "Reduce equivocation penalty".into(),
                old_bp: 3333,
                new_bp: 2500,
            },
            5_000_000,
            &staking,
        );

        assert!(result.is_ok());
        let id = result.unwrap();
        let proposal = gov.get_proposal(&id).unwrap();
        assert_eq!(
            proposal.required_approval,
            RequiredApproval::BothSuperMajority
        );
    }

    #[test]
    fn submit_proposal_constitutional() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[]);

        let result = gov.submit_proposal(
            addr(30),
            ProposalType::Constitutional {
                amendment: "Change maximum validator count to 200".into(),
            },
            5_000_000,
            &staking,
        );

        assert!(result.is_ok());
        let id = result.unwrap();
        let proposal = gov.get_proposal(&id).unwrap();
        assert_eq!(proposal.required_approval, RequiredApproval::Constitutional);
    }

    #[test]
    fn proposal_cooldown_enforced() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[]);
        let proposer = addr(50);

        // First proposal succeeds
        let r1 = gov.submit_proposal(
            proposer,
            ProposalType::FeeChange {
                parameter: "gas_price".into(),
                old_value: 1,
                new_value: 2,
            },
            1_000_000,
            &staking,
        );
        assert!(r1.is_ok());

        // Second proposal within cooldown period should fail
        let r2 = gov.submit_proposal(
            proposer,
            ProposalType::FeeChange {
                parameter: "gas_limit".into(),
                old_value: 10,
                new_value: 20,
            },
            1_000_000 + PROPOSAL_COOLDOWN_BLOCKS - 1, // still within cooldown
            &staking,
        );
        assert!(r2.is_err());

        // Third proposal after cooldown should succeed
        let r3 = gov.submit_proposal(
            proposer,
            ProposalType::FeeChange {
                parameter: "gas_limit".into(),
                old_value: 10,
                new_value: 20,
            },
            1_000_000 + PROPOSAL_COOLDOWN_BLOCKS, // exactly at cooldown end
            &staking,
        );
        assert!(r3.is_ok());
    }

    // ───────────────────────────────────────────────────────────
    // Sequencer Voting Tests
    // ───────────────────────────────────────────────────────────

    #[test]
    fn sequencer_vote_yes() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000), (2, 3_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        let result = gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001);
        assert!(result.is_ok());

        let proposal = gov.get_proposal(&id).unwrap();
        assert_eq!(proposal.sequencer_yes_stake, 10_000_000);
        assert_eq!(proposal.sequencer_no_stake, 0);
        assert!(proposal.sequencer_votes.contains_key(&addr(1)));
    }

    #[test]
    fn sequencer_vote_no() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000), (2, 3_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        let result = gov.vote_sequencer(&id, addr(2), Vote::No, &staking, 2_000_001);
        assert!(result.is_ok());

        let proposal = gov.get_proposal(&id).unwrap();
        assert_eq!(proposal.sequencer_yes_stake, 0);
        assert_eq!(proposal.sequencer_no_stake, 3_000_000);
    }

    #[test]
    fn sequencer_double_vote_rejected() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        // Second vote should fail
        let result = gov.vote_sequencer(&id, addr(1), Vote::No, &staking, 2_000_002);
        assert!(result.is_err());
    }

    // ───────────────────────────────────────────────────────────
    // User Voting Tests
    // ───────────────────────────────────────────────────────────

    #[test]
    fn user_vote_eligible() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);

        make_eligible(&mut gov, 100);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        let result = gov.vote_user(&id, addr(100), Vote::Yes, 2_000_001);
        assert!(result.is_ok());

        let proposal = gov.get_proposal(&id).unwrap();
        // sqrt(1_000_000) = 1000 vote power
        assert_eq!(proposal.user_yes_power, 1000);
        assert_eq!(proposal.user_no_power, 0);
    }

    #[test]
    fn user_vote_ineligible_low_tx() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);

        // Only 5 txs (below MIN_TX_FOR_VOTING = 10)
        gov.update_voter_eligibility(addr(101), 1_000_000, 0, 5);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        let result = gov.vote_user(&id, addr(101), Vote::Yes, 2_000_001);
        assert!(result.is_err());
    }

    #[test]
    fn user_vote_ineligible_low_balance() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);

        // Balance of 50,000 sat (below MIN_BALANCE_FOR_VOTING = 1,000,000)
        gov.update_voter_eligibility(addr(102), 50_000, 0, 100);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        let result = gov.vote_user(&id, addr(102), Vote::Yes, 2_000_001);
        assert!(result.is_err());
    }

    #[test]
    fn user_vote_ineligible_new_account() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);

        // Account created at block 1_500_000, current height 2_000_001
        // Age = 2_000_001 - 1_500_000 = 500_001 blocks < MIN_ACCOUNT_AGE_BLOCKS (1_728_000)
        gov.update_voter_eligibility(addr(103), 1_000_000, 1_500_000, 100);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        let result = gov.vote_user(&id, addr(103), Vote::Yes, 2_000_001);
        assert!(result.is_err());
    }

    // ───────────────────────────────────────────────────────────
    // Finalization Tests
    // ───────────────────────────────────────────────────────────

    #[test]
    fn finalize_technical_sequencers_only() {
        let mut gov = GovernanceManager::new();
        // Two validators: 70% + 30% of total stake
        let staking = setup_staking(&[(1, 70_000_000), (2, 30_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "Upgrade VM".into(),
                },
                1_000_000,
                &staking,
            )
            .unwrap();

        // Validator 1 votes Yes (70% of total stake) — exceeds 67%
        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 1_000_001)
            .unwrap();

        // Finalize after voting period ends
        let results = gov.finalize_proposals(1_000_000 + VOTING_PERIOD_BLOCKS, &staking);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, ProposalStatus::Passed);
    }

    #[test]
    fn finalize_fee_change_both_chambers() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 7_000_000), (2, 3_000_000)]);

        let id = gov
            .submit_proposal(
                addr(10),
                ProposalType::FeeChange {
                    parameter: "base_fee".into(),
                    old_value: 100,
                    new_value: 200,
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        // Sequencer chamber: 70% yes
        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        // User chamber: 8 yes, 3 no = 11 total (72.7% > 51%, quorum >= 10)
        for i in 100..111u8 {
            make_eligible(&mut gov, i);
        }
        for i in 100..108u8 {
            gov.vote_user(&id, addr(i), Vote::Yes, 2_000_002).unwrap();
        }
        for i in 108..111u8 {
            gov.vote_user(&id, addr(i), Vote::No, 2_000_003).unwrap();
        }

        let results = gov.finalize_proposals(2_000_000 + VOTING_PERIOD_BLOCKS, &staking);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, ProposalStatus::Passed);
    }

    #[test]
    fn finalize_slashing_super_majority() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 7_000_000), (2, 3_000_000)]);

        let id = gov
            .submit_proposal(
                addr(20),
                ProposalType::SlashingChange {
                    reason: "Reduce penalty".into(),
                    old_bp: 3333,
                    new_bp: 2500,
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        // Sequencer: 70% yes
        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        // User chamber: need >= 75%. Use 10 voters: 8 yes, 2 no = 80% (quorum >= 10)
        for i in 100..110u8 {
            make_eligible(&mut gov, i);
        }
        for i in 100..108u8 {
            gov.vote_user(&id, addr(i), Vote::Yes, 2_000_002).unwrap();
        }
        for i in 108..110u8 {
            gov.vote_user(&id, addr(i), Vote::No, 2_000_003).unwrap();
        }

        let results = gov.finalize_proposals(2_000_000 + VOTING_PERIOD_BLOCKS, &staking);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, ProposalStatus::Passed);
    }

    #[test]
    fn finalize_constitutional_90_percent() {
        let mut gov = GovernanceManager::new();
        // Need >= 90% sequencer stake: use 9_000_000 + 1_000_000
        let staking = setup_staking(&[(1, 9_000_000), (2, 1_000_000)]);

        let id = gov
            .submit_proposal(
                addr(30),
                ProposalType::Constitutional {
                    amendment: "Change max validators".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        // Sequencer: both vote yes (100% >= 90%)
        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();
        gov.vote_sequencer(&id, addr(2), Vote::Yes, &staking, 2_000_002)
            .unwrap();

        // User chamber: 10 voters, 9 yes, 1 no = 90%
        for i in 100..110u8 {
            make_eligible(&mut gov, i);
        }
        for i in 100..109u8 {
            gov.vote_user(&id, addr(i), Vote::Yes, 2_000_003).unwrap();
        }
        gov.vote_user(&id, addr(109), Vote::No, 2_000_004).unwrap();

        let results = gov.finalize_proposals(2_000_000 + VOTING_PERIOD_BLOCKS, &staking);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, ProposalStatus::Passed);
    }

    #[test]
    fn proposal_fails_insufficient_votes() {
        let mut gov = GovernanceManager::new();
        // Validator 1 has only ~12.5% of total stake
        let staking = setup_staking(&[(1, 10_000_000), (2, 70_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "Upgrade VM".into(),
                },
                1_000_000,
                &staking,
            )
            .unwrap();

        // Only validator 1 votes Yes (30% < 67%)
        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 1_000_001)
            .unwrap();

        let results = gov.finalize_proposals(1_000_000 + VOTING_PERIOD_BLOCKS, &staking);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, ProposalStatus::Failed);
    }

    // ───────────────────────────────────────────────────────────
    // Cancellation Tests
    // ───────────────────────────────────────────────────────────

    #[test]
    fn cancel_proposal_by_proposer() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[]);
        let proposer = addr(50);

        let id = gov
            .submit_proposal(
                proposer,
                ProposalType::FeeChange {
                    parameter: "gas_price".into(),
                    old_value: 1,
                    new_value: 2,
                },
                5_000_000,
                &staking,
            )
            .unwrap();

        let result = gov.cancel_proposal(&id, proposer);
        assert!(result.is_ok());

        let proposal = gov.get_proposal(&id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Cancelled);
    }

    #[test]
    fn cancel_proposal_by_other_rejected() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[]);
        let proposer = addr(50);
        let other = addr(99);

        let id = gov
            .submit_proposal(
                proposer,
                ProposalType::FeeChange {
                    parameter: "gas_price".into(),
                    old_value: 1,
                    new_value: 2,
                },
                5_000_000,
                &staking,
            )
            .unwrap();

        let result = gov.cancel_proposal(&id, other);
        assert!(result.is_err());

        // Proposal should still be active
        let proposal = gov.get_proposal(&id).unwrap();
        assert_eq!(proposal.status, ProposalStatus::Active);
    }

    // ───────────────────────────────────────────────────────────
    // Stats Tracking
    // ───────────────────────────────────────────────────────────

    #[test]
    fn governance_stats_tracking() {
        let mut gov = GovernanceManager::new();
        // addr(2) is a registered validator so it can submit TechnicalUpdate
        let staking = setup_staking(&[(1, 70_000_000), (2, 10_000_000)]);

        // Submit 2 proposals (different proposers to avoid cooldown)
        let id1 = gov
            .submit_proposal(
                addr(10),
                ProposalType::FeeChange {
                    parameter: "fee_a".into(),
                    old_value: 1,
                    new_value: 2,
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        let id2 = gov
            .submit_proposal(
                addr(2), // Must be a registered validator for TechnicalUpdate
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        assert_eq!(gov.stats().total_proposals, 2);
        assert_eq!(gov.stats().active_proposals, 2);

        // Vote on proposal 2 to make it pass (TechnicalUpdate: sequencers-only 67%)
        gov.vote_sequencer(&id2, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        // Check unique voters
        assert_eq!(gov.stats().total_unique_voters, 1);

        // Add user votes on proposal 1 (need quorum >= 10 for BothChambers)
        for i in 100..111u8 {
            make_eligible(&mut gov, i);
        }
        for i in 100..111u8 {
            gov.vote_user(&id1, addr(i), Vote::Yes, 2_000_002).unwrap();
        }

        // 12 unique voters total (addr(1) + addr(100)..addr(110))
        assert_eq!(gov.stats().total_unique_voters, 12);

        // Finalize both
        let results = gov.finalize_proposals(2_000_000 + VOTING_PERIOD_BLOCKS, &staking);
        assert_eq!(results.len(), 2);

        // Proposal 2 should pass (70% > 67%)
        let p2 = gov.get_proposal(&id2).unwrap();
        assert_eq!(p2.status, ProposalStatus::Passed);

        // Proposal 1 should fail (no sequencer votes, needs BothChambers)
        let p1 = gov.get_proposal(&id1).unwrap();
        assert_eq!(p1.status, ProposalStatus::Failed);

        assert_eq!(gov.stats().active_proposals, 0);
        assert_eq!(gov.stats().passed_proposals, 1);
        assert_eq!(gov.stats().failed_proposals, 1);

        // Must process time-lock before execution
        let finalization_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        // Advance past the time-lock (TechnicalUpdate → TIMELOCK_TECHNICAL_BLOCKS)
        let post_timelock = finalization_height + TIMELOCK_TECHNICAL_BLOCKS;
        gov.process_timelocks(post_timelock);
        gov.mark_executed(&id2, post_timelock).unwrap();
        assert_eq!(gov.stats().executed_proposals, 1);
        assert_eq!(gov.stats().passed_proposals, 0);
    }
    // ---------------------------------------------------------------
    // Overflow & Edge-Case Tests
    // ---------------------------------------------------------------

    #[test]
    fn test_account_age_overflow_safe() {
        // When first_tx_height + MIN_ACCOUNT_AGE_BLOCKS would overflow u64,
        // saturating_add caps at u64::MAX, so current_height < u64::MAX means
        // the voter is NOT eligible.
        let mut gov = GovernanceManager::new();
        gov.update_voter_eligibility(
            addr(200),
            1_000_000,      // balance OK
            u64::MAX - 100, // first_tx_height near u64::MAX
            100,            // tx count OK
        );
        // u64::MAX - 100 + 1_728_000 overflows -> saturates to u64::MAX.
        // The check is: current_height < u64::MAX -> with current_height = u64::MAX - 1, true.
        // So the voter is NOT eligible at u64::MAX - 1.
        let not_eligible = gov.is_eligible_voter(&addr(200), u64::MAX - 1);
        assert!(
            !not_eligible,
            "Voter with near-overflow first_tx_height should NOT be eligible at u64::MAX - 1"
        );
    }

    #[test]
    fn test_suspended_validator_cannot_vote() {
        let mut gov = GovernanceManager::new();
        let mut staking = setup_staking(&[(1, 10_000_000), (2, 3_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test suspended".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        // Manually suspend validator 2
        staking.validators.get_mut(&addr(2)).unwrap().status = ValidatorStatus::Suspended;

        // Suspended validator should not be able to vote
        let result = gov.vote_sequencer(&id, addr(2), Vote::Yes, &staking, 2_000_001);
        let err = result.unwrap_err();
        assert!(
            matches!(&err, ConsensusError::InvalidBlock { reason } if reason.contains("not active")),
            "suspended validator should be rejected with 'not active', got: {}",
            err,
        );
    }

    #[test]
    fn test_sequencer_stake_overflow_safe() {
        // Two validators with huge stakes - saturating_add should prevent panic
        let mut gov = GovernanceManager::new();
        let mut staking = StakingState::new(u64::MAX); // very high cap so no sqrt capping
        let half = u64::MAX / 2;

        staking.register_validator(addr(1), half).unwrap();
        staking.register_validator(addr(2), half).unwrap();

        let id = gov
            .submit_proposal(
                addr(10),
                ProposalType::FeeChange {
                    parameter: "gas_price".into(),
                    old_value: 1,
                    new_value: 2,
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        // Both vote yes - their combined stake would overflow without saturating_add
        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();
        gov.vote_sequencer(&id, addr(2), Vote::Yes, &staking, 2_000_002)
            .unwrap();

        let proposal = gov.get_proposal(&id).unwrap();
        // saturating_add caps at u64::MAX (half + half = u64::MAX - 1, no overflow here,
        // but the point is the code uses saturating_add and does not panic)
        assert!(
            proposal.sequencer_yes_stake >= half,
            "sequencer_yes_stake should be at least half"
        );
    }

    #[test]
    fn test_user_abstain_counted_in_quorum() {
        // Abstain votes should count toward quorum (user_total) but NOT toward
        // the yes percentage. With 3/10 = 30% yes, a 51% threshold should fail.
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 7_000_000), (2, 3_000_000)]);

        let id = gov
            .submit_proposal(
                addr(10),
                ProposalType::FeeChange {
                    parameter: "base_fee".into(),
                    old_value: 100,
                    new_value: 200,
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        // Sequencer chamber: 70% yes (passes 67% threshold)
        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        // User chamber: 10 voters - 3 yes, 2 no, 5 abstain
        for i in 100..110u8 {
            make_eligible(&mut gov, i);
        }
        // 3 yes
        for i in 100..103u8 {
            gov.vote_user(&id, addr(i), Vote::Yes, 2_000_002).unwrap();
        }
        // 2 no
        for i in 103..105u8 {
            gov.vote_user(&id, addr(i), Vote::No, 2_000_003).unwrap();
        }
        // 5 abstain
        for i in 105..110u8 {
            gov.vote_user(&id, addr(i), Vote::Abstain, 2_000_004)
                .unwrap();
        }

        // Verify raw counts
        let proposal = gov.get_proposal(&id).unwrap();
        // each voter has balance 1_000_000, sqrt(1_000_000) = 1000 power
        assert_eq!(proposal.user_yes_power, 3000);
        assert_eq!(proposal.user_no_power, 2000);
        assert_eq!(proposal.user_abstain_power, 5000);

        // Finalize - user_total_power = 3000 + 2000 + 5000 = 10000, yes% = 3000/10000 = 30% < 51%
        let results = gov.finalize_proposals(2_000_000 + VOTING_PERIOD_BLOCKS, &staking);
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].1,
            ProposalStatus::Failed,
            "Proposal should fail: 3/10 = 30% yes < 51% user threshold"
        );
    }

    #[test]
    #[cfg(feature = "sequencer-rotation")]
    fn test_deregister_sequencer() {
        use crate::registration::*;

        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        // Register a sequencer
        let req = RegistrationRequest {
            address: addr(1),
            self_stake: MIN_SEQUENCER_STAKE,
            region: Region::Europe,
            commission_bp: 500,
            eots_pubkey: None,
        };
        mgr.register(req, &mut staking, 100).unwrap();
        assert_eq!(mgr.count(), 1);

        // Delegate to it
        let del_req = DelegationRequest {
            delegator: addr(10),
            sequencer: addr(1),
            amount: 500_000,
        };
        mgr.delegate(del_req, &mut staking, 200).unwrap();

        // Verify region count before deregister
        assert_eq!(
            mgr.region_counts.get(&Region::Europe).copied().unwrap_or(0),
            1,
        );

        // Deregister
        let outstanding = mgr.deregister(&addr(1)).unwrap();

        // (a) Returns the outstanding delegations
        assert_eq!(outstanding.len(), 1);
        assert_eq!(outstanding[0].0, addr(10));
        assert_eq!(outstanding[0].1, 500_000);

        // (b) Region count decreased
        assert_eq!(
            mgr.region_counts.get(&Region::Europe).copied().unwrap_or(0),
            0,
        );

        // (c) Sequencer is no longer findable
        assert!(mgr.get_sequencer(&addr(1)).is_none());
        assert_eq!(mgr.count(), 0);
    }

    #[test]
    fn custom_params_change_voting_period() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);
        let proposer = addr(1);

        // Submit with default params — voting period should be VOTING_PERIOD_BLOCKS
        let id1 = gov
            .submit_proposal(
                proposer,
                ProposalType::TechnicalUpdate {
                    description: "test1".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();
        let p1 = gov.get_proposal(&id1).unwrap();
        assert_eq!(p1.voting_ends_at, 2_000_000 + VOTING_PERIOD_BLOCKS);

        // Set custom params with shorter voting period
        let mut custom = ConsensusParams::default();
        custom.voting_period_blocks = 100;
        custom.proposal_cooldown_blocks = 0; // no cooldown for test
        custom.min_proposal_stake = 1; // allow low stake for test
        gov.set_params(custom);

        // Submit with custom params — voting period should be 100
        let id2 = gov
            .submit_proposal(
                proposer,
                ProposalType::TechnicalUpdate {
                    description: "test2".into(),
                },
                2_000_001,
                &staking,
            )
            .unwrap();
        let p2 = gov.get_proposal(&id2).unwrap();
        assert_eq!(p2.voting_ends_at, 2_000_001 + 100);
    }

    #[test]
    #[cfg(feature = "governance-extensions")]
    fn submit_proposal_rejected_by_doctrine() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);

        let result = gov.submit_proposal(
            addr(1),
            ProposalType::TechnicalUpdate {
                description: "Remove SLH-DSA to save block space".into(),
            },
            2_000_000,
            &staking,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, ConsensusError::DoctrineViolation { law_number: 2, .. }),
            "expected DoctrineViolation law 2, got: {:?}",
            err,
        );
    }

    #[test]
    #[cfg(feature = "governance-extensions")]
    fn unicode_bypass_blocked() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 10_000_000)]);

        // Attempt to bypass with zero-width characters and Cyrillic 'е' (U+0435)
        // After normalization, non-ASCII chars are stripped and text becomes
        // "remove slh-dsa..." which matches the prohibited pattern.
        let result = gov.submit_proposal(
            addr(1),
            ProposalType::TechnicalUpdate {
                description: "R\u{200B}emove\u{200B} SLH-DSA from consensus".into(),
            },
            2_000_000,
            &staking,
        );

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ConsensusError::DoctrineViolation { law_number: 2, .. }
        ),);
    }

    #[test]
    #[cfg(feature = "governance-extensions")]
    fn finalize_doctrine_recheck() {
        // Even if a proposal somehow entered voting, the double firewall at
        // finalization prevents doctrine-violating proposals from passing.
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 100_000_000)]);

        // Manually inject a doctrine-violating proposal that is Active
        // (simulating a malicious node that skipped the pre-vote check)
        let fake_id = compute_proposal_id(
            &addr(1),
            1000,
            &ProposalType::TechnicalUpdate {
                description: "Remove SLH-DSA completely".into(),
            },
        );
        gov.proposals.insert(
            fake_id,
            Proposal {
                id: fake_id,
                proposer: addr(1),
                proposal_type: ProposalType::TechnicalUpdate {
                    description: "Remove SLH-DSA completely".into(),
                },
                required_approval: RequiredApproval::SequencersOnly,
                submitted_at: 1000,
                voting_ends_at: 1100,
                status: ProposalStatus::Active,
                sequencer_votes: HashMap::new(),
                user_votes: HashMap::new(),
                sequencer_yes_stake: 100_000_000, // 100% yes
                sequencer_no_stake: 0,
                user_yes_power: 0,
                user_no_power: 0,
                user_abstain_power: 0,
                execution_deadline: None,
                snapshot_total_effective_stake: 100_000_000,
                timelock_expires_at: None,
                vetoed: false,
                veto_sequencer_stake: 0,
                veto_user_power: 0,
                veto_voters: std::collections::HashSet::new(),
            },
        );
        gov.stats.active_proposals = 1;

        // Finalize at height past voting_ends_at
        let results = gov.finalize_proposals(1200, &staking);

        assert_eq!(results.len(), 1);
        // Despite 100% yes votes, the doctrine recheck should force Failed
        assert_eq!(results[0].1, ProposalStatus::Failed);
    }

    // ═══════════════════════════════════════════════════════════════
    // Anti-Sybil Governance Tests
    // ═══════════════════════════════════════════════════════════════

    /// Helper: create a StakingState with validators registered at a specific height.
    fn setup_staking_at_height(stakes: &[(u8, u64)], registration_height: u64) -> StakingState {
        let mut staking = StakingState::new(100_000_000_000);
        staking.min_validator_stake = 0;
        for &(id, stake) in stakes {
            staking
                .register_validator_at_height(addr(id), stake, registration_height)
                .expect("register should succeed");
        }
        staking
    }

    #[test]
    fn test_m11_newly_staked_zero_voting_power() {
        // Newly staked funds should have 0 voting power during cooldown.
        let stake = 100_000_000; // 1 BTC
        let registration_block = 1_000_000;
        let during_cooldown = registration_block + GOVERNANCE_STAKE_COOLDOWN_BLOCKS - 1;

        // During cooldown: voting power should be 0
        let power = calculate_governance_voting_power(stake, registration_block, during_cooldown);
        assert_eq!(
            power, 0,
            "M-11: newly staked funds should have 0 voting power during cooldown"
        );

        // At exact cooldown boundary: still 0 (< not <=)
        let at_boundary = registration_block + GOVERNANCE_STAKE_COOLDOWN_BLOCKS - 1;
        let power_boundary =
            calculate_governance_voting_power(stake, registration_block, at_boundary);
        assert_eq!(
            power_boundary, 0,
            "M-11: voting power should be 0 at cooldown boundary"
        );

        // After cooldown: full voting power
        let after_cooldown = registration_block + GOVERNANCE_STAKE_COOLDOWN_BLOCKS;
        let power_after =
            calculate_governance_voting_power(stake, registration_block, after_cooldown);
        assert_eq!(
            power_after, stake,
            "M-11: voting power should equal stake after cooldown"
        );
    }

    #[test]
    fn test_m11_sybil_stake_weighted_prevents_identity_splitting() {
        // 1000 accounts with 1 BRQ each should equal
        // 1 account with 1000 BRQ in stake-weighted voting.
        //
        // This is the fundamental anti-Sybil property: voting power is
        // proportional to staked amount, not number of identities.
        let registration_block = 0;
        let current_block = 100_000; // Well past cooldown

        // Single whale: 1000 BRQ stake
        let whale_power =
            calculate_governance_voting_power(1000, registration_block, current_block);

        // 1000 Sybil accounts with 1 BRQ each
        let sybil_total: u64 = (0..1000)
            .map(|_| calculate_governance_voting_power(1, registration_block, current_block))
            .sum();

        assert_eq!(
            whale_power, sybil_total,
            "M-11: 1 account with 1000 stake should equal 1000 accounts with 1 stake"
        );
        assert_eq!(whale_power, 1000);
        assert_eq!(sybil_total, 1000);
    }

    #[test]
    fn test_m11_vote_sequencer_rejects_during_cooldown() {
        // A validator that just registered should NOT be able
        // to vote in governance until the cooldown has passed.
        let registration_height = 1_000_000;
        let staking = setup_staking_at_height(&[(1, 10_000_000)], registration_height);
        let mut gov = GovernanceManager::new();

        // Submit proposal at a height where validator 1 is past cooldown
        // (need at least one validator that CAN submit)
        let proposal_height = registration_height + GOVERNANCE_STAKE_COOLDOWN_BLOCKS + 1;
        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "M-11 cooldown test".into(),
                },
                proposal_height,
                &staking,
            )
            .unwrap();

        // Now register a NEW validator at the current height (during cooldown)
        let mut staking_with_new = staking.clone();
        staking_with_new
            .register_validator_at_height(addr(2), 5_000_000, proposal_height)
            .unwrap();

        // Validator 2 tries to vote immediately — should be rejected (cooldown)
        let result = gov.vote_sequencer(
            &id,
            addr(2),
            Vote::Yes,
            &staking_with_new,
            proposal_height + 1,
        );
        assert!(
            result.is_err(),
            "M-11: newly registered validator should be rejected during cooldown"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("cooldown"),
            "M-11: error should mention cooldown, got: {}",
            err_msg,
        );

        // Validator 1 (registered long ago) should be able to vote
        let result = gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, proposal_height + 1);
        assert!(
            result.is_ok(),
            "M-11: validator past cooldown should be able to vote"
        );
    }

    #[test]
    fn test_m11_cooldown_overflow_safe() {
        // Ensure cooldown calculation is overflow-safe.
        let stake = 100_000_000;

        // Registration at near-u64::MAX — saturating_add prevents overflow.
        // When registered_at = u64::MAX - 100, saturating_add(28800) = u64::MAX.
        // current_block = u64::MAX >= u64::MAX, so cooldown HAS passed.
        let power = calculate_governance_voting_power(stake, u64::MAX - 100, u64::MAX);
        assert_eq!(
            power, stake,
            "M-11: at u64::MAX block, cooldown has elapsed (overflow-safe)"
        );

        // But at u64::MAX - 1, cooldown has NOT passed:
        // registered_at + cooldown = u64::MAX, current_block = u64::MAX - 1 < u64::MAX
        let power2 = calculate_governance_voting_power(stake, u64::MAX - 100, u64::MAX - 1);
        assert_eq!(power2, 0, "M-11: at u64::MAX - 1, cooldown not yet elapsed");
    }

    #[test]
    fn test_m11_governance_vote_struct() {
        // Verify GovernanceVote struct captures all required fields.
        let vote = GovernanceVote {
            voter: addr(1),
            proposal_id: Hash256([0u8; 32]),
            vote: Vote::Yes,
            stake_weight: 100_000_000,
            stake_lock_block: 500_000,
        };

        assert_eq!(vote.stake_weight, 100_000_000);
        assert_eq!(vote.stake_lock_block, 500_000);
        assert_eq!(vote.vote, Vote::Yes);
    }

    // ═══════════════════════════════════════════════════════════════
    // Time-Lock and Veto Tests
    // ═══════════════════════════════════════════════════════════════

    #[test]
    fn gt3_timelock_set_on_pass() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 70_000_000), (2, 30_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test timelock".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        let finalize_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        let results = gov.finalize_proposals(finalize_height, &staking);
        assert_eq!(results[0].1, ProposalStatus::Passed);

        let p = gov.get_proposal(&id).unwrap();
        assert_eq!(
            p.timelock_expires_at,
            Some(finalize_height + TIMELOCK_TECHNICAL_BLOCKS),
        );
        // No execution deadline yet — must wait for timelock
        assert!(p.execution_deadline.is_none());
    }

    #[test]
    fn gt3_cannot_execute_during_timelock() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 70_000_000), (2, 30_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        let finalize_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        gov.finalize_proposals(finalize_height, &staking);

        // Try to execute during time-lock
        let result = gov.mark_executed(&id, finalize_height + 1);
        assert!(result.is_err(), "execution during time-lock must fail");
    }

    #[test]
    fn gt3_execute_after_timelock() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 70_000_000), (2, 30_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        let finalize_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        gov.finalize_proposals(finalize_height, &staking);

        // Process time-lock after it expires
        let post_timelock = finalize_height + TIMELOCK_TECHNICAL_BLOCKS;
        let executable = gov.process_timelocks(post_timelock);
        assert_eq!(executable.len(), 1);

        // Now execution should succeed
        let result = gov.mark_executed(&id, post_timelock);
        assert!(result.is_ok(), "execution after time-lock must succeed");
    }

    #[test]
    fn gt3_veto_prevents_execution() {
        let mut gov = GovernanceManager::new();
        // 3 validators: 40%, 35%, 25%
        let staking = setup_staking(&[(1, 40_000_000), (2, 35_000_000), (3, 25_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test veto".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        // Validators 1 and 2 vote Yes (75% > 67%)
        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();
        gov.vote_sequencer(&id, addr(2), Vote::Yes, &staking, 2_000_002)
            .unwrap();

        let finalize_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        gov.finalize_proposals(finalize_height, &staking);
        assert_eq!(
            gov.get_proposal(&id).unwrap().status,
            ProposalStatus::Passed,
        );

        // During time-lock, validators 2 and 3 submit vetoes
        // Need MIN_VETO_VOTERS (3) distinct voters at 33.33% threshold.
        // Register 3 more validators for veto votes
        let mut staking2 = staking.clone();
        staking2.register_validator(addr(4), 10_000_000).unwrap();

        // addr(2): 35M, addr(3): 25M, addr(4): 10M = 70M veto stake
        // Total: 100M. 70M/100M = 70% > 33.33% ✓
        let veto_height = finalize_height + 1;
        gov.submit_veto(&id, addr(2), &staking2, veto_height).unwrap();
        gov.submit_veto(&id, addr(3), &staking2, veto_height).unwrap();
        let vetoed = gov.submit_veto(&id, addr(4), &staking2, veto_height).unwrap();
        assert!(vetoed, "veto should be triggered with 70% stake");

        assert_eq!(
            gov.get_proposal(&id).unwrap().status,
            ProposalStatus::Vetoed,
        );

        // Execution should fail
        let post_timelock = finalize_height + TIMELOCK_TECHNICAL_BLOCKS;
        let result = gov.mark_executed(&id, post_timelock);
        assert!(result.is_err(), "vetoed proposal must not execute");
    }

    #[test]
    fn gt3_veto_requires_min_voters() {
        let mut gov = GovernanceManager::new();
        // Single whale with 50% stake
        let staking = setup_staking(&[(1, 50_000_000), (2, 50_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test min voters".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();
        gov.vote_sequencer(&id, addr(2), Vote::Yes, &staking, 2_000_002)
            .unwrap();

        let finalize_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        gov.finalize_proposals(finalize_height, &staking);

        // Single whale veto — 50% stake exceeds 33.33% but only 1 voter < MIN_VETO_VOTERS (3)
        let vetoed = gov.submit_veto(&id, addr(2), &staking, finalize_height + 1).unwrap();
        assert!(
            !vetoed,
            "single voter should not be able to veto despite sufficient stake"
        );
    }

    #[test]
    fn gt3_double_veto_rejected() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 70_000_000), (2, 30_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        let finalize_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        gov.finalize_proposals(finalize_height, &staking);

        // First veto succeeds
        gov.submit_veto(&id, addr(2), &staking, finalize_height + 1).unwrap();

        // Second veto by same voter fails
        let result = gov.submit_veto(&id, addr(2), &staking, finalize_height + 2);
        assert!(result.is_err(), "double veto must be rejected");
    }

    #[test]
    fn gt3_veto_after_timelock_rejected() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 70_000_000), (2, 30_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        let finalize_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        gov.finalize_proposals(finalize_height, &staking);

        // Try to veto after time-lock expires
        let post_timelock = finalize_height + TIMELOCK_TECHNICAL_BLOCKS;
        let result = gov.submit_veto(&id, addr(2), &staking, post_timelock);
        assert!(result.is_err(), "veto after time-lock must be rejected");
    }

    #[test]
    fn gt3_constitutional_has_longest_timelock() {
        assert!(TIMELOCK_CONSTITUTIONAL_BLOCKS > TIMELOCK_SLASHING_BLOCKS);
        assert!(TIMELOCK_SLASHING_BLOCKS > TIMELOCK_FEE_BLOCKS);
        assert!(TIMELOCK_FEE_BLOCKS > TIMELOCK_TECHNICAL_BLOCKS);
    }

    #[test]
    fn gt3_is_in_timelock() {
        let mut gov = GovernanceManager::new();
        let staking = setup_staking(&[(1, 70_000_000), (2, 30_000_000)]);

        let id = gov
            .submit_proposal(
                addr(1),
                ProposalType::TechnicalUpdate {
                    description: "test".into(),
                },
                2_000_000,
                &staking,
            )
            .unwrap();

        gov.vote_sequencer(&id, addr(1), Vote::Yes, &staking, 2_000_001)
            .unwrap();

        let finalize_height = 2_000_000 + VOTING_PERIOD_BLOCKS;
        gov.finalize_proposals(finalize_height, &staking);

        assert!(gov.is_in_timelock(&id, finalize_height + 1));
        assert!(!gov.is_in_timelock(&id, finalize_height + TIMELOCK_TECHNICAL_BLOCKS));
    }
}
