//! Sequencer rotation state machine.
//!
//! ## Design (§9.3 — Multi-Sequencer Rotation)
//!
//! Per-height leader election with 2/3 quorum voting and timeout-based
//! round advance. Each height proceeds through:
//!
//! 1. **WaitingForProposal**: Elected leader proposes a block.
//! 2. **Voting**: Validators vote on the proposed block.
//!    - If 2/3 effective stake votes → **Finalized**.
//! 3. **Timeout**: If no valid proposal within `proposal_timeout_ms`,
//!    validators send timeout votes. At 2/3 quorum → advance round,
//!    new leader elected.
//!
//! ## EOTS Equivocation
//!
//! Two proposals at the same height by the same EOTS key means the key
//! is extractable → automatic 33.33% slash. This is detected by
//! `receive_proposal()` tracking seen proposals per height.

use std::collections::{HashMap, HashSet};

use brrq_crypto::hash::Hash256;
use brrq_types::Address;

use crate::error::ConsensusError;
use crate::staking::StakingState;

/// Configuration for the rotation protocol.
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// How many blocks each sequencer produces per slot.
    pub blocks_per_slot: u64,
    /// Maximum rounds before halting at a height (safety valve).
    pub max_rounds: u32,
    /// Milliseconds before a proposal is considered timed out.
    pub proposal_timeout_ms: u64,
    /// Quorum numerator (default 2 for 2/3 quorum).
    pub quorum_numerator: u64,
    /// Quorum denominator (default 3 for 2/3 quorum).
    pub quorum_denominator: u64,
    /// Number of subsequent blocks required after quorum before a block is
    /// considered fully settled. Default: 1.
    pub finality_depth: u64,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            blocks_per_slot: 1,
            max_rounds: 5,
            proposal_timeout_ms: 6_000,
            quorum_numerator: 2,
            quorum_denominator: 3,
            finality_depth: DEFAULT_FINALITY_DEPTH,
        }
    }
}

/// Current phase of the rotation protocol at a given height.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationPhase {
    /// Waiting for the elected leader to propose a block.
    WaitingForProposal,
    /// A proposal has been received and dry-run; collecting PreVotes.
    PreVoting {
        /// Hash of the proposed block.
        block_hash: Hash256,
        /// The proposer's address.
        proposer: Address,
    },
    /// 2/3 PreVotes reached; collecting PreCommits.
    PreCommitting {
        /// Hash of the proposed block.
        block_hash: Hash256,
        /// The proposer's address.
        proposer: Address,
    },
    /// Block has been finalized by 2/3 PreCommit quorum.
    Finalized {
        /// Hash of the finalized block.
        block_hash: Hash256,
    },
}

/// Actions the caller should take in response to rotation state changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationAction {
    /// No action needed.
    None,
    /// Cast a PreVote for the proposed block after dry-run.
    PreVote {
        height: u64,
        round: u32,
        block_hash: Hash256,
    },
    /// Cast a PreCommit after seeing 2/3 PreVotes.
    PreCommit {
        height: u64,
        round: u32,
        block_hash: Hash256,
    },
    /// Block finalized — commit dry-run state to disk.
    Finalize { block_hash: Hash256 },
    /// Broadcast a timeout vote for the current round (triggers Rollback).
    BroadcastTimeout { height: u64, round: u32 },
    /// Advance to a new round with a new leader.
    NewRound { round: u32, leader: Address },
}

/// Default finality depth: number of blocks after quorum before a block is
/// considered fully settled. A depth of 1 means the block is settled as soon
/// as one subsequent block is finalized on top of it.
pub const DEFAULT_FINALITY_DEPTH: u64 = 1;

/// Per-height rotation state tracking.
///
/// ## Validator Snapshot Isolation
///
/// `RotationState::new()` takes a snapshot of voter stakes from `StakingState`
/// at construction time. All subsequent operations (`receive_vote`,
/// `receive_timeout_vote`) use this snapshot rather than the live staking state.
/// This ensures that mid-round stake changes (e.g., slashing a validator who
/// equivocated) cannot retroactively invalidate finality decisions that were
/// made using the original validator set.
#[derive(Debug, Clone)]
pub struct RotationState {
    /// Configuration.
    config: RotationConfig,
    /// Current block height.
    height: u64,
    /// Current round within this height (starts at 0).
    round: u32,
    /// Current elected leader for this round.
    leader: Address,
    /// Current phase.
    phase: RotationPhase,
    /// PreVotes collected for the current round: voter → block_hash.
    pre_votes: HashMap<Address, Hash256>,
    /// PreCommits collected for the current round: voter → block_hash.
    pre_commits: HashMap<Address, Hash256>,
    /// Effective stake of each voter (for quorum calculation).
    voter_stakes: HashMap<Address, u64>,
    /// Total effective stake of all active validators.
    total_stake: u64,
    /// Timeout votes collected for the current round.
    timeout_votes: HashSet<Address>,
    /// Timeout stake accumulated.
    timeout_stake: u64,
    /// Timestamp (ms) when the current phase started (for timeout detection).
    phase_start_ms: u64,
    /// Proposals seen at this height: proposer → list of block hashes.
    /// Used for equivocation detection.
    proposals_seen: HashMap<Address, Vec<Hash256>>,
}

impl RotationState {
    /// Create a new rotation state for the given height.
    pub fn new(
        config: RotationConfig,
        height: u64,
        leader: Address,
        staking: &StakingState,
        now_ms: u64,
    ) -> Self {
        let mut voter_stakes = HashMap::new();
        let mut total_stake = 0u64;

        for (addr, v) in &staking.validators {
            if v.is_eligible(height) {
                let eff = StakingState::apply_sqrt_cap(v.total_stake(), staking.stake_cap);
                voter_stakes.insert(*addr, eff);
                total_stake = total_stake.saturating_add(eff);
            }
        }

        Self {
            config,
            height,
            round: 0,
            leader,
            phase: RotationPhase::WaitingForProposal,
            pre_votes: HashMap::new(),
            pre_commits: HashMap::new(),
            voter_stakes,
            total_stake,
            timeout_votes: HashSet::new(),
            timeout_stake: 0,
            phase_start_ms: now_ms,
            proposals_seen: HashMap::new(),
        }
    }

    /// Current height.
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Current round.
    pub fn round(&self) -> u32 {
        self.round
    }

    /// Current leader.
    pub fn leader(&self) -> &Address {
        &self.leader
    }

    /// Current phase.
    pub fn phase(&self) -> &RotationPhase {
        &self.phase
    }

    /// Is the block finalized at this height?
    pub fn is_finalized(&self) -> bool {
        matches!(self.phase, RotationPhase::Finalized { .. })
    }

    /// Check if the given stake meets the quorum threshold.
    ///
    /// Standard BFT: `stake * denominator >= total * numerator`.
    /// For 2/3 quorum: `stake * 3 >= total * 2` means "at least 2/3".
    fn has_quorum(&self, stake: u64) -> bool {
        let lhs = stake as u128 * self.config.quorum_denominator as u128;
        let rhs = self.total_stake as u128 * self.config.quorum_numerator as u128;
        lhs >= rhs
    }

    /// Receive a block proposal.
    ///
    /// Returns `RotationAction::Vote` if the proposal is valid and from the
    /// current leader. Returns equivocation evidence if the proposer has
    /// already proposed a different block at this height.
    pub fn receive_proposal(
        &mut self,
        proposer: Address,
        block_hash: Hash256,
        now_ms: u64,
    ) -> Result<RotationAction, ConsensusError> {
        // Reject proposals after finalization
        if self.is_finalized() {
            return Ok(RotationAction::None);
        }

        // Track proposal for equivocation detection
        let seen = self.proposals_seen.entry(proposer).or_default();
        if !seen.contains(&block_hash) {
            seen.push(block_hash);
        }

        // Check for equivocation: same proposer, same height, different blocks
        if seen.len() > 1 {
            return Err(ConsensusError::Equivocation {
                height: self.height,
            });
        }

        // Only accept proposals from the current leader
        if proposer != self.leader {
            return Ok(RotationAction::None);
        }

        // Only accept during WaitingForProposal
        if self.phase != RotationPhase::WaitingForProposal {
            return Ok(RotationAction::None);
        }

        // Transition to PreVoting — reset phase timer for voting timeout.
        self.phase = RotationPhase::PreVoting {
            block_hash,
            proposer,
        };
        self.phase_start_ms = now_ms;

        Ok(RotationAction::PreVote {
            height: self.height,
            round: self.round,
            block_hash,
        })
    }

    /// Check if a combined sum of stakes meets the 2/3 BFT quorum.
    fn calculate_quorum(&self, stakes: impl Iterator<Item = u64>) -> bool {
        let sum: u64 = stakes.fold(0u64, |acc, s| acc.saturating_add(s));
        self.has_quorum(sum)
    }

    /// Receive a PreVote for a block.
    ///
    /// Returns `RotationAction::PreCommit` when 2/3 PreVote quorum is reached.
    pub fn receive_prevote(
        &mut self,
        voter: Address,
        block_hash: Hash256,
        now_ms: u64,
    ) -> Result<RotationAction, ConsensusError> {
        if self.is_finalized() {
            return Ok(RotationAction::None);
        }

        let expected_hash = match &self.phase {
            RotationPhase::PreVoting { block_hash, .. } => *block_hash,
            _ => return Ok(RotationAction::None),
        };

        if block_hash != expected_hash {
            return Ok(RotationAction::None);
        }

        let _voter_stake = match self.voter_stakes.get(&voter) {
            Some(s) => *s,
            None => return Ok(RotationAction::None),
        };

        if self.pre_votes.contains_key(&voter) {
            return Ok(RotationAction::None);
        }

        self.pre_votes.insert(voter, block_hash);

        let stakes = self
            .pre_votes
            .keys()
            .filter_map(|v| self.voter_stakes.get(v))
            .copied();
        if self.calculate_quorum(stakes) {
            self.phase = RotationPhase::PreCommitting {
                block_hash,
                proposer: self.leader,
            };
            self.phase_start_ms = now_ms;
            return Ok(RotationAction::PreCommit {
                height: self.height,
                round: self.round,
                block_hash,
            });
        }

        Ok(RotationAction::None)
    }

    /// Receive a PreCommit for a block.
    ///
    /// Returns `RotationAction::Finalize` when 2/3 PreCommit quorum is reached.
    pub fn receive_precommit(
        &mut self,
        voter: Address,
        block_hash: Hash256,
    ) -> Result<RotationAction, ConsensusError> {
        if self.is_finalized() {
            return Ok(RotationAction::None);
        }

        let expected_hash = match &self.phase {
            RotationPhase::PreCommitting { block_hash, .. } => *block_hash,
            _ => return Ok(RotationAction::None),
        };

        if block_hash != expected_hash {
            return Ok(RotationAction::None);
        }

        let _voter_stake = match self.voter_stakes.get(&voter) {
            Some(s) => *s,
            None => return Ok(RotationAction::None),
        };

        if self.pre_commits.contains_key(&voter) {
            return Ok(RotationAction::None);
        }

        self.pre_commits.insert(voter, block_hash);

        let stakes = self
            .pre_commits
            .keys()
            .filter_map(|v| self.voter_stakes.get(v))
            .copied();
        if self.calculate_quorum(stakes) {
            self.phase = RotationPhase::Finalized { block_hash };
            return Ok(RotationAction::Finalize { block_hash });
        }

        Ok(RotationAction::None)
    }

    /// Receive a timeout vote.
    ///
    /// Returns `RotationAction::NewRound` when 2/3 timeout quorum is reached.
    pub fn receive_timeout_vote(
        &mut self,
        voter: Address,
    ) -> Result<RotationAction, ConsensusError> {
        // Reject after finalization
        if self.is_finalized() {
            return Ok(RotationAction::None);
        }

        // Voter must be in active set
        let voter_stake = match self.voter_stakes.get(&voter) {
            Some(s) => *s,
            None => return Ok(RotationAction::None),
        };

        // Deduplicate
        if self.timeout_votes.contains(&voter) {
            return Ok(RotationAction::None);
        }

        self.timeout_votes.insert(voter);
        self.timeout_stake = self.timeout_stake.saturating_add(voter_stake);

        // Check timeout quorum (same formula as vote quorum)
        if self.has_quorum(self.timeout_stake) {
            // Advance round — caller must re-elect leader
            return Ok(RotationAction::NewRound {
                round: self.round.saturating_add(1),
                leader: Address::ZERO, // Placeholder: caller computes via LeaderElection
            });
        }

        Ok(RotationAction::None)
    }

    /// Check if the current phase has timed out.
    ///
    /// Call this periodically (e.g., every 500ms tick).
    /// Returns `BroadcastTimeout` if the timeout has elapsed.
    ///
    /// Applies to:
    /// - `WaitingForProposal` (1x timeout)
    /// - `PreVoting` (2x timeout)
    /// - `PreCommitting` (3x timeout)
    pub fn check_timeout(&self, now_ms: u64) -> Option<RotationAction> {
        if self.is_finalized() {
            return None;
        }

        let elapsed = now_ms.saturating_sub(self.phase_start_ms);

        match &self.phase {
            RotationPhase::WaitingForProposal => {
                if elapsed >= self.config.proposal_timeout_ms {
                    return Some(RotationAction::BroadcastTimeout {
                        height: self.height,
                        round: self.round,
                    });
                }
            }
            RotationPhase::PreVoting { .. } => {
                let prevote_timeout = self.config.proposal_timeout_ms.saturating_mul(2);
                if elapsed >= prevote_timeout {
                    return Some(RotationAction::BroadcastTimeout {
                        height: self.height,
                        round: self.round,
                    });
                }
            }
            RotationPhase::PreCommitting { .. } => {
                let precommit_timeout = self.config.proposal_timeout_ms.saturating_mul(3);
                if elapsed >= precommit_timeout {
                    return Some(RotationAction::BroadcastTimeout {
                        height: self.height,
                        round: self.round,
                    });
                }
            }
            RotationPhase::Finalized { .. } => {}
        }

        None
    }

    /// Advance to the next round after a timeout quorum.
    ///
    /// Resets votes and timeout state, elects new leader.
    pub fn advance_round(
        &mut self,
        new_leader: Address,
        now_ms: u64,
    ) -> Result<(), ConsensusError> {
        if self.is_finalized() {
            return Err(ConsensusError::InvalidBlock {
                reason: "cannot advance round: already finalized".into(),
            });
        }

        let new_round = self.round.saturating_add(1);
        if new_round > self.config.max_rounds {
            return Err(ConsensusError::LeaderElectionFailed {
                reason: format!(
                    "max rounds ({}) exceeded at height {}",
                    self.config.max_rounds, self.height
                ),
            });
        }

        self.round = new_round;
        self.leader = new_leader;
        self.phase = RotationPhase::WaitingForProposal;
        self.pre_votes.clear();
        self.pre_commits.clear();
        self.timeout_votes.clear();
        self.timeout_stake = 0;
        self.phase_start_ms = now_ms;

        Ok(())
    }

    /// Advance to a specific round, skipping intermediate rounds.
    ///
    /// Used after partition rejoin when the view sync protocol determines
    /// the network should continue from a higher round. Target round should
    /// be `max(local_highest, peer_highest) + 1`.
    pub fn advance_to_round(
        &mut self,
        target_round: u32,
        new_leader: Address,
        now_ms: u64,
    ) -> Result<(), ConsensusError> {
        if self.is_finalized() {
            return Err(ConsensusError::InvalidBlock {
                reason: "cannot advance round: already finalized".into(),
            });
        }

        if target_round <= self.round {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "advance_to_round: target round {} must be > current round {}",
                    target_round, self.round
                ),
            });
        }

        if target_round > self.config.max_rounds {
            return Err(ConsensusError::LeaderElectionFailed {
                reason: format!(
                    "max rounds ({}) exceeded at height {}",
                    self.config.max_rounds, self.height
                ),
            });
        }

        self.round = target_round;
        self.leader = new_leader;
        self.phase = RotationPhase::WaitingForProposal;
        self.pre_votes.clear();
        self.pre_commits.clear();
        self.timeout_votes.clear();
        self.timeout_stake = 0;
        self.phase_start_ms = now_ms;

        Ok(())
    }

    /// Get the total effective stake snapshot (for view sync initialization).
    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    /// Get equivocation evidence for a proposer, if any.
    ///
    /// Returns the list of distinct block hashes proposed by this address
    /// at the current height. Length > 1 means equivocation.
    pub fn equivocation_evidence(&self, proposer: &Address) -> Option<&Vec<Hash256>> {
        self.proposals_seen
            .get(proposer)
            .filter(|hashes| hashes.len() > 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;

    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address(bytes)
    }

    fn hash(n: u8) -> Hash256 {
        Hasher::hash(&[n; 32])
    }

    fn setup_staking() -> StakingState {
        let mut s = StakingState::new(100_000_000_000);
        s.register_validator(addr(1), 1_000_000_000).unwrap();
        s.register_validator(addr(2), 1_000_000_000).unwrap();
        s.register_validator(addr(3), 1_000_000_000).unwrap();
        s
    }

    fn default_config() -> RotationConfig {
        RotationConfig::default()
    }

    #[test]
    fn test_happy_path_proposal_to_finalize() {
        let staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        // Leader proposes
        let action = state.receive_proposal(addr(1), hash(1), 100).unwrap();
        assert_eq!(
            action,
            RotationAction::PreVote {
                height: 100,
                round: 0,
                block_hash: hash(1),
            }
        );
        assert!(matches!(state.phase(), RotationPhase::PreVoting { .. }));

        // Validator 1 prevotes
        let action = state.receive_prevote(addr(1), hash(1), 100).unwrap();
        assert_eq!(action, RotationAction::None); // Not enough yet

        // Validator 2 prevotes → 2/3 quorum (2 out of 3, equal stake) → Phase transitions to PreCommitting
        let action = state.receive_prevote(addr(2), hash(1), 100).unwrap();
        assert_eq!(
            action,
            RotationAction::PreCommit {
                height: 100,
                round: 0,
                block_hash: hash(1)
            }
        );
        assert!(matches!(state.phase(), RotationPhase::PreCommitting { .. }));

        // Validator 1 precommits
        let action = state.receive_precommit(addr(1), hash(1)).unwrap();
        assert_eq!(action, RotationAction::None); // Not enough yet

        // Validator 2 precommits → 2/3 quorum → Finalized
        let action = state.receive_precommit(addr(2), hash(1)).unwrap();
        assert_eq!(
            action,
            RotationAction::Finalize {
                block_hash: hash(1)
            }
        );
        assert!(state.is_finalized());
    }

    #[test]
    fn test_non_leader_proposal_ignored() {
        let staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        // addr(2) is not the leader
        let action = state.receive_proposal(addr(2), hash(1), 100).unwrap();
        assert_eq!(action, RotationAction::None);
        assert!(matches!(state.phase(), RotationPhase::WaitingForProposal));
    }

    #[test]
    fn test_timeout_and_round_advance() {
        let staking = setup_staking();
        let config = RotationConfig {
            proposal_timeout_ms: 1000,
            ..default_config()
        };
        let state = RotationState::new(config, 100, addr(1), &staking, 0);

        // Not timed out at 500ms
        assert!(state.check_timeout(500).is_none());

        // Timed out at 1000ms
        let action = state.check_timeout(1000);
        assert_eq!(
            action,
            Some(RotationAction::BroadcastTimeout {
                height: 100,
                round: 0,
            })
        );
    }

    #[test]
    fn test_timeout_quorum_advances_round() {
        let staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        // Collect timeout votes
        let action = state.receive_timeout_vote(addr(1)).unwrap();
        assert_eq!(action, RotationAction::None);

        let action = state.receive_timeout_vote(addr(2)).unwrap();
        assert!(matches!(action, RotationAction::NewRound { round: 1, .. }));

        // Advance round with new leader
        state.advance_round(addr(2), 7000).unwrap();
        assert_eq!(state.round(), 1);
        assert_eq!(*state.leader(), addr(2));
        assert!(matches!(state.phase(), RotationPhase::WaitingForProposal));
    }

    #[test]
    fn test_equivocation_detected() {
        let staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        // First proposal — accepted
        state.receive_proposal(addr(1), hash(1), 100).unwrap();

        // Reset phase to accept another proposal (simulate receiving via gossip)
        state.phase = RotationPhase::WaitingForProposal;

        // Second proposal with different hash — equivocation!
        let result = state.receive_proposal(addr(1), hash(2), 200);
        assert!(result.is_err());

        // Evidence should be available
        let evidence = state.equivocation_evidence(&addr(1));
        assert!(evidence.is_some());
        assert_eq!(evidence.unwrap().len(), 2);
    }

    #[test]
    fn test_duplicate_vote_ignored() {
        let staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        state.receive_proposal(addr(1), hash(1), 100).unwrap();

        // First prevote from addr(1)
        state.receive_prevote(addr(1), hash(1), 0).unwrap();

        // Duplicate prevote from addr(1) — ignored
        let action = state.receive_prevote(addr(1), hash(1), 0).unwrap();
        assert_eq!(action, RotationAction::None);
    }

    #[test]
    fn test_vote_wrong_hash_ignored() {
        let staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        state.receive_proposal(addr(1), hash(1), 100).unwrap();

        // Prevote for wrong block
        let action = state.receive_prevote(addr(2), hash(99), 0).unwrap();
        assert_eq!(action, RotationAction::None);
    }

    #[test]
    fn test_max_rounds_exceeded() {
        let staking = setup_staking();
        let config = RotationConfig {
            max_rounds: 2,
            ..default_config()
        };
        let mut state = RotationState::new(config, 100, addr(1), &staking, 0);

        // Advance to round 1
        state.advance_round(addr(2), 1000).unwrap();
        // Advance to round 2
        state.advance_round(addr(3), 2000).unwrap();
        // Round 3 should fail (max_rounds = 2)
        let result = state.advance_round(addr(1), 3000);
        assert!(result.is_err());
    }

    #[test]
    fn test_finalized_rejects_further_actions() {
        let staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        // Finalize: proposal → prevotes → precommits
        state.receive_proposal(addr(1), hash(1), 100).unwrap();
        state.receive_prevote(addr(1), hash(1), 0).unwrap();
        state.receive_prevote(addr(2), hash(1), 0).unwrap();
        state.receive_precommit(addr(1), hash(1)).unwrap();
        state.receive_precommit(addr(2), hash(1)).unwrap();
        assert!(state.is_finalized());

        // Further proposals ignored
        let action = state.receive_proposal(addr(1), hash(2), 200).unwrap();
        assert_eq!(action, RotationAction::None);

        // Further prevotes ignored
        let action = state.receive_prevote(addr(3), hash(1), 0).unwrap();
        assert_eq!(action, RotationAction::None);

        // Timeout check returns None
        assert!(state.check_timeout(999_999).is_none());

        // Advance round fails
        assert!(state.advance_round(addr(2), 10000).is_err());
    }

    #[test]
    fn test_non_validator_vote_ignored() {
        let staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        state.receive_proposal(addr(1), hash(1), 100).unwrap();

        // addr(99) is not a validator
        let action = state.receive_prevote(addr(99), hash(1), 0).unwrap();
        assert_eq!(action, RotationAction::None);
    }

    #[test]
    fn test_voting_phase_timeout() {
        // H-3: voting phase must timeout if quorum is never reached.
        let staking = setup_staking();
        let config = RotationConfig {
            proposal_timeout_ms: 1000,
            ..default_config()
        };
        let mut state = RotationState::new(config, 100, addr(1), &staking, 0);

        // Leader proposes at t=500.
        state.receive_proposal(addr(1), hash(1), 500).unwrap();
        assert!(matches!(state.phase(), RotationPhase::PreVoting { .. }));

        // Not timed out at t=1500 (1000ms elapsed, but voting timeout = 2000ms).
        assert!(state.check_timeout(1500).is_none());

        // Timed out at t=2600 (2100ms elapsed > 2× 1000ms).
        let action = state.check_timeout(2600);
        assert_eq!(
            action,
            Some(RotationAction::BroadcastTimeout {
                height: 100,
                round: 0,
            })
        );
    }

    #[test]
    fn test_snapshot_isolation_from_live_staking() {
        // Verify that RotationState snapshots voter stakes at construction
        // time and uses the snapshot for quorum, even if staking changes later.
        let mut staking = setup_staking();
        let mut state = RotationState::new(default_config(), 100, addr(1), &staking, 0);

        // Slash validator 1 in the live staking state (33.33% slash)
        staking.slash(&addr(1), 3333).unwrap();

        // Propose and vote — the snapshot should still have the original stakes
        state.receive_proposal(addr(1), hash(1), 100).unwrap();

        // Prevote from the slashed validator — should still use original stake
        let action = state.receive_prevote(addr(1), hash(1), 0).unwrap();
        assert_eq!(action, RotationAction::None); // 1/3, not enough

        // Prevote from validator 2 → should reach prevote quorum (2/3)
        let action = state.receive_prevote(addr(2), hash(1), 0).unwrap();
        assert_eq!(
            action,
            RotationAction::PreCommit {
                height: 100,
                round: 0,
                block_hash: hash(1)
            }
        );

        // Precommit from validator 1
        let action = state.receive_precommit(addr(1), hash(1)).unwrap();
        assert_eq!(action, RotationAction::None); // 1/3, not enough

        // Precommit from validator 2 → should reach quorum (2/3) → Finalize
        let action = state.receive_precommit(addr(2), hash(1)).unwrap();
        assert_eq!(
            action,
            RotationAction::Finalize {
                block_hash: hash(1)
            }
        );
    }

    #[test]
    fn test_advance_to_round_multi_skip() {
        let staking = setup_staking();
        let mut state = RotationState::new(
            RotationConfig {
                max_rounds: 10,
                ..default_config()
            },
            100,
            addr(1),
            &staking,
            0,
        );

        // Skip directly to round 5
        state.advance_to_round(5, addr(3), 5000).unwrap();
        assert_eq!(state.round(), 5);
        assert_eq!(*state.leader(), addr(3));
        assert!(matches!(state.phase(), RotationPhase::WaitingForProposal));
    }

    #[test]
    fn test_finality_depth_in_config() {
        let config = RotationConfig::default();
        assert_eq!(config.finality_depth, DEFAULT_FINALITY_DEPTH);
        assert_eq!(config.finality_depth, 1);

        let custom = RotationConfig {
            finality_depth: 3,
            ..Default::default()
        };
        assert_eq!(custom.finality_depth, 3);
    }

    #[test]
    fn test_voting_phase_timer_reset() {
        // Verify that phase_start_ms is reset when entering Voting phase.
        let staking = setup_staking();
        let config = RotationConfig {
            proposal_timeout_ms: 1000,
            ..default_config()
        };
        let mut state = RotationState::new(config, 100, addr(1), &staking, 0);

        // Proposal arrives at t=800 — timer should reset.
        state.receive_proposal(addr(1), hash(1), 800).unwrap();

        // At t=2700 (1900ms since proposal): should NOT timeout (< 2000ms voting timeout).
        assert!(state.check_timeout(2700).is_none());

        // At t=2900 (2100ms since proposal): SHOULD timeout.
        assert!(state.check_timeout(2900).is_some());
    }
}
