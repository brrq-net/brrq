//! Commit-Reveal voting — Dark DAO defense.
//!
//! ## Design (Article 10)
//!
//! Standard open voting allows vote-buying via Dark DAOs (smart contracts on
//! other chains that pay users to vote a certain way and prove it on-chain).
//!
//! Commit-Reveal breaks this by making the vote direction unknowable until
//! the reveal phase:
//!
//! **Phase 1 — Commit**: Voter submits `H(proposal_id || voter || vote || salt)`.
//!   Nobody knows which way they voted.
//!
//! **Phase 2 — Reveal**: Voter reveals `(vote, salt)`. Nodes verify the hash.
//!
//! **Anti-bribery property**: Since votes can be changed during the confirmation
//! phase, no smart contract can guarantee a vote outcome, making bribery futile.

use std::collections::HashMap;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_types::Address;

use crate::ConsensusError;
use crate::governance::Vote;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Commit phase duration: 3 days at 3s/block.
pub const COMMIT_PHASE_BLOCKS: u64 = 86_400;

/// Reveal phase duration: 1 day at 3s/block.
pub const REVEAL_PHASE_BLOCKS: u64 = 28_800;

/// Domain separation tag for vote commitments.
const VOTE_COMMIT_DOMAIN: &[u8] = b"brrq/governance/vote-commit/v1";

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// Current phase of a commit-reveal voting session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitRevealPhase {
    /// Voters submit commitments (hashed votes).
    Commit,
    /// Voters reveal their votes and salts.
    Reveal,
    /// Session is complete — all reveals processed.
    Completed,
}

/// A single vote commitment.
#[derive(Debug, Clone)]
pub struct VoteCommitment {
    /// The commitment hash: H(domain || proposal_id || voter || vote || salt).
    pub commitment: Hash256,
    /// Block height when committed.
    pub committed_at: u64,
    /// Whether the vote has been revealed.
    pub revealed: bool,
    /// The revealed vote (None until revealed).
    pub revealed_vote: Option<Vote>,
}

/// A commit-reveal voting session for a single proposal.
#[derive(Debug, Clone)]
pub struct CommitRevealSession {
    /// The proposal this session belongs to.
    pub proposal_id: Hash256,
    /// Current phase.
    pub phase: CommitRevealPhase,
    /// Block height when commit phase started.
    pub commit_start: u64,
    /// Block height when reveal phase starts.
    pub reveal_start: u64,
    /// Block height when the session ends.
    pub session_end: u64,
    /// Commitments keyed by voter address.
    pub commitments: HashMap<Address, VoteCommitment>,
    /// Revealed votes: address → (vote, vote_power).
    pub revealed_votes: HashMap<Address, (Vote, u64)>,
    /// Total Yes vote power (from reveals).
    pub yes_power: u64,
    /// Total No vote power (from reveals).
    pub no_power: u64,
    /// Total Abstain vote power (from reveals).
    pub abstain_power: u64,
}

/// Events emitted by the commit-reveal system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitRevealEvent {
    /// Emitted when a session completes with voters who committed but did not
    /// reveal their vote. These voters should be penalized (e.g., reputation
    /// hit or small slash) to discourage commitment without follow-through.
    NonRevealed {
        /// The proposal this event is for.
        session_id: Hash256,
        /// Addresses that committed but failed to reveal.
        non_revealers: Vec<Address>,
    },
}

// ═══════════════════════════════════════════════════════════════
// Commitment Hash
// ═══════════════════════════════════════════════════════════════

/// Compute the vote commitment hash.
///
/// `commitment = H(domain || proposal_id || voter || vote_byte || vote_power || salt)`
///
/// Domain separation ensures commitments from different contexts don't collide.
/// `vote_power` is included in the hash to prevent inflation at reveal time —
/// the voter commits to their stake weight alongside their vote direction.
pub fn compute_commitment(
    proposal_id: &Hash256,
    voter: &Address,
    vote: Vote,
    vote_power: u64,
    salt: &[u8; 32],
) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(VOTE_COMMIT_DOMAIN);
    hasher.update(proposal_id.as_bytes());
    hasher.update(voter.as_bytes());
    hasher.update(&[vote_to_byte(vote)]);
    hasher.update(&vote_power.to_le_bytes());
    hasher.update(salt);
    hasher.finalize()
}

fn vote_to_byte(vote: Vote) -> u8 {
    match vote {
        Vote::Yes => 1,
        Vote::No => 2,
        Vote::Abstain => 3,
    }
}

// ═══════════════════════════════════════════════════════════════
// CommitRevealManager
// ═══════════════════════════════════════════════════════════════

/// Manages commit-reveal voting sessions for governance proposals.
///
/// One session per proposal. Sessions are created when a proposal enters
/// the voting phase and progress through Commit → Reveal → Completed.
#[derive(Debug, Clone)]
pub struct CommitRevealManager {
    /// Active sessions keyed by proposal ID.
    pub sessions: HashMap<Hash256, CommitRevealSession>,
}

impl Default for CommitRevealManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitRevealManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Start a new commit-reveal session for a proposal.
    pub fn start_session(
        &mut self,
        proposal_id: Hash256,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        if self.sessions.contains_key(&proposal_id) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("commit-reveal session already exists for {}", proposal_id),
            });
        }

        let reveal_start = current_height.saturating_add(COMMIT_PHASE_BLOCKS);
        let session_end = reveal_start.saturating_add(REVEAL_PHASE_BLOCKS);

        let session = CommitRevealSession {
            proposal_id,
            phase: CommitRevealPhase::Commit,
            commit_start: current_height,
            reveal_start,
            session_end,
            commitments: HashMap::new(),
            revealed_votes: HashMap::new(),
            yes_power: 0,
            no_power: 0,
            abstain_power: 0,
        };

        self.sessions.insert(proposal_id, session);
        Ok(())
    }

    /// Submit a vote commitment during the commit phase.
    ///
    /// The voter provides `H(proposal_id || voter || vote || salt)` without
    /// revealing the actual vote. This prevents vote-buying because no one
    /// (including a Dark DAO contract) can verify the vote direction.
    pub fn submit_commitment(
        &mut self,
        proposal_id: &Hash256,
        voter: Address,
        commitment: Hash256,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let session =
            self.sessions
                .get_mut(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no commit-reveal session for {}", proposal_id),
                })?;

        // Must be in commit phase
        if session.phase != CommitRevealPhase::Commit {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("session is in {:?} phase, expected Commit", session.phase,),
            });
        }

        if current_height >= session.reveal_start {
            return Err(ConsensusError::InvalidBlock {
                reason: "commit phase has ended".to_string(),
            });
        }

        // No duplicate commitments (but allow re-commit to change vote secretly)
        let vote_commitment = VoteCommitment {
            commitment,
            committed_at: current_height,
            revealed: false,
            revealed_vote: None,
        };

        session.commitments.insert(voter, vote_commitment);
        Ok(())
    }

    /// Reveal a previously committed vote.
    ///
    /// The voter provides the actual vote and salt. The node verifies that
    /// `H(proposal_id || voter || vote || salt) == commitment`.
    pub fn reveal_vote(
        &mut self,
        proposal_id: &Hash256,
        voter: Address,
        vote: Vote,
        salt: &[u8; 32],
        vote_power: u64,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let session =
            self.sessions
                .get_mut(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no commit-reveal session for {}", proposal_id),
                })?;

        // Must be in reveal phase
        if session.phase != CommitRevealPhase::Reveal {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("session is in {:?} phase, expected Reveal", session.phase,),
            });
        }

        if current_height >= session.session_end {
            return Err(ConsensusError::InvalidBlock {
                reason: "reveal phase has ended".to_string(),
            });
        }

        // Must have a commitment
        let commitment_entry =
            session
                .commitments
                .get_mut(&voter)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no commitment found for voter {}", voter),
                })?;

        if commitment_entry.revealed {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("voter {} has already revealed", voter),
            });
        }

        // Verify the commitment (includes vote_power to prevent inflation)
        let expected = compute_commitment(proposal_id, &voter, vote, vote_power, salt);
        if expected != commitment_entry.commitment {
            return Err(ConsensusError::InvalidBlock {
                reason: "commitment verification failed: hash mismatch".to_string(),
            });
        }

        // Record the revealed vote
        commitment_entry.revealed = true;
        commitment_entry.revealed_vote = Some(vote);
        session.revealed_votes.insert(voter, (vote, vote_power));

        match vote {
            Vote::Yes => {
                session.yes_power = session.yes_power.saturating_add(vote_power);
            }
            Vote::No => {
                session.no_power = session.no_power.saturating_add(vote_power);
            }
            Vote::Abstain => {
                session.abstain_power = session.abstain_power.saturating_add(vote_power);
            }
        }

        Ok(())
    }

    /// Process block — transition phases based on block height.
    ///
    /// Also cleans up completed sessions that are older than one full
    /// session cycle (commit + reveal) to prevent unbounded HashMap growth.
    ///
    /// Delegates to `process_block_with_events` to avoid duplicated logic.
    pub fn process_block(&mut self, current_height: u64) {
        let _ = self.process_block_with_events(current_height);
    }

    /// Get the results of a completed session.
    ///
    /// Returns `(yes_power, no_power, abstain_power, total_committed, total_revealed)`.
    pub fn get_results(&self, proposal_id: &Hash256) -> Option<(u64, u64, u64, usize, usize)> {
        let session = self.sessions.get(proposal_id)?;
        if session.phase != CommitRevealPhase::Completed {
            return None;
        }
        Some((
            session.yes_power,
            session.no_power,
            session.abstain_power,
            session.commitments.len(),
            session.revealed_votes.len(),
        ))
    }

    /// Count unrevealed commitments (voters who committed but didn't reveal).
    pub fn unrevealed_count(&self, proposal_id: &Hash256) -> Option<usize> {
        let session = self.sessions.get(proposal_id)?;
        let total = session.commitments.len();
        let revealed = session.revealed_votes.len();
        Some(total - revealed)
    }

    /// Get the list of voters who committed but failed to reveal.
    ///
    /// Returns `None` if the session doesn't exist, or `Some(vec)` with the
    /// addresses of non-revealers. An empty vec means everyone revealed.
    pub fn non_revealers(&self, proposal_id: &Hash256) -> Option<Vec<Address>> {
        let session = self.sessions.get(proposal_id)?;
        let non_revealers: Vec<Address> = session
            .commitments
            .iter()
            .filter(|(_, commitment)| !commitment.revealed)
            .map(|(addr, _)| *addr)
            .collect();
        Some(non_revealers)
    }

    /// Process block with events — transition phases and emit NonRevealed events.
    ///
    /// Returns a list of events for sessions that transitioned to Completed
    /// with unrevealed commitments. The caller should use these to apply
    /// penalties to non-revealers.
    pub fn process_block_with_events(&mut self, current_height: u64) -> Vec<CommitRevealEvent> {
        let mut events = Vec::new();

        for session in self.sessions.values_mut() {
            match session.phase {
                CommitRevealPhase::Commit if current_height >= session.reveal_start => {
                    session.phase = CommitRevealPhase::Reveal;
                }
                CommitRevealPhase::Reveal if current_height >= session.session_end => {
                    session.phase = CommitRevealPhase::Completed;

                    // Collect non-revealers
                    let non_revealers: Vec<Address> = session
                        .commitments
                        .iter()
                        .filter(|(_, c)| !c.revealed)
                        .map(|(addr, _)| *addr)
                        .collect();

                    if !non_revealers.is_empty() {
                        events.push(CommitRevealEvent::NonRevealed {
                            session_id: session.proposal_id,
                            non_revealers,
                        });
                    }
                }
                _ => {}
            }
        }

        // Garbage-collect completed sessions older than one full cycle.
        let gc_threshold = COMMIT_PHASE_BLOCKS + REVEAL_PHASE_BLOCKS;
        self.sessions.retain(|_, session| {
            if session.phase == CommitRevealPhase::Completed {
                current_height < session.session_end.saturating_add(gc_threshold)
            } else {
                true
            }
        });

        events
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pid(val: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        Hash256(bytes)
    }

    fn voter(val: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = val;
        Address(bytes)
    }

    fn salt(val: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = val;
        s
    }

    #[test]
    fn full_commit_reveal_cycle() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);
        let alice = voter(1);
        let alice_salt = salt(42);

        // Start session
        mgr.start_session(proposal, 1000).unwrap();

        // Alice commits: Yes vote with 10_000 vote power
        let commitment = compute_commitment(&proposal, &alice, Vote::Yes, 10_000, &alice_salt);
        mgr.submit_commitment(&proposal, alice, commitment, 1500)
            .unwrap();

        // Transition to reveal phase
        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS);
        let session = mgr.sessions.get(&proposal).unwrap();
        assert_eq!(session.phase, CommitRevealPhase::Reveal);

        // Alice reveals
        mgr.reveal_vote(
            &proposal,
            alice,
            Vote::Yes,
            &alice_salt,
            10_000,
            1000 + COMMIT_PHASE_BLOCKS + 100,
        )
        .unwrap();

        // Transition to completed
        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS + REVEAL_PHASE_BLOCKS);
        let session = mgr.sessions.get(&proposal).unwrap();
        assert_eq!(session.phase, CommitRevealPhase::Completed);

        // Check results
        let (yes, no, abstain, committed, revealed) = mgr.get_results(&proposal).unwrap();
        assert_eq!(yes, 10_000);
        assert_eq!(no, 0);
        assert_eq!(abstain, 0);
        assert_eq!(committed, 1);
        assert_eq!(revealed, 1);
    }

    #[test]
    fn wrong_salt_fails_reveal() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);
        let alice = voter(1);

        mgr.start_session(proposal, 1000).unwrap();

        let commitment = compute_commitment(&proposal, &alice, Vote::Yes, 10_000, &salt(42));
        mgr.submit_commitment(&proposal, alice, commitment, 1500)
            .unwrap();

        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS);

        // Wrong salt
        let err = mgr
            .reveal_vote(
                &proposal,
                alice,
                Vote::Yes,
                &salt(99),
                10_000,
                1000 + COMMIT_PHASE_BLOCKS + 100,
            )
            .unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn wrong_vote_fails_reveal() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);
        let alice = voter(1);
        let alice_salt = salt(42);

        mgr.start_session(proposal, 1000).unwrap();

        let commitment = compute_commitment(&proposal, &alice, Vote::Yes, 10_000, &alice_salt);
        mgr.submit_commitment(&proposal, alice, commitment, 1500)
            .unwrap();

        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS);

        // Claims No but committed Yes
        let err = mgr
            .reveal_vote(
                &proposal,
                alice,
                Vote::No,
                &alice_salt,
                10_000,
                1000 + COMMIT_PHASE_BLOCKS + 100,
            )
            .unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn cannot_commit_during_reveal() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);

        mgr.start_session(proposal, 1000).unwrap();
        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS);

        let err = mgr
            .submit_commitment(
                &proposal,
                voter(1),
                Hash256::default(),
                1000 + COMMIT_PHASE_BLOCKS + 100,
            )
            .unwrap_err();
        assert!(err.to_string().contains("Commit"));
    }

    #[test]
    fn cannot_reveal_during_commit() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);

        mgr.start_session(proposal, 1000).unwrap();

        let err = mgr
            .reveal_vote(&proposal, voter(1), Vote::Yes, &salt(1), 100, 1500)
            .unwrap_err();
        assert!(err.to_string().contains("Reveal"));
    }

    #[test]
    fn unrevealed_count() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);

        mgr.start_session(proposal, 1000).unwrap();

        // Two commits
        let c1 = compute_commitment(&proposal, &voter(1), Vote::Yes, 100, &salt(1));
        let c2 = compute_commitment(&proposal, &voter(2), Vote::No, 100, &salt(2));
        mgr.submit_commitment(&proposal, voter(1), c1, 1100)
            .unwrap();
        mgr.submit_commitment(&proposal, voter(2), c2, 1200)
            .unwrap();

        // Only one reveals
        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS);
        mgr.reveal_vote(
            &proposal,
            voter(1),
            Vote::Yes,
            &salt(1),
            100,
            1000 + COMMIT_PHASE_BLOCKS + 100,
        )
        .unwrap();

        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS + REVEAL_PHASE_BLOCKS);

        assert_eq!(mgr.unrevealed_count(&proposal).unwrap(), 1);
    }

    #[test]
    fn non_revealers_tracked() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);

        mgr.start_session(proposal, 1000).unwrap();

        // Two commits
        let c1 = compute_commitment(&proposal, &voter(1), Vote::Yes, 100, &salt(1));
        let c2 = compute_commitment(&proposal, &voter(2), Vote::No, 100, &salt(2));
        mgr.submit_commitment(&proposal, voter(1), c1, 1100)
            .unwrap();
        mgr.submit_commitment(&proposal, voter(2), c2, 1200)
            .unwrap();

        // Only voter(1) reveals
        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS);
        mgr.reveal_vote(
            &proposal,
            voter(1),
            Vote::Yes,
            &salt(1),
            100,
            1000 + COMMIT_PHASE_BLOCKS + 100,
        )
        .unwrap();

        // Complete session
        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS + REVEAL_PHASE_BLOCKS);

        let non_rev = mgr.non_revealers(&proposal).unwrap();
        assert_eq!(non_rev.len(), 1);
        assert_eq!(non_rev[0], voter(2));
    }

    #[test]
    fn process_block_with_events_emits_non_revealed() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);

        mgr.start_session(proposal, 1000).unwrap();

        // Commit but don't reveal
        let c1 = compute_commitment(&proposal, &voter(1), Vote::Yes, 100, &salt(1));
        mgr.submit_commitment(&proposal, voter(1), c1, 1100)
            .unwrap();

        // Transition to reveal
        mgr.process_block_with_events(1000 + COMMIT_PHASE_BLOCKS);

        // Complete — should emit NonRevealed event
        let events =
            mgr.process_block_with_events(1000 + COMMIT_PHASE_BLOCKS + REVEAL_PHASE_BLOCKS);
        assert_eq!(events.len(), 1);
        match &events[0] {
            CommitRevealEvent::NonRevealed {
                session_id,
                non_revealers,
            } => {
                assert_eq!(*session_id, proposal);
                assert_eq!(non_revealers.len(), 1);
                assert_eq!(non_revealers[0], voter(1));
            }
        }
    }

    #[test]
    fn all_revealed_no_event() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);

        mgr.start_session(proposal, 1000).unwrap();

        let c1 = compute_commitment(&proposal, &voter(1), Vote::Yes, 100, &salt(1));
        mgr.submit_commitment(&proposal, voter(1), c1, 1100)
            .unwrap();

        mgr.process_block_with_events(1000 + COMMIT_PHASE_BLOCKS);
        mgr.reveal_vote(
            &proposal,
            voter(1),
            Vote::Yes,
            &salt(1),
            100,
            1000 + COMMIT_PHASE_BLOCKS + 100,
        )
        .unwrap();

        let events =
            mgr.process_block_with_events(1000 + COMMIT_PHASE_BLOCKS + REVEAL_PHASE_BLOCKS);
        assert!(events.is_empty(), "all revealed → no NonRevealed event");
    }

    #[test]
    fn re_commit_replaces_previous() {
        let mut mgr = CommitRevealManager::new();
        let proposal = pid(1);
        let alice = voter(1);

        mgr.start_session(proposal, 1000).unwrap();

        // First commit: Yes with power 100
        let c1 = compute_commitment(&proposal, &alice, Vote::Yes, 100, &salt(1));
        mgr.submit_commitment(&proposal, alice, c1, 1100).unwrap();

        // Re-commit: No (changes mind secretly)
        let c2 = compute_commitment(&proposal, &alice, Vote::No, 100, &salt(2));
        mgr.submit_commitment(&proposal, alice, c2, 1200).unwrap();

        // Reveal phase
        mgr.process_block(1000 + COMMIT_PHASE_BLOCKS);

        // Old commit no longer valid (hash mismatch because commitment was replaced)
        let err = mgr
            .reveal_vote(
                &proposal,
                alice,
                Vote::Yes,
                &salt(1),
                100,
                1000 + COMMIT_PHASE_BLOCKS + 100,
            )
            .unwrap_err();
        assert!(err.to_string().contains("hash mismatch"));

        // New commit is valid (vote_power=100 matches what was committed)
        mgr.reveal_vote(
            &proposal,
            alice,
            Vote::No,
            &salt(2),
            100,
            1000 + COMMIT_PHASE_BLOCKS + 200,
        )
        .unwrap();
    }
}
