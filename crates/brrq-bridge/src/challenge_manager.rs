//! Challenge manager — BitVM2 dispute resolution protocol.
//!
//! Implements the L2-side logic for the BitVM2 challenge game (SS6.4):
//!
//! ```text
//! Observer ──[submit_challenge]──→ ChallengeManager (Pending)
//!                                        │
//!                    ┌───────────────────┴──────────────────────┐
//!                    ↓                                          ↓
//!     Operator responds with proof              No response within window
//!     [respond_to_challenge]                    [process_expired_challenges]
//!                    │                                          │
//!              ┌─────┴─────┐                                    ↓
//!              ↓           ↓                               Expired (guilty)
//!         Dismissed    Proven (fraud)
//!       (innocent)    (guilty)
//! ```
//!
//! In production, steps happen via Bitcoin transactions (Kickoff/Assert/Disprove).
//! The verification logic is identical — this module can be tested without Bitcoin.

use imbl::HashMap;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_prover::StarkVerifier;
use brrq_prover::types::StarkProof;
use brrq_types::Address;
use serde::{Deserialize, Serialize};

use crate::challenge::{
    CHALLENGE_RESPONSE_WINDOW, Challenge, ChallengeResponse, ChallengeStats, ChallengeStatus,
    ChallengeType,
};
use crate::error::BridgeError;
use crate::types::{CHALLENGE_COOLDOWN_BLOCKS, MAX_PENDING_PER_CHALLENGER};

/// Manages the BitVM2 challenge protocol.
///
/// Any observer can submit a challenge with evidence of fraud. The operator
/// has `CHALLENGE_RESPONSE_WINDOW` blocks to respond with a valid STARK proof.
/// If no response is received, the challenge auto-resolves as proven (guilty).
#[derive(Clone, Serialize, Deserialize)]
pub struct ChallengeManager {
    /// Active and resolved challenges.
    challenges: HashMap<Hash256, Challenge>,
    /// Cumulative statistics.
    stats: ChallengeStats,
    /// Track pending L1 dispute transactions.
    /// Maps L1 txid → (challenge_id, submitted_at_l1_height, escalation_count).
    /// If a dispute TX isn't confirmed within ALARM_THRESHOLD_BLOCKS,
    /// the escalation daemon triggers CPFP fee bumping.
    pending_dispute_txs: HashMap<Hash256, PendingDisputeTx>,
}

/// A dispute transaction being tracked in the L1 mempool.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingDisputeTx {
    /// Challenge this TX belongs to.
    pub challenge_id: Hash256,
    /// L1 block height when the TX was broadcast.
    pub broadcast_at_l1: u64,
    /// Number of fee escalation attempts so far.
    pub escalation_count: u32,
    /// Whether the TX has been confirmed on L1.
    pub confirmed: bool,
}

/// Number of L1 blocks to wait before triggering fee escalation alarm.
/// ~40 minutes at 10 min/block — if TX isn't confirmed by then, it's likely
/// being censored or outbid.
pub const ALARM_THRESHOLD_L1_BLOCKS: u64 = 4;

/// Maximum fee escalation attempts before alerting for manual intervention.
pub const MAX_ESCALATION_ATTEMPTS: u32 = 5;

impl ChallengeManager {
    /// Create a new empty challenge manager.
    pub fn new() -> Self {
        Self {
            challenges: HashMap::new(),
            stats: ChallengeStats::default(),
            pending_dispute_txs: HashMap::new(),
        }
    }

    /// Track a dispute TX broadcast to L1 mempool.
    pub fn track_dispute_tx(&mut self, l1_txid: Hash256, challenge_id: Hash256, current_l1_height: u64) {
        self.pending_dispute_txs.insert(l1_txid, PendingDisputeTx {
            challenge_id,
            broadcast_at_l1: current_l1_height,
            escalation_count: 0,
            confirmed: false,
        });
    }

    /// Mark a dispute TX as confirmed on L1.
    pub fn confirm_dispute_tx(&mut self, l1_txid: &Hash256) {
        if let Some(tx) = self.pending_dispute_txs.get_mut(l1_txid) {
            tx.confirmed = true;
        }
    }

    /// Check for stuck dispute TXs and return those needing fee escalation.
    ///
    /// Called periodically by the node's L1 monitoring loop.
    /// Returns list of (l1_txid, challenge_id) pairs needing CPFP escalation.
    pub fn check_alarms(&mut self, current_l1_height: u64) -> Vec<(Hash256, Hash256)> {
        let mut needs_escalation = Vec::new();

        for (txid, pending) in self.pending_dispute_txs.iter_mut() {
            if pending.confirmed {
                continue;
            }

            let blocks_waiting = current_l1_height.saturating_sub(pending.broadcast_at_l1);
            if blocks_waiting >= ALARM_THRESHOLD_L1_BLOCKS {
                if pending.escalation_count < MAX_ESCALATION_ATTEMPTS {
                    pending.escalation_count += 1;
                    needs_escalation.push((*txid, pending.challenge_id));
                }
            }
        }

        // Prune confirmed TXs
        self.pending_dispute_txs.retain(|_, p| !p.confirmed);

        needs_escalation
    }

    /// Submit a new challenge.
    ///
    /// Validates:
    /// 1. Challenge evidence is internally consistent (non-trivial)
    /// 2. No duplicate challenge for the same issue exists
    /// 3. Challenger has not exceeded the pending challenge cap (M-1 anti-spam)
    /// 4. Challenger is not in cooldown period (M-1 rate limiting)
    ///
    /// Returns the unique challenge ID.
    pub fn submit_challenge(
        &mut self,
        challenger: Address,
        challenge_type: ChallengeType,
        current_l2_height: u64,
        bond: u64,
    ) -> Result<Hash256, BridgeError> {
        // Require minimum challenge bond to deter spam.
        if bond < crate::challenge::CHALLENGE_BOND {
            return Err(BridgeError::InvalidChallengeEvidence {
                reason: format!(
                    "insufficient challenge bond: {} sat < {} sat minimum",
                    bond,
                    crate::challenge::CHALLENGE_BOND,
                ),
            });
        }
        // Validate evidence
        validate_challenge_evidence(&challenge_type)?;

        // Anti-spam — cap concurrent pending challenges per address.
        // Each challenge forces the operator to generate an expensive STARK proof,
        // so unlimited challenges from one address enables resource exhaustion.
        let pending_from_challenger = self
            .challenges
            .values()
            .filter(|c| c.challenger == challenger && c.status == ChallengeStatus::Pending)
            .count();
        if pending_from_challenger >= MAX_PENDING_PER_CHALLENGER {
            return Err(BridgeError::InvalidChallengeEvidence {
                reason: format!(
                    "challenger has {} pending challenges (max {})",
                    pending_from_challenger, MAX_PENDING_PER_CHALLENGER,
                ),
            });
        }

        // Cooldown — prevent burst submissions from the same address.
        // Cooldown is per (address, challenge_type_discriminant) pair.
        // Cooldown is scoped per challenge type so that independent fraud types
        // can be reported concurrently without cross-type interference.
        let new_type_disc = challenge_type_discriminant(&challenge_type);
        let last_submission_height = self
            .challenges
            .values()
            .filter(|c| {
                c.challenger == challenger
                    && challenge_type_discriminant(&c.challenge_type) == new_type_disc
            })
            .map(|c| c.submitted_at_height)
            .max();
        if let Some(last_height) = last_submission_height {
            if current_l2_height.saturating_sub(last_height) < CHALLENGE_COOLDOWN_BLOCKS {
                return Err(BridgeError::InvalidChallengeEvidence {
                    reason: format!(
                        "challenger must wait {} blocks between submissions of same type (last at height {})",
                        CHALLENGE_COOLDOWN_BLOCKS, last_height,
                    ),
                });
            }
        }

        // Generate challenge ID from content
        let challenge_id = compute_challenge_id(&challenge_type, &challenger, current_l2_height);

        // Check for duplicates
        if self.challenges.contains_key(&challenge_id) {
            return Err(BridgeError::DuplicateChallenge);
        }

        let challenge = Challenge {
            challenge_id,
            challenge_type,
            challenger,
            submitted_at_height: current_l2_height,
            status: ChallengeStatus::Pending,
            response: None,
            bond,
        };

        self.challenges.insert(challenge_id, challenge);
        self.stats.total += 1;
        self.stats.pending += 1;

        Ok(challenge_id)
    }

    /// Operator responds to a challenge with a STARK proof.
    ///
    /// The response includes a proof hash and the correct state root.
    /// The manager verifies the STARK proof and resolves the challenge:
    /// - If proof is valid AND state root matches the response → Dismissed
    /// - If proof is invalid OR state root contradicts → Proven (fraud)
    pub fn respond_to_challenge(
        &mut self,
        challenge_id: &Hash256,
        response: ChallengeResponse,
        proof: &StarkProof,
    ) -> Result<ChallengeStatus, BridgeError> {
        let challenge =
            self.challenges
                .get_mut(challenge_id)
                .ok_or(BridgeError::ChallengeNotFound {
                    challenge_id: *challenge_id,
                })?;

        if challenge.status != ChallengeStatus::Pending {
            return Err(BridgeError::InvalidChallengeEvidence {
                reason: format!(
                    "challenge is {:?}, only Pending challenges accept responses",
                    challenge.status
                ),
            });
        }

        // SNARK wrapping is an L1 anchoring concern. StarkVerifier::verify()
        // below provides the cryptographic check for challenge responses.
        // When real-plonky2 is disabled, SNARK proofs are simulated but this
        // does not affect challenge resolution — STARK verification is sufficient.
        #[cfg(not(feature = "real-plonky2"))]
        tracing::warn!(
            "Challenge response SNARK is simulated (real-plonky2 not enabled). \
             Proceeding with STARK verification only."
        );

        // Verify the STARK proof
        // Log verification errors instead of silently converting to false.
        // A verification error (e.g., corrupted proof, internal prover bug) is
        // materially different from a proof that verifies but proves fraud.
        let proof_valid = match StarkVerifier::verify(proof) {
            Ok(valid) => valid,
            Err(e) => {
                tracing::error!(
                    ?challenge_id,
                    %e,
                    "STARK verification error — treating as invalid",
                );
                false
            }
        };

        if proof_valid && is_response_consistent(&challenge.challenge_type, &response, proof) {
            // Operator provided valid evidence — challenge dismissed
            challenge.status = ChallengeStatus::Dismissed;
            challenge.response = Some(response);
            self.stats.pending = self.stats.pending.saturating_sub(1);
            self.stats.dismissed += 1;
            Ok(ChallengeStatus::Dismissed)
        } else {
            // Proof invalid or inconsistent — fraud proven
            challenge.status = ChallengeStatus::Proven;
            challenge.response = Some(response);
            self.stats.pending = self.stats.pending.saturating_sub(1);
            self.stats.proven += 1;
            Ok(ChallengeStatus::Proven)
        }
    }

    /// Check for expired challenges and auto-resolve them.
    ///
    /// Challenges that have exceeded `CHALLENGE_RESPONSE_WINDOW` without
    /// a response are marked as `Expired` (operator guilty by default).
    ///
    /// Returns the IDs of newly expired challenges.
    pub fn process_expired_challenges(&mut self, current_l2_height: u64) -> Vec<Hash256> {
        let mut expired_ids = Vec::new();

        for (_, challenge) in self.challenges.iter_mut() {
            if challenge.status == ChallengeStatus::Pending {
                let deadline = challenge
                    .submitted_at_height
                    .saturating_add(CHALLENGE_RESPONSE_WINDOW);
                if current_l2_height >= deadline {
                    challenge.status = ChallengeStatus::Expired;
                    expired_ids.push(challenge.challenge_id);
                }
            }
        }

        // Update stats
        let expired_count = expired_ids.len() as u64;
        self.stats.pending = self.stats.pending.saturating_sub(expired_count);
        self.stats.expired += expired_count;

        expired_ids
    }

    /// Get challenge by ID.
    pub fn get_challenge(&self, id: &Hash256) -> Option<&Challenge> {
        self.challenges.get(id)
    }

    /// Get all active (Pending) challenges.
    pub fn active_challenges(&self) -> Vec<&Challenge> {
        self.challenges
            .values()
            .filter(|c| c.status == ChallengeStatus::Pending)
            .collect()
    }

    /// Get all challenges (any status).
    pub fn all_challenges(&self) -> Vec<&Challenge> {
        self.challenges.values().collect()
    }

    /// Aggregate statistics.
    pub fn stats(&self) -> &ChallengeStats {
        &self.stats
    }

    /// Total number of challenges.
    pub fn count(&self) -> usize {
        self.challenges.len()
    }

    /// Prune resolved challenges older than `before_height`.
    ///
    /// Removes Proven, Dismissed, and Expired challenges submitted before
    /// `before_height`. Returns the number of pruned challenges.
    pub fn prune_resolved(&mut self, before_height: u64) -> usize {
        let before = self.challenges.len();
        self.challenges
            .retain(|_, c| !c.status.is_resolved() || c.submitted_at_height >= before_height);
        before - self.challenges.len()
    }
}

impl Default for ChallengeManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Internal Helpers ────────────────────────────────────────────────────────

/// Compute a unique challenge ID from its content.
/// Challenge ID now excludes height to prevent re-submission
/// of the same evidence at different heights. The ID is derived from
/// the evidence content itself, making dismissed challenges non-repeatable.
fn compute_challenge_id(
    challenge_type: &ChallengeType,
    challenger: &Address,
    _height: u64,
) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(b"CHALLENGE-V2");
    hasher.update(challenger.as_bytes());

    match challenge_type {
        ChallengeType::InvalidStateRoot {
            claimed_state_root,
            actual_state_root,
            l2_height,
        } => {
            hasher.update(b"ISR");
            hasher.update(claimed_state_root.as_bytes());
            hasher.update(actual_state_root.as_bytes());
            hasher.update(&l2_height.to_le_bytes());
        }
        ChallengeType::InvalidSnarkWrapping {
            anchor_snark_commitment,
            actual_snark_commitment,
            l2_height_start,
            l2_height_end,
        } => {
            hasher.update(b"ISW");
            hasher.update(anchor_snark_commitment);
            hasher.update(actual_snark_commitment);
            hasher.update(&l2_height_start.to_le_bytes());
            hasher.update(&l2_height_end.to_le_bytes());
        }
        ChallengeType::InvalidWithdrawalProof {
            withdrawal_id,
            proof_state_root,
            claimed_state_root,
        } => {
            hasher.update(b"IWP");
            hasher.update(withdrawal_id.as_bytes());
            hasher.update(proof_state_root.as_bytes());
            hasher.update(claimed_state_root.as_bytes());
        }
    }

    hasher.finalize()
}

/// Validate that challenge evidence is non-trivial.
fn validate_challenge_evidence(challenge_type: &ChallengeType) -> Result<(), BridgeError> {
    match challenge_type {
        ChallengeType::InvalidStateRoot {
            claimed_state_root,
            actual_state_root,
            l2_height,
        } => {
            if *l2_height == 0 {
                return Err(BridgeError::InvalidChallengeEvidence {
                    reason: "l2_height must be nonzero".into(),
                });
            }
            if claimed_state_root == actual_state_root {
                return Err(BridgeError::InvalidChallengeEvidence {
                    reason: "claimed and actual state roots are identical — no fraud".into(),
                });
            }
        }
        ChallengeType::InvalidSnarkWrapping {
            anchor_snark_commitment,
            actual_snark_commitment,
            l2_height_start,
            l2_height_end,
        } => {
            if *l2_height_start == 0 || *l2_height_end == 0 || l2_height_end < l2_height_start {
                return Err(BridgeError::InvalidChallengeEvidence {
                    reason: "invalid block range: start and end must be nonzero and end >= start"
                        .into(),
                });
            }
            if anchor_snark_commitment == actual_snark_commitment {
                return Err(BridgeError::InvalidChallengeEvidence {
                    reason: "SNARK commitments are identical — no discrepancy".into(),
                });
            }
        }
        ChallengeType::InvalidWithdrawalProof {
            withdrawal_id,
            proof_state_root,
            claimed_state_root,
        } => {
            if *withdrawal_id == Hash256::ZERO {
                return Err(BridgeError::InvalidChallengeEvidence {
                    reason: "withdrawal_id must be nonzero".into(),
                });
            }
            if proof_state_root == claimed_state_root {
                return Err(BridgeError::InvalidChallengeEvidence {
                    reason: "proof state root matches claimed — no fraud".into(),
                });
            }
        }
    }
    Ok(())
}

/// Return a discriminant for the challenge type (for per-type cooldown).
fn challenge_type_discriminant(ct: &ChallengeType) -> u8 {
    match ct {
        ChallengeType::InvalidStateRoot { .. } => 0,
        ChallengeType::InvalidSnarkWrapping { .. } => 1,
        ChallengeType::InvalidWithdrawalProof { .. } => 2,
    }
}

/// Check if the operator's response is consistent with the challenge.
///
/// For `InvalidStateRoot`: the response must show the correct state root
/// matching the claimed root (proving the anchor was correct).
fn is_response_consistent(
    challenge_type: &ChallengeType,
    response: &ChallengeResponse,
    proof: &StarkProof,
) -> bool {
    match challenge_type {
        ChallengeType::InvalidStateRoot {
            claimed_state_root, ..
        } => {
            // Operator must show that the claimed state root is correct
            // by providing a proof whose final_state_root matches it
            response.correct_state_root == *claimed_state_root
                && proof.final_state_root == *claimed_state_root
        }
        ChallengeType::InvalidSnarkWrapping {
            anchor_snark_commitment,
            l2_height_start,
            l2_height_end,
            ..
        } => {
            // For SNARK wrapping challenges, the operator must:
            // 1. Provide a valid STARK proof (verified above)
            // 2. Show the proof_hash matches the actual proof
            // 3. Show the SNARK wrapping of this proof produces a commitment
            //    matching what was posted on L1 (anchor_snark_commitment)
            let proof_bytes = match proof.to_bytes() {
                Ok(bytes) => bytes,
                Err(e) => {
                    tracing::error!(
                        "proof.to_bytes() failed — treating as inconsistent: {e}"
                    );
                    return false;
                }
            };
            let proof_hash = Hasher::hash(&proof_bytes);
            if response.proof_hash != proof_hash {
                return false;
            }
            // Use actual block range instead of hardcoded (0, 0).
            // wrap_best_available() picks real Plonky2 when enabled, otherwise simulated.
            let snark = match brrq_prover::WrappedSnarkProof::wrap_best_available(
                proof,
                (*l2_height_start, *l2_height_end),
            ) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "wrap_best_available() failed — treating as inconsistent: {e}"
                    );
                    return false;
                }
            };

            // SNARK simulation guard for wrapping consistency check (feature-gated).
            // With real-plonky2: reject simulated SNARKs (indicates misconfiguration).
            // Without real-plonky2: warn only — the commitment comparison below
            // will naturally fail if the L1 anchor used a real SNARK.
            if snark.is_simulated() {
                #[cfg(all(
                    not(any(test, feature = "test-utils")),
                    feature = "real-plonky2"
                ))]
                return false;

                #[cfg(not(feature = "real-plonky2"))]
                tracing::warn!(
                    "SNARK wrapping check uses simulated SNARK (real-plonky2 not enabled). \
                     Commitment comparison may fail if L1 anchor used real SNARK."
                );
            }

            let commitment = snark.commitment_hash();
            let truncated: [u8; 31] = commitment.as_bytes()[..31].try_into().unwrap_or([0; 31]);
            truncated == *anchor_snark_commitment
        }
        ChallengeType::InvalidWithdrawalProof {
            claimed_state_root, ..
        } => {
            // Operator must show the proof binds to the claimed state root
            response.correct_state_root == *claimed_state_root
                && proof.final_state_root == *claimed_state_root
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::CHALLENGE_BOND;
    use brrq_prover::batch::prove_batch;
    use brrq_prover::prover::StarkProver;

    /// Default bond for tests — meets minimum requirement.
    const TEST_BOND: u64 = CHALLENGE_BOND;

    fn make_proof_with_final_root(final_root: Hash256) -> StarkProof {
        let prover = StarkProver::new();
        let record = prove_batch(
            &prover,
            Hash256::from_bytes([0x01; 32]),
            final_root,
            (1, 10),
            50,
            21_000,
        )
        .unwrap();
        record.proof
    }

    #[test]
    fn submit_challenge_invalid_state_root() {
        let mut mgr = ChallengeManager::new();

        let ct = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };

        let id = mgr.submit_challenge(Address::ZERO, ct, 1000, TEST_BOND).unwrap();
        assert_ne!(id, Hash256::ZERO);
        assert_eq!(mgr.count(), 1);
        assert_eq!(mgr.stats().pending, 1);

        let challenge = mgr.get_challenge(&id).unwrap();
        assert_eq!(challenge.status, ChallengeStatus::Pending);
        assert_eq!(challenge.challenger, Address::ZERO);
    }

    #[test]
    fn submit_duplicate_challenge_rejected() {
        let mut mgr = ChallengeManager::new();

        let ct = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };

        mgr.submit_challenge(Address::ZERO, ct.clone(), 1000, TEST_BOND)
            .unwrap();
        let result = mgr.submit_challenge(Address::ZERO, ct, 1000, TEST_BOND);
        assert!(result.is_err());
    }

    #[test]
    fn respond_with_valid_proof_dismisses() {
        let mut mgr = ChallengeManager::new();

        let claimed_root = Hash256::from_bytes([0xAA; 32]);
        let ct = ChallengeType::InvalidStateRoot {
            claimed_state_root: claimed_root,
            actual_state_root: Hash256::from_bytes([0xBB; 32]),
            l2_height: 100,
        };

        let id = mgr.submit_challenge(Address::ZERO, ct, 1000, TEST_BOND).unwrap();

        // Operator provides a valid proof with matching final_state_root
        let proof = make_proof_with_final_root(claimed_root);
        let response = ChallengeResponse {
            proof_hash: Hasher::hash(&proof.to_bytes().unwrap()),
            correct_state_root: claimed_root,
            responder: Address::ZERO,
        };

        let status = mgr.respond_to_challenge(&id, response, &proof).unwrap();
        assert_eq!(status, ChallengeStatus::Dismissed);
        assert_eq!(mgr.stats().dismissed, 1);
        assert_eq!(mgr.stats().pending, 0);
    }

    #[test]
    fn respond_with_wrong_state_root_proves_fraud() {
        let mut mgr = ChallengeManager::new();

        let claimed_root = Hash256::from_bytes([0xAA; 32]);
        let ct = ChallengeType::InvalidStateRoot {
            claimed_state_root: claimed_root,
            actual_state_root: Hash256::from_bytes([0xBB; 32]),
            l2_height: 100,
        };

        let id = mgr.submit_challenge(Address::ZERO, ct, 1000, TEST_BOND).unwrap();

        // Operator provides proof but with WRONG state root
        let wrong_root = Hash256::from_bytes([0xCC; 32]);
        let proof = make_proof_with_final_root(wrong_root);
        let response = ChallengeResponse {
            proof_hash: Hasher::hash(&proof.to_bytes().unwrap()),
            correct_state_root: wrong_root, // Does not match claimed
            responder: Address::ZERO,
        };

        let status = mgr.respond_to_challenge(&id, response, &proof).unwrap();
        assert_eq!(status, ChallengeStatus::Proven);
        assert_eq!(mgr.stats().proven, 1);
    }

    #[test]
    fn expired_challenge_auto_resolves() {
        let mut mgr = ChallengeManager::new();

        let ct = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };

        let id = mgr.submit_challenge(Address::ZERO, ct, 1000, TEST_BOND).unwrap();

        // Not yet expired
        let expired = mgr.process_expired_challenges(1000 + CHALLENGE_RESPONSE_WINDOW - 1);
        assert!(expired.is_empty());

        // Now expired
        let expired = mgr.process_expired_challenges(1000 + CHALLENGE_RESPONSE_WINDOW);
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], id);

        let challenge = mgr.get_challenge(&id).unwrap();
        assert_eq!(challenge.status, ChallengeStatus::Expired);
        assert_eq!(mgr.stats().expired, 1);
        assert_eq!(mgr.stats().pending, 0);
    }

    #[test]
    fn challenge_nonexistent_returns_error() {
        let mut mgr = ChallengeManager::new();
        let fake_id = Hash256::from_bytes([0xFF; 32]);
        let response = ChallengeResponse {
            proof_hash: Hash256::ZERO,
            correct_state_root: Hash256::ZERO,
            responder: Address::ZERO,
        };
        let proof = make_proof_with_final_root(Hash256::ZERO);

        let result = mgr.respond_to_challenge(&fake_id, response, &proof);
        assert!(result.is_err());
    }

    #[test]
    fn challenge_stats_tracking() {
        let mut mgr = ChallengeManager::new();

        // Submit 3 challenges
        for i in 0u8..3 {
            let ct = ChallengeType::InvalidStateRoot {
                claimed_state_root: Hash256::from_bytes([i + 1; 32]),
                actual_state_root: Hash256::from_bytes([i + 10; 32]),
                l2_height: (i as u64 + 1) * 100,
            };
            mgr.submit_challenge(Address::from_bytes([i; 20]), ct, i as u64 * 1000, TEST_BOND)
                .unwrap();
        }

        assert_eq!(mgr.stats().total, 3);
        assert_eq!(mgr.stats().pending, 3);
        assert_eq!(mgr.active_challenges().len(), 3);
    }

    #[test]
    fn invalid_evidence_same_roots_rejected() {
        let mut mgr = ChallengeManager::new();

        // Same claimed and actual roots → no fraud
        let ct = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([1; 32]), // Same!
            l2_height: 100,
        };

        let result = mgr.submit_challenge(Address::ZERO, ct, 1000, TEST_BOND);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_snark_wrapping_challenge() {
        let mut mgr = ChallengeManager::new();

        let ct = ChallengeType::InvalidSnarkWrapping {
            anchor_snark_commitment: [0xAA; 31],
            actual_snark_commitment: [0xBB; 31],
            l2_height_start: 1,
            l2_height_end: 10,
        };

        let id = mgr.submit_challenge(Address::ZERO, ct, 1000, TEST_BOND).unwrap();
        let challenge = mgr.get_challenge(&id).unwrap();
        assert_eq!(challenge.status, ChallengeStatus::Pending);
    }

    #[test]
    fn invalid_withdrawal_proof_challenge() {
        let mut mgr = ChallengeManager::new();

        let ct = ChallengeType::InvalidWithdrawalProof {
            withdrawal_id: Hash256::from_bytes([0xDE; 32]),
            proof_state_root: Hash256::from_bytes([1; 32]),
            claimed_state_root: Hash256::from_bytes([2; 32]),
        };

        let id = mgr.submit_challenge(Address::ZERO, ct, 1000, TEST_BOND).unwrap();
        assert_eq!(mgr.count(), 1);
        assert!(mgr.get_challenge(&id).is_some());
    }

    #[test]
    fn multiple_concurrent_challenges() {
        let mut mgr = ChallengeManager::new();

        // Submit challenges from different challengers for different heights
        for i in 0u8..5 {
            let ct = ChallengeType::InvalidStateRoot {
                claimed_state_root: Hash256::from_bytes([i + 1; 32]),
                actual_state_root: Hash256::from_bytes([i + 20; 32]),
                l2_height: (i as u64 + 1) * 50,
            };
            mgr.submit_challenge(Address::from_bytes([i; 20]), ct, 1000 + i as u64, TEST_BOND)
                .unwrap();
        }

        assert_eq!(mgr.count(), 5);
        assert_eq!(mgr.active_challenges().len(), 5);
    }

    #[test]
    fn challenge_manager_default() {
        let mgr = ChallengeManager::default();
        assert_eq!(mgr.count(), 0);
        assert_eq!(mgr.stats().total, 0);
        assert!(mgr.active_challenges().is_empty());
    }

    #[test]
    fn challenge_id_uniqueness() {
        let mut mgr = ChallengeManager::new();

        // Different challengers for same evidence → different IDs
        let ct = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };

        let id1 = mgr
            .submit_challenge(Address::from_bytes([1; 20]), ct.clone(), 1000, TEST_BOND)
            .unwrap();
        let id2 = mgr
            .submit_challenge(Address::from_bytes([2; 20]), ct, 1000, TEST_BOND)
            .unwrap();

        assert_ne!(id1, id2);
    }

    // ── Tests: Challenge Anti-Spam ──────────────────

    #[test]
    fn challenge_rate_limit_max_pending() {
        let mut mgr = ChallengeManager::new();
        let challenger = Address::ZERO;

        // Submit MAX_PENDING_PER_CHALLENGER challenges (spaced by cooldown)
        for i in 0u8..3 {
            let ct = ChallengeType::InvalidStateRoot {
                claimed_state_root: Hash256::from_bytes([i + 1; 32]),
                actual_state_root: Hash256::from_bytes([i + 10; 32]),
                l2_height: (i as u64 + 1) * 100,
            };
            let height = 1000 + (i as u64 * CHALLENGE_COOLDOWN_BLOCKS);
            mgr.submit_challenge(challenger, ct, height, TEST_BOND).unwrap();
        }

        // 4th challenge from same address should be rejected (max pending = 3)
        let ct4 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([4; 32]),
            actual_state_root: Hash256::from_bytes([14; 32]),
            l2_height: 400,
        };
        let height4 = 1000 + 3 * CHALLENGE_COOLDOWN_BLOCKS;
        let result = mgr.submit_challenge(challenger, ct4, height4, TEST_BOND);
        assert!(
            result.is_err(),
            "should reject when max pending challenges exceeded"
        );
    }

    #[test]
    fn challenge_rate_limit_cooldown() {
        let mut mgr = ChallengeManager::new();
        let challenger = Address::ZERO;

        let ct1 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };
        mgr.submit_challenge(challenger, ct1, 1000, TEST_BOND).unwrap();

        // Submit too soon (within CHALLENGE_COOLDOWN_BLOCKS)
        let ct2 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([3; 32]),
            actual_state_root: Hash256::from_bytes([4; 32]),
            l2_height: 200,
        };
        let result = mgr.submit_challenge(challenger, ct2.clone(), 1050, TEST_BOND); // 50 < 100 cooldown
        assert!(result.is_err(), "should reject within cooldown period");

        // Submit after cooldown — should succeed
        let result = mgr.submit_challenge(challenger, ct2, 1100, TEST_BOND); // 100 >= 100 cooldown
        assert!(result.is_ok(), "should allow after cooldown period");
    }

    #[test]
    fn challenge_cooldown_per_type_independent() {
        // Different challenge types from the same address should have
        // independent cooldowns. If operator commits both InvalidStateRoot AND
        // InvalidSnarkWrapping fraud, the challenger must report both without
        // cross-type cooldown interference.
        let mut mgr = ChallengeManager::new();
        let challenger = Address::ZERO;

        let ct_state = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };
        mgr.submit_challenge(challenger, ct_state, 1000, TEST_BOND).unwrap();

        // Different type immediately (within cooldown) — should SUCCEED
        let ct_snark = ChallengeType::InvalidSnarkWrapping {
            anchor_snark_commitment: [0xAA; 31],
            actual_snark_commitment: [0xBB; 31],
            l2_height_start: 1,
            l2_height_end: 50,
        };
        let result = mgr.submit_challenge(challenger, ct_snark, 1001, TEST_BOND);
        assert!(
            result.is_ok(),
            "different challenge type should bypass cooldown"
        );

        // Same type within cooldown — should FAIL
        let ct_state2 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([3; 32]),
            actual_state_root: Hash256::from_bytes([4; 32]),
            l2_height: 200,
        };
        let result = mgr.submit_challenge(challenger, ct_state2, 1050, TEST_BOND);
        assert!(
            result.is_err(),
            "same challenge type within cooldown should be rejected"
        );
    }

    #[test]
    fn challenge_rate_limit_different_challengers_independent() {
        let mut mgr = ChallengeManager::new();

        // Two different challengers should NOT affect each other's limits
        let ct1 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };
        let ct2 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([3; 32]),
            actual_state_root: Hash256::from_bytes([4; 32]),
            l2_height: 200,
        };

        mgr.submit_challenge(Address::from_bytes([1; 20]), ct1, 1000, TEST_BOND)
            .unwrap();
        // Second challenger at same height — should succeed (different address)
        mgr.submit_challenge(Address::from_bytes([2; 20]), ct2, 1000, TEST_BOND)
            .unwrap();

        assert_eq!(mgr.count(), 2);
    }

    #[test]
    fn get_active_challenges_filter() {
        let mut mgr = ChallengeManager::new();

        // Submit and expire one, keep one pending
        let ct1 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([1; 32]),
            actual_state_root: Hash256::from_bytes([2; 32]),
            l2_height: 100,
        };
        let ct2 = ChallengeType::InvalidStateRoot {
            claimed_state_root: Hash256::from_bytes([3; 32]),
            actual_state_root: Hash256::from_bytes([4; 32]),
            l2_height: 200,
        };

        mgr.submit_challenge(Address::ZERO, ct1, 100, TEST_BOND).unwrap(); // Will expire
        mgr.submit_challenge(Address::from_bytes([1; 20]), ct2, 100_000, TEST_BOND)
            .unwrap(); // Fresh

        // Expire the first one
        mgr.process_expired_challenges(100 + CHALLENGE_RESPONSE_WINDOW);

        assert_eq!(mgr.active_challenges().len(), 1);
        assert_eq!(mgr.all_challenges().len(), 2);
    }
}
