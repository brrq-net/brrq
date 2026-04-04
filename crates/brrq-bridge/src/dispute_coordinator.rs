//! L1 Dispute Game Coordinator.
//!
//! Observes L2 ChallengeManager events and coordinates the broadcast of
//! L1 BitVM2 taproot transactions (Kickoff, Assert, Disprove, Take) to enforce
//! the dispute game on the Bitcoin blockchain.
//!
//! ## Architecture
//!
//! The coordinator acts as the bridge between L2 state disputes and L1
//! execution. It listens for `ChallengeStatus` changes and constructs the
//! appropriate `DisputeStep` using `DisputeGameBuilder`. The constructed
//! steps are passed to `BitVM2TransactionBuilder` (in `dispute_game.rs`)
//! for L1 transaction construction.

use imbl::HashMap;
use serde::{Deserialize, Serialize};

use crate::challenge::ChallengeStatus;
use crate::dispute_game::{DisputeGameBuilder, DisputeStep};
use crate::operator::BitVM2Bond;
use brrq_crypto::hash::Hash256;
use tracing::{debug, info, warn};

/// Coordinates L1 BitVM2 dispute game execution.
#[derive(Clone)]
pub struct DisputeCoordinator {
    /// Active disputes being managed on L1, keyed by L2 challenge ID.
    active_disputes: HashMap<Hash256, DisputeStateContext>,
}

/// Context for an active L1 dispute.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisputeStateContext {
    pub l2_challenge_id: Hash256,
    pub bond: BitVM2Bond,
    pub current_step: Option<DisputeStep>,
    pub kickoff_l1_height: Option<u64>,
}

impl DisputeCoordinator {
    /// Create a new DisputeCoordinator.
    pub fn new() -> Self {
        Self {
            active_disputes: HashMap::new(),
        }
    }

    /// Process an L2 challenge event and transition the L1 dispute game.
    ///
    /// This function intercepts state changes from the L2 `ChallengeManager`
    /// and constructs the corresponding L1 `DisputeStep` (Kickoff, Assert, Disprove, Take).
    pub fn handle_challenge_event(
        &mut self,
        challenge_id: Hash256,
        status: ChallengeStatus,
        bond: &BitVM2Bond,
        current_l1_height: u64,
        actual_state_root: Option<[u8; 32]>,
        asserted_state_root: Option<[u8; 32]>,
    ) -> Result<Option<DisputeStep>, String> {
        debug!(
            "DisputeCoordinator handling event for challenge {}: {:?}",
            hex::encode(challenge_id.as_bytes()),
            status
        );

        let context = self
            .active_disputes
            .entry(challenge_id)
            .or_insert(DisputeStateContext {
                l2_challenge_id: challenge_id,
                bond: bond.clone(),
                current_step: None,
                kickoff_l1_height: None,
            });

        match status {
            ChallengeStatus::Pending => {
                // Challenger initiated a dispute. We need to Kickoff on L1.
                if context.current_step.is_none() {
                    match DisputeGameBuilder::build_kickoff(challenge_id, bond) {
                        Ok(step) => {
                            info!(
                                "L1 Dispute Coordinator: Kickoff built for challenge {}",
                                hex::encode(challenge_id.as_bytes())
                            );
                            context.current_step = Some(step.clone());
                            context.kickoff_l1_height = Some(current_l1_height);
                            Ok(Some(step))
                        }
                        Err(e) => {
                            warn!("Failed to build L1 Kickoff: {}", e);
                            Err(e)
                        }
                    }
                } else {
                    Ok(None) // Already kicked off
                }
            }
            ChallengeStatus::Responded => {
                // Operator posted a response. We need to Assert on L1.
                let asserted_root =
                    asserted_state_root.ok_or("OperatorResponded requires asserted_state_root")?;
                match DisputeGameBuilder::build_assert(
                    challenge_id,
                    bond,
                    current_l1_height,
                    asserted_root,
                ) {
                    Ok(step) => {
                        info!(
                            "L1 Dispute Coordinator: Assert built for challenge {}",
                            hex::encode(challenge_id.as_bytes())
                        );
                        context.current_step = Some(step.clone());
                        Ok(Some(step))
                    }
                    Err(e) => {
                        warn!("Failed to build L1 Assert: {}", e);
                        Err(e)
                    }
                }
            }
            ChallengeStatus::Proven => {
                // Fraud was proven on L2 (bisection completed). We need to Disprove on L1.
                let actual_root =
                    actual_state_root.ok_or("FraudProven requires actual_state_root")?;
                match DisputeGameBuilder::build_disprove(challenge_id, bond, actual_root) {
                    Ok(step) => {
                        info!(
                            "L1 Dispute Coordinator: Disprove built for challenge {}",
                            hex::encode(challenge_id.as_bytes())
                        );
                        context.current_step = Some(step.clone());
                        Ok(Some(step))
                    }
                    Err(e) => {
                        warn!("Failed to build L1 Disprove: {}", e);
                        Err(e)
                    }
                }
            }
            ChallengeStatus::Expired => {
                // The challenge ended in slashing via timeout. We need to Take on L1.
                let kickoff_height = context.kickoff_l1_height.unwrap_or(current_l1_height); // Fallback to current if missing

                // Determine reason based on previous step
                let reason = if matches!(context.current_step, Some(DisputeStep::Disprove(_))) {
                    crate::dispute_game::TakeReason::FraudProven
                } else {
                    crate::dispute_game::TakeReason::OperatorTimeout
                };

                let step = DisputeGameBuilder::build_take(bond, reason, kickoff_height);
                info!(
                    "L1 Dispute Coordinator: Take built for challenge {}",
                    hex::encode(challenge_id.as_bytes())
                );
                context.current_step = Some(step.clone());

                // Remove from active tracking as it is resolved
                self.active_disputes.remove(&challenge_id);

                Ok(Some(step))
            }
            ChallengeStatus::Dismissed => {
                // The challenge was resolved successfully (operator was honest). No L1 action needed (bond is unencumbered).
                info!(
                    "L1 Dispute Coordinator: Challenge {} resolved honestly. No L1 Take required.",
                    hex::encode(challenge_id.as_bytes())
                );
                self.active_disputes.remove(&challenge_id);
                Ok(None)
            }
        }
    }

    /// Returns the active dispute context for a given challenge ID, if any.
    pub fn get_dispute(&self, challenge_id: &Hash256) -> Option<&DisputeStateContext> {
        self.active_disputes.get(challenge_id)
    }

    /// Number of active disputes currently being coordinated.
    pub fn active_dispute_count(&self) -> usize {
        self.active_disputes.len()
    }
}

impl Default for DisputeCoordinator {
    fn default() -> Self {
        Self::new()
    }
}
