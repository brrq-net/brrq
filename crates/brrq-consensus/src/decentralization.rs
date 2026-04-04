//! Decentralization phase tracking — monitors transition milestones.
//!
//! ## Design (Article 11)
//!
//! Four-phase transition from founder control to full sovereignty:
//!
//! - **Phase 0 (Foundation)**: Founder team controls decisions.
//! - **Phase 1 (Federation)**: Covenant committee 6/9, sequencer chamber active.
//! - **Phase 2 (Dual Consensus)**: Both chambers active, BitVM2 hybrid bridge.
//! - **Phase 3 (Full Sovereignty)**: Three chambers, BitVM2 bridge, no central entity.
//!
//! Phase transitions are automatic when all milestones are met, but require
//! a governance vote to confirm (to prevent premature transitions).

use crate::ConsensusError;

// ═══════════════════════════════════════════════════════════════
// Phase transition thresholds
// ═══════════════════════════════════════════════════════════════

/// Phase 0 → 1: Minimum independent sequencers.
pub const PHASE_0_MIN_SEQUENCERS: u64 = 10;
/// Phase 0 → 1: Minimum active users meeting Sybil requirements.
pub const PHASE_0_MIN_USERS: u64 = 1_000;
/// Phase 0 → 1: Minimum BTC locked in bridge (100 BTC in sats).
pub const PHASE_0_MIN_LOCKED_SATS: u64 = 10_000_000_000;
/// Phase 0 → 1: Minimum regions with sequencers.
pub const PHASE_0_MIN_REGIONS: u64 = 3;
/// Phase 0 → 1: Minimum operational blocks without critical incidents.
pub const PHASE_0_MIN_UPTIME_BLOCKS: u64 = 5_184_000; // ~6 months

/// Phase 1 → 2: Minimum independent sequencers.
pub const PHASE_1_MIN_SEQUENCERS: u64 = 30;
/// Phase 1 → 2: Minimum active users.
pub const PHASE_1_MIN_USERS: u64 = 5_000;
/// Phase 1 → 2: Minimum BTC locked (500 BTC in sats).
pub const PHASE_1_MIN_LOCKED_SATS: u64 = 50_000_000_000;
/// Phase 1 → 2: Minimum regions.
pub const PHASE_1_MIN_REGIONS: u64 = 5;
/// Phase 1 → 2: Minimum successful governance proposals executed.
pub const PHASE_1_MIN_PROPOSALS_EXECUTED: u64 = 5;
/// Phase 1 → 2: Founder must have 0 seats in covenant committee.
pub const PHASE_1_MAX_FOUNDER_SEATS: u64 = 0;

/// Phase 2 → 3: Minimum independent sequencers.
pub const PHASE_2_MIN_SEQUENCERS: u64 = 100;
/// Phase 2 → 3: Minimum active users.
pub const PHASE_2_MIN_USERS: u64 = 20_000;
/// Phase 2 → 3: Minimum % of peg-outs via BitVM2 (in basis points).
pub const PHASE_2_MIN_BITVM2_PEGOUT_BP: u64 = 9_000; // 90%
/// Phase 2 → 3: Rage Quit tested successfully at least once.
pub const PHASE_2_RAGE_QUIT_TESTED: bool = true;

// ═══════════════════════════════════════════════════════════════
// Bridge Metrics
// ═══════════════════════════════════════════════════════════════

/// Bridge metrics for tracking BitVM2 peg-out adoption.
///
/// Used to determine readiness for Phase 2→3 transition, which requires
/// ≥90% of peg-outs to use the BitVM2 trustless bridge.
#[derive(Debug, Clone, Default)]
pub struct BridgeMetrics {
    /// Total peg-outs completed (all types).
    pub total_pegouts: u64,
    /// Peg-outs completed via BitVM2 trustless bridge.
    pub bitvm2_pegouts: u64,
}

impl BridgeMetrics {
    /// Compute BitVM2 peg-out percentage in basis points (0..10000).
    /// Returns 0 if no peg-outs have been recorded (prevents division by zero).
    pub fn bitvm2_pegout_bp(&self) -> u64 {
        if self.total_pegouts == 0 {
            return 0;
        }
        self.bitvm2_pegouts
            .saturating_mul(10_000)
            .checked_div(self.total_pegouts)
            .unwrap_or(0)
    }

    /// Record a peg-out event.
    pub fn record_pegout(&mut self, is_bitvm2: bool) {
        self.total_pegouts = self.total_pegouts.saturating_add(1);
        if is_bitvm2 {
            self.bitvm2_pegouts = self.bitvm2_pegouts.saturating_add(1);
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// Current decentralization phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DecentralizationPhase {
    /// Founder team controls decisions.
    Foundation = 0,
    /// Covenant committee active, sequencer chamber limited.
    Federation = 1,
    /// Both chambers active, hybrid bridge.
    DualConsensus = 2,
    /// Full three-chamber governance, BitVM2 bridge.
    FullSovereignty = 3,
}

/// Snapshot of current network metrics for phase evaluation.
#[derive(Debug, Clone)]
pub struct NetworkMetrics {
    /// Number of active, independent sequencers.
    pub active_sequencers: u64,
    /// Number of eligible voters (users meeting Sybil criteria).
    pub eligible_users: u64,
    /// Total BTC locked in bridge (in satoshis).
    pub locked_sats: u64,
    /// Number of distinct geographic regions with sequencers.
    pub distinct_regions: u64,
    /// Consecutive blocks without critical security incidents.
    pub uptime_blocks: u64,
    /// Number of governance proposals successfully executed.
    pub proposals_executed: u64,
    /// Number of founder seats remaining in covenant committee.
    pub founder_seats: u64,
    /// Percentage of peg-outs via BitVM2 (in basis points).
    pub bitvm2_pegout_bp: u64,
    /// Whether Rage Quit has been tested successfully.
    pub rage_quit_tested: bool,
    /// Number of Technical Council elections completed.
    pub council_elections: u64,
}

/// Result of phase transition evaluation.
#[derive(Debug, Clone)]
pub struct PhaseEvaluation {
    /// Current phase.
    pub current_phase: DecentralizationPhase,
    /// Whether all milestones for the next phase are met.
    pub next_phase_ready: bool,
    /// Individual milestone statuses.
    pub milestones: Vec<Milestone>,
}

/// A single milestone for phase transition.
#[derive(Debug, Clone)]
pub struct Milestone {
    /// Description of the milestone.
    pub description: String,
    /// Whether this milestone is satisfied.
    pub satisfied: bool,
    /// Current value (for numeric milestones).
    pub current: u64,
    /// Required value.
    pub required: u64,
}

// ═══════════════════════════════════════════════════════════════
// DecentralizationTracker
// ═══════════════════════════════════════════════════════════════

/// Tracks the decentralization phase and evaluates transition readiness.
#[derive(Debug, Clone)]
pub struct DecentralizationTracker {
    /// Current phase.
    pub current_phase: DecentralizationPhase,
    /// Block height when the current phase was entered.
    pub phase_entered_at: u64,
    /// Whether a governance vote has confirmed the next transition.
    pub transition_confirmed: bool,
}

impl Default for DecentralizationTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DecentralizationTracker {
    pub fn new() -> Self {
        Self {
            current_phase: DecentralizationPhase::Foundation,
            phase_entered_at: 0,
            transition_confirmed: false,
        }
    }

    /// Evaluate whether the network is ready for the next phase.
    pub fn evaluate(&self, metrics: &NetworkMetrics) -> PhaseEvaluation {
        let milestones = match self.current_phase {
            DecentralizationPhase::Foundation => self.phase_0_milestones(metrics),
            DecentralizationPhase::Federation => self.phase_1_milestones(metrics),
            DecentralizationPhase::DualConsensus => self.phase_2_milestones(metrics),
            DecentralizationPhase::FullSovereignty => {
                // Already at the final phase
                return PhaseEvaluation {
                    current_phase: self.current_phase,
                    next_phase_ready: false,
                    milestones: vec![],
                };
            }
        };

        let all_satisfied = milestones.iter().all(|m| m.satisfied);

        PhaseEvaluation {
            current_phase: self.current_phase,
            next_phase_ready: all_satisfied,
            milestones,
        }
    }

    /// Advance to the next phase if all milestones are met and confirmed.
    pub fn advance_phase(
        &mut self,
        metrics: &NetworkMetrics,
        current_height: u64,
    ) -> Result<DecentralizationPhase, ConsensusError> {
        if self.current_phase == DecentralizationPhase::FullSovereignty {
            return Err(ConsensusError::InvalidBlock {
                reason: "already at full sovereignty — no further phases".to_string(),
            });
        }

        let eval = self.evaluate(metrics);

        if !eval.next_phase_ready {
            let unmet: Vec<_> = eval
                .milestones
                .iter()
                .filter(|m| !m.satisfied)
                .map(|m| m.description.clone())
                .collect();

            return Err(ConsensusError::InvalidBlock {
                reason: format!("milestones not met: {}", unmet.join(", ")),
            });
        }

        if !self.transition_confirmed {
            return Err(ConsensusError::InvalidBlock {
                reason: "phase transition requires governance vote confirmation".to_string(),
            });
        }

        let new_phase = match self.current_phase {
            DecentralizationPhase::Foundation => DecentralizationPhase::Federation,
            DecentralizationPhase::Federation => DecentralizationPhase::DualConsensus,
            DecentralizationPhase::DualConsensus => DecentralizationPhase::FullSovereignty,
            DecentralizationPhase::FullSovereignty => {
                return Err(ConsensusError::InvalidBlock {
                    reason: "already at final phase — no further transitions possible".to_string(),
                });
            }
        };

        self.current_phase = new_phase;
        self.phase_entered_at = current_height;
        self.transition_confirmed = false; // Reset for next transition

        Ok(new_phase)
    }

    /// Confirm a phase transition via governance vote.
    pub fn confirm_transition(&mut self) {
        self.transition_confirmed = true;
    }

    fn phase_0_milestones(&self, m: &NetworkMetrics) -> Vec<Milestone> {
        vec![
            Milestone {
                description: "≥10 independent sequencers".to_string(),
                satisfied: m.active_sequencers >= PHASE_0_MIN_SEQUENCERS,
                current: m.active_sequencers,
                required: PHASE_0_MIN_SEQUENCERS,
            },
            Milestone {
                description: "≥1,000 eligible users".to_string(),
                satisfied: m.eligible_users >= PHASE_0_MIN_USERS,
                current: m.eligible_users,
                required: PHASE_0_MIN_USERS,
            },
            Milestone {
                description: "≥100 BTC locked in bridge".to_string(),
                satisfied: m.locked_sats >= PHASE_0_MIN_LOCKED_SATS,
                current: m.locked_sats,
                required: PHASE_0_MIN_LOCKED_SATS,
            },
            Milestone {
                description: "≥3 geographic regions".to_string(),
                satisfied: m.distinct_regions >= PHASE_0_MIN_REGIONS,
                current: m.distinct_regions,
                required: PHASE_0_MIN_REGIONS,
            },
            Milestone {
                description: "≥6 months uptime without critical incidents".to_string(),
                satisfied: m.uptime_blocks >= PHASE_0_MIN_UPTIME_BLOCKS,
                current: m.uptime_blocks,
                required: PHASE_0_MIN_UPTIME_BLOCKS,
            },
        ]
    }

    fn phase_1_milestones(&self, m: &NetworkMetrics) -> Vec<Milestone> {
        vec![
            Milestone {
                description: "≥30 independent sequencers".to_string(),
                satisfied: m.active_sequencers >= PHASE_1_MIN_SEQUENCERS,
                current: m.active_sequencers,
                required: PHASE_1_MIN_SEQUENCERS,
            },
            Milestone {
                description: "≥5,000 eligible users".to_string(),
                satisfied: m.eligible_users >= PHASE_1_MIN_USERS,
                current: m.eligible_users,
                required: PHASE_1_MIN_USERS,
            },
            Milestone {
                description: "≥500 BTC locked in bridge".to_string(),
                satisfied: m.locked_sats >= PHASE_1_MIN_LOCKED_SATS,
                current: m.locked_sats,
                required: PHASE_1_MIN_LOCKED_SATS,
            },
            Milestone {
                description: "≥5 regions with sequencers".to_string(),
                satisfied: m.distinct_regions >= PHASE_1_MIN_REGIONS,
                current: m.distinct_regions,
                required: PHASE_1_MIN_REGIONS,
            },
            Milestone {
                description: "≥5 governance proposals executed".to_string(),
                satisfied: m.proposals_executed >= PHASE_1_MIN_PROPOSALS_EXECUTED,
                current: m.proposals_executed,
                required: PHASE_1_MIN_PROPOSALS_EXECUTED,
            },
            Milestone {
                description: "0 founder seats in covenant committee".to_string(),
                satisfied: m.founder_seats == PHASE_1_MAX_FOUNDER_SEATS,
                current: m.founder_seats,
                required: PHASE_1_MAX_FOUNDER_SEATS,
            },
            Milestone {
                description: "≥2 successful council elections".to_string(),
                satisfied: m.council_elections >= 2,
                current: m.council_elections,
                required: 2,
            },
        ]
    }

    fn phase_2_milestones(&self, m: &NetworkMetrics) -> Vec<Milestone> {
        vec![
            Milestone {
                description: "≥100 independent sequencers".to_string(),
                satisfied: m.active_sequencers >= PHASE_2_MIN_SEQUENCERS,
                current: m.active_sequencers,
                required: PHASE_2_MIN_SEQUENCERS,
            },
            Milestone {
                description: "≥20,000 eligible users".to_string(),
                satisfied: m.eligible_users >= PHASE_2_MIN_USERS,
                current: m.eligible_users,
                required: PHASE_2_MIN_USERS,
            },
            Milestone {
                description: "≥90% peg-outs via BitVM2".to_string(),
                satisfied: m.bitvm2_pegout_bp >= PHASE_2_MIN_BITVM2_PEGOUT_BP,
                current: m.bitvm2_pegout_bp,
                required: PHASE_2_MIN_BITVM2_PEGOUT_BP,
            },
            Milestone {
                description: "Rage Quit mechanism tested".to_string(),
                satisfied: m.rage_quit_tested,
                current: m.rage_quit_tested as u64,
                required: 1,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_metrics() -> NetworkMetrics {
        NetworkMetrics {
            active_sequencers: 0,
            eligible_users: 0,
            locked_sats: 0,
            distinct_regions: 0,
            uptime_blocks: 0,
            proposals_executed: 0,
            founder_seats: 2,
            bitvm2_pegout_bp: 0,
            rage_quit_tested: false,
            council_elections: 0,
        }
    }

    #[test]
    fn phase_0_not_ready() {
        let tracker = DecentralizationTracker::new();
        let eval = tracker.evaluate(&default_metrics());

        assert_eq!(eval.current_phase, DecentralizationPhase::Foundation);
        assert!(!eval.next_phase_ready);
        assert_eq!(eval.milestones.len(), 5);
    }

    #[test]
    fn phase_0_ready() {
        let tracker = DecentralizationTracker::new();
        let metrics = NetworkMetrics {
            active_sequencers: 15,
            eligible_users: 2_000,
            locked_sats: 15_000_000_000,
            distinct_regions: 5,
            uptime_blocks: 6_000_000,
            ..default_metrics()
        };

        let eval = tracker.evaluate(&metrics);
        assert!(eval.next_phase_ready);
        assert!(eval.milestones.iter().all(|m| m.satisfied));
    }

    #[test]
    fn advance_requires_confirmation() {
        let mut tracker = DecentralizationTracker::new();
        let metrics = NetworkMetrics {
            active_sequencers: 15,
            eligible_users: 2_000,
            locked_sats: 15_000_000_000,
            distinct_regions: 5,
            uptime_blocks: 6_000_000,
            ..default_metrics()
        };

        // Milestones met but not confirmed
        let err = tracker.advance_phase(&metrics, 10_000).unwrap_err();
        assert!(err.to_string().contains("governance vote"));

        // Confirm and advance
        tracker.confirm_transition();
        let new_phase = tracker.advance_phase(&metrics, 10_000).unwrap();
        assert_eq!(new_phase, DecentralizationPhase::Federation);
    }

    #[test]
    fn cannot_advance_past_full_sovereignty() {
        let mut tracker = DecentralizationTracker::new();
        tracker.current_phase = DecentralizationPhase::FullSovereignty;

        let err = tracker
            .advance_phase(&default_metrics(), 10_000)
            .unwrap_err();
        assert!(err.to_string().contains("full sovereignty"));
    }

    #[test]
    fn phase_1_requires_zero_founder_seats() {
        let mut tracker = DecentralizationTracker::new();
        tracker.current_phase = DecentralizationPhase::Federation;

        let metrics = NetworkMetrics {
            active_sequencers: 50,
            eligible_users: 10_000,
            locked_sats: 60_000_000_000,
            distinct_regions: 7,
            proposals_executed: 10,
            founder_seats: 1, // Still 1 — should fail
            council_elections: 3,
            ..default_metrics()
        };

        let eval = tracker.evaluate(&metrics);
        assert!(!eval.next_phase_ready);

        let founder_milestone = eval
            .milestones
            .iter()
            .find(|m| m.description.contains("founder"));
        assert!(founder_milestone.is_some());
        assert!(!founder_milestone.unwrap().satisfied);
    }

    // ── Bridge Metrics ──────────────────────────────────────────

    #[test]
    fn bridge_metrics_ratio_calculation() {
        let mut bm = BridgeMetrics::default();
        for _ in 0..7 {
            bm.record_pegout(true);
        }
        for _ in 0..3 {
            bm.record_pegout(false);
        }
        assert_eq!(bm.total_pegouts, 10);
        assert_eq!(bm.bitvm2_pegouts, 7);
        assert_eq!(bm.bitvm2_pegout_bp(), 7000);
    }

    #[test]
    fn bridge_metrics_zero_division_guard() {
        let bm = BridgeMetrics::default();
        assert_eq!(bm.bitvm2_pegout_bp(), 0);
    }

    #[test]
    fn phase_2_transition_with_bridge_metrics() {
        let mut tracker = DecentralizationTracker::new();
        tracker.current_phase = DecentralizationPhase::DualConsensus;

        // Without sufficient BitVM2 peg-outs
        let metrics_low = NetworkMetrics {
            active_sequencers: 150,
            eligible_users: 30_000,
            bitvm2_pegout_bp: 5000, // only 50%
            rage_quit_tested: true,
            ..default_metrics()
        };
        let eval = tracker.evaluate(&metrics_low);
        assert!(!eval.next_phase_ready);

        // With sufficient BitVM2 peg-outs (≥90%)
        let metrics_ok = NetworkMetrics {
            bitvm2_pegout_bp: 9500, // 95%
            ..metrics_low
        };
        let eval = tracker.evaluate(&metrics_ok);
        assert!(eval.next_phase_ready);
    }
}
