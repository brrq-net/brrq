//! Bridge monitor — L1 monitoring, prover-strike detection, federation sunset.
//!
//! Monitors L1 for proof gaps and federation sunset status.

use brrq_api::events::NodeEvent;
use brrq_api::state::NodeState;

/// Run pre-block L1 monitoring checks.
///
/// Called from `produce_block` before block building:
/// 1. Detect proof gap and activate fallback prover (PROVER-STRIKE)
/// 2. Check federation sunset status
pub(crate) fn run_l1_checks(ns: &mut NodeState, height: u64) {
    // ── Detect proof gap and activate fallback ──
    let proof_gap = height.saturating_sub(ns.last_proved_height);
    if proof_gap >= ns.max_unproven_blocks && !ns.fallback_prover_active {
        tracing::error!(
            proof_gap,
            height,
            last_proved = ns.last_proved_height,
            "PROVER-STRIKE: Proof gap ({} blocks) exceeds threshold ({}). \
             Activating emergency fallback prover to prevent fund lockup.",
            proof_gap,
            ns.max_unproven_blocks,
        );
        ns.fallback_prover_active = true;

        // Emit event for monitoring systems
        if let Some(ref event_tx) = ns.event_tx {
            let _ = event_tx.send(NodeEvent::ProverStrikeDetected {
                proof_gap,
                last_proved_height: ns.last_proved_height,
                current_height: height,
            });
        }
    }

    // ── Check federation sunset every block (not just on deposits) ──
    ns.bridge.check_federation_sunset();
}
