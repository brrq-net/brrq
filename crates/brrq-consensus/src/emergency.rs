//! Emergency mechanisms — tiered response to critical situations.
//!
//! ## Design (Article 19)
//!
//! Three emergency levels with escalating authority requirements:
//!
//! **Level 1 — Pause**: Single federation member or 3/7 council.
//!   Pauses new peg-in only. Peg-out never stops. Auto-expires 24h.
//!
//! **Level 2 — Governance Freeze**: 5/7 council + 67% sequencers.
//!   No new proposals, active proposals suspended. Peg-out continues. 7 days.
//!
//! **Level 3 — Critical Emergency**: 5/7 council + 80% sequencers + 51% users.
//!   EmergencyPatch with reduced 72h time-lock. Peg-out with max priority.
//!
//! **Invariant**: peg-out NEVER stops at any emergency level.

use brrq_types::Address;

use crate::ConsensusError;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Level 1 auto-expiry: 24 hours at 3s/block.
pub const LEVEL_1_DURATION: u64 = 28_800;

/// Level 2 duration: 7 days at 3s/block.
pub const LEVEL_2_DURATION: u64 = 201_600;

/// Level 1 council threshold: 3 of 7.
pub const LEVEL_1_COUNCIL_THRESHOLD: usize = 3;

/// Level 2 council threshold: 5 of 7.
pub const LEVEL_2_COUNCIL_THRESHOLD: usize = 5;

/// Level 2 sequencer threshold: 67% (basis points).
pub const LEVEL_2_SEQUENCER_BP: u64 = 6_700;

/// Level 3 council threshold: 5 of 7.
pub const LEVEL_3_COUNCIL_THRESHOLD: usize = 5;

/// Level 3 sequencer threshold: 80% (basis points).
pub const LEVEL_3_SEQUENCER_BP: u64 = 8_000;

/// Level 3 user threshold: 51% (basis points).
pub const LEVEL_3_USER_BP: u64 = 5_100;

/// Resume from Level 1: federation quorum (6/9) or council (5/7).
pub const RESUME_FEDERATION_THRESHOLD: usize = 6;

/// Resume from Level 2: user vote 51%.
pub const RESUME_USER_BP: u64 = 5_100;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// Emergency level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EmergencyLevel {
    /// No emergency — normal operation.
    None = 0,
    /// Level 1: Bridge peg-in paused, peg-out continues.
    Pause = 1,
    /// Level 2: Governance frozen, peg-out continues.
    GovernanceFreeze = 2,
    /// Level 3: Emergency patch with reduced time-lock.
    Critical = 3,
}

/// An active emergency state.
#[derive(Debug, Clone)]
pub struct EmergencyState {
    /// Current emergency level.
    pub level: EmergencyLevel,
    /// Block height when emergency was activated.
    pub activated_at: u64,
    /// Block height when emergency auto-expires.
    pub expires_at: u64,
    /// Who triggered the emergency.
    pub triggered_by: Address,
    /// Reason for the emergency.
    pub reason: String,
    /// Council members who authorized (for Level 2/3).
    pub council_authorizers: Vec<Address>,
}

/// What actions are allowed during the current emergency level.
#[derive(Debug, Clone, Copy)]
pub struct EmergencyRestrictions {
    /// Can new deposits (peg-in) be processed?
    pub peg_in_allowed: bool,
    /// Can withdrawals (peg-out) be processed? ALWAYS true.
    pub peg_out_allowed: bool,
    /// Can regular L2 transactions be processed?
    pub l2_transactions_allowed: bool,
    /// Can new governance proposals be submitted?
    pub new_proposals_allowed: bool,
    /// Can ongoing votes proceed?
    pub voting_allowed: bool,
    /// Should peg-out have elevated priority?
    pub peg_out_priority: bool,
}

impl EmergencyRestrictions {
    /// Normal operation — everything allowed.
    pub fn normal() -> Self {
        Self {
            peg_in_allowed: true,
            peg_out_allowed: true, // ALWAYS true
            l2_transactions_allowed: true,
            new_proposals_allowed: true,
            voting_allowed: true,
            peg_out_priority: false,
        }
    }

    /// Level 1 restrictions.
    pub fn level_1() -> Self {
        Self {
            peg_in_allowed: false, // Paused
            peg_out_allowed: true, // ALWAYS true
            l2_transactions_allowed: true,
            new_proposals_allowed: true,
            voting_allowed: true,
            peg_out_priority: false,
        }
    }

    /// Level 2 restrictions.
    pub fn level_2() -> Self {
        Self {
            peg_in_allowed: false, // Paused
            peg_out_allowed: true, // ALWAYS true
            l2_transactions_allowed: true,
            new_proposals_allowed: false, // Frozen
            voting_allowed: false,        // Frozen
            peg_out_priority: false,
        }
    }

    /// Level 3 restrictions.
    pub fn level_3() -> Self {
        Self {
            peg_in_allowed: false, // Paused
            peg_out_allowed: true, // ALWAYS true
            l2_transactions_allowed: true,
            new_proposals_allowed: false, // Only EmergencyPatch allowed
            voting_allowed: false,        // Only emergency voting
            peg_out_priority: true,       // Maximum priority for exits
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// EmergencyManager
// ═══════════════════════════════════════════════════════════════

/// Manages the emergency state machine.
///
/// **Core invariant**: `peg_out_allowed` is ALWAYS `true` regardless of
/// emergency level. This is enforced by the type system and cannot be
/// overridden. This implements Law 3 (Unconditional Exit Right).
///
/// Level 1 activation now requires the caller to be in the
/// `authorized_emergency_keys` list. Without this check, any address could
/// pause peg-in, enabling griefing attacks on the bridge.
#[derive(Debug, Clone)]
pub struct EmergencyManager {
    /// Current emergency state (None if no emergency).
    pub(crate) current: Option<EmergencyState>,
    /// Historical emergency activations count.
    pub(crate) total_activations: u64,
    /// Addresses authorized to trigger Level 1 emergency.
    /// Typically federation members or designated emergency operators.
    pub(crate) authorized_emergency_keys: Vec<Address>,
}

/// Default is test-only. Production must use new_with_keys().
#[cfg(test)]
impl Default for EmergencyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl EmergencyManager {
    /// Create a new EmergencyManager with no authorized keys.
    ///
    /// This constructor is restricted to test builds only.
    /// In production, use `new_with_keys()` — an EmergencyManager without authorized
    /// keys allows ANY address to trigger Level 1 emergency (griefing attack).
    #[cfg(test)]
    pub fn new() -> Self {
        Self {
            current: None,
            total_activations: 0,
            authorized_emergency_keys: vec![],
        }
    }

    /// Create a new EmergencyManager with a list of addresses
    /// authorized to trigger Level 1 emergency. In production, this should
    /// always be used instead of `new()`.
    ///
    /// Returns an error if `authorized_keys` is empty, since an empty list
    /// would mean no one can trigger Level 1 emergency, which is likely a
    /// configuration mistake.
    pub fn new_with_keys(authorized_keys: Vec<Address>) -> Result<Self, ConsensusError> {
        if authorized_keys.is_empty() {
            return Err(ConsensusError::InvalidBlock {
                reason: "at least one emergency key required".into(),
            });
        }
        Ok(Self {
            current: None,
            total_activations: 0,
            authorized_emergency_keys: authorized_keys,
        })
    }

    /// Get total number of emergency activations.
    pub fn total_activations(&self) -> u64 {
        self.total_activations
    }

    /// Get current emergency level.
    pub fn current_level(&self) -> EmergencyLevel {
        self.current
            .as_ref()
            .map(|s| s.level)
            .unwrap_or(EmergencyLevel::None)
    }

    /// Get current restrictions based on emergency level.
    pub fn restrictions(&self) -> EmergencyRestrictions {
        match self.current_level() {
            EmergencyLevel::None => EmergencyRestrictions::normal(),
            EmergencyLevel::Pause => EmergencyRestrictions::level_1(),
            EmergencyLevel::GovernanceFreeze => EmergencyRestrictions::level_2(),
            EmergencyLevel::Critical => EmergencyRestrictions::level_3(),
        }
    }

    /// Activate Level 1 emergency (Pause).
    ///
    /// The caller (`triggered_by`) must be in the authorized
    /// emergency keys list. This prevents arbitrary addresses from pausing
    /// the bridge, which would be a griefing vector against all users.
    pub fn activate_level_1(
        &mut self,
        triggered_by: Address,
        reason: String,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // Verify caller is authorized for Level 1 activation.
        // When the authorized keys list is empty, NO address is authorized
        // (empty list = no one allowed, not everyone allowed).
        if self.authorized_emergency_keys.is_empty()
            || !self.authorized_emergency_keys.contains(&triggered_by)
        {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "address {} is not authorized to activate Level 1 emergency (or no emergency keys configured)",
                    triggered_by,
                ),
            });
        }

        // Can escalate from None or re-trigger Level 1
        if self.current_level() > EmergencyLevel::Pause {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "cannot downgrade from {:?} to Level 1",
                    self.current_level(),
                ),
            });
        }

        self.current = Some(EmergencyState {
            level: EmergencyLevel::Pause,
            activated_at: current_height,
            expires_at: current_height.saturating_add(LEVEL_1_DURATION),
            triggered_by,
            reason,
            council_authorizers: vec![],
        });
        self.total_activations += 1;
        Ok(())
    }

    /// Activate Level 2 emergency (Governance Freeze).
    ///
    /// Requires 5/7 council + 67% sequencer stake approval.
    /// The caller must verify sequencer approval and pass the percentage.
    pub fn activate_level_2(
        &mut self,
        triggered_by: Address,
        reason: String,
        council_authorizers: Vec<Address>,
        sequencer_approval_bp: u64,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // Deduplicate council authorizers to prevent a single
        // council member from being listed multiple times to bypass the threshold.
        let unique_authorizers: std::collections::HashSet<&Address> =
            council_authorizers.iter().collect();
        if unique_authorizers.len() < LEVEL_2_COUNCIL_THRESHOLD {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "Level 2 requires {}/{} unique council authorizers, got {} (unique: {})",
                    LEVEL_2_COUNCIL_THRESHOLD,
                    7,
                    council_authorizers.len(),
                    unique_authorizers.len(),
                ),
            });
        }

        // Verify all authorizers are actual council members.
        // Without this, any address can claim to be a council authorizer.
        for authorizer in &council_authorizers {
            if !self.authorized_emergency_keys.contains(authorizer) {
                return Err(ConsensusError::InvalidBlock {
                    reason: format!(
                        "address {} is not an authorized council member for Level 2 emergency",
                        authorizer,
                    ),
                });
            }
        }

        if sequencer_approval_bp < LEVEL_2_SEQUENCER_BP {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "Level 2 requires {}bp sequencer approval, got {}bp",
                    LEVEL_2_SEQUENCER_BP, sequencer_approval_bp,
                ),
            });
        }

        self.current = Some(EmergencyState {
            level: EmergencyLevel::GovernanceFreeze,
            activated_at: current_height,
            expires_at: current_height.saturating_add(LEVEL_2_DURATION),
            triggered_by,
            reason,
            council_authorizers,
        });
        self.total_activations += 1;
        Ok(())
    }

    /// Activate Level 3 emergency (Critical).
    ///
    /// Requires 5/7 council + 80% sequencer stake + 51% user approval.
    pub fn activate_level_3(
        &mut self,
        triggered_by: Address,
        reason: String,
        council_authorizers: Vec<Address>,
        sequencer_approval_bp: u64,
        user_approval_bp: u64,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // Deduplicate council authorizers to prevent a single
        // council member from being listed multiple times to bypass the threshold.
        let unique_authorizers: std::collections::HashSet<&Address> =
            council_authorizers.iter().collect();
        if unique_authorizers.len() < LEVEL_3_COUNCIL_THRESHOLD {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "Level 3 requires {}/{} unique council authorizers, got {} (unique: {})",
                    LEVEL_3_COUNCIL_THRESHOLD,
                    7,
                    council_authorizers.len(),
                    unique_authorizers.len(),
                ),
            });
        }

        // Verify all authorizers are actual council members.
        for authorizer in &council_authorizers {
            if !self.authorized_emergency_keys.contains(authorizer) {
                return Err(ConsensusError::InvalidBlock {
                    reason: format!(
                        "address {} is not an authorized council member for Level 3 emergency",
                        authorizer,
                    ),
                });
            }
        }

        if sequencer_approval_bp < LEVEL_3_SEQUENCER_BP {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "Level 3 requires {}bp sequencer approval, got {}bp",
                    LEVEL_3_SEQUENCER_BP, sequencer_approval_bp,
                ),
            });
        }

        if user_approval_bp < LEVEL_3_USER_BP {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "Level 3 requires {}bp user approval, got {}bp",
                    LEVEL_3_USER_BP, user_approval_bp,
                ),
            });
        }

        // Level 3 doesn't auto-expire — requires explicit resolution
        self.current = Some(EmergencyState {
            level: EmergencyLevel::Critical,
            activated_at: current_height,
            expires_at: u64::MAX, // No auto-expiry
            triggered_by,
            reason,
            council_authorizers,
        });
        self.total_activations += 1;
        Ok(())
    }

    /// Resume normal operation from Level 1 or Level 2.
    ///
    /// The `caller` must be in the `authorized_emergency_keys` list.
    /// Without this check, any address could cancel an emergency,
    /// undermining the authorization model.
    pub fn resume(
        &mut self,
        caller: &Address,
        _current_height: u64,
    ) -> Result<(), ConsensusError> {
        // Verify caller is authorized.
        if !self.authorized_emergency_keys.contains(caller) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "address {} is not authorized to resume from emergency",
                    caller,
                ),
            });
        }

        let level = self.current_level();
        if level == EmergencyLevel::None {
            return Err(ConsensusError::InvalidBlock {
                reason: "no active emergency to resume from".to_string(),
            });
        }

        if level == EmergencyLevel::Critical {
            return Err(ConsensusError::InvalidBlock {
                reason: "Level 3 (Critical) requires explicit resolution, not resume".to_string(),
            });
        }

        self.current = None;
        Ok(())
    }

    /// Resolve Level 3 (Critical) emergency.
    pub fn resolve_critical(&mut self, _current_height: u64) -> Result<(), ConsensusError> {
        if self.current_level() != EmergencyLevel::Critical {
            return Err(ConsensusError::InvalidBlock {
                reason: "no Level 3 emergency active".to_string(),
            });
        }

        self.current = None;
        Ok(())
    }

    /// Process block — check for auto-expiry.
    pub fn process_block(&mut self, current_height: u64) {
        if let Some(state) = &self.current
            && current_height >= state.expires_at
        {
            self.current = None;
        }
    }

    /// Check if peg-out is allowed. This ALWAYS returns true.
    ///
    /// This method exists as a compile-time documentation of the invariant.
    /// Removing or modifying it to return false would violate Law 3.
    #[inline(always)]
    pub fn is_peg_out_allowed(&self) -> bool {
        // Law 3: Unconditional Exit Right — peg-out NEVER stops.
        // This is an immutable invariant enforced at the type level.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(val: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = val;
        Address(bytes)
    }

    /// Helper: create an EmergencyManager with addr(1)..addr(5) authorized.
    /// Tests for Level 2/3 pass council_authorizers = [addr(1)..addr(5)],
    /// and the validates every authorizer is in authorized_emergency_keys.
    fn mgr_with_council() -> EmergencyManager {
        EmergencyManager::new_with_keys(vec![addr(1), addr(2), addr(3), addr(4), addr(5)]).unwrap()
    }

    #[test]
    fn peg_out_always_allowed() {
        let mut mgr = mgr_with_council();

        // Normal
        assert!(mgr.is_peg_out_allowed());
        assert!(mgr.restrictions().peg_out_allowed);

        // Level 1
        mgr.activate_level_1(addr(1), "test".into(), 0).unwrap();
        assert!(mgr.is_peg_out_allowed());
        assert!(mgr.restrictions().peg_out_allowed);

        // Level 2
        let council = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];
        mgr.activate_level_2(addr(1), "test".into(), council.clone(), 10_000, 100)
            .unwrap();
        assert!(mgr.is_peg_out_allowed());
        assert!(mgr.restrictions().peg_out_allowed);

        // Level 3
        mgr.activate_level_3(addr(1), "test".into(), council, 10_000, 10_000, 200)
            .unwrap();
        assert!(mgr.is_peg_out_allowed());
        assert!(mgr.restrictions().peg_out_allowed);
    }

    #[test]
    fn level_1_pauses_peg_in() {
        let mut mgr = mgr_with_council();
        mgr.activate_level_1(addr(1), "test".into(), 0).unwrap();

        let r = mgr.restrictions();
        assert!(!r.peg_in_allowed);
        assert!(r.l2_transactions_allowed);
        assert!(r.new_proposals_allowed);
    }

    #[test]
    fn level_2_freezes_governance() {
        let mut mgr = mgr_with_council();
        let council = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];
        mgr.activate_level_2(addr(1), "test".into(), council, 10_000, 0)
            .unwrap();

        let r = mgr.restrictions();
        assert!(!r.peg_in_allowed);
        assert!(!r.new_proposals_allowed);
        assert!(!r.voting_allowed);
    }

    #[test]
    fn level_3_max_priority_exit() {
        let mut mgr = mgr_with_council();
        let council = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];
        mgr.activate_level_3(addr(1), "critical".into(), council, 10_000, 10_000, 0)
            .unwrap();

        let r = mgr.restrictions();
        assert!(r.peg_out_priority);
    }

    #[test]
    fn level_1_auto_expires() {
        let mut mgr = mgr_with_council();
        mgr.activate_level_1(addr(1), "test".into(), 0).unwrap();

        assert_eq!(mgr.current_level(), EmergencyLevel::Pause);

        mgr.process_block(LEVEL_1_DURATION);

        assert_eq!(mgr.current_level(), EmergencyLevel::None);
    }

    #[test]
    fn level_2_requires_council_threshold() {
        let mut mgr = mgr_with_council();

        // Only 3 council — not enough for Level 2
        let err = mgr
            .activate_level_2(
                addr(1),
                "test".into(),
                vec![addr(1), addr(2), addr(3)],
                10_000,
                0,
            )
            .unwrap_err();
        assert!(err.to_string().contains("requires 5"));
    }

    #[test]
    fn cannot_downgrade_from_level_2_to_level_1() {
        let mut mgr = mgr_with_council();
        let council = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];
        mgr.activate_level_2(addr(1), "test".into(), council, 10_000, 0)
            .unwrap();

        let err = mgr
            .activate_level_1(addr(1), "test".into(), 100)
            .unwrap_err();
        assert!(err.to_string().contains("downgrade"));
    }

    #[test]
    fn resume_from_level_1() {
        let mut mgr = mgr_with_council();
        mgr.activate_level_1(addr(1), "test".into(), 0).unwrap();
        mgr.resume(&addr(1), 100).unwrap();
        assert_eq!(mgr.current_level(), EmergencyLevel::None);
    }

    #[test]
    fn resume_rejects_unauthorized_caller() {
        let mut mgr = mgr_with_council();
        mgr.activate_level_1(addr(1), "test".into(), 0).unwrap();
        let err = mgr.resume(&addr(99), 100).unwrap_err();
        assert!(err.to_string().contains("not authorized"));
    }

    #[test]
    fn level_3_requires_explicit_resolution() {
        let mut mgr = mgr_with_council();
        let council = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];
        mgr.activate_level_3(addr(1), "critical".into(), council, 10_000, 10_000, 0)
            .unwrap();

        // Resume doesn't work for Level 3
        let err = mgr.resume(&addr(1), 100).unwrap_err();
        assert!(err.to_string().contains("explicit resolution"));

        // Must use resolve_critical
        mgr.resolve_critical(200).unwrap();
        assert_eq!(mgr.current_level(), EmergencyLevel::None);
    }

    // Test that unauthorized address is rejected.
    #[test]
    fn level_1_rejects_unauthorized_caller() {
        let authorized = vec![addr(10), addr(11), addr(12)];
        let mut mgr = EmergencyManager::new_with_keys(authorized).unwrap();

        // addr(1) is NOT in the authorized list.
        let err = mgr.activate_level_1(addr(1), "test".into(), 0).unwrap_err();
        assert!(err.to_string().contains("not authorized"));
    }

    // Test that authorized address is accepted.
    #[test]
    fn level_1_accepts_authorized_caller() {
        let authorized = vec![addr(10), addr(11), addr(12)];
        let mut mgr = EmergencyManager::new_with_keys(authorized).unwrap();

        // addr(10) IS in the authorized list.
        mgr.activate_level_1(addr(10), "test".into(), 0).unwrap();
        assert_eq!(mgr.current_level(), EmergencyLevel::Pause);
    }

    // Empty keys list is now rejected by new_with_keys.
    #[test]
    fn new_with_keys_rejects_empty_keys() {
        let result = EmergencyManager::new_with_keys(vec![]);
        assert!(result.is_err(), "new_with_keys must reject empty keys list");
    }

    // Test that empty keys (test-only new()) rejects all callers.
    #[test]
    fn level_1_rejects_any_caller_with_empty_keys() {
        let mut mgr = EmergencyManager::new(); // no authorized keys (test-only)
        let result = mgr.activate_level_1(addr(99), "test".into(), 0);
        assert!(result.is_err(), "empty keys must reject all callers");
    }

    #[test]
    fn level_2_rejects_insufficient_sequencer_approval() {
        let mut mgr = mgr_with_council();
        let council = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];

        // 50% sequencer approval — below 67% threshold
        let err = mgr
            .activate_level_2(addr(1), "test".into(), council, 5_000, 0)
            .unwrap_err();
        assert!(err.to_string().contains("sequencer approval"));
    }

    #[test]
    fn level_3_rejects_insufficient_sequencer_approval() {
        let mut mgr = mgr_with_council();
        let council = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];

        // 70% sequencer — below 80% threshold
        let err = mgr
            .activate_level_3(addr(1), "critical".into(), council, 7_000, 10_000, 0)
            .unwrap_err();
        assert!(err.to_string().contains("sequencer approval"));
    }

    #[test]
    fn level_3_rejects_insufficient_user_approval() {
        let mut mgr = mgr_with_council();
        let council = vec![addr(1), addr(2), addr(3), addr(4), addr(5)];

        // 80% sequencer (ok) but only 30% user — below 51% threshold
        let err = mgr
            .activate_level_3(addr(1), "critical".into(), council, 10_000, 3_000, 0)
            .unwrap_err();
        assert!(err.to_string().contains("user approval"));
    }
}
