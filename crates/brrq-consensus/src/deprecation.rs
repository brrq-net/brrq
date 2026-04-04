//! EOTS deprecation gate.
//!
//! EOTS (Extractable One-Time Signatures) is the primary slashing mechanism
//! in Brrq's dual-signing scheme. While EOTS provides instant self-enforcing
//! equivocation detection, its Schnorr-based construction is vulnerable to
//! quantum attacks (Shor's algorithm).
//!
//! This module defines the deprecation gate: a set of conditions that MUST
//! be met before EOTS can be safely disabled. Premature removal of EOTS
//! without a replacement leaves the protocol without instant slashing,
//! creating a window where equivocation is economically viable.
//!
//! ## Deprecation Conditions
//!
//! All three conditions must be TRUE before EOTS can be disabled:
//!
//! 1. **SLH-DSA Equivocation Proofs**: L1 Bitcoin script must be able to
//!    verify SLH-DSA equivocation proofs (BitVM2 opcodes or soft fork).
//! 2. **Quantum Threat Materialized**: NIST or equivalent body has declared
//!    Schnorr-based signatures unsafe (CRQC > 2000 logical qubits).
//! 3. **Community Governance**: Constitutional amendment (90% both chambers)
//!    approving EOTS removal.

/// Master flag: whether EOTS is still required for block signing.
///
/// When `true`, every block MUST include an EOTS signature alongside SLH-DSA.
/// When `false`, SLH-DSA alone is sufficient.
///
/// This flag should only be set to `false` after ALL deprecation conditions
/// are met AND a constitutional governance vote has passed.
pub const EOTS_REQUIRED: bool = true;

/// The three conditions required to safely deprecate EOTS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EotsDeprecationCheck {
    /// Condition 1: SLH-DSA equivocation proofs are verifiable on L1.
    /// Requires either: BitVM2 support for SLH-DSA verification, or
    /// a Bitcoin soft fork adding SLH-DSA opcodes.
    pub slh_dsa_l1_verifiable: bool,

    /// Condition 2: Quantum threat has materialized.
    /// Defined as: NIST advisory declares Schnorr/ECDSA unsafe, OR
    /// a demonstrated CRQC with >2000 logical qubits exists.
    pub quantum_threat_active: bool,

    /// Condition 3: Constitutional governance vote passed.
    /// Requires 90% approval in both sequencer and user chambers.
    pub governance_approved: bool,
}

impl EotsDeprecationCheck {
    /// Create a new deprecation check with all conditions unmet.
    pub fn new() -> Self {
        Self {
            slh_dsa_l1_verifiable: false,
            quantum_threat_active: false,
            governance_approved: false,
        }
    }

    /// Whether ALL three conditions are met for safe EOTS deprecation.
    pub fn can_deprecate(&self) -> bool {
        self.slh_dsa_l1_verifiable && self.quantum_threat_active && self.governance_approved
    }

    /// Whether EOTS is currently required for block signing.
    ///
    /// Returns `true` if either the master flag is set OR deprecation
    /// conditions are not yet met.
    pub fn eots_required(&self) -> bool {
        EOTS_REQUIRED || !self.can_deprecate()
    }

    /// Human-readable status of each condition.
    pub fn status_report(&self) -> Vec<(&'static str, bool)> {
        vec![
            ("SLH-DSA L1 verifiable", self.slh_dsa_l1_verifiable),
            ("Quantum threat active", self.quantum_threat_active),
            ("Governance approved", self.governance_approved),
        ]
    }

    /// Count of conditions met (0-3).
    pub fn conditions_met(&self) -> u8 {
        self.slh_dsa_l1_verifiable as u8
            + self.quantum_threat_active as u8
            + self.governance_approved as u8
    }
}

impl Default for EotsDeprecationCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_all_conditions_unmet() {
        let check = EotsDeprecationCheck::new();
        assert!(!check.can_deprecate());
        assert!(check.eots_required());
        assert_eq!(check.conditions_met(), 0);
    }

    #[test]
    fn test_partial_conditions_not_sufficient() {
        let mut check = EotsDeprecationCheck::new();
        check.slh_dsa_l1_verifiable = true;
        check.quantum_threat_active = true;
        // governance_approved still false
        assert!(!check.can_deprecate());
        assert!(check.eots_required());
        assert_eq!(check.conditions_met(), 2);
    }

    #[test]
    fn test_all_conditions_met() {
        let check = EotsDeprecationCheck {
            slh_dsa_l1_verifiable: true,
            quantum_threat_active: true,
            governance_approved: true,
        };
        assert!(check.can_deprecate());
        assert_eq!(check.conditions_met(), 3);
        // Still required because EOTS_REQUIRED master flag is true
        assert!(check.eots_required());
    }

    #[test]
    fn test_status_report() {
        let check = EotsDeprecationCheck::new();
        let report = check.status_report();
        assert_eq!(report.len(), 3);
        assert!(report.iter().all(|(_, met)| !met));
    }
}
