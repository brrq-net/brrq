//! Technical Council — advisory body with Security Veto power.
//!
//! ## Architecture (Article 3.3)
//!
//! The Technical Council is a 7-member body with three roles:
//! - 3 Security Auditors
//! - 2 Core Protocol Developers
//! - 2 Cryptographers
//!
//! ## Powers
//! 1. **Security Veto** (5/7): Suspend any proposal for 30 days for audit.
//! 2. **Mandatory Report**: TechnicalUpdate and Constitutional proposals
//!    require a council report before voting begins.
//! 3. **Emergency Brake** (5/7): Trigger emergency pause.
//! 4. **No legislative power**: Cannot submit proposals — review only.
//!
//! ## Constraints
//! - 6-month non-renewable terms
//! - Max 1 member per institution
//! - Max 3 vetos per term without proven vulnerability
//! - Abuse triggers removal vote (51% both chambers)

use std::collections::HashMap;

use brrq_crypto::hash::Hash256;
use brrq_types::Address;

use crate::ConsensusError;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Council size: 7 members.
pub const COUNCIL_SIZE: usize = 7;

/// Security veto threshold: 5 of 7 members.
pub const SECURITY_VETO_THRESHOLD: usize = 5;

/// Emergency brake threshold: 5 of 7 members.
pub const EMERGENCY_BRAKE_THRESHOLD: usize = 5;

/// Council term in L2 blocks: ~6 months at 3s/block.
pub const COUNCIL_TERM_BLOCKS: u64 = 2_592_000;

/// Maximum vetos per term without proven vulnerability.
pub const MAX_VETOS_PER_TERM: u8 = 3;

/// Security veto duration: 30 days at 3s/block.
pub const SECURITY_VETO_DURATION: u64 = 864_000;

/// Deadline for security report after veto: 14 days at 3s/block.
pub const SECURITY_REPORT_DEADLINE: u64 = 403_200;

/// Minimum seats for security auditors.
pub const MIN_AUDITOR_SEATS: usize = 3;

/// Minimum seats for core developers.
pub const MIN_DEV_SEATS: usize = 2;

/// Minimum seats for cryptographers.
pub const MIN_CRYPTO_SEATS: usize = 2;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// Role of a council member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CouncilRole {
    /// Security auditor — reviews proposals for vulnerabilities.
    SecurityAuditor,
    /// Core protocol developer — reviews technical correctness.
    CoreDeveloper,
    /// Cryptographer — reviews cryptographic soundness.
    Cryptographer,
}

/// A single council member.
#[derive(Debug, Clone)]
pub struct CouncilMember {
    /// Member's address (identity).
    pub address: Address,
    /// Assigned role.
    pub role: CouncilRole,
    /// Institution/entity identifier (for diversity enforcement).
    pub institution: String,
    /// Block height when the member was seated.
    pub seated_at: u64,
    /// Block height when the term expires.
    pub term_expires_at: u64,
    /// Number of vetos cast this term.
    pub vetos_cast: u8,
    /// Whether this member is currently active.
    pub active: bool,
}

/// A Security Veto on a specific proposal.
#[derive(Debug, Clone)]
pub struct SecurityVeto {
    /// The proposal being vetoed.
    pub proposal_id: Hash256,
    /// Block height when the veto was issued.
    pub issued_at: u64,
    /// Block height when the veto expires.
    pub expires_at: u64,
    /// Members who voted for the veto.
    pub veto_voters: Vec<Address>,
    /// Deadline for the security report.
    pub report_deadline: u64,
    /// Whether the security report has been submitted.
    pub report_submitted: bool,
    /// Whether the veto has been overridden by 90/90 vote.
    pub overridden: bool,
}

/// A mandatory council report on a proposal.
#[derive(Debug, Clone)]
pub struct CouncilReport {
    /// The proposal this report covers.
    pub proposal_id: Hash256,
    /// Summary of findings.
    pub summary: String,
    /// Recommendation: approve, reject, or modify.
    pub recommendation: ReportRecommendation,
    /// Members who signed the report.
    pub signers: Vec<Address>,
    /// Block height when the report was submitted.
    pub submitted_at: u64,
}

/// Council's recommendation on a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportRecommendation {
    /// No security concerns found.
    Approve,
    /// Security concerns found — recommend rejection.
    Reject,
    /// Modifications needed before safe to proceed.
    ModifyAndResubmit,
}

// ═══════════════════════════════════════════════════════════════
// TechnicalCouncil
// ═══════════════════════════════════════════════════════════════

/// Manages the Technical Council lifecycle and powers.
#[derive(Debug, Clone)]
pub struct TechnicalCouncil {
    /// Current council members keyed by address.
    pub members: HashMap<Address, CouncilMember>,
    /// Active security vetos keyed by proposal ID.
    pub active_vetos: HashMap<Hash256, SecurityVeto>,
    /// Submitted reports keyed by proposal ID.
    pub reports: HashMap<Hash256, CouncilReport>,
    /// Current council term number.
    pub term_number: u64,
    /// Historical count of vetos that found real vulnerabilities.
    pub confirmed_vulnerabilities: u64,
    /// Historical count of vetos without confirmed vulnerability.
    pub unconfirmed_vetos: u64,
}

impl Default for TechnicalCouncil {
    fn default() -> Self {
        Self::new()
    }
}

impl TechnicalCouncil {
    /// Create a new, empty council.
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            active_vetos: HashMap::new(),
            reports: HashMap::new(),
            term_number: 0,
            confirmed_vulnerabilities: 0,
            unconfirmed_vetos: 0,
        }
    }

    /// Seat a new council member after election.
    ///
    /// Enforces:
    /// - Council size limit (7 members)
    /// - Role quotas (3 auditors, 2 devs, 2 cryptographers)
    /// - Institutional diversity (max 1 per institution)
    pub fn seat_member(
        &mut self,
        address: Address,
        role: CouncilRole,
        institution: String,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // Size limit
        let active_count = self.active_member_count();
        if active_count >= COUNCIL_SIZE {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "council is full ({}/{} seats occupied)",
                    active_count, COUNCIL_SIZE,
                ),
            });
        }

        // No duplicate addresses
        if self.members.contains_key(&address) && self.members[&address].active {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("address {} is already a council member", address),
            });
        }

        // Role quota check
        let role_count = self.count_role(role);
        let max_for_role = match role {
            CouncilRole::SecurityAuditor => MIN_AUDITOR_SEATS,
            CouncilRole::CoreDeveloper => MIN_DEV_SEATS,
            CouncilRole::Cryptographer => MIN_CRYPTO_SEATS,
        };
        if role_count >= max_for_role {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "role {:?} is full ({}/{} seats)",
                    role, role_count, max_for_role,
                ),
            });
        }

        // Institutional diversity: max 1 per institution
        let inst_lower = institution.to_lowercase();
        for member in self.members.values() {
            if member.active && member.institution.to_lowercase() == inst_lower {
                return Err(ConsensusError::InvalidBlock {
                    reason: format!(
                        "institution '{}' already represented by {}",
                        institution, member.address,
                    ),
                });
            }
        }

        let member = CouncilMember {
            address,
            role,
            institution,
            seated_at: current_height,
            term_expires_at: current_height.saturating_add(COUNCIL_TERM_BLOCKS),
            vetos_cast: 0,
            active: true,
        };

        self.members.insert(address, member);
        Ok(())
    }

    /// Remove a council member (resignation, removal vote, or term expiry).
    pub fn remove_member(&mut self, address: &Address) -> Result<(), ConsensusError> {
        let member = self
            .members
            .get_mut(address)
            .ok_or_else(|| ConsensusError::InvalidBlock {
                reason: format!("council member {} not found", address),
            })?;

        if !member.active {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("council member {} is already inactive", address),
            });
        }

        member.active = false;
        Ok(())
    }

    /// Process block — check for term expirations.
    pub fn process_block(&mut self, current_height: u64) {
        // Expire terms
        for member in self.members.values_mut() {
            if member.active && current_height >= member.term_expires_at {
                member.active = false;
            }
        }

        // Expire vetos where report deadline passed without report
        let expired_vetos: Vec<Hash256> = self
            .active_vetos
            .iter()
            .filter(|(_, veto)| {
                !veto.report_submitted && !veto.overridden && current_height >= veto.report_deadline
            })
            .map(|(id, _)| *id)
            .collect();

        for id in &expired_vetos {
            if let Some(veto) = self.active_vetos.get_mut(id) {
                // Veto lapses if report not submitted by deadline
                veto.overridden = true;
                self.unconfirmed_vetos += 1;
            }
        }
    }

    /// Issue a Security Veto on a proposal.
    ///
    /// Requires 5/7 active members to vote for the veto.
    /// Each member can only contribute one vote to a veto.
    pub fn issue_security_veto(
        &mut self,
        proposal_id: Hash256,
        voting_members: &[Address],
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // No duplicate vetos
        if self.active_vetos.contains_key(&proposal_id) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("security veto already active for proposal {}", proposal_id),
            });
        }

        // Validate all voters are active council members
        let mut valid_voters = Vec::new();
        for addr in voting_members {
            match self.members.get(addr) {
                Some(member) if member.active => {
                    valid_voters.push(*addr);
                }
                _ => {
                    return Err(ConsensusError::InvalidBlock {
                        reason: format!("{} is not an active council member", addr),
                    });
                }
            }
        }

        // Deduplicate
        valid_voters.sort();
        valid_voters.dedup();

        // Threshold check
        if valid_voters.len() < SECURITY_VETO_THRESHOLD {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "security veto requires {}/{} members, got {}",
                    SECURITY_VETO_THRESHOLD,
                    COUNCIL_SIZE,
                    valid_voters.len(),
                ),
            });
        }

        // Check veto abuse limit
        for addr in &valid_voters {
            if let Some(member) = self.members.get(addr)
                && member.vetos_cast >= MAX_VETOS_PER_TERM
            {
                return Err(ConsensusError::InvalidBlock {
                    reason: format!(
                        "member {} has exhausted veto allowance ({}/{} this term)",
                        addr, member.vetos_cast, MAX_VETOS_PER_TERM,
                    ),
                });
            }
        }

        // Increment veto count for participating members
        for addr in &valid_voters {
            if let Some(member) = self.members.get_mut(addr) {
                member.vetos_cast += 1;
            }
        }

        let veto = SecurityVeto {
            proposal_id,
            issued_at: current_height,
            expires_at: current_height.saturating_add(SECURITY_VETO_DURATION),
            veto_voters: valid_voters,
            report_deadline: current_height.saturating_add(SECURITY_REPORT_DEADLINE),
            report_submitted: false,
            overridden: false,
        };

        self.active_vetos.insert(proposal_id, veto);
        Ok(())
    }

    /// Submit a mandatory council report for a proposal.
    ///
    /// For proposals that require a report (TechnicalUpdate, Constitutional,
    /// BridgeUpdate, ConsensusChange), voting cannot begin without this report.
    pub fn submit_report(
        &mut self,
        proposal_id: Hash256,
        summary: String,
        recommendation: ReportRecommendation,
        signers: &[Address],
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // Validate signers are active members and deduplicate
        let mut unique_signers = Vec::new();
        for addr in signers {
            match self.members.get(addr) {
                Some(member) if member.active => {
                    if !unique_signers.contains(addr) {
                        unique_signers.push(*addr);
                    }
                }
                _ => {
                    return Err(ConsensusError::InvalidBlock {
                        reason: format!("{} is not an active council member", addr),
                    });
                }
            }
        }

        // Need at least 4/7 unique signers for a valid report
        if unique_signers.len() < 4 {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "council report requires at least 4 signers, got {}",
                    signers.len(),
                ),
            });
        }

        let report = CouncilReport {
            proposal_id,
            summary,
            recommendation,
            signers: unique_signers,
            submitted_at: current_height,
        };

        self.reports.insert(proposal_id, report);

        // If there's an active veto for this proposal, mark report as submitted
        if let Some(veto) = self.active_vetos.get_mut(&proposal_id) {
            veto.report_submitted = true;
        }

        Ok(())
    }

    /// Override a security veto with 90/90 supermajority.
    ///
    /// Called when both chambers reach 90% approval to override.
    pub fn override_veto(&mut self, proposal_id: &Hash256) -> Result<(), ConsensusError> {
        let veto =
            self.active_vetos
                .get_mut(proposal_id)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("no active veto for proposal {}", proposal_id),
                })?;

        if veto.overridden {
            return Err(ConsensusError::InvalidBlock {
                reason: "veto already overridden".to_string(),
            });
        }

        veto.overridden = true;
        Ok(())
    }

    /// Check if a proposal has a required council report.
    pub fn has_report(&self, proposal_id: &Hash256) -> bool {
        self.reports.contains_key(proposal_id)
    }

    /// Check if a proposal has an active (non-overridden) security veto.
    pub fn has_active_veto(&self, proposal_id: &Hash256) -> bool {
        self.active_vetos
            .get(proposal_id)
            .map(|v| !v.overridden)
            .unwrap_or(false)
    }

    /// Get the number of active members.
    pub fn active_member_count(&self) -> usize {
        self.members.values().filter(|m| m.active).count()
    }

    /// Count active members with a specific role.
    fn count_role(&self, role: CouncilRole) -> usize {
        self.members
            .values()
            .filter(|m| m.active && m.role == role)
            .count()
    }

    /// Check if the council has enough members to function.
    pub fn is_operational(&self) -> bool {
        self.active_member_count() >= SECURITY_VETO_THRESHOLD
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

    fn pid(val: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        Hash256(bytes)
    }

    fn seat_full_council(council: &mut TechnicalCouncil, height: u64) {
        council
            .seat_member(
                addr(1),
                CouncilRole::SecurityAuditor,
                "Firm-A".into(),
                height,
            )
            .unwrap();
        council
            .seat_member(
                addr(2),
                CouncilRole::SecurityAuditor,
                "Firm-B".into(),
                height,
            )
            .unwrap();
        council
            .seat_member(
                addr(3),
                CouncilRole::SecurityAuditor,
                "Firm-C".into(),
                height,
            )
            .unwrap();
        council
            .seat_member(addr(4), CouncilRole::CoreDeveloper, "Dev-A".into(), height)
            .unwrap();
        council
            .seat_member(addr(5), CouncilRole::CoreDeveloper, "Dev-B".into(), height)
            .unwrap();
        council
            .seat_member(
                addr(6),
                CouncilRole::Cryptographer,
                "Crypto-A".into(),
                height,
            )
            .unwrap();
        council
            .seat_member(
                addr(7),
                CouncilRole::Cryptographer,
                "Crypto-B".into(),
                height,
            )
            .unwrap();
    }

    #[test]
    fn seat_full_council_ok() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);
        assert_eq!(council.active_member_count(), 7);
        assert!(council.is_operational());
    }

    #[test]
    fn rejects_8th_member() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);
        let err = council
            .seat_member(addr(8), CouncilRole::SecurityAuditor, "Firm-X".into(), 1000)
            .unwrap_err();
        assert!(err.to_string().contains("full"));
    }

    #[test]
    fn rejects_duplicate_institution() {
        let mut council = TechnicalCouncil::new();
        council
            .seat_member(
                addr(1),
                CouncilRole::SecurityAuditor,
                "SameOrg".into(),
                1000,
            )
            .unwrap();
        let err = council
            .seat_member(
                addr(2),
                CouncilRole::SecurityAuditor,
                "SameOrg".into(),
                1000,
            )
            .unwrap_err();
        assert!(err.to_string().contains("already represented"));
    }

    #[test]
    fn security_veto_requires_threshold() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);

        // Only 4 members — not enough
        let err = council
            .issue_security_veto(pid(1), &[addr(1), addr(2), addr(3), addr(4)], 2000)
            .unwrap_err();
        assert!(err.to_string().contains("requires 5"));
    }

    #[test]
    fn security_veto_with_threshold_ok() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);

        council
            .issue_security_veto(pid(1), &[addr(1), addr(2), addr(3), addr(4), addr(5)], 2000)
            .unwrap();

        assert!(council.has_active_veto(&pid(1)));
    }

    #[test]
    fn no_double_veto_on_same_proposal() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);

        let voters = [addr(1), addr(2), addr(3), addr(4), addr(5)];
        council.issue_security_veto(pid(1), &voters, 2000).unwrap();

        let err = council
            .issue_security_veto(pid(1), &voters, 3000)
            .unwrap_err();
        assert!(err.to_string().contains("already active"));
    }

    #[test]
    fn term_expiry() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);

        assert_eq!(council.active_member_count(), 7);

        // Fast-forward past term
        council.process_block(1000 + COUNCIL_TERM_BLOCKS);

        assert_eq!(council.active_member_count(), 0);
        assert!(!council.is_operational());
    }

    #[test]
    fn veto_report_deadline() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);

        let voters = [addr(1), addr(2), addr(3), addr(4), addr(5)];
        council.issue_security_veto(pid(1), &voters, 2000).unwrap();

        assert!(council.has_active_veto(&pid(1)));

        // Past report deadline without report
        council.process_block(2000 + SECURITY_REPORT_DEADLINE);

        // Veto should lapse (overridden = true)
        assert!(!council.has_active_veto(&pid(1)));
    }

    #[test]
    fn submit_report_ok() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);

        council
            .submit_report(
                pid(1),
                "No vulnerabilities found".into(),
                ReportRecommendation::Approve,
                &[addr(1), addr(2), addr(3), addr(4)],
                2000,
            )
            .unwrap();

        assert!(council.has_report(&pid(1)));
    }

    #[test]
    fn report_needs_minimum_signers() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);

        let err = council
            .submit_report(
                pid(1),
                "Summary".into(),
                ReportRecommendation::Approve,
                &[addr(1), addr(2)], // Only 2 — need 4
                2000,
            )
            .unwrap_err();
        assert!(err.to_string().contains("at least 4"));
    }

    #[test]
    fn override_veto_ok() {
        let mut council = TechnicalCouncil::new();
        seat_full_council(&mut council, 1000);

        let voters = [addr(1), addr(2), addr(3), addr(4), addr(5)];
        council.issue_security_veto(pid(1), &voters, 2000).unwrap();

        assert!(council.has_active_veto(&pid(1)));

        council.override_veto(&pid(1)).unwrap();

        assert!(!council.has_active_veto(&pid(1)));
    }
}
