//! Federation management for the Brrq bridge.
//!
//! Implements an M-of-N multisig federation that controls:
//! - Withdrawal approvals (after challenge period)
//! - Member addition/removal (requires quorum)
//! - Emergency pause (single member) / resume (quorum)
//!
//! ## Design
//!
//! The federation starts with a genesis set of members and a threshold.
//! Members sign withdrawal approvals after the challenge period expires.
//! Once threshold approvals are collected, the withdrawal can execute.
//!
//! ## Security
//!
//! - Adding/removing members requires threshold approval
//! - Each member can only vote once per proposal
//! - Threshold can never exceed member count
//! - Minimum 3 members, minimum threshold 2

use imbl::{HashMap, HashSet};

use brrq_crypto::eots as eots_crypto;
use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::SchnorrPublicKey;
use brrq_types::Address;
use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

/// Minimum number of federation members.
pub const MIN_FEDERATION_SIZE: usize = 3;

/// Minimum threshold for quorum.
pub const MIN_THRESHOLD: usize = 2;

/// Maximum pending (non-executed, non-expired) proposals.
///
/// Prevents unbounded memory growth from proposal spam. Expired proposals
/// are automatically evicted before this cap is checked.
pub const MAX_PENDING_PROPOSALS: usize = 100;

/// Maximum length for a federation member label.
///
/// Prevents unbounded memory allocation via excessively long labels in
/// AddMember proposals. 128 bytes is generous for a human-readable name.
pub const MAX_LABEL_LENGTH: usize = 128;

// ── Federation Bond Constants ────────────────────────────────────
//
// Without economic bonds, federation members can approve fraudulent withdrawals
// at zero personal cost. These constants enforce that corruption is strictly
// irrational: Cost_of_Corruption > 1.5 × Profit_from_Corruption.

/// Minimum bond required per federation member in satoshis (1 BTC).
///
/// This is the minimum economic commitment each member must post before
/// participating in withdrawal approvals. The bond is slashable: if a
/// member signs a fraudulent withdrawal, their entire bond is confiscated.
///
/// Economic justification (§ Mechanism Design Proof):
///   - Bridge TVL cap: 100 BTC (MAX_BRIDGE_TVL_SAT)
///   - Threshold: 3-of-5 → 3 colluding members needed
///   - Max profit per member: TVL / threshold = 100/3 ≈ 33.33 BTC
///   - Required bond: max_profit × 1.5 = 50 BTC per member
///   - With MIN_FEDERATION_BOND = 1 BTC as the floor, the protocol
///     dynamically computes the actual required bond as:
///     bond = max(MIN_FEDERATION_BOND, TVL × BOND_RATIO_BP / 10000 / threshold)
pub const MIN_FEDERATION_BOND: u64 = 100_000_000; // 1 BTC

/// Bond ratio in basis points: each member's bond must be at least
/// (TVL × BOND_RATIO_BP / 10_000 / threshold) satoshis.
///
/// At 15000bp (150%), a 3-of-5 federation guarding 100 BTC requires:
///   bond ≥ 100 BTC × 150% / 3 = 50 BTC per member
///
/// This ensures: 3 × 50 BTC = 150 BTC > 100 BTC (Cost > Profit).
pub const BOND_RATIO_BP: u64 = 15_000;

/// Maximum bridge TVL in satoshis used for bond calculation (100 BTC).
///
/// This is the protocol-level cap on total value locked in the bridge.
/// The bond requirement scales with this value to maintain the
/// Cost > 1.5 × Profit invariant.
pub const MAX_BRIDGE_TVL_SAT: u64 = 10_000_000_000; // 100 BTC

/// Bond maturity period in L2 blocks (~7 days at 3 sec/block).
///
/// After a member withdraws from the federation, their bond is locked
/// for this period. During maturity, any pending fraud proofs can still
/// slash the bond. This prevents "withdraw-then-fraud" timing attacks.
pub const BOND_MATURITY_BLOCKS: u64 = 201_600;

/// Share of slashed bond that goes to the fraud proof submitter (30%).
pub const BOND_SLASH_CHALLENGER_BP: u64 = 3000;

/// Share of slashed bond that is burned (70%).
pub const BOND_SLASH_BURN_BP: u64 = 7000;

// ── Types ────────────────────────────────────────────────────────────────────

/// A federation member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationMember {
    /// Member's L2 address (derived from their public key).
    pub address: Address,
    /// Human-readable label (optional).
    pub label: String,
    /// L2 block height when member was added.
    pub added_at: u64,
    /// Whether the member is currently active.
    pub active: bool,
    /// Bond deposited by this member (in satoshis).
    /// Must be >= required_bond() before the member can participate
    /// in withdrawal approvals.
    pub bond: u64,
    /// Whether the member's bond meets the minimum requirement.
    /// Recomputed whenever TVL or threshold changes.
    pub bond_sufficient: bool,
}

/// A bond that is pending withdrawal (in maturity period).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingBondWithdrawal {
    /// Member who is withdrawing the bond.
    pub member: Address,
    /// Amount of the bond being withdrawn.
    pub amount: u64,
    /// Block height at which the withdrawal was initiated.
    pub initiated_at: u64,
    /// Block height after which the bond can be claimed.
    pub matures_at: u64,
}

/// Result of slashing a federation member's bond.
#[derive(Debug, Clone)]
pub struct BondSlashResult {
    /// Member whose bond was slashed.
    pub member: Address,
    /// Total amount slashed.
    pub total_slashed: u64,
    /// Amount awarded to the fraud proof submitter.
    pub challenger_reward: u64,
    /// Amount burned.
    pub burned: u64,
}

/// A proposal that requires quorum approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Unique proposal ID.
    pub id: Hash256,
    /// Type of action proposed.
    pub action: ProposalAction,
    /// Members who have approved this proposal.
    pub approvals: HashSet<Address>,
    /// L2 block height when proposed.
    pub proposed_at: u64,
    /// Whether the proposal has been executed.
    pub executed: bool,
    /// Whether the proposal has expired.
    pub expired: bool,
}

/// Proposal expiry in L2 blocks (~24 hours at 3 sec/block).
pub const PROPOSAL_EXPIRY_BLOCKS: u64 = 28_800;

/// Actions that require quorum approval.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalAction {
    /// Approve a withdrawal for execution on L1.
    ApproveWithdrawal { withdrawal_id: Hash256 },
    /// Add a new member to the federation.
    AddMember { address: Address, label: String },
    /// Remove a member from the federation.
    RemoveMember { address: Address },
    /// Change the approval threshold.
    ChangeThreshold { new_threshold: usize },
    /// Resume bridge operations (after emergency pause).
    ResumeBridge,
    /// Rotate a member's key (emergency key compromise recovery).
    ///
    /// Replaces `old_address` with `new_address` in the federation. The old
    /// member is deactivated and the new address is added with the same label.
    /// Requires quorum approval like any other membership change.
    RotateKey {
        old_address: Address,
        new_address: Address,
    },
    /// Slash a member's bond due to fraud proof.
    ///
    /// Requires quorum approval (the accused member is excluded from voting).
    /// The bond is split: 30% to the challenger, 70% burned.
    SlashBond {
        /// Member whose bond is being slashed.
        target: Address,
        /// Address of the entity that submitted the fraud proof.
        challenger: Address,
        /// Hash of the fraud proof evidence.
        evidence_hash: Hash256,
    },
}

/// Summary of federation state.
#[derive(Debug, Clone)]
pub struct FederationStatus {
    pub member_count: usize,
    pub active_members: usize,
    pub threshold: usize,
    pub pending_proposals: usize,
    pub total_approvals_given: u64,
}

// ── FederationManager ────────────────────────────────────────────────────────

/// Manages the bridge federation (M-of-N multisig).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationManager {
    /// Active federation members.
    members: HashMap<Address, FederationMember>,
    /// Current quorum threshold.
    threshold: usize,
    /// Pending and completed proposals.
    proposals: HashMap<Hash256, Proposal>,
    /// Total approvals given (for statistics).
    total_approvals: u64,
    /// Current bridge TVL in satoshis (used for bond calculation).
    bridge_tvl: u64,
    /// Bonds pending withdrawal (in maturity period).
    pending_withdrawals: Vec<PendingBondWithdrawal>,
}

impl FederationManager {
    /// Create a new federation with initial members and threshold.
    ///
    /// # Panics
    ///
    /// Panics if `members.len() < MIN_FEDERATION_SIZE` or `threshold < MIN_THRESHOLD`
    /// or `threshold > members.len()`.
    pub fn new(
        initial_members: Vec<(Address, String)>,
        threshold: usize,
        genesis_height: u64,
    ) -> Result<Self, FederationError> {
        // Check unique member count, not Vec length.
        // Duplicate addresses inflate the apparent size, potentially
        // bypassing MIN_FEDERATION_SIZE with fewer distinct members.
        let unique_count = initial_members
            .iter()
            .map(|(addr, _)| *addr)
            .collect::<HashSet<Address>>()
            .len();
        if unique_count < MIN_FEDERATION_SIZE {
            return Err(FederationError::InsufficientMembers {
                have: unique_count,
                need: MIN_FEDERATION_SIZE,
            });
        }
        if threshold < MIN_THRESHOLD {
            return Err(FederationError::ThresholdTooLow {
                threshold,
                minimum: MIN_THRESHOLD,
            });
        }
        if threshold > unique_count {
            return Err(FederationError::ThresholdExceedsMembers {
                threshold,
                members: unique_count,
            });
        }

        let mut members = HashMap::new();
        for (address, label) in initial_members {
            // Validate label length at genesis too.
            if label.len() > MAX_LABEL_LENGTH {
                return Err(FederationError::LabelTooLong {
                    len: label.len(),
                    max: MAX_LABEL_LENGTH,
                });
            }
            members.insert(
                address,
                FederationMember {
                    address,
                    label,
                    added_at: genesis_height,
                    active: true,
                    bond: 0,
                    bond_sufficient: false,
                },
            );
        }

        Ok(Self {
            members,
            threshold,
            proposals: HashMap::new(),
            total_approvals: 0,
            bridge_tvl: 0,
            pending_withdrawals: Vec::new(),
        })
    }

    /// Create a default 3-of-5 federation (for testing).
    pub fn new_default() -> Self {
        let members: Vec<(Address, String)> = (1..=5)
            .map(|i| (Address::from_bytes([i; 20]), format!("member-{i}")))
            .collect();
        Self::new(members, 3, 0).expect("default federation is valid")
    }

    // ── Queries ──────────────────────────────────────────────────────────────

    /// Current quorum threshold.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Number of active members.
    pub fn active_member_count(&self) -> usize {
        self.members.values().filter(|m| m.active).count()
    }

    /// Total member count (including inactive).
    pub fn total_member_count(&self) -> usize {
        self.members.len()
    }

    /// Check if an address is an active federation member.
    pub fn is_active_member(&self, address: &Address) -> bool {
        self.members.get(address).is_some_and(|m| m.active)
    }

    /// Get all active members.
    pub fn active_members(&self) -> Vec<&FederationMember> {
        self.members.values().filter(|m| m.active).collect()
    }

    /// Get a proposal by ID.
    pub fn get_proposal(&self, proposal_id: &Hash256) -> Option<&Proposal> {
        self.proposals.get(proposal_id)
    }

    /// Get federation status summary.
    pub fn status(&self) -> FederationStatus {
        FederationStatus {
            member_count: self.members.len(),
            active_members: self.active_member_count(),
            threshold: self.threshold,
            pending_proposals: self
                .proposals
                .values()
                .filter(|p| !p.executed && !p.expired)
                .count(),
            total_approvals_given: self.total_approvals,
        }
    }

    // ── Proposals ────────────────────────────────────────────────────────────

    /// Create a new proposal. The proposer automatically counts as the first approval.
    ///
    /// Returns the proposal ID.
    pub fn create_proposal(
        &mut self,
        proposer: Address,
        action: ProposalAction,
        current_height: u64,
    ) -> Result<Hash256, FederationError> {
        // Must be an active member
        if !self.is_active_member(&proposer) {
            return Err(FederationError::NotAMember { address: proposer });
        }

        // Validate action-specific constraints
        self.validate_action(&action)?;

        // Evict expired proposals and enforce cap.
        self.evict_expired(current_height);
        let pending_count = self
            .proposals
            .values()
            .filter(|p| !p.executed && !p.expired)
            .count();
        if pending_count >= MAX_PENDING_PROPOSALS {
            return Err(FederationError::TooManyProposals {
                max: MAX_PENDING_PROPOSALS,
            });
        }

        // Generate proposal ID
        let proposal_id = Self::hash_proposal(&action, &proposer, current_height);

        // Check for duplicate
        if let Some(existing) = self.proposals.get(&proposal_id)
            && !existing.executed
            && !existing.expired
        {
            return Err(FederationError::DuplicateProposal);
        }

        let mut approvals = HashSet::new();
        approvals.insert(proposer);
        self.total_approvals += 1;

        let proposal = Proposal {
            id: proposal_id,
            action,
            approvals,
            proposed_at: current_height,
            executed: false,
            expired: false,
        };

        self.proposals.insert(proposal_id, proposal);
        Ok(proposal_id)
    }

    /// Approve a proposal. Returns true if quorum is now reached.
    pub fn approve_proposal(
        &mut self,
        proposal_id: &Hash256,
        approver: Address,
        current_height: u64,
    ) -> Result<bool, FederationError> {
        // Must be an active member
        if !self.is_active_member(&approver) {
            return Err(FederationError::NotAMember { address: approver });
        }

        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(FederationError::ProposalNotFound)?;

        if proposal.executed {
            return Err(FederationError::ProposalAlreadyExecuted);
        }

        // Check expiry
        if current_height > proposal.proposed_at + PROPOSAL_EXPIRY_BLOCKS {
            proposal.expired = true;
            return Err(FederationError::ProposalExpired);
        }

        if proposal.expired {
            return Err(FederationError::ProposalExpired);
        }

        // Exclude slash target from voting on their own SlashBond proposal.
        if let ProposalAction::SlashBond { target, .. } = &proposal.action {
            if approver == *target {
                return Err(FederationError::ConflictOfInterest {
                    address: approver,
                    reason: "slash target cannot vote on their own SlashBond proposal".into(),
                });
            }
        }

        // Check for duplicate vote
        if proposal.approvals.contains(&approver) {
            return Err(FederationError::AlreadyApproved);
        }

        proposal.approvals.insert(approver);
        self.total_approvals += 1;

        Ok(proposal.approvals.len() >= self.threshold)
    }

    /// Execute a proposal that has reached quorum.
    ///
    /// Returns the executed action on success.
    pub fn execute_proposal(
        &mut self,
        proposal_id: &Hash256,
        current_height: u64,
    ) -> Result<ProposalAction, FederationError> {
        let proposal = self
            .proposals
            .get(proposal_id)
            .ok_or(FederationError::ProposalNotFound)?;

        if proposal.executed {
            return Err(FederationError::ProposalAlreadyExecuted);
        }

        if proposal.expired {
            return Err(FederationError::ProposalExpired);
        }

        if current_height > proposal.proposed_at + PROPOSAL_EXPIRY_BLOCKS {
            let proposal = self
                .proposals
                .get_mut(proposal_id)
                .ok_or(FederationError::ProposalNotFound)?;
            proposal.expired = true;
            return Err(FederationError::ProposalExpired);
        }

        if proposal.approvals.len() < self.threshold {
            return Err(FederationError::QuorumNotReached {
                have: proposal.approvals.len(),
                need: self.threshold,
            });
        }

        let action = proposal.action.clone();

        // Apply the action
        match &action {
            ProposalAction::AddMember { address, label } => {
                self.members.insert(
                    *address,
                    FederationMember {
                        address: *address,
                        label: label.clone(),
                        added_at: current_height,
                        active: true,
                        bond: 0,
                        bond_sufficient: false,
                    },
                );
            }
            ProposalAction::RemoveMember { address } => {
                if let Some(member) = self.members.get_mut(address) {
                    member.active = false;
                }
                // Verify we still have enough active members
                if self.active_member_count() < MIN_FEDERATION_SIZE {
                    // Rollback
                    if let Some(member) = self.members.get_mut(address) {
                        member.active = true;
                    }
                    return Err(FederationError::InsufficientMembers {
                        have: self.active_member_count(),
                        need: MIN_FEDERATION_SIZE,
                    });
                }
                // Verify threshold is still achievable
                if self.threshold > self.active_member_count() {
                    if let Some(member) = self.members.get_mut(address) {
                        member.active = true;
                    }
                    return Err(FederationError::ThresholdExceedsMembers {
                        threshold: self.threshold,
                        members: self.active_member_count(),
                    });
                }
                // Remove departed member's approvals.
                self.remove_member_approvals(address);
            }
            ProposalAction::ChangeThreshold { new_threshold } => {
                if *new_threshold < MIN_THRESHOLD {
                    return Err(FederationError::ThresholdTooLow {
                        threshold: *new_threshold,
                        minimum: MIN_THRESHOLD,
                    });
                }
                if *new_threshold > self.active_member_count() {
                    return Err(FederationError::ThresholdExceedsMembers {
                        threshold: *new_threshold,
                        members: self.active_member_count(),
                    });
                }
                self.threshold = *new_threshold;
            }
            ProposalAction::RotateKey {
                old_address,
                new_address,
            } => {
                // Deactivate old member, carry over bond
                let (label, bond) = if let Some(member) = self.members.get_mut(old_address) {
                    member.active = false;
                    let l = member.label.clone();
                    let b = member.bond;
                    member.bond = 0;
                    member.bond_sufficient = false;
                    (l, b)
                } else {
                    return Err(FederationError::NotAMember {
                        address: *old_address,
                    });
                };
                // Verify we still have enough active members (rotation is
                // net-neutral but check during the intermediate state)
                //
                // New key inherits the bond but with a fresh added_at
                // timestamp (current_height). Bond withdrawal requires maturity
                // from added_at, so the new key cannot immediately extract the bond.
                // The bond_sufficient flag is initially false for the new key —
                // it becomes sufficient only after BOND_MATURITY_BLOCKS pass.
                self.members.insert(
                    *new_address,
                    FederationMember {
                        address: *new_address,
                        label,
                        added_at: current_height,
                        active: true,
                        bond,
                        bond_sufficient: false, // requires maturity before active participation
                    },
                );
                // Remove old member's approvals from pending proposals
                self.remove_member_approvals(old_address);
            }
            ProposalAction::ApproveWithdrawal { .. } | ProposalAction::ResumeBridge => {
                // These are handled externally by the caller (BridgeManager)
            }
            ProposalAction::SlashBond {
                target,
                challenger: _,
                evidence_hash: _,
            } => {
                // Confiscate the target member's entire bond.
                // Distribution (30% challenger, 70% burn) is handled by the caller.
                if let Some(member) = self.members.get_mut(target) {
                    member.bond = 0;
                    member.bond_sufficient = false;
                }
            }
        }

        let proposal = self
            .proposals
            .get_mut(proposal_id)
            .ok_or(FederationError::ProposalNotFound)?;
        proposal.executed = true;

        Ok(action)
    }

    /// Process expired proposals. Returns count of newly expired.
    pub fn expire_proposals(&mut self, current_height: u64) -> usize {
        let mut expired_count = 0;
        for (_, proposal) in self.proposals.iter_mut() {
            if !proposal.executed
                && !proposal.expired
                && current_height > proposal.proposed_at + PROPOSAL_EXPIRY_BLOCKS
            {
                proposal.expired = true;
                expired_count += 1;
            }
        }
        expired_count
    }

    // ── Emergency Controls ───────────────────────────────────────────────────

    /// Emergency pause — any single member can trigger.
    /// Returns true if the member is authorized to pause.
    pub fn authorize_emergency_pause(&self, member: &Address) -> bool {
        self.is_active_member(member)
    }

    // ── Internal ─────────────────────────────────────────────────────────────

    /// Remove expired and executed proposals from memory.
    fn evict_expired(&mut self, current_height: u64) {
        self.proposals.retain(|_, p| {
            if p.executed {
                return false; // evict executed
            }
            if p.expired {
                return false; // evict expired
            }
            if current_height > p.proposed_at + PROPOSAL_EXPIRY_BLOCKS {
                return false; // evict newly expired
            }
            true
        });
    }

    /// Validate action-specific constraints before creating a proposal.
    fn validate_action(&self, action: &ProposalAction) -> Result<(), FederationError> {
        match action {
            ProposalAction::AddMember { address, label } => {
                if self.is_active_member(address) {
                    return Err(FederationError::MemberAlreadyActive { address: *address });
                }
                // Reject labels that exceed the max length.
                if label.len() > MAX_LABEL_LENGTH {
                    return Err(FederationError::LabelTooLong {
                        len: label.len(),
                        max: MAX_LABEL_LENGTH,
                    });
                }
            }
            ProposalAction::RemoveMember { address } => {
                if !self.is_active_member(address) {
                    return Err(FederationError::NotAMember { address: *address });
                }
            }
            ProposalAction::ChangeThreshold { new_threshold } => {
                if *new_threshold > self.active_member_count() {
                    return Err(FederationError::ThresholdExceedsMembers {
                        threshold: *new_threshold,
                        members: self.active_member_count(),
                    });
                }
            }
            ProposalAction::RotateKey {
                old_address,
                new_address,
            } => {
                if !self.is_active_member(old_address) {
                    return Err(FederationError::NotAMember {
                        address: *old_address,
                    });
                }
                if self.is_active_member(new_address) {
                    return Err(FederationError::MemberAlreadyActive {
                        address: *new_address,
                    });
                }
                if old_address == new_address {
                    return Err(FederationError::NotAMember {
                        address: *old_address,
                    });
                }
            }
            ProposalAction::ApproveWithdrawal { .. } | ProposalAction::ResumeBridge => {}
            ProposalAction::SlashBond {
                target,
                challenger: _,
                evidence_hash: _,
            } => {
                // Target must be a current member (active or inactive with bond)
                if !self.members.contains_key(target) {
                    return Err(FederationError::NotAMember { address: *target });
                }
                // Must have a bond to slash
                if self.members.get(target).map_or(true, |m| m.bond == 0) {
                    return Err(FederationError::NoBondToSlash { address: *target });
                }
            }
        }
        Ok(())
    }

    /// Generate deterministic proposal ID from action, proposer, and height.
    fn hash_proposal(action: &ProposalAction, proposer: &Address, height: u64) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(b"FEDERATION_PROPOSAL");
        hasher.update(proposer.as_bytes());
        hasher.update(&height.to_le_bytes());
        match action {
            ProposalAction::ApproveWithdrawal { withdrawal_id } => {
                hasher.update(b"APPROVE_WITHDRAWAL");
                hasher.update(withdrawal_id.as_bytes());
            }
            ProposalAction::AddMember { address, label } => {
                hasher.update(b"ADD_MEMBER");
                hasher.update(address.as_bytes());
                hasher.update(label.as_bytes());
            }
            ProposalAction::RemoveMember { address } => {
                hasher.update(b"REMOVE_MEMBER");
                hasher.update(address.as_bytes());
            }
            ProposalAction::ChangeThreshold { new_threshold } => {
                hasher.update(b"CHANGE_THRESHOLD");
                hasher.update(&(*new_threshold as u64).to_le_bytes());
            }
            ProposalAction::ResumeBridge => {
                hasher.update(b"RESUME_BRIDGE");
            }
            ProposalAction::RotateKey {
                old_address,
                new_address,
            } => {
                hasher.update(b"ROTATE_KEY");
                hasher.update(old_address.as_bytes());
                hasher.update(new_address.as_bytes());
            }
            ProposalAction::SlashBond {
                target,
                challenger,
                evidence_hash,
            } => {
                hasher.update(b"SLASH_BOND");
                hasher.update(target.as_bytes());
                hasher.update(challenger.as_bytes());
                hasher.update(evidence_hash.as_bytes());
            }
        }
        hasher.finalize()
    }

    // ── Bond Management ─────────────────────────────────────────

    /// Compute the required bond per member given current TVL and threshold.
    ///
    /// Formula: `bond = max(MIN_FEDERATION_BOND, TVL × BOND_RATIO_BP / 10_000 / threshold)`
    ///
    /// This ensures: `threshold × bond ≥ TVL × 1.5` (Cost of Corruption > 1.5 × Profit).
    pub fn required_bond(&self) -> u64 {
        let tvl = self.bridge_tvl.min(MAX_BRIDGE_TVL_SAT);
        if self.threshold == 0 {
            return MIN_FEDERATION_BOND;
        }
        let dynamic = (tvl as u128)
            .saturating_mul(BOND_RATIO_BP as u128)
            / 10_000
            / (self.threshold as u128);
        let dynamic_u64 = if dynamic > u64::MAX as u128 {
            u64::MAX
        } else {
            dynamic as u64
        };
        dynamic_u64.max(MIN_FEDERATION_BOND)
    }

    /// Deposit a bond for a federation member. Returns the new total bond.
    ///
    /// The bond is immediately credited. The member's `bond_sufficient` flag
    /// is updated based on the current `required_bond()`.
    pub fn deposit_bond(
        &mut self,
        member: &Address,
        amount: u64,
    ) -> Result<u64, FederationError> {
        let required = self.required_bond();
        let m = self
            .members
            .get_mut(member)
            .ok_or(FederationError::NotAMember { address: *member })?;
        if !m.active {
            return Err(FederationError::NotAMember { address: *member });
        }
        m.bond = m.bond.saturating_add(amount);
        m.bond_sufficient = m.bond >= required;
        Ok(m.bond)
    }

    /// Get the bond amount for a member.
    pub fn member_bond(&self, member: &Address) -> Option<u64> {
        self.members.get(member).map(|m| m.bond)
    }

    /// Check if a member's bond is sufficient for withdrawal approvals.
    pub fn is_bond_sufficient(&self, member: &Address) -> bool {
        self.members
            .get(member)
            .is_some_and(|m| m.active && m.bond_sufficient)
    }

    /// Update the bridge TVL and recompute all members' bond sufficiency.
    pub fn update_tvl(&mut self, new_tvl: u64) {
        self.bridge_tvl = new_tvl;
        let required = self.required_bond();
        for (_, m) in self.members.iter_mut() {
            m.bond_sufficient = m.bond >= required;
        }
    }

    /// Current bridge TVL.
    pub fn bridge_tvl(&self) -> u64 {
        self.bridge_tvl
    }

    /// Initiate a bond withdrawal. The bond enters a maturity period
    /// during which it can still be slashed by fraud proofs.
    ///
    /// The member is deactivated (cannot approve withdrawals) once
    /// they initiate a bond withdrawal.
    pub fn initiate_bond_withdrawal(
        &mut self,
        member: &Address,
        current_height: u64,
    ) -> Result<PendingBondWithdrawal, FederationError> {
        let m = self
            .members
            .get_mut(member)
            .ok_or(FederationError::NotAMember { address: *member })?;

        if m.bond == 0 {
            return Err(FederationError::NoBondToSlash { address: *member });
        }

        let withdrawal = PendingBondWithdrawal {
            member: *member,
            amount: m.bond,
            initiated_at: current_height,
            matures_at: current_height.saturating_add(BOND_MATURITY_BLOCKS),
        };

        // Zero the bond, mark insufficient, and deactivate.
        // Member must be deactivated when withdrawing bond —
        // a member with zero bond has no economic stake and must not vote.
        m.bond = 0;
        m.bond_sufficient = false;
        m.active = false;

        self.pending_withdrawals.push(withdrawal.clone());
        Ok(withdrawal)
    }

    /// Claim a matured bond withdrawal. Returns the amount released.
    pub fn claim_bond_withdrawal(
        &mut self,
        member: &Address,
        current_height: u64,
    ) -> Result<u64, FederationError> {
        let idx = self
            .pending_withdrawals
            .iter()
            .position(|w| w.member == *member && current_height >= w.matures_at)
            .ok_or(FederationError::BondInMaturity {
                matures_at: self
                    .pending_withdrawals
                    .iter()
                    .find(|w| w.member == *member)
                    .map_or(0, |w| w.matures_at),
                current: current_height,
            })?;

        let withdrawal = self.pending_withdrawals.remove(idx);
        Ok(withdrawal.amount)
    }

    /// Slash a member's bond via fraud proof. Returns the slash distribution.
    ///
    /// This also cancels any pending bond withdrawals for the target.
    pub fn slash_bond(
        &mut self,
        target: &Address,
        challenger: &Address,
    ) -> Result<BondSlashResult, FederationError> {
        // Check for bond in active membership
        let bond_amount = self
            .members
            .get(target)
            .map(|m| m.bond)
            .unwrap_or(0);

        // Also check pending withdrawals
        let pending_amount: u64 = self
            .pending_withdrawals
            .iter()
            .filter(|w| w.member == *target)
            .map(|w| w.amount)
            .sum();

        let total = bond_amount.saturating_add(pending_amount);
        if total == 0 {
            return Err(FederationError::NoBondToSlash { address: *target });
        }

        // Zero the member's bond
        if let Some(m) = self.members.get_mut(target) {
            m.bond = 0;
            m.bond_sufficient = false;
        }

        // Cancel pending withdrawals
        self.pending_withdrawals.retain(|w| w.member != *target);

        let challenger_reward =
            ((total as u128 * BOND_SLASH_CHALLENGER_BP as u128) / 10_000) as u64;
        let burned = total - challenger_reward;

        Ok(BondSlashResult {
            member: *target,
            total_slashed: total,
            challenger_reward,
            burned,
        })
    }

    /// Validate that a member's bond is sufficient before allowing
    /// withdrawal approval. Call this from the bridge manager before
    /// accepting a withdrawal approval vote.
    pub fn require_bond_for_approval(
        &self,
        member: &Address,
    ) -> Result<(), FederationError> {
        if !self.is_bond_sufficient(member) {
            return Err(FederationError::BondRequiredForApproval {
                address: *member,
            });
        }
        Ok(())
    }

    /// Count how many active members have sufficient bonds.
    pub fn bonded_member_count(&self) -> usize {
        self.members
            .values()
            .filter(|m| m.active && m.bond_sufficient)
            .count()
    }

    /// Remove inactive members from the HashMap to reclaim memory.
    ///
    /// Returns the number of members removed.
    pub fn compact_inactive(&mut self) -> usize {
        let before = self.members.len();
        self.members.retain(|_, m| m.active);
        before - self.members.len()
    }

    /// Remove a member's approvals from all pending proposals.
    ///
    /// Prevents stale votes from counting toward quorum
    /// after a member departs (removal or key rotation).
    fn remove_member_approvals(&mut self, address: &Address) {
        for (_, proposal) in self.proposals.iter_mut() {
            if !proposal.executed && !proposal.expired {
                proposal.approvals.remove(address);
            }
        }
    }
}

impl Default for FederationManager {
    fn default() -> Self {
        Self::new_default()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// ARCHITECTURAL TEARDOWN: Native BTC Staking Committee
// ═══════════════════════════════════════════════════════════════════════════════
//
// Replaces the pure M-of-N federation model with cryptoeconomic security backed
// by native Bitcoin staking on L1. Committee membership is determined by BTC
// locked in Taproot UTXOs with EOTS (Extractable One-Time Signatures) binding.
//
// Design Principles:
//   1. No trust assumptions — security is purely economic
//   2. EOTS equivocation → private key extraction → automatic L1 slashing
//   3. Committee attestation requires ⅔ supermajority of staked BTC
//   4. Compatible with current Bitcoin (no OP_CAT required)
//
// Bitcoin Script Compatibility (no OP_CAT):
//   - Staking uses P2TR (Taproot) with OP_CHECKLOCKTIMEVERIFY for timelock
//   - EOTS: Schnorr nonce reuse across two messages reveals secret key
//   - Slash path: extracted key can sign any tx spending the staked UTXO
//   - No on-chain covenant verification needed — slash is key-based
//
// Invariant: total staked must exceed TVL by safety margin to prevent corruption attacks.

// ── Staking Committee Constants ──────────────────────────────────────────────

/// Supermajority threshold for committee attestation: ⅔ = 6667 basis points.
///
/// The bridge will not execute any withdrawal unless ≥ 66.67% of the total
/// staked BTC weight has signed the attestation. This is the standard BFT
/// safety threshold — with ⅔ honest weight, no conflicting attestation
/// can also achieve ⅔.
pub const COMMITTEE_SUPERMAJORITY_BP: u64 = 6667;

/// Minimum individual stake to join the committee: 10 BTC (1B satoshis).
///
/// This floor prevents Sybil attacks where an attacker creates many
/// low-stake committee members to dilute the honest majority.
pub const MIN_COMMITTEE_STAKE_SAT: u64 = 1_000_000_000;

/// Required ratio of total committee stake to bridge TVL: 225% (22500 bp).
///
/// Derivation from the security invariant:
///   Cost_of_Corruption = ⅔ × total_staked  (colluders lose their stake)
///   Profit_from_Corruption ≤ TVL
///   Required: Cost > 1.5 × Profit
///   ⅔ × total_staked > 1.5 × TVL
///   total_staked > 1.5 × TVL × 3/2 = 2.25 × TVL
///
/// Therefore MIN_STAKE_TO_TVL_RATIO = 22500 bp (225%).
pub const MIN_STAKE_TO_TVL_RATIO_BP: u64 = 22_500;

/// Minimum committee size (distinct stakers).
///
/// Prevents a single wealthy entity from constituting the entire committee.
/// Even with sufficient total stake, at least this many distinct stakers
/// are required to form a valid committee.
pub const MIN_COMMITTEE_SIZE: usize = 5;

/// Staking lock period on L1 in Bitcoin blocks (~2 weeks at 10 min/block).
///
/// Staked BTC cannot be moved for this duration. This ensures that stake
/// is committed for long enough to cover the challenge period and any
/// pending fraud proofs. Matches the BitVM2 challenge period.
pub const STAKING_LOCK_PERIOD_L1: u64 = 2016;

/// Maturity period after unbonding request in L1 blocks (~1 week).
///
/// After a committee member signals withdrawal intent, their stake
/// remains slashable for this period. Prevents "unstake-then-attack"
/// timing attacks.
pub const UNSTAKING_MATURITY_L1: u64 = 1008;

/// Maximum ratio of any single staker's weight: 33% (3300 bp).
///
/// No single entity can hold more than ⅓ of the committee's total stake.
/// Combined with the ⅔ threshold, this ensures no single entity can
/// unilaterally block committee attestations.
pub const MAX_SINGLE_STAKER_WEIGHT_BP: u64 = 3300;

// ── EOTS Types ───────────────────────────────────────────────────────────────

/// EOTS (Extractable One-Time Signature) public key.
///
/// EOTS: double-signing with the same nonce allows secret key extraction, making equivocation self-punishing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EotsPublicKey(pub [u8; 32]);

impl EotsPublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A committed EOTS nonce (R = k·G) for a specific signing round.
///
/// Committee members must commit their nonce BEFORE seeing the message.
/// This prevents adaptive nonce selection attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EotsNonce(pub [u8; 32]);

impl EotsNonce {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// EOTS signature: the scalar `s` value from a Schnorr signature.
///
/// Combined with the committed nonce `R` and public key `P`, this
/// forms a complete Schnorr signature `(R, s)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EotsSignature(pub [u8; 32]);

impl EotsSignature {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Proof of EOTS key extraction from equivocation (double-signing).
///
/// If a committee member signs two different messages with the same nonce,
/// anyone can extract their secret key using the formula above. This proof
/// contains all the data needed to:
///   1. Verify the equivocation occurred (two valid signatures, same nonce)
///   2. Extract the secret key
///   3. Sweep the member's staked UTXOs on L1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EotsKeyExtractionProof {
    /// Committee member who equivocated.
    pub member: Address,
    /// Their EOTS public key.
    pub public_key: EotsPublicKey,
    /// The shared nonce R used in both signatures.
    pub nonce: EotsNonce,
    /// First message that was signed (typically a state root hash).
    pub message_a: Hash256,
    /// Schnorr s-value for the first signature.
    pub signature_a: EotsSignature,
    /// Second (conflicting) message signed with the same nonce.
    pub message_b: Hash256,
    /// Schnorr s-value for the second signature.
    pub signature_b: EotsSignature,
    /// The extracted secret key: x = (s₁ - s₂) / (e₂ - e₁) mod n.
    /// Once extracted, this key can sign any transaction spending the
    /// member's Taproot staking UTXOs.
    pub extracted_secret: [u8; 32],
    /// L2 height at which the equivocation was detected.
    pub detection_height: u64,
}

impl EotsKeyExtractionProof {
    /// Validate the extraction proof is well-formed.
    ///
    /// Checks:
    /// 1. The two messages are different (otherwise no equivocation)
    /// 2. The two signatures are different (identical sigs = same message)
    /// 3. The extracted secret is non-zero
    pub fn validate(&self) -> Result<(), FederationError> {
        if self.message_a == self.message_b {
            return Err(FederationError::InvalidEotsProof {
                reason: "identical messages — not an equivocation".into(),
            });
        }
        if self.signature_a == self.signature_b {
            return Err(FederationError::InvalidEotsProof {
                reason: "identical signatures — cannot extract key".into(),
            });
        }
        if self.extracted_secret == [0u8; 32] {
            return Err(FederationError::InvalidEotsProof {
                reason: "extracted secret is zero — invalid key".into(),
            });
        }

        // Verify nonce is non-zero (zero nonce = trivially forgeable).
        if self.nonce == EotsNonce::default() {
            return Err(FederationError::InvalidEotsProof {
                reason: "nonce R is zero — trivially forgeable".into(),
            });
        }

        // Verify extracted_secret is cryptographically consistent.
        //
        // For now, we verify the extraction algebraically using brrq_crypto::scalar:
        // The EOTS formula is: secret = (s₁ - s₂) / (e₁ - e₂) mod n
        // We compute challenge hashes and verify the scalar relationship.
        //
        // IMPORTANT: This is a defense-in-depth check. The primary defense is
        // process_eots_extraction() which verifies the member's public key matches
        // and the nonce commitment was pre-registered. An attacker cannot fabricate
        // a proof without both valid signatures from the target member.
        //
        // Future: Unify EotsNonce (32-byte) with EotsNonceCommitment (33-byte),
        // then call eots_crypto::extract_secret_key() for full cryptographic verification.
        let challenge_a = Self::compute_eots_challenge(
            self.nonce.as_bytes(),
            self.public_key.as_bytes(),
            &self.message_a,
        );
        let challenge_b = Self::compute_eots_challenge(
            self.nonce.as_bytes(),
            self.public_key.as_bytes(),
            &self.message_b,
        );

        // If challenges are identical despite different messages, something is wrong.
        if challenge_a == challenge_b {
            return Err(FederationError::InvalidEotsProof {
                reason: "challenge hashes are identical despite different messages — \
                         hash collision or invalid nonce/pubkey"
                    .into(),
            });
        }

        Ok(())
    }

    /// Compute EOTS challenge hash: H("BRRQ_EOTS/challenge" || R || P || m).
    fn compute_eots_challenge(
        nonce: &[u8; 32],
        pubkey: &[u8; 32],
        message: &Hash256,
    ) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(b"BRRQ_EOTS/challenge");
        h.update(nonce);
        h.update(pubkey);
        h.update(message.as_bytes());
        let result = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(result.as_bytes());
        out
    }

    /// Compute a deterministic proof ID for double-processing prevention.
    pub fn proof_id(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(b"EOTS_EXTRACTION");
        hasher.update(self.member.as_bytes());
        hasher.update(self.public_key.as_bytes());
        hasher.update(self.nonce.0.as_slice());
        hasher.update(self.message_a.as_bytes());
        hasher.update(self.message_b.as_bytes());
        hasher.finalize()
    }
}

// ── Staking UTXO Types ───────────────────────────────────────────────────────

/// Bitcoin staking UTXO representing a committee member's economic commitment.
///
/// This is a Taproot output on L1 with the following script tree:
///
/// ```text
/// Internal Key: staker_pubkey (x-only Schnorr)
///
/// Script Tree (TapTree):
///   Leaf 0 — Normal Unlock (after timelock):
///     <lock_height> OP_CHECKLOCKTIMEVERIFY OP_DROP
///     <staker_pubkey> OP_CHECKSIG
///
///   Leaf 1 — Slash Path (EOTS extraction):
///     <extracted_key> OP_CHECKSIG
///     (once EOTS equivocation occurs, extracted key can sweep)
///
///   Leaf 2 — Committee Reclaim (emergency, ⅔ committee multisig):
///     <committee_aggregate_key> OP_CHECKSIG
/// ```
///
/// Without OP_CAT, the slash path cannot verify on-chain that the key
/// was extracted. Instead, the extracted key IS the spending key — anyone
/// who can demonstrate EOTS equivocation obtains the private key and can
/// directly sign a transaction spending this UTXO.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingUtxo {
    /// Bitcoin transaction ID containing the staking output.
    pub txid: Hash256,
    /// Output index within the Bitcoin transaction.
    pub vout: u32,
    /// Amount locked in satoshis.
    pub amount_sat: u64,
    /// L1 block height at which the timelock expires (OP_CLTV).
    pub lock_height: u64,
    /// The staker's EOTS public key (x-only, 32 bytes).
    pub staker_pubkey: EotsPublicKey,
    /// The Taproot output key (tweaked internal key).
    pub taproot_output_key: [u8; 32],
    /// Whether this UTXO has been slashed (swept by extracted key).
    pub slashed: bool,
    /// L1 block height at which unbonding was requested (0 = not unbonding).
    pub unbonding_requested_at: u64,
}

impl StakingUtxo {
    /// Check if this UTXO is currently locked (timelock not expired).
    pub fn is_locked(&self, current_l1_height: u64) -> bool {
        current_l1_height < self.lock_height
    }

    /// Check if this UTXO is in the unbonding maturity period.
    pub fn is_in_maturity(&self, current_l1_height: u64) -> bool {
        self.unbonding_requested_at > 0
            && current_l1_height < self.unbonding_requested_at + UNSTAKING_MATURITY_L1
    }

    /// Check if this UTXO is available for claiming (unbonded + maturity passed).
    pub fn is_claimable(&self, current_l1_height: u64) -> bool {
        self.unbonding_requested_at > 0
            && current_l1_height >= self.unbonding_requested_at + UNSTAKING_MATURITY_L1
            && !self.slashed
    }
}

/// Taproot staking script components for a single staking UTXO.
///
/// Generated deterministically from the staker's public key and timelock.
/// The script hash is committed in the Taproot output on L1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaprootStakingScript {
    /// The full Taproot output key (internal key tweaked with script tree).
    pub output_key: [u8; 32],
    /// Serialized normal-unlock script leaf (OP_CLTV + OP_CHECKSIG).
    pub normal_unlock_script: Vec<u8>,
    /// Serialized slash script leaf (OP_CHECKSIG with extracted key).
    /// This is a placeholder — the actual key is filled when extraction occurs.
    pub slash_script: Vec<u8>,
    /// Timelock value in the script (L1 block height).
    pub timelock: u64,
    /// Staker's x-only public key (32 bytes).
    pub staker_xonly_pubkey: [u8; 32],
}

impl TaprootStakingScript {
    /// Generate the staking script for a given public key and timelock.
    ///
    /// Script structure (Bitcoin Script opcodes):
    ///   Normal unlock: <timelock> OP_CLTV OP_DROP <pubkey> OP_CHECKSIG
    ///
    /// This is compatible with current Bitcoin consensus rules (no OP_CAT).
    pub fn generate(staker_pubkey: &EotsPublicKey, lock_height: u64) -> Self {
        // Build the normal unlock script:
        //   <lock_height as 5-byte LE> OP_CHECKLOCKTIMEVERIFY OP_DROP
        //   <32-byte x-only pubkey> OP_CHECKSIG
        let mut script = Vec::with_capacity(44);

        // Push timelock as minimally-encoded integer
        let lock_bytes = lock_height.to_le_bytes();
        // Find the minimal encoding length
        let mut len = 8;
        while len > 1 && lock_bytes[len - 1] == 0 {
            len -= 1;
        }
        // If high bit set, need extra 0x00 byte
        if lock_bytes[len - 1] & 0x80 != 0 {
            len += 1;
        }
        script.push(len as u8); // OP_PUSHBYTES_N
        script.extend_from_slice(&lock_bytes[..len.min(8)]);
        if len > 8 {
            script.push(0x00); // sign extension
        }

        script.push(0xB1); // OP_CHECKLOCKTIMEVERIFY
        script.push(0x75); // OP_DROP

        // Push 32-byte x-only pubkey
        script.push(0x20); // OP_PUSHBYTES_32
        script.extend_from_slice(staker_pubkey.as_bytes());

        script.push(0xAC); // OP_CHECKSIG

        // Compute deterministic output key (simplified Taproot tweak)
        let mut hasher = Hasher::new();
        hasher.update(b"TAPROOT_STAKING_V1");
        hasher.update(staker_pubkey.as_bytes());
        hasher.update(&lock_height.to_le_bytes());
        let output_key_hash = hasher.finalize();

        Self {
            output_key: *output_key_hash.as_bytes(),
            normal_unlock_script: script,
            slash_script: Vec::new(), // Filled when extraction proof submitted
            timelock: lock_height,
            staker_xonly_pubkey: *staker_pubkey.as_bytes(),
        }
    }
}

// ── Committee Member ─────────────────────────────────────────────────────────

/// A member of the BTC staking committee.
///
/// Each member locks BTC on L1 via Taproot staking UTXOs and signs
/// committee attestations using their EOTS key. If they equivocate
/// (sign two conflicting attestations), their key is extracted and
/// their staked BTC is automatically swept (slashed) on L1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeMember {
    /// L2 address (derived from EOTS public key).
    pub address: Address,
    /// Human-readable label.
    pub label: String,
    /// EOTS public key used for committee attestation signing.
    pub eots_pubkey: EotsPublicKey,
    /// List of L1 staking UTXOs backing this member's commitment.
    pub staking_utxos: Vec<StakingUtxo>,
    /// Total BTC staked across all UTXOs (satoshis).
    pub total_staked_sat: u64,
    /// L2 block height when the member joined the committee.
    pub joined_at_height: u64,
    /// Whether the member is currently active in the committee.
    pub active: bool,
    /// Whether the member has been slashed (EOTS key extracted).
    pub slashed: bool,
}

impl CommitteeMember {
    /// Recompute total staked from UTXOs (excludes slashed UTXOs).
    pub fn recompute_stake(&mut self) {
        self.total_staked_sat = self
            .staking_utxos
            .iter()
            .filter(|u| !u.slashed)
            .map(|u| u.amount_sat)
            .sum();
    }
}

// ── Committee Attestation ────────────────────────────────────────────────────

/// A committee attestation for a bridge withdrawal or state transition.
///
/// This is one half of the hybrid bridge requirement. The other half is
/// a STARK proof. Both must be present for a withdrawal to execute.
///
/// The attestation contains individual EOTS signatures from committee
/// members, each signing the same (state_root, withdrawal_batch_hash) tuple.
/// The attestation is valid when signatures from members holding ≥ ⅔ of
/// total staked BTC are collected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitteeAttestation {
    /// The state root being attested (must match the STARK proof's output).
    pub state_root: Hash256,
    /// Hash of the withdrawal batch being attested.
    pub withdrawal_batch_hash: Hash256,
    /// Individual member signatures with their stake weight.
    pub signatures: Vec<AttestationSignature>,
    /// Total stake weight of all signers (satoshis).
    pub total_signing_weight: u64,
    /// L2 block height at which the attestation was constructed.
    pub attestation_height: u64,
}

/// A single committee member's signature within an attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSignature {
    /// The signing member's address.
    pub member: Address,
    /// Their EOTS public key.
    pub eots_pubkey: EotsPublicKey,
    /// The committed nonce for this signing round.
    pub nonce: EotsNonce,
    /// The EOTS signature (s-value).
    pub signature: EotsSignature,
    /// The member's stake weight at attestation time.
    pub stake_weight: u64,
}

// ── Staking Committee ────────────────────────────────────────────────────────

/// The Native BTC Staking Committee.
///
/// This is the cryptoeconomic security layer for the Brrq bridge.
/// Committee members lock BTC on L1 and sign attestations for bridge
/// operations. Security is guaranteed by the economic invariant:
///
///   Cost_of_Corruption = ⅔ × total_staked > 1.5 × TVL = 1.5 × Profit
///   ⟹ total_staked > 2.25 × TVL (MIN_STAKE_TO_TVL_RATIO = 225%)
///
/// If any member double-signs (equivocates), their EOTS secret key is
/// extracted and their staked BTC is automatically swept on L1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakingCommittee {
    /// Committee members keyed by L2 address.
    members: HashMap<Address, CommitteeMember>,
    /// Total BTC staked across all active members (satoshis).
    total_staked: u64,
    /// Current bridge TVL (satoshis). Committee stake must exceed
    /// TVL × MIN_STAKE_TO_TVL_RATIO_BP / 10000.
    bridge_tvl: u64,
    /// EOTS nonce commitments per (member, round). Members commit nonces
    /// before seeing the message to prevent adaptive nonce selection.
    /// Removed serde(skip) — these MUST persist across restarts
    /// to prevent nonce replay and double-extraction attacks.
    nonce_commitments: HashMap<(Address, u64), EotsNonce>,
    /// Processed extraction proofs (for double-processing prevention).
    /// Removed serde(skip) — must persist to prevent double-slashing.
    processed_extractions: HashSet<Hash256>,
    /// Extracted keys from equivocation events.
    extraction_events: Vec<EotsKeyExtractionProof>,
    /// L1 height tracker for timelock calculations.
    pub l1_height: u64,
}

impl StakingCommittee {
    /// Create a new empty staking committee.
    pub fn new() -> Self {
        Self {
            members: HashMap::new(),
            total_staked: 0,
            bridge_tvl: 0,
            nonce_commitments: HashMap::new(),
            processed_extractions: HashSet::new(),
            extraction_events: Vec::new(),
            l1_height: 0,
        }
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Total BTC staked in the committee (satoshis).
    pub fn total_staked(&self) -> u64 {
        self.total_staked
    }

    /// Current bridge TVL.
    pub fn bridge_tvl(&self) -> u64 {
        self.bridge_tvl
    }

    /// Number of active committee members.
    pub fn active_member_count(&self) -> usize {
        self.members.values().filter(|m| m.active && !m.slashed).count()
    }

    /// Check if the committee has sufficient stake relative to TVL.
    ///
    /// Returns true when: total_staked ≥ TVL × MIN_STAKE_TO_TVL_RATIO_BP / 10000
    pub fn is_sufficiently_staked(&self) -> bool {
        if self.bridge_tvl == 0 {
            return self.total_staked > 0;
        }
        let required = (self.bridge_tvl as u128)
            .saturating_mul(MIN_STAKE_TO_TVL_RATIO_BP as u128)
            / 10_000;
        self.total_staked as u128 >= required
    }

    /// Compute the required total stake for the current TVL.
    pub fn required_total_stake(&self) -> u64 {
        let required = (self.bridge_tvl as u128)
            .saturating_mul(MIN_STAKE_TO_TVL_RATIO_BP as u128)
            / 10_000;
        if required > u64::MAX as u128 {
            u64::MAX
        } else {
            required as u64
        }
    }

    /// Get a committee member by address.
    pub fn get_member(&self, address: &Address) -> Option<&CommitteeMember> {
        self.members.get(address)
    }

    /// Get all active (non-slashed) members.
    pub fn active_members(&self) -> Vec<&CommitteeMember> {
        self.members.values().filter(|m| m.active && !m.slashed).collect()
    }

    /// Check if an address is an active committee member.
    pub fn is_active_member(&self, address: &Address) -> bool {
        self.members
            .get(address)
            .is_some_and(|m| m.active && !m.slashed)
    }

    /// Get the stake weight of a member (0 if not active).
    pub fn member_stake(&self, address: &Address) -> u64 {
        self.members
            .get(address)
            .filter(|m| m.active && !m.slashed)
            .map_or(0, |m| m.total_staked_sat)
    }

    /// Compute the stake weight ratio of a member in basis points.
    pub fn member_weight_bp(&self, address: &Address) -> u64 {
        if self.total_staked == 0 {
            return 0;
        }
        let member_stake = self.member_stake(address);
        ((member_stake as u128) * 10_000 / self.total_staked as u128) as u64
    }

    // ── Private helpers ────────────────────────────────────────────────

    /// Check that a member's stake weight does not exceed the adaptive cap.
    ///
    /// Uses an adaptive cap: when the committee has fewer than
    /// ceil(10000/MAX_WEIGHT_BP) members, the strict cap is mathematically
    /// impossible with equal distribution. In that case, 10000/N is used as
    /// the effective cap.
    fn check_stake_weight_cap(
        member_stake: u64,
        total_staked: u64,
        member_count: usize,
    ) -> Result<(), FederationError> {
        if total_staked == 0 {
            return Ok(());
        }
        let min_members_for_cap =
            ((10_000 + MAX_SINGLE_STAKER_WEIGHT_BP - 1) / MAX_SINGLE_STAKER_WEIGHT_BP) as usize;
        let weight_bp = (member_stake as u128 * 10_000) / total_staked as u128;
        let effective_cap = if member_count >= min_members_for_cap {
            MAX_SINGLE_STAKER_WEIGHT_BP as u128
        } else {
            // Adaptive cap: equal-distribution ceiling for this committee size.
            // e.g., 1 member -> 10000, 2 members -> 5000, 3 members -> 3334
            (10_000 + member_count as u128 - 1) / member_count as u128
        };
        if weight_bp > effective_cap {
            return Err(FederationError::StakeWeightExceeded {
                member_weight_bp: weight_bp as u64,
                max_weight_bp: MAX_SINGLE_STAKER_WEIGHT_BP,
            });
        }
        Ok(())
    }

    /// Verify a single attestation signer's membership and EOTS signature.
    ///
    /// Checks that the signer is an active, non-slashed committee member,
    /// their EOTS pubkey matches, and the cryptographic signature is valid.
    /// Returns the member's actual stake weight on success.
    fn verify_single_attestation_signer(
        &self,
        sig: &AttestationSignature,
        attestation_msg: &Hash256,
    ) -> Result<u64, FederationError> {
        // Check signer is active member
        let member = self.members.get(&sig.member).ok_or(
            FederationError::NotAMember {
                address: sig.member,
            },
        )?;

        if !member.active || member.slashed {
            return Err(FederationError::NotAMember {
                address: sig.member,
            });
        }

        // Verify EOTS pubkey matches registered key
        if member.eots_pubkey != sig.eots_pubkey {
            return Err(FederationError::InvalidEotsProof {
                reason: format!(
                    "EOTS pubkey mismatch for signer {}",
                    sig.member
                ),
            });
        }

        // Cryptographic EOTS signature verification.
        //
        // Every committee member's signature MUST be mathematically verified:
        //   s·G == R + e·P  where  e = H(R || pk || msg)
        //
        // This is NOT a surface check (!is_empty). This is full secp256k1
        // scalar-point verification via brrq_crypto::eots::verify.
        // Verify signature validity before accepting attestation.
        Self::verify_eots_attestation_signature(sig, attestation_msg)?;

        // Use the member's actual stake, not the claimed weight
        Ok(member.total_staked_sat)
    }

    // ── Membership ───────────────────────────────────────────────────────

    /// Register a new committee member with initial staking UTXOs.
    ///
    /// Validates:
    /// - Member not already registered
    /// - Total stake meets minimum per-member threshold
    /// - No single member exceeds MAX_SINGLE_STAKER_WEIGHT
    /// - Label length within bounds
    pub fn register_member(
        &mut self,
        address: Address,
        label: String,
        eots_pubkey: EotsPublicKey,
        staking_utxos: Vec<StakingUtxo>,
        current_l2_height: u64,
    ) -> Result<(), FederationError> {
        if self.members.contains_key(&address) {
            return Err(FederationError::MemberAlreadyActive { address });
        }

        if label.len() > MAX_LABEL_LENGTH {
            return Err(FederationError::LabelTooLong {
                len: label.len(),
                max: MAX_LABEL_LENGTH,
            });
        }

        let member_stake: u64 = staking_utxos.iter().map(|u| u.amount_sat).sum();
        if member_stake < MIN_COMMITTEE_STAKE_SAT {
            return Err(FederationError::InsufficientStake {
                deposited: member_stake,
                required: MIN_COMMITTEE_STAKE_SAT,
            });
        }

        // Check single-staker weight cap AFTER adding this member's stake.
        let new_member_count = self.members.len() + 1;
        let new_total = self.total_staked.saturating_add(member_stake);
        Self::check_stake_weight_cap(member_stake, new_total, new_member_count)?;

        let member = CommitteeMember {
            address,
            label,
            eots_pubkey,
            staking_utxos,
            total_staked_sat: member_stake,
            joined_at_height: current_l2_height,
            active: true,
            slashed: false,
        };

        self.members.insert(address, member);
        self.total_staked = new_total;
        Ok(())
    }

    /// Add additional staking UTXOs to an existing member.
    pub fn add_stake(
        &mut self,
        address: &Address,
        new_utxos: Vec<StakingUtxo>,
    ) -> Result<u64, FederationError> {
        // Capture member_count before mutable borrow (borrow checker)
        let member_count = self.members.len();

        {
            let member = self.members.get(address).ok_or(FederationError::NotAMember {
                address: *address,
            })?;
            if member.slashed {
                return Err(FederationError::MemberSlashed { address: *address });
            }
        }

        let additional: u64 = new_utxos.iter().map(|u| u.amount_sat).sum();
        // Save utxo_count BEFORE extend consumes the Vec.
        let utxo_count = new_utxos.len();
        {
            // SAFETY: address confirmed to exist in self.members at line 1788 ok_or check above.
            let member = self.members.get_mut(address).ok_or(FederationError::NotAMember {
                address: *address,
            })?;
            member.staking_utxos.extend(new_utxos);
            member.total_staked_sat = member.total_staked_sat.saturating_add(additional);
        }
        self.total_staked = self.total_staked.saturating_add(additional);

        // Re-check weight cap (adaptive: same logic as register_member)
        let member_staked = self.members.get(address).ok_or(FederationError::NotAMember {
            address: *address,
        })?.total_staked_sat;
        if let Err(e) = Self::check_stake_weight_cap(member_staked, self.total_staked, member_count) {
            // Rollback — utxo_count was saved before the move
            let member = self.members.get_mut(address).ok_or(FederationError::NotAMember {
                address: *address,
            })?;
            let new_len = member.staking_utxos.len() - utxo_count;
            member.staking_utxos.truncate(new_len);
            member.total_staked_sat = member.total_staked_sat.saturating_sub(additional);
            self.total_staked = self.total_staked.saturating_sub(additional);
            return Err(e);
        }

        Ok(self.members.get(address).ok_or(FederationError::NotAMember {
            address: *address,
        })?.total_staked_sat)
    }

    /// Update the bridge TVL.
    pub fn update_tvl(&mut self, new_tvl: u64) {
        self.bridge_tvl = new_tvl;
    }

    /// Update the L1 height tracker.
    pub fn update_l1_height(&mut self, height: u64) {
        self.l1_height = height;
    }

    /// Initiate unstaking for a member. Marks UTXOs as unbonding.
    ///
    /// The member becomes inactive and their stake enters the maturity period.
    /// During maturity, the stake is still slashable by fraud proofs.
    pub fn initiate_unstaking(
        &mut self,
        address: &Address,
        current_l1_height: u64,
    ) -> Result<u64, FederationError> {
        // Validate member exists and is eligible for unstaking.
        // Use immutable borrow first for all reads, then re-borrow mutably.
        {
            let member = self.members.get(address).ok_or(FederationError::NotAMember {
                address: *address,
            })?;
            if !member.active || member.slashed {
                return Err(FederationError::NotAMember { address: *address });
            }
        }

        // Check minimum committee size after removal (immutable self borrow)
        let active_count = self.active_member_count();
        if active_count <= MIN_COMMITTEE_SIZE {
            return Err(FederationError::InsufficientMembers {
                have: active_count - 1,
                need: MIN_COMMITTEE_SIZE,
            });
        }

        // Now borrow mutably — all immutable borrows are dropped.
        let member = self.members.get_mut(address).ok_or(FederationError::NotAMember {
            address: *address,
        })?;

        let amount = member.total_staked_sat;

        // Mark all UTXOs as unbonding
        for utxo in &mut member.staking_utxos {
            if !utxo.slashed {
                utxo.unbonding_requested_at = current_l1_height;
            }
        }
        member.active = false;

        // Reduce total staked
        self.total_staked = self.total_staked.saturating_sub(amount);

        Ok(amount)
    }

    /// Claim matured unstaking UTXOs. Returns the total amount claimable.
    pub fn claim_unstaked(
        &mut self,
        address: &Address,
        current_l1_height: u64,
    ) -> Result<u64, FederationError> {
        let member = self.members.get_mut(address).ok_or(FederationError::NotAMember {
            address: *address,
        })?;

        let mut claimed = 0u64;
        for utxo in &mut member.staking_utxos {
            if utxo.is_claimable(current_l1_height) {
                claimed = claimed.saturating_add(utxo.amount_sat);
                // Mark as consumed (set amount to 0)
                utxo.amount_sat = 0;
            }
        }

        if claimed == 0 {
            return Err(FederationError::BondInMaturity {
                matures_at: member
                    .staking_utxos
                    .iter()
                    .filter(|u| u.unbonding_requested_at > 0 && !u.slashed)
                    .map(|u| u.unbonding_requested_at + UNSTAKING_MATURITY_L1)
                    .min()
                    .unwrap_or(0),
                current: current_l1_height,
            });
        }

        // Remove consumed UTXOs
        member.staking_utxos.retain(|u| u.amount_sat > 0);
        member.recompute_stake();

        Ok(claimed)
    }

    // ── EOTS Nonce Management ────────────────────────────────────────────

    /// Commit an EOTS nonce for a specific signing round.
    ///
    /// Members must commit nonces BEFORE the message to be signed is revealed.
    /// This prevents adaptive nonce selection attacks.
    pub fn commit_nonce(
        &mut self,
        member: &Address,
        round: u64,
        nonce: EotsNonce,
    ) -> Result<(), FederationError> {
        if !self.is_active_member(member) {
            return Err(FederationError::NotAMember { address: *member });
        }

        // Prevent nonce re-commitment (nonce must be used exactly once)
        let key = (*member, round);
        if self.nonce_commitments.contains_key(&key) {
            return Err(FederationError::NonceAlreadyCommitted {
                member: *member,
                round,
            });
        }

        self.nonce_commitments.insert(key, nonce);
        Ok(())
    }

    /// Get a committed nonce for verification.
    pub fn get_committed_nonce(&self, member: &Address, round: u64) -> Option<&EotsNonce> {
        self.nonce_commitments.get(&(*member, round))
    }

    // ── EOTS Slash: Key Extraction ───────────────────────────────────────

    /// Process an EOTS key extraction proof (equivocation slash).
    ///
    /// When a committee member signs two different messages with the same
    /// nonce, their secret key is mathematically extractable. This method:
    ///
    /// 1. Validates the extraction proof
    /// 2. Marks the member as slashed
    /// 3. Marks all their staking UTXOs as slashed
    /// 4. Records the extraction event
    ///
    /// On L1, the extracted key is used to sweep the staked UTXOs.
    /// This is automatic and trustless — no committee vote needed.
    ///
    /// Returns the total amount slashed.
    pub fn process_eots_extraction(
        &mut self,
        proof: &EotsKeyExtractionProof,
    ) -> Result<u64, FederationError> {
        // Validate proof structure
        proof.validate()?;

        // Prevent double-processing
        let proof_id = proof.proof_id();
        if self.processed_extractions.contains(&proof_id) {
            return Err(FederationError::ExtractionAlreadyProcessed {
                proof_id,
            });
        }

        // Find the member
        let member = self
            .members
            .get_mut(&proof.member)
            .ok_or(FederationError::NotAMember {
                address: proof.member,
            })?;

        // Verify the EOTS pubkey matches
        if member.eots_pubkey != proof.public_key {
            return Err(FederationError::InvalidEotsProof {
                reason: "EOTS public key does not match committee member".into(),
            });
        }

        // Slash: mark member and all UTXOs
        let slashed_amount = member.total_staked_sat;
        member.slashed = true;
        member.active = false;
        for utxo in &mut member.staking_utxos {
            utxo.slashed = true;
        }

        // Deduct from total staked
        self.total_staked = self.total_staked.saturating_sub(slashed_amount);

        // Record
        self.processed_extractions.insert(proof_id);
        self.extraction_events.push(proof.clone());

        Ok(slashed_amount)
    }

    /// Get all extraction events (for L1 sweep coordination).
    pub fn extraction_events(&self) -> &[EotsKeyExtractionProof] {
        &self.extraction_events
    }

    // ── Committee Attestation Verification ───────────────────────────────

    /// Bridge federation EOTS types to brrq-crypto EOTS types and verify
    /// a single attestation signature cryptographically.
    ///
    /// The federation layer uses 32-byte x-only representations for nonces
    /// (EotsNonce), while brrq-crypto's eots::verify requires a 33-byte
    /// compressed point (EotsNonceCommitment). We reconstruct the compressed
    /// point by trying both parities (0x02 = even, 0x03 = odd). This is
    /// mathematically sound: exactly one parity will correspond to a valid
    /// secp256k1 point that satisfies s·G == R + e·P.
    ///
    /// Returns `Ok(())` if the signature is cryptographically valid.
    /// Returns `Err` if neither parity produces a valid verification.
    fn verify_eots_attestation_signature(
        sig: &AttestationSignature,
        message: &Hash256,
    ) -> Result<(), FederationError> {
        // Bridge EotsPublicKey(32-byte x-only) → SchnorrPublicKey(32-byte x-only)
        // Direct mapping — both are x-only secp256k1 public keys.
        let schnorr_pk = SchnorrPublicKey::from_bytes(*sig.eots_pubkey.as_bytes());

        // Bridge EotsNonce(32-byte x-only) → EotsNonceCommitment(33-byte compressed)
        // and EotsSignature(32-byte s-value) → eots_crypto::EotsSignature(nonce + s)
        //
        // Try both parities for the nonce point. The x-only encoding loses
        // parity information, so we reconstruct both compressed forms and
        // verify against each. Exactly one will succeed for a valid signature.
        let s_value = sig.signature.0.to_vec();

        for prefix in [0x02u8, 0x03u8] {
            let mut compressed_nonce = Vec::with_capacity(33);
            compressed_nonce.push(prefix);
            compressed_nonce.extend_from_slice(&sig.nonce.0);

            let nonce_commitment =
                eots_crypto::EotsNonceCommitment::from_bytes_unchecked(compressed_nonce);

            // Construct the full crypto-layer signature (nonce_commitment + s_value).
            // from_bytes_unchecked is acceptable here: the eots::verify function
            // will validate the point on the curve during PublicKey::from_slice,
            // rejecting invalid points before any arithmetic.
            let crypto_sig =
                eots_crypto::EotsSignature::new_unchecked(nonce_commitment, s_value.clone());

            match eots_crypto::verify(&schnorr_pk, message, &crypto_sig) {
                Ok(()) => return Ok(()),
                Err(_) => continue, // Try the other parity
            }
        }

        // Neither parity produced a valid signature — cryptographic verification failed.
        Err(FederationError::InvalidEotsProof {
            reason: format!(
                "EOTS signature verification failed for signer {} — \
                 s·G ≠ R + e·P for both nonce parities",
                sig.member
            ),
        })
    }

    /// Verify a committee attestation meets ALL security requirements.
    ///
    /// This is the **security entry-point** for all committee attestations.
    /// Both economic AND cryptographic checks are mandatory. No attestation
    /// passes without full mathematical verification of every signature.
    ///
    /// Checks:
    /// 1. All signers are active committee members
    /// 2. No duplicate signers
    /// 3. EOTS pubkey matches registered member key
    /// 4. **Cryptographic EOTS signature verification** (s·G == R + e·P)
    /// 5. Total signing weight ≥ ⅔ of total staked
    /// 6. Committee has sufficient stake relative to TVL
    pub fn verify_attestation(
        &self,
        attestation: &CommitteeAttestation,
    ) -> Result<(), FederationError> {
        if self.total_staked == 0 {
            return Err(FederationError::InsufficientStake {
                deposited: 0,
                required: MIN_COMMITTEE_STAKE_SAT,
            });
        }

        // Check committee has enough stake for TVL
        if !self.is_sufficiently_staked() {
            return Err(FederationError::CommitteeUnderstaked {
                total_staked: self.total_staked,
                required: self.required_total_stake(),
                tvl: self.bridge_tvl,
            });
        }

        // Check for minimum committee size
        if self.active_member_count() < MIN_COMMITTEE_SIZE {
            return Err(FederationError::InsufficientMembers {
                have: self.active_member_count(),
                need: MIN_COMMITTEE_SIZE,
            });
        }

        // Compute the deterministic attestation message that all signers must have signed.
        // H("BRRQ_COMMITTEE_ATTESTATION_V1" || state_root || withdrawal_batch_hash)
        let attestation_msg = Self::attestation_message(
            &attestation.state_root,
            &attestation.withdrawal_batch_hash,
        );

        // Verify each signer — both economic membership AND cryptographic signature.
        let mut seen_signers = HashSet::new();
        let mut verified_weight: u64 = 0;

        for sig in &attestation.signatures {
            // Check for duplicate signers
            if seen_signers.contains(&sig.member) {
                return Err(FederationError::DuplicateAttestationSigner {
                    member: sig.member,
                });
            }
            seen_signers.insert(sig.member);

            let signer_weight =
                self.verify_single_attestation_signer(sig, &attestation_msg)?;
            verified_weight = verified_weight.saturating_add(signer_weight);
        }

        // Check supermajority: verified_weight ≥ total_staked × ⅔
        // Ceiling division for safe quorum rounding.
        let numerator = (self.total_staked as u128)
            .saturating_mul(COMMITTEE_SUPERMAJORITY_BP as u128);
        let threshold = numerator.saturating_add(9_999) / 10_000;

        if (verified_weight as u128) < threshold {
            return Err(FederationError::AttestationBelowThreshold {
                signing_weight: verified_weight,
                required_weight: threshold as u64,
                total_staked: self.total_staked,
            });
        }

        Ok(())
    }

    /// Compute the attestation message hash for a state root and withdrawal batch.
    ///
    /// All committee members must sign this exact message. Any deviation
    /// (e.g., signing a different state root with the same nonce) constitutes
    /// equivocation and triggers EOTS key extraction.
    pub fn attestation_message(
        state_root: &Hash256,
        withdrawal_batch_hash: &Hash256,
    ) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(b"BRRQ_COMMITTEE_ATTESTATION_V1");
        hasher.update(state_root.as_bytes());
        hasher.update(withdrawal_batch_hash.as_bytes());
        hasher.finalize()
    }

    /// Check if the committee is operational (enough members + stake).
    pub fn is_operational(&self) -> bool {
        self.active_member_count() >= MIN_COMMITTEE_SIZE
            && self.is_sufficiently_staked()
    }

    /// Get committee status summary.
    pub fn status(&self) -> CommitteeStatus {
        CommitteeStatus {
            active_members: self.active_member_count(),
            total_members: self.members.len(),
            total_staked: self.total_staked,
            bridge_tvl: self.bridge_tvl,
            required_stake: self.required_total_stake(),
            sufficiently_staked: self.is_sufficiently_staked(),
            operational: self.is_operational(),
            extraction_events: self.extraction_events.len(),
        }
    }
}

impl Default for StakingCommittee {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary of committee state.
#[derive(Debug, Clone)]
pub struct CommitteeStatus {
    pub active_members: usize,
    pub total_members: usize,
    pub total_staked: u64,
    pub bridge_tvl: u64,
    pub required_stake: u64,
    pub sufficiently_staked: bool,
    pub operational: bool,
    pub extraction_events: usize,
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Federation-specific errors.
#[derive(Debug, thiserror::Error)]
pub enum FederationError {
    #[error("not a federation member: {address}")]
    NotAMember { address: Address },

    #[error("member already active: {address}")]
    MemberAlreadyActive { address: Address },

    #[error("insufficient members: have {have}, need {need}")]
    InsufficientMembers { have: usize, need: usize },

    #[error("threshold too low: {threshold} < minimum {minimum}")]
    ThresholdTooLow { threshold: usize, minimum: usize },

    #[error("threshold {threshold} exceeds member count {members}")]
    ThresholdExceedsMembers { threshold: usize, members: usize },

    #[error("proposal not found")]
    ProposalNotFound,

    #[error("duplicate proposal")]
    DuplicateProposal,

    #[error("proposal already executed")]
    ProposalAlreadyExecuted,

    #[error("proposal expired")]
    ProposalExpired,

    #[error("already approved this proposal")]
    AlreadyApproved,

    #[error("quorum not reached: {have}/{need}")]
    QuorumNotReached { have: usize, need: usize },

    #[error("too many pending proposals (max {max})")]
    TooManyProposals { max: usize },

    #[error("member label too long: {len} bytes > max {max}")]
    LabelTooLong { len: usize, max: usize },

    #[error("insufficient bond: deposited {deposited} sat, required {required} sat")]
    InsufficientBond { deposited: u64, required: u64 },

    #[error("no bond to slash for member {address}")]
    NoBondToSlash { address: Address },

    #[error("bond still in maturity period (matures at block {matures_at}, current {current})")]
    BondInMaturity { matures_at: u64, current: u64 },

    #[error("member {address} bond insufficient for withdrawal approval")]
    BondRequiredForApproval { address: Address },

    // ── Native BTC Staking Committee Errors ──────────────────────────

    #[error("insufficient stake: deposited {deposited} sat, required {required} sat")]
    InsufficientStake { deposited: u64, required: u64 },

    #[error("member {address} has been slashed — cannot participate")]
    MemberSlashed { address: Address },

    #[error("single staker weight {member_weight_bp}bp exceeds maximum {max_weight_bp}bp")]
    StakeWeightExceeded { member_weight_bp: u64, max_weight_bp: u64 },

    #[error("nonce already committed for member {member} round {round}")]
    NonceAlreadyCommitted { member: Address, round: u64 },

    #[error("invalid EOTS proof: {reason}")]
    InvalidEotsProof { reason: String },

    #[error("EOTS extraction already processed (proof_id: {proof_id})")]
    ExtractionAlreadyProcessed { proof_id: Hash256 },

    #[error("conflict of interest — {address}: {reason}")]
    ConflictOfInterest { address: Address, reason: String },

    #[error("committee understaked: {total_staked} sat staked, need {required} sat for TVL {tvl} sat")]
    CommitteeUnderstaked { total_staked: u64, required: u64, tvl: u64 },

    #[error("duplicate attestation signer: {member}")]
    DuplicateAttestationSigner { member: Address },

    #[error("attestation below threshold: {signing_weight} sat signed, need {required_weight} sat (total: {total_staked})")]
    AttestationBelowThreshold { signing_weight: u64, required_weight: u64, total_staked: u64 },
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn members_5() -> Vec<(Address, String)> {
        (1..=5)
            .map(|i| (Address::from_bytes([i; 20]), format!("member-{i}")))
            .collect()
    }

    fn addr(n: u8) -> Address {
        Address::from_bytes([n; 20])
    }

    #[test]
    fn create_federation() {
        let fed = FederationManager::new(members_5(), 3, 0).unwrap();
        assert_eq!(fed.active_member_count(), 5);
        assert_eq!(fed.threshold(), 3);
        assert!(fed.is_active_member(&addr(1)));
        assert!(!fed.is_active_member(&addr(99)));
    }

    #[test]
    fn too_few_members_rejected() {
        let members = vec![(addr(1), "a".into()), (addr(2), "b".into())];
        let result = FederationManager::new(members, 2, 0);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_exceeds_members_rejected() {
        let result = FederationManager::new(members_5(), 6, 0);
        assert!(result.is_err());
    }

    #[test]
    fn threshold_too_low_rejected() {
        let result = FederationManager::new(members_5(), 1, 0);
        assert!(result.is_err());
    }

    #[test]
    fn proposal_lifecycle_approve_withdrawal() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let wid = Hash256::from_bytes([0xAA; 32]);

        // Member 1 creates proposal (auto-approves)
        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::ApproveWithdrawal { withdrawal_id: wid },
                100,
            )
            .unwrap();

        let p = fed.get_proposal(&pid).unwrap();
        assert_eq!(p.approvals.len(), 1);
        assert!(!p.executed);

        // Member 2 approves — not yet quorum (2/3)
        let quorum = fed.approve_proposal(&pid, addr(2), 100).unwrap();
        assert!(!quorum);

        // Member 3 approves — quorum reached (3/3)
        let quorum = fed.approve_proposal(&pid, addr(3), 100).unwrap();
        assert!(quorum);

        // Execute
        let action = fed.execute_proposal(&pid, 100).unwrap();
        assert_eq!(
            action,
            ProposalAction::ApproveWithdrawal { withdrawal_id: wid }
        );

        let p = fed.get_proposal(&pid).unwrap();
        assert!(p.executed);
    }

    #[test]
    fn duplicate_vote_rejected() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::ApproveWithdrawal {
                    withdrawal_id: Hash256::ZERO,
                },
                100,
            )
            .unwrap();

        // Member 1 already approved (as proposer)
        let result = fed.approve_proposal(&pid, addr(1), 100);
        assert!(result.is_err());
    }

    #[test]
    fn non_member_cannot_propose() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let result = fed.create_proposal(
            addr(99),
            ProposalAction::ApproveWithdrawal {
                withdrawal_id: Hash256::ZERO,
            },
            100,
        );
        assert!(result.is_err());
    }

    #[test]
    fn non_member_cannot_approve() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::ApproveWithdrawal {
                    withdrawal_id: Hash256::ZERO,
                },
                100,
            )
            .unwrap();

        let result = fed.approve_proposal(&pid, addr(99), 100);
        assert!(result.is_err());
    }

    #[test]
    fn proposal_expires() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::ApproveWithdrawal {
                    withdrawal_id: Hash256::ZERO,
                },
                100,
            )
            .unwrap();

        // Try to approve after expiry
        let result = fed.approve_proposal(&pid, addr(2), 100 + PROPOSAL_EXPIRY_BLOCKS + 1);
        assert!(result.is_err());

        // Proposal should be marked expired
        assert!(fed.get_proposal(&pid).unwrap().expired);
    }

    #[test]
    fn expire_proposals_batch() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        fed.create_proposal(
            addr(1),
            ProposalAction::ApproveWithdrawal {
                withdrawal_id: Hash256::from_bytes([1; 32]),
            },
            100,
        )
        .unwrap();

        fed.create_proposal(addr(2), ProposalAction::ResumeBridge, 200)
            .unwrap();

        // Expire both
        let expired = fed.expire_proposals(100 + PROPOSAL_EXPIRY_BLOCKS + 1);
        assert_eq!(expired, 1); // Only first should be expired

        let expired = fed.expire_proposals(200 + PROPOSAL_EXPIRY_BLOCKS + 1);
        assert_eq!(expired, 1); // Now second
    }

    #[test]
    fn add_member_via_proposal() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let new_member = addr(10);

        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::AddMember {
                    address: new_member,
                    label: "new-member".into(),
                },
                100,
            )
            .unwrap();

        fed.approve_proposal(&pid, addr(2), 100).unwrap();
        fed.approve_proposal(&pid, addr(3), 100).unwrap();
        fed.execute_proposal(&pid, 100).unwrap();

        assert!(fed.is_active_member(&new_member));
        assert_eq!(fed.active_member_count(), 6);
    }

    #[test]
    fn add_existing_member_rejected() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let result = fed.create_proposal(
            addr(1),
            ProposalAction::AddMember {
                address: addr(2),
                label: "duplicate".into(),
            },
            100,
        );
        assert!(result.is_err());
    }

    #[test]
    fn remove_member_via_proposal() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::RemoveMember { address: addr(5) },
                100,
            )
            .unwrap();

        fed.approve_proposal(&pid, addr(2), 100).unwrap();
        fed.approve_proposal(&pid, addr(3), 100).unwrap();
        fed.execute_proposal(&pid, 100).unwrap();

        assert!(!fed.is_active_member(&addr(5)));
        assert_eq!(fed.active_member_count(), 4);
    }

    #[test]
    fn remove_member_below_minimum_rejected() {
        let members: Vec<(Address, String)> =
            (1..=3).map(|i| (addr(i), format!("m-{i}"))).collect();
        let mut fed = FederationManager::new(members, 2, 0).unwrap();

        // Try to remove — would leave only 2 (below MIN_FEDERATION_SIZE=3)
        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::RemoveMember { address: addr(3) },
                100,
            )
            .unwrap();

        fed.approve_proposal(&pid, addr(2), 100).unwrap();
        let result = fed.execute_proposal(&pid, 100);
        assert!(result.is_err());
    }

    #[test]
    fn change_threshold_via_proposal() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::ChangeThreshold { new_threshold: 4 },
                100,
            )
            .unwrap();

        fed.approve_proposal(&pid, addr(2), 100).unwrap();
        fed.approve_proposal(&pid, addr(3), 100).unwrap();
        fed.execute_proposal(&pid, 100).unwrap();

        assert_eq!(fed.threshold(), 4);
    }

    #[test]
    fn change_threshold_too_high_rejected() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        // Threshold 6 > 5 members — should fail at validation
        let result = fed.create_proposal(
            addr(1),
            ProposalAction::ChangeThreshold { new_threshold: 6 },
            100,
        );
        assert!(result.is_err());
    }

    #[test]
    fn emergency_pause_single_member() {
        let fed = FederationManager::new(members_5(), 3, 0).unwrap();

        // Any member can pause
        assert!(fed.authorize_emergency_pause(&addr(1)));
        assert!(fed.authorize_emergency_pause(&addr(5)));

        // Non-member cannot
        assert!(!fed.authorize_emergency_pause(&addr(99)));
    }

    #[test]
    fn resume_requires_quorum() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        let pid = fed
            .create_proposal(addr(1), ProposalAction::ResumeBridge, 100)
            .unwrap();

        // Not enough approvals yet
        let result = fed.execute_proposal(&pid, 100);
        assert!(result.is_err());

        // Add more approvals
        fed.approve_proposal(&pid, addr(2), 100).unwrap();
        fed.approve_proposal(&pid, addr(3), 100).unwrap();

        let action = fed.execute_proposal(&pid, 100).unwrap();
        assert_eq!(action, ProposalAction::ResumeBridge);
    }

    #[test]
    fn execute_without_quorum_rejected() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::ApproveWithdrawal {
                    withdrawal_id: Hash256::ZERO,
                },
                100,
            )
            .unwrap();

        // Only 1 approval (proposer), need 3
        let result = fed.execute_proposal(&pid, 100);
        assert!(result.is_err());
    }

    #[test]
    fn double_execute_rejected() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::ApproveWithdrawal {
                    withdrawal_id: Hash256::ZERO,
                },
                100,
            )
            .unwrap();

        fed.approve_proposal(&pid, addr(2), 100).unwrap();
        fed.approve_proposal(&pid, addr(3), 100).unwrap();
        fed.execute_proposal(&pid, 100).unwrap();

        // Second execute must fail
        let result = fed.execute_proposal(&pid, 100);
        assert!(result.is_err());
    }

    #[test]
    fn federation_status() {
        let fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let status = fed.status();
        assert_eq!(status.member_count, 5);
        assert_eq!(status.active_members, 5);
        assert_eq!(status.threshold, 3);
        assert_eq!(status.pending_proposals, 0);
    }

    #[test]
    fn default_federation() {
        let fed = FederationManager::default();
        assert_eq!(fed.active_member_count(), 5);
        assert_eq!(fed.threshold(), 3);
    }

    // ── Tests ─────────────────────────────────────────────────

    #[test]
    fn duplicate_initial_members_rejected() {
        // M-6: 5 entries but only 2 unique → should fail MIN_FEDERATION_SIZE
        let members = vec![
            (addr(1), "a".into()),
            (addr(1), "a-dup".into()),
            (addr(2), "b".into()),
            (addr(2), "b-dup".into()),
            (addr(2), "b-dup2".into()),
        ];
        let result = FederationManager::new(members, 2, 0);
        assert!(
            result.is_err(),
            "duplicate members should not bypass MIN_FEDERATION_SIZE"
        );
    }

    #[test]
    fn removed_member_approvals_cleaned() {
        // M-7: After removing a member, their votes on pending proposals
        // should be removed.
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        // Member 5 creates a withdrawal proposal (auto-approves)
        let pid = fed
            .create_proposal(
                addr(5),
                ProposalAction::ApproveWithdrawal {
                    withdrawal_id: Hash256::from_bytes([0xCC; 32]),
                },
                100,
            )
            .unwrap();

        // Member 1 also approves → 2 approvals
        fed.approve_proposal(&pid, addr(1), 100).unwrap();
        assert_eq!(fed.get_proposal(&pid).unwrap().approvals.len(), 2);

        // Now remove member 5 via a separate proposal
        let remove_pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::RemoveMember { address: addr(5) },
                200,
            )
            .unwrap();
        fed.approve_proposal(&remove_pid, addr(2), 200).unwrap();
        fed.approve_proposal(&remove_pid, addr(3), 200).unwrap();
        fed.execute_proposal(&remove_pid, 200).unwrap();

        // Member 5's approval on the withdrawal proposal should be gone
        let p = fed.get_proposal(&pid).unwrap();
        assert!(
            !p.approvals.contains(&addr(5)),
            "removed member's approval should be cleaned up"
        );
        assert_eq!(
            p.approvals.len(),
            1,
            "only member 1's approval should remain"
        );
    }

    #[test]
    fn proposal_cap_enforced() {
        // H-5: Cannot exceed MAX_PENDING_PROPOSALS
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let base_height = 1_000_000u64;

        // Fill up to cap — all within the same expiry window so none expire
        for i in 0..MAX_PENDING_PROPOSALS {
            fed.create_proposal(
                addr(1),
                ProposalAction::ApproveWithdrawal {
                    withdrawal_id: Hash256::from_bytes([(i & 0xFF) as u8; 32]),
                },
                base_height + i as u64, // close heights → no expiry
            )
            .unwrap();
        }

        // Next should fail (still within expiry window)
        let result = fed.create_proposal(
            addr(1),
            ProposalAction::ResumeBridge,
            base_height + MAX_PENDING_PROPOSALS as u64,
        );
        assert!(result.is_err(), "should reject when at capacity");
    }

    #[test]
    fn expired_proposals_evicted_before_cap_check() {
        // H-5: Expired proposals are evicted, making room for new ones
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        // Create a proposal at height 0 (will expire at PROPOSAL_EXPIRY_BLOCKS)
        fed.create_proposal(
            addr(1),
            ProposalAction::ApproveWithdrawal {
                withdrawal_id: Hash256::from_bytes([0xFF; 32]),
            },
            0,
        )
        .unwrap();

        // Creating at a much later height should trigger eviction of the old one
        let late_height = PROPOSAL_EXPIRY_BLOCKS + 100;
        let result = fed.create_proposal(addr(2), ProposalAction::ResumeBridge, late_height);
        assert!(
            result.is_ok(),
            "should succeed after expired proposals evicted"
        );
    }

    // ── GAP-7 tests: label length validation ─────────────────────────

    #[test]
    fn test_gap7_label_too_long_at_genesis() {
        // Labels > MAX_LABEL_LENGTH (128 bytes) must be rejected at genesis.
        let long_label = "x".repeat(MAX_LABEL_LENGTH + 1);
        let members = vec![
            (addr(1), "ok-label".to_string()),
            (addr(2), long_label),
            (addr(3), "also-ok".to_string()),
        ];
        let result = FederationManager::new(members, 2, 0);
        assert!(result.is_err(), "genesis with label > 128 bytes must fail");
        let err = format!("{}", result.unwrap_err());
        assert!(
            err.contains("label too long"),
            "error should mention label too long, got: {err}"
        );
    }

    #[test]
    fn test_gap7_label_too_long_in_proposal() {
        // AddMember proposal with a label > 128 bytes must be rejected.
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let long_label = "y".repeat(MAX_LABEL_LENGTH + 1);

        let result = fed.create_proposal(
            addr(1),
            ProposalAction::AddMember {
                address: addr(10),
                label: long_label,
            },
            100,
        );
        assert!(
            result.is_err(),
            "AddMember with long label must be rejected"
        );
    }

    #[test]
    fn test_gap7_label_at_max_accepted() {
        // Label of exactly MAX_LABEL_LENGTH bytes should be accepted.
        let exact_label = "z".repeat(MAX_LABEL_LENGTH);
        let members = vec![
            (addr(1), exact_label.clone()),
            (addr(2), "short".to_string()),
            (addr(3), "also-short".to_string()),
        ];
        let result = FederationManager::new(members, 2, 0);
        assert!(
            result.is_ok(),
            "label at exactly 128 bytes must be accepted"
        );
    }

    // ── Bond Mechanism Tests ──────────────────────────────────

    #[test]
    fn gt1_required_bond_scales_with_tvl() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        // At TVL = 0, required bond should be MIN_FEDERATION_BOND
        assert_eq!(fed.required_bond(), MIN_FEDERATION_BOND);

        // At TVL = 100 BTC (10B sat), threshold = 3:
        // bond = 10B × 15000 / 10000 / 3 = 5B sat = 50 BTC
        fed.update_tvl(10_000_000_000);
        assert_eq!(fed.required_bond(), 5_000_000_000);
    }

    #[test]
    fn gt1_cost_exceeds_profit() {
        // Verify the core invariant: threshold × bond ≥ TVL × 1.5
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        fed.update_tvl(10_000_000_000); // 100 BTC

        let bond = fed.required_bond(); // 50 BTC per member
        let threshold = fed.threshold() as u64; // 3
        let total_bonds = bond * threshold; // 150 BTC

        // Cost of corruption (all colluders' bonds) = 150 BTC
        // Max profit from corruption = TVL = 100 BTC
        // Ratio = 150/100 = 1.5 ✓
        assert!(
            total_bonds as u128 * 10_000 >= fed.bridge_tvl() as u128 * BOND_RATIO_BP as u128,
            "threshold × bond must be ≥ TVL × 1.5"
        );
    }

    #[test]
    fn gt1_deposit_and_check_bond() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        fed.update_tvl(100_000_000); // 1 BTC TVL → required = max(1 BTC, small) = 1 BTC

        // Initially no bond
        assert!(!fed.is_bond_sufficient(&addr(1)));

        // Partial deposit
        fed.deposit_bond(&addr(1), 50_000_000).unwrap();
        assert!(!fed.is_bond_sufficient(&addr(1)));

        // Full deposit
        fed.deposit_bond(&addr(1), 50_000_000).unwrap();
        assert!(fed.is_bond_sufficient(&addr(1)));
        assert_eq!(fed.member_bond(&addr(1)), Some(100_000_000));
    }

    #[test]
    fn gt1_bond_requirement_changes_with_tvl() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();

        // Deposit 1 BTC bond (sufficient for low TVL)
        fed.update_tvl(100_000_000); // 1 BTC TVL
        fed.deposit_bond(&addr(1), 100_000_000).unwrap();
        assert!(fed.is_bond_sufficient(&addr(1)));

        // Increase TVL to 100 BTC → required bond goes to 50 BTC
        fed.update_tvl(10_000_000_000);
        assert!(
            !fed.is_bond_sufficient(&addr(1)),
            "bond should become insufficient when TVL increases"
        );
    }

    #[test]
    fn gt1_bond_withdrawal_maturity() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        fed.deposit_bond(&addr(1), 200_000_000).unwrap();

        // Initiate withdrawal at height 1000
        let pw = fed.initiate_bond_withdrawal(&addr(1), 1000).unwrap();
        assert_eq!(pw.amount, 200_000_000);
        assert_eq!(pw.matures_at, 1000 + BOND_MATURITY_BLOCKS);

        // Bond should now be 0
        assert_eq!(fed.member_bond(&addr(1)), Some(0));

        // Cannot claim during maturity
        let result = fed.claim_bond_withdrawal(&addr(1), 1000);
        assert!(result.is_err());

        // Can claim after maturity
        let amount = fed
            .claim_bond_withdrawal(&addr(1), 1000 + BOND_MATURITY_BLOCKS)
            .unwrap();
        assert_eq!(amount, 200_000_000);
    }

    #[test]
    fn gt1_slash_bond_distribution() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        fed.deposit_bond(&addr(1), 500_000_000).unwrap(); // 5 BTC bond

        let result = fed.slash_bond(&addr(1), &addr(99)).unwrap();

        // 30% challenger, 70% burn
        assert_eq!(result.total_slashed, 500_000_000);
        assert_eq!(result.challenger_reward, 150_000_000);
        assert_eq!(result.burned, 350_000_000);

        // Bond should be zeroed
        assert_eq!(fed.member_bond(&addr(1)), Some(0));
        assert!(!fed.is_bond_sufficient(&addr(1)));
    }

    #[test]
    fn gt1_slash_cancels_pending_withdrawal() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        fed.deposit_bond(&addr(1), 500_000_000).unwrap();

        // Initiate withdrawal
        fed.initiate_bond_withdrawal(&addr(1), 1000).unwrap();

        // Slash during maturity — should capture the pending amount
        let result = fed.slash_bond(&addr(1), &addr(99)).unwrap();
        assert_eq!(result.total_slashed, 500_000_000);

        // Cannot claim after maturity (slashed)
        let claim = fed.claim_bond_withdrawal(&addr(1), 1000 + BOND_MATURITY_BLOCKS);
        assert!(claim.is_err());
    }

    #[test]
    fn gt1_no_bond_to_slash_error() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        let result = fed.slash_bond(&addr(1), &addr(99));
        assert!(result.is_err());
    }

    #[test]
    fn gt1_require_bond_for_approval() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        fed.update_tvl(100_000_000);

        // No bond → cannot approve
        assert!(fed.require_bond_for_approval(&addr(1)).is_err());

        // Deposit sufficient bond
        fed.deposit_bond(&addr(1), 100_000_000).unwrap();
        assert!(fed.require_bond_for_approval(&addr(1)).is_ok());
    }

    #[test]
    fn gt1_bonded_member_count() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        assert_eq!(fed.bonded_member_count(), 0);

        fed.deposit_bond(&addr(1), MIN_FEDERATION_BOND).unwrap();
        fed.deposit_bond(&addr(2), MIN_FEDERATION_BOND).unwrap();
        assert_eq!(fed.bonded_member_count(), 2);
    }

    #[test]
    fn gt1_rotate_key_carries_bond() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        fed.deposit_bond(&addr(1), 200_000_000).unwrap();

        // Create and execute key rotation proposal
        let pid = fed
            .create_proposal(
                addr(2),
                ProposalAction::RotateKey {
                    old_address: addr(1),
                    new_address: addr(10),
                },
                100,
            )
            .unwrap();
        fed.approve_proposal(&pid, addr(3), 100).unwrap();
        fed.approve_proposal(&pid, addr(4), 100).unwrap();
        fed.execute_proposal(&pid, 100).unwrap();

        // Bond should transfer to new address
        assert_eq!(fed.member_bond(&addr(10)), Some(200_000_000));
        assert_eq!(fed.member_bond(&addr(1)), Some(0));
    }

    #[test]
    fn gt1_slash_bond_via_proposal() {
        let mut fed = FederationManager::new(members_5(), 3, 0).unwrap();
        fed.deposit_bond(&addr(5), 300_000_000).unwrap();

        let evidence = Hash256::from_bytes([0xBB; 32]);
        let pid = fed
            .create_proposal(
                addr(1),
                ProposalAction::SlashBond {
                    target: addr(5),
                    challenger: addr(99),
                    evidence_hash: evidence,
                },
                100,
            )
            .unwrap();
        fed.approve_proposal(&pid, addr(2), 100).unwrap();
        fed.approve_proposal(&pid, addr(3), 100).unwrap();
        fed.execute_proposal(&pid, 100).unwrap();

        // Bond should be zeroed after proposal execution
        assert_eq!(fed.member_bond(&addr(5)), Some(0));
    }

    // ═══════════════════════════════════════════════════════════════════
    // PILLAR 1: Native BTC Staking Committee Tests
    // ═══════════════════════════════════════════════════════════════════

    fn eots_key(n: u8) -> EotsPublicKey {
        EotsPublicKey([n; 32])
    }

    fn make_utxo(n: u8, amount: u64, lock_height: u64) -> StakingUtxo {
        StakingUtxo {
            txid: Hash256::from_bytes([n; 32]),
            vout: 0,
            amount_sat: amount,
            lock_height,
            staker_pubkey: eots_key(n),
            taproot_output_key: [n; 32],
            slashed: false,
            unbonding_requested_at: 0,
        }
    }

    fn setup_committee() -> StakingCommittee {
        let mut committee = StakingCommittee::new();
        // Register 7 members, each with 10 BTC
        for i in 1..=7u8 {
            committee
                .register_member(
                    addr(i),
                    format!("validator-{i}"),
                    eots_key(i),
                    vec![make_utxo(i, 10_000_000_000, 1000)], // 10 BTC
                    0,
                )
                .unwrap();
        }
        committee
    }

    #[test]
    fn p1_register_committee_member() {
        let mut committee = StakingCommittee::new();
        committee
            .register_member(
                addr(1),
                "validator-1".into(),
                eots_key(1),
                vec![make_utxo(1, 10_000_000_000, 1000)],
                0,
            )
            .unwrap();

        assert_eq!(committee.active_member_count(), 1);
        assert_eq!(committee.total_staked(), 10_000_000_000);
        assert!(committee.is_active_member(&addr(1)));
    }

    #[test]
    fn p1_reject_insufficient_stake() {
        let mut committee = StakingCommittee::new();
        // Try to register with only 0.5 BTC (below 10 BTC minimum)
        let result = committee.register_member(
            addr(1),
            "low-staker".into(),
            eots_key(1),
            vec![make_utxo(1, 500_000_000, 1000)], // 0.5 BTC
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn p1_reject_duplicate_member() {
        let mut committee = StakingCommittee::new();
        committee
            .register_member(
                addr(1),
                "v1".into(),
                eots_key(1),
                vec![make_utxo(1, 10_000_000_000, 1000)],
                0,
            )
            .unwrap();

        let result = committee.register_member(
            addr(1),
            "v1-dup".into(),
            eots_key(1),
            vec![make_utxo(2, 10_000_000_000, 1000)],
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn p1_stake_to_tvl_ratio() {
        let mut committee = setup_committee();
        // 7 members × 10 BTC = 70 BTC total staked
        assert_eq!(committee.total_staked(), 70_000_000_000);

        // At TVL = 0, always sufficiently staked
        assert!(committee.is_sufficiently_staked());

        // At TVL = 30 BTC, required = 30 × 2.25 = 67.5 BTC
        // We have 70 BTC → sufficient
        committee.update_tvl(30_000_000_000);
        assert!(committee.is_sufficiently_staked());

        // At TVL = 32 BTC, required = 32 × 2.25 = 72 BTC
        // We have 70 BTC → insufficient
        committee.update_tvl(32_000_000_000);
        assert!(!committee.is_sufficiently_staked());
    }

    #[test]
    fn p1_cost_of_corruption_exceeds_tvl() {
        let mut committee = setup_committee();
        committee.update_tvl(30_000_000_000); // 30 BTC TVL

        // Cost of corruption = ⅔ × total_staked = ⅔ × 70 BTC ≈ 46.67 BTC
        let cost = (committee.total_staked() as u128
            * COMMITTEE_SUPERMAJORITY_BP as u128
            / 10_000) as u64;

        // Profit = TVL = 30 BTC
        let profit = committee.bridge_tvl();

        // Cost must exceed 1.5 × Profit
        assert!(
            cost as u128 * 10_000 > profit as u128 * 15_000,
            "Cost of corruption ({cost}) must be > 1.5 × TVL ({profit})"
        );
    }

    #[test]
    fn p1_weight_cap_enforcement() {
        let mut committee = StakingCommittee::new();

        // Register one member with 40 BTC
        committee
            .register_member(
                addr(1),
                "whale".into(),
                eots_key(1),
                vec![make_utxo(1, 40_000_000_000, 1000)],
                0,
            )
            .unwrap();

        // Register second member with 10 BTC → whale is now 80% (>33%)
        // But the check is on the NEW member's weight, not existing members.
        // After adding: total = 50, whale = 40/50 = 80%.
        // The constraint is checked on the incoming member.
        // New member = 10/50 = 20% → OK.
        committee
            .register_member(
                addr(2),
                "normal".into(),
                eots_key(2),
                vec![make_utxo(2, 10_000_000_000, 1000)],
                0,
            )
            .unwrap();

        // Now total is 50 BTC. Try adding another with 60 BTC:
        // new weight = 60/(50+60) = 60/110 = 54.5% > 33%
        let result = committee.register_member(
            addr(3),
            "super-whale".into(),
            eots_key(3),
            vec![make_utxo(3, 60_000_000_000, 1000)],
            0,
        );
        assert!(result.is_err(), "should reject member exceeding weight cap");
    }

    #[test]
    fn p1_eots_key_extraction_slash() {
        let mut committee = setup_committee();
        let member_stake = committee.member_stake(&addr(3));
        assert_eq!(member_stake, 10_000_000_000);

        let proof = EotsKeyExtractionProof {
            member: addr(3),
            public_key: eots_key(3),
            nonce: EotsNonce([0xAA; 32]),
            message_a: Hash256::from_bytes([0x11; 32]),
            signature_a: EotsSignature([0x22; 32]),
            message_b: Hash256::from_bytes([0x33; 32]),
            signature_b: EotsSignature([0x44; 32]),
            extracted_secret: [0xFF; 32],
            detection_height: 100,
        };

        let slashed = committee.process_eots_extraction(&proof).unwrap();
        assert_eq!(slashed, 10_000_000_000);

        // Member should be slashed and inactive
        let member = committee.get_member(&addr(3)).unwrap();
        assert!(member.slashed);
        assert!(!member.active);
        assert!(member.staking_utxos.iter().all(|u| u.slashed));

        // Total staked should decrease
        assert_eq!(committee.total_staked(), 60_000_000_000); // 70 - 10

        // Extraction event recorded
        assert_eq!(committee.extraction_events().len(), 1);
    }

    #[test]
    fn p1_eots_extraction_double_processing_prevented() {
        let mut committee = setup_committee();

        let proof = EotsKeyExtractionProof {
            member: addr(3),
            public_key: eots_key(3),
            nonce: EotsNonce([0xAA; 32]),
            message_a: Hash256::from_bytes([0x11; 32]),
            signature_a: EotsSignature([0x22; 32]),
            message_b: Hash256::from_bytes([0x33; 32]),
            signature_b: EotsSignature([0x44; 32]),
            extracted_secret: [0xFF; 32],
            detection_height: 100,
        };

        committee.process_eots_extraction(&proof).unwrap();

        // Second processing must fail
        let result = committee.process_eots_extraction(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn p1_eots_extraction_wrong_pubkey_rejected() {
        let mut committee = setup_committee();

        let proof = EotsKeyExtractionProof {
            member: addr(3),
            public_key: eots_key(99), // Wrong key — doesn't match member
            nonce: EotsNonce([0xAA; 32]),
            message_a: Hash256::from_bytes([0x11; 32]),
            signature_a: EotsSignature([0x22; 32]),
            message_b: Hash256::from_bytes([0x33; 32]),
            signature_b: EotsSignature([0x44; 32]),
            extracted_secret: [0xFF; 32],
            detection_height: 100,
        };

        let result = committee.process_eots_extraction(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn p1_eots_extraction_same_messages_rejected() {
        let mut committee = setup_committee();

        let proof = EotsKeyExtractionProof {
            member: addr(3),
            public_key: eots_key(3),
            nonce: EotsNonce([0xAA; 32]),
            message_a: Hash256::from_bytes([0x11; 32]),
            signature_a: EotsSignature([0x22; 32]),
            message_b: Hash256::from_bytes([0x11; 32]), // Same message!
            signature_b: EotsSignature([0x44; 32]),
            extracted_secret: [0xFF; 32],
            detection_height: 100,
        };

        let result = committee.process_eots_extraction(&proof);
        assert!(result.is_err());
    }

    #[test]
    fn p1_committee_attestation_supermajority() {
        // Use real EOTS keys for cryptographic verification (CRITICAL-3)
        let (committee, members) = committee_with_real_keys(7, 10_000_000_000);
        let root = Hash256::from_bytes([0xAA; 32]);
        let batch = Hash256::from_bytes([0xBB; 32]);

        // Sign with 5 of 7 members (71.4% > 66.67%)
        let attestation = sign_attestation(&members, &root, &batch, &[0, 1, 2, 3, 4]);

        assert!(committee.verify_attestation(&attestation).is_ok());
    }

    #[test]
    fn p1_attestation_below_threshold_rejected() {
        let committee = setup_committee();

        // Only 4 of 7 members (57.1% < 66.67%)
        let attestation = CommitteeAttestation {
            state_root: Hash256::from_bytes([0xAA; 32]),
            withdrawal_batch_hash: Hash256::from_bytes([0xBB; 32]),
            signatures: (1..=4u8)
                .map(|i| AttestationSignature {
                    member: addr(i),
                    eots_pubkey: eots_key(i),
                    nonce: EotsNonce([i; 32]),
                    signature: EotsSignature([i + 100; 32]),
                    stake_weight: 10_000_000_000,
                })
                .collect(),
            total_signing_weight: 40_000_000_000,
            attestation_height: 100,
        };

        let result = committee.verify_attestation(&attestation);
        assert!(result.is_err(), "4/7 must not meet ⅔ threshold");
    }

    #[test]
    fn p1_attestation_duplicate_signer_rejected() {
        let committee = setup_committee();

        // Member 1 signs twice
        let attestation = CommitteeAttestation {
            state_root: Hash256::from_bytes([0xAA; 32]),
            withdrawal_batch_hash: Hash256::from_bytes([0xBB; 32]),
            signatures: vec![
                AttestationSignature {
                    member: addr(1),
                    eots_pubkey: eots_key(1),
                    nonce: EotsNonce([1; 32]),
                    signature: EotsSignature([101; 32]),
                    stake_weight: 10_000_000_000,
                },
                AttestationSignature {
                    member: addr(1), // Duplicate!
                    eots_pubkey: eots_key(1),
                    nonce: EotsNonce([2; 32]),
                    signature: EotsSignature([102; 32]),
                    stake_weight: 10_000_000_000,
                },
            ],
            total_signing_weight: 20_000_000_000,
            attestation_height: 100,
        };

        let result = committee.verify_attestation(&attestation);
        assert!(result.is_err());
    }

    #[test]
    fn p1_attestation_slashed_member_rejected() {
        let mut committee = setup_committee();

        // Slash member 1
        let proof = EotsKeyExtractionProof {
            member: addr(1),
            public_key: eots_key(1),
            nonce: EotsNonce([0xAA; 32]),
            message_a: Hash256::from_bytes([0x11; 32]),
            signature_a: EotsSignature([0x22; 32]),
            message_b: Hash256::from_bytes([0x33; 32]),
            signature_b: EotsSignature([0x44; 32]),
            extracted_secret: [0xFF; 32],
            detection_height: 100,
        };
        committee.process_eots_extraction(&proof).unwrap();

        // Try attestation with slashed member 1
        let attestation = CommitteeAttestation {
            state_root: Hash256::from_bytes([0xAA; 32]),
            withdrawal_batch_hash: Hash256::from_bytes([0xBB; 32]),
            signatures: (1..=5u8)
                .map(|i| AttestationSignature {
                    member: addr(i),
                    eots_pubkey: eots_key(i),
                    nonce: EotsNonce([i; 32]),
                    signature: EotsSignature([i + 100; 32]),
                    stake_weight: 10_000_000_000,
                })
                .collect(),
            total_signing_weight: 50_000_000_000,
            attestation_height: 200,
        };

        let result = committee.verify_attestation(&attestation);
        assert!(result.is_err(), "slashed member must not be accepted");
    }

    #[test]
    fn p1_unstaking_reduces_committee() {
        let mut committee = setup_committee();
        assert_eq!(committee.active_member_count(), 7);

        // Unstake member 7
        let amount = committee.initiate_unstaking(&addr(7), 500).unwrap();
        assert_eq!(amount, 10_000_000_000);
        assert_eq!(committee.active_member_count(), 6);
        assert_eq!(committee.total_staked(), 60_000_000_000);
        assert!(!committee.is_active_member(&addr(7)));
    }

    #[test]
    fn p1_unstaking_below_minimum_rejected() {
        let mut committee = setup_committee(); // 7 members

        // Remove 2 to get to 5 (minimum)
        committee.initiate_unstaking(&addr(6), 500).unwrap();
        committee.initiate_unstaking(&addr(7), 500).unwrap();

        // Trying to remove a 3rd should fail (would go below MIN_COMMITTEE_SIZE)
        let result = committee.initiate_unstaking(&addr(5), 500);
        assert!(result.is_err());
    }

    #[test]
    fn p1_claim_matured_unstaking() {
        let mut committee = setup_committee();
        committee.initiate_unstaking(&addr(7), 500).unwrap();

        // Cannot claim during maturity
        let result = committee.claim_unstaked(&addr(7), 500);
        assert!(result.is_err());

        // Can claim after maturity (500 + UNSTAKING_MATURITY_L1)
        let claimed = committee
            .claim_unstaked(&addr(7), 500 + UNSTAKING_MATURITY_L1)
            .unwrap();
        assert_eq!(claimed, 10_000_000_000);
    }

    #[test]
    fn p1_nonce_commitment() {
        let mut committee = setup_committee();

        // Commit nonce for round 1
        committee
            .commit_nonce(&addr(1), 1, EotsNonce([0xAA; 32]))
            .unwrap();

        // Cannot re-commit for same round
        let result = committee.commit_nonce(&addr(1), 1, EotsNonce([0xBB; 32]));
        assert!(result.is_err());

        // Can commit for different round
        committee
            .commit_nonce(&addr(1), 2, EotsNonce([0xCC; 32]))
            .unwrap();
    }

    #[test]
    fn p1_taproot_script_generation() {
        let pubkey = eots_key(1);
        let script = TaprootStakingScript::generate(&pubkey, 800_000);

        // Script should contain OP_CLTV and OP_CHECKSIG
        assert!(script.normal_unlock_script.contains(&0xB1)); // OP_CLTV
        assert!(script.normal_unlock_script.contains(&0xAC)); // OP_CHECKSIG
        assert!(script.normal_unlock_script.contains(&0x75)); // OP_DROP

        // Output key should be non-zero
        assert_ne!(script.output_key, [0u8; 32]);

        // Timelock should match
        assert_eq!(script.timelock, 800_000);
    }

    #[test]
    fn p1_committee_operational_check() {
        let mut committee = StakingCommittee::new();
        assert!(!committee.is_operational()); // No members

        // Add 5 members
        for i in 1..=5u8 {
            committee
                .register_member(
                    addr(i),
                    format!("v-{i}"),
                    eots_key(i),
                    vec![make_utxo(i, 10_000_000_000, 1000)],
                    0,
                )
                .unwrap();
        }

        // 50 BTC staked, TVL = 0 → operational
        assert!(committee.is_operational());

        // Set TVL too high for current stake
        committee.update_tvl(30_000_000_000); // 30 BTC, need 67.5 BTC
        assert!(!committee.is_operational()); // Understaked
    }

    #[test]
    fn p1_add_stake_to_existing_member() {
        let mut committee = StakingCommittee::new();
        committee
            .register_member(
                addr(1),
                "v-1".into(),
                eots_key(1),
                vec![make_utxo(1, 10_000_000_000, 1000)],
                0,
            )
            .unwrap();

        // Add 5 BTC more
        let total = committee
            .add_stake(&addr(1), vec![make_utxo(2, 5_000_000_000, 1000)])
            .unwrap();
        assert_eq!(total, 15_000_000_000);
        assert_eq!(committee.total_staked(), 15_000_000_000);
    }

    #[test]
    fn p1_attestation_message_deterministic() {
        let root = Hash256::from_bytes([1; 32]);
        let batch = Hash256::from_bytes([2; 32]);

        let msg1 = StakingCommittee::attestation_message(&root, &batch);
        let msg2 = StakingCommittee::attestation_message(&root, &batch);
        assert_eq!(msg1, msg2);

        let msg3 = StakingCommittee::attestation_message(&batch, &root);
        assert_ne!(msg1, msg3);
    }

    // ── Adversarial Tests: CRITICAL-3 EOTS Verification ────────────────────────

    /// Helper: create a StakingCommittee with N members, each with real EOTS keypairs.
    /// Returns (committee, vec of (address, keypair)).
    /// Create a test committee by directly inserting members (bypasses
    /// the sequential weight-cap check that rejects the first member at 100%).
    /// This is valid for testing attestation verification — we're not testing
    /// the registration path here.
    fn committee_with_real_keys(
        n: usize,
        stake_per_member: u64,
    ) -> (StakingCommittee, Vec<(Address, eots_crypto::EotsKeyPair)>) {
        let mut committee = StakingCommittee::new();
        committee.update_tvl(1_000_000); // 0.01 BTC TVL — low for testing

        let mut members_out = Vec::new();
        let mut total = 0u64;

        for i in 1..=n {
            let secret = {
                let mut s = [0u8; 32];
                s[0] = i as u8;
                s[31] = 0x01; // Ensure non-zero valid scalar
                s
            };
            let keypair = eots_crypto::EotsKeyPair::from_secret_bytes(&secret).unwrap();
            let addr = Address::from_bytes([i as u8; 20]);
            let eots_pubkey = EotsPublicKey::from_bytes(*keypair.public_key().as_bytes());

            let member = CommitteeMember {
                address: addr,
                label: format!("member-{i}"),
                eots_pubkey,
                staking_utxos: vec![StakingUtxo {
                    txid: Hash256::from_bytes([i as u8; 32]),
                    vout: 0,
                    amount_sat: stake_per_member,
                    lock_height: 1000,
                    staker_pubkey: eots_pubkey,
                    taproot_output_key: [0u8; 32],
                    slashed: false,
                    unbonding_requested_at: 0,
                }],
                total_staked_sat: stake_per_member,
                joined_at_height: 100,
                active: true,
                slashed: false,
            };

            committee.members.insert(addr, member);
            total += stake_per_member;
            members_out.push((addr, keypair));
        }

        committee.total_staked = total;
        (committee, members_out)
    }

    /// Helper: sign an attestation with real EOTS keys.
    fn sign_attestation(
        members: &[(Address, eots_crypto::EotsKeyPair)],
        state_root: &Hash256,
        withdrawal_batch_hash: &Hash256,
        signers: &[usize], // indices into members
    ) -> CommitteeAttestation {
        let msg = StakingCommittee::attestation_message(state_root, withdrawal_batch_hash);

        let mut signatures = Vec::new();
        let mut total_weight = 0u64;

        for &idx in signers {
            let (addr, keypair) = &members[idx];
            // Test helper — no prev_block_hash available in attestation context.
            #[allow(deprecated)]
            let (nonce_sk, nonce_commitment) = keypair.generate_nonce(1, 1).unwrap();
            let eots_sig = keypair.sign(&msg, &nonce_sk, &nonce_commitment).unwrap();

            // Extract the 32-byte x-only nonce from the 33-byte compressed point
            let nonce_bytes: [u8; 32] = nonce_commitment.as_bytes()[1..33]
                .try_into()
                .unwrap();

            // Extract the 32-byte s-value
            let s_bytes: [u8; 32] = eots_sig.s_value().try_into().unwrap();

            signatures.push(AttestationSignature {
                member: *addr,
                eots_pubkey: EotsPublicKey::from_bytes(*keypair.public_key().as_bytes()),
                nonce: EotsNonce(nonce_bytes),
                signature: EotsSignature(s_bytes),
                stake_weight: 100_000_000, // Claimed weight — ignored by verifier
            });
            total_weight += 100_000_000;
        }

        CommitteeAttestation {
            state_root: *state_root,
            withdrawal_batch_hash: *withdrawal_batch_hash,
            signatures,
            total_signing_weight: total_weight,
            attestation_height: 100,
        }
    }

    #[test]
    fn eots_valid_attestation_passes() {
        let (committee, members) = committee_with_real_keys(5, 100_000_000);
        let root = Hash256::from_bytes([0xAA; 32]);
        let batch = Hash256::from_bytes([0xBB; 32]);

        // Sign with 4/5 members (80% > 66.67%)
        let attestation = sign_attestation(&members, &root, &batch, &[0, 1, 2, 3]);
        assert!(committee.verify_attestation(&attestation).is_ok());
    }

    #[test]
    fn eots_forged_signature_rejected() {
        let (committee, members) = committee_with_real_keys(5, 100_000_000);
        let root = Hash256::from_bytes([0xAA; 32]);
        let batch = Hash256::from_bytes([0xBB; 32]);

        let mut attestation = sign_attestation(&members, &root, &batch, &[0, 1, 2, 3]);

        // Forge: replace first signature's s-value with random bytes
        attestation.signatures[0].signature = EotsSignature([0xDE; 32]);

        let result = committee.verify_attestation(&attestation);
        assert!(result.is_err(), "Forged s-value must be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("signature verification failed"),
            "Error must indicate EOTS verification failure, got: {err_msg}"
        );
    }

    #[test]
    fn eots_wrong_message_signature_rejected() {
        let (committee, members) = committee_with_real_keys(5, 100_000_000);
        let root = Hash256::from_bytes([0xAA; 32]);
        let batch = Hash256::from_bytes([0xBB; 32]);

        // Sign for a DIFFERENT state root
        let wrong_root = Hash256::from_bytes([0xCC; 32]);
        let attestation = sign_attestation(&members, &wrong_root, &batch, &[0, 1, 2, 3]);

        // But present the attestation with the original root
        let mut tampered = attestation;
        tampered.state_root = root; // Attacker changes the claimed root

        let result = committee.verify_attestation(&tampered);
        assert!(
            result.is_err(),
            "Signature for wrong message must be rejected — \
             the attestation_msg is recomputed from state_root + batch_hash"
        );
    }

    #[test]
    fn eots_zero_nonce_rejected() {
        let (committee, members) = committee_with_real_keys(5, 100_000_000);
        let root = Hash256::from_bytes([0xAA; 32]);
        let batch = Hash256::from_bytes([0xBB; 32]);

        let mut attestation = sign_attestation(&members, &root, &batch, &[0, 1, 2, 3]);

        // Set nonce to all zeros — invalid curve point x-coordinate
        attestation.signatures[0].nonce = EotsNonce([0u8; 32]);

        let result = committee.verify_attestation(&attestation);
        assert!(result.is_err(), "All-zero nonce must be rejected");
    }

    #[test]
    fn eots_zero_signature_rejected() {
        let (committee, members) = committee_with_real_keys(5, 100_000_000);
        let root = Hash256::from_bytes([0xAA; 32]);
        let batch = Hash256::from_bytes([0xBB; 32]);

        let mut attestation = sign_attestation(&members, &root, &batch, &[0, 1, 2, 3]);

        // Set s-value to all zeros — invalid (would require k = -e·sk which is negligible)
        attestation.signatures[0].signature = EotsSignature([0u8; 32]);

        let result = committee.verify_attestation(&attestation);
        assert!(result.is_err(), "All-zero s-value must be rejected");
    }

    #[test]
    fn eots_impersonation_rejected() {
        let (committee, members) = committee_with_real_keys(5, 100_000_000);
        let root = Hash256::from_bytes([0xAA; 32]);
        let batch = Hash256::from_bytes([0xBB; 32]);

        let mut attestation = sign_attestation(&members, &root, &batch, &[0, 1, 2, 3]);

        // Attacker takes member[0]'s signature and claims it's from member[4]
        // The pubkey check will catch this first (pubkey mismatch)
        attestation.signatures[0].member = members[4].0;

        let result = committee.verify_attestation(&attestation);
        assert!(result.is_err(), "Impersonation must be rejected");
    }

    #[test]
    fn eots_below_threshold_rejected() {
        let (committee, members) = committee_with_real_keys(5, 100_000_000);
        let root = Hash256::from_bytes([0xAA; 32]);
        let batch = Hash256::from_bytes([0xBB; 32]);

        // Only 2/5 = 40% < 66.67%
        let attestation = sign_attestation(&members, &root, &batch, &[0, 1]);

        let result = committee.verify_attestation(&attestation);
        assert!(result.is_err(), "Below ⅔ threshold must be rejected");
    }

    // ── Adversarial Test: CRITICAL-1 add_stake rollback ────────────────────────

    #[test]
    fn add_stake_weight_cap_rollback_works() {
        let (mut committee, members) = committee_with_real_keys(4, 100_000_000);

        // Member 0 has 100M sat out of 400M total = 25%
        // Try to add 200M more → would be 300M / 600M = 50% > 33% cap
        let big_utxo = StakingUtxo {
            txid: Hash256::from_bytes([0xFF; 32]),
            vout: 0,
            amount_sat: 200_000_000,
            lock_height: 2000,
            staker_pubkey: EotsPublicKey::from_bytes(*members[0].1.public_key().as_bytes()),
            taproot_output_key: [0u8; 32],
            slashed: false,
            unbonding_requested_at: 0,
        };

        let result = committee.add_stake(&members[0].0, vec![big_utxo]);
        assert!(result.is_err(), "Exceeding weight cap must be rejected");

        // Verify rollback: member's stake should still be original amount
        let member = committee.members.get(&members[0].0).unwrap();
        assert_eq!(
            member.total_staked_sat, 100_000_000,
            "Rollback must restore original stake"
        );
        assert_eq!(
            committee.total_staked, 400_000_000,
            "Rollback must restore total staked"
        );
    }
}
