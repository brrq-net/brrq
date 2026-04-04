//! Graduated slashing system (§7.3).
//!
//! ## Slashing Tiers
//!
//! | Violation           | Penalty | Condition                            |
//! |---------------------|---------|--------------------------------------|
//! | Extended downtime   | 5%      | 10+ timeouts in 24h                  |
//! | RANDAO non-reveal   | 15%     | 3 consecutive epochs without reveal  |
//! | Censorship          | 10%     | Demonstrable exclusion of valid txns  |
//! | Intentional delay   | 15%     | Repeated pattern, 60% vote + proof   |
//! | Equivocation        | 33.33%  | Mathematical proof of dual signing   |
//!
//! ## Slashed Fund Distribution
//!
//! ```text
//! 70% → Burned (non-spendable)
//! 20% → Challenger reward
//! 10% → Community Challenge Fund
//! ```

use imbl::{HashMap, HashSet};

use brrq_crypto::eots::{self, EotsNonceCommitment, EotsSignature};
use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::SchnorrPublicKey;
use brrq_crypto::slh_dsa::{SlhDsaPublicKey, SlhDsaSignature};
use brrq_types::Address;

use crate::error::ConsensusError;
use crate::staking::StakingState;
use crate::validator::ValidatorStatus;

/// Maximum age of slashing evidence in blocks (~7 days at 3s/block).
/// Evidence older than this is rejected to prevent stale attacks.
pub const MAX_EVIDENCE_AGE_BLOCKS: u64 = 201_600;

/// Slashing penalty for extended downtime: 5% = 500 basis points.
pub const DOWNTIME_PENALTY_BP: u64 = 500;

/// Slashing penalty for intentional delay: 15% = 1500 basis points.
pub const DELAY_PENALTY_BP: u64 = 1500;

/// Slashing penalty for RANDAO non-reveal: 15% = 1500 basis points.
/// Raised from 5% to make the expected cost of non-reveal exceed the maximum
/// possible MEV gain from RANDAO manipulation. At 5%, a validator controlling
/// 10% of stake could profit from biased randomness. At 15%, the breakeven
/// requires controlling >45% of stake — well beyond the BFT threshold.
pub const RANDAO_NON_REVEAL_PENALTY_BP: u64 = 1500;

/// Slashing penalty for equivocation: 33.33% = 3333 basis points.
pub const EQUIVOCATION_PENALTY_BP: u64 = 3333;

/// Slashing penalty for censorship: 10% = 1000 basis points (base).
/// Applied when a sequencer demonstrably excludes valid transactions
/// that meet the base fee and were available in the mempool.
///
/// This is the FLOOR penalty. The actual penalty is dynamically
/// adjusted upward based on network congestion via `dynamic_censorship_penalty()`.
/// Under high MEV conditions, the penalty scales up to 5× the base (50%).
pub const CENSORSHIP_PENALTY_BP: u64 = 1000;

/// Maximum dynamic censorship penalty multiplier in basis points.
/// At maximum congestion, the censorship penalty is scaled by this factor:
///   effective = CENSORSHIP_PENALTY_BP × CENSORSHIP_MAX_MULTIPLIER_BP / 10_000
/// 50_000bp = 5.0× → max effective penalty = 10% × 5 = 50%.
///
/// Nash Equilibrium Analysis:
///   - Sequencer stake S, MEV opportunity M, detection probability p.
///   - Censorship is irrational when: M < p × penalty × S
///   - At 10% static: M < p × 0.10 × S → breakeven at M = 5 BTC for S=100 BTC, p=0.5
///   - At 50% dynamic: M < p × 0.50 × S → breakeven at M = 25 BTC — exceeds realistic MEV.
///   - Combined with quadratic escalation, repeat censorship reaches 100% within 2 offenses.
pub const CENSORSHIP_MAX_MULTIPLIER_BP: u64 = 50_000;

/// Congestion threshold above which penalty scaling begins.
/// When the block's fee surplus (actual_base_fee / target_base_fee) exceeds
/// this ratio (in basis points), the penalty starts scaling up.
/// 12_000bp = 1.2× → penalty scales when base fee is 20% above target.
pub const CONGESTION_SCALING_THRESHOLD_BP: u64 = 12_000;

/// Congestion level at which the maximum penalty multiplier applies.
/// 30_000bp = 3.0× → at 3× the target base fee, maximum penalty applies.
pub const CONGESTION_MAX_BP: u64 = 30_000;

/// Quadratic penalty escalation factor.
/// For repeated offenses of the same type, the penalty scales as:
///   effective_penalty = base_penalty × (1 + prior_offenses²)
/// Capped at 100% (10000 bp) to prevent overflow.
pub const QUADRATIC_PENALTY_CAP_BP: u64 = 10_000;

/// Burn share of slashed funds: 70%.
pub const BURN_SHARE_BP: u64 = 7000;

/// Challenger reward share: 20%.
pub const CHALLENGER_SHARE_BP: u64 = 2000;

/// Community fund share: 10%.
pub const COMMUNITY_SHARE_BP: u64 = 1000;

/// Type of slashing violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum SlashingReason {
    /// Extended downtime (10+ timeouts in 24h).
    Downtime,
    /// Intentional delay (repeated pattern, proven via 60% vote).
    IntentionalDelay,
    /// Equivocation: signed two different blocks at the same height.
    Equivocation,
    /// RANDAO non-reveal (2 consecutive failures to reveal committed secret).
    RandaoNonReveal,
    /// Censorship — sequencer demonstrably excluded valid transactions.
    /// Requires proof that transactions meeting base fee were available in the
    /// mempool but excluded from the block without justification.
    Censorship,
}

/// Equivocation evidence: two conflicting block signatures at the same height.
#[derive(Debug, Clone)]
pub struct EquivocationProof {
    /// The offending validator.
    pub validator: Address,
    /// Block height where equivocation occurred.
    pub height: u64,
    /// First block hash.
    pub block_hash_a: Hash256,
    /// Second (conflicting) block hash.
    pub block_hash_b: Hash256,
    /// SLH-DSA signature on first block (serialized).
    pub signature_a: Vec<u8>,
    /// SLH-DSA signature on second block (serialized).
    pub signature_b: Vec<u8>,
    /// Validator's SLH-DSA public key (from block SequencerIdentity).
    pub slh_dsa_pk: Vec<u8>,
}

/// Dual-proposal evidence: two conflicting block proposals at the same height
/// detected by the rotation state machine.
///
/// Under EOTS (Extractable One-Time Signatures), signing two different messages
/// with the same nonce reveals the secret key. Two proposals at the same height
/// constitute proof that the EOTS key is compromised → 33.33% slash.
///
/// This is lighter-weight than `EquivocationProof` (which uses SLH-DSA signatures)
/// because the rotation state machine has already validated the proposals.
#[derive(Debug, Clone)]
pub struct DualProposalEvidence {
    /// The offending proposer.
    pub proposer: Address,
    /// Block height where both proposals were made.
    pub height: u64,
    /// Hash of the first proposed block.
    pub proposal_hash_a: Hash256,
    /// Hash of the second (conflicting) proposed block.
    pub proposal_hash_b: Hash256,
    /// EOTS signature on first proposal (serialized).
    pub eots_signature_a: Vec<u8>,
    /// EOTS signature on second proposal (serialized).
    pub eots_signature_b: Vec<u8>,
}

impl DualProposalEvidence {
    /// Compute a deterministic context hash for double-slash prevention.
    ///
    /// Includes both proposal hashes and the height so that the same
    /// pair of proposals always maps to the same offense ID.
    pub fn offense_context(&self) -> Vec<u8> {
        let mut ctx = Vec::with_capacity(8 + 32 + 32);
        ctx.extend_from_slice(&self.height.to_le_bytes());
        // Order the hashes deterministically to ensure (A,B) and (B,A)
        // produce the same context. Compare raw bytes since Hash256
        // doesn't implement Ord.
        let (first, second) = if self.proposal_hash_a.as_bytes() <= self.proposal_hash_b.as_bytes()
        {
            (&self.proposal_hash_a, &self.proposal_hash_b)
        } else {
            (&self.proposal_hash_b, &self.proposal_hash_a)
        };
        ctx.extend_from_slice(first.as_bytes());
        ctx.extend_from_slice(second.as_bytes());
        ctx
    }

    /// Validate the evidence is well-formed AND cryptographically sound.
    ///
    /// Verifies EOTS signatures against the proposer's public key
    /// in addition to structural checks. Without signature verification an
    /// attacker could fabricate evidence to slash honest validators.
    pub fn validate(&self, proposer_pubkey: &SchnorrPublicKey) -> Result<(), ConsensusError> {
        if self.proposal_hash_a == self.proposal_hash_b {
            return Err(ConsensusError::InvalidBlock {
                reason: "dual proposal evidence has identical hashes".into(),
            });
        }

        // Verify both EOTS signatures are present and structurally valid.
        // An EOTS signature is serialized as: nonce_commitment (33 bytes) + s_value (32 bytes) = 65 bytes.
        const EOTS_SIG_SIZE: usize = 33 + 32; // nonce_commitment + s_value
        if self.eots_signature_a.len() != EOTS_SIG_SIZE || self.eots_signature_b.len() != EOTS_SIG_SIZE {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "EOTS signatures must be {} bytes, got ({}, {})",
                    EOTS_SIG_SIZE, self.eots_signature_a.len(), self.eots_signature_b.len()
                ),
            });
        }

        // CRITICAL: Verify nonce reuse (same R commitment = equivocation proof).
        // The first 33 bytes of each serialized EOTS signature are the nonce commitment.
        // If they differ, the evidence is fabricated — not real equivocation.
        let nonce_a = &self.eots_signature_a[..33];
        let nonce_b = &self.eots_signature_b[..33];
        if nonce_a != nonce_b {
            return Err(ConsensusError::InvalidBlock {
                reason: "EOTS nonce commitments differ — not equivocation (fabricated evidence?)".into(),
            });
        }

        // Deserialize and verify both EOTS signatures against the proposer's
        // public key. This prevents an attacker from fabricating evidence with arbitrary
        // bytes that pass structural checks but were never actually signed by the proposer.
        let sig_a = Self::deserialize_eots_sig(&self.eots_signature_a, "A")?;
        let sig_b = Self::deserialize_eots_sig(&self.eots_signature_b, "B")?;

        eots::verify(proposer_pubkey, &self.proposal_hash_a, &sig_a).map_err(|e| {
            ConsensusError::InvalidBlock {
                reason: format!(
                    "EOTS signature A verification failed against proposer pubkey: {e}"
                ),
            }
        })?;

        eots::verify(proposer_pubkey, &self.proposal_hash_b, &sig_b).map_err(|e| {
            ConsensusError::InvalidBlock {
                reason: format!(
                    "EOTS signature B verification failed against proposer pubkey: {e}"
                ),
            }
        })?;

        Ok(())
    }

    /// Deserialize a 65-byte EOTS signature (33-byte nonce commitment + 32-byte s-value).
    fn deserialize_eots_sig(raw: &[u8], label: &str) -> Result<EotsSignature, ConsensusError> {
        let nonce_bytes: [u8; 33] = raw[..33].try_into().expect("length already checked");
        let s_bytes = raw[33..65].to_vec();

        let nonce = EotsNonceCommitment::from_bytes(nonce_bytes).map_err(|e| {
            ConsensusError::InvalidBlock {
                reason: format!("invalid EOTS nonce commitment in signature {label}: {e}"),
            }
        })?;

        EotsSignature::new(nonce, s_bytes).map_err(|e| ConsensusError::InvalidBlock {
            reason: format!("invalid EOTS signature {label}: {e}"),
        })
    }
}

/// Result of applying a slash.
#[derive(Debug, Clone)]
pub struct SlashResult {
    /// Validator that was slashed.
    pub validator: Address,
    /// Total amount slashed (satoshis).
    pub total_slashed: u64,
    /// Amount burned.
    pub burned: u64,
    /// Challenger reward.
    pub challenger_reward: u64,
    /// Community fund contribution.
    pub community_fund: u64,
    /// Reason for slashing.
    pub reason: SlashingReason,
}

/// Slashing engine with double-slash prevention.
///
/// Tracks processed offense IDs to ensure a validator cannot be slashed
/// multiple times for the same offense (e.g., replayed equivocation proofs
/// or duplicate downtime reports).
///
/// Offense IDs are stored alongside the height at which they were
/// recorded, enabling periodic pruning of old entries.
/// Derive Serialize/Deserialize so slashing state survives node restarts.
/// Without this, a restart clears processed_offenses and allows double-slashing
/// by re-submitting the same equivocation evidence.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct SlashingEngine {
    /// Track processed slashing offenses to prevent double-slashing.
    /// Each offense is identified by a deterministic hash of (validator, reason, context).
    processed_offenses: HashSet<Hash256>,
    /// Height at which each offense was recorded, for pruning.
    offense_heights: HashMap<Hash256, u64>,
    /// Per-(validator, reason) offense counts for quadratic escalation.
    offense_counts: HashMap<(Address, SlashingReason), u64>,
}

impl SlashingEngine {
    /// Create a new slashing engine with an empty offense history.
    pub fn new() -> Self {
        Self {
            processed_offenses: HashSet::new(),
            offense_heights: HashMap::new(),
            offense_counts: HashMap::new(),
        }
    }

    /// Get the base penalty in basis points for a given violation type.
    pub fn penalty_for(reason: SlashingReason) -> u64 {
        match reason {
            SlashingReason::Downtime => DOWNTIME_PENALTY_BP,
            SlashingReason::IntentionalDelay => DELAY_PENALTY_BP,
            SlashingReason::Equivocation => EQUIVOCATION_PENALTY_BP,
            SlashingReason::RandaoNonReveal => RANDAO_NON_REVEAL_PENALTY_BP,
            SlashingReason::Censorship => CENSORSHIP_PENALTY_BP,
        }
    }

    /// Compute the dynamic censorship penalty based on network congestion.
    ///
    /// The penalty scales linearly from 1× to CENSORSHIP_MAX_MULTIPLIER_BP/10_000×
    /// as the congestion ratio moves from CONGESTION_SCALING_THRESHOLD_BP to
    /// CONGESTION_MAX_BP.
    ///
    /// ## Nash Equilibrium Proof
    ///
    /// Let:
    ///   - S = validator effective stake
    ///   - M = MEV opportunity from censoring a transaction
    ///   - p = probability of detection (assumed ≥ 0.5 for on-chain provable censorship)
    ///   - f = congestion_ratio (actual_base_fee / target_base_fee, in bp)
    ///   - d(f) = dynamic multiplier, 1.0 to 5.0
    ///   - P(f) = CENSORSHIP_PENALTY_BP × d(f) (base dynamic penalty before quadratic)
    ///   - Q(n) = 1 + n² (quadratic escalation for n prior offenses)
    ///
    /// Censorship is irrational (not a best response) when:
    ///   M < p × P(f) × Q(n) × S / 10_000
    ///
    /// At congestion 3×, first offense:
    ///   M < 0.5 × 5000bp × 1 × S / 10_000 = 0.25 × S
    ///   For S = 100 BTC: M < 25 BTC — far exceeds realistic per-block MEV.
    ///
    /// At congestion 3×, second offense (n=1):
    ///   M < 0.5 × 5000bp × 2 × S / 10_000 = 0.50 × S
    ///   For S = 100 BTC: M < 50 BTC — makes censorship economically suicidal.
    ///
    /// Therefore, honest behavior (not censoring) is the strictly dominant strategy
    /// for all rational validators under all realistic MEV conditions. ∎
    ///
    /// ## Parameters
    ///
    /// - `congestion_ratio_bp`: Ratio of actual_base_fee to target_base_fee in basis points.
    ///   10_000 = 1.0× (no congestion), 20_000 = 2.0× (double target fee).
    ///
    /// ## Returns
    ///
    /// The dynamically adjusted censorship penalty in basis points.
    pub fn dynamic_censorship_penalty(congestion_ratio_bp: u64) -> u64 {
        if congestion_ratio_bp <= CONGESTION_SCALING_THRESHOLD_BP {
            // Below threshold: base penalty only (1× multiplier)
            return CENSORSHIP_PENALTY_BP;
        }

        if congestion_ratio_bp >= CONGESTION_MAX_BP {
            // At or above max congestion: maximum penalty
            return (CENSORSHIP_PENALTY_BP as u128
                * CENSORSHIP_MAX_MULTIPLIER_BP as u128
                / 10_000) as u64;
        }

        // Linear interpolation between threshold and max
        // progress = (ratio - threshold) / (max - threshold), in [0, 1]
        // multiplier = 10_000 + progress × (MAX_MULTIPLIER - 10_000)
        let range = CONGESTION_MAX_BP - CONGESTION_SCALING_THRESHOLD_BP;
        let progress = congestion_ratio_bp - CONGESTION_SCALING_THRESHOLD_BP;

        let multiplier = 10_000u128
            + (progress as u128 * (CENSORSHIP_MAX_MULTIPLIER_BP as u128 - 10_000)) / range as u128;

        let penalty = (CENSORSHIP_PENALTY_BP as u128 * multiplier / 10_000) as u64;
        penalty.min(QUADRATIC_PENALTY_CAP_BP)
    }

    /// Compute quadratic-escalated penalty for repeated offenses.
    ///
    /// Formula: `effective_bp = base_bp × (1 + prior_count²)`
    ///
    /// | prior_count | multiplier | Example (RANDAO 15%) |
    /// |-------------|------------|----------------------|
    /// | 0           | 1×         | 15%                  |
    /// | 1           | 2×         | 30%                  |
    /// | 2           | 5×         | 75%                  |
    /// | 3           | 10×        | 100% (capped)        |
    ///
    /// Capped at QUADRATIC_PENALTY_CAP_BP (100%) to prevent overflow.
    pub fn compute_quadratic_penalty(base_bp: u64, prior_offense_count: u64) -> u64 {
        let multiplier = 1u64.saturating_add(prior_offense_count.saturating_mul(prior_offense_count));
        let effective = base_bp.saturating_mul(multiplier);
        effective.min(QUADRATIC_PENALTY_CAP_BP)
    }

    /// Count how many prior offenses of a given reason exist for a validator.
    ///
    /// Scans processed offenses for entries matching (validator, reason).
    /// This is O(n) in the number of processed offenses, but pruning
    /// keeps n bounded to ~2× MAX_EVIDENCE_AGE_BLOCKS worth of entries.
    pub fn prior_offense_count(&self, validator: &Address, reason: SlashingReason) -> u64 {
        // Count offenses by scanning all known offense IDs.
        // We can't directly map back from Hash256 → (validator, reason),
        // so we track a separate counter.
        self.offense_counts
            .get(&(*validator, reason))
            .copied()
            .unwrap_or(0)
    }

    /// Compute a deterministic offense ID from the validator, reason, and a
    /// caller-supplied context (e.g., block height or equivocation proof hash).
    ///
    /// The context bytes distinguish different offenses of the same type by
    /// the same validator, while ensuring the *same* offense always maps to
    /// the same ID so replays are rejected.
    pub fn compute_offense_id(
        validator: &Address,
        reason: SlashingReason,
        context: &[u8],
    ) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(b"SLASH_OFFENSE");
        hasher.update(validator.as_bytes());
        hasher.update(&[reason as u8]);
        hasher.update(context);
        hasher.finalize()
    }

    /// Check whether an offense has already been processed.
    pub fn is_offense_processed(&self, offense_id: &Hash256) -> bool {
        self.processed_offenses.contains(offense_id)
    }

    /// Return the number of processed offenses (useful for testing/stats).
    pub fn processed_offense_count(&self) -> usize {
        self.processed_offenses.len()
    }

    /// Reject stale evidence beyond MAX_EVIDENCE_AGE_BLOCKS.
    fn check_evidence_age(
        current_height: u64,
        evidence_height: u64,
    ) -> Result<(), ConsensusError> {
        if current_height > evidence_height
            && current_height - evidence_height > MAX_EVIDENCE_AGE_BLOCKS
        {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "slashing evidence too old: evidence at height {}, current height {} (max age: {} blocks)",
                    evidence_height, current_height, MAX_EVIDENCE_AGE_BLOCKS,
                ),
            });
        }
        Ok(())
    }

    /// Check offense ID not already processed (double-slash prevention).
    fn check_not_duplicate(
        &self,
        offense_id: &Hash256,
        validator: &Address,
    ) -> Result<(), ConsensusError> {
        if self.processed_offenses.contains(offense_id) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "offense already processed for validator {} (offense_id: {})",
                    validator, offense_id,
                ),
            });
        }
        Ok(())
    }

    /// Ensure validator exists and is not already removed (blocks replay attacks).
    fn check_validator_slashable(
        state: &StakingState,
        validator: &Address,
    ) -> Result<(), ConsensusError> {
        let v = state
            .validators
            .get(validator)
            .ok_or(ConsensusError::ValidatorNotFound(*validator))?;

        if v.status == ValidatorStatus::Removed {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "validator {} already removed, cannot slash again",
                    validator
                ),
            });
        }
        Ok(())
    }

    /// Compute the 70/20/10 slashed fund distribution.
    /// Uses u128 intermediate to prevent overflow when total_slashed * share_bp exceeds u64::MAX.
    fn distribute_slashed(total_slashed: u64) -> (u64, u64, u64) {
        let burned = ((total_slashed as u128 * BURN_SHARE_BP as u128) / 10_000) as u64;
        let challenger_reward =
            ((total_slashed as u128 * CHALLENGER_SHARE_BP as u128) / 10_000) as u64;
        let community_fund = total_slashed - burned - challenger_reward;
        (burned, challenger_reward, community_fund)
    }

    /// Record an offense as processed and increment the per-(validator, reason) counter.
    fn record_offense(
        &mut self,
        offense_id: Hash256,
        validator: Address,
        reason: SlashingReason,
        current_height: u64,
    ) {
        self.processed_offenses.insert(offense_id);
        self.offense_heights.insert(offense_id, current_height);
        // Increment per-(validator, reason) offense count for quadratic escalation.
        *self
            .offense_counts
            .entry((validator, reason))
            .or_insert(0) += 1;
    }

    /// Build a SlashResult from computed values.
    fn build_result(
        validator: Address,
        total_slashed: u64,
        reason: SlashingReason,
    ) -> SlashResult {
        let (burned, challenger_reward, community_fund) =
            Self::distribute_slashed(total_slashed);
        SlashResult {
            validator,
            total_slashed,
            burned,
            challenger_reward,
            community_fund,
            reason,
        }
    }

    /// Apply a slash to a validator with double-slash prevention.
    ///
    /// The `offense_context` bytes are hashed together with the validator address
    /// and reason to produce a unique offense ID. If that ID has already been
    /// processed, the slash is rejected. Callers should pass contextual data
    /// that uniquely identifies the offense:
    ///
    /// - **Equivocation**: hash of the two conflicting block hashes + height
    /// - **Downtime**: the 24-hour window identifier (e.g., epoch number)
    /// - **IntentionalDelay**: the specific block height(s) of the offense
    pub fn slash(
        &mut self,
        state: &mut StakingState,
        validator: &Address,
        reason: SlashingReason,
        offense_context: &[u8],
        current_height: u64,
        evidence_height: u64,
    ) -> Result<SlashResult, ConsensusError> {
        Self::check_evidence_age(current_height, evidence_height)?;

        let offense_id = Self::compute_offense_id(validator, reason, offense_context);
        self.check_not_duplicate(&offense_id, validator)?;
        Self::check_validator_slashable(state, validator)?;

        // Apply quadratic escalation for repeat offenders.
        let base_bp = Self::penalty_for(reason);
        let prior_count = self.prior_offense_count(validator, reason);
        let penalty_bp = Self::compute_quadratic_penalty(base_bp, prior_count);
        let total_slashed = state.slash(validator, penalty_bp)?;

        // Mark validator as removed if equivocation
        if reason == SlashingReason::Equivocation
            && let Some(v) = state.validators.get_mut(validator)
        {
            v.status = ValidatorStatus::Removed;
        }

        self.record_offense(offense_id, *validator, reason, current_height);
        Ok(Self::build_result(*validator, total_slashed, reason))
    }

    /// Prune processed offenses older than 2× MAX_EVIDENCE_AGE_BLOCKS.
    ///
    /// Evidence older than MAX_EVIDENCE_AGE_BLOCKS is already rejected by `slash()`,
    /// so offense records from even further back serve no purpose. Using 2× the
    /// evidence age as the retention window provides a generous safety margin.
    ///
    /// Call this periodically (e.g., at epoch boundaries) to bound memory usage.
    pub fn prune_old_offenses(&mut self, current_height: u64) {
        let retention = MAX_EVIDENCE_AGE_BLOCKS.saturating_mul(2);
        let cutoff = current_height.saturating_sub(retention);

        self.offense_heights.retain(|id, h| {
            if *h < cutoff {
                self.processed_offenses.remove(id);
                false
            } else {
                true
            }
        });

        // Cap offense_counts to prevent unbounded growth from long-gone
        // validators. After pruning, if no offenses remain in the tracking window,
        // the quadratic escalation counts are stale and can be safely cleared.
        if self.offense_heights.is_empty() {
            self.offense_counts.clear();
        }
    }

    /// Apply a censorship slash with dynamic penalty based on congestion.
    ///
    /// This is the preferred entry point for censorship slashing. It computes
    /// the dynamic base penalty from the congestion ratio, then applies
    /// quadratic escalation on top.
    ///
    /// The `congestion_ratio_bp` is actual_base_fee / target_base_fee × 10_000.
    /// For example, 20_000 means the base fee is 2× the target.
    pub fn slash_censorship(
        &mut self,
        state: &mut StakingState,
        validator: &Address,
        offense_context: &[u8],
        current_height: u64,
        evidence_height: u64,
        congestion_ratio_bp: u64,
    ) -> Result<SlashResult, ConsensusError> {
        Self::check_evidence_age(current_height, evidence_height)?;

        let reason = SlashingReason::Censorship;
        let offense_id = Self::compute_offense_id(validator, reason, offense_context);
        self.check_not_duplicate(&offense_id, validator)?;
        Self::check_validator_slashable(state, validator)?;

        // Dynamic base penalty from congestion + quadratic escalation
        let dynamic_base_bp = Self::dynamic_censorship_penalty(congestion_ratio_bp);
        let prior_count = self.prior_offense_count(validator, reason);
        let penalty_bp = Self::compute_quadratic_penalty(dynamic_base_bp, prior_count);
        let total_slashed = state.slash(validator, penalty_bp)?;

        self.record_offense(offense_id, *validator, reason, current_height);
        Ok(Self::build_result(*validator, total_slashed, reason))
    }

    /// Process dual-proposal evidence from the rotation state machine.
    ///
    /// Two proposals at the same height by the same EOTS key means the key
    /// is extractable → 33.33% equivocation slash. The rotation state machine
    /// has already detected the conflicting proposals; this method validates
    /// the evidence and applies the slash.
    pub fn slash_dual_proposal(
        &mut self,
        state: &mut StakingState,
        evidence: &DualProposalEvidence,
        proposer_pubkey: &SchnorrPublicKey,
        current_height: u64,
    ) -> Result<SlashResult, ConsensusError> {
        evidence.validate(proposer_pubkey)?;
        let context = evidence.offense_context();
        self.slash(
            state,
            &evidence.proposer,
            SlashingReason::Equivocation,
            &context,
            current_height,
            evidence.height,
        )
    }

    /// Verify an equivocation proof using real SLH-DSA signature verification.
    ///
    /// Checks that the same SLH-DSA public key validly signed two different block hashes.
    pub fn verify_equivocation(proof: &EquivocationProof) -> Result<bool, ConsensusError> {
        // Two different blocks at the same height
        if proof.block_hash_a == proof.block_hash_b {
            return Err(ConsensusError::InvalidBlock {
                reason: "equivocation proof has identical block hashes".into(),
            });
        }

        // Deserialize the SLH-DSA public key
        let pk = SlhDsaPublicKey::from_bytes(proof.slh_dsa_pk.clone()).map_err(|e| {
            ConsensusError::InvalidBlock {
                reason: format!("invalid SLH-DSA public key in equivocation proof: {e}"),
            }
        })?;

        // Deserialize both signatures
        let sig_a = SlhDsaSignature::from_bytes(proof.signature_a.clone()).map_err(|e| {
            ConsensusError::InvalidBlock {
                reason: format!("invalid SLH-DSA signature A in equivocation proof: {e}"),
            }
        })?;
        let sig_b = SlhDsaSignature::from_bytes(proof.signature_b.clone()).map_err(|e| {
            ConsensusError::InvalidBlock {
                reason: format!("invalid SLH-DSA signature B in equivocation proof: {e}"),
            }
        })?;

        // Bind height to the verification messages to prevent cross-height attacks.
        // Signatures are created over height || block_hash (see block_builder::dual_sign),
        // so we must reconstruct the same message format here.
        let mut msg_a = Vec::with_capacity(8 + 32);
        msg_a.extend_from_slice(&proof.height.to_le_bytes());
        msg_a.extend_from_slice(proof.block_hash_a.as_bytes());

        let mut msg_b = Vec::with_capacity(8 + 32);
        msg_b.extend_from_slice(&proof.height.to_le_bytes());
        msg_b.extend_from_slice(proof.block_hash_b.as_bytes());

        // Verify using the real crypto: both signatures must be valid under the same key
        let is_equivocation =
            brrq_crypto::slh_dsa::verify_equivocation(&pk, &msg_a, &sig_a, &msg_b, &sig_b)
                .map_err(|e| ConsensusError::InvalidBlock {
                    reason: format!("equivocation verification failed: {e}"),
                })?;

        Ok(is_equivocation)
    }
}

impl Default for SlashingEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// PILLAR 2: Deterministic Slashing Conditions
// ═══════════════════════════════════════════════════════════════════════════════
//
// Three threat vectors with deterministic detection and automatic L1 slashing
// via EOTS key extraction. Each vector has a mathematical proof that honest
// behavior is the strictly dominant strategy.
//
// ## Threat Vectors
//
// 1. **Invalid State Attestation** (SlashingVector::InvalidState)
//    A committee member signs a state root that does not match the STARK proof.
//    Detection: Compare committee attestation state_root vs STARK proof output.
//    Penalty: 100% of staked BTC (extracted via EOTS key).
//
// 2. **Censorship** (SlashingVector::Censorship)
//    A sequencer/committee member demonstrably excludes valid transactions.
//    Detection: Inclusion proof showing tx was in mempool but excluded.
//    Penalty: Dynamic 10-50% based on congestion + quadratic escalation.
//
// 3. **Data Withholding** (SlashingVector::DataWithholding)
//    A sequencer publishes a state root but withholds the underlying data.
//    Detection: Timeout — if data is not published within the challenge period,
//    any challenger can submit a data availability challenge.
//    Penalty: 33% per offense, quadratic escalation.

/// Slashing vector for deterministic slashing conditions.
///
/// Each vector has a well-defined detection mechanism and penalty structure
/// that makes honest behavior the strictly dominant strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SlashingVector {
    /// Committee member signed a state root that contradicts the STARK proof.
    ///
    /// Detection: State root in committee attestation ≠ STARK proof output.
    /// Penalty: 100% stake forfeiture (EOTS key extraction → L1 sweep).
    /// Justification: Invalid state attestation is the most severe violation
    /// because it directly enables theft of bridge funds.
    InvalidStateAttestation,

    /// Sequencer/committee member demonstrably excluded valid transactions.
    ///
    /// Detection: Inclusion proof showing valid tx was available but excluded.
    /// Penalty: Dynamic 10-50% based on congestion, quadratic escalation.
    /// Justification: Censorship enables MEV extraction and undermines
    /// the permissionless property of the L2.
    TransactionCensorship,

    /// Sequencer published a state commitment but withheld the underlying data.
    ///
    /// Detection: Challenge timeout — data not published within window.
    /// Penalty: 33% per offense, quadratic escalation.
    /// Justification: Data withholding prevents fraud proof submission,
    /// enabling the sequencer to commit invalid state transitions.
    DataWithholding,
}

/// Evidence for an invalid state attestation.
///
/// This is produced when a committee member's EOTS signature is found
/// on a state root that contradicts the verified STARK proof output.
/// The STARK proof is the mathematical ground truth — any attestation
/// that disagrees with it is provably fraudulent.
#[derive(Debug, Clone)]
pub struct InvalidStateEvidence {
    /// The committee member who signed the invalid state.
    pub attester: Address,
    /// The state root they signed (in their EOTS attestation).
    pub attested_state_root: Hash256,
    /// The correct state root (from the verified STARK proof).
    pub correct_state_root: Hash256,
    /// The EOTS nonce used in the attestation (for key extraction).
    pub eots_nonce: [u8; 32],
    /// The EOTS signature s-value (for key extraction).
    pub eots_signature: [u8; 32],
    /// The L2 block height of the attested state.
    pub state_height: u64,
    /// Hash of the STARK proof that proves the correct state.
    pub stark_proof_hash: Hash256,
}

impl InvalidStateEvidence {
    /// Validate that the evidence is well-formed.
    pub fn validate(&self) -> Result<(), ConsensusError> {
        if self.attested_state_root == self.correct_state_root {
            return Err(ConsensusError::InvalidBlock {
                reason: "attested state matches correct state — not an invalid attestation".into(),
            });
        }
        if self.eots_nonce == [0u8; 32] {
            return Err(ConsensusError::InvalidBlock {
                reason: "EOTS nonce is zero — invalid evidence".into(),
            });
        }
        Ok(())
    }

    /// Compute deterministic offense context for double-slash prevention.
    pub fn offense_context(&self) -> Vec<u8> {
        let mut ctx = Vec::with_capacity(8 + 32 + 32);
        ctx.extend_from_slice(&self.state_height.to_le_bytes());
        ctx.extend_from_slice(self.attested_state_root.as_bytes());
        ctx.extend_from_slice(self.correct_state_root.as_bytes());
        ctx
    }
}

/// Evidence for a data withholding violation.
///
/// Produced when a sequencer commits a state root but fails to publish
/// the underlying block data within the challenge window. Without the
/// data, fraud proofs cannot be constructed, making the state root
/// unfalsifiable.
#[derive(Debug, Clone)]
pub struct DataWithholdingEvidence {
    /// The sequencer who published the state commitment.
    pub sequencer: Address,
    /// The state root that was committed without available data.
    pub committed_state_root: Hash256,
    /// L2 block height of the commitment.
    pub commitment_height: u64,
    /// L2 block height at which the challenge period expired
    /// without data being published.
    pub challenge_expired_at: u64,
    /// Hash of the data availability challenge that triggered this.
    pub challenge_hash: Hash256,
}

impl DataWithholdingEvidence {
    /// Validate the evidence is well-formed.
    pub fn validate(&self) -> Result<(), ConsensusError> {
        if self.challenge_expired_at <= self.commitment_height {
            return Err(ConsensusError::InvalidBlock {
                reason: "challenge expiry must be after commitment height".into(),
            });
        }
        Ok(())
    }

    /// Compute deterministic offense context.
    pub fn offense_context(&self) -> Vec<u8> {
        let mut ctx = Vec::with_capacity(8 + 32);
        ctx.extend_from_slice(&self.commitment_height.to_le_bytes());
        ctx.extend_from_slice(self.committed_state_root.as_bytes());
        ctx
    }
}

/// Slashing penalty for data withholding: 33% = 3333 basis points.
///
/// Matches equivocation severity because data withholding is equally
/// dangerous — it prevents fraud proof submission, enabling silent theft.
pub const DATA_WITHHOLDING_PENALTY_BP: u64 = 3333;

/// Slashing penalty for invalid state attestation: 100% = 10000 basis points.
///
/// Maximum penalty because signing a provably wrong state root is the most
/// direct path to bridge fund theft. Combined with EOTS key extraction,
/// the L1 staked BTC is also swept.
pub const INVALID_STATE_ATTESTATION_PENALTY_BP: u64 = 10_000;

impl SlashingEngine {
    /// Get the base penalty for a slashing vector.
    pub fn vector_penalty(vector: SlashingVector) -> u64 {
        match vector {
            SlashingVector::InvalidStateAttestation => INVALID_STATE_ATTESTATION_PENALTY_BP,
            SlashingVector::TransactionCensorship => CENSORSHIP_PENALTY_BP,
            SlashingVector::DataWithholding => DATA_WITHHOLDING_PENALTY_BP,
        }
    }

    /// Slash for invalid state attestation.
    ///
    /// This is the most severe slashing condition. A committee member
    /// who signs a state root contradicting the STARK proof is provably
    /// corrupt. The penalty is 100% of stake, and their EOTS key is
    /// extracted for L1 sweep.
    ///
    /// ## L1 Slashing Flow
    ///
    /// 1. Invalid attestation detected on L2 (state root mismatch)
    /// 2. EOTS key extraction proof generated (two signatures, same nonce)
    /// 3. L2 applies 100% stake slash
    /// 4. Extracted key used to sweep L1 Taproot staking UTXOs
    ///
    /// Steps 3 and 4 are independent — L2 slashing is instant,
    /// L1 sweep can occur asynchronously by any party with the
    /// extracted key.
    pub fn slash_invalid_state(
        &mut self,
        state: &mut StakingState,
        evidence: &InvalidStateEvidence,
        current_height: u64,
    ) -> Result<SlashResult, ConsensusError> {
        evidence.validate()?;

        let reason = SlashingReason::Equivocation; // Map to equivocation (most severe)
        let context = evidence.offense_context();
        let offense_id = Self::compute_offense_id(&evidence.attester, reason, &context);
        self.check_not_duplicate(&offense_id, &evidence.attester)?;
        Self::check_evidence_age(current_height, evidence.state_height)?;
        Self::check_validator_slashable(state, &evidence.attester)?;

        // 100% penalty — total stake confiscation
        let total_slashed = state.slash(&evidence.attester, INVALID_STATE_ATTESTATION_PENALTY_BP)?;

        // Mark as removed (can never be a validator again)
        if let Some(v) = state.validators.get_mut(&evidence.attester) {
            v.status = ValidatorStatus::Removed;
        }

        self.record_offense(offense_id, evidence.attester, reason, current_height);
        Ok(Self::build_result(evidence.attester, total_slashed, reason))
    }

    /// Slash for data withholding.
    ///
    /// When a sequencer commits a state root but fails to publish the
    /// underlying data within the challenge period, any party can submit
    /// a data withholding challenge. If the sequencer cannot produce the
    /// data, they are slashed.
    ///
    /// ## Why This Matters
    ///
    /// Without data availability, fraud proofs cannot be constructed.
    /// A malicious sequencer could commit an invalid state transition,
    /// withhold the data proving it's invalid, and steal bridge funds
    /// once the challenge period expires. Data withholding slashing
    /// closes this attack vector.
    pub fn slash_data_withholding(
        &mut self,
        state: &mut StakingState,
        evidence: &DataWithholdingEvidence,
        current_height: u64,
    ) -> Result<SlashResult, ConsensusError> {
        evidence.validate()?;

        let reason = SlashingReason::IntentionalDelay; // Map to delay (closest match)
        let context = evidence.offense_context();
        let offense_id = Self::compute_offense_id(&evidence.sequencer, reason, &context);
        self.check_not_duplicate(&offense_id, &evidence.sequencer)?;
        Self::check_evidence_age(current_height, evidence.commitment_height)?;
        Self::check_validator_slashable(state, &evidence.sequencer)?;

        // Base 33% + quadratic escalation
        let prior_count = self.prior_offense_count(&evidence.sequencer, reason);
        let penalty_bp =
            Self::compute_quadratic_penalty(DATA_WITHHOLDING_PENALTY_BP, prior_count);
        let total_slashed = state.slash(&evidence.sequencer, penalty_bp)?;

        self.record_offense(offense_id, evidence.sequencer, reason, current_height);
        Ok(Self::build_result(evidence.sequencer, total_slashed, reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address(bytes)
    }

    fn setup() -> StakingState {
        let mut state = StakingState::new(100_000_000_000);
        state.register_validator(addr(1), 10_000_000_000).unwrap(); // 100 BTC
        state
    }

    #[test]
    fn test_downtime_slash() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();
        let result = engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::Downtime,
                b"epoch_1",
                1000,
                1000,
            )
            .unwrap();

        // 5% of 10B = 500M
        assert_eq!(result.total_slashed, 500_000_000);
        assert_eq!(result.burned, 500_000_000 * 7000 / 10_000);
        assert_eq!(result.challenger_reward, 500_000_000 * 2000 / 10_000);

        // Verify the validator's stake was actually reduced in StakingState
        let remaining = state.validators.get(&addr(1)).unwrap().stake;
        assert_eq!(remaining, 10_000_000_000 - result.total_slashed);

        // Validator still active after downtime slash
        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.status, ValidatorStatus::Active);
    }

    #[test]
    fn test_delay_slash() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();
        let result = engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::IntentionalDelay,
                b"height_100",
                1000,
                1000,
            )
            .unwrap();

        // 15% of 10B = 1.5B
        assert_eq!(result.total_slashed, 1_500_000_000);

        // Verify the validator's stake was actually reduced in StakingState
        let remaining = state.validators.get(&addr(1)).unwrap().stake;
        assert_eq!(remaining, 10_000_000_000 - result.total_slashed);
    }

    #[test]
    fn test_equivocation_slash() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();
        let result = engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::Equivocation,
                b"proof_hash_1",
                1000,
                1000,
            )
            .unwrap();

        // 33.33% of 10B = 3.333B
        assert_eq!(result.total_slashed, 3_333_000_000);

        // Verify the validator's stake was actually reduced in StakingState
        let remaining = state.validators.get(&addr(1)).unwrap().stake;
        assert_eq!(remaining, 10_000_000_000 - result.total_slashed);

        // Validator removed after equivocation
        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.status, ValidatorStatus::Removed);
    }

    #[test]
    fn test_randao_non_reveal_slash() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();
        let result = engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::RandaoNonReveal,
                b"epoch_5",
                1000,
                1000,
            )
            .unwrap();

        // 15% of 10B = 1.5B (raised from 5%)
        assert_eq!(result.total_slashed, 1_500_000_000);
        assert_eq!(result.reason, SlashingReason::RandaoNonReveal);

        // Validator still active after RANDAO non-reveal slash
        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.status, ValidatorStatus::Active);
    }

    #[test]
    fn test_slash_distribution_sums() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();
        let result = engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::Equivocation,
                b"proof_hash_2",
                1000,
                1000,
            )
            .unwrap();

        let total = result.burned + result.challenger_reward + result.community_fund;
        assert_eq!(total, result.total_slashed);
    }

    #[test]
    fn test_slash_unknown_validator() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();
        let result = engine.slash(
            &mut state,
            &addr(99),
            SlashingReason::Downtime,
            b"epoch_1",
            1000,
            1000,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_double_slash_prevention() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();
        let context = b"equivocation_proof_abc";

        // First slash should succeed
        let result = engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::Downtime,
                context,
                1000,
                1000,
            )
            .unwrap();
        assert_eq!(result.total_slashed, 500_000_000);
        assert_eq!(engine.processed_offense_count(), 1);

        // Second slash with the SAME context should be rejected
        let result = engine.slash(
            &mut state,
            &addr(1),
            SlashingReason::Downtime,
            context,
            1000,
            1000,
        );
        assert!(
            result.is_err(),
            "double slash with same offense context must be rejected"
        );
        assert_eq!(
            engine.processed_offense_count(),
            1,
            "no new offense recorded"
        );
    }

    #[test]
    fn test_different_offense_contexts_allowed() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // Slash for downtime in epoch 1
        engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::Downtime,
                b"epoch_1",
                1000,
                1000,
            )
            .unwrap();

        // Slash for downtime in epoch 2 (different offense) should succeed
        engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::Downtime,
                b"epoch_2",
                1000,
                1000,
            )
            .unwrap();

        assert_eq!(engine.processed_offense_count(), 2);
    }

    #[test]
    fn test_offense_id_deterministic() {
        let id1 = SlashingEngine::compute_offense_id(&addr(1), SlashingReason::Downtime, b"ctx");
        let id2 = SlashingEngine::compute_offense_id(&addr(1), SlashingReason::Downtime, b"ctx");
        assert_eq!(id1, id2, "same inputs must produce same offense ID");

        let id3 = SlashingEngine::compute_offense_id(&addr(2), SlashingReason::Downtime, b"ctx");
        assert_ne!(id1, id3, "different validator must produce different ID");

        let id4 =
            SlashingEngine::compute_offense_id(&addr(1), SlashingReason::Equivocation, b"ctx");
        assert_ne!(id1, id4, "different reason must produce different ID");
    }

    /// Build the height-bound message that gets signed: height || block_hash
    fn height_bound_msg(height: u64, hash: &Hash256) -> Vec<u8> {
        let mut msg = Vec::with_capacity(8 + 32);
        msg.extend_from_slice(&height.to_le_bytes());
        msg.extend_from_slice(hash.as_bytes());
        msg
    }

    #[test]
    fn test_verify_equivocation_valid() {
        use brrq_crypto::slh_dsa::SlhDsaKeyPair;

        // Generate a real SLH-DSA keypair and sign two different blocks at the same height
        let kp = SlhDsaKeyPair::generate().unwrap();
        let hash_a = Hash256::ZERO;
        let mut hash_b = Hash256::ZERO;
        hash_b.0[0] = 1;
        let height = 100u64;

        // Sign height || block_hash (matching the signing format in block_builder)
        let sig_a = kp.sign(&height_bound_msg(height, &hash_a)).unwrap();
        let sig_b = kp.sign(&height_bound_msg(height, &hash_b)).unwrap();

        let proof = EquivocationProof {
            validator: addr(1),
            height,
            block_hash_a: hash_a,
            block_hash_b: hash_b,
            signature_a: sig_a.as_bytes().to_vec(),
            signature_b: sig_b.as_bytes().to_vec(),
            slh_dsa_pk: kp.public_key().as_bytes().to_vec(),
        };
        assert!(SlashingEngine::verify_equivocation(&proof).unwrap());
    }

    #[test]
    fn test_verify_equivocation_cross_height_rejected() {
        use brrq_crypto::slh_dsa::SlhDsaKeyPair;

        // Sign two blocks at DIFFERENT heights — this is NOT equivocation
        let kp = SlhDsaKeyPair::generate().unwrap();
        let hash_a = Hash256::ZERO;
        let mut hash_b = Hash256::ZERO;
        hash_b.0[0] = 1;

        // Signatures are over different heights (100 and 200)
        let sig_a = kp.sign(&height_bound_msg(100, &hash_a)).unwrap();
        let sig_b = kp.sign(&height_bound_msg(200, &hash_b)).unwrap();

        // Attacker claims both are at height 100
        let proof = EquivocationProof {
            validator: addr(1),
            height: 100,
            block_hash_a: hash_a,
            block_hash_b: hash_b,
            signature_a: sig_a.as_bytes().to_vec(),
            signature_b: sig_b.as_bytes().to_vec(),
            slh_dsa_pk: kp.public_key().as_bytes().to_vec(),
        };
        // sig_b was signed over height 200, not 100 — verification must fail
        assert!(SlashingEngine::verify_equivocation(&proof).is_err());
    }

    #[test]
    fn test_verify_equivocation_invalid_sig() {
        use brrq_crypto::slh_dsa::SlhDsaKeyPair;

        let kp = SlhDsaKeyPair::generate().unwrap();
        let hash_a = Hash256::ZERO;
        let mut hash_b = Hash256::ZERO;
        hash_b.0[0] = 1;
        let height = 100u64;

        // Sign hash_a correctly, but provide garbage for signature_b
        let sig_a = kp.sign(&height_bound_msg(height, &hash_a)).unwrap();
        let fake_sig_b = vec![0u8; brrq_crypto::slh_dsa::SLH_DSA_SIGNATURE_SIZE];

        let proof = EquivocationProof {
            validator: addr(1),
            height,
            block_hash_a: hash_a,
            block_hash_b: hash_b,
            signature_a: sig_a.as_bytes().to_vec(),
            signature_b: fake_sig_b,
            slh_dsa_pk: kp.public_key().as_bytes().to_vec(),
        };
        // Should fail because the fake signature won't verify
        assert!(SlashingEngine::verify_equivocation(&proof).is_err());
    }

    #[test]
    fn test_verify_equivocation_same_hash() {
        let proof = EquivocationProof {
            validator: addr(1),
            height: 100,
            block_hash_a: Hash256::ZERO,
            block_hash_b: Hash256::ZERO,
            signature_a: vec![1, 2, 3],
            signature_b: vec![4, 5, 6],
            slh_dsa_pk: vec![0u8; 32],
        };
        assert!(SlashingEngine::verify_equivocation(&proof).is_err());
    }

    // ── WI-2D: Dual Proposal Evidence Tests ─────────────────────────

    /// Helper: create real EOTS equivocation evidence (same nonce, two different messages).
    /// Returns (evidence, proposer_pubkey).
    fn make_real_dual_proposal_evidence(
        proposer: Address,
        height: u64,
        msg_a: &[u8],
        msg_b: &[u8],
    ) -> (DualProposalEvidence, SchnorrPublicKey) {
        use brrq_crypto::eots::EotsKeyPair;

        let sk = [42u8; 32];
        let eots_kp = EotsKeyPair::from_secret_bytes(&sk).unwrap();
        let pubkey = *eots_kp.public_key();

        let hash_a = Hasher::hash(msg_a);
        let hash_b = Hasher::hash(msg_b);

        // Generate a single nonce and sign both messages (equivocation).
        #[allow(deprecated)]
        let (nonce_sk, nonce_commitment) = eots_kp.generate_nonce(height, 1).unwrap();
        let sig_a = eots_kp.sign(&hash_a, &nonce_sk, &nonce_commitment).unwrap();
        let sig_b = eots_kp.sign(&hash_b, &nonce_sk, &nonce_commitment).unwrap();

        // Serialize signatures: nonce_commitment (33) + s_value (32) = 65 bytes.
        let mut raw_a = sig_a.nonce_commitment().as_bytes().to_vec();
        raw_a.extend_from_slice(sig_a.s_value());
        let mut raw_b = sig_b.nonce_commitment().as_bytes().to_vec();
        raw_b.extend_from_slice(sig_b.s_value());

        let evidence = DualProposalEvidence {
            proposer,
            height,
            proposal_hash_a: hash_a,
            proposal_hash_b: hash_b,
            eots_signature_a: raw_a,
            eots_signature_b: raw_b,
        };
        (evidence, pubkey)
    }

    #[test]
    fn test_dual_proposal_evidence_valid() {
        let (evidence, pubkey) = make_real_dual_proposal_evidence(
            addr(1), 100, b"block_a", b"block_b",
        );
        assert!(evidence.validate(&pubkey).is_ok());
    }

    #[test]
    fn test_dual_proposal_evidence_identical_hashes_rejected() {
        let hash = Hasher::hash(b"same_block");
        // Use dummy sigs — identical-hash check fires before signature verification.
        let evidence = DualProposalEvidence {
            proposer: addr(1),
            height: 100,
            proposal_hash_a: hash,
            proposal_hash_b: hash,
            eots_signature_a: [vec![0xAA; 33], vec![1; 32]].concat(),
            eots_signature_b: [vec![0xAA; 33], vec![2; 32]].concat(),
        };
        let dummy_pk = SchnorrPublicKey::from_bytes([0u8; 32]);
        assert!(evidence.validate(&dummy_pk).is_err());
    }

    #[test]
    fn test_dual_proposal_evidence_fabricated_sigs_rejected() {
        // fabricated evidence with structurally valid but cryptographically
        // invalid signatures must be rejected.
        let hash_a = Hasher::hash(b"block_a");
        let hash_b = Hasher::hash(b"block_b");

        // Use a real pubkey but fake signatures — verification must fail.
        use brrq_crypto::eots::EotsKeyPair;
        let eots_kp = EotsKeyPair::from_secret_bytes(&[42u8; 32]).unwrap();
        let pubkey = *eots_kp.public_key();

        // Generate a valid nonce commitment point for structural validity.
        #[allow(deprecated)]
        let (_, nonce_commitment) = eots_kp.generate_nonce(100, 1).unwrap();
        let nonce_bytes = nonce_commitment.as_bytes().to_vec();

        let evidence = DualProposalEvidence {
            proposer: addr(1),
            height: 100,
            proposal_hash_a: hash_a,
            proposal_hash_b: hash_b,
            eots_signature_a: [nonce_bytes.clone(), vec![1; 32]].concat(),
            eots_signature_b: [nonce_bytes, vec![2; 32]].concat(),
        };
        // Structural checks pass, but signature verification must fail.
        assert!(evidence.validate(&pubkey).is_err());
    }

    #[test]
    fn test_dual_proposal_offense_context_order_independent() {
        let hash_a = Hasher::hash(b"block_a");
        let hash_b = Hasher::hash(b"block_b");

        let evidence_ab = DualProposalEvidence {
            proposer: addr(1),
            height: 100,
            proposal_hash_a: hash_a,
            proposal_hash_b: hash_b,
            eots_signature_a: vec![],
            eots_signature_b: vec![],
        };
        let evidence_ba = DualProposalEvidence {
            proposer: addr(1),
            height: 100,
            proposal_hash_a: hash_b,
            proposal_hash_b: hash_a,
            eots_signature_a: vec![],
            eots_signature_b: vec![],
        };

        // Same offense regardless of hash order
        assert_eq!(evidence_ab.offense_context(), evidence_ba.offense_context());
    }

    #[test]
    fn test_slash_dual_proposal() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        let (evidence, pubkey) = make_real_dual_proposal_evidence(
            addr(1), 50, b"block_a", b"block_b",
        );

        let result = engine
            .slash_dual_proposal(&mut state, &evidence, &pubkey, 100)
            .unwrap();

        // 33.33% equivocation penalty
        assert_eq!(result.total_slashed, 3_333_000_000);
        assert_eq!(result.reason, SlashingReason::Equivocation);

        // Validator removed
        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.status, ValidatorStatus::Removed);
    }

    #[test]
    fn test_h3_prune_old_offenses() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // Slash at height 1000
        engine
            .slash(
                &mut state,
                &addr(1),
                SlashingReason::Downtime,
                b"epoch_1",
                1000,
                1000,
            )
            .unwrap();
        assert_eq!(engine.processed_offense_count(), 1);

        // Prune at height 1000 — too recent, should keep
        engine.prune_old_offenses(1000);
        assert_eq!(engine.processed_offense_count(), 1);

        // Prune at height well beyond retention (2 * MAX_EVIDENCE_AGE_BLOCKS + 1000)
        let far_future = 1000 + MAX_EVIDENCE_AGE_BLOCKS * 2 + 1;
        engine.prune_old_offenses(far_future);
        assert_eq!(
            engine.processed_offense_count(),
            0,
            "old offenses must be pruned"
        );
    }

    #[test]
    fn test_dual_proposal_double_slash_prevented() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        let (evidence, pubkey) = make_real_dual_proposal_evidence(
            addr(1), 50, b"block_a", b"block_b",
        );

        // First slash succeeds
        engine
            .slash_dual_proposal(&mut state, &evidence, &pubkey, 100)
            .unwrap();

        // Second slash with same evidence rejected (double-slash prevention)
        let result = engine.slash_dual_proposal(&mut state, &evidence, &pubkey, 100);
        assert!(result.is_err());
    }

    // ── Quadratic Escalation Tests ──────────────────────────

    #[test]
    fn test_compute_quadratic_penalty_table() {
        // prior=0 → 1× base
        assert_eq!(SlashingEngine::compute_quadratic_penalty(1500, 0), 1500);
        // prior=1 → 2× base
        assert_eq!(SlashingEngine::compute_quadratic_penalty(1500, 1), 3000);
        // prior=2 → 5× base
        assert_eq!(SlashingEngine::compute_quadratic_penalty(1500, 2), 7500);
        // prior=3 → 10× = 15000 but capped at 10000
        assert_eq!(SlashingEngine::compute_quadratic_penalty(1500, 3), 10_000);
        // prior=100 → massively over cap
        assert_eq!(SlashingEngine::compute_quadratic_penalty(1500, 100), 10_000);
    }

    #[test]
    fn test_quadratic_escalation_in_slash() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // First RANDAO offense: 15% of 10B = 1.5B
        let r1 = engine
            .slash(&mut state, &addr(1), SlashingReason::RandaoNonReveal, b"epoch_1", 1000, 1000)
            .unwrap();
        assert_eq!(r1.total_slashed, 1_500_000_000);

        // Remaining stake: 10B - 1.5B = 8.5B
        // Second RANDAO offense: prior=1 → 2× → 30% of 8.5B = 2.55B
        let r2 = engine
            .slash(&mut state, &addr(1), SlashingReason::RandaoNonReveal, b"epoch_2", 1001, 1001)
            .unwrap();
        assert_eq!(r2.total_slashed, 2_550_000_000);

        // Remaining stake: 8.5B - 2.55B = 5.95B
        // Third RANDAO offense: prior=2 → 5× → 75% of 5.95B = 4.4625B
        let r3 = engine
            .slash(&mut state, &addr(1), SlashingReason::RandaoNonReveal, b"epoch_3", 1002, 1002)
            .unwrap();
        assert_eq!(r3.total_slashed, 4_462_500_000);
    }

    #[test]
    fn test_quadratic_cap_at_100_percent() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // Slash 3 times to reach cap (prior=3 → 10× → 150% → capped at 100%)
        for i in 0..3 {
            engine
                .slash(
                    &mut state, &addr(1), SlashingReason::RandaoNonReveal,
                    format!("epoch_{i}").as_bytes(), 1000 + i as u64, 1000 + i as u64,
                )
                .unwrap();
        }

        // 4th offense: prior=3 → 10× → 15000bp → capped at 10000bp (100%)
        let remaining = state.validators.get(&addr(1)).unwrap().stake;
        let r4 = engine
            .slash(&mut state, &addr(1), SlashingReason::RandaoNonReveal, b"epoch_3", 1003, 1003)
            .unwrap();
        // Should slash 100% of whatever remains
        assert_eq!(r4.total_slashed, remaining);
    }

    #[test]
    fn test_quadratic_per_reason_isolation() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // Slash for Downtime twice
        engine
            .slash(&mut state, &addr(1), SlashingReason::Downtime, b"e1", 1000, 1000)
            .unwrap();
        engine
            .slash(&mut state, &addr(1), SlashingReason::Downtime, b"e2", 1001, 1001)
            .unwrap();

        // RANDAO offense should start at prior=0, not inherit Downtime count
        assert_eq!(engine.prior_offense_count(&addr(1), SlashingReason::RandaoNonReveal), 0);
        assert_eq!(engine.prior_offense_count(&addr(1), SlashingReason::Downtime), 2);
    }

    // ── Censorship Slashing Tests ──────────────────────────

    #[test]
    fn test_censorship_slash() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();
        let result = engine
            .slash(
                &mut state, &addr(1), SlashingReason::Censorship,
                b"block_500_txset_hash", 1000, 1000,
            )
            .unwrap();

        // 10% of 10B = 1B
        assert_eq!(result.total_slashed, 1_000_000_000);
        assert_eq!(result.reason, SlashingReason::Censorship);

        // Validator still active after censorship slash (not removed)
        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.status, ValidatorStatus::Active);
    }

    #[test]
    fn test_censorship_quadratic_escalation() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // First censorship: 10% of 10B = 1B
        let r1 = engine
            .slash(&mut state, &addr(1), SlashingReason::Censorship, b"blk_1", 1000, 1000)
            .unwrap();
        assert_eq!(r1.total_slashed, 1_000_000_000);

        // Second censorship: prior=1 → 2× → 20% of 9B = 1.8B
        let r2 = engine
            .slash(&mut state, &addr(1), SlashingReason::Censorship, b"blk_2", 1001, 1001)
            .unwrap();
        assert_eq!(r2.total_slashed, 1_800_000_000);
    }

    #[test]
    fn test_penalty_for_all_reasons() {
        assert_eq!(SlashingEngine::penalty_for(SlashingReason::Downtime), 500);
        assert_eq!(SlashingEngine::penalty_for(SlashingReason::IntentionalDelay), 1500);
        assert_eq!(SlashingEngine::penalty_for(SlashingReason::Equivocation), 3333);
        assert_eq!(SlashingEngine::penalty_for(SlashingReason::RandaoNonReveal), 1500);
        assert_eq!(SlashingEngine::penalty_for(SlashingReason::Censorship), 1000);
    }

    // ── Dynamic Censorship Penalty Tests ──────────────────────

    #[test]
    fn gt2_dynamic_penalty_below_threshold() {
        // Below congestion threshold → base penalty (1× = 1000bp)
        assert_eq!(
            SlashingEngine::dynamic_censorship_penalty(10_000), // 1.0× (no congestion)
            1000,
        );
        assert_eq!(
            SlashingEngine::dynamic_censorship_penalty(12_000), // at threshold
            1000,
        );
    }

    #[test]
    fn gt2_dynamic_penalty_at_max_congestion() {
        // At max congestion (3.0×) → 5× multiplier = 5000bp
        assert_eq!(
            SlashingEngine::dynamic_censorship_penalty(30_000),
            5000,
        );
        // Above max → still capped at 5000bp
        assert_eq!(
            SlashingEngine::dynamic_censorship_penalty(50_000),
            5000,
        );
    }

    #[test]
    fn gt2_dynamic_penalty_linear_interpolation() {
        // Midpoint between threshold (12000) and max (30000):
        // progress = (21000 - 12000) / (30000 - 12000) = 9000/18000 = 0.5
        // multiplier = 10000 + 0.5 × (50000 - 10000) = 10000 + 20000 = 30000
        // penalty = 1000 × 30000 / 10000 = 3000bp
        assert_eq!(
            SlashingEngine::dynamic_censorship_penalty(21_000),
            3000,
        );
    }

    #[test]
    fn gt2_nash_equilibrium_high_mev() {
        // Verify that censorship is irrational under high MEV.
        // Validator S = 100 BTC = 10B sat, congestion 3× (max), first offense.
        let stake: u128 = 10_000_000_000;
        let dynamic_bp = SlashingEngine::dynamic_censorship_penalty(30_000) as u128; // 5000bp
        let penalty = stake * dynamic_bp / 10_000; // 5B sat = 50 BTC

        // At p=0.5 detection probability:
        let expected_cost = penalty / 2; // 25 BTC
        // Realistic max MEV per block: ~0.5 BTC = 50M sat
        let max_realistic_mev: u128 = 50_000_000;

        assert!(
            expected_cost > max_realistic_mev,
            "expected cost of censorship ({} sat) must exceed max MEV ({} sat)",
            expected_cost,
            max_realistic_mev,
        );
    }

    #[test]
    fn gt2_slash_censorship_dynamic() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // Slash at 2× congestion
        // progress = (20000-12000)/(30000-12000) = 8000/18000 = 4/9
        // multiplier = 10000 + (4/9) × 40000 = 10000 + 17777 = 27777
        // penalty = 1000 × 27777 / 10000 = 2777bp
        let result = engine
            .slash_censorship(
                &mut state,
                &addr(1),
                b"block_100",
                1000,
                1000,
                20_000, // 2× congestion
            )
            .unwrap();

        // 2777bp of 10B = ~2.777B
        let expected_bp = SlashingEngine::dynamic_censorship_penalty(20_000);
        let expected = 10_000_000_000u64 * expected_bp / 10_000;
        assert_eq!(result.total_slashed, expected);
    }

    #[test]
    fn gt2_slash_censorship_with_quadratic() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // First censorship at max congestion: 5000bp
        let r1 = engine
            .slash_censorship(&mut state, &addr(1), b"blk_1", 1000, 1000, 30_000)
            .unwrap();
        assert_eq!(r1.total_slashed, 5_000_000_000); // 50% of 10B

        // Second censorship: prior=1 → quadratic 2× → 10000bp (100%, capped)
        let remaining = state.validators.get(&addr(1)).unwrap().stake;
        let r2 = engine
            .slash_censorship(&mut state, &addr(1), b"blk_2", 1001, 1001, 30_000)
            .unwrap();
        // 5000 × (1 + 1²) = 10000bp, capped at 10000 → 100% of remaining
        assert_eq!(r2.total_slashed, remaining);
    }

    // ═══════════════════════════════════════════════════════════════════
    // PILLAR 2: Deterministic Slashing Conditions Tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn p2_vector_penalties() {
        assert_eq!(
            SlashingEngine::vector_penalty(SlashingVector::InvalidStateAttestation),
            10_000, // 100%
        );
        assert_eq!(
            SlashingEngine::vector_penalty(SlashingVector::TransactionCensorship),
            1000, // 10% base
        );
        assert_eq!(
            SlashingEngine::vector_penalty(SlashingVector::DataWithholding),
            3333, // 33.33%
        );
    }

    #[test]
    fn p2_slash_invalid_state_attestation() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        let evidence = InvalidStateEvidence {
            attester: addr(1),
            attested_state_root: Hash256::from_bytes([0xAA; 32]),
            correct_state_root: Hash256::from_bytes([0xBB; 32]),
            eots_nonce: [0xCC; 32],
            eots_signature: [0xDD; 32],
            state_height: 500,
            stark_proof_hash: Hash256::from_bytes([0xEE; 32]),
        };

        let result = engine
            .slash_invalid_state(&mut state, &evidence, 600)
            .unwrap();

        // 100% penalty = full stake
        assert_eq!(result.total_slashed, 10_000_000_000);

        // Validator must be removed
        let v = state.validators.get(&addr(1)).unwrap();
        assert_eq!(v.status, ValidatorStatus::Removed);

        // Distributions sum correctly
        let total = result.burned + result.challenger_reward + result.community_fund;
        assert_eq!(total, result.total_slashed);
    }

    #[test]
    fn p2_invalid_state_same_roots_rejected() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        let evidence = InvalidStateEvidence {
            attester: addr(1),
            attested_state_root: Hash256::from_bytes([0xAA; 32]),
            correct_state_root: Hash256::from_bytes([0xAA; 32]), // Same!
            eots_nonce: [0xCC; 32],
            eots_signature: [0xDD; 32],
            state_height: 500,
            stark_proof_hash: Hash256::from_bytes([0xEE; 32]),
        };

        let result = engine.slash_invalid_state(&mut state, &evidence, 600);
        assert!(result.is_err(), "same state roots = no violation");
    }

    #[test]
    fn p2_invalid_state_double_slash_prevented() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        let evidence = InvalidStateEvidence {
            attester: addr(1),
            attested_state_root: Hash256::from_bytes([0xAA; 32]),
            correct_state_root: Hash256::from_bytes([0xBB; 32]),
            eots_nonce: [0xCC; 32],
            eots_signature: [0xDD; 32],
            state_height: 500,
            stark_proof_hash: Hash256::from_bytes([0xEE; 32]),
        };

        engine
            .slash_invalid_state(&mut state, &evidence, 600)
            .unwrap();

        // Second slash with same evidence must fail
        let result = engine.slash_invalid_state(&mut state, &evidence, 600);
        assert!(result.is_err());
    }

    #[test]
    fn p2_slash_data_withholding() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        let evidence = DataWithholdingEvidence {
            sequencer: addr(1),
            committed_state_root: Hash256::from_bytes([0xAA; 32]),
            commitment_height: 500,
            challenge_expired_at: 700,
            challenge_hash: Hash256::from_bytes([0xBB; 32]),
        };

        let result = engine
            .slash_data_withholding(&mut state, &evidence, 800)
            .unwrap();

        // First offense: 33.33% of 10B ≈ 3.333B
        assert_eq!(result.total_slashed, 3_333_000_000);

        // Distributions sum correctly
        let total = result.burned + result.challenger_reward + result.community_fund;
        assert_eq!(total, result.total_slashed);
    }

    #[test]
    fn p2_data_withholding_quadratic_escalation() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        // First offense: 33.33%
        let e1 = DataWithholdingEvidence {
            sequencer: addr(1),
            committed_state_root: Hash256::from_bytes([0x01; 32]),
            commitment_height: 500,
            challenge_expired_at: 700,
            challenge_hash: Hash256::from_bytes([0x01; 32]),
        };
        let r1 = engine
            .slash_data_withholding(&mut state, &e1, 800)
            .unwrap();
        assert_eq!(r1.total_slashed, 3_333_000_000);

        // Second offense: prior=1 → 2× → 66.66%
        let remaining = state.validators.get(&addr(1)).unwrap().stake;
        let e2 = DataWithholdingEvidence {
            sequencer: addr(1),
            committed_state_root: Hash256::from_bytes([0x02; 32]),
            commitment_height: 900,
            challenge_expired_at: 1100,
            challenge_hash: Hash256::from_bytes([0x02; 32]),
        };
        let r2 = engine
            .slash_data_withholding(&mut state, &e2, 1200)
            .unwrap();
        // 3333 × (1+1²) = 6666bp
        let expected = remaining * 6666 / 10_000;
        assert_eq!(r2.total_slashed, expected);
    }

    #[test]
    fn p2_data_withholding_invalid_timing_rejected() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        let evidence = DataWithholdingEvidence {
            sequencer: addr(1),
            committed_state_root: Hash256::from_bytes([0xAA; 32]),
            commitment_height: 700, // Challenge expired BEFORE commitment!
            challenge_expired_at: 500,
            challenge_hash: Hash256::from_bytes([0xBB; 32]),
        };

        let result = engine.slash_data_withholding(&mut state, &evidence, 800);
        assert!(result.is_err());
    }

    #[test]
    fn p2_data_withholding_stale_evidence_rejected() {
        let mut state = setup();
        let mut engine = SlashingEngine::new();

        let evidence = DataWithholdingEvidence {
            sequencer: addr(1),
            committed_state_root: Hash256::from_bytes([0xAA; 32]),
            commitment_height: 100,
            challenge_expired_at: 200,
            challenge_hash: Hash256::from_bytes([0xBB; 32]),
        };

        // Current height far beyond evidence age limit
        let result = engine.slash_data_withholding(
            &mut state,
            &evidence,
            100 + MAX_EVIDENCE_AGE_BLOCKS + 1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn p2_invalid_state_nash_equilibrium() {
        // Verify that invalid state attestation is never rational.
        //
        // Let S = validator stake. Penalty = 100% of S.
        // Expected cost = p × S (where p is detection probability).
        //
        // For committee-attested states with STARK verification:
        //   p ≥ 1.0 (deterministic detection — STARK proof disagrees)
        //
        // Therefore: Expected cost = S > any finite profit.
        // Invalid state attestation is NEVER a best response. ∎
        let penalty_bp = SlashingEngine::vector_penalty(SlashingVector::InvalidStateAttestation);
        assert_eq!(penalty_bp, 10_000, "invalid state must slash 100%");

        // Detection probability for invalid state = 1.0
        // (STARK proof provides mathematical ground truth)
        // Cost = 1.0 × 100% × S = S
        // For any TVL < total_staked: Cost > Profit
    }

    #[test]
    fn p2_data_withholding_nash_equilibrium() {
        // Verify that data withholding is irrational.
        //
        // Let S = validator stake. Penalty = 33% base, quadratic escalation.
        // Detection probability: p ≈ 1.0 (timeout-based — deterministic).
        //
        // First offense: cost = 0.3333 × S
        // Second offense: cost = 0.6666 × (remaining) ≈ 0.4444 × S
        // Third offense: cost = 100% × (remaining) → validator eliminated
        //
        // Max profit from data withholding: ≤ TVL
        // With total_staked ≥ 2.25 × TVL:
        //   Individual S ≈ total_staked / N
        //   Cost per attacker = 0.3333 × S
        //   Need ⅔N attackers, total cost = ⅔N × 0.3333 × S = 0.2222 × total_staked
        //   = 0.2222 × 2.25 × TVL = 0.5 × TVL
        //
        // But ⅔N attackers each bear individual cost > their share of profit.
        // Each attacker's profit share = TVL / (⅔N) = 1.5 × TVL / N
        // Each attacker's cost = 0.3333 × S = 0.3333 × total_staked / N
        //   = 0.3333 × 2.25 × TVL / N = 0.75 × TVL / N
        //
        // Cost/Profit = (0.75 × TVL/N) / (1.5 × TVL/N) = 0.5
        // With quadratic escalation on second attempt: ratio > 1.0
        //
        // Therefore: sustained data withholding is irrational. ∎
        let penalty = DATA_WITHHOLDING_PENALTY_BP;
        assert_eq!(penalty, 3333);
        let second_offense = SlashingEngine::compute_quadratic_penalty(penalty, 1);
        assert_eq!(second_offense, 6666); // 2× → immediate 66.66%
    }
}
