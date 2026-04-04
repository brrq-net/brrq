//! Epoch management with RANDAO commit-reveal randomness.
//!
//! An epoch is a fixed-length period during which:
//! - Validators commit to signing keys (SLH-DSA + Schnorr/EOTS)
//! - Stake weights and caps are stable
//! - Leader election parameters are fixed
//!
//! Epoch boundaries trigger:
//! - Key rotation for all validators
//! - Stake cap recalculation
//! - Daily timeout counter resets
//!
//! ## RANDAO Commit-Reveal (§9.1 Security)
//!
//! The epoch seed is derived via a RANDAO-style protocol to prevent
//! any single validator from predicting or grinding future leaders:
//!
//! 1. **Commit phase**: Each validator submits `H(secret)` during the epoch.
//! 2. **Reveal phase**: At epoch boundary, validators reveal their `secret`.
//!    The system verifies `H(secret) == commitment`.
//! 3. **Seed derivation**: `epoch_seed = XOR(all revealed secrets) ^ H(prev_seed)`.
//!
//! If a validator commits but fails to reveal, their commitment is excluded
//! and they receive a reputation penalty (handled by the caller).

use imbl::HashMap;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_types::Address;

use crate::error::ConsensusError;
use crate::slashing::{SlashingEngine, SlashingReason};
use crate::staking::StakingState;
use crate::validator::CONSECUTIVE_RANDAO_LIMIT;

/// Default epoch length in blocks (~6 hours at 3-5s/block).
pub const DEFAULT_EPOCH_LENGTH: u64 = 7_200;

/// Fraction of epoch (denominator) after which reveals are locked out.
/// Reveals are only accepted during the first 3/4 of the epoch.
/// This prevents last-moment reveal manipulation where a validator waits
/// until the very end to decide whether to reveal based on others' reveals.
const REVEAL_DEADLINE_FRACTION: u64 = 4;

/// Epoch state.
#[derive(Debug, Clone)]
pub struct EpochState {
    /// Current epoch number.
    pub current_epoch: u64,
    /// Block height when current epoch started.
    pub epoch_start_height: u64,
    /// Epoch length in blocks.
    pub epoch_length: u64,
    /// Randomness seed for this epoch (derived from RANDAO reveals).
    ///
    /// **MEV safety**: This field is set during epoch transitions but the
    /// sequencer MUST NOT use it for `EpochKey` derivation directly.
    /// Instead, the epoch key is derived via `EpochKey::derive_with_anchor`
    /// which requires the L1 block hash — unavailable until after the
    /// ordering commitment is mined on L1.
    pub epoch_seed: Hash256,
    /// Pending epoch seed — set during transition, not yet revealed for MEV decryption.
    ///
    /// The pending seed becomes available for key derivation only after
    /// `reveal_epoch_seed()` is called, which requires proof that the
    /// ordering commitment has been anchored on L1.
    pending_epoch_seed: Option<Hash256>,
    /// Whether the epoch seed has been revealed for MEV decryption.
    /// This is set to `true` by `reveal_epoch_seed()` after the ordering
    /// commitment is confirmed on L1.
    epoch_seed_revealed: bool,
    /// The L1 block hash that anchored the ordering commitment.
    /// Required for `EpochKey::derive_with_anchor`. Only set after
    /// `reveal_epoch_seed()` is called with the L1 anchor hash.
    l1_anchor_hash: Option<Hash256>,
    /// Validator set snapshot for this epoch (addresses of active validators).
    pub validator_set: Vec<Address>,
    /// RANDAO commitments for the next epoch: validator → H(secret).
    randao_commitments: HashMap<Address, Hash256>,
    /// RANDAO reveals for the next epoch: validator → secret.
    randao_reveals: HashMap<Address, Hash256>,
}

impl EpochState {
    /// Create a new epoch state.
    pub fn new(epoch_length: u64) -> Self {
        Self {
            current_epoch: 0,
            epoch_start_height: 0,
            epoch_length,
            epoch_seed: Hash256::ZERO,
            pending_epoch_seed: None,
            epoch_seed_revealed: false,
            l1_anchor_hash: None,
            validator_set: Vec::new(),
            randao_commitments: HashMap::new(),
            randao_reveals: HashMap::new(),
        }
    }

    /// Check if a block height is at an epoch boundary.
    pub fn is_epoch_boundary(&self, height: u64) -> bool {
        height > 0 && (height - self.epoch_start_height) >= self.epoch_length
    }

    /// Compute the epoch number for a given block height.
    ///
    /// Uses `epoch_start_height` to be consistent with `is_epoch_boundary()`.
    /// The current epoch is the base epoch plus completed epoch-lengths since start.
    pub fn epoch_for_height(&self, height: u64) -> u64 {
        if height < self.epoch_start_height {
            // Height before current epoch start — compute from genesis.
            height / self.epoch_length
        } else {
            self.current_epoch + (height - self.epoch_start_height) / self.epoch_length
        }
    }

    /// Submit a RANDAO commitment `H(secret)` for the next epoch.
    ///
    /// Each validator must commit exactly once per epoch. Duplicate
    /// commitments from the same validator are silently replaced.
    ///
    /// # Errors
    /// - Zero commitment (trivially guessable, always invalid)
    /// - Validator not in the active set for this epoch
    pub fn submit_randao_commitment(
        &mut self,
        validator: Address,
        commitment: Hash256,
    ) -> Result<(), ConsensusError> {
        // Reject zero commitment (H(x) == 0 is computationally infeasible
        // for SHA-256; a zero value indicates a bug or attack)
        if commitment == Hash256::ZERO {
            return Err(ConsensusError::InvalidRandaoCommitment {
                reason: "commitment must be non-zero".into(),
            });
        }

        // Validator must be in the active set for this epoch
        if !self.validator_set.contains(&validator) {
            return Err(ConsensusError::InvalidRandaoCommitment {
                reason: format!("validator {validator} not in active set"),
            });
        }

        self.randao_commitments.insert(validator, commitment);
        Ok(())
    }

    /// Submit a RANDAO reveal (the secret whose hash was committed).
    ///
    /// Returns `true` if the reveal matches the commitment, `false` otherwise.
    /// Invalid reveals are silently discarded.
    ///
    /// Accepts `current_height` to enforce a reveal deadline.
    /// Reveals are rejected in the final 1/4 of the epoch to prevent
    /// last-moment manipulation where a validator withholds or submits
    /// strategically based on others' reveals.
    pub fn submit_randao_reveal(
        &mut self,
        validator: Address,
        secret: Hash256,
        current_height: u64,
    ) -> bool {
        // Enforce reveal deadline
        let blocks_into_epoch = current_height.saturating_sub(self.epoch_start_height);
        let deadline =
            self.epoch_length * (REVEAL_DEADLINE_FRACTION - 1) / REVEAL_DEADLINE_FRACTION;
        if blocks_into_epoch > deadline {
            return false;
        }

        let commitment = match self.randao_commitments.get(&validator) {
            Some(c) => *c,
            None => return false,
        };

        // Verify: H(secret) == commitment
        let computed = Hasher::hash(secret.as_bytes());
        if computed != commitment {
            return false;
        }

        self.randao_reveals.insert(validator, secret);
        true
    }

    /// Number of validators that have committed for the next epoch.
    pub fn randao_commitment_count(&self) -> usize {
        self.randao_commitments.len()
    }

    /// Number of validators that have revealed for the next epoch.
    pub fn randao_reveal_count(&self) -> usize {
        self.randao_reveals.len()
    }

    /// Transition to a new epoch.
    ///
    /// This should be called at each epoch boundary to:
    /// 1. Snapshot the active validator set
    /// 2. Recalculate stake cap
    /// 3. Derive new epoch seed from RANDAO reveals
    /// 4. Track RANDAO non-reveal counters and slash after 3 consecutive failures
    /// 5. Reset daily timeout counters
    /// 6. Clear RANDAO state for the next epoch
    ///
    /// Returns the list of validators who committed but failed to reveal.
    /// Automatically increments `consecutive_randao_failures` for
    /// non-revealers (resets to 0 for successful revealers). When the counter
    /// reaches `CONSECUTIVE_RANDAO_LIMIT` (2), a 5% slash is applied.
    pub fn transition(
        &mut self,
        height: u64,
        staking: &mut StakingState,
        last_block_hash: &Hash256,
        slashing_engine: &mut SlashingEngine,
    ) -> Vec<Address> {
        self.current_epoch += 1;
        self.epoch_start_height = height;

        // Derive new epoch seed from RANDAO reveals + chain entropy
        //
        // seed = H("EPOCH_SEED" || prev_seed || epoch || last_block_hash || randao_component)
        //
        // The XOR of all reveals provides the unbiasable randomness.
        // The prev_seed + last_block_hash provide chain continuity as fallback
        // when no reveals are available (e.g., genesis or early epochs).

        // Minimum reveal threshold to prevent RANDAO manipulation.
        // If fewer than 2/3 of active validators revealed, the RANDAO entropy
        // is unreliable. Fall back to pure chain entropy.
        let min_reveals = (self.validator_set.len() * 2).div_ceil(3); // ceil(2n/3)
        let use_randao = self.randao_reveals.len() >= min_reveals;

        let randao_component = if use_randao {
            self.compute_randao_xor()
        } else {
            Hash256::ZERO
        };

        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::EPOCH_SEED_RANDAO);
        hasher.update(self.epoch_seed.as_bytes());
        hasher.update(&self.current_epoch.to_le_bytes());
        hasher.update(last_block_hash.as_bytes());
        hasher.update(randao_component.as_bytes());
        let new_seed = hasher.finalize();

        // Store the new seed as pending — it is NOT immediately available
        // for MEV epoch key derivation. The sequencer must first commit
        // the ordering on L1, then call reveal_epoch_seed() with the
        // L1 block hash to unlock it for key derivation.
        self.pending_epoch_seed = Some(new_seed);
        self.epoch_seed_revealed = false;
        self.l1_anchor_hash = None;

        // The epoch_seed field is still updated for non-MEV uses
        // (leader election, RANDAO continuity, etc.) but MUST NOT be
        // used for EpochKey derivation by the sequencer.
        self.epoch_seed = new_seed;

        // Identify validators who committed but did not reveal
        let non_revealers: Vec<Address> = self
            .randao_commitments
            .keys()
            .filter(|addr| !self.randao_reveals.contains_key(addr))
            .copied()
            .collect();

        // Collect successful revealers for counter reset
        let revealers: Vec<Address> = self.randao_reveals.keys().copied().collect();

        // Reset consecutive_randao_failures for successful revealers
        for addr in &revealers {
            if let Some(v) = staking.validators.get_mut(addr) {
                v.consecutive_randao_failures = 0;
            }
        }

        // Increment consecutive_randao_failures for non-revealers
        // and trigger slashing when the limit is reached.
        for addr in &non_revealers {
            if let Some(v) = staking.validators.get_mut(addr) {
                v.consecutive_randao_failures = v.consecutive_randao_failures.saturating_add(1);

                if v.consecutive_randao_failures >= CONSECUTIVE_RANDAO_LIMIT {
                    // Build a unique offense context: epoch number for dedup
                    let mut context = Vec::with_capacity(8);
                    context.extend_from_slice(&self.current_epoch.to_le_bytes());

                    // Apply the slash. Errors (e.g. already-processed, removed
                    // validator) are intentionally ignored — the non-revealer
                    // list is still returned to the caller for logging/metrics.
                    let _ = slashing_engine.slash(
                        staking,
                        addr,
                        SlashingReason::RandaoNonReveal,
                        &context,
                        height,
                        height,
                    );

                    // Reset the counter after slashing so the validator must
                    // accumulate 3 new failures before being slashed again.
                    if let Some(v) = staking.validators.get_mut(addr) {
                        v.consecutive_randao_failures = 0;
                    }
                }
            }
        }

        // Clear RANDAO state for next epoch
        self.randao_commitments.clear();
        self.randao_reveals.clear();

        // Prune old processed offense records to prevent unbounded growth.
        slashing_engine.prune_old_offenses(height);

        // Reactivate validators whose suspension period has expired.
        // Without this, suspended validators' status never transitions back to Active,
        // excluding them from active_validators_sorted() and total_effective_stake().
        staking.reactivate_expired_suspensions(height);

        // Recalculate stake cap with current height to respect cap cooldown.
        staking.process_exit_queue(height);
        staking.recalculate_cap_at_height(height);

        // Snapshot active validator set
        self.validator_set = staking
            .validators
            .iter()
            .filter(|(_, v)| v.status == crate::validator::ValidatorStatus::Active)
            .map(|(addr, _)| *addr)
            .collect();
        self.validator_set.sort();

        // Reset daily timeout counters
        for (_, v) in staking.validators.iter_mut() {
            v.reset_daily_timeouts();
        }

        non_revealers
    }

    /// Reveal the epoch seed for MEV key derivation.
    ///
    /// This method MUST only be called after the ordering commitment has been
    /// anchored on L1. The `l1_anchor_hash` is the Bitcoin block hash
    /// containing the ordering commitment transaction.
    ///
    /// After this call, `revealed_epoch_seed()` and `l1_anchor_hash()` become
    /// available, enabling `EpochKey::derive_with_anchor()`.
    ///
    /// # Errors
    /// - No pending seed (epoch transition has not occurred yet)
    /// - Seed already revealed (double-reveal attempt)
    /// - Zero L1 anchor hash (invalid anchor)
    pub fn reveal_epoch_seed(
        &mut self,
        l1_anchor_hash: Hash256,
    ) -> Result<(), ConsensusError> {
        if self.pending_epoch_seed.is_none() {
            return Err(ConsensusError::InvalidRandaoCommitment {
                reason: "no pending epoch seed to reveal".into(),
            });
        }
        if self.epoch_seed_revealed {
            return Err(ConsensusError::InvalidRandaoCommitment {
                reason: "epoch seed already revealed for this epoch".into(),
            });
        }
        if l1_anchor_hash == Hash256::ZERO {
            return Err(ConsensusError::InvalidRandaoCommitment {
                reason: "L1 anchor hash must be non-zero".into(),
            });
        }

        self.epoch_seed_revealed = true;
        self.l1_anchor_hash = Some(l1_anchor_hash);
        Ok(())
    }

    /// Get the revealed epoch seed for MEV key derivation.
    ///
    /// Returns `None` if the seed has not been revealed yet (i.e.,
    /// `reveal_epoch_seed()` has not been called for this epoch).
    pub fn revealed_epoch_seed(&self) -> Option<&Hash256> {
        if self.epoch_seed_revealed {
            self.pending_epoch_seed.as_ref()
        } else {
            None
        }
    }

    /// Get the L1 anchor hash for anchored epoch key derivation.
    ///
    /// Returns `None` if the epoch seed has not been revealed yet.
    pub fn l1_anchor_hash(&self) -> Option<&Hash256> {
        self.l1_anchor_hash.as_ref()
    }

    /// Whether the epoch seed has been revealed for MEV decryption.
    pub fn is_epoch_seed_revealed(&self) -> bool {
        self.epoch_seed_revealed
    }

    /// Split the revealed epoch key into Shamir shares for threshold decryption.
    ///
    /// Called by the leader after `reveal_epoch_seed()` succeeds. Produces
    /// one [`KeyShare`] per validator in the current epoch's validator set.
    ///
    /// The threshold is `max(N/2 + 1, 2)` — a strict majority is required
    /// to reconstruct the key. For testnet (N=3) this means threshold=2.
    ///
    /// # Errors
    /// - Epoch seed not yet revealed
    /// - Fewer than 3 validators (minimum for threshold scheme)
    pub fn split_epoch_key_shares(
        &self,
    ) -> Result<(Vec<brrq_crypto::encryption::KeyShare>, brrq_crypto::encryption::ThresholdEncryptionConfig, brrq_crypto::encryption::ShareCommitments), ConsensusError> {
        let seed = self.revealed_epoch_seed().ok_or_else(|| {
            ConsensusError::InvalidRandaoCommitment {
                reason: "cannot split shares: epoch seed not yet revealed".into(),
            }
        })?;
        let anchor = self.l1_anchor_hash().ok_or_else(|| {
            ConsensusError::InvalidRandaoCommitment {
                reason: "cannot split shares: no L1 anchor hash".into(),
            }
        })?;

        let n = self.validator_set.len() as u32;
        if n < 3 {
            return Err(ConsensusError::InvalidRandaoCommitment {
                reason: format!("need at least 3 validators for threshold scheme, got {n}"),
            });
        }

        let threshold = std::cmp::max(n / 2 + 1, 2);
        let config = brrq_crypto::encryption::ThresholdEncryptionConfig::new(threshold, n)
            .map_err(|e| ConsensusError::InvalidRandaoCommitment {
                reason: format!("invalid threshold config: {e}"),
            })?;

        let epoch_key = brrq_crypto::encryption::EpochKey::derive_with_anchor(
            seed,
            self.current_epoch,
            anchor,
        );

        let (shares, commitments) = brrq_crypto::encryption::split_secret(&epoch_key, &config)
            .map_err(|e| ConsensusError::InvalidRandaoCommitment {
                reason: format!("failed to split epoch key: {e}"),
            })?;

        Ok((shares, config, commitments))
    }

    /// Compute the threshold required for the current validator set.
    ///
    /// `threshold = max(N/2 + 1, 2)` — strict majority.
    pub fn threshold_for_current_set(&self) -> u32 {
        let n = self.validator_set.len() as u32;
        std::cmp::max(n / 2 + 1, 2)
    }

    /// Compute XOR of all RANDAO reveals, then hash for bias resistance.
    ///
    /// After computing the raw XOR, we hash the result with the
    /// epoch number and previous seed. This makes the output computationally
    /// infeasible to predict even if the last actor knows all other reveals,
    /// mitigating last-actor bias in the RANDAO protocol.
    ///
    /// Deterministic: reveals are sorted by validator address before XOR
    /// to ensure all nodes compute the same result regardless of insertion order.
    fn compute_randao_xor(&self) -> Hash256 {
        if self.randao_reveals.is_empty() {
            return Hash256::ZERO;
        }

        // Sort by address for deterministic ordering
        let mut reveals: Vec<(&Address, &Hash256)> = self.randao_reveals.iter().collect();
        reveals.sort_by_key(|(addr, _)| **addr);

        let mut xor_result = [0u8; 32];
        for (_, secret) in &reveals {
            let secret_bytes = secret.as_bytes();
            for (i, byte) in xor_result.iter_mut().enumerate() {
                *byte ^= secret_bytes[i];
            }
        }

        // Hash the XOR result with epoch number and previous seed
        // to prevent last-actor bias. The last revealer cannot predict the
        // hash output, so withholding provides no advantage.
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::RANDAO_XOR_HASH);
        hasher.update(&xor_result);
        hasher.update(&self.current_epoch.to_le_bytes());
        hasher.update(self.epoch_seed.as_bytes());
        hasher.finalize()
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

    fn make_secret(n: u8) -> Hash256 {
        Hasher::hash(&[n; 32])
    }

    fn make_commitment(secret: &Hash256) -> Hash256 {
        Hasher::hash(secret.as_bytes())
    }

    #[test]
    fn test_epoch_boundary() {
        let epoch = EpochState::new(100);
        assert!(!epoch.is_epoch_boundary(0));
        assert!(!epoch.is_epoch_boundary(50));
        assert!(!epoch.is_epoch_boundary(99));
        assert!(epoch.is_epoch_boundary(100));
        assert!(epoch.is_epoch_boundary(200));
    }

    #[test]
    fn test_epoch_for_height() {
        let epoch = EpochState::new(100);
        assert_eq!(epoch.epoch_for_height(0), 0);
        assert_eq!(epoch.epoch_for_height(99), 0);
        assert_eq!(epoch.epoch_for_height(100), 1);
        assert_eq!(epoch.epoch_for_height(250), 2);
    }

    #[test]
    fn test_epoch_transition() {
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();
        staking.register_validator(addr(2), 2_000_000_000).unwrap();

        let non_revealers = epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        assert_eq!(epoch.current_epoch, 1);
        assert_eq!(epoch.epoch_start_height, 100);
        assert_ne!(epoch.epoch_seed, Hash256::ZERO);
        assert_eq!(epoch.validator_set.len(), 2);
        assert!(non_revealers.is_empty());
    }

    #[test]
    fn test_epoch_seed_changes() {
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();

        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);
        let seed1 = epoch.epoch_seed;

        epoch.transition(200, &mut staking, &Hash256::ZERO, &mut slashing);
        let seed2 = epoch.epoch_seed;

        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_timeout_reset_on_transition() {
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();

        // Record some timeouts
        staking
            .validators
            .get_mut(&addr(1))
            .unwrap()
            .timeout_count_24h = 5;

        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        assert_eq!(
            staking.validators.get(&addr(1)).unwrap().timeout_count_24h,
            0
        );
    }

    // ── RANDAO commit-reveal tests ──────────────────────────────────

    #[test]
    fn test_randao_commit_reveal_basic() {
        let mut epoch = EpochState::new(100);
        epoch.validator_set = vec![addr(1)];

        let secret = make_secret(1);
        let commitment = make_commitment(&secret);

        epoch.submit_randao_commitment(addr(1), commitment).unwrap();
        assert_eq!(epoch.randao_commitment_count(), 1);

        let ok = epoch.submit_randao_reveal(addr(1), secret, 50);
        assert!(ok, "valid reveal should succeed");
        assert_eq!(epoch.randao_reveal_count(), 1);
    }

    #[test]
    fn test_randao_invalid_reveal_rejected() {
        let mut epoch = EpochState::new(100);
        epoch.validator_set = vec![addr(1)];

        let secret = make_secret(1);
        let commitment = make_commitment(&secret);
        epoch.submit_randao_commitment(addr(1), commitment).unwrap();

        // Submit wrong secret
        let wrong_secret = make_secret(99);
        let ok = epoch.submit_randao_reveal(addr(1), wrong_secret, 50);
        assert!(!ok, "invalid reveal should be rejected");
        assert_eq!(epoch.randao_reveal_count(), 0);
    }

    #[test]
    fn test_randao_reveal_without_commitment() {
        let mut epoch = EpochState::new(100);

        let secret = make_secret(1);
        let ok = epoch.submit_randao_reveal(addr(1), secret, 50);
        assert!(!ok, "reveal without commitment should fail");
    }

    #[test]
    fn test_randao_affects_epoch_seed() {
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();

        // Transition without RANDAO reveals
        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);
        let seed_no_randao = epoch.epoch_seed;

        // Reset to epoch 0
        let mut epoch2 = EpochState::new(100);
        epoch2.validator_set = vec![addr(1)];

        // Submit RANDAO commitment + reveal
        let secret = make_secret(42);
        let commitment = make_commitment(&secret);
        epoch2
            .submit_randao_commitment(addr(1), commitment)
            .unwrap();
        epoch2.submit_randao_reveal(addr(1), secret, 50);

        epoch2.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);
        let seed_with_randao = epoch2.epoch_seed;

        assert_ne!(
            seed_no_randao, seed_with_randao,
            "RANDAO reveals must change the epoch seed"
        );
    }

    #[test]
    fn test_randao_non_revealers_reported() {
        let mut epoch = EpochState::new(100);
        epoch.validator_set = vec![addr(1), addr(2)];
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();
        staking.register_validator(addr(2), 1_000_000_000).unwrap();

        // Validator 1: commits and reveals
        let secret1 = make_secret(1);
        epoch
            .submit_randao_commitment(addr(1), make_commitment(&secret1))
            .unwrap();
        epoch.submit_randao_reveal(addr(1), secret1, 50);

        // Validator 2: commits but does NOT reveal
        let secret2 = make_secret(2);
        epoch
            .submit_randao_commitment(addr(2), make_commitment(&secret2))
            .unwrap();

        let non_revealers = epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        assert_eq!(non_revealers.len(), 1);
        assert_eq!(non_revealers[0], addr(2));
    }

    #[test]
    fn test_randao_state_cleared_after_transition() {
        let mut epoch = EpochState::new(100);
        epoch.validator_set = vec![addr(1)];
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();

        let secret = make_secret(1);
        epoch
            .submit_randao_commitment(addr(1), make_commitment(&secret))
            .unwrap();
        epoch.submit_randao_reveal(addr(1), secret, 50);

        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        assert_eq!(
            epoch.randao_commitment_count(),
            0,
            "commitments must be cleared"
        );
        assert_eq!(epoch.randao_reveal_count(), 0, "reveals must be cleared");
    }

    #[test]
    fn test_randao_multiple_validators_xor() {
        let mut epoch1 = EpochState::new(100);
        epoch1.validator_set = vec![addr(1), addr(2)];
        let mut epoch2 = EpochState::new(100);
        epoch2.validator_set = vec![addr(1), addr(2)];
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();
        staking.register_validator(addr(2), 1_000_000_000).unwrap();

        let secret1 = make_secret(10);
        let secret2 = make_secret(20);

        // Epoch1: both validators reveal
        epoch1
            .submit_randao_commitment(addr(1), make_commitment(&secret1))
            .unwrap();
        epoch1
            .submit_randao_commitment(addr(2), make_commitment(&secret2))
            .unwrap();
        epoch1.submit_randao_reveal(addr(1), secret1, 50);
        epoch1.submit_randao_reveal(addr(2), secret2, 50);

        // Epoch2: only validator 1 reveals
        epoch2
            .submit_randao_commitment(addr(1), make_commitment(&secret1))
            .unwrap();
        epoch2.submit_randao_reveal(addr(1), secret1, 50);

        epoch1.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);
        epoch2.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        assert_ne!(
            epoch1.epoch_seed, epoch2.epoch_seed,
            "Different reveal sets must produce different seeds"
        );
    }

    // ── RANDAO bias mitigation tests ─────────────────────────────

    #[test]
    fn test_v06_randao_threshold_fallback() {
        // With 3 validators in the set, min_reveals = ceil(2*3/3) = 2.
        // If only 1 reveals, RANDAO should be ignored (fallback to chain entropy).
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();
        staking.register_validator(addr(2), 1_000_000_000).unwrap();
        staking.register_validator(addr(3), 1_000_000_000).unwrap();

        // First transition to populate validator_set (3 validators)
        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);
        let seed_after_first = epoch.epoch_seed;
        assert_eq!(epoch.validator_set.len(), 3);

        // Second transition with only 1 RANDAO reveal (below 2/3 threshold)
        let secret1 = make_secret(1);
        epoch
            .submit_randao_commitment(addr(1), make_commitment(&secret1))
            .unwrap();
        epoch.submit_randao_reveal(addr(1), secret1, 150);

        epoch.transition(200, &mut staking, &Hash256::ZERO, &mut slashing);
        let seed_insufficient_reveals = epoch.epoch_seed;

        // Third transition, reset and do with NO reveals at all
        // (also falls back, so should use same randao_component = ZERO)
        let mut epoch2 = EpochState::new(100);
        let mut slashing2 = SlashingEngine::new();
        // Manually set up to match state after first transition
        epoch2.current_epoch = 1;
        epoch2.epoch_start_height = 100;
        epoch2.epoch_seed = seed_after_first;
        epoch2.validator_set = vec![addr(1), addr(2), addr(3)];

        // No reveals at all
        epoch2.transition(200, &mut staking, &Hash256::ZERO, &mut slashing2);
        let seed_no_reveals = epoch2.epoch_seed;

        // Both should produce the same seed since both fall back to Hash256::ZERO
        // for the randao component (insufficient reveals)
        assert_eq!(
            seed_insufficient_reveals, seed_no_reveals,
            "Below-threshold reveals should be treated same as no reveals"
        );
    }

    #[test]
    fn test_v06_randao_threshold_met() {
        // With 3 validators, min_reveals = 2. If 2 reveal, RANDAO is used.
        let mut epoch_with = EpochState::new(100);
        let mut epoch_without = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 1_000_000_000).unwrap();
        staking.register_validator(addr(2), 1_000_000_000).unwrap();
        staking.register_validator(addr(3), 1_000_000_000).unwrap();

        // First transition to populate validator_set
        epoch_with.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);
        epoch_without.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        // epoch_with: 2 reveals (meets threshold)
        let secret1 = make_secret(10);
        let secret2 = make_secret(20);
        epoch_with
            .submit_randao_commitment(addr(1), make_commitment(&secret1))
            .unwrap();
        epoch_with
            .submit_randao_commitment(addr(2), make_commitment(&secret2))
            .unwrap();
        epoch_with.submit_randao_reveal(addr(1), secret1, 150);
        epoch_with.submit_randao_reveal(addr(2), secret2, 150);

        // epoch_without: no reveals (below threshold)
        epoch_with.transition(200, &mut staking, &Hash256::ZERO, &mut slashing);
        epoch_without.transition(200, &mut staking, &Hash256::ZERO, &mut slashing);

        assert_ne!(
            epoch_with.epoch_seed, epoch_without.epoch_seed,
            "Sufficient reveals should produce different seed than no reveals"
        );
    }

    #[test]
    fn test_v06_randao_xor_is_hashed() {
        // Verify that compute_randao_xor returns a hashed result,
        // not the raw XOR. The raw XOR of a single secret would equal
        // the secret itself, but hashing changes it.
        let mut epoch = EpochState::new(100);
        epoch.validator_set = vec![addr(1)];
        let secret = make_secret(42);
        epoch
            .submit_randao_commitment(addr(1), make_commitment(&secret))
            .unwrap();
        epoch.submit_randao_reveal(addr(1), secret, 50);

        let xor_result = epoch.compute_randao_xor();
        // The result should NOT equal the raw secret (it's been hashed)
        assert_ne!(
            xor_result, secret,
            "compute_randao_xor should hash the XOR, not return raw XOR"
        );
    }

    // ── RANDAO commitment validation tests ─────────────────────

    #[test]
    fn test_randao_zero_commitment_rejected() {
        let mut epoch = EpochState::new(100);
        epoch.validator_set = vec![addr(1)];

        let result = epoch.submit_randao_commitment(addr(1), Hash256::ZERO);
        assert!(result.is_err(), "zero commitment must be rejected");
    }

    #[test]
    fn test_randao_non_active_validator_rejected() {
        let mut epoch = EpochState::new(100);
        epoch.validator_set = vec![addr(1)]; // only addr(1) is active

        let secret = make_secret(1);
        let commitment = make_commitment(&secret);

        // addr(2) is not in the active set
        let result = epoch.submit_randao_commitment(addr(2), commitment);
        assert!(result.is_err(), "non-active validator must be rejected");
    }

    #[test]
    fn test_randao_active_validator_accepted() {
        let mut epoch = EpochState::new(100);
        epoch.validator_set = vec![addr(1), addr(2)];

        let secret = make_secret(1);
        let commitment = make_commitment(&secret);

        let result = epoch.submit_randao_commitment(addr(1), commitment);
        assert!(
            result.is_ok(),
            "active validator with valid commitment must succeed"
        );
        assert_eq!(epoch.randao_commitment_count(), 1);
    }

    // ── RANDAO non-revealer slashing tests ─────────────────────

    /// Helper: commit (but do NOT reveal) for a validator during an epoch,
    /// then transition. Returns the non-revealers list.
    fn commit_no_reveal_and_transition(
        epoch: &mut EpochState,
        staking: &mut StakingState,
        slashing: &mut SlashingEngine,
        non_revealer: Address,
        secret_seed: u8,
        height: u64,
    ) -> Vec<Address> {
        let secret = make_secret(secret_seed);
        epoch
            .submit_randao_commitment(non_revealer, make_commitment(&secret))
            .unwrap();
        epoch.transition(height, staking, &Hash256::ZERO, slashing)
    }

    #[test]
    fn test_wi5a_randao_counter_increments_on_non_reveal() {
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 10_000_000_000).unwrap();

        // First transition to populate validator_set
        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);
        assert_eq!(epoch.validator_set, vec![addr(1)]);

        // Epoch 2: validator commits but does NOT reveal
        let non_revealers = commit_no_reveal_and_transition(
            &mut epoch,
            &mut staking,
            &mut slashing,
            addr(1),
            1,
            200,
        );

        assert_eq!(non_revealers.len(), 1);
        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            1,
            "counter should be 1 after first non-reveal"
        );
    }

    #[test]
    fn test_wi5a_randao_counter_resets_on_successful_reveal() {
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 10_000_000_000).unwrap();

        // First transition to populate validator_set
        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        // Epoch 2: non-reveal (counter → 1)
        commit_no_reveal_and_transition(&mut epoch, &mut staking, &mut slashing, addr(1), 1, 200);
        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            1,
        );

        // Epoch 3: successful reveal (counter → 0)
        let secret = make_secret(10);
        epoch
            .submit_randao_commitment(addr(1), make_commitment(&secret))
            .unwrap();
        epoch.submit_randao_reveal(addr(1), secret, 250);
        epoch.transition(300, &mut staking, &Hash256::ZERO, &mut slashing);

        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            0,
            "counter must reset to 0 after a successful reveal"
        );
    }

    #[test]
    fn test_wi5a_randao_slash_after_3_consecutive_failures() {
        // Slash happens on the 2nd consecutive non-reveal.
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 10_000_000_000).unwrap(); // 100 BTC

        // First transition to populate validator_set
        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        let stake_before = staking.validators.get(&addr(1)).unwrap().stake;

        // Epoch 2: non-reveal #1 (counter → 1, no slash — first failure is a warning)
        commit_no_reveal_and_transition(&mut epoch, &mut staking, &mut slashing, addr(1), 1, 200);
        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            1,
        );
        assert_eq!(
            staking.validators.get(&addr(1)).unwrap().stake,
            stake_before,
            "no slash after 1 failure (warning only)"
        );

        // Epoch 3: non-reveal #2 (counter hits 2 → SLASH → counter reset to 0)
        commit_no_reveal_and_transition(&mut epoch, &mut staking, &mut slashing, addr(1), 2, 300);

        // After the slash, the counter should be reset to 0
        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            0,
            "counter must reset after slashing"
        );

        // Stake should have been reduced by 15% (1500 basis points).
        let expected_slash = stake_before * 1500 / 10_000; // 15% of 10B = 1.5B
        let expected_remaining = stake_before - expected_slash;
        assert_eq!(
            staking.validators.get(&addr(1)).unwrap().stake,
            expected_remaining,
            "validator should have been slashed 15% after 2 consecutive RANDAO failures"
        );

        // The slashing engine should have recorded the offense
        assert_eq!(slashing.processed_offense_count(), 1);
    }

    #[test]
    fn test_wi5a_randao_no_slash_at_1_then_reset() {
        // With LIMIT=2, verify that 1 failure followed by a reveal
        // does NOT trigger slash, and the counter resets properly.
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 10_000_000_000).unwrap();

        // Populate validator set
        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);
        let stake_before = staking.validators.get(&addr(1)).unwrap().stake;

        // 1 non-reveal (counter → 1, no slash — just a warning)
        commit_no_reveal_and_transition(&mut epoch, &mut staking, &mut slashing, addr(1), 1, 200);
        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            1,
        );
        // Successful reveal resets counter.
        // Reveal must happen within the deadline: epoch_start + epoch_length * 3/4.
        // Epoch started at height 200, deadline = 200 + 75 = height 275.
        let secret = make_secret(50);
        epoch
            .submit_randao_commitment(addr(1), make_commitment(&secret))
            .unwrap();
        let revealed = epoch.submit_randao_reveal(addr(1), secret, 250);
        assert!(revealed, "reveal must be accepted (within deadline)");
        epoch.transition(400, &mut staking, &Hash256::ZERO, &mut slashing);
        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            0,
        );

        // 1 more non-reveal (counter 1 — still no slash, warning only)
        commit_no_reveal_and_transition(&mut epoch, &mut staking, &mut slashing, addr(1), 3, 500);
        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            1,
        );

        // Stake unchanged — no slash occurred (both times only 1 failure before reset)
        assert_eq!(
            staking.validators.get(&addr(1)).unwrap().stake,
            stake_before,
            "1 failure, reset, 1 more failure should NOT trigger slash"
        );
        assert_eq!(slashing.processed_offense_count(), 0);
    }

    #[test]
    fn test_c2_epoch_transition_respects_cap_cooldown() {
        // C-2: New validators registered just before epoch transition should NOT
        // affect cap calculation if they haven't passed the cooldown period.
        use crate::staking::NEW_VALIDATOR_CAP_COOLDOWN;

        let cooldown = NEW_VALIDATOR_CAP_COOLDOWN;
        let epoch_len = 100;
        let mut epoch = EpochState::new(epoch_len);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();

        // Register validator 1 at height 0 — make it cap-eligible immediately
        staking
            .register_validator_at_height(addr(1), 10_000_000_000, 0)
            .unwrap();
        staking
            .validators
            .get_mut(&addr(1))
            .unwrap()
            .cap_eligible_height = 0;

        // First transition far enough that validator 1 is eligible
        let h1 = epoch_len;
        epoch.transition(h1, &mut staking, &Hash256::ZERO, &mut slashing);
        let cap_without_v2 = staking.stake_cap;

        // Register validator 2 with a much larger stake, just before next epoch
        let h_reg = h1 + 50;
        staking
            .register_validator_at_height(addr(2), 100_000_000_000, h_reg)
            .unwrap();
        // v2.cap_eligible_height = h_reg + cooldown >> h1 + epoch_len

        // Second transition — v2 should NOT affect cap
        let h2 = h1 + epoch_len;
        epoch.transition(h2, &mut staking, &Hash256::ZERO, &mut slashing);

        // Cap should be same as before (only v1 is cap-eligible)
        assert_eq!(
            staking.stake_cap, cap_without_v2,
            "cap must not change when only cooldown-ineligible validator was added (cap={}, expected={})",
            staking.stake_cap, cap_without_v2,
        );

        // Now fast-forward past the cooldown and verify v2 IS included
        let h3 = h_reg + cooldown + epoch_len;
        epoch.epoch_start_height = h3 - epoch_len;
        epoch.transition(h3, &mut staking, &Hash256::ZERO, &mut slashing);
        assert_ne!(
            staking.stake_cap, cap_without_v2,
            "cap must change after v2 passes cooldown"
        );
    }

    #[test]
    fn test_wi5a_randao_counter_saturates() {
        // Ensure saturating_add prevents overflow if counter is somehow near u32::MAX
        let mut epoch = EpochState::new(100);
        let mut staking = StakingState::new(100_000_000_000);
        let mut slashing = SlashingEngine::new();
        staking.register_validator(addr(1), 10_000_000_000).unwrap();

        // Populate validator set
        epoch.transition(100, &mut staking, &Hash256::ZERO, &mut slashing);

        // Manually set counter near max to test that a non-reveal
        // increments via saturating_add without panic.
        // Note: this will trigger a slash since counter >= CONSECUTIVE_RANDAO_LIMIT (2).
        staking
            .validators
            .get_mut(&addr(1))
            .unwrap()
            .consecutive_randao_failures = u32::MAX - 1;

        // This should not panic, and should trigger a slash (counter >= 3).
        commit_no_reveal_and_transition(&mut epoch, &mut staking, &mut slashing, addr(1), 1, 200);

        // After slash, counter is reset to 0
        assert_eq!(
            staking
                .validators
                .get(&addr(1))
                .unwrap()
                .consecutive_randao_failures,
            0,
        );
    }
}
