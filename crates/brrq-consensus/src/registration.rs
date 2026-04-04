//! Sequencer registration and delegation management (§14.7–14.8).
//!
//! ## Open Registration
//!
//! Any entity can become a sequencer by locking ≥ 1 BTC in a Taproot contract.
//! Geographic diversity is incentivised: regions that exceed 33% of the active
//! set are soft-capped, and under-represented regions receive a diversity bonus
//! of up to 1.3×.
//!
//! ## Delegation
//!
//! Token holders who do not wish to run a sequencer can delegate to an existing
//! one.  The sequencer sets a commission rate (in basis points) and can toggle
//! whether new delegations are accepted.

use imbl::{HashMap, HashSet};

use brrq_crypto::schnorr::SchnorrPublicKey;
use brrq_types::Address;
use serde::{Deserialize, Serialize};

use crate::ConsensusError;
use crate::staking::StakingState;

// ═══════════════════════════════════════════════════════════════════
// Constants (§14.7)
// ═══════════════════════════════════════════════════════════════════

/// Minimum self-stake to register as a sequencer: 1 BTC in satoshis.
pub const MIN_SEQUENCER_STAKE: u64 = 100_000_000;

/// Minimum delegation amount: 0.001 BTC in satoshis.
pub const MIN_DELEGATION: u64 = 100_000;

/// Maximum share of sequencers any single region may hold, in basis points.
/// 3333 bp ≈ 33.33%.
pub const MAX_REGION_SHARE_BP: u64 = 3333;

/// Diversity bonus floor: 1.1× (11000 bp).
pub const DIVERSITY_BONUS_MIN_BP: u64 = 11000;

/// Diversity bonus ceiling: 1.3× (13000 bp).
pub const DIVERSITY_BONUS_MAX_BP: u64 = 13000;

/// Reputation evaluation window in blocks (~6 months at 3 s/block).
pub const REPUTATION_WINDOW_BLOCKS: u64 = 5_184_000;

/// Unbonding period in L2 blocks (~1 epoch = 7200 blocks ≈ 6 hours at 3 s/block).
///
/// Delegators who undelegate must wait this period before funds are released.
/// This prevents flash-loan style attacks where stake is delegated to vote,
/// then immediately withdrawn.
pub const UNBONDING_PERIOD_BLOCKS: u64 = 7_200;

// ═══════════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════════

/// Geographic region for sequencer diversity tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Region {
    NorthAmerica,
    SouthAmerica,
    Europe,
    Africa,
    MiddleEast,
    Asia,
    Oceania,
    Unknown,
}

/// A single delegation from a token holder to a sequencer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Address of the delegator.
    pub delegator: Address,
    /// Delegated amount in satoshis.
    pub amount: u64,
    /// Block height at which the delegation was created.
    pub delegated_at: u64,
}

/// Full registration record for a sequencer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SequencerRegistration {
    /// Sequencer address.
    pub address: Address,
    /// Own stake in satoshis.
    pub self_stake: u64,
    /// Declared geographic region.
    pub region: Region,
    /// Block height at which the sequencer registered.
    pub registered_at: u64,
    /// Number of blocks successfully produced.
    pub blocks_produced: u64,
    /// Number of blocks missed.
    pub blocks_missed: u64,
    /// Active delegations, keyed by delegator address.
    pub delegations: HashMap<Address, Delegation>,
    /// Running total of delegated stake (cache).
    pub total_delegated: u64,
    /// Whether the sequencer is currently accepting new delegations.
    pub accepting_delegations: bool,
    /// Commission charged on delegation rewards, in basis points.
    pub commission_bp: u64,
    /// EOTS public key for signature verification (32-byte x-only).
    #[serde(default)]
    pub eots_pubkey: Option<SchnorrPublicKey>,
    /// Archived EOTS keys from previous epochs — still slashable until expiry.
    ///
    /// When a sequencer rotates their EOTS key, the old key is moved here
    /// with a `slashable_until` block height. Evidence submitted against an
    /// expired key is still valid if the evidence height < slashable_until.
    ///
    /// Without this, a malicious sequencer could
    /// equivocate at height N, then rotate their key at N+1. When evidence
    /// arrives at N+2, the old key is gone → evidence verification fails
    /// → sequencer escapes slashing.
    #[serde(default)]
    pub expired_eots_keys: Vec<ArchivedEotsKey>,
}

/// An archived EOTS key with slashing window.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivedEotsKey {
    /// The old EOTS public key.
    pub pubkey: SchnorrPublicKey,
    /// Block height at which this key was rotated out.
    pub rotated_at: u64,
    /// This key is still slashable until this block height.
    /// Typically: rotated_at + SLASHABLE_GRACE_BLOCKS
    pub slashable_until: u64,
}

/// Grace period after key rotation during which the old key is still slashable.
/// ~7 days at 3s/block = 201,600 blocks. Matches MAX_EVIDENCE_AGE_BLOCKS.
pub const SLASHABLE_GRACE_BLOCKS: u64 = 201_600;

/// Request to register a new sequencer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrationRequest {
    pub address: Address,
    pub self_stake: u64,
    pub region: Region,
    pub commission_bp: u64,
    /// EOTS public key for RANDAO signature verification.
    #[serde(default)]
    pub eots_pubkey: Option<SchnorrPublicKey>,
}

/// Request to delegate stake to a sequencer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationRequest {
    pub delegator: Address,
    pub sequencer: Address,
    pub amount: u64,
}

// ═══════════════════════════════════════════════════════════════════
// RegistrationManager
// ═══════════════════════════════════════════════════════════════════

/// A pending undelegation that is waiting for the unbonding period to expire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbondingEntry {
    /// Delegator who initiated the undelegation.
    pub delegator: Address,
    /// Sequencer from whom stake was removed.
    pub sequencer: Address,
    /// Amount being undelegated (satoshis).
    pub amount: u64,
    /// L2 block height when undelegation was requested.
    pub requested_at: u64,
    /// L2 block height when funds become available.
    pub mature_at: u64,
}

/// Manages sequencer registrations and delegations.
#[derive(Debug, Clone)]
pub struct RegistrationManager {
    /// All registered sequencers keyed by address.
    pub registrations: HashMap<Address, SequencerRegistration>,
    /// Count of sequencers per region.
    pub region_counts: HashMap<Region, usize>,
    /// Pending undelegations waiting for unbonding period.
    pub unbonding_queue: Vec<UnbondingEntry>,
    /// Global history of all EOTS keys ever used. Prevents reuse after deregister.
    /// Keys are never removed from this set — a key used once is burned forever.
    eots_key_history: HashSet<[u8; 32]>,
}

impl Default for RegistrationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistrationManager {
    /// Create a new, empty registration manager.
    pub fn new() -> Self {
        Self {
            registrations: HashMap::new(),
            eots_key_history: HashSet::new(),
            region_counts: HashMap::new(),
            unbonding_queue: Vec::new(),
        }
    }

    /// Look up the EOTS public key for a registered validator.
    pub fn get_eots_pubkey(&self, address: &Address) -> Option<&SchnorrPublicKey> {
        self.registrations
            .get(address)
            .and_then(|r| r.eots_pubkey.as_ref())
    }

    /// Rotate a sequencer's EOTS key.
    ///
    /// The old key is archived with a slashable grace period — evidence
    /// submitted against it remains valid until `current_height + SLASHABLE_GRACE_BLOCKS`.
    ///
    /// Without archival, a malicious sequencer could
    /// equivocate then immediately rotate their key to escape slashing.
    pub fn update_eots_key(
        &mut self,
        address: &Address,
        new_eots_pubkey: SchnorrPublicKey,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        let reg = self.registrations.get_mut(address).ok_or(ConsensusError::InvalidBlock {
            reason: format!("sequencer {} not registered", address),
        })?;

        // Archive the old key (if any) with slashable window
        if let Some(old_key) = reg.eots_pubkey.take() {
            // Prune expired archived keys while we're here
            reg.expired_eots_keys.retain(|k| k.slashable_until > current_height);

            reg.expired_eots_keys.push(ArchivedEotsKey {
                pubkey: old_key,
                rotated_at: current_height,
                slashable_until: current_height.saturating_add(SLASHABLE_GRACE_BLOCKS),
            });
        }

        // Ensure new EOTS key is globally unique.
        // Also check archived (expired but still slashable) keys.
        // Without this, an attacker could register with another validator's archived
        // key and then produce equivocation evidence that slashes the wrong validator.
        for (addr, other_reg) in &self.registrations {
            if addr == address {
                continue;
            }
            if let Some(ref existing_eots) = other_reg.eots_pubkey {
                if *existing_eots == new_eots_pubkey {
                    return Err(ConsensusError::InvalidBlock {
                        reason: format!(
                            "EOTS key already in use by validator {}",
                            addr
                        ),
                    });
                }
            }
            // Check archived keys that are still within slashable window
            for archived in &other_reg.expired_eots_keys {
                if archived.pubkey == new_eots_pubkey && archived.slashable_until > current_height {
                    return Err(ConsensusError::InvalidBlock {
                        reason: format!(
                            "EOTS key still slashable for validator {} until block {}",
                            addr, archived.slashable_until
                        ),
                    });
                }
            }
        }

        reg.eots_pubkey = Some(new_eots_pubkey);
        // Insert rotated key into global history so it cannot be reused
        // after this validator deregisters and the key is pruned from archived keys.
        self.eots_key_history.insert(*new_eots_pubkey.as_bytes());
        Ok(())
    }

    /// Check if a given EOTS public key was ever used by this sequencer
    /// and is still within the slashable window.
    ///
    /// Returns true if the key matches the current key OR any archived key
    /// whose `slashable_until > evidence_height`.
    pub fn is_eots_key_slashable(
        &self,
        address: &Address,
        key: &SchnorrPublicKey,
        evidence_height: u64,
    ) -> bool {
        let reg = match self.registrations.get(address) {
            Some(r) => r,
            None => return false,
        };

        // Check current key
        if reg.eots_pubkey.as_ref() == Some(key) {
            return true;
        }

        // Check archived keys still in slashable window
        reg.expired_eots_keys.iter().any(|k| {
            &k.pubkey == key && evidence_height <= k.slashable_until
        })
    }

    /// Register a new sequencer.
    ///
    /// Validates:
    /// - Self-stake ≥ `MIN_SEQUENCER_STAKE`
    /// - Not already registered
    /// - Region does not exceed the 33% cap (enforced when ≥ 3 sequencers)
    /// - Commission ≤ 10 000 bp
    ///
    /// Also registers the sequencer as a validator in the staking layer.
    pub fn register(
        &mut self,
        request: RegistrationRequest,
        staking: &mut StakingState,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // 1. Minimum stake check.
        if request.self_stake < MIN_SEQUENCER_STAKE {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "insufficient self-stake: need {} sat, have {} sat",
                    MIN_SEQUENCER_STAKE, request.self_stake
                ),
            });
        }

        // 2. Duplicate check.
        if self.registrations.contains_key(&request.address) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!("sequencer already registered: {}", request.address),
            });
        }

        // 3. Region diversity cap (only enforced when total ≥ 3).
        let total = self.registrations.len();
        if total >= 3 {
            let region_count = self
                .region_counts
                .get(&request.region)
                .copied()
                .unwrap_or(0);
            // After adding this sequencer the new share would be:
            //   (region_count + 1) / (total + 1)
            // Reject if (region_count + 1) * 10000 / (total + 1) > MAX_REGION_SHARE_BP
            let new_share_bp = ((region_count as u64 + 1) * 10_000) / (total as u64 + 1);
            if new_share_bp > MAX_REGION_SHARE_BP {
                return Err(ConsensusError::InvalidBlock {
                    reason: format!("region cap exceeded: {:?}", request.region),
                });
            }
        }

        // EOTS key must be globally unique to prevent framing attacks.
        // If two validators share the same EOTS key, equivocation by one triggers
        // slashing for both.
        // Also scan archived (expired) EOTS keys that are still
        // within the slashable grace window. Without this, an attacker can deregister
        // (destroying archived keys) then re-register with a victim's old key to
        // frame them, or inherit old equivocation evidence.
        if let Some(ref new_eots) = request.eots_pubkey {
            // Global history check — catches keys from deregistered validators
            if self.eots_key_history.contains(new_eots.as_bytes()) {
                return Err(ConsensusError::InvalidBlock {
                    reason: "EOTS key was previously used by another validator (global history)".to_string(),
                });
            }
            for (addr, reg) in &self.registrations {
                // Check current key
                if let Some(ref existing_eots) = reg.eots_pubkey {
                    if existing_eots == new_eots {
                        return Err(ConsensusError::InvalidBlock {
                            reason: format!(
                                "EOTS key already registered by validator {}",
                                addr
                            ),
                        });
                    }
                }
                // Check archived keys still within slashable window
                for archived in &reg.expired_eots_keys {
                    if archived.pubkey == *new_eots && archived.slashable_until > current_height {
                        return Err(ConsensusError::InvalidBlock {
                            reason: format!(
                                "EOTS key still slashable (archived by validator {} until block {})",
                                addr, archived.slashable_until
                            ),
                        });
                    }
                }
            }
        }

        // 4. Commission sanity check.
        if request.commission_bp > 10_000 {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "commission too high: {} bp (max 10000)",
                    request.commission_bp
                ),
            });
        }

        // 5. Register in staking layer.
        staking.register_validator(request.address, request.self_stake)?;

        // 6. Build registration record.
        let registration = SequencerRegistration {
            address: request.address,
            self_stake: request.self_stake,
            region: request.region,
            registered_at: current_height,
            blocks_produced: 0,
            blocks_missed: 0,
            delegations: HashMap::new(),
            total_delegated: 0,
            accepting_delegations: true,
            commission_bp: request.commission_bp,
            eots_pubkey: request.eots_pubkey,
            expired_eots_keys: Vec::new(),
        };

        // Record EOTS key in global history (never removed)
        if let Some(ref eots) = request.eots_pubkey {
            self.eots_key_history.insert(*eots.as_bytes());
        }

        self.registrations.insert(request.address, registration);
        *self.region_counts.entry(request.region).or_insert(0) += 1;

        Ok(())
    }

    /// Delegate stake to an existing sequencer.
    ///
    /// Validates:
    /// - Sequencer exists and is accepting delegations
    /// - Amount ≥ `MIN_DELEGATION`
    /// - Delegator has not already delegated to this sequencer
    pub fn delegate(
        &mut self,
        request: DelegationRequest,
        staking: &mut StakingState,
        current_height: u64,
    ) -> Result<(), ConsensusError> {
        // 1. Sequencer must exist.
        let reg = self.registrations.get(&request.sequencer).ok_or_else(|| {
            ConsensusError::InvalidBlock {
                reason: format!("sequencer not found: {}", request.sequencer),
            }
        })?;

        // 2. Must be accepting delegations.
        if !reg.accepting_delegations {
            return Err(ConsensusError::InvalidBlock {
                reason: "not accepting delegations".to_string(),
            });
        }

        // 3. Self-delegation not allowed.
        if request.delegator == request.sequencer {
            return Err(ConsensusError::InvalidBlock {
                reason: "self-delegation not allowed".to_string(),
            });
        }

        // 4. Minimum delegation.
        if request.amount < MIN_DELEGATION {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "delegation too small: need {} sat, have {} sat",
                    MIN_DELEGATION, request.amount
                ),
            });
        }

        // 5. No duplicate delegation.
        if reg.delegations.contains_key(&request.delegator) {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "delegator {} already delegated to sequencer {}",
                    request.delegator, request.sequencer
                ),
            });
        }

        // 6. Reflect in staking layer (delegated stake on the validator).
        staking.delegate(&request.sequencer, request.amount)?;

        // 7. Record delegation.
        let reg = self
            .registrations
            .get_mut(&request.sequencer)
            .ok_or_else(|| ConsensusError::InvalidBlock {
                reason: format!("sequencer not found: {}", request.sequencer),
            })?;

        let delegation = Delegation {
            delegator: request.delegator,
            amount: request.amount,
            delegated_at: current_height,
        };
        reg.delegations.insert(request.delegator, delegation);
        reg.total_delegated = reg.total_delegated.saturating_add(request.amount);

        Ok(())
    }

    /// Remove a delegation with unbonding delay.
    ///
    /// The delegation is removed from the sequencer immediately (reducing their
    /// voting power), but the delegator's funds enter an unbonding queue and are
    /// only released after `UNBONDING_PERIOD_BLOCKS`. This prevents flash-loan
    /// style attacks where stake is delegated to influence a vote, then
    /// immediately withdrawn.
    ///
    /// Returns the amount that was queued for undelegation.
    ///
    /// The staking layer is updated **first** so that if it fails, local
    /// registration state remains consistent (no partial mutation).
    pub fn undelegate(
        &mut self,
        delegator: Address,
        sequencer: Address,
        staking: &mut StakingState,
        current_height: u64,
    ) -> Result<u64, ConsensusError> {
        // 1. Look up the delegation without removing it yet.
        let reg =
            self.registrations
                .get(&sequencer)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("sequencer not found: {}", sequencer),
                })?;

        let amount = reg
            .delegations
            .get(&delegator)
            .ok_or_else(|| ConsensusError::InvalidBlock {
                reason: "delegation not found".to_string(),
            })?
            .amount;

        // 2. Update staking layer FIRST — if this fails, no local state is mutated.
        staking.undelegate(&sequencer, amount)?;

        // 3. Now safe to mutate local state.
        let reg =
            self.registrations
                .get_mut(&sequencer)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("sequencer not found: {}", sequencer),
                })?;
        reg.delegations.remove(&delegator);
        reg.total_delegated = reg.total_delegated.saturating_sub(amount);

        // 4. Queue the unbonding entry.
        self.unbonding_queue.push(UnbondingEntry {
            delegator,
            sequencer,
            amount,
            requested_at: current_height,
            mature_at: current_height.saturating_add(UNBONDING_PERIOD_BLOCKS),
        });

        Ok(amount)
    }

    /// Process matured unbonding entries. Returns list of (delegator, amount) pairs
    /// that are now fully released and available to the delegator.
    ///
    /// Should be called once per block by the consensus layer.
    pub fn process_unbonding(&mut self, current_height: u64) -> Vec<(Address, u64)> {
        let mut matured = Vec::new();
        self.unbonding_queue.retain(|entry| {
            if current_height >= entry.mature_at {
                matured.push((entry.delegator, entry.amount));
                false // remove from queue
            } else {
                true // keep in queue
            }
        });
        matured
    }

    /// Get pending unbonding entries for a specific delegator.
    pub fn pending_unbonding(&self, delegator: &Address) -> Vec<&UnbondingEntry> {
        self.unbonding_queue
            .iter()
            .filter(|e| e.delegator == *delegator)
            .collect()
    }

    /// Deregister a sequencer.
    ///
    /// Removes the sequencer from the registration manager and decrements the
    /// region count. Any remaining delegations are returned as a list of
    /// `(delegator, amount)` tuples so the caller can process refunds.
    ///
    /// **Note**: This does NOT modify staking state — the caller must handle
    /// validator removal / unbonding separately (e.g., via `begin_unbonding`).
    pub fn deregister(&mut self, address: &Address) -> Result<Vec<(Address, u64)>, ConsensusError> {
        let reg =
            self.registrations
                .remove(address)
                .ok_or_else(|| ConsensusError::InvalidBlock {
                    reason: format!("sequencer not found: {}", address),
                })?;

        // Decrement region count
        if let Some(count) = self.region_counts.get_mut(&reg.region) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                self.region_counts.remove(&reg.region);
            }
        }

        // Collect outstanding delegations for refund
        let delegations: Vec<(Address, u64)> = reg
            .delegations
            .into_iter()
            .map(|(_, d)| (d.delegator, d.amount))
            .collect();

        Ok(delegations)
    }

    /// Look up a sequencer by address.
    pub fn get_sequencer(&self, address: &Address) -> Option<&SequencerRegistration> {
        self.registrations.get(address)
    }

    /// Return all registered sequencers.
    pub fn all_sequencers(&self) -> Vec<&SequencerRegistration> {
        self.registrations.values().collect()
    }

    /// Return all delegations made by a given delegator.
    pub fn delegations_by_delegator(&self, delegator: &Address) -> Vec<(&Address, &Delegation)> {
        let mut results = Vec::new();
        for (seq_addr, reg) in &self.registrations {
            if let Some(d) = reg.delegations.get(delegator) {
                results.push((seq_addr, d));
            }
        }
        results
    }

    /// Record a successful block production for a sequencer.
    pub fn record_block_produced(&mut self, sequencer: &Address) {
        if let Some(reg) = self.registrations.get_mut(sequencer) {
            reg.blocks_produced = reg.blocks_produced.saturating_add(1);
        }
    }

    /// Record a missed block for a sequencer.
    pub fn record_block_missed(&mut self, sequencer: &Address) {
        if let Some(reg) = self.registrations.get_mut(sequencer) {
            reg.blocks_missed = reg.blocks_missed.saturating_add(1);
        }
    }

    /// Compute the participation ratio for a sequencer, in basis points (0–10000).
    ///
    /// Returns `produced * 10000 / (produced + missed)`, or `10000` if both are zero
    /// (benefit-of-the-doubt for newly registered sequencers).
    ///
    /// Uses integer arithmetic for cross-platform determinism — f64 division
    /// can produce different results on different platforms/compilers, which
    /// is unacceptable in consensus-critical code.
    pub fn participation_ratio_bp(&self, sequencer: &Address) -> u64 {
        match self.registrations.get(sequencer) {
            Some(reg) => {
                let total = reg.blocks_produced.saturating_add(reg.blocks_missed);
                if total == 0 {
                    10_000 // 100% benefit-of-the-doubt
                } else {
                    reg.blocks_produced.saturating_mul(10_000) / total
                }
            }
            None => 0,
        }
    }

    /// Compute the diversity bonus for a given region, in basis points.
    ///
    /// - Under-represented region (< average share) → `DIVERSITY_BONUS_MAX_BP` (1.3×)
    /// - Average-represented region (= average share) → `DIVERSITY_BONUS_MIN_BP` (1.1×)
    /// - Over-represented region (> average share)  → 10 000 (1.0×, no bonus)
    pub fn diversity_bonus(&self, region: &Region) -> u64 {
        let total = self.registrations.len();
        if total == 0 {
            return DIVERSITY_BONUS_MIN_BP;
        }

        let region_count = self.region_counts.get(region).copied().unwrap_or(0);
        let num_regions = self.region_counts.len().max(1);

        // Use cross-multiplication to avoid integer truncation:
        // region_count < total / num_regions  ⟹  region_count * num_regions < total
        if region_count * num_regions < total {
            DIVERSITY_BONUS_MAX_BP
        } else if region_count * num_regions == total {
            DIVERSITY_BONUS_MIN_BP
        } else {
            10_000
        }
    }

    /// Return current sequencer counts per region.
    pub fn region_stats(&self) -> HashMap<Region, usize> {
        self.region_counts.clone()
    }

    /// Compute each region's share of the active sequencer set in basis points.
    ///
    /// Returns a map of Region → share_bp (0–10000). Used by the diversity
    /// bonus system to determine under/over-represented regions.
    pub fn region_shares(&self) -> HashMap<Region, u64> {
        let total = self.registrations.len();
        if total == 0 {
            return HashMap::new();
        }
        self.region_counts
            .iter()
            .map(|(region, &count)| {
                let share_bp = (count as u64).saturating_mul(10_000) / total as u64;
                (*region, share_bp)
            })
            .collect()
    }

    /// Check whether a region still has capacity under the 33% cap.
    ///
    /// When there are fewer than 3 sequencers the cap is not enforced.
    pub fn region_has_capacity(&self, region: &Region) -> bool {
        let total = self.registrations.len();
        if total < 3 {
            return true;
        }
        let region_count = self.region_counts.get(region).copied().unwrap_or(0);
        let new_share_bp = ((region_count as u64 + 1) * 10_000) / (total as u64 + 1);
        new_share_bp <= MAX_REGION_SHARE_BP
    }

    /// Total number of registered sequencers.
    pub fn count(&self) -> usize {
        self.registrations.len()
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a deterministic address from a single byte.
    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address::from_bytes(bytes)
    }

    /// Helper: build a registration request with sensible defaults.
    fn reg_request(n: u8, region: Region) -> RegistrationRequest {
        RegistrationRequest {
            address: addr(n),
            self_stake: MIN_SEQUENCER_STAKE,
            region,
            commission_bp: 500, // 5%
            eots_pubkey: None,
        }
    }

    // ─── 1. register_sequencer_valid ────────────────────────────────

    #[test]
    fn register_sequencer_valid() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        let req = reg_request(1, Region::Europe);
        mgr.register(req, &mut staking, 100).unwrap();

        assert_eq!(mgr.count(), 1);
        let seq = mgr.get_sequencer(&addr(1)).unwrap();
        assert_eq!(seq.self_stake, MIN_SEQUENCER_STAKE);
        assert_eq!(seq.region, Region::Europe);
        assert_eq!(seq.registered_at, 100);
        assert!(seq.accepting_delegations);
        assert_eq!(seq.commission_bp, 500);

        // Should also be registered in the staking layer.
        assert!(staking.validators.contains_key(&addr(1)));
    }

    // ─── 2. register_insufficient_stake_rejected ────────────────────

    #[test]
    fn register_insufficient_stake_rejected() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        let req = RegistrationRequest {
            address: addr(1),
            self_stake: MIN_SEQUENCER_STAKE - 1,
            region: Region::Asia,
            commission_bp: 0,
            eots_pubkey: None,
        };

        let result = mgr.register(req, &mut staking, 0);
        assert!(result.is_err());
        assert_eq!(mgr.count(), 0);
    }

    // ─── 3. register_duplicate_rejected ─────────────────────────────

    #[test]
    fn register_duplicate_rejected() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        let result = mgr.register(reg_request(1, Region::Asia), &mut staking, 1);
        assert!(result.is_err());
        assert_eq!(mgr.count(), 1);
    }

    // ─── 4. register_region_cap_enforced ────────────────────────────

    #[test]
    fn register_region_cap_enforced() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        // Register 3 sequencers: 1 Europe, 1 Asia, 1 Africa
        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(2, Region::Asia), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(3, Region::Africa), &mut staking, 0)
            .unwrap();

        // Now we have 3 sequencers. Adding a 2nd Europe would give
        // Europe 2/4 = 50% > 33.33% → should be rejected.
        let result = mgr.register(reg_request(4, Region::Europe), &mut staking, 0);
        assert!(result.is_err());
        assert_eq!(mgr.count(), 3);

        // But adding a new region (Oceania) should succeed: 1/4 = 25%.
        mgr.register(reg_request(5, Region::Oceania), &mut staking, 0)
            .unwrap();
        assert_eq!(mgr.count(), 4);
    }

    // ─── 5. delegate_to_sequencer ───────────────────────────────────

    #[test]
    fn delegate_to_sequencer() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        let del_req = DelegationRequest {
            delegator: addr(10),
            sequencer: addr(1),
            amount: 500_000,
        };
        mgr.delegate(del_req, &mut staking, 50).unwrap();

        let seq = mgr.get_sequencer(&addr(1)).unwrap();
        assert_eq!(seq.total_delegated, 500_000);
        assert_eq!(seq.delegations.len(), 1);

        let d = seq.delegations.get(&addr(10)).unwrap();
        assert_eq!(d.amount, 500_000);
        assert_eq!(d.delegated_at, 50);
    }

    // ─── 6. delegate_below_minimum_rejected ─────────────────────────

    #[test]
    fn delegate_below_minimum_rejected() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        let del_req = DelegationRequest {
            delegator: addr(10),
            sequencer: addr(1),
            amount: MIN_DELEGATION - 1,
        };
        let result = mgr.delegate(del_req, &mut staking, 0);
        assert!(result.is_err());
    }

    // ─── 7. undelegate_returns_amount ───────────────────────────────

    #[test]
    fn undelegate_returns_amount() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        let del_req = DelegationRequest {
            delegator: addr(10),
            sequencer: addr(1),
            amount: 1_000_000,
        };
        mgr.delegate(del_req, &mut staking, 0).unwrap();

        let amount = mgr
            .undelegate(addr(10), addr(1), &mut staking, 100)
            .unwrap();
        assert_eq!(amount, 1_000_000);

        let seq = mgr.get_sequencer(&addr(1)).unwrap();
        assert_eq!(seq.total_delegated, 0);
        assert!(seq.delegations.is_empty());

        // Funds are in unbonding queue, not yet released
        assert_eq!(mgr.unbonding_queue.len(), 1);
        assert_eq!(
            mgr.unbonding_queue[0].mature_at,
            100 + UNBONDING_PERIOD_BLOCKS
        );

        // Process before maturity — nothing released
        let released = mgr.process_unbonding(100);
        assert!(released.is_empty());

        // Process at maturity — funds released
        let released = mgr.process_unbonding(100 + UNBONDING_PERIOD_BLOCKS);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0], (addr(10), 1_000_000));
        assert!(mgr.unbonding_queue.is_empty());
    }

    // ─── 8. undelegate_nonexistent_rejected ─────────────────────────

    #[test]
    fn undelegate_nonexistent_rejected() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        // No delegation was ever made by addr(10).
        let result = mgr.undelegate(addr(10), addr(1), &mut staking, 0);
        assert!(result.is_err());
    }

    // ─── 9. participation_ratio_calculation ─────────────────────────

    #[test]
    fn participation_ratio_calculation() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        // Fresh sequencer → 10000 bp (100%, benefit of the doubt).
        assert_eq!(mgr.participation_ratio_bp(&addr(1)), 10_000);

        // 7 produced, 3 missed → 7000 bp (70%)
        for _ in 0..7 {
            mgr.record_block_produced(&addr(1));
        }
        for _ in 0..3 {
            mgr.record_block_missed(&addr(1));
        }

        assert_eq!(mgr.participation_ratio_bp(&addr(1)), 7_000);
    }

    // ─── 10. diversity_bonus_underrepresented ───────────────────────

    #[test]
    fn diversity_bonus_underrepresented() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        // Register 2 Europe + 1 Asia → total=3, num_regions=2, avg=3/2=1.
        // A region with 0 members (Oceania) has count 0 < avg 1 → MAX bonus.
        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(2, Region::Europe), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(3, Region::Asia), &mut staking, 0)
            .unwrap();

        assert_eq!(
            mgr.diversity_bonus(&Region::Oceania),
            DIVERSITY_BONUS_MAX_BP,
            "Under-represented region (0 members) should get max bonus (1.3x)"
        );
    }

    // ─── 11. diversity_bonus_overrepresented ────────────────────────

    #[test]
    fn diversity_bonus_overrepresented() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        // Register 2 Europe + 1 Asia → total=3, num_regions=2, avg=3/2=1.
        // Europe has count 2 > avg 1 → no bonus (1.0x).
        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(2, Region::Europe), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(3, Region::Asia), &mut staking, 0)
            .unwrap();

        assert_eq!(
            mgr.diversity_bonus(&Region::Europe),
            10_000,
            "Over-represented region should get no bonus (1.0x)"
        );
    }

    // ─── 12. record_block_produced_updates_stats ────────────────────

    #[test]
    fn record_block_produced_updates_stats() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        mgr.record_block_produced(&addr(1));
        mgr.record_block_produced(&addr(1));
        mgr.record_block_produced(&addr(1));

        let seq = mgr.get_sequencer(&addr(1)).unwrap();
        assert_eq!(seq.blocks_produced, 3);
        assert_eq!(seq.blocks_missed, 0);
    }

    // ─── 13. record_block_missed_updates_stats ──────────────────────

    #[test]
    fn record_block_missed_updates_stats() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        mgr.record_block_missed(&addr(1));
        mgr.record_block_missed(&addr(1));

        let seq = mgr.get_sequencer(&addr(1)).unwrap();
        assert_eq!(seq.blocks_produced, 0);
        assert_eq!(seq.blocks_missed, 2);
    }

    // ─── 14. all_sequencers_list ────────────────────────────────────

    #[test]
    fn all_sequencers_list() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(2, Region::Asia), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(3, Region::Africa), &mut staking, 0)
            .unwrap();

        let all = mgr.all_sequencers();
        assert_eq!(all.len(), 3);
    }

    // ─── 15. delegations_by_delegator ───────────────────────────────

    #[test]
    fn delegations_by_delegator() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();
        mgr.register(reg_request(2, Region::Asia), &mut staking, 0)
            .unwrap();

        let delegator = addr(20);

        // Delegate to both sequencers.
        mgr.delegate(
            DelegationRequest {
                delegator,
                sequencer: addr(1),
                amount: 200_000,
            },
            &mut staking,
            10,
        )
        .unwrap();

        mgr.delegate(
            DelegationRequest {
                delegator,
                sequencer: addr(2),
                amount: 300_000,
            },
            &mut staking,
            20,
        )
        .unwrap();

        let dels = mgr.delegations_by_delegator(&delegator);
        assert_eq!(dels.len(), 2);

        let total: u64 = dels.iter().map(|(_, d)| d.amount).sum();
        assert_eq!(total, 500_000);
    }

    // --- test_self_delegation_rejected ---

    #[test]
    fn test_self_delegation_rejected() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        // Register a sequencer.
        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        // Try to delegate where delegator == sequencer (self-delegation).
        let del_req = DelegationRequest {
            delegator: addr(1),
            sequencer: addr(1),
            amount: 500_000,
        };
        let result = mgr.delegate(del_req, &mut staking, 10);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("self-delegation not allowed"),
            "expected self-delegation error, got: {}",
            err_msg
        );
    }

    // --- test_deregister_returns_delegations ---

    #[test]
    fn test_deregister_returns_delegations() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        // Register a sequencer.
        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        // Delegate from 2 different delegators.
        mgr.delegate(
            DelegationRequest {
                delegator: addr(10),
                sequencer: addr(1),
                amount: 200_000,
            },
            &mut staking,
            10,
        )
        .unwrap();

        mgr.delegate(
            DelegationRequest {
                delegator: addr(11),
                sequencer: addr(1),
                amount: 300_000,
            },
            &mut staking,
            20,
        )
        .unwrap();

        // Deregister the sequencer.
        let returned = mgr.deregister(&addr(1)).unwrap();

        // Should return 2 delegations.
        assert_eq!(returned.len(), 2);

        // Verify total amount matches.
        let total: u64 = returned.iter().map(|(_, amt)| amt).sum();
        assert_eq!(total, 500_000);

        // Verify each delegation is present (order is not guaranteed).
        let has_10 = returned
            .iter()
            .any(|(a, amt)| *a == addr(10) && *amt == 200_000);
        let has_11 = returned
            .iter()
            .any(|(a, amt)| *a == addr(11) && *amt == 300_000);
        assert!(has_10, "delegation from addr(10) not found in returned");
        assert!(has_11, "delegation from addr(11) not found in returned");

        // Sequencer should no longer be in registrations.
        assert!(mgr.get_sequencer(&addr(1)).is_none());

        // Region count should be decremented.
        let europe_count = mgr.region_counts.get(&Region::Europe).copied().unwrap_or(0);
        assert_eq!(europe_count, 0);
    }

    // --- test_undelegate_staking_first ---

    #[test]
    fn test_undelegate_staking_first() {
        let mut mgr = RegistrationManager::new();
        let mut staking = StakingState::new(10_000_000_000);

        // Register a sequencer.
        mgr.register(reg_request(1, Region::Europe), &mut staking, 0)
            .unwrap();

        // Delegate.
        let amount = 1_000_000;
        mgr.delegate(
            DelegationRequest {
                delegator: addr(10),
                sequencer: addr(1),
                amount,
            },
            &mut staking,
            10,
        )
        .unwrap();

        // Verify staking layer has the delegation.
        let validator = staking.validators.get(&addr(1)).unwrap();
        assert_eq!(validator.delegated_stake, amount);

        // Undelegate.
        let returned = mgr
            .undelegate(addr(10), addr(1), &mut staking, 1000)
            .unwrap();
        assert_eq!(returned, amount);

        // Staking layer should reflect the undelegation.
        let validator = staking.validators.get(&addr(1)).unwrap();
        assert_eq!(validator.delegated_stake, 0);

        // Local registration state should also be consistent.
        let seq = mgr.get_sequencer(&addr(1)).unwrap();
        assert_eq!(seq.total_delegated, 0);
        assert!(seq.delegations.is_empty());
    }
}
