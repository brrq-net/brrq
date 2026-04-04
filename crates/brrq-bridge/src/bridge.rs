//! Bridge manager for peg-in/peg-out operations.
//!
//! # Current Trust Model (Federated)
//!
//! This module implements the L2-side bridge logic. All Bitcoin interactions
//! are currently mediated by a 5-of-9 federation, NOT by on-chain BitVM2
//! scripts. See `lib.rs` module docs for the full trust model and roadmap
//! toward trustless operation.
//!
//! ## Flow
//!
//! ### Peg-in (BTC → brqBTC)
//! 1. User sends BTC to federation-controlled address on L1
//! 2. Federation member attests to deposit after 6 confirmations
//! 3. Bridge mints equivalent brqBTC on L2 (minus 0.05% fee)
//!
//! ### Peg-out (brqBTC → BTC)
//! 1. User requests withdrawal on L2
//! 2. L2 challenge period begins (144 blocks federated / 2016×200 BitVM2)
//! 3. If unchallenged, federation approves and operator fronts BTC
//! 4. Operator reimbursed from bridge reserve after challenge period

use imbl::HashMap;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_prover::StarkVerifier;
use brrq_prover::types::{BatchProofRecord, StarkProof};
use brrq_types::Address;
use serde::{Deserialize, Serialize};

use crate::challenge::{ChallengeResponse, ChallengeStatus, ChallengeType};
use crate::challenge_manager::ChallengeManager;
use crate::error::BridgeError;
use crate::federation::{FederationError, FederationManager, ProposalAction};
use crate::operator::OperatorManager;
use crate::proof_store::ProofStore;
use crate::rate_limiter::BridgeRateLimiter;
use crate::types::*;

/// Challenge period mode — determines withdrawal security model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeMode {
    /// MVP: 24-hour period, federated bridge.
    Federated,
    /// Future: 2-week period, BitVM2 trustless.
    BitVM2,
    /// ZK Validity: STARK-verified withdrawals with configurable (default zero)
    /// challenge period. Security relies on `StarkVerifier::verify()` — every
    /// withdrawal must be accompanied by a valid STARK proof. Without a proof,
    /// falls back to the Federated challenge period.
    ZkValidity,
    /// PILLAR 3: Hybrid Cryptoeconomic ZK-Bridge.
    ///
    /// The strongest security model. Withdrawals require BOTH:
    ///   (a) A valid STARK proof (mathematical correctness of state transition)
    ///   (b) ⅔ committee attestation (data availability + economic security)
    ///
    /// Neither condition alone is sufficient:
    ///   - STARK proof without attestation: data might be withheld
    ///   - Attestation without STARK proof: state might be invalid
    ///
    /// The AND-conjunction eliminates the weaknesses of each individual approach.
    HybridCryptoeconomic,
}

/// Per-address daily volume tracker.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AddressVolume {
    /// Total satoshis deposited/withdrawn in the current window.
    volume: u64,
    /// L2 block height when the current window started.
    window_start: u64,
}

/// Bridge manager handles all peg-in/peg-out operations.
#[derive(Clone, Serialize, Deserialize)]
pub struct BridgeManager {
    /// Active deposits keyed by (btc_tx_id, btc_vout) — composite key
    /// to correctly handle multiple outputs from the same Bitcoin transaction.
    pub deposits: HashMap<(Hash256, u32), DepositRequest>,
    /// Active withdrawals keyed by withdrawal ID.
    pub withdrawals: HashMap<Hash256, WithdrawalRequest>,
    /// Total BTC locked in the bridge (satoshis).
    pub total_locked: u64,
    /// Total brqBTC minted (satoshis).
    pub total_minted: u64,
    /// Whether the bridge is paused.
    pub paused: bool,
    /// Current L1 block height (for confirmation tracking).
    pub l1_height: u64,
    /// Current L2 block height.
    pub l2_height: u64,
    /// Committed L2 state roots (height → state_root).
    /// STARK proofs must bind initial_state_root to one of these.
    pub committed_state_roots: HashMap<u64, Hash256>,
    /// Highest committed state root height (monotonic guard).
    #[serde(default)]
    last_committed_height: u64,
    /// Challenge manager for fraud detection.
    pub challenge_manager: ChallengeManager,
    /// Operator manager for liquidity providers.
    pub operator_manager: OperatorManager,
    /// Proof store for data availability.
    pub proof_store: ProofStore,
    /// Challenge period mode.
    pub challenge_mode: ChallengeMode,
    /// ZK Validity challenge period in L2 blocks (default: 0).
    /// Only used when `challenge_mode == ZkValidity`.
    /// Set to 0 for testnet (instant withdrawals), or a small value
    /// (e.g., 1200 = ~1 hour at 3s/block) for mainnet safety net.
    pub zk_validity_challenge_l2: u64,
    /// Federation manager for multisig governance.
    pub federation: Option<FederationManager>,
    /// PILLAR 3: Native BTC Staking Committee for cryptoeconomic security.
    ///
    /// When present and `challenge_mode == HybridCryptoeconomic`, all withdrawals
    /// require both a STARK proof AND ⅔ committee attestation.
    pub staking_committee: Option<crate::federation::StakingCommittee>,
    /// Monotonic counter for withdrawal ID uniqueness.
    /// Prevents ID collisions when two withdrawal requests have the same
    /// sender, amount, destination, and L2 height.
    withdrawal_counter: u64,
    /// Per-address daily volume tracker (anti-monopolization).
    daily_volumes: HashMap<Address, AddressVolume>,
    /// Pending emergency exits awaiting timelock expiry.
    /// Keyed by withdrawal_id. Populated by `initiate_emergency_exit`,
    /// consumed by `claim_emergency_exit`.
    emergency_exits: HashMap<Hash256, EmergencyExitPath>,
    /// Block monitor for SPV chain verification.
    /// When present, SPV proofs are verified against the canonical chain.
    /// When absent, SPV proofs are rejected (federation attestation required).
    #[serde(skip)]
    block_monitor: Option<brrq_bitcoin::BlockMonitor>,
    /// Bridge-level rate limiter for deposit/withdrawal/challenge DoS protection.
    rate_limiter: BridgeRateLimiter,
    /// REORG-FIX: Debt registry for failed clawbacks after L1 reorg.
    ///
    /// When a deposit is invalidated but the recipient has already spent the tokens,
    /// the unrecovered amount is recorded as debt. This debt:
    /// 1. Blocks the debtor from withdrawing BTC until repaid
    /// 2. Is deducted from any future deposits to the same address
    /// 3. Prevents unbacked tokens from circulating permanently
    ///
    /// Key: recipient address, Value: total unrecovered debt in satoshis.
    #[serde(default)]
    pub reorg_debt: HashMap<Address, u64>,
}

impl BridgeManager {
    /// Create a new bridge manager.
    pub fn new() -> Self {
        Self {
            deposits: HashMap::new(),
            withdrawals: HashMap::new(),
            total_locked: 0,
            total_minted: 0,
            paused: false,
            l1_height: 0,
            l2_height: 0,
            committed_state_roots: HashMap::new(),
            last_committed_height: 0,
            challenge_manager: ChallengeManager::new(),
            operator_manager: OperatorManager::new(),
            proof_store: ProofStore::new(),
            challenge_mode: ChallengeMode::Federated,
            zk_validity_challenge_l2: 0,
            federation: None,
            staking_committee: None,
            withdrawal_counter: 0,
            daily_volumes: HashMap::new(),
            emergency_exits: HashMap::new(),
            block_monitor: None,
            rate_limiter: BridgeRateLimiter::new(),
            reorg_debt: HashMap::new(),
        }
    }

    /// Set the block monitor for SPV chain verification.
    ///
    /// Once set, SPV proofs are verified against the canonical chain cached
    /// in the monitor. Without a monitor, SPV proofs are rejected and
    /// deposits require federation attestation.
    pub fn set_block_monitor(&mut self, monitor: brrq_bitcoin::BlockMonitor) {
        self.block_monitor = Some(monitor);
    }

    /// Access the bridge-level rate limiter.
    pub fn rate_limiter(&self) -> &BridgeRateLimiter {
        &self.rate_limiter
    }

    /// Replace the bridge-level rate limiter (for testing or configuration).
    pub fn set_rate_limiter(&mut self, limiter: BridgeRateLimiter) {
        self.rate_limiter = limiter;
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// Verify an SPV proof against the block monitor's canonical chain.
    ///
    /// Returns `Ok(true)` if the proof is valid, `Ok(false)` if no proof was
    /// provided. Returns `Err` if a proof was provided but verification failed.
    fn verify_spv_proof(
        &self,
        btc_tx_id: &Hash256,
        spv_proof: &Option<brrq_bitcoin::spv::SpvProof>,
    ) -> Result<bool, BridgeError> {
        let proof = match spv_proof {
            Some(p) => p,
            None => return Ok(false),
        };

        // 1. Ensure the proof is for the exact transaction claimed
        if proof.txid != *btc_tx_id.as_bytes() {
            return Err(BridgeError::Unauthorized {
                reason: "SPV proof txid does not match the claimed deposit txid".into(),
            });
        }

        // 2. Use verify_in_chain() instead of verify() to ensure
        //    the block is on the canonical best chain. verify() alone would
        //    accept proofs from orphan/stale blocks, enabling fund inflation.
        //
        //    BlockMonitor.has_block() verifies the block hash
        //    is in the recent canonical chain cache. If no monitor is set,
        //    we reject the SPV proof entirely — federation attestation is
        //    required as a fallback.
        let chain_check_result = match &self.block_monitor {
            Some(monitor) => {
                // Reject SPV proofs if block monitor is stale.
                // A stale monitor could accept proofs for blocks that have been reorged.
                let monitor_height = monitor.height();
                if self.l1_height > 0 && monitor_height + 6 < self.l1_height {
                    tracing::warn!(
                        monitor_height,
                        l1_height = self.l1_height,
                        "Block monitor stale — rejecting SPV proof"
                    );
                    return Err(BridgeError::Unauthorized {
                        reason: format!(
                            "block monitor stale: monitor at {}, L1 at {}, gap > 6",
                            monitor_height, self.l1_height
                        ),
                    });
                }
                proof.verify_in_chain(|block_hash| monitor.has_block(block_hash))
            }
            None => {
                // No block monitor — cannot verify chain membership.
                // Reject SPV proof; caller must provide federation attestation.
                brrq_bitcoin::spv::SpvVerifyResult::BlockNotInBestChain
            }
        };
        if chain_check_result != brrq_bitcoin::spv::SpvVerifyResult::Valid {
            return Err(BridgeError::Unauthorized {
                reason: "cryptographic SPV verification failed".into(),
            });
        }

        Ok(true)
    }

    /// Require federation attestation for a deposit when SPV proof is absent.
    ///
    /// Validates that the submitter is an active federation member and that
    /// the federation has not been sunset.
    fn require_federation_attestation(
        &self,
        submitter: Option<Address>,
    ) -> Result<(), BridgeError> {
        // After sunset, federation attestation is invalid — SPV proof required.
        if self.l1_height >= FEDERATION_SUNSET_L1_HEIGHT {
            return Err(BridgeError::Unauthorized {
                reason: format!(
                    "federation sunset reached at L1 height {} (current: {}). \
                     SPV proof required — federation attestation no longer accepted.",
                    FEDERATION_SUNSET_L1_HEIGHT, self.l1_height,
                ),
            });
        }

        let federation = self.federation.as_ref().ok_or(BridgeError::Unauthorized {
            reason: format!("no federation configured. submitter = {:?}", submitter),
        })?;

        let submitter_addr = submitter.ok_or(BridgeError::Unauthorized {
            reason: "deposit requires SPV proof or federation member attestation".into(),
        })?;

        if !federation.is_active_member(&submitter_addr) {
            return Err(BridgeError::Unauthorized {
                reason: "submitter is not an active federation member".into(),
            });
        }

        Ok(())
    }

    /// Validate deposit amount against limits and bridge cap.
    ///
    /// Returns the new total_locked value on success.
    fn validate_deposit_amount(&self, amount: u64) -> Result<u64, BridgeError> {
        if amount == 0 {
            return Err(BridgeError::InvalidAmount {
                reason: "zero amount".into(),
            });
        }

        if amount < MIN_DEPOSIT_AMOUNT {
            return Err(BridgeError::DepositBelowMinimum {
                amount,
                min: MIN_DEPOSIT_AMOUNT,
            });
        }
        if amount > MAX_DEPOSIT_AMOUNT {
            return Err(BridgeError::DepositExceedsMaximum {
                amount,
                max: MAX_DEPOSIT_AMOUNT,
            });
        }
        // Overflow-safe cap check: if total_locked + amount overflows, it exceeds cap
        let new_total_locked =
            self.total_locked
                .checked_add(amount)
                .ok_or(BridgeError::BridgeCapReached {
                    current: self.total_locked,
                    amount,
                    cap: TOTAL_BRIDGE_CAP,
                })?;
        if new_total_locked > TOTAL_BRIDGE_CAP {
            return Err(BridgeError::BridgeCapReached {
                current: self.total_locked,
                amount,
                cap: TOTAL_BRIDGE_CAP,
            });
        }

        Ok(new_total_locked)
    }

    /// Compute the effective number of confirmations for a deposit.
    ///
    /// SECURITY: When SPV proof is available, compute confirmations from
    /// proof.block_height vs current L1 height — don't trust caller's value.
    /// This prevents forged-confirmation attacks where a malicious caller
    /// passes confirmations=6 to bypass the waiting period.
    fn compute_effective_confirmations(
        &self,
        spv_proof: &Option<brrq_bitcoin::spv::SpvProof>,
        caller_confirmations: u32,
    ) -> u32 {
        if let Some(proof) = spv_proof {
            // SPV proof was already verified above (verify_in_chain passed).
            // Compute confirmations from L1 chain height difference.
            if self.l1_height >= proof.block_height {
                (self.l1_height - proof.block_height + 1) as u32
            } else {
                // Block is ahead of our L1 view — treat as 0 confirmations
                0
            }
        } else {
            // Federation attestation path — use caller-provided confirmations.
            // Federation members are trusted (they can already mint arbitrarily).
            caller_confirmations
        }
    }

    /// §4.4: Generate sovereign deposit recovery info.
    ///
    /// The committee pre-signs a timelocked refund transaction at deposit time.
    /// The user retains the signed transaction off-chain as an escape hatch.
    fn build_recovery_info(
        &self,
        btc_tx_id: &Hash256,
        btc_vout: u32,
        amount: u64,
    ) -> DepositRecoveryInfo {
        DepositRecoveryInfo {
            deposit_l1_height: self.l1_height,
            refund_available_at_l1: self.l1_height + DEPOSIT_RECOVERY_TIMELOCK_L1,
            refund_btc_address: String::new(), // Populated by L1 signing layer
            refund_tx_hash: {
                // Deterministic commitment: H("BRRQ_DEPOSIT_RECOVERY" || tx_id || vout || amount || l1_height)
                let mut hasher = Hasher::new();
                hasher.update(b"BRRQ_DEPOSIT_RECOVERY");
                hasher.update(btc_tx_id.as_bytes());
                hasher.update(&btc_vout.to_le_bytes());
                hasher.update(&amount.to_le_bytes());
                hasher.update(&self.l1_height.to_le_bytes());
                hasher.finalize()
            },
            recovered: false,
        }
    }

    /// Validate a Bitcoin destination address.
    ///
    /// Uses `bitcoin::Address` for full Bech32/Base58Check checksum
    /// validation so that a malformed address cannot burn peg-out funds.
    fn validate_btc_address(btc_destination: &str) -> Result<(), BridgeError> {
        if btc_destination.is_empty() {
            return Err(BridgeError::InvalidAmount {
                reason: "empty Bitcoin destination address".into(),
            });
        }

        // Full parse: Bech32 checksum for bc1/tb1, Base58Check for legacy.
        // `Address::from_str` returns `Address<NetworkUnchecked>` — it
        // validates format and checksum without requiring a specific network.
        use std::str::FromStr;
        bitcoin::Address::from_str(btc_destination).map_err(|e| {
            BridgeError::InvalidAmount {
                reason: format!("invalid Bitcoin address: {e}"),
            }
        })?;

        Ok(())
    }

    /// Validate STARK proof state roots against committed L2 state roots.
    ///
    /// Shared validation between `verify_withdrawal_with_stark_proof` and
    /// `hybrid_complete_withdrawal`. Verifies:
    /// 1. Committed state roots exist
    /// 2. Initial state root is committed
    /// 3. Final state root is committed
    /// 4. State transition is not a no-op (initial != final)
    ///
    /// Returns the height at which the final state root was committed.
    fn validate_proof_state_roots(
        &self,
        proof: &StarkProof,
        context: &str,
    ) -> Result<Option<u64>, BridgeError> {
        if self.committed_state_roots.is_empty() {
            return Err(BridgeError::InvalidProof {
                reason: format!(
                    "no committed L2 state roots — cannot verify proof binding{}",
                    if context.is_empty() { String::new() } else { format!(" in {context} path") },
                ),
            });
        }

        let root_known = self
            .committed_state_roots
            .values()
            .any(|r| *r == proof.initial_state_root);
        if !root_known {
            return Err(BridgeError::InvalidProof {
                reason: format!(
                    "proof initial_state_root does not match any committed L2 state root{}",
                    if context.is_empty() { String::new() } else { format!(" — {context} path rejects unbound proofs") },
                ),
            });
        }

        let final_root_known = self
            .committed_state_roots
            .values()
            .any(|r| *r == proof.final_state_root);
        if !final_root_known {
            return Err(BridgeError::InvalidProof {
                reason: format!(
                    "proof final_state_root does not match any committed L2 state root \
                     — state transition target is not recognized{}",
                    if context.is_empty() { String::new() } else { format!(" in {context} path") },
                ),
            });
        }

        // Reject no-op state transitions
        // BEFORE modifying state. A proof where initial == final proves nothing.
        if proof.initial_state_root == proof.final_state_root {
            return Err(BridgeError::InvalidProof {
                reason: "proof initial_state_root == final_state_root — \
                         no-op state transition is invalid for withdrawals"
                    .to_string(),
            });
        }

        // Bind verified_at_height to the
        // FINAL state root, not the initial. The committee attests to the post-
        // transition state ("after executing these transactions, the state root
        // became X"). Using initial_state_root here would cause the cross-check
        // in hybrid_complete_withdrawal to compare the attestation against the
        // pre-transition state — a semantic mismatch.
        let final_root_height = self
            .committed_state_roots
            .iter()
            .find(|(_, r)| **r == proof.final_state_root)
            .map(|(h, _)| *h);

        Ok(final_root_height)
    }

    /// Ensure a withdrawal is in Ready status and not already completed.
    ///
    /// Shared guard between `complete_withdrawal` and `permissionless_complete`.
    fn require_withdrawal_ready(
        &self,
        withdrawal_id: &Hash256,
    ) -> Result<(), BridgeError> {
        let withdrawal =
            self.withdrawals
                .get(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        if withdrawal.status == WithdrawalStatus::Completed {
            return Err(BridgeError::AlreadyClaimed {
                tx_id: *withdrawal_id,
            });
        }

        if withdrawal.status != WithdrawalStatus::Ready {
            return Err(BridgeError::InvalidProof {
                reason: "Withdrawal not yet verified by STARK proof".to_string(),
            });
        }

        Ok(())
    }

    /// Slash operators for all withdrawals verified at heights within a range.
    ///
    /// Shared between `tick_challenges` and `respond_to_challenge` for
    /// InvalidSnarkWrapping challenge resolution.
    fn slash_operators_in_height_range(
        &mut self,
        start: u64,
        end: u64,
        challenge_id: &Hash256,
        slash_failures: &mut Vec<(Hash256, BridgeError)>,
    ) {
        let affected: Vec<Hash256> = self
            .withdrawals
            .iter()
            .filter(|(_, w)| {
                w.verified_at_height
                    .map(|h| h >= start && h <= end)
                    .unwrap_or(false)
            })
            .map(|(id, _)| *id)
            .collect();
        for wid in &affected {
            if self.operator_manager.has_reimbursement(wid) {
                if let Err(e) = self.operator_manager.slash_operator(wid) {
                    tracing::error!(?wid, ?challenge_id, %e,
                        "Failed to slash for InvalidSnarkWrapping");
                    slash_failures.push((*challenge_id, e));
                }
            }
        }
        if affected.is_empty() {
            tracing::warn!(?challenge_id, start, end,
                "No withdrawals found in range for InvalidSnarkWrapping slash");
        }
    }

    // ── Accounting invariant assertion ───────────────────────
    //
    // Core safety property: total_minted ≤ total_locked (fees go to the
    // bridge, so locked always ≥ minted). Any violation means a bug in
    // the deposit/withdrawal/completion paths.
    //
    // Called after every state mutation on the money-flow paths. In debug
    // builds this panics immediately; in release builds it ALSO panics —
    // an unbacked token supply is catastrophic and must halt the bridge.
    //
    // Uses assert! (not debug_assert!) so the invariant is enforced in production. A bridge that
    // continues operating with total_minted > total_locked will drain real
    // BTC from the reserve when users withdraw unbacked tokens.
    fn assert_accounting_invariant(&self) {
        // Account for reorg debt in invariant check.
        // After a deep L1 reorg, tokens may circulate without L1 backing
        // (recorded as reorg_debt). The invariant must tolerate this:
        //   total_minted <= total_locked + total_reorg_debt
        // Without this, any deep reorg permanently halts the node.
        let total_debt: u64 = self.reorg_debt.values().copied().sum();
        if self.total_minted > self.total_locked.saturating_add(total_debt) {
            let msg = format!(
                "ACCOUNTING INVARIANT VIOLATED: total_minted ({}) > total_locked ({}) + reorg_debt ({})",
                self.total_minted, self.total_locked, total_debt,
            );
            #[cfg(not(test))]
            tracing::error!("{msg}");
            assert!(false, "{}", msg);
        }
    }

    /// Serialize entire bridge state to bytes (bincode).
    pub fn to_bytes(&self) -> Result<Vec<u8>, String> {
        bincode::serialize(self).map_err(|e| format!("bridge serialize: {e}"))
    }

    /// Deserialize bridge state from bytes (bincode).
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        bincode::deserialize(data).map_err(|e| format!("bridge deserialize: {e}"))
    }

    /// Check and update daily volume for an address.
    ///
    /// Returns an error if adding `amount` would exceed the daily limit.
    /// Resets the window if `DAILY_VOLUME_WINDOW_BLOCKS` have passed.
    fn check_daily_volume(&mut self, address: &Address, amount: u64) -> Result<(), BridgeError> {
        let entry = self.daily_volumes.entry(*address).or_insert(AddressVolume {
            volume: 0,
            window_start: self.l2_height,
        });

        // Reset window if enough blocks have passed.
        if self.l2_height.saturating_sub(entry.window_start) >= DAILY_VOLUME_WINDOW_BLOCKS {
            entry.volume = 0;
            entry.window_start = self.l2_height;
        }

        let new_volume = entry.volume.saturating_add(amount);
        if new_volume > MAX_DAILY_VOLUME_PER_ADDRESS {
            return Err(BridgeError::DailyVolumeLimitExceeded {
                used: entry.volume,
                amount,
                limit: MAX_DAILY_VOLUME_PER_ADDRESS,
            });
        }

        entry.volume = new_volume;
        Ok(())
    }

    /// Register a committed L2 state root at a given height.
    ///
    /// Called by the node after each block is finalized. STARK proofs
    /// must have their `initial_state_root` match one of these committed
    /// roots to prevent fabricated proofs with arbitrary state.
    pub fn commit_state_root(&mut self, height: u64, state_root: Hash256) {
        if height <= self.last_committed_height && self.last_committed_height > 0 {
            tracing::warn!(
                height,
                last = self.last_committed_height,
                "Rejected non-monotonic state root commit",
            );
            return;
        }
        self.committed_state_roots.insert(height, state_root);
        self.last_committed_height = height;
    }

    /// Prune old committed state roots to prevent unbounded memory growth.
    ///
    /// Retains only state roots at or above `min_height`. Called periodically
    /// (e.g., after each epoch) to free memory from roots that are too old to
    /// be relevant for proof verification.
    ///
    /// Use `challenge_period_l2_blocks() + safety_margin` as the retention window
    /// to ensure all in-flight proofs can still be verified.
    ///
    /// Returns the number of pruned entries.
    pub fn prune_state_roots(&mut self, min_height: u64) -> usize {
        let before = self.committed_state_roots.len();
        self.committed_state_roots.retain(|h, _| *h >= min_height);
        before - self.committed_state_roots.len()
    }

    /// Prune expired daily volume entries to prevent unbounded growth.
    ///
    /// Removes entries whose volume window has expired (older than
    /// `DAILY_VOLUME_WINDOW_BLOCKS` from current L2 height). Should be
    /// called periodically (e.g., once per epoch).
    ///
    /// Returns the number of pruned entries.
    pub fn prune_expired_volumes(&mut self) -> usize {
        let current = self.l2_height;
        let before = self.daily_volumes.len();
        self.daily_volumes
            .retain(|_, v| current.saturating_sub(v.window_start) < DAILY_VOLUME_WINDOW_BLOCKS);
        before - self.daily_volumes.len()
    }

    /// Process a new peg-in deposit.
    ///
    /// ## Authentication
    ///
    /// Deposits can be authenticated in two ways:
    /// 1. **SPV proof** (`spv_verified = true`): The caller has already verified
    ///    a Bitcoin SPV inclusion proof. No federation attestation needed.
    /// 2. **Federation attestation** (`spv_verified = false`): The `submitter`
    ///    must be an active federation member.
    ///
    /// **NOTE**: SPV proof verification is now handled internally via the
    /// `spv_proof` parameter and `BlockMonitor`. When an `SpvProof`
    /// is provided, it is verified against the canonical chain.
    //
    // Note: #[allow(clippy::too_many_arguments)] is on process_deposit below.
    //
    /// H4-FIX: Check and enforce federation sunset at current L1 height.
    ///
    /// MUST be called every L2 block (not just on deposits).
    /// After FEDERATION_SUNSET_L1_HEIGHT, the federation is dissolved and
    /// ChallengeMode switches to BitVM2 unconditionally.
    ///
    /// This is a constitutional guarantee — no governance can override it.
    pub fn check_federation_sunset(&mut self) {
        if self.l1_height >= FEDERATION_SUNSET_L1_HEIGHT {
            // Dissolve federation in ALL modes, not just Federated.
            if self.federation.is_some() {
                let prev_mode = self.challenge_mode;
                if self.challenge_mode == ChallengeMode::Federated {
                    self.challenge_mode = ChallengeMode::BitVM2;
                }
                self.federation = None;
                tracing::warn!(
                    l1_height = self.l1_height,
                    sunset = FEDERATION_SUNSET_L1_HEIGHT,
                    ?prev_mode,
                    "FEDERATION-SUNSET: Federation auto-dissolved. \
                     Federation object removed regardless of challenge mode."
                );
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn process_deposit(
        &mut self,
        btc_tx_id: Hash256,
        btc_vout: u32,
        amount: u64,
        recipient: Address,
        confirmations: u32,
        submitter: Option<Address>,
        spv_proof: Option<brrq_bitcoin::spv::SpvProof>,
    ) -> Result<u64, BridgeError> {
        if self.paused {
            return Err(BridgeError::BridgePaused);
        }

        // Rate limiting — prevent deposit spam from a single address.
        self.rate_limiter
            .check_deposit(&recipient, self.l2_height)?;

        // --- CRYPTOGRAPHIC ZERO-TRUST VALIDATION ---
        let spv_verified = self.verify_spv_proof(&btc_tx_id, &spv_proof)?;

        // H4-FIX: Sunset check delegated to reusable method
        self.check_federation_sunset();

        if !spv_verified {
            self.require_federation_attestation(submitter)?;
        }

        let new_total_locked = self.validate_deposit_amount(amount)?;

        // Per-address daily volume limit (anti-monopolization).
        self.check_daily_volume(&recipient, amount)?;

        let effective_confirmations =
            self.compute_effective_confirmations(&spv_proof, confirmations);

        let status = if effective_confirmations >= REQUIRED_CONFIRMATIONS {
            DepositStatus::Confirmed
        } else {
            DepositStatus::Pending
        };

        let fee = amount.saturating_mul(PEGIN_FEE_BP) / 10_000;
        let minted = amount.checked_sub(fee).ok_or(BridgeError::InvalidAmount {
            reason: "deposit fee exceeds amount".into(),
        })?;

        let recovery_info = self.build_recovery_info(&btc_tx_id, btc_vout, amount);

        let deposit = DepositRequest {
            btc_tx_id,
            btc_vout,
            amount,
            recipient,
            confirmations: effective_confirmations,
            status,
            spv_proof,
            recovery_info: Some(recovery_info),
        };

        // Use composite key (btc_tx_id, btc_vout) to prevent deposit overwrite
        // when the same Bitcoin transaction has multiple outputs.
        let key = (btc_tx_id, btc_vout);
        if self.deposits.contains_key(&key) {
            return Err(BridgeError::DuplicateDeposit {
                tx_id: btc_tx_id,
                vout: btc_vout,
            });
        }
        self.deposits.insert(key, deposit);

        if status == DepositStatus::Confirmed {
            // Safe: new_total_locked was pre-validated via checked_add above
            self.total_locked = new_total_locked;
            self.total_minted =
                self.total_minted
                    .checked_add(minted)
                    .ok_or(BridgeError::InvalidAmount {
                        reason: "total_minted overflow on deposit".into(),
                    })?;
            self.assert_accounting_invariant();

            // Repay any outstanding reorg debt for this recipient.
            // When a deep L1 reorg previously invalidated finalized deposits,
            // the recipient's debt was recorded. New deposits automatically
            // deduct from this debt to prevent unbacked token circulation.
            let repaid = self.repay_reorg_debt(&recipient, minted);
            if repaid > 0 {
                tracing::info!(
                    recipient = %recipient,
                    repaid,
                    remaining_debt = self.reorg_debt.get(&recipient).copied().unwrap_or(0),
                    "reorg debt partially repaid from new deposit"
                );
            }
        }

        Ok(minted)
    }

    /// Update confirmations for a pending deposit.
    pub fn update_deposit_confirmations(
        &mut self,
        btc_tx_id: &Hash256,
        btc_vout: u32,
        confirmations: u32,
    ) -> Result<DepositStatus, BridgeError> {
        let key = (*btc_tx_id, btc_vout);
        let deposit = self
            .deposits
            .get_mut(&key)
            .ok_or(BridgeError::DepositNotFound { tx_id: *btc_tx_id })?;

        deposit.confirmations = confirmations;

        if deposit.status == DepositStatus::Pending && confirmations >= REQUIRED_CONFIRMATIONS {
            // Enforce bridge cap even on confirmation (prevents pending deposit race)
            let new_locked = self.total_locked.checked_add(deposit.amount).ok_or(
                BridgeError::BridgeCapReached {
                    current: self.total_locked,
                    amount: deposit.amount,
                    cap: TOTAL_BRIDGE_CAP,
                },
            )?;
            if new_locked > TOTAL_BRIDGE_CAP {
                return Err(BridgeError::BridgeCapReached {
                    current: self.total_locked,
                    amount: deposit.amount,
                    cap: TOTAL_BRIDGE_CAP,
                });
            }
            deposit.status = DepositStatus::Confirmed;
            // Use checked_sub consistently (matches process_deposit).
            let fee = deposit.amount.saturating_mul(PEGIN_FEE_BP) / 10_000;
            let minted = deposit
                .amount
                .checked_sub(fee)
                .ok_or(BridgeError::InvalidAmount {
                    reason: "deposit fee exceeds amount on confirmation".into(),
                })?;
            self.total_locked = new_locked;
            self.total_minted =
                self.total_minted
                    .checked_add(minted)
                    .ok_or(BridgeError::InvalidAmount {
                        reason: "total_minted overflow on confirmation".into(),
                    })?;
        }

        let status = deposit.status;
        self.assert_accounting_invariant();
        Ok(status)
    }

    /// §4.4: Mark a deposit as recovered via the sovereign exit path.
    ///
    /// Called when the user has broadcast their pre-signed refund transaction
    /// on L1 after the OP_CLTV timelock expired. The bridge updates its
    /// accounting to reflect that the BTC has been returned to the user.
    ///
    /// **Preconditions:**
    /// - Deposit must exist and not already be recovered.
    /// - Current L1 height must be >= refund_available_at_l1.
    pub fn mark_deposit_recovered(
        &mut self,
        btc_tx_id: &Hash256,
        btc_vout: u32,
    ) -> Result<u64, BridgeError> {
        let key = (*btc_tx_id, btc_vout);
        let deposit = self
            .deposits
            .get_mut(&key)
            .ok_or(BridgeError::DepositNotFound { tx_id: *btc_tx_id })?;

        let recovery = deposit.recovery_info.as_mut().ok_or(BridgeError::InvalidProof {
            reason: "deposit has no recovery info".into(),
        })?;

        if recovery.recovered {
            return Err(BridgeError::AlreadyClaimed { tx_id: *btc_tx_id });
        }

        if self.l1_height < recovery.refund_available_at_l1 {
            return Err(BridgeError::ChallengePeriodActive {
                remaining_blocks: recovery.refund_available_at_l1 - self.l1_height,
            });
        }

        // Only allow recovery for deposits NOT yet credited to L2.
        // If the deposit was Confirmed/Finalized, L2 tokens were minted and may
        // have been spent. Recovering the L1 BTC while L2 tokens still circulate
        // creates a double-spend that makes the bridge insolvent.
        //
        // §4.4: Recovery is an escape hatch for when the bridge fails. If the
        // deposit WAS confirmed, the bridge was working — use normal withdrawal.
        if deposit.status == DepositStatus::Confirmed
            || deposit.status == DepositStatus::Finalized
        {
            return Err(BridgeError::InvalidProof {
                reason: "cannot recover deposit already credited to L2 state — \
                         L2 tokens were minted and may have been spent. \
                         Use normal withdrawal instead (prevents double-spend)"
                    .into(),
            });
        }

        recovery.recovered = true;
        let amount = deposit.amount;

        // No accounting reversal needed: Pending deposits have not been
        // credited to total_locked or total_minted yet.

        Ok(amount)
    }

    /// Check if a deposit's sovereign recovery timelock has expired.
    pub fn is_deposit_recovery_available(
        &self,
        btc_tx_id: &Hash256,
        btc_vout: u32,
    ) -> Result<bool, BridgeError> {
        let key = (*btc_tx_id, btc_vout);
        let deposit = self
            .deposits
            .get(&key)
            .ok_or(BridgeError::DepositNotFound { tx_id: *btc_tx_id })?;

        match &deposit.recovery_info {
            Some(info) => Ok(!info.recovered && self.l1_height >= info.refund_available_at_l1),
            None => Ok(false),
        }
    }

    /// Mark a confirmed deposit as finalized (included in L2 state root on L1).
    ///
    /// Called after the L2 block containing this deposit is anchored on L1
    /// via a STARK proof commitment. Finalized deposits are safe to prune.
    pub fn finalize_deposit(
        &mut self,
        btc_tx_id: &Hash256,
        btc_vout: u32,
    ) -> Result<(), BridgeError> {
        let key = (*btc_tx_id, btc_vout);
        let deposit = self
            .deposits
            .get_mut(&key)
            .ok_or(BridgeError::DepositNotFound { tx_id: *btc_tx_id })?;
        if deposit.status != DepositStatus::Confirmed {
            return Err(BridgeError::InvalidAmount {
                reason: format!(
                    "deposit is {:?}, only Confirmed can be finalized",
                    deposit.status
                ),
            });
        }
        deposit.status = DepositStatus::Finalized;
        Ok(())
    }

    /// Invalidate deposits that were confirmed but not yet finalized.
    ///
    /// Called when a Bitcoin chain reorg is detected. Deposits that were
    /// confirmed at or after `reorg_height` are reverted to Pending status,
    /// and their minted amounts are reversed from the bridge totals.
    ///
    /// Only deposits whose confirmation would have been at or above the reorg
    /// height are affected. Deposits confirmed well before the reorg remain
    /// valid, reducing unnecessary disruption.
    ///
    /// Returns the list of affected (btc_tx_id, btc_vout, recipient, amount) tuples
    /// so the caller can debit the recipients on L2.
    /// Depth of L1 reorg (in blocks) that triggers the circuit breaker.
    /// A reorg deeper than 6 blocks (our confirmation requirement) means
    /// Finalized deposits may have lost their L1 backing.
    const DEEP_REORG_THRESHOLD: u64 = 6;

    pub fn invalidate_unfinalized_deposits(
        &mut self,
        reorg_height: u64,
    ) -> Vec<(Hash256, u32, Address, u64)> {
        let mut invalidated = Vec::new();

        // Detect reorgs deeper than
        // confirmation threshold. If a Finalized deposit's SPV proof block
        // was orphaned, the minted brqBTC has no L1 backing → inflation.
        //
        // Defense: if reorg depth > REQUIRED_CONFIRMATIONS:
        // 1. Pause bridge immediately (prevent withdrawal of unbacked tokens)
        // 2. Log critical alert for operator intervention
        // 3. Finalized deposits in the reorg range are flagged
        let reorg_depth = self.l1_height.saturating_sub(reorg_height);
        if reorg_depth > Self::DEEP_REORG_THRESHOLD as u64 {
            tracing::error!(
                reorg_depth,
                reorg_height,
                current_l1 = self.l1_height,
                "CIRCUIT-BREAKER: Deep L1 reorg detected (depth {} > threshold {}). \
                 Pausing bridge to prevent unbacked brqBTC withdrawal.",
                reorg_depth,
                Self::DEEP_REORG_THRESHOLD,
            );
            self.paused = true;

            // Flag Finalized deposits that may have lost L1 backing
            for ((tx_id, vout), deposit) in self.deposits.iter() {
                if deposit.status == DepositStatus::Finalized {
                    // Check if this deposit's SPV proof block might be in the reorg range
                    if let Some(ref proof) = deposit.spv_proof {
                        if proof.block_height >= reorg_height {
                            tracing::error!(
                                tx_id = %tx_id,
                                vout,
                                amount = deposit.amount,
                                proof_block = proof.block_height,
                                "CIRCUIT-BREAKER: Finalized deposit may have lost L1 backing!"
                            );
                        }
                    }
                }
            }
        }

        for ((tx_id, vout), deposit) in self.deposits.iter_mut() {
            // Only revert Confirmed (not Finalized) deposits
            if deposit.status == DepositStatus::Confirmed {
                // Only invalidate deposits whose confirmation height falls at or
                // after the reorg height. A deposit confirmed at L1 height H is
                // affected by a reorg at height R only if H >= R.
                let confirmed_at_l1 = self.l1_height.saturating_sub(deposit.confirmations as u64);
                if confirmed_at_l1 < reorg_height {
                    // This deposit was confirmed well before the reorg — safe.
                    continue;
                }

                let fee = deposit.amount.saturating_mul(PEGIN_FEE_BP) / 10_000;
                let minted = deposit.amount.saturating_sub(fee);

                deposit.status = DepositStatus::Pending;
                deposit.confirmations = 0;
                // Clear stale SPV proof on reorg.
                // After a reorg, the stored proof points to an orphaned block.
                // If the transaction is re-included, a fresh proof must be
                // obtained — the old proof cannot be reused.
                deposit.spv_proof = None;

                // REORG-FIX: Only decrement total_locked here (L1 BTC is genuinely gone).
                // total_minted is decremented AFTER the caller reports actual recovery.
                // This prevents the invariant violation where total_minted < actual circulation.
                self.total_locked = self.total_locked.saturating_sub(deposit.amount);

                // Decrement daily volume for the recipient.
                // Without this, the per-address daily volume stays inflated
                // after a reorg reverts the deposit — locking out the user
                // from future deposits until the window expires naturally.
                if let Some(vol) = self.daily_volumes.get_mut(&deposit.recipient) {
                    vol.volume = vol.volume.saturating_sub(deposit.amount);
                }

                invalidated.push((*tx_id, *vout, deposit.recipient, minted));
            }
        }

        if !invalidated.is_empty() {
            tracing::warn!(
                count = invalidated.len(),
                reorg_height,
                "Invalidated unfinalized deposits due to L1 reorg",
            );
        }

        invalidated
    }

    /// REORG-FIX: Report the result of a clawback attempt after deposit invalidation.
    ///
    /// The caller (bitcoin_sync.rs) reports how much was actually recovered from
    /// the recipient's balance. Any shortfall becomes reorg_debt.
    ///
    /// - `recovered`: satoshis actually debited from recipient's WorldState balance
    /// - `expected`: satoshis that should have been recovered (minted amount)
    /// - `recipient`: address whose deposit was invalidated
    pub fn report_clawback_result(
        &mut self,
        recipient: Address,
        expected: u64,
        recovered: u64,
    ) {
        // Decrement total_minted by what was ACTUALLY recovered
        self.total_minted = self.total_minted.saturating_sub(recovered);

        // Record unrecovered amount as debt
        let debt = expected.saturating_sub(recovered);
        if debt > 0 {
            *self.reorg_debt.entry(recipient).or_insert(0) += debt;
            tracing::error!(
                recipient = %recipient,
                expected,
                recovered,
                debt,
                total_debt = self.reorg_debt[&recipient],
                "REORG CLAWBACK SHORTFALL: unbacked tokens in circulation — debt recorded"
            );
        }
    }

    /// Check if an address has reorg debt (blocks withdrawals until repaid).
    pub fn has_reorg_debt(&self, address: &Address) -> bool {
        self.reorg_debt.get(address).copied().unwrap_or(0) > 0
    }

    /// Get the reorg debt for an address.
    pub fn get_reorg_debt(&self, address: &Address) -> u64 {
        self.reorg_debt.get(address).copied().unwrap_or(0)
    }

    /// Repay reorg debt (called when debtor receives new deposits or transfers).
    pub fn repay_reorg_debt(&mut self, address: &Address, amount: u64) -> u64 {
        if let Some(debt) = self.reorg_debt.get_mut(address) {
            let repaid = amount.min(*debt);
            *debt -= repaid;
            self.total_minted = self.total_minted.saturating_sub(repaid);
            if *debt == 0 {
                self.reorg_debt.remove(address);
            }
            repaid
        } else {
            0
        }
    }

    // ── Single withdrawal completion path ──────────────
    //
    // All completion paths (complete_withdrawal, permissionless_complete,
    // approve_federation_proposal, force_exit) must converge here for the
    // final accounting step. This eliminates the risk of drift between
    // duplicated payout/accounting logic.
    //
    // Preconditions enforced by caller:
    //   - withdrawal_id exists
    //   - status is Ready (or Pending/Ready for force_exit)
    //   - authorization/challenge period checks have passed
    //
    // Returns the BTC payout amount on success.
    fn finalize_withdrawal_internal(
        &mut self,
        withdrawal_id: &Hash256,
        target_status: WithdrawalStatus,
    ) -> Result<u64, BridgeError> {
        let withdrawal =
            self.withdrawals
                .get(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        // State transition guard — reject invalid transitions.
        if !withdrawal.status.can_transition_to(target_status) {
            return Err(BridgeError::InvalidProof {
                reason: format!(
                    "invalid withdrawal state transition: {:?} → {:?}",
                    withdrawal.status, target_status,
                ),
            });
        }

        // Compute payout with checked arithmetic.
        let payout =
            withdrawal
                .amount
                .checked_sub(withdrawal.fee)
                .ok_or(BridgeError::InvalidAmount {
                    reason: format!(
                        "withdrawal fee ({}) exceeds amount ({})",
                        withdrawal.fee, withdrawal.amount,
                    ),
                })?;
        if payout == 0 {
            return Err(BridgeError::InvalidAmount {
                reason: "withdrawal payout is zero after fee deduction".into(),
            });
        }

        // Compute new totals BEFORE mutating state — if either underflows,
        // no state has changed and we return an error cleanly.
        let amount = withdrawal.amount;
        let new_minted =
            self.total_minted
                .checked_sub(amount)
                .ok_or(BridgeError::InvalidAmount {
                    reason: "total_minted underflow during withdrawal finalization".into(),
                })?;
        let new_locked =
            self.total_locked
                .checked_sub(amount)
                .ok_or(BridgeError::InvalidAmount {
                    reason: "total_locked underflow during withdrawal finalization".into(),
                })?;

        // Commit atomically: status + both counters together.
        let withdrawal =
            self.withdrawals
                .get_mut(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;
        withdrawal.status = target_status;
        self.total_minted = new_minted;
        self.total_locked = new_locked;
        self.assert_accounting_invariant();

        Ok(payout)
    }

    /// Request a peg-out withdrawal.
    pub fn request_withdrawal(
        &mut self,
        sender: Address,
        amount: u64,
        btc_destination: String,
    ) -> Result<Hash256, BridgeError> {
        if self.paused {
            return Err(BridgeError::BridgePaused);
        }

        // Rate limiting — prevent withdrawal spam from a single address.
        self.rate_limiter
            .check_withdrawal(&sender, self.l2_height)?;

        if amount == 0 {
            return Err(BridgeError::InvalidAmount {
                reason: "zero amount".into(),
            });
        }

        // Enforce minimum withdrawal to prevent dust attacks.
        if amount < MIN_WITHDRAWAL_AMOUNT {
            return Err(BridgeError::AmountBelowMinimum {
                amount,
                min: MIN_WITHDRAWAL_AMOUNT,
            });
        }

        if amount > MAX_WITHDRAWAL_AMOUNT {
            return Err(BridgeError::WithdrawalExceedsMaximum {
                amount,
                max: MAX_WITHDRAWAL_AMOUNT,
            });
        }

        // Per-address daily volume limit (anti-monopolization).
        self.check_daily_volume(&sender, amount)?;

        // Use saturating_mul for overflow safety (matches deposit path).
        let fee = amount.saturating_mul(PEGOUT_FEE_BP) / 10_000;
        if fee >= amount {
            return Err(BridgeError::InvalidAmount {
                reason: "fee exceeds amount".into(),
            });
        }

        // Basic Bitcoin address validation.
        Self::validate_btc_address(&btc_destination)?;

        // Generate withdrawal ID with monotonic counter for uniqueness.
        // Without the counter, two requests with the same (sender, amount,
        // destination, l2_height) would produce the same ID, silently
        // overwriting the first withdrawal in the HashMap.
        //
        // Use checked_add to prevent counter wrap-around.
        // At u64::MAX (practically unreachable but defense-in-depth), reject
        // the withdrawal rather than risk ID collisions.
        let counter = self.withdrawal_counter;
        self.withdrawal_counter =
            self.withdrawal_counter
                .checked_add(1)
                .ok_or(BridgeError::InvalidAmount {
                    reason: "withdrawal counter overflow — too many withdrawals".into(),
                })?;

        let mut hasher = Hasher::new();
        hasher.update(b"WITHDRAWAL");
        hasher.update(sender.as_bytes());
        hasher.update(&amount.to_le_bytes());
        hasher.update(&self.l2_height.to_le_bytes());
        hasher.update(btc_destination.as_bytes());
        hasher.update(&counter.to_le_bytes());
        let withdrawal_id = hasher.finalize();

        // Reject duplicate withdrawal IDs (should never happen with the
        // monotonic counter, but guard against it defensively).
        if self.withdrawals.contains_key(&withdrawal_id) {
            return Err(BridgeError::DuplicateWithdrawal(withdrawal_id));
        }

        // Lock the challenge period at request time so that mode
        // transitions (Federated→BitVM2 or vice versa) don't retroactively
        // change in-flight withdrawal timelines.
        let challenge_period_l2 = self.challenge_period_l2_blocks();

        let withdrawal = WithdrawalRequest {
            withdrawal_id,
            sender,
            amount,
            btc_destination,
            fee,
            request_height: self.l2_height,
            status: WithdrawalStatus::Pending,
            is_verified: false,
            verified_at_height: None,
            challenge_period_l2,
        };

        self.withdrawals.insert(withdrawal_id, withdrawal);
        Ok(withdrawal_id)
    }

    /// Verify a withdrawal using a serialized (bincode) STARK proof.
    ///
    /// This is the primary verification method used by the RPC layer.
    /// It deserializes the proof bytes, runs full STARK verification,
    /// and validates that the proof's state roots are consistent.
    pub fn verify_withdrawal_proof(
        &mut self,
        withdrawal_id: &Hash256,
        proof_payload: &[u8],
    ) -> Result<WithdrawalStatus, BridgeError> {
        const MAX_PROOF_PAYLOAD_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

        if proof_payload.is_empty() {
            return Err(BridgeError::InvalidProof {
                reason: "empty STARK proof payload".to_string(),
            });
        }
        if proof_payload.len() > MAX_PROOF_PAYLOAD_BYTES {
            return Err(BridgeError::InvalidProof {
                reason: "proof payload exceeds maximum size".to_string(),
            });
        }

        let proof =
            StarkProof::from_bytes(proof_payload).map_err(|_| BridgeError::InvalidProof {
                reason: "proof deserialization failed".to_string(),
            })?;

        self.verify_withdrawal_with_stark_proof(withdrawal_id, &proof)
    }

    /// Verify a withdrawal using a `StarkProof` struct directly.
    ///
    /// This method performs full STARK proof verification using
    /// `StarkVerifier::verify()`, then validates:
    /// 1. Proof is cryptographically valid (AIR, FRI, Merkle, LogUp)
    /// 2. Proof covers a valid state transition (non-zero steps)
    /// 3. Withdrawal request height is compatible with the proof
    ///
    /// On success, marks the withdrawal as `Ready` and `is_verified = true`.
    pub fn verify_withdrawal_with_stark_proof(
        &mut self,
        withdrawal_id: &Hash256,
        proof: &StarkProof,
    ) -> Result<WithdrawalStatus, BridgeError> {
        // Check withdrawal exists and is not already completed (immutable borrow).
        {
            let withdrawal =
                self.withdrawals
                    .get(withdrawal_id)
                    .ok_or(BridgeError::WithdrawalNotFound {
                        tx_id: *withdrawal_id,
                    })?;

            if withdrawal.status == WithdrawalStatus::Completed {
                return Err(BridgeError::AlreadyClaimed {
                    tx_id: *withdrawal_id,
                });
            }
        }

        // ── Step 1: Full STARK cryptographic verification ──
        // This is the critical security check — verifies AIR constraints,
        // FRI low-degree test, Merkle proofs, coprocessor LogUp, and
        // Fiat-Shamir transcript consistency.
        StarkVerifier::verify(proof).map_err(|_| BridgeError::InvalidProof {
            reason: "STARK verification failed".to_string(),
        })?;

        // SNARK wrapping is an L1 anchoring concern, not withdrawal verification.
        // When `real-plonky2` is enabled, SNARK proofs are generated for L1 posting
        // but are not re-verified here — STARK verification is the trust anchor for
        // withdrawal approval. The SNARK layer is verified at L1 anchor time.
        #[cfg(not(feature = "real-plonky2"))]
        tracing::warn!(
            "SNARK layer is simulated (real-plonky2 not enabled). \
             Withdrawal approved based on STARK verification only."
        );

        // ── Step 2: Validate proof covers meaningful execution ──
        if proof.num_steps == 0 {
            return Err(BridgeError::InvalidProof {
                reason: "proof covers zero execution steps".to_string(),
            });
        }

        // ── Step 3: State root binding ──
        // Verify the proof commits to a valid state transition.
        // The initial and final state roots must not both be zero
        // (which would indicate a trivial/synthetic proof).
        if proof.initial_state_root == Hash256::ZERO && proof.final_state_root == Hash256::ZERO {
            return Err(BridgeError::InvalidProof {
                reason: "proof has null state roots — cannot bind to a real state transition"
                    .to_string(),
            });
        }

        // ── Steps 4-5: Validate state roots against committed L2 roots ──
        // Fix
        let final_root_height = self.validate_proof_state_roots(proof, "")?;

        // Update withdrawal: mark as verified and ready (mutable borrow).
        let withdrawal =
            self.withdrawals
                .get_mut(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;
        withdrawal.verified_at_height = final_root_height;
        withdrawal.status = WithdrawalStatus::Ready;
        withdrawal.is_verified = true;

        Ok(withdrawal.status)
    }

    /// Verify a withdrawal against a stored `BatchProofRecord`.
    ///
    /// Used by the node when it already has a generated and pre-verified
    /// batch proof. This method checks:
    /// 1. The batch proof was internally verified (record.verified == true)
    /// 2. The withdrawal request height falls within the batch's block range
    /// 3. The proof is cryptographically valid (re-verification for safety)
    pub fn verify_withdrawal_with_batch_proof(
        &mut self,
        withdrawal_id: &Hash256,
        record: &brrq_prover::BatchProofRecord,
    ) -> Result<WithdrawalStatus, BridgeError> {
        // Check the batch proof was pre-verified
        if !record.verified {
            return Err(BridgeError::InvalidProof {
                reason: "batch proof record was not verified by StarkVerifier".to_string(),
            });
        }

        // SNARK simulation guard for batch proofs (feature-gated).
        // With real-plonky2: hard-reject simulated SNARKs (indicates misconfiguration).
        // Without real-plonky2: warn only — batch was pre-verified by StarkVerifier.
        if let Some(ref snark) = record.snark_proof
            && snark.is_simulated()
        {
            #[cfg(all(
                not(any(test, feature = "test-utils")),
                feature = "real-plonky2"
            ))]
            return Err(BridgeError::InvalidProof {
                reason: "simulated SNARK rejected — real-plonky2 is enabled but SNARK is simulated".into(),
            });

            #[cfg(not(feature = "real-plonky2"))]
            tracing::warn!(
                "Batch SNARK is simulated (real-plonky2 not enabled). \
                 Proceeding based on StarkVerifier pre-verification."
            );
        }

        // Check withdrawal request height is within the batch's block range
        let withdrawal =
            self.withdrawals
                .get(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        let (batch_start, batch_end) = record.block_range;
        if withdrawal.request_height < batch_start || withdrawal.request_height > batch_end {
            return Err(BridgeError::InvalidProof {
                reason: format!(
                    "withdrawal at height {} is not within batch proof range [{}, {}]",
                    withdrawal.request_height, batch_start, batch_end
                ),
            });
        }

        // Re-verify the STARK proof for defense-in-depth
        self.verify_withdrawal_with_stark_proof(withdrawal_id, &record.proof)
    }

    /// Check if a withdrawal's challenge period has expired.
    pub fn is_challenge_period_expired(
        &self,
        withdrawal_id: &Hash256,
    ) -> Result<bool, BridgeError> {
        let withdrawal =
            self.withdrawals
                .get(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        // Use the challenge period that was locked at withdrawal request time,
        // not the current challenge_mode.
        //
        // Using the locked challenge period ensures mode transitions do not
        // retroactively alter in-flight withdrawal timelines.
        let l2_challenge_blocks = withdrawal.challenge_period_l2;
        Ok(self.l2_height
            >= withdrawal
                .request_height
                .saturating_add(l2_challenge_blocks))
    }

    /// Complete a withdrawal (after challenge period + STARK proof verification).
    ///
    /// Enforces challenge period expiration before completion.
    /// Requires `submitter` to be the original withdrawal requester
    /// or an active federation member.
    /// `submitter` is mandatory for access control enforcement.
    pub fn complete_withdrawal(
        &mut self,
        withdrawal_id: &Hash256,
        submitter: Option<Address>,
    ) -> Result<u64, BridgeError> {
        // Require a submitter identity for access control.
        let submitter_addr = submitter.ok_or(BridgeError::Unauthorized {
            reason: "submitter address is required to complete withdrawal".to_string(),
        })?;

        // Access control — only the requester or federation can complete
        {
            let withdrawal =
                self.withdrawals
                    .get(withdrawal_id)
                    .ok_or(BridgeError::WithdrawalNotFound {
                        tx_id: *withdrawal_id,
                    })?;

            let is_requester = submitter_addr == withdrawal.sender;
            let is_federation = self
                .federation
                .as_ref()
                .is_some_and(|f| f.is_active_member(&submitter_addr));
            if !is_requester && !is_federation {
                return Err(BridgeError::Unauthorized {
                    reason: "only the requester or federation can complete withdrawal".to_string(),
                });
            }
        }

        // Enforce challenge period has expired
        if !self.is_challenge_period_expired(withdrawal_id)? {
            return Err(BridgeError::InvalidProof {
                reason: "challenge period has not expired yet".to_string(),
            });
        }

        self.require_withdrawal_ready(withdrawal_id)?;

        // Delegate to unified completion path.
        self.finalize_withdrawal_internal(withdrawal_id, WithdrawalStatus::Completed)
    }

    // ══════════════════════════════════════════════════════════════════
    // Trustless Bridge Methods
    // ══════════════════════════════════════════════════════════════════

    /// Permissionless withdrawal: verify proof + check challenge period + complete.
    ///
    /// Anyone can call this with a valid STARK proof covering the withdrawal.
    /// If the proof is valid AND the challenge period has expired, the
    /// withdrawal completes atomically.
    ///
    /// This is the trustless path — no federation or operator required.
    pub fn permissionless_complete(
        &mut self,
        withdrawal_id: &Hash256,
        proof: &StarkProof,
        current_l2_height: u64,
    ) -> Result<u64, BridgeError> {
        // Step 1: Verify the STARK proof (if not already verified)
        {
            let withdrawal =
                self.withdrawals
                    .get(withdrawal_id)
                    .ok_or(BridgeError::WithdrawalNotFound {
                        tx_id: *withdrawal_id,
                    })?;

            if withdrawal.status == WithdrawalStatus::Completed {
                return Err(BridgeError::AlreadyClaimed {
                    tx_id: *withdrawal_id,
                });
            }

            if withdrawal.status != WithdrawalStatus::Ready {
                // Need to verify first — let the immutable borrow end
                let _ = withdrawal;
                self.verify_withdrawal_with_stark_proof(withdrawal_id, proof)?;
            }
        }

        // Step 2: Check challenge period
        // Use the per-withdrawal locked challenge period.
        // Use checked_add to prevent overflow.
        {
            let withdrawal =
                self.withdrawals
                    .get(withdrawal_id)
                    .ok_or(BridgeError::WithdrawalNotFound {
                        tx_id: *withdrawal_id,
                    })?;
            let challenge_deadline = withdrawal
                .request_height
                .checked_add(withdrawal.challenge_period_l2)
                .ok_or_else(|| BridgeError::InvalidProof {
                    reason: "challenge period deadline overflows u64".into(),
                })?;

            if current_l2_height < challenge_deadline {
                return Err(BridgeError::ChallengePeriodActive {
                    remaining_blocks: challenge_deadline.saturating_sub(current_l2_height),
                });
            }
        }

        // Step 3: Verify the withdrawal is in the correct state.
        self.require_withdrawal_ready(withdrawal_id)?;

        // Reject permissionless completion for operator-claimed withdrawals.
        // If an operator has claimed this withdrawal, only they or federation can complete it.
        if self
            .operator_manager
            .get_reimbursement(withdrawal_id)
            .is_some()
        {
            return Err(BridgeError::Unauthorized {
                reason: "withdrawal claimed by operator — use complete_withdrawal instead".into(),
            });
        }

        // Delegate to unified completion path.
        self.finalize_withdrawal_internal(withdrawal_id, WithdrawalStatus::Completed)
    }

    // ═══════════════════════════════════════════════════════════════════
    // PILLAR 3: Hybrid Cryptoeconomic ZK-Bridge
    // ═══════════════════════════════════════════════════════════════════
    //
    // The strongest withdrawal security model. Two conditions must BOTH
    // be satisfied — neither alone is sufficient:
    //
    //   Condition A: Valid STARK proof (mathematical correctness)
    //     - Proves the state transition is valid
    //     - Guarantees computational integrity
    //     - Cannot verify data availability alone
    //
    //   Condition B: ⅔ Committee attestation (economic security)
    //     - Proves data is available (committee members verified the data)
    //     - Provides economic guarantee (⅔ stake at risk)
    //     - Cannot verify computational correctness alone
    //
    //   Withdrawal = A ∧ B (AND, not OR)
    //
    // Security: Both a valid STARK proof and committee attestation are
    // required simultaneously (AND-conjunction).

    /// Set the staking committee for hybrid bridge mode.
    pub fn set_staking_committee(
        &mut self,
        committee: crate::federation::StakingCommittee,
    ) {
        self.staking_committee = Some(committee);
    }

    /// PILLAR 3: Complete a withdrawal in HybridCryptoeconomic mode.
    ///
    /// Requires TWO conditions, both mandatory (AND-conjunction):
    ///
    /// 1. **STARK Proof** (`proof`): Cryptographic proof that the L2 state
    ///    transition resulting in this withdrawal is computationally valid.
    ///    Verified by `StarkVerifier::verify()`.
    ///
    /// 2. **Committee Attestation** (`attestation`): Signatures from ≥ ⅔
    ///    of the staking committee's BTC weight, attesting that:
    ///    - The state root matches the STARK proof output
    ///    - The underlying block data is available
    ///    - The withdrawal batch is correctly formed
    ///
    /// The attestation's `state_root` MUST match the STARK proof's final
    /// state root. Any mismatch is evidence of committee fraud (invalid
    /// state attestation → 100% slash + EOTS key extraction).
    ///
    /// Returns the payout amount on success.
    pub fn hybrid_complete_withdrawal(
        &mut self,
        withdrawal_id: &Hash256,
        proof: &StarkProof,
        attestation: &crate::federation::CommitteeAttestation,
        current_l2_height: u64,
    ) -> Result<u64, BridgeError> {
        // ── Gate 0: Bridge must be in HybridCryptoeconomic mode ──
        if self.challenge_mode != ChallengeMode::HybridCryptoeconomic {
            return Err(BridgeError::InvalidProof {
                reason: "hybrid_complete_withdrawal requires HybridCryptoeconomic mode".into(),
            });
        }

        // ── Gate 1: Withdrawal exists and is in a valid state ──
        let withdrawal = self
            .withdrawals
            .get(withdrawal_id)
            .ok_or(BridgeError::WithdrawalNotFound {
                tx_id: *withdrawal_id,
            })?;

        if withdrawal.status == WithdrawalStatus::Completed {
            return Err(BridgeError::AlreadyClaimed {
                tx_id: *withdrawal_id,
            });
        }

        if withdrawal.status.is_terminal() {
            return Err(BridgeError::InvalidProof {
                reason: format!(
                    "withdrawal {} is in terminal state {:?}",
                    withdrawal_id, withdrawal.status,
                ),
            });
        }

        // ── Condition A: STARK Proof Verification ──
        //
        // Mathematical guarantee: the state transition is computationally valid.
        // This is the cryptographic anchor — no economic assumption needed.
        //
        // The hybrid path MUST apply the same committed state
        // root validation as the STARK-only path. STARK verification is conditional
        // (skip if already done), but root binding always runs.

        // STARK verification: only run if not already verified
        if !withdrawal.is_verified {
            StarkVerifier::verify(proof).map_err(|_| BridgeError::InvalidProof {
                reason: "STARK proof verification failed (Condition A)".into(),
            })?;
        }

        // Root binding: ALWAYS validate, even when is_verified is true.
        // This prevents stale verified_at_height from a different code path.
        // Fix
        let final_root_height = self.validate_proof_state_roots(proof, "hybrid")?;

        // Mark as verified + bind to FINAL state root height
        {
            let withdrawal = self
                .withdrawals
                .get_mut(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;
            withdrawal.is_verified = true;
            withdrawal.verified_at_height = final_root_height;
            withdrawal.status = WithdrawalStatus::Ready;
        }

        // ── Condition B: Committee Attestation Verification ──
        //
        // Economic guarantee: ≥ ⅔ of staked BTC weight attests to:
        //   1. Data availability (they have seen the data)
        //   2. State root correctness (matches STARK proof)
        //   3. Withdrawal batch validity
        let committee = self
            .staking_committee
            .as_ref()
            .ok_or(BridgeError::InvalidProof {
                reason: "staking committee not configured".into(),
            })?;

        // Verify attestation meets ⅔ threshold
        committee
            .verify_attestation(attestation)
            .map_err(|e| BridgeError::InvalidProof {
                reason: format!("committee attestation failed (Condition B): {e}"),
            })?;

        // ── Cross-condition binding: state root consistency (MANDATORY) ──
        //
        // The attestation's state_root MUST match the STARK
        // proof's committed state root. This is a mandatory AND-conjunction,
        // not an optional check. Both conditions must agree on the same state.
        //
        // Both MUST be present and consistent — no silent fallthrough.
        let withdrawal = self
            .withdrawals
            .get(withdrawal_id)
            .ok_or(BridgeError::WithdrawalNotFound {
                tx_id: *withdrawal_id,
            })?;

        // verified_at_height MUST be set by Condition A above.
        let verified_height = withdrawal.verified_at_height.ok_or_else(|| {
            BridgeError::InvalidProof {
                reason: "hybrid path: withdrawal has no verified_at_height — \
                         STARK proof did not bind to a committed state root"
                    .to_string(),
            }
        })?;

        // The committed root at that height MUST exist.
        let committed_root =
            self.committed_state_roots
                .get(&verified_height)
                .ok_or_else(|| BridgeError::InvalidProof {
                    reason: format!(
                        "hybrid path: no committed state root at height {} — \
                         state root store is inconsistent",
                        verified_height,
                    ),
                })?;

        // The attestation's state_root MUST match the committed root.
        // A mismatch is evidence of committee fraud (invalid state attestation).
        if attestation.state_root != *committed_root {
            return Err(BridgeError::InvalidProof {
                reason: format!(
                    "committee attestation state_root ({}) does not match \
                     committed state_root ({}) at height {} — \
                     potential invalid state attestation (EOTS extractable)",
                    attestation.state_root, committed_root, verified_height,
                ),
            });
        }

        // ── Gate 2: Challenge period expired ──
        let challenge_blocks = withdrawal.challenge_period_l2;
        let challenge_deadline = withdrawal
            .request_height
            .checked_add(challenge_blocks)
            .ok_or_else(|| BridgeError::InvalidProof {
                reason: "challenge period deadline overflows u64".into(),
            })?;

        if current_l2_height < challenge_deadline {
            return Err(BridgeError::ChallengePeriodActive {
                remaining_blocks: challenge_deadline.saturating_sub(current_l2_height),
            });
        }

        // ── Both conditions met: finalize withdrawal ──
        self.finalize_withdrawal_internal(withdrawal_id, WithdrawalStatus::Completed)
    }

    /// Verify that a withdrawal is eligible for hybrid completion.
    ///
    /// Returns `Ok(true)` if both conditions (STARK + attestation) can
    /// potentially be met, `Ok(false)` if missing prerequisites.
    pub fn can_hybrid_complete(
        &self,
        withdrawal_id: &Hash256,
    ) -> Result<bool, BridgeError> {
        let withdrawal = self
            .withdrawals
            .get(withdrawal_id)
            .ok_or(BridgeError::WithdrawalNotFound {
                tx_id: *withdrawal_id,
            })?;

        if withdrawal.status.is_terminal() {
            return Ok(false);
        }

        // Check STARK verification status
        let stark_ok = withdrawal.is_verified;

        // Check committee availability
        let committee_ok = self
            .staking_committee
            .as_ref()
            .is_some_and(|c| c.is_operational());

        Ok(stark_ok && committee_ok)
    }

    /// Submit a challenge against a withdrawal or anchor.
    ///
    /// Requires a challenge bond (minimum CHALLENGE_BOND satoshis).
    /// Bond is returned if fraud is proven; forfeited if challenge is dismissed.
    pub fn submit_challenge(
        &mut self,
        challenger: Address,
        challenge_type: ChallengeType,
        bond: u64,
    ) -> Result<Hash256, BridgeError> {
        self.challenge_manager
            .submit_challenge(challenger, challenge_type, self.l2_height, bond)
    }

    /// Resolve an InvalidStateRoot challenge that has been proven (fraud confirmed).
    ///
    /// This is called from two paths:
    /// 1. `tick_challenges()` — when the operator didn't respond and the challenge expired
    /// 2. `respond_to_challenge()` — when the operator responded but fraud was confirmed
    ///
    /// Effects:
    /// - Removes the fraudulent state root from `committed_state_roots`
    /// - Freezes all withdrawals that were verified against that root
    /// - Slashes the sequencer via operator_manager
    fn resolve_invalid_state_root(&mut self, l2_height: u64, challenge_id: &Hash256) {
        // 1. Remove the fraudulent state root
        let removed = self.committed_state_roots.remove(&l2_height);
        if removed.is_some() {
            tracing::warn!(
                l2_height,
                ?challenge_id,
                "Removed fraudulent state root at height {}",
                l2_height,
            );
        }

        // Allow re-committing a corrected root at this height.
        // If the removed height was the last committed, roll back the guard.
        if self.last_committed_height == l2_height {
            // Find the highest remaining committed height, or 0 if none left.
            self.last_committed_height = self
                .committed_state_roots
                .iter()
                .map(|(h, _)| *h)
                .max()
                .unwrap_or(0);
            tracing::info!(
                new_last = self.last_committed_height,
                "Rolled back last_committed_height after removing fraudulent root",
            );
        }

        // 2. Freeze withdrawals that were verified against this root.
        // Skip terminal states (Completed, Challenged, ForceExited)
        // and Executing (BTC already in flight on L1 — freezing is moot).
        let to_freeze: Vec<Hash256> = self
            .withdrawals
            .iter()
            .filter(|(_, w)| {
                w.verified_at_height == Some(l2_height)
                    && !w.status.is_terminal()
                    && w.status != WithdrawalStatus::Executing
            })
            .map(|(id, _)| *id)
            .collect();

        for wid in &to_freeze {
            if let Some(w) = self.withdrawals.get_mut(wid) {
                w.status = WithdrawalStatus::Frozen;
                tracing::warn!(
                    ?wid,
                    l2_height,
                    "Withdrawal frozen: verified against invalidated state root",
                );
            }
        }
        if !to_freeze.is_empty() {
            tracing::warn!(
                count = to_freeze.len(),
                l2_height,
                "Froze {} withdrawal(s) due to InvalidStateRoot",
                to_freeze.len(),
            );
        }

        // Slash operators who claimed withdrawals verified against the
        // fraudulent root. `slash_operator` expects a withdrawal_id, NOT a
        // challenge_id. Collect all affected claimed withdrawal IDs.
        let affected_withdrawal_ids: Vec<Hash256> = self
            .withdrawals
            .iter()
            .filter(|(_, w)| w.verified_at_height == Some(l2_height))
            .map(|(id, _)| *id)
            .collect();

        let mut slashed_any = false;
        for wid in &affected_withdrawal_ids {
            // Only slash if there's a reimbursement for this withdrawal
            if self.operator_manager.has_reimbursement(wid) {
                if let Err(e) = self.operator_manager.slash_operator(wid) {
                    tracing::error!(
                        ?wid,
                        ?challenge_id,
                        %e,
                        "Failed to slash operator reimbursement for InvalidStateRoot",
                    );
                } else {
                    slashed_any = true;
                }
            }
        }
        if !slashed_any && !affected_withdrawal_ids.is_empty() {
            tracing::warn!(
                ?challenge_id,
                l2_height,
                "No operator reimbursements found to slash for InvalidStateRoot at height {}",
                l2_height,
            );
        }
    }

    /// Unfreeze a frozen withdrawal so the user can re-verify
    /// against a valid state root. Resets `verified_at_height` and `is_verified`.
    pub fn unfreeze_withdrawal(
        &mut self,
        withdrawal_id: &Hash256,
    ) -> Result<WithdrawalStatus, BridgeError> {
        let withdrawal =
            self.withdrawals
                .get_mut(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        if withdrawal.status != WithdrawalStatus::Frozen {
            return Err(BridgeError::InvalidStatusTransition {
                from: format!("{:?}", withdrawal.status),
                to: "Pending".to_string(),
            });
        }

        withdrawal.status = WithdrawalStatus::Pending;
        withdrawal.is_verified = false;
        withdrawal.verified_at_height = None;
        tracing::info!(
            ?withdrawal_id,
            "Withdrawal unfrozen — user can re-submit STARK proof against a valid state root",
        );
        Ok(withdrawal.status)
    }

    /// Process expired challenges (call periodically).
    ///
    /// Returns `(expired_ids, slash_failures)`:
    /// - `expired_ids`: IDs of newly expired challenges.
    /// - `slash_failures`: `(challenge_id, error)` pairs for slashes that failed.
    ///
    /// Slash failures are returned so callers can detect and handle them
    /// (e.g., retry, alert, or escalate to federation).
    pub fn tick_challenges(&mut self) -> (Vec<Hash256>, Vec<(Hash256, BridgeError)>) {
        // Check federation sunset on every tick (not just during deposits).
        // This ensures sunset fires even if no deposits occur after the sunset height.
        self.check_federation_sunset();

        let expired = self
            .challenge_manager
            .process_expired_challenges(self.l2_height);

        let mut slash_failures: Vec<(Hash256, BridgeError)> = Vec::new();
        for challenge_id in &expired {
            if let Some(challenge) = self.challenge_manager.get_challenge(challenge_id) {
                match &challenge.challenge_type {
                    // Expired InvalidWithdrawalProof: slash the operator
                    ChallengeType::InvalidWithdrawalProof { withdrawal_id, .. } => {
                        if let Err(e) = self.operator_manager.slash_operator(withdrawal_id) {
                            tracing::error!(
                                ?challenge_id,
                                %e,
                                "Failed to slash operator for expired challenge",
                            );
                            slash_failures.push((*challenge_id, e));
                        }
                    }
                    // Expired InvalidStateRoot: operator didn't respond → assumed guilty
                    ChallengeType::InvalidStateRoot { l2_height, .. } => {
                        let h = *l2_height;
                        self.resolve_invalid_state_root(h, challenge_id);
                    }
                    // Expired InvalidSnarkWrapping -- operator didn't respond,
                    // assumed guilty. Slash all reimbursements in the affected height range.
                    ChallengeType::InvalidSnarkWrapping {
                        l2_height_start,
                        l2_height_end,
                        ..
                    } => {
                        self.slash_operators_in_height_range(
                            *l2_height_start,
                            *l2_height_end,
                            challenge_id,
                            &mut slash_failures,
                        );
                    }
                }
            }
        }

        (expired, slash_failures)
    }

    /// Operator responds to a challenge with a STARK proof.
    ///
    /// Delegates to `ChallengeManager::respond_to_challenge()`. If the response
    /// proves fraud (returns `ChallengeStatus::Proven`), automatically triggers
    /// resolution effects (state root removal, withdrawal freezing, slashing).
    pub fn respond_to_challenge(
        &mut self,
        challenge_id: &Hash256,
        response: ChallengeResponse,
        proof: &StarkProof,
    ) -> Result<ChallengeStatus, BridgeError> {
        // Only registered operators can respond to challenges.
        if !self
            .operator_manager
            .is_registered_operator(&response.responder)
        {
            return Err(BridgeError::OperatorNotRegistered);
        }

        let status =
            self.challenge_manager
                .respond_to_challenge(challenge_id, response, proof)?;

        // If fraud was proven, trigger resolution immediately
        if status == ChallengeStatus::Proven {
            if let Some(ch) = self.challenge_manager.get_challenge(challenge_id) {
                match &ch.challenge_type {
                    ChallengeType::InvalidStateRoot { l2_height, .. } => {
                        self.resolve_invalid_state_root(*l2_height, challenge_id);
                    }
                    // Slash operator for proven InvalidWithdrawalProof
                    ChallengeType::InvalidWithdrawalProof { withdrawal_id, .. } => {
                        let wid = *withdrawal_id;
                        if let Err(e) = self.operator_manager.slash_operator(&wid) {
                            tracing::error!(?challenge_id, ?wid, %e,
                                "Failed to slash operator for proven InvalidWithdrawalProof");
                        }
                    }
                    // Slash for proven InvalidSnarkWrapping
                    ChallengeType::InvalidSnarkWrapping {
                        l2_height_start,
                        l2_height_end,
                        ..
                    } => {
                        let mut discard = Vec::new();
                        self.slash_operators_in_height_range(
                            *l2_height_start,
                            *l2_height_end,
                            challenge_id,
                            &mut discard,
                        );
                    }
                }
            }
        }

        Ok(status)
    }

    /// Operator claims a withdrawal to front BTC to the user.
    ///
    /// In BitVM2 mode, the operator MUST have a posted bond. This ensures
    /// economic accountability: if the operator fronts BTC for a fraudulent
    /// withdrawal, the bond can be slashed through the challenge protocol.
    ///
    /// Delegates to `OperatorManager::claim_withdrawal()` after the bond check.
    pub fn claim_withdrawal(
        &mut self,
        operator: Address,
        withdrawal_id: Hash256,
        amount: u64,
        current_height: u64,
    ) -> Result<(), BridgeError> {
        // In BitVM2 mode, require the operator to have a bond.
        if self.challenge_mode == ChallengeMode::BitVM2 {
            let op = self
                .operator_manager
                .get_operator(&operator)
                .ok_or(BridgeError::OperatorNotFound { address: operator })?;
            if !op.has_bitvm2_bond() {
                return Err(BridgeError::OperatorMissingBond { address: operator });
            }
            // Require on-chain bond verification before claiming.
            // Without this, an operator could register a fake bond UTXO and
            // front withdrawals without economic skin-in-the-game.
            if !op.bond_verified_onchain {
                return Err(BridgeError::Unauthorized {
                    reason: "operator bond UTXO not verified on-chain — \
                             call verify_operator_bond_onchain() first"
                        .to_string(),
                });
            }
            // Verify total bond covers the withdrawal amount.
            // The operator's total bond must be at least equal to the withdrawal amount
            // to ensure slashing is economically meaningful.
            let total_bond = op.total_bond_amount();
            if total_bond < amount {
                return Err(BridgeError::InvalidAmount {
                    reason: format!(
                        "operator total bond {} sat insufficient for withdrawal {} sat",
                        total_bond, amount
                    ),
                });
            }
        }

        let challenge_period = self.challenge_period_l2_blocks();
        self.operator_manager.claim_withdrawal(
            operator,
            withdrawal_id,
            amount,
            current_height,
            challenge_period,
        )
    }

    /// Store a batch proof in the proof store.
    ///
    /// Returns the STARK proof hash on success.
    pub fn store_batch_proof(&mut self, record: &BatchProofRecord) -> Result<Hash256, String> {
        self.proof_store.store_proof(record)
    }

    /// Activate BitVM2 mode — transition from federated to trustless bridge.
    ///
    /// ## Challenge Mode Transition
    ///
    /// Requires at least 3 registered operators for security. The BitVM2
    /// dispute game needs multiple independent operators to ensure liveness.
    ///
    /// In-flight withdrawals keep their original challenge period (federated 24h).
    /// Only new withdrawals use the BitVM2 2-week challenge period.
    ///
    /// Returns `Err` if:
    /// - Already in BitVM2 mode (idempotency guard)
    /// - Fewer than 3 operators registered
    pub fn activate_bitvm2_mode(&mut self) -> Result<(), BridgeError> {
        if self.challenge_mode == ChallengeMode::BitVM2 {
            // Already in BitVM2 mode — no-op success
            return Ok(());
        }

        const MIN_OPERATORS_FOR_BITVM2: usize = 3;
        let operator_count = self.operator_manager.operator_count();
        if operator_count < MIN_OPERATORS_FOR_BITVM2 {
            return Err(BridgeError::InsufficientOperators {
                required: MIN_OPERATORS_FOR_BITVM2,
                actual: operator_count,
            });
        }

        // Switch mode. In-flight withdrawals are unaffected because each
        // withdrawal's challenge period is locked at request time via
        // `challenge_period_l2`. Only new withdrawals created
        // after this point will use the BitVM2 challenge period.
        self.challenge_mode = ChallengeMode::BitVM2;

        Ok(())
    }

    /// Get the active challenge period in L2 blocks based on current mode.
    pub fn challenge_period_l2_blocks(&self) -> u64 {
        match self.challenge_mode {
            ChallengeMode::Federated => CHALLENGE_PERIOD_BLOCKS * L1_TO_L2_BLOCK_RATIO,
            ChallengeMode::BitVM2 => BITVM2_CHALLENGE_PERIOD_BLOCKS * L1_TO_L2_BLOCK_RATIO,
            ChallengeMode::ZkValidity => self.zk_validity_challenge_l2,
            // Hybrid uses the ZK Validity challenge period since STARK proof is mandatory.
            ChallengeMode::HybridCryptoeconomic => self.zk_validity_challenge_l2,
        }
    }

    /// Activate ZK Validity mode with a configurable challenge period.
    ///
    /// In this mode, withdrawals with a valid STARK proof can complete after
    /// `challenge_l2_blocks` L2 blocks (0 = instant). Security relies on
    /// `StarkVerifier::verify()` — the STARK proof IS the trust anchor.
    ///
    /// Recommended values:
    ///   - Testnet: 0 (instant)
    ///   - Mainnet beta: 1200 (~1 hour at 3s/block)
    ///   - Mainnet: 0 (full ZK Validity)
    pub fn activate_zk_validity_mode(&mut self, challenge_l2_blocks: u64) {
        if challenge_l2_blocks == 0 {
            if let Ok(network) = std::env::var("BRRQ_NETWORK") {
                if network.eq_ignore_ascii_case("mainnet") {
                    tracing::warn!(
                        "ZkValidity with zero challenge period on mainnet. \
                         Recommended: use challenge_l2_blocks >= 1200 (~1 hour)."
                    );
                }
            }
        }
        self.challenge_mode = ChallengeMode::ZkValidity;
        self.zk_validity_challenge_l2 = challenge_l2_blocks;
    }

    // ══════════════════════════════════════════════════════════════════
    // Federation Management
    // ══════════════════════════════════════════════════════════════════

    /// Initialize the federation with a set of members and threshold.
    ///
    /// Must be called once during bridge setup. Once initialized,
    /// withdrawals require federation quorum approval in federated mode.
    pub fn init_federation(
        &mut self,
        members: Vec<(Address, String)>,
        threshold: usize,
        genesis_height: u64,
    ) -> Result<(), FederationError> {
        let fed = FederationManager::new(members, threshold, genesis_height)?;
        self.federation = Some(fed);
        Ok(())
    }

    /// Propose a withdrawal approval. Returns the proposal ID.
    ///
    /// A federation member proposes that a verified withdrawal should be
    /// executed on L1. Requires `threshold` approvals before execution.
    pub fn propose_withdrawal_approval(
        &mut self,
        proposer: Address,
        withdrawal_id: Hash256,
    ) -> Result<Hash256, BridgeError> {
        let fed = self.federation.as_mut().ok_or(BridgeError::InvalidAmount {
            reason: "federation not initialized".into(),
        })?;

        // Withdrawal must exist and be verified
        let withdrawal =
            self.withdrawals
                .get(&withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: withdrawal_id,
                })?;

        if withdrawal.status != WithdrawalStatus::Ready {
            return Err(BridgeError::InvalidProof {
                reason: "withdrawal must be verified before federation approval".into(),
            });
        }

        fed.create_proposal(
            proposer,
            ProposalAction::ApproveWithdrawal { withdrawal_id },
            self.l2_height,
        )
        .map_err(|e| BridgeError::InvalidChallengeEvidence {
            reason: e.to_string(),
        })
    }

    /// Approve a federation proposal. Returns true if quorum reached.
    ///
    /// When quorum is reached for an `ApproveWithdrawal` proposal,
    /// the proposal is automatically executed and the withdrawal status is
    /// updated to `Completed`. This ensures federation voting actually gates
    /// withdrawal execution rather than being a disconnected ceremony.
    pub fn approve_federation_proposal(
        &mut self,
        proposal_id: &Hash256,
        approver: Address,
    ) -> Result<bool, BridgeError> {
        let fed = self.federation.as_mut().ok_or(BridgeError::InvalidAmount {
            reason: "federation not initialized".into(),
        })?;

        let quorum_reached = fed
            .approve_proposal(proposal_id, approver, self.l2_height)
            .map_err(|e| BridgeError::InvalidChallengeEvidence {
                reason: e.to_string(),
            })?;

        // When quorum is reached, execute the proposal
        if quorum_reached {
            let fed = self.federation.as_mut().ok_or(BridgeError::Unauthorized {
                reason: "federation not initialized".into(),
            })?;
            let action = fed
                .execute_proposal(proposal_id, self.l2_height)
                .map_err(|e| BridgeError::InvalidChallengeEvidence {
                    reason: e.to_string(),
                })?;

            // Execute the proposal action.
            // Update both total_locked and total_minted atomically.
            // Also handle ResumeBridge to unpause the bridge.
            match action {
                ProposalAction::ApproveWithdrawal { withdrawal_id } => {
                    if let Some(w) = self.withdrawals.get(&withdrawal_id) {
                        if w.status == WithdrawalStatus::Ready {
                            // Verify challenge period has expired before completing.
                            // Use the per-withdrawal locked challenge period.
                            let challenge_expired = self.l2_height
                                >= w.request_height.saturating_add(w.challenge_period_l2);
                            if !challenge_expired {
                                // Don't complete yet — challenge period still active.
                                // The proposal is executed (won't be re-proposed) but
                                // the withdrawal remains Ready for later completion.
                                return Ok(quorum_reached);
                            }

                            // Delegate to unified completion path.
                            // Errors here are non-fatal — the proposal executed but
                            // completion failed (e.g., accounting underflow). Log it.
                            if let Err(e) = self.finalize_withdrawal_internal(
                                &withdrawal_id,
                                WithdrawalStatus::Completed,
                            ) {
                                tracing::error!(
                                    ?withdrawal_id,
                                    %e,
                                    "Federation completion failed",
                                );
                            }
                        }
                    }
                }
                ProposalAction::ResumeBridge => {
                    self.paused = false;
                }
                // Other proposal actions (AddMember, RemoveMember, ChangeThreshold)
                // are handled internally by the federation manager's execute_proposal.
                _ => {}
            }
        }

        Ok(quorum_reached)
    }

    /// Require federation authorization for pause.
    pub fn emergency_pause(&mut self, member: &Address) -> Result<(), BridgeError> {
        match self.federation {
            Some(ref fed) => {
                if !fed.authorize_emergency_pause(member) {
                    return Err(BridgeError::Unauthorized {
                        reason: "only active federation members can pause the bridge".into(),
                    });
                }
            }
            None => {
                return Err(BridgeError::Unauthorized {
                    reason: "bridge has no federation configured; pause requires federation".into(),
                });
            }
        }
        self.paused = true;
        Ok(())
    }

    /// Remove finalized deposits older than a retention period.
    ///
    /// Prevents unbounded memory growth. Deposits that have been Confirmed
    /// and processed more than `retention_blocks` L2 blocks ago are safe to
    /// remove since they have already been credited on L2.
    ///
    /// Uses L1 confirmation height estimate to correctly compare against
    /// the current L1 height with a retention window.
    ///
    /// Should be called periodically (e.g., once per epoch or every N blocks).
    /// Returns the number of pruned deposits.
    pub fn prune_finalized_deposits(&mut self, retention_l1_blocks: u64) -> usize {
        let current_l1 = self.l1_height;
        let to_remove: Vec<(Hash256, u32)> = self
            .deposits
            .iter()
            .filter(|(_, d)| {
                if d.status != DepositStatus::Finalized {
                    return false; // Keep non-finalized deposits (Pending/Confirmed)
                }
                // Use the SPV proof block_height (the actual L1
                // block containing the deposit tx) when available. When absent,
                // fall back to the estimated confirmation height. A finalized
                // deposit is safe to prune when the L1 chain has advanced
                // retention_l1_blocks past its inclusion block.
                let inclusion_l1 = d
                    .spv_proof
                    .as_ref()
                    .map(|p| p.block_height)
                    .unwrap_or_else(|| current_l1.saturating_sub(d.confirmations as u64));
                current_l1.saturating_sub(inclusion_l1) > retention_l1_blocks
            })
            .map(|(key, _)| *key)
            .collect();
        let count = to_remove.len();
        for key in to_remove {
            self.deposits.remove(&key);
        }
        count
    }

    /// Get bridge status summary.
    pub fn status(&self) -> BridgeStatus {
        BridgeStatus {
            total_locked: self.total_locked,
            total_minted: self.total_minted,
            pending_deposits: self
                .deposits
                .values()
                .filter(|d| d.status == DepositStatus::Pending)
                .count(),
            pending_withdrawals: self
                .withdrawals
                .values()
                .filter(|w| w.status == WithdrawalStatus::Pending)
                .count(),
            paused: self.paused,
            challenge_mode: self.challenge_mode,
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Force Exit
    // ═══════════════════════════════════════════════════════════════

    /// Force-exit a withdrawal when no operator processes it.
    ///
    /// If a withdrawal has been pending for longer than `FORCE_EXIT_TIMEOUT`
    /// blocks without any operator fronting BTC, the user can trigger a
    /// direct exit via the BitVM2 escape hatch. This prevents operator
    /// censorship from trapping user funds.
    ///
    /// Force exit requires the withdrawal to be STARK-verified (`is_verified
    /// == true` / status `Ready`) to ensure valid state transitions.
    ///
    /// Returns the payout amount on success.
    pub fn force_exit(
        &mut self,
        withdrawal_id: &Hash256,
        current_l2_height: u64,
    ) -> Result<u64, BridgeError> {
        let withdrawal =
            self.withdrawals
                .get(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        // Only pending/ready withdrawals can be force-exited
        if withdrawal.status != WithdrawalStatus::Pending
            && withdrawal.status != WithdrawalStatus::Ready
        {
            return Err(BridgeError::InvalidProof {
                reason: format!(
                    "withdrawal {} cannot be force-exited: status is {:?}",
                    withdrawal_id, withdrawal.status,
                ),
            });
        }

        // Require STARK proof verification before force exit.
        if !withdrawal.is_verified {
            return Err(BridgeError::InvalidProof {
                reason: "force exit requires STARK-verified withdrawal"
                    .into(),
            });
        }

        // Check timeout has elapsed
        let deadline = withdrawal.request_height.saturating_add(FORCE_EXIT_TIMEOUT);
        if current_l2_height < deadline {
            return Err(BridgeError::ChallengePeriodActive {
                remaining_blocks: deadline.saturating_sub(current_l2_height),
            });
        }

        // Delegate to unified completion path with ForceExited status.
        self.finalize_withdrawal_internal(withdrawal_id, WithdrawalStatus::ForceExited)
    }

    // ═══════════════════════════════════════════════════════════════
    // Emergency Exit
    // ═══════════════════════════════════════════════════════════════

    /// Initiate an emergency exit when the bridge is unresponsive.
    ///
    /// Creates a pre-signed Bitcoin transaction with a timelock that allows
    /// the user to unilaterally withdraw their funds if the bridge operators
    /// fail to process their withdrawal.
    ///
    /// This is the last resort mechanism — uses a longer timelock than
    /// force_exit to give operators every chance to resume service.
    pub fn initiate_emergency_exit(
        &mut self,
        withdrawal_id: &Hash256,
        current_l2_height: u64,
    ) -> Result<EmergencyExitPath, BridgeError> {
        let withdrawal =
            self.withdrawals
                .get(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        match withdrawal.status {
            WithdrawalStatus::Completed
            | WithdrawalStatus::ForceExited
            | WithdrawalStatus::Challenged => {
                return Err(BridgeError::AlreadyClaimed {
                    tx_id: *withdrawal_id,
                });
            }
            _ => {}
        }

        // Require STARK proof verification before emergency exit.
        if !withdrawal.is_verified {
            return Err(BridgeError::InvalidProof {
                reason: "emergency exit requires STARK-verified withdrawal \
                         (prevents proof system bypass via emergency path)"
                    .into(),
            });
        }

        // Emergency exit uses 2x the force exit timeout
        let emergency_deadline = withdrawal
            .request_height
            .saturating_add(FORCE_EXIT_TIMEOUT.saturating_mul(2));

        let payout =
            withdrawal
                .amount
                .checked_sub(withdrawal.fee)
                .ok_or(BridgeError::InvalidAmount {
                    reason: format!(
                        "fee ({}) exceeds withdrawal amount ({})",
                        withdrawal.fee, withdrawal.amount,
                    ),
                })?;

        // Create the emergency exit script commitment
        let script_hash = {
            let mut hasher = Hasher::new();
            hasher.update(brrq_crypto::domain_tags::EMERGENCY_EXIT_V1);
            hasher.update(withdrawal_id.as_bytes());
            hasher.update(&payout.to_le_bytes());
            hasher.update(&emergency_deadline.to_le_bytes());
            hasher.finalize()
        };

        let status = if current_l2_height >= emergency_deadline {
            EmergencyExitStatus::Claimable
        } else {
            EmergencyExitStatus::Initiated
        };

        // Do NOT finalize immediately. The old code called
        // finalize_withdrawal_internal here, which debited accounting before
        // the BTC timelock expired on L1. Instead, record the emergency exit
        // and require a separate `claim_emergency_exit` call after the
        // timelock deadline has passed.
        let exit_path = EmergencyExitPath {
            withdrawal_id: *withdrawal_id,
            payout_amount: payout,
            timelock_height: emergency_deadline,
            script_hash,
            status,
        };

        self.emergency_exits
            .insert(*withdrawal_id, exit_path.clone());

        Ok(exit_path)
    }

    /// Claim a previously initiated emergency exit after the
    /// timelock has expired.
    ///
    /// Claim step of the two-phase emergency exit flow:
    /// 1. `initiate_emergency_exit` — records the exit, no accounting change.
    /// 2. `claim_emergency_exit` — verifies timelock expired, then finalizes
    ///    the withdrawal and debits accounting.
    ///
    /// Returns the payout amount on success.
    pub fn claim_emergency_exit(
        &mut self,
        withdrawal_id: &Hash256,
        current_l2_height: u64,
    ) -> Result<u64, BridgeError> {
        let exit =
            self.emergency_exits
                .get(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        if current_l2_height < exit.timelock_height {
            return Err(BridgeError::InvalidAmount {
                reason: format!(
                    "emergency exit timelock not expired: current {} < deadline {}",
                    current_l2_height, exit.timelock_height,
                ),
            });
        }

        let payout = exit.payout_amount;

        // Finalize the withdrawal — debits accounting atomically.
        self.finalize_withdrawal_internal(withdrawal_id, WithdrawalStatus::ForceExited)?;

        // Remove the emergency exit record now that it's been claimed.
        if let Some(e) = self.emergency_exits.get_mut(withdrawal_id) {
            e.status = EmergencyExitStatus::Claimed;
        }

        Ok(payout)
    }
}

/// Emergency exit path information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyExitPath {
    /// The withdrawal this exit path corresponds to.
    pub withdrawal_id: Hash256,
    /// BTC amount to be released (after fees).
    pub payout_amount: u64,
    /// L2 block height at which the timelock expires.
    pub timelock_height: u64,
    /// Hash of the exit script for Bitcoin transaction construction.
    pub script_hash: Hash256,
    /// Current status of the emergency exit.
    pub status: EmergencyExitStatus,
}

impl Default for BridgeManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Bridge status summary.
#[derive(Debug, Clone)]
pub struct BridgeStatus {
    pub total_locked: u64,
    pub total_minted: u64,
    pub pending_deposits: usize,
    pub pending_withdrawals: usize,
    pub paused: bool,
    /// Current challenge mode (Federated/BitVM2).
    pub challenge_mode: ChallengeMode,
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_prover::batch::prove_batch;
    use brrq_prover::prover::StarkProver;

    /// Helper: setup a test bridge with a mock federation to bypass strictly-enforced SPV checks.
    fn setup_test_bridge() -> BridgeManager {
        let mut bridge = BridgeManager::new();
        // Use lenient rate limits for tests to avoid interfering with
        // existing test patterns that submit many ops from one address.
        bridge.rate_limiter = BridgeRateLimiter::with_limits(1000, 1000, 100);
        let mut members: Vec<(Address, String)> = (1..=5u8)
            .map(|i| (Address::from_bytes([i; 20]), format!("m{i}")))
            .collect();
        members.push((Address::from_bytes([9u8; 20]), "dummy".into()));
        bridge.init_federation(members, 3, 0).unwrap();
        bridge
    }

    /// The initial state root used by test STARK proofs.
    const TEST_INITIAL_STATE_ROOT: [u8; 32] = [0x01; 32];

    /// The final state root used by test STARK proofs.
    const TEST_FINAL_STATE_ROOT: [u8; 32] = [0x02; 32];

    /// Helper: generate a real verified STARK proof.
    fn make_verified_proof() -> StarkProof {
        let prover = StarkProver::new();
        let initial = Hash256::from_bytes(TEST_INITIAL_STATE_ROOT);
        let final_root = Hash256::from_bytes(TEST_FINAL_STATE_ROOT);
        let record = prove_batch(&prover, initial, final_root, (1, 4), 10, 5000).unwrap();
        assert!(record.verified);
        record.proof
    }

    /// Helper: commit both the initial and final test STARK proof state roots to a bridge.
    ///
    /// The final_state_root must also be committed, so we commit both
    /// at different heights to satisfy both the initial root (Step 4) and final root
    /// (Step 5) cross-reference checks.
    fn commit_test_state_root(bridge: &mut BridgeManager) {
        bridge.commit_state_root(1, Hash256::from_bytes(TEST_INITIAL_STATE_ROOT));
        bridge.commit_state_root(4, Hash256::from_bytes(TEST_FINAL_STATE_ROOT));
    }

    #[test]
    fn test_deposit_confirmed() {
        let mut bridge = setup_test_bridge();
        let tx_id = Hash256::ZERO;
        let minted = bridge
            .process_deposit(
                tx_id,
                0,
                1_000_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        // 0.05% fee: 1_000_000 * 5 / 10_000 = 500
        assert_eq!(minted, 999_500);
        assert_eq!(bridge.total_locked, 1_000_000);
        assert_eq!(bridge.total_minted, 999_500);
    }

    #[test]
    fn test_deposit_pending() {
        let mut bridge = setup_test_bridge();
        let tx_id = Hash256::ZERO;
        let _minted = bridge
            .process_deposit(
                tx_id,
                0,
                1_000_000,
                Address::ZERO,
                2,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        let deposit = bridge.deposits.get(&(tx_id, 0)).unwrap();
        assert_eq!(deposit.status, DepositStatus::Pending);
        assert_eq!(bridge.total_locked, 0); // Not confirmed yet
    }

    #[test]
    fn test_deposit_confirmation_update() {
        let mut bridge = setup_test_bridge();
        let tx_id = Hash256::ZERO;
        bridge
            .process_deposit(
                tx_id,
                0,
                1_000_000,
                Address::ZERO,
                2,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        let status = bridge.update_deposit_confirmations(&tx_id, 0, 6).unwrap();
        assert_eq!(status, DepositStatus::Confirmed);
        assert_eq!(bridge.total_locked, 1_000_000);
    }

    #[test]
    fn test_withdrawal_lifecycle_with_real_proof() {
        let mut bridge = setup_test_bridge();
        bridge.total_minted = 1_000_000;
        bridge.total_locked = 1_000_000;
        // Withdrawal at height 2 (within batch range 1..4)
        bridge.l2_height = 2;
        commit_test_state_root(&mut bridge);

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                500_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let withdrawal = bridge.withdrawals.get(&wid).unwrap();
        assert_eq!(withdrawal.status, WithdrawalStatus::Pending);
        assert_eq!(withdrawal.fee, 500); // 0.1% of 500_000

        // Empty proof should fail
        assert!(bridge.verify_withdrawal_proof(&wid, &[]).is_err());

        // Invalid bytes should fail deserialization
        assert!(bridge.verify_withdrawal_proof(&wid, &[1, 2, 3]).is_err());

        // Real STARK proof should succeed
        let proof = make_verified_proof();
        bridge
            .verify_withdrawal_with_stark_proof(&wid, &proof)
            .unwrap();

        let withdrawal = bridge.withdrawals.get(&wid).unwrap();
        assert_eq!(withdrawal.status, WithdrawalStatus::Ready);
        assert!(withdrawal.is_verified);

        // Advance past challenge period before completing
        bridge.l2_height += 30_000;
        let payout = bridge
            .complete_withdrawal(&wid, Some(Address::ZERO))
            .unwrap();
        assert_eq!(payout, 500_000 - 500);
    }

    #[test]
    fn test_withdrawal_with_serialized_proof() {
        let mut bridge = setup_test_bridge();
        bridge.total_minted = 1_000_000;
        bridge.total_locked = 1_000_000;
        bridge.l2_height = 3;
        commit_test_state_root(&mut bridge);

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                200_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        // Serialize a real proof to bytes and verify via the bytes path
        let proof = make_verified_proof();
        let proof_bytes = proof.to_bytes().unwrap();

        bridge.verify_withdrawal_proof(&wid, &proof_bytes).unwrap();
        let withdrawal = bridge.withdrawals.get(&wid).unwrap();
        assert_eq!(withdrawal.status, WithdrawalStatus::Ready);
        assert!(withdrawal.is_verified);
    }

    #[test]
    fn test_withdrawal_with_batch_proof_record() {
        let mut bridge = setup_test_bridge();
        bridge.total_minted = 1_000_000;
        bridge.total_locked = 1_000_000;
        // Withdrawal at height 2 — within batch range [1, 4]
        bridge.l2_height = 2;
        commit_test_state_root(&mut bridge);

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                300_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let prover = StarkProver::new();
        let record = prove_batch(
            &prover,
            Hash256::from_bytes([0x01; 32]),
            Hash256::from_bytes([0x02; 32]),
            (1, 4),
            10,
            5000,
        )
        .unwrap();

        bridge
            .verify_withdrawal_with_batch_proof(&wid, &record)
            .unwrap();
        let withdrawal = bridge.withdrawals.get(&wid).unwrap();
        assert_eq!(withdrawal.status, WithdrawalStatus::Ready);
        assert!(withdrawal.is_verified);
    }

    #[test]
    fn test_withdrawal_batch_proof_wrong_range() {
        let mut bridge = setup_test_bridge();
        // Withdrawal at height 100 — outside batch range [1, 4]
        bridge.l2_height = 100;

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let prover = StarkProver::new();
        let record = prove_batch(
            &prover,
            Hash256::from_bytes([0x01; 32]),
            Hash256::from_bytes([0x02; 32]),
            (1, 4),
            10,
            5000,
        )
        .unwrap();

        let result = bridge.verify_withdrawal_with_batch_proof(&wid, &record);
        assert!(
            result.is_err(),
            "Withdrawal outside batch range should fail"
        );
    }

    #[test]
    fn test_null_state_roots_rejected() {
        let mut bridge = setup_test_bridge();
        bridge.l2_height = 2;
        // Commit Hash256::ZERO so state root check passes —
        // we want to specifically test the null state root rejection (Step 3),
        // not the "no committed roots" rejection (Step 4).
        bridge.commit_state_root(1, Hash256::ZERO);

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        // Generate a proof with ZERO state roots — should be rejected
        let prover = StarkProver::new();
        let record = prove_batch(&prover, Hash256::ZERO, Hash256::ZERO, (1, 4), 10, 5000).unwrap();

        let result = bridge.verify_withdrawal_with_stark_proof(&wid, &record.proof);
        assert!(result.is_err(), "Null state root proof should be rejected");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("null state roots"),
            "Error should specifically mention null state roots, got: {err_msg}"
        );
    }

    #[test]
    fn test_double_claim_rejected() {
        let mut bridge = setup_test_bridge();
        bridge.l2_height = 2;
        commit_test_state_root(&mut bridge);

        // Deposit first so total_minted/total_locked can cover the withdrawal
        bridge
            .process_deposit(
                Hash256::ZERO,
                0,
                500_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let proof = make_verified_proof();
        bridge
            .verify_withdrawal_with_stark_proof(&wid, &proof)
            .unwrap();
        // Advance past challenge period before completing
        bridge.l2_height += 30_000;
        bridge
            .complete_withdrawal(&wid, Some(Address::ZERO))
            .unwrap();

        // Second claim should fail
        assert!(
            bridge
                .complete_withdrawal(&wid, Some(Address::ZERO))
                .is_err()
        );
    }

    #[test]
    fn test_bridge_paused() {
        let mut bridge = setup_test_bridge();
        bridge.paused = true;

        let result = bridge.process_deposit(
            Hash256::ZERO,
            0,
            100_000,
            Address::ZERO,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(result.is_err());

        let result = bridge.request_withdrawal(
            Address::ZERO,
            100_000,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_bridge_status() {
        let mut bridge = setup_test_bridge();
        bridge
            .process_deposit(
                Hash256::ZERO,
                0,
                1_000_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        let status = bridge.status();
        assert_eq!(status.total_locked, 1_000_000);
        assert!(!status.paused);
    }

    // ══════════════════════════════════════════════════════════════
    // Adversarial / Double-Spend / Manipulation Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_zero_amount_deposit_rejected() {
        let mut bridge = setup_test_bridge();
        let result = bridge.process_deposit(
            Hash256::ZERO,
            0,
            0,
            Address::ZERO,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(result.is_err(), "Zero amount deposit must be rejected");
    }

    #[test]
    fn adversarial_zero_amount_withdrawal_rejected() {
        let mut bridge = setup_test_bridge();
        let result = bridge.request_withdrawal(
            Address::ZERO,
            0,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
        );
        assert!(result.is_err(), "Zero amount withdrawal must be rejected");
    }

    #[test]
    fn adversarial_fee_rounding_tiny_amount() {
        let mut bridge = setup_test_bridge();
        // 1 satoshi is below MIN_WITHDRAWAL_AMOUNT (100,000 sats).
        // This must be rejected to prevent dust attacks.
        let result = bridge.request_withdrawal(
            Address::ZERO,
            1,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
        );
        assert!(
            result.is_err(),
            "1 satoshi withdrawal must be rejected (below MIN_WITHDRAWAL_AMOUNT)"
        );

        // Minimum valid withdrawal: fee = 100_000 * 10 / 10_000 = 100 sats.
        // Net = 99_900 sats — fee rounds correctly, does not exceed amount.
        let result = bridge.request_withdrawal(
            Address::ZERO,
            100_000,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
        );
        assert!(
            result.is_ok(),
            "MIN_WITHDRAWAL_AMOUNT withdrawal should succeed"
        );
    }

    #[test]
    fn adversarial_complete_unverified_withdrawal() {
        let mut bridge = setup_test_bridge();
        bridge.l2_height = 1;

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let result = bridge.complete_withdrawal(&wid, Some(Address::ZERO));
        assert!(result.is_err(), "Unverified withdrawal must not complete");
    }

    #[test]
    fn adversarial_verify_nonexistent_withdrawal() {
        let mut bridge = setup_test_bridge();
        let fake_id = Hash256::from_bytes([0xDE; 32]);
        let proof = make_verified_proof();

        let result = bridge.verify_withdrawal_with_stark_proof(&fake_id, &proof);
        assert!(
            result.is_err(),
            "Verifying nonexistent withdrawal must fail"
        );
    }

    #[test]
    fn adversarial_complete_nonexistent_withdrawal() {
        let mut bridge = setup_test_bridge();
        let fake_id = Hash256::from_bytes([0xDE; 32]);
        let result = bridge.complete_withdrawal(&fake_id, Some(Address::ZERO));
        assert!(
            result.is_err(),
            "Completing nonexistent withdrawal must fail"
        );
    }

    #[test]
    fn adversarial_already_confirmed_deposit_no_double_count() {
        let mut bridge = setup_test_bridge();
        let tx_id = Hash256::ZERO;
        bridge
            .process_deposit(
                tx_id,
                0,
                1_000_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        let locked_before = bridge.total_locked;
        let minted_before = bridge.total_minted;

        // Update to 100 confirmations — must NOT double-count
        let status = bridge.update_deposit_confirmations(&tx_id, 0, 100).unwrap();
        assert_eq!(status, DepositStatus::Confirmed);
        assert_eq!(
            bridge.total_locked, locked_before,
            "Must not double-count locked"
        );
        assert_eq!(
            bridge.total_minted, minted_before,
            "Must not double-count minted"
        );
    }

    #[test]
    fn adversarial_pause_unpause_lifecycle() {
        let mut bridge = setup_test_bridge();

        bridge
            .process_deposit(
                Hash256::ZERO,
                0,
                100_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        bridge.paused = true;
        assert!(
            bridge
                .process_deposit(
                    Hash256::from_bytes([1; 32]),
                    0,
                    200_000,
                    Address::ZERO,
                    6,
                    Some(Address::from_bytes([9u8; 20])),
                    None
                )
                .is_err()
        );
        assert!(
            bridge
                .request_withdrawal(
                    Address::ZERO,
                    50_000,
                    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into()
                )
                .is_err()
        );

        bridge.paused = false;
        bridge
            .process_deposit(
                Hash256::from_bytes([2; 32]),
                0,
                300_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();
        assert_eq!(bridge.total_locked, 400_000);
    }

    #[test]
    fn adversarial_double_verify_idempotent() {
        let mut bridge = setup_test_bridge();
        bridge.total_minted = 1_000_000;
        bridge.total_locked = 1_000_000;
        bridge.l2_height = 2;
        commit_test_state_root(&mut bridge);

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                500_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let proof = make_verified_proof();
        bridge
            .verify_withdrawal_with_stark_proof(&wid, &proof)
            .unwrap();
        // Verify again — should not crash or change state
        let status = bridge
            .verify_withdrawal_with_stark_proof(&wid, &proof)
            .unwrap();
        assert_eq!(status, WithdrawalStatus::Ready);
    }

    #[test]
    fn adversarial_withdrawal_accounting_conservation() {
        let mut bridge = setup_test_bridge();
        let deposit_amount = 100_000_000u64;
        bridge
            .process_deposit(
                Hash256::ZERO,
                0,
                deposit_amount,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();
        let fee_in = deposit_amount * PEGIN_FEE_BP / 10_000;
        let minted = deposit_amount - fee_in;

        assert_eq!(bridge.total_locked, deposit_amount);
        assert_eq!(bridge.total_minted, minted);

        bridge.l2_height = 2;
        commit_test_state_root(&mut bridge);
        let withdraw_amount = minted / 2;
        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                withdraw_amount,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let proof = make_verified_proof();
        bridge
            .verify_withdrawal_with_stark_proof(&wid, &proof)
            .unwrap();

        // Advance past challenge period before completing
        bridge.l2_height += 30_000;
        let fee_out = withdraw_amount * PEGOUT_FEE_BP / 10_000;
        let payout = bridge
            .complete_withdrawal(&wid, Some(Address::ZERO))
            .unwrap();
        assert_eq!(payout, withdraw_amount - fee_out);

        assert_eq!(bridge.total_locked, deposit_amount - withdraw_amount);
        assert_eq!(bridge.total_minted, minted - withdraw_amount);
    }

    #[test]
    fn adversarial_challenge_period_check() {
        let mut bridge = setup_test_bridge();
        bridge.l2_height = 100;

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        // Not yet expired
        assert!(!bridge.is_challenge_period_expired(&wid).unwrap());

        // Advance past challenge period (144 × 200 = 28800 L2 blocks)
        bridge.l2_height = 100 + CHALLENGE_PERIOD_BLOCKS * L1_TO_L2_BLOCK_RATIO;
        assert!(bridge.is_challenge_period_expired(&wid).unwrap());
    }

    #[test]
    fn adversarial_multiple_withdrawals_different_ids() {
        let mut bridge = setup_test_bridge();
        bridge.total_minted = 10_000_000;
        bridge.total_locked = 10_000_000;
        bridge.l2_height = 2;
        commit_test_state_root(&mut bridge);

        let wid1 = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kaaaaa1".into(),
            )
            .unwrap();
        let wid2 = bridge
            .request_withdrawal(
                Address::from_bytes([1; 20]),
                200_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kaaaaa2".into(),
            )
            .unwrap();

        assert_ne!(wid1, wid2, "Withdrawal IDs must be unique");

        let proof = make_verified_proof();
        bridge
            .verify_withdrawal_with_stark_proof(&wid1, &proof)
            .unwrap();
        bridge
            .verify_withdrawal_with_stark_proof(&wid2, &proof)
            .unwrap();

        // Advance past challenge period before completing
        bridge.l2_height += 30_000;
        bridge
            .complete_withdrawal(&wid1, Some(Address::ZERO))
            .unwrap();
        bridge
            .complete_withdrawal(&wid2, Some(Address::from_bytes([1; 20])))
            .unwrap();

        assert!(
            bridge
                .complete_withdrawal(&wid1, Some(Address::ZERO))
                .is_err()
        );
        assert!(
            bridge
                .complete_withdrawal(&wid2, Some(Address::from_bytes([1; 20])))
                .is_err()
        );
    }

    #[test]
    fn adversarial_deposit_not_found() {
        let mut bridge = setup_test_bridge();
        let result = bridge.update_deposit_confirmations(&Hash256::from_bytes([0xFF; 32]), 0, 10);
        assert!(result.is_err(), "Updating nonexistent deposit must fail");
    }

    #[test]
    fn test_deposit_composite_key_no_overwrite() {
        let mut bridge = setup_test_bridge();
        let tx_id = Hash256::ZERO;

        // Same btc_tx_id, different vout — both should succeed
        bridge
            .process_deposit(
                tx_id,
                0,
                500_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();
        bridge
            .process_deposit(
                tx_id,
                1,
                300_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        // Both deposits exist
        assert!(bridge.deposits.get(&(tx_id, 0)).is_some());
        assert!(bridge.deposits.get(&(tx_id, 1)).is_some());
        assert_eq!(bridge.deposits.get(&(tx_id, 0)).unwrap().amount, 500_000);
        assert_eq!(bridge.deposits.get(&(tx_id, 1)).unwrap().amount, 300_000);
        assert_eq!(bridge.total_locked, 800_000);
    }

    #[test]
    fn test_duplicate_deposit_rejected() {
        let mut bridge = setup_test_bridge();
        let tx_id = Hash256::ZERO;

        bridge
            .process_deposit(
                tx_id,
                0,
                500_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        // Same (tx_id, vout) — must be rejected
        let result = bridge.process_deposit(
            tx_id,
            0,
            999_000,
            Address::ZERO,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(result.is_err(), "Duplicate deposit must be rejected");

        // Original deposit unchanged
        assert_eq!(bridge.deposits.get(&(tx_id, 0)).unwrap().amount, 500_000);
    }

    #[test]
    fn adversarial_truncated_proof_rejected() {
        let mut bridge = setup_test_bridge();
        bridge.l2_height = 2;

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let proof = make_verified_proof();
        let full_bytes = proof.to_bytes().unwrap();
        let truncated = &full_bytes[..full_bytes.len() / 2];

        let result = bridge.verify_withdrawal_proof(&wid, truncated);
        assert!(
            result.is_err(),
            "Truncated proof bytes must fail deserialization"
        );
    }

    #[test]
    fn test_unbound_state_root_rejected() {
        let mut bridge = setup_test_bridge();
        bridge.l2_height = 2;
        // Commit a DIFFERENT state root than what the proof uses
        bridge.commit_state_root(1, Hash256::from_bytes([0xAA; 32]));

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let proof = make_verified_proof(); // uses [0x01; 32] as initial_state_root

        let result = bridge.verify_withdrawal_with_stark_proof(&wid, &proof);
        assert!(
            result.is_err(),
            "Proof with non-committed initial_state_root must be rejected"
        );
    }

    #[test]
    fn test_committed_state_root_accepted() {
        let mut bridge = setup_test_bridge();
        bridge.l2_height = 2;
        // Commit the correct state root
        commit_test_state_root(&mut bridge);

        let wid = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();

        let proof = make_verified_proof();

        let result = bridge.verify_withdrawal_with_stark_proof(&wid, &proof);
        assert!(
            result.is_ok(),
            "Proof with committed initial_state_root must succeed"
        );
    }

    // ══════════════════════════════════════════════════════════════
    //  Liquidity Limit Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_deposit_below_minimum_rejected() {
        let mut bridge = setup_test_bridge();
        let result = bridge.process_deposit(
            Hash256::ZERO,
            0,
            MIN_DEPOSIT_AMOUNT - 1,
            Address::ZERO,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), BridgeError::DepositBelowMinimum { .. }),
            "Amount below minimum must be rejected"
        );
    }

    #[test]
    fn test_deposit_at_minimum_accepted() {
        let mut bridge = setup_test_bridge();
        let result = bridge.process_deposit(
            Hash256::ZERO,
            0,
            MIN_DEPOSIT_AMOUNT,
            Address::ZERO,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(result.is_ok(), "Exact minimum amount should be accepted");
    }

    #[test]
    fn test_deposit_exceeds_maximum_rejected() {
        let mut bridge = setup_test_bridge();
        let result = bridge.process_deposit(
            Hash256::ZERO,
            0,
            MAX_DEPOSIT_AMOUNT + 1,
            Address::ZERO,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                BridgeError::DepositExceedsMaximum { .. }
            ),
            "Amount above maximum must be rejected"
        );
    }

    #[test]
    fn test_bridge_cap_enforcement() {
        let mut bridge = setup_test_bridge();

        // Fill to near cap with MAX_DEPOSIT_AMOUNT deposits.
        // Use unique recipient addresses to avoid daily volume limit.
        let deposits_needed = TOTAL_BRIDGE_CAP / MAX_DEPOSIT_AMOUNT;
        for i in 0..deposits_needed {
            let tx_id = Hash256::from_bytes({
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&(i as u64).to_le_bytes());
                b
            });
            let recipient = Address::from_bytes({
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&(i as u64).to_le_bytes());
                a
            });
            bridge
                .process_deposit(
                    tx_id,
                    0,
                    MAX_DEPOSIT_AMOUNT,
                    recipient,
                    6,
                    Some(Address::from_bytes([9u8; 20])),
                    None,
                )
                .unwrap();
        }

        assert_eq!(bridge.total_locked, TOTAL_BRIDGE_CAP);

        // Next deposit should be rejected
        let result = bridge.process_deposit(
            Hash256::from_bytes([0xFF; 32]),
            0,
            MIN_DEPOSIT_AMOUNT,
            Address::ZERO,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), BridgeError::BridgeCapReached { .. }),
            "Exceeding bridge cap must be rejected"
        );
    }

    #[test]
    fn test_withdrawal_exceeds_maximum_rejected() {
        let mut bridge = setup_test_bridge();
        let result = bridge.request_withdrawal(
            Address::ZERO,
            MAX_WITHDRAWAL_AMOUNT + 1,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
        );
        assert!(result.is_err());
        assert!(
            matches!(
                result.unwrap_err(),
                BridgeError::WithdrawalExceedsMaximum { .. }
            ),
            "Withdrawal above maximum must be rejected"
        );
    }

    #[test]
    fn test_withdrawal_at_maximum_accepted() {
        let mut bridge = setup_test_bridge();
        let result = bridge.request_withdrawal(
            Address::ZERO,
            MAX_WITHDRAWAL_AMOUNT,
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
        );
        assert!(
            result.is_ok(),
            "Exact maximum withdrawal should be accepted"
        );
    }

    #[test]
    fn test_pending_deposits_cannot_bypass_cap() {
        // Regression test: multiple pending deposits passing cap check individually,
        // then all confirming to exceed the cap.
        let mut bridge = setup_test_bridge();

        // Fill to 90% of cap with confirmed deposits (each <= MAX_DEPOSIT_AMOUNT).
        // Use unique addresses to avoid daily volume limit.
        let fill_target = TOTAL_BRIDGE_CAP * 9 / 10; // 90 BTC
        let deposits_needed = fill_target / MAX_DEPOSIT_AMOUNT; // 9 deposits of 10 BTC
        for i in 0..deposits_needed {
            let tx_id = Hash256::from_bytes({
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&(i as u64).to_le_bytes());
                b
            });
            let recipient = Address::from_bytes({
                let mut a = [0u8; 20];
                a[..8].copy_from_slice(&(i as u64).to_le_bytes());
                a
            });
            bridge
                .process_deposit(
                    tx_id,
                    0,
                    MAX_DEPOSIT_AMOUNT,
                    recipient,
                    6,
                    Some(Address::from_bytes([9u8; 20])),
                    None,
                )
                .unwrap();
        }
        assert_eq!(bridge.total_locked, fill_target);

        // Two pending deposits that individually fit but together exceed cap.
        // Use different addresses for the final two deposits.
        let deposit_a = MAX_DEPOSIT_AMOUNT; // 10 BTC (fills to 100%)
        let deposit_b = MAX_DEPOSIT_AMOUNT; // 10 BTC (would push to 110%)

        let tx_a = Hash256::from_bytes([0xAA; 32]);
        let tx_b = Hash256::from_bytes([0xBB; 32]);
        let addr_a = Address::from_bytes([0xAA; 20]);
        let addr_b = Address::from_bytes([0xBB; 20]);

        // Both pass cap check (total_locked = 90%, each deposit = 10%, 90+10 = 100%)
        bridge
            .process_deposit(
                tx_a,
                0,
                deposit_a,
                addr_a,
                2,
                Some(Address::from_bytes([9u8; 20])),
                None,
            ) // pending
            .unwrap();
        bridge
            .process_deposit(
                tx_b,
                0,
                deposit_b,
                addr_b,
                2,
                Some(Address::from_bytes([9u8; 20])),
                None,
            ) // pending
            .unwrap();

        // First confirmation: 90% + 10% = 100% → OK
        bridge.update_deposit_confirmations(&tx_a, 0, 6).unwrap();
        assert_eq!(bridge.total_locked, fill_target + deposit_a);

        // Second confirmation: 100% + 10% = 110% → must be REJECTED
        let result = bridge.update_deposit_confirmations(&tx_b, 0, 6);
        assert!(
            result.is_err(),
            "Second pending deposit confirmation must fail when it would exceed bridge cap"
        );
        assert!(matches!(
            result.unwrap_err(),
            BridgeError::BridgeCapReached { .. }
        ));
    }

    // ══════════════════════════════════════════════════════════════
    //  Deposit Pruning Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_prune_finalized_deposits_removes_old_confirmed() {
        let mut bridge = setup_test_bridge();
        // prune logic uses L1 height math, so l1_height must be
        // set high enough for saturating_sub to produce meaningful results.
        bridge.l1_height = 200;

        // Deposit with many confirmations (old, should be pruned)
        let tx_old = Hash256::from_bytes([0x01; 32]);
        bridge
            .process_deposit(
                tx_old,
                0,
                500_000,
                Address::ZERO,
                100,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        // Deposit with few confirmations (recent, should be kept)
        let tx_recent = Hash256::from_bytes([0x02; 32]);
        bridge
            .process_deposit(
                tx_recent,
                0,
                500_000,
                Address::ZERO,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        assert_eq!(bridge.deposits.len(), 2);

        // Finalize the old deposit (prune only removes Finalized deposits)
        bridge.finalize_deposit(&tx_old, 0).unwrap();

        // Prune deposits with more than 50 confirmations
        let pruned = bridge.prune_finalized_deposits(50);
        assert_eq!(pruned, 1, "Should prune 1 old confirmed deposit");
        assert_eq!(bridge.deposits.len(), 1);
        assert!(
            bridge.deposits.get(&(tx_old, 0)).is_none(),
            "Old deposit should be pruned"
        );
        assert!(
            bridge.deposits.get(&(tx_recent, 0)).is_some(),
            "Recent deposit should remain"
        );
    }

    #[test]
    fn test_prune_finalized_deposits_skips_pending() {
        let mut bridge = setup_test_bridge();

        // Pending deposit (only 2 confirmations, not Confirmed status)
        let tx_pending = Hash256::from_bytes([0x03; 32]);
        bridge
            .process_deposit(
                tx_pending,
                0,
                500_000,
                Address::ZERO,
                2,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        let pruned = bridge.prune_finalized_deposits(0);
        assert_eq!(pruned, 0, "Pending deposits must not be pruned");
        assert_eq!(bridge.deposits.len(), 1);
    }

    #[test]
    fn test_prune_finalized_deposits_none_to_prune() {
        let mut bridge = setup_test_bridge();
        let pruned = bridge.prune_finalized_deposits(100);
        assert_eq!(pruned, 0, "Empty deposits map should prune nothing");
    }

    // ── Withdrawal ID collision tests ────────────────────────────

    #[test]
    fn test_withdrawal_id_no_collision_same_params() {
        // Two withdrawals with identical (sender, amount, destination, l2_height)
        // must produce different IDs thanks to the monotonic counter.
        let mut bridge = setup_test_bridge();
        let id1 = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();
        let id2 = bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();
        assert_ne!(
            id1, id2,
            "identical withdrawal params must produce different IDs"
        );
        assert_eq!(
            bridge.withdrawals.len(),
            2,
            "both withdrawals must be stored"
        );
    }

    #[test]
    fn test_withdrawal_counter_increments() {
        let mut bridge = setup_test_bridge();
        assert_eq!(bridge.withdrawal_counter, 0);
        bridge
            .request_withdrawal(
                Address::ZERO,
                100_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();
        assert_eq!(bridge.withdrawal_counter, 1);
        bridge
            .request_withdrawal(
                Address::ZERO,
                200_000,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
            )
            .unwrap();
        assert_eq!(bridge.withdrawal_counter, 2);
    }

    #[test]
    fn test_multiple_withdrawals_all_unique() {
        let mut bridge = setup_test_bridge();
        let mut ids = std::collections::HashSet::new();
        for _ in 0..10 {
            let id = bridge
                .request_withdrawal(
                    Address::ZERO,
                    100_000,
                    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".into(),
                )
                .unwrap();
            assert!(ids.insert(id), "every withdrawal ID must be unique");
        }
        assert_eq!(bridge.withdrawals.len(), 10);
    }

    // ══════════════════════════════════════════════════════════════
    //  Daily Volume Limit Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn test_daily_volume_limit_deposit() {
        let mut bridge = setup_test_bridge();
        let addr = Address::from_bytes([0x01; 20]);

        // Deposit up to daily limit (50 BTC = 5 × 10 BTC deposits)
        for i in 0..5u64 {
            let tx_id = Hash256::from_bytes({
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&i.to_le_bytes());
                b
            });
            bridge
                .process_deposit(
                    tx_id,
                    0,
                    MAX_DEPOSIT_AMOUNT,
                    addr,
                    6,
                    Some(Address::from_bytes([9u8; 20])),
                    None,
                )
                .unwrap();
        }

        // Next deposit from same address should fail
        let result = bridge.process_deposit(
            Hash256::from_bytes([0xFF; 32]),
            0,
            MIN_DEPOSIT_AMOUNT,
            addr,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(
            matches!(
                result.unwrap_err(),
                BridgeError::DailyVolumeLimitExceeded { .. }
            ),
            "Exceeding daily volume limit must be rejected"
        );

        // Different address should still work
        let other_addr = Address::from_bytes([0x02; 20]);
        let result = bridge.process_deposit(
            Hash256::from_bytes([0xEE; 32]),
            0,
            MAX_DEPOSIT_AMOUNT,
            other_addr,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(
            result.is_ok(),
            "Different address should have its own daily limit"
        );
    }

    #[test]
    fn test_daily_volume_limit_resets_after_window() {
        let mut bridge = setup_test_bridge();
        let addr = Address::from_bytes([0x01; 20]);

        // Exhaust daily limit
        for i in 0..5u64 {
            let tx_id = Hash256::from_bytes({
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&i.to_le_bytes());
                b
            });
            bridge
                .process_deposit(
                    tx_id,
                    0,
                    MAX_DEPOSIT_AMOUNT,
                    addr,
                    6,
                    Some(Address::from_bytes([9u8; 20])),
                    None,
                )
                .unwrap();
        }

        // Advance past the daily window
        bridge.l2_height = DAILY_VOLUME_WINDOW_BLOCKS + 1;

        // Should work again after window reset
        let result = bridge.process_deposit(
            Hash256::from_bytes([0xDD; 32]),
            0,
            MAX_DEPOSIT_AMOUNT,
            addr,
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(
            result.is_ok(),
            "Volume limit should reset after window passes"
        );
    }

    // ── GAP fix tests ─────────────────────────────────────────────────

    #[test]
    fn test_gap3_federation_quorum_completes_withdrawal() {
        // Federation approval reaching quorum should auto-execute
        // and mark withdrawal as Completed.
        let mut bridge = setup_test_bridge();

        // Setup: deposit 1 BTC
        let addr1 = Address::from_bytes([0x01; 20]);
        bridge
            .process_deposit(
                Hash256::from_bytes([0xAA; 32]),
                0,
                100_000_000,
                addr1,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        // Request withdrawal
        let wid = bridge
            .request_withdrawal(addr1, 50_000_000, "bc1qtest12345678901234".to_string())
            .unwrap();

        // Verify withdrawal with STARK proof so it becomes Ready
        let proof = make_verified_proof();
        commit_test_state_root(&mut bridge);
        bridge
            .verify_withdrawal_with_stark_proof(&wid, &proof)
            .unwrap();
        assert_eq!(
            bridge.withdrawals.get(&wid).unwrap().status,
            WithdrawalStatus::Ready
        );

        // Advance l2_height past the challenge period.
        // Federation completion now correctly requires the challenge period
        // to have expired before marking withdrawal as Completed.
        let challenge_l2 = CHALLENGE_PERIOD_BLOCKS.saturating_mul(L1_TO_L2_BLOCK_RATIO);
        bridge.l2_height = challenge_l2 + 1;

        // Init federation (3-of-5)
        let members: Vec<(Address, String)> = (1..=5u8)
            .map(|i| (Address::from_bytes([i; 20]), format!("member-{i}")))
            .collect();
        bridge.init_federation(members, 3, 0).unwrap();

        // Propose withdrawal approval
        let proposal_id = bridge
            .propose_withdrawal_approval(Address::from_bytes([1; 20]), wid)
            .unwrap();

        // Approve from 2 more members (proposer = member 1 already voted)
        bridge
            .approve_federation_proposal(&proposal_id, Address::from_bytes([2; 20]))
            .unwrap();
        let quorum = bridge
            .approve_federation_proposal(&proposal_id, Address::from_bytes([3; 20]))
            .unwrap();
        assert!(quorum, "3rd approval should reach quorum");

        // Withdrawal should now be Completed
        assert_eq!(
            bridge.withdrawals.get(&wid).unwrap().status,
            WithdrawalStatus::Completed,
            "federation quorum must auto-complete withdrawal"
        );
    }

    #[test]
    fn test_gap8_force_exit_nonexistent() {
        // force_exit on a nonexistent withdrawal should return Err, not panic.
        let mut bridge = setup_test_bridge();
        let fake_id = Hash256::from_bytes([0xFF; 32]);
        let result = bridge.force_exit(&fake_id, 999_999);
        assert!(
            result.is_err(),
            "force_exit on missing withdrawal must return Err"
        );
    }

    // ── Attack surface tests ──────────────────────────────────────────

    #[test]
    fn test_overflow_bridge_cap_near_max() {
        // Verify that deposits exceeding bridge cap are rejected.
        let mut bridge = setup_test_bridge();

        // Fill bridge to cap using different addresses to avoid daily volume limit
        let deposits_needed = TOTAL_BRIDGE_CAP / MAX_DEPOSIT_AMOUNT;
        for i in 0..deposits_needed {
            let tx = Hash256::from_bytes({
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&i.to_le_bytes());
                b
            });
            // Use a unique address per deposit to avoid daily volume limits
            let mut addr_bytes = [0u8; 20];
            addr_bytes[..8].copy_from_slice(&i.to_le_bytes());
            bridge
                .process_deposit(
                    tx,
                    0,
                    MAX_DEPOSIT_AMOUNT,
                    Address::from_bytes(addr_bytes),
                    6,
                    Some(Address::from_bytes([9u8; 20])),
                    None,
                )
                .unwrap();
        }
        assert_eq!(bridge.total_locked, TOTAL_BRIDGE_CAP);

        // One more deposit should fail (bridge cap exceeded)
        let result = bridge.process_deposit(
            Hash256::from_bytes([0xEE; 32]),
            0,
            1,
            Address::from_bytes([0xFE; 20]),
            6,
            Some(Address::from_bytes([9u8; 20])),
            None,
        );
        assert!(
            result.is_err(),
            "deposit exceeding bridge cap must be rejected"
        );
    }

    #[test]
    fn test_full_lifecycle_deposit_to_withdrawal() {
        // End-to-end: deposit → withdrawal request → verify → complete
        let mut bridge = setup_test_bridge();
        let user = Address::from_bytes([0x42; 20]);

        // 1. Deposit
        let deposit_amount = 500_000_000; // 5 BTC
        bridge
            .process_deposit(
                Hash256::from_bytes([0xD0; 32]),
                0,
                deposit_amount,
                user,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();
        assert_eq!(bridge.total_locked, deposit_amount);
        assert_eq!(
            bridge.total_minted,
            deposit_amount - (deposit_amount * 5 / 10_000)
        );

        // 2. Withdraw
        let withdraw_amount = 100_000_000; // 1 BTC
        let wid = bridge
            .request_withdrawal(user, withdraw_amount, "bc1qlifecycletest12345".to_string())
            .unwrap();
        assert_eq!(
            bridge.withdrawals.get(&wid).unwrap().status,
            WithdrawalStatus::Pending
        );

        // 3. Verify with STARK proof → Ready
        let proof = make_verified_proof();
        commit_test_state_root(&mut bridge);
        let status = bridge
            .verify_withdrawal_with_stark_proof(&wid, &proof)
            .unwrap();
        assert_eq!(status, WithdrawalStatus::Ready);
        assert!(bridge.withdrawals.get(&wid).unwrap().is_verified);

        // 4. Init federation and approve → Completed
        // Advance l2_height past the challenge period first.
        let challenge_l2 = CHALLENGE_PERIOD_BLOCKS.saturating_mul(L1_TO_L2_BLOCK_RATIO);
        bridge.l2_height = challenge_l2 + 1;

        let members: Vec<(Address, String)> = (1..=5u8)
            .map(|i| (Address::from_bytes([i; 20]), format!("m{i}")))
            .collect();
        bridge.init_federation(members, 3, 0).unwrap();

        let pid = bridge
            .propose_withdrawal_approval(Address::from_bytes([1; 20]), wid)
            .unwrap();
        bridge
            .approve_federation_proposal(&pid, Address::from_bytes([2; 20]))
            .unwrap();
        bridge
            .approve_federation_proposal(&pid, Address::from_bytes([3; 20]))
            .unwrap();
        assert_eq!(
            bridge.withdrawals.get(&wid).unwrap().status,
            WithdrawalStatus::Completed
        );
    }

    #[test]
    fn test_tick_challenges_auto_slashes_expired() {
        // When a challenge expires, the operator's reimbursement should be slashed.
        use crate::challenge::CHALLENGE_RESPONSE_WINDOW;
        use crate::challenge::ChallengeType;

        let mut bridge = setup_test_bridge();
        let user = Address::from_bytes([0x10; 20]);
        let operator = Address::from_bytes([0x20; 20]);

        // Setup: deposit and withdraw
        bridge
            .process_deposit(
                Hash256::from_bytes([0xBB; 32]),
                0,
                100_000_000,
                user,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();
        let wid = bridge
            .request_withdrawal(user, 50_000_000, "bc1qticktest123456789".to_string())
            .unwrap();

        // Register operator and claim withdrawal
        bridge
            .operator_manager
            .register_operator(operator, 0)
            .unwrap();
        bridge
            .operator_manager
            .claim_withdrawal(operator, wid, 50_000_000, 0, CHALLENGE_PERIOD_BLOCKS)
            .unwrap();

        // Submit challenge for this withdrawal
        bridge.l2_height = 100;
        let challenge_id = bridge
            .submit_challenge(
                user,
                ChallengeType::InvalidWithdrawalProof {
                    withdrawal_id: wid,
                    proof_state_root: Hash256::from_bytes([0xDD; 32]),
                    claimed_state_root: Hash256::from_bytes([0xCC; 32]),
                },
                crate::challenge::CHALLENGE_BOND,
            )
            .unwrap();

        // Advance past challenge window
        bridge.l2_height = 100 + CHALLENGE_RESPONSE_WINDOW + 1;
        let (expired, slash_failures) = bridge.tick_challenges();
        assert!(expired.contains(&challenge_id), "challenge should expire");
        assert!(slash_failures.is_empty(), "slash should succeed");

        // The operator's reimbursement should be slashed
        let reimb = bridge.operator_manager.get_reimbursement(&wid).unwrap();
        assert_eq!(
            reimb.status,
            crate::operator::ReimbursementStatus::Slashed,
            "expired challenge must auto-slash operator"
        );
    }

    #[test]
    fn test_bridge_state_serialization_roundtrip() {
        // Verify BridgeManager survives serialize/deserialize.
        let mut bridge = setup_test_bridge();
        let addr = Address::from_bytes([0x42; 20]);

        // Add some state
        bridge
            .process_deposit(
                Hash256::from_bytes([0xAA; 32]),
                0,
                100_000_000,
                addr,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();
        bridge
            .request_withdrawal(addr, 50_000_000, "bc1qroundtrip12345678".to_string())
            .unwrap();
        bridge.l2_height = 42;

        // Roundtrip
        let bytes = bridge.to_bytes().unwrap();
        let restored = BridgeManager::from_bytes(&bytes).unwrap();

        assert_eq!(restored.deposits.len(), bridge.deposits.len());
        assert_eq!(restored.withdrawals.len(), bridge.withdrawals.len());
        assert_eq!(restored.total_locked, bridge.total_locked);
        assert_eq!(restored.total_minted, bridge.total_minted);
        assert_eq!(restored.l2_height, 42);
    }

    #[test]
    fn test_resume_bridge_via_federation() {
        // Verify that a ResumeBridge proposal actually unpauses the bridge.
        let mut bridge = setup_test_bridge();

        // Init federation (3-of-5)
        let members: Vec<(Address, String)> = (1..=5u8)
            .map(|i| (Address::from_bytes([i; 20]), format!("member-{i}")))
            .collect();
        bridge.init_federation(members, 3, 0).unwrap();

        // Pause the bridge via emergency_pause
        let member1 = Address::from_bytes([1; 20]);
        bridge.emergency_pause(&member1).unwrap();
        assert!(
            bridge.paused,
            "bridge should be paused after emergency_pause"
        );

        // Create a ResumeBridge proposal
        let proposal_id = bridge
            .federation
            .as_mut()
            .unwrap()
            .create_proposal(member1, ProposalAction::ResumeBridge, 100)
            .unwrap();

        // Approve from 2 more members (proposer = member 1 already voted)
        bridge
            .approve_federation_proposal(&proposal_id, Address::from_bytes([2; 20]))
            .unwrap();
        let quorum = bridge
            .approve_federation_proposal(&proposal_id, Address::from_bytes([3; 20]))
            .unwrap();
        assert!(quorum, "3rd approval should reach quorum");

        // Bridge should now be unpaused
        assert!(
            !bridge.paused,
            "ResumeBridge proposal must unpause the bridge"
        );
    }

    #[test]
    fn test_emergency_exit_two_phase() {
        // Emergency exit must NOT finalize accounting until timelock expires.
        let mut bridge = setup_test_bridge();
        let user = Address::from_bytes([0x42; 20]);

        // Deposit 1 BTC
        bridge
            .process_deposit(
                Hash256::from_bytes([0xAA; 32]),
                0,
                100_000_000,
                user,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();
        let locked_before = bridge.total_locked;
        let minted_before = bridge.total_minted;

        // Request withdrawal
        let wid = bridge
            .request_withdrawal(user, 50_000_000, "bc1qemergency123456789".to_string())
            .unwrap();

        // Mark withdrawal as STARK-verified (required by security fix)
        bridge.withdrawals.get_mut(&wid).unwrap().is_verified = true;

        // Step 1: Initiate emergency exit BEFORE timelock
        let exit = bridge.initiate_emergency_exit(&wid, 0).unwrap();
        assert_eq!(exit.status, EmergencyExitStatus::Initiated);
        assert!(exit.timelock_height > 0);

        // Accounting must NOT have changed after initiation
        assert_eq!(
            bridge.total_locked, locked_before,
            "total_locked must not change on initiation"
        );
        assert_eq!(
            bridge.total_minted, minted_before,
            "total_minted must not change on initiation"
        );

        // Withdrawal must still be in its original status (not ForceExited)
        assert_ne!(
            bridge.withdrawals.get(&wid).unwrap().status,
            WithdrawalStatus::ForceExited,
            "withdrawal must not be ForceExited before claim"
        );

        // Step 2a: Claim BEFORE timelock should fail
        let early_claim = bridge.claim_emergency_exit(&wid, 0);
        assert!(
            early_claim.is_err(),
            "claim before timelock expiry must fail"
        );

        // Step 2b: Claim AFTER timelock should succeed
        let payout = bridge
            .claim_emergency_exit(&wid, exit.timelock_height)
            .unwrap();
        assert!(payout > 0, "payout must be positive");

        // NOW accounting should be debited
        assert!(
            bridge.total_locked < locked_before,
            "total_locked must decrease after claim"
        );
        assert!(
            bridge.total_minted < minted_before,
            "total_minted must decrease after claim"
        );

        // Withdrawal should be ForceExited
        assert_eq!(
            bridge.withdrawals.get(&wid).unwrap().status,
            WithdrawalStatus::ForceExited,
            "withdrawal must be ForceExited after claim"
        );
    }
}
