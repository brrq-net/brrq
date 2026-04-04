//! Operator management for liquidity providers.
//!
//! Per whitepaper SS6.4, liquidity operators front BTC to users immediately
//! for withdrawals, then get reimbursed from the bridge after the challenge
//! period expires. This enables fast user-facing withdrawals while maintaining
//! the full security of the challenge protocol.
//!
//! ## Flow
//!
//! 1. Operator registers with `register_operator()`
//! 2. User requests withdrawal via `BridgeManager::request_withdrawal()`
//! 3. Operator claims the withdrawal: `claim_withdrawal()` — fronts BTC to user
//! 4. Challenge period elapses (24h MVP / 2 weeks BitVM2)
//! 5. Operator calls `process_reimbursement()` to reclaim funds + fee
//!
//! ## Slashing
//!
//! If a challenge proves fraud during the challenge period, the operator's
//! pending reimbursement is slashed via `slash_operator()`.

use imbl::HashMap;

use brrq_crypto::hash::Hash256;
use brrq_types::Address;
use serde::{Deserialize, Serialize};

use crate::error::BridgeError;
use crate::taproot;

// ── Economic Constants (Economic Specification §8) ──────────────────────────

/// Operator leverage factor: max concurrent exposure = bond × this factor.
///
/// Economic Specification §8.1: With 5× leverage, a 10 BTC bond supports
/// up to 50 BTC in concurrent withdrawals.
pub const OPERATOR_LEVERAGE_FACTOR: u64 = 5;

/// Maximum single withdrawal as fraction of bond (basis points).
/// 5000 bp = 50% → single withdrawal cannot exceed half the bond.
///
/// Economic Specification §8.3: Prevents fraud from being profitable
/// since max gain (withdrawal) < bond that would be forfeited.
pub const MAX_WITHDRAWAL_BOND_RATIO_BP: u64 = 5000;

// ── Types ───────────────────────────────────────────────────────────────────

/// BitVM2 bond — a Bitcoin UTXO pledged as collateral by an operator.
///
/// In BitVM2 mode, operators must post a bond before claiming withdrawals.
/// If the operator is proven fraudulent during the challenge period, the bond
/// UTXO can be spent by the challenger via the BitVM2 disprove script.
///
/// ## L1 Verification
///
/// The bond includes the operator's x-only (Schnorr) public key and a committed
/// state root. These are used to construct the expected Taproot bond output via
/// `taproot::build_bond_output()`. At registration time, the bridge verifies that
/// the on-chain UTXO's `script_pubkey` matches the expected Taproot output —
/// ensuring the bond is actually locked in the BitVM2 dispute game scripts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitVM2Bond {
    /// Bitcoin transaction ID of the bond UTXO.
    pub utxo_txid: Hash256,
    /// Output index of the bond UTXO.
    pub utxo_vout: u32,
    /// Bond amount in satoshis.
    pub bond_amount: u64,
    /// L1 block height when the bond was registered.
    pub registered_height: u64,
    /// Operator's x-only (Schnorr) public key (32 bytes).
    ///
    /// This is the internal key of the Taproot bond output. The operator
    /// uses this key for the Assert script (proving identity) and for the
    /// key-path cooperative close.
    pub operator_pubkey: [u8; 32],
    /// State root the operator is committing to.
    ///
    /// Used in the Kickoff and Disprove scripts to verify the operator's
    /// commitment. If the operator commits to a fraudulent state root,
    /// a challenger can use the Disprove script to claim the bond.
    pub committed_state_root: [u8; 32],
    /// The expected `script_pubkey` of the bond UTXO (34 bytes: OP_1 <32-byte-key>).
    ///
    /// Computed at registration time by building the full Taproot output from
    /// `operator_pubkey` + `committed_state_root` via `taproot::build_bond_output()`.
    /// Stored so that L1 watchers can verify the UTXO without rebuilding scripts.
    ///
    /// Using `Vec<u8>` instead of `[u8; 34]` because the field is
    /// initialized empty at creation and populated lazily by `set_bitvm2_bond()`.
    /// A fixed-size array would require a sentinel value ([0; 34]) that could be
    /// confused with a legitimate all-zero script. The empty Vec is unambiguous.
    /// All validation code already asserts length == 34 after population.
    pub expected_script_pubkey: Vec<u8>,
    /// Whether this specific bond UTXO has been verified on Bitcoin L1.
    ///
    /// Set by `verify_onchain_utxo()` after confirming this bond's UTXO
    /// exists on-chain with the correct script and value. Enables per-bond
    /// dispute isolation: verifying bond[0] does not mark bond[1] as verified.
    #[serde(default)]
    pub verified_onchain: bool,
}

/// Information about a registered operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorInfo {
    /// Operator's L2 address.
    pub address: Address,
    /// Total BTC fronted to users (satoshis).
    pub total_fronted: u64,
    /// Total BTC reimbursed from bridge (satoshis).
    pub total_reimbursed: u64,
    /// Currently active withdrawal claims.
    pub active_withdrawals: Vec<Hash256>,
    /// L2 block height when operator registered.
    pub registered_at: u64,
    /// BitVM2 bond UTXOs (required for claiming withdrawals in BitVM2 mode).
    ///
    /// Empty means the operator has not posted any bonds. In Federated mode this
    /// is optional, but in BitVM2 mode the bridge will reject `claim_withdrawal`
    /// unless at least one bond is present.
    ///
    /// Multiple bonds allow dispute isolation: a dispute on bond[0] does not
    /// block withdrawals served by bond[1]. Maximum [`MAX_BONDS_PER_OPERATOR`]
    /// bonds per operator.
    #[serde(default)]
    pub bitvm2_bonds: Vec<BitVM2Bond>,
    /// Whether the bond UTXOs have been verified on Bitcoin L1.
    ///
    /// Set to `true` by `verify_onchain_utxo()` after confirming the UTXOs
    /// exist on-chain with the correct script and value. In BitVM2 mode,
    /// `claim_withdrawal()` requires this to be `true`.
    ///
    /// Applies globally — all bonds must be verified before claiming.
    #[serde(default)]
    pub bond_verified_onchain: bool,
}

/// Maximum number of bonds a single operator can register.
/// Limits complexity while providing dispute isolation.
pub const MAX_BONDS_PER_OPERATOR: usize = 4;

impl OperatorInfo {
    /// Returns `true` if this operator has posted at least one BitVM2 bond.
    ///
    /// Required for claiming withdrawals in BitVM2 mode. The bond ensures
    /// that operators have economic skin-in-the-game and can be slashed
    /// if they front BTC for a fraudulent withdrawal.
    pub fn has_bitvm2_bond(&self) -> bool {
        !self.bitvm2_bonds.is_empty()
    }

    /// Get the first (primary) bond, if any. For backward compatibility.
    pub fn primary_bond(&self) -> Option<&BitVM2Bond> {
        self.bitvm2_bonds.first()
    }

    /// Total bond amount across all registered bonds.
    pub fn total_bond_amount(&self) -> u64 {
        self.bitvm2_bonds.iter().map(|b| b.bond_amount).sum()
    }

    /// Find the first available bond (not under dispute) with sufficient amount.
    /// `disputed_indices` contains indices of bonds currently in dispute.
    pub fn find_available_bond(&self, disputed_indices: &[usize]) -> Option<(usize, &BitVM2Bond)> {
        self.bitvm2_bonds
            .iter()
            .enumerate()
            .find(|(i, _)| !disputed_indices.contains(i))
    }
}

/// A pending reimbursement for an operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reimbursement {
    /// The withdrawal this reimbursement covers.
    pub withdrawal_id: Hash256,
    /// Operator who fronted the BTC.
    pub operator: Address,
    /// Amount to reimburse (satoshis).
    pub amount: u64,
    /// L2 block height when reimbursement becomes eligible.
    pub eligible_at_height: u64,
    /// Current status.
    pub status: ReimbursementStatus,
}

/// Reimbursement status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReimbursementStatus {
    /// Challenge period still active.
    Pending,
    /// Challenge period expired, operator can claim.
    Eligible,
    /// Operator has been reimbursed.
    Claimed,
    /// Fraud detected, reimbursement forfeited.
    Slashed,
}

// ── OperatorManager ─────────────────────────────────────────────────────────

/// Manages liquidity operators who front BTC for withdrawals.
#[derive(Clone, Serialize, Deserialize)]
pub struct OperatorManager {
    /// Registered operators by address.
    operators: HashMap<Address, OperatorInfo>,
    /// Pending reimbursements by withdrawal ID.
    reimbursements: HashMap<Hash256, Reimbursement>,
}

impl OperatorManager {
    /// Create a new empty operator manager.
    pub fn new() -> Self {
        Self {
            operators: HashMap::new(),
            reimbursements: HashMap::new(),
        }
    }

    /// Check if an address is a registered operator.
    pub fn is_registered_operator(&self, address: &Address) -> bool {
        self.operators.contains_key(address)
    }

    /// Check if a reimbursement exists for a given withdrawal ID.
    pub fn has_reimbursement(&self, withdrawal_id: &Hash256) -> bool {
        self.reimbursements.contains_key(withdrawal_id)
    }

    /// Register a new operator.
    pub fn register_operator(&mut self, address: Address, height: u64) -> Result<(), BridgeError> {
        if self.operators.contains_key(&address) {
            return Err(BridgeError::OperatorAlreadyRegistered);
        }

        self.operators.insert(
            address,
            OperatorInfo {
                address,
                total_fronted: 0,
                total_reimbursed: 0,
                active_withdrawals: Vec::new(),
                registered_at: height,
                bitvm2_bonds: Vec::new(),
                bond_verified_onchain: false,
            },
        );

        Ok(())
    }

    /// Deregister an operator, removing them from the active set.
    ///
    /// Preconditions:
    /// - Operator must exist.
    /// - Operator must have no active withdrawals (unresolved claims).
    /// - Operator must have no pending/eligible reimbursements.
    /// - Removing the operator must not drop below `MIN_ACTIVE_OPERATORS`.
    pub fn deregister_operator(
        &mut self,
        address: &Address,
        _current_height: u64,
    ) -> Result<(), BridgeError> {
        // 1. Check operator exists
        let op = self
            .operators
            .get(address)
            .ok_or(BridgeError::OperatorNotFound { address: *address })?;

        // 2. Reject if operator has active withdrawals
        if !op.active_withdrawals.is_empty() {
            return Err(BridgeError::OperatorHasActiveWithdrawals {
                count: op.active_withdrawals.len(),
            });
        }

        // 3. Reject if operator has pending/eligible reimbursements
        let pending_count = self
            .reimbursements
            .values()
            .filter(|r| {
                r.operator == *address
                    && matches!(
                        r.status,
                        ReimbursementStatus::Pending | ReimbursementStatus::Eligible
                    )
            })
            .count();
        if pending_count > 0 {
            return Err(BridgeError::OperatorHasPendingReimbursements {
                count: pending_count,
            });
        }

        // 4. Prevent dropping below minimum operator count
        self.enforce_min_operators(address)?;

        // 5. Remove operator
        self.operators.remove(address);

        Ok(())
    }

    /// Operator claims a withdrawal to front BTC to the user.
    ///
    /// Creates a reimbursement entry that becomes eligible after
    /// `challenge_period` L2 blocks from `current_height`.
    ///
    /// If the operator has a BitVM2 bond registered, exposure limits are
    /// enforced automatically (single withdrawal cap + total exposure cap).
    /// Without a bond, the operator can only claim in Federated mode.
    pub fn claim_withdrawal(
        &mut self,
        operator: Address,
        withdrawal_id: Hash256,
        amount: u64,
        current_height: u64,
        challenge_period: u64,
    ) -> Result<(), BridgeError> {
        // Must be registered
        let op = self
            .operators
            .get(&operator)
            .ok_or(BridgeError::OperatorNotFound { address: operator })?;

        // Defense-in-depth — verify bond is confirmed
        // on-chain before allowing withdrawal claims. The primary check is in
        // bridge.rs, but we enforce it here too to prevent callers from
        // bypassing the bridge-level check.
        if op.has_bitvm2_bond() && !op.bond_verified_onchain {
            return Err(BridgeError::Unauthorized {
                reason: "operator bond not verified on-chain — \
                         call verify_operator_bond_onchain() first"
                    .to_string(),
            });
        }

        // Enforce exposure limits inline if operator has a bond.
        if op.has_bitvm2_bond() {
            // Re-borrow as immutable for the exposure check
            self.check_exposure_limit(&operator, amount)?;

            // Dispute isolation: ensure at least one bond is not under dispute.
            // Future: disputed_indices will come from dispute_game state once
            // the full dispute tracking is wired. For now, we check that at
            // least one bond exists and is verified on-chain (per-bond).
            let all_unverified = op.bitvm2_bonds.iter().all(|b| !b.verified_onchain);
            if all_unverified && op.bitvm2_bonds.iter().any(|_| true) {
                // If global flag is set (legacy path), allow through
                if !op.bond_verified_onchain {
                    return Err(BridgeError::Unauthorized {
                        reason: "no individually verified bonds available — \
                                 verify each bond on-chain first"
                            .to_string(),
                    });
                }
            }
        }

        // Re-borrow as mutable after immutable check
        let op = self
            .operators
            .get_mut(&operator)
            .ok_or(BridgeError::OperatorNotFound { address: operator })?;

        // Can't claim same withdrawal twice
        if self.reimbursements.contains_key(&withdrawal_id) {
            return Err(BridgeError::WithdrawalAlreadyClaimed);
        }

        // Validate amount
        if amount == 0 {
            return Err(BridgeError::InvalidAmount {
                reason: "operator cannot claim zero amount".into(),
            });
        }

        // Record the reimbursement
        let reimbursement = Reimbursement {
            withdrawal_id,
            operator,
            amount,
            eligible_at_height: current_height.saturating_add(challenge_period),
            status: ReimbursementStatus::Pending,
        };

        self.reimbursements.insert(withdrawal_id, reimbursement);
        op.total_fronted = op.total_fronted.saturating_add(amount);
        op.active_withdrawals.push(withdrawal_id);

        Ok(())
    }

    /// Process reimbursement after challenge period expires.
    ///
    /// Returns the reimbursement amount on success.
    pub fn process_reimbursement(
        &mut self,
        withdrawal_id: &Hash256,
        current_height: u64,
    ) -> Result<u64, BridgeError> {
        let reimbursement =
            self.reimbursements
                .get_mut(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        match reimbursement.status {
            ReimbursementStatus::Pending => {
                if current_height < reimbursement.eligible_at_height {
                    return Err(BridgeError::ReimbursementNotEligible {
                        remaining_blocks: reimbursement.eligible_at_height - current_height,
                    });
                }
                reimbursement.status = ReimbursementStatus::Eligible;
                // Fall through to claim
            }
            ReimbursementStatus::Eligible => {
                // Already eligible, proceed to claim
            }
            ReimbursementStatus::Claimed => {
                return Err(BridgeError::AlreadyClaimed {
                    tx_id: *withdrawal_id,
                });
            }
            ReimbursementStatus::Slashed => {
                return Err(BridgeError::InvalidAmount {
                    reason: "reimbursement was slashed due to fraud".into(),
                });
            }
        }

        let amount = reimbursement.amount;
        reimbursement.status = ReimbursementStatus::Claimed;

        // Update operator stats
        if let Some(op) = self.operators.get_mut(&reimbursement.operator) {
            op.total_reimbursed = op.total_reimbursed.saturating_add(amount);
            op.active_withdrawals.retain(|id| id != withdrawal_id);
        }

        Ok(amount)
    }

    /// Slash an operator's reimbursement for proven fraud.
    ///
    /// Returns the slashed amount.
    pub fn slash_operator(&mut self, withdrawal_id: &Hash256) -> Result<u64, BridgeError> {
        let reimbursement =
            self.reimbursements
                .get_mut(withdrawal_id)
                .ok_or(BridgeError::WithdrawalNotFound {
                    tx_id: *withdrawal_id,
                })?;

        match reimbursement.status {
            ReimbursementStatus::Claimed => {
                return Err(BridgeError::AlreadyClaimed {
                    tx_id: *withdrawal_id,
                });
            }
            ReimbursementStatus::Slashed => {
                return Err(BridgeError::InvalidAmount {
                    reason: "reimbursement already slashed".into(),
                });
            }
            ReimbursementStatus::Pending | ReimbursementStatus::Eligible => {
                // Proceed with slashing
            }
        }

        let amount = reimbursement.amount;
        reimbursement.status = ReimbursementStatus::Slashed;

        // Remove from operator's active list
        if let Some(op) = self.operators.get_mut(&reimbursement.operator) {
            op.active_withdrawals.retain(|id| id != withdrawal_id);
            // Reduce bond amount after slash to prevent the operator
            // from claiming more withdrawals than their remaining bond supports.
            // Slash is distributed across all bonds proportionally.
            let total_bond = op.total_bond_amount();
            if total_bond > 0 {
                let mut remaining_slash = amount;
                for bond in &mut op.bitvm2_bonds {
                    let share = (bond.bond_amount as u128 * amount as u128 / total_bond as u128) as u64;
                    let actual = std::cmp::min(share, remaining_slash);
                    bond.bond_amount = bond.bond_amount.saturating_sub(actual);
                    remaining_slash = remaining_slash.saturating_sub(actual);
                }
                // Apply any rounding remainder to the first bond
                if remaining_slash > 0 {
                    if let Some(first) = op.bitvm2_bonds.first_mut() {
                        first.bond_amount = first.bond_amount.saturating_sub(remaining_slash);
                    }
                }
            }
        }

        Ok(amount)
    }

    /// Verify that a bond's script_pubkey matches the expected Taproot output.
    ///
    /// Constructs the full BitVM2 Taproot bond output from the operator's pubkey
    /// and committed state root, then compares the resulting `script_pubkey`
    /// against the one provided in the bond (which should match the on-chain UTXO).
    ///
    /// This is the critical link between L2 bond tracking and L1 UTXO enforcement:
    /// without this check, an operator could register a bond pointing to an
    /// arbitrary UTXO that isn't actually locked in the BitVM2 dispute game scripts.
    ///
    /// Returns `Ok(expected_script_pubkey_bytes)` on success.
    pub fn verify_bond_script(bond: &BitVM2Bond) -> Result<Vec<u8>, BridgeError> {
        let params = taproot::BondParams {
            operator_pubkey: bond.operator_pubkey,
            committed_state_root: bond.committed_state_root,
            // Use the bond's registered height. Currently not embedded in scripts,
            // but if taproot scripts ever bind to height this prevents a silent
            // verification bypass.
            l2_height: bond.registered_height,
            bond_amount: bond.bond_amount,
        };

        let output =
            taproot::build_bond_output(&params).ok_or(BridgeError::InvalidOperatorPubkey)?;

        let expected = output.script_pubkey.as_bytes().to_vec();

        // If the bond already has a script_pubkey set, verify it matches.
        // If it's empty (new bond), the caller should set it from the return value.
        if !bond.expected_script_pubkey.is_empty() && bond.expected_script_pubkey != expected {
            return Err(BridgeError::BondScriptMismatch);
        }

        Ok(expected)
    }

    /// Set a BitVM2 bond for an operator.
    ///
    /// The operator must already be registered. The bond is verified against
    /// the expected Taproot output computed from the operator's pubkey and
    /// committed state root. If the bond's `expected_script_pubkey` is empty,
    /// it is filled in from the computed output.
    ///
    /// ## L1 Verification Flow
    ///
    /// 1. Operator submits bond with their Schnorr pubkey + state root commitment
    /// 2. Bridge computes the expected Taproot `script_pubkey` from those params
    /// 3. L1 watcher confirms the on-chain UTXO's `script_pubkey` matches
    /// 4. Bond is accepted — operator can now claim withdrawals
    ///
    /// Without step 2-3, an operator could register a bond pointing to any
    /// UTXO (even one they don't control or that isn't BitVM2-locked).
    pub fn set_bitvm2_bond(
        &mut self,
        operator: Address,
        mut bond: BitVM2Bond,
    ) -> Result<(), BridgeError> {
        let op = self
            .operators
            .get_mut(&operator)
            .ok_or(BridgeError::OperatorNotFound { address: operator })?;

        // Enforce maximum bonds per operator to limit complexity.
        if op.bitvm2_bonds.len() >= MAX_BONDS_PER_OPERATOR {
            return Err(BridgeError::InvalidAmount {
                reason: format!(
                    "operator already has {} bonds (max {})",
                    op.bitvm2_bonds.len(),
                    MAX_BONDS_PER_OPERATOR,
                ),
            });
        }

        // Check for duplicate UTXO — same bond UTXO cannot be registered twice.
        if op.bitvm2_bonds.iter().any(|b| b.utxo_txid == bond.utxo_txid && b.utxo_vout == bond.utxo_vout) {
            return Err(BridgeError::InvalidAmount {
                reason: "bond UTXO already registered for this operator".into(),
            });
        }

        // Enforce minimum bond amount.
        // Without a minimum, an operator could set a 1-satoshi bond and claim
        // million-satoshi withdrawals, making slashing economically meaningless.
        const MIN_BITVM2_BOND: u64 = 10_000_000; // 0.1 BTC in satoshis
        if bond.bond_amount < MIN_BITVM2_BOND {
            return Err(BridgeError::InvalidAmount {
                reason: format!(
                    "BitVM2 bond amount {} sat is below minimum {} sat (0.1 BTC)",
                    bond.bond_amount, MIN_BITVM2_BOND
                ),
            });
        }

        // Verify the Taproot output and compute expected script_pubkey.
        let expected_script = Self::verify_bond_script(&bond)?;

        // Fill in the expected script_pubkey if not already set.
        if bond.expected_script_pubkey.is_empty() {
            bond.expected_script_pubkey = expected_script;
        }

        op.bitvm2_bonds.push(bond);
        Ok(())
    }

    /// Verify that an on-chain UTXO matches an operator's bond.
    ///
    /// Called by the L1 watcher after fetching the UTXO from Bitcoin. Verifies:
    /// 1. `script_pubkey` matches the expected Taproot output.
    /// 2. UTXO value ≥ the bond's registered `bond_amount`.
    ///
    /// Both checks are necessary:
    /// - Without script check: operator could point to a non-BitVM2 UTXO.
    /// - Without value check: operator could claim a 10 BTC bond with a 1 sat UTXO,
    ///   undermining the economic security assumption.
    ///
    /// This is the "trust-but-verify" step: the operator claims a UTXO is
    /// their bond, and the L1 watcher confirms it's actually locked in the
    /// BitVM2 dispute game scripts with sufficient value.
    pub fn verify_onchain_utxo(
        &mut self,
        operator: &Address,
        onchain_script_pubkey: &[u8],
        onchain_value_sats: u64,
    ) -> Result<(), BridgeError> {
        let op = self
            .operators
            .get(operator)
            .ok_or(BridgeError::OperatorNotFound { address: *operator })?;

        // Find the bond matching the on-chain script_pubkey
        let matching_bond = op
            .bitvm2_bonds
            .iter()
            .find(|b| b.expected_script_pubkey == onchain_script_pubkey);

        let bond = matching_bond
            .ok_or(BridgeError::BondScriptMismatch)?;

        // Verify bond UTXO amount matches declared bond to prevent inflation.
        if onchain_value_sats < bond.bond_amount {
            return Err(BridgeError::InvalidAmount {
                reason: format!(
                    "on-chain UTXO value {} sat < registered bond amount {} sat",
                    onchain_value_sats, bond.bond_amount,
                ),
            });
        }

        // Mark the specific matching bond as verified on-chain.
        // Per-bond verification enables dispute isolation: verifying bond[0]
        // does not mark bond[1] as verified.
        if let Some(op) = self.operators.get_mut(operator) {
            if let Some(bond) = op
                .bitvm2_bonds
                .iter_mut()
                .find(|b| b.expected_script_pubkey == onchain_script_pubkey)
            {
                bond.verified_onchain = true;
            }
            // Update global flag: true when ALL bonds are verified
            op.bond_verified_onchain = op.bitvm2_bonds.iter().all(|b| b.verified_onchain);
        }

        Ok(())
    }

    /// Mark all bonds for an operator as verified on-chain (test helper).
    ///
    /// Production code should use `verify_onchain_utxo()` to verify each bond
    /// individually against the Bitcoin L1 state.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn mark_bonds_verified(&mut self, operator: &Address) {
        if let Some(op) = self.operators.get_mut(operator) {
            for bond in &mut op.bitvm2_bonds {
                bond.verified_onchain = true;
            }
            op.bond_verified_onchain = true;
        }
    }

    /// Get operator info by address.
    pub fn get_operator(&self, address: &Address) -> Option<&OperatorInfo> {
        self.operators.get(address)
    }

    /// Get reimbursement by withdrawal ID.
    pub fn get_reimbursement(&self, withdrawal_id: &Hash256) -> Option<&Reimbursement> {
        self.reimbursements.get(withdrawal_id)
    }

    /// List all pending reimbursements.
    pub fn pending_reimbursements(&self) -> Vec<&Reimbursement> {
        self.reimbursements
            .values()
            .filter(|r| {
                matches!(
                    r.status,
                    ReimbursementStatus::Pending | ReimbursementStatus::Eligible
                )
            })
            .collect()
    }

    /// Number of registered operators.
    pub fn operator_count(&self) -> usize {
        self.operators.len()
    }

    /// All registered operators.
    pub fn all_operators(&self) -> Vec<&OperatorInfo> {
        self.operators.values().collect()
    }

    // ── Economic Specification §8: Exposure Limits & Revenue ────────────

    /// Check if an operator can claim a withdrawal given their bond and exposure.
    ///
    /// Enforces two limits from Economic Specification §8:
    /// 1. Total exposure ≤ bond × OPERATOR_LEVERAGE_FACTOR
    /// 2. Single withdrawal ≤ bond × MAX_WITHDRAWAL_BOND_RATIO_BP / 10000
    ///
    /// Returns `Ok(())` if the claim is within limits, `Err` otherwise.
    pub fn check_exposure_limit(
        &self,
        operator: &Address,
        withdrawal_amount: u64,
    ) -> Result<(), BridgeError> {
        let op = self
            .operators
            .get(operator)
            .ok_or(BridgeError::OperatorNotFound { address: *operator })?;

        let total_bond = op.total_bond_amount();

        if total_bond == 0 {
            return Err(BridgeError::OperatorMissingBond { address: *operator });
        }

        // Single withdrawal cap uses the SMALLEST bond, not the total.
        // Reason: each withdrawal is backed by a single bond. If the smallest
        // bond is 0.1 BTC, allowing a 5 BTC withdrawal would mean the dispute
        // on that bond cannot cover the loss.
        let smallest_bond = op
            .bitvm2_bonds
            .iter()
            .map(|b| b.bond_amount)
            .min()
            .unwrap_or(0);

        // Check single withdrawal cap: amount ≤ smallest_bond × 50%
        let max_single =
            (smallest_bond as u128 * MAX_WITHDRAWAL_BOND_RATIO_BP as u128 / 10_000) as u64;
        if withdrawal_amount > max_single {
            return Err(BridgeError::InvalidAmount {
                reason: format!(
                    "withdrawal {} sat exceeds single-withdrawal cap {} sat ({}bp of {} sat smallest bond)",
                    withdrawal_amount, max_single, MAX_WITHDRAWAL_BOND_RATIO_BP, smallest_bond,
                ),
            });
        }

        // Calculate current exposure (sum of all pending reimbursements).
        let current_exposure: u64 = self
            .reimbursements
            .values()
            .filter(|r| {
                r.operator == *operator
                    && matches!(
                        r.status,
                        ReimbursementStatus::Pending | ReimbursementStatus::Eligible
                    )
            })
            .map(|r| r.amount)
            .fold(0u64, |acc, a| acc.saturating_add(a));

        // Total exposure cap uses total_bond — correct because it covers
        // aggregate risk across all bonds.
        let max_exposure =
            (total_bond as u128 * OPERATOR_LEVERAGE_FACTOR as u128).min(u64::MAX as u128) as u64;
        let new_exposure = current_exposure.saturating_add(withdrawal_amount);
        if new_exposure > max_exposure {
            return Err(BridgeError::InvalidAmount {
                reason: format!(
                    "total exposure {} sat would exceed max {} sat ({}× of {} sat total bond)",
                    new_exposure, max_exposure, OPERATOR_LEVERAGE_FACTOR, total_bond,
                ),
            });
        }

        Ok(())
    }

    /// Calculate operator revenue for a withdrawal (Economic Specification §8.2).
    ///
    /// Returns the fee in satoshis: `withdrawal_amount × PEGOUT_FEE_BP / 10000`
    pub fn calculate_operator_fee(withdrawal_amount: u64) -> u64 {
        (withdrawal_amount as u128 * crate::types::PEGOUT_FEE_BP as u128 / 10_000) as u64
    }

    /// Estimate annual returns for an operator given their bond and daily throughput.
    ///
    /// Returns (annual_revenue_sats, roi_basis_points) where roi_bp = revenue / bond × 10000.
    pub fn estimate_operator_roi(bond_amount: u64, daily_throughput: u64) -> (u64, u64) {
        let daily_revenue = Self::calculate_operator_fee(daily_throughput);
        let annual_revenue = daily_revenue.saturating_mul(365);
        let roi_bp = if bond_amount > 0 {
            (annual_revenue as u128 * 10_000 / bond_amount as u128) as u64
        } else {
            0
        };
        (annual_revenue, roi_bp)
    }

    // ── Operator SLA Enforcement ────────────────────────────────────────

    /// Check operator SLA compliance for pending withdrawals.
    ///
    /// If any pending reimbursement has been waiting longer than
    /// `OPERATOR_SLA_DEADLINE` after its `eligible_at_height` without
    /// the operator claiming it, the operator's bond is penalized
    /// by `OPERATOR_SLA_PENALTY_BP` (5%).
    ///
    /// Returns a list of (operator_address, penalty_amount) pairs.
    pub fn check_operator_sla(&mut self, current_height: u64) -> Vec<(Address, u64)> {
        use crate::types::{OPERATOR_SLA_DEADLINE, OPERATOR_SLA_PENALTY_BP};

        let mut penalties: Vec<(Address, u64)> = Vec::new();

        // Collect overdue reimbursements: still Pending and eligible_at + SLA_DEADLINE
        // has passed, meaning the operator was negligent in claiming.
        let overdue: Vec<(Address, Hash256)> = self
            .reimbursements
            .iter()
            .filter(|(_, r)| {
                r.status == ReimbursementStatus::Pending
                    && current_height >= r.eligible_at_height.saturating_add(OPERATOR_SLA_DEADLINE)
            })
            .map(|(_, r)| (r.operator, r.withdrawal_id))
            .collect();

        for (operator_addr, _withdrawal_id) in &overdue {
            if let Some(op) = self.operators.get(operator_addr) {
                let total_bond = op.total_bond_amount();
                if total_bond > 0 {
                    // Use u128 to prevent overflow: bond_amount × 500 can exceed u64.
                    let penalty =
                        (total_bond as u128 * OPERATOR_SLA_PENALTY_BP as u128 / 10_000) as u64;
                    if penalty > 0 {
                        penalties.push((*operator_addr, penalty));
                    }
                }
            }
        }

        penalties
    }

    /// Apply an SLA penalty to an operator's bond.
    ///
    /// Reduces the operator's `bond_amount` by `penalty_amount`.
    /// Called after `check_operator_sla()` returns breaches.
    pub fn apply_sla_penalty(
        &mut self,
        operator: &Address,
        penalty_amount: u64,
    ) -> Result<(), BridgeError> {
        let op = self
            .operators
            .get_mut(operator)
            .ok_or(BridgeError::OperatorNotFound { address: *operator })?;
        if op.bitvm2_bonds.is_empty() {
            return Err(BridgeError::OperatorMissingBond { address: *operator });
        }
        // Distribute penalty across bonds proportionally (same as slash_operator)
        let total_bond = op.total_bond_amount();
        if total_bond > 0 {
            let mut remaining = penalty_amount;
            for bond in &mut op.bitvm2_bonds {
                let share = (bond.bond_amount as u128 * penalty_amount as u128 / total_bond as u128) as u64;
                let actual = std::cmp::min(share, remaining);
                bond.bond_amount = bond.bond_amount.saturating_sub(actual);
                remaining = remaining.saturating_sub(actual);
            }
            if remaining > 0 {
                if let Some(first) = op.bitvm2_bonds.first_mut() {
                    first.bond_amount = first.bond_amount.saturating_sub(remaining);
                }
            }
        }
        Ok(())
    }

    /// Enforce minimum active operator count.
    ///
    /// Prevents the last `MIN_ACTIVE_OPERATORS` operators from
    /// deregistering, which would leave users stranded with no one to
    /// front BTC for withdrawals.
    ///
    /// Returns `Ok(())` if the operator may exit, `Err` if removing them
    /// would drop below the minimum.
    pub fn enforce_min_operators(&self, _operator: &Address) -> Result<(), BridgeError> {
        use crate::types::MIN_ACTIVE_OPERATORS;

        let active_count = self.operators.len();
        if active_count <= MIN_ACTIVE_OPERATORS {
            return Err(BridgeError::InsufficientOperators {
                required: MIN_ACTIVE_OPERATORS,
                actual: active_count,
            });
        }
        Ok(())
    }
}

impl Default for OperatorManager {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        Address::from_bytes([n; 20])
    }

    fn wid(n: u8) -> Hash256 {
        Hash256::from_bytes([n; 32])
    }

    /// Valid secp256k1 x-only public key (generator point x-coordinate).
    fn valid_operator_pubkey() -> [u8; 32] {
        [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ]
    }

    /// Create a valid BitVM2Bond with taproot verification.
    fn make_bond(bond_amount: u64) -> BitVM2Bond {
        BitVM2Bond {
            utxo_txid: wid(99),
            utxo_vout: 0,
            bond_amount,
            registered_height: 1000,
            operator_pubkey: valid_operator_pubkey(),
            committed_state_root: [0xAA; 32],
            expected_script_pubkey: Vec::new(), // Will be computed by set_bitvm2_bond
            verified_onchain: false,
        }
    }

    #[test]
    fn register_and_get_operator() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        let op = mgr.get_operator(&addr(1)).unwrap();
        assert_eq!(op.address, addr(1));
        assert_eq!(op.registered_at, 1000);
        assert_eq!(op.total_fronted, 0);
        assert_eq!(mgr.operator_count(), 1);
    }

    #[test]
    fn register_duplicate_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        assert!(mgr.register_operator(addr(1), 2000).is_err());
    }

    #[test]
    fn claim_and_reimburse_withdrawal() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        let challenge_period = 28_800u64;
        mgr.claim_withdrawal(addr(1), wid(1), 500_000, 10_000, challenge_period)
            .unwrap();

        let op = mgr.get_operator(&addr(1)).unwrap();
        assert_eq!(op.total_fronted, 500_000);
        assert_eq!(op.active_withdrawals.len(), 1);

        // Too early
        let result = mgr.process_reimbursement(&wid(1), 10_000);
        assert!(result.is_err());

        // After challenge period
        let amount = mgr
            .process_reimbursement(&wid(1), 10_000 + challenge_period)
            .unwrap();
        assert_eq!(amount, 500_000);

        let op = mgr.get_operator(&addr(1)).unwrap();
        assert_eq!(op.total_reimbursed, 500_000);
        assert!(op.active_withdrawals.is_empty());
    }

    #[test]
    fn slash_operator_forfeits_reimbursement() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.claim_withdrawal(addr(1), wid(1), 500_000, 10_000, 28_800)
            .unwrap();

        let slashed = mgr.slash_operator(&wid(1)).unwrap();
        assert_eq!(slashed, 500_000);

        let r = mgr.get_reimbursement(&wid(1)).unwrap();
        assert_eq!(r.status, ReimbursementStatus::Slashed);

        // Can't reimburse after slash
        assert!(mgr.process_reimbursement(&wid(1), 100_000).is_err());

        // Can't double-slash (C1 fix)
        assert!(mgr.slash_operator(&wid(1)).is_err());
    }

    #[test]
    fn duplicate_claim_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.claim_withdrawal(addr(1), wid(1), 500_000, 10_000, 28_800)
            .unwrap();

        // Same withdrawal again
        assert!(
            mgr.claim_withdrawal(addr(1), wid(1), 500_000, 10_000, 28_800)
                .is_err()
        );
    }

    #[test]
    fn unregistered_operator_cannot_claim() {
        let mut mgr = OperatorManager::new();
        assert!(
            mgr.claim_withdrawal(addr(99), wid(1), 500_000, 10_000, 28_800)
                .is_err()
        );
    }

    #[test]
    fn pending_reimbursements_list() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.claim_withdrawal(addr(1), wid(1), 100_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(2), 200_000, 10_000, 28_800)
            .unwrap();

        assert_eq!(mgr.pending_reimbursements().len(), 2);

        // Process one
        mgr.process_reimbursement(&wid(1), 10_000 + 28_800).unwrap();
        assert_eq!(mgr.pending_reimbursements().len(), 1);
    }

    #[test]
    fn multiple_operators() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.register_operator(addr(2), 2000).unwrap();

        mgr.claim_withdrawal(addr(1), wid(1), 100_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(2), wid(2), 200_000, 10_000, 28_800)
            .unwrap();

        assert_eq!(mgr.operator_count(), 2);
        assert_eq!(mgr.get_operator(&addr(1)).unwrap().total_fronted, 100_000);
        assert_eq!(mgr.get_operator(&addr(2)).unwrap().total_fronted, 200_000);
    }

    #[test]
    fn double_reimburse_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.claim_withdrawal(addr(1), wid(1), 100_000, 10_000, 28_800)
            .unwrap();
        mgr.process_reimbursement(&wid(1), 10_000 + 28_800).unwrap();

        // Second reimbursement should fail
        assert!(mgr.process_reimbursement(&wid(1), 10_000 + 28_800).is_err());
    }

    #[test]
    fn operator_manager_default() {
        let mgr = OperatorManager::default();
        assert_eq!(mgr.operator_count(), 0);
        assert!(mgr.pending_reimbursements().is_empty());
    }

    #[test]
    fn zero_amount_claim_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        assert!(
            mgr.claim_withdrawal(addr(1), wid(1), 0, 10_000, 28_800)
                .is_err()
        );
    }

    #[test]
    fn slash_already_slashed_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.claim_withdrawal(addr(1), wid(1), 500_000, 10_000, 28_800)
            .unwrap();

        mgr.slash_operator(&wid(1)).unwrap();
        // Second slash must fail
        assert!(mgr.slash_operator(&wid(1)).is_err());
    }

    #[test]
    fn check_operator_sla_no_overdue() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.claim_withdrawal(addr(1), wid(1), 500_000, 10_000, 28_800)
            .unwrap();

        // Not overdue yet (current_height < eligible + SLA_DEADLINE)
        let penalties = mgr.check_operator_sla(10_000 + 28_800);
        assert!(penalties.is_empty());
    }

    #[test]
    fn check_operator_sla_overdue_with_bond() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // Set bond (1 BTC)
        mgr.set_bitvm2_bond(addr(1), make_bond(100_000_000))
            .unwrap();
        mgr.mark_bonds_verified(&addr(1));

        let challenge_period = 28_800u64;
        mgr.claim_withdrawal(addr(1), wid(1), 500_000, 10_000, challenge_period)
            .unwrap();

        // Way past SLA deadline: eligible_at = 10_000 + 28_800 = 38_800
        // SLA breach at: 38_800 + 28_800 = 67_600
        let penalties = mgr.check_operator_sla(70_000);
        assert_eq!(penalties.len(), 1);
        assert_eq!(penalties[0].0, addr(1));
        // 5% of 1 BTC = 5_000_000 sat
        assert_eq!(penalties[0].1, 5_000_000);
    }

    #[test]
    fn enforce_min_operators_prevents_exit() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.register_operator(addr(2), 1000).unwrap();
        mgr.register_operator(addr(3), 1000).unwrap();

        // With exactly MIN_ACTIVE_OPERATORS (3), no one can exit
        assert!(mgr.enforce_min_operators(&addr(1)).is_err());
    }

    #[test]
    fn enforce_min_operators_allows_exit_above_min() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.register_operator(addr(2), 1000).unwrap();
        mgr.register_operator(addr(3), 1000).unwrap();
        mgr.register_operator(addr(4), 1000).unwrap();

        // With 4 operators (> 3 min), one can exit
        assert!(mgr.enforce_min_operators(&addr(1)).is_ok());
    }

    // ── Tests ─────────────────────────────────────────────

    #[test]
    fn eligible_at_height_no_overflow() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), u64::MAX - 100).unwrap();

        // challenge_period would overflow: u64::MAX - 100 + 200 > u64::MAX
        // Should use saturating_add instead of panicking.
        let result = mgr.claim_withdrawal(addr(1), wid(1), 500_000, u64::MAX - 100, 200);
        assert!(result.is_ok(), "should not overflow on large heights");

        // Verify eligible_at_height is clamped to u64::MAX
        let r = mgr.get_reimbursement(&wid(1)).unwrap();
        assert_eq!(
            r.eligible_at_height,
            u64::MAX,
            "eligible_at_height should be saturated, not wrapped"
        );
    }

    #[test]
    fn sla_penalty_no_overflow_large_bond() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // Set a very large bond to test overflow in penalty calculation.
        // Use make_bond then override amount — taproot verification still works
        // because the pubkey is valid regardless of bond_amount.
        mgr.set_bitvm2_bond(addr(1), make_bond(u64::MAX)).unwrap();
        mgr.mark_bonds_verified(&addr(1));

        // Create a withdrawal that will become overdue.
        let challenge_period = 100u64;
        mgr.claim_withdrawal(addr(1), wid(1), 500_000, 10_000, challenge_period)
            .unwrap();

        // Way past SLA deadline.
        let penalties = mgr.check_operator_sla(10_000 + challenge_period + 100_000);
        assert_eq!(penalties.len(), 1);

        // Penalty = u64::MAX * 500 / 10_000 — must not overflow.
        // u64::MAX * 500 / 10_000 = 922337203685477580 (fits in u64)
        let expected = (u64::MAX as u128 * 500 / 10_000) as u64;
        assert_eq!(
            penalties[0].1, expected,
            "SLA penalty with max bond must use u128 intermediate"
        );
    }

    #[test]
    fn exposure_limit_enforced() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // Set bond (1 BTC)
        mgr.set_bitvm2_bond(addr(1), make_bond(100_000_000))
            .unwrap();
        mgr.mark_bonds_verified(&addr(1));

        // Single withdrawal within cap (50% of 1 BTC = 0.5 BTC)
        assert!(mgr.check_exposure_limit(&addr(1), 50_000_000).is_ok());

        // Single withdrawal exceeding cap
        assert!(mgr.check_exposure_limit(&addr(1), 50_000_001).is_err());

        // Add some exposure
        mgr.claim_withdrawal(addr(1), wid(1), 50_000_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(2), 50_000_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(3), 50_000_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(4), 50_000_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(5), 50_000_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(6), 50_000_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(7), 50_000_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(8), 50_000_000, 10_000, 28_800)
            .unwrap();
        mgr.claim_withdrawal(addr(1), wid(9), 50_000_000, 10_000, 28_800)
            .unwrap();

        // Current exposure: 9 × 50M = 450M (< 500M = 5× bond)
        // Adding 50M more = 500M (exactly at limit) → should pass
        assert!(mgr.check_exposure_limit(&addr(1), 50_000_000).is_ok());

        // Adding one more sat would exceed → should fail
        mgr.claim_withdrawal(addr(1), wid(10), 50_000_000, 10_000, 28_800)
            .unwrap();
        assert!(
            mgr.check_exposure_limit(&addr(1), 1).is_err(),
            "should reject when total exposure exceeds 5× bond"
        );
    }

    #[test]
    fn operator_fee_and_roi() {
        // 1 BTC withdrawal → 0.1% fee = 100,000 sats
        let fee = OperatorManager::calculate_operator_fee(100_000_000);
        assert_eq!(fee, 100_000);

        // 10 BTC bond, 3.57 BTC/day throughput
        let (annual, roi_bp) = OperatorManager::estimate_operator_roi(1_000_000_000, 357_000_000);
        // daily = 357M * 10 / 10000 = 357000
        // annual = 357000 * 365 = 130,305,000
        assert_eq!(annual, 130_305_000);
        assert_eq!(roi_bp, 1303);
    }

    // ── UTXO bond locking tests ────────────────────────────────────

    #[test]
    fn set_bond_computes_expected_script_pubkey() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        mgr.set_bitvm2_bond(addr(1), make_bond(100_000_000))
            .unwrap();

        let op = mgr.get_operator(&addr(1)).unwrap();
        let bond = op.primary_bond().unwrap();

        // expected_script_pubkey should be filled in (34 bytes: OP_1 <32-byte-key>)
        assert_eq!(bond.expected_script_pubkey.len(), 34);
        assert_eq!(bond.expected_script_pubkey[0], 0x51); // OP_1
        assert_eq!(bond.expected_script_pubkey[1], 0x20); // push 32 bytes
    }

    #[test]
    fn set_bond_with_correct_script_pubkey_accepted() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // First, compute the expected script_pubkey
        let mut bond = make_bond(100_000_000);
        let expected = OperatorManager::verify_bond_script(&bond).unwrap();
        bond.expected_script_pubkey = expected;

        // Set with pre-filled script_pubkey — should pass
        mgr.set_bitvm2_bond(addr(1), bond).unwrap();
    }

    #[test]
    fn set_bond_with_wrong_script_pubkey_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // Create a bond with a wrong script_pubkey
        let mut bond = make_bond(100_000_000);
        bond.expected_script_pubkey = vec![0xFF; 34]; // garbage

        let result = mgr.set_bitvm2_bond(addr(1), bond);
        assert!(result.is_err(), "wrong script_pubkey must be rejected");
    }

    #[test]
    fn set_bond_with_invalid_pubkey_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        let mut bond = make_bond(100_000_000);
        bond.operator_pubkey = [0x00; 32]; // invalid x-only pubkey

        let result = mgr.set_bitvm2_bond(addr(1), bond);
        assert!(result.is_err(), "invalid pubkey must be rejected");
    }

    #[test]
    fn verify_bond_script_deterministic() {
        let bond = make_bond(100_000_000);
        let s1 = OperatorManager::verify_bond_script(&bond).unwrap();
        let s2 = OperatorManager::verify_bond_script(&bond).unwrap();
        assert_eq!(s1, s2, "same params must produce same script_pubkey");
    }

    #[test]
    fn verify_bond_script_different_state_roots() {
        let mut bond1 = make_bond(100_000_000);
        bond1.committed_state_root = [0xAA; 32];

        let mut bond2 = make_bond(100_000_000);
        bond2.committed_state_root = [0xBB; 32];

        let s1 = OperatorManager::verify_bond_script(&bond1).unwrap();
        let s2 = OperatorManager::verify_bond_script(&bond2).unwrap();
        assert_ne!(
            s1, s2,
            "different state roots must produce different scripts"
        );
    }

    #[test]
    fn verify_onchain_utxo_matching() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.set_bitvm2_bond(addr(1), make_bond(100_000_000))
            .unwrap();

        let expected_spk = mgr
            .get_operator(&addr(1))
            .unwrap()
            .primary_bond()
            .unwrap()
            .expected_script_pubkey
            .clone();

        // Matching on-chain UTXO with sufficient value → Ok
        assert!(
            mgr.verify_onchain_utxo(&addr(1), &expected_spk, 100_000_000)
                .is_ok()
        );
        // Verify bond is now marked as on-chain verified
        assert!(mgr.get_operator(&addr(1)).unwrap().bond_verified_onchain);
    }

    #[test]
    fn verify_onchain_utxo_mismatch() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.set_bitvm2_bond(addr(1), make_bond(100_000_000))
            .unwrap();

        // Different on-chain script_pubkey → BondScriptMismatch
        let fake_spk = vec![0xDE; 34]; // wrong script
        assert!(
            mgr.verify_onchain_utxo(&addr(1), &fake_spk, 100_000_000)
                .is_err()
        );
    }

    #[test]
    fn verify_onchain_utxo_no_bond() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // No bond set → OperatorMissingBond
        assert!(mgr.verify_onchain_utxo(&addr(1), &[], 0).is_err());
    }

    #[test]
    fn verify_onchain_utxo_insufficient_value() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.set_bitvm2_bond(addr(1), make_bond(100_000_000))
            .unwrap();

        let expected_spk = mgr
            .get_operator(&addr(1))
            .unwrap()
            .primary_bond()
            .unwrap()
            .expected_script_pubkey
            .clone();

        // On-chain UTXO value too low → InvalidAmount
        assert!(
            mgr.verify_onchain_utxo(&addr(1), &expected_spk, 99_999_999)
                .is_err(),
            "UTXO with less value than bond must be rejected"
        );
    }

    #[test]
    fn set_bond_duplicate_utxo_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.set_bitvm2_bond(addr(1), make_bond(100_000_000))
            .unwrap();

        // Trying to add same UTXO again → should fail (duplicate UTXO)
        let result = mgr.set_bitvm2_bond(addr(1), make_bond(200_000_000));
        assert!(
            result.is_err(),
            "duplicate bond UTXO must be rejected"
        );
    }

    #[test]
    fn set_bond_multi_bond_up_to_max() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // Add MAX_BONDS_PER_OPERATOR bonds with different UTXOs
        for i in 0..MAX_BONDS_PER_OPERATOR {
            let mut bond = make_bond(100_000_000);
            bond.utxo_txid = wid(50 + i as u8);
            mgr.set_bitvm2_bond(addr(1), bond).unwrap();
        }

        let op = mgr.get_operator(&addr(1)).unwrap();
        assert_eq!(op.bitvm2_bonds.len(), MAX_BONDS_PER_OPERATOR);
        assert_eq!(op.total_bond_amount(), 100_000_000 * MAX_BONDS_PER_OPERATOR as u64);

        // 5th bond should be rejected
        let mut extra = make_bond(100_000_000);
        extra.utxo_txid = wid(99);
        let result = mgr.set_bitvm2_bond(addr(1), extra);
        assert!(result.is_err(), "5th bond must be rejected");
    }

    // ── Tests: Bond enforcement in claim_withdrawal ──

    #[test]
    fn claim_withdrawal_enforces_exposure_with_bond() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // Set a bond of 1 BTC (100M sat)
        mgr.set_bitvm2_bond(addr(1), make_bond(100_000_000))
            .unwrap();
        mgr.mark_bonds_verified(&addr(1));

        // Single withdrawal exceeding 50% of bond (50M+1 sat) should fail
        let result = mgr.claim_withdrawal(addr(1), wid(1), 50_000_001, 10_000, 28_800);
        assert!(
            result.is_err(),
            "claim_withdrawal should enforce single-withdrawal cap when bond exists"
        );

        // Within cap should succeed
        mgr.claim_withdrawal(addr(1), wid(2), 50_000_000, 10_000, 28_800)
            .unwrap();
    }

    #[test]
    fn claim_withdrawal_no_enforcement_without_bond() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // No bond set — exposure limits should NOT be enforced
        // (federated mode doesn't require bonds)
        let result = mgr.claim_withdrawal(addr(1), wid(1), 999_999_999, 10_000, 28_800);
        assert!(
            result.is_ok(),
            "claim_withdrawal without bond should not enforce exposure limits"
        );
    }

    #[test]
    fn bond_script_matches_taproot_directly() {
        // Cross-validate: building via taproot module directly must produce
        // the same script_pubkey as going through operator verification.
        let bond = make_bond(50_000_000);
        let operator_script = OperatorManager::verify_bond_script(&bond).unwrap();

        let params = taproot::BondParams {
            operator_pubkey: bond.operator_pubkey,
            committed_state_root: bond.committed_state_root,
            l2_height: 0,
            bond_amount: bond.bond_amount,
        };
        let taproot_output = taproot::build_bond_output(&params).unwrap();
        let taproot_script = taproot_output.script_pubkey.as_bytes().to_vec();

        assert_eq!(
            operator_script, taproot_script,
            "operator verification and direct taproot build must agree"
        );
    }

    // ── Deregister operator tests ─────────────────────────────

    #[test]
    fn test_deregister_operator() {
        let mut mgr = OperatorManager::new();
        // Register 4 operators (above MIN_ACTIVE_OPERATORS = 3)
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.register_operator(addr(2), 1000).unwrap();
        mgr.register_operator(addr(3), 1000).unwrap();
        mgr.register_operator(addr(4), 1000).unwrap();
        assert_eq!(mgr.operator_count(), 4);

        // Deregister operator 4 (no active withdrawals, above minimum)
        mgr.deregister_operator(&addr(4), 2000).unwrap();
        assert_eq!(mgr.operator_count(), 3);
        assert!(mgr.get_operator(&addr(4)).is_none());

        // Cannot deregister again (not found)
        assert!(mgr.deregister_operator(&addr(4), 2001).is_err());

        // Cannot deregister below minimum (3 operators, min is 3)
        assert!(mgr.deregister_operator(&addr(1), 2002).is_err());
    }

    #[test]
    fn test_deregister_with_active_withdrawals_rejected() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();
        mgr.register_operator(addr(2), 1000).unwrap();
        mgr.register_operator(addr(3), 1000).unwrap();
        mgr.register_operator(addr(4), 1000).unwrap();

        // Operator 4 claims a withdrawal
        mgr.claim_withdrawal(addr(4), wid(1), 500_000, 10_000, 28_800)
            .unwrap();

        // Cannot deregister with active withdrawal
        let result = mgr.deregister_operator(&addr(4), 20_000);
        assert!(
            result.is_err(),
            "operator with active withdrawals must not deregister"
        );
    }

    // ── smallest_bond exposure cap tests ─────────────────────

    #[test]
    fn exposure_cap_uses_smallest_bond_for_single_withdrawal() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // Add two bonds: small (0.1 BTC) + large (10 BTC)
        let mut small_bond = make_bond(10_000_000); // 0.1 BTC
        small_bond.utxo_txid = wid(50);
        mgr.set_bitvm2_bond(addr(1), small_bond).unwrap();

        let mut large_bond = make_bond(1_000_000_000); // 10 BTC
        large_bond.utxo_txid = wid(51);
        large_bond.committed_state_root = [0xBB; 32];
        mgr.set_bitvm2_bond(addr(1), large_bond).unwrap();
        mgr.mark_bonds_verified(&addr(1));

        // Single withdrawal cap = 50% of smallest bond = 50% of 0.1 BTC = 0.05 BTC
        assert!(
            mgr.check_exposure_limit(&addr(1), 5_000_000).is_ok(),
            "5M sat (50% of smallest 10M bond) should be allowed"
        );
        assert!(
            mgr.check_exposure_limit(&addr(1), 5_000_001).is_err(),
            "5M+1 sat should exceed single-withdrawal cap based on smallest bond"
        );

        // Total exposure cap still uses total bond (10.1 BTC × 5 = 50.5 BTC)
        // So total exposure of 50 BTC should be fine
        // (but single cap prevents it from being one big withdrawal)
    }

    #[test]
    fn per_bond_verification_only_marks_matched_bond() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        // Add two bonds with different UTXOs and different state roots
        let mut bond1 = make_bond(100_000_000);
        bond1.utxo_txid = wid(50);
        mgr.set_bitvm2_bond(addr(1), bond1).unwrap();

        let mut bond2 = make_bond(100_000_000);
        bond2.utxo_txid = wid(51);
        bond2.committed_state_root = [0xBB; 32];
        mgr.set_bitvm2_bond(addr(1), bond2).unwrap();

        // Get first bond's script_pubkey
        let spk1 = mgr
            .get_operator(&addr(1))
            .unwrap()
            .bitvm2_bonds[0]
            .expected_script_pubkey
            .clone();

        // Verify only the first bond
        mgr.verify_onchain_utxo(&addr(1), &spk1, 100_000_000).unwrap();

        let op = mgr.get_operator(&addr(1)).unwrap();
        // First bond verified, second not
        assert!(op.bitvm2_bonds[0].verified_onchain);
        assert!(!op.bitvm2_bonds[1].verified_onchain);
        // Global flag should be false (not ALL bonds verified)
        assert!(!op.bond_verified_onchain, "global flag should be false until all bonds verified");
    }

    #[test]
    fn per_bond_verification_all_verified_sets_global() {
        let mut mgr = OperatorManager::new();
        mgr.register_operator(addr(1), 1000).unwrap();

        let mut bond1 = make_bond(100_000_000);
        bond1.utxo_txid = wid(50);
        mgr.set_bitvm2_bond(addr(1), bond1).unwrap();

        // Use different committed_state_root to get a different expected_script_pubkey
        let mut bond2 = make_bond(100_000_000);
        bond2.utxo_txid = wid(51);
        bond2.committed_state_root = [0xBB; 32];
        mgr.set_bitvm2_bond(addr(1), bond2).unwrap();

        let spk1 = mgr.get_operator(&addr(1)).unwrap().bitvm2_bonds[0]
            .expected_script_pubkey.clone();
        let spk2 = mgr.get_operator(&addr(1)).unwrap().bitvm2_bonds[1]
            .expected_script_pubkey.clone();
        assert_ne!(spk1, spk2, "bonds should have different script_pubkeys");

        mgr.verify_onchain_utxo(&addr(1), &spk1, 100_000_000).unwrap();
        mgr.verify_onchain_utxo(&addr(1), &spk2, 100_000_000).unwrap();

        let op = mgr.get_operator(&addr(1)).unwrap();
        assert!(op.bitvm2_bonds[0].verified_onchain);
        assert!(op.bitvm2_bonds[1].verified_onchain);
        assert!(op.bond_verified_onchain, "global flag should be true when all bonds verified");
    }
}
