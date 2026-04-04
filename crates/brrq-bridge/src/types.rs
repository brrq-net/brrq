//! Bridge types for peg-in/peg-out operations.

use brrq_crypto::hash::Hash256;
use brrq_types::Address;
use serde::{Deserialize, Serialize};

/// Peg-in fee: 0.05% = 5 basis points.
pub const PEGIN_FEE_BP: u64 = 5;

/// Peg-out fee: 0.1% = 10 basis points.
pub const PEGOUT_FEE_BP: u64 = 10;

/// Required Bitcoin confirmations for a peg-in.
pub const REQUIRED_CONFIRMATIONS: u32 = 6;

/// Challenge period for peg-out in MVP federated bridge (in L1 blocks, ~24 hours).
///
/// The whitepaper §6.4 specifies a ~2-week challenge period for the BitVM2
/// bridge. The MVP federated bridge uses a shorter 24-hour period because
/// security relies on the 5-of-9 federation quorum, not on-chain dispute resolution.
///
/// See [`BITVM2_CHALLENGE_PERIOD_BLOCKS`] for the future BitVM2 period.
pub const CHALLENGE_PERIOD_BLOCKS: u64 = 144;

/// Challenge period for the BitVM2 bridge (~2 weeks).
///
/// Per whitepaper §6.4: "challenge period (~2 weeks)" — the BitVM2 dispute game requires
/// a longer window because any observer must be able to submit a Challenge/Disprove
/// transaction. This constant is defined now for forward-compatibility.
pub const BITVM2_CHALLENGE_PERIOD_BLOCKS: u64 = 2016; // 14 days × 144 blocks/day

/// Minimum deposit amount in satoshis (0.001 BTC = 100,000 sat).
pub const MIN_DEPOSIT_AMOUNT: u64 = 100_000;

/// Maximum single deposit amount in satoshis (10 BTC).
pub const MAX_DEPOSIT_AMOUNT: u64 = 1_000_000_000;

/// Minimum withdrawal amount in satoshis (0.001 BTC = 100,000 sat).
/// Without this, dust withdrawals (< 1000 sat) incur zero fee because
/// `amount * PEGOUT_FEE_BP / 10_000` truncates to 0, enabling free spam.
pub const MIN_WITHDRAWAL_AMOUNT: u64 = 100_000;

/// Maximum single withdrawal amount in satoshis (10 BTC).
pub const MAX_WITHDRAWAL_AMOUNT: u64 = 1_000_000_000;

/// Total bridge cap in satoshis (100 BTC).
///
/// Once total_locked reaches this cap, new deposits are rejected until
/// withdrawals free capacity. This protects against unlimited exposure
/// during the initial mainnet launch.
pub const TOTAL_BRIDGE_CAP: u64 = 10_000_000_000;

/// Maximum daily volume per L2 address in satoshis (50 BTC).
///
/// Prevents a single address from monopolizing bridge capacity.
/// Resets every `DAILY_VOLUME_WINDOW_BLOCKS` L2 blocks.
pub const MAX_DAILY_VOLUME_PER_ADDRESS: u64 = 5_000_000_000;

/// Daily volume window in L2 blocks (~24 hours at 3s/block).
pub const DAILY_VOLUME_WINDOW_BLOCKS: u64 = 28_800;

/// Approximate ratio of L1 block time to L2 block time.
///
/// L1 ≈ 600 seconds/block, L2 ≈ 3 seconds/block → ratio ≈ 200.
/// Used to convert L1 challenge periods to L2 block equivalents.
pub const L1_TO_L2_BLOCK_RATIO: u64 = 200;

// ═══════════════════════════════════════════════════════════════
// §4.4 Sovereign Deposit Recovery Constants
// ═══════════════════════════════════════════════════════════════

/// OP_CLTV timelock for sovereign deposit recovery (in L1 blocks).
///
/// Yellow Paper §4.4: After 2016 L1 blocks (~2 weeks), the user can
/// broadcast the pre-signed refund transaction to recover their original
/// deposit if the committee is censoring or has disappeared.
pub const DEPOSIT_RECOVERY_TIMELOCK_L1: u64 = 2016;

/// Hardcoded L1 block height at which the
/// federation is automatically dissolved and replaced by BitVM2.
///
/// After this height:
/// - `ChallengeMode` switches to `BitVM2` unconditionally
/// - Federation attestations are rejected
/// - All withdrawals require STARK proof + BitVM2 dispute resolution
///
/// This is a constitutional guarantee: no governance proposal can extend
/// the federation's lifetime beyond this point. The transition is
/// deterministic and cannot be stopped.
///
/// ~6 months from estimated mainnet launch.
/// 880,000 is approximately Bitcoin block height in early 2026.
/// Adjust before mainnet based on actual launch date.
pub const FEDERATION_SUNSET_L1_HEIGHT: u64 = 880_000;

/// Deposit (peg-in) request: BTC → brqBTC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositRequest {
    /// Bitcoin transaction ID.
    pub btc_tx_id: Hash256,
    /// Bitcoin output index.
    pub btc_vout: u32,
    /// Amount in satoshis.
    pub amount: u64,
    /// Destination address on Brrq L2.
    pub recipient: Address,
    /// Number of Bitcoin confirmations.
    pub confirmations: u32,
    /// Status of the deposit.
    pub status: DepositStatus,
    /// SPV cryptographic proof (if provided instead of federation attestation)
    pub spv_proof: Option<brrq_bitcoin::spv::SpvProof>,
    /// §4.4 Sovereign Deposit Recovery: Pre-signed refund metadata.
    ///
    /// Generated at deposit time. The committee pre-signs a timelocked
    /// refund transaction: OP_CLTV(deposit_l1_height + 2016) → user_address.
    /// The user retains this off-chain. If the committee censors or
    /// disappears, the user broadcasts after the timelock expires.
    ///
    /// **Constraint:** Recovers the original deposit only, not L2 state.
    #[serde(default)]
    pub recovery_info: Option<DepositRecoveryInfo>,
}

/// §4.4 Pre-signed refund information for sovereign deposit recovery.
///
/// This is generated during peg-in and handed to the user off-chain.
/// The bridge stores a record for accounting; the user stores the
/// actual signed transaction bytes independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositRecoveryInfo {
    /// L1 block height when the deposit was made.
    pub deposit_l1_height: u64,
    /// L1 block height after which the refund can be broadcast.
    /// = deposit_l1_height + DEPOSIT_RECOVERY_TIMELOCK_L1
    pub refund_available_at_l1: u64,
    /// The Bitcoin address to which the refund will be sent.
    pub refund_btc_address: String,
    /// Hash of the pre-signed refund transaction (for verification).
    /// The actual signed transaction is held by the user off-chain.
    pub refund_tx_hash: Hash256,
    /// Whether this recovery path has been exercised (refund broadcast).
    pub recovered: bool,
}

/// Deposit status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStatus {
    /// Waiting for sufficient Bitcoin confirmations.
    Pending,
    /// Confirmed on L1, brqBTC minted on L2.
    Confirmed,
    /// Finalized (included in L2 state root committed to L1).
    Finalized,
}

impl DepositStatus {
    /// State machine guard — only legal one-way transitions allowed.
    /// Prevents code bugs from transitioning Finalized → Pending (double-minting).
    pub fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Pending, Self::Confirmed) | (Self::Confirmed, Self::Finalized)
        )
    }
}

/// Withdrawal (peg-out) request: brqBTC → BTC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// Unique withdrawal ID (L2 tx hash).
    pub withdrawal_id: Hash256,
    /// Requesting address on Brrq L2.
    pub sender: Address,
    /// Amount in satoshis (before fees).
    pub amount: u64,
    /// Bitcoin destination address (as string for simplicity).
    pub btc_destination: String,
    /// Fee deducted (in satoshis).
    pub fee: u64,
    /// L2 block height when withdrawal was requested.
    pub request_height: u64,
    /// Status.
    pub status: WithdrawalStatus,
    /// Whether a valid ZK-STARK proof has verified this withdrawal.
    pub is_verified: bool,
    /// Height of the committed state root used as the proof's initial_state_root.
    /// Set during STARK verification; used to freeze withdrawals if that root
    /// is later invalidated by an InvalidStateRoot challenge.
    #[serde(default)]
    pub verified_at_height: Option<u64>,
    /// Challenge period in L2 blocks, locked at request time.
    ///
    /// Stores the challenge period that was active when this withdrawal was
    /// created. Prevents mode transitions (Federated→BitVM2 or vice versa)
    /// from retroactively extending or shortening in-flight withdrawals'
    /// challenge periods.
    pub challenge_period_l2: u64,
}

/// Withdrawal status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WithdrawalStatus {
    /// Waiting for challenge period to expire.
    Pending,
    /// Challenge period expired, ready for execution.
    Ready,
    /// Bitcoin transaction broadcast.
    Executing,
    /// Bitcoin transaction confirmed, withdrawal complete.
    Completed,
    /// Challenged and rejected.
    Challenged,
    /// Force-exited by user after operator SLA breach.
    ForceExited,
    /// Frozen due to an InvalidStateRoot challenge being proven.
    /// The committed state root this withdrawal was verified against has been
    /// invalidated. Withdrawal cannot proceed until re-verified against a
    /// valid state root.
    Frozen,
}

impl WithdrawalStatus {
    /// Validate that a state transition is legal.
    ///
    /// Valid transitions:
    ///   Pending   → Ready (STARK verified)
    ///   Pending   → Challenged
    ///   Pending   → ForceExited (emergency exit, requires is_verified)
    ///   Pending   → Frozen (InvalidStateRoot proven)
    ///   Ready     → Executing (BTC transaction broadcast)
    ///   Ready     → Completed (challenge period expired + authorization)
    ///   Ready     → Challenged
    ///   Ready     → ForceExited (force exit / emergency exit)
    ///   Ready     → Frozen (InvalidStateRoot proven)
    ///   Executing → Completed (BTC transaction confirmed)
    ///
    /// Terminal states (Completed, Challenged, ForceExited) cannot transition.
    /// Frozen can transition back to Pending (recovery path).
    /// Executing is NOT terminal — it transitions to Completed.
    pub fn can_transition_to(self, target: Self) -> bool {
        matches!(
            (self, target),
            (Self::Pending, Self::Ready)
                | (Self::Pending, Self::Challenged)
                | (Self::Pending, Self::ForceExited)
                | (Self::Pending, Self::Frozen)
                | (Self::Ready, Self::Executing)
                | (Self::Ready, Self::Completed)
                | (Self::Ready, Self::Challenged)
                | (Self::Ready, Self::ForceExited)
                | (Self::Ready, Self::Frozen)
                | (Self::Executing, Self::Completed)
                // Allow frozen withdrawals to be re-verified.
                // After the fraudulent state root is removed, users can
                // re-submit their withdrawal proof against a valid root.
                | (Self::Frozen, Self::Pending)
        )
    }

    /// Returns true if this is a terminal (non-reversible) status.
    /// Frozen is NOT terminal -- it can recover to Pending.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Challenged | Self::ForceExited
        )
    }
}

// ═══════════════════════════════════════════════════════════════
// Force Exit + Operator SLA Constants
// ═══════════════════════════════════════════════════════════════

/// Timeout in L2 blocks before a user can force-exit without operator.
/// ~7 days at 3s/block = 201,600 blocks.
/// If no operator processes a withdrawal within this period, the user can
/// trigger a direct exit via the BitVM2 escape hatch.
pub const FORCE_EXIT_TIMEOUT: u64 = 201_600;

/// Deadline in L2 blocks for an operator to process a withdrawal.
/// ~1 day at 3s/block = 28,800 blocks.
pub const OPERATOR_SLA_DEADLINE: u64 = 28_800;

/// Minimum number of active operators required.
/// Prevents the last operators from exiting and leaving users stranded.
pub const MIN_ACTIVE_OPERATORS: usize = 3;

/// Penalty in basis points for operator SLA breach (5%).
pub const OPERATOR_SLA_PENALTY_BP: u64 = 500;

// ═══════════════════════════════════════════════════════════════
// Challenge Anti-Spam Constants
// ═══════════════════════════════════════════════════════════════

/// Maximum concurrent pending challenges per challenger address.
///
/// Prevents a single address from flooding the challenge system with spam
/// challenges that force the operator to generate expensive STARK proofs.
/// Each challenge consumes operator resources even if ultimately dismissed.
///
/// In a production system, this would be complemented by a challenge
/// deposit/bond that is forfeited if the challenge is dismissed, providing
/// economic disincentives against spam.
pub const MAX_PENDING_PER_CHALLENGER: usize = 3;

/// Minimum L2 blocks between challenge submissions from the same address.
///
/// Rate-limits challenge frequency to prevent burst-spam attacks where a
/// challenger submits many challenges in rapid succession within the same
/// block batch.
pub const CHALLENGE_COOLDOWN_BLOCKS: u64 = 100;

// ═══════════════════════════════════════════════════════════════
// Bridge Escrow Hold Period
// ═══════════════════════════════════════════════════════════════

/// Escrow hold period in L2 blocks.
/// Operator bond remains locked for this duration after they front BTC,
/// covering the full BitVM2 challenge period + safety margin.
/// ~16 days at 3s/block = 460,800 blocks.
pub const ESCROW_HOLD_PERIOD: u64 = 460_800;

// ═══════════════════════════════════════════════════════════════
// Emergency Exit Types
// ═══════════════════════════════════════════════════════════════

/// Status of an emergency exit process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmergencyExitStatus {
    /// Emergency exit initiated, waiting for timelock.
    Initiated,
    /// Timelock expired, exit can be claimed.
    Claimable,
    /// Exit claimed and BTC released (set by `claim_emergency_exit()`).
    Claimed,
    /// Exit was cancelled — operator resumed service (set by `cancel_emergency_exit()`).
    Cancelled,
}

/// Validate a Bitcoin address with full checksum verification.
///
/// Uses `bitcoin::Address` for Bech32 checksum (bc1/tb1) and
/// Base58Check (legacy) validation so malformed addresses are rejected.
pub fn validate_btc_address(addr: &str) -> Result<(), String> {
    if addr.is_empty() {
        return Err("empty Bitcoin address".into());
    }
    use std::str::FromStr;
    bitcoin::Address::from_str(addr)
        .map_err(|e| format!("invalid Bitcoin address: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pegin_fee() {
        let amount = 10_000_000u64; // 0.1 BTC
        let fee = amount * PEGIN_FEE_BP / 10_000;
        assert_eq!(fee, 5_000); // 0.05% of 0.1 BTC = 5000 sat
    }

    #[test]
    fn test_pegout_fee() {
        let amount = 10_000_000u64;
        let fee = amount * PEGOUT_FEE_BP / 10_000;
        assert_eq!(fee, 10_000); // 0.1% of 0.1 BTC = 10000 sat
    }

    #[test]
    fn test_deposit_lifecycle() {
        let deposit = DepositRequest {
            btc_tx_id: Hash256::ZERO,
            btc_vout: 0,
            amount: 100_000,
            recipient: Address::ZERO,
            confirmations: 0,
            status: DepositStatus::Pending,
            spv_proof: None,
            recovery_info: None,
        };
        assert_eq!(deposit.status, DepositStatus::Pending);
    }

    #[test]
    fn test_prot4_withdrawal_state_transitions() {
        use WithdrawalStatus::*;

        // Valid transitions
        assert!(Pending.can_transition_to(Ready));
        assert!(Pending.can_transition_to(Challenged));
        assert!(Pending.can_transition_to(ForceExited));
        assert!(Ready.can_transition_to(Executing));
        assert!(Ready.can_transition_to(Completed));
        assert!(Ready.can_transition_to(Challenged));
        assert!(Ready.can_transition_to(ForceExited));
        assert!(Executing.can_transition_to(Completed));

        // Invalid transitions — terminal states cannot transition
        assert!(!Completed.can_transition_to(Ready));
        assert!(!Completed.can_transition_to(Pending));
        assert!(!Completed.can_transition_to(ForceExited));
        assert!(!ForceExited.can_transition_to(Completed));
        assert!(!Challenged.can_transition_to(Ready));

        // Invalid transitions — backwards
        assert!(!Ready.can_transition_to(Pending));
        assert!(!Completed.can_transition_to(Completed));
        assert!(!Executing.can_transition_to(Ready));
        assert!(!Executing.can_transition_to(Pending));

        // Terminal check
        assert!(Completed.is_terminal());
        assert!(Challenged.is_terminal());
        assert!(ForceExited.is_terminal());
        assert!(!Pending.is_terminal());
        assert!(!Ready.is_terminal());
        assert!(!Executing.is_terminal());
    }

    #[test]
    fn test_withdrawal_has_challenge_period() {
        let w = WithdrawalRequest {
            withdrawal_id: Hash256::ZERO,
            sender: Address::ZERO,
            amount: 100_000,
            btc_destination: "bc1qtest".into(),
            fee: 100,
            request_height: 0,
            status: WithdrawalStatus::Pending,
            is_verified: false,
            verified_at_height: None,
            challenge_period_l2: CHALLENGE_PERIOD_BLOCKS * L1_TO_L2_BLOCK_RATIO,
        };
        assert_eq!(
            w.challenge_period_l2,
            CHALLENGE_PERIOD_BLOCKS * L1_TO_L2_BLOCK_RATIO
        );
    }

    #[test]
    fn test_deposit_recovery_info() {
        let info = DepositRecoveryInfo {
            deposit_l1_height: 800_000,
            refund_available_at_l1: 800_000 + DEPOSIT_RECOVERY_TIMELOCK_L1,
            refund_btc_address: "bc1qtest".into(),
            refund_tx_hash: Hash256::ZERO,
            recovered: false,
        };
        assert_eq!(info.refund_available_at_l1, 802_016);
        assert!(!info.recovered);
    }

    #[test]
    fn test_deposit_recovery_timelock_constant() {
        // 2016 L1 blocks ≈ 2 weeks (14 days × 144 blocks/day)
        assert_eq!(DEPOSIT_RECOVERY_TIMELOCK_L1, 2016);
    }
}
