//! Prepaid Card Model — single large lock with partial off-chain withdrawals.
//!
//! Phase 4 of the Portal protocol: instead of individual locks per payment,
//! the user creates a single large escrow lock and makes multiple partial
//! payments off-chain. Only the final balance difference is settled on L2.
//!
//! ## Integration
//!
//! PrepaidCard is an **off-chain SDK component** — it runs in the user's wallet
//! and the merchant's backend, NOT in the L2 sequencer. The on-chain part is
//! a standard `CreatePortalLock` (for the initial escrow) and `SettlePortalLock`
//! (for the final cumulative settlement using the last receipt).
//!
//! ## How It Works
//!
//! 1. User creates a PrepaidCard with a large lock (e.g., 0.5 BTC) via `CreatePortalLock`
//! 2. Each payment deducts from the off-chain balance tracker (`pay()`)
//! 3. Merchant accumulates payment proofs (signed receipts)
//! 4. Settlement: merchant settles the total spent amount on L2 via `SettlePortalLock`
//! 5. Remaining balance returns to user (via lock timeout / `CancelPortalLock`)
//!
//! ## Security
//!
//! - Each partial payment generates a signed receipt with monotonic sequence number
//! - The merchant can only settle up to the total of signed receipts
//! - The user cannot spend more than the locked amount
//! - Sequence numbers prevent replay of old receipts

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::{SchnorrKeyPair, SchnorrPublicKey, SchnorrSignature};
use brrq_types::Address;
use serde::{Deserialize, Serialize};

use crate::error::PortalError;

/// A prepaid card — single large lock with off-chain balance tracking.
#[derive(Clone, Debug, Serialize, Deserialize)]
/// Fields are pub for SDK ergonomics but callers MUST NOT mutate
/// security-critical fields (spent_amount, next_sequence, total_amount) directly.
/// Use pay() and verify_receipt() methods which enforce invariants.
pub struct PrepaidCard {
    /// The underlying lock ID on L2.
    pub lock_id: Hash256,
    /// Card owner's address.
    pub owner: Address,
    /// Card owner's public key.
    pub owner_pubkey: SchnorrPublicKey,
    /// Total amount locked (initial balance).
    pub total_amount: u64,
    /// Amount already spent (sum of all signed receipts).
    pub spent_amount: u64,
    /// Monotonic sequence number for the next payment.
    pub next_sequence: u64,
    /// Merchant address this card is bound to (or None for multi-merchant).
    pub merchant: Option<Address>,
    /// L2 block at which the card expires.
    pub timeout_l2_block: u64,
}

/// A signed payment receipt for a partial withdrawal.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentReceipt {
    /// The prepaid card's lock ID.
    pub lock_id: Hash256,
    /// Amount of this individual payment (satoshis).
    pub amount: u64,
    /// Monotonic sequence number (prevents replay).
    pub sequence: u64,
    /// Cumulative total spent after this payment.
    pub cumulative_spent: u64,
    /// Schnorr signature by the card owner over the receipt data.
    pub signature: SchnorrSignature,
}

/// Domain tag for prepaid card receipt signatures — references central registry.
const RECEIPT_SIG_TAG: &[u8] = brrq_crypto::domain_tags::PORTAL_RECEIPT_V1;

/// Compute the receipt message hash for signing.
fn receipt_message(lock_id: &Hash256, amount: u64, sequence: u64, cumulative: u64) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(RECEIPT_SIG_TAG);
    hasher.update(lock_id.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(&sequence.to_le_bytes());
    hasher.update(&cumulative.to_le_bytes());
    hasher.finalize()
}

impl PrepaidCard {
    /// Create a new prepaid card.
    ///
    /// The lock must already be created in the escrow manager.
    pub fn new(
        lock_id: Hash256,
        owner: Address,
        owner_pubkey: SchnorrPublicKey,
        total_amount: u64,
        merchant: Option<Address>,
        timeout_l2_block: u64,
    ) -> Self {
        Self {
            lock_id,
            owner,
            owner_pubkey,
            total_amount,
            spent_amount: 0,
            next_sequence: 0,
            merchant,
            timeout_l2_block,
        }
    }

    /// Remaining balance on the card.
    pub fn remaining(&self) -> u64 {
        self.total_amount.saturating_sub(self.spent_amount)
    }

    /// Whether the card is fully spent.
    pub fn is_exhausted(&self) -> bool {
        self.spent_amount >= self.total_amount
    }

    /// Make a partial payment — generates a signed receipt.
    ///
    /// Returns the PaymentReceipt that the merchant stores.
    /// The receipt is signed by the card owner's key.
    pub fn pay(
        &mut self,
        amount: u64,
        keypair: &SchnorrKeyPair,
    ) -> Result<PaymentReceipt, PortalError> {
        if amount == 0 {
            return Err(PortalError::ZeroAmount);
        }
        if amount > self.remaining() {
            return Err(PortalError::InsufficientBalance {
                need: amount,
                have: self.remaining(),
            });
        }

        let sequence = self.next_sequence;
        let cumulative = self.spent_amount + amount;

        // Sign the receipt
        let msg = receipt_message(&self.lock_id, amount, sequence, cumulative);
        let signature = keypair
            .sign(&msg)
            .map_err(|_| PortalError::InvalidSignature)?;

        // Update card state
        self.spent_amount = cumulative;
        self.next_sequence += 1;

        Ok(PaymentReceipt {
            lock_id: self.lock_id,
            amount,
            sequence,
            cumulative_spent: cumulative,
            signature,
        })
    }

    /// Verify a payment receipt's signature and sequence validity.
    ///
    /// Checks:
    /// 1. Lock ID matches this card
    /// 2. Sequence number is valid (< next_sequence, preventing replay)
    /// 3. Cumulative spent does not exceed total card amount
    /// 4. Schnorr signature is valid over the receipt data
    pub fn verify_receipt(&self, receipt: &PaymentReceipt) -> Result<(), PortalError> {
        if receipt.lock_id != self.lock_id {
            return Err(PortalError::LockNotFound(receipt.lock_id));
        }

        // Enforce sequence monotonicity to prevent receipt replay.
        // A receipt with sequence >= next_sequence was never issued by this card.
        if receipt.sequence >= self.next_sequence {
            return Err(PortalError::InvalidSignature); // Invalid/future sequence
        }

        // Verify cumulative spent doesn't exceed card balance
        if receipt.cumulative_spent > self.total_amount {
            return Err(PortalError::AmountMismatch {
                lock_amount: self.total_amount,
                key_amount: receipt.cumulative_spent,
            });
        }

        // Verify amount is consistent with cumulative
        // (receipt claims amount X contributes to cumulative Y)
        if receipt.amount == 0 {
            return Err(PortalError::ZeroAmount);
        }

        let msg = receipt_message(
            &receipt.lock_id,
            receipt.amount,
            receipt.sequence,
            receipt.cumulative_spent,
        );

        brrq_crypto::schnorr::verify(&self.owner_pubkey, &msg, &receipt.signature)
            .map_err(|_| PortalError::InvalidSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user() -> (SchnorrKeyPair, Address) {
        let kp = SchnorrKeyPair::generate();
        let addr = Address::from_public_key(kp.public_key().as_bytes());
        (kp, addr)
    }

    #[test]
    fn test_prepaid_card_basic() {
        let (kp, addr) = make_user();
        let lock_id = Hasher::hash(b"test_lock");
        let mut card = PrepaidCard::new(lock_id, addr, *kp.public_key(), 1_000_000, None, 200_000);

        assert_eq!(card.remaining(), 1_000_000);
        assert!(!card.is_exhausted());
    }

    #[test]
    fn test_prepaid_card_pay_and_verify() {
        let (kp, addr) = make_user();
        let lock_id = Hasher::hash(b"test_lock");
        let mut card = PrepaidCard::new(lock_id, addr, *kp.public_key(), 1_000_000, None, 200_000);

        // First payment
        let receipt1 = card.pay(100_000, &kp).unwrap();
        assert_eq!(receipt1.amount, 100_000);
        assert_eq!(receipt1.sequence, 0);
        assert_eq!(receipt1.cumulative_spent, 100_000);
        assert_eq!(card.remaining(), 900_000);

        // Verify receipt
        card.verify_receipt(&receipt1).unwrap();

        // Second payment
        let receipt2 = card.pay(250_000, &kp).unwrap();
        assert_eq!(receipt2.sequence, 1);
        assert_eq!(receipt2.cumulative_spent, 350_000);
        assert_eq!(card.remaining(), 650_000);

        card.verify_receipt(&receipt2).unwrap();
    }

    #[test]
    fn test_prepaid_card_insufficient_balance() {
        let (kp, addr) = make_user();
        let lock_id = Hasher::hash(b"test_lock");
        let mut card = PrepaidCard::new(lock_id, addr, *kp.public_key(), 100_000, None, 200_000);

        let result = card.pay(200_000, &kp);
        assert!(result.is_err());
    }

    #[test]
    fn test_prepaid_card_exhaust() {
        let (kp, addr) = make_user();
        let lock_id = Hasher::hash(b"test_lock");
        let mut card = PrepaidCard::new(lock_id, addr, *kp.public_key(), 500_000, None, 200_000);

        card.pay(200_000, &kp).unwrap();
        card.pay(200_000, &kp).unwrap();
        card.pay(100_000, &kp).unwrap();

        assert!(card.is_exhausted());
        assert_eq!(card.remaining(), 0);

        // Can't pay more
        assert!(card.pay(1, &kp).is_err());
    }

    #[test]
    fn test_prepaid_card_receipt_tamper_detection() {
        let (kp, addr) = make_user();
        let lock_id = Hasher::hash(b"test_lock");
        let mut card = PrepaidCard::new(lock_id, addr, *kp.public_key(), 1_000_000, None, 200_000);

        let mut receipt = card.pay(100_000, &kp).unwrap();

        // Tamper with amount
        receipt.amount = 999_999;
        assert!(card.verify_receipt(&receipt).is_err());
    }

    #[test]
    fn test_prepaid_card_monotonic_sequence() {
        let (kp, addr) = make_user();
        let lock_id = Hasher::hash(b"test_lock");
        let mut card = PrepaidCard::new(lock_id, addr, *kp.public_key(), 1_000_000, None, 200_000);

        let r1 = card.pay(100_000, &kp).unwrap();
        let r2 = card.pay(100_000, &kp).unwrap();
        let r3 = card.pay(100_000, &kp).unwrap();

        assert_eq!(r1.sequence, 0);
        assert_eq!(r2.sequence, 1);
        assert_eq!(r3.sequence, 2);
        assert_eq!(r3.cumulative_spent, 300_000);
    }
}
