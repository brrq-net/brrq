// Multi-UTXO bridge pool
//!
//! Manages a pool of Bitcoin UTXOs held in bridge custody, enabling
//! concurrent withdrawals and dispute isolation. Instead of a single UTXO
//! that blocks the entire bridge when disputed, the pool maintains many
//! independent UTXOs — a dispute on one leaves the rest available.
//!
//! ## Design
//!
//! Each [`BridgeUtxo`] tracks its lifecycle through [`UtxoStatus`]:
//!
//! - **Available** — can be selected for a withdrawal
//! - **Reserved** — earmarked for a pending withdrawal (not yet broadcast)
//! - **Disputed** — locked during a challenge; automatically unlocks after
//!   `locked_until` height
//! - **Spent** — BTC transaction broadcast; awaiting confirmation
//!
//! The pool never touches Disputed or Reserved UTXOs when selecting coins
//! for a new withdrawal, ensuring that an ongoing dispute cannot stall
//! unrelated peg-outs.

use serde::{Deserialize, Serialize};

use crate::error::BridgeError;

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// A single UTXO in the bridge's custody pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeUtxo {
    /// Bitcoin transaction ID (32-byte hash, big-endian).
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub vout: u32,
    /// Value in satoshis.
    pub amount_sats: u64,
    /// Current lifecycle status.
    pub status: UtxoStatus,
    /// L1 block height at which this UTXO was confirmed.
    pub confirmed_at_height: u64,
}

/// Lifecycle status of a bridge UTXO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UtxoStatus {
    /// Available for use in withdrawals.
    Available,
    /// Reserved for a pending withdrawal (not yet broadcast).
    Reserved { withdrawal_id: u64 },
    /// Locked in a dispute/challenge — cannot be spent until `locked_until`.
    Disputed { dispute_id: u64, locked_until: u64 },
    /// Spent — BTC transaction broadcast, awaiting confirmation.
    Spent { spending_txid: [u8; 32] },
}

// ═══════════════════════════════════════════════════════════════
// UTXO selection
// ═══════════════════════════════════════════════════════════════

/// Select UTXOs for a withdrawal using largest-first strategy.
///
/// Only considers [`UtxoStatus::Available`] UTXOs. Returns an error if
/// the available balance is insufficient to cover `target_amount`.
pub fn select_utxos_for_withdrawal(
    pool: &[BridgeUtxo],
    target_amount: u64,
) -> Result<Vec<&BridgeUtxo>, BridgeError> {
    if target_amount == 0 {
        return Err(BridgeError::ZeroAmount);
    }

    // Collect available UTXOs and sort largest-first.
    let mut available: Vec<&BridgeUtxo> = pool
        .iter()
        .filter(|u| u.status == UtxoStatus::Available)
        .collect();
    available.sort_by(|a, b| b.amount_sats.cmp(&a.amount_sats));

    let mut selected = Vec::new();
    let mut accumulated: u64 = 0;

    for utxo in available {
        selected.push(utxo);
        accumulated = accumulated.saturating_add(utxo.amount_sats);
        if accumulated >= target_amount {
            return Ok(selected);
        }
    }

    Err(BridgeError::InsufficientPoolBalance {
        required: target_amount,
        available: accumulated,
    })
}

// ═══════════════════════════════════════════════════════════════
// Dispute isolation
// ═══════════════════════════════════════════════════════════════

/// Lock a specific UTXO for a dispute without affecting the rest of the pool.
///
/// The UTXO must currently be [`UtxoStatus::Available`]; attempting to lock
/// a Reserved or already-Disputed UTXO returns an error.
pub fn lock_utxo_for_dispute(
    pool: &mut Vec<BridgeUtxo>,
    txid: &[u8; 32],
    vout: u32,
    dispute_id: u64,
    lock_duration: u64,
    current_height: u64,
) -> Result<(), BridgeError> {
    let txid_hex = hex::encode(txid);

    let utxo = pool
        .iter_mut()
        .find(|u| u.txid == *txid && u.vout == vout)
        .ok_or_else(|| BridgeError::UtxoNotFound {
            txid: txid_hex.clone(),
            vout,
        })?;

    if utxo.status != UtxoStatus::Available {
        return Err(BridgeError::UtxoNotAvailable {
            txid: txid_hex,
            vout,
        });
    }

    utxo.status = UtxoStatus::Disputed {
        dispute_id,
        locked_until: current_height.saturating_add(lock_duration),
    };

    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Pool status queries
// ═══════════════════════════════════════════════════════════════

/// Total satoshis across all Available UTXOs.
pub fn pool_available_balance(pool: &[BridgeUtxo]) -> u64 {
    pool.iter()
        .filter(|u| u.status == UtxoStatus::Available)
        .map(|u| u.amount_sats)
        .sum()
}

/// Total satoshis across *all* UTXOs regardless of status.
pub fn pool_total_balance(pool: &[BridgeUtxo]) -> u64 {
    pool.iter().map(|u| u.amount_sats).sum()
}

/// Number of UTXOs currently locked in a dispute.
pub fn pool_disputed_count(pool: &[BridgeUtxo]) -> usize {
    pool.iter()
        .filter(|u| matches!(u.status, UtxoStatus::Disputed { .. }))
        .count()
}

/// Release any disputed UTXOs whose lock has expired.
///
/// UTXOs with `locked_until <= current_height` are returned to
/// [`UtxoStatus::Available`] so they can participate in withdrawals again.
pub fn release_expired_disputes(pool: &mut [BridgeUtxo], current_height: u64) {
    for utxo in pool.iter_mut() {
        if let UtxoStatus::Disputed { locked_until, .. } = utxo.status {
            if locked_until <= current_height {
                utxo.status = UtxoStatus::Available;
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a pool UTXO with the given amount and status.
    fn make_utxo(id_byte: u8, vout: u32, amount_sats: u64, status: UtxoStatus) -> BridgeUtxo {
        let mut txid = [0u8; 32];
        txid[0] = id_byte;
        BridgeUtxo {
            txid,
            vout,
            amount_sats,
            status,
            confirmed_at_height: 100,
        }
    }

    // ── Selection tests ──────────────────────────────────────────

    #[test]
    fn test_select_utxos_largest_first() {
        let pool = vec![
            make_utxo(1, 0, 50_000, UtxoStatus::Available),
            make_utxo(2, 0, 200_000, UtxoStatus::Available),
            make_utxo(3, 0, 100_000, UtxoStatus::Available),
        ];

        let selected = select_utxos_for_withdrawal(&pool, 150_000).unwrap();
        // Largest-first: picks 200_000 first, which already covers 150_000.
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].amount_sats, 200_000);
    }

    #[test]
    fn test_select_utxos_multiple_needed() {
        let pool = vec![
            make_utxo(1, 0, 80_000, UtxoStatus::Available),
            make_utxo(2, 0, 60_000, UtxoStatus::Available),
            make_utxo(3, 0, 40_000, UtxoStatus::Available),
        ];

        let selected = select_utxos_for_withdrawal(&pool, 130_000).unwrap();
        // 80k + 60k = 140k >= 130k
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].amount_sats, 80_000);
        assert_eq!(selected[1].amount_sats, 60_000);
    }

    #[test]
    fn test_select_utxos_skips_disputed() {
        let pool = vec![
            make_utxo(
                1,
                0,
                500_000,
                UtxoStatus::Disputed {
                    dispute_id: 1,
                    locked_until: 999,
                },
            ),
            make_utxo(2, 0, 100_000, UtxoStatus::Available),
            make_utxo(3, 0, 50_000, UtxoStatus::Available),
        ];

        let selected = select_utxos_for_withdrawal(&pool, 120_000).unwrap();
        // The 500k disputed UTXO is skipped; 100k + 50k = 150k >= 120k.
        assert_eq!(selected.len(), 2);
        assert!(selected.iter().all(|u| u.status == UtxoStatus::Available));
    }

    #[test]
    fn test_select_utxos_skips_reserved() {
        let pool = vec![
            make_utxo(1, 0, 300_000, UtxoStatus::Reserved { withdrawal_id: 42 }),
            make_utxo(2, 0, 100_000, UtxoStatus::Available),
        ];

        let selected = select_utxos_for_withdrawal(&pool, 100_000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].amount_sats, 100_000);
    }

    #[test]
    fn test_select_utxos_skips_spent() {
        let pool = vec![
            make_utxo(
                1,
                0,
                300_000,
                UtxoStatus::Spent {
                    spending_txid: [0xAA; 32],
                },
            ),
            make_utxo(2, 0, 100_000, UtxoStatus::Available),
        ];

        let selected = select_utxos_for_withdrawal(&pool, 100_000).unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].amount_sats, 100_000);
    }

    #[test]
    fn test_select_utxos_insufficient_balance() {
        let pool = vec![
            make_utxo(1, 0, 50_000, UtxoStatus::Available),
            make_utxo(2, 0, 30_000, UtxoStatus::Available),
        ];

        let err = select_utxos_for_withdrawal(&pool, 100_000).unwrap_err();
        match err {
            BridgeError::InsufficientPoolBalance {
                required,
                available,
            } => {
                assert_eq!(required, 100_000);
                assert_eq!(available, 80_000);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_select_utxos_zero_amount() {
        let pool = vec![make_utxo(1, 0, 100_000, UtxoStatus::Available)];
        let err = select_utxos_for_withdrawal(&pool, 0).unwrap_err();
        assert!(matches!(err, BridgeError::ZeroAmount));
    }

    #[test]
    fn test_select_utxos_empty_pool() {
        let pool: Vec<BridgeUtxo> = vec![];
        let err = select_utxos_for_withdrawal(&pool, 100_000).unwrap_err();
        assert!(matches!(err, BridgeError::InsufficientPoolBalance { .. }));
    }

    // ── Dispute isolation tests ──────────────────────────────────

    #[test]
    fn test_lock_utxo_for_dispute() {
        let mut pool = vec![
            make_utxo(1, 0, 100_000, UtxoStatus::Available),
            make_utxo(2, 0, 200_000, UtxoStatus::Available),
        ];

        let txid = pool[0].txid;
        lock_utxo_for_dispute(&mut pool, &txid, 0, 42, 144, 1000).unwrap();

        // First UTXO is now disputed.
        assert_eq!(
            pool[0].status,
            UtxoStatus::Disputed {
                dispute_id: 42,
                locked_until: 1144,
            }
        );
        // Second UTXO is unaffected.
        assert_eq!(pool[1].status, UtxoStatus::Available);
    }

    #[test]
    fn test_lock_utxo_not_found() {
        let mut pool = vec![make_utxo(1, 0, 100_000, UtxoStatus::Available)];
        let bad_txid = [0xFF; 32];
        let err = lock_utxo_for_dispute(&mut pool, &bad_txid, 0, 1, 144, 1000).unwrap_err();
        assert!(matches!(err, BridgeError::UtxoNotFound { .. }));
    }

    #[test]
    fn test_lock_utxo_already_reserved() {
        let mut pool = vec![make_utxo(
            1,
            0,
            100_000,
            UtxoStatus::Reserved { withdrawal_id: 7 },
        )];
        let txid = pool[0].txid;
        let err = lock_utxo_for_dispute(&mut pool, &txid, 0, 1, 144, 1000).unwrap_err();
        assert!(matches!(err, BridgeError::UtxoNotAvailable { .. }));
    }

    #[test]
    fn test_lock_utxo_already_disputed() {
        let mut pool = vec![make_utxo(
            1,
            0,
            100_000,
            UtxoStatus::Disputed {
                dispute_id: 5,
                locked_until: 999,
            },
        )];
        let txid = pool[0].txid;
        let err = lock_utxo_for_dispute(&mut pool, &txid, 0, 2, 144, 1000).unwrap_err();
        assert!(matches!(err, BridgeError::UtxoNotAvailable { .. }));
    }

    // ── Dispute only locks affected UTXO ─────────────────────────

    #[test]
    fn test_dispute_isolates_single_utxo() {
        let mut pool = vec![
            make_utxo(1, 0, 100_000, UtxoStatus::Available),
            make_utxo(2, 0, 200_000, UtxoStatus::Available),
            make_utxo(3, 0, 300_000, UtxoStatus::Available),
        ];

        let txid = pool[1].txid;
        lock_utxo_for_dispute(&mut pool, &txid, 0, 1, 2016, 500).unwrap();

        // Only the targeted UTXO is disputed.
        assert_eq!(pool_disputed_count(&pool), 1);
        // Other UTXOs remain available for withdrawals.
        assert_eq!(pool_available_balance(&pool), 400_000); // 100k + 300k
    }

    // ── Withdrawal with partial pool availability ────────────────

    #[test]
    fn test_withdrawal_with_partial_availability() {
        let pool = vec![
            make_utxo(1, 0, 100_000, UtxoStatus::Available),
            make_utxo(
                2,
                0,
                500_000,
                UtxoStatus::Disputed {
                    dispute_id: 1,
                    locked_until: 9999,
                },
            ),
            make_utxo(3, 0, 200_000, UtxoStatus::Available),
            make_utxo(4, 0, 150_000, UtxoStatus::Reserved { withdrawal_id: 10 }),
        ];

        // Available: 100k + 200k = 300k. Target 250k should succeed.
        let selected = select_utxos_for_withdrawal(&pool, 250_000).unwrap();
        assert_eq!(selected.len(), 2);
        let total: u64 = selected.iter().map(|u| u.amount_sats).sum();
        assert!(total >= 250_000);
    }

    // ── Concurrent dispute + withdrawal don't interfere ──────────

    #[test]
    fn test_concurrent_dispute_and_withdrawal() {
        let mut pool = vec![
            make_utxo(1, 0, 100_000, UtxoStatus::Available),
            make_utxo(2, 0, 200_000, UtxoStatus::Available),
            make_utxo(3, 0, 300_000, UtxoStatus::Available),
            make_utxo(4, 0, 50_000, UtxoStatus::Available),
        ];

        // Dispute locks UTXO #3 (300k).
        let txid3 = pool[2].txid;
        lock_utxo_for_dispute(&mut pool, &txid3, 0, 1, 144, 1000).unwrap();

        // Withdrawal can still proceed using the remaining available UTXOs.
        let selected = select_utxos_for_withdrawal(&pool, 250_000).unwrap();
        // Should pick from 200k, 100k, 50k (sorted largest-first).
        let total: u64 = selected.iter().map(|u| u.amount_sats).sum();
        assert!(total >= 250_000);
        // The disputed UTXO must NOT be in the selection.
        assert!(selected.iter().all(|u| u.status == UtxoStatus::Available));
    }

    // ── Pool status queries ──────────────────────────────────────

    #[test]
    fn test_pool_available_balance() {
        let pool = vec![
            make_utxo(1, 0, 100_000, UtxoStatus::Available),
            make_utxo(
                2,
                0,
                200_000,
                UtxoStatus::Disputed {
                    dispute_id: 1,
                    locked_until: 999,
                },
            ),
            make_utxo(3, 0, 300_000, UtxoStatus::Available),
        ];

        assert_eq!(pool_available_balance(&pool), 400_000);
    }

    #[test]
    fn test_pool_total_balance() {
        let pool = vec![
            make_utxo(1, 0, 100_000, UtxoStatus::Available),
            make_utxo(
                2,
                0,
                200_000,
                UtxoStatus::Disputed {
                    dispute_id: 1,
                    locked_until: 999,
                },
            ),
            make_utxo(
                3,
                0,
                300_000,
                UtxoStatus::Spent {
                    spending_txid: [0; 32],
                },
            ),
        ];

        assert_eq!(pool_total_balance(&pool), 600_000);
    }

    #[test]
    fn test_pool_disputed_count() {
        let pool = vec![
            make_utxo(1, 0, 100_000, UtxoStatus::Available),
            make_utxo(
                2,
                0,
                200_000,
                UtxoStatus::Disputed {
                    dispute_id: 1,
                    locked_until: 999,
                },
            ),
            make_utxo(
                3,
                0,
                300_000,
                UtxoStatus::Disputed {
                    dispute_id: 2,
                    locked_until: 1500,
                },
            ),
        ];

        assert_eq!(pool_disputed_count(&pool), 2);
    }

    // ── Expired dispute release ──────────────────────────────────

    #[test]
    fn test_release_expired_disputes() {
        let mut pool = vec![
            make_utxo(
                1,
                0,
                100_000,
                UtxoStatus::Disputed {
                    dispute_id: 1,
                    locked_until: 500,
                },
            ),
            make_utxo(
                2,
                0,
                200_000,
                UtxoStatus::Disputed {
                    dispute_id: 2,
                    locked_until: 1000,
                },
            ),
            make_utxo(3, 0, 300_000, UtxoStatus::Available),
        ];

        // At height 500, dispute #1 expires.
        release_expired_disputes(&mut pool, 500);
        assert_eq!(pool[0].status, UtxoStatus::Available);
        assert!(matches!(pool[1].status, UtxoStatus::Disputed { .. }));

        // At height 1000, dispute #2 also expires.
        release_expired_disputes(&mut pool, 1000);
        assert_eq!(pool[1].status, UtxoStatus::Available);
    }
}
