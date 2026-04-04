//! BitVM2 on-chain dispute game — L1 witness data construction.
//!
//! Connects the L2-side challenge manager (`challenge_manager.rs`) with the L1-side
//! Taproot scripts (`taproot.rs`) to produce valid Bitcoin witness data for each
//! step of the BitVM2 challenge-response protocol.
//!
//! ## Protocol Flow (L1 Transactions)
//!
//! ```text
//! [Bond UTXO] ──→ [Kickoff TX] ──→ [Assert TX] ──→ (resolved)
//!                      │                                  │
//!                      │              ┌───────────────────┘
//!                      │              ↓
//!                      │         [Disprove TX] ──→ [Take TX]
//!                      │
//!                      └──→ (timeout) ──→ [Take TX]
//! ```
//!
//! ## Security
//!
//! - Witness data is constructed from L2 state but enforced by Bitcoin Script.
//! - The bond UTXO can only be spent through protocol-defined paths.
//! - Domain-separated commitments prevent cross-script witness reuse.

use brrq_crypto::hash::{Hash256, Hasher};
use serde::{Deserialize, Serialize};

use crate::operator::BitVM2Bond;
use crate::taproot::ASSERT_RESPONSE_DEADLINE_BLOCKS;
use crate::types::BITVM2_CHALLENGE_PERIOD_BLOCKS;

// ── Types ────────────────────────────────────────────────────────────────────

/// A step in the BitVM2 dispute game, ready for L1 broadcast.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DisputeStep {
    /// Kickoff: challenger initiates dispute against operator's state claim.
    ///
    /// Spends the bond UTXO via Taproot script-path leaf 0.
    /// Witness: `<committed_state_root>` (matches the hash in the script).
    Kickoff(KickoffData),

    /// Assert: operator responds to challenge with execution transcript.
    ///
    /// Spends via Taproot script-path leaf 1.
    /// Witness: `<operator_signature>` (Schnorr sig proving identity).
    Assert(AssertData),

    /// Disprove: challenger proves fraud by revealing state root mismatch.
    ///
    /// Spends via Taproot script-path leaf 2.
    /// Witness: `<actual_state_root> <committed_state_root>` (the script
    /// verifies committed matches the bond and actual does NOT).
    Disprove(DisproveData),

    /// Take: claim the slashed bond after timeout or successful disprove.
    ///
    /// Spends via Taproot script-path leaf 3.
    /// Witness: (empty — the script only checks CSV timelock).
    Take(TakeData),
}

/// Kickoff transaction data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KickoffData {
    /// The operator's committed state root (witness data for leaf 0).
    pub committed_state_root: [u8; 32],
    /// The L2 challenge ID this kickoff corresponds to.
    pub l2_challenge_id: Hash256,
    /// The bond UTXO being challenged.
    pub bond_utxo_txid: Hash256,
    pub bond_utxo_vout: u32,
    /// The bond's expected script_pubkey (for UTXO lookup).
    pub bond_script_pubkey: Vec<u8>,
}

/// Assert transaction data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssertData {
    /// The operator's x-only public key (for signature generation).
    pub operator_pubkey: [u8; 32],
    /// The L2 challenge ID this assert responds to.
    pub l2_challenge_id: Hash256,
    /// State root the operator is asserting is correct.
    pub asserted_state_root: [u8; 32],
    /// L1 block height deadline for the assert response.
    pub deadline_l1_height: u64,
    /// Pre-computed Schnorr signature from the operator.
    /// OP_CHECKSIG expects a 64-byte Schnorr signature, not a state root.
    /// The operator must sign (asserted_state_root || l2_challenge_id) with their key.
    /// Stored as Vec<u8> (must be exactly 64 bytes) for serde compatibility.
    pub operator_signature: Option<Vec<u8>>,
}

/// Disprove transaction data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisproveData {
    /// The operator's committed state root (first witness item).
    pub committed_state_root: [u8; 32],
    /// The actual state root (second witness item — proves fraud).
    pub actual_state_root: [u8; 32],
    /// The L2 challenge ID this disprove resolves.
    pub l2_challenge_id: Hash256,
    /// The bond UTXO being claimed.
    pub bond_utxo_txid: Hash256,
    pub bond_utxo_vout: u32,
}

/// Take transaction data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeData {
    /// The bond UTXO being claimed.
    pub bond_utxo_txid: Hash256,
    pub bond_utxo_vout: u32,
    /// Reason the bond is being taken.
    pub reason: TakeReason,
    /// Minimum L1 block height at which the Take is valid.
    pub valid_after_l1_height: u64,
}

/// Why the bond is being taken.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum TakeReason {
    /// Fraud proven via Disprove transaction.
    FraudProven,
    /// Operator failed to Assert within timeout.
    OperatorTimeout,
}

// ── Dispute Phase Tracking ───────────────────────────────────────────────────

/// Tracks the current phase of a dispute for a specific bond.
///
/// Enforces state machine transitions:
/// `None -> KickedOff -> Asserted -> Resolved`
/// `None -> KickedOff -> Disproved -> Resolved`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DisputePhase {
    /// Kickoff transaction broadcast.
    KickedOff,
    /// Operator responded with Assert.
    Asserted,
    /// Challenger proved fraud via Disprove.
    Disproved,
    /// Bond taken (terminal).
    Resolved,
}

// ── Dispute Game Manager ─────────────────────────────────────────────────────

/// Constructs L1 witness data for each BitVM2 dispute step.
///
/// Pure logic — does not broadcast transactions. The constructed
/// `DisputeStep` values are passed to the L1 transaction builder
/// in `brrq-node::bitcoin_sync` for actual broadcasting.
pub struct DisputeGameBuilder;

impl DisputeGameBuilder {
    /// Construct a Kickoff transaction for an L2 challenge.
    ///
    /// The challenger must provide:
    /// - The L2 challenge ID (links L2 dispute to L1 bond)
    /// - The operator's bond (contains the committed state root)
    ///
    /// Returns the KickoffData with witness data matching the Kickoff script.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the bond's `expected_script_pubkey` is empty (bond was
    /// never verified against the Taproot output). Without a verified script,
    /// the Kickoff transaction would target a nonexistent or wrong UTXO.
    pub fn build_kickoff(
        l2_challenge_id: Hash256,
        bond: &BitVM2Bond,
    ) -> Result<DisputeStep, String> {
        if bond.expected_script_pubkey.is_empty() {
            return Err(
                "bond has no expected_script_pubkey — call verify_bond_script() first".into(),
            );
        }

        let bond_script_pubkey = bond.expected_script_pubkey.clone();

        Ok(DisputeStep::Kickoff(KickoffData {
            committed_state_root: bond.committed_state_root,
            l2_challenge_id,
            bond_utxo_txid: bond.utxo_txid,
            bond_utxo_vout: bond.utxo_vout,
            bond_script_pubkey,
        }))
    }

    /// Construct an Assert transaction for the operator's response.
    ///
    /// The operator must:
    /// 1. Sign the Assert transaction with their Schnorr key
    /// 2. Publish their execution transcript (off-chain or via OP_RETURN)
    /// 3. Do this before `BITVM2_CHALLENGE_PERIOD_BLOCKS` elapses (enforced by Take path)
    ///
    /// The Assert script itself has NO timelock — the operator can respond
    /// immediately after a Kickoff. The deadline is enforced indirectly: if the
    /// operator doesn't Assert before `BITVM2_CHALLENGE_PERIOD_BLOCKS`, the Take path
    /// becomes spendable and the bond is forfeited.
    ///
    /// Returns the AssertData. The operator must sign externally (private key
    /// never enters this module).
    ///
    /// The `asserted_state_root` parameter lets the operator assert any state root
    /// (which may differ from the bond's committed root if the operator is correcting
    /// a previous assertion).
    ///
    /// # Errors
    ///
    /// Returns `Err` if the bond's operator pubkey is all-zeros (likely
    /// uninitialized or invalid).
    pub fn build_assert(
        l2_challenge_id: Hash256,
        bond: &BitVM2Bond,
        current_l1_height: u64,
        asserted_state_root: [u8; 32],
    ) -> Result<DisputeStep, String> {
        if bond.operator_pubkey == [0u8; 32] {
            return Err("bond has zero operator_pubkey — invalid or uninitialized".into());
        }

        Ok(DisputeStep::Assert(AssertData {
            operator_pubkey: bond.operator_pubkey,
            l2_challenge_id,
            asserted_state_root,
            deadline_l1_height: current_l1_height
                .saturating_add(ASSERT_RESPONSE_DEADLINE_BLOCKS as u64),
            operator_signature: None, // caller must set this before broadcasting
        }))
    }

    /// Construct a Disprove transaction when fraud is proven.
    ///
    /// The challenger provides:
    /// - The committed state root (from the bond)
    /// - The actual state root (proven different via L2 challenge)
    ///
    /// The Disprove script verifies:
    /// 1. `SHA256(committed_root)` matches the bond commitment
    /// 2. `SHA256(actual_root)` does NOT match (proves fraud)
    pub fn build_disprove(
        l2_challenge_id: Hash256,
        bond: &BitVM2Bond,
        actual_state_root: [u8; 32],
    ) -> Result<DisputeStep, String> {
        // Ensure the actual root differs from committed (otherwise no fraud)
        if actual_state_root == bond.committed_state_root {
            return Err("actual state root matches committed — no fraud to prove".into());
        }

        Ok(DisputeStep::Disprove(DisproveData {
            committed_state_root: bond.committed_state_root,
            actual_state_root,
            l2_challenge_id,
            bond_utxo_txid: bond.utxo_txid,
            bond_utxo_vout: bond.utxo_vout,
        }))
    }

    /// Construct a Take transaction to claim the slashed bond.
    ///
    /// Valid after:
    /// - A Disprove transaction has been confirmed (fraud proven), OR
    /// - The operator failed to Assert within `ASSERT_RESPONSE_DEADLINE_BLOCKS`
    ///
    /// The Take script only checks that `BITVM2_CHALLENGE_PERIOD_BLOCKS` have
    /// elapsed via OP_CSV.
    pub fn build_take(
        bond: &BitVM2Bond,
        reason: TakeReason,
        kickoff_l1_height: u64,
    ) -> DisputeStep {
        DisputeStep::Take(TakeData {
            bond_utxo_txid: bond.utxo_txid,
            bond_utxo_vout: bond.utxo_vout,
            reason,
            valid_after_l1_height: kickoff_l1_height.saturating_add(BITVM2_CHALLENGE_PERIOD_BLOCKS),
        })
    }

    /// Verify that a Kickoff's committed state root matches the bond's taproot commitment.
    ///
    /// Cross-checks:
    /// 1. The witness state root matches the bond's commitment (byte equality).
    /// 2. The Taproot script can be reconstructed — the bond's expected_script_pubkey
    ///    matches what `taproot::build_bond_output()` produces from the bond params.
    ///    This catches corrupted bonds where the state root and script are inconsistent.
    pub fn verify_kickoff_commitment(kickoff: &KickoffData, bond: &BitVM2Bond) -> bool {
        // Check 1: Witness state root matches bond commitment
        if kickoff.committed_state_root != bond.committed_state_root {
            return false;
        }

        // Check 2: Bond script_pubkey matches the kickoff's stored script_pubkey
        // (prevents corrupted or swapped bond data)
        if kickoff.bond_script_pubkey != bond.expected_script_pubkey {
            return false;
        }

        // Check 3: The bond's expected_script_pubkey can be recomputed from scratch
        // This verifies taproot script integrity — catches mutations.
        if bond.expected_script_pubkey.is_empty() {
            return false;
        }
        let recomputed = crate::operator::OperatorManager::verify_bond_script(bond);
        match recomputed {
            Ok(spk) => spk == bond.expected_script_pubkey,
            Err(_) => false,
        }
    }

    /// Verify that a Disprove's witness data will satisfy the Disprove script.
    ///
    /// Checks:
    /// 1. Committed root matches bond commitment (SHA256 check in script)
    /// 2. Actual root differs from committed root (NOT check in script)
    pub fn verify_disprove_witness(disprove: &DisproveData, bond: &BitVM2Bond) -> bool {
        // Committed root must match
        disprove.committed_state_root == bond.committed_state_root
            // Actual root must differ (otherwise no fraud)
            && disprove.actual_state_root != disprove.committed_state_root
    }

    /// Compute the dispute game hash — a unique identifier for the full dispute.
    ///
    /// Used to link L1 transactions to L2 challenge resolution.
    pub fn dispute_game_hash(
        l2_challenge_id: &Hash256,
        bond_utxo_txid: &Hash256,
        bond_utxo_vout: u32,
    ) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(brrq_crypto::domain_tags::DISPUTE_GAME_V1);
        hasher.update(l2_challenge_id.as_bytes());
        hasher.update(bond_utxo_txid.as_bytes());
        hasher.update(&bond_utxo_vout.to_le_bytes());
        hasher.finalize()
    }
}

// ── L1 Transaction Builder ──────────────────────────────────────────────

use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction, TxIn, TxOut, Witness};

/// Converts L2 Dispute Steps into signed L1 `bitcoin::Transaction` objects.
///
/// SAFETY: These transactions are templates for future BitVM2 implementation.
/// They MUST NOT be broadcast on mainnet in their current form.
#[cfg(not(any(test, feature = "phase4-placeholder")))]
compile_error!("BitVM2 dispute game requires the bitvm2 feature flag");

pub struct BitVM2TransactionBuilder;

impl BitVM2TransactionBuilder {
    /// Builds the raw transaction for the given dispute step.
    pub fn build_tx(step: &DisputeStep) -> Transaction {
        match step {
            DisputeStep::Kickoff(data) => {
                let txid = bitcoin::Txid::from_slice(data.bond_utxo_txid.as_bytes())
                    .expect("Invalid Txid length");
                let outpoint = OutPoint::new(txid, data.bond_utxo_vout);

                let mut witness = Witness::new();
                witness.push(&data.committed_state_root);

                let input = TxIn {
                    previous_output: outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::from_height(
                        crate::taproot::KICKOFF_MIN_AGE_BLOCKS as u16,
                    ),
                    witness,
                };

                // Assert phase UTXO output (script_pubkey set by caller for real broadcasts).
                let output = TxOut {
                    value: bitcoin::Amount::from_sat(100_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                };

                // Absolute Optimal Architecture: CPFP Anchor Output for dynamic RBF/Mempool pinning defense
                // This 330-satoshi output allows the operator or challenger to dynamically bump the transaction
                // fee using a Child-Pays-For-Parent (CPFP) transaction if the L1 mempool becomes congested.
                let anchor_output = TxOut {
                    value: bitcoin::Amount::from_sat(330),
                    script_pubkey: bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(
                        &[0x00; 33],
                    )),
                };

                Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![input],
                    output: vec![output, anchor_output],
                }
            }
            DisputeStep::Assert(data) => {
                // Assert witness now pushes Schnorr signature (not state_root).
                // OP_CHECKSIG expects a 64-byte Schnorr signature. The operator must
                // pre-sign (asserted_state_root || l2_challenge_id) with their key.
                //
                // Spends the Kickoff output (uses challenge ID as placeholder txid).
                let txid = bitcoin::Txid::from_slice(data.l2_challenge_id.as_bytes())
                    .unwrap_or_else(|_| bitcoin::Txid::from_byte_array([0; 32]));
                let outpoint = OutPoint::new(txid, 0);

                let mut witness = Witness::new();
                if let Some(ref sig) = data.operator_signature {
                    if sig.len() == 64 {
                        witness.push(sig.as_slice());
                    } else {
                        // Invalid signature length — fall back to placeholder.
                        witness.push(&data.asserted_state_root);
                    }
                } else {
                    // Fallback: push state_root as placeholder for testing.
                    // This will FAIL Bitcoin Script validation in production.
                    witness.push(&data.asserted_state_root);
                }

                let input = TxIn {
                    previous_output: outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::from_height(1),
                    witness,
                };

                let output = TxOut {
                    value: bitcoin::Amount::from_sat(90_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                };

                let anchor_output = TxOut {
                    value: bitcoin::Amount::from_sat(330),
                    script_pubkey: bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(
                        &[0x00; 33],
                    )),
                };

                Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![input],
                    output: vec![output, anchor_output],
                }
            }
            DisputeStep::Disprove(data) => {
                let txid = bitcoin::Txid::from_slice(data.bond_utxo_txid.as_bytes())
                    .unwrap_or_else(|_| bitcoin::Txid::from_byte_array([0; 32]));
                let outpoint = OutPoint::new(txid, data.bond_utxo_vout);

                let mut witness = Witness::new();
                witness.push(&data.committed_state_root);
                witness.push(&data.actual_state_root);

                let input = TxIn {
                    previous_output: outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::from_height(1),
                    witness,
                };

                let output = TxOut {
                    value: bitcoin::Amount::from_sat(80_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                };

                let anchor_output = TxOut {
                    value: bitcoin::Amount::from_sat(330),
                    script_pubkey: bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(
                        &[0x00; 33],
                    )),
                };

                Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![input],
                    output: vec![output, anchor_output],
                }
            }
            DisputeStep::Take(data) => {
                let txid = bitcoin::Txid::from_slice(data.bond_utxo_txid.as_bytes())
                    .unwrap_or_else(|_| bitcoin::Txid::from_byte_array([0; 32]));
                let outpoint = OutPoint::new(txid, data.bond_utxo_vout);

                let witness = Witness::new();

                let input = TxIn {
                    previous_output: outpoint,
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::from_height(
                        crate::types::BITVM2_CHALLENGE_PERIOD_BLOCKS as u16,
                    ),
                    witness,
                };

                let output = TxOut {
                    value: bitcoin::Amount::from_sat(70_000),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                };

                let anchor_output = TxOut {
                    value: bitcoin::Amount::from_sat(330),
                    script_pubkey: bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(
                        &[0x00; 33],
                    )),
                };

                Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: LockTime::ZERO,
                    input: vec![input],
                    output: vec![output, anchor_output],
                }
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::taproot::{self, BondParams};

    fn make_bond() -> BitVM2Bond {
        // Valid secp256k1 x-only pubkey (generator point)
        let operator_pubkey = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
            0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
            0x16, 0xF8, 0x17, 0x98,
        ];

        // Compute expected script_pubkey via taproot
        let params = BondParams {
            operator_pubkey,
            committed_state_root: [0xAA; 32],
            l2_height: 1000,
            bond_amount: 100_000_000,
        };
        let output = taproot::build_bond_output(&params).unwrap();
        let expected_spk = output.script_pubkey.as_bytes().to_vec();

        BitVM2Bond {
            utxo_txid: Hash256::from_bytes([0x01; 32]),
            utxo_vout: 0,
            bond_amount: 100_000_000,
            registered_height: 1000,
            operator_pubkey,
            committed_state_root: [0xAA; 32],
            expected_script_pubkey: expected_spk,
            verified_onchain: false,
        }
    }

    fn challenge_id() -> Hash256 {
        Hash256::from_bytes([0xCC; 32])
    }

    #[test]
    fn build_kickoff_has_correct_witness() {
        let bond = make_bond();
        let step = DisputeGameBuilder::build_kickoff(challenge_id(), &bond).unwrap();

        if let DisputeStep::Kickoff(data) = step {
            assert_eq!(data.committed_state_root, [0xAA; 32]);
            assert_eq!(data.l2_challenge_id, challenge_id());
            assert_eq!(data.bond_utxo_txid, bond.utxo_txid);
            assert_eq!(data.bond_utxo_vout, 0);
            assert!(!data.bond_script_pubkey.is_empty());
        } else {
            panic!("expected Kickoff step");
        }
    }

    #[test]
    fn build_kickoff_rejects_empty_script_pubkey() {
        let mut bond = make_bond();
        bond.expected_script_pubkey = Vec::new(); // Unverified bond

        let result = DisputeGameBuilder::build_kickoff(challenge_id(), &bond);
        assert!(
            result.is_err(),
            "kickoff with empty script_pubkey must fail"
        );
    }

    #[test]
    fn build_assert_has_deadline() {
        let bond = make_bond();
        let step = DisputeGameBuilder::build_assert(
            challenge_id(),
            &bond,
            800_000,
            bond.committed_state_root,
        )
        .unwrap();

        if let DisputeStep::Assert(data) = step {
            assert_eq!(data.operator_pubkey, bond.operator_pubkey);
            assert_eq!(
                data.deadline_l1_height,
                800_000 + ASSERT_RESPONSE_DEADLINE_BLOCKS as u64
            );
            assert_eq!(data.asserted_state_root, [0xAA; 32]);
        } else {
            panic!("expected Assert step");
        }
    }

    #[test]
    fn build_assert_rejects_zero_pubkey() {
        let mut bond = make_bond();
        bond.operator_pubkey = [0u8; 32]; // Invalid

        let result = DisputeGameBuilder::build_assert(
            challenge_id(),
            &bond,
            800_000,
            bond.committed_state_root,
        );
        assert!(result.is_err(), "assert with zero pubkey must fail");
    }

    #[test]
    fn build_disprove_rejects_matching_roots() {
        let bond = make_bond();
        // Same root → no fraud → should fail
        let result = DisputeGameBuilder::build_disprove(
            challenge_id(),
            &bond,
            [0xAA; 32], // Same as committed
        );
        assert!(result.is_err());
    }

    #[test]
    fn build_disprove_accepts_different_roots() {
        let bond = make_bond();
        let step = DisputeGameBuilder::build_disprove(
            challenge_id(),
            &bond,
            [0xBB; 32], // Different from committed [0xAA]
        )
        .unwrap();

        if let DisputeStep::Disprove(data) = step {
            assert_eq!(data.committed_state_root, [0xAA; 32]);
            assert_eq!(data.actual_state_root, [0xBB; 32]);
            assert_eq!(data.l2_challenge_id, challenge_id());
        } else {
            panic!("expected Disprove step");
        }
    }

    #[test]
    fn build_take_after_fraud() {
        let bond = make_bond();
        let step = DisputeGameBuilder::build_take(&bond, TakeReason::FraudProven, 800_000);

        if let DisputeStep::Take(data) = step {
            assert_eq!(data.reason, TakeReason::FraudProven);
            assert_eq!(
                data.valid_after_l1_height,
                800_000 + BITVM2_CHALLENGE_PERIOD_BLOCKS
            );
        } else {
            panic!("expected Take step");
        }
    }

    #[test]
    fn build_take_after_timeout() {
        let bond = make_bond();
        let step = DisputeGameBuilder::build_take(&bond, TakeReason::OperatorTimeout, 800_000);

        if let DisputeStep::Take(data) = step {
            assert_eq!(data.reason, TakeReason::OperatorTimeout);
        } else {
            panic!("expected Take step");
        }
    }

    #[test]
    fn verify_kickoff_commitment_valid() {
        let bond = make_bond();
        let step = DisputeGameBuilder::build_kickoff(challenge_id(), &bond).unwrap();

        if let DisputeStep::Kickoff(data) = step {
            assert!(DisputeGameBuilder::verify_kickoff_commitment(&data, &bond));
        }
    }

    #[test]
    fn verify_kickoff_commitment_invalid_root() {
        let bond = make_bond();
        let data = KickoffData {
            committed_state_root: [0xFF; 32], // Wrong root
            l2_challenge_id: challenge_id(),
            bond_utxo_txid: bond.utxo_txid,
            bond_utxo_vout: 0,
            bond_script_pubkey: bond.expected_script_pubkey.clone(),
        };

        assert!(!DisputeGameBuilder::verify_kickoff_commitment(&data, &bond));
    }

    #[test]
    fn verify_disprove_witness_valid() {
        let bond = make_bond();
        let data = DisproveData {
            committed_state_root: [0xAA; 32],
            actual_state_root: [0xBB; 32],
            l2_challenge_id: challenge_id(),
            bond_utxo_txid: bond.utxo_txid,
            bond_utxo_vout: 0,
        };

        assert!(DisputeGameBuilder::verify_disprove_witness(&data, &bond));
    }

    #[test]
    fn verify_disprove_witness_same_roots_invalid() {
        let bond = make_bond();
        let data = DisproveData {
            committed_state_root: [0xAA; 32],
            actual_state_root: [0xAA; 32], // Same as committed → no fraud
            l2_challenge_id: challenge_id(),
            bond_utxo_txid: bond.utxo_txid,
            bond_utxo_vout: 0,
        };

        assert!(!DisputeGameBuilder::verify_disprove_witness(&data, &bond));
    }

    #[test]
    fn dispute_game_hash_deterministic() {
        let h1 = DisputeGameBuilder::dispute_game_hash(
            &challenge_id(),
            &Hash256::from_bytes([0x01; 32]),
            0,
        );
        let h2 = DisputeGameBuilder::dispute_game_hash(
            &challenge_id(),
            &Hash256::from_bytes([0x01; 32]),
            0,
        );
        assert_eq!(h1, h2);
        assert_ne!(h1, Hash256::ZERO);
    }

    #[test]
    fn dispute_game_hash_varies_by_challenge() {
        let h1 = DisputeGameBuilder::dispute_game_hash(
            &Hash256::from_bytes([0xAA; 32]),
            &Hash256::from_bytes([0x01; 32]),
            0,
        );
        let h2 = DisputeGameBuilder::dispute_game_hash(
            &Hash256::from_bytes([0xBB; 32]),
            &Hash256::from_bytes([0x01; 32]),
            0,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn full_dispute_lifecycle() {
        let bond = make_bond();
        let cid = challenge_id();

        // Step 1: Kickoff
        let kickoff = DisputeGameBuilder::build_kickoff(cid, &bond).unwrap();
        assert!(matches!(kickoff, DisputeStep::Kickoff(_)));

        // Step 2a: Operator responds (Assert)
        let assert_step =
            DisputeGameBuilder::build_assert(cid, &bond, 800_000, bond.committed_state_root)
                .unwrap();
        assert!(matches!(assert_step, DisputeStep::Assert(_)));

        // Step 2b: Challenger proves fraud (Disprove)
        let actual_root = [0xBB; 32]; // Different from committed [0xAA]
        let disprove = DisputeGameBuilder::build_disprove(cid, &bond, actual_root).unwrap();
        assert!(matches!(disprove, DisputeStep::Disprove(_)));

        // Step 3: Take the bond
        let take = DisputeGameBuilder::build_take(&bond, TakeReason::FraudProven, 800_000);
        assert!(matches!(take, DisputeStep::Take(_)));

        // Verify cross-step consistency
        if let DisputeStep::Kickoff(k) = &kickoff {
            assert!(DisputeGameBuilder::verify_kickoff_commitment(k, &bond));
        }
        if let DisputeStep::Disprove(d) = &disprove {
            assert!(DisputeGameBuilder::verify_disprove_witness(d, &bond));
        }
    }

    #[test]
    fn take_valid_after_height_overflow_safe() {
        let bond = make_bond();
        let step = DisputeGameBuilder::build_take(
            &bond,
            TakeReason::OperatorTimeout,
            u64::MAX - 100, // Would overflow without saturating
        );

        if let DisputeStep::Take(data) = step {
            assert_eq!(data.valid_after_l1_height, u64::MAX);
        }
    }
}
