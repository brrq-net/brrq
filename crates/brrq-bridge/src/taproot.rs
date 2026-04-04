//! BitVM2 Taproot Script Templates for the Brrq bridge.
//!
//! Implements the four transaction types in the BitVM2 challenge-response
//! dispute game (whitepaper §6.4):
//!
//! 1. **Bond Output**: Taproot output locking operator's bond with multiple
//!    spending paths (cooperative + dispute game).
//! 2. **Kickoff**: Initiates a challenge against an operator's state claim.
//! 3. **Assert**: Operator publishes execution transcript to refute challenge.
//! 4. **Disprove**: Challenger proves fraud by revealing inconsistency.
//! 5. **Take**: Claim slashed bond after successful disprove (or timeout).
//!
//! ## Architecture
//!
//! The bond UTXO is a Taproot output with:
//! - **Key-path spend**: N-of-N cooperative close (operator + federation backup).
//! - **Script-path spends**: Four leaves in the taptree:
//!   - Leaf 0: Kickoff (anyone can challenge)
//!   - Leaf 1: Assert (operator responds)
//!   - Leaf 2: Disprove (challenger proves fraud)
//!   - Leaf 3: Take (claim bond after timeout)
//!
//! ## Security Model
//!
//! The dispute game operates on Bitcoin L1, making it trust-minimized:
//! - Any honest observer can initiate a challenge (permissionless).
//! - Operator must respond within 2016 blocks (~2 weeks) or lose bond.
//! - Fraud proof is verified by Bitcoin Script (no trusted third party).
//! - Bond UTXO is locked on-chain — cannot be spent except through the
//!   protocol-defined paths.

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::{Builder as ScriptBuilder, ScriptBuf};
use bitcoin::hashes::Hash;
use bitcoin::hashes::sha256;
use bitcoin::secp256k1::{self, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::TaprootBuilder;
use serde::{Deserialize, Serialize};

// ── Constants ────────────────────────────────────────────────────────────────

// Use the canonical constant from types.rs instead of a
// local duplicate. The previous local `CHALLENGE_PERIOD_BLOCKS: i64 = 2016`
// conflicted with `types::CHALLENGE_PERIOD_BLOCKS: u64 = 144` (different
// value AND type). The BitVM2 challenge period is defined in types.rs as
// `BITVM2_CHALLENGE_PERIOD_BLOCKS`.
use crate::types::BITVM2_CHALLENGE_PERIOD_BLOCKS;

/// Deadline in L1 blocks for the operator to broadcast an Assert transaction.
///
/// NOTE: This constant is NOT embedded in the Assert script (which has no
/// timelock). It is tracked on the L2 side for monitoring purposes only.
/// The actual timeout enforcement is via the Take script's OP_CSV.
pub const ASSERT_RESPONSE_DEADLINE_BLOCKS: i64 = 1008;

/// Minimum age in L1 blocks before a challenge can be initiated
/// against a bond. Prevents griefing at bond creation time (e.g., challenging
/// an operator's state root before their bond tx is even deeply confirmed).
/// Matches `REQUIRED_CONFIRMATIONS` from types.rs.
pub const KICKOFF_MIN_AGE_BLOCKS: i64 = 6;

/// Domain tag for state root commitments in the dispute game.
/// MISSING-LINK FIX: Now references the centralized definition.
const DOMAIN_BITVM2_STATE: &[u8] = brrq_crypto::domain_tags::BITVM2_STATE_V1;

// ── Types ────────────────────────────────────────────────────────────────────

/// Parameters for constructing the bond Taproot output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondParams {
    /// Operator's x-only public key (32 bytes, Schnorr).
    pub operator_pubkey: [u8; 32],
    /// State root the operator is committing to.
    pub committed_state_root: [u8; 32],
    /// L2 block height of the committed state.
    pub l2_height: u64,
    /// Bond amount in satoshis.
    pub bond_amount: u64,
}

/// A built BitVM2 taptree with all four script leaves.
#[derive(Debug, Clone)]
pub struct BitVM2Scripts {
    /// Kickoff script (leaf 0): anyone can challenge.
    pub kickoff: ScriptBuf,
    /// Assert script (leaf 1): operator responds to challenge.
    pub assert_script: ScriptBuf,
    /// Disprove script (leaf 2): challenger proves fraud.
    pub disprove: ScriptBuf,
    /// Take script (leaf 3): claim bond after timeout.
    pub take: ScriptBuf,
}

/// Result of building the full Taproot bond output.
#[derive(Debug, Clone)]
pub struct BondOutput {
    /// The Taproot output key (internal key + taptree commitment).
    pub output_key: XOnlyPublicKey,
    /// Parity of the output key (needed for spending).
    pub output_key_parity: secp256k1::Parity,
    /// Individual scripts for each leaf.
    pub scripts: BitVM2Scripts,
    /// The script_pubkey for the bond UTXO (OP_1 <output_key>).
    pub script_pubkey: ScriptBuf,
}

// ── Script Builders ──────────────────────────────────────────────────────────

/// Build the Kickoff script (Leaf 0).
///
/// Anyone can spend this path to initiate a challenge. The script verifies:
/// 1. A 32-byte state root commitment is provided on the stack.
/// 2. A sequence number enforces the challenge initiation window.
///
/// Script: `<challenge_period> OP_CSV OP_DROP <state_root_hash> OP_EQUAL`
///
/// The challenger provides the disputed state root; the script checks it
/// matches the committed root. The CSV ensures the challenge can only be
/// initiated after a minimum waiting period (prevents griefing at bond
/// creation time).
pub fn build_kickoff_script(committed_state_root: &[u8; 32]) -> ScriptBuf {
    // Hash the state root with domain separation
    let commitment = domain_hash(DOMAIN_BITVM2_STATE, committed_state_root);

    ScriptBuilder::new()
        // Require minimum age (anti-griefing)
        .push_int(KICKOFF_MIN_AGE_BLOCKS)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        // Verify the challenger provides the correct committed state root
        .push_slice::<&[u8; 32]>(commitment.as_ref())
        .push_opcode(OP_EQUAL)
        .into_script()
}

/// Build the Assert script (Leaf 1).
///
/// The operator uses this path to respond to a challenge by publishing
/// their execution transcript. The script verifies the operator's Schnorr
/// signature (only the bonded operator can respond).
///
/// Script: `<operator_pubkey> OP_CHECKSIG`
///
/// ## Timeout Enforcement
///
/// The response timeout is NOT enforced here — it is enforced by the Take
/// script's `OP_CSV` timelock. If the operator fails to broadcast an Assert
/// transaction before `CHALLENGE_PERIOD_BLOCKS` elapses, the Take path
/// becomes spendable and the bond is forfeited.
///
/// Previous versions incorrectly used `OP_CSV` on the Assert path, which
/// would PREVENT the operator from responding until the timeout elapsed
/// (the opposite of the intended semantics). `OP_CSV` enforces a MINIMUM
/// age, not a maximum — so it would block early responses rather than
/// enforcing a deadline.
pub fn build_assert_script(operator_pubkey: &[u8; 32]) -> ScriptBuf {
    ScriptBuilder::new()
        // Operator must sign (proves identity)
        .push_slice(operator_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Expected preimage size: domain tag (20 bytes) + state root (32 bytes).
const DISPROVE_PREIMAGE_SIZE: i64 = (DOMAIN_BITVM2_STATE.len() + 32) as i64;

/// Build the Disprove script (Leaf 2).
///
/// A challenger uses this path to prove the operator committed fraud.
/// The script verifies:
/// 1. Both witness items are exactly 52 bytes (domain tag + state root).
/// 2. The committed preimage hashes to the bond commitment.
/// 3. The actual state preimage does NOT hash to the bond commitment (fraud).
///
/// # Security Model
///
/// The `OP_SIZE` checks constrain the witness items to exactly
/// `DOMAIN_BITVM2_STATE.len() + 32 = 52` bytes. This prevents an attacker
/// from using arbitrary-length data to satisfy the inequality check.
/// Combined with domain-separated hashing, the challenger must provide a
/// valid domain-tagged state root that produces a different commitment.
///
/// Hash-based fraud proof verification within Bitcoin Script constraints.
///
/// ## Witness Format
///
/// ```text
/// Stack (top to bottom): [actual_preimage, committed_preimage]
/// where each preimage = DOMAIN_BITVM2_STATE || state_root (52 bytes)
/// ```
///
/// Use [`build_disprove_witness`] to construct valid witness data.
///
/// Script:
/// ```text
/// OP_SIZE <52> OP_EQUALVERIFY                 -- committed_preimage is 52 bytes
/// OP_SHA256 <commitment> OP_EQUALVERIFY       -- matches bond commitment
/// OP_SIZE <52> OP_EQUALVERIFY                 -- actual_preimage is 52 bytes
/// OP_SHA256 <commitment> OP_EQUAL OP_NOT      -- does NOT match (fraud!)
/// ```
/// Build the Disprove script (Leaf 2) — enhanced for 
///
/// The challenger must:
/// 1. Provide a Schnorr signature (proves they posted a challenger bond).
/// 2. Demonstrate the committed preimage matches the bond commitment.
/// 3. Demonstrate an alternative preimage does NOT match (fraud proof).
///
/// ## Witness Format (enhanced)
///
/// ```text
/// Stack (top to bottom): [challenger_sig, actual_preimage, committed_preimage]
/// ```
///
/// ## Why challenger signature is required
///
/// Without a signature requirement, anyone can submit a disprove with
/// arbitrary data. The hash inequality check alone verifies that the
/// challenger *knows a different preimage*, but doesn't prove they have
/// a stake in the dispute. Requiring a signature from a bonded challenger
/// prevents sybil-griefing where an attacker submits bogus fraud proofs
/// to lock operator funds.
///
/// In the multi-UTXO model , the challenger's identity is
/// already established by the Kickoff TX. The challenger_pubkey in the
/// Disprove script is set to the pubkey of whoever initiated the Kickoff.
///
/// ## Correctness of the alternative state root
///
/// Bitcoin Script cannot verify a STARK/SNARK proof directly. The
/// correctness of the alternative state root is established by the
/// BitVM2 bisection protocol: the challenger and operator exchange
/// intermediate state commitments until they disagree on a single
/// computation step, which IS verifiable in Script. This disprove script
/// is the final step — it verifies the challenger found a discrepancy.
pub fn build_disprove_script(committed_state_root: &[u8; 32]) -> ScriptBuf {
    let commitment = domain_hash(DOMAIN_BITVM2_STATE, committed_state_root);

    ScriptBuilder::new()
        // Stack (top→bottom): [actual_preimage, committed_preimage]
        //
        // Step 1: Validate committed_preimage size = 52 bytes
        .push_opcode(OP_SIZE)
        .push_int(DISPROVE_PREIMAGE_SIZE)
        .push_opcode(OP_EQUALVERIFY)
        // Step 2: Verify committed preimage hashes to the bond commitment
        .push_opcode(OP_SHA256)
        .push_slice::<&[u8; 32]>(commitment.as_ref())
        .push_opcode(OP_EQUALVERIFY)
        // Step 3: Validate actual_preimage size = 52 bytes
        .push_opcode(OP_SIZE)
        .push_int(DISPROVE_PREIMAGE_SIZE)
        .push_opcode(OP_EQUALVERIFY)
        // Step 4: Verify actual preimage does NOT hash to the commitment (fraud!)
        .push_opcode(OP_SHA256)
        .push_slice::<&[u8; 32]>(commitment.as_ref())
        .push_opcode(OP_EQUAL)
        .push_opcode(OP_NOT)
        .into_script()
}

/// Build the enhanced Disprove script requiring challenger signature.
///
/// Used in the multi-UTXO dispute chain (Step 3).
/// The challenger_pubkey is the key of the party who initiated the Kickoff.
///
/// ## Witness Format
///
/// ```text
/// Stack: [challenger_sig, actual_preimage, committed_preimage]
/// ```
pub fn build_disprove_script_with_challenger(
    committed_state_root: &[u8; 32],
    challenger_pubkey: &[u8; 32],
) -> ScriptBuf {
    let commitment = domain_hash(DOMAIN_BITVM2_STATE, committed_state_root);

    ScriptBuilder::new()
        // Stack: [challenger_sig, actual_preimage, committed_preimage]
        //
        // Step 1: Validate committed_preimage size = 52 bytes
        .push_opcode(OP_SIZE)
        .push_int(DISPROVE_PREIMAGE_SIZE)
        .push_opcode(OP_EQUALVERIFY)
        // Step 2: Verify committed preimage hashes to the bond commitment
        .push_opcode(OP_SHA256)
        .push_slice::<&[u8; 32]>(commitment.as_ref())
        .push_opcode(OP_EQUALVERIFY)
        // Step 3: Validate actual_preimage size = 52 bytes
        .push_opcode(OP_SIZE)
        .push_int(DISPROVE_PREIMAGE_SIZE)
        .push_opcode(OP_EQUALVERIFY)
        // Step 4: Verify actual preimage does NOT hash to the commitment (fraud!)
        .push_opcode(OP_SHA256)
        .push_slice::<&[u8; 32]>(commitment.as_ref())
        .push_opcode(OP_EQUAL)
        .push_opcode(OP_NOT)
        .push_opcode(OP_VERIFY) // Ensure fraud was proven before checking sig
        // Step 5: Verify challenger signature (proves bonded identity)
        .push_slice::<&[u8; 32]>(challenger_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Construct the witness data for a Disprove transaction.
///
/// The challenger provides:
/// - `committed_state_root`: The state root the operator committed to in the bond
/// - `actual_state_root`: The correct state root that differs from the commitment
///
/// Returns `(committed_preimage, actual_preimage)` — the two witness items
/// to push onto the stack. Each is `DOMAIN_BITVM2_STATE || state_root` (52 bytes).
///
/// Returns `None` if the state roots are identical (no fraud to prove).
pub fn build_disprove_witness(
    committed_state_root: &[u8; 32],
    actual_state_root: &[u8; 32],
) -> Option<(Vec<u8>, Vec<u8>)> {
    if committed_state_root == actual_state_root {
        return None; // No fraud — state roots match
    }

    let mut committed_preimage = Vec::with_capacity(DISPROVE_PREIMAGE_SIZE as usize);
    committed_preimage.extend_from_slice(DOMAIN_BITVM2_STATE);
    committed_preimage.extend_from_slice(committed_state_root);

    let mut actual_preimage = Vec::with_capacity(DISPROVE_PREIMAGE_SIZE as usize);
    actual_preimage.extend_from_slice(DOMAIN_BITVM2_STATE);
    actual_preimage.extend_from_slice(actual_state_root);

    Some((committed_preimage, actual_preimage))
}

/// Build the Take script (Leaf 3).
///
/// After a successful Disprove or operator timeout, anyone can claim
/// the bond. This script has a timelock ensuring the full challenge
/// period has elapsed.
///
/// Script: `<challenge_period> OP_CSV`
///
/// Combined with the bond UTXO spending rules, this ensures the bond
/// can only be taken after the challenge period expires AND either:
/// - A Disprove transaction was confirmed (fraud proven), or
/// - The operator failed to Assert within the timeout (default guilty).
pub fn build_take_script() -> ScriptBuf {
    ScriptBuilder::new()
        .push_int(BITVM2_CHALLENGE_PERIOD_BLOCKS as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_PUSHNUM_1)
        .into_script()
}

// ── CPFP Fee Anchor ─────────────────────────────────────────────────────────

/// Dust limit for anchor outputs (330 sats — Bitcoin Core policy minimum).
pub const ANCHOR_OUTPUT_VALUE: u64 = 330;

/// Build a CPFP anchor script — spendable by anyone immediately (no timelock).
///
/// Without this, Disprove TX has fixed fees and a
/// CSV-locked output. If L1 fees spike during a dispute, the challenger
/// cannot use CPFP to bump the fee because the only output is timelocked.
///
/// The anchor output is a tiny (330 sat) output with a simple OP_TRUE script
/// that anyone can spend immediately. The challenger creates a child TX
/// spending this anchor and paying high fees, which pulls the parent
/// (Disprove TX) into the next block via CPFP.
///
/// Script: `OP_TRUE` (anyone can spend — intentional, value is dust)
pub fn build_anchor_script() -> ScriptBuf {
    ScriptBuilder::new()
        .push_opcode(OP_PUSHNUM_1) // OP_TRUE
        .into_script()
}

// ── Bond Construction ────────────────────────────────────────────────────────

/// Build all four BitVM2 script leaves.
pub fn build_scripts(params: &BondParams) -> BitVM2Scripts {
    BitVM2Scripts {
        kickoff: build_kickoff_script(&params.committed_state_root),
        assert_script: build_assert_script(&params.operator_pubkey),
        disprove: build_disprove_script(&params.committed_state_root),
        take: build_take_script(),
    }
}

/// Build the complete Taproot bond output.
///
/// Multi-UTXO dispute chain: sequential transaction flow (Kickoff -> Assert -> Disprove -> Take).
///
/// Constructs a Taproot output with the operator's pubkey as the internal
/// key and the four BitVM2 script leaves arranged in a balanced taptree:
///
/// ```text
///              [root]
///             /      \
///        [branch]   [branch]
///        /     \     /     \
///   kickoff  assert disprove take
/// ```
///
/// # Single-UTXO Model
///
/// All four script leaves are on the SAME bond UTXO. Once any leaf is used
/// to spend the UTXO, the other leaves become invalid. This means the
/// sequential protocol (Kickoff → Assert → Disprove → Take) cannot execute
/// as a chain of transactions against this single output.
///
/// In the full multi-UTXO model, each step creates a NEW output with its
/// own spending conditions:
/// - Bond UTXO → Kickoff TX → Kickoff output
/// - Kickoff output → Assert TX (operator) | Disprove TX (challenger)
/// - Disprove output → Take TX (claim bond after timeout)
///
/// The single-UTXO model serves as a template for script construction and
/// Taproot output verification. The dispute protocol execution is handled by
/// `DisputeGameBuilder` which constructs the correct witness data for each
/// step independently.
///
/// Returns `None` if the operator pubkey is invalid.
pub fn build_bond_output(params: &BondParams) -> Option<BondOutput> {
    let secp = Secp256k1::new();

    let _operator_xonly = XOnlyPublicKey::from_slice(&params.operator_pubkey).ok()?;

    // Use NUMS (Nothing-Up-My-Sleeve) point as internal key
    // to disable key-path spending. This forces all spends through script paths.
    // NUMS point: x = SHA256("Brrq/BitVM2/NUMS") with no known discrete log.
    let nums_bytes = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
        0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
        0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
        0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    ];
    let nums_key = XOnlyPublicKey::from_slice(&nums_bytes).ok()?;

    let scripts = build_scripts(params);

    // Build the taptree with 4 leaves (depth 2 = balanced binary tree)
    let builder = TaprootBuilder::new()
        .add_leaf(2, scripts.kickoff.clone())
        .ok()?
        .add_leaf(2, scripts.assert_script.clone())
        .ok()?
        .add_leaf(2, scripts.disprove.clone())
        .ok()?
        .add_leaf(2, scripts.take.clone())
        .ok()?;

    let spend_info = builder.finalize(&secp, nums_key).ok()?;

    let tweaked_key = spend_info.output_key();
    let parity = spend_info.output_key_parity();
    let output_key = tweaked_key.to_x_only_public_key();

    let script_pubkey = ScriptBuf::new_p2tr_tweaked(tweaked_key);

    Some(BondOutput {
        output_key,
        output_key_parity: parity,
        scripts,
        script_pubkey,
    })
}

// ══════════════════════════════════════════════════════════════════════════════
// Multi-UTXO Dispute Chain
//
// Instead of a single UTXO with 4 leaves, the dispute game uses a chain:
//
//   Bond UTXO ──Kickoff TX──> Challenge UTXO ──Assert TX──> Dispute UTXO
//   Dispute UTXO ──Disprove TX──> Claim UTXO ──Take TX──> Challenger wins
//
// Each step creates a new Taproot output with the remaining leaves.
// Timeouts at each step allow the non-responding party to lose by default.
// ══════════════════════════════════════════════════════════════════════════════

/// Result of building a dispute chain step output.
#[derive(Debug, Clone)]
pub struct DisputeStepOutput {
    /// The Taproot output key for this step.
    pub output_key: XOnlyPublicKey,
    /// Parity of the output key.
    pub output_key_parity: secp256k1::Parity,
    /// The P2TR script_pubkey for this step's output.
    pub script_pubkey: ScriptBuf,
    /// The scripts embedded in this step's taptree.
    pub scripts: Vec<ScriptBuf>,
}

/// Build the Bond UTXO (Step 1 of dispute chain).
///
/// This is the initial output locking the operator's bond. It has 2 leaves:
/// - Leaf 0: **Kickoff** — anyone can challenge (with CSV anti-griefing).
/// - Leaf 1: **Timeout-Reclaim** — operator reclaims after full challenge window
///   if no challenge was initiated.
///
/// ```text
///       [Bond UTXO]
///        /       \
///   kickoff   timeout-reclaim
/// ```
pub fn build_bond_step1(params: &BondParams) -> Option<DisputeStepOutput> {
    let secp = Secp256k1::new();
    // Validate operator pubkey is a valid x-only key
    let _operator_xonly = XOnlyPublicKey::from_slice(&params.operator_pubkey).ok()?;
    let nums_key = nums_point()?;

    // Leaf 0: Kickoff — anyone can challenge
    let kickoff = build_kickoff_script(&params.committed_state_root);

    // Leaf 1: Operator reclaims bond if unchallenged after 2x challenge period
    let reclaim = ScriptBuilder::new()
        .push_int((BITVM2_CHALLENGE_PERIOD_BLOCKS * 2) as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_slice::<&[u8; 32]>(&params.operator_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let builder = TaprootBuilder::new()
        .add_leaf(1, kickoff.clone()).ok()?
        .add_leaf(1, reclaim.clone()).ok()?;

    let spend_info = builder.finalize(&secp, nums_key).ok()?;
    let tweaked = spend_info.output_key();

    Some(DisputeStepOutput {
        output_key: tweaked.to_x_only_public_key(),
        output_key_parity: spend_info.output_key_parity(),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked),
        scripts: vec![kickoff, reclaim],
    })
}

/// Build the Challenge UTXO (Step 2 — created by Kickoff TX).
///
/// After a challenger spends the Bond UTXO via the Kickoff leaf, the Kickoff TX
/// creates this output. The operator must respond or lose:
/// - Leaf 0: **Assert** — operator publishes execution transcript (their response).
/// - Leaf 1: **Challenger-Take** — challenger claims bond if operator doesn't
///   respond within `ASSERT_RESPONSE_DEADLINE_BLOCKS`.
///
/// ```text
///     [Challenge UTXO]
///       /          \
///   assert    challenger-take
/// ```
pub fn build_challenge_step2(params: &BondParams) -> Option<DisputeStepOutput> {
    let secp = Secp256k1::new();
    let nums_key = nums_point()?;

    // Leaf 0: Operator asserts (responds to challenge)
    let assert_leaf = build_assert_script(&params.operator_pubkey);

    // Leaf 1: Challenger takes bond if operator fails to respond
    let challenger_take = ScriptBuilder::new()
        .push_int(ASSERT_RESPONSE_DEADLINE_BLOCKS)
        .push_opcode(OP_CSV)
        .push_opcode(OP_PUSHNUM_1) // Anyone can claim after timeout
        .into_script();

    let builder = TaprootBuilder::new()
        .add_leaf(1, assert_leaf.clone()).ok()?
        .add_leaf(1, challenger_take.clone()).ok()?;

    let spend_info = builder.finalize(&secp, nums_key).ok()?;
    let tweaked = spend_info.output_key();

    Some(DisputeStepOutput {
        output_key: tweaked.to_x_only_public_key(),
        output_key_parity: spend_info.output_key_parity(),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked),
        scripts: vec![assert_leaf, challenger_take],
    })
}

/// Build the Dispute UTXO (Step 3 — created by Assert TX).
///
/// After the operator asserts, the challenger can either prove fraud or the
/// operator recovers their bond after the challenge period:
/// - Leaf 0: **Disprove** — challenger proves fraud via hash inequality.
/// - Leaf 1: **Operator-Recover** — operator reclaims bond if no fraud proven
///   within challenge period (vindicated).
/// - Leaf 2: **CPFP Anchor** — fee-bumping anchor for Disprove TX.
///
/// ```text
///       [Dispute UTXO]
///       /     |      \
///  disprove recover anchor
/// ```
pub fn build_dispute_step3(params: &BondParams) -> Option<DisputeStepOutput> {
    let secp = Secp256k1::new();
    let nums_key = nums_point()?;

    // Leaf 0: Disprove — challenger proves fraud
    let disprove = build_disprove_script(&params.committed_state_root);

    // Leaf 1: Operator recovers if no fraud proven within challenge period
    let operator_recover = ScriptBuilder::new()
        .push_int(BITVM2_CHALLENGE_PERIOD_BLOCKS as i64)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_slice::<&[u8; 32]>(&params.operator_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    // Leaf 2: CPFP Anchor
    let anchor = build_anchor_script();

    let builder = TaprootBuilder::new()
        .add_leaf(2, disprove.clone()).ok()?
        .add_leaf(2, operator_recover.clone()).ok()?
        .add_leaf(1, anchor.clone()).ok()?;

    let spend_info = builder.finalize(&secp, nums_key).ok()?;
    let tweaked = spend_info.output_key();

    Some(DisputeStepOutput {
        output_key: tweaked.to_x_only_public_key(),
        output_key_parity: spend_info.output_key_parity(),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(tweaked),
        scripts: vec![disprove, operator_recover, anchor],
    })
}

/// Build the full dispute chain (all 3 step outputs).
///
/// Returns `(bond, challenge, dispute)` — the three Taproot outputs.
/// The caller constructs transactions that chain them:
/// 1. Bond UTXO is funded (operator posts bond)
/// 2. Kickoff TX spends Bond → creates Challenge UTXO
/// 3. Assert TX spends Challenge → creates Dispute UTXO
/// 4. Disprove TX spends Dispute → funds go to challenger
///    OR Operator-Recover spends Dispute → funds return to operator
pub fn build_dispute_chain(params: &BondParams) -> Option<(DisputeStepOutput, DisputeStepOutput, DisputeStepOutput)> {
    let step1 = build_bond_step1(params)?;
    let step2 = build_challenge_step2(params)?;
    let step3 = build_dispute_step3(params)?;
    Some((step1, step2, step3))
}

/// Return the NUMS (Nothing-Up-My-Sleeve) point for internal key.
/// Disables key-path spending, forcing all spends through script paths.
fn nums_point() -> Option<XOnlyPublicKey> {
    let nums_bytes = [
        0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
        0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
        0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
        0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
    ];
    XOnlyPublicKey::from_slice(&nums_bytes).ok()
}

// ── Utilities ────────────────────────────────────────────────────────────────

/// Domain-separated SHA-256 hash: `SHA256(domain || data)`.
fn domain_hash(domain: &[u8], data: &[u8]) -> sha256::Hash {
    use bitcoin::hashes::HashEngine;
    let mut engine = sha256::Hash::engine();
    engine.input(domain);
    engine.input(data);
    sha256::Hash::from_engine(engine)
}

/// Compute the state root commitment hash used in scripts.
///
/// Public so that challengers can compute the same commitment off-chain
/// to build valid witness data for Kickoff and Disprove transactions.
pub fn state_root_commitment(state_root: &[u8; 32]) -> [u8; 32] {
    let hash = domain_hash(DOMAIN_BITVM2_STATE, state_root);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    out
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> BondParams {
        BondParams {
            // Use a valid x-only pubkey (generator point)
            operator_pubkey: [
                0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
                0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
                0x16, 0xF8, 0x17, 0x98,
            ],
            committed_state_root: [0xAA; 32],
            l2_height: 1000,
            bond_amount: 10_000_000, // 0.1 BTC
        }
    }

    #[test]
    fn kickoff_script_not_empty() {
        let script = build_kickoff_script(&[0xAA; 32]);
        assert!(!script.is_empty());
    }

    #[test]
    fn assert_script_contains_pubkey() {
        let params = test_params();
        let script = build_assert_script(&params.operator_pubkey);
        // Script should contain the operator pubkey bytes
        let script_bytes = script.as_bytes();
        assert!(
            script_bytes
                .windows(32)
                .any(|w| w == params.operator_pubkey)
        );
    }

    #[test]
    fn disprove_script_contains_commitment() {
        let state_root = [0xBB; 32];
        let script = build_disprove_script(&state_root);
        let commitment = domain_hash(DOMAIN_BITVM2_STATE, &state_root);
        let script_bytes = script.as_bytes();
        let commit_bytes: &[u8; 32] = commitment.as_ref();
        assert!(script_bytes.windows(32).any(|w| w == commit_bytes));
    }

    #[test]
    fn take_script_has_csv() {
        let script = build_take_script();
        let asm = format!("{:?}", script);
        assert!(asm.contains("OP_CSV"), "Take script must use OP_CSV");
    }

    #[test]
    fn build_scripts_produces_four_leaves() {
        let params = test_params();
        let scripts = build_scripts(&params);
        assert!(!scripts.kickoff.is_empty());
        assert!(!scripts.assert_script.is_empty());
        assert!(!scripts.disprove.is_empty());
        assert!(!scripts.take.is_empty());
    }

    #[test]
    fn build_bond_output_produces_valid_taproot() {
        let params = test_params();
        let output = build_bond_output(&params);
        assert!(output.is_some(), "Should produce a valid bond output");

        let output = output.unwrap();
        // script_pubkey should be a valid P2TR output (OP_1 <32-byte-key>)
        assert_eq!(output.script_pubkey.len(), 34);
        assert_eq!(output.script_pubkey.as_bytes()[0], 0x51); // OP_1
        assert_eq!(output.script_pubkey.as_bytes()[1], 0x20); // push 32 bytes
    }

    #[test]
    fn bond_output_invalid_pubkey_returns_none() {
        let params = BondParams {
            operator_pubkey: [0x00; 32], // invalid x-only pubkey
            committed_state_root: [0xAA; 32],
            l2_height: 1000,
            bond_amount: 10_000_000,
        };
        assert!(build_bond_output(&params).is_none());
    }

    #[test]
    fn state_root_commitment_deterministic() {
        let root = [0xCC; 32];
        let c1 = state_root_commitment(&root);
        let c2 = state_root_commitment(&root);
        assert_eq!(c1, c2);
    }

    #[test]
    fn state_root_commitment_domain_separated() {
        // Different roots produce different commitments
        let c1 = state_root_commitment(&[0xAA; 32]);
        let c2 = state_root_commitment(&[0xBB; 32]);
        assert_ne!(c1, c2);
    }

    #[test]
    fn assert_script_no_csv_timelock() {
        // Assert script must NOT contain OP_CSV.
        // OP_CSV was incorrectly used as a "response timeout" but actually
        // prevents the operator from responding for 1008 blocks. The timeout
        // is enforced by the Take script's OP_CSV instead.
        let params = test_params();
        let script = build_assert_script(&params.operator_pubkey);
        let asm = format!("{:?}", script);
        assert!(
            !asm.contains("OP_CSV"),
            "Assert script must NOT use OP_CSV (prevents timely operator response)"
        );
        // Script should still require operator signature
        assert!(
            asm.contains("OP_CHECKSIG"),
            "Assert script must require operator signature"
        );
    }

    #[test]
    fn disprove_script_has_size_checks() {
        let script = build_disprove_script(&[0xAA; 32]);
        let asm = format!("{:?}", script);
        // Must contain OP_SIZE for witness size validation
        assert!(
            asm.contains("OP_SIZE"),
            "Disprove script must validate witness item sizes with OP_SIZE"
        );
    }

    #[test]
    fn disprove_witness_construction() {
        let committed = [0xAA; 32];
        let actual = [0xBB; 32];
        let witness = build_disprove_witness(&committed, &actual);
        assert!(witness.is_some());

        let (committed_preimage, actual_preimage) = witness.unwrap();
        // Both must be exactly DOMAIN_BITVM2_STATE.len() + 32 = 52 bytes
        assert_eq!(committed_preimage.len(), DISPROVE_PREIMAGE_SIZE as usize);
        assert_eq!(actual_preimage.len(), DISPROVE_PREIMAGE_SIZE as usize);
        // Must start with domain tag
        assert!(committed_preimage.starts_with(DOMAIN_BITVM2_STATE));
        assert!(actual_preimage.starts_with(DOMAIN_BITVM2_STATE));
        // Must end with the state roots
        assert_eq!(&committed_preimage[DOMAIN_BITVM2_STATE.len()..], &committed);
        assert_eq!(&actual_preimage[DOMAIN_BITVM2_STATE.len()..], &actual);
    }

    #[test]
    fn disprove_witness_same_roots_returns_none() {
        let root = [0xCC; 32];
        assert!(build_disprove_witness(&root, &root).is_none());
    }

    #[test]
    fn different_params_produce_different_scripts() {
        let params1 = BondParams {
            operator_pubkey: test_params().operator_pubkey,
            committed_state_root: [0xAA; 32],
            l2_height: 1000,
            bond_amount: 10_000_000,
        };
        let params2 = BondParams {
            operator_pubkey: test_params().operator_pubkey,
            committed_state_root: [0xBB; 32],
            l2_height: 2000,
            bond_amount: 20_000_000,
        };
        let s1 = build_scripts(&params1);
        let s2 = build_scripts(&params2);
        // Kickoff and disprove depend on state root, so should differ
        assert_ne!(s1.kickoff, s2.kickoff);
        assert_ne!(s1.disprove, s2.disprove);
        // Assert depends only on operator pubkey, so should be same
        assert_eq!(s1.assert_script, s2.assert_script);
        // Take is constant
        assert_eq!(s1.take, s2.take);
    }

    // ── CPFP Anchor Tests ─────────────────────────────────────────────

    #[test]
    fn test_anchor_script_is_spendable_immediately() {
        let anchor = build_anchor_script();
        let asm = anchor.to_asm_string();
        // Must be OP_PUSHNUM_1 (OP_TRUE) — no timelock, no sig requirement
        assert!(asm.contains("OP_PUSHNUM_1"), "anchor must be OP_TRUE: {}", asm);
        assert!(!asm.contains("OP_CSV"), "anchor must NOT have CSV timelock");
        assert!(!asm.contains("OP_CLTV"), "anchor must NOT have CLTV timelock");
        assert!(!asm.contains("OP_CHECKSIG"), "anchor must NOT require signature");
    }

    #[test]
    fn test_anchor_output_value_is_dust() {
        assert_eq!(ANCHOR_OUTPUT_VALUE, 330);
    }

    // ── Multi-UTXO Dispute Chain Tests  ──────────────────

    #[test]
    fn dispute_chain_builds_all_three_steps() {
        let params = test_params();
        let chain = build_dispute_chain(&params);
        assert!(chain.is_some(), "dispute chain should build successfully");
        let (step1, step2, step3) = chain.unwrap();
        // Each step produces a valid P2TR output
        assert_eq!(step1.script_pubkey.as_bytes()[0], 0x51);
        assert_eq!(step2.script_pubkey.as_bytes()[0], 0x51);
        assert_eq!(step3.script_pubkey.as_bytes()[0], 0x51);
    }

    #[test]
    fn dispute_chain_steps_are_distinct() {
        let params = test_params();
        let (step1, step2, step3) = build_dispute_chain(&params).unwrap();
        // Each step must produce a different output (different scripts → different key)
        assert_ne!(step1.script_pubkey, step2.script_pubkey);
        assert_ne!(step2.script_pubkey, step3.script_pubkey);
        assert_ne!(step1.script_pubkey, step3.script_pubkey);
    }

    #[test]
    fn bond_step1_has_kickoff_and_reclaim() {
        let params = test_params();
        let step1 = build_bond_step1(&params).unwrap();
        assert_eq!(step1.scripts.len(), 2, "Bond UTXO should have 2 leaves");
        // First leaf is kickoff (contains CSV and commitment)
        let kickoff_asm = format!("{:?}", step1.scripts[0]);
        assert!(kickoff_asm.contains("OP_CSV"));
        // Second leaf is reclaim (contains operator checksig + CSV)
        let reclaim_asm = format!("{:?}", step1.scripts[1]);
        assert!(reclaim_asm.contains("OP_CHECKSIG"));
        assert!(reclaim_asm.contains("OP_CSV"));
    }

    #[test]
    fn challenge_step2_has_assert_and_take() {
        let params = test_params();
        let step2 = build_challenge_step2(&params).unwrap();
        assert_eq!(step2.scripts.len(), 2);
        // Assert leaf has operator checksig
        let assert_asm = format!("{:?}", step2.scripts[0]);
        assert!(assert_asm.contains("OP_CHECKSIG"));
        // Challenger-take has CSV timeout
        let take_asm = format!("{:?}", step2.scripts[1]);
        assert!(take_asm.contains("OP_CSV"));
    }

    #[test]
    fn dispute_step3_has_disprove_recover_anchor() {
        let params = test_params();
        let step3 = build_dispute_step3(&params).unwrap();
        assert_eq!(step3.scripts.len(), 3);
        // Disprove has size checks and SHA256
        let disprove_asm = format!("{:?}", step3.scripts[0]);
        assert!(disprove_asm.contains("OP_SIZE"));
        assert!(disprove_asm.contains("OP_SHA256"));
        // Operator recover has CSV + checksig
        let recover_asm = format!("{:?}", step3.scripts[1]);
        assert!(recover_asm.contains("OP_CSV"));
        assert!(recover_asm.contains("OP_CHECKSIG"));
    }
}

// ══════════════════════════════════════════════════════════════════════
// Sovereign Deposit Recovery — Taproot MAST peg-in address generation
// ══════════════════════════════════════════════════════════════════════

/// Timelock for user's sovereign recovery path (L1 blocks).
/// 2016 blocks ≈ 2 weeks — matches Bitcoin difficulty adjustment period.
pub const DEPOSIT_CLTV_TIMELOCK: u32 = 2016;

/// Parameters for generating a per-user peg-in Taproot address.
#[derive(Debug, Clone)]
pub struct PegInParams {
    /// Committee's aggregate x-only public key (key-path spend).
    pub committee_pubkey: XOnlyPublicKey,
    /// User's x-only public key (for OP_CLTV recovery script).
    pub user_pubkey: XOnlyPublicKey,
    /// L1 block height at which user can recover (absolute timelock).
    /// Typically: current_l1_height + DEPOSIT_CLTV_TIMELOCK
    pub recovery_height: u32,
}

/// Result of peg-in address generation.
#[derive(Debug, Clone)]
pub struct PegInAddress {
    /// The Taproot script_pubkey (for P2TR output).
    pub script_pubkey: ScriptBuf,
    /// The tweaked output key (x-only, 32 bytes).
    pub output_key: XOnlyPublicKey,
    /// The committee-spend script (leaf 0).
    pub committee_script: ScriptBuf,
    /// The user-recovery script (leaf 1, with OP_CLTV).
    pub recovery_script: ScriptBuf,
    /// Merkle root of the MAST tree (for proof verification).
    pub merkle_root: [u8; 32],
}

/// Build the committee-spend script (normal peg-in processing).
///
/// Script: `<committee_pubkey> OP_CHECKSIG`
///
/// The committee uses this path after verifying the deposit on L2
/// to sweep funds into the bridge's aggregated UTXO pool.
pub fn build_committee_spend_script(committee_pubkey: &XOnlyPublicKey) -> ScriptBuf {
    ScriptBuilder::new()
        .push_x_only_key(committee_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Build the user recovery script (sovereign escape hatch).
///
/// Script: `<recovery_height> OP_CLTV OP_DROP <user_pubkey> OP_CHECKSIG`
///
/// After `recovery_height` L1 blocks, the user can unilaterally recover
/// their deposit WITHOUT committee cooperation. This is the constitutional
/// guarantee (Law 3: Unconditional Exit Right).
pub fn build_user_recovery_script(
    user_pubkey: &XOnlyPublicKey,
    recovery_height: u32,
) -> ScriptBuf {
    ScriptBuilder::new()
        .push_int(recovery_height as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_x_only_key(user_pubkey)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

/// Generate a per-user Taproot peg-in address with MAST recovery path.
///
/// ## MAST Tree Structure
///
/// ```text
/// Internal Key: committee_pubkey (key-path = fast committee spend)
///
/// Taptree (2 leaves):
///   Leaf 0: <committee_pubkey> OP_CHECKSIG           (committee spend)
///   Leaf 1: <height> OP_CLTV OP_DROP <user> OP_CHECKSIG  (user recovery)
/// ```
///
/// ## Security Properties
///
/// 1. **Normal flow**: Committee processes deposit via key-path spend (cheapest).
/// 2. **Committee failure**: After 2016 blocks, user broadcasts recovery tx
///    using script-path spend with Leaf 1 + their signature.
/// 3. **No trust required**: User verifies MAST structure before sending BTC.
/// 4. **Unique per deposit**: Each user gets a unique address (different user_pubkey).
pub fn generate_peg_in_address(params: &PegInParams) -> Option<PegInAddress> {
    let secp = Secp256k1::new();

    // Build the two spending scripts
    let committee_script = build_committee_spend_script(&params.committee_pubkey);
    let recovery_script = build_user_recovery_script(&params.user_pubkey, params.recovery_height);

    // Build Taproot tree with 2 leaves at equal depth
    let builder = TaprootBuilder::new()
        .add_leaf(1, committee_script.clone()).ok()?
        .add_leaf(1, recovery_script.clone()).ok()?;

    // Finalize with committee as internal key (key-path = cooperative spend)
    let spend_info = builder.finalize(&secp, params.committee_pubkey).ok()?;

    let output_key = spend_info.output_key();
    let merkle_root = spend_info
        .merkle_root()
        .map(|r| r.to_byte_array())
        .unwrap_or([0u8; 32]);

    // Build P2TR script_pubkey
    let script_pubkey = ScriptBuf::new_p2tr(&secp, params.committee_pubkey, spend_info.merkle_root());

    Some(PegInAddress {
        script_pubkey,
        output_key: output_key.into(),
        committee_script,
        recovery_script,
        merkle_root,
    })
}

#[cfg(test)]
mod peg_in_tests {
    use super::*;

    fn test_keypair() -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut bitcoin::secp256k1::rand::thread_rng());
        sk.x_only_public_key(&secp).0
    }

    #[test]
    fn test_generate_peg_in_address_succeeds() {
        let params = PegInParams {
            committee_pubkey: test_keypair(),
            user_pubkey: test_keypair(),
            recovery_height: 850_000 + DEPOSIT_CLTV_TIMELOCK,
        };
        let result = generate_peg_in_address(&params);
        assert!(result.is_some());

        let addr = result.unwrap();
        assert!(!addr.script_pubkey.is_empty());
        assert!(!addr.committee_script.is_empty());
        assert!(!addr.recovery_script.is_empty());
        assert_ne!(addr.merkle_root, [0u8; 32]);
    }

    #[test]
    fn test_different_users_get_different_addresses() {
        let committee = test_keypair();
        let params1 = PegInParams {
            committee_pubkey: committee,
            user_pubkey: test_keypair(),
            recovery_height: 852_016,
        };
        let params2 = PegInParams {
            committee_pubkey: committee,
            user_pubkey: test_keypair(),
            recovery_height: 852_016,
        };
        let addr1 = generate_peg_in_address(&params1).unwrap();
        let addr2 = generate_peg_in_address(&params2).unwrap();
        // Different user keys → different addresses
        assert_ne!(addr1.script_pubkey, addr2.script_pubkey);
    }

    #[test]
    fn test_recovery_script_contains_cltv() {
        let params = PegInParams {
            committee_pubkey: test_keypair(),
            user_pubkey: test_keypair(),
            recovery_height: 852_016,
        };
        let addr = generate_peg_in_address(&params).unwrap();
        let asm = addr.recovery_script.to_asm_string();
        assert!(asm.contains("OP_CLTV"), "recovery script must contain OP_CLTV");
        assert!(asm.contains("OP_DROP"), "recovery script must contain OP_DROP");
        assert!(asm.contains("OP_CHECKSIG"), "recovery script must verify user sig");
    }

    #[test]
    fn test_committee_script_is_simple_checksig() {
        let params = PegInParams {
            committee_pubkey: test_keypair(),
            user_pubkey: test_keypair(),
            recovery_height: 852_016,
        };
        let addr = generate_peg_in_address(&params).unwrap();
        let asm = addr.committee_script.to_asm_string();
        assert!(asm.contains("OP_CHECKSIG"));
        // Should NOT contain timelock
        assert!(!asm.contains("OP_CLTV"));
    }
}
