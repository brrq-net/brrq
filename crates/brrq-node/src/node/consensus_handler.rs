//! Consensus handler — epoch transitions, rotation, RANDAO, slashing.
//! Extracted from node.rs.

#[cfg(feature = "sequencer-rotation")]
use std::sync::Arc;

#[cfg(feature = "sequencer-rotation")]
use bincode::Options;
#[cfg(feature = "sequencer-rotation")]
use brrq_consensus::{LeaderElection, RotationAction, RotationPhase, RotationState};
#[cfg(feature = "sequencer-rotation")]
use brrq_crypto::hash::Hash256;
use brrq_sequencer::block_builder::BlockBuilder;
#[cfg(feature = "sequencer-rotation")]
use brrq_state::persistent::PersistentStore;
#[cfg(feature = "sequencer-rotation")]
use brrq_types::block::Block;

use super::NodeState;
#[cfg(feature = "sequencer-rotation")]
use super::SharedState;

/// Rotation tick interval (500ms) for checking timeouts and state changes.
#[cfg(feature = "sequencer-rotation")]
pub(crate) const ROTATION_TICK_MS: u64 = 500;

/// Event-driven block production loop for multi-sequencer rotation.
///
/// Ticks every 500ms and checks the rotation state machine. The rotation state
/// is initialized at each new height and driven by network messages (proposals,
/// votes, timeout votes) arriving via `handle_rotation_message()`.
#[cfg(feature = "sequencer-rotation")]
pub(crate) async fn rotation_production_loop(
    builder: &mut BlockBuilder,
    shared: &SharedState,
    store: Option<Arc<PersistentStore>>,
    _block_time_secs: u64,
    da_client: &dyn brrq_types::DaSubmit,
) {
    let mut tick = tokio::time::interval(tokio::time::Duration::from_millis(ROTATION_TICK_MS));

    loop {
        tick.tick().await;

        let mut ns = shared.write().await;
        let my_addr = builder.sequencer_address();
        let height = ns.height.saturating_add(1);
        let parent_hash = ns.parent_hash;
        let has_validators = !ns.staking.validators.is_empty();

        if !has_validators {
            continue;
        }

        // Initialize rotation state for new height if needed
        if ns.rotation.is_none() || ns.rotation.as_ref().is_some_and(|r| r.height() < height) {
            let seed = ns.epoch.epoch_seed;
            match LeaderElection::elect(&ns.staking, &parent_hash, height, 0, &seed) {
                Ok(leader) => {
                    let now_ms = now_millis();
                    let config = ns.rotation_config.clone();
                    let rotation = RotationState::new(config, height, leader, &ns.staking, now_ms);
                    tracing::info!(
                        "Rotation: height={}, round=0, leader={}, i_am_leader={}",
                        height,
                        leader,
                        leader == my_addr,
                    );
                    ns.rotation = Some(rotation);
                }
                Err(e) => {
                    tracing::warn!("Rotation leader election failed: {e}");
                    continue;
                }
            }
        }

        // Snapshot rotation phase data (avoids holding immutable borrow across mutable ops)
        let phase_snapshot = match ns.rotation.as_ref() {
            Some(r) => r.phase().clone(),
            None => continue,
        };
        let rotation_leader = ns
            .rotation
            .as_ref()
            .map(|r| *r.leader())
            .unwrap_or(brrq_types::Address::ZERO);
        let rotation_round = ns.rotation.as_ref().map(|r| r.round()).unwrap_or(0);

        match phase_snapshot {
            RotationPhase::WaitingForProposal => {
                if rotation_leader == my_addr {
                    // I'm the leader — produce and broadcast proposal
                    tracing::debug!(
                        "Rotation: I am leader for height={} round={}, producing block",
                        height,
                        rotation_round,
                    );
                    // Drop ns to call produce_block (which acquires its own lock)
                    drop(ns);
                    super::produce_block(builder, shared, store.clone(), da_client).await;
                } else {
                    // Not the leader — check for timeout
                    handle_rotation_timeout(
                        &mut ns, my_addr, height, parent_hash,
                    );
                }
            }
            RotationPhase::PreVoting { .. } | RotationPhase::PreCommitting { .. } => {
                // Votes arrive via network_service → handle_rotation_message.
                // Nothing to do here; the rotation state machine is driven by
                // receive_vote() calls from the network handler.
            }
            RotationPhase::Finalized { block_hash } => {
                tracing::info!(
                    "Rotation: block finalized at height={}, hash={:?}",
                    height,
                    block_hash,
                );
                // Clear rotation state — next tick will initialize for height+1
                ns.rotation = None;

                // =========================================================
                // OPTIMISTIC FINALIZATION
                // =========================================================
                ns.optimistic_snapshot = None; // Drop snapshot, state is permanent
                let Some(block) = ns.optimistic_block.take() else { continue };

                // Extract newly dirtied state logic to disk
                let current_state_root = ns.state.state_root();
                let diff = ns.state.extract_diff();

                let receipt_data_to_store: Vec<_> = block.transactions.iter().filter_map(|tx| {
                    let receipt = ns.receipts.get(&tx.hash())?;
                    Some((tx.hash(), brrq_state::persistent::ReceiptData {
                        block_height: receipt.block_height,
                        gas_used: receipt.gas_used,
                        success: receipt.success,
                        block_hash: receipt.block_hash,
                    }))
                }).collect();

                let Some(store) = store.clone() else { continue };
                let Some(tx) = &ns.persistence_tx else { continue };
                // Serialize bridge state for atomic persistence.
                let bridge_state_blob = ns.bridge.to_bytes().ok();
                if let Err(e) = tx.try_send(brrq_api::state::PersistenceTask::PersistBlock {
                    diff,
                    height: block.header.height,
                    parent_hash: block.header.parent_hash,
                    block: block.clone(),
                    receipts: receipt_data_to_store,
                    state_root: current_state_root,
                    bridge_state_blob,
                    permit: None,
                }) {
                    tracing::error!("Persistence channel full, dropped block {}: {}", block.header.height, e);
                }
            }
        }
    }
}

/// Handle a rotation timeout for a non-leader validator.
///
/// Checks the rotation state machine for a timeout, performs optimistic rollback
/// if needed, broadcasts a timeout vote, and attempts to advance the round.
#[cfg(feature = "sequencer-rotation")]
fn handle_rotation_timeout(
    ns: &mut tokio::sync::RwLockWriteGuard<'_, NodeState>,
    my_addr: brrq_types::Address,
    height: u64,
    parent_hash: Hash256,
) {
    let now_ms = now_millis();
    let timed_out = ns.rotation.as_ref().and_then(|r| r.check_timeout(now_ms));
    let Some(action @ RotationAction::BroadcastTimeout { height: h, round }) = timed_out else {
        return;
    };

    tracing::info!(
        "Rotation: timeout at height={} round={}, broadcasting timeout vote",
        h, round,
    );

    // OPTIMISTIC ROLLBACK: revert any optimistic execution from the block proposal.
    if let Some(snapshot) = ns.optimistic_snapshot.take() {
        ns.restore_snapshot(*snapshot);
        ns.optimistic_block = None;
        tracing::info!(
            "Consensus timeout: Rolled back optimistic state snapshot for height {}.", h
        );
    }

    broadcast_rotation_action(&mut *ns, action);

    // Attempt to advance the round after our own timeout vote.
    let seed = ns.epoch.epoch_seed;
    let ns_ref = &mut **ns;
    let Some(rotation_mut) = ns_ref.rotation.as_mut() else {
        tracing::error!("rotation is None despite check_timeout returning action");
        return;
    };

    let new_round = match rotation_mut.receive_timeout_vote(my_addr) {
        Ok(RotationAction::NewRound { round: r, .. }) => r,
        Ok(_) => return, // Not enough timeout votes yet
        Err(e) => {
            tracing::warn!("Rotation timeout_vote error: {e}");
            return;
        }
    };

    let new_leader = match LeaderElection::elect(
        &ns_ref.staking, &parent_hash, height, new_round, &seed,
    ) {
        Ok(leader) => leader,
        Err(e) => {
            tracing::warn!("Leader election for new round failed: {e}");
            return;
        }
    };

    let now = now_millis();
    if let Err(e) = rotation_mut.advance_round(new_leader, now) {
        tracing::warn!("Rotation advance_round failed: {e}");
    } else {
        tracing::info!(
            "Rotation: advanced to round={}, new leader={}", new_round, new_leader,
        );
    }
}

#[cfg(feature = "sequencer-rotation")]
fn construct_timeout_vote(
    keys: &brrq_sequencer::block_builder::SequencerKeys,
    height: u64,
    round: u32,
    epoch: u64,
) -> Option<brrq_network::Message> {
    let mut hasher = brrq_crypto::hash::Hasher::new();
    hasher.update(brrq_crypto::domain_tags::TIMEOUT_VOTE_V1);
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    let msg_hash = hasher.finalize();

    // Secure nonce generation: offset 0x01 bounds Timeout votes.
    let nonce_height = (0x01_u64 << 60) | (height << 10) | (round as u64);
    // EOTS V1: Consensus votes (timeout/prevote/precommit) are protocol messages,
    // not block proposals — no prev_block_hash available for chain binding.
    // Each vote type uses a distinct nonce domain (0x01/0x02/0x03 << 60).
    #[allow(deprecated)]
    let (nonce_sk, nonce_commitment) = match keys
        .eots_key
        .generate_nonce(nonce_height, epoch)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("EOTS nonce generation failed for timeout vote at height={height} round={round}: {e}");
            return None;
        }
    };

    let eots_sig = match keys
        .eots_key
        .sign(&msg_hash, &nonce_sk, &nonce_commitment)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("EOTS signing failed for timeout vote at height={height} round={round}: {e}");
            return None;
        }
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&eots_sig.nonce_commitment().as_bytes()[1..33]);
    sig_bytes[32..].copy_from_slice(eots_sig.s_value());
    let eots_signature = brrq_types::Signature::Schnorr(
        brrq_crypto::schnorr::SchnorrSignature::from_bytes(sig_bytes),
    );

    Some(brrq_network::Message::TimeoutVote(brrq_network::message::TimeoutVoteMessage {
        height,
        round,
        voter: keys.address,
        eots_signature,
    }))
}

#[cfg(feature = "sequencer-rotation")]
fn construct_prevote(
    keys: &brrq_sequencer::block_builder::SequencerKeys,
    height: u64,
    round: u32,
    epoch: u64,
    block_hash: Hash256,
) -> Option<brrq_network::Message> {
    let mut hasher = brrq_crypto::hash::Hasher::new();
    hasher.update(brrq_crypto::domain_tags::BLOCK_PREVOTE_V1);
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(block_hash.as_bytes());
    let msg_hash = hasher.finalize();

    // Secure nonce generation: offset 0x02 bounds PreVotes.
    let nonce_height = (0x02_u64 << 60) | (height << 10) | (round as u64);
    // EOTS V1: see construct_timeout_vote rationale — consensus votes lack prev_block_hash.
    #[allow(deprecated)]
    let (nonce_sk, nonce_commitment) = match keys
        .eots_key
        .generate_nonce(nonce_height, epoch)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("EOTS nonce generation failed for prevote at height={height} round={round}: {e}");
            return None;
        }
    };

    let eots_sig = match keys
        .eots_key
        .sign(&msg_hash, &nonce_sk, &nonce_commitment)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("EOTS signing failed for prevote at height={height} round={round}: {e}");
            return None;
        }
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&eots_sig.nonce_commitment().as_bytes()[1..33]);
    sig_bytes[32..].copy_from_slice(eots_sig.s_value());
    let eots_signature = brrq_types::Signature::Schnorr(
        brrq_crypto::schnorr::SchnorrSignature::from_bytes(sig_bytes),
    );

    Some(brrq_network::Message::BlockPreVote(brrq_network::message::BlockPreVoteMessage {
        height,
        round,
        block_hash,
        voter: keys.address,
        eots_signature,
    }))
}

#[cfg(feature = "sequencer-rotation")]
fn construct_precommit(
    keys: &brrq_sequencer::block_builder::SequencerKeys,
    height: u64,
    round: u32,
    epoch: u64,
    block_hash: Hash256,
) -> Option<brrq_network::Message> {
    let mut hasher = brrq_crypto::hash::Hasher::new();
    hasher.update(brrq_crypto::domain_tags::BLOCK_PRECOMMIT_V1);
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.update(block_hash.as_bytes());
    let msg_hash = hasher.finalize();

    // Secure nonce generation: offset 0x03 bounds PreCommits.
    let nonce_height = (0x03_u64 << 60) | (height << 10) | (round as u64);
    // EOTS V1: see construct_timeout_vote rationale — consensus votes lack prev_block_hash.
    #[allow(deprecated)]
    let (nonce_sk, nonce_commitment) = match keys
        .eots_key
        .generate_nonce(nonce_height, epoch)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("EOTS nonce generation failed for precommit at height={height} round={round}: {e}");
            return None;
        }
    };

    let eots_sig = match keys
        .eots_key
        .sign(&msg_hash, &nonce_sk, &nonce_commitment)
    {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("EOTS signing failed for precommit at height={height} round={round}: {e}");
            return None;
        }
    };

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&eots_sig.nonce_commitment().as_bytes()[1..33]);
    sig_bytes[32..].copy_from_slice(eots_sig.s_value());
    let eots_signature = brrq_types::Signature::Schnorr(
        brrq_crypto::schnorr::SchnorrSignature::from_bytes(sig_bytes),
    );

    Some(brrq_network::Message::BlockPreCommit(brrq_network::message::BlockPreCommitMessage {
        height,
        round,
        block_hash,
        voter: keys.address,
        eots_signature,
    }))
}

/// Helper to serialize and append a signed consensus message to the broadcast queue.
#[cfg(feature = "sequencer-rotation")]
pub fn broadcast_rotation_action(ns: &mut NodeState, action: RotationAction) {
    let epoch = ns.epoch.current_epoch;
    let keys = match ns.sequencer_keys.as_ref() {
        Some(k) => k.clone(),
        None => return, // No keys, cannot participate in consensus broadcasting
    };

    let msg = match action {
        RotationAction::PreVote {
            height,
            round,
            block_hash,
        } => construct_prevote(&keys, height, round, epoch, block_hash),
        RotationAction::PreCommit {
            height,
            round,
            block_hash,
        } => construct_precommit(&keys, height, round, epoch, block_hash),
        RotationAction::BroadcastTimeout { height, round } => {
            construct_timeout_vote(&keys, height, round, epoch)
        }
        _ => return, // Other actions (Finalize, NewRound, None) don't trigger direct network broadcasts
    };

    let Some(msg) = msg else {
        // EOTS crypto failure — skip this vote round (already logged by construct_* fn)
        return;
    };

    if let Ok(raw) = bincode::options()
        .with_limit(brrq_network::message::MAX_MESSAGE_SIZE as u64)
        .serialize(&msg)
    {
        ns.pending_consensus_messages.push(raw);
    }
}

/// Handle a rotation-related network message.
///
/// Called from `network_service.rs` when a `BlockProposal`, `BlockPreVote`,
/// `BlockPreCommit`, or `TimeoutVote` message is received. Updates the rotation
/// state machine and returns the resulting action for the caller to act on
/// (e.g., broadcast a vote).
#[cfg(feature = "sequencer-rotation")]
pub fn handle_rotation_message(
    ns: &mut NodeState,
    my_addr: brrq_types::Address,
    msg: &brrq_network::Message,
) -> Option<RotationAction> {
    use brrq_network::Message;

    // Check rotation exists and get the current height (without holding borrow)
    let rotation_height = ns.rotation.as_ref()?.height();

    match msg {
        Message::BlockProposal(proposal) => {
            if proposal.height != rotation_height {
                return None;
            }
            let now_ms = now_millis();
            let action_res = ns.rotation.as_mut()?.receive_proposal(
                proposal.proposer,
                proposal.block_hash,
                now_ms,
            );

            match action_res {
                Ok(action @ RotationAction::PreVote { .. }) => {
                    tracing::debug!(
                        "Rotation: prevoting for proposal from {} at height={}",
                        proposal.proposer,
                        proposal.height,
                    );

                    // =========================================================
                    // OPTIMISTIC SNAPSHOT AND DRY-RUN PRE-VALIDATION
                    // =========================================================
                    if proposal.block_data.is_empty() {
                        tracing::warn!("Empty block data from proposer {}", proposal.proposer);
                        return None;
                    }

                    let block: Block = match bincode::options()
                        .with_limit(32 * 1024 * 1024)
                        .deserialize(&proposal.block_data)
                    {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!(
                                "Failed to deserialize block from {}: {e}",
                                proposal.proposer
                            );
                            // Invalid proposal, revert our record of having received it?
                            // BFT handles equivocation, but invalid blocks can be safely ignored.
                            return None;
                        }
                    };

                    if !block.verify_signature() {
                        tracing::warn!("Invalid signature on block from {}", proposal.proposer);
                        return None;
                    }

                    // Take a pristine snapshot prior to applying any WorldState mutations.
                    let snapshot = ns.snapshot();

                    // Optimistically execute the proposed block locally without disk persistence.
                    let exec_result = match super::apply_block(ns, block.clone()) {
                        Ok(res) => res,
                        Err(e) => {
                            tracing::warn!(
                                "Block proposal {} execution failed: {e}. Restoring state snapshot.",
                                proposal.block_hash
                            );
                            // Abort the vote if execution fails, and cleanly revert the memory changes.
                            ns.restore_snapshot(snapshot);
                            return None;
                        }
                    };

                    // Execution passed! Save the snapshot for future rollbacks on timeouts.
                    ns.optimistic_snapshot = Some(Box::new(snapshot));
                    ns.optimistic_exec_result = Some(exec_result);
                    ns.optimistic_block = Some(block);

                    // Proceed to cast our own internal prevote against this valid block.
                    if let Ok(precommit_action) =
                        ns.rotation
                            .as_mut()?
                            .receive_prevote(my_addr, proposal.block_hash, now_ms)
                        && matches!(precommit_action, RotationAction::PreCommit { .. })
                    {
                        return Some(precommit_action);
                    }
                    Some(action)
                }
                Ok(action) => {
                    if action != RotationAction::None {
                        Some(action)
                    } else {
                        None
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "Rotation: equivocation detected from {}: {e}",
                        proposal.proposer,
                    );

                    // Verify the proposal's block data before slashing to prevent
                    // malicious peers from fabricating equivocation evidence with
                    // forged signatures to slash innocent validators.
                    let sig_valid = if !proposal.block_data.is_empty() {
                        // Deserialize the proposed block and verify its dual signature
                        let des_res: Result<Block, _> = bincode::options()
                            .with_limit(32 * 1024 * 1024)
                            .deserialize(&proposal.block_data);
                        match des_res {
                            Ok(block) => block.verify_signature(),
                            Err(_) => false,
                        }
                    } else {
                        // Empty block_data — cannot verify signature, reject evidence
                        false
                    };

                    if !sig_valid {
                        tracing::warn!(
                            "Equivocation evidence from {} has invalid/missing block signature — ignoring",
                            proposal.proposer,
                        );
                        return None;
                    }

                    // Signature verified — proceed with slash
                    let context = proposal.block_hash;
                    let current_height = ns.height;
                    let ns_ref = &mut *ns;
                    match ns_ref.slashing.slash(
                        &mut ns_ref.staking,
                        &proposal.proposer,
                        brrq_consensus::SlashingReason::Equivocation,
                        &context.0,
                        current_height,
                        current_height,
                    ) {
                        Ok(result) => {
                            tracing::warn!(
                                "Slashed {} for equivocation: penalty={}",
                                result.validator,
                                result.total_slashed,
                            );
                        }
                        Err(slash_err) => {
                            tracing::debug!(
                                "Equivocation slash skipped for {}: {slash_err}",
                                proposal.proposer,
                            );
                        }
                    }
                    None
                }
            }
        }
        Message::BlockPreVote(vote) => {
            if vote.height != rotation_height {
                return None;
            }
            let rotation = ns.rotation.as_mut()?;
            let now_ms = now_millis();
            match rotation.receive_prevote(vote.voter, vote.block_hash, now_ms) {
                Ok(action @ RotationAction::PreCommit { .. }) => {
                    tracing::debug!(
                        "Rotation: 2/3 PreVote quorum reached at height={}, broadcasting PreCommit",
                        vote.height,
                    );
                    Some(action)
                }
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!("Rotation prevote error: {e}");
                    None
                }
            }
        }
        Message::BlockPreCommit(commit) => {
            if commit.height != rotation_height {
                return None;
            }
            let rotation = ns.rotation.as_mut()?;
            match rotation.receive_precommit(commit.voter, commit.block_hash) {
                Ok(action @ RotationAction::Finalize { .. }) => {
                    tracing::info!(
                        "Rotation: 2/3 PreCommit quorum reached at height={}, finalizing",
                        commit.height,
                    );
                    Some(action)
                }
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!("Rotation precommit error: {e}");
                    None
                }
            }
        }
        Message::TimeoutVote(timeout) => {
            if timeout.height != rotation_height {
                return None;
            }
            // Split borrow: use ns_ref to access disjoint fields
            let ns_ref = &mut *ns;
            let rotation = ns_ref.rotation.as_mut()?;
            match rotation.receive_timeout_vote(timeout.voter) {
                Ok(RotationAction::NewRound {
                    round: new_round, ..
                }) => {
                    let parent_hash = ns_ref.parent_hash;
                    let seed = ns_ref.epoch.epoch_seed;
                    match LeaderElection::elect(
                        &ns_ref.staking,
                        &parent_hash,
                        timeout.height,
                        new_round,
                        &seed,
                    ) {
                        Ok(new_leader) => {
                            let now = now_millis();
                            if let Err(e) = rotation.advance_round(new_leader, now) {
                                tracing::warn!("Rotation advance_round failed: {e}");
                                return None;
                            }
                            tracing::info!(
                                "Rotation: timeout quorum → round={}, leader={}",
                                new_round,
                                new_leader,
                            );
                            Some(RotationAction::NewRound {
                                round: new_round,
                                leader: new_leader,
                            })
                        }
                        Err(e) => {
                            tracing::warn!("Leader election for timeout round failed: {e}");
                            None
                        }
                    }
                }
                Ok(_) => None,
                Err(e) => {
                    tracing::warn!("Rotation timeout vote error: {e}");
                    None
                }
            }
        }
        Message::ShareDistribution(share_msg) => {
            // Route share distribution messages to PendingShares
            // for threshold key reconstruction (§4.7 MEV Protection).

            // Validate epoch matches
            if share_msg.epoch != ns.epoch.current_epoch {
                tracing::warn!(
                    share_epoch = share_msg.epoch,
                    current_epoch = ns.epoch.current_epoch,
                    "Ignoring share for wrong epoch"
                );
                return None;
            }

            // Validate sender is in the current validator set
            if !ns.epoch.validator_set.contains(&share_msg.sender) {
                tracing::warn!(sender = ?share_msg.sender, "Share from non-validator");
                return None;
            }

            let share = brrq_crypto::encryption::KeyShare::new(
                share_msg.share_index,
                share_msg.share_data,
            );
            let threshold_reached = ns.pending_shares.add_share(share, share_msg.sender, ns.height);

            if threshold_reached {
                tracing::info!(
                    epoch = share_msg.epoch,
                    "Share threshold reached — attempting epoch key reconstruction"
                );
                if let Some(Ok(_key)) = ns.pending_shares.try_reconstruct() {
                    tracing::info!(epoch = share_msg.epoch, "Epoch key reconstructed");
                }
            }
            None
        }
        _ => None,
    }
}

/// Get the current time in milliseconds.
///
/// Uses `Instant::now()` relative to a fixed epoch for monotonic behavior.
/// `SystemTime` can go backwards due to NTP adjustments, which would cause
/// rotation timeouts to fire incorrectly or never fire.
#[cfg(feature = "sequencer-rotation")]
fn now_millis() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_millis() as u64
}

/// Handle RANDAO commit/reveal participation for the current validator.
///
/// Handle RANDAO commit/reveal for the current epoch phase.
/// Commit in the first quarter of the epoch.
/// Reveal in the second quarter.
pub(crate) fn participate_in_randao(ns: &mut NodeState, builder: &mut BlockBuilder, height: u64) {
    let my_addr = builder.sequencer_address();
    let current_epoch = ns.epoch.current_epoch;
    let blocks_into_epoch = height.saturating_sub(ns.epoch.epoch_start_height);
    let epoch_quarter = ns.epoch.epoch_length / 4;
    let is_in_active_set = ns.epoch.validator_set.contains(&my_addr);

    if !is_in_active_set {
        return;
    }

    // Commit in the first quarter of the epoch.
    if blocks_into_epoch <= epoch_quarter && ns.randao_committed_epoch != Some(current_epoch) {
        let secret = builder.randao_secret(current_epoch);
        let commitment = brrq_crypto::hash::Hasher::hash(secret.as_bytes());
        ns.randao_current_secret = Some(secret);
        // Persist RANDAO secret so crash after commit doesn't cause penalty
        if let Some(ref s) = ns.store {
            if let Err(e) = s.save_randao_secret(current_epoch, &secret) {
                tracing::error!("Failed to persist RANDAO secret: {e}");
            }
        }

        if ns
            .epoch
            .submit_randao_commitment(my_addr, commitment)
            .is_ok()
        {
            let msg_hash = {
                use brrq_crypto::hash::Hasher;
                let mut h = Hasher::new();
                h.update(brrq_crypto::domain_tags::RANDAO_COMMITMENT_V1);
                h.update(&current_epoch.to_le_bytes());
                h.update(commitment.as_bytes());
                h.finalize()
            };
            let sig = builder.sign_randao(&msg_hash, current_epoch, false);
            ns.randao_committed_epoch = Some(current_epoch);
            ns.randao_pending.push(brrq_api::state::PendingRandaoMsg {
                epoch: current_epoch,
                validator: my_addr,
                data: commitment,
                is_reveal: false,
                signature: sig,
            });
            tracing::info!(
                "RANDAO: committed for epoch {}, commitment={:?}",
                current_epoch,
                commitment,
            );
        }
    }

    // Reveal in the second quarter of the epoch.
    if let Some(secret) = ns.randao_current_secret
        && blocks_into_epoch > epoch_quarter
        && blocks_into_epoch <= epoch_quarter * 3
        && ns.randao_revealed_epoch != Some(current_epoch)
        && ns.randao_committed_epoch == Some(current_epoch)
        && ns.epoch.submit_randao_reveal(my_addr, secret, height)
    {
        let msg_hash = {
            use brrq_crypto::hash::Hasher;
            let mut h = Hasher::new();
            h.update(brrq_crypto::domain_tags::RANDAO_REVEAL_V1);
            h.update(&current_epoch.to_le_bytes());
            h.update(secret.as_bytes());
            h.finalize()
        };
        let sig = builder.sign_randao(&msg_hash, current_epoch, true);
        ns.randao_revealed_epoch = Some(current_epoch);
        ns.randao_current_secret = None;
        if let Some(ref s) = ns.store {
            let _ = s.clear_randao_secret();
        }
        ns.randao_pending.push(brrq_api::state::PendingRandaoMsg {
            epoch: current_epoch,
            validator: my_addr,
            data: secret,
            is_reveal: true,
            signature: sig,
        });
        tracing::info!("RANDAO: revealed for epoch {}", current_epoch);
    }
}
