//! Multi-sequencer E2E tests.
//!
//! Validates sequencer rotation, BFT voting, equivocation slashing,
//! and RANDAO integration across 3 validator nodes.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use tokio::sync::RwLock;

    use brrq_consensus::{LeaderElection, StakingState};
    #[cfg(feature = "sequencer-rotation")]
    use brrq_consensus::{RotationAction, RotationConfig, RotationState};
    use brrq_crypto::hash::{Hash256, Hasher};
    use brrq_sequencer::block_builder::{BlockBuilder, SequencerKeys};
    use brrq_state::persistent::PersistentStore;
    use brrq_types::account::Account;
    use brrq_types::address::Address;

    use crate::node::{NodeState, SharedState};

    fn addr(n: u8) -> Address {
        Address::from_bytes([n; 20])
    }

    /// Helper: create a SharedState with the builder as the dominant validator
    /// plus 2 others. The builder gets highest stake to always win leader election.
    async fn setup_three_validators() -> (SharedState, BlockBuilder) {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let builder = BlockBuilder::new(keys.into());
        let my_addr = builder.sequencer_address();

        {
            let mut ns = shared.write().await;
            // Register builder with overwhelming stake so it wins leader election
            // nearly every round (97%+ probability per round).
            // With 950M / 1000M = 95% win rate and 8 attempts,
            // P(wins >= 4) > 99.99% — effectively deterministic.
            ns.staking.register_validator(my_addr, 950_000_000).unwrap();
            // Register 2 more with minimal stake
            for i in 2..=3u8 {
                ns.staking.register_validator(addr(i), 25_000_000).unwrap();
            }

            let alice = addr(0xAA);
            ns.state.set_account(Account::new_eoa(alice, 500_000_000));
        }

        (shared, builder)
    }

    // ═══════════════════════════════════════════════════════════════
    // Test 1: Three validators — leader election produces blocks
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn multi_seq_leader_election_and_block_production() {
        let (shared, mut builder) = setup_three_validators().await;
        let da_client = crate::da::HttpDaClient::new(crate::da::DaConfig::default());

        // Attempt 8 produce_block calls — not all will succeed because
        // leader election may select a different validator some rounds.
        for _ in 0..8 {
            crate::node::produce_block(&mut builder, &shared, None, &da_client).await;
        }

        let ns = shared.read().await;
        assert!(
            ns.height >= 4,
            "should have produced at least 4 blocks out of 8 attempts with dominant stake (got {})",
            ns.height
        );
        assert_eq!(
            ns.blocks.len(),
            ns.height as usize,
            "block count matches height"
        );

        // Verify block chain integrity
        for i in 1..ns.blocks.len() {
            let prev = &ns.blocks[i - 1];
            let curr = &ns.blocks[i];
            assert_eq!(
                curr.header.parent_hash,
                prev.hash(),
                "block {} parent hash must match block {} hash",
                curr.header.height,
                prev.header.height
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Test 2: Consensus rotation — leader elected via VRF + stake
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn multi_seq_rotation_leader_elected() {
        let mut staking = StakingState::new(100_000_000);
        for i in 1..=3u8 {
            staking.register_validator(addr(i), 100_000_000).unwrap();
        }

        let vrf_seed = Hasher::hash(b"rotation-test-seed");
        let prev_hash = Hash256::ZERO;

        // Elect leader at height 1
        let leader = LeaderElection::elect(&staking, &prev_hash, 1, 0, &vrf_seed);
        assert!(leader.is_ok(), "must elect a leader");

        let leader = leader.unwrap();
        assert!(
            leader == addr(1) || leader == addr(2) || leader == addr(3),
            "leader must be a registered validator"
        );

        // Advance height — leaders may rotate
        let mut leaders_seen = std::collections::HashSet::new();
        for h in 1..=100u64 {
            if let Ok(l) = LeaderElection::elect(&staking, &prev_hash, h, 0, &vrf_seed) {
                leaders_seen.insert(l);
            }
        }
        assert_eq!(
            leaders_seen.len(),
            3,
            "all 3 equal-stake validators must appear as leaders over 100 heights (got {})",
            leaders_seen.len()
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Test 3: BFT quorum — 2/3 votes finalize, less does not
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    #[cfg(feature = "sequencer-rotation")]
    async fn multi_seq_bft_quorum_finalization() {
        let mut staking = StakingState::new(100_000_000);
        for i in 1..=3u8 {
            staking.register_validator(addr(i), 100_000_000).unwrap();
        }

        let vrf_seed = Hasher::hash(b"quorum-test");
        let prev_hash = Hash256::ZERO;

        let leader = LeaderElection::elect(&staking, &prev_hash, 1, 0, &vrf_seed).unwrap();

        let mut rotation = RotationState::new(RotationConfig::default(), 1, leader, &staking, 0);

        let block_hash = Hasher::hash(b"test-block");

        // Leader proposes
        let result = rotation.receive_proposal(leader, block_hash, 100);
        assert!(result.is_ok(), "proposal from leader must succeed");

        // 1 prevote — not enough for quorum
        let action = rotation.receive_prevote(addr(1), block_hash, 0u64).unwrap();
        assert!(
            !matches!(action, RotationAction::Finalize { .. }),
            "1/3 prevotes should not finalize"
        );

        // 2nd prevote — reaches 2/3 quorum, triggers precommit phase
        let action = rotation.receive_prevote(addr(2), block_hash, 0u64).unwrap();
        assert!(
            matches!(action, RotationAction::PreCommit { .. }),
            "2/3 prevotes should trigger precommit"
        );

        // Precommit phase: 2/3 precommits to finalize
        let _ = rotation.receive_precommit(addr(1), block_hash).unwrap();
        let action = rotation.receive_precommit(addr(2), block_hash).unwrap();
        let finalized = matches!(action, RotationAction::Finalize { .. });
        assert!(finalized, "2/3 precommits should finalize the block");
    }

    // ═══════════════════════════════════════════════════════════════
    // Test 4: Equivocation detection — two proposals at same height
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    #[cfg(feature = "sequencer-rotation")]
    async fn multi_seq_equivocation_detected() {
        let mut staking = StakingState::new(100_000_000);
        for i in 1..=3u8 {
            staking.register_validator(addr(i), 100_000_000).unwrap();
        }

        let vrf_seed = Hasher::hash(b"equivocation-test");
        let prev_hash = Hash256::ZERO;

        let leader = LeaderElection::elect(&staking, &prev_hash, 1, 0, &vrf_seed).unwrap();

        let mut rotation = RotationState::new(RotationConfig::default(), 1, leader, &staking, 0);

        let block_a = Hasher::hash(b"block-a");
        let block_b = Hasher::hash(b"block-b");

        // First proposal — legitimate
        let r1 = rotation.receive_proposal(leader, block_a, 100);
        assert!(r1.is_ok());

        // Second proposal from same leader at same height — equivocation!
        let r2 = rotation.receive_proposal(leader, block_b, 200);
        assert!(
            r2.is_err(),
            "second proposal from same leader must be rejected as equivocation"
        );
    }

    // ═══════════════════════════════════════════════════════════════
    // Test 5: Epoch tracking across multiple blocks
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn multi_seq_epoch_tracking() {
        let (shared, mut builder) = setup_three_validators().await;
        let da_client = crate::da::HttpDaClient::new(crate::da::DaConfig::default());

        for _ in 0..5 {
            crate::node::produce_block(&mut builder, &shared, None, &da_client).await;
        }

        let ns = shared.read().await;
        assert!(
            ns.height >= 2,
            "should have produced at least 2 blocks out of 5 attempts with dominant stake (got {})",
            ns.height
        );
        // At any height < 7200 with epoch_length=7200, we're still in epoch 0
        assert_eq!(ns.epoch.epoch_for_height(ns.height), 0, "still in epoch 0");
    }

    // ═══════════════════════════════════════════════════════════════
    // Test 6: Unequal stake — sqrt(x) cap compresses ratios
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn multi_seq_sqrt_cap_fairness() {
        let mut staking = StakingState::new(100_000_000);
        // Validator 1: whale (10 BTC)
        staking.register_validator(addr(1), 1_000_000_000).unwrap();
        // Validator 2: normal (1 BTC)
        staking.register_validator(addr(2), 100_000_000).unwrap();

        let e1 = staking.effective_stake(&addr(1)).unwrap_or(0);
        let e2 = staking.effective_stake(&addr(2)).unwrap_or(0);

        // With sqrt cap, the whale's effective stake should be compressed from 10:1
        if e2 > 0 {
            let ratio = e1 as f64 / e2 as f64;
            assert!(
                ratio < 5.0,
                "sqrt cap should compress 10:1 stake ratio (got {:.2}:1)",
                ratio
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // Test 7: Block production with persistence (recovery)
    // ═══════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn multi_seq_persistence_and_recovery() {
        let store = Arc::new(PersistentStore::open_temporary().unwrap());

        let (shared, mut builder) = setup_three_validators().await;
        let da_client = crate::da::HttpDaClient::new(crate::da::DaConfig::default());

        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<brrq_api::state::PersistenceTask>(1000);
        {
            let mut ns = shared.write().await;
            ns.persistence_tx = Some(tx.clone());
        }

        let store_clone = store.clone();
        tokio::spawn(async move {
            while let Some(task) = rx.recv().await {
                match task {
                    brrq_api::state::PersistenceTask::PersistBlock {
                        diff,
                        height,
                        parent_hash,
                        block,
                        receipts,
                        state_root,
                        ..
                    } => {
                        store_clone.save_world_state(&diff).unwrap();
                        store_clone.save_chain_meta(height, &parent_hash).unwrap();
                        store_clone.save_state_root(&state_root).unwrap();
                        store_clone.save_block(&block).unwrap();
                        store_clone.save_receipts(&receipts).unwrap();
                    }
                    brrq_api::state::PersistenceTask::Flush(sender) => {
                        let _ = sender.send(());
                    }
                }
            }
        });

        for _ in 0..5 {
            crate::node::produce_block(&mut builder, &shared, Some(store.clone()), &da_client)
                .await;
        }

        let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
        let _ = tx.try_send(brrq_api::state::PersistenceTask::Flush(flush_tx));
        let _ = flush_rx.await;

        let ns = shared.read().await;
        assert!(
            ns.height >= 2,
            "should have produced at least 2 blocks out of 5 attempts with persistence (got {})",
            ns.height
        );

        // Verify blocks are persisted
        let (stored_height, _parent_hash) = store.load_chain_meta().unwrap();
        assert_eq!(stored_height, ns.height, "store must reflect block height");
    }
}
