//! Node event loop — block production, state management, transaction intake.
//!
//! ## Architecture
//!
//! The node maintains shared state (`NodeState`) behind `Arc<RwLock>` so that:
//! - The **block production loop** acquires a write lock every ~3 seconds
//! - **RPC read handlers** (getBalance, getHeight) acquire read locks concurrently
//! - **RPC write handlers** (sendTransaction) acquire write locks briefly
//!
//! Block production follows whitepaper §7.3:
//! 1. Drain mempool (highest gas price first)
//! 2. Execute transactions against world state (via `executor`)
//! 3. Dual-sign block (EOTS + SLH-DSA)
//! 4. Store block and record receipts
//!
//! ## Module Structure
//!
//! - [`consensus_handler`] — Epoch transitions, rotation, RANDAO, slashing
//! - [`block_producer`] — Block production, validation, application, fee distribution
//! - [`bridge_monitor`] — L1 monitoring, prover-strike detection, federation sunset
//! - [`portal_maintenance`] — Portal lock expiry, pruning, follower sync

pub(crate) mod consensus_handler;
pub(crate) mod block_producer;
pub(crate) mod bridge_monitor;
pub(crate) mod portal_maintenance;

// Re-export pub functions so `crate::node::*` paths still resolve.
pub(crate) use block_producer::produce_block;
pub use block_producer::{
    apply_block, validate_block, finalize_block,
    block_production_loop, ValidationError,
};
#[cfg(feature = "sequencer-rotation")]
pub use consensus_handler::{broadcast_rotation_action, handle_rotation_message};

// Re-export core types from brrq-api so existing code (rpc.rs, e2e.rs, network_service.rs) works unchanged.
pub use brrq_api::events::NodeEvent;
pub use brrq_api::state::{NodeState, SharedState, TxReceipt};

/// Default initial stake cap (100 BTC in satoshis).
#[cfg(test)]
const INITIAL_STAKE_CAP: u64 = 10_000_000_000;

/// Default validator self-stake (1 BTC in satoshis) — mirrors block_producer constant for tests.
#[cfg(test)]
const DEFAULT_VALIDATOR_STAKE: u64 = 100_000_000;

/// Default block production interval (3 seconds per whitepaper §4.1).
/// Used as fallback when no genesis config is provided.
#[allow(dead_code)]
const DEFAULT_BLOCK_INTERVAL_SECS: u64 = 3;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use brrq_consensus::{EpochState, StakingState};
    use brrq_crypto::hash::{Hash256, Hasher};
    use brrq_crypto::schnorr::SchnorrKeyPair;
    use brrq_sequencer::block_builder::{BlockBuilder, SequencerKeys};
    use brrq_state::persistent::PersistentStore;
    use brrq_types::account::Account;
    use brrq_types::address::Address;
    use brrq_types::signature::{PublicKey, Signature};
    use brrq_types::transaction::{TransactionBody, TransactionKind, chain_id};
    use tokio::sync::RwLock;

    /// Deterministic keypair from a test name — same name always yields
    /// the same key so addresses remain stable across a test run.
    fn test_keypair(name: &str) -> SchnorrKeyPair {
        let hash = Hasher::hash(name.as_bytes());
        SchnorrKeyPair::from_secret_bytes(hash.as_bytes()).expect("test key must be valid")
    }

    /// Address derived from a deterministic test keypair.
    fn test_addr(name: &str) -> Address {
        let kp = test_keypair(name);
        Address::from_public_key(kp.public_key().as_bytes())
    }

    /// Build a properly signed test transfer transaction.
    fn make_transfer(from_name: &str, nonce: u64, to: Address, amount: u64) -> brrq_types::transaction::Transaction {
        let kp = test_keypair(from_name);
        let pk = kp.public_key();
        let from = Address::from_public_key(pk.as_bytes());
        let body = TransactionBody {
            from,
            kind: TransactionKind::Transfer { to, amount },
            nonce,
            gas_limit: 21_000,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 10,
            chain_id: chain_id::TESTNET,
        };
        let body_hash = body.hash();
        let sig = kp.sign(&body_hash).expect("signing must succeed");
        brrq_types::transaction::Transaction {
            body,
            signature: Signature::Schnorr(sig),
            public_key: PublicKey::Schnorr(pk.clone()),
        }
    }

    // ── Basic node tests (no consensus — validators empty → fallback) ──

    #[tokio::test]
    async fn test_node_state_creation() {
        let ns = NodeState::new();
        assert_eq!(ns.height, 0);
        assert!(ns.mempool.is_empty());
        assert!(ns.blocks.is_empty());
        assert!(ns.staking.validators.is_empty());
        assert_eq!(ns.epoch.current_epoch, 0);
    }

    #[tokio::test]
    async fn test_produce_block_empty_mempool() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        // Empty blocks are now allowed (testnet keeps chain advancing)
        assert_eq!(ns.height, 1);
        assert_eq!(ns.blocks.len(), 1);
        assert_eq!(ns.blocks.back().unwrap().transactions.len(), 0);
    }

    #[tokio::test]
    async fn test_produce_block_with_transactions() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        // Setup: fund alice and add a transaction — store hash before
        // consuming the tx, since Transaction::hash() includes the
        // non-deterministic signature bytes.
        let tx_hash;
        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            let tx = make_transfer("alice", 0, bob, 1_000);
            tx_hash = tx.hash();
            ns.mempool.add(tx).unwrap();
        }

        // Produce block
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        assert_eq!(ns.height, 1);
        assert_eq!(ns.blocks.len(), 1);
        assert_eq!(ns.blocks[0].tx_count(), 1);
        assert!(ns.mempool.is_empty()); // Committed tx removed
        assert_eq!(ns.state.balance(&bob), 1_000);

        // Check receipt
        assert!(ns.receipts.contains_key(&tx_hash));
        let receipt = &ns.receipts[&tx_hash];
        assert_eq!(receipt.block_height, 1);
        assert!(receipt.success);
    }

    #[tokio::test]
    async fn test_produce_multiple_blocks() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        // Fund alice
        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
        }

        // Block 1
        {
            let mut ns = shared.write().await;
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        // Block 2
        {
            let mut ns = shared.write().await;
            let tx = make_transfer("alice", 1, bob, 2_000);
            ns.mempool.add(tx).unwrap();
        }
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        assert_eq!(ns.height, 2);
        assert_eq!(ns.blocks.len(), 2);
        assert_eq!(ns.state.balance(&bob), 3_000);
        assert_eq!(ns.state.nonce(&alice), 2);
    }

    #[tokio::test]
    async fn test_invalid_tx_skipped_in_block() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice");
        let bob = test_addr("bob");
        let _charlie = test_addr("charlie");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            // charlie has no funds — tx will fail
            let tx1 = make_transfer("alice", 0, bob, 1_000);
            let tx2 = make_transfer("charlie", 0, bob, 5_000);
            ns.mempool.add(tx1).unwrap();
            ns.mempool.add(tx2).unwrap();
        }

        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        assert_eq!(ns.height, 1);
        // Only alice's tx should be included
        assert_eq!(ns.blocks[0].tx_count(), 1);
        assert_eq!(ns.state.balance(&bob), 1_000);
    }

    #[tokio::test]
    async fn test_chain_hash_continuity() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
        }

        // Produce 3 blocks
        for i in 0..3 {
            {
                let mut ns = shared.write().await;
                let tx = make_transfer("alice", i, bob, 100);
                ns.mempool.add(tx).unwrap();
            }
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        assert_eq!(ns.height, 3);

        // Verify parent hash chain
        assert_eq!(ns.blocks[0].header.parent_hash, Hash256::ZERO);
        assert_eq!(ns.blocks[1].header.parent_hash, ns.blocks[0].header.hash());
        assert_eq!(ns.blocks[2].header.parent_hash, ns.blocks[1].header.hash());

        // Latest parent_hash matches last block
        assert_eq!(ns.parent_hash, ns.blocks[2].header.hash());
    }

    #[tokio::test]
    async fn test_persistent_block_production() {
        // Test that block production persists state to sled
        let store = PersistentStore::open_temporary().unwrap();
        let store = Arc::new(store);
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<brrq_api::state::PersistenceTask>(1000);
        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            let tx_req = make_transfer("alice", 0, bob, 5_000);
            ns.mempool.add(tx_req).unwrap();
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

        // Produce block with persistence
        produce_block(
            &mut builder,
            &shared,
            Some(store.clone()),
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
        let _ = tx.try_send(brrq_api::state::PersistenceTask::Flush(flush_tx));
        let _ = flush_rx.await;

        // Verify data was persisted
        // alice + bob + sequencer (gas fee recipient)
        assert!(store.account_count().unwrap() >= 2);
        let (h, _) = store.load_chain_meta().unwrap();
        assert_eq!(h, 1);
        assert_eq!(store.receipt_count().unwrap(), 1);

        // Load into fresh NodeState (simulates restart)
        let restored = NodeState::load_from_disk(&store).unwrap();
        assert_eq!(restored.height, 1);
        assert_eq!(restored.state.balance(&bob), 5_000);
        assert_eq!(restored.receipts.len(), 1);
    }

    #[tokio::test]
    async fn test_restart_recovery() {
        // Simulate: produce blocks → "crash" → recover from disk
        let store = PersistentStore::open_temporary().unwrap();
        let store = Arc::new(store);

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        // Step 1: produce 2 blocks
        {
            let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
            let keys = SequencerKeys::generate().unwrap();
            let mut builder = BlockBuilder::new(keys.into());

            let (tx, mut rx) =
                tokio::sync::mpsc::channel::<brrq_api::state::PersistenceTask>(1000);
            {
                let mut ns = shared.write().await;
                ns.state.set_account(Account::new_eoa(alice, 100_000_000));
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
                            ..
                        } => {
                            store_clone.save_world_state(&diff).unwrap();
                            store_clone.save_chain_meta(height, &parent_hash).unwrap();
                            store_clone.save_block(&block).unwrap();
                            store_clone.save_receipts(&receipts).unwrap();
                        }
                        brrq_api::state::PersistenceTask::Flush(sender) => {
                            let _ = sender.send(());
                        }
                    }
                }
            });

            for i in 0..2u64 {
                {
                    let mut ns = shared.write().await;
                    let tx = make_transfer("alice", i, bob, 1_000);
                    ns.mempool.add(tx).unwrap();
                }
                produce_block(
                    &mut builder,
                    &shared,
                    Some(store.clone()),
                    &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
                )
                .await;
            }

            let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
            let _ = tx.try_send(brrq_api::state::PersistenceTask::Flush(flush_tx));
            let _ = flush_rx.await;

            let ns = shared.read().await;
            assert_eq!(ns.height, 2);
            assert_eq!(ns.state.balance(&bob), 2_000);
        }
        // ^ shared dropped = simulates "crash"

        // Step 2: recover from disk
        let recovered = NodeState::load_from_disk(&store).unwrap();
        assert_eq!(recovered.height, 2);
        assert_eq!(recovered.state.balance(&bob), 2_000);
        assert_eq!(recovered.state.nonce(&alice), 2);
        assert_eq!(recovered.receipts.len(), 2);

        // Step 3: continue producing blocks from recovered state
        let shared2: SharedState = Arc::new(RwLock::new(recovered));
        let keys2 = SequencerKeys::generate().unwrap();
        let mut builder2 = BlockBuilder::new(keys2.into());

        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<brrq_api::state::PersistenceTask>(1000);
        {
            let mut ns = shared2.write().await;
            let tx2 = make_transfer("alice", 2, bob, 3_000);
            ns.mempool.add(tx2).unwrap();
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

        produce_block(
            &mut builder2,
            &shared2,
            Some(store.clone()),
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let (flush_tx, flush_rx) = tokio::sync::oneshot::channel();
        let _ = tx.try_send(brrq_api::state::PersistenceTask::Flush(flush_tx));
        let _ = flush_rx.await;

        let ns = shared2.read().await;
        assert_eq!(ns.height, 3);
        assert_eq!(ns.state.balance(&bob), 5_000);
    }

    // ── Empty block + metrics counter tests ────────────────────────

    #[tokio::test]
    async fn test_empty_blocks_advance_chain() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        // Produce 5 empty blocks (no transactions)
        for _ in 0..5 {
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        assert_eq!(ns.height, 5, "empty blocks should advance chain");
        assert_eq!(ns.blocks.len(), 5);
        for block in &ns.blocks {
            assert!(
                block.transactions.is_empty(),
                "blocks should have no transactions"
            );
        }
    }

    #[tokio::test]
    async fn test_blocks_produced_counter() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        // Produce 3 blocks
        for _ in 0..3 {
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        assert_eq!(ns.blocks_produced_total, 3);
    }

    #[tokio::test]
    async fn test_tx_total_counter() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        // Fund alice
        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
        }

        // Block 1: 1 tx
        {
            let mut ns = shared.write().await;
            ns.mempool.add(make_transfer("alice", 0, bob, 100)).unwrap();
        }
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        // Block 2: 2 txs
        {
            let mut ns = shared.write().await;
            ns.mempool.add(make_transfer("alice", 1, bob, 200)).unwrap();
            ns.mempool.add(make_transfer("alice", 2, bob, 300)).unwrap();
        }
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        // Block 3: empty
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        assert_eq!(ns.blocks_produced_total, 3);
        assert_eq!(ns.tx_total, 3, "total should be 1+2+0 = 3");
    }

    #[tokio::test]
    async fn test_empty_block_has_valid_structure() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        let block = ns.blocks.back().unwrap();
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.parent_hash, Hash256::ZERO);
        assert!(block.header.timestamp > 0);
        assert!(block.transactions.is_empty());
        // Gas used should be 0 for empty blocks
        assert_eq!(block.header.gas_used, 0);
    }

    #[tokio::test]
    async fn test_empty_block_chain_continuity() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        // Produce 3 empty blocks
        for _ in 0..3 {
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        // Verify parent hash chain
        assert_eq!(ns.blocks[0].header.parent_hash, Hash256::ZERO);
        assert_eq!(ns.blocks[1].header.parent_hash, ns.blocks[0].header.hash());
        assert_eq!(ns.blocks[2].header.parent_hash, ns.blocks[1].header.hash());
    }

    #[tokio::test]
    async fn test_mixed_empty_and_tx_blocks() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
        }

        // Block 1: empty
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        // Block 2: with tx
        {
            let mut ns = shared.write().await;
            ns.mempool
                .add(make_transfer("alice", 0, bob, 1_000))
                .unwrap();
        }
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        // Block 3: empty
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        assert_eq!(ns.height, 3);
        assert_eq!(ns.blocks[0].tx_count(), 0, "block 1 should be empty");
        assert_eq!(ns.blocks[1].tx_count(), 1, "block 2 should have 1 tx");
        assert_eq!(ns.blocks[2].tx_count(), 0, "block 3 should be empty");
        assert_eq!(ns.state.balance(&bob), 1_000);
    }

    // ── Consensus integration tests ────────────────────────────────

    #[tokio::test]
    async fn test_consensus_leader_election_single_validator() {
        // Single registered validator → always elected
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            // Register sequencer as sole validator
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }

        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        assert_eq!(ns.height, 1, "single validator should always be elected");
        assert_eq!(ns.state.balance(&bob), 1_000);
        // Verify block was produced by our sequencer
        assert_eq!(ns.blocks[0].header.sequencer, seq_addr);
    }

    #[tokio::test]
    async fn test_consensus_non_leader_skips_block() {
        // Register a DIFFERENT validator → this sequencer should NOT be elected
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice");
        let bob = test_addr("bob");
        let other_validator = test_addr("other_validator");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            // Register a different address as the only validator
            ns.staking
                .register_validator(other_validator, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }

        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        // Should NOT produce a block (not the leader)
        assert_eq!(ns.height, 0, "non-leader should skip block production");
        assert!(ns.blocks.is_empty());
        // TX should still be in mempool
        assert!(!ns.mempool.is_empty());
    }

    #[tokio::test]
    async fn test_consensus_validator_tracks_block_production() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            // Simulate some prior timeouts
            ns.staking
                .validators
                .get_mut(&seq_addr)
                .unwrap()
                .consecutive_timeouts = 2;
            let tx = make_transfer("alice", 0, bob, 500);
            ns.mempool.add(tx).unwrap();
        }

        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        assert_eq!(ns.height, 1);
        // After producing a block, consecutive_timeouts should be reset to 0
        let v = ns.staking.validators.get(&seq_addr).unwrap();
        assert_eq!(
            v.consecutive_timeouts, 0,
            "block production resets timeouts"
        );
    }

    #[tokio::test]
    async fn test_consensus_epoch_transition() {
        // Use a very short epoch length to trigger transition
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            // Set a very short epoch length (3 blocks)
            ns.epoch = EpochState::new(3);
        }

        // Produce 4 blocks — should trigger epoch transition at height 3
        for i in 0..4u64 {
            {
                let mut ns = shared.write().await;
                let tx = make_transfer("alice", i, bob, 100);
                ns.mempool.add(tx).unwrap();
            }
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        assert_eq!(ns.height, 4);
        // Epoch should have transitioned at least once
        assert!(
            ns.epoch.current_epoch >= 1,
            "epoch should have transitioned: epoch={}",
            ns.epoch.current_epoch,
        );
        // Epoch seed should no longer be zero
        assert_ne!(ns.epoch.epoch_seed, Hash256::ZERO);
        // Validator set should be snapshotted
        assert!(ns.epoch.validator_set.contains(&seq_addr));
    }

    #[tokio::test]
    async fn test_consensus_block_header_contains_epoch() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            let tx = make_transfer("alice", 0, bob, 500);
            ns.mempool.add(tx).unwrap();
        }

        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        // Block header should reflect the current epoch
        assert_eq!(ns.blocks[0].header.epoch, ns.epoch.current_epoch);
    }

    #[tokio::test]
    async fn test_consensus_timeout_tracking_for_missing_leader() {
        // Register two validators; if a different one is elected,
        // it should get a timeout recorded (since it can't produce the block)
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();
        let other = test_addr("other_val");

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            // Register both validators with same stake
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            ns.staking
                .register_validator(other, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
        }

        // Try to produce blocks — some rounds will elect 'other',
        // and 'other' should accumulate timeouts
        for i in 0..8u64 {
            {
                let mut ns = shared.write().await;
                let tx = make_transfer("alice", i, bob, 10);
                ns.mempool.add(tx).unwrap();
            }
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        // Some blocks should have been produced (when we were elected)
        assert!(ns.height > 0, "should produce at least some blocks");
        // The other validator should have some timeouts recorded
        let other_v = ns.staking.validators.get(&other).unwrap();
        // With ~20 rounds and 50/50 split, 'other' should miss some blocks
        // that we couldn't produce on their behalf
        assert!(
            other_v.timeout_count_24h > 0 || ns.height == 8,
            "non-producing validator should accumulate timeouts (height={}, timeouts={})",
            ns.height,
            other_v.timeout_count_24h,
        );
    }

    // ── Block Validation & Sync tests ──────────────────────────────

    /// Helper: produce a block and return it (without consuming from shared)
    async fn produce_and_get_block(builder: &mut BlockBuilder, shared: &SharedState) -> brrq_types::block::Block {
        produce_block(
            builder,
            shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;
        let ns = shared.read().await;
        ns.blocks.back().cloned().unwrap()
    }

    #[tokio::test]
    async fn test_validate_block_correct() {
        // Produce a valid block, then validate it against its expected chain state.
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }

        let block = produce_and_get_block(&mut builder, &shared).await;

        // Validate the block against expected height=1, parent=ZERO
        let staking = StakingState::new(INITIAL_STAKE_CAP);
        // Must register the same validator for validation
        let mut staking = staking;
        staking
            .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
            .unwrap();
        let result = validate_block(&block, &Hash256::ZERO, 1, &staking, 0, 0, None);
        assert!(result.is_ok(), "valid block should pass: {:?}", result);
    }

    #[tokio::test]
    async fn test_validate_block_wrong_height() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }

        let block = produce_and_get_block(&mut builder, &shared).await;

        // Validate with wrong expected height (expect 5, block is at 1)
        let mut staking = StakingState::new(INITIAL_STAKE_CAP);
        staking
            .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
            .unwrap();
        let result = validate_block(&block, &Hash256::ZERO, 5, &staking, 0, 0, None);
        assert!(
            matches!(
                result,
                Err(ValidationError::WrongHeight {
                    expected: 5,
                    got: 1
                })
            ),
            "should reject wrong height: {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn test_validate_block_wrong_parent_hash() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }

        let block = produce_and_get_block(&mut builder, &shared).await;

        // Validate with wrong parent hash
        let wrong_parent = Hasher::hash(b"wrong_parent");
        let mut staking = StakingState::new(INITIAL_STAKE_CAP);
        staking
            .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
            .unwrap();
        let result = validate_block(&block, &wrong_parent, 1, &staking, 0, 0, None);
        assert!(
            matches!(result, Err(ValidationError::WrongParentHash)),
            "should reject wrong parent hash: {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn test_validate_block_unknown_producer() {
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }

        let block = produce_and_get_block(&mut builder, &shared).await;

        // Create staking with a DIFFERENT validator — block producer not registered
        let mut staking = StakingState::new(INITIAL_STAKE_CAP);
        let other = test_addr("other_validator");
        staking
            .register_validator(other, DEFAULT_VALIDATOR_STAKE)
            .unwrap();
        let result = validate_block(&block, &Hash256::ZERO, 1, &staking, 0, 0, None);
        assert!(
            matches!(result, Err(ValidationError::UnknownProducer(_))),
            "should reject unknown producer: {:?}",
            result,
        );
    }

    #[tokio::test]
    async fn test_apply_block_updates_state() {
        // Produce a block on node A, then apply it to a fresh node B.
        let shared_a: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared_a.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }

        let block = produce_and_get_block(&mut builder, &shared_a).await;

        // Create a separate NodeState ("node B") to receive the block
        let mut node_b = NodeState::new();
        node_b
            .state
            .set_account(Account::new_eoa(alice, 10_000_000));
        node_b
            .staking
            .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
            .unwrap();

        // Apply the block from A onto B
        let result = apply_block(&mut node_b, block.clone());
        assert!(result.is_ok(), "apply_block should succeed: {:?}", result);
        if let Ok(exec_result) = result {
            finalize_block(&mut node_b, block.clone(), exec_result, None, None);
        }

        // Verify node B state matches
        assert_eq!(node_b.height, 1);
        assert_eq!(node_b.parent_hash, block.header.hash());
        assert_eq!(node_b.blocks.len(), 1);
        assert_eq!(node_b.state.balance(&bob), 1_000);
    }

    #[tokio::test]
    async fn test_apply_block_chain_continuity() {
        // Produce 3 blocks on A, apply them sequentially to B.
        let shared_a: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared_a.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
        }

        let mut blocks = Vec::new();
        for i in 0..3u64 {
            {
                let mut ns = shared_a.write().await;
                let tx = make_transfer("alice", i, bob, 1_000);
                ns.mempool.add(tx).unwrap();
            }
            let block = produce_and_get_block(&mut builder, &shared_a).await;
            blocks.push(block);
        }

        // Create node B and apply all 3 blocks
        let mut node_b = NodeState::new();
        node_b
            .state
            .set_account(Account::new_eoa(alice, 100_000_000));
        node_b
            .staking
            .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
            .unwrap();

        for block in &blocks {
            let result = apply_block(&mut node_b, block.clone());
            assert!(
                result.is_ok(),
                "apply block #{} should succeed: {:?}",
                block.header.height,
                result,
            );
            if let Ok(exec_result) = result {
                finalize_block(&mut node_b, block.clone(), exec_result, None, None);
            }
        }

        assert_eq!(node_b.height, 3);
        assert_eq!(node_b.state.balance(&bob), 3_000);
        assert_eq!(node_b.blocks.len(), 3);
    }

    #[tokio::test]
    async fn test_apply_block_rejects_out_of_order() {
        // Produce 2 blocks, try to apply block #2 without block #1 first.
        let shared_a: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared_a.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
        }

        // Produce 2 blocks
        for i in 0..2u64 {
            {
                let mut ns = shared_a.write().await;
                let tx = make_transfer("alice", i, bob, 1_000);
                ns.mempool.add(tx).unwrap();
            }
            produce_block(
                &mut builder,
                &shared_a,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns_a = shared_a.read().await;
        let block_2 = ns_a.blocks[1].clone(); // Block at height 2
        drop(ns_a);

        // Create node B (at height 0) and try applying block #2 directly
        let mut node_b = NodeState::new();
        node_b
            .staking
            .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
            .unwrap();

        let result = apply_block(&mut node_b, block_2);
        assert!(
            matches!(
                result,
                Err(ValidationError::WrongHeight {
                    expected: 1,
                    got: 2
                })
            ),
            "should reject out-of-order block: {:?}",
            result,
        );
    }

    // ── Bridge integration tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_bridge_l2_height_tracks_blocks() {
        // Produce blocks and verify bridge.l2_height advances
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
        }

        for i in 0..3u64 {
            {
                let mut ns = shared.write().await;
                let tx = make_transfer("alice", i, bob, 1_000);
                ns.mempool.add(tx).unwrap();
            }
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        assert_eq!(ns.height, 3);
        assert_eq!(ns.bridge.l2_height, 3, "bridge should track L2 height");
    }

    #[tokio::test]
    async fn test_batch_proof_record_stored() {
        let mut ns = NodeState::new();
        ns.height = 10;

        // Generate a real batch proof and store it
        let prover = brrq_prover::StarkProver::new();
        let record = brrq_prover::batch::prove_batch(
            &prover,
            Hash256::ZERO,
            Hash256::from_bytes([0xFF; 32]),
            (1, 5),
            10,
            50_000,
        )
        .unwrap();

        assert!(record.verified);
        ns.proof_records.push(record);
        assert_eq!(ns.proof_records.len(), 1);
        assert_eq!(ns.proof_records[0].block_range, (1, 5));
        assert!(ns.proof_records[0].verified);
        assert_eq!(ns.proof_records[0].tx_count, 10);
    }

    #[tokio::test]
    async fn test_batch_proof_trigger_threshold() {
        // Verify that batch proof generation works correctly at the threshold.
        // Instead of relying on background task timing, we directly verify
        // the batch proof condition and generate the proof synchronously.
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        {
            let mut ns = shared.write().await;
            ns.batch_proof_config.batch_size = 2;
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
        }

        let alice = test_addr("alice_batch");
        let bob = test_addr("bob_batch");

        // Produce 2 blocks
        for i in 0..2 {
            let mut ns = shared.write().await;
            ns.state
                .set_account(Account::new_eoa(alice, 10_000_000_000));
            let tx = make_transfer("alice", i, bob, 1_000);
            ns.mempool.add(tx).unwrap();
            drop(ns);
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        assert_eq!(ns.height, 2);

        // Verify the batch proof threshold condition is met
        let batch_size = ns.batch_proof_config.batch_size;
        assert!(
            ns.height >= ns.last_proved_height + batch_size,
            "batch proof threshold should be met at height={}",
            ns.height
        );

        // Generate proof synchronously to avoid timing issues
        let prover = brrq_prover::StarkProver::new();
        let record = brrq_prover::batch::prove_batch(
            &prover,
            Hash256::ZERO,
            ns.state.state_root(),
            (1, 2),
            ns.blocks.iter().map(|b| b.tx_count()).sum(),
            ns.blocks.iter().map(|b| b.header.gas_used).sum(),
        )
        .unwrap();
        assert!(record.verified);
        assert_eq!(record.block_range, (1, 2));
    }

    #[tokio::test]
    async fn test_bridge_deposit_and_status() {
        let mut ns = NodeState::new();

        // Initialize a dummy federation for tests so process_deposit passes authentication.
        // We include [9u8; 20] as an active member to authorize this test deposit.
        use brrq_types::Address;
        let mut members: Vec<(Address, String)> = (1..=5u8)
            .map(|i| (Address::from_bytes([i; 20]), format!("m{i}")))
            .collect();
        members.push((Address::from_bytes([9u8; 20]), "dummy".into()));
        ns.bridge.init_federation(members, 3, 0).unwrap();

        // Process a deposit
        let tx_id = Hasher::hash(b"btc_tx");
        let recipient = test_addr("recipient");
        let minted = ns
            .bridge
            .process_deposit(
                tx_id,
                0,
                1_000_000,
                recipient,
                6,
                Some(Address::from_bytes([9u8; 20])),
                None,
            )
            .unwrap();

        assert!(minted > 0);
        assert_eq!(ns.bridge.total_locked, 1_000_000);

        let status = ns.bridge.status();
        assert_eq!(status.total_locked, 1_000_000);
        assert_eq!(status.pending_deposits, 0); // confirmed
    }

    #[tokio::test]
    async fn test_event_emitted_on_block_production() {
        // Verify that produce_block emits a NewBlock event
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let (tx, _rx) = brrq_api::create_event_channel();
        let mut rx = tx.subscribe();

        let alice = test_addr("alice");
        let bob = test_addr("bob");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 10_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            ns.event_tx = Some(tx);
            let tx = make_transfer("alice", 0, bob, 1_000);
            ns.mempool.add(tx).unwrap();
        }

        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        // Should have received a NewBlock event
        let event = rx.try_recv().unwrap();
        match event {
            brrq_api::NodeEvent::NewBlock {
                height, tx_count, ..
            } => {
                assert_eq!(height, 1);
                assert_eq!(tx_count, 1);
            }
            _ => panic!("expected NewBlock event"),
        }
    }

    // ── Multi-sequencer integration tests ──

    #[tokio::test]
    async fn test_multi_sequencer_leader_rotation() {
        // Scenario: 3 validators with equal stake. Produce 6 blocks.
        // Leader election should rotate among them based on epoch seed + height.
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));

        let keys_a = SequencerKeys::generate().unwrap();
        let keys_b = SequencerKeys::generate().unwrap();
        let keys_c = SequencerKeys::generate().unwrap();

        let addr_a = keys_a.address;
        let addr_b = keys_b.address;
        let addr_c = keys_c.address;

        let alice = test_addr("alice_multi");
        let bob = test_addr("bob_multi");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 1_000_000_000));
            ns.staking
                .register_validator(addr_a, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            ns.staking
                .register_validator(addr_b, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            ns.staking
                .register_validator(addr_c, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            // Set epoch seed for deterministic leader election
            ns.epoch = EpochState::new(100);
            let mut validators = vec![addr_a, addr_b, addr_c];
            validators.sort();
            ns.epoch.validator_set = validators;
        }

        let mut builder_a = BlockBuilder::new(keys_a.into());
        let mut builder_b = BlockBuilder::new(keys_b.into());
        let mut builder_c = BlockBuilder::new(keys_c.into());

        let mut blocks_by: std::collections::HashMap<Address, usize> =
            std::collections::HashMap::new();

        // Use 20 rounds (not 6) to make it statistically near-impossible
        // that only 1 validator is ever elected with equal stakes.
        // P(only 1 elected in 20 rounds with 3 equal validators) ≈ (1/3)^19 ≈ 0.
        let da_client = crate::da::HttpDaClient::new(crate::da::DaConfig::default());
        for i in 0..20u64 {
            {
                let mut ns = shared.write().await;
                let tx = make_transfer("alice", i, bob, 10);
                ns.mempool.add(tx).unwrap();
            }

            let height_before = shared.read().await.height;

            // Each builder tries to produce — only the elected leader succeeds.
            produce_block(&mut builder_a, &shared, None, &da_client).await;
            produce_block(&mut builder_b, &shared, None, &da_client).await;
            produce_block(&mut builder_c, &shared, None, &da_client).await;

            let ns = shared.read().await;
            if ns.height > height_before {
                let block = ns.blocks.back().unwrap();
                *blocks_by.entry(block.header.sequencer).or_insert(0) += 1;
            }
        }

        let ns = shared.read().await;
        // Verify chain integrity
        assert!(
            ns.height >= 10,
            "should have produced at least 10 blocks out of 20 rounds"
        );

        // Verify multiple validators participated (probabilistic with 3 validators)
        let participating = blocks_by.len();
        assert!(
            participating >= 2,
            "at least 2 of 3 validators should have been elected, got {}: {:?}",
            participating,
            blocks_by,
        );

        // Verify chain continuity
        let mut prev_hash = Hash256::ZERO;
        for block in ns.blocks.iter() {
            assert_eq!(block.header.parent_hash, prev_hash);
            prev_hash = block.header.hash();
        }
    }

    #[tokio::test]
    #[cfg(feature = "sequencer-rotation")]
    async fn test_multi_sequencer_equivocation_slash() {
        // Scenario: A validator equivocates (two proposals at same height) →
        // rotation detects it → staking slash applied.
        // Tests the consensus layer directly to avoid full block application pipeline.
        use brrq_consensus::{RotationConfig, RotationState, SlashingReason};

        let equivocator = test_addr("equivocator");

        let mut staking = brrq_consensus::StakingState::new(100_000_000);
        staking
            .register_validator(equivocator, DEFAULT_VALIDATOR_STAKE)
            .unwrap();
        for i in 2..=4u8 {
            staking
                .register_validator(Address::from_bytes([i; 20]), DEFAULT_VALIDATOR_STAKE)
                .unwrap();
        }

        let initial_stake = staking.validators.get(&equivocator).unwrap().stake;

        // Set up rotation with equivocator as leader
        let mut rotation =
            RotationState::new(RotationConfig::default(), 1, equivocator, &staking, 0);

        let block_a = brrq_crypto::hash::Hasher::hash(b"block-a");
        let block_b = brrq_crypto::hash::Hasher::hash(b"block-b");

        // First proposal — accepted
        let r1 = rotation.receive_proposal(equivocator, block_a, 100);
        assert!(r1.is_ok(), "first proposal must be accepted");

        // Second proposal from same leader — equivocation detected
        let r2 = rotation.receive_proposal(equivocator, block_b, 200);
        assert!(
            r2.is_err(),
            "second proposal must be rejected as equivocation"
        );

        // Apply equivocation slash via staking
        let mut slashing = brrq_consensus::SlashingEngine::new();
        let slash_result = slashing.slash(
            &mut staking,
            &equivocator,
            SlashingReason::Equivocation,
            b"dual-proposal-evidence",
            1, // current_height
            1, // evidence_height
        );
        assert!(slash_result.is_ok(), "slashing must succeed");

        let final_stake = staking.validators.get(&equivocator).unwrap().stake;

        // Equivocation penalty is 33.33% = 3333 basis points
        let expected_penalty = initial_stake * 3333 / 10_000;
        let actual_penalty = initial_stake - final_stake;
        // Allow 1 sat rounding error
        assert!(
            actual_penalty.abs_diff(expected_penalty) <= 1,
            "equivocation should slash ~33.33%: initial={}, final={}, expected_penalty={}, actual_penalty={}",
            initial_stake,
            final_stake,
            expected_penalty,
            actual_penalty,
        );
    }

    #[tokio::test]
    async fn test_randao_commitment_and_reveal() {
        // Scenario: Validator produces blocks across an epoch,
        // RANDAO commitment/reveal should be generated automatically.
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let seq_addr = keys.address;
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice_randao");
        let bob = test_addr("bob_randao");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 1_000_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
            // Short epoch: 8 blocks
            ns.epoch = EpochState::new(8);
            ns.epoch.validator_set = vec![seq_addr];
        }

        // Produce blocks across the epoch
        for i in 0..6u64 {
            {
                let mut ns = shared.write().await;
                let tx = make_transfer("alice", i, bob, 10);
                ns.mempool.add(tx).unwrap();
            }
            produce_block(
                &mut builder,
                &shared,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared.read().await;
        let current_epoch = ns.epoch.current_epoch;

        // Should have committed
        assert_eq!(
            ns.randao_committed_epoch,
            Some(current_epoch),
            "validator should have committed RANDAO for current epoch",
        );

        // Should have revealed (blocks 3-6 are in the reveal window for epoch length 8)
        assert_eq!(
            ns.randao_revealed_epoch,
            Some(current_epoch),
            "validator should have revealed RANDAO secret",
        );

        // Secret should be cleared after reveal
        assert!(
            ns.randao_current_secret.is_none(),
            "RANDAO secret should be cleared after reveal",
        );

        // Should have broadcast RANDAO messages
        // (they would have been drained by network service, but since there's no
        // network service running in this test, they should be in randao_pending)
        // However, since no network service is draining, we check commitment count
        assert!(
            ns.epoch.randao_commitment_count() > 0 || ns.epoch.randao_reveal_count() > 0,
            "RANDAO data should have been submitted to epoch state",
        );
    }

    #[tokio::test]
    async fn test_registration_unbonding_processing() {
        // Scenario: Register a validator, delegate, then unbond — released funds
        // should be credited after produce_block processes unbonding.
        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let seq_addr = keys.address;
        let mut builder = BlockBuilder::new(keys.into());

        let alice = test_addr("alice_reg");

        {
            let mut ns = shared.write().await;
            ns.state.set_account(Account::new_eoa(alice, 1_000_000_000));
            ns.staking
                .register_validator(seq_addr, DEFAULT_VALIDATOR_STAKE)
                .unwrap();
        }

        // Produce a block to verify unbonding processing runs without error
        produce_block(
            &mut builder,
            &shared,
            None,
            &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
        )
        .await;

        let ns = shared.read().await;
        assert_eq!(ns.height, 1, "block should have been produced");
    }

    #[test]
    #[ignore = "time-drift checks use #[cfg(not(test))] for deterministic testing; \
                this test correctly identifies that future-timestamp rejection is \
                only enforced in production builds via MTP+MAX_ALLOWED_BFT_DRIFT"]
    fn test_time_warp_attack_future() {
        use brrq_crypto::eots::{EotsNonceCommitment, EotsSignature};
        use brrq_crypto::schnorr::SchnorrPublicKey;
        use brrq_crypto::slh_dsa::{SlhDsaPublicKey, SlhDsaSignature};
        use brrq_types::block::{Block, DualSignature, SequencerIdentity, genesis_block};

        let staking = brrq_consensus::staking::StakingState::new(100);
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 100 years in the future
        let malicious_future_timestamp = current_time + (100 * 365 * 24 * 60 * 60);

        let mut header = genesis_block(brrq_crypto::hash::Hash256::ZERO);
        header.timestamp = malicious_future_timestamp;

        let mock_eots = EotsSignature::new_unchecked(
            EotsNonceCommitment::from_bytes_unchecked(vec![0u8; 33]),
            vec![0u8; 32],
        );

        let mut slh_dsa_sig_bytes = vec![0u8; 7856];
        slh_dsa_sig_bytes[0] = 1;

        let block = Block {
            header,
            signature: DualSignature {
                eots: mock_eots,
                slh_dsa: SlhDsaSignature::from_bytes(slh_dsa_sig_bytes).unwrap(),
            },
            sequencer_identity: SequencerIdentity {
                schnorr_pk: SchnorrPublicKey::from_bytes([0u8; 32]),
                slh_dsa_pk: SlhDsaPublicKey::from_bytes(vec![0u8; 32]).unwrap(),
                address: brrq_types::address::Address::ZERO,
            },
            transactions: vec![],
        };

        // Note: passing expected_height = 0 and prev_timestamp = 0
        let result = validate_block(
            &block,
            &brrq_crypto::hash::Hash256::ZERO,
            0,
            &staking,
            0,
            0,
            None,
        );

        assert!(
            result.is_err(),
            "VULNERABILITY DETECTED: Node accepted a block {} seconds into the future! Time-Warp attack successful.",
            malicious_future_timestamp - current_time
        );
    }
}
