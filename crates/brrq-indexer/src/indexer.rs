//! Indexer engine — converts Brrq blocks into indexed database records.

use brrq_crypto::hash::Hash256;
use brrq_types::block::Block;
use brrq_types::transaction::TransactionKind;
use tracing::warn;

use crate::db::Database;
use crate::models::{IndexedBlock, IndexedTransaction};

/// Blockchain indexer that processes blocks into SQLite.
pub struct Indexer {
    db: Database,
}

impl Indexer {
    /// Create a new indexer with the given database.
    pub fn new(db: Database) -> Self {
        Self { db }
    }

    /// Get a reference to the database.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Index a single block and its transactions atomically.
    pub fn index_block(
        &self,
        block: &Block,
        receipts: &std::collections::HashMap<Hash256, (u64, bool)>,
    ) -> Result<(), rusqlite::Error> {
        self.db.conn.execute("BEGIN", [])?;

        let result = self.index_block_inner(block, receipts);

        match result {
            Ok(()) => {
                self.db.conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                if let Err(rb_err) = self.db.conn.execute("ROLLBACK", []) {
                    warn!(
                        rollback_error = %rb_err,
                        original_error = %e,
                        "ROLLBACK failed after index_block error"
                    );
                }
                Err(e)
            }
        }
    }

    /// Inner implementation of block indexing (called within a transaction).
    fn index_block_inner(
        &self,
        block: &Block,
        receipts: &std::collections::HashMap<Hash256, (u64, bool)>,
    ) -> Result<(), rusqlite::Error> {
        let block_hash = block.hash();
        let indexed_block = IndexedBlock {
            height: block.header.height,
            hash: format!("0x{}", hex::encode(block_hash.as_bytes())),
            parent_hash: format!("0x{}", hex::encode(block.header.parent_hash.as_bytes())),
            timestamp: block.header.timestamp,
            tx_count: block.transactions.len(),
            gas_used: block.header.gas_used,
            gas_limit: block.header.gas_limit,
            state_root: format!("0x{}", hex::encode(block.header.state_root.as_bytes())),
            sequencer: format!("0x{}", hex::encode(block.header.sequencer.as_bytes())),
            epoch: block.header.epoch,
            size_bytes: block.size(),
        };
        self.db.insert_block(&indexed_block)?;

        for (i, tx) in block.transactions.iter().enumerate() {
            let tx_hash = tx.hash();
            let (to_addr, amount, tx_type) = match &tx.body.kind {
                TransactionKind::Transfer { to, amount } => (
                    Some(format!("0x{}", hex::encode(to.as_bytes()))),
                    Some(*amount),
                    "transfer",
                ),
                TransactionKind::Deploy { .. } => (None, None, "deploy"),
                TransactionKind::ContractCall { to, value, .. } => (
                    Some(format!("0x{}", hex::encode(to.as_bytes()))),
                    Some(*value),
                    "contract_call",
                ),
                _ => (None, None, "other"),
            };

            let (gas_used, success) = match receipts.get(&tx_hash) {
                Some((g, s)) => (Some(*g), *s),
                None => {
                    warn!(
                        tx_hash = %format!("0x{}", hex::encode(tx_hash.as_bytes())),
                        block_height = block.header.height,
                        "missing receipt for transaction — defaulting to failed"
                    );
                    (None, false)
                }
            };

            let indexed_tx = IndexedTransaction {
                hash: format!("0x{}", hex::encode(tx_hash.as_bytes())),
                block_height: block.header.height,
                tx_index: i,
                from_addr: format!("0x{}", hex::encode(tx.body.from.as_bytes())),
                to_addr,
                amount,
                tx_type: tx_type.to_string(),
                gas_used,
                max_fee_per_gas: tx.body.max_fee_per_gas,
                max_priority_fee_per_gas: tx.body.max_priority_fee_per_gas,
                nonce: tx.body.nonce,
                success,
                created_at: block.header.timestamp,
            };
            self.db.insert_transaction(&indexed_tx)?;
        }

        Ok(())
    }

    /// Get the latest indexed height.
    pub fn latest_height(&self) -> Option<u64> {
        self.db.latest_height().ok().flatten()
    }

    /// Revert a block and its transactions during a chain reorganization.
    /// Removes the block and all associated transactions at the given height.
    ///
    /// Only the current tip (highest indexed block) may be reverted. Attempting
    /// to revert a non-tip height is a logic error and returns an error to
    /// prevent leaving gaps in the indexed chain.
    pub fn revert_block(&self, height: u64) -> Result<(), rusqlite::Error> {
        // Verify that the height being reverted is the current tip.
        if let Some(tip) = self.latest_height() {
            if height != tip {
                warn!(
                    requested_height = height,
                    current_tip = tip,
                    "revert_block called for non-tip height"
                );
                return Err(rusqlite::Error::QueryReturnedNoRows);
            }
        } else {
            warn!(height = height, "revert_block called on empty index");
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }

        self.db.conn.execute("BEGIN", [])?;

        let result = (|| {
            // Delete transactions first (foreign key style ordering)
            self.db.conn.execute(
                "DELETE FROM transactions WHERE block_height = ?1",
                rusqlite::params![height as i64],
            )?;
            // Delete the block
            self.db.conn.execute(
                "DELETE FROM blocks WHERE height = ?1",
                rusqlite::params![height as i64],
            )?;
            Ok::<(), rusqlite::Error>(())
        })();

        match result {
            Ok(()) => {
                self.db.conn.execute("COMMIT", [])?;
                Ok(())
            }
            Err(e) => {
                if let Err(rb_err) = self.db.conn.execute("ROLLBACK", []) {
                    warn!(
                        rollback_error = %rb_err,
                        original_error = %e,
                        "ROLLBACK failed after revert_block error"
                    );
                }
                Err(e)
            }
        }
    }

    /// Revert all blocks above the given height (for multi-block reorgs).
    pub fn revert_above(&self, height: u64) -> Result<u64, rusqlite::Error> {
        self.db.conn.execute("BEGIN", [])?;

        let result = (|| {
            let _tx_count = self.db.conn.execute(
                "DELETE FROM transactions WHERE block_height > ?1",
                rusqlite::params![height as i64],
            )?;
            let block_count = self.db.conn.execute(
                "DELETE FROM blocks WHERE height > ?1",
                rusqlite::params![height as i64],
            )?;
            Ok::<u64, rusqlite::Error>(block_count as u64)
        })();

        match result {
            Ok(count) => {
                self.db.conn.execute("COMMIT", [])?;
                Ok(count)
            }
            Err(e) => {
                if let Err(rb_err) = self.db.conn.execute("ROLLBACK", []) {
                    warn!(
                        rollback_error = %rb_err,
                        original_error = %e,
                        "ROLLBACK failed after revert_above error"
                    );
                }
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_indexer_creation() {
        let db = Database::open_memory().unwrap();
        let indexer = Indexer::new(db);
        assert_eq!(indexer.latest_height(), None);
    }
}
