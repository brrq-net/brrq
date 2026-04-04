//! Database layer — SQLite connection and operations.

use rusqlite::Connection;
use tracing::info;

use crate::models::{IndexedBlock, IndexedTransaction};
use crate::schema::CREATE_TABLES;

/// SQLite database wrapper.
pub struct Database {
    pub(crate) conn: Connection,
}

impl Database {
    /// Open or create a database at the given path.
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;",
        )?;
        conn.execute_batch(CREATE_TABLES)?;
        info!("Indexer database opened at {}", path);
        Ok(Self { conn })
    }

    /// Open an in-memory database (for testing).
    pub fn open_memory() -> Result<Self, rusqlite::Error> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        conn.execute_batch(CREATE_TABLES)?;
        Ok(Self { conn })
    }

    /// Insert a block record.
    pub fn insert_block(&self, block: &IndexedBlock) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO blocks (height, hash, parent_hash, timestamp, tx_count, gas_used, gas_limit, state_root, sequencer, epoch, size_bytes) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![
                block.height as i64,
                block.hash,
                block.parent_hash,
                block.timestamp as i64,
                block.tx_count as i64,
                block.gas_used as i64,
                block.gas_limit as i64,
                block.state_root,
                block.sequencer,
                block.epoch as i64,
                block.size_bytes as i64,
            ],
        )?;
        Ok(())
    }

    /// Insert a transaction record.
    pub fn insert_transaction(&self, tx: &IndexedTransaction) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO transactions (hash, block_height, tx_index, from_addr, to_addr, amount, tx_type, gas_used, max_fee_per_gas, max_priority_fee_per_gas, nonce, success, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            rusqlite::params![
                tx.hash,
                tx.block_height as i64,
                tx.tx_index as i64,
                tx.from_addr,
                tx.to_addr,
                tx.amount.map(|a| a as i64),
                tx.tx_type,
                tx.gas_used.map(|g| g as i64),
                tx.max_fee_per_gas as i64,
                tx.max_priority_fee_per_gas as i64,
                tx.nonce as i64,
                tx.success as i64,
                tx.created_at as i64,
            ],
        )?;
        Ok(())
    }

    /// Get the latest indexed block height.
    pub fn latest_height(&self) -> Result<Option<u64>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached("SELECT MAX(height) FROM blocks")?;
        let result: Option<i64> = stmt.query_row([], |row| row.get(0))?;
        Ok(result.map(|h| h as u64))
    }

    /// Get block count.
    pub fn block_count(&self) -> Result<u64, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached("SELECT COUNT(*) FROM blocks")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Get transaction count.
    pub fn transaction_count(&self) -> Result<u64, rusqlite::Error> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT COUNT(*) FROM transactions")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_memory_db() {
        let db = Database::open_memory().unwrap();
        assert_eq!(db.block_count().unwrap(), 0);
        assert_eq!(db.transaction_count().unwrap(), 0);
    }

    #[test]
    fn test_insert_and_query_block() {
        let db = Database::open_memory().unwrap();
        let block = IndexedBlock {
            height: 0,
            hash: "0xabc".into(),
            parent_hash: "0x000".into(),
            timestamp: 1000,
            tx_count: 5,
            gas_used: 105_000,
            gas_limit: 30_000_000,
            state_root: "0xdef".into(),
            sequencer: "0x111".into(),
            epoch: 0,
            size_bytes: 1024,
        };
        db.insert_block(&block).unwrap();
        assert_eq!(db.block_count().unwrap(), 1);
        assert_eq!(db.latest_height().unwrap(), Some(0));
    }

    #[test]
    fn test_insert_and_query_transaction() {
        let db = Database::open_memory().unwrap();
        // First insert a block
        let block = IndexedBlock {
            height: 0,
            hash: "0xabc".into(),
            parent_hash: "0x000".into(),
            timestamp: 1000,
            tx_count: 1,
            gas_used: 21_000,
            gas_limit: 30_000_000,
            state_root: "0xdef".into(),
            sequencer: "0x111".into(),
            epoch: 0,
            size_bytes: 512,
        };
        db.insert_block(&block).unwrap();

        let tx = IndexedTransaction {
            hash: "0xtx1".into(),
            block_height: 0,
            tx_index: 0,
            from_addr: "0xaaa".into(),
            to_addr: Some("0xbbb".into()),
            amount: Some(1000),
            tx_type: "transfer".into(),
            gas_used: Some(21_000),
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            nonce: 0,
            success: true,
            created_at: 1000,
        };
        db.insert_transaction(&tx).unwrap();
        assert_eq!(db.transaction_count().unwrap(), 1);
    }

    #[test]
    fn test_insert_multiple_blocks() {
        let db = Database::open_memory().unwrap();
        for i in 0..10 {
            let block = IndexedBlock {
                height: i,
                hash: format!("0x{:03}", i),
                parent_hash: if i == 0 {
                    "0x000".into()
                } else {
                    format!("0x{:03}", i - 1)
                },
                timestamp: 1000 + i * 3,
                tx_count: i as usize % 5,
                gas_used: 21_000 * i,
                gas_limit: 30_000_000,
                state_root: format!("0xstate{}", i),
                sequencer: "0x111".into(),
                epoch: 0,
                size_bytes: 256,
            };
            db.insert_block(&block).unwrap();
        }
        assert_eq!(db.block_count().unwrap(), 10);
        assert_eq!(db.latest_height().unwrap(), Some(9));
    }

    #[test]
    fn test_empty_db_latest_height() {
        let db = Database::open_memory().unwrap();
        assert_eq!(db.latest_height().unwrap(), None);
    }
}
