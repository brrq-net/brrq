//! Prepared queries for common data access patterns.

use crate::db::Database;
use crate::models::{IndexedBlock, IndexedTransaction};

/// Maximum number of rows a single query can return.
const MAX_QUERY_LIMIT: usize = 1000;

impl Database {
    /// Get blocks with pagination (latest first).
    pub fn get_blocks(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<IndexedBlock>, rusqlite::Error> {
        let limit = limit.min(MAX_QUERY_LIMIT);
        let mut stmt = self.conn.prepare_cached(
            "SELECT height, hash, parent_hash, timestamp, tx_count, gas_used, gas_limit, state_root, sequencer, epoch, size_bytes FROM blocks ORDER BY height DESC LIMIT ?1 OFFSET ?2"
        )?;
        let rows = stmt.query_map(
            rusqlite::params![limit as i64, offset as i64],
            Self::map_block_row,
        )?;
        rows.collect()
    }

    /// Get block by height.
    pub fn get_block_by_height(
        &self,
        height: u64,
    ) -> Result<Option<IndexedBlock>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT height, hash, parent_hash, timestamp, tx_count, gas_used, gas_limit, state_root, sequencer, epoch, size_bytes FROM blocks WHERE height = ?1"
        )?;
        let mut rows = stmt.query_map(rusqlite::params![height as i64], Self::map_block_row)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Get block by hash.
    pub fn get_block_by_hash(&self, hash: &str) -> Result<Option<IndexedBlock>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT height, hash, parent_hash, timestamp, tx_count, gas_used, gas_limit, state_root, sequencer, epoch, size_bytes FROM blocks WHERE hash = ?1"
        )?;
        let mut rows = stmt.query_map(rusqlite::params![hash], Self::map_block_row)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Get transaction by hash.
    pub fn get_transaction_by_hash(
        &self,
        hash: &str,
    ) -> Result<Option<IndexedTransaction>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT hash, block_height, tx_index, from_addr, to_addr, amount, tx_type, gas_used, max_fee_per_gas, max_priority_fee_per_gas, nonce, success, created_at FROM transactions WHERE hash = ?1"
        )?;
        let mut rows = stmt.query_map(rusqlite::params![hash], Self::map_tx_row)?;
        match rows.next() {
            Some(row) => Ok(Some(row?)),
            None => Ok(None),
        }
    }

    /// Get transactions for a block.
    ///
    /// Results are capped at MAX_QUERY_LIMIT to prevent unbounded result sets.
    pub fn get_transactions_by_block(
        &self,
        block_height: u64,
    ) -> Result<Vec<IndexedTransaction>, rusqlite::Error> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT hash, block_height, tx_index, from_addr, to_addr, amount, tx_type, gas_used, max_fee_per_gas, max_priority_fee_per_gas, nonce, success, created_at FROM transactions WHERE block_height = ?1 ORDER BY tx_index ASC LIMIT ?2"
        )?;
        let rows = stmt.query_map(
            rusqlite::params![block_height as i64, MAX_QUERY_LIMIT as i64],
            Self::map_tx_row,
        )?;
        rows.collect()
    }

    /// Get transactions by address (sender).
    pub fn get_transactions_by_address(
        &self,
        address: &str,
        limit: usize,
    ) -> Result<Vec<IndexedTransaction>, rusqlite::Error> {
        let limit = limit.min(MAX_QUERY_LIMIT);
        let mut stmt = self.conn.prepare_cached(
            "SELECT hash, block_height, tx_index, from_addr, to_addr, amount, tx_type, gas_used, max_fee_per_gas, max_priority_fee_per_gas, nonce, success, created_at FROM transactions WHERE from_addr = ?1 OR to_addr = ?1 ORDER BY block_height DESC, tx_index DESC LIMIT ?2"
        )?;
        let rows = stmt.query_map(rusqlite::params![address, limit as i64], Self::map_tx_row)?;
        rows.collect()
    }

    /// Convert an i64 from SQLite to u64, rejecting negative values.
    fn i64_to_u64(val: i64, col: &str) -> Result<u64, rusqlite::Error> {
        if val < 0 {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Integer,
                format!("negative value {} in column '{}'", val, col).into(),
            ));
        }
        Ok(val as u64)
    }

    /// Convert an i64 from SQLite to usize, rejecting negative values.
    fn i64_to_usize(val: i64, col: &str) -> Result<usize, rusqlite::Error> {
        if val < 0 {
            return Err(rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Integer,
                format!("negative value {} in column '{}'", val, col).into(),
            ));
        }
        Ok(val as usize)
    }

    fn map_tx_row(row: &rusqlite::Row) -> Result<IndexedTransaction, rusqlite::Error> {
        Ok(IndexedTransaction {
            hash: row.get(0)?,
            block_height: Self::i64_to_u64(row.get::<_, i64>(1)?, "block_height")?,
            tx_index: Self::i64_to_usize(row.get::<_, i64>(2)?, "tx_index")?,
            from_addr: row.get(3)?,
            to_addr: row.get(4)?,
            amount: row
                .get::<_, Option<i64>>(5)?
                .map(|a| Self::i64_to_u64(a, "amount"))
                .transpose()?,
            tx_type: row.get(6)?,
            gas_used: row
                .get::<_, Option<i64>>(7)?
                .map(|g| Self::i64_to_u64(g, "gas_used"))
                .transpose()?,
            max_fee_per_gas: Self::i64_to_u64(row.get::<_, i64>(8)?, "max_fee_per_gas")?,
            max_priority_fee_per_gas: Self::i64_to_u64(
                row.get::<_, i64>(9)?,
                "max_priority_fee_per_gas",
            )?,
            nonce: Self::i64_to_u64(row.get::<_, i64>(10)?, "nonce")?,
            success: row.get::<_, i64>(11)? != 0,
            created_at: Self::i64_to_u64(row.get::<_, i64>(12)?, "created_at")?,
        })
    }

    fn map_block_row(row: &rusqlite::Row) -> Result<IndexedBlock, rusqlite::Error> {
        Ok(IndexedBlock {
            height: Self::i64_to_u64(row.get::<_, i64>(0)?, "height")?,
            hash: row.get(1)?,
            parent_hash: row.get(2)?,
            timestamp: Self::i64_to_u64(row.get::<_, i64>(3)?, "timestamp")?,
            tx_count: Self::i64_to_usize(row.get::<_, i64>(4)?, "tx_count")?,
            gas_used: Self::i64_to_u64(row.get::<_, i64>(5)?, "gas_used")?,
            gas_limit: Self::i64_to_u64(row.get::<_, i64>(6)?, "gas_limit")?,
            state_root: row.get(7)?,
            sequencer: row.get(8)?,
            epoch: Self::i64_to_u64(row.get::<_, i64>(9)?, "epoch")?,
            size_bytes: Self::i64_to_usize(row.get::<_, i64>(10)?, "size_bytes")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_db() -> Database {
        let db = Database::open_memory().unwrap();
        for i in 0..5u64 {
            let block = IndexedBlock {
                height: i,
                hash: format!("0x{:064x}", i),
                parent_hash: format!("0x{:064x}", i.wrapping_sub(1)),
                timestamp: 1000 + i * 3,
                tx_count: 2,
                gas_used: 42_000,
                gas_limit: 30_000_000,
                state_root: format!("0xstate{}", i),
                sequencer: "0x1111111111111111111111111111111111111111".into(),
                epoch: 0,
                size_bytes: 512,
            };
            db.insert_block(&block).unwrap();

            for j in 0..2 {
                let tx = IndexedTransaction {
                    hash: format!("0xtx_{}_{}", i, j),
                    block_height: i,
                    tx_index: j,
                    from_addr: "0xaaa".into(),
                    to_addr: Some("0xbbb".into()),
                    amount: Some(1000),
                    tx_type: "transfer".into(),
                    gas_used: Some(21_000),
                    max_fee_per_gas: 1,
                    max_priority_fee_per_gas: 1,
                    nonce: (i * 2 + j as u64),
                    success: true,
                    created_at: 1000 + i * 3,
                };
                db.insert_transaction(&tx).unwrap();
            }
        }
        db
    }

    #[test]
    fn test_get_blocks_pagination() {
        let db = setup_db();
        let blocks = db.get_blocks(3, 0).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].height, 4); // Latest first
        assert_eq!(blocks[2].height, 2);
    }

    #[test]
    fn test_get_blocks_offset() {
        let db = setup_db();
        let blocks = db.get_blocks(2, 2).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].height, 2);
    }

    #[test]
    fn test_get_block_by_height() {
        let db = setup_db();
        let block = db.get_block_by_height(3).unwrap();
        assert!(block.is_some());
        assert_eq!(block.unwrap().height, 3);
    }

    #[test]
    fn test_get_block_not_found() {
        let db = setup_db();
        let block = db.get_block_by_height(999).unwrap();
        assert!(block.is_none());
    }

    #[test]
    fn test_get_transactions_by_block() {
        let db = setup_db();
        let txs = db.get_transactions_by_block(2).unwrap();
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].tx_index, 0);
        assert_eq!(txs[1].tx_index, 1);
    }

    #[test]
    fn test_get_transactions_by_address() {
        let db = setup_db();
        let txs = db.get_transactions_by_address("0xaaa", 5).unwrap();
        assert_eq!(txs.len(), 5);
    }
}
