//! Database schema — table definitions and migrations.

/// SQL to create all tables.
pub const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS blocks (
    height INTEGER PRIMARY KEY,
    hash TEXT UNIQUE NOT NULL,
    parent_hash TEXT NOT NULL,
    timestamp INTEGER NOT NULL,
    tx_count INTEGER NOT NULL,
    gas_used INTEGER NOT NULL,
    gas_limit INTEGER NOT NULL,
    state_root TEXT NOT NULL,
    sequencer TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    size_bytes INTEGER NOT NULL
);

-- UNIQUE(block_height, tx_index) prevents duplicate tx_index per block.
CREATE TABLE IF NOT EXISTS transactions (
    hash TEXT PRIMARY KEY,
    block_height INTEGER NOT NULL REFERENCES blocks(height),
    tx_index INTEGER NOT NULL,
    from_addr TEXT NOT NULL,
    to_addr TEXT,
    amount INTEGER,
    tx_type TEXT NOT NULL,
    gas_used INTEGER,
    max_fee_per_gas INTEGER NOT NULL,
    max_priority_fee_per_gas INTEGER NOT NULL,
    nonce INTEGER NOT NULL,
    success INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(block_height, tx_index)
);

CREATE TABLE IF NOT EXISTS accounts_cache (
    address TEXT PRIMARY KEY,
    balance INTEGER NOT NULL,
    nonce INTEGER NOT NULL,
    is_contract INTEGER NOT NULL,
    last_updated_height INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_tx_from ON transactions(from_addr);
CREATE INDEX IF NOT EXISTS idx_tx_to ON transactions(to_addr);
CREATE INDEX IF NOT EXISTS idx_tx_block ON transactions(block_height);
CREATE INDEX IF NOT EXISTS idx_blocks_timestamp ON blocks(timestamp);
"#;
