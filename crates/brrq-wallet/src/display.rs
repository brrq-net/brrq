//! Display formatting utilities for CLI output.
//!
//! Provides human-readable formatting for balances, hashes, blocks, and receipts.

/// Format a balance in satoshis as human-readable BRQ amount.
///
/// Uses 8 decimal places (like Bitcoin).
///
/// # Examples
///
/// - `0` → `"0.00000000 BRQ"`
/// - `100_000_000` → `"1.00000000 BRQ"`
/// - `12345` → `"0.00012345 BRQ"`
pub fn format_balance(satoshis: u64) -> String {
    let whole = satoshis / 100_000_000;
    let frac = satoshis % 100_000_000;
    format!("{whole}.{frac:08} BRQ")
}

/// Truncate a hex hash for display.
///
/// Shows the first 6 and last 4 hex characters.
///
/// # Examples
///
/// - `"0xabcdef0123456789..."` → `"0xabcdef...6789"`
pub fn format_hash(hash: &str) -> String {
    let clean = hash.strip_prefix("0x").unwrap_or(hash);
    if clean.len() <= 10 {
        return format!("0x{clean}");
    }
    format!("0x{}...{}", &clean[..6], &clean[clean.len() - 4..])
}

/// Format block information from JSON for display.
pub fn format_block_info(block: &serde_json::Value) -> String {
    let height = block["height"].as_u64().unwrap_or(0);
    let tx_count = block["tx_count"].as_u64().unwrap_or(0);
    let gas_used = block["gas_used"].as_u64().unwrap_or(0);
    let gas_limit = block["gas_limit"].as_u64().unwrap_or(0);
    let timestamp = block["timestamp"].as_u64().unwrap_or(0);
    let hash = block["hash"].as_str().unwrap_or("unknown");
    let parent = block["parent_hash"].as_str().unwrap_or("unknown");
    let state_root = block["state_root"].as_str().unwrap_or("unknown");
    let sequencer = block["sequencer"].as_str().unwrap_or("unknown");
    let epoch = block["epoch"].as_u64().unwrap_or(0);

    format!(
        "Block #{height}\n\
         ├─ Hash:       {}\n\
         ├─ Parent:     {}\n\
         ├─ State Root: {}\n\
         ├─ Sequencer:  {}\n\
         ├─ Epoch:      {epoch}\n\
         ├─ Timestamp:  {timestamp}\n\
         ├─ Txs:        {tx_count}\n\
         └─ Gas:        {gas_used} / {gas_limit}",
        format_hash(hash),
        format_hash(parent),
        format_hash(state_root),
        format_hash(sequencer),
    )
}

/// Format a transaction receipt from JSON for display.
pub fn format_receipt(receipt: &serde_json::Value) -> String {
    let block_height = receipt["block_height"].as_u64().unwrap_or(0);
    let gas_used = receipt["gas_used"].as_u64().unwrap_or(0);
    let success = receipt["success"].as_bool().unwrap_or(false);
    let block_hash = receipt["block_hash"].as_str().unwrap_or("unknown");
    let status = if success { "Success" } else { "Failed" };
    let log_count = receipt["logs"].as_array().map(|a| a.len()).unwrap_or(0);

    format!(
        "Transaction Receipt\n\
         ├─ Status:      {status}\n\
         ├─ Block:       #{block_height}\n\
         ├─ Block Hash:  {}\n\
         ├─ Gas Used:    {gas_used}\n\
         └─ Logs:        {log_count}",
        format_hash(block_hash),
    )
}

/// Format an account info from JSON for display.
pub fn format_account_info(account: &serde_json::Value) -> String {
    let address = account["address"].as_str().unwrap_or("unknown");
    let balance = account["balance"].as_u64().unwrap_or(0);
    let nonce = account["nonce"].as_u64().unwrap_or(0);
    let code_hash = account["code_hash"].as_str().unwrap_or("unknown");
    let storage_root = account["storage_root"].as_str().unwrap_or("unknown");
    let has_code = account["has_code"].as_bool().unwrap_or(false);

    let account_type = if has_code { "Contract" } else { "EOA" };

    format!(
        "Account ({account_type})\n\
         ├─ Address:      {}\n\
         ├─ Balance:      {}\n\
         ├─ Nonce:        {nonce}\n\
         ├─ Code Hash:    {}\n\
         └─ Storage Root: {}",
        format_hash(address),
        format_balance(balance),
        format_hash(code_hash),
        format_hash(storage_root),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_balance_zero() {
        assert_eq!(format_balance(0), "0.00000000 BRQ");
    }

    #[test]
    fn test_format_balance_one_brq() {
        assert_eq!(format_balance(100_000_000), "1.00000000 BRQ");
    }

    #[test]
    fn test_format_balance_satoshis() {
        assert_eq!(format_balance(12345), "0.00012345 BRQ");
    }

    #[test]
    fn test_format_balance_large() {
        assert_eq!(
            format_balance(2_100_000_000_000_000),
            "21000000.00000000 BRQ"
        );
    }

    #[test]
    fn test_format_hash_short() {
        assert_eq!(format_hash("0xaabb"), "0xaabb");
    }

    #[test]
    fn test_format_hash_truncation() {
        let hash = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let formatted = format_hash(hash);
        assert!(formatted.starts_with("0xabcdef"));
        assert!(formatted.ends_with("6789"));
        assert!(formatted.contains("..."));
    }

    #[test]
    fn test_format_block_info() {
        let block = serde_json::json!({
            "height": 42,
            "tx_count": 3,
            "gas_used": 63000,
            "gas_limit": 8000000,
            "timestamp": 1700000000,
            "hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "parent_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "state_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
            "sequencer": "0xaabbccdd00112233445566778899aabb",
            "epoch": 1,
        });

        let output = format_block_info(&block);
        assert!(output.contains("Block #42"));
        assert!(output.contains("Txs:        3"));
        assert!(output.contains("63000 / 8000000"));
    }

    #[test]
    fn test_format_receipt() {
        let receipt = serde_json::json!({
            "block_height": 10,
            "gas_used": 21000,
            "success": true,
            "block_hash": "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "logs": [],
        });

        let output = format_receipt(&receipt);
        assert!(output.contains("Success"));
        assert!(output.contains("#10"));
        assert!(output.contains("21000"));
    }
}
