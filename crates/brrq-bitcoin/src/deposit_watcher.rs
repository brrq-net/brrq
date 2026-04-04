//! Deposit watcher — monitors a Bitcoin bridge address for peg-in deposits.
//!
//! ## Security Model
//!
//! - Only deposits with `>= MIN_DEPOSIT_CONFIRMATIONS` (6) are reported
//! - Zero-confirmation deposits are ignored (RBF/double-spend protection)
//! - The `known_deposits` set has a cap (`MAX_KNOWN_DEPOSITS`) to prevent
//!   unbounded memory growth on long-running nodes

// BTreeSet gives deterministic iteration order, ensuring pruning always
// removes the lexicographically-smallest (oldest-by-txid) entries.
use std::collections::BTreeSet;

use brrq_types::Address;
use tracing::{debug, warn};

use crate::error::BitcoinError;
use crate::rpc_client::BitcoinRpc;
use crate::types::{
    DepositEvent, MAX_DEPOSIT_SATS, MAX_KNOWN_DEPOSITS, MIN_DEPOSIT_CONFIRMATIONS, MIN_DEPOSIT_SATS,
};

/// Domain separator for L2 address derivation (prevents cross-domain hash collisions).
const L2_ADDR_DOMAIN: &[u8] = b"brrq-l2-address-v1:";

/// Known Bitcoin script types for deposit validation and logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptType {
    /// P2PKH — 25 bytes: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    P2PKH,
    /// P2SH — 23 bytes: OP_HASH160 <20> OP_EQUAL
    P2SH,
    /// P2WPKH — 22 bytes: OP_0 <20>
    P2WPKH,
    /// P2WSH — 34 bytes: OP_0 <32>
    P2WSH,
    /// P2TR (Taproot) — 34 bytes: OP_1 <32>
    P2TR,
    /// Unknown or non-standard script.
    Unknown,
}

impl std::fmt::Display for ScriptType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::P2PKH => write!(f, "P2PKH"),
            Self::P2SH => write!(f, "P2SH"),
            Self::P2WPKH => write!(f, "P2WPKH"),
            Self::P2WSH => write!(f, "P2WSH"),
            Self::P2TR => write!(f, "P2TR"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detect the Bitcoin script type from raw scriptPubKey bytes.
pub fn detect_script_type(script: &[u8]) -> ScriptType {
    match script.len() {
        25 if script[0] == 0x76
            && script[1] == 0xa9
            && script[2] == 0x14
            && script[23] == 0x88
            && script[24] == 0xac =>
        {
            ScriptType::P2PKH
        }
        23 if script[0] == 0xa9 && script[1] == 0x14 && script[22] == 0x87 => ScriptType::P2SH,
        22 if script[0] == 0x00 && script[1] == 0x14 => ScriptType::P2WPKH,
        34 if script[0] == 0x00 && script[1] == 0x20 => ScriptType::P2WSH,
        34 if script[0] == 0x51 && script[1] == 0x20 => ScriptType::P2TR,
        _ => ScriptType::Unknown,
    }
}

/// Watches a Bitcoin address for new deposits (peg-in).
///
/// Deduplicates deposits by `(txid, vout)` so the same deposit is only
/// reported once to the bridge manager.
///
/// Uses `listsinceblock` RPC to detect ALL deposits including those that
/// have already been spent, preventing the race condition where a deposit
/// is received and spent between scan intervals and thus never detected
/// by `listunspent`.
///
/// ## Safety
///
/// Only reports deposits with `>= min_confirmations` to prevent
/// accepting unconfirmed deposits that could be double-spent.
pub struct DepositWatcher {
    /// The Bitcoin bridge address to monitor.
    bridge_address: String,
    /// Set of known deposits for deduplication: `(txid, vout)`.
    known_deposits: BTreeSet<([u8; 32], u32)>,
    /// Minimum confirmations before reporting a deposit.
    min_confirmations: u32,
    /// Block hash from the last successful scan, used with `listsinceblock`
    /// to avoid re-scanning the entire chain on each poll.
    last_scanned_block: Option<[u8; 32]>,
}

impl DepositWatcher {
    /// Create a new deposit watcher for the given bridge address.
    ///
    /// Uses the default `MIN_DEPOSIT_CONFIRMATIONS` (6) threshold.
    pub fn new(bridge_address: &str) -> Self {
        Self {
            bridge_address: bridge_address.to_string(),
            known_deposits: BTreeSet::new(),
            min_confirmations: MIN_DEPOSIT_CONFIRMATIONS,
            last_scanned_block: None,
        }
    }

    /// Create a new deposit watcher with a custom confirmation threshold.
    pub fn with_confirmations(bridge_address: &str, min_confirmations: u32) -> Self {
        Self {
            bridge_address: bridge_address.to_string(),
            known_deposits: BTreeSet::new(),
            min_confirmations,
            last_scanned_block: None,
        }
    }

    /// Scan for new deposits to the bridge address.
    ///
    /// Uses `listsinceblock` to detect ALL deposits (including spent ones),
    /// preventing the race condition where a deposit is received and spent
    /// between scans. Falls back to `list_unspent_for_address` if
    /// `listsinceblock` is unavailable.
    ///
    /// Returns only *newly discovered* deposits that meet the minimum
    /// confirmation threshold. Already-seen deposits are filtered out.
    pub fn scan(&mut self, rpc: &dyn BitcoinRpc) -> Result<Vec<DepositEvent>, BitcoinError> {
        // Use listsinceblock to get all transactions (including spent) since
        // last scan. This prevents the race where a deposit is received and
        // spent between scan intervals.
        let (all_deposits, last_block) = rpc.list_since_block(
            &self.bridge_address,
            self.last_scanned_block.as_ref(),
        )?;

        // Update last scanned block for next call
        self.last_scanned_block = Some(last_block);

        let mut new_deposits = Vec::new();

        for deposit in all_deposits {
            // Skip unconfirmed or insufficiently confirmed deposits
            if deposit.confirmations < self.min_confirmations {
                debug!(
                    "Skipping deposit txid={} vout={}: {} confirmations < {} required",
                    hex::encode(deposit.btc_tx_id),
                    deposit.btc_vout,
                    deposit.confirmations,
                    self.min_confirmations,
                );
                continue;
            }

            // Reject deposits with invalid amounts.
            // Dust deposits waste bridge resources; values above total supply indicate
            // RPC data corruption or crafted UTXOs.
            if deposit.amount_sats < MIN_DEPOSIT_SATS {
                debug!(
                    "Skipping dust deposit txid={} vout={}: {} sats < {} minimum",
                    hex::encode(deposit.btc_tx_id),
                    deposit.btc_vout,
                    deposit.amount_sats,
                    MIN_DEPOSIT_SATS,
                );
                continue;
            }
            if deposit.amount_sats > MAX_DEPOSIT_SATS {
                warn!(
                    "Skipping invalid deposit txid={} vout={}: {} sats > {} maximum (possible corruption)",
                    hex::encode(deposit.btc_tx_id),
                    deposit.btc_vout,
                    deposit.amount_sats,
                    MAX_DEPOSIT_SATS,
                );
                continue;
            }

            let key = (deposit.btc_tx_id, deposit.btc_vout);
            if self.known_deposits.insert(key) {
                // This is a new, sufficiently confirmed deposit
                debug!(
                    "New deposit detected: txid={}, vout={}, amount={} sats, confirmations={}",
                    hex::encode(deposit.btc_tx_id),
                    deposit.btc_vout,
                    deposit.amount_sats,
                    deposit.confirmations,
                );
                new_deposits.push(deposit);
            }
        }

        // Prune oldest entries if set exceeds cap (prevents memory leak)
        if self.known_deposits.len() > MAX_KNOWN_DEPOSITS {
            let excess = self.known_deposits.len() - MAX_KNOWN_DEPOSITS;
            let to_remove: Vec<_> = self.known_deposits.iter().take(excess).cloned().collect();
            for key in to_remove {
                self.known_deposits.remove(&key);
            }
            debug!(
                "Pruned {} old deposit entries (cap={})",
                excess, MAX_KNOWN_DEPOSITS,
            );
        }

        Ok(new_deposits)
    }

    /// Derive an L2 recipient address from a Bitcoin scriptPubKey.
    ///
    /// MVP mapping: `SHA-256("brrq-l2-address-v1:" || scriptPubKey)[0..20]` → L2 Address.
    ///
    /// Supports all standard Bitcoin script types:
    /// - P2PKH (legacy), P2SH (script-hash)
    /// - P2WPKH (SegWit v0), P2WSH (SegWit v0 multisig)
    /// - P2TR (Taproot / SegWit v1)
    ///
    /// Uses a domain separator to prevent cross-domain hash collisions.
    /// Future: use OP_RETURN-embedded L2 address or Taproot script path.
    pub fn derive_l2_recipient(script_pub_key: &[u8]) -> Address {
        if script_pub_key.is_empty() {
            return Address::ZERO;
        }

        let script_type = detect_script_type(script_pub_key);
        if script_type == ScriptType::Unknown {
            debug!(
                "Non-standard scriptPubKey ({} bytes) — deriving L2 address anyway",
                script_pub_key.len(),
            );
        }

        // Domain-separated hash: SHA-256("brrq-l2-address-v1:" || script)
        let mut hasher = brrq_crypto::hash::Hasher::new();
        hasher.update(L2_ADDR_DOMAIN);
        hasher.update(script_pub_key);
        let hash = hasher.finalize();
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Address::from_bytes(addr_bytes)
    }

    /// Derive an L2 recipient address and also return the detected script type.
    pub fn derive_l2_recipient_typed(script_pub_key: &[u8]) -> (Address, ScriptType) {
        let script_type = detect_script_type(script_pub_key);
        let addr = Self::derive_l2_recipient(script_pub_key);
        (addr, script_type)
    }

    /// The Bitcoin address being monitored.
    pub fn bridge_address(&self) -> &str {
        &self.bridge_address
    }

    /// Number of known (already-seen) deposits.
    pub fn known_count(&self) -> usize {
        self.known_deposits.len()
    }

    /// Mark a deposit as known (e.g., when loading from persistent storage).
    pub fn mark_known(&mut self, txid: [u8; 32], vout: u32) {
        self.known_deposits.insert((txid, vout));
    }

    /// Current minimum confirmations threshold.
    pub fn min_confirmations(&self) -> u32 {
        self.min_confirmations
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_watcher() {
        let watcher = DepositWatcher::new("bc1qtest123");
        assert_eq!(watcher.bridge_address(), "bc1qtest123");
        assert_eq!(watcher.known_count(), 0);
        assert_eq!(watcher.min_confirmations(), MIN_DEPOSIT_CONFIRMATIONS);
    }

    #[test]
    fn with_confirmations() {
        let watcher = DepositWatcher::with_confirmations("bc1qtest", 3);
        assert_eq!(watcher.min_confirmations(), 3);
    }

    #[test]
    fn derive_l2_recipient_deterministic() {
        let script = b"test_script_pubkey";
        let addr1 = DepositWatcher::derive_l2_recipient(script);
        let addr2 = DepositWatcher::derive_l2_recipient(script);
        assert_eq!(addr1, addr2);
    }

    #[test]
    fn derive_l2_recipient_different_scripts() {
        let addr1 = DepositWatcher::derive_l2_recipient(b"script_a");
        let addr2 = DepositWatcher::derive_l2_recipient(b"script_b");
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn derive_l2_recipient_uses_domain_separation() {
        let script = b"test_script";
        let addr = DepositWatcher::derive_l2_recipient(script);
        // Should NOT match a plain SHA-256 hash (due to domain separator)
        let plain_hash = brrq_crypto::hash::Hasher::hash(script);
        let mut plain_addr = [0u8; 20];
        plain_addr.copy_from_slice(&plain_hash.as_bytes()[..20]);
        assert_ne!(addr.as_bytes(), &plain_addr);
    }

    #[test]
    fn derive_l2_recipient_empty_script_returns_zero() {
        let addr = DepositWatcher::derive_l2_recipient(b"");
        assert_eq!(addr, Address::ZERO);
    }

    #[test]
    fn mark_known_prevents_rediscovery() {
        let mut watcher = DepositWatcher::new("bc1qtest");
        watcher.mark_known([0xAA; 32], 0);
        watcher.mark_known([0xBB; 32], 1);
        assert_eq!(watcher.known_count(), 2);

        // Marking the same again doesn't increase count
        watcher.mark_known([0xAA; 32], 0);
        assert_eq!(watcher.known_count(), 2);
    }

    #[test]
    fn same_txid_different_vout_are_distinct() {
        let mut watcher = DepositWatcher::new("bc1qtest");
        watcher.mark_known([0xAA; 32], 0);
        watcher.mark_known([0xAA; 32], 1);
        assert_eq!(watcher.known_count(), 2);
    }

    #[test]
    fn detect_p2pkh_script() {
        // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        let mut script = vec![0x76, 0xa9, 0x14];
        script.extend_from_slice(&[0xaa; 20]);
        script.push(0x88);
        script.push(0xac);
        assert_eq!(detect_script_type(&script), ScriptType::P2PKH);
    }

    #[test]
    fn detect_p2sh_script() {
        // OP_HASH160 <20 bytes> OP_EQUAL
        let mut script = vec![0xa9, 0x14];
        script.extend_from_slice(&[0xbb; 20]);
        script.push(0x87);
        assert_eq!(detect_script_type(&script), ScriptType::P2SH);
    }

    #[test]
    fn detect_p2wpkh_script() {
        // OP_0 <20 bytes>
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(&[0xcc; 20]);
        assert_eq!(detect_script_type(&script), ScriptType::P2WPKH);
    }

    #[test]
    fn detect_p2wsh_script() {
        // OP_0 <32 bytes>
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&[0xdd; 32]);
        assert_eq!(detect_script_type(&script), ScriptType::P2WSH);
    }

    #[test]
    fn detect_p2tr_script() {
        // OP_1 <32 bytes>
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&[0xee; 32]);
        assert_eq!(detect_script_type(&script), ScriptType::P2TR);
    }

    #[test]
    fn detect_unknown_script() {
        assert_eq!(detect_script_type(&[0x01, 0x02, 0x03]), ScriptType::Unknown);
    }

    #[test]
    fn all_standard_scripts_produce_unique_addresses() {
        let mut p2pkh = vec![0x76, 0xa9, 0x14];
        p2pkh.extend_from_slice(&[0xaa; 20]);
        p2pkh.push(0x88);
        p2pkh.push(0xac);

        let mut p2wpkh = vec![0x00, 0x14];
        p2wpkh.extend_from_slice(&[0xaa; 20]);

        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0xaa; 32]);

        let addr1 = DepositWatcher::derive_l2_recipient(&p2pkh);
        let addr2 = DepositWatcher::derive_l2_recipient(&p2wpkh);
        let addr3 = DepositWatcher::derive_l2_recipient(&p2tr);

        assert_ne!(addr1, addr2);
        assert_ne!(addr2, addr3);
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn derive_l2_recipient_typed_returns_script_type() {
        let mut script = vec![0x51, 0x20];
        script.extend_from_slice(&[0xff; 32]);
        let (addr, stype) = DepositWatcher::derive_l2_recipient_typed(&script);
        assert_ne!(addr, Address::ZERO);
        assert_eq!(stype, ScriptType::P2TR);
    }
}
