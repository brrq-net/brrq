//! Bitcoin Core RPC client wrapper with retry logic and graceful degradation.

use bitcoin::hashes::Hash as _;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use tracing::{debug, error, warn};

use crate::error::BitcoinError;
use crate::types::{DepositEvent, L1BlockInfo};

/// Trait abstracting Bitcoin RPC operations for testability.
///
/// Implemented by `BitcoinRpcClient` (real) and `MockBitcoinRpc` (simulation).
/// Enables swapping between real Bitcoin Core and in-memory mock in tests.
pub trait BitcoinRpc: Send + Sync {
    /// Get the current blockchain height.
    fn get_block_count(&self) -> Result<u64, BitcoinError>;
    /// Get the block hash at a given height.
    fn get_block_hash(&self, height: u64) -> Result<[u8; 32], BitcoinError>;
    /// Get full block info (height, hash, timestamp).
    fn get_block_info(&self, height: u64) -> Result<L1BlockInfo, BitcoinError>;
    /// List unspent outputs for the given Bitcoin address.
    fn list_unspent_for_address(&self, address: &str) -> Result<Vec<DepositEvent>, BitcoinError>;
    /// List all receive transactions for the given address since the given block hash.
    ///
    /// Unlike `list_unspent_for_address`, this returns deposits that have been
    /// spent as well, preventing the race where a deposit is received and spent
    /// between scans and thus never detected.
    ///
    /// `since_block_hash` is the block hash to start scanning from (exclusive).
    /// Pass `None` to scan from genesis.
    ///
    /// Returns `(deposits, last_block_hash)` where `last_block_hash` is the
    /// block hash to pass on the next call.
    fn list_since_block(
        &self,
        address: &str,
        since_block_hash: Option<&[u8; 32]>,
    ) -> Result<(Vec<DepositEvent>, [u8; 32]), BitcoinError>;
    /// Broadcast a raw transaction hex.
    fn broadcast_raw_tx(&self, raw_tx_hex: &str) -> Result<[u8; 32], BitcoinError>;
    /// Create a funded, signed OP_RETURN transaction.
    fn create_op_return_tx(&self, data: &[u8]) -> Result<String, BitcoinError>;
    /// Send a signed transaction hex.
    fn send_signed_tx(&self, signed_hex: &str) -> Result<[u8; 32], BitcoinError>;
    /// Get SPV inclusion proof for a confirmed transaction.
    fn get_tx_out_proof(&self, txid: &[u8; 32]) -> Result<Vec<u8>, BitcoinError>;
    /// Get block info for a confirmed transaction.
    fn get_tx_block_info(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<([u8; 32], u64, u32)>, BitcoinError>;
    /// Returns true if a client object exists (does NOT verify actual connectivity).
    fn has_client(&self) -> bool;
    /// Performs a lightweight RPC call to verify actual connectivity to bitcoind.
    fn is_connected(&self) -> bool;
    /// The Bitcoin network this client is configured for.
    fn network(&self) -> bitcoin::Network;
}

/// Wrapper around `bitcoincore-rpc::Client` with retry and reconnection.
pub struct BitcoinRpcClient {
    /// The underlying RPC client (None if connection failed).
    client: Option<Client>,
    /// RPC endpoint URL.
    url: String,
    /// RPC username.
    user: String,
    /// RPC password.
    pass: String,
    /// Bitcoin network.
    network: bitcoin::Network,
}

impl BitcoinRpcClient {
    /// Create a new Bitcoin RPC client.
    ///
    /// Attempts to connect immediately. If the connection fails, the client is
    /// created in a disconnected state and can be reconnected later.
    ///
    /// # Security
    ///
    /// The underlying `bitcoincore-rpc` crate uses `minreq` without TLS,
    /// meaning all RPC traffic (including wallet credentials) is plaintext
    /// HTTP.  This constructor **rejects non-localhost URLs** unless the
    /// environment variable `BRRQ_ALLOW_REMOTE_RPC=true` is set.
    pub fn new(url: &str, user: &str, pass: &str, network_str: &str) -> Result<Self, BitcoinError> {
        validate_rpc_url_localhost(url)?;
        let network = parse_network(network_str)?;

        let client = match Client::new(url, Auth::UserPass(user.to_string(), pass.to_string())) {
            Ok(c) => {
                // Test the connection with a simple call
                match c.get_blockchain_info() {
                    Ok(info) => {
                        debug!(
                            "Connected to Bitcoin node: chain={}, blocks={}, headers={}",
                            info.chain, info.blocks, info.headers
                        );
                        Some(c)
                    }
                    Err(e) => {
                        warn!("Bitcoin RPC connected but test call failed: {}", e);
                        Some(c) // Keep the client — may work for future calls
                    }
                }
            }
            Err(e) => {
                warn!("Failed to create Bitcoin RPC client: {}", e);
                None
            }
        };

        Ok(Self {
            client,
            url: url.to_string(),
            user: user.to_string(),
            pass: pass.to_string(),
            network,
        })
    }

    /// Returns true if a client object exists (does NOT verify actual connectivity).
    pub fn has_client(&self) -> bool {
        self.client.is_some()
    }

    /// Performs a lightweight RPC call to verify actual connectivity to bitcoind.
    pub fn is_connected(&self) -> bool {
        match &self.client {
            None => false,
            Some(client) => client.get_blockchain_info().is_ok(),
        }
    }

    /// The Bitcoin network this client is configured for.
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    /// Attempt to reconnect to bitcoind.
    ///
    /// Re-validates the localhost requirement before reconnecting.
    pub fn reconnect(&mut self) -> Result<(), BitcoinError> {
        validate_rpc_url_localhost(&self.url)?;
        let client = Client::new(
            &self.url,
            Auth::UserPass(self.user.clone(), self.pass.clone()),
        )
        .map_err(|e| BitcoinError::RpcConnectionFailed(e.to_string()))?;

        // Verify connectivity
        client
            .get_blockchain_info()
            .map_err(|e| BitcoinError::RpcCallFailed(e.to_string()))?;

        self.client = Some(client);
        debug!("Reconnected to Bitcoin node at {}", self.url);
        Ok(())
    }

    /// Get the current blockchain height.
    pub fn get_block_count(&self) -> Result<u64, BitcoinError> {
        let client = self.require_client()?;
        client
            .get_block_count()
            .map_err(|e| BitcoinError::RpcCallFailed(e.to_string()))
    }

    /// Get the block hash at a given height.
    pub fn get_block_hash(&self, height: u64) -> Result<[u8; 32], BitcoinError> {
        let client = self.require_client()?;
        let hash = client
            .get_block_hash(height)
            .map_err(|e| BitcoinError::RpcCallFailed(e.to_string()))?;

        // bitcoin::BlockHash → [u8; 32]
        Ok(hash.to_byte_array())
    }

    /// Get full block info (height, hash, timestamp) for a given height.
    pub fn get_block_info(&self, height: u64) -> Result<L1BlockInfo, BitcoinError> {
        let client = self.require_client()?;

        let hash = client
            .get_block_hash(height)
            .map_err(|e| BitcoinError::RpcCallFailed(e.to_string()))?;

        let header = client
            .get_block_header(&hash)
            .map_err(|e| BitcoinError::RpcCallFailed(e.to_string()))?;

        Ok(L1BlockInfo {
            height,
            hash: hash.to_byte_array(),
            timestamp: header.time as u64,
        })
    }

    /// List unspent outputs for the given Bitcoin address.
    ///
    /// Returns deposits as `DepositEvent`s for the bridge to process.
    pub fn list_unspent_for_address(
        &self,
        address: &str,
    ) -> Result<Vec<DepositEvent>, BitcoinError> {
        let client = self.require_client()?;

        let addr = address
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map_err(|e| BitcoinError::AddressParseError(e.to_string()))?
            .require_network(self.network)
            .map_err(|e| BitcoinError::AddressParseError(e.to_string()))?;

        let unspent = client
            .list_unspent(Some(0), None, Some(&[&addr]), None, None)
            .map_err(|e| BitcoinError::RpcCallFailed(e.to_string()))?;

        let deposits = unspent
            .into_iter()
            .map(|utxo| {
                let txid_bytes: [u8; 32] = utxo.txid.to_byte_array();
                let script_bytes = utxo.script_pub_key.as_bytes().to_vec();

                DepositEvent {
                    btc_tx_id: txid_bytes,
                    btc_vout: utxo.vout,
                    amount_sats: utxo.amount.to_sat(),
                    recipient_script: script_bytes,
                    confirmations: utxo.confirmations,
                }
            })
            .collect();

        Ok(deposits)
    }

    /// List all receive transactions for the given address since a block hash.
    ///
    /// Uses Bitcoin Core's `listsinceblock` RPC, which returns both spent and
    /// unspent transactions, preventing the deposit race where a UTXO is spent
    /// between scan intervals and never detected by `listunspent`.
    pub fn list_since_block(
        &self,
        address: &str,
        since_block_hash: Option<&[u8; 32]>,
    ) -> Result<(Vec<DepositEvent>, [u8; 32]), BitcoinError> {
        let client = self.require_client()?;

        // Build args: listsinceblock [blockhash] [target_confirmations=1] [include_watchonly=true]
        let mut args: Vec<serde_json::Value> = Vec::new();
        if let Some(hash) = since_block_hash {
            let hash_obj = bitcoin::BlockHash::from_byte_array(*hash);
            args.push(serde_json::Value::String(hash_obj.to_string()));
        } else {
            args.push(serde_json::Value::String(String::new()));
        }
        // target_confirmations = 1 (return txs with at least 1 confirmation)
        args.push(serde_json::json!(1));
        // include_watchonly = true
        args.push(serde_json::json!(true));

        let result: serde_json::Value = client
            .call("listsinceblock", &args)
            .map_err(|e| BitcoinError::RpcCallFailed(format!("listsinceblock: {}", e)))?;

        // Parse lastblock hash for next call
        let lastblock_hex = result["lastblock"]
            .as_str()
            .ok_or_else(|| BitcoinError::RpcCallFailed("no lastblock in listsinceblock response".to_string()))?;
        let lastblock_obj: bitcoin::BlockHash = lastblock_hex
            .parse()
            .map_err(|e| BitcoinError::RpcCallFailed(format!("parse lastblock: {}", e)))?;
        let lastblock = lastblock_obj.to_byte_array();

        // Filter transactions: only "receive" category to the target address
        let transactions = result["transactions"]
            .as_array()
            .unwrap_or(&Vec::new())
            .clone();

        let mut deposits = Vec::new();
        for tx in &transactions {
            let category = tx["category"].as_str().unwrap_or("");
            if category != "receive" {
                continue;
            }

            let tx_address = tx["address"].as_str().unwrap_or("");
            if tx_address != address {
                continue;
            }

            // Parse txid
            let txid_hex = match tx["txid"].as_str() {
                Some(h) => h,
                None => continue,
            };
            let txid_obj: bitcoin::Txid = match txid_hex.parse() {
                Ok(t) => t,
                Err(_) => continue,
            };
            let txid_bytes = txid_obj.to_byte_array();

            let vout = tx["vout"].as_u64().unwrap_or(0) as u32;

            // Amount is in BTC as a float; convert to sats
            let amount_btc = tx["amount"].as_f64().unwrap_or(0.0);
            let amount_sats = (amount_btc * 100_000_000.0).round() as u64;

            let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;

            // scriptPubKey is not directly in listsinceblock output; use empty
            // vec as placeholder — the deposit watcher derives L2 address from
            // this, but for spent deposits the script can be looked up separately
            // if needed. For new deposits, list_unspent will provide it.
            let script_bytes = Vec::new();

            deposits.push(DepositEvent {
                btc_tx_id: txid_bytes,
                btc_vout: vout,
                amount_sats,
                recipient_script: script_bytes,
                confirmations,
            });
        }

        Ok((deposits, lastblock))
    }

    /// Broadcast a raw transaction to the Bitcoin network.
    pub fn broadcast_raw_tx(&self, raw_tx_hex: &str) -> Result<[u8; 32], BitcoinError> {
        let client = self.require_client()?;

        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(
            &hex::decode(raw_tx_hex)
                .map_err(|e| BitcoinError::BroadcastFailed(format!("invalid hex: {}", e)))?,
        )
        .map_err(|e| BitcoinError::BroadcastFailed(format!("invalid tx: {}", e)))?;

        let txid = client
            .send_raw_transaction(&tx)
            .map_err(|e| BitcoinError::BroadcastFailed(e.to_string()))?;

        Ok(txid.to_byte_array())
    }

    /// Create a funded, signed raw transaction with an OP_RETURN output.
    ///
    /// Uses bitcoind's wallet to select inputs, compute change, and sign.
    /// Returns the signed transaction hex ready for broadcast.
    pub fn create_op_return_tx(&self, data: &[u8]) -> Result<String, BitcoinError> {
        let client = self.require_client()?;

        if data.len() > 80 {
            return Err(BitcoinError::InvalidAnchorData(format!(
                "OP_RETURN data too large: {} bytes (max 80)",
                data.len()
            )));
        }

        // Use createrawtransaction + fundrawtransaction + signrawtransactionwithwallet
        // via the JSON-RPC interface directly.
        //
        // Step 1: Create a raw tx with OP_RETURN output
        let outputs = serde_json::json!([
            { "data": hex::encode(data) }
        ]);
        let inputs = serde_json::json!([]);

        let raw_tx: String = client
            .call("createrawtransaction", &[inputs, outputs])
            .map_err(|e| BitcoinError::RpcCallFailed(format!("createrawtransaction: {}", e)))?;

        // Step 2: Fund the transaction (add inputs + change)
        let funded: serde_json::Value = client
            .call("fundrawtransaction", &[serde_json::Value::String(raw_tx)])
            .map_err(|e| BitcoinError::RpcCallFailed(format!("fundrawtransaction: {}", e)))?;

        let funded_hex = funded["hex"]
            .as_str()
            .ok_or_else(|| BitcoinError::RpcCallFailed("no hex in funded tx".to_string()))?;

        // Step 3: Sign with the wallet
        let signed: serde_json::Value = client
            .call(
                "signrawtransactionwithwallet",
                &[serde_json::Value::String(funded_hex.to_string())],
            )
            .map_err(|e| {
                BitcoinError::SigningFailed(format!("signrawtransactionwithwallet: {}", e))
            })?;

        let complete = signed["complete"].as_bool().unwrap_or(false);
        if !complete {
            return Err(BitcoinError::SigningFailed(
                "wallet signing incomplete".to_string(),
            ));
        }

        let signed_hex = signed["hex"]
            .as_str()
            .ok_or_else(|| BitcoinError::SigningFailed("no hex in signed tx".to_string()))?;

        Ok(signed_hex.to_string())
    }

    /// Send a signed transaction hex and return its txid.
    pub fn send_signed_tx(&self, signed_hex: &str) -> Result<[u8; 32], BitcoinError> {
        let client = self.require_client()?;

        let txid: bitcoin::Txid = client
            .call(
                "sendrawtransaction",
                &[serde_json::Value::String(signed_hex.to_string())],
            )
            .map_err(|e| BitcoinError::BroadcastFailed(e.to_string()))?;

        Ok(txid.to_byte_array())
    }

    /// Get the SPV inclusion proof (MerkleBlock) for a confirmed transaction.
    ///
    /// Calls Bitcoin Core's `gettxoutproof` RPC.
    /// Returns the raw serialized MerkleBlock bytes.
    pub fn get_tx_out_proof(&self, txid: &[u8; 32]) -> Result<Vec<u8>, BitcoinError> {
        let client = self.require_client()?;
        let txid_obj = bitcoin::Txid::from_byte_array(*txid);

        let result: String = client
            .call(
                "gettxoutproof",
                &[serde_json::json!([txid_obj.to_string()])],
            )
            .map_err(|e| BitcoinError::RpcCallFailed(format!("gettxoutproof: {}", e)))?;

        hex::decode(&result)
            .map_err(|e| BitcoinError::RpcCallFailed(format!("gettxoutproof hex decode: {}", e)))
    }

    /// Get block information for a confirmed transaction.
    ///
    /// Calls `getrawtransaction` with verbose=true.
    /// Returns `Some((block_hash, block_height, confirmations))` if confirmed,
    /// `None` if unconfirmed.
    pub fn get_tx_block_info(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<([u8; 32], u64, u32)>, BitcoinError> {
        let client = self.require_client()?;
        let txid_obj = bitcoin::Txid::from_byte_array(*txid);

        let result: serde_json::Value = client
            .call(
                "getrawtransaction",
                &[
                    serde_json::Value::String(txid_obj.to_string()),
                    serde_json::Value::Bool(true), // verbose
                ],
            )
            .map_err(|e| BitcoinError::RpcCallFailed(format!("getrawtransaction: {}", e)))?;

        // Unconfirmed transactions have no blockhash field
        let block_hash_hex = match result.get("blockhash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return Ok(None),
        };

        let block_hash_obj: bitcoin::BlockHash = block_hash_hex
            .parse()
            .map_err(|e| BitcoinError::RpcCallFailed(format!("parse blockhash: {}", e)))?;
        let block_hash = block_hash_obj.to_byte_array();

        // blockheight might not exist on older Bitcoin Core — fall back to 0
        let block_height = result
            .get("blockheight")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let confirmations = result
            .get("confirmations")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        Ok(Some((block_hash, block_height, confirmations)))
    }

    /// Get a reference to the inner client, or error if disconnected.
    fn require_client(&self) -> Result<&Client, BitcoinError> {
        self.client.as_ref().ok_or(BitcoinError::NotConnected)
    }
}

impl BitcoinRpc for BitcoinRpcClient {
    fn get_block_count(&self) -> Result<u64, BitcoinError> {
        self.get_block_count()
    }
    fn get_block_hash(&self, height: u64) -> Result<[u8; 32], BitcoinError> {
        self.get_block_hash(height)
    }
    fn get_block_info(&self, height: u64) -> Result<L1BlockInfo, BitcoinError> {
        self.get_block_info(height)
    }
    fn list_unspent_for_address(&self, address: &str) -> Result<Vec<DepositEvent>, BitcoinError> {
        self.list_unspent_for_address(address)
    }
    fn list_since_block(
        &self,
        address: &str,
        since_block_hash: Option<&[u8; 32]>,
    ) -> Result<(Vec<DepositEvent>, [u8; 32]), BitcoinError> {
        self.list_since_block(address, since_block_hash)
    }
    fn broadcast_raw_tx(&self, raw_tx_hex: &str) -> Result<[u8; 32], BitcoinError> {
        self.broadcast_raw_tx(raw_tx_hex)
    }
    fn create_op_return_tx(&self, data: &[u8]) -> Result<String, BitcoinError> {
        self.create_op_return_tx(data)
    }
    fn send_signed_tx(&self, signed_hex: &str) -> Result<[u8; 32], BitcoinError> {
        self.send_signed_tx(signed_hex)
    }
    fn get_tx_out_proof(&self, txid: &[u8; 32]) -> Result<Vec<u8>, BitcoinError> {
        self.get_tx_out_proof(txid)
    }
    fn get_tx_block_info(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<([u8; 32], u64, u32)>, BitcoinError> {
        self.get_tx_block_info(txid)
    }
    fn has_client(&self) -> bool {
        self.has_client()
    }
    fn is_connected(&self) -> bool {
        self.is_connected()
    }
    fn network(&self) -> bitcoin::Network {
        self.network()
    }
}

// Best-effort credential wipe on drop using the `zeroize` crate.
impl Drop for BitcoinRpcClient {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.user.zeroize();
        self.pass.zeroize();
    }
}

/// Validate that the RPC URL points to localhost.
///
/// `bitcoincore-rpc` uses `minreq` **without TLS**, so all RPC traffic —
/// including wallet credentials and raw transactions — is sent as plaintext
/// HTTP.  To prevent accidental credential leakage over the network, we
/// reject any URL whose host is not `127.0.0.1`, `::1`, or `localhost`.
///
/// Set the environment variable `BRRQ_ALLOW_REMOTE_RPC=true` to override
/// this check (e.g. when bitcoind is behind a TLS-terminating reverse proxy).
fn validate_rpc_url_localhost(url: &str) -> Result<(), BitcoinError> {
    // Strip the scheme to isolate the host portion.
    let host_part = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .unwrap_or(url);

    // Extract host (before port or path).
    let host = host_part
        .split(':')
        .next()
        .unwrap_or(host_part)
        .split('/')
        .next()
        .unwrap_or(host_part);

    let is_localhost = matches!(
        host,
        "127.0.0.1" | "::1" | "[::1]" | "localhost"
    );

    if !is_localhost {
        if std::env::var("BRRQ_ALLOW_REMOTE_RPC").as_deref() == Ok("true") {
            warn!(
                url = %url,
                "SECURITY: Remote Bitcoin RPC URL allowed via BRRQ_ALLOW_REMOTE_RPC. \
                 Traffic is plaintext HTTP — ensure a TLS proxy is in place."
            );
            return Ok(());
        }

        error!(
            url = %url,
            "CRITICAL: Bitcoin RPC URL is not localhost. bitcoincore-rpc sends \
             credentials and transactions as plaintext HTTP. Set \
             BRRQ_ALLOW_REMOTE_RPC=true to override."
        );
        return Err(BitcoinError::RemoteRpcNotAllowed(url.to_string()));
    }

    Ok(())
}

/// Parse a network name string into a `bitcoin::Network`.
fn parse_network(s: &str) -> Result<bitcoin::Network, BitcoinError> {
    match s.to_lowercase().as_str() {
        "mainnet" | "main" | "bitcoin" => Ok(bitcoin::Network::Bitcoin),
        "testnet" | "testnet3" | "test" => Ok(bitcoin::Network::Testnet),
        "regtest" | "reg" => Ok(bitcoin::Network::Regtest),
        "signet" => Ok(bitcoin::Network::Signet),
        other => Err(BitcoinError::ConfigError(format!(
            "unknown Bitcoin network: '{}' (expected mainnet/testnet/regtest/signet)",
            other
        ))),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_network_mainnet() {
        assert_eq!(parse_network("mainnet").unwrap(), bitcoin::Network::Bitcoin);
        assert_eq!(parse_network("main").unwrap(), bitcoin::Network::Bitcoin);
        assert_eq!(parse_network("bitcoin").unwrap(), bitcoin::Network::Bitcoin);
    }

    #[test]
    fn parse_network_testnet() {
        assert_eq!(parse_network("testnet").unwrap(), bitcoin::Network::Testnet);
        assert_eq!(parse_network("test").unwrap(), bitcoin::Network::Testnet);
    }

    #[test]
    fn parse_network_regtest() {
        assert_eq!(parse_network("regtest").unwrap(), bitcoin::Network::Regtest);
        assert_eq!(parse_network("reg").unwrap(), bitcoin::Network::Regtest);
    }

    #[test]
    fn parse_network_signet() {
        assert_eq!(parse_network("signet").unwrap(), bitcoin::Network::Signet);
    }

    #[test]
    fn parse_network_case_insensitive() {
        assert_eq!(parse_network("MAINNET").unwrap(), bitcoin::Network::Bitcoin);
        assert_eq!(parse_network("Regtest").unwrap(), bitcoin::Network::Regtest);
    }

    #[test]
    fn parse_network_unknown() {
        assert!(parse_network("foobar").is_err());
    }

    #[test]
    fn localhost_urls_accepted() {
        assert!(validate_rpc_url_localhost("http://127.0.0.1:8332").is_ok());
        assert!(validate_rpc_url_localhost("http://localhost:8332").is_ok());
        assert!(validate_rpc_url_localhost("http://[::1]:8332").is_ok());
        assert!(validate_rpc_url_localhost("http://127.0.0.1").is_ok());
    }

    #[test]
    fn remote_urls_rejected() {
        assert!(validate_rpc_url_localhost("http://10.0.0.5:8332").is_err());
        assert!(validate_rpc_url_localhost("http://bitcoin.example.com:8332").is_err());
        assert!(validate_rpc_url_localhost("http://192.168.1.1:8332").is_err());
    }

    #[test]
    fn disconnected_client_returns_not_connected() {
        // Creating with invalid URL — client will be None
        let client = BitcoinRpcClient {
            client: None,
            url: "http://invalid:1234".to_string(),
            user: String::new(),
            pass: String::new(),
            network: bitcoin::Network::Regtest,
        };
        assert!(!client.has_client());
        assert!(!client.is_connected());
        assert!(client.get_block_count().is_err());
    }

    #[test]
    fn client_network_accessor() {
        let client = BitcoinRpcClient {
            client: None,
            url: String::new(),
            user: String::new(),
            pass: String::new(),
            network: bitcoin::Network::Testnet,
        };
        assert_eq!(client.network(), bitcoin::Network::Testnet);
    }
}
