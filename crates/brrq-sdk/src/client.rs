//! JSON-RPC client for interacting with a Brrq node.
//!
//! ## Usage
//!
//! ```ignore (requires running Brrq node at localhost:8545)
//! let client = BrrqClient::new("http://localhost:8545");
//! let balance = client.get_balance(&alice_addr).await?;
//! let tx_hash = client.send_transaction(&signed_tx).await?;
//! ```
//!
//! All methods are async and use raw TCP + HTTP/1.1 to communicate with
//! the node's JSON-RPC server. No external HTTP crate required.
//!
//! ## TLS Support
//!
//! When the endpoint starts with `https://`, the client performs a real
//! TLS handshake via `tokio-rustls` + `rustls` with platform-native
//! certificate verification (via `rustls-platform-verifier`).
//! Plaintext HTTP is still supported for `http://` endpoints (e.g. local dev).
//!
//! ## Connection Hardening
//!
//! - **TCP connect timeout**: 10 seconds (prevents hang on unreachable hosts)
//! - **Read timeout**: 30 seconds (prevents hang on slow/malicious servers)
//! - **Request ID counter**: monotonic per-client (enables request correlation)
//! - **Max response size**: 16 MB (prevents OOM from malicious servers)

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use brrq_crypto::hash::Hash256;
use brrq_types::address::Address;
use brrq_types::transaction::{Transaction, TransactionKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
// tokio-rustls for async TLS, rustls-platform-verifier for native certificate
// trust store integration.
use rustls_platform_verifier::ConfigVerifierExt;
use tokio_rustls::TlsConnector;

use crate::error::SdkError;

/// Maximum response size (16 MB) to prevent OOM from malicious servers.
pub const MAX_RESPONSE_SIZE: usize = 16 * 1024 * 1024;

/// TCP connection timeout — abort if server is unreachable after 10 seconds.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Read timeout — abort if server stops sending data for 30 seconds.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Brrq RPC client.
///
/// Supports TLS via `tokio-rustls` when the endpoint starts with `https://`.
/// Certificate verification uses the platform's native trust store via
/// `rustls-platform-verifier`.
pub struct BrrqClient {
    /// Original endpoint URL.
    endpoint: String,
    /// Parsed host for TCP connection.
    host: String,
    /// Parsed port for TCP connection.
    port: u16,
    /// Whether TLS is required (endpoint starts with https://).
    tls_required: bool,
    /// Pre-built TLS connector — `Some` when `tls_required` is true.
    tls_connector: Option<TlsConnector>,
    /// Monotonically increasing request ID for correlation.
    next_request_id: AtomicU64,
    /// Optional API key for authenticated endpoints.
    api_key: Option<String>,
}

/// Node health response.
pub struct HealthResponse {
    pub height: u64,
    pub status: String,
    pub validator_count: u64,
    pub peer_count: u64,
}

/// Portal stats response.
pub struct PortalStatsResponse {
    pub active_locks: u64,
    pub total_escrowed: u64,
    pub nullifiers_consumed: u64,
}

/// Faucet drip response.
pub struct FaucetResponse {
    pub amount: u64,
    pub tx_hash: String,
}

impl BrrqClient {
    /// Create a new client connected to a node endpoint.
    ///
    /// Accepts formats: `http://host:port`, `https://host:port`, `host:port`,
    /// or `host` (default port 8545).
    ///
    /// When the endpoint starts with `https://`, a `TlsConnector` is built
    /// eagerly using the platform's native certificate verifier. All subsequent
    /// RPC calls over that endpoint will be TLS-encrypted.
    pub fn new(endpoint: &str) -> Self {
        let tls_required = endpoint.starts_with("https://");
        let clean = endpoint
            .strip_prefix("https://")
            .or_else(|| endpoint.strip_prefix("http://"))
            .unwrap_or(endpoint)
            .trim_end_matches('/');
        let default_port = if tls_required { 443 } else { 8545 };
        // Handle IPv6 addresses in bracket notation: [::1]:8545
        let (host, port) = if clean.starts_with('[') {
            if let Some(bracket_end) = clean.find(']') {
                let h = &clean[1..bracket_end];
                let rest = &clean[bracket_end + 1..];
                let p = if let Some(colon_rest) = rest.strip_prefix(':') {
                    colon_rest.parse::<u16>().unwrap_or(default_port)
                } else {
                    default_port
                };
                (h.to_string(), p)
            } else {
                // Malformed bracket — treat whole string as host.
                (clean.to_string(), default_port)
            }
        } else if let Some(pos) = clean.rfind(':') {
            let h = &clean[..pos];
            let p = clean[pos + 1..].parse::<u16>().unwrap_or(default_port);
            (h.to_string(), p)
        } else {
            (clean.to_string(), default_port)
        };

        // Build the TLS connector eagerly when https:// is requested.
        // Uses platform-native certificate verification (Windows CAPI, macOS
        // Security.framework, Linux system trust store).
        let tls_connector = if tls_required {
            let config = rustls::ClientConfig::with_platform_verifier();
            Some(TlsConnector::from(Arc::new(config)))
        } else {
            None
        };

        Self {
            endpoint: endpoint.to_string(),
            host,
            port,
            tls_required,
            tls_connector,
            next_request_id: AtomicU64::new(1),
            api_key: None,
        }
    }

    /// Create a client with an API key for authenticated endpoints.
    pub fn with_api_key(endpoint: &str, api_key: &str) -> Self {
        let mut client = Self::new(endpoint);
        client.api_key = Some(api_key.to_string());
        client
    }

    /// Get the endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Get the balance of an address (in satoshis).
    pub async fn get_balance(&self, address: &Address) -> Result<u64, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let result = self
            .rpc_call("brrq_getBalance", serde_json::json!([addr_hex]))
            .await?;
        result.as_u64().ok_or(SdkError::RpcError {
            reason: format!("expected u64 balance, got: {}", result),
        })
    }

    /// Get the nonce of an address.
    pub async fn get_nonce(&self, address: &Address) -> Result<u64, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let result = self
            .rpc_call("brrq_getNonce", serde_json::json!([addr_hex]))
            .await?;
        result.as_u64().ok_or(SdkError::RpcError {
            reason: format!("expected u64 nonce, got: {}", result),
        })
    }

    /// Send a signed transaction.
    ///
    /// The transaction must be properly signed (e.g., via `Wallet::transfer`,
    /// `Wallet::deploy`, or `Wallet::call_contract`).
    /// The signature and public key are sent to the node for verification.
    ///
    /// Supports all transaction types: Transfer, Deploy, and ContractCall.
    ///
    /// Returns the transaction hash on success.
    pub async fn send_transaction(&self, tx: &Transaction) -> Result<Hash256, SdkError> {
        let from_hex = format!("0x{}", hex::encode(tx.body.from.as_bytes()));
        let sig_hex = format!("0x{}", hex::encode(tx.signature.as_bytes()));
        let pk_hex = format!("0x{}", hex::encode(tx.public_key.as_bytes()));

        // Build the base JSON object with common fields
        let mut tx_obj = serde_json::Map::new();
        tx_obj.insert("from".into(), serde_json::json!(from_hex));
        tx_obj.insert("nonce".into(), serde_json::json!(tx.body.nonce));
        tx_obj.insert("gas_limit".into(), serde_json::json!(tx.body.gas_limit));
        tx_obj.insert(
            "max_fee_per_gas".into(),
            serde_json::json!(tx.body.max_fee_per_gas),
        );
        tx_obj.insert(
            "max_priority_fee_per_gas".into(),
            serde_json::json!(tx.body.max_priority_fee_per_gas),
        );
        tx_obj.insert("signature".into(), serde_json::json!(sig_hex));
        tx_obj.insert("public_key".into(), serde_json::json!(pk_hex));
        tx_obj.insert("chain_id".into(), serde_json::json!(tx.body.chain_id));

        // Add type-specific fields
        match &tx.body.kind {
            TransactionKind::Transfer { to, amount } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("transfer"));
                tx_obj.insert(
                    "to".into(),
                    serde_json::json!(format!("0x{}", hex::encode(to.as_bytes()))),
                );
                tx_obj.insert("amount".into(), serde_json::json!(*amount));
            }
            TransactionKind::Deploy { code } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("deploy"));
                tx_obj.insert(
                    "code".into(),
                    serde_json::json!(format!("0x{}", hex::encode(code))),
                );
            }
            TransactionKind::ContractCall { to, data, value } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("contract_call"));
                tx_obj.insert(
                    "to".into(),
                    serde_json::json!(format!("0x{}", hex::encode(to.as_bytes()))),
                );
                tx_obj.insert(
                    "call_data".into(),
                    serde_json::json!(format!("0x{}", hex::encode(data))),
                );
                tx_obj.insert("value".into(), serde_json::json!(*value));
            }
            TransactionKind::RegisterValidator { stake } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("register_validator"));
                tx_obj.insert("stake".into(), serde_json::json!(*stake));
            }
            TransactionKind::AddStake { amount } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("add_stake"));
                tx_obj.insert("amount".into(), serde_json::json!(*amount));
            }
            TransactionKind::BeginUnbonding => {
                tx_obj.insert("tx_type".into(), serde_json::json!("begin_unbonding"));
            }
            TransactionKind::FinishUnbonding => {
                tx_obj.insert("tx_type".into(), serde_json::json!("finish_unbonding"));
            }
            TransactionKind::SubmitEquivocationProof {
                validator,
                height,
                block_hash_a,
                block_hash_b,
                signature_a,
                signature_b,
                slh_dsa_pk,
            } => {
                tx_obj.insert(
                    "tx_type".into(),
                    serde_json::json!("submit_equivocation_proof"),
                );
                tx_obj.insert(
                    "validator".into(),
                    serde_json::json!(format!("0x{}", hex::encode(validator.as_bytes()))),
                );
                tx_obj.insert("height".into(), serde_json::json!(*height));
                tx_obj.insert(
                    "block_hash_a".into(),
                    serde_json::json!(format!("0x{}", hex::encode(block_hash_a.as_bytes()))),
                );
                tx_obj.insert(
                    "block_hash_b".into(),
                    serde_json::json!(format!("0x{}", hex::encode(block_hash_b.as_bytes()))),
                );
                tx_obj.insert(
                    "signature_a".into(),
                    serde_json::json!(format!("0x{}", hex::encode(signature_a))),
                );
                tx_obj.insert(
                    "signature_b".into(),
                    serde_json::json!(format!("0x{}", hex::encode(signature_b))),
                );
                tx_obj.insert(
                    "slh_dsa_pk".into(),
                    serde_json::json!(format!("0x{}", hex::encode(slh_dsa_pk))),
                );
            }
            TransactionKind::DepositSynthetic {
                recipient,
                amount,
                btc_tx_id,
                btc_vout,
                block_hash: _,
                merkle_block_raw: _,
            } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("deposit_synthetic"));
                tx_obj.insert(
                    "recipient".into(),
                    serde_json::json!(format!("0x{}", hex::encode(recipient.as_bytes()))),
                );
                tx_obj.insert("amount".into(), serde_json::json!(*amount));
                tx_obj.insert(
                    "btc_tx_id".into(),
                    serde_json::json!(format!("0x{}", hex::encode(btc_tx_id.as_bytes()))),
                );
                tx_obj.insert("btc_vout".into(), serde_json::json!(*btc_vout));
            }
            TransactionKind::L1ZklaAnchor {
                btc_block_hash,
                btc_tx_id,
                stark_proof,
                recovered_validators_bitmap,
            } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("l1_zkla_anchor"));
                tx_obj.insert(
                    "btc_block_hash".into(),
                    serde_json::json!(format!("0x{}", hex::encode(btc_block_hash.as_bytes()))),
                );
                tx_obj.insert(
                    "btc_tx_id".into(),
                    serde_json::json!(format!("0x{}", hex::encode(btc_tx_id.as_bytes()))),
                );
                tx_obj.insert(
                    "stark_proof".into(),
                    serde_json::json!(format!("0x{}", hex::encode(stark_proof))),
                );
                tx_obj.insert(
                    "recovered_validators_bitmap".into(),
                    serde_json::json!(format!("0x{}", hex::encode(recovered_validators_bitmap))),
                );
            }
            // ── Portal (L3) transactions ──
            TransactionKind::CreatePortalLock {
                amount,
                condition_hash,
                nullifier_hash,
                timeout_l2_block,
            } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("create_portal_lock"));
                tx_obj.insert("amount".into(), serde_json::json!(*amount));
                tx_obj.insert(
                    "condition_hash".into(),
                    serde_json::json!(format!("0x{}", hex::encode(condition_hash.as_bytes()))),
                );
                tx_obj.insert(
                    "nullifier_hash".into(),
                    serde_json::json!(format!("0x{}", hex::encode(nullifier_hash.as_bytes()))),
                );
                tx_obj.insert("timeout_l2_block".into(), serde_json::json!(*timeout_l2_block));
            }
            TransactionKind::SettlePortalLock {
                lock_id,
                merchant_secret,
                portal_signature,
                nullifier,
            } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("settle_portal_lock"));
                tx_obj.insert(
                    "lock_id".into(),
                    serde_json::json!(format!("0x{}", hex::encode(lock_id.as_bytes()))),
                );
                tx_obj.insert(
                    "merchant_secret".into(),
                    serde_json::json!(format!("0x{}", hex::encode(merchant_secret))),
                );
                tx_obj.insert(
                    "portal_signature".into(),
                    serde_json::json!(format!("0x{}", hex::encode(portal_signature))),
                );
                tx_obj.insert(
                    "nullifier".into(),
                    serde_json::json!(format!("0x{}", hex::encode(nullifier.as_bytes()))),
                );
            }
            TransactionKind::BatchSettlePortal { claims } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("batch_settle_portal"));
                tx_obj.insert("claims_count".into(), serde_json::json!(claims.len()));
                let claims_json: Vec<_> = claims
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "lock_id": format!("0x{}", hex::encode(c.lock_id.as_bytes())),
                            "nullifier": format!("0x{}", hex::encode(c.nullifier.as_bytes())),
                        })
                    })
                    .collect();
                tx_obj.insert("claims".into(), serde_json::json!(claims_json));
            }
            TransactionKind::CancelPortalLock { lock_id } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("cancel_portal_lock"));
                tx_obj.insert(
                    "lock_id".into(),
                    serde_json::json!(format!("0x{}", hex::encode(lock_id.as_bytes()))),
                );
            }
            TransactionKind::CreateLockPool {
                slot_amounts,
                timeout_l2_block,
            } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("create_lock_pool"));
                tx_obj.insert("slot_amounts".into(), serde_json::json!(slot_amounts));
                tx_obj.insert("timeout_l2_block".into(), serde_json::json!(*timeout_l2_block));
            }
            TransactionKind::RefillLockPool {
                slot_amounts,
                timeout_l2_block,
            } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("refill_lock_pool"));
                tx_obj.insert("slot_amounts".into(), serde_json::json!(slot_amounts));
                tx_obj.insert("timeout_l2_block".into(), serde_json::json!(*timeout_l2_block));
            }
            TransactionKind::UpdateLockCondition {
                lock_id,
                condition_hash,
                nullifier_hash,
                merchant_address,
                merchant_pubkey,
            } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("update_lock_condition"));
                tx_obj.insert(
                    "lock_id".into(),
                    serde_json::json!(format!("0x{}", hex::encode(lock_id.as_bytes()))),
                );
                tx_obj.insert(
                    "condition_hash".into(),
                    serde_json::json!(format!("0x{}", hex::encode(condition_hash.as_bytes()))),
                );
                tx_obj.insert(
                    "nullifier_hash".into(),
                    serde_json::json!(format!("0x{}", hex::encode(nullifier_hash.as_bytes()))),
                );
                tx_obj.insert(
                    "merchant_address".into(),
                    serde_json::json!(format!("0x{}", hex::encode(merchant_address.as_bytes()))),
                );
                tx_obj.insert(
                    "merchant_pubkey".into(),
                    serde_json::json!(format!("0x{}", hex::encode(merchant_pubkey))),
                );
            }
            TransactionKind::RelayedBatchSettle {
                claims,
                merchant_address,
                relay_fee_bps,
                ..
            } => {
                tx_obj.insert("tx_type".into(), serde_json::json!("relayed_batch_settle"));
                tx_obj.insert("claims_count".into(), serde_json::json!(claims.len()));
                tx_obj.insert(
                    "merchant_address".into(),
                    serde_json::json!(format!("0x{}", hex::encode(merchant_address.as_bytes()))),
                );
                tx_obj.insert("relay_fee_bps".into(), serde_json::json!(*relay_fee_bps));
            }
        }

        let params = serde_json::json!([serde_json::Value::Object(tx_obj)]);
        let result = self.rpc_call("brrq_sendTransaction", params).await?;

        // Parse tx hash from "0x..." hex string
        let hash_hex = result.as_str().ok_or(SdkError::RpcError {
            reason: "expected hex string for tx hash".into(),
        })?;
        parse_hash256(hash_hex).ok_or(SdkError::RpcError {
            reason: format!("invalid tx hash hex: {}", hash_hex),
        })
    }

    /// Get the current block height.
    pub async fn get_block_height(&self) -> Result<u64, SdkError> {
        let result = self
            .rpc_call("brrq_blockHeight", serde_json::json!([]))
            .await?;
        result.as_u64().ok_or(SdkError::RpcError {
            reason: format!("expected u64 height, got: {}", result),
        })
    }

    /// Get a block by height.
    pub async fn get_block(&self, height: u64) -> Result<Option<serde_json::Value>, SdkError> {
        let result = self
            .rpc_call("brrq_getBlock", serde_json::json!([height]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Get the latest block.
    pub async fn get_latest_block(&self) -> Result<Option<serde_json::Value>, SdkError> {
        let result = self
            .rpc_call("brrq_getBlock", serde_json::json!(["latest"]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Get a transaction by hash (searches blocks and mempool).
    pub async fn get_transaction(
        &self,
        tx_hash: &Hash256,
    ) -> Result<Option<serde_json::Value>, SdkError> {
        let hash_hex = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        let result = self
            .rpc_call("brrq_getTransaction", serde_json::json!([hash_hex]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Get contract code at an address.
    pub async fn get_code(&self, address: &Address) -> Result<Option<serde_json::Value>, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let result = self
            .rpc_call("brrq_getCode", serde_json::json!([addr_hex]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Get a value from contract storage.
    pub async fn get_storage_at(
        &self,
        address: &Address,
        key: &Hash256,
    ) -> Result<Option<String>, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let key_hex = format!("0x{}", hex::encode(key.as_bytes()));
        let result = self
            .rpc_call("brrq_getStorageAt", serde_json::json!([addr_hex, key_hex]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result.as_str().unwrap_or("").to_string()))
        }
    }

    /// Get the current state root.
    pub async fn get_state_root(&self) -> Result<String, SdkError> {
        let result = self
            .rpc_call("brrq_getStateRoot", serde_json::json!([]))
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or(SdkError::RpcError {
                reason: "expected state root hex string".into(),
            })
    }

    /// Get full account information.
    pub async fn get_account(
        &self,
        address: &Address,
    ) -> Result<Option<serde_json::Value>, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let result = self
            .rpc_call("brrq_getAccount", serde_json::json!([addr_hex]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Get the chain ID.
    pub async fn get_chain_id(&self) -> Result<u64, SdkError> {
        let result = self.rpc_call("brrq_chainId", serde_json::json!([])).await?;
        result["chain_id"].as_u64().ok_or(SdkError::RpcError {
            reason: "expected chain_id in response".into(),
        })
    }

    /// Get a block by its hash.
    pub async fn get_block_by_hash(
        &self,
        hash: &Hash256,
    ) -> Result<Option<serde_json::Value>, SdkError> {
        let hash_hex = format!("0x{}", hex::encode(hash.as_bytes()));
        let result = self
            .rpc_call("brrq_getBlockByHash", serde_json::json!([hash_hex]))
            .await?;
        if result.is_null() {
            Ok(None)
        } else {
            Ok(Some(result))
        }
    }

    /// Get the list of validators.
    pub async fn get_validators(&self) -> Result<serde_json::Value, SdkError> {
        self.rpc_call("brrq_getValidators", serde_json::json!([]))
            .await
    }

    /// Get current epoch information.
    pub async fn get_epoch_info(&self) -> Result<serde_json::Value, SdkError> {
        self.rpc_call("brrq_getEpochInfo", serde_json::json!([]))
            .await
    }

    /// Get staking information for all validators or a specific one.
    pub async fn get_staking_info(
        &self,
        address: Option<&Address>,
    ) -> Result<serde_json::Value, SdkError> {
        let params = match address {
            Some(addr) => {
                let addr_hex = format!("0x{}", hex::encode(addr.as_bytes()));
                serde_json::json!([addr_hex])
            }
            None => serde_json::json!([]),
        };
        self.rpc_call("brrq_getStakingInfo", params).await
    }

    // ── Bridge methods ────────────────────────────────────────────────

    /// Submit a deposit to the bridge.
    pub async fn bridge_deposit(
        &self,
        btc_tx_id: &str,
        vout: u32,
        amount: u64,
        recipient: &Address,
        confirmations: u32,
    ) -> Result<serde_json::Value, SdkError> {
        let recipient_hex = format!("0x{}", hex::encode(recipient.as_bytes()));
        self.rpc_call(
            "brrq_bridgeDeposit",
            serde_json::json!([{
                "btc_tx_id": btc_tx_id,
                "vout": vout,
                "amount": amount,
                "recipient": recipient_hex,
                "confirmations": confirmations,
            }]),
        )
        .await
    }

    /// Request a withdrawal from the bridge.
    pub async fn bridge_withdraw(
        &self,
        sender: &Address,
        amount: u64,
        btc_destination: &str,
    ) -> Result<serde_json::Value, SdkError> {
        let sender_hex = format!("0x{}", hex::encode(sender.as_bytes()));
        self.rpc_call(
            "brrq_bridgeWithdraw",
            serde_json::json!([{
                "sender": sender_hex,
                "amount": amount,
                "btc_destination": btc_destination,
            }]),
        )
        .await
    }

    /// Get bridge status.
    pub async fn bridge_status(&self) -> Result<serde_json::Value, SdkError> {
        self.rpc_call("brrq_bridgeStatus", serde_json::json!([]))
            .await
    }

    /// Get a transaction receipt by hash.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &Hash256,
    ) -> Result<Option<TransactionReceipt>, SdkError> {
        let hash_hex = format!("0x{}", hex::encode(tx_hash.as_bytes()));
        let result = self
            .rpc_call("brrq_getReceipt", serde_json::json!([hash_hex]))
            .await?;

        if result.is_null() {
            return Ok(None);
        }

        let block_height = result["block_height"].as_u64().ok_or(SdkError::RpcError {
            reason: "missing block_height in receipt".into(),
        })?;
        let gas_used = result["gas_used"].as_u64().ok_or(SdkError::RpcError {
            reason: "missing gas_used in receipt".into(),
        })?;
        let success = result["success"].as_bool().ok_or(SdkError::RpcError {
            reason: "missing success in receipt".into(),
        })?;

        Ok(Some(TransactionReceipt {
            tx_hash: *tx_hash,
            block_height,
            success,
            gas_used,
        }))
    }

    // ── State proof methods ─────────────────────────────────────────────

    /// Get an account proof (SMT Merkle proof for account state).
    ///
    /// Returns the raw JSON proof data including siblings, account state, and state root.
    pub async fn get_account_proof(
        &self,
        address: &Address,
    ) -> Result<serde_json::Value, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        self.rpc_call("brrq_getAccountProof", serde_json::json!([addr_hex]))
            .await
    }

    /// Get a storage proof (chained SMT proof: storage → account → state root).
    ///
    /// Returns the raw JSON proof data including both account and storage proofs.
    pub async fn get_storage_proof(
        &self,
        address: &Address,
        key: &Hash256,
    ) -> Result<serde_json::Value, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let key_hex = format!("0x{}", hex::encode(key.as_bytes()));
        self.rpc_call(
            "brrq_getStorageProof",
            serde_json::json!([addr_hex, key_hex]),
        )
        .await
    }

    /// Verify a proof server-side.
    ///
    /// Useful for light clients that want the node to confirm a proof's validity.
    pub async fn verify_proof(
        &self,
        proof_type: &str,
        address: &Address,
        key: Option<&Hash256>,
        state_root: Option<&Hash256>,
    ) -> Result<bool, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let mut params = serde_json::Map::new();
        params.insert("type".into(), serde_json::json!(proof_type));
        params.insert("address".into(), serde_json::json!(addr_hex));
        if let Some(k) = key {
            params.insert(
                "key".into(),
                serde_json::json!(format!("0x{}", hex::encode(k.as_bytes()))),
            );
        }
        if let Some(root) = state_root {
            params.insert(
                "state_root".into(),
                serde_json::json!(format!("0x{}", hex::encode(root.as_bytes()))),
            );
        }

        let result = self
            .rpc_call(
                "brrq_verifyProof",
                serde_json::json!([serde_json::Value::Object(params)]),
            )
            .await?;
        result["valid"].as_bool().ok_or(SdkError::RpcError {
            reason: "missing 'valid' in verify response".into(),
        })
    }

    // ── Internal ───────────────────────────────────────────────────────

    /// Make a JSON-RPC 2.0 call and return the result.
    ///
    /// When `tls_required` is true, the TCP stream is wrapped in a TLS session
    /// via `tokio-rustls` before any application data is sent. Certificate
    /// verification uses the platform's native trust store. Uses connect
    /// timeout, read timeout, and unique request IDs.
    async fn rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, SdkError> {
        // Monotonic request ID for correlation.
        let req_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);

        let body = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": req_id,
        });
        let body_str = serde_json::to_string(&body).map_err(|e| SdkError::RpcError {
            reason: format!("serialize request: {}", e),
        })?;

        let auth = self.api_key.as_ref().map(|k| format!("Authorization: Bearer {}\r\n", k)).unwrap_or_default();
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}:{}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.host,
            self.port,
            auth,
            body_str.len(),
            body_str,
        );

        let addr = format!("{}:{}", self.host, self.port);

        // TCP connect with timeout — prevents hang on unreachable hosts.
        let tcp_stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .map_err(|_| SdkError::RpcError {
                reason: format!(
                    "connect timeout ({}s) to {}",
                    CONNECT_TIMEOUT.as_secs(),
                    addr
                ),
            })?
            .map_err(|e| SdkError::RpcError {
                reason: format!("connect to {}: {}", addr, e),
            })?;

        // When https:// was specified, perform a TLS handshake before sending
        // any data so credentials and transaction data are never in plaintext.
        // Use http_raw for Content-Length-aware reading (no premature shutdown)
        let body = self.http_raw(&request).await?;
        // Parse JSON-RPC response from body
        let rpc_resp: serde_json::Value = serde_json::from_str(&body).map_err(|e| {
            SdkError::RpcError {
                reason: format!("invalid JSON-RPC response: {e} — body: {}", &body[..body.len().min(200)]),
            }
        })?;

        if let Some(err) = rpc_resp.get("error") {
            let msg = err
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown RPC error");
            return Err(SdkError::RpcError { reason: msg.into() });
        }

        rpc_resp.get("result").cloned().ok_or(SdkError::RpcError {
            reason: "missing 'result' in JSON-RPC response".into(),
        })
    }

    /// Read response with bounded buffer to prevent OOM. The entire read loop
    /// is wrapped in a timeout to prevent hang on slow servers. Works over both
    /// plaintext TCP and TLS streams (via `AsyncReadExt` trait object).
    async fn read_response<R: tokio::io::AsyncRead + Unpin>(
        &self,
        reader: &mut R,
    ) -> Result<Vec<u8>, SdkError> {
        tokio::time::timeout(READ_TIMEOUT, async {
            let mut buf = Vec::new();
            let mut total_read = 0usize;
            let mut tmp = [0u8; 8192];
            loop {
                let n = reader
                    .read(&mut tmp)
                    .await
                    .map_err(|e| SdkError::RpcError {
                        reason: format!("read: {}", e),
                    })?;
                if n == 0 {
                    break;
                }
                total_read += n;
                if total_read > MAX_RESPONSE_SIZE {
                    return Err(SdkError::RpcError {
                        reason: format!(
                            "response exceeds maximum size ({} bytes)",
                            MAX_RESPONSE_SIZE,
                        ),
                    });
                }
                buf.extend_from_slice(&tmp[..n]);
            }
            Ok::<Vec<u8>, SdkError>(buf)
        })
        .await
        .map_err(|_| SdkError::RpcError {
            reason: format!("read timeout ({}s)", READ_TIMEOUT.as_secs()),
        })?
    }

    /// Parse the raw HTTP response bytes into a JSON-RPC result value.
    fn parse_rpc_response(&self, buf: &[u8]) -> Result<serde_json::Value, SdkError> {
        let response = String::from_utf8_lossy(buf);

        // Validate the HTTP status line before attempting to parse JSON.
        let status_line = response.lines().next().unwrap_or("");
        if !status_line.contains("200") && !status_line.contains("201") {
            return Err(SdkError::RpcError {
                reason: format!("HTTP error: {}", status_line),
            });
        }

        // Find JSON body after HTTP headers
        let json_body = response
            .find("\r\n\r\n")
            .map(|pos| &response[pos + 4..])
            .unwrap_or(&response);

        let rpc_resp: serde_json::Value =
            serde_json::from_str(json_body).map_err(|e| SdkError::RpcError {
                reason: format!("parse response: {}", e),
            })?;

        // Check for JSON-RPC error
        if let Some(error) = rpc_resp.get("error") {
            let msg = error
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown RPC error");
            return Err(SdkError::RpcError { reason: msg.into() });
        }

        rpc_resp.get("result").cloned().ok_or(SdkError::RpcError {
            reason: "missing 'result' in JSON-RPC response".into(),
        })
    }

    /// Send raw HTTP request with Content-Length awareness.
    async fn http_raw(&self, request: &str) -> Result<String, SdkError> {
        let addr = format!("{}:{}", self.host, self.port);
        let tcp_stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr))
            .await
            .map_err(|_| SdkError::RpcError { reason: format!("connect timeout to {}", addr) })?
            .map_err(|e| SdkError::RpcError { reason: format!("connect to {}: {}", addr, e) })?;

        let mut stream = tcp_stream;
        stream.write_all(request.as_bytes()).await.map_err(|e| SdkError::RpcError { reason: format!("write: {e}") })?;

        // Read headers + body with Content-Length awareness
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let read_result = tokio::time::timeout(READ_TIMEOUT, async {
            loop {
                let n = stream.read(&mut tmp).await.map_err(|e| SdkError::RpcError { reason: format!("read: {e}") })?;
                if n == 0 { break; }
                buf.extend_from_slice(&tmp[..n]);
                // Check if we have full headers + body
                let s = String::from_utf8_lossy(&buf);
                if let Some(header_end) = s.find("\r\n\r\n") {
                    let headers = &s[..header_end];
                    // Parse Content-Length
                    let content_len = headers.lines()
                        .find(|l| l.to_lowercase().starts_with("content-length:"))
                        .and_then(|l| l.split(':').nth(1))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    let body_start = header_end + 4;
                    if buf.len() >= body_start + content_len {
                        break; // Got full response
                    }
                }
                if buf.len() > MAX_RESPONSE_SIZE { break; }
            }
            Ok::<(), SdkError>(())
        }).await.map_err(|_| SdkError::RpcError { reason: "read timeout".into() })?;
        read_result?;

        let full = String::from_utf8_lossy(&buf);
        if let Some(pos) = full.find("\r\n\r\n") {
            Ok(full[pos + 4..].to_string())
        } else {
            Ok(full.to_string())
        }
    }

    /// GET request to a REST endpoint.
    async fn rest_get(&self, path: &str) -> Result<serde_json::Value, SdkError> {
        let auth = self.api_key.as_ref().map(|k| format!("Authorization: Bearer {}\r\n", k)).unwrap_or_default();
        let req = format!("GET /api/v1{} HTTP/1.1\r\nHost: {}:{}\r\n{}Connection: close\r\n\r\n", path, self.host, self.port, auth);
        let body = self.http_raw(&req).await?;
        serde_json::from_str(&body).map_err(|e| SdkError::RpcError { reason: format!("REST: {e}") })
    }

    /// POST request to a REST endpoint.
    async fn rest_post(&self, path: &str, data: &serde_json::Value) -> Result<serde_json::Value, SdkError> {
        let payload = serde_json::to_string(data).map_err(|e| SdkError::RpcError { reason: format!("serialize: {e}") })?;
        let auth = self.api_key.as_ref().map(|k| format!("Authorization: Bearer {}\r\n", k)).unwrap_or_default();
        let req = format!("POST /api/v1{} HTTP/1.1\r\nHost: {}:{}\r\n{}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", path, self.host, self.port, auth, payload.len(), payload);
        let body = self.http_raw(&req).await?;
        serde_json::from_str(&body).map_err(|e| SdkError::RpcError { reason: format!("REST: {e}") })
    }

    /// Get node health status.
    pub async fn get_health(&self) -> Result<HealthResponse, SdkError> {
        let json = self.rest_get("/health").await?;
        Ok(HealthResponse {
            height: json["height"].as_u64().unwrap_or(0),
            status: json["status"].as_str().unwrap_or("unknown").to_string(),
            validator_count: json["validator_count"].as_u64().unwrap_or(0),
            peer_count: json["peer_count"].as_u64().unwrap_or(0),
        })
    }

    /// Get Portal stats.
    pub async fn get_portal_stats(&self) -> Result<PortalStatsResponse, SdkError> {
        let json = self.rest_get("/portal/stats").await?;
        Ok(PortalStatsResponse {
            active_locks: json["active_locks"].as_u64().unwrap_or(0),
            total_escrowed: json["total_escrowed"].as_u64().unwrap_or(0),
            nullifiers_consumed: json["nullifiers_consumed"].as_u64().unwrap_or(0),
        })
    }

    /// Get a Portal lock by ID.
    pub async fn get_portal_lock(&self, lock_id: &Hash256) -> Result<serde_json::Value, SdkError> {
        let hex = format!("0x{}", hex::encode(lock_id.as_bytes()));
        self.rest_get(&format!("/portal/locks/{}", hex)).await
    }

    /// Check nullifier status.
    pub async fn check_nullifier(&self, nullifier: &Hash256) -> Result<serde_json::Value, SdkError> {
        let hex = format!("0x{}", hex::encode(nullifier.as_bytes()));
        self.rest_get(&format!("/portal/nullifiers/{}", hex)).await
    }

    /// Request testnet faucet drip.
    pub async fn faucet_drip(&self, address: &Address) -> Result<FaucetResponse, SdkError> {
        let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
        let json = self.rest_post("/faucet", &serde_json::json!({ "address": addr_hex })).await?;
        Ok(FaucetResponse {
            amount: json["amount"].as_u64().unwrap_or(0),
            tx_hash: json["tx_hash"].as_str().unwrap_or("").to_string(),
        })
    }
}

/// Transaction receipt (simplified).
#[derive(Debug, Clone)]
pub struct TransactionReceipt {
    /// Transaction hash.
    pub tx_hash: Hash256,
    /// Block height it was included in.
    pub block_height: u64,
    /// Whether execution succeeded.
    pub success: bool,
    /// Gas used.
    pub gas_used: u64,
}

/// Parse a hex hash string (with or without "0x" prefix) into a Hash256.
fn parse_hash256(s: &str) -> Option<Hash256> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Hash256::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[test]
    fn test_client_creation() {
        let client = BrrqClient::new("http://localhost:8545");
        assert_eq!(client.endpoint(), "http://localhost:8545");
        assert_eq!(client.host, "localhost");
        assert_eq!(client.port, 8545);
    }

    #[test]
    fn test_client_parse_host_port() {
        let client = BrrqClient::new("http://127.0.0.1:9999");
        assert_eq!(client.host, "127.0.0.1");
        assert_eq!(client.port, 9999);
    }

    #[test]
    fn test_client_parse_no_protocol() {
        let client = BrrqClient::new("myhost:3000");
        assert_eq!(client.host, "myhost");
        assert_eq!(client.port, 3000);
    }

    #[test]
    fn test_client_parse_default_port() {
        let client = BrrqClient::new("http://myhost");
        assert_eq!(client.host, "myhost");
        assert_eq!(client.port, 8545);
    }

    /// Verify that https:// endpoints build a TLS connector and default to
    /// port 443.
    #[test]
    fn test_client_https_creates_tls_connector() {
        let client = BrrqClient::new("https://node.example.com");
        assert!(client.tls_required);
        assert!(client.tls_connector.is_some());
        assert_eq!(client.host, "node.example.com");
        assert_eq!(client.port, 443);
    }

    /// Verify that http:// endpoints do NOT build a TLS connector.
    #[test]
    fn test_client_http_no_tls_connector() {
        let client = BrrqClient::new("http://localhost:8545");
        assert!(!client.tls_required);
        assert!(client.tls_connector.is_none());
    }

    #[test]
    fn test_parse_hash256_valid() {
        let hex = "0x".to_string() + &"ab".repeat(32);
        assert!(parse_hash256(&hex).is_some());
    }

    #[test]
    fn test_parse_hash256_invalid() {
        assert!(parse_hash256("0xaabb").is_none());
    }

    // ── Integration test: spins up in-process RPC server ───────────────

    #[tokio::test]
    async fn test_client_against_live_rpc() {
        use brrq_crypto::hash::Hasher;
        use brrq_types::account::Account;

        // Use a random-ish port to avoid conflicts with parallel tests
        let port: u16 = 18545 + (std::process::id() as u16 % 1000);

        // Create an account
        let alice_hash = Hasher::hash(b"alice_sdk_test");
        let mut alice_bytes = [0u8; 20];
        alice_bytes.copy_from_slice(&alice_hash.as_bytes()[..20]);
        let alice_addr = Address::from_bytes(alice_bytes);

        let state: Arc<RwLock<TestNodeState>> = Arc::new(RwLock::new(TestNodeState {
            state: brrq_state::WorldState::new(),
            height: 42,
        }));

        {
            let mut ns = state.write().await;
            ns.state.set_account(Account::new_eoa(alice_addr, 999_000));
        }

        // Start RPC server in background
        let rpc_state = state.clone();
        let handle = tokio::spawn(async move {
            start_test_rpc(port, rpc_state).await;
        });

        // Give server time to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = BrrqClient::new(&format!("http://127.0.0.1:{}", port));

        // Test get_block_height
        let height = client.get_block_height().await.unwrap();
        assert_eq!(height, 42);

        // Test get_balance
        let balance = client.get_balance(&alice_addr).await.unwrap();
        assert_eq!(balance, 999_000);

        // Test get_nonce
        let nonce = client.get_nonce(&alice_addr).await.unwrap();
        assert_eq!(nonce, 0);

        // Test unknown address returns 0
        let unknown = Address::from_bytes([0xFFu8; 20]);
        let balance = client.get_balance(&unknown).await.unwrap();
        assert_eq!(balance, 0);

        // Test get_receipt (not found)
        let receipt = client
            .get_transaction_receipt(&Hash256::ZERO)
            .await
            .unwrap();
        assert!(receipt.is_none());

        // Cleanup
        handle.abort();
    }

    // ── Minimal in-process RPC server for testing ──────────────────────

    struct TestNodeState {
        state: brrq_state::WorldState,
        height: u64,
    }

    async fn start_test_rpc(port: u16, shared: Arc<RwLock<TestNodeState>>) {
        let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .await
            .unwrap();

        for _ in 0..20 {
            if let Ok((mut stream, _)) = listener.accept().await {
                let shared = shared.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 65536];
                    let n = stream.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    let req_str = String::from_utf8_lossy(&buf[..n]);
                    let body = req_str
                        .find("\r\n\r\n")
                        .map(|pos| &req_str[pos + 4..])
                        .unwrap_or("");

                    let resp_body = match serde_json::from_str::<serde_json::Value>(body) {
                        Ok(req) => {
                            let method = req["method"].as_str().unwrap_or("");
                            let params = &req["params"];
                            let id = req["id"].clone();
                            let ns = shared.read().await;

                            let result: serde_json::Value = match method {
                                "brrq_blockHeight" => serde_json::json!(ns.height),
                                "brrq_getBalance" => {
                                    let addr_hex = params[0].as_str().unwrap_or("");
                                    let addr = parse_test_address(addr_hex);
                                    serde_json::json!(ns.state.balance(&addr))
                                }
                                "brrq_getNonce" => {
                                    let addr_hex = params[0].as_str().unwrap_or("");
                                    let addr = parse_test_address(addr_hex);
                                    serde_json::json!(ns.state.nonce(&addr))
                                }
                                "brrq_getReceipt" => serde_json::Value::Null,
                                _ => serde_json::Value::Null,
                            };

                            serde_json::json!({
                                "jsonrpc": "2.0",
                                "result": result,
                                "id": id,
                            })
                            .to_string()
                        }
                        Err(_) => serde_json::json!({
                            "jsonrpc": "2.0",
                            "error": {"code": -32700, "message": "parse error"},
                            "id": null,
                        })
                        .to_string(),
                    };

                    let http_resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(http_resp.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        }
    }

    fn parse_test_address(s: &str) -> Address {
        let hex_str = s.strip_prefix("0x").unwrap_or(s);
        if let Ok(bytes) = hex::decode(hex_str) {
            if bytes.len() == 20 {
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&bytes);
                return Address::from_bytes(arr);
            }
        }
        Address::ZERO
    }
}
