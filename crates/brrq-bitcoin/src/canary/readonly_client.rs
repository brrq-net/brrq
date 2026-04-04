//! Read-only Bitcoin RPC client wrapper.
//!
//! Exposes only read methods from `BitcoinRpcClient`. Write methods
//! (broadcast, sign, send) are not available — there is no runtime
//! check because the methods simply don't exist on this type.

use crate::canary::safety::{CanarySafetyGuard, RateLimiter};
use crate::types::{DepositEvent, L1BlockInfo};
use crate::{BitcoinError, BitcoinRpcClient};

/// A read-only wrapper around `BitcoinRpcClient`.
///
/// Only exposes query methods — no transaction broadcast, signing, or
/// sending is possible through this type.
///
/// # Safety
///
/// - Type-level safety: write methods don't exist on this type.
/// - Runtime safety: requires `BRRQ_CANARY_MODE=readonly`.
/// - Network assertion: verifies mainnet on construction.
/// - Rate limiting: 1 RPC call per second.
pub struct ReadOnlyBitcoinClient {
    inner: BitcoinRpcClient,
    _guard: CanarySafetyGuard,
    rate_limiter: RateLimiter,
}

impl ReadOnlyBitcoinClient {
    /// Create a new read-only client.
    ///
    /// # Errors
    ///
    /// - If `BRRQ_CANARY_MODE=readonly` is not set.
    /// - If the connected network is not Bitcoin mainnet.
    /// - If the client cannot connect to the RPC endpoint.
    pub fn new(url: &str, user: &str, pass: &str) -> Result<Self, BitcoinError> {
        let guard = CanarySafetyGuard::new()?;
        let inner = BitcoinRpcClient::new(url, user, pass, "mainnet")?;

        // Verify mainnet
        let network = inner.network();
        CanarySafetyGuard::assert_mainnet(network)?;

        Ok(Self {
            inner,
            _guard: guard,
            rate_limiter: RateLimiter::new(),
        })
    }

    // ── Read-only methods ────────────────────────────────────────────

    /// Get the current block count.
    pub fn get_block_count(&self) -> Result<u64, BitcoinError> {
        self.rate_limiter.wait_and_mark();
        self.inner.get_block_count()
    }

    /// Get the block hash at a given height.
    pub fn get_block_hash(&self, height: u64) -> Result<[u8; 32], BitcoinError> {
        self.rate_limiter.wait_and_mark();
        self.inner.get_block_hash(height)
    }

    /// Get block info at a given height.
    pub fn get_block_info(&self, height: u64) -> Result<L1BlockInfo, BitcoinError> {
        self.rate_limiter.wait_and_mark();
        self.inner.get_block_info(height)
    }

    /// List unspent outputs for an address.
    pub fn list_unspent_for_address(
        &self,
        address: &str,
    ) -> Result<Vec<DepositEvent>, BitcoinError> {
        self.rate_limiter.wait_and_mark();
        self.inner.list_unspent_for_address(address)
    }

    /// Get a transaction inclusion proof.
    pub fn get_tx_out_proof(&self, txid: &[u8; 32]) -> Result<Vec<u8>, BitcoinError> {
        self.rate_limiter.wait_and_mark();
        self.inner.get_tx_out_proof(txid)
    }

    /// Get transaction block info (block hash, height, confirmations).
    pub fn get_tx_block_info(
        &self,
        txid: &[u8; 32],
    ) -> Result<Option<([u8; 32], u64, u32)>, BitcoinError> {
        self.rate_limiter.wait_and_mark();
        self.inner.get_tx_block_info(txid)
    }

    /// Returns true if a client object exists (does NOT verify actual connectivity).
    pub fn has_client(&self) -> bool {
        self.inner.has_client()
    }

    /// Performs a lightweight RPC call to verify actual connectivity to bitcoind.
    pub fn is_connected(&self) -> bool {
        self.inner.is_connected()
    }

    /// Get the network type (should always be Bitcoin mainnet).
    pub fn network(&self) -> bitcoin::Network {
        self.inner.network()
    }

    // NOTE: No broadcast_raw_tx, create_op_return_tx, or send_signed_tx methods.
    // This is intentional — canary mode is read-only by design.
}
