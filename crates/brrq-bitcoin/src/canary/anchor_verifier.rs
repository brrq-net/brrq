//! Verify anchors posted to Bitcoin mainnet.

use crate::BitcoinError;
use crate::canary::readonly_client::ReadOnlyBitcoinClient;
use crate::types::AnchorData;

/// Result of verifying an anchor.
#[derive(Debug, Clone)]
pub struct AnchorVerifyResult {
    /// L2 height of the anchor.
    pub l2_height: u64,
    /// Whether the anchor was found on chain.
    pub found: bool,
    /// L1 block height where the anchor was mined.
    pub l1_height: Option<u64>,
    /// Number of confirmations.
    pub confirmations: Option<u32>,
    /// The anchor data (if found and parsed).
    pub anchor_data: Option<AnchorData>,
}

/// Verifies anchors posted to Bitcoin mainnet.
pub struct AnchorVerifier {
    btc: ReadOnlyBitcoinClient,
}

impl AnchorVerifier {
    /// Create a new anchor verifier.
    pub fn new(btc: ReadOnlyBitcoinClient) -> Self {
        Self { btc }
    }

    /// Verify that an anchor transaction exists on chain.
    pub fn verify_anchor_tx(
        &self,
        anchor_tx_id: &[u8; 32],
        expected_l2_height: u64,
    ) -> Result<AnchorVerifyResult, BitcoinError> {
        match self.btc.get_tx_block_info(anchor_tx_id)? {
            Some((_, l1_height, confirmations)) => {
                Ok(AnchorVerifyResult {
                    l2_height: expected_l2_height,
                    found: true,
                    l1_height: Some(l1_height),
                    confirmations: Some(confirmations),
                    anchor_data: None, // Would need raw tx parsing for full validation
                })
            }
            None => Ok(AnchorVerifyResult {
                l2_height: expected_l2_height,
                found: false,
                l1_height: None,
                confirmations: None,
                anchor_data: None,
            }),
        }
    }

    /// Get the current chain tip for context.
    pub fn chain_tip(&self) -> Result<u64, BitcoinError> {
        self.btc.get_block_count()
    }

    /// Verify that the mainnet is reachable and we're on the right network.
    pub fn health_check(&self) -> Result<bool, BitcoinError> {
        let connected = self.btc.is_connected();
        if !connected {
            return Ok(false);
        }
        let network = self.btc.network();
        Ok(network == bitcoin::Network::Bitcoin)
    }
}
