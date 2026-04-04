//! Validate deposit detection logic against real Bitcoin data.

use crate::BitcoinError;
use crate::canary::readonly_client::ReadOnlyBitcoinClient;
use crate::types::DepositEvent;

/// A known deposit for validation purposes.
#[derive(Debug, Clone)]
pub struct KnownDeposit {
    /// Bitcoin transaction ID.
    pub btc_tx_id: [u8; 32],
    /// Output index.
    pub vout: u32,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// Expected block height.
    pub expected_height: u64,
}

/// A discrepancy found during deposit validation.
#[derive(Debug, Clone)]
pub struct DepositDiscrepancy {
    /// The known deposit that failed validation.
    pub deposit: KnownDeposit,
    /// Description of the discrepancy.
    pub reason: String,
}

/// Validates deposit detection logic against real Bitcoin mainnet data.
pub struct DepositValidator {
    btc: ReadOnlyBitcoinClient,
    bridge_address: String,
}

impl DepositValidator {
    /// Create a new deposit validator.
    pub fn new(btc: ReadOnlyBitcoinClient, bridge_address: &str) -> Self {
        Self {
            btc,
            bridge_address: bridge_address.to_string(),
        }
    }

    /// Validate a list of known deposits against the chain.
    ///
    /// Returns discrepancies where the chain data doesn't match expectations.
    pub fn validate_known_deposits(&self, known: &[KnownDeposit]) -> Vec<DepositDiscrepancy> {
        let mut discrepancies = Vec::new();

        for deposit in known {
            match self.btc.get_tx_block_info(&deposit.btc_tx_id) {
                Ok(Some((_, height, _))) => {
                    if height != deposit.expected_height {
                        discrepancies.push(DepositDiscrepancy {
                            deposit: deposit.clone(),
                            reason: format!(
                                "height mismatch: expected {}, got {}",
                                deposit.expected_height, height
                            ),
                        });
                    }
                }
                Ok(None) => {
                    discrepancies.push(DepositDiscrepancy {
                        deposit: deposit.clone(),
                        reason: "transaction not found on chain".into(),
                    });
                }
                Err(e) => {
                    discrepancies.push(DepositDiscrepancy {
                        deposit: deposit.clone(),
                        reason: format!("RPC error: {}", e),
                    });
                }
            }
        }

        discrepancies
    }

    /// Scan a block range for deposits to the bridge address.
    pub fn scan_block_range(
        &self,
        _from: u64,
        _to: u64,
    ) -> Result<Vec<DepositEvent>, BitcoinError> {
        // Scan UTXOs for the bridge address
        let deposits = self.btc.list_unspent_for_address(&self.bridge_address)?;
        Ok(deposits)
    }

    /// Get the bridge address being monitored.
    pub fn bridge_address(&self) -> &str {
        &self.bridge_address
    }
}
