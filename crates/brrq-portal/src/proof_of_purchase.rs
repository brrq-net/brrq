//! Brrq Proof of Purchase (BPoP) — cryptographic payment receipts.
//!
//! An unforgeable, non-repudiable receipt that proves:
//! 1. The merchant requested a specific payment (URI)
//! 2. The user's TEE authorized it (signature)
//! 3. The merchant received the funds (revealed secret matches condition)
//!
//! ## Structure
//!
//! ```text
//! BPoP = {
//!     payment_request:  BrrqPaymentUri,       // merchant's original request
//!     portal_signature: SchnorrSignature,      // user's TEE-backed approval
//!     owner_pubkey:     SchnorrPublicKey,       // user's identity
//!     merchant_secret:  Vec<u8>,               // revealed preimage (proves merchant got paid)
//!     settled_at_block: Option<u64>,           // L2 block where settlement confirmed
//!     timestamp:        u64,                   // Unix timestamp of payment
//! }
//! ```
//!
//! ## Verification
//!
//! Anyone can verify a BPoP by checking:
//! 1. `SHA-256(merchant_secret) == payment_request.condition_hash`
//! 2. Schnorr signature is valid over the payment payload
//! 3. All fields are internally consistent

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::{SchnorrPublicKey, SchnorrSignature};
use serde::{Deserialize, Serialize};

use crate::uri::BrrqPaymentUri;

/// Domain tag for BPoP payload hashing.
const BPOP_DOMAIN: &[u8] = b"BRRQ_PROOF_OF_PURCHASE_V1";

/// A cryptographic proof of purchase — unforgeable payment receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfPurchase {
    /// The original payment request URI from the merchant.
    pub payment_uri: String,
    /// Amount paid in satoshis (must match URI amount).
    pub amount: u64,
    /// Merchant's condition hash from the URI.
    pub condition_hash: Hash256,
    /// User's TEE-backed Schnorr signature over the payment payload.
    pub portal_signature: SchnorrSignature,
    /// User's public key (proves identity).
    pub owner_pubkey: SchnorrPublicKey,
    /// The merchant's revealed secret (preimage of condition_hash).
    /// This proves the merchant received and acknowledged the payment.
    pub merchant_secret: Vec<u8>,
    /// L2 block height where settlement was confirmed (if known).
    pub settled_at_block: Option<u64>,
    /// Unix timestamp when the payment was made.
    pub timestamp: u64,
    /// CONTEXT-BIND: Chain identifier (e.g., "mainnet", "testnet").
    /// Signed in payload to prevent cross-chain replay.
    pub chain: String,
    /// CONTEXT-BIND: Asset identifier (e.g., "BTC").
    /// Signed in payload to prevent cross-asset replay.
    pub asset: String,
}

/// Errors from BPoP verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BpopError {
    /// merchant_secret doesn't hash to condition_hash.
    SecretMismatch,
    /// Schnorr signature is invalid.
    InvalidSignature,
    /// Amount mismatch between receipt and URI.
    AmountMismatch { receipt: u64, uri: u64 },
    /// Condition hash mismatch between receipt and URI.
    ConditionMismatch,
    /// Payment URI failed to parse.
    InvalidUri(String),
    /// Timestamp is zero (clearly invalid).
    InvalidTimestamp,
}

impl std::fmt::Display for BpopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BpopError::SecretMismatch => {
                write!(f, "merchant_secret does not hash to condition_hash")
            }
            BpopError::InvalidSignature => write!(f, "portal signature verification failed"),
            BpopError::AmountMismatch { receipt, uri } => {
                write!(f, "amount mismatch: receipt={receipt}, uri={uri}")
            }
            BpopError::ConditionMismatch => {
                write!(f, "condition_hash mismatch between receipt and URI")
            }
            BpopError::InvalidUri(e) => write!(f, "payment URI parse error: {e}"),
            BpopError::InvalidTimestamp => write!(f, "timestamp must be > 0"),
        }
    }
}

impl std::error::Error for BpopError {}

/// Compute the BPoP payload that the user's TEE signs.
///
/// Includes chain + asset to prevent cross-asset/cross-chain
/// replay attacks where a valid BPoP for a cheap asset is re-presented as
/// proof of payment for an expensive asset.
///
/// ```text
/// payload = SHA-256(BRRQ_PROOF_OF_PURCHASE_V1 || condition_hash || amount || timestamp || chain || asset)
/// ```
pub fn compute_bpop_payload(
    condition_hash: &Hash256,
    amount: u64,
    timestamp: u64,
    chain: &str,
    asset: &str,
) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(BPOP_DOMAIN);
    hasher.update(condition_hash.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(&timestamp.to_le_bytes());
    // CONTEXT-BIND: chain and asset prevent cross-context replay
    // Length-prefix variable-length fields to prevent concatenation ambiguity
    // ("mainnet" + "BTC" must hash differently from "mainnetB" + "TC")
    hasher.update(&(chain.len() as u32).to_le_bytes());
    hasher.update(chain.as_bytes());
    hasher.update(&(asset.len() as u32).to_le_bytes());
    hasher.update(asset.as_bytes());
    hasher.finalize()
}

impl ProofOfPurchase {
    /// Create a new BPoP from payment components.
    ///
    /// Call this in the wallet after the merchant reveals their secret.
    pub fn new(
        payment_uri: String,
        amount: u64,
        condition_hash: Hash256,
        portal_signature: SchnorrSignature,
        owner_pubkey: SchnorrPublicKey,
        merchant_secret: Vec<u8>,
        settled_at_block: Option<u64>,
        timestamp: u64,
        chain: String,
        asset: String,
    ) -> Self {
        Self {
            payment_uri,
            amount,
            condition_hash,
            portal_signature,
            owner_pubkey,
            merchant_secret,
            settled_at_block,
            timestamp,
            chain,
            asset,
        }
    }

    /// Verify the proof of purchase is valid and internally consistent.
    ///
    /// Checks:
    /// 1. URI parses and matches receipt fields
    /// 2. `SHA-256(merchant_secret) == condition_hash`
    /// 3. Schnorr signature is valid over the BPoP payload
    pub fn verify(&self) -> Result<(), BpopError> {
        // 1. Timestamp must be valid
        if self.timestamp == 0 {
            return Err(BpopError::InvalidTimestamp);
        }

        // 2. Parse URI and verify consistency
        let uri = BrrqPaymentUri::parse(&self.payment_uri)
            .map_err(|e| BpopError::InvalidUri(e.to_string()))?;

        if uri.amount != self.amount {
            return Err(BpopError::AmountMismatch {
                receipt: self.amount,
                uri: uri.amount,
            });
        }

        if uri.condition_hash != self.condition_hash {
            return Err(BpopError::ConditionMismatch);
        }

        // CONTEXT-BIND: Verify chain and asset match URI
        if uri.chain.as_str() != self.chain {
            return Err(BpopError::InvalidUri(format!(
                "chain mismatch: receipt='{}', uri='{}'", self.chain, uri.chain.as_str()
            )));
        }
        if uri.asset != self.asset {
            return Err(BpopError::InvalidUri(format!(
                "asset mismatch: receipt='{}', uri='{}'", self.asset, uri.asset
            )));
        }

        // 3. Verify merchant secret → condition hash
        let computed_hash = Hasher::hash(&self.merchant_secret);
        if computed_hash != self.condition_hash {
            return Err(BpopError::SecretMismatch);
        }

        // 4. Verify Schnorr signature (CONTEXT-BIND: includes chain + asset)
        let payload = compute_bpop_payload(
            &self.condition_hash,
            self.amount,
            self.timestamp,
            &self.chain,
            &self.asset,
        );
        brrq_crypto::schnorr::verify(&self.owner_pubkey, &payload, &self.portal_signature)
            .map_err(|_| BpopError::InvalidSignature)?;

        Ok(())
    }

    /// Serialize the BPoP to JSON for storage or transfer.
    pub fn to_json(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| e.to_string())
    }

    /// Deserialize a BPoP from JSON.
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| e.to_string())
    }

    /// Human-readable summary for display in wallet UI.
    pub fn summary(&self) -> String {
        format!(
            "Payment of {} sats | Verified: {} | Block: {}",
            self.amount,
            self.verify().is_ok(),
            self.settled_at_block
                .map(|b| b.to_string())
                .unwrap_or_else(|| "pending".into()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::schnorr::SchnorrKeyPair;
    use crate::uri::{BrrqChain, BrrqPaymentUri};

    fn make_valid_bpop() -> ProofOfPurchase {
        let user_kp = SchnorrKeyPair::generate();
        let merchant_secret = b"coffee_order_42_secret_preimage".to_vec();
        let condition_hash = Hasher::hash(&merchant_secret);
        let amount = 500_000u64;
        let timestamp = 1700000000u64;

        let uri = BrrqPaymentUri {
            version: 1,
            chain: BrrqChain::Mainnet,
            amount,
            condition_hash,
            timeout: 200_000,
            callback: None,
            memo: Some("Coffee order #42".into()),
            asset: "BTC".into(),
        };
        let uri_str = uri.to_uri_string();

        let chain = "mainnet".to_string();
        let asset = "BTC".to_string();
        let payload = compute_bpop_payload(&condition_hash, amount, timestamp, &chain, &asset);
        let sig = user_kp.sign(&payload).unwrap();

        ProofOfPurchase::new(
            uri_str,
            amount,
            condition_hash,
            sig,
            *user_kp.public_key(),
            merchant_secret,
            Some(150_000),
            timestamp,
            chain,
            asset,
        )
    }

    #[test]
    fn test_valid_bpop_verifies() {
        let bpop = make_valid_bpop();
        bpop.verify().unwrap();
    }

    #[test]
    fn test_bpop_wrong_secret_fails() {
        let mut bpop = make_valid_bpop();
        bpop.merchant_secret = b"wrong_secret".to_vec();
        assert_eq!(bpop.verify().unwrap_err(), BpopError::SecretMismatch);
    }

    #[test]
    fn test_bpop_tampered_amount_fails() {
        let mut bpop = make_valid_bpop();
        bpop.amount = 999_999; // tamper
        // URI still says 500_000 → mismatch
        assert!(matches!(
            bpop.verify().unwrap_err(),
            BpopError::AmountMismatch { .. }
        ));
    }

    #[test]
    fn test_bpop_tampered_signature_fails() {
        let mut bpop = make_valid_bpop();
        // Corrupt one byte of signature
        let mut sig_bytes = bpop.portal_signature.as_bytes().to_vec();
        sig_bytes[0] ^= 0xFF;
        bpop.portal_signature =
            SchnorrSignature::from_bytes(sig_bytes.try_into().unwrap());
        assert_eq!(bpop.verify().unwrap_err(), BpopError::InvalidSignature);
    }

    #[test]
    fn test_bpop_zero_timestamp_fails() {
        let mut bpop = make_valid_bpop();
        bpop.timestamp = 0;
        assert_eq!(bpop.verify().unwrap_err(), BpopError::InvalidTimestamp);
    }

    #[test]
    fn test_bpop_json_roundtrip() {
        let bpop = make_valid_bpop();
        let json = bpop.to_json().unwrap();
        let restored = ProofOfPurchase::from_json(&json).unwrap();
        restored.verify().unwrap();
        assert_eq!(restored.amount, bpop.amount);
        assert_eq!(restored.condition_hash, bpop.condition_hash);
        assert_eq!(restored.merchant_secret, bpop.merchant_secret);
    }

    #[test]
    fn test_bpop_summary() {
        let bpop = make_valid_bpop();
        let summary = bpop.summary();
        assert!(summary.contains("500000 sats"));
        assert!(summary.contains("Verified: true"));
        assert!(summary.contains("150000"));
    }

    #[test]
    fn test_bpop_different_user_signature_fails() {
        let mut bpop = make_valid_bpop();
        // Sign with a different key
        let other_kp = SchnorrKeyPair::generate();
        let payload = compute_bpop_payload(&bpop.condition_hash, bpop.amount, bpop.timestamp, &bpop.chain, &bpop.asset);
        bpop.portal_signature = other_kp.sign(&payload).unwrap();
        // owner_pubkey still points to original — sig won't match
        assert_eq!(bpop.verify().unwrap_err(), BpopError::InvalidSignature);
    }
}
