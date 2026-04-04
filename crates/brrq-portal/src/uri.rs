//! Brrq Universal Payment URI Scheme (BPS-1).
//!
//! Standard format for QR codes, deep links, and POS integration.
//!
//! ```text
//! brrq://pay?v=1&chain=mainnet&amount=50000&cond=0xABC...&timeout=200000&callback=https://...
//! ```
//!
//! ## Parameters
//!
//! | Param      | Required | Description                                       |
//! |------------|----------|---------------------------------------------------|
//! | `v`        | yes      | Protocol version (currently `1`)                  |
//! | `chain`    | yes      | `mainnet` or `testnet`                            |
//! | `amount`   | yes      | Amount in satoshis                                |
//! | `cond`     | yes      | Merchant condition hash (`0x`-prefixed hex)       |
//! | `timeout`  | yes      | L2 block height deadline                          |
//! | `callback` | no       | Webhook URL for instant Portal Key delivery       |
//! | `memo`     | no       | Human-readable payment memo (URL-encoded)         |
//! | `asset`    | no       | Asset identifier (default: `BTC`)                 |

use brrq_crypto::hash::Hash256;

/// Supported chain networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrrqChain {
    Mainnet,
    Testnet,
}

impl BrrqChain {
    pub fn as_str(&self) -> &'static str {
        match self {
            BrrqChain::Mainnet => "mainnet",
            BrrqChain::Testnet => "testnet",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "mainnet" => Some(BrrqChain::Mainnet),
            "testnet" => Some(BrrqChain::Testnet),
            _ => None,
        }
    }
}

/// Current protocol version for the URI scheme.
pub const URI_VERSION: u32 = 1;

/// Parsed Brrq payment URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrrqPaymentUri {
    /// Protocol version.
    pub version: u32,
    /// Target chain.
    pub chain: BrrqChain,
    /// Payment amount in satoshis.
    pub amount: u64,
    /// Merchant condition hash: H(merchant_secret).
    pub condition_hash: Hash256,
    /// L2 block height deadline for settlement.
    pub timeout: u64,
    /// Optional webhook URL for Portal Key delivery.
    pub callback: Option<String>,
    /// Optional human-readable memo.
    pub memo: Option<String>,
    /// Asset identifier (default: "BTC").
    pub asset: String,
}

/// Errors from URI parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    /// URI doesn't start with `brrq://pay?`
    InvalidScheme,
    /// Required parameter missing.
    MissingParam(&'static str),
    /// Parameter has invalid value.
    InvalidParam { name: &'static str, reason: String },
    /// Unsupported version.
    UnsupportedVersion(u32),
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UriError::InvalidScheme => write!(f, "URI must start with brrq://pay?"),
            UriError::MissingParam(p) => write!(f, "missing required parameter: {p}"),
            UriError::InvalidParam { name, reason } => {
                write!(f, "invalid parameter '{name}': {reason}")
            }
            UriError::UnsupportedVersion(v) => {
                write!(f, "unsupported URI version: {v} (expected {URI_VERSION})")
            }
        }
    }
}

impl std::error::Error for UriError {}

impl BrrqPaymentUri {
    /// Generate a URI string from this payment request.
    pub fn to_uri_string(&self) -> String {
        let mut uri = format!(
            "brrq://pay?v={}&chain={}&amount={}&cond=0x{}&timeout={}",
            self.version,
            self.chain.as_str(),
            self.amount,
            hex::encode(self.condition_hash.as_bytes()),
            self.timeout,
        );
        if self.asset != "BTC" {
            uri.push_str(&format!("&asset={}", self.asset));
        }
        if let Some(ref cb) = self.callback {
            uri.push_str(&format!(
                "&callback={}",
                url_encode(cb)
            ));
        }
        if let Some(ref memo) = self.memo {
            uri.push_str(&format!("&memo={}", url_encode(memo)));
        }
        uri
    }

    /// Parse a URI string into a payment request.
    pub fn parse(uri: &str) -> Result<Self, UriError> {
        // Validate scheme
        let query = uri
            .strip_prefix("brrq://pay?")
            .ok_or(UriError::InvalidScheme)?;

        // Parse query parameters
        let params: Vec<(&str, &str)> = query
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                Some((parts.next()?, parts.next()?))
            })
            .collect();

        let get = |name: &'static str| -> Result<&str, UriError> {
            params
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| *v)
                .ok_or(UriError::MissingParam(name))
        };

        let get_opt = |name: &str| -> Option<&str> {
            params.iter().find(|(k, _)| *k == name).map(|(_, v)| *v)
        };

        // Version (required)
        let version: u32 = get("v")?
            .parse()
            .map_err(|_| UriError::InvalidParam {
                name: "v",
                reason: "not a valid integer".into(),
            })?;
        if version != URI_VERSION {
            return Err(UriError::UnsupportedVersion(version));
        }

        // Chain (required)
        let chain_str = get("chain")?;
        let chain = BrrqChain::from_str(chain_str).ok_or(UriError::InvalidParam {
            name: "chain",
            reason: format!("expected 'mainnet' or 'testnet', got '{chain_str}'"),
        })?;

        // Amount (required, non-zero)
        let amount: u64 = get("amount")?
            .parse()
            .map_err(|_| UriError::InvalidParam {
                name: "amount",
                reason: "not a valid u64".into(),
            })?;
        if amount == 0 {
            return Err(UriError::InvalidParam {
                name: "amount",
                reason: "amount must be > 0".into(),
            });
        }

        // Condition hash (required, 0x-prefixed 64 hex chars)
        let cond_hex = get("cond")?;
        let cond_clean = cond_hex.strip_prefix("0x").unwrap_or(cond_hex);
        if cond_clean.len() != 64 {
            return Err(UriError::InvalidParam {
                name: "cond",
                reason: format!("expected 64 hex chars, got {}", cond_clean.len()),
            });
        }
        let cond_bytes = hex::decode(cond_clean).map_err(|_| UriError::InvalidParam {
            name: "cond",
            reason: "invalid hex".into(),
        })?;
        let mut cond_arr = [0u8; 32];
        cond_arr.copy_from_slice(&cond_bytes);
        let condition_hash = Hash256::from_bytes(cond_arr);

        // Timeout (required, must be reasonable)
        let timeout: u64 = get("timeout")?
            .parse()
            .map_err(|_| UriError::InvalidParam {
                name: "timeout",
                reason: "not a valid u64".into(),
            })?;
        if timeout == 0 {
            return Err(UriError::InvalidParam {
                name: "timeout",
                reason: "timeout must be > 0".into(),
            });
        }

        // Asset (optional, default BTC)
        let asset = get_opt("asset")
            .unwrap_or("BTC")
            .to_string();

        // Callback (optional, URL-decoded)
        // Validate callback scheme to prevent javascript: XSS and file: SSRF
        let callback = get_opt("callback").map(|s| url_decode(s)).and_then(|cb| {
            if cb.starts_with("https://") || cb.starts_with("http://") {
                Some(cb)
            } else {
                None // Reject non-HTTP(S) callbacks silently
            }
        });

        // Memo (optional, URL-decoded)
        let memo = get_opt("memo").map(|s| url_decode(s));

        Ok(Self {
            version,
            chain,
            amount,
            condition_hash,
            timeout,
            callback,
            memo,
            asset,
        })
    }
}

/// Minimal percent-encoding for URI query values.
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

/// Minimal percent-decoding for URI query values.
fn url_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or(""),
                16,
            ) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;

    fn sample_uri() -> BrrqPaymentUri {
        BrrqPaymentUri {
            version: 1,
            chain: BrrqChain::Testnet,
            amount: 500_000,
            condition_hash: Hasher::hash(b"merchant_secret_coffee"),
            timeout: 200_000,
            callback: Some("https://shop.example.com/webhook".into()),
            memo: Some("Coffee order #42".into()),
            asset: "BTC".into(),
        }
    }

    #[test]
    fn test_roundtrip() {
        let original = sample_uri();
        let uri_str = original.to_uri_string();
        assert!(uri_str.starts_with("brrq://pay?"));
        let parsed = BrrqPaymentUri::parse(&uri_str).unwrap();
        assert_eq!(parsed.version, original.version);
        assert_eq!(parsed.chain, original.chain);
        assert_eq!(parsed.amount, original.amount);
        assert_eq!(parsed.condition_hash, original.condition_hash);
        assert_eq!(parsed.timeout, original.timeout);
        assert_eq!(parsed.asset, original.asset);
        assert_eq!(parsed.callback, original.callback);
        assert_eq!(parsed.memo, original.memo);
    }

    #[test]
    fn test_minimal_uri() {
        let cond = Hasher::hash(b"secret");
        let uri = format!(
            "brrq://pay?v=1&chain=mainnet&amount=1000&cond=0x{}&timeout=100000",
            hex::encode(cond.as_bytes())
        );
        let parsed = BrrqPaymentUri::parse(&uri).unwrap();
        assert_eq!(parsed.amount, 1000);
        assert_eq!(parsed.chain, BrrqChain::Mainnet);
        assert_eq!(parsed.condition_hash, cond);
        assert!(parsed.callback.is_none());
        assert!(parsed.memo.is_none());
        assert_eq!(parsed.asset, "BTC");
    }

    #[test]
    fn test_invalid_scheme() {
        assert_eq!(
            BrrqPaymentUri::parse("https://pay?v=1").unwrap_err(),
            UriError::InvalidScheme
        );
    }

    #[test]
    fn test_missing_amount() {
        let cond = Hasher::hash(b"s");
        let uri = format!(
            "brrq://pay?v=1&chain=testnet&cond=0x{}&timeout=100",
            hex::encode(cond.as_bytes())
        );
        assert_eq!(
            BrrqPaymentUri::parse(&uri).unwrap_err(),
            UriError::MissingParam("amount")
        );
    }

    #[test]
    fn test_zero_amount_rejected() {
        let cond = Hasher::hash(b"s");
        let uri = format!(
            "brrq://pay?v=1&chain=testnet&amount=0&cond=0x{}&timeout=100",
            hex::encode(cond.as_bytes())
        );
        match BrrqPaymentUri::parse(&uri) {
            Err(UriError::InvalidParam { name: "amount", .. }) => {}
            other => panic!("expected InvalidParam(amount), got {:?}", other),
        }
    }

    #[test]
    fn test_unsupported_version() {
        let cond = Hasher::hash(b"s");
        let uri = format!(
            "brrq://pay?v=99&chain=testnet&amount=1000&cond=0x{}&timeout=100",
            hex::encode(cond.as_bytes())
        );
        assert_eq!(
            BrrqPaymentUri::parse(&uri).unwrap_err(),
            UriError::UnsupportedVersion(99)
        );
    }

    #[test]
    fn test_invalid_chain() {
        let cond = Hasher::hash(b"s");
        let uri = format!(
            "brrq://pay?v=1&chain=devnet&amount=1000&cond=0x{}&timeout=100",
            hex::encode(cond.as_bytes())
        );
        match BrrqPaymentUri::parse(&uri) {
            Err(UriError::InvalidParam { name: "chain", .. }) => {}
            other => panic!("expected InvalidParam(chain), got {:?}", other),
        }
    }

    #[test]
    fn test_short_cond_hash_rejected() {
        let uri = "brrq://pay?v=1&chain=testnet&amount=1000&cond=0xABCD&timeout=100";
        match BrrqPaymentUri::parse(uri) {
            Err(UriError::InvalidParam { name: "cond", .. }) => {}
            other => panic!("expected InvalidParam(cond), got {:?}", other),
        }
    }

    #[test]
    fn test_url_encoding_callback() {
        let uri_obj = BrrqPaymentUri {
            callback: Some("https://api.shop.com/hook?id=42&token=abc".into()),
            ..sample_uri()
        };
        let uri_str = uri_obj.to_uri_string();
        // URL-encoded & should not break parsing
        let parsed = BrrqPaymentUri::parse(&uri_str).unwrap();
        assert_eq!(parsed.callback, uri_obj.callback);
    }

    #[test]
    fn test_custom_asset() {
        let cond = Hasher::hash(b"s");
        let uri = format!(
            "brrq://pay?v=1&chain=mainnet&amount=5000&cond=0x{}&timeout=100&asset=USDC",
            hex::encode(cond.as_bytes())
        );
        let parsed = BrrqPaymentUri::parse(&uri).unwrap();
        assert_eq!(parsed.asset, "USDC");
    }
}
