//! Safety guards for canary mode.

use crate::BitcoinError;

/// Environment variable that must be set for canary mode.
pub const CANARY_ENV_VAR: &str = "BRRQ_CANARY_MODE";

/// Expected value of the canary mode env var.
pub const CANARY_MODE_READONLY: &str = "readonly";

/// Safety guard that validates canary mode is properly configured.
///
/// Checks:
/// 1. `BRRQ_CANARY_MODE=readonly` environment variable is set.
/// 2. The connected network is Bitcoin mainnet.
/// 3. Rate limiting is respected.
pub struct CanarySafetyGuard {
    /// Whether the guard has been validated.
    validated: bool,
}

impl CanarySafetyGuard {
    /// Create and validate a new safety guard.
    ///
    /// Fails if `BRRQ_CANARY_MODE` is not set to `readonly`.
    pub fn new() -> Result<Self, BitcoinError> {
        let mode = std::env::var(CANARY_ENV_VAR).unwrap_or_default();
        if mode != CANARY_MODE_READONLY {
            return Err(BitcoinError::RpcCallFailed(format!(
                "canary safety: {}={} required, got '{}'",
                CANARY_ENV_VAR, CANARY_MODE_READONLY, mode
            )));
        }

        Ok(Self { validated: true })
    }

    /// Check if the guard is validated.
    pub fn is_validated(&self) -> bool {
        self.validated
    }

    /// Validate that the network is Bitcoin mainnet.
    pub fn assert_mainnet(network: bitcoin::Network) -> Result<(), BitcoinError> {
        if network != bitcoin::Network::Bitcoin {
            return Err(BitcoinError::RpcCallFailed(format!(
                "canary safety: expected Bitcoin mainnet, got {:?}",
                network
            )));
        }
        Ok(())
    }
}

/// Rate limiter for mainnet RPC calls (1 call/second).
pub struct RateLimiter {
    last_call: std::sync::Mutex<std::time::Instant>,
    pub min_interval: std::time::Duration,
}

impl RateLimiter {
    /// Create a new rate limiter with 1 call/second.
    pub fn new() -> Self {
        Self {
            last_call: std::sync::Mutex::new(std::time::Instant::now()),
            min_interval: std::time::Duration::from_secs(1),
        }
    }

    /// Create with custom interval.
    pub fn with_interval(interval: std::time::Duration) -> Self {
        Self {
            last_call: std::sync::Mutex::new(std::time::Instant::now()),
            min_interval: interval,
        }
    }

    /// Wait until the next call is allowed, then mark as called.
    pub fn wait_and_mark(&self) {
        let mut last = self.last_call.lock().unwrap();
        let elapsed = last.elapsed();
        if elapsed < self.min_interval {
            std::thread::sleep(self.min_interval - elapsed);
        }
        *last = std::time::Instant::now();
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_mainnet_rejects_testnet() {
        let result = CanarySafetyGuard::assert_mainnet(bitcoin::Network::Testnet);
        assert!(result.is_err());
    }

    #[test]
    fn assert_mainnet_rejects_regtest() {
        let result = CanarySafetyGuard::assert_mainnet(bitcoin::Network::Regtest);
        assert!(result.is_err());
    }

    #[test]
    fn assert_mainnet_accepts_bitcoin() {
        let result = CanarySafetyGuard::assert_mainnet(bitcoin::Network::Bitcoin);
        assert!(result.is_ok());
    }

    #[test]
    fn rate_limiter_creates() {
        let rl = RateLimiter::new();
        assert_eq!(rl.min_interval, std::time::Duration::from_secs(1));
    }

    #[test]
    fn rate_limiter_custom_interval() {
        let rl = RateLimiter::with_interval(std::time::Duration::from_millis(100));
        assert_eq!(rl.min_interval, std::time::Duration::from_millis(100));
    }
}
