//! Bridge-level rate limiter for deposit/withdrawal DoS protection.
//!
//! This supplements the HTTP-layer rate limiter (`brrq-api::middleware`)
//! with business-logic-level throttling keyed by L2 address and measured
//! in L2 blocks rather than wall-clock time.

use imbl::HashMap;
use serde::{Deserialize, Serialize};

use brrq_types::Address;

use crate::error::BridgeError;

/// Per-address request counter within a block window.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct WindowCounter {
    /// L2 block height when the current window started.
    window_start: u64,
    /// Number of requests in the current window.
    count: u32,
}

/// Bridge-level rate limiter.
///
/// Tracks per-address request counts within rolling block windows.
/// Each operation type (deposit, withdrawal) has independent limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeRateLimiter {
    deposit_counters: HashMap<Address, WindowCounter>,
    withdrawal_counters: HashMap<Address, WindowCounter>,
    /// Maximum deposit requests per address per window.
    pub max_deposits_per_window: u32,
    /// Maximum withdrawal requests per address per window.
    pub max_withdrawals_per_window: u32,
    /// Window size in L2 blocks.
    pub window_blocks: u64,
}

impl BridgeRateLimiter {
    /// Create a rate limiter with default thresholds.
    pub fn new() -> Self {
        Self {
            deposit_counters: HashMap::new(),
            withdrawal_counters: HashMap::new(),
            max_deposits_per_window: 10,
            max_withdrawals_per_window: 5,
            window_blocks: 100,
        }
    }

    /// Create a rate limiter with custom thresholds.
    pub fn with_limits(max_deposits: u32, max_withdrawals: u32, window_blocks: u64) -> Self {
        Self {
            deposit_counters: HashMap::new(),
            withdrawal_counters: HashMap::new(),
            max_deposits_per_window: max_deposits,
            max_withdrawals_per_window: max_withdrawals,
            window_blocks,
        }
    }

    /// Check if a deposit request from `addr` at `current_height` is allowed.
    ///
    /// Returns `Ok(())` if allowed, `Err(RateLimited)` if throttled.
    /// Increments the counter on success.
    pub fn check_deposit(
        &mut self,
        addr: &Address,
        current_height: u64,
    ) -> Result<(), BridgeError> {
        Self::check_and_increment(
            &mut self.deposit_counters,
            addr,
            current_height,
            self.max_deposits_per_window,
            self.window_blocks,
        )
    }

    /// Check if a withdrawal request from `addr` at `current_height` is allowed.
    pub fn check_withdrawal(
        &mut self,
        addr: &Address,
        current_height: u64,
    ) -> Result<(), BridgeError> {
        Self::check_and_increment(
            &mut self.withdrawal_counters,
            addr,
            current_height,
            self.max_withdrawals_per_window,
            self.window_blocks,
        )
    }

    fn check_and_increment(
        counters: &mut HashMap<Address, WindowCounter>,
        addr: &Address,
        current_height: u64,
        max_per_window: u32,
        window_blocks: u64,
    ) -> Result<(), BridgeError> {
        if let Some(counter) = counters.get(addr) {
            let window_expired =
                current_height.saturating_sub(counter.window_start) >= window_blocks;
            if window_expired {
                // Window expired — reset counter.
                counters.insert(
                    *addr,
                    WindowCounter {
                        window_start: current_height,
                        count: 1,
                    },
                );
                return Ok(());
            }
            if counter.count >= max_per_window {
                let remaining = window_blocks
                    .saturating_sub(current_height.saturating_sub(counter.window_start));
                return Err(BridgeError::RateLimited {
                    retry_after_blocks: remaining,
                });
            }
            // Saturating arithmetic to prevent counter overflow.
            counters.insert(
                *addr,
                WindowCounter {
                    window_start: counter.window_start,
                    count: counter.count.saturating_add(1),
                },
            );
        } else {
            // First request — start a new window.
            counters.insert(
                *addr,
                WindowCounter {
                    window_start: current_height,
                    count: 1,
                },
            );
        }
        Ok(())
    }

    /// Prune expired window entries to prevent unbounded growth.
    pub fn prune_expired(&mut self, current_height: u64) -> usize {
        let window = self.window_blocks;
        let before_d = self.deposit_counters.len();
        let before_w = self.withdrawal_counters.len();
        self.deposit_counters
            .retain(|_, c| current_height.saturating_sub(c.window_start) < window);
        self.withdrawal_counters
            .retain(|_, c| current_height.saturating_sub(c.window_start) < window);
        (before_d - self.deposit_counters.len()) + (before_w - self.withdrawal_counters.len())
    }
}

impl Default for BridgeRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address::from_bytes(bytes)
    }

    #[test]
    fn allows_requests_within_limit() {
        let mut rl = BridgeRateLimiter::with_limits(3, 2, 10);
        let a = addr(1);
        assert!(rl.check_deposit(&a, 100).is_ok());
        assert!(rl.check_deposit(&a, 100).is_ok());
        assert!(rl.check_deposit(&a, 100).is_ok());
        // 4th should fail
        assert!(rl.check_deposit(&a, 100).is_err());
    }

    #[test]
    fn resets_after_window() {
        let mut rl = BridgeRateLimiter::with_limits(2, 2, 10);
        let a = addr(1);
        assert!(rl.check_deposit(&a, 100).is_ok());
        assert!(rl.check_deposit(&a, 100).is_ok());
        assert!(rl.check_deposit(&a, 100).is_err());
        // After window expires (height 110), should work again
        assert!(rl.check_deposit(&a, 110).is_ok());
    }

    #[test]
    fn independent_addresses() {
        let mut rl = BridgeRateLimiter::with_limits(1, 1, 10);
        let a = addr(1);
        let b = addr(2);
        assert!(rl.check_deposit(&a, 100).is_ok());
        assert!(rl.check_deposit(&a, 100).is_err());
        // Different address should still be allowed
        assert!(rl.check_deposit(&b, 100).is_ok());
    }

    #[test]
    fn independent_operations() {
        let mut rl = BridgeRateLimiter::with_limits(1, 1, 10);
        let a = addr(1);
        assert!(rl.check_deposit(&a, 100).is_ok());
        assert!(rl.check_deposit(&a, 100).is_err());
        // Withdrawal limit is independent
        assert!(rl.check_withdrawal(&a, 100).is_ok());
    }

    #[test]
    fn error_includes_retry_after() {
        let mut rl = BridgeRateLimiter::with_limits(1, 1, 10);
        let a = addr(1);
        assert!(rl.check_deposit(&a, 100).is_ok());
        match rl.check_deposit(&a, 105) {
            Err(BridgeError::RateLimited { retry_after_blocks }) => {
                assert_eq!(retry_after_blocks, 5); // 10 - (105 - 100) = 5
            }
            other => panic!("expected RateLimited, got {:?}", other),
        }
    }

    #[test]
    fn prune_removes_expired() {
        let mut rl = BridgeRateLimiter::with_limits(10, 10, 10);
        let a = addr(1);
        let b = addr(2);
        rl.check_deposit(&a, 100).unwrap();
        rl.check_deposit(&b, 108).unwrap();
        let pruned = rl.prune_expired(115);
        // addr(1) started at 100, window=10, 115-100=15 >= 10 → expired
        // addr(2) started at 108, window=10, 115-108=7 < 10 → active
        assert_eq!(pruned, 1);
    }
}
