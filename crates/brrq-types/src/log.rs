//! Contract event logs.
//!
//! Structured event emission from smart contracts, similar to Ethereum events.
//!
//! ## Structure
//!
//! Each log has:
//! - **address**: The contract that emitted the event
//! - **topics**: Up to 4 indexed 32-byte values (for filtering)
//! - **data**: Non-indexed payload (up to 1 KB)
//!
//! ## Filtering
//!
//! `LogFilter` supports filtering by:
//! - Block range (`from_block`, `to_block`)
//! - Emitting contract address
//! - Topic values (positional matching)

use brrq_crypto::hash::Hash256;
use serde::{Deserialize, Serialize};

use crate::address::Address;

/// Maximum number of indexed topics per log entry.
pub const MAX_LOG_TOPICS: usize = 4;

/// Maximum size of non-indexed data in bytes.
pub const MAX_LOG_DATA_SIZE: usize = 1024;

/// Maximum number of logs a single transaction can emit.
pub const MAX_LOGS_PER_TX: usize = 256;

/// A contract event log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// The contract address that emitted this log.
    pub address: Address,
    /// Indexed topic values (up to 4).
    pub topics: Vec<Hash256>,
    /// Non-indexed data payload.
    pub data: Vec<u8>,
}

impl Log {
    /// Create a new log entry.
    ///
    /// Returns `None` if topics exceed `MAX_LOG_TOPICS` (4) or
    /// data exceeds `MAX_LOG_DATA_SIZE` (1024 bytes).
    pub fn new(address: Address, topics: Vec<Hash256>, data: Vec<u8>) -> Option<Self> {
        if topics.len() > MAX_LOG_TOPICS || data.len() > MAX_LOG_DATA_SIZE {
            return None;
        }
        Some(Self {
            address,
            topics,
            data,
        })
    }

    /// Check if this log matches a filter.
    pub fn matches(&self, filter: &LogFilter) -> bool {
        // Filter by address
        if let Some(ref addr) = filter.address
            && self.address != *addr
        {
            return false;
        }

        // Filter by topics (positional matching)
        for (i, topic_filter) in filter.topics.iter().enumerate() {
            if let Some(expected_topic) = topic_filter
                && (i >= self.topics.len() || self.topics[i] != *expected_topic)
            {
                return false;
            }
        }

        true
    }
}

/// Filter for querying logs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LogFilter {
    /// Start block height (inclusive).
    pub from_block: Option<u64>,
    /// End block height (inclusive).
    pub to_block: Option<u64>,
    /// Filter by emitting contract address.
    pub address: Option<Address>,
    /// Positional topic filters. `None` means "any value" at that position.
    pub topics: Vec<Option<Hash256>>,
}

impl LogFilter {
    /// Check if a block height is within this filter's range.
    pub fn matches_block(&self, height: u64) -> bool {
        if let Some(from) = self.from_block
            && height < from
        {
            return false;
        }
        if let Some(to) = self.to_block
            && height > to
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;

    fn test_addr(s: &str) -> Address {
        let hash = Hasher::hash(s.as_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Address::from_bytes(bytes)
    }

    #[test]
    fn test_log_creation() {
        let addr = test_addr("contract_a");
        let topic1 = Hasher::hash(b"Transfer");
        let topic2 = Hasher::hash(b"from_addr");
        let data = vec![1, 2, 3, 4];

        let log = Log::new(addr, vec![topic1, topic2], data.clone()).unwrap();
        assert_eq!(log.address, addr);
        assert_eq!(log.topics.len(), 2);
        assert_eq!(log.topics[0], topic1);
        assert_eq!(log.topics[1], topic2);
        assert_eq!(log.data, data);
    }

    #[test]
    fn test_log_filter_address() {
        let addr_a = test_addr("contract_a");
        let addr_b = test_addr("contract_b");
        let topic = Hasher::hash(b"Event");

        let log = Log::new(addr_a, vec![topic], vec![]).unwrap();

        // Filter matches same address
        let filter_a = LogFilter {
            address: Some(addr_a),
            ..Default::default()
        };
        assert!(log.matches(&filter_a));

        // Filter doesn't match different address
        let filter_b = LogFilter {
            address: Some(addr_b),
            ..Default::default()
        };
        assert!(!log.matches(&filter_b));
    }

    #[test]
    fn test_log_filter_topic() {
        let addr = test_addr("contract");
        let topic_transfer = Hasher::hash(b"Transfer");
        let topic_approve = Hasher::hash(b"Approve");

        let log = Log::new(addr, vec![topic_transfer], vec![]).unwrap();

        // Filter matches correct topic
        let filter = LogFilter {
            topics: vec![Some(topic_transfer)],
            ..Default::default()
        };
        assert!(log.matches(&filter));

        // Filter doesn't match wrong topic
        let filter_wrong = LogFilter {
            topics: vec![Some(topic_approve)],
            ..Default::default()
        };
        assert!(!log.matches(&filter_wrong));
    }

    #[test]
    fn test_log_filter_combined() {
        let addr = test_addr("contract_combined");
        let topic1 = Hasher::hash(b"Transfer");
        let topic2 = Hasher::hash(b"from");

        let log = Log::new(addr, vec![topic1, topic2], vec![42]).unwrap();

        // Combined filter: correct address + correct topic
        let filter = LogFilter {
            address: Some(addr),
            topics: vec![Some(topic1)],
            ..Default::default()
        };
        assert!(log.matches(&filter));

        // Combined filter: correct address + wrong topic
        let filter_wrong = LogFilter {
            address: Some(addr),
            topics: vec![Some(Hasher::hash(b"Approval"))],
            ..Default::default()
        };
        assert!(!log.matches(&filter_wrong));
    }

    #[test]
    fn test_log_filter_empty_matches_all() {
        let addr = test_addr("any_contract");
        let log = Log::new(addr, vec![Hasher::hash(b"Event")], vec![1, 2, 3]).unwrap();

        let empty_filter = LogFilter::default();
        assert!(log.matches(&empty_filter));
    }

    #[test]
    fn test_log_filter_block_range() {
        let filter = LogFilter {
            from_block: Some(10),
            to_block: Some(20),
            ..Default::default()
        };

        assert!(!filter.matches_block(5));
        assert!(filter.matches_block(10));
        assert!(filter.matches_block(15));
        assert!(filter.matches_block(20));
        assert!(!filter.matches_block(25));
    }
}
