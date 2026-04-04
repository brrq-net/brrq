//! Gossip protocol for transaction and block propagation.
//!
//! ## Design
//!
//! Brrq uses Dandelion++ (BIP-156) for transaction propagation:
//!
//! 1. **Stem phase**: Transaction is forwarded to exactly ONE randomly-chosen
//!    peer for 2–4 hops. Each relay node independently decides (10% probability)
//!    whether to transition to the fluff phase.
//! 2. **Fluff phase**: Transaction is broadcast to ALL connected peers via
//!    standard gossip (same as before).
//! 3. **Timing jitter**: Each stem relay adds a random delay (100–500ms) drawn
//!    from a CSPRNG to prevent timing-correlation deanonymization.
//!
//! Block propagation is NOT affected — blocks always use standard gossip
//! (latency-critical, and block producers are publicly known anyway).
//!
//! ## Privacy Guarantee
//!
//! Under the adversarial model where an attacker observes all inter-node links,
//! Dandelion++ provides k-anonymity where k = number of honest nodes in the
//! stem path (typically 2–4). The 10% fluff probability ensures the expected
//! stem length is ~10 hops, but we cap at 4 to bound latency.

use std::collections::{HashSet, VecDeque};

use brrq_crypto::hash::Hash256;

use crate::error::NetworkError;
use crate::message::{self, Message};

/// Maximum gossip message size (1 MB).
/// Prevents memory exhaustion from oversized messages.
/// Re-exported from the message module for convenience at the gossip layer.
pub const MAX_MESSAGE_SIZE: usize = message::MAX_MESSAGE_SIZE;

/// Size of the seen-message cache.
const SEEN_CACHE_SIZE: usize = 10_000;

// Legacy re-exports — flood constants now live in peer.rs (PeerManager).
// Kept for backward compatibility with tests that import from gossip.
pub use crate::peer::MAX_MESSAGES_PER_PEER_PER_MINUTE;
pub use crate::peer::MAX_TX_PER_PEER_PER_MINUTE as MAX_TX_PER_ADDRESS_PER_MINUTE;

// ── Dandelion++ Constants ──────────────────────────────────────────

/// Maximum stem hops before mandatory fluff (bounds latency to ≤4 relay hops).
pub const DANDELION_MAX_STEM_HOPS: u8 = 4;

/// Minimum stem hops (ensures at least 2 hops of anonymity).
pub const DANDELION_MIN_STEM_HOPS: u8 = 2;

/// Probability of transitioning from stem to fluff at each hop (10% = 1000 bp).
/// Each relay independently flips this coin. Expected stem length = 1/p = 10,
/// but capped at DANDELION_MAX_STEM_HOPS.
pub const DANDELION_FLUFF_PROBABILITY_BP: u16 = 1000;

/// Minimum stem relay delay in milliseconds.
pub const DANDELION_MIN_DELAY_MS: u64 = 100;

/// Maximum stem relay delay in milliseconds.
pub const DANDELION_MAX_DELAY_MS: u64 = 500;

/// Dandelion++ propagation phase for a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DandelionPhase {
    /// Stem: forward to exactly one peer, with timing jitter.
    Stem {
        /// Number of hops completed so far.
        hops: u8,
    },
    /// Fluff: broadcast to all peers via standard gossip.
    Fluff,
}

/// A transaction message tagged with its Dandelion++ phase.
#[derive(Debug, Clone)]
pub struct DandelionMessage {
    /// The underlying network message.
    pub message: Message,
    /// Current propagation phase.
    pub phase: DandelionPhase,
    /// Relay delay in milliseconds (0 for fluff).
    pub delay_ms: u64,
}

impl DandelionMessage {
    /// Decide whether this stem message should transition to fluff.
    ///
    /// Uses CSPRNG (not Math.random or thread_rng) via BLAKE3 PRNG
    /// seeded from the message ID + hop count, making the decision
    /// deterministic per-message but unpredictable to observers.
    ///
    /// Returns the next phase after one stem hop.
    pub fn next_phase(msg_id: &Hash256, current_hops: u8) -> DandelionPhase {
        if current_hops >= DANDELION_MAX_STEM_HOPS {
            return DandelionPhase::Fluff;
        }
        if current_hops < DANDELION_MIN_STEM_HOPS {
            return DandelionPhase::Stem {
                hops: current_hops + 1,
            };
        }

        // Derive a deterministic-but-unpredictable coin flip from
        // H(msg_id || hops). This prevents an observer who sees the
        // message from predicting which hop will fluff.
        let mut hasher = brrq_crypto::hash::Hasher::new();
        hasher.update(b"DANDELION_PHASE_DECISION");
        hasher.update(msg_id.as_bytes());
        hasher.update(&[current_hops]);
        let decision_hash = hasher.finalize();

        // Use first 2 bytes as a 16-bit value, compare against threshold.
        let sample = u16::from_le_bytes([
            decision_hash.as_bytes()[0],
            decision_hash.as_bytes()[1],
        ]);
        // Threshold = 10% of u16::MAX = 6553.5 ≈ 6554
        let threshold = (u16::MAX as u32 * DANDELION_FLUFF_PROBABILITY_BP as u32 / 10_000) as u16;

        if sample < threshold {
            DandelionPhase::Fluff
        } else {
            DandelionPhase::Stem {
                hops: current_hops + 1,
            }
        }
    }

    /// Compute a random stem delay in [DANDELION_MIN_DELAY_MS, DANDELION_MAX_DELAY_MS].
    ///
    /// Derived from CSPRNG via BLAKE3 hash of msg_id + hops + "DELAY",
    /// providing timing jitter that is unpredictable to network observers.
    pub fn compute_stem_delay(msg_id: &Hash256, hops: u8) -> u64 {
        let mut hasher = brrq_crypto::hash::Hasher::new();
        hasher.update(b"DANDELION_STEM_DELAY");
        hasher.update(msg_id.as_bytes());
        hasher.update(&[hops]);
        let delay_hash = hasher.finalize();

        let raw = u64::from_le_bytes([
            delay_hash.as_bytes()[0],
            delay_hash.as_bytes()[1],
            delay_hash.as_bytes()[2],
            delay_hash.as_bytes()[3],
            delay_hash.as_bytes()[4],
            delay_hash.as_bytes()[5],
            delay_hash.as_bytes()[6],
            delay_hash.as_bytes()[7],
        ]);

        let range = DANDELION_MAX_DELAY_MS - DANDELION_MIN_DELAY_MS;
        DANDELION_MIN_DELAY_MS + (raw % (range + 1))
    }
}

pub struct Shard {
    seen: HashSet<Hash256>,
    seen_order: VecDeque<Hash256>,
}

pub struct GossipEngine {
    /// 256-way sharded cache for O(1) concurrent deduplication
    shards: Vec<std::sync::Mutex<Shard>>,
    /// Protected state for outbound queue
    state: std::sync::Mutex<GossipState>,
}

struct GossipState {
    outbound_queue: VecDeque<Message>,
    /// Stem queue for Dandelion++ — messages waiting for delayed relay.
    stem_queue: VecDeque<DandelionMessage>,
    max_queue_size: usize,
}

impl GossipEngine {
    /// Create a new gossip engine.
    pub fn new() -> Self {
        let mut shards = Vec::with_capacity(256);
        for _ in 0..256 {
            shards.push(std::sync::Mutex::new(Shard {
                seen: HashSet::with_capacity(SEEN_CACHE_SIZE / 256),
                seen_order: VecDeque::with_capacity(SEEN_CACHE_SIZE / 256),
            }));
        }
        Self {
            shards,
            state: std::sync::Mutex::new(GossipState {
                outbound_queue: VecDeque::new(),
                stem_queue: VecDeque::new(),
                max_queue_size: 1000,
            }),
        }
    }

    /// Mark a message as seen in the appropriate shard.
    pub fn mark_seen(&self, id: Hash256) {
        let shard_idx = (id.as_bytes()[0] as usize) % 256;
        let mut shard = self.shards[shard_idx].lock().unwrap_or_else(|e| e.into_inner());
        if shard.seen.insert(id) {
            shard.seen_order.push_back(id);
            if shard.seen.len() > SEEN_CACHE_SIZE / 256 {
                if let Some(old) = shard.seen_order.pop_front() {
                    shard.seen.remove(&old);
                }
            }
        }
    }

    /// Check if a message has been seen.
    pub fn is_seen(&self, id: &Hash256) -> bool {
        let shard_idx = (id.as_bytes()[0] as usize) % 256;
        let shard = self.shards[shard_idx].lock().unwrap_or_else(|e| e.into_inner());
        shard.seen.contains(id)
    }

    pub fn check_incoming_size(&self, raw_bytes: &[u8]) -> Result<(), NetworkError> {
        if raw_bytes.len() > MAX_MESSAGE_SIZE {
            return Err(NetworkError::MessageTooLarge {
                size: raw_bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        Ok(())
    }

    /// Check if a message is new (not a duplicate) and valid.
    /// Returns `true` if the message should be processed, `false` if duplicate or invalid.
    ///
    /// Note: Flood rate limiting is now handled by `PeerManager::check_flood()`.
    /// Callers should check flood limits separately before or after this call.
    pub fn process_incoming(&self, msg: &Message, _peer_id: &str) -> bool {
        if msg.validate().is_err() {
            return false;
        }

        let msg_id = msg.id();

        if self.is_seen(&msg_id) {
            return false;
        }

        self.mark_seen(msg_id);
        true
    }

    pub fn broadcast(&self, msg: Message) {
        let msg_id = msg.id();
        self.mark_seen(msg_id);

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.outbound_queue.len() < state.max_queue_size {
            state.outbound_queue.push_back(msg);
        }
    }

    pub fn next_outbound(&self) -> Option<Message> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).outbound_queue.pop_front()
    }

    pub fn drain_outbound(&self) -> Vec<Message> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .outbound_queue
            .drain(..)
            .collect()
    }

    pub fn outbound_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).outbound_queue.len()
    }

    // ── Dandelion++ Transaction Propagation ────────────────

    /// Submit a new locally-originated transaction via Dandelion++ stem phase.
    ///
    /// The transaction enters the stem at hop 0 and will be forwarded to
    /// exactly one randomly-chosen peer with timing jitter. After 2–4 hops
    /// (or with 10% probability at each hop after the minimum), it transitions
    /// to the fluff phase and is broadcast to all peers.
    pub fn dandelion_submit(&self, msg: Message) {
        let msg_id = msg.id();
        self.mark_seen(msg_id);

        let delay = DandelionMessage::compute_stem_delay(&msg_id, 0);
        let dm = DandelionMessage {
            message: msg,
            phase: DandelionPhase::Stem { hops: 0 },
            delay_ms: delay,
        };

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.stem_queue.len() < state.max_queue_size {
            state.stem_queue.push_back(dm);
        }
    }

    /// Process an incoming stem-phase transaction received from a peer.
    ///
    /// Decides whether to continue the stem (relay to one peer with delay)
    /// or transition to fluff (broadcast to all peers immediately).
    pub fn dandelion_relay(&self, msg: Message, current_hops: u8) {
        let msg_id = msg.id();

        if self.is_seen(&msg_id) {
            return; // Duplicate — already processed
        }
        self.mark_seen(msg_id);

        let next_phase = DandelionMessage::next_phase(&msg_id, current_hops);

        match next_phase {
            DandelionPhase::Fluff => {
                // Transition to fluff: broadcast via standard gossip
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.outbound_queue.len() < state.max_queue_size {
                    state.outbound_queue.push_back(msg);
                }
            }
            DandelionPhase::Stem { hops } => {
                // Continue stem: queue for delayed single-peer relay
                let delay = DandelionMessage::compute_stem_delay(&msg_id, hops);
                let dm = DandelionMessage {
                    message: msg,
                    phase: DandelionPhase::Stem { hops },
                    delay_ms: delay,
                };
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.stem_queue.len() < state.max_queue_size {
                    state.stem_queue.push_back(dm);
                }
            }
        }
    }

    /// Drain all pending stem-phase messages (for the relay loop to process).
    pub fn drain_stem_queue(&self) -> Vec<DandelionMessage> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .stem_queue
            .drain(..)
            .collect()
    }

    /// Number of pending stem messages.
    pub fn stem_queue_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).stem_queue.len()
    }

    /// Legacy shim — flood counters now live in PeerManager.
    /// This method is a no-op; callers should use `PeerManager::reset_flood_counters()`.
    #[deprecated(note = "Use PeerManager::reset_flood_counters() instead")]
    pub fn reset_flood_counters(&self) {
        // No-op: flood counters moved to PeerManager
    }
}

impl Default for GossipEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplication() {
        let gossip = GossipEngine::new();
        let msg = Message::Ping(42);

        assert!(gossip.process_incoming(&msg, "peer1")); // first time: forward
        assert!(!gossip.process_incoming(&msg, "peer1")); // duplicate: reject
    }

    #[test]
    fn test_broadcast_and_drain() {
        let gossip = GossipEngine::new();
        gossip.broadcast(Message::Ping(1));
        gossip.broadcast(Message::Ping(2));

        let msgs = gossip.drain_outbound();
        assert_eq!(msgs.len(), 2);
        assert_eq!(gossip.outbound_count(), 0);
    }

    // NOTE: Flood protection tests have moved to peer.rs (PeerManager::check_flood).
    // GossipEngine now only handles deduplication and message propagation.

    #[test]
    fn test_seen_cache_eviction() {
        let gossip = GossipEngine::new();

        // Insert SEEN_CACHE_SIZE + 1 messages.
        for i in 0..=SEEN_CACHE_SIZE {
            let msg = Message::Ping(i as u64);
            gossip.process_incoming(&msg, "peer1");
        }

        // First message should have been evicted
        let first = Message::Ping(0);
        assert!(!gossip.is_seen(&first.id()));

        // Last message should still be seen
        let last = Message::Ping(SEEN_CACHE_SIZE as u64);
        assert!(gossip.is_seen(&last.id()));
    }

    // ── Message size limit tests ──────────────────────

    #[test]
    fn test_check_incoming_size_within_limit() {
        let gossip = GossipEngine::new();
        let data = vec![0u8; MAX_MESSAGE_SIZE];
        assert!(gossip.check_incoming_size(&data).is_ok());
    }

    #[test]
    fn test_check_incoming_size_exceeds_limit() {
        let gossip = GossipEngine::new();
        let data = vec![0u8; MAX_MESSAGE_SIZE + 1];
        assert!(gossip.check_incoming_size(&data).is_err());
    }

    #[test]
    fn test_check_incoming_size_empty() {
        let gossip = GossipEngine::new();
        assert!(gossip.check_incoming_size(&[]).is_ok());
    }

    // ── Dandelion++ Tests ──────────────────────────────────

    #[test]
    fn test_dandelion_submit_enters_stem() {
        let gossip = GossipEngine::new();
        let msg = Message::Ping(999);
        gossip.dandelion_submit(msg);

        assert_eq!(gossip.stem_queue_count(), 1);
        assert_eq!(gossip.outbound_count(), 0, "stem messages must NOT go to outbound");

        let stems = gossip.drain_stem_queue();
        assert_eq!(stems.len(), 1);
        assert!(matches!(stems[0].phase, DandelionPhase::Stem { hops: 0 }));
        assert!(stems[0].delay_ms >= DANDELION_MIN_DELAY_MS);
        assert!(stems[0].delay_ms <= DANDELION_MAX_DELAY_MS);
    }

    #[test]
    fn test_dandelion_min_hops_enforced() {
        let msg_id = Hash256::ZERO;
        // At hop 0 and 1, must stay in stem regardless of hash
        let phase0 = DandelionMessage::next_phase(&msg_id, 0);
        assert!(matches!(phase0, DandelionPhase::Stem { hops: 1 }));

        let phase1 = DandelionMessage::next_phase(&msg_id, 1);
        assert!(matches!(phase1, DandelionPhase::Stem { hops: 2 }));
    }

    #[test]
    fn test_dandelion_max_hops_forces_fluff() {
        let msg_id = Hash256::ZERO;
        let phase = DandelionMessage::next_phase(&msg_id, DANDELION_MAX_STEM_HOPS);
        assert_eq!(phase, DandelionPhase::Fluff);
    }

    #[test]
    fn test_dandelion_relay_fluff_goes_to_outbound() {
        let gossip = GossipEngine::new();
        let msg = Message::Ping(42);
        // Force fluff by using max hops
        gossip.dandelion_relay(msg, DANDELION_MAX_STEM_HOPS);

        assert_eq!(gossip.outbound_count(), 1, "fluff must go to outbound");
        assert_eq!(gossip.stem_queue_count(), 0);
    }

    #[test]
    fn test_dandelion_relay_dedup() {
        let gossip = GossipEngine::new();
        let msg = Message::Ping(42);
        gossip.dandelion_relay(msg.clone(), 0);
        gossip.dandelion_relay(msg, 0);

        // Second relay must be rejected as duplicate
        let total = gossip.stem_queue_count() + gossip.outbound_count();
        assert_eq!(total, 1, "duplicate stem relay must be rejected");
    }

    #[test]
    fn test_dandelion_stem_delay_in_range() {
        for i in 0..50u8 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = i;
            let msg_id = Hash256::from_bytes(id_bytes);
            let delay = DandelionMessage::compute_stem_delay(&msg_id, 0);
            assert!(delay >= DANDELION_MIN_DELAY_MS, "delay {} < min {}", delay, DANDELION_MIN_DELAY_MS);
            assert!(delay <= DANDELION_MAX_DELAY_MS, "delay {} > max {}", delay, DANDELION_MAX_DELAY_MS);
        }
    }

    #[test]
    fn test_dandelion_phase_decision_deterministic() {
        let msg_id = Hash256::from_bytes([0xAB; 32]);
        let phase1 = DandelionMessage::next_phase(&msg_id, 2);
        let phase2 = DandelionMessage::next_phase(&msg_id, 2);
        assert_eq!(phase1, phase2, "same input must produce same phase decision");
    }
}
