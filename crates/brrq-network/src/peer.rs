//! Peer management.
//!
//! Tracks connected peers, their state, and reputation.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use crate::error::NetworkError;

/// Maximum number of connected peers (total).
pub const MAX_PEERS: usize = 50;

// Inbound/Outbound slot separation prevents an attacker from filling all
// peer slots with cheap inbound connections, enabling eclipse attacks.

/// Maximum number of *inbound* peers (peers that connected to us).
/// Kept lower than total to guarantee outbound slots remain available.
pub const MAX_INBOUND_PEERS: usize = 30;

/// Maximum number of *outbound* peers (peers we connected to).
/// Outbound slots are more valuable — we chose them, so they are harder
/// for an attacker to control.
pub const MAX_OUTBOUND_PEERS: usize = 20;

// Enforced timeouts prevent a malicious peer from holding a slot
// indefinitely during handshake or sync.

/// Maximum seconds allowed for completing the handshake.
/// If a peer does not finish the handshake within this window it is
/// disconnected immediately.
pub const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Maximum seconds allowed for a sync response.
/// If a peer does not respond to a sync/block request within this window
/// the request is considered failed and the peer is penalized.
pub const SYNC_TIMEOUT_SECS: u64 = 30;

/// Maximum seconds of inactivity before a peer is considered stale.
/// Stale peers are periodically reaped to free slots for healthier peers.
pub const IDLE_TIMEOUT_SECS: u64 = 300;

/// Minimum reputation before automatic disconnection.
/// Peers below this threshold are considered malicious and banned.
pub const MIN_REPUTATION_THRESHOLD: i32 = -200;

/// Maximum peers per /16 subnet to prevent eclipse attacks.
/// Limiting peers per subnet ensures peer diversity and makes it harder
/// for an attacker controlling a single subnet to eclipse a node.
pub const MAX_PEERS_PER_SUBNET: usize = 3;

/// Max transactions per peer per minute (flood protection).
pub const MAX_TX_PER_PEER_PER_MINUTE: u32 = 100;

/// Max total messages (any type) per peer per minute.
/// Prevents cache eviction attacks via Ping/Pong floods.
pub const MAX_MESSAGES_PER_PEER_PER_MINUTE: u32 = 500;

/// Direction of the TCP connection.
///
/// Distinguishing inbound from outbound is critical for eclipse-attack
/// resistance: outbound peers are chosen by *us*, so an attacker cannot
/// force them.  By reserving dedicated outbound slots we ensure the node
/// always has self-selected peers in its view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    /// We initiated the connection (we dialed the remote peer).
    Outbound,
    /// The remote peer initiated the connection (they dialed us).
    Inbound,
}

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// Connecting (handshake in progress).
    Connecting,
    /// Connected and active.
    Connected,
    /// Disconnected.
    Disconnected,
}

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Unique peer identifier.
    pub peer_id: String,
    /// Remote address (host:port).
    pub address: String,
    /// Connection state.
    pub state: PeerState,
    /// Whether we dialed them (Outbound) or they dialed us (Inbound).
    pub direction: ConnectionDirection,
    /// Whether the peer has completed signature-verified authentication.
    /// Set to `true` only after `verify_message_signature()` succeeds on the
    /// peer's Hello message. Unauthenticated peers must not receive or relay
    /// consensus-critical messages (proposals, votes, slashing evidence).
    pub is_authenticated: bool,
    /// Protocol version negotiated.
    pub version: u32,
    /// Peer's best known block height.
    pub best_height: u64,
    /// Time of last message received.
    pub last_seen: Instant,
    /// Reputation score (higher = more trusted).
    pub reputation: Arc<AtomicI32>,
    /// Number of messages received from this peer.
    pub messages_received: u64,
    /// Flood counter: messages this minute (auto-resets after 60s).
    pub msg_count: u32,
    /// Flood counter: transactions this minute (auto-resets after 60s).
    pub tx_count: u32,
    /// Timestamp of last flood counter reset (seconds since UNIX epoch).
    pub flood_reset_at: u64,
}

impl PeerInfo {
    /// Create a new peer info with the given connection direction.
    /// `is_authenticated` starts as `false` — set to `true` only after the
    /// Hello signature has been cryptographically verified.
    pub fn new(peer_id: String, address: String, direction: ConnectionDirection) -> Self {
        Self {
            peer_id,
            address,
            state: PeerState::Connecting,
            direction,
            is_authenticated: false,
            version: 0,
            best_height: 0,
            last_seen: Instant::now(),
            reputation: Arc::new(AtomicI32::new(100)),
            messages_received: 0,
            msg_count: 0,
            tx_count: 0,
            flood_reset_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Check if the peer has been idle longer than `IDLE_TIMEOUT_SECS`.
    ///
    /// A stale peer is one we have not heard from within the idle window.
    /// Callers should periodically sweep stale peers to free connection
    /// slots for healthier nodes.
    pub fn is_stale(&self) -> bool {
        self.last_seen.elapsed() >= Duration::from_secs(IDLE_TIMEOUT_SECS)
    }

    /// Adjust reputation (clamped to [-1000, 1000]).
    ///
    /// Returns `true` if the peer's reputation has dropped below the ban
    /// threshold and should be disconnected.
    pub fn adjust_reputation(&self, delta: i32) -> bool {
        // Atomically clamp bounds without an exclusive write lock.
        let _ = self
            .reputation
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_add(delta).clamp(-1000, 1000))
            });
        self.should_ban()
    }

    /// Check if this peer's reputation is below the ban threshold.
    pub fn should_ban(&self) -> bool {
        self.reputation.load(Ordering::Relaxed) <= MIN_REPUTATION_THRESHOLD
    }
}

/// Peer manager: tracks all connected peers.
pub struct PeerManager {
    /// Connected peers keyed by peer_id.
    peers: HashMap<String, PeerInfo>,
    /// Maximum number of peers.
    max_peers: usize,
    /// Per-peer Hello nonce tracking to prevent replay attacks.
    /// Maps peer_id to the set of nonces seen from that peer.
    seen_hello_nonces: HashMap<String, HashSet<u64>>,
}

impl PeerManager {
    /// Create a new peer manager.
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            max_peers: MAX_PEERS,
            seen_hello_nonces: HashMap::new(),
        }
    }

    /// Create with a custom max peer count.
    pub fn with_max_peers(max_peers: usize) -> Self {
        Self {
            peers: HashMap::new(),
            max_peers,
            seen_hello_nonces: HashMap::new(),
        }
    }

    /// Add a new peer with explicit connection direction.
    ///
    /// Enforces separate inbound/outbound slot limits.
    /// Inbound connections are capped at `MAX_INBOUND_PEERS` and outbound at
    /// `MAX_OUTBOUND_PEERS`.  This prevents an attacker from eclipsing the node
    /// by flooding inbound connections that consume all peer slots.
    pub fn add_peer(
        &mut self,
        peer_id: String,
        address: String,
        direction: ConnectionDirection,
    ) -> Result<(), NetworkError> {
        // Check direction-specific slot limits before total limit.
        let (dir_count, dir_max) = match direction {
            ConnectionDirection::Inbound => (self.inbound_count(), MAX_INBOUND_PEERS),
            ConnectionDirection::Outbound => (self.outbound_count(), MAX_OUTBOUND_PEERS),
        };
        if dir_count >= dir_max {
            return match direction {
                ConnectionDirection::Inbound => {
                    Err(NetworkError::InboundSlotsFull { max: dir_max })
                }
                ConnectionDirection::Outbound => {
                    Err(NetworkError::OutboundSlotsFull { max: dir_max })
                }
            };
        }

        if self.peers.len() >= self.max_peers {
            // Evict the peer with worst reputation
            self.evict_worst_peer();
        }

        // Subnet diversity check: reject peers if the /16 subnet already has
        // MAX_PEERS_PER_SUBNET peers (eclipse attack prevention).
        let subnet = Self::extract_subnet(&address);
        let subnet_count = self
            .peers
            .values()
            .filter(|p| Self::extract_subnet(&p.address) == subnet)
            .count();
        if subnet_count >= MAX_PEERS_PER_SUBNET {
            return Err(NetworkError::SubnetLimitReached { subnet });
        }

        self.peers
            .insert(peer_id.clone(), PeerInfo::new(peer_id, address, direction));
        Ok(())
    }

    // ── Inbound / outbound counting ────────────────────────────────────

    /// Count currently connected inbound peers.
    pub fn inbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.direction == ConnectionDirection::Inbound)
            .count()
    }

    /// Count currently connected outbound peers.
    pub fn outbound_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.direction == ConnectionDirection::Outbound)
            .count()
    }

    // ── Authentication gate ────────────────────────────────────────────

    /// Mark a peer as authenticated after its Hello signature has been verified.
    ///
    /// Returns an error if the peer is not found.
    pub fn mark_authenticated(&mut self, peer_id: &str) -> Result<(), NetworkError> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| NetworkError::PeerNotFound {
                peer_id: peer_id.to_string(),
            })?;
        peer.is_authenticated = true;
        Ok(())
    }

    /// Reject (disconnect) all peers that are still unauthenticated
    /// after the handshake timeout has elapsed.
    ///
    /// Returns the list of evicted peer IDs so the caller can close their
    /// transport-level connections.
    pub fn evict_unauthenticated(&mut self) -> Vec<String> {
        let handshake_deadline = Duration::from_secs(HANDSHAKE_TIMEOUT_SECS);
        let stale: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| !p.is_authenticated && p.last_seen.elapsed() >= handshake_deadline)
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale {
            self.peers.remove(id);
        }
        stale
    }

    /// Check whether a peer is authenticated before allowing a
    /// security-sensitive operation.  Returns an error if the peer does not
    /// exist or is not authenticated.
    pub fn require_authenticated(&self, peer_id: &str) -> Result<(), NetworkError> {
        let peer = self
            .peers
            .get(peer_id)
            .ok_or_else(|| NetworkError::PeerNotFound {
                peer_id: peer_id.to_string(),
            })?;
        if !peer.is_authenticated {
            return Err(NetworkError::PeerNotAuthenticated {
                peer_id: peer_id.to_string(),
            });
        }
        Ok(())
    }

    /// Check if a Hello nonce has been seen before for a given peer.
    /// Returns `true` if the nonce is new (first time), `false` if it is a replay.
    /// Records the nonce so future calls with the same value return `false`.
    pub fn check_hello_nonce(&mut self, peer_id: &str, nonce: u64) -> bool {
        const MAX_NONCES_PER_PEER: usize = 1000;
        let nonces = self.seen_hello_nonces.entry(peer_id.to_string()).or_default();
        // Cap nonce set to prevent memory exhaustion from Hello replay attacks.
        if nonces.len() >= MAX_NONCES_PER_PEER {
            nonces.clear(); // Reset — old nonces expired anyway
        }
        nonces.insert(nonce)
    }

    /// Mark a peer as connected (handshake complete).
    pub fn mark_connected(
        &mut self,
        peer_id: &str,
        version: u32,
        best_height: u64,
    ) -> Result<(), NetworkError> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| NetworkError::PeerNotFound {
                peer_id: peer_id.to_string(),
            })?;

        peer.state = PeerState::Connected;
        peer.version = version;
        peer.best_height = best_height;
        Ok(())
    }

    /// Record a message from a peer.
    pub fn record_message(&mut self, peer_id: &str) -> Result<(), NetworkError> {
        let peer = self
            .peers
            .get_mut(peer_id)
            .ok_or_else(|| NetworkError::PeerNotFound {
                peer_id: peer_id.to_string(),
            })?;

        peer.last_seen = Instant::now();
        peer.messages_received = peer.messages_received.saturating_add(1);
        Ok(())
    }

    /// Remove a peer.
    pub fn remove_peer(&mut self, peer_id: &str) -> Option<PeerInfo> {
        self.seen_hello_nonces.remove(peer_id);
        self.peers.remove(peer_id)
    }

    /// Get a peer's info.
    pub fn get_peer(&self, peer_id: &str) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }

    /// Get a mutable reference to a peer's info (for reputation adjustments).
    pub fn get_peer_mut(&mut self, peer_id: &str) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }

    /// Get all connected peers.
    pub fn connected_peers(&self) -> Vec<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .collect()
    }

    /// Total peer count (all states).
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Get the highest known block height across all peers.
    pub fn best_peer_height(&self) -> u64 {
        self.peers
            .values()
            .map(|p| p.best_height)
            .max()
            .unwrap_or(0)
    }

    /// Get addresses of all connected peers (for gossip).
    pub fn peer_addresses(&self) -> Vec<String> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .map(|p| p.address.clone())
            .collect()
    }

    /// Remove all peers that have exceeded `IDLE_TIMEOUT_SECS`
    /// without sending any message.  Returns the IDs of reaped peers so
    /// the caller can close the underlying connections.
    pub fn prune_stale_peers(&mut self) -> Vec<String> {
        let stale: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| p.is_stale())
            .map(|(id, _)| id.clone())
            .collect();
        for id in &stale {
            self.peers.remove(id);
        }
        stale
    }

    /// Remove all peers whose reputation is below the ban threshold.
    /// Returns the list of banned peer IDs (caller should close their connections).
    pub fn prune_banned_peers(&mut self) -> Vec<String> {
        let banned: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| p.should_ban())
            .map(|(id, _)| id.clone())
            .collect();
        for id in &banned {
            self.peers.remove(id);
        }
        banned
    }

    /// Extract subnet prefix from address for diversity enforcement.
    ///
    /// - IPv4 "192.168.1.50:30303" → /24 subnet "192.168.1"
    /// - IPv6 "[2001:db8:85a3::1]:30303" → /48 prefix "2001:db8:85a3"
    /// - Hostname "localhost:30303" → "localhost"
    pub fn extract_subnet(address: &str) -> String {
        // Strip port: handle [IPv6]:port and IPv4:port
        let host = if address.starts_with('[') {
            // IPv6 with brackets: [2001:db8::1]:30303
            address
                .split(']')
                .next()
                .unwrap_or("")
                .trim_start_matches('[')
        } else {
            address.split(':').next().unwrap_or("")
        };

        if host.contains(':') {
            // IPv6: extract /48 prefix (first three groups)
            let groups: Vec<&str> = host.split(':').collect();
            if groups.len() >= 3 {
                format!("{}:{}:{}", groups[0], groups[1], groups[2])
            } else if groups.len() == 2 {
                format!("{}:{}", groups[0], groups[1])
            } else {
                host.to_string()
            }
        } else {
            // IPv4 or hostname: extract /24 (first three octets)
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() >= 3 {
                format!("{}.{}.{}", parts[0], parts[1], parts[2])
            } else if parts.len() == 2 {
                format!("{}.{}", parts[0], parts[1])
            } else {
                host.to_string()
            }
        }
    }

    // ── Flood counter management (merged from GossipEngine) ────────────

    /// Check if a peer has exceeded its message rate limit.
    /// Increments the counter and returns `true` if the message is allowed,
    /// `false` if the peer is over the limit.
    /// If `is_tx` is true, also checks the per-peer transaction limit.
    pub fn check_flood(&mut self, peer_id: &str, is_tx: bool) -> bool {
        let peer = match self.peers.get_mut(peer_id) {
            Some(p) => p,
            None => return false, // unknown peer — reject
        };

        // Auto-reset counters every 60 seconds (removes dependency on external caller).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now.saturating_sub(peer.flood_reset_at) >= 60 {
            peer.msg_count = 0;
            peer.tx_count = 0;
            peer.flood_reset_at = now;
        }

        if peer.msg_count >= MAX_MESSAGES_PER_PEER_PER_MINUTE {
            return false;
        }
        peer.msg_count += 1;

        if is_tx {
            if peer.tx_count >= MAX_TX_PER_PEER_PER_MINUTE {
                return false;
            }
            peer.tx_count += 1;
        }

        true
    }

    /// Reset all per-peer flood counters. Called periodically (e.g., every 60s).
    pub fn reset_flood_counters(&mut self) {
        for peer in self.peers.values_mut() {
            peer.msg_count = 0;
            peer.tx_count = 0;
        }
    }

    /// Evict the peer with the lowest reputation.
    fn evict_worst_peer(&mut self) {
        if let Some(worst_id) = self
            .peers
            .iter()
            .min_by_key(|(_, p)| p.reputation.load(Ordering::Relaxed))
            .map(|(id, _)| id.clone())
        {
            self.peers.remove(&worst_id);
        }
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_peer() {
        let mut pm = PeerManager::new();
        pm.add_peer(
            "peer1".into(),
            "127.0.0.1:30303".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();
        assert_eq!(pm.peer_count(), 1);
    }

    #[test]
    fn test_mark_connected() {
        let mut pm = PeerManager::new();
        pm.add_peer(
            "peer1".into(),
            "127.0.0.1:30303".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();
        pm.mark_connected("peer1", 1, 100).unwrap();

        let peer = pm.get_peer("peer1").unwrap();
        assert_eq!(peer.state, PeerState::Connected);
        assert_eq!(peer.best_height, 100);
    }

    #[test]
    fn test_connected_peers() {
        let mut pm = PeerManager::new();
        pm.add_peer(
            "peer1".into(),
            "addr1".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();
        pm.add_peer("peer2".into(), "addr2".into(), ConnectionDirection::Inbound)
            .unwrap();
        pm.mark_connected("peer1", 1, 100).unwrap();

        let connected = pm.connected_peers();
        assert_eq!(connected.len(), 1);
    }

    #[test]
    fn test_remove_peer() {
        let mut pm = PeerManager::new();
        pm.add_peer(
            "peer1".into(),
            "addr1".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();
        let removed = pm.remove_peer("peer1");
        assert!(removed.is_some());
        assert_eq!(pm.peer_count(), 0);
    }

    #[test]
    fn test_best_peer_height() {
        let mut pm = PeerManager::new();
        pm.add_peer("p1".into(), "a1".into(), ConnectionDirection::Outbound)
            .unwrap();
        pm.add_peer("p2".into(), "a2".into(), ConnectionDirection::Outbound)
            .unwrap();
        pm.mark_connected("p1", 1, 50).unwrap();
        pm.mark_connected("p2", 1, 150).unwrap();
        assert_eq!(pm.best_peer_height(), 150);
    }

    #[test]
    fn test_eviction() {
        let mut pm = PeerManager::with_max_peers(2);
        pm.add_peer("p1".into(), "a1".into(), ConnectionDirection::Outbound)
            .unwrap();
        pm.add_peer("p2".into(), "a2".into(), ConnectionDirection::Outbound)
            .unwrap();
        // Lower p1's reputation
        pm.peers
            .get("p1")
            .unwrap()
            .reputation
            .store(-100, Ordering::Relaxed);
        // Adding p3 should evict p1
        pm.add_peer("p3".into(), "a3".into(), ConnectionDirection::Outbound)
            .unwrap();
        assert_eq!(pm.peer_count(), 2);
        assert!(pm.get_peer("p1").is_none());
    }

    #[test]
    fn test_reputation_clamp() {
        let info = PeerInfo::new("p1".into(), "a1".into(), ConnectionDirection::Outbound);
        info.adjust_reputation(2000);
        assert_eq!(info.reputation.load(Ordering::Relaxed), 1000);
        info.adjust_reputation(-3000);
        assert_eq!(info.reputation.load(Ordering::Relaxed), -1000);
    }

    // ── Authentication tests ───────────────────────────────────────────

    #[test]
    fn test_peer_starts_unauthenticated() {
        let info = PeerInfo::new("p1".into(), "a1".into(), ConnectionDirection::Inbound);
        assert!(
            !info.is_authenticated,
            "new peers must start unauthenticated"
        );
    }

    #[test]
    fn test_mark_authenticated() {
        let mut pm = PeerManager::new();
        pm.add_peer("p1".into(), "a1".into(), ConnectionDirection::Inbound)
            .unwrap();
        assert!(!pm.get_peer("p1").unwrap().is_authenticated);
        pm.mark_authenticated("p1").unwrap();
        assert!(pm.get_peer("p1").unwrap().is_authenticated);
    }

    #[test]
    fn test_require_authenticated_rejects() {
        let mut pm = PeerManager::new();
        pm.add_peer("p1".into(), "a1".into(), ConnectionDirection::Inbound)
            .unwrap();
        assert!(pm.require_authenticated("p1").is_err());
        pm.mark_authenticated("p1").unwrap();
        assert!(pm.require_authenticated("p1").is_ok());
    }

    // ── Inbound/outbound slot tests ─────────────────────────────────

    #[test]
    fn test_inbound_slot_limit() {
        let mut pm = PeerManager::new();
        for i in 0..MAX_INBOUND_PEERS {
            pm.add_peer(
                format!("in_{i}"),
                format!(
                    "{}.{}.{}.1:30303",
                    i / 256 / 256 % 256,
                    i / 256 % 256,
                    i % 256
                ),
                ConnectionDirection::Inbound,
            )
            .unwrap();
        }
        let result = pm.add_peer(
            "in_extra".into(),
            "99.99.99.1:30303".into(),
            ConnectionDirection::Inbound,
        );
        assert!(result.is_err(), "should reject inbound when slots full");
    }

    #[test]
    fn test_outbound_slot_limit() {
        let mut pm = PeerManager::new();
        for i in 0..MAX_OUTBOUND_PEERS {
            pm.add_peer(
                format!("out_{i}"),
                format!(
                    "{}.{}.{}.1:30303",
                    i / 256 / 256 % 256,
                    i / 256 % 256,
                    i % 256
                ),
                ConnectionDirection::Outbound,
            )
            .unwrap();
        }
        let result = pm.add_peer(
            "out_extra".into(),
            "88.88.88.1:30303".into(),
            ConnectionDirection::Outbound,
        );
        assert!(result.is_err(), "should reject outbound when slots full");
    }

    // ── V-09 subnet diversity tests ───────────────────────────────────

    #[test]
    fn test_v09_subnet_limit_enforced() {
        let mut pm = PeerManager::new();
        for i in 0..MAX_PEERS_PER_SUBNET {
            pm.add_peer(
                format!("p{i}"),
                format!("192.168.1.{i}:30303"),
                ConnectionDirection::Outbound,
            )
            .unwrap();
        }
        let result = pm.add_peer(
            "p_extra".into(),
            "192.168.1.99:30303".into(),
            ConnectionDirection::Outbound,
        );
        assert!(result.is_err(), "should reject peer from full subnet");
    }

    #[test]
    fn test_v09_different_subnets_allowed() {
        let mut pm = PeerManager::new();
        for i in 0..MAX_PEERS_PER_SUBNET {
            pm.add_peer(
                format!("p_a{i}"),
                format!("192.168.1.{i}:30303"),
                ConnectionDirection::Outbound,
            )
            .unwrap();
        }
        for i in 0..MAX_PEERS_PER_SUBNET {
            pm.add_peer(
                format!("p_b{i}"),
                format!("10.0.1.{i}:30303"),
                ConnectionDirection::Outbound,
            )
            .unwrap();
        }
        assert_eq!(pm.peer_count(), MAX_PEERS_PER_SUBNET * 2);
    }

    #[test]
    fn test_v09_extract_subnet() {
        assert_eq!(
            PeerManager::extract_subnet("192.168.1.50:30303"),
            "192.168.1"
        );
        assert_eq!(PeerManager::extract_subnet("10.0.0.1:8080"), "10.0.0");
        assert_eq!(PeerManager::extract_subnet("localhost:30303"), "localhost");
    }

    #[test]
    fn test_extract_subnet_ipv6() {
        // IPv6 addresses extract /48 prefix
        assert_eq!(
            PeerManager::extract_subnet("[2001:db8:85a3::1]:30303"),
            "2001:db8:85a3"
        );
        assert_eq!(
            PeerManager::extract_subnet("[fe80:0000:abcd::1]:8080"),
            "fe80:0000:abcd"
        );
    }

    #[test]
    fn test_reputation_saturating_add() {
        // Ensure i32 overflow doesn't wrap before clamp
        let info = PeerInfo::new("p1".into(), "a1".into(), ConnectionDirection::Outbound);
        info.reputation.store(1000, Ordering::Relaxed);
        info.adjust_reputation(i32::MAX);
        assert_eq!(info.reputation.load(Ordering::Relaxed), 1000); // saturated, not wrapped
        info.reputation.store(-1000, Ordering::Relaxed);
        info.adjust_reputation(i32::MIN);
        assert_eq!(info.reputation.load(Ordering::Relaxed), -1000); // saturated, not wrapped
    }

    // ── Flood counter tests (merged from GossipEngine) ───────────────

    #[test]
    fn test_flood_tx_limit() {
        let mut pm = PeerManager::new();
        pm.add_peer(
            "peer1".into(),
            "10.0.0.1:30303".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();

        // 100 tx should be allowed
        for _ in 0..MAX_TX_PER_PEER_PER_MINUTE {
            assert!(pm.check_flood("peer1", true));
        }
        // 101st tx rejected
        assert!(!pm.check_flood("peer1", true));
    }

    #[test]
    fn test_flood_msg_limit() {
        let mut pm = PeerManager::new();
        pm.add_peer(
            "peer1".into(),
            "10.0.0.1:30303".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();

        for _ in 0..MAX_MESSAGES_PER_PEER_PER_MINUTE {
            assert!(pm.check_flood("peer1", false));
        }
        // Next message rejected
        assert!(!pm.check_flood("peer1", false));
    }

    #[test]
    fn test_flood_reset() {
        let mut pm = PeerManager::new();
        pm.add_peer(
            "peer1".into(),
            "10.0.0.1:30303".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();

        // Fill up counter
        for _ in 0..MAX_MESSAGES_PER_PEER_PER_MINUTE {
            pm.check_flood("peer1", false);
        }
        assert!(!pm.check_flood("peer1", false));

        // Reset and verify messages are allowed again
        pm.reset_flood_counters();
        assert!(pm.check_flood("peer1", false));
    }

    #[test]
    fn test_flood_per_peer_isolation() {
        let mut pm = PeerManager::new();
        pm.add_peer(
            "peer1".into(),
            "10.0.0.1:30303".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();
        pm.add_peer(
            "peer2".into(),
            "10.0.1.1:30303".into(),
            ConnectionDirection::Outbound,
        )
        .unwrap();

        // Exhaust peer1's limit
        for _ in 0..MAX_MESSAGES_PER_PEER_PER_MINUTE {
            pm.check_flood("peer1", false);
        }
        assert!(!pm.check_flood("peer1", false));

        // peer2 is unaffected
        assert!(pm.check_flood("peer2", false));
    }

    #[test]
    fn test_flood_unknown_peer_rejected() {
        let mut pm = PeerManager::new();
        assert!(!pm.check_flood("unknown", false));
    }
}
