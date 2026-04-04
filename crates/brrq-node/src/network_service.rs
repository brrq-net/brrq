//! Network service — integrates brrq-network into the node.
//!
//! ## Architecture
//!
//! The `NetworkService` bridges the P2P network layer with the node's shared
//! state. It manages:
//!
//! - **TCP listener**: Accepts inbound peer connections on the P2P port
//! - **Message framing**: Length-prefixed (4-byte BE + bincode) serialization
//! - **Gossip integration**: Deduplicates and forwards transactions/blocks
//! - **Sync integration**: Tracks peer heights and requests missing blocks
//! - **Peer management**: Tracks connected peers with reputation scoring
//!
//! ## Message Flow
//!
//! ```text
//! Inbound:  TCP → read_message → GossipEngine.process_incoming → handle
//! Outbound: GossipEngine.broadcast → drain_outbound → TCP → peers
//! ```

#![allow(dead_code)] // Public APIs used by main.rs at runtime

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

use bincode::Options;

use brrq_crypto::hash::Hash256;
use brrq_network::message::{
    BlockAnnounce, BlocksResponse, HelloMessage, MAX_MESSAGE_SIZE, PeersResponse,
    RandaoCommitmentMessage, RandaoRevealMessage, TransactionAnnounce,
};
use brrq_network::{ConnectionDirection, GossipEngine, Message, PeerManager, SyncManager};
use brrq_types::block::Block;
use brrq_types::transaction::Transaction;

#[cfg(feature = "sequencer-rotation")]
use crate::node::handle_rotation_message;
use crate::node::{SharedState, apply_block};
use brrq_network::message::GetBlocksRequest;

/// Shared RANDAO EOTS signature verification for Commitment + Reveal handlers.
/// Returns true if verification passes (or is skipped), false if invalid.
#[cfg(feature = "sequencer-rotation")]
pub(crate) fn verify_randao_eots_sig(
    pubkey: &brrq_crypto::schnorr::SchnorrPublicKey,
    msg_hash: &brrq_crypto::hash::Hash256,
    sig: &brrq_types::signature::Signature,
    peer_id: &str,
    msg_type: &str,
) -> bool {
    if let brrq_types::Signature::Schnorr(ref s) = sig {
        let commitment_bytes: Vec<u8> = std::iter::once(0x02)
            .chain(s.0[..32].iter().copied())
            .collect();
        let nonce_commitment = match brrq_crypto::eots::EotsNonceCommitment::from_bytes(
            commitment_bytes.as_slice().try_into().unwrap_or([0u8; 33]),
        ) {
            Ok(nc) => nc,
            Err(_) => {
                tracing::warn!("RANDAO {msg_type} from {peer_id}: invalid nonce commitment");
                return false;
            }
        };
        let eots_sig = match brrq_crypto::eots::EotsSignature::new(
            nonce_commitment,
            s.0[32..64].to_vec(),
        ) {
            Ok(s) => s,
            Err(_) => {
                tracing::warn!("RANDAO {msg_type} from {peer_id}: invalid EOTS s-value");
                return false;
            }
        };
        if brrq_crypto::eots::verify(pubkey, msg_hash, &eots_sig).is_err() {
            tracing::warn!("RANDAO {msg_type} from {peer_id}: invalid EOTS signature");
            return false;
        }
    }
    true
}

/// Network service configuration.
pub struct NetworkConfig {
    /// Port for P2P connections.
    pub p2p_port: u16,
    /// Unique node identifier (hex-encoded secp256k1 public key).
    pub node_id: String,
    /// Network name (e.g., "testnet").
    pub network: String,
    /// Bootstrap node addresses for initial peer discovery.
    pub bootstrap_nodes: Vec<String>,
    /// This node's sequencer address for rotation votes.
    /// When set, used instead of guessing from the first staking HashMap key.
    pub sequencer_address: Option<brrq_types::Address>,
    /// Persistent secp256k1 secret key for P2P identity (32 bytes).
    /// Used to sign Hello messages and prove node identity.
    pub node_secret_key: Option<[u8; 32]>,
}

/// The network service wrapping gossip, sync, and peer management.
///
/// Runs as an async task, connecting the P2P layer to the node's `SharedState`.
pub struct NetworkService {
    /// Configuration.
    config: NetworkConfig,
    /// Gossip engine for message deduplication and propagation.
    gossip: Arc<GossipEngine>,
    /// Sync manager for chain synchronization.
    sync_manager: Arc<RwLock<SyncManager>>,
    /// Peer manager for tracking connected peers.
    peers: Arc<RwLock<PeerManager>>,
    /// Active peer connections (peer_id → write half).
    connections: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<Arc<Vec<u8>>>>>>,
    banned_edge_ips: tokio::sync::watch::Sender<Arc<HashSet<IpAddr>>>,
}

/// Compute the Hello handshake challenge hash: SHA-256(nonce || network || version).
///
/// NOTE: peer_ip was removed from the challenge because the signer and verifier
/// see different IP representations (0.0.0.0 vs 127.0.0.1 vs real IP) depending
/// on connection direction and NAT. The random nonce provides sufficient replay
/// protection — each Hello is unique and valid only for this handshake.
fn hello_challenge_hash(nonce: u64, network: &str, version: u32, _peer_ip: &str) -> Hash256 {
    let mut hasher = brrq_crypto::hash::Hasher::new();
    hasher.update(&nonce.to_le_bytes());
    hasher.update(network.as_bytes());
    hasher.update(&version.to_le_bytes());
    hasher.finalize()
}

/// Sign a Hello handshake challenge with the node's persistent identity key.
fn sign_hello_challenge(
    secret_key: &[u8; 32],
    nonce: u64,
    network: &str,
    version: u32,
    peer_ip: &str,
) -> Vec<u8> {
    let challenge = hello_challenge_hash(nonce, network, version, peer_ip);
    match brrq_crypto::schnorr::SchnorrKeyPair::from_secret_bytes(secret_key) {
        Ok(kp) => match kp.sign(&challenge) {
            Ok(sig) => sig.as_bytes().to_vec(),
            Err(_) => vec![],
        },
        Err(_) => vec![],
    }
}

/// Verify a Hello handshake signature against the claimed node_id (hex public key).
pub(crate) fn verify_hello_signature(
    node_id: &str,
    nonce: u64,
    network: &str,
    version: u32,
    peer_ip: &str,
    signature: &[u8],
) -> bool {
    if signature.is_empty() || signature.len() != 64 {
        return false;
    }

    let pubkey_bytes = match hex::decode(node_id) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return false,
    };

    let challenge = hello_challenge_hash(nonce, network, version, peer_ip);
    let pubkey = brrq_crypto::schnorr::SchnorrPublicKey::from_bytes(pubkey_bytes);
    let sig = match brrq_crypto::schnorr::SchnorrSignature::from_slice(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    brrq_crypto::schnorr::verify(&pubkey, &challenge, &sig).is_ok()
}

impl NetworkService {
    /// Create a new network service.
    pub fn new(config: NetworkConfig) -> Self {
        let (ban_tx, _) = tokio::sync::watch::channel(Arc::new(HashSet::new()));
        Self {
            config,
            gossip: Arc::new(GossipEngine::new()),
            sync_manager: Arc::new(RwLock::new(SyncManager::new())),
            peers: Arc::new(RwLock::new(PeerManager::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            banned_edge_ips: ban_tx,
        }
    }

    /// Get a reference to the gossip engine (for broadcasting from block production).
    pub fn gossip(&self) -> Arc<GossipEngine> {
        self.gossip.clone()
    }

    /// Run the network service. This spawns background tasks and runs forever.
    pub async fn run(self, shared: SharedState) {
        let gossip = self.gossip.clone();
        let sync_mgr = self.sync_manager.clone();
        let peers = self.peers.clone();
        let connections = self.connections.clone();

        // Spawn TCP accept loop
        let accept_gossip = gossip.clone();
        let accept_sync = sync_mgr.clone();
        let accept_peers = peers.clone();
        let accept_conns = connections.clone();
        let accept_shared = shared.clone();
        let p2p_port = self.config.p2p_port;
        let node_id = self.config.node_id.clone();
        let network = self.config.network.clone();

        let accept_config_network = self.config.network.clone();
        let accept_seq_addr = self.config.sequencer_address;
        let accept_node_key = self.config.node_secret_key;
        let accept_banned_ips_rx = self.banned_edge_ips.subscribe();
        let accept_banned_ips_tx = self.banned_edge_ips.clone();
        let accept_handle = tokio::spawn(async move {
            Self::accept_loop(
                p2p_port,
                node_id,
                network,
                accept_gossip,
                accept_sync,
                accept_peers,
                accept_conns,
                accept_shared,
                accept_config_network,
                accept_seq_addr,
                accept_node_key,
                accept_banned_ips_rx,
                accept_banned_ips_tx,
            )
            .await;
        });

        // Spawn flood counter reset (every 60s) — resets per-peer rate limits
        let flood_peers = peers.clone();
        let flood_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                flood_peers.write().await.reset_flood_counters();
            }
        });

        // Spawn unauthenticated peer eviction (every 10s) — disconnect peers
        // that never completed the Hello handshake within HANDSHAKE_TIMEOUT_SECS.
        let evict_peers = peers.clone();
        let _evict_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));
            loop {
                interval.tick().await;
                let evicted = evict_peers.write().await.evict_unauthenticated();
                if !evicted.is_empty() {
                    tracing::info!(
                        count = evicted.len(),
                        "evicted unauthenticated peers (handshake timeout)"
                    );
                }
            }
        });

        // Spawn partition detection (every 30s) — warn when peer count is dangerously low.
        let partition_peers = peers.clone();
        let _partition_handle = tokio::spawn(async move {
            const MIN_PEERS_WARNING: usize = 2;
            const MIN_PEERS_CRITICAL: usize = 0;

            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                let peer_count = partition_peers.read().await.connected_peers().len();
                if peer_count <= MIN_PEERS_CRITICAL {
                    tracing::error!(
                        "PARTITION ALERT: Zero connected peers. Node may be partitioned from the network."
                    );
                } else if peer_count <= MIN_PEERS_WARNING {
                    tracing::warn!(
                        peer_count,
                        "Low peer count. Node may be at risk of network partition."
                    );
                }
            }
        });

        // Spawn outbound message pump (every 100ms)
        let outbound_gossip = gossip.clone();
        let outbound_conns = connections.clone();
        let outbound_shared = shared.clone();
        let outbound_handle = tokio::spawn(async move {
            Self::outbound_pump_loop(outbound_gossip, outbound_conns, outbound_shared).await;
        });

        // Spawn bootstrap connection task
        let bootstrap_nodes = self.config.bootstrap_nodes.clone();
        let bootstrap_gossip = gossip.clone();
        let bootstrap_sync = sync_mgr.clone();
        let bootstrap_peers = peers.clone();
        let bootstrap_conns = connections.clone();
        let bootstrap_shared = shared.clone();
        let bootstrap_node_id = self.config.node_id.clone();
        let bootstrap_network = self.config.network.clone();
        let bootstrap_config_network = self.config.network.clone();
        let bootstrap_seq_addr = self.config.sequencer_address;
        let bootstrap_banned_ips_tx = self.banned_edge_ips.clone();
        let bootstrap_node_key = self.config.node_secret_key;
        let bootstrap_handle = tokio::spawn(async move {
            Self::bootstrap_and_discover_loop(
                bootstrap_nodes,
                bootstrap_node_id,
                bootstrap_network,
                bootstrap_gossip,
                bootstrap_sync,
                bootstrap_peers,
                bootstrap_conns,
                bootstrap_shared,
                bootstrap_config_network,
                bootstrap_seq_addr,
                bootstrap_banned_ips_tx,
                bootstrap_node_key,
            )
            .await;
        });

        tracing::info!("Network service started on port {}", self.config.p2p_port);

        let _ = tokio::join!(
            accept_handle,
            flood_handle,
            outbound_handle,
            bootstrap_handle
        );
    }

    /// Connect to a remote peer.
    pub async fn connect_to_peer(&self, address: &str, shared: SharedState) -> std::io::Result<()> {
        let mut stream = TcpStream::connect(address).await?;

        // Send Hello with signed challenge for identity proof.
        let nonce: u64 = rand::random();
        let ns = shared.read().await;
        let signature = match &self.config.node_secret_key {
            Some(sk) => sign_hello_challenge(sk, nonce, &self.config.network, 1, address),
            None => vec![],
        };
        let hello = Message::Hello(HelloMessage {
            node_id: self.config.node_id.clone(),
            version: 1,
            best_height: ns.height,
            network: self.config.network.clone(),
            nonce,
            signature,
        });
        drop(ns);
        if tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            write_message(&mut stream, &hello),
        )
        .await
        .is_err()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Timeout sending Hello to outbound peer",
            ));
        }

        // Register peer
        let peer_id = format!("outbound_{}", address);
        self.peers
            .write()
            .await
            .add_peer(
                peer_id.clone(),
                address.to_string(),
                ConnectionDirection::Outbound,
            )
            .ok();

        // Spawn handler for this connection
        let gossip = self.gossip.clone();
        let sync_mgr = self.sync_manager.clone();
        let peers = self.peers.clone();
        let conns = self.connections.clone();
        let config_network = self.config.network.clone();
        let sequencer_address = self.config.sequencer_address;
        let banned_ips_tx = self.banned_edge_ips.clone();
        tokio::spawn(async move {
            Self::handle_connection(
                peer_id,
                stream,
                gossip,
                sync_mgr,
                peers,
                conns,
                shared,
                config_network,
                sequencer_address,
                banned_ips_tx,
                false,
            )
            .await;
        });

        Ok(())
    }

    /// Outbound message pump — drain gossip engine outbound queue and send to all peers.
    async fn outbound_pump_loop(
        gossip: Arc<GossipEngine>,
        connections: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<Arc<Vec<u8>>>>>>,
        shared: SharedState,
    ) {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_millis(100));
        loop {
            interval.tick().await;

            // Drain pending block announcements from shared state
            let announcements: Vec<(Hash256, u64, brrq_types::Address)> = {
                let mut ns = shared.write().await;
                ns.pending_block_announcements.drain(..).collect()
            };
            for (hash, height, producer) in announcements {
                let msg = make_block_announce(hash, height, producer);
                gossip.broadcast(msg);
            }

            // Drain stem-phase Dandelion messages and forward each to a DIFFERENT
            // random peer (Dandelion++ privacy: batching to one peer is a deanon vector).
            let stems = gossip.drain_stem_queue();
            if !stems.is_empty() {
                let conns_stem = connections.read().await;
                if !conns_stem.is_empty() {
                    let peer_keys: Vec<_> = conns_stem.keys().collect();
                    for (i, dm) in stems.iter().enumerate() {
                        let idx = (dm.delay_ms as usize).wrapping_add(i) % peer_keys.len();
                        if let Some(tx) = conns_stem.get(peer_keys[idx]) {
                            if let Ok(raw) = bincode::options()
                                .with_limit(32 * 1024 * 1024)
                                .serialize(&dm.message)
                            {
                                let _ = tx.try_send(Arc::new(raw));
                            }
                        }
                    }
                }
            }

            // Drain outbound messages from gossip engine and send to all connected peers
            let outbound = gossip.drain_outbound();
            if outbound.is_empty() {
                continue;
            }
            let conns = connections.read().await;
            for msg in outbound {
                if let Ok(raw) = bincode::options()
                    .with_limit(32 * 1024 * 1024)
                    .serialize(&msg)
                {
                    let raw = Arc::new(raw);
                    for (_peer_id, tx) in conns.iter() {
                        let _ = tx.try_send(raw.clone());
                    }
                }
            }
        }
    }

    /// Send a Hello message over a stream with a 5-second timeout.
    /// Returns `Ok(())` on success, or an error description on failure.
    async fn send_hello_with_timeout(
        stream: &mut TcpStream,
        node_id: &str,
        network: &str,
        shared: &SharedState,
        secret_key: Option<&[u8; 32]>,
        peer_address: &str,
    ) -> Result<(), &'static str> {
        let ns = shared.read().await;
        let nonce: u64 = rand::random();
        // Sign bootstrap Hello to pass authentication.
        let signature = match secret_key {
            Some(sk) => sign_hello_challenge(sk, nonce, network, 1, peer_address),
            None => vec![],
        };
        let hello = Message::Hello(HelloMessage {
            node_id: node_id.to_string(),
            version: 1,
            best_height: ns.height,
            network: network.to_string(),
            nonce,
            signature,
        });
        drop(ns);
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            write_message(stream, &hello),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(_)) => Err("failed to send Hello"),
            Err(_) => Err("timeout sending Hello"),
        }
    }

    /// Spawn a connection handler for a newly connected peer.
    #[allow(clippy::too_many_arguments)]
    fn spawn_peer_handler(
        peer_id: String,
        stream: TcpStream,
        gossip: Arc<GossipEngine>,
        sync_mgr: Arc<RwLock<SyncManager>>,
        peers: Arc<RwLock<PeerManager>>,
        connections: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<Arc<Vec<u8>>>>>>,
        shared: SharedState,
        config_network: String,
        sequencer_address: Option<brrq_types::Address>,
        banned_ips_tx: tokio::sync::watch::Sender<Arc<HashSet<IpAddr>>>,
        requires_validator_proof: bool,
    ) {
        tokio::spawn(async move {
            NetworkService::handle_connection(
                peer_id,
                stream,
                gossip,
                sync_mgr,
                peers,
                connections,
                shared,
                config_network,
                sequencer_address,
                banned_ips_tx,
                requires_validator_proof,
            )
            .await;
        });
    }

    /// Bootstrap connection task: connect to bootstrap nodes, then periodically discover new peers.
    #[allow(clippy::too_many_arguments)]
    async fn bootstrap_and_discover_loop(
        bootstrap_nodes: Vec<String>,
        node_id: String,
        network: String,
        gossip: Arc<GossipEngine>,
        sync_mgr: Arc<RwLock<SyncManager>>,
        peers: Arc<RwLock<PeerManager>>,
        connections: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<Arc<Vec<u8>>>>>>,
        shared: SharedState,
        config_network: String,
        sequencer_address: Option<brrq_types::Address>,
        banned_ips_tx: tokio::sync::watch::Sender<Arc<HashSet<IpAddr>>>,
        node_secret_key: Option<[u8; 32]>,
    ) {
        // Wait briefly for the listener to bind
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        // Connect to all bootstrap nodes on startup
        for addr in &bootstrap_nodes {
            tracing::info!("Connecting to bootstrap node: {}", addr);
            let mut stream = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("Failed to connect to bootstrap {}: {}", addr, e);
                    continue;
                }
            };

            if let Err(reason) = Self::send_hello_with_timeout(&mut stream, &node_id, &network, &shared, node_secret_key.as_ref(), addr).await {
                tracing::warn!("{} to bootstrap {}", reason, addr);
                continue;
            }

            let peer_id = format!("bootstrap_{}", addr);
            peers
                .write()
                .await
                .add_peer(peer_id.clone(), addr.to_string(), ConnectionDirection::Outbound)
                .ok();

            Self::spawn_peer_handler(
                peer_id, stream,
                gossip.clone(), sync_mgr.clone(), peers.clone(), connections.clone(),
                shared.clone(), config_network.clone(), sequencer_address, banned_ips_tx.clone(),
                false,
            );
            tracing::info!("Connected to bootstrap node: {}", addr);
        }

        // Periodic peer discovery: request more peers every 30s and connect to discovered ones
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            Self::discover_and_connect_peers(
                &node_id, &network, &gossip, &sync_mgr, &peers, &connections,
                &shared, &config_network, sequencer_address, &banned_ips_tx,
                node_secret_key.as_ref(),
            )
            .await;
        }
    }

    /// Single round of peer discovery: ask for more peers, connect to discovered ones.
    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    async fn discover_and_connect_peers(
        node_id: &str,
        network: &str,
        gossip: &Arc<GossipEngine>,
        sync_mgr: &Arc<RwLock<SyncManager>>,
        peers: &Arc<RwLock<PeerManager>>,
        connections: &Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<Arc<Vec<u8>>>>>>,
        shared: &SharedState,
        config_network: &str,
        sequencer_address: Option<brrq_types::Address>,
        banned_ips_tx: &tokio::sync::watch::Sender<Arc<HashSet<IpAddr>>>,
        node_secret_key: Option<&[u8; 32]>,
    ) {
        let conn_count = connections.read().await.len();
        if conn_count >= 8 {
            return;
        }

        // Ask a random connected peer for more peers
        let conns = connections.read().await;
        if let Some((_peer_id, tx)) = conns.iter().next() {
            if let Ok(raw) = bincode::options()
                .with_limit(32 * 1024 * 1024)
                .serialize(&Message::GetPeers)
            {
                let _ = tx.try_send(Arc::new(raw));
            }
        }
        drop(conns);

        // Try to connect to known but unconnected peers
        let known_addrs = peers.read().await.peer_addresses();
        for addr in &known_addrs {
            if connections.read().await.len() >= 8 {
                break;
            }
            let already_connected = connections
                .read()
                .await
                .keys()
                .any(|k| k.contains(addr));
            if already_connected {
                continue;
            }
            let mut new_stream = match TcpStream::connect(addr).await {
                Ok(s) => s,
                Err(_) => continue,
            };

            if let Err(reason) = Self::send_hello_with_timeout(&mut new_stream, node_id, network, shared, node_secret_key, addr).await {
                tracing::warn!("{} to discovered peer {}", reason, addr);
                continue;
            }

            let disc_peer_id = format!("discovered_{}", addr);
            tracing::info!("Connected to discovered peer: {}", addr);

            Self::spawn_peer_handler(
                disc_peer_id, new_stream,
                gossip.clone(), sync_mgr.clone(), peers.clone(), connections.clone(),
                shared.clone(), config_network.to_string(), sequencer_address, banned_ips_tx.clone(),
                false,
            );
        }
    }

    /// TCP accept loop — listen for inbound connections.
    #[allow(clippy::too_many_arguments)]
    async fn accept_loop(
        p2p_port: u16,
        node_id: String,
        network: String,
        gossip: Arc<GossipEngine>,
        sync_mgr: Arc<RwLock<SyncManager>>,
        peers: Arc<RwLock<PeerManager>>,
        connections: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<Arc<Vec<u8>>>>>>,
        shared: SharedState,
        config_network: String,
        sequencer_address: Option<brrq_types::Address>,
        node_secret_key: Option<[u8; 32]>,
        banned_ips_rx: tokio::sync::watch::Receiver<Arc<HashSet<IpAddr>>>,
        banned_ips_tx: tokio::sync::watch::Sender<Arc<HashSet<IpAddr>>>,
    ) {
        let listener = match TcpListener::bind(format!("0.0.0.0:{}", p2p_port)).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind P2P port {}: {}", p2p_port, e);
                return;
            }
        };

        tracing::info!("P2P listener bound on port {}", p2p_port);

        loop {
            let (stream, addr) = match listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!("Accept error: {}", e);
                    continue;
                }
            };

            // Zero-Allocation Edge Dropping (O(1) TCP Termination)
            if banned_ips_rx.borrow().contains(&addr.ip()) {
                tracing::debug!(
                    "SYN-flood protection: Dropped connection from banned IP {}",
                    addr.ip()
                );
                drop(stream);
                continue;
            }

            let requires_validator_proof = match Self::check_inbound_limits(
                &connections, &peers, &addr,
            )
            .await
            {
                None => {
                    drop(stream);
                    continue; // rejected by capacity or eclipse check
                }
                Some(v) => v,
            };

            tracing::debug!("Inbound connection from {}", addr);

            let mut stream = stream;
            if let Err(()) = Self::send_signed_hello(
                &mut stream, &node_id, &network, &node_secret_key, &shared, &addr,
            )
            .await
            {
                continue;
            }

            let peer_id = format!("inbound_{}", addr);
            if let Err(e) = peers.write().await.add_peer(
                peer_id.clone(),
                addr.to_string(),
                ConnectionDirection::Inbound,
            ) {
                tracing::warn!("Rejecting inbound connection from {}: {}", addr, e);
                drop(stream);
                continue;
            }

            Self::spawn_peer_handler(
                peer_id, stream,
                gossip.clone(), sync_mgr.clone(), peers.clone(), connections.clone(),
                shared.clone(), config_network.clone(), sequencer_address, banned_ips_tx.clone(),
                requires_validator_proof,
            );
        }
    }

    /// Check capacity and eclipse limits for an inbound connection.
    /// Returns `Some(requires_validator_proof)` if accepted, `None` if rejected.
    async fn check_inbound_limits(
        connections: &Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<Arc<Vec<u8>>>>>>,
        peers: &Arc<RwLock<PeerManager>>,
        addr: &std::net::SocketAddr,
    ) -> Option<bool> {
        // HIGH: Reject inbound connections when at capacity, but leave room for Validators.
        const RESERVED_VALIDATOR_SLOTS: usize = 10;
        let mut requires_validator_proof = false;

        let conn_count = connections.read().await.len();
        if conn_count >= brrq_network::peer::MAX_PEERS + RESERVED_VALIDATOR_SLOTS {
            tracing::warn!(
                "P2P connection absolute limit reached ({}/{}), rejecting {}",
                conn_count,
                brrq_network::peer::MAX_PEERS + RESERVED_VALIDATOR_SLOTS,
                addr,
            );
            return None;
        } else if conn_count >= brrq_network::peer::MAX_PEERS {
            requires_validator_proof = true;
            tracing::debug!(
                "P2P connection soft limit reached ({}/{}), requiring validator proof for {}",
                conn_count,
                brrq_network::peer::MAX_PEERS,
                addr,
            );
        }

        // HIGH: Strict Subnet eclipse protection at the TCP connection layer!
        let new_subnet = brrq_network::PeerManager::extract_subnet(&addr.to_string());
        let peers_lock = peers.read().await;
        let subnet_count = peers_lock
            .connected_peers()
            .iter()
            .filter(|p| brrq_network::PeerManager::extract_subnet(&p.address) == new_subnet)
            .count();

        if subnet_count >= brrq_network::peer::MAX_PEERS_PER_SUBNET {
            tracing::warn!(
                "Eclipse protection: Rejected connection from over-represented subnet {} (limit: {})",
                new_subnet,
                brrq_network::peer::MAX_PEERS_PER_SUBNET
            );
            return None;
        }

        Some(requires_validator_proof)
    }

    /// Send a signed Hello handshake to an inbound peer with timeout.
    /// Returns `Ok(())` on success, `Err(())` on failure (already logged).
    async fn send_signed_hello(
        stream: &mut TcpStream,
        node_id: &str,
        network: &str,
        node_secret_key: &Option<[u8; 32]>,
        shared: &SharedState,
        addr: &std::net::SocketAddr,
    ) -> Result<(), ()> {
        let nonce: u64 = rand::random();
        let ns = shared.read().await;
        let signature = match node_secret_key {
            Some(sk) => sign_hello_challenge(sk, nonce, network, 1, &addr.to_string()),
            None => vec![],
        };
        let hello = Message::Hello(HelloMessage {
            node_id: node_id.to_string(),
            version: 1,
            best_height: ns.height,
            network: network.to_string(),
            nonce,
            signature,
        });
        drop(ns);
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(5),
            write_message(stream, &hello),
        )
        .await
        {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => {
                tracing::debug!("Failed to send Hello to {}: {}", addr, e);
                Err(())
            }
            Err(_) => {
                tracing::warn!(
                    "Timeout (Slowloris protection) sending Hello to {}",
                    addr
                );
                Err(())
            }
        }
    }

    /// Handle messages from a single peer connection.
    #[allow(unused_variables)] // sequencer_address used only with sequencer-rotation feature
    async fn handle_connection(
        peer_id: String,
        stream: TcpStream,
        gossip: Arc<GossipEngine>,
        sync_mgr: Arc<RwLock<SyncManager>>,
        peers: Arc<RwLock<PeerManager>>,
        connections: Arc<RwLock<HashMap<String, tokio::sync::mpsc::Sender<Arc<Vec<u8>>>>>>,
        shared: SharedState,
        config_network: String,
        sequencer_address: Option<brrq_types::Address>,
        banned_ips_tx: tokio::sync::watch::Sender<Arc<HashSet<IpAddr>>>,
        requires_validator_proof: bool,
    ) {
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Arc<Vec<u8>>>(2048);
        let egress_tx = tx.clone();
        connections
            .write()
            .await
            .insert(peer_id.clone(), tx);

        let egress_peer_id = peer_id.clone();
        tokio::spawn(async move {
            while let Some(raw_msg) = rx.recv().await {
                if let Err(e) = write_raw_message(&mut writer, &raw_msg).await {
                    tracing::debug!("Egress failed for {}: {}", egress_peer_id, e);
                    break;
                }
            }
        });

        // Track this peer in the live peer count (read by /metrics).
        {
            let mut ns = shared.write().await;
            ns.peer_count = ns.peer_count.saturating_add(1);
            if let Some(ref m) = ns.metrics {
                m.peer_count.store(ns.peer_count, Ordering::Relaxed);
            }
        }

        loop {
            // P2P-FIX: Increased from 30s to 300s (5 minutes).
            // 30s caused false-positive Slowloris bans on legitimate P2P peers
            // that were idle between block announcements. Real Slowloris attacks
            // send partial data continuously — idle connections send nothing.
            // The 5-minute timeout still catches genuine Slowloris while allowing
            // normal P2P idle periods.
            let msg = match Self::read_peer_message(&mut reader, &peer_id, &banned_ips_tx).await {
                Some(m) => m,
                None => break,
            };

            // Dedup first — don't penalize peers for forwarding messages we already have
            let should_forward = gossip.process_incoming(&msg, &peer_id);

            // Record activity and check flood limits (only for non-duplicate messages)
            if should_forward {
                let mut pm = peers.write().await;
                pm.record_message(&peer_id).ok();
                let is_tx = matches!(msg, Message::NewTransaction(_));
                if !pm.check_flood(&peer_id, is_tx) {
                    continue; // rate-limited — drop message
                }
            }

            match &msg {
                Message::Hello(hello) => {
                    match crate::message_handlers::handle_hello(
                        hello, &peer_id, &shared, &peers, &sync_mgr,
                        &egress_tx, &config_network, sequencer_address,
                        requires_validator_proof,
                    ).await {
                        crate::message_handlers::HelloResult::Disconnect => break,
                        crate::message_handlers::HelloResult::Continue => {}
                    }
                }
                Message::NewTransaction(tx_announce) => {
                    if should_forward {
                        if crate::message_handlers::handle_new_transaction(
                            &tx_announce, &peer_id, &shared, &peers, &gossip, msg.clone(),
                        ).await {
                            break; // was `return` — skipped cleanup. Now breaks to cleanup block.
                        }
                    }
                }
                Message::NewBlock(block_announce) => {
                    if should_forward {
                        if crate::message_handlers::handle_new_block(
                            block_announce, &peer_id, &shared, &sync_mgr,
                            &gossip, &egress_tx, msg.clone(),
                        ).await {
                            break; // was `return` — skipped cleanup. Now breaks to cleanup block.
                        }
                    }
                }
                Message::GetBlocks(req) => {
                    crate::message_handlers::handle_get_blocks(
                        req, &peer_id, &shared, &egress_tx,
                    ).await;
                }
                Message::Blocks(resp) => {
                    if crate::message_handlers::handle_blocks_response(
                        &resp, &peer_id, &shared, &peers, &sync_mgr,
                    ).await {
                        break; // peer banned — disconnect (cleanup needed)
                    }
                }
                Message::GetPeers => {
                    let addrs = peers.read().await.peer_addresses();
                    let resp = Message::Peers(PeersResponse { peers: addrs });
                    if let Ok(raw) = bincode::options()
                        .with_limit(32 * 1024 * 1024)
                        .serialize(&resp)
                    {
                        let _ = egress_tx.try_send(Arc::new(raw));
                    }
                }
                Message::Peers(resp) => {
                    tracing::debug!(
                        "Received {} peer addresses from {}",
                        resp.peers.len(),
                        peer_id
                    );
                    // Store discovered peers for the background discovery loop to connect
                    let current_count = connections.read().await.len();
                    if current_count < 8 {
                        let mut pm = peers.write().await;
                        for addr in &resp.peers {
                            // Record as known peer (discovery loop will connect)
                            let disc_id = format!("discovered_{}", addr);
                            pm.add_peer(disc_id, addr.clone(), ConnectionDirection::Outbound)
                                .ok();
                        }
                    }
                }
                Message::Ping(nonce) => {
                    let pong = Message::Pong(*nonce);
                    if let Ok(raw) = bincode::options()
                        .with_limit(32 * 1024 * 1024)
                        .serialize(&pong)
                    {
                        let _ = egress_tx.try_send(Arc::new(raw));
                    }
                }
                Message::Pong(_) => {
                    // Heartbeat response — already recorded via record_message
                }

                // ── Consensus rotation messages ────────────────────────
                Message::BlockProposal(_)
                | Message::BlockPreVote(_)
                | Message::BlockPreCommit(_)
                | Message::TimeoutVote(_) => {
                    #[cfg(feature = "sequencer-rotation")]
                    {
                        // Gate consensus messages behind flood check.
                        if !should_forward {
                            tracing::debug!(
                                "Dropping flood-limited consensus message from {peer_id}"
                            );
                            continue;
                        }
                        let mut ns = shared.write().await;
                        if ns.rotation_enabled {
                            // Use configured sequencer address instead of
                            // non-deterministic first HashMap key.
                            let my_addr = sequencer_address
                                .or_else(|| ns.staking.validators.keys().next().copied())
                                .unwrap_or(brrq_types::Address::ZERO);
                            if let Some(action) =
                                crate::node::handle_rotation_message(&mut ns, my_addr, &msg)
                            {
                                tracing::debug!("Rotation action from {peer_id}: {:?}", action,);
                                crate::node::broadcast_rotation_action(&mut ns, action);
                            }
                        } else {
                            tracing::debug!(
                                "Received rotation message from {peer_id} (rotation not active)"
                            );
                        }
                    }
                    #[cfg(not(feature = "sequencer-rotation"))]
                    {
                        tracing::debug!(
                            "Ignoring rotation message from {peer_id} (sequencer-rotation feature disabled)"
                        );
                    }
                }
                Message::MevOrderingCommitment(commitment) => {
                    if !should_forward {
                        tracing::debug!(
                            "Dropping flood-limited MevOrderingCommitment from {peer_id}"
                        );
                        continue;
                    }
                    // Record the ordering commitment in the MEV state and rebroadcast.
                    let mut ns = shared.write().await;
                    if matches!(ns.mev_mode, brrq_api::MevActivationMode::Decentralized) {
                        tracing::debug!(
                            "MEV ordering commitment from {} at height={}: {:?}",
                            commitment.sequencer,
                            commitment.height,
                            commitment.ordering_commitment,
                        );
                        // Store the commitment height so peers can verify ordering
                        if ns.mev_ordering_locked_at.is_none()
                            || ns.mev_ordering_locked_at == Some(commitment.height)
                        {
                            ns.mev_ordering_locked_at = Some(commitment.height);
                        }
                        drop(ns);
                        // Rebroadcast to other peers
                        gossip.broadcast(msg.clone());
                    }
                }
                Message::SlashingEvidence(evidence) => {
                    // Gate slashing evidence behind flood check.
                    if !should_forward {
                        tracing::debug!("Dropping flood-limited slashing evidence from {peer_id}");
                        continue;
                    }
                    if crate::message_handlers::handle_slashing_evidence(
                        evidence, &peer_id, &shared,
                    ).await {
                        break; // peer banned — disconnect (cleanup needed)
                    }
                }
                Message::RandaoCommitment(randao_msg) => {
                    if !should_forward {
                        tracing::debug!("Dropping flood-limited RANDAO commitment from {peer_id}");
                        continue;
                    }
                    #[cfg(feature = "sequencer-rotation")]
                    crate::message_handlers::handle_randao_commitment(
                        &randao_msg, &peer_id, &shared,
                    ).await;
                    #[cfg(not(feature = "sequencer-rotation"))]
                    {
                        let mut ns = shared.write().await;
                        if let Err(e) = ns
                            .epoch
                            .submit_randao_commitment(randao_msg.validator, randao_msg.commitment)
                        {
                            tracing::warn!("RANDAO commitment from {peer_id} rejected: {e}");
                        }
                    }
                }
                Message::RandaoReveal(reveal_msg) => {
                    if !should_forward {
                        tracing::debug!("Dropping flood-limited RANDAO reveal from {peer_id}");
                        continue;
                    }
                    #[cfg(feature = "sequencer-rotation")]
                    crate::message_handlers::handle_randao_reveal(
                        &reveal_msg, &peer_id, &shared,
                    ).await;
                    #[cfg(not(feature = "sequencer-rotation"))]
                    {
                        let mut ns = shared.write().await;
                        let current_height = ns.height;
                        ns.epoch.submit_randao_reveal(
                            reveal_msg.validator,
                            reveal_msg.secret,
                            current_height,
                        );
                    }
                }
                Message::ShareDistribution(share_msg) => {
                    if !should_forward {
                        tracing::debug!(
                            "Dropping flood-limited ShareDistribution from {peer_id}"
                        );
                        continue;
                    }
                    tracing::debug!(
                        "Received share distribution from {} for epoch {}",
                        peer_id,
                        share_msg.epoch,
                    );
                    // Share distribution is processed by the MEV threshold encryption
                    // subsystem. For now, log and forward — the decryption logic will
                    // collect shares when enough arrive.
                }

                // ── Snapshot Sync Messages ────────────────────
                Message::RequestSnapshot(_req) => {
                    // Snapshot serving requires RocksDB checkpoint API integration.
                    // For now, log and ignore — snapshot serving requires
                    // RocksDB checkpoint API integration.
                    tracing::debug!("Snapshot sync not available");
                }
                Message::SnapshotChunk(_chunk) => {
                    // Snapshot chunk reassembly requires state_root matching and fast bootstrap.
                    // Requires: chunk verification, state_root matching, fast bootstrap.
                    tracing::debug!("Snapshot sync not available");
                }
            }
        }

        // Cleanup on disconnect
        connections.write().await.remove(&peer_id);
        peers.write().await.remove_peer(&peer_id);
        {
            let mut ns = shared.write().await;
            ns.peer_count = ns.peer_count.saturating_sub(1);
            if let Some(ref m) = ns.metrics {
                m.peer_count.store(ns.peer_count, Ordering::Relaxed);
            }
        }
        tracing::debug!("Peer {} removed", peer_id);
    }

    /// Read a single P2P message with timeout, banning Slowloris attackers.
    /// Returns `Some(msg)` on success, `None` to signal disconnect.
    async fn read_peer_message(
        reader: &mut tokio::net::tcp::OwnedReadHalf,
        peer_id: &str,
        banned_ips_tx: &tokio::sync::watch::Sender<Arc<HashSet<IpAddr>>>,
    ) -> Option<Message> {
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(300),
            read_message_split(reader),
        )
        .await
        {
            Ok(Ok(m)) => Some(m),
            Ok(Err(e)) => {
                tracing::debug!("Peer {} disconnected: {}", peer_id, e);
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::UnexpectedEof
                {
                    tracing::warn!(
                        "Socket transmission broke from {peer_id}, dropping edge securely."
                    );
                }
                None
            }
            Err(_) => {
                // The timeout elapsed before any complete P2P message could be processed.
                // This strictly identifies the Slowloris Drip-Feed behavior natively.
                tracing::warn!(
                    "Absolute socket deadline exceeded (30s) from {peer_id}. Banning Slowloris attacker IP."
                );
                let ip_part = peer_id.replace("inbound_", "").replace("outbound_", "");
                let ip_only = ip_part.split(':').next().unwrap_or("");
                if let Ok(ip_addr) = ip_only.parse::<IpAddr>() {
                    let mut hs = (**banned_ips_tx.borrow()).clone();
                    hs.insert(ip_addr);
                    let _ = banned_ips_tx.send(Arc::new(hs));
                }
                None
            }
        }
    }
}

// ── Message framing ──────────────────────────────────────────────────────

/// Write a length-prefixed bincode message to a stream.

/// Write a length-prefixed raw data message to a stream.
pub async fn write_raw_message(
    stream: &mut tokio::net::tcp::OwnedWriteHalf,
    data: &[u8],
) -> std::io::Result<()> {
    let len = (data.len() as u32).to_be_bytes();
    use tokio::io::AsyncWriteExt;
    stream.write_all(&len).await?;
    stream.write_all(data).await?;
    stream.flush().await
}

/// Read a length-prefixed bincode message from a stream.
pub async fn read_message_split(
    reader: &mut tokio::net::tcp::OwnedReadHalf,
) -> std::io::Result<Message> {
    let mut len_buf = [0u8; 4];
    use tokio::io::AsyncReadExt;
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reader.read_exact(&mut len_buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "P2P read timeout (Slowloris protection)",
            ));
        }
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {} > {}", len, MAX_MESSAGE_SIZE),
        ));
    }
    let mut buf = vec![0u8; len];
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        reader.read_exact(&mut buf),
    )
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "P2P read timeout (Slowloris protection)",
            ));
        }
    }
    bincode::options()
        .with_limit(32 * 1024 * 1024)
        .deserialize(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

pub async fn write_message(stream: &mut TcpStream, msg: &Message) -> std::io::Result<()> {
    let data = bincode::options()
        .with_limit(32 * 1024 * 1024)
        .serialize(msg)
        .map_err(std::io::Error::other)?;
    let len = (data.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&data).await?;
    stream.flush().await
}

/// Read a length-prefixed bincode message from a stream.
pub async fn read_message(stream: &mut TcpStream) -> std::io::Result<Message> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_MESSAGE_SIZE {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("message too large: {} > {}", len, MAX_MESSAGE_SIZE),
        ));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    bincode::options()
        .with_limit(32 * 1024 * 1024)
        .deserialize(&buf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Broadcast a new transaction announcement via the gossip engine.
pub fn make_tx_announce(tx: &Transaction) -> Message {
    let tx_hash = tx.hash();
    let data = bincode::options()
        .with_limit(32 * 1024 * 1024)
        .serialize(tx)
        .unwrap_or_default();
    // sender field removed — address derived from signature at execution time.
    Message::NewTransaction(TransactionAnnounce {
        tx_hash,
        max_fee_per_gas: tx.body.max_fee_per_gas,
        max_priority_fee_per_gas: tx.body.max_priority_fee_per_gas,
        data,
    })
}

/// Broadcast a new block announcement via the gossip engine.
pub fn make_block_announce(
    block_hash: Hash256,
    height: u64,
    producer: brrq_types::address::Address,
) -> Message {
    Message::NewBlock(BlockAnnounce {
        block_hash,
        height,
        producer,
        header_data: block_hash.as_bytes().to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_write_and_read_message() {
        let (mut client, mut server) = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            (client, server)
        };

        // Write a Ping message
        write_message(&mut client, &Message::Ping(42))
            .await
            .unwrap();

        // Read it on the server side
        let msg = read_message(&mut server).await.unwrap();
        match msg {
            Message::Ping(n) => assert_eq!(n, 42),
            _ => panic!("expected Ping"),
        }
    }

    #[tokio::test]
    async fn test_write_and_read_hello() {
        let (mut client, mut server) = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            (client, server)
        };

        let hello = Message::Hello(HelloMessage {
            node_id: "node_abc".into(),
            version: 1,
            best_height: 100,
            network: "testnet".into(),
            nonce: 0,
            signature: vec![],
        });
        write_message(&mut client, &hello).await.unwrap();

        let msg = read_message(&mut server).await.unwrap();
        match msg {
            Message::Hello(h) => {
                assert_eq!(h.node_id, "node_abc");
                assert_eq!(h.best_height, 100);
            }
            _ => panic!("expected Hello"),
        }
    }

    #[tokio::test]
    async fn test_multiple_messages_roundtrip() {
        let (mut client, mut server) = {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = TcpStream::connect(addr).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            (client, server)
        };

        // Send 3 messages
        write_message(&mut client, &Message::Ping(1)).await.unwrap();
        write_message(&mut client, &Message::Pong(2)).await.unwrap();
        write_message(&mut client, &Message::GetPeers)
            .await
            .unwrap();

        // Read them in order
        let m1 = read_message(&mut server).await.unwrap();
        let m2 = read_message(&mut server).await.unwrap();
        let m3 = read_message(&mut server).await.unwrap();

        assert!(matches!(m1, Message::Ping(1)));
        assert!(matches!(m2, Message::Pong(2)));
        assert!(matches!(m3, Message::GetPeers));
    }

    #[tokio::test]
    async fn test_network_service_creation() {
        let config = NetworkConfig {
            p2p_port: 0,
            node_id: "test_node".into(),
            network: "testnet".into(),
            bootstrap_nodes: Vec::new(),
            sequencer_address: None,
            node_secret_key: None,
        };
        let service = NetworkService::new(config);
        assert_eq!(service.peers.read().await.peer_count(), 0);
    }

    #[tokio::test]
    async fn test_two_node_communication() {
        use crate::node::NodeState;

        // Node A
        let shared_a: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let config_a = NetworkConfig {
            p2p_port: 0, // OS-assigned
            node_id: "node_a".into(),
            network: "testnet".into(),
            bootstrap_nodes: Vec::new(),
            sequencer_address: None,
            node_secret_key: None,
        };
        let service_a = NetworkService::new(config_a);

        // Bind to OS-assigned port
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();

        // Spawn accept handler for node A
        let gossip_a = service_a.gossip.clone();
        let peers_a = service_a.peers.clone();
        let sync_a = service_a.sync_manager.clone();
        let conns_a = service_a.connections.clone();
        let shared_a_clone = shared_a.clone();

        tokio::spawn(async move {
            if let Ok((mut stream, addr)) = listener_a.accept().await {
                // Send Hello
                let hello = Message::Hello(HelloMessage {
                    node_id: "node_a".into(),
                    version: 1,
                    best_height: 0,
                    network: "testnet".into(),
                    nonce: 0,
                    signature: vec![],
                });
                write_message(&mut stream, &hello).await.ok();

                let peer_id = format!("inbound_{}", addr);
                peers_a
                    .write()
                    .await
                    .add_peer(
                        peer_id.clone(),
                        addr.to_string(),
                        ConnectionDirection::Inbound,
                    )
                    .ok();

                let (banned_tx, _) =
                    tokio::sync::watch::channel(Arc::new(std::collections::HashSet::new()));
                NetworkService::handle_connection(
                    peer_id,
                    stream,
                    gossip_a,
                    sync_a,
                    peers_a,
                    conns_a,
                    shared_a_clone,
                    String::new(),
                    None,
                    banned_tx,
                    false, // Testing Node validation bypass
                )
                .await;
            }
        });

        // Node B connects to Node A
        let mut stream_b = TcpStream::connect(format!("127.0.0.1:{}", port_a))
            .await
            .unwrap();

        // Send Hello from B (same height as A so no sync triggered)
        let hello_b = Message::Hello(HelloMessage {
            node_id: "node_b".into(),
            version: 1,
            best_height: 0,
            network: "testnet".into(),
            nonce: 0,
            signature: vec![],
        });
        write_message(&mut stream_b, &hello_b).await.unwrap();

        // Read Hello from A
        let msg = read_message(&mut stream_b).await.unwrap();
        match msg {
            Message::Hello(h) => {
                assert_eq!(h.node_id, "node_a");
                assert_eq!(h.best_height, 0);
            }
            _ => panic!("expected Hello from node A"),
        }

        // Send a Ping from B
        write_message(&mut stream_b, &Message::Ping(123))
            .await
            .unwrap();

        // Should get Pong back
        let pong = read_message(&mut stream_b).await.unwrap();
        assert!(matches!(pong, Message::Pong(123)));

        // Send GetPeers from B
        write_message(&mut stream_b, &Message::GetPeers)
            .await
            .unwrap();

        // Should get Peers response
        let peers_msg = read_message(&mut stream_b).await.unwrap();
        assert!(matches!(peers_msg, Message::Peers(_)));
    }

    #[tokio::test]
    async fn test_sync_request_on_hello() {
        // Verify that a node behind sends GetBlocks after receiving Hello from an ahead peer
        use crate::node::NodeState;

        let shared_a: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let config_a = NetworkConfig {
            p2p_port: 0,
            node_id: "sync_node_a".into(),
            network: "testnet".into(),
            bootstrap_nodes: Vec::new(),
            sequencer_address: None,
            node_secret_key: None,
        };
        let service_a = NetworkService::new(config_a);

        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();

        let gossip_a = service_a.gossip.clone();
        let peers_a = service_a.peers.clone();
        let sync_a = service_a.sync_manager.clone();
        let conns_a = service_a.connections.clone();
        let shared_a_clone = shared_a.clone();

        tokio::spawn(async move {
            if let Ok((mut stream, addr)) = listener_a.accept().await {
                let hello = Message::Hello(HelloMessage {
                    node_id: "sync_node_a".into(),
                    version: 1,
                    best_height: 0,
                    network: "testnet".into(),
                    nonce: 0,
                    signature: vec![],
                });
                write_message(&mut stream, &hello).await.ok();
                let peer_id = format!("inbound_{}", addr);
                peers_a
                    .write()
                    .await
                    .add_peer(
                        peer_id.clone(),
                        addr.to_string(),
                        ConnectionDirection::Inbound,
                    )
                    .ok();
                /* let stream = Arc::new(RwLock::new(stream)); */
                let (banned_tx, _) =
                    tokio::sync::watch::channel(Arc::new(std::collections::HashSet::new()));
                NetworkService::handle_connection(
                    peer_id,
                    stream,
                    gossip_a,
                    sync_a,
                    peers_a,
                    conns_a,
                    shared_a_clone,
                    String::new(),
                    None,
                    banned_tx,
                    false, // Fuzzer/Test node validation bypass
                )
                .await;
            }
        });

        let mut stream_b = TcpStream::connect(format!("127.0.0.1:{}", port_a))
            .await
            .unwrap();

        // Node B claims to be at height 5 — A should request blocks
        let hello_b = Message::Hello(HelloMessage {
            node_id: "sync_node_b".into(),
            version: 1,
            best_height: 5,
            network: "testnet".into(),
            nonce: 0,
            signature: vec![],
        });
        write_message(&mut stream_b, &hello_b).await.unwrap();

        // Read Hello from A
        let msg = read_message(&mut stream_b).await.unwrap();
        assert!(matches!(msg, Message::Hello(_)));

        // A is at height 0, B claims 5 → A should send GetBlocks(1, 5)
        let sync_req = read_message(&mut stream_b).await.unwrap();
        match sync_req {
            Message::GetBlocks(req) => {
                assert_eq!(req.from_height, 1);
                assert_eq!(req.to_height, 5);
            }
            other => panic!("expected GetBlocks, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_block_serving_via_get_blocks() {
        use crate::node::NodeState;
        use brrq_sequencer::block_builder::SequencerKeys;
        use brrq_types::account::Account;

        // Set up node A with 2 blocks
        let shared_a: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let keys = SequencerKeys::generate().unwrap();
        let mut builder = brrq_sequencer::block_builder::BlockBuilder::new(keys.into());
        let seq_addr = builder.sequencer_address();

        let alice_kp = {
            let hash = brrq_crypto::hash::Hasher::hash(b"alice");
            brrq_crypto::schnorr::SchnorrKeyPair::from_secret_bytes(hash.as_bytes())
                .expect("test key must be valid")
        };
        let alice = brrq_types::address::Address::from_public_key(alice_kp.public_key().as_bytes());
        let bob = {
            let hash = brrq_crypto::hash::Hasher::hash(b"bob");
            let kp = brrq_crypto::schnorr::SchnorrKeyPair::from_secret_bytes(hash.as_bytes())
                .expect("test key must be valid");
            brrq_types::address::Address::from_public_key(kp.public_key().as_bytes())
        };

        {
            let mut ns = shared_a.write().await;
            ns.state.set_account(Account::new_eoa(alice, 100_000_000));
            ns.staking
                .register_validator(seq_addr, 100_000_000)
                .unwrap();
        }

        // Produce 2 blocks — use real signatures so mempool admission passes
        for i in 0..2u64 {
            let mut ns = shared_a.write().await;
            let body = brrq_types::transaction::TransactionBody {
                from: alice,
                kind: brrq_types::transaction::TransactionKind::Transfer {
                    to: bob,
                    amount: 1_000,
                },
                nonce: i,
                gas_limit: 21_000,
                max_fee_per_gas: 10,
                max_priority_fee_per_gas: 10,
                chain_id: brrq_types::transaction::chain_id::TESTNET,
            };
            let body_hash = body.hash();
            let sig = alice_kp.sign(&body_hash).expect("signing must succeed");
            let tx = brrq_types::transaction::Transaction {
                body,
                signature: brrq_types::signature::Signature::Schnorr(sig),
                public_key: brrq_types::signature::PublicKey::Schnorr(
                    alice_kp.public_key().clone(),
                ),
            };
            ns.mempool.add(tx).unwrap();
            drop(ns);
            crate::node::produce_block(
                &mut builder,
                &shared_a,
                None,
                &crate::da::HttpDaClient::new(crate::da::DaConfig::default()),
            )
            .await;
        }

        let ns = shared_a.read().await;
        assert_eq!(ns.height, 2);
        drop(ns);

        // Set up network nodes
        let config_a = NetworkConfig {
            p2p_port: 0,
            node_id: "serve_a".into(),
            network: "testnet".into(),
            bootstrap_nodes: Vec::new(),
            sequencer_address: None,
            node_secret_key: None,
        };
        let service_a = NetworkService::new(config_a);
        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port_a = listener_a.local_addr().unwrap().port();

        let gossip_a = service_a.gossip.clone();
        let peers_a = service_a.peers.clone();
        let sync_a = service_a.sync_manager.clone();
        let conns_a = service_a.connections.clone();
        let shared_a_clone = shared_a.clone();

        tokio::spawn(async move {
            if let Ok((mut stream, addr)) = listener_a.accept().await {
                let hello = Message::Hello(HelloMessage {
                    node_id: "serve_a".into(),
                    version: 1,
                    best_height: 2,
                    network: "testnet".into(),
                    nonce: 0,
                    signature: vec![],
                });
                write_message(&mut stream, &hello).await.ok();
                let peer_id = format!("inbound_{}", addr);
                peers_a
                    .write()
                    .await
                    .add_peer(
                        peer_id.clone(),
                        addr.to_string(),
                        ConnectionDirection::Inbound,
                    )
                    .ok();
                /* let stream = Arc::new(RwLock::new(stream)); */
                let (banned_tx, _) =
                    tokio::sync::watch::channel(Arc::new(std::collections::HashSet::new()));
                NetworkService::handle_connection(
                    peer_id,
                    stream,
                    gossip_a,
                    sync_a,
                    peers_a,
                    conns_a,
                    shared_a_clone,
                    String::new(),
                    None,
                    banned_tx,
                    false, // Fuzzer/Test node validation bypass
                )
                .await;
            }
        });

        let mut stream_b = TcpStream::connect(format!("127.0.0.1:{}", port_a))
            .await
            .unwrap();

        // Handshake
        let hello = Message::Hello(HelloMessage {
            node_id: "serve_b".into(),
            version: 1,
            best_height: 0,
            network: "testnet".into(),
            nonce: 0,
            signature: vec![],
        });
        write_message(&mut stream_b, &hello).await.unwrap();
        let _ = read_message(&mut stream_b).await.unwrap(); // Hello from A

        // Request blocks 1-2
        let get_blocks = Message::GetBlocks(brrq_network::message::GetBlocksRequest {
            from_height: 1,
            to_height: 2,
        });
        write_message(&mut stream_b, &get_blocks).await.unwrap();

        // Read blocks response
        let resp = read_message(&mut stream_b).await.unwrap();
        match resp {
            Message::Blocks(blocks_resp) => {
                assert_eq!(blocks_resp.blocks.len(), 2, "should serve 2 blocks");
                // Verify they deserialize correctly
                for (i, block_data) in blocks_resp.blocks.iter().enumerate() {
                    let block: brrq_types::block::Block = bincode::options()
                        .with_limit(32 * 1024 * 1024)
                        .deserialize(block_data)
                        .unwrap();
                    assert_eq!(block.header.height, (i + 1) as u64);
                }
            }
            other => panic!("expected Blocks response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_p2p_fuzzing() {
        use crate::node::NodeState;

        let shared: SharedState = Arc::new(RwLock::new(NodeState::new()));
        let config = NetworkConfig {
            p2p_port: 0,
            node_id: "fuzz_target".into(),
            network: "testnet".into(),
            bootstrap_nodes: Vec::new(),
            sequencer_address: None,
            node_secret_key: None,
        };

        let service = NetworkService::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let gossip = service.gossip.clone();
        let peers = service.peers.clone();
        let sync = service.sync_manager.clone();
        let conns = service.connections.clone();
        let shared_clone = shared.clone();

        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                let peer_id = format!("fuzzed_{}", addr);
                /* let stream = Arc::new(RwLock::new(stream)); */
                let (banned_tx, _) =
                    tokio::sync::watch::channel(Arc::new(std::collections::HashSet::new()));
                NetworkService::handle_connection(
                    peer_id,
                    stream,
                    gossip.clone(),
                    sync.clone(),
                    peers.clone(),
                    conns.clone(),
                    shared_clone.clone(),
                    String::new(),
                    None,
                    banned_tx,
                    false, // Testing Fuzzer Validation Constraints
                )
                .await;
            }
        });

        // Test 1: Random Garbage under length limit
        {
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            let len = 100u32.to_be_bytes();
            client.write_all(&len).await.unwrap();
            let garbage = vec![0x42; 100];
            client.write_all(&garbage).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            let mut buf = [0u8; 1];
            let res = client.read(&mut buf).await;
            assert!(
                res.is_err() || res.unwrap() == 0,
                "Server must close connection on garbage data"
            );
        }

        // Test 2: Message missing bytes — server must survive truncated messages
        {
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            let len = 100u32.to_be_bytes();
            client.write_all(&len).await.unwrap();
            let partial = vec![0x11; 10];
            client.write_all(&partial).await.unwrap();
            drop(client);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;

            // Verify the server is still accepting connections after truncated message
            let probe = TcpStream::connect(format!("127.0.0.1:{}", port)).await;
            assert!(
                probe.is_ok(),
                "Server must still accept connections after receiving truncated message"
            );
        }

        // Test 3: Valid Hello prefix but malformed extremely long payload
        {
            let mut client = TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .unwrap();
            let msg_len = 1_000_000u32;
            client.write_all(&msg_len.to_be_bytes()).await.unwrap();
            let mut payload = vec![0; 1_000_000];
            payload[0] = 0;
            client.write_all(&payload).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;

            // Server should have closed this connection (rejected oversized payload)
            let mut buf = [0u8; 1];
            let res = client.read(&mut buf).await;
            assert!(
                res.is_err() || res.unwrap() == 0,
                "Server must close connection on oversized malformed payload"
            );

            // Verify the server is still accepting connections after oversized payload
            let probe = TcpStream::connect(format!("127.0.0.1:{}", port)).await;
            assert!(
                probe.is_ok(),
                "Server must still accept connections after receiving oversized payload"
            );
        }
    }
}
