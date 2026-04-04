//! libp2p-based transport layer for Brrq P2P networking.
//!
//! This module provides an alternative transport using libp2p instead of
//! the native TCP + Noise_XK implementation. It maps Brrq's existing
//! message types to libp2p's gossipsub for propagation and request-response
//! for sync operations.
//!
//! ## Migration Path
//!
//! The libp2p transport reuses:
//! - `message.rs` — same 23 message types (serialized via bincode)
//! - `peer.rs` — reputation system (augmented with libp2p peer IDs)
//! - `gossip.rs` — deduplication logic (gossipsub handles flooding)
//! - `sync.rs` — block sync state machine
//!
//! It replaces:
//! - `noise.rs` — libp2p provides its own Noise implementation
//! - TCP connection management — libp2p handles this
//! - Peer discovery — replaced by Kademlia DHT
//!
//! ## Feature flag
//!
//! Enable with `--features libp2p-transport`. The `native-p2p` feature
//! (default) uses the original custom implementation.

#[cfg(feature = "libp2p-transport")]
pub mod transport {
    use crate::error::NetworkError;
    use crate::message::Message;

    use libp2p::{
        Multiaddr, PeerId, Swarm, SwarmBuilder, gossipsub, identify, kad, noise,
        swarm::{NetworkBehaviour, SwarmEvent},
        tcp, yamux,
    };
    use std::collections::HashMap;
    use std::time::Duration;
    use tokio::sync::mpsc;
    use tracing::{info, warn};

    /// Brrq-specific gossipsub topics.
    pub const TOPIC_TRANSACTIONS: &str = "/brrq/tx/0.1.0";
    pub const TOPIC_BLOCKS: &str = "/brrq/block/0.1.0";
    pub const TOPIC_CONSENSUS: &str = "/brrq/consensus/0.1.0";
    pub const TOPIC_SLASHING: &str = "/brrq/slashing/0.1.0";

    /// Combined network behaviour for Brrq.
    #[derive(NetworkBehaviour)]
    pub struct BrrqBehaviour {
        /// Gossipsub for transaction/block propagation.
        pub gossipsub: gossipsub::Behaviour,
        /// Kademlia DHT for peer discovery.
        pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
        /// Identify protocol for peer metadata exchange.
        pub identify: identify::Behaviour,
    }

    /// Configuration for the libp2p transport.
    pub struct Libp2pConfig {
        /// Listen address (e.g., "/ip4/0.0.0.0/tcp/30303").
        pub listen_addr: Multiaddr,
        /// Bootstrap peer addresses.
        pub bootstrap_peers: Vec<(PeerId, Multiaddr)>,
        /// Node keypair (ed25519 derived from Brrq's secp256k1 key).
        pub keypair: libp2p::identity::Keypair,
        /// Network name for protocol versioning.
        pub network: String,
    }

    /// libp2p transport service for Brrq.
    pub struct Libp2pService {
        config: Libp2pConfig,
    }

    impl Libp2pService {
        pub fn new(config: Libp2pConfig) -> Self {
            Self { config }
        }

        /// Build and configure the libp2p swarm.
        pub fn build_swarm(&self) -> Result<Swarm<BrrqBehaviour>, NetworkError> {
            // Configure gossipsub with Brrq-specific parameters.
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Strict)
                .max_transmit_size(1_048_576) // 1 MB, matching native P2P
                .build()
                .map_err(|e| {
                    NetworkError::ConnectionFailed(format!("gossipsub config error: {e}"))
                })?;

            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(self.config.keypair.clone()),
                gossipsub_config,
            )
            .map_err(|e| NetworkError::ConnectionFailed(format!("gossipsub init error: {e}")))?;

            // Configure Kademlia for peer discovery.
            let local_peer_id = PeerId::from(self.config.keypair.public());
            let kademlia =
                kad::Behaviour::new(local_peer_id, kad::store::MemoryStore::new(local_peer_id));

            // Configure identify for peer metadata.
            let identify = identify::Behaviour::new(
                identify::Config::new(
                    format!("/brrq/{}/0.1.0", self.config.network),
                    self.config.keypair.public(),
                )
                .with_agent_version(format!("brrq-node/{}", env!("CARGO_PKG_VERSION"))),
            );

            let behaviour = BrrqBehaviour {
                gossipsub,
                kademlia,
                identify,
            };

            // Build the swarm with Noise encryption and Yamux multiplexing.
            let swarm = SwarmBuilder::with_existing_identity(self.config.keypair.clone())
                .with_tokio()
                .with_tcp(
                    tcp::Config::default().nodelay(true),
                    noise::Config::new,
                    yamux::Config::default,
                )
                .map_err(|e| NetworkError::ConnectionFailed(format!("TCP transport error: {e}")))?
                .with_behaviour(|_key| behaviour)
                .map_err(|e| NetworkError::ConnectionFailed(format!("behaviour error: {e}")))?
                .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(300)))
                .build();

            Ok(swarm)
        }

        /// Convert a Brrq Message to gossipsub topic + payload.
        pub fn message_to_gossip(msg: &Message) -> Option<(String, Vec<u8>)> {
            let topic = match msg {
                Message::NewTransaction(_) => TOPIC_TRANSACTIONS,
                Message::NewBlock(_) => TOPIC_BLOCKS,
                Message::BlockProposal { .. }
                | Message::BlockPreVote { .. }
                | Message::BlockPreCommit { .. }
                | Message::TimeoutVote { .. }
                | Message::MevOrderingCommitment { .. }
                | Message::RandaoCommitment { .. }
                | Message::RandaoReveal { .. } => TOPIC_CONSENSUS,
                Message::SlashingEvidence { .. } => TOPIC_SLASHING,
                // Non-gossip messages (sync, ping, peers) are handled
                // via request-response, not gossipsub.
                _ => return None,
            };

            let payload = bincode::serialize(msg).ok()?;
            Some((topic.to_string(), payload))
        }

        /// Parse a gossipsub message back to a Brrq Message.
        pub fn gossip_to_message(data: &[u8]) -> Option<Message> {
            bincode::deserialize(data).ok()
        }
    }
}

// Re-export for convenience when the feature is enabled.
#[cfg(feature = "libp2p-transport")]
pub use transport::*;
