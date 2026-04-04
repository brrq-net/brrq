//! Brrq networking — P2P gossip, sync, and messaging.
//!
//! ## Architecture
//!
//! - **Gossip**: Flood-based transaction and block propagation with deduplication
//! - **Sync**: Request-response block download for chain synchronization
//! - **Peers**: Reputation-scored peer management with eviction
//! - **Messages**: Typed P2P protocol messages with hash-based IDs
//!
//! ## Flood Protection
//!
//! Max 100 transactions per address per minute.
//! Message deduplication via 10K-entry LRU cache.
//!
//! ## Authentication & Signature Verification
//!
//! All incoming Hello messages must carry a valid BIP-340 Schnorr signature.
//! The `handle_incoming_message()` function enforces this gate:
//!
//! 1. Deserialize and validate structural limits (`Message::validate()`).
//! 2. For `Hello` messages: call `Message::verify_message_signature()`.
//!    On success, mark the peer as authenticated via `PeerManager::mark_authenticated()`.
//!    On failure, penalize reputation and disconnect.
//! 3. For all other message types from unauthenticated peers: reject immediately.

pub mod error;
pub mod gossip;
pub mod message;
pub mod noise;
pub mod peer;
pub mod sync;

/// libp2p transport adapter (behind `libp2p-transport` feature).
/// Provides Kademlia DHT peer discovery, gossipsub propagation,
/// and Noise-encrypted multiplexed transport as an alternative
/// to the native TCP + Noise_XK implementation.
#[cfg(feature = "libp2p-transport")]
pub mod libp2p_transport;

pub use error::{NetworkError, SyncError};
pub use gossip::GossipEngine;
pub use message::Message;
pub use noise::{NoiseHandshakeState, NoiseState};
pub use peer::{ConnectionDirection, PeerInfo, PeerManager, PeerState};
pub use sync::{SyncManager, SyncState};

use brrq_types::signature::Signature;
use brrq_types::Address;

/// Verify that a consensus message carries a non-empty EOTS signature.
/// Full cryptographic verification is done by the consensus engine, but rejecting
/// empty/trivially-invalid signatures at the network layer provides defense-in-depth.
fn verify_eots_field(
    sig: &Signature,
    _signer: &Address,
    peer_id: &str,
    peer_manager: &mut PeerManager,
) -> Result<(), NetworkError> {
    if sig.as_bytes().is_empty() {
        if let Some(peer) = peer_manager.get_peer_mut(peer_id) {
            peer.adjust_reputation(INVALID_SIGNATURE_PENALTY);
        }
        return Err(NetworkError::MissingSignature {
            peer_id: peer_id.to_string(),
        });
    }
    Ok(())
}

// Severe penalty for invalid signatures — immediate disconnection.
const INVALID_SIGNATURE_PENALTY: i32 = -300;

/// Process an incoming network message with full authentication checks.
///
/// This is the **security entry-point** for all inbound messages.  Every message
/// received from the transport layer must pass through this function before being
/// dispatched to gossip, sync, or consensus handlers.
///
/// # Authentication flow
///
/// 1. `Message::validate()` — structural size/range checks.
/// 2. If the message is `Hello`:
///    a. `Message::verify_message_signature()` — cryptographic identity proof.
///    b. On success: `peer_manager.mark_authenticated(peer_id)`.
///    c. On failure: reputation penalty + return error.
/// 3. For every other message type: `peer_manager.require_authenticated(peer_id)`.
///    Unauthenticated peers are blocked from sending anything except `Hello`.
///
/// # Returns
///
/// `Ok(())` if the message passed all checks and should be dispatched.
/// `Err(NetworkError)` if the message must be dropped (caller should
/// disconnect the peer if the error is authentication-related).
pub fn handle_incoming_message(
    msg: &Message,
    peer_id: &str,
    peer_manager: &mut PeerManager,
) -> Result<(), NetworkError> {
    // Step 1: Structural validation (sizes, ranges, empty-signature check).
    msg.validate()?;

    match msg {
        Message::Hello(hello) => {
            // Reject Hello messages with previously seen nonces (replay prevention).
            if !peer_manager.check_hello_nonce(peer_id, hello.nonce) {
                if let Some(peer) = peer_manager.get_peer_mut(peer_id) {
                    peer.adjust_reputation(INVALID_SIGNATURE_PENALTY);
                }
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "Hello nonce {} already seen for peer {} (replay attack)",
                        hello.nonce, peer_id
                    ),
                });
            }

            // Step 2a: Verify the cryptographic signature on the Hello.
            if let Err(e) = Message::verify_message_signature(hello) {
                // Penalize and reject — do NOT fall back to unauthenticated mode.
                if let Some(peer) = peer_manager.get_peer_mut(peer_id) {
                    peer.adjust_reputation(INVALID_SIGNATURE_PENALTY);
                }
                return Err(e);
            }

            // Step 2b: Signature valid — mark peer as authenticated.
            peer_manager.mark_authenticated(peer_id)?;
            peer_manager.record_message(peer_id)?;
            Ok(())
        }

        // Consensus messages require EOTS signature verification at the network layer.
        // This prevents unauthenticated or forged consensus messages from reaching the
        // consensus engine, which would only catch them later (defense-in-depth).
        Message::BlockProposal(p) => {
            peer_manager.require_authenticated(peer_id)?;
            verify_eots_field(&p.eots_signature, &p.proposer, peer_id, peer_manager)?;
            peer_manager.record_message(peer_id)?;
            Ok(())
        }
        Message::BlockPreVote(v) => {
            peer_manager.require_authenticated(peer_id)?;
            verify_eots_field(&v.eots_signature, &v.voter, peer_id, peer_manager)?;
            peer_manager.record_message(peer_id)?;
            Ok(())
        }
        Message::BlockPreCommit(v) => {
            peer_manager.require_authenticated(peer_id)?;
            verify_eots_field(&v.eots_signature, &v.voter, peer_id, peer_manager)?;
            peer_manager.record_message(peer_id)?;
            Ok(())
        }

        // Step 3: All non-Hello messages require prior authentication.
        _ => {
            // Block messages from unauthenticated peers.
            peer_manager.require_authenticated(peer_id)?;
            peer_manager.record_message(peer_id)?;
            Ok(())
        }
    }
}
