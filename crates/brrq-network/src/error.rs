//! Network error types.

use brrq_crypto::hash::Hash256;
use thiserror::Error;

/// Network-layer errors.
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("connection failed to {addr}: {reason}")]
    ConnectionFailed { addr: String, reason: String },

    #[error("message too large: {size} bytes (max {max})")]
    MessageTooLarge { size: usize, max: usize },

    #[error("invalid message: {reason}")]
    InvalidMessage { reason: String },

    #[error("peer not found: {peer_id}")]
    PeerNotFound { peer_id: String },

    /// Too many peers from the same /16 subnet.
    #[error("subnet limit reached for {subnet}: max peers per subnet exceeded")]
    SubnetLimitReached { subnet: String },

    /// Hello message missing mandatory signature.
    #[error("missing signature in Hello from {peer_id}")]
    MissingSignature { peer_id: String },

    /// Signature verification failed — peer is impersonating or corrupted.
    #[error("invalid signature from {peer_id}: {reason}")]
    InvalidSignature { peer_id: String, reason: String },

    /// Peer is not authenticated — handshake incomplete or failed.
    #[error("peer not authenticated: {peer_id}")]
    PeerNotAuthenticated { peer_id: String },

    /// Outbound connection slots exhausted.
    #[error("outbound slot limit reached ({max} max)")]
    OutboundSlotsFull { max: usize },

    /// Inbound connection slots exhausted.
    #[error("inbound slot limit reached ({max} max)")]
    InboundSlotsFull { max: usize },
}

/// Sync-specific errors for block validation during chain sync.
#[derive(Debug, Error)]
pub enum SyncError {
    /// Block's parent hash does not match the expected previous block hash.
    #[error("invalid parent hash at height {height}: expected {expected}, got {got}")]
    InvalidParentHash {
        height: u64,
        expected: Hash256,
        got: Hash256,
    },

    /// Block at the weak subjectivity checkpoint height has the wrong hash.
    #[error("weak subjectivity violation at height {height}: expected {expected}, got {got}")]
    WeakSubjectivityViolation {
        height: u64,
        expected: Hash256,
        got: Hash256,
    },
}
