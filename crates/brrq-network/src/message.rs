//! Network message types for P2P gossip.
//!
//! Messages are the fundamental unit of communication between Brrq nodes.
//! All messages are serialized with a type tag + payload.
//!
//! ## Security Limits
//!
//! - `MAX_MESSAGE_SIZE`: Hard cap on serialized message bytes (enforced at reception).
//! - `MAX_BLOCKS_PER_RESPONSE`: Limits `BlocksResponse` to prevent memory exhaustion.
//! - `MAX_PEERS_PER_RESPONSE`: Limits `PeersResponse` similarly.
//! - `MAX_TX_DATA_SIZE`: Limits transaction payload in announcements.
//!
//! The `Message::validate()` method must be called on every deserialized message
//! before processing to reject oversized payloads that pass deserialization but
//! would exhaust memory during handling.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_types::Address;
use brrq_types::signature::Signature;
use serde::{Deserialize, Serialize};

use crate::error::NetworkError;

/// Maximum message size (1 MB).
pub const MAX_MESSAGE_SIZE: usize = 1_048_576;

/// Maximum blocks in a single BlocksResponse.
pub const MAX_BLOCKS_PER_RESPONSE: usize = 100;

/// Maximum peers in a single PeersResponse.
pub const MAX_PEERS_PER_RESPONSE: usize = 500;

/// Maximum transaction data payload size (64 KB).
pub const MAX_TX_DATA_SIZE: usize = 65_536;

/// Maximum block header data size in a BlockAnnounce (8 KB).
pub const MAX_HEADER_DATA_SIZE: usize = 8_192;

/// Maximum block height range in a single GetBlocks request.
pub const MAX_BLOCK_RANGE: u64 = 500;

/// Network message types exchanged between peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    /// Handshake: announce node identity and capabilities.
    Hello(HelloMessage),
    /// Announce a new transaction to the network.
    NewTransaction(TransactionAnnounce),
    /// Announce a new block to the network.
    NewBlock(BlockAnnounce),
    /// Request blocks by height range.
    GetBlocks(GetBlocksRequest),
    /// Response with requested blocks.
    Blocks(BlocksResponse),
    /// Request current peer list.
    GetPeers,
    /// Response with known peers.
    Peers(PeersResponse),
    /// Ping for liveness.
    Ping(u64),
    /// Pong response.
    Pong(u64),

    // ── Sequencer Rotation ───────────────────────────────────────
    /// Propose a block for the current height/round.
    BlockProposal(BlockProposalMessage),
    /// PreVote: Vote to accept a proposed block after dry-run.
    BlockPreVote(BlockPreVoteMessage),
    /// PreCommit: Commit to finality after a 2/3 PreVote quorum.
    BlockPreCommit(BlockPreCommitMessage),
    /// Vote to advance the round (timeout on proposal).
    TimeoutVote(TimeoutVoteMessage),

    // ── MEV Ordering ─────────────────────────────────────────────
    /// Commit to a specific MEV transaction ordering.
    MevOrderingCommitment(MevOrderingCommitmentMessage),

    // ── RANDAO ──────────────────────────────────────────────────
    /// Submit a RANDAO commitment H(secret) for the next epoch.
    RandaoCommitment(RandaoCommitmentMessage),
    /// Reveal the RANDAO secret whose hash was committed.
    RandaoReveal(RandaoRevealMessage),

    // ── Slashing ─────────────────────────────────────────────────
    /// Broadcast evidence of a slashable offense (equivocation, dual proposal).
    SlashingEvidence(SlashingEvidenceMessage),

    // ── Threshold Key Sharing (§4.7 MEV Protection) ────────────
    /// Distribute a Shamir share of the epoch encryption key.
    ShareDistribution(ShareDistributionMessage),

    // ── Snapshot Sync (prevents network closure after pruning) ──
    /// Request a state snapshot for fast bootstrapping.
    /// New nodes that are too far behind use this instead of block-by-block sync.
    RequestSnapshot(SnapshotRequest),
    /// Response with a state snapshot chunk.
    SnapshotChunk(SnapshotChunkMessage),
}

impl Message {
    /// Check that a raw byte payload does not exceed the maximum message size.
    ///
    /// Call this **before** deserializing to prevent allocating oversized buffers.
    pub fn check_size(bytes: &[u8]) -> Result<(), NetworkError> {
        if bytes.len() > MAX_MESSAGE_SIZE {
            return Err(NetworkError::MessageTooLarge {
                size: bytes.len(),
                max: MAX_MESSAGE_SIZE,
            });
        }
        Ok(())
    }

    /// Validate structural limits on a deserialized message.
    ///
    /// This catches payloads that are within `MAX_MESSAGE_SIZE` but contain
    /// unreasonably large collections that could exhaust memory during processing.
    pub fn validate(&self) -> Result<(), NetworkError> {
        match self {
            Message::Blocks(resp) if resp.blocks.len() > MAX_BLOCKS_PER_RESPONSE => {
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "BlocksResponse contains {} blocks (max {})",
                        resp.blocks.len(),
                        MAX_BLOCKS_PER_RESPONSE,
                    ),
                });
            }
            Message::Peers(resp) if resp.peers.len() > MAX_PEERS_PER_RESPONSE => {
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "PeersResponse contains {} peers (max {})",
                        resp.peers.len(),
                        MAX_PEERS_PER_RESPONSE,
                    ),
                });
            }
            Message::NewTransaction(tx) if tx.data.len() > MAX_TX_DATA_SIZE => {
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "transaction data {} bytes (max {})",
                        tx.data.len(),
                        MAX_TX_DATA_SIZE,
                    ),
                });
            }
            // Validate BlockAnnounce header_data size.
            Message::NewBlock(blk) if blk.header_data.len() > MAX_HEADER_DATA_SIZE => {
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "block header data {} bytes (max {})",
                        blk.header_data.len(),
                        MAX_HEADER_DATA_SIZE,
                    ),
                });
            }
            Message::GetBlocks(req)
                if req.to_height > req.from_height
                    && req.to_height - req.from_height > MAX_BLOCK_RANGE =>
            {
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "block range {} exceeds max {}",
                        req.to_height - req.from_height,
                        MAX_BLOCK_RANGE,
                    ),
                });
            }
            Message::BlockProposal(p) if p.block_data.len() > MAX_PROPOSAL_DATA_SIZE => {
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "block proposal data {} bytes (max {})",
                        p.block_data.len(),
                        MAX_PROPOSAL_DATA_SIZE,
                    ),
                });
            }
            // Reject Hello messages with empty signatures at validation time.
            Message::Hello(hello) if hello.signature.is_empty() => {
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "Hello from {} has empty signature (authentication required)",
                        hello.node_id,
                    ),
                });
            }
            // Validate SnapshotChunk data size and total_chunks
            Message::SnapshotChunk(chunk) if chunk.data.len() > 512 * 1024 || chunk.total_chunks > 100_000 || chunk.total_chunks == 0 => {
                return Err(NetworkError::InvalidMessage {
                    reason: format!(
                        "SnapshotChunk: data={} bytes (max 512KB), total_chunks={} (max 100K)",
                        chunk.data.len(), chunk.total_chunks,
                    ),
                });
            }
            // Cap Hello string field lengths to prevent DoS
            Message::Hello(hello) if hello.node_id.len() > 256 || hello.network.len() > 64 => {
                return Err(NetworkError::InvalidMessage {
                    reason: "Hello node_id or network too long".into(),
                });
            }
            // Explicit validation for all remaining message types.
            // Validate all remaining message types explicitly.
            Message::BlockPreVote(v) => {
                if v.block_hash.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "BlockPreVote has zero block_hash".into(),
                    });
                }
                if v.voter.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "BlockPreVote has zero voter address".into(),
                    });
                }
            }
            Message::BlockPreCommit(v) => {
                if v.block_hash.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "BlockPreCommit has zero block_hash".into(),
                    });
                }
                if v.voter.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "BlockPreCommit has zero voter address".into(),
                    });
                }
            }
            Message::TimeoutVote(t) => {
                if t.voter.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "TimeoutVote has zero voter address".into(),
                    });
                }
            }
            Message::MevOrderingCommitment(m) => {
                if m.ordering_commitment.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "MevOrderingCommitment has zero ordering_commitment".into(),
                    });
                }
                if m.sequencer.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "MevOrderingCommitment has zero sequencer address".into(),
                    });
                }
            }
            Message::RandaoCommitment(r) => {
                if r.commitment.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "RandaoCommitment has zero commitment hash".into(),
                    });
                }
                if r.validator.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "RandaoCommitment has zero validator address".into(),
                    });
                }
            }
            Message::RandaoReveal(r) => {
                if r.secret.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "RandaoReveal has zero secret".into(),
                    });
                }
                if r.validator.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "RandaoReveal has zero validator address".into(),
                    });
                }
            }
            Message::SlashingEvidence(s) => {
                if s.offender.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "SlashingEvidence has zero offender address".into(),
                    });
                }
                if s.challenger.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "SlashingEvidence has zero challenger address".into(),
                    });
                }
                if s.evidence_hash_a.is_zero() || s.evidence_hash_b.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "SlashingEvidence has zero evidence hash".into(),
                    });
                }
                if s.offense_type.is_empty() || s.offense_type.len() > 64 {
                    return Err(NetworkError::InvalidMessage {
                        reason: format!(
                            "SlashingEvidence offense_type invalid (len={})",
                            s.offense_type.len(),
                        ),
                    });
                }
            }
            Message::ShareDistribution(sd) => {
                if sd.sender.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "ShareDistribution has zero sender address".into(),
                    });
                }
                if sd.recipient.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "ShareDistribution has zero recipient address".into(),
                    });
                }
                if sd.share_index == 0 {
                    return Err(NetworkError::InvalidMessage {
                        reason: "ShareDistribution share_index must be >= 1 (Shamir convention)".into(),
                    });
                }
                if sd.share_data == [0u8; 32] {
                    return Err(NetworkError::InvalidMessage {
                        reason: "ShareDistribution has all-zero share_data".into(),
                    });
                }
            }
            Message::RequestSnapshot(req) => {
                if req.requester_id.is_zero() {
                    return Err(NetworkError::InvalidMessage {
                        reason: "RequestSnapshot has zero requester_id".into(),
                    });
                }
            }
            // These message types have already been validated by the guard
            // arms above, or are simple scalars that need no further checks.
            Message::Hello(_) => {}
            Message::NewTransaction(_) => {}
            Message::NewBlock(_) => {}
            Message::GetBlocks(_) => {}
            Message::Blocks(_) => {}
            Message::Peers(_) => {}
            Message::BlockProposal(_) => {}
            Message::SnapshotChunk(_) => {}
            Message::GetPeers | Message::Ping(_) | Message::Pong(_) => {}
        }
        Ok(())
    }

    /// Verify the cryptographic signature on a Hello handshake message.
    ///
    /// The signature must cover `SHA-256(nonce || network || version)` and be
    /// verifiable against the public key encoded in `hello.node_id`.
    ///
    /// Returns `Ok(())` if the signature is valid, or a `NetworkError` explaining
    /// the failure. Uses BIP-340 Schnorr verification via `brrq_crypto::schnorr`.
    ///
    /// The digest is `SHA-256(nonce_le_bytes || network_utf8 || version_le_bytes)`.
    pub fn verify_message_signature(hello: &HelloMessage) -> Result<(), NetworkError> {
        // Reject empty signatures unconditionally.
        if hello.signature.is_empty() {
            return Err(NetworkError::MissingSignature {
                peer_id: hello.node_id.clone(),
            });
        }

        // Decode the public key from hex-encoded node_id (32-byte x-only Schnorr key).
        let pk_bytes = hex::decode(&hello.node_id).map_err(|_| NetworkError::InvalidSignature {
            peer_id: hello.node_id.clone(),
            reason: "node_id is not valid hex".into(),
        })?;
        let public_key =
            brrq_crypto::schnorr::SchnorrPublicKey::from_slice(&pk_bytes).map_err(|_| {
                NetworkError::InvalidSignature {
                    peer_id: hello.node_id.clone(),
                    reason: format!(
                        "node_id must be 32 bytes (x-only Schnorr key), got {}",
                        pk_bytes.len()
                    ),
                }
            })?;

        // Decode the signature (64 bytes per BIP-340).
        let signature =
            brrq_crypto::schnorr::SchnorrSignature::from_slice(&hello.signature).map_err(|_| {
                NetworkError::InvalidSignature {
                    peer_id: hello.node_id.clone(),
                    reason: format!(
                        "signature must be 64 bytes, got {}",
                        hello.signature.len()
                    ),
                }
            })?;

        // Build the digest: SHA-256(nonce || network || version)
        let mut hasher = Hasher::new();
        hasher.update(&hello.nonce.to_le_bytes());
        hasher.update(hello.network.as_bytes());
        hasher.update(&hello.version.to_le_bytes());
        let digest = hasher.finalize();

        // Cryptographic Schnorr verification (BIP-340).
        brrq_crypto::schnorr::verify(&public_key, &digest, &signature).map_err(|_| {
            NetworkError::InvalidSignature {
                peer_id: hello.node_id.clone(),
                reason: "Schnorr signature verification failed".into(),
            }
        })
    }

    /// Compute a unique ID for this message (for deduplication).
    pub fn id(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(b"MSG_ID");
        match self {
            Message::Hello(h) => {
                hasher.update(b"HELLO");
                hasher.update(h.node_id.as_bytes());
            }
            Message::NewTransaction(tx) => {
                hasher.update(b"TX");
                hasher.update(tx.tx_hash.as_bytes());
            }
            Message::NewBlock(blk) => {
                hasher.update(b"BLK");
                hasher.update(blk.block_hash.as_bytes());
            }
            Message::GetBlocks(req) => {
                hasher.update(b"GETBLK");
                hasher.update(&req.from_height.to_le_bytes());
                hasher.update(&req.to_height.to_le_bytes());
            }
            Message::Blocks(resp) => {
                hasher.update(b"BLKS");
                hasher.update(&(resp.blocks.len() as u64).to_le_bytes());
                // Hash actual block content for unique ID (limit to prevent OOM)
                for block in resp.blocks.iter().take(100) {
                    hasher.update(&(block.len() as u64).to_le_bytes());
                    hasher.update(block);
                }
            }
            Message::GetPeers => {
                hasher.update(b"GETPEERS");
            }
            Message::Peers(resp) => {
                hasher.update(b"PEERS");
                hasher.update(&(resp.peers.len() as u64).to_le_bytes());
                // Hash actual peer content for unique ID (limit to prevent OOM)
                for peer in resp.peers.iter().take(100) {
                    hasher.update(peer.as_bytes());
                }
            }
            Message::Ping(nonce) => {
                hasher.update(b"PING");
                hasher.update(&nonce.to_le_bytes());
            }
            Message::Pong(nonce) => {
                hasher.update(b"PONG");
                hasher.update(&nonce.to_le_bytes());
            }
            Message::BlockProposal(p) => {
                hasher.update(b"PROPOSAL");
                hasher.update(&p.height.to_le_bytes());
                hasher.update(&p.round.to_le_bytes());
                hasher.update(p.block_hash.as_bytes());
                hasher.update(p.proposer.as_bytes());
            }
            Message::BlockPreVote(v) => {
                hasher.update(b"PRE_VOTE");
                hasher.update(&v.height.to_le_bytes());
                hasher.update(&v.round.to_le_bytes());
                hasher.update(v.block_hash.as_bytes());
                hasher.update(v.voter.as_bytes());
            }
            Message::BlockPreCommit(v) => {
                hasher.update(b"PRE_COMMIT");
                hasher.update(&v.height.to_le_bytes());
                hasher.update(&v.round.to_le_bytes());
                hasher.update(v.block_hash.as_bytes());
                hasher.update(v.voter.as_bytes());
            }
            Message::TimeoutVote(t) => {
                hasher.update(b"TIMEOUT");
                hasher.update(&t.height.to_le_bytes());
                hasher.update(&t.round.to_le_bytes());
                hasher.update(t.voter.as_bytes());
            }
            Message::MevOrderingCommitment(m) => {
                hasher.update(b"MEV_ORD");
                hasher.update(&m.height.to_le_bytes());
                hasher.update(m.ordering_commitment.as_bytes());
                hasher.update(m.sequencer.as_bytes());
            }
            Message::RandaoCommitment(r) => {
                hasher.update(b"RANDAO_C");
                hasher.update(&r.epoch.to_le_bytes());
                hasher.update(r.commitment.as_bytes());
                hasher.update(r.validator.as_bytes());
            }
            Message::RandaoReveal(r) => {
                hasher.update(b"RANDAO_R");
                hasher.update(&r.epoch.to_le_bytes());
                hasher.update(r.secret.as_bytes());
                hasher.update(r.validator.as_bytes());
            }
            Message::SlashingEvidence(s) => {
                hasher.update(b"SLASH_EV");
                hasher.update(s.offender.as_bytes());
                hasher.update(&s.height.to_le_bytes());
                hasher.update(s.evidence_hash_a.as_bytes());
                hasher.update(s.evidence_hash_b.as_bytes());
            }
            Message::ShareDistribution(sd) => {
                hasher.update(b"SHARE_DIST");
                hasher.update(&sd.epoch.to_le_bytes());
                hasher.update(&sd.share_index.to_le_bytes());
                hasher.update(sd.sender.as_bytes());
                hasher.update(sd.recipient.as_bytes());
            }
            Message::RequestSnapshot(req) => {
                hasher.update(b"SNAP_REQ");
                hasher.update(&req.target_height.to_le_bytes());
                hasher.update(req.requester_id.as_bytes());
            }
            Message::SnapshotChunk(chunk) => {
                hasher.update(b"SNAP_CHUNK");
                hasher.update(&chunk.snapshot_height.to_le_bytes());
                hasher.update(&chunk.chunk_index.to_le_bytes());
                hasher.update(chunk.chunk_hash.as_bytes());
            }
        }
        hasher.finalize()
    }
}

/// Handshake message.
///
/// The `signature` field is mandatory (no `#[serde(default)]`).
/// Deserialization of a Hello without a `signature` field will fail at the
/// protocol layer, preventing unauthenticated peers from connecting.
///
/// The signature covers `SHA-256(nonce || network || version)` and proves the
/// sender controls the private key corresponding to `node_id`.
///
/// Legacy nodes that omit `nonce` / `signature` are rejected — there is
/// no backward-compatible fallback. Operators must upgrade before reconnecting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    /// Node identifier (hex-encoded public key).
    pub node_id: String,
    /// Protocol version.
    pub version: u32,
    /// Current best block height.
    pub best_height: u64,
    /// Network identifier.
    pub network: String,
    /// Random nonce for handshake freshness (prevents replay).
    pub nonce: u64,
    /// Mandatory signature over `SHA-256(nonce || network || version)`.
    /// Must not be empty. Peers sending an empty signature are rejected.
    pub signature: Vec<u8>,
}

/// Transaction announcement.
///
/// The sender is derived from `tx.verify_signature()` during mempool
/// admission (see `network_service.rs:1053`), not from the gossip layer.
///
/// The sender address is now exclusively derived from the cryptographic
/// signature inside the serialized transaction `data` at execution time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionAnnounce {
    /// Transaction hash.
    pub tx_hash: Hash256,
    /// Gas price (for prioritization).
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    /// Serialized transaction data (contains signed transaction with recoverable sender).
    pub data: Vec<u8>,
}

/// Block announcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockAnnounce {
    /// Block hash.
    pub block_hash: Hash256,
    /// Block height.
    pub height: u64,
    /// Block producer.
    pub producer: Address,
    /// Serialized block header data.
    pub header_data: Vec<u8>,
}

/// Request blocks by height range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetBlocksRequest {
    /// Start height (inclusive).
    pub from_height: u64,
    /// End height (inclusive).
    pub to_height: u64,
}

/// Response with block data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocksResponse {
    /// Serialized blocks.
    pub blocks: Vec<Vec<u8>>,
}

/// Response with known peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeersResponse {
    /// Known peer addresses (host:port).
    pub peers: Vec<String>,
}

// ── Sequencer Rotation Messages ─────────────────────────────────────

/// Maximum block proposal data size (256 KB).
pub const MAX_PROPOSAL_DATA_SIZE: usize = 262_144;

/// Block proposal from the elected leader for a given height/round.
///
/// Signed with EOTS (Extractable One-Time Signature): if the proposer
/// equivocates (two proposals at the same height), the EOTS key is
/// extractable and the proposer is automatically slashed (33.33%).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposalMessage {
    /// L2 block height.
    pub height: u64,
    /// Rotation round within this height (0 = first attempt).
    pub round: u32,
    /// Epoch number.
    pub epoch: u64,
    /// Hash of the proposed block.
    pub block_hash: Hash256,
    /// Serialized block data.
    pub block_data: Vec<u8>,
    /// Proposer's validator address.
    pub proposer: Address,
    /// EOTS signature over `H(BLOCK_PROPOSAL_V1 ∥ height ∥ round ∥ block_hash)`.
    pub eots_signature: Signature,
    /// SLH-DSA signature for post-quantum equivocation detection.
    pub slh_dsa_signature: Signature,
}

/// PreVote: Vote to accept a proposed block after dry-run.
///
/// Each validator signs at most one PreVote per (height, round).
/// 2/3 quorum of effective stake advances to PreCommit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPreVoteMessage {
    /// L2 block height.
    pub height: u64,
    /// Rotation round.
    pub round: u32,
    /// Hash of the block being voted for.
    pub block_hash: Hash256,
    /// Voter's validator address.
    pub voter: Address,
    /// EOTS signature over `H(BLOCK_PREVOTE_V1 ∥ height ∥ round ∥ block_hash)`.
    pub eots_signature: Signature,
}

/// PreCommit: Commit to finality after seeing 2/3 PreVotes.
///
/// 2/3 quorum of effective stake finalizes the block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockPreCommitMessage {
    /// L2 block height.
    pub height: u64,
    /// Rotation round.
    pub round: u32,
    /// Hash of the block being committed.
    pub block_hash: Hash256,
    /// Voter's validator address.
    pub voter: Address,
    /// EOTS signature over `H(BLOCK_PRECOMMIT_V1 ∥ height ∥ round ∥ block_hash)`.
    pub eots_signature: Signature,
}

/// Timeout vote to advance the round when no valid proposal is received.
///
/// If 2/3 of effective stake sends timeout votes, the round advances
/// and a new leader is elected via `LeaderElection::elect(...)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutVoteMessage {
    /// L2 block height.
    pub height: u64,
    /// Round that timed out.
    pub round: u32,
    /// Voter's validator address.
    pub voter: Address,
    /// EOTS signature over `H(TIMEOUT_VOTE_V1 ∥ height ∥ round)`.
    pub eots_signature: Signature,
}

/// MEV ordering commitment broadcast by the sequencer.
///
/// The sequencer commits to a specific ordering of encrypted envelopes
/// before decryption. Validators verify this commitment matches the
/// actual transaction ordering in the decrypted block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MevOrderingCommitmentMessage {
    /// L2 block height at which ordering was locked.
    pub height: u64,
    /// Hash of the ordering: `H(MEV_ORDERING_V1 ∥ height ∥ hash_1 ∥ ... ∥ hash_n)`.
    pub ordering_commitment: Hash256,
    /// Sequencer's validator address.
    pub sequencer: Address,
    /// EOTS signature over the ordering commitment.
    pub eots_signature: Signature,
}

/// RANDAO commitment: `H(secret)` for the next epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandaoCommitmentMessage {
    /// Epoch number this commitment is for.
    pub epoch: u64,
    /// The commitment: `H(secret)`.
    pub commitment: Hash256,
    /// Validator address.
    pub validator: Address,
    /// EOTS signature over `H(RANDAO_COMMITMENT_V1 ∥ epoch ∥ commitment)`.
    pub eots_signature: Signature,
}

/// RANDAO reveal: the secret whose hash was committed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RandaoRevealMessage {
    /// Epoch number this reveal is for.
    pub epoch: u64,
    /// The secret (preimage of the commitment).
    pub secret: Hash256,
    /// Validator address.
    pub validator: Address,
    /// EOTS signature over `H(RANDAO_REVEAL_V1 ∥ epoch ∥ secret)`.
    pub eots_signature: Signature,
}

/// A Shamir share of the epoch encryption key (§4.7 MEV Protection).
///
/// During epoch transitions, the leader splits the epoch key into shares
/// and distributes one share to each validator. Once a threshold of shares
/// is collected, the epoch key can be reconstructed for batch decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareDistributionMessage {
    /// Epoch this share belongs to.
    pub epoch: u64,
    /// Share index (1-based, as per Shamir SSS convention).
    pub share_index: u32,
    /// The share value (32 bytes).
    pub share_data: [u8; 32],
    /// Intended recipient (only this sequencer should use this share).
    pub recipient: Address,
    /// Address of the sender (the leader distributing shares).
    pub sender: Address,
    /// Sender's signature over the share hash for authentication.
    pub signature: Signature,
}

/// Evidence of a slashable offense, broadcast for other validators to verify.
///
/// Contains enough data for any validator to independently verify the offense
/// and apply the slashing penalty. The 70/20/10 split (burn/challenger/fund)
/// incentivizes timely evidence submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvidenceMessage {
    /// Address of the offending validator.
    pub offender: Address,
    /// Block height at which the offense occurred.
    pub height: u64,
    /// Type of offense: "equivocation", "dual_proposal", or "randao_non_reveal".
    pub offense_type: String,
    /// Hash of the first conflicting proposal/block (for equivocation).
    pub evidence_hash_a: Hash256,
    /// Hash of the second conflicting proposal/block (for equivocation).
    pub evidence_hash_b: Hash256,
    /// Address of the challenger submitting the evidence.
    pub challenger: Address,
    /// EOTS signature from the challenger.
    pub eots_signature: Signature,
}

// ── Snapshot Sync Messages ─────────────────────────────────────

/// Request a state snapshot from a peer.
///
/// Sent by new nodes that detect they're too far behind for block-by-block sync
/// (gap > SNAPSHOT_SYNC_THRESHOLD). The peer responds with SnapshotChunk messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRequest {
    /// Requested snapshot at or near this height (0 = latest available).
    pub target_height: u64,
    /// Requester's node ID (for response routing).
    pub requester_id: Hash256,
}

/// A chunk of a state snapshot being streamed to a syncing node.
///
/// Large snapshots are split into chunks to stay within P2P message size limits.
/// The receiver reassembles chunks, verifies the final state_root against
/// the block header, and applies the snapshot to bootstrap its WorldState.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChunkMessage {
    /// Height of the snapshot.
    pub snapshot_height: u64,
    /// State root at this height (for verification against block headers).
    pub state_root: Hash256,
    /// Chunk index (0-based).
    pub chunk_index: u32,
    /// Total number of chunks.
    pub total_chunks: u32,
    /// Raw serialized state data for this chunk.
    pub data: Vec<u8>,
    /// SHA-256 hash of this chunk's data (integrity check).
    pub chunk_hash: Hash256,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_id_deterministic() {
        let msg = Message::Ping(42);
        let id1 = msg.id();
        let id2 = msg.id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_messages_different_ids() {
        let ping = Message::Ping(1);
        let pong = Message::Pong(1);
        assert_ne!(ping.id(), pong.id());
    }

    #[test]
    fn test_tx_announce_id() {
        let msg = Message::NewTransaction(TransactionAnnounce {
            tx_hash: Hash256::ZERO,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            data: vec![1, 2, 3],
        });
        let id = msg.id();
        assert_ne!(id, Hash256::ZERO);
    }

    // ── Validation tests ───────────────────────────────────────────

    #[test]
    fn test_validate_blocks_within_limit() {
        let msg = Message::Blocks(BlocksResponse {
            blocks: vec![vec![0u8; 32]; MAX_BLOCKS_PER_RESPONSE],
        });
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_validate_blocks_exceeds_limit() {
        let msg = Message::Blocks(BlocksResponse {
            blocks: vec![vec![0u8; 1]; MAX_BLOCKS_PER_RESPONSE + 1],
        });
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_validate_peers_within_limit() {
        let msg = Message::Peers(PeersResponse {
            peers: vec!["127.0.0.1:30303".into(); MAX_PEERS_PER_RESPONSE],
        });
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_validate_peers_exceeds_limit() {
        let msg = Message::Peers(PeersResponse {
            peers: vec!["127.0.0.1:30303".into(); MAX_PEERS_PER_RESPONSE + 1],
        });
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_validate_tx_data_within_limit() {
        let msg = Message::NewTransaction(TransactionAnnounce {
            tx_hash: Hash256::ZERO,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            data: vec![0u8; MAX_TX_DATA_SIZE],
        });
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_validate_tx_data_exceeds_limit() {
        let msg = Message::NewTransaction(TransactionAnnounce {
            tx_hash: Hash256::ZERO,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            data: vec![0u8; MAX_TX_DATA_SIZE + 1],
        });
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_validate_get_blocks_range_ok() {
        let msg = Message::GetBlocks(GetBlocksRequest {
            from_height: 0,
            to_height: MAX_BLOCK_RANGE,
        });
        assert!(msg.validate().is_ok());
    }

    #[test]
    fn test_validate_get_blocks_range_too_large() {
        let msg = Message::GetBlocks(GetBlocksRequest {
            from_height: 0,
            to_height: MAX_BLOCK_RANGE + 1,
        });
        assert!(msg.validate().is_err());
    }

    #[test]
    fn test_validate_ping_always_ok() {
        assert!(Message::Ping(0).validate().is_ok());
        assert!(Message::Pong(u64::MAX).validate().is_ok());
        assert!(Message::GetPeers.validate().is_ok());
    }
}
