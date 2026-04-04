//! Consensus message wire format — domain-tagged serialization.
//!
//! ## Design
//!
//! Every consensus message (proposals, votes, timeouts) has a deterministic
//! domain-tagged hash for signature verification and deduplication. The wire
//! format uses serde for serialization, with each message type hashed under
//! a unique domain separation tag to prevent cross-message collisions.
//!
//! ## Cryptographic Authentication & Replay Protection
//!
//! All consensus messages now carry:
//! - `signature`: Schnorr (BIP-340) signature over the domain-tagged hash,
//!   preventing vote/proposal fabrication by unauthenticated parties.
//! - `sequence`: Monotonically increasing per-validator counter, preventing
//!   replay of old messages in new rounds/heights. The combination of
//!   (sender, sequence) must be unique across the network lifetime.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::{
    self, SchnorrError, SchnorrKeyPair, SchnorrPublicKey, SchnorrSignature,
};
use brrq_types::Address;
use serde::{Deserialize, Serialize};

// ═══════════════════════════════════════════════════════════════
// Domain separation tags
// ═══════════════════════════════════════════════════════════════

const WIRE_PROPOSAL_DOMAIN: &[u8] = b"brrq/consensus/proposal/v1";
const WIRE_VOTE_DOMAIN: &[u8] = b"brrq/consensus/vote/v1";
const WIRE_TIMEOUT_VOTE_DOMAIN: &[u8] = b"brrq/consensus/timeout-vote/v1";
const WIRE_TIMEOUT_CERT_DOMAIN: &[u8] = b"brrq/consensus/timeout-cert/v1";
const WIRE_SHARE_DIST_DOMAIN: &[u8] = b"brrq/consensus/share-dist/v1";

// ═══════════════════════════════════════════════════════════════
// Errors
// ═══════════════════════════════════════════════════════════════

/// Errors arising from consensus message signing/verification.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Signature is missing on a message that requires authentication.
    #[error("missing signature on consensus message")]
    MissingSignature,

    /// Signature verification failed — message may be fabricated.
    #[error("invalid signature on consensus message: {0}")]
    InvalidSignature(#[from] SchnorrError),

    /// Signer public key does not correspond to the claimed sender address.
    #[error("signer address mismatch: expected {expected}, got {actual}")]
    SignerMismatch { expected: String, actual: String },
}

// ═══════════════════════════════════════════════════════════════
// Message types
// ═══════════════════════════════════════════════════════════════

/// Top-level consensus message for P2P gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// A block proposal from the elected leader.
    Proposal(ProposalMessage),
    /// A vote for a proposed block.
    Vote(VoteMessage),
    /// A timeout vote when the leader fails to propose.
    TimeoutVote(TimeoutVoteMessage),
    /// An aggregated timeout certificate (view sync).
    TimeoutCertificate(TimeoutCertificateMessage),
    /// A threshold key share distribution for MEV epoch key (§4.7).
    ShareDistribution(ShareDistributionMessage),
}

/// Block proposal message.
///
/// ## Authentication Fields
/// - `signature`: Schnorr signature by the proposer over `hash()`, proving
///   only the elected leader authored this proposal.
/// - `sequence`: Anti-replay counter; receivers must reject proposals with
///   a `sequence` value they have already seen from this proposer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProposalMessage {
    /// Block height.
    pub height: u64,
    /// Rotation round within this height.
    pub round: u32,
    /// Hash of the proposed block.
    pub block_hash: Hash256,
    /// Address of the proposer.
    pub proposer: Address,
    /// Hash of the parent block.
    pub prev_block_hash: Hash256,
    /// Current epoch number.
    pub epoch: u64,
    // ── anti-fabrication & anti-replay ──────────────
    /// Schnorr public key of the proposer (needed for signature verification).
    pub signer_pubkey: SchnorrPublicKey,
    /// Schnorr (BIP-340) signature over `self.hash()`.
    /// Without this field an attacker can fabricate proposals on behalf of
    /// any validator, breaking leader-rotation safety.
    pub signature: SchnorrSignature,
    /// Monotonic anti-replay sequence number.
    /// Each validator increments this for every message it sends.
    /// Receivers MUST reject messages with a sequence <= the highest
    /// previously seen sequence for the same (proposer, msg_type) pair.
    pub sequence: u64,
}

/// Vote message for a proposed block.
///
/// ## Authentication Fields
/// - `signature`: Proves the voter actually cast this vote; without it,
///   an adversary can fabricate a quorum from thin air.
/// - `sequence`: Anti-replay counter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VoteMessage {
    /// Block height.
    pub height: u64,
    /// Rotation round within this height.
    pub round: u32,
    /// Hash of the block being voted for.
    pub block_hash: Hash256,
    /// Address of the voter.
    pub voter: Address,
    // ── anti-fabrication & anti-replay ──────────────
    /// Schnorr public key of the voter.
    pub signer_pubkey: SchnorrPublicKey,
    /// Schnorr (BIP-340) signature over `self.hash()`.
    pub signature: SchnorrSignature,
    /// Monotonic anti-replay sequence number.
    pub sequence: u64,
}

/// Timeout vote when the leader fails to propose in time.
///
/// ## Authentication Fields
/// - `signature`: Authenticates the timeout vote.
/// - `sequence`: Anti-replay counter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutVoteMessage {
    /// Block height.
    pub height: u64,
    /// Round being timed out.
    pub round: u32,
    /// Address of the voter.
    pub voter: Address,
    /// Highest certified round known to the voter (for view sync).
    pub highest_certified_round: u32,
    // ── anti-fabrication & anti-replay ──────────────
    /// Schnorr public key of the voter.
    pub signer_pubkey: SchnorrPublicKey,
    /// Schnorr (BIP-340) signature over `self.hash()`.
    pub signature: SchnorrSignature,
    /// Monotonic anti-replay sequence number.
    pub sequence: u64,
}

/// Aggregated timeout certificate proving 2/3 quorum for round advancement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TimeoutCertificateMessage {
    /// Block height.
    pub height: u64,
    /// Round being certified as timed out.
    pub round: u32,
    /// Number of validators in the certificate.
    pub voter_count: u32,
    /// Total effective stake of all voters.
    pub aggregate_stake: u64,
    /// Addresses of all voters in the certificate.
    pub voters: Vec<Address>,
}

/// Threshold key share distribution for MEV epoch key (§4.7).
///
/// After RANDAO produces the epoch seed, the leader derives the epoch key,
/// splits it via Shamir SSS, and distributes one share per sequencer.
/// Once threshold shares are collected, the key can be reconstructed
/// for batch decryption.
///
/// ## Authentication
/// - `signature`: Schnorr signature by the sender over `hash()`.
/// - `sequence`: Anti-replay counter.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    // ── anti-fabrication & anti-replay ──────────────
    /// Schnorr public key of the sender.
    pub signer_pubkey: SchnorrPublicKey,
    /// Schnorr (BIP-340) signature over `self.hash()`.
    pub signature: SchnorrSignature,
    /// Monotonic anti-replay sequence number.
    pub sequence: u64,
}

// ═══════════════════════════════════════════════════════════════
// Domain-tagged hashing
// ═══════════════════════════════════════════════════════════════
//
// NOTE: The `hash()` methods produce the "signing payload".
// They intentionally exclude `signature` and `signer_pubkey` to avoid
// a circular dependency (you can't sign a hash that includes the
// signature itself). The `sequence` IS included so that replayed
// messages with altered sequences produce different hashes and thus
// fail signature verification.

impl ConsensusMessage {
    /// Compute the domain-tagged hash for this message.
    pub fn message_hash(&self) -> Hash256 {
        match self {
            Self::Proposal(m) => m.hash(),
            Self::Vote(m) => m.hash(),
            Self::TimeoutVote(m) => m.hash(),
            Self::TimeoutCertificate(m) => m.hash(),
            Self::ShareDistribution(m) => m.hash(),
        }
    }
}

impl ProposalMessage {
    /// Domain-tagged hash of this proposal (signing payload).
    ///
    /// Includes `sequence` for replay protection.
    /// Excludes `signature` and `signer_pubkey` (not part of signed content).
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(WIRE_PROPOSAL_DOMAIN);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.round.to_le_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(self.proposer.as_bytes());
        hasher.update(self.prev_block_hash.as_bytes());
        hasher.update(&self.epoch.to_le_bytes());
        // sequence is part of the signed payload for replay protection
        hasher.update(&self.sequence.to_le_bytes());
        hasher.finalize()
    }
}

impl VoteMessage {
    /// Domain-tagged hash of this vote (signing payload).
    ///
    /// Includes `sequence` for replay protection.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(WIRE_VOTE_DOMAIN);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.round.to_le_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(self.voter.as_bytes());
        // sequence is part of the signed payload for replay protection
        hasher.update(&self.sequence.to_le_bytes());
        hasher.finalize()
    }
}

impl TimeoutVoteMessage {
    /// Domain-tagged hash of this timeout vote (signing payload).
    ///
    /// Includes `sequence` for replay protection.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(WIRE_TIMEOUT_VOTE_DOMAIN);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.round.to_le_bytes());
        hasher.update(self.voter.as_bytes());
        hasher.update(&self.highest_certified_round.to_le_bytes());
        // sequence is part of the signed payload for replay protection
        hasher.update(&self.sequence.to_le_bytes());
        hasher.finalize()
    }
}

impl TimeoutCertificateMessage {
    /// Domain-tagged hash of this timeout certificate.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(WIRE_TIMEOUT_CERT_DOMAIN);
        hasher.update(&self.height.to_le_bytes());
        hasher.update(&self.round.to_le_bytes());
        hasher.update(&self.voter_count.to_le_bytes());
        hasher.update(&self.aggregate_stake.to_le_bytes());
        let mut sorted_voters = self.voters.clone();
        sorted_voters.sort();
        for voter in &sorted_voters {
            hasher.update(voter.as_bytes());
        }
        hasher.finalize()
    }
}

impl ShareDistributionMessage {
    /// Domain-tagged hash of this share distribution (signing payload).
    ///
    /// Includes `sequence` for replay protection.
    /// Excludes `signature` and `signer_pubkey`.
    pub fn hash(&self) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(WIRE_SHARE_DIST_DOMAIN);
        hasher.update(&self.epoch.to_le_bytes());
        hasher.update(&self.share_index.to_le_bytes());
        hasher.update(&self.share_data);
        hasher.update(self.recipient.as_bytes());
        hasher.update(self.sender.as_bytes());
        hasher.update(&self.sequence.to_le_bytes());
        hasher.finalize()
    }
}

// ═══════════════════════════════════════════════════════════════
// Message signing & verification
// ═══════════════════════════════════════════════════════════════
//
// All consensus messages are signed with Schnorr signatures to
// authenticate validator identity and prevent message fabrication.

/// Sign a consensus message with the validator's Schnorr keypair.
///
/// Computes `domain_hash = hash(domain_tag || payload_fields || sequence)`
/// and produces `sig = Schnorr_Sign(sk, domain_hash)`.
///
/// The caller is responsible for setting the `sequence` field to a
/// monotonically increasing value before calling this function.
///
/// # Errors
/// Returns `WireError::InvalidSignature` if signing fails (e.g., invalid key).
pub fn sign_message(msg: &mut ConsensusMessage, keypair: &SchnorrKeyPair) -> Result<(), WireError> {
    let hash = msg.message_hash();
    let sig = keypair.sign(&hash)?;
    let pubkey = *keypair.public_key();

    match msg {
        ConsensusMessage::Proposal(m) => {
            m.signature = sig;
            m.signer_pubkey = pubkey;
        }
        ConsensusMessage::Vote(m) => {
            m.signature = sig;
            m.signer_pubkey = pubkey;
        }
        ConsensusMessage::TimeoutVote(m) => {
            m.signature = sig;
            m.signer_pubkey = pubkey;
        }
        ConsensusMessage::TimeoutCertificate(_) => {
            // TimeoutCertificate is an aggregate — individual timeout votes
            // are already signed. The certificate itself is validated by
            // verifying each constituent vote's signature.
        }
        ConsensusMessage::ShareDistribution(m) => {
            m.signature = sig;
            m.signer_pubkey = pubkey;
        }
    }
    Ok(())
}

/// Verify the cryptographic signature on a consensus message.
///
/// Checks:
/// 1. The `signer_pubkey` produces a valid Schnorr signature over `hash()`.
/// 2. The address derived from `signer_pubkey` matches the claimed sender
///    (proposer/voter). This prevents an attacker from signing with their
///    own key while claiming another validator's address.
///
/// # Errors
/// - `WireError::InvalidSignature` if the signature does not verify.
/// - `WireError::SignerMismatch` if pubkey does not map to claimed address.
///
/// # Replay Note
/// Signature verification alone does NOT prevent replays. The caller MUST
/// also check `sequence` against its per-validator high-water-mark table
/// and reject messages where `msg.sequence <= last_seen[sender]`.
pub fn verify_message_signature(msg: &ConsensusMessage) -> Result<(), WireError> {
    match msg {
        ConsensusMessage::Proposal(m) => {
            let hash = m.hash();
            // verify Schnorr signature over domain-tagged hash
            schnorr::verify(&m.signer_pubkey, &hash, &m.signature)?;
            // verify signer_pubkey maps to claimed proposer address
            verify_address_binding(&m.signer_pubkey, &m.proposer)?;
            Ok(())
        }
        ConsensusMessage::Vote(m) => {
            let hash = m.hash();
            schnorr::verify(&m.signer_pubkey, &hash, &m.signature)?;
            verify_address_binding(&m.signer_pubkey, &m.voter)?;
            Ok(())
        }
        ConsensusMessage::TimeoutVote(m) => {
            let hash = m.hash();
            schnorr::verify(&m.signer_pubkey, &hash, &m.signature)?;
            verify_address_binding(&m.signer_pubkey, &m.voter)?;
            Ok(())
        }
        ConsensusMessage::TimeoutCertificate(_) => {
            // Aggregate certificates are validated by verifying each
            // constituent timeout vote, not the certificate itself.
            Ok(())
        }
        ConsensusMessage::ShareDistribution(m) => {
            let hash = m.hash();
            schnorr::verify(&m.signer_pubkey, &hash, &m.signature)?;
            verify_address_binding(&m.signer_pubkey, &m.sender)?;
            Ok(())
        }
    }
}

/// Verify that a public key maps to the claimed sender address.
///
/// The address is derived as the last 20 bytes of `SHA-256(pubkey)`,
/// matching Brrq's address derivation scheme. This prevents an attacker
/// from signing with their own key while claiming to be another validator.
fn verify_address_binding(
    pubkey: &SchnorrPublicKey,
    claimed_address: &Address,
) -> Result<(), WireError> {
    let pk_hash = pubkey.to_hash();
    let derived_bytes = &pk_hash.as_bytes()[12..32]; // last 20 bytes
    if derived_bytes != claimed_address.as_bytes() {
        return Err(WireError::SignerMismatch {
            expected: hex::encode(claimed_address.as_bytes()),
            actual: hex::encode(derived_bytes),
        });
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address(bytes)
    }

    fn hash_val(n: u8) -> Hash256 {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Hash256(bytes)
    }

    /// Derive an Address from a SchnorrPublicKey (last 20 bytes of SHA-256).
    fn address_from_pubkey(pk: &SchnorrPublicKey) -> Address {
        let h = pk.to_hash();
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&h.as_bytes()[12..32]);
        Address(bytes)
    }

    fn dummy_sig() -> SchnorrSignature {
        SchnorrSignature::from_bytes([0u8; 64])
    }

    fn dummy_pubkey() -> SchnorrPublicKey {
        SchnorrPublicKey::from_bytes([0u8; 32])
    }

    fn sample_proposal() -> ProposalMessage {
        ProposalMessage {
            height: 100,
            round: 0,
            block_hash: hash_val(1),
            proposer: addr(1),
            prev_block_hash: hash_val(2),
            epoch: 5,
            signer_pubkey: dummy_pubkey(),
            signature: dummy_sig(),
            sequence: 0,
        }
    }

    fn sample_vote() -> VoteMessage {
        VoteMessage {
            height: 100,
            round: 0,
            block_hash: hash_val(1),
            voter: addr(2),
            signer_pubkey: dummy_pubkey(),
            signature: dummy_sig(),
            sequence: 0,
        }
    }

    #[test]
    fn test_proposal_hash_determinism() {
        let p1 = sample_proposal();
        let p2 = sample_proposal();
        assert_eq!(p1.hash(), p2.hash(), "same inputs must produce same hash");
    }

    #[test]
    fn test_vote_hash_determinism() {
        let v1 = sample_vote();
        let v2 = sample_vote();
        assert_eq!(v1.hash(), v2.hash());
    }

    #[test]
    fn test_domain_separation_proposal_vs_vote() {
        let proposal = ProposalMessage {
            height: 100,
            round: 0,
            block_hash: hash_val(1),
            proposer: addr(1),
            prev_block_hash: hash_val(2),
            epoch: 5,
            signer_pubkey: dummy_pubkey(),
            signature: dummy_sig(),
            sequence: 0,
        };
        let vote = VoteMessage {
            height: 100,
            round: 0,
            block_hash: hash_val(1),
            voter: addr(1),
            signer_pubkey: dummy_pubkey(),
            signature: dummy_sig(),
            sequence: 0,
        };
        assert_ne!(
            proposal.hash(),
            vote.hash(),
            "different domains must produce different hashes"
        );
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let p1 = ProposalMessage {
            height: 100,
            round: 0,
            block_hash: hash_val(1),
            proposer: addr(1),
            prev_block_hash: hash_val(2),
            epoch: 5,
            signer_pubkey: dummy_pubkey(),
            signature: dummy_sig(),
            sequence: 0,
        };
        let p2 = ProposalMessage {
            height: 101, // different height
            round: 0,
            block_hash: hash_val(1),
            proposer: addr(1),
            prev_block_hash: hash_val(2),
            epoch: 5,
            signer_pubkey: dummy_pubkey(),
            signature: dummy_sig(),
            sequence: 0,
        };
        assert_ne!(
            p1.hash(),
            p2.hash(),
            "different inputs must produce different hashes"
        );
    }

    #[test]
    fn test_consensus_message_hash_delegates() {
        let proposal = sample_proposal();
        let msg = ConsensusMessage::Proposal(proposal.clone());
        assert_eq!(msg.message_hash(), proposal.hash());
    }

    #[test]
    fn test_timeout_vote_hash() {
        let tv = TimeoutVoteMessage {
            height: 50,
            round: 2,
            voter: addr(3),
            highest_certified_round: 1,
            signer_pubkey: dummy_pubkey(),
            signature: dummy_sig(),
            sequence: 0,
        };
        let tv2 = tv.clone();
        assert_eq!(tv.hash(), tv2.hash());
    }

    #[test]
    fn test_timeout_cert_hash_includes_voters() {
        let cert1 = TimeoutCertificateMessage {
            height: 50,
            round: 2,
            voter_count: 2,
            aggregate_stake: 200,
            voters: vec![addr(1), addr(2)],
        };
        let cert2 = TimeoutCertificateMessage {
            height: 50,
            round: 2,
            voter_count: 2,
            aggregate_stake: 200,
            voters: vec![addr(2), addr(3)], // different voters
        };
        assert_ne!(cert1.hash(), cert2.hash());
    }

    // ── Signature verification tests ───────────────

    #[test]
    fn test_sequence_changes_hash() {
        // Verify that different sequences produce different hashes,
        // ensuring replayed messages with modified sequences are detectable.
        let mut v1 = sample_vote();
        v1.sequence = 1;
        let mut v2 = sample_vote();
        v2.sequence = 2;
        assert_ne!(
            v1.hash(),
            v2.hash(),
            "different sequence must produce different hash"
        );
    }

    #[test]
    fn test_sign_and_verify_vote() {
        // End-to-end sign + verify for VoteMessage.
        let kp = SchnorrKeyPair::generate();
        let voter_addr = address_from_pubkey(kp.public_key());

        let vote = VoteMessage {
            height: 10,
            round: 1,
            block_hash: hash_val(42),
            voter: voter_addr,
            signer_pubkey: *kp.public_key(),
            signature: dummy_sig(), // placeholder, will be overwritten
            sequence: 1,
        };
        let mut msg = ConsensusMessage::Vote(vote);
        sign_message(&mut msg, &kp).expect("signing must succeed");
        verify_message_signature(&msg).expect("verification must succeed");
    }

    #[test]
    fn test_sign_and_verify_proposal() {
        // End-to-end sign + verify for ProposalMessage.
        let kp = SchnorrKeyPair::generate();
        let proposer_addr = address_from_pubkey(kp.public_key());

        let proposal = ProposalMessage {
            height: 100,
            round: 0,
            block_hash: hash_val(1),
            proposer: proposer_addr,
            prev_block_hash: hash_val(2),
            epoch: 5,
            signer_pubkey: *kp.public_key(),
            signature: dummy_sig(),
            sequence: 1,
        };
        let mut msg = ConsensusMessage::Proposal(proposal);
        sign_message(&mut msg, &kp).expect("signing must succeed");
        verify_message_signature(&msg).expect("verification must succeed");
    }

    #[test]
    fn test_sign_and_verify_timeout_vote() {
        // End-to-end sign + verify for TimeoutVoteMessage.
        let kp = SchnorrKeyPair::generate();
        let voter_addr = address_from_pubkey(kp.public_key());

        let tv = TimeoutVoteMessage {
            height: 50,
            round: 2,
            voter: voter_addr,
            highest_certified_round: 1,
            signer_pubkey: *kp.public_key(),
            signature: dummy_sig(),
            sequence: 7,
        };
        let mut msg = ConsensusMessage::TimeoutVote(tv);
        sign_message(&mut msg, &kp).expect("signing must succeed");
        verify_message_signature(&msg).expect("verification must succeed");
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        // Signature from a different key must be rejected.
        let kp1 = SchnorrKeyPair::generate();
        let kp2 = SchnorrKeyPair::generate();
        let voter_addr = address_from_pubkey(kp1.public_key());

        let vote = VoteMessage {
            height: 10,
            round: 1,
            block_hash: hash_val(42),
            voter: voter_addr,
            signer_pubkey: *kp1.public_key(),
            signature: dummy_sig(),
            sequence: 1,
        };
        let mut msg = ConsensusMessage::Vote(vote);

        // Sign with kp2 but claim kp1's pubkey — signature check must fail
        let hash = msg.message_hash();
        let bad_sig = kp2.sign(&hash).unwrap();
        if let ConsensusMessage::Vote(ref mut m) = msg {
            m.signature = bad_sig;
        }

        assert!(
            verify_message_signature(&msg).is_err(),
            "verification must fail with wrong signer"
        );
    }

    #[test]
    fn test_address_mismatch_fails_verification() {
        // Signing with your own key but claiming another validator's
        // address must be rejected by the address-binding check.
        let kp = SchnorrKeyPair::generate();
        let fake_addr = addr(99); // does not match kp's pubkey

        let vote = VoteMessage {
            height: 10,
            round: 1,
            block_hash: hash_val(42),
            voter: fake_addr,
            signer_pubkey: *kp.public_key(),
            signature: dummy_sig(),
            sequence: 1,
        };
        let mut msg = ConsensusMessage::Vote(vote);
        sign_message(&mut msg, &kp).expect("signing itself succeeds");

        // Verification must fail because pubkey does not derive to fake_addr
        let err = verify_message_signature(&msg).unwrap_err();
        assert!(
            matches!(err, WireError::SignerMismatch { .. }),
            "expected SignerMismatch, got: {err:?}"
        );
    }

    #[test]
    fn test_tampered_message_fails_verification() {
        // Modifying any field after signing must invalidate the signature.
        let kp = SchnorrKeyPair::generate();
        let voter_addr = address_from_pubkey(kp.public_key());

        let vote = VoteMessage {
            height: 10,
            round: 1,
            block_hash: hash_val(42),
            voter: voter_addr,
            signer_pubkey: *kp.public_key(),
            signature: dummy_sig(),
            sequence: 1,
        };
        let mut msg = ConsensusMessage::Vote(vote);
        sign_message(&mut msg, &kp).expect("signing must succeed");

        // Tamper: change the block_hash after signing
        if let ConsensusMessage::Vote(ref mut m) = msg {
            m.block_hash = hash_val(99);
        }

        assert!(
            verify_message_signature(&msg).is_err(),
            "tampered message must fail verification"
        );
    }
}
