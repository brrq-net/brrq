//! View synchronization protocol — partition recovery.
//!
//! ## Design
//!
//! When the network partitions, different groups of validators may be at
//! different rounds for the same height. Upon rejoin, they need to agree on
//! a common round to continue from.
//!
//! View sync uses **Timeout Certificates** — aggregated timeout votes proving
//! that 2/3 of stake agreed a particular round timed out. The highest certified
//! round becomes the starting point for the next round.
//!
//! ## Partition Recovery
//!
//! 1. Partition A: round 0 → timeout → cert(round=0) → round 1
//! 2. Partition B: round 0 → proposes block, gets <2/3 votes, stalls
//! 3. Rejoin: exchange timeout certificates
//! 4. Both advance to max(certified_round_A, certified_round_B) + 1
//! 5. New leader elected for the advanced round — consensus continues

use std::collections::HashMap;

use brrq_crypto::hash::Hasher;
use brrq_crypto::schnorr::{self, SchnorrPublicKey, SchnorrSignature};
use brrq_types::Address;

use crate::error::ConsensusError;
use crate::wire::TimeoutVoteMessage;

// ═══════════════════════════════════════════════════════════════
// Signing helpers
// ═══════════════════════════════════════════════════════════════

/// Construct the deterministic signing message for a timeout vote.
///
/// The message is `SHA-256(BRRQ_TIMEOUT_VOTE_V1 || height || round)` and is
/// used both when creating a timeout vote signature and when verifying one
/// inside a `TimeoutCertificate`.
pub fn timeout_vote_signing_message(height: u64, round: u32) -> brrq_crypto::hash::Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(brrq_crypto::domain_tags::TIMEOUT_VOTE_V1);
    hasher.update(&height.to_le_bytes());
    hasher.update(&round.to_le_bytes());
    hasher.finalize()
}

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

/// A timeout certificate proving 2/3 quorum agreed to advance past a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutCertificate {
    /// Block height this certificate applies to.
    pub height: u64,
    /// The round being timed out (all voters agree this round failed).
    pub round: u32,
    /// Number of validators who contributed timeout votes.
    pub voter_count: u32,
    /// Total effective stake of the timeout voters.
    pub aggregate_stake: u64,
    /// The highest certified round known to the certificate creator.
    pub highest_certified_round: u32,
    /// Individual voter signatures proving each timeout vote is authentic.
    /// Required to prevent forged timeout certificates.
    pub voter_signatures: Vec<(Address, SchnorrSignature)>,
}

/// View synchronization state for partition recovery.
#[derive(Debug, Clone)]
pub struct ViewSyncState {
    /// Current height being tracked.
    current_height: u64,
    /// The highest round for which we hold a valid `TimeoutCertificate`.
    highest_certified_round: u32,
    /// Stored timeout certificates keyed by (height, round).
    certificates: HashMap<(u64, u32), TimeoutCertificate>,
    /// Pending timeout votes for the current round: voter → (stake, signature).
    pending_timeout_votes: HashMap<Address, (u64, SchnorrSignature)>,
    /// Total effective stake that has submitted timeout votes.
    pending_timeout_stake: u64,
    /// Current round being voted on.
    pending_round: u32,
    /// Total stake in the validator set (for quorum computation).
    total_stake: u64,
    /// Quorum numerator (default 2).
    quorum_numerator: u64,
    /// Quorum denominator (default 3).
    quorum_denominator: u64,
}

impl ViewSyncState {
    /// Create a new view sync state for a height.
    pub fn new(height: u64, total_stake: u64) -> Self {
        Self {
            current_height: height,
            highest_certified_round: 0,
            certificates: HashMap::new(),
            pending_timeout_votes: HashMap::new(),
            pending_timeout_stake: 0,
            pending_round: 0,
            total_stake,
            quorum_numerator: 2,
            quorum_denominator: 3,
        }
    }

    /// Create a local timeout vote for the current round.
    ///
    /// Requires `signer_pubkey` and `sequence` for cryptographic
    /// authentication and replay protection. The caller must call
    /// `sign_message()` on the resulting `ConsensusMessage` before
    /// broadcasting.
    pub fn create_timeout_vote(
        &self,
        voter: Address,
        round: u32,
        signer_pubkey: SchnorrPublicKey,
        sequence: u64,
    ) -> TimeoutVoteMessage {
        TimeoutVoteMessage {
            height: self.current_height,
            round,
            voter,
            highest_certified_round: self.highest_certified_round,
            signer_pubkey,
            signature: SchnorrSignature::from_bytes([0u8; 64]), // placeholder until sign_message()
            sequence,
        }
    }

    /// Submit a single timeout vote. Returns `Some(TimeoutCertificate)` when
    /// 2/3 quorum of effective stake is reached.
    ///
    /// Duplicate votes from the same voter are ignored (no double-counting).
    ///
    /// Requires a `voter_signature` so that the resulting
    /// `TimeoutCertificate` carries proof of each individual vote.
    /// Also requires `validator_pubkeys` to verify the voter's signature
    /// before accepting the vote, preventing forged votes from forming
    /// invalid certificates.
    pub fn submit_timeout_vote(
        &mut self,
        voter: Address,
        voter_stake: u64,
        round: u32,
        voter_signature: SchnorrSignature,
        validator_pubkeys: &HashMap<Address, SchnorrPublicKey>,
    ) -> Result<Option<TimeoutCertificate>, ConsensusError> {
        // Reject votes for past rounds.
        if round < self.highest_certified_round {
            return Ok(None);
        }

        // Reject votes for rounds behind our pending round (forward-only).
        if round < self.pending_round {
            return Ok(None);
        }
        // If round advanced forward, reset pending votes for new round.
        if round > self.pending_round {
            self.pending_timeout_votes.clear();
            self.pending_timeout_stake = 0;
            self.pending_round = round;
        }

        // Verify the voter's signature before accepting the vote.
        let pubkey = validator_pubkeys
            .get(&voter)
            .ok_or(ConsensusError::ValidatorNotFound(voter))?;
        let msg = timeout_vote_signing_message(self.current_height, round);
        schnorr::verify(pubkey, &msg, &voter_signature).map_err(|_| {
            ConsensusError::InvalidBlock {
                reason: format!("invalid timeout vote signature from {}", voter),
            }
        })?;

        // Deduplicate: one vote per voter per round.
        if self.pending_timeout_votes.contains_key(&voter) {
            return Ok(None);
        }

        self.pending_timeout_votes
            .insert(voter, (voter_stake, voter_signature));
        self.pending_timeout_stake = self.pending_timeout_stake.saturating_add(voter_stake);

        // Check quorum: stake * denom >= total * numer (using u128).
        if self.has_quorum(self.pending_timeout_stake) {
            // Collect all individual voter signatures into the certificate.
            let voter_signatures: Vec<(Address, SchnorrSignature)> = self
                .pending_timeout_votes
                .iter()
                .map(|(addr, (_stake, sig))| (*addr, sig.clone()))
                .collect();

            let cert = TimeoutCertificate {
                height: self.current_height,
                round,
                voter_count: self.pending_timeout_votes.len() as u32,
                aggregate_stake: self.pending_timeout_stake,
                highest_certified_round: self.highest_certified_round,
                voter_signatures,
            };

            // Advance highest certified round.
            self.highest_certified_round = round;
            self.certificates
                .insert((self.current_height, round), cert.clone());

            // Reset for next round.
            self.pending_timeout_votes.clear();
            self.pending_timeout_stake = 0;
            self.pending_round = round.saturating_add(1);

            return Ok(Some(cert));
        }

        Ok(None)
    }

    /// Receive and validate a timeout certificate from a peer.
    ///
    /// Returns `Ok(true)` if the certificate advanced our highest certified
    /// round, `Ok(false)` if we're already at or past this round.
    ///
    /// Requires a validator public-key map so that each individual Schnorr
    /// signature in the certificate can be verified cryptographically.
    /// Without this, an attacker could forge a `TimeoutCertificate` with
    /// random bytes for signatures.
    /// This method trusts the claimed `aggregate_stake`
    /// in the certificate without verifying it against actual validator stakes.
    /// An attacker could forge a certificate with inflated stake to bypass
    /// the quorum check. Use `receive_timeout_certificate_with_stakes` instead.
    #[deprecated(
        since = "0.1.0",
        note = "Trusts claimed aggregate_stake without verification. \
                Use receive_timeout_certificate_with_stakes() instead."
    )]
    pub fn receive_timeout_certificate(
        &mut self,
        cert: TimeoutCertificate,
        validator_pubkeys: &HashMap<Address, SchnorrPublicKey>,
    ) -> Result<bool, ConsensusError> {
        self.receive_timeout_certificate_inner(cert, validator_pubkeys, None)
    }

    /// Receive and validate a timeout certificate with full stake verification.
    ///
    /// Like `receive_timeout_certificate`, but additionally verifies that the
    /// claimed `aggregate_stake` matches the actual sum of individual voter stakes.
    /// This prevents an attacker from inflating `aggregate_stake` to bypass
    /// the quorum check.
    pub fn receive_timeout_certificate_with_stakes(
        &mut self,
        cert: TimeoutCertificate,
        validator_pubkeys: &HashMap<Address, SchnorrPublicKey>,
        validator_stakes: &HashMap<Address, u64>,
    ) -> Result<bool, ConsensusError> {
        self.receive_timeout_certificate_inner(cert, validator_pubkeys, Some(validator_stakes))
    }

    fn receive_timeout_certificate_inner(
        &mut self,
        cert: TimeoutCertificate,
        validator_pubkeys: &HashMap<Address, SchnorrPublicKey>,
        validator_stakes: Option<&HashMap<Address, u64>>,
    ) -> Result<bool, ConsensusError> {
        // Must be for our current height.
        if cert.height != self.current_height {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "timeout cert height {} != current {}",
                    cert.height, self.current_height
                ),
            });
        }

        // Reject stale certificates.
        if cert.round <= self.highest_certified_round {
            return Err(ConsensusError::StaleTimeoutCertificate {
                round: cert.round,
                highest: self.highest_certified_round,
            });
        }

        // Validate quorum.
        if !self.has_quorum(cert.aggregate_stake) {
            return Err(ConsensusError::TimeoutCertificateQuorumInsufficient {
                aggregate_stake: cert.aggregate_stake,
                required_stake: self.required_quorum_stake(),
            });
        }

        // Validate voter_count is nonzero and plausible.
        if cert.voter_count == 0 {
            return Err(ConsensusError::InvalidBlock {
                reason: "timeout certificate has zero voters".into(),
            });
        }

        // Verify individual voter signatures are present and consistent
        // with the claimed voter_count.
        if cert.voter_signatures.len() != cert.voter_count as usize {
            return Err(ConsensusError::InvalidBlock {
                reason: format!(
                    "timeout certificate voter_signatures count ({}) != voter_count ({})",
                    cert.voter_signatures.len(),
                    cert.voter_count,
                ),
            });
        }

        // Deduplicate voter addresses before verification.
        // An attacker could include the same voter multiple times to inflate
        // aggregate_stake past the quorum threshold.
        {
            let mut seen = std::collections::HashSet::new();
            for (addr, _sig) in &cert.voter_signatures {
                if !seen.insert(*addr) {
                    return Err(ConsensusError::InvalidBlock {
                        reason: format!("duplicate voter {} in timeout certificate", addr),
                    });
                }
            }
        }

        // Verify each individual Schnorr signature against the validator's
        // public key. This prevents an attacker from filling voter_signatures
        // with random bytes and passing the length check.
        let msg = timeout_vote_signing_message(cert.height, cert.round);
        for (addr, sig) in &cert.voter_signatures {
            let pubkey = validator_pubkeys
                .get(addr)
                .ok_or(ConsensusError::ValidatorNotFound(*addr))?;
            schnorr::verify(pubkey, &msg, sig).map_err(|_| ConsensusError::InvalidBlock {
                reason: format!("invalid timeout signature from {}", addr),
            })?;
        }

        // Recompute aggregate_stake from actual validator stakes rather than
        // trusting the claimed value, preventing inflation attacks.
        if let Some(stakes) = validator_stakes {
            let mut computed_stake: u64 = 0;
            for (addr, _sig) in &cert.voter_signatures {
                let stake = stakes
                    .get(addr)
                    .ok_or(ConsensusError::ValidatorNotFound(*addr))?;
                computed_stake = computed_stake.saturating_add(*stake);
            }
            if computed_stake != cert.aggregate_stake {
                return Err(ConsensusError::InvalidBlock {
                    reason: format!(
                        "timeout certificate aggregate_stake mismatch: claimed {} but computed {}",
                        cert.aggregate_stake, computed_stake
                    ),
                });
            }
            // Re-verify quorum with the computed stake.
            if !self.has_quorum(computed_stake) {
                return Err(ConsensusError::TimeoutCertificateQuorumInsufficient {
                    aggregate_stake: computed_stake,
                    required_stake: self.required_quorum_stake(),
                });
            }
        }

        // Advance.
        self.highest_certified_round = cert.round;
        self.certificates.insert((cert.height, cert.round), cert);

        // Reset pending votes for the next round.
        self.pending_timeout_votes.clear();
        self.pending_timeout_stake = 0;
        self.pending_round = self.highest_certified_round.saturating_add(1);

        Ok(true)
    }

    /// Get the highest certified round.
    pub fn highest_certified_round(&self) -> u32 {
        self.highest_certified_round
    }

    /// Advance to a specific round (used after partition rejoin).
    ///
    /// Target round should be `max(local_highest, peer_highest) + 1`.
    pub fn advance_to_round(&mut self, round: u32) {
        if round > self.highest_certified_round {
            self.highest_certified_round = round;
        }
        self.pending_timeout_votes.clear();
        self.pending_timeout_stake = 0;
        self.pending_round = round.saturating_add(1);
    }

    /// Reset for a new height.
    pub fn reset_for_height(&mut self, height: u64, total_stake: u64) {
        self.current_height = height;
        self.highest_certified_round = 0;
        self.certificates.clear();
        self.pending_timeout_votes.clear();
        self.pending_timeout_stake = 0;
        self.pending_round = 0;
        self.total_stake = total_stake;
    }

    /// Get the current height.
    pub fn height(&self) -> u64 {
        self.current_height
    }

    /// Check if the given stake meets the 2/3 quorum threshold.
    fn has_quorum(&self, stake: u64) -> bool {
        if self.total_stake == 0 {
            return false;
        }
        let lhs = stake as u128 * self.quorum_denominator as u128;
        let rhs = self.total_stake as u128 * self.quorum_numerator as u128;
        lhs >= rhs
    }

    /// Compute the minimum stake required for quorum.
    fn required_quorum_stake(&self) -> u64 {
        // ceil(total * numer / denom)
        let numer = self.total_stake as u128 * self.quorum_numerator as u128;
        let denom = self.quorum_denominator as u128;
        let result = numer.saturating_add(denom).saturating_sub(1) / denom;
        result.min(u64::MAX as u128) as u64
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::schnorr::SchnorrKeyPair;

    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address(bytes)
    }

    /// Dummy signature for tests — not cryptographically valid.
    fn dummy_sig() -> SchnorrSignature {
        SchnorrSignature::from_bytes([0u8; 64])
    }

    /// Create a keypair for testing. Returns `(address, keypair)`.
    fn test_keypair(n: u8) -> (Address, SchnorrKeyPair) {
        let mut bytes = [0u8; 32];
        bytes[31] = n.wrapping_add(1);
        bytes[0] = n.wrapping_add(42);
        let kp = SchnorrKeyPair::from_secret_bytes(&bytes)
            .unwrap_or_else(|_| SchnorrKeyPair::generate());
        (addr(n), kp)
    }

    /// Build a validator pubkey map.
    fn make_pubkey_map(pairs: &[(Address, &SchnorrKeyPair)]) -> HashMap<Address, SchnorrPublicKey> {
        pairs.iter().map(|(a, kp)| (*a, *kp.public_key())).collect()
    }

    /// Create a properly signed timeout certificate.
    fn make_signed_cert(
        height: u64,
        round: u32,
        highest_certified_round: u32,
        signers: &[(Address, &SchnorrKeyPair)],
        stake_each: u64,
    ) -> TimeoutCertificate {
        let msg = timeout_vote_signing_message(height, round);
        let voter_signatures: Vec<(Address, SchnorrSignature)> = signers
            .iter()
            .map(|(a, kp)| (*a, kp.sign(&msg).expect("signing failed")))
            .collect();
        TimeoutCertificate {
            height,
            round,
            voter_count: signers.len() as u32,
            aggregate_stake: stake_each * signers.len() as u64,
            highest_certified_round,
            voter_signatures,
        }
    }

    /// Helper: sign a timeout vote for the given height and round.
    fn sign_timeout_vote(kp: &SchnorrKeyPair, height: u64, round: u32) -> SchnorrSignature {
        let msg = timeout_vote_signing_message(height, round);
        kp.sign(&msg).expect("signing failed")
    }

    #[test]
    fn test_timeout_vote_quorum_creates_certificate() {
        // 3 validators with 100 stake each = total 300.
        // 2/3 quorum requires 200 stake.
        let mut vs = ViewSyncState::new(100, 300);

        let (a1, kp1) = test_keypair(1);
        let (a2, kp2) = test_keypair(2);
        let pubkeys = make_pubkey_map(&[(a1, &kp1), (a2, &kp2)]);

        // First vote: 100 stake — no quorum yet.
        let sig1 = sign_timeout_vote(&kp1, 100, 0);
        let result = vs.submit_timeout_vote(a1, 100, 0, sig1, &pubkeys).unwrap();
        assert!(result.is_none());

        // Second vote: 200 stake total — quorum reached.
        let sig2 = sign_timeout_vote(&kp2, 100, 0);
        let result = vs.submit_timeout_vote(a2, 100, 0, sig2, &pubkeys).unwrap();
        assert!(result.is_some());

        let cert = result.unwrap();
        assert_eq!(cert.height, 100);
        assert_eq!(cert.round, 0);
        assert_eq!(cert.voter_count, 2);
        assert_eq!(cert.aggregate_stake, 200);
        assert_eq!(vs.highest_certified_round(), 0);
    }

    #[test]
    fn test_receive_certificate_advances_round() {
        let mut vs = ViewSyncState::new(100, 300);
        assert_eq!(vs.highest_certified_round(), 0);

        let (a1, kp1) = test_keypair(1);
        let (a2, kp2) = test_keypair(2);
        let pubkeys = make_pubkey_map(&[(a1, &kp1), (a2, &kp2)]);
        let cert = make_signed_cert(100, 3, 2, &[(a1, &kp1), (a2, &kp2)], 100);

        let advanced = vs.receive_timeout_certificate(cert, &pubkeys).unwrap();
        assert!(advanced);
        assert_eq!(vs.highest_certified_round(), 3);
    }

    #[test]
    fn test_stale_certificate_rejected() {
        let mut vs = ViewSyncState::new(100, 300);
        vs.advance_to_round(5);
        let empty_pubkeys: HashMap<Address, SchnorrPublicKey> = HashMap::new();

        // Rejected before sig check (stale round).
        let stale_cert = TimeoutCertificate {
            height: 100,
            round: 3, // older than 5
            voter_count: 2,
            aggregate_stake: 200,
            highest_certified_round: 2,
            voter_signatures: vec![(addr(1), dummy_sig()), (addr(2), dummy_sig())],
        };

        let result = vs.receive_timeout_certificate(stale_cert, &empty_pubkeys);
        assert!(matches!(
            result,
            Err(ConsensusError::StaleTimeoutCertificate {
                round: 3,
                highest: 5
            })
        ));
    }

    #[test]
    fn test_quorum_validation_rejects_insufficient() {
        let mut vs = ViewSyncState::new(100, 300);
        let empty_pubkeys: HashMap<Address, SchnorrPublicKey> = HashMap::new();

        // Rejected before sig check (insufficient quorum).
        let weak_cert = TimeoutCertificate {
            height: 100,
            round: 1,
            voter_count: 1,
            aggregate_stake: 50, // way below 2/3 of 300
            highest_certified_round: 0,
            voter_signatures: vec![(addr(1), dummy_sig())],
        };

        let result = vs.receive_timeout_certificate(weak_cert, &empty_pubkeys);
        assert!(matches!(
            result,
            Err(ConsensusError::TimeoutCertificateQuorumInsufficient { .. })
        ));
    }

    #[test]
    fn test_partition_rejoin_scenario() {
        // Partition A reached round 3, Partition B reached round 5.
        let mut vs_a = ViewSyncState::new(100, 300);
        vs_a.advance_to_round(3);

        let mut vs_b = ViewSyncState::new(100, 300);
        vs_b.advance_to_round(5);

        let (a1, kp1) = test_keypair(1);
        let (a2, kp2) = test_keypair(2);
        let pubkeys = make_pubkey_map(&[(a1, &kp1), (a2, &kp2)]);

        // On rejoin, A receives B's certificate for round 5.
        let cert_b = make_signed_cert(100, 5, 4, &[(a1, &kp1), (a2, &kp2)], 100);

        let advanced = vs_a.receive_timeout_certificate(cert_b, &pubkeys).unwrap();
        assert!(advanced);
        assert_eq!(vs_a.highest_certified_round(), 5);

        // Both are now at round 5 — can advance to round 6 together.
        assert_eq!(
            vs_a.highest_certified_round(),
            vs_b.highest_certified_round()
        );
    }

    #[test]
    fn test_duplicate_timeout_vote_ignored() {
        let mut vs = ViewSyncState::new(100, 300);

        let (a1, kp1) = test_keypair(1);
        let pubkeys = make_pubkey_map(&[(a1, &kp1)]);
        let sig1 = sign_timeout_vote(&kp1, 100, 0);

        // Same voter votes twice — second is ignored.
        let r1 = vs
            .submit_timeout_vote(a1, 100, 0, sig1.clone(), &pubkeys)
            .unwrap();
        assert!(r1.is_none());

        let r2 = vs.submit_timeout_vote(a1, 100, 0, sig1, &pubkeys).unwrap();
        assert!(r2.is_none());
        assert_eq!(vs.pending_timeout_stake, 100); // still 100, not 200
    }

    #[test]
    fn test_reset_for_new_height() {
        let mut vs = ViewSyncState::new(100, 300);
        vs.advance_to_round(5);

        vs.reset_for_height(101, 400);
        assert_eq!(vs.current_height, 101);
        assert_eq!(vs.highest_certified_round(), 0);
        assert_eq!(vs.total_stake, 400);
    }

    #[test]
    fn test_create_timeout_vote() {
        let vs = ViewSyncState::new(100, 300);
        let dummy_pk = SchnorrPublicKey::from_bytes([0u8; 32]);
        let tv = vs.create_timeout_vote(addr(1), 2, dummy_pk, 1);
        assert_eq!(tv.height, 100);
        assert_eq!(tv.round, 2);
        assert_eq!(tv.voter, addr(1));
        assert_eq!(tv.highest_certified_round, 0);
        assert_eq!(tv.sequence, 1);
    }

    #[test]
    fn test_zero_total_stake_no_quorum() {
        let mut vs = ViewSyncState::new(100, 0);
        let (a1, kp1) = test_keypair(1);
        let pubkeys = make_pubkey_map(&[(a1, &kp1)]);
        let sig1 = sign_timeout_vote(&kp1, 100, 0);
        let result = vs.submit_timeout_vote(a1, 100, 0, sig1, &pubkeys).unwrap();
        assert!(result.is_none()); // zero total stake means no quorum possible
    }

    // Test that voter_signatures count must match voter_count.
    #[test]
    fn test_reject_certificate_with_mismatched_signature_count() {
        let mut vs = ViewSyncState::new(100, 300);
        let empty_pubkeys: HashMap<Address, SchnorrPublicKey> = HashMap::new();

        // Claims 2 voters but only provides 1 signature — must be rejected.
        let forged_cert = TimeoutCertificate {
            height: 100,
            round: 1,
            voter_count: 2,
            aggregate_stake: 200,
            highest_certified_round: 0,
            voter_signatures: vec![(addr(1), dummy_sig())], // only 1
        };

        let result = vs.receive_timeout_certificate(forged_cert, &empty_pubkeys);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("voter_signatures count")
        );
    }

    // Test that an empty voter_signatures with nonzero voter_count is rejected.
    #[test]
    fn test_reject_certificate_with_no_signatures() {
        let mut vs = ViewSyncState::new(100, 300);
        let empty_pubkeys: HashMap<Address, SchnorrPublicKey> = HashMap::new();

        let forged_cert = TimeoutCertificate {
            height: 100,
            round: 1,
            voter_count: 2,
            aggregate_stake: 200,
            highest_certified_round: 0,
            voter_signatures: vec![], // no signatures at all
        };

        let result = vs.receive_timeout_certificate(forged_cert, &empty_pubkeys);
        assert!(result.is_err());
    }

    // Test that submit_timeout_vote includes signatures in the certificate.
    #[test]
    fn test_certificate_from_votes_includes_signatures() {
        let mut vs = ViewSyncState::new(100, 300);

        let (a1, kp1) = test_keypair(1);
        let (a2, kp2) = test_keypair(2);
        let pubkeys = make_pubkey_map(&[(a1, &kp1), (a2, &kp2)]);
        let sig1 = sign_timeout_vote(&kp1, 100, 0);
        let sig2 = sign_timeout_vote(&kp2, 100, 0);

        let _ = vs.submit_timeout_vote(a1, 100, 0, sig1, &pubkeys).unwrap();
        let result = vs.submit_timeout_vote(a2, 100, 0, sig2, &pubkeys).unwrap();

        let cert = result.expect("quorum should be reached");
        assert_eq!(cert.voter_signatures.len(), 2);
        assert_eq!(cert.voter_count as usize, cert.voter_signatures.len());
    }

    // Forged signatures with valid count but random bytes must be rejected.
    #[test]
    fn test_c11_forged_signatures_rejected() {
        let mut vs = ViewSyncState::new(100, 300);

        // Create real keypairs so we have a valid pubkey map.
        let (a1, kp1) = test_keypair(1);
        let (a2, kp2) = test_keypair(2);
        let pubkeys = make_pubkey_map(&[(a1, &kp1), (a2, &kp2)]);

        // Certificate with correct count but random (invalid) signatures.
        let forged_cert = TimeoutCertificate {
            height: 100,
            round: 1,
            voter_count: 2,
            aggregate_stake: 200,
            highest_certified_round: 0,
            voter_signatures: vec![
                (a1, SchnorrSignature::from_bytes([0xAB; 64])),
                (a2, SchnorrSignature::from_bytes([0xCD; 64])),
            ],
        };

        let result = vs.receive_timeout_certificate(forged_cert, &pubkeys);
        assert!(result.is_err(), "forged signatures must be rejected");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid timeout signature"),
            "error should mention invalid signature, got: {}",
            err_msg
        );
    }

    // Unknown validator address in signature list must be rejected.
    #[test]
    fn test_c11_unknown_validator_rejected() {
        let mut vs = ViewSyncState::new(100, 300);

        let (a1, kp1) = test_keypair(1);
        // Only register validator 1, not validator 2.
        let pubkeys = make_pubkey_map(&[(a1, &kp1)]);

        let (a2, kp2) = test_keypair(2);
        // Certificate signed by both, but validator 2 is unknown.
        let cert = make_signed_cert(100, 1, 0, &[(a1, &kp1), (a2, &kp2)], 100);

        let result = vs.receive_timeout_certificate(cert, &pubkeys);
        assert!(result.is_err(), "unknown validator must be rejected");
        assert!(matches!(result, Err(ConsensusError::ValidatorNotFound(_))));
    }

    // Valid signatures pass verification successfully.
    #[test]
    fn test_c11_valid_signatures_accepted() {
        let mut vs = ViewSyncState::new(100, 300);

        let (a1, kp1) = test_keypair(1);
        let (a2, kp2) = test_keypair(2);
        let pubkeys = make_pubkey_map(&[(a1, &kp1), (a2, &kp2)]);
        let cert = make_signed_cert(100, 1, 0, &[(a1, &kp1), (a2, &kp2)], 100);

        let result = vs.receive_timeout_certificate(cert, &pubkeys);
        assert!(result.is_ok(), "valid signatures must be accepted");
        assert!(result.unwrap(), "round should have advanced");
        assert_eq!(vs.highest_certified_round(), 1);
    }
}
