//! Stake-weighted leader election.
//!
//! ## Algorithm (§9.1)
//!
//! Leader probability is proportional to effective stake:
//! ```text
//! P_i = EffectiveStake_i / Σ(EffectiveStake_j)
//! ```
//!
//! Selection uses a deterministic hash-based VRF (Verifiable Random Function)
//! seeded with the previous block hash, height, and epoch.
//!
//! ## VRF Leader Election
//!
//! Leader election now uses a VRF (Verifiable Random Function) output to
//! prevent attackers from predicting the next leader and targeting them
//! with DoS attacks. The VRF output is unpredictable before reveal but
//! verifiable after publication.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::schnorr::SchnorrPublicKey;
use brrq_crypto::vrf::{self as crypto_vrf, VrfProof};
use brrq_types::Address;
use serde::{Deserialize, Serialize};

use crate::error::ConsensusError;
use crate::staking::StakingState;

// ── VRF types and functions ──────────────────────────────────

/// VRF output used for unpredictable leader election.
///
/// The VRF output is computed by the current leader using their private key.
/// It is unpredictable before the leader reveals it, but anyone can verify
/// it after publication using the leader's public key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfOutput {
    /// The VRF proof (opaque bytes, scheme-dependent).
    /// In production this would be a cryptographic VRF proof (e.g., ECVRF).
    pub proof: Vec<u8>,
    /// The 32-byte pseudorandom output derived from the proof.
    /// This is the value used for leader selection.
    pub output: [u8; 32],
    /// The public key of the leader who produced this VRF output.
    /// Required for cryptographic proof verification. When `Some`, the VRF
    /// proof is verified against this key before the output is used for
    /// leader election.
    pub leader_pubkey: Option<SchnorrPublicKey>,
    /// The VRF alpha input (domain-tagged bytes) that was used to produce
    /// this VRF output. Required alongside `leader_pubkey` for verification.
    #[serde(default)]
    pub alpha: Vec<u8>,
    /// Structured ECVRF proof components for cryptographic verification.
    /// Stored as serialized components: gamma (33 bytes) || challenge (32 bytes)
    /// || response (32 bytes) || pk_parity (1 byte) = 98 bytes total.
    #[serde(default)]
    pub ecvrf_proof: Vec<u8>,
}

/// Length of a serialized ECVRF proof: gamma(33) + challenge(32) + response(32) + pk_parity(1).
const ECVRF_PROOF_LEN: usize = 33 + 32 + 32 + 1;

impl VrfOutput {
    /// Convert the VRF output to a Hash256 for use in election computations.
    pub fn to_hash(&self) -> Hash256 {
        Hash256::from_bytes(self.output)
    }

    /// Reconstruct a [`VrfProof`] from the serialized `ecvrf_proof` bytes.
    ///
    /// Returns `None` if `ecvrf_proof` is empty or malformed.
    fn to_vrf_proof(&self) -> Option<VrfProof> {
        if self.ecvrf_proof.len() != ECVRF_PROOF_LEN {
            return None;
        }
        let gamma = self.ecvrf_proof[..33].to_vec();
        let challenge: [u8; 32] = self.ecvrf_proof[33..65].try_into().ok()?;
        let response: [u8; 32] = self.ecvrf_proof[65..97].try_into().ok()?;
        let pk_parity = self.ecvrf_proof[97];
        Some(VrfProof {
            gamma,
            challenge,
            response,
            pk_parity,
        })
    }

    /// Serialize a [`VrfProof`] into compact bytes for storage in `ecvrf_proof`.
    pub fn ecvrf_proof_from(proof: &VrfProof) -> Vec<u8> {
        let mut buf = Vec::with_capacity(ECVRF_PROOF_LEN);
        buf.extend_from_slice(&proof.gamma);
        buf.extend_from_slice(&proof.challenge);
        buf.extend_from_slice(&proof.response);
        buf.push(proof.pk_parity);
        buf
    }
}

/// Elect a leader using VRF output for unpredictable selection.
///
/// The election uses `hash(vrf_output || view)` to index into the weighted
/// validator set, ensuring the leader is unpredictable before the VRF
/// output is revealed.
///
/// # Arguments
/// - `validators`: Slice of (address, effective_stake) pairs, pre-sorted.
/// - `vrf_output`: The VRF output from the previous leader.
/// - `view`: The current view/round number.
///
/// # Returns
/// The elected leader's address.
pub fn elect_leader(
    validators: &[(Address, u64)],
    vrf_output: &VrfOutput,
    view: u64,
) -> Result<Address, ConsensusError> {
    if validators.is_empty() {
        return Err(ConsensusError::NoActiveValidators);
    }

    // Compute total effective stake with overflow checking.
    let total: u64 = validators
        .iter()
        .try_fold(0u64, |acc, (_, s)| acc.checked_add(*s))
        .ok_or(ConsensusError::StakeOverflow)?;

    if total == 0 {
        return Err(ConsensusError::NoActiveValidators);
    }

    // ── VRF proof verification ──────────────────────────────────
    // When the VRF output carries a leader public key and an ECVRF proof,
    // verify the proof cryptographically before trusting the output.
    // This prevents an attacker from submitting a forged VRF output to
    // manipulate leader election.
    if let Some(ref leader_pubkey) = vrf_output.leader_pubkey {
        if let Some(crypto_proof) = vrf_output.to_vrf_proof() {
            let crypto_output = crypto_vrf::VrfOutput(vrf_output.output);
            crypto_vrf::vrf_verify(leader_pubkey, &vrf_output.alpha, &crypto_output, &crypto_proof)
                .map_err(|_| ConsensusError::InvalidVrfProof)?;
        } else if !vrf_output.ecvrf_proof.is_empty() {
            // Proof bytes present but malformed — reject.
            return Err(ConsensusError::InvalidVrfProof);
        } else {
            // Empty ecvrf_proof with a leader_pubkey is no longer
            // accepted. An attacker could forge VRF output by providing a
            // leader_pubkey with no proof. All nodes must supply a valid
            // ECVRF proof for leader election.
            return Err(ConsensusError::InvalidVrfProof);
        }
    }

    // M-12: Hash(vrf_output || view) → deterministic but unpredictable index.
    let mut hasher = Hasher::new();
    hasher.update(b"VRF_LEADER_ELECTION_V1");
    hasher.update(&vrf_output.output);
    hasher.update(&view.to_le_bytes());
    let election_hash = hasher.finalize();

    // Use rejection sampling for unbiased modular reduction.
    let val = hash_to_u64(&election_hash);
    let limit = u64::MAX - (u64::MAX % total);
    let random_value = if val < limit {
        val % total
    } else {
        // Rehash with incrementing nonce for rejection sampling.
        let mut nonce = 1u32;
        loop {
            let mut h = Hasher::new();
            h.update(b"VRF_LEADER_ELECTION_V1");
            h.update(&vrf_output.output);
            h.update(&view.to_le_bytes());
            h.update(&nonce.to_le_bytes());
            let hash = h.finalize();
            let v = hash_to_u64(&hash);
            if v < limit {
                break v % total;
            }
            nonce += 1;
        }
    };

    // Select leader using cumulative stake.
    let mut cumulative = 0u64;
    for (addr, stake) in validators {
        cumulative = cumulative.saturating_add(*stake);
        if random_value < cumulative {
            return Ok(*addr);
        }
    }

    // Defense-in-depth: return last validator.
    validators
        .last()
        .map(|(addr, _)| *addr)
        .ok_or(ConsensusError::NoActiveValidators)
}

/// Verify that the claimed leader was correctly elected
/// using the given VRF proof and view number.
///
/// This function re-runs the election with the provided VRF output and
/// checks that the result matches the claimed leader address.
///
/// # Arguments
/// - `leader`: The claimed leader address.
/// - `vrf_proof`: The VRF output (proof + output bytes).
/// - `view`: The view/round number.
/// - `validators`: Slice of (address, effective_stake) pairs, pre-sorted.
///
/// # Returns
/// `true` if the leader was correctly elected, `false` otherwise.
pub fn verify_leader_vrf(
    leader: &Address,
    vrf_proof: &VrfOutput,
    view: u64,
    validators: &[(Address, u64)],
) -> bool {
    match elect_leader(validators, vrf_proof, view) {
        Ok(elected) => &elected == leader,
        Err(_) => false,
    }
}

/// Convert a Hash256 to a u64 value (shared helper).
fn hash_to_u64(hash: &Hash256) -> u64 {
    let bytes = hash.as_bytes();
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Leader election engine.
pub struct LeaderElection;

impl LeaderElection {
    /// Select the leader for a given block height.
    ///
    /// Uses a deterministic hash of (prev_hash, height, round) to select
    /// a leader proportional to effective stake.
    pub fn elect(
        state: &StakingState,
        prev_block_hash: &Hash256,
        height: u64,
        round: u32,
        vrf_seed: &Hash256,
    ) -> Result<Address, ConsensusError> {
        // Gather eligible validators with their effective stakes.
        let mut eligible: Vec<(Address, u64)> = state
            .validators
            .iter()
            .filter(|(_, v)| v.is_eligible(height))
            .map(|(addr, v)| {
                let eff = StakingState::apply_sqrt_cap(v.total_stake(), state.stake_cap);
                (*addr, eff)
            })
            .collect();

        if eligible.is_empty() {
            return Err(ConsensusError::NoActiveValidators);
        }

        // Sort deterministically by address for consistent ordering
        eligible.sort_by_key(|(addr, _)| *addr);

        // Compute total effective stake using checked arithmetic to prevent overflow.
        let total: u64 = eligible
            .iter()
            .try_fold(0u64, |acc, (_, s)| acc.checked_add(*s))
            .ok_or(ConsensusError::StakeOverflow)?;

        // Guard against total == 0, which would cause division by zero
        // in unbiased_mod(). This can happen if all eligible validators have been
        // slashed to zero stake but remain in Active status.
        if total == 0 {
            return Err(ConsensusError::NoActiveValidators);
        }

        // Use rejection sampling to eliminate modular reduction bias.
        // `hash_to_u64() % total` biases toward lower indices when total is not
        // a power of 2. Rejection sampling discards values in the biased tail.
        let random_value = Self::unbiased_mod(prev_block_hash, height, round, vrf_seed, total);

        // Select leader using cumulative stake
        let mut cumulative = 0u64;
        for (addr, stake) in &eligible {
            cumulative = cumulative.saturating_add(*stake);
            if random_value < cumulative {
                return Ok(*addr);
            }
        }

        // Defense-in-depth: should never reach here with correct arithmetic,
        // but return error instead of panicking on adversarial input.
        eligible
            .last()
            .map(|(addr, _)| *addr)
            .ok_or(ConsensusError::NoActiveValidators)
    }

    /// Compute the next N leaders for lookahead using the current epoch VRF seed.
    pub fn lookahead(
        state: &StakingState,
        prev_block_hash: &Hash256,
        start_height: u64,
        count: usize,
        vrf_seed: &Hash256,
    ) -> Result<Vec<(u64, Address)>, ConsensusError> {
        let mut leaders = Vec::with_capacity(count);
        let mut current_hash = *prev_block_hash;

        for i in 0..count {
            let height = start_height + i as u64;
            let leader = Self::elect(state, &current_hash, height, 0, vrf_seed)?;
            leaders.push((height, leader));

            // Chain hashes for deterministic lookahead within the epoch
            let mut hasher = Hasher::new();
            hasher.update(current_hash.as_bytes());
            hasher.update(&height.to_le_bytes());
            current_hash = hasher.finalize();
        }

        Ok(leaders)
    }

    /// Rejection-sampled modular reduction to eliminate bias.
    ///
    /// Computes a uniform random value in `[0, modulus)` by rehashing with
    /// incrementing nonces until the raw u64 falls below the largest
    /// multiple of `modulus` that fits in u64. This guarantees uniform
    /// distribution regardless of whether `modulus` is a power of 2.
    fn unbiased_mod(
        prev_hash: &Hash256,
        height: u64,
        round: u32,
        vrf_seed: &Hash256,
        modulus: u64,
    ) -> u64 {
        let limit = u64::MAX - (u64::MAX % modulus);
        let mut nonce: u32 = 0;
        loop {
            let hash = Self::election_hash_with_nonce(prev_hash, height, round, vrf_seed, nonce);
            let val = Self::hash_to_u64_internal(&hash);
            if val < limit {
                return val % modulus;
            }
            nonce += 1;
        }
    }

    /// Election hash variant that includes a rejection-sampling nonce.
    fn election_hash_with_nonce(
        prev_hash: &Hash256,
        height: u64,
        round: u32,
        vrf_seed: &Hash256,
        nonce: u32,
    ) -> Hash256 {
        let mut hasher = Hasher::new();
        hasher.update(b"LEADER_ELECTION");
        hasher.update(prev_hash.as_bytes());
        hasher.update(&height.to_le_bytes());
        hasher.update(&round.to_le_bytes());
        hasher.update(vrf_seed.as_bytes());
        hasher.update(&nonce.to_le_bytes());
        hasher.finalize()
    }

    /// Convert a Hash256 to a u64 value.
    fn hash_to_u64_internal(hash: &Hash256) -> u64 {
        hash_to_u64(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[0] = n;
        Address(bytes)
    }

    fn setup_state() -> StakingState {
        let mut state = StakingState::new(100_000_000_000); // High cap, no capping
        state.register_validator(addr(1), 1_000_000_000).unwrap(); // 10 BTC
        state.register_validator(addr(2), 2_000_000_000).unwrap(); // 20 BTC
        state.register_validator(addr(3), 3_000_000_000).unwrap(); // 30 BTC
        state
    }

    fn test_vrf_seed() -> Hash256 {
        Hasher::hash(b"test_vrf_seed_entropy")
    }

    #[test]
    fn test_elect_deterministic() {
        let state = setup_state();
        let prev = Hash256::ZERO;
        let seed = test_vrf_seed();

        let leader1 = LeaderElection::elect(&state, &prev, 100, 0, &seed).unwrap();
        let leader2 = LeaderElection::elect(&state, &prev, 100, 0, &seed).unwrap();
        assert_eq!(leader1, leader2);
    }

    #[test]
    fn test_different_heights_may_differ() {
        let state = setup_state();
        let prev = Hash256::ZERO;
        let seed = test_vrf_seed();

        // Run many elections — at least some should differ
        let mut leaders = std::collections::HashSet::new();
        for h in 0..100 {
            let l = LeaderElection::elect(&state, &prev, h, 0, &seed).unwrap();
            leaders.insert(l);
        }
        // With 3 validators and 100 tries, should get more than 1
        assert!(leaders.len() > 1);
    }

    #[test]
    fn test_elect_no_validators() {
        let state = StakingState::new(1_000_000_000);
        let seed = test_vrf_seed();
        let result = LeaderElection::elect(&state, &Hash256::ZERO, 0, 0, &seed);
        assert!(result.is_err());
    }

    #[test]
    fn test_stake_proportional() {
        let state = setup_state();
        let prev = Hash256::ZERO;
        let seed = test_vrf_seed();

        // Run 1000 elections and count wins
        let mut wins = std::collections::HashMap::new();
        for h in 0..1000 {
            let leader = LeaderElection::elect(&state, &prev, h, 0, &seed).unwrap();
            *wins.entry(leader).or_insert(0u32) += 1;
        }

        // addr(3) has 30 BTC (50%), should win roughly 500 times
        // addr(1) has 10 BTC (~16.7%), should win roughly 167 times
        let wins3 = *wins.get(&addr(3)).unwrap_or(&0);
        let wins1 = *wins.get(&addr(1)).unwrap_or(&0);
        // Allow generous tolerance, but addr(3) should win more than addr(1)
        assert!(
            wins3 > wins1,
            "Higher stake should win more: wins3={wins3}, wins1={wins1}"
        );
    }

    #[test]
    fn test_lookahead() {
        let state = setup_state();
        let prev = Hash256::ZERO;
        let seed = test_vrf_seed();

        let lookahead = LeaderElection::lookahead(&state, &prev, 100, 10, &seed).unwrap();
        assert_eq!(lookahead.len(), 10);
        assert_eq!(lookahead[0].0, 100);
        assert_eq!(lookahead[9].0, 109);
    }

    #[test]
    fn test_round_changes_leader() {
        let state = setup_state();
        let prev = Hash256::ZERO;
        let seed = test_vrf_seed();

        // Different rounds may produce different leaders
        let mut leaders = std::collections::HashSet::new();
        for r in 0..100 {
            let l = LeaderElection::elect(&state, &prev, 100, r, &seed).unwrap();
            leaders.insert(l);
        }
        // Should see variation across rounds too
        assert!(leaders.len() > 1);
    }

    #[test]
    fn test_elect_zero_stake_validators() {
        // C-1: All validators have 0 effective stake → should return error, not panic.
        let mut state = StakingState::new(100_000_000_000);
        state.min_validator_stake = 0;
        state.register_validator(addr(1), 0).unwrap();
        state.register_validator(addr(2), 0).unwrap();
        let seed = test_vrf_seed();
        let result = LeaderElection::elect(&state, &Hash256::ZERO, 0, 0, &seed);
        assert!(
            result.is_err(),
            "zero total stake must return error, not panic"
        );
    }

    #[test]
    fn test_different_vrf_seeds_differ() {
        let state = setup_state();
        let prev = Hash256::ZERO;
        let seed1 = Hasher::hash(b"seed_one");
        let seed2 = Hasher::hash(b"seed_two");

        let _leader1 = LeaderElection::elect(&state, &prev, 100, 0, &seed1).unwrap();
        let _leader2 = LeaderElection::elect(&state, &prev, 100, 0, &seed2).unwrap();

        // With different seeds, at least some elections should differ
        let mut differ = false;
        for h in 0..100 {
            let l1 = LeaderElection::elect(&state, &prev, h, 0, &seed1).unwrap();
            let l2 = LeaderElection::elect(&state, &prev, h, 0, &seed2).unwrap();
            if l1 != l2 {
                differ = true;
                break;
            }
        }
        assert!(
            differ,
            "Different VRF seeds should produce different leader schedules"
        );
    }

    // ── VRF leader election tests ────────────────────

    fn test_vrf_output(seed: &[u8]) -> VrfOutput {
        let output = Hasher::hash(seed);
        VrfOutput {
            proof: seed.to_vec(),
            output: *output.as_bytes(),
            leader_pubkey: None,
            alpha: Vec::new(),
            ecvrf_proof: Vec::new(),
        }
    }

    fn setup_validators() -> Vec<(Address, u64)> {
        vec![
            (addr(1), 1_000_000_000), // 10 BTC
            (addr(2), 2_000_000_000), // 20 BTC
            (addr(3), 3_000_000_000), // 30 BTC
        ]
    }

    #[test]
    fn m12_elect_leader_deterministic() {
        let validators = setup_validators();
        let vrf = test_vrf_output(b"deterministic_seed");

        let l1 = elect_leader(&validators, &vrf, 100).unwrap();
        let l2 = elect_leader(&validators, &vrf, 100).unwrap();
        assert_eq!(l1, l2, "Same VRF + view must produce same leader");
    }

    #[test]
    fn m12_elect_leader_different_views() {
        let validators = setup_validators();
        let vrf = test_vrf_output(b"view_test");

        let mut leaders = std::collections::HashSet::new();
        for view in 0..100 {
            let l = elect_leader(&validators, &vrf, view).unwrap();
            leaders.insert(l);
        }
        assert!(
            leaders.len() > 1,
            "Different views should produce different leaders"
        );
    }

    #[test]
    fn m12_elect_leader_different_vrf_outputs() {
        let validators = setup_validators();
        let vrf1 = test_vrf_output(b"vrf_one");
        let vrf2 = test_vrf_output(b"vrf_two");

        let mut differ = false;
        for view in 0..100 {
            let l1 = elect_leader(&validators, &vrf1, view).unwrap();
            let l2 = elect_leader(&validators, &vrf2, view).unwrap();
            if l1 != l2 {
                differ = true;
                break;
            }
        }
        assert!(
            differ,
            "Different VRF outputs must produce different leader schedules"
        );
    }

    #[test]
    fn m12_elect_leader_empty_validators() {
        let vrf = test_vrf_output(b"empty");
        let result = elect_leader(&[], &vrf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn m12_elect_leader_zero_stake() {
        let validators = vec![(addr(1), 0), (addr(2), 0)];
        let vrf = test_vrf_output(b"zero_stake");
        let result = elect_leader(&validators, &vrf, 0);
        assert!(result.is_err(), "Zero total stake must return error");
    }

    #[test]
    fn m12_verify_leader_vrf_correct() {
        let validators = setup_validators();
        let vrf = test_vrf_output(b"verify_correct");
        let leader = elect_leader(&validators, &vrf, 42).unwrap();

        assert!(
            verify_leader_vrf(&leader, &vrf, 42, &validators),
            "Correct leader must verify"
        );
    }

    #[test]
    fn m12_verify_leader_vrf_wrong_leader() {
        let validators = setup_validators();
        let vrf = test_vrf_output(b"verify_wrong");
        let leader = elect_leader(&validators, &vrf, 42).unwrap();

        // Use a different address that isn't the elected leader.
        let wrong_addr = if leader == addr(1) { addr(2) } else { addr(1) };
        assert!(
            !verify_leader_vrf(&wrong_addr, &vrf, 42, &validators),
            "Wrong leader must not verify"
        );
    }

    #[test]
    fn m12_verify_leader_vrf_wrong_view() {
        let validators = setup_validators();
        let vrf = test_vrf_output(b"verify_view");
        let leader = elect_leader(&validators, &vrf, 42).unwrap();

        // Different view number — may elect a different leader.
        // Even if it happens to be the same, this tests the path.
        let _ = verify_leader_vrf(&leader, &vrf, 99, &validators);
    }

    #[test]
    fn m12_verify_leader_vrf_wrong_proof() {
        let validators = setup_validators();
        let vrf = test_vrf_output(b"verify_proof");
        let leader = elect_leader(&validators, &vrf, 42).unwrap();

        // Different VRF output → different election result.
        let bad_vrf = test_vrf_output(b"wrong_proof");
        // This may or may not match; we just ensure it doesn't panic.
        let _ = verify_leader_vrf(&leader, &bad_vrf, 42, &validators);
    }

    #[test]
    fn m12_stake_proportional_with_vrf() {
        let validators = setup_validators();
        let vrf = test_vrf_output(b"proportional");

        let mut wins = std::collections::HashMap::new();
        for view in 0u64..1000 {
            // Use different VRF outputs per view to simulate real usage.
            let mut vrf_i = test_vrf_output(&view.to_le_bytes());
            vrf_i.output =
                *Hasher::hash(&[&vrf.output[..], &view.to_le_bytes()].concat()).as_bytes();
            let leader = elect_leader(&validators, &vrf_i, view).unwrap();
            *wins.entry(leader).or_insert(0u32) += 1;
        }

        let wins3 = *wins.get(&addr(3)).unwrap_or(&0);
        let wins1 = *wins.get(&addr(1)).unwrap_or(&0);
        assert!(
            wins3 > wins1,
            "Higher stake should win more: wins3={wins3}, wins1={wins1}"
        );
    }

    #[test]
    fn m12_vrf_output_struct_serialization() {
        let vrf = test_vrf_output(b"serialize_test");
        let bytes = bincode::serialize(&vrf).unwrap();
        let restored: VrfOutput = bincode::deserialize(&bytes).unwrap();
        assert_eq!(vrf, restored);
    }
}
