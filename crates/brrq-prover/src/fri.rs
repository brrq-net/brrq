//! FRI — Fast Reed-Solomon Interactive Oracle Proof.
//!
//! ## Protocol Overview
//!
//! FRI proves that a committed function is close to a polynomial of bounded degree.
//! It is the core commitment scheme in STARKs.
//!
//! ### Commit Phase
//! 1. Prover commits to polynomial evaluations on a coset domain
//! 2. Verifier sends random folding challenge α
//! 3. Prover folds: P'(x²) = (P(x) + P(-x))/2 + α · (P(x) - P(-x))/(2x)
//! 4. Commit to folded evaluations on halved domain
//! 5. Repeat until polynomial is constant
//!
//! ### Query Phase
//! 1. Verifier selects random query indices
//! 2. Prover opens evaluations at queried positions with Merkle proofs
//! 3. Verifier checks folding consistency between layers
//!
//! ## Field
//!
//! Uses BabyBear (p = 15×2²⁷+1) which supports power-of-2 multiplicative
//! subgroups for efficient FRI folding. SHA-256 Merkle commitments.

use std::sync::LazyLock;

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::merkle::{MerkleTree, Poseidon2MerkleTree};
use serde::{Deserialize, Serialize};

use crate::error::ProverError;
use crate::field::Fp;
use crate::hash_config::ProverHashConfig;
use crate::transcript::Transcript;

/// Cached multiplicative inverse of 2 in BabyBear.
static TWO_INV: LazyLock<Fp> = LazyLock::new(|| Fp::TWO.inv());

/// FRI configuration.
pub struct FriConfig {
    /// Number of queries for soundness.
    pub num_queries: usize,
    /// Maximum number of FRI folding rounds.
    pub max_rounds: usize,
    /// Hash backend for Merkle commitments.
    pub hash_config: ProverHashConfig,
}

impl Default for FriConfig {
    fn default() -> Self {
        Self {
            num_queries: 64, // 64 × log2(4) = 128-bit security
            max_rounds: 20,
            hash_config: ProverHashConfig::default(),
        }
    }
}

/// A single FRI layer: evaluations and their Merkle commitment.
struct FriLayer {
    evaluations: Vec<Fp>,
    merkle_tree: MerkleTree,
    #[allow(dead_code)]
    commitment: Hash256,
    /// Domain generator for this layer.
    #[allow(dead_code)]
    domain_gen: Fp,
}

/// FRI proof data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriProof {
    /// Merkle root commitments for each FRI layer (including initial).
    pub layer_commitments: Vec<Hash256>,
    /// Poseidon2 Merkle root commitments (parallel to `layer_commitments`).
    /// Present only when `ProverHashConfig::DualCommitment` was used.
    #[serde(default)]
    pub poseidon2_commitments: Option<Vec<Hash256>>,
    /// Folding challenges α for each round (derived from Fiat-Shamir).
    pub alphas: Vec<Fp>,
    /// Final constant value after all folding rounds.
    pub final_value: Fp,
    /// Domain sizes for each layer (needed for verification).
    pub layer_sizes: Vec<usize>,
    /// Query openings across all layers.
    pub query_openings: Vec<FriQueryOpening>,
}

/// Opening data for a single FRI query across all layers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriQueryOpening {
    /// Query index in the initial domain (half-domain index).
    pub initial_pos: usize,
    /// For each layer: (value at pos, value at pos+half) = (f(x), f(-x)).
    pub layer_values: Vec<(Fp, Fp)>,
    /// Merkle proofs for f(x) at each layer.
    pub merkle_paths_pos: Vec<Vec<Hash256>>,
    /// Merkle proofs for f(-x) at each layer.
    pub merkle_paths_sibling: Vec<Vec<Hash256>>,
}

// ── Helper functions ──

/// Hash an Fp field element for Merkle leaf.
fn hash_fp(val: Fp) -> Hash256 {
    Hasher::hash(&val.value().to_le_bytes())
}

/// Build a Merkle tree from field element evaluations (one element per leaf).
fn commit_evaluations(evals: &[Fp]) -> (MerkleTree, Hash256) {
    use rayon::prelude::*;
    let leaves: Vec<Hash256> = evals.par_iter().map(|&e| hash_fp(e)).collect();
    let tree = MerkleTree::from_hashes(leaves).expect("FRI evaluation exceeds 16M leaves");
    let root = tree.root();
    (tree, root)
}

/// Build a Poseidon2 Merkle tree from field element evaluations.
///
/// Returns only the root hash — the Poseidon2 tree is used solely for
/// in-circuit verification by the Plonky2 wrapper. The SHA-256 tree
/// remains authoritative for L1 / STARK verification.
///
/// Uses Poseidon2 for leaf hashing (not SHA-256) so in-circuit verification
/// is purely Poseidon2 (~300 constraints/hash vs ~27K for SHA-256).
fn commit_evaluations_poseidon2(evals: &[Fp]) -> Hash256 {
    use brrq_crypto::poseidon2::poseidon2_hash;
    use rayon::prelude::*;
    let leaves: Vec<Hash256> = evals
        .par_iter()
        .map(|&e| poseidon2_hash(&e.value().to_le_bytes()))
        .collect();
    let tree = Poseidon2MerkleTree::from_hashes(leaves)
        .expect("FRI Poseidon2 evaluation exceeds 16M leaves");
    tree.root()
}

/// Perform one FRI folding step.
///
/// Given evaluations of P(x) on domain D of size 2n,
/// compute evaluations of the folded polynomial P'(y) on domain D' of size n.
///
/// The domain has generator g, so D = {g^0, g^1, ..., g^(2n-1)}.
/// Since g^n = -1, the conjugate pairs are (g^i, g^(i+n)) = (x, -x).
///
/// Folding formula:
///   P'(x²) = (P(x) + P(-x))/2 + α · (P(x) - P(-x))/(2x)
///
/// Returns `Err` if evaluations length is < 2 or odd.
pub fn fri_fold(evals: &[Fp], alpha: Fp, domain_gen: Fp) -> Result<Vec<Fp>, ProverError> {
    let n = evals.len();
    if n < 2 || !n.is_multiple_of(2) {
        return Err(ProverError::InvalidTrace {
            reason: format!("FRI fold: need even-length evaluations >= 2, got {}", n),
        });
    }
    let half = n / 2;
    let two_inv = *TWO_INV;

    let mut folded = Vec::with_capacity(half);
    let mut x = Fp::ONE;
    for i in 0..half {
        let f_x = evals[i];
        let f_neg_x = evals[i + half];

        // P_even = (f(x) + f(-x)) / 2
        let p_even = f_x.add(f_neg_x).mul(two_inv);

        // P_odd = (f(x) - f(-x)) / (2x)
        // x is a domain generator power, always nonzero for valid inputs.
        // Use try_inv for defense-in-depth against adversarial evaluations.
        let x_inv = x.try_inv().ok_or_else(|| ProverError::InvalidTrace {
            reason: format!("FRI fold: domain element at index {} is zero", i),
        })?;
        let p_odd = f_x.sub(f_neg_x).mul(two_inv).mul(x_inv);

        // Folded = P_even + α · P_odd
        folded.push(p_even.add(alpha.mul(p_odd)));

        x = x.mul(domain_gen);
    }
    Ok(folded)
}

/// Compute the expected folded value given a conjugate pair.
///
/// Returns `None` if x is zero (invalid domain point).
fn compute_fold_value(f_x: Fp, f_neg_x: Fp, alpha: Fp, x: Fp) -> Option<Fp> {
    let two_inv = *TWO_INV;
    let p_even = f_x.add(f_neg_x).mul(two_inv);
    let x_inv = x.try_inv()?;
    let p_odd = f_x.sub(f_neg_x).mul(two_inv).mul(x_inv);
    Some(p_even.add(alpha.mul(p_odd)))
}

/// Convert leaf index to Merkle path direction indicators.
fn index_to_path(mut index: usize, depth: usize) -> Vec<bool> {
    let mut path = Vec::with_capacity(depth);
    for _ in 0..depth {
        path.push(!index.is_multiple_of(2));
        index /= 2;
    }
    path
}

/// Build a single query opening across all FRI layers.
///
/// For each layer, records (f(x), f(-x)) values and their Merkle proofs
/// at the conjugate-pair positions derived from `initial_pos`.
fn build_query_opening(initial_pos: usize, layers: &[FriLayer]) -> FriQueryOpening {
    let mut layer_values = Vec::new();
    let mut merkle_paths_pos = Vec::new();
    let mut merkle_paths_sibling = Vec::new();
    let mut current_pos = initial_pos;

    for layer in layers {
        let half = layer.evaluations.len() / 2;
        if half == 0 {
            break;
        }
        let pos = current_pos % half;
        let sib = pos + half;

        // Values.
        let f_x = layer.evaluations[pos];
        let f_neg_x = layer.evaluations[sib];
        layer_values.push((f_x, f_neg_x));

        // Merkle proofs.
        let proof_pos = layer.merkle_tree.proof(pos);
        merkle_paths_pos.push(proof_pos.map(|p| p.siblings).unwrap_or_default());

        let proof_sib = layer.merkle_tree.proof(sib);
        merkle_paths_sibling.push(proof_sib.map(|p| p.siblings).unwrap_or_default());

        current_pos = pos;
    }

    FriQueryOpening {
        initial_pos,
        layer_values,
        merkle_paths_pos,
        merkle_paths_sibling,
    }
}

// ══════════════════════════════════════════════════════════════════════
// FRI Prove
// ══════════════════════════════════════════════════════════════════════

/// Generate a FRI proof for polynomial evaluations.
///
/// The evaluations must be on a power-of-2 multiplicative domain.
pub fn fri_prove(
    evaluations: &[Fp],
    domain_gen: Fp,
    config: &FriConfig,
    transcript: &mut Transcript,
) -> Result<FriProof, ProverError> {
    if evaluations.is_empty() {
        return Err(ProverError::EmptyTrace);
    }
    if !evaluations.len().is_power_of_two() {
        return Err(ProverError::InvalidTrace {
            reason: format!(
                "FRI: evaluations length {} is not power of 2",
                evaluations.len()
            ),
        });
    }

    let dual = config.hash_config.has_poseidon2();

    let mut layers: Vec<FriLayer> = Vec::new();
    let mut layer_commitments = Vec::new();
    let mut poseidon2_roots: Vec<Hash256> = Vec::new();
    let mut layer_sizes = Vec::new();
    let mut alphas = Vec::new();

    // ── Initial commitment ──
    let (tree, root) = commit_evaluations(evaluations);
    transcript.absorb_hash(&root);
    layer_commitments.push(root);
    if dual {
        let p2_root = commit_evaluations_poseidon2(evaluations);
        // Bind Poseidon2 commitment to Fiat-Shamir transcript.
        // Without this, an attacker can swap Poseidon2 roots freely
        // since they don't influence challenge derivation.
        transcript.absorb_hash(&p2_root);
        poseidon2_roots.push(p2_root);
    }
    layer_sizes.push(evaluations.len());
    layers.push(FriLayer {
        evaluations: evaluations.to_vec(),
        merkle_tree: tree,
        commitment: root,
        domain_gen,
    });

    // ── Folding rounds ──
    let mut current_evals = evaluations.to_vec();
    let mut current_gen = domain_gen;

    let max_folds = config
        .max_rounds
        .min(evaluations.len().trailing_zeros() as usize - 1); // -1: stop before size 1

    for _ in 0..max_folds {
        if current_evals.len() <= 2 {
            break;
        }

        // Draw folding challenge.
        let alpha = transcript.challenge_field();
        alphas.push(alpha);

        // Fold.
        current_evals = fri_fold(&current_evals, alpha, current_gen)?;
        current_gen = current_gen.mul(current_gen); // Square the generator.

        // Commit.
        let (tree, root) = commit_evaluations(&current_evals);
        transcript.absorb_hash(&root);
        layer_commitments.push(root);
        if dual {
            let p2_root = commit_evaluations_poseidon2(&current_evals);
            transcript.absorb_hash(&p2_root);
            poseidon2_roots.push(p2_root);
        }
        layer_sizes.push(current_evals.len());
        layers.push(FriLayer {
            evaluations: current_evals.clone(),
            merkle_tree: tree,
            commitment: root,
            domain_gen: current_gen,
        });
    }

    // ── Final constant ──
    let final_value = if current_evals.is_empty() {
        Fp::ZERO
    } else {
        current_evals[0]
    };
    transcript.absorb_fp(final_value);

    // ── Query phase ──
    let initial_half = evaluations.len() / 2;
    let mut query_openings = Vec::with_capacity(config.num_queries);

    for _ in 0..config.num_queries {
        let initial_pos = transcript.challenge_index(initial_half);
        query_openings.push(build_query_opening(initial_pos, &layers));
    }

    Ok(FriProof {
        layer_commitments,
        poseidon2_commitments: if dual { Some(poseidon2_roots) } else { None },
        alphas,
        final_value,
        layer_sizes,
        query_openings,
    })
}

// ══════════════════════════════════════════════════════════════════════
// FRI Verify
// ══════════════════════════════════════════════════════════════════════

/// Verify a FRI proof.
///
/// Checks:
/// 1. Fiat-Shamir transcript consistency
/// 2. Merkle authentication for all query openings
/// 3. **Folding consistency** between adjacent layers (the critical check)
/// 4. Final value consistency
pub fn fri_verify(
    proof: &FriProof,
    initial_commitment: &Hash256,
    initial_domain_gen: Fp,
    _config: &FriConfig,
    transcript: &mut Transcript,
) -> Result<bool, ProverError> {
    validate_fri_proof_structure(proof, initial_commitment)?;

    // ── Replay Fiat-Shamir and verify challenges ──
    replay_fiat_shamir(proof, initial_commitment, transcript)?;

    // ── Reconstruct domain generators ──
    let domain_gens = build_domain_generators(initial_domain_gen, proof.layer_commitments.len());

    // ── Verify each query opening ──
    for opening in &proof.query_openings {
        verify_query_opening(proof, opening, &domain_gens)?;
    }

    Ok(true)
}

/// Validate basic FRI proof structure before detailed verification.
fn validate_fri_proof_structure(
    proof: &FriProof,
    initial_commitment: &Hash256,
) -> Result<(), ProverError> {
    if proof.layer_commitments.is_empty() {
        return Err(ProverError::InvalidProof {
            reason: "no FRI layer commitments".into(),
        });
    }

    const MAX_FRI_LAYERS: usize = 32;
    if proof.layer_commitments.len() > MAX_FRI_LAYERS {
        return Err(ProverError::InvalidProof {
            reason: "too many FRI layers".into(),
        });
    }
    if proof.query_openings.len() > 256 {
        return Err(ProverError::InvalidProof {
            reason: "too many FRI query openings".into(),
        });
    }

    if proof.layer_commitments[0] != *initial_commitment {
        return Err(ProverError::CommitmentMismatch { index: 0 });
    }

    Ok(())
}

/// Replay Fiat-Shamir transcript and verify folding challenges match.
fn replay_fiat_shamir(
    proof: &FriProof,
    initial_commitment: &Hash256,
    transcript: &mut Transcript,
) -> Result<(), ProverError> {
    transcript.absorb_hash(initial_commitment);

    // If Poseidon2 commitments are present, absorb initial one into transcript.
    if let Some(p2_commits) = &proof.poseidon2_commitments {
        if !p2_commits.is_empty() {
            transcript.absorb_hash(&p2_commits[0]);
        }
    }

    for (i, commitment) in proof.layer_commitments.iter().skip(1).enumerate() {
        let alpha = transcript.challenge_field();

        // Verify challenge matches proof.
        if i < proof.alphas.len() && proof.alphas[i] != alpha {
            return Err(ProverError::InvalidProof {
                reason: format!("FRI: alpha mismatch at round {i}"),
            });
        }

        transcript.absorb_hash(commitment);
        // Absorb corresponding Poseidon2 commitment if present.
        if let Some(p2_commits) = &proof.poseidon2_commitments {
            if let Some(p2_root) = p2_commits.get(i + 1) {
                transcript.absorb_hash(p2_root);
            }
        }
    }
    transcript.absorb_fp(proof.final_value);

    Ok(())
}

/// Build domain generators for each FRI layer by successive squaring.
fn build_domain_generators(initial_domain_gen: Fp, num_layers: usize) -> Vec<Fp> {
    let mut domain_gens = Vec::with_capacity(num_layers);
    let mut cur_gen = initial_domain_gen;
    for _ in 0..num_layers {
        domain_gens.push(cur_gen);
        cur_gen = cur_gen.mul(cur_gen);
    }
    domain_gens
}

/// Verify a single FRI evaluation opening at a given leaf position.
///
/// Rejects empty or missing Merkle paths. An attacker can pass
/// empty siblings to bypass Merkle authentication entirely, allowing
/// arbitrary claimed evaluations without any commitment binding.
///
/// MerkleTree::from_hashes applies hash_leaf() to inputs,
/// so the verifier must also domain-separate the recomputed leaf hash.
fn verify_layer_merkle_auth(
    value: Fp,
    leaf_index: usize,
    paths: &[Vec<Hash256>],
    layer_idx: usize,
    commitment: &Hash256,
    label: &str,
    query_id: usize,
) -> Result<(), ProverError> {
    if layer_idx >= paths.len() {
        // Missing Merkle path entirely for this layer.
        return Err(ProverError::InvalidProof {
            reason: format!(
                "FRI: missing Merkle path for {label} at layer {layer_idx}, query {query_id}"
            ),
        });
    }
    let path = &paths[layer_idx];
    // Reject empty Merkle paths.
    if path.is_empty() {
        return Err(ProverError::InvalidProof {
            reason: format!(
                "FRI: empty Merkle path for {label} at layer {layer_idx}, query {query_id} — \
                 proof authentication bypassed"
            ),
        });
    }
    let leaf = Hasher::hash_leaf(hash_fp(value).as_bytes());
    let merkle_proof = brrq_crypto::merkle::MerkleProof {
        leaf,
        siblings: path.clone(),
        path_indices: index_to_path(leaf_index, path.len()),
    };
    if !merkle_proof.verify(commitment) {
        return Err(ProverError::InvalidProof {
            reason: format!(
                "FRI: Merkle proof failed for {label} at layer {layer_idx}, query {query_id}"
            ),
        });
    }
    Ok(())
}

/// Verify a single query opening across all FRI layers: Merkle auth,
/// folding consistency, and final value cross-check.
fn verify_query_opening(
    proof: &FriProof,
    opening: &FriQueryOpening,
    domain_gens: &[Fp],
) -> Result<(), ProverError> {
    let mut current_pos = opening.initial_pos;

    for (layer_idx, &(f_x, f_neg_x)) in opening.layer_values.iter().enumerate() {
        if layer_idx >= proof.layer_commitments.len() || layer_idx >= proof.layer_sizes.len() {
            break;
        }

        let half = proof.layer_sizes[layer_idx] / 2;
        if half == 0 {
            return Err(ProverError::InvalidProof {
                reason: format!("FRI: layer {layer_idx} has zero half-size"),
            });
        }
        let pos = current_pos % half;
        let sib = pos + half;

        // Merkle proof for f(x)
        verify_layer_merkle_auth(
            f_x, pos,
            &opening.merkle_paths_pos, layer_idx,
            &proof.layer_commitments[layer_idx],
            "f(x)", opening.initial_pos,
        )?;

        // Merkle proof for f(-x)
        verify_layer_merkle_auth(
            f_neg_x, sib,
            &opening.merkle_paths_sibling, layer_idx,
            &proof.layer_commitments[layer_idx],
            "f(-x)", opening.initial_pos,
        )?;

        // ── Folding consistency check ──
        // The fold of (f(x), f(-x)) at layer k produces a value at position
        // `pos` in layer k+1. If pos < next_layer_half, this value appears as
        // f_x of the next query pair. If pos >= next_layer_half, it appears as
        // f_neg_x (the sibling element).
        if layer_idx + 1 < opening.layer_values.len() && layer_idx < proof.alphas.len() {
            verify_folding_consistency(
                proof, opening, domain_gens, layer_idx, f_x, f_neg_x, pos,
            )?;
        }

        current_pos = pos;
    }

    // ── Final value cross-check ──
    // After all folding rounds, the last folded value from this query
    // must equal `proof.final_value`. Without this check an attacker
    // can claim an arbitrary final_value that is never tied to the
    // actual query evaluations.
    verify_final_value(proof, opening, domain_gens, current_pos)
}

/// Verify folding consistency between adjacent FRI layers.
fn verify_folding_consistency(
    proof: &FriProof,
    opening: &FriQueryOpening,
    domain_gens: &[Fp],
    layer_idx: usize,
    f_x: Fp,
    f_neg_x: Fp,
    pos: usize,
) -> Result<(), ProverError> {
    let alpha = proof.alphas[layer_idx];
    let x = domain_gens[layer_idx].pow(pos as u64);

    // Compute expected folded value.
    let expected_folded =
        compute_fold_value(f_x, f_neg_x, alpha, x).ok_or_else(|| {
            ProverError::InvalidProof {
                reason: format!(
                    "FRI: domain element is zero at layer {layer_idx}, pos {pos}"
                ),
            }
        })?;

    // Determine which element of the next layer's pair holds the folded value.
    let next_half = if layer_idx + 1 < proof.layer_sizes.len() {
        proof.layer_sizes[layer_idx + 1] / 2
    } else {
        1
    };
    let (next_fx, next_fnx) = opening.layer_values[layer_idx + 1];
    let actual_folded = if pos < next_half { next_fx } else { next_fnx };

    if expected_folded != actual_folded {
        return Err(ProverError::InvalidProof {
            reason: format!(
                "FRI: folding consistency failed at layer {layer_idx}, query {}. \
                 Expected {}, got {}",
                opening.initial_pos, expected_folded, actual_folded
            ),
        });
    }
    Ok(())
}

/// Verify the final value cross-check for a query opening.
///
/// After all folding rounds, the last folded value must equal
/// `proof.final_value`.
fn verify_final_value(
    proof: &FriProof,
    opening: &FriQueryOpening,
    domain_gens: &[Fp],
    current_pos: usize,
) -> Result<(), ProverError> {
    let Some(&(last_fx, last_fnx)) = opening.layer_values.last() else {
        return Ok(());
    };
    let last_layer_idx = opening.layer_values.len() - 1;

    // If there is a folding alpha for the last layer, compute the
    // folded value and compare against final_value.
    if last_layer_idx < proof.alphas.len() && last_layer_idx < domain_gens.len() {
        let alpha = proof.alphas[last_layer_idx];
        let half = if last_layer_idx < proof.layer_sizes.len() {
            proof.layer_sizes[last_layer_idx] / 2
        } else {
            1
        };
        let pos = current_pos % half.max(1);
        let x = domain_gens[last_layer_idx].pow(pos as u64);

        let folded = compute_fold_value(last_fx, last_fnx, alpha, x).ok_or_else(|| {
            ProverError::InvalidProof {
                reason: format!(
                    "FRI: domain element is zero at final layer {last_layer_idx}, pos {pos}"
                ),
            }
        })?;

        if folded != proof.final_value {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "FRI: final value mismatch for query {}. \
                     Expected {}, got {}",
                    opening.initial_pos, proof.final_value, folded
                ),
            });
        }
    } else if opening.layer_values.len() == 1 {
        // Only one layer (no folding): the value at the query position
        // in the last committed layer should itself be the final value.
        // Use the element at the query's position within the last layer.
        let half = if !proof.layer_sizes.is_empty() {
            proof.layer_sizes[0] / 2
        } else {
            1
        };
        let pos = opening.initial_pos % half.max(1);
        let actual = if pos < half { last_fx } else { last_fnx };
        if actual != proof.final_value {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "FRI: final value mismatch (single layer) for query {}. \
                     Expected {}, got {}",
                    opening.initial_pos, proof.final_value, actual
                ),
            });
        }
    } else if proof.alphas.len() == last_layer_idx {
        // n layers, exactly n-1 alphas: all inter-layer folds
        // were verified in the main loop above.  The value at
        // the last layer position must match the claimed
        // final_value -- compare directly (no extra fold needed).
        let half = if last_layer_idx < proof.layer_sizes.len() {
            proof.layer_sizes[last_layer_idx] / 2
        } else {
            1
        };
        let pos = current_pos % half.max(1);
        let actual = if pos < half { last_fx } else { last_fnx };
        if actual != proof.final_value {
            return Err(ProverError::InvalidProof {
                reason: format!(
                    "FRI: final value mismatch for query {} (last layer {}). \
                     Expected {}, got {}",
                    opening.initial_pos, last_layer_idx, proof.final_value, actual
                ),
            });
        }
    } else {
        // Multiple layers but fewer alphas than layers-1.
        // The main folding loop skipped some inter-layer
        // transitions, leaving those layers unverified.
        // An attacker can exploit this to bypass the
        // final-value cross-check entirely.
        return Err(ProverError::InvalidProof {
            reason: format!(
                "FRI: insufficient alphas — have {} but need {} for {} layers. \
                 Proof is structurally invalid.",
                proof.alphas.len(),
                last_layer_idx,
                opening.layer_values.len()
            ),
        });
    }

    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{self, Domain};

    /// Create polynomial evaluations on a power-of-2 domain.
    fn make_polynomial_evals(coeffs: &[Fp], log_domain_size: u32) -> (Vec<Fp>, Fp) {
        let domain = Domain::new(log_domain_size);
        let evals = field::poly_eval_domain(coeffs, &domain);
        (evals, domain.generator)
    }

    #[test]
    fn test_fri_fold_halves_size() {
        let (evals, omega) = make_polynomial_evals(&[Fp::new(1), Fp::new(2), Fp::new(3)], 4);
        let alpha = Fp::new(7);
        let folded = fri_fold(&evals, alpha, omega).unwrap();
        assert_eq!(folded.len(), 8);
    }

    #[test]
    fn test_fri_fold_constant_polynomial() {
        let (evals, omega) = make_polynomial_evals(&[Fp::new(42)], 3);
        let alpha = Fp::new(99);
        let folded = fri_fold(&evals, alpha, omega).unwrap();
        for (i, &v) in folded.iter().enumerate() {
            assert_eq!(v.value(), 42, "folded[{i}] should be 42");
        }
    }

    #[test]
    fn test_commit_evaluations() {
        let evals: Vec<Fp> = (0..8).map(|i| Fp::new(i + 1)).collect();
        let (tree, root) = commit_evaluations(&evals);
        assert_ne!(root, Hash256::ZERO);
        assert_eq!(tree.leaf_count(), 8);
    }

    #[test]
    fn test_fri_prove_verify_roundtrip() {
        let coeffs: Vec<Fp> = (1..=4).map(Fp::new).collect();
        let (evals, omega) = make_polynomial_evals(&coeffs, 4);

        // Explicitly test SHA-256 only path (no Poseidon2).
        let config = FriConfig {
            num_queries: 5,
            max_rounds: 3,
            hash_config: ProverHashConfig::Sha256,
        };

        let mut transcript_p = Transcript::new(b"fri_test");
        let proof = fri_prove(&evals, omega, &config, &mut transcript_p).unwrap();

        assert!(!proof.layer_commitments.is_empty());
        assert!(!proof.query_openings.is_empty());
        assert!(proof.poseidon2_commitments.is_none());

        let initial_commitment = proof.layer_commitments[0];
        let mut transcript_v = Transcript::new(b"fri_test");
        let result = fri_verify(
            &proof,
            &initial_commitment,
            omega,
            &config,
            &mut transcript_v,
        )
        .unwrap();
        assert!(result);
    }

    #[test]
    fn test_fri_different_polys_different_commitments() {
        let config = FriConfig {
            num_queries: 3,
            max_rounds: 2,
            hash_config: ProverHashConfig::default(),
        };

        let (evals1, omega1) = make_polynomial_evals(&[Fp::new(1), Fp::new(2)], 3);
        let (evals2, omega2) = make_polynomial_evals(&[Fp::new(3), Fp::new(4)], 3);

        let mut t1 = Transcript::new(b"test1");
        let mut t2 = Transcript::new(b"test1");

        let proof1 = fri_prove(&evals1, omega1, &config, &mut t1).unwrap();
        let proof2 = fri_prove(&evals2, omega2, &config, &mut t2).unwrap();

        assert_ne!(proof1.layer_commitments[0], proof2.layer_commitments[0]);
    }

    #[test]
    fn test_compute_fold_value_consistency() {
        // Check that fold function and verify function agree.
        let f_x = Fp::new(10);
        let f_neg_x = Fp::new(6);
        let alpha = Fp::new(3);
        let x = Fp::new(5);

        let expected = compute_fold_value(f_x, f_neg_x, alpha, x).unwrap();
        // Should be deterministic.
        let expected2 = compute_fold_value(f_x, f_neg_x, alpha, x).unwrap();
        assert_eq!(expected, expected2);

        // Wrong value should differ.
        assert_ne!(expected, Fp::new(999));
    }

    #[test]
    fn test_compute_fold_value_zero_x_returns_none() {
        let f_x = Fp::new(10);
        let f_neg_x = Fp::new(6);
        let alpha = Fp::new(3);
        assert!(compute_fold_value(f_x, f_neg_x, alpha, Fp::ZERO).is_none());
    }

    #[test]
    fn test_fri_fold_odd_length_returns_error() {
        let evals = vec![Fp::new(1), Fp::new(2), Fp::new(3)]; // len=3
        let result = fri_fold(&evals, Fp::new(7), Fp::new(5));
        assert!(result.is_err());
    }

    #[test]
    fn test_fri_fold_empty_returns_error() {
        let result = fri_fold(&[], Fp::new(7), Fp::new(5));
        assert!(result.is_err());
    }

    // Verify that empty Merkle paths are rejected.
    #[test]
    fn test_fri_empty_merkle_paths_rejected() {
        let coeffs: Vec<Fp> = (1..=4).map(Fp::new).collect();
        let (evals, omega) = make_polynomial_evals(&coeffs, 4);

        let config = FriConfig {
            num_queries: 5,
            max_rounds: 3,
            hash_config: ProverHashConfig::Sha256,
        };

        let mut transcript_p = Transcript::new(b"fri_c02_test");
        let mut proof = fri_prove(&evals, omega, &config, &mut transcript_p).unwrap();

        // Tamper: clear all Merkle paths for f(x) in the first query opening
        if !proof.query_openings.is_empty() && !proof.query_openings[0].merkle_paths_pos.is_empty()
        {
            proof.query_openings[0].merkle_paths_pos[0] = vec![];
        }

        let initial_commitment = proof.layer_commitments[0];
        let mut transcript_v = Transcript::new(b"fri_c02_test");
        let result = fri_verify(
            &proof,
            &initial_commitment,
            omega,
            &config,
            &mut transcript_v,
        );
        assert!(
            result.is_err(),
            "FRI proof with empty Merkle paths must be rejected (C-02)"
        );
    }

    #[test]
    fn test_fri_dual_commitment_produces_poseidon2_roots() {
        let coeffs: Vec<Fp> = (1..=4).map(Fp::new).collect();
        let (evals, omega) = make_polynomial_evals(&coeffs, 4);

        let config = FriConfig {
            num_queries: 5,
            max_rounds: 3,
            hash_config: ProverHashConfig::DualCommitment,
        };

        let mut transcript = Transcript::new(b"dual_test");
        let proof = fri_prove(&evals, omega, &config, &mut transcript).unwrap();

        // Dual mode: Poseidon2 roots must be present and match layer count.
        let p2 = proof
            .poseidon2_commitments
            .as_ref()
            .expect("should have poseidon2 roots");
        assert_eq!(p2.len(), proof.layer_commitments.len());

        // Poseidon2 roots must differ from SHA-256 roots (different hash functions).
        for (sha, pos) in proof.layer_commitments.iter().zip(p2.iter()) {
            assert_ne!(sha, pos, "SHA-256 and Poseidon2 roots should differ");
        }

        // SHA-256 verification still works (transcript is authoritative over SHA-256).
        let initial_commitment = proof.layer_commitments[0];
        let mut transcript_v = Transcript::new(b"dual_test");
        let result = fri_verify(
            &proof,
            &initial_commitment,
            omega,
            &config,
            &mut transcript_v,
        )
        .unwrap();
        assert!(result);
    }
}
