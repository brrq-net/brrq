//! Merkle Tree with pluggable hash backends — Layer 3 of PHA.
//!
//! Supports two hash backends:
//! - **SHA-256** (default): External-facing state data committed to Bitcoin L1
//! - **Poseidon2**: Internal zkVM state (~138x fewer ZK constraints)
//!
//! See whitepaper §3.5 for the dual-hash architecture.

use std::marker::PhantomData;

use crate::hash::{Hash256, Hasher};
use crate::poseidon2::{poseidon2_hash, poseidon2_hash_leaf, poseidon2_hash_node};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Error type ──────────────────────────────────────────────────────────────

/// Errors from Merkle tree operations.
#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("tree exceeds maximum leaf count ({count} > {max})")]
    TooManyLeaves { count: usize, max: usize },
}

// ── MerkleHasher Trait ──────────────────────────────────────────────────────

/// Abstraction over the hash function used by a Merkle tree.
///
/// Implementations must provide domain-separated leaf and node hashing
/// to prevent second-preimage attacks.
pub trait MerkleHasher: Clone {
    /// Hash raw leaf data with domain separation (distinct from node hashing).
    fn hash_leaf(data: &[u8]) -> Hash256;
    /// Hash two child nodes into a parent with domain separation.
    fn hash_node(left: &Hash256, right: &Hash256) -> Hash256;
    /// Hash arbitrary data (used for sentinel computation).
    fn hash_raw(data: &[u8]) -> Hash256;
}

/// SHA-256 Merkle hasher — default for L1-facing commitments.
#[derive(Clone, Debug)]
pub struct Sha256Hasher;

impl MerkleHasher for Sha256Hasher {
    #[inline]
    fn hash_leaf(data: &[u8]) -> Hash256 {
        Hasher::hash_leaf(data)
    }
    #[inline]
    fn hash_node(left: &Hash256, right: &Hash256) -> Hash256 {
        Hasher::hash_node(left, right)
    }
    #[inline]
    fn hash_raw(data: &[u8]) -> Hash256 {
        Hasher::hash(data)
    }
}

/// Poseidon2 Merkle hasher — for ZK-internal commitments (~138x cheaper in-circuit).
#[derive(Clone, Debug)]
pub struct Poseidon2Hasher;

impl MerkleHasher for Poseidon2Hasher {
    #[inline]
    fn hash_leaf(data: &[u8]) -> Hash256 {
        poseidon2_hash_leaf(data)
    }
    #[inline]
    fn hash_node(left: &Hash256, right: &Hash256) -> Hash256 {
        poseidon2_hash_node(left, right)
    }
    #[inline]
    fn hash_raw(data: &[u8]) -> Hash256 {
        poseidon2_hash(data)
    }
}

// ── MerkleProof ─────────────────────────────────────────────────────────────

/// A Merkle proof for verifying inclusion of a leaf in a Merkle tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// The leaf hash being proved.
    pub leaf: Hash256,
    /// Sibling hashes along the path from leaf to root.
    pub siblings: Vec<Hash256>,
    /// Path direction indicators (false = left, true = right).
    pub path_indices: Vec<bool>,
}

impl MerkleProof {
    /// Verify this proof against a known root using SHA-256 (default).
    #[inline]
    pub fn verify(&self, root: &Hash256) -> bool {
        self.verify_with::<Sha256Hasher>(root)
    }

    /// Verify this proof using a specific hash backend.
    pub fn verify_with<H: MerkleHasher>(&self, root: &Hash256) -> bool {
        let mut current = self.leaf;

        if self.siblings.len() != self.path_indices.len() {
            return false;
        }

        for (sibling, is_right) in self.siblings.iter().zip(self.path_indices.iter()) {
            current = if *is_right {
                H::hash_node(sibling, &current)
            } else {
                H::hash_node(&current, sibling)
            };
        }

        current == *root
    }

    /// Get the depth of this proof.
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }

    /// Estimated size in bytes.
    pub fn size_bytes(&self) -> usize {
        32 + // leaf
        self.siblings.len() * 32 + // siblings
        self.path_indices.len() // path indices
    }
}

// ── MerkleTree ──────────────────────────────────────────────────────────────

/// A complete Merkle tree parameterized by its hash backend.
///
/// Default: `MerkleTree` (alias for `MerkleTree<Sha256Hasher>`) — backward-compatible
/// with all existing code. Use `MerkleTree<Poseidon2Hasher>` for ZK-internal trees.
#[derive(Clone, Debug)]
pub struct MerkleTree<H: MerkleHasher = Sha256Hasher> {
    /// All leaves (bottom layer).
    leaves: Vec<Hash256>,
    /// All tree layers, from leaves (index 0) to root.
    layers: Vec<Vec<Hash256>>,
    /// Hash backend marker.
    _hasher: PhantomData<H>,
}

impl<H: MerkleHasher> MerkleTree<H> {
    /// Build a Merkle tree from pre-hashed leaves.
    ///
    /// All inputs are passed through `hash_leaf()` (domain-separated) to prevent
    /// second-preimage attacks. Odd-leaf duplication uses a sentinel hash to
    /// prevent phantom leaf inclusion proofs. Maximum tree depth is enforced.
    pub fn from_hashes(leaves: Vec<Hash256>) -> Result<Self, MerkleError> {
        const MAX_LEAVES: usize = 1 << 24; // 16M leaves max (~24 levels)

        if leaves.is_empty() {
            return Ok(Self {
                leaves: vec![],
                layers: vec![vec![Hash256::ZERO]],
                _hasher: PhantomData,
            });
        }

        if leaves.len() > MAX_LEAVES {
            return Err(MerkleError::TooManyLeaves {
                count: leaves.len(),
                max: MAX_LEAVES,
            });
        }

        // Apply leaf domain separation to all inputs
        let domain_separated: Vec<Hash256> =
            leaves.iter().map(|h| H::hash_leaf(h.as_bytes())).collect();

        let mut layers = vec![domain_separated.clone()];
        let mut current_layer = domain_separated;

        while current_layer.len() > 1 {
            // Use a unique sentinel instead of duplicating the last leaf.
            if !current_layer.len().is_multiple_of(2) {
                let last = current_layer.last().unwrap().as_bytes();
                let mut sentinel_input = vec![0x02u8]; // Distinct prefix for padding sentinel
                sentinel_input.extend_from_slice(last);
                let sentinel = H::hash_raw(&sentinel_input);
                current_layer.push(sentinel);
                *layers.last_mut().unwrap() = current_layer.clone();
            }

            let mut next_layer = Vec::with_capacity(current_layer.len() / 2);
            for chunk in current_layer.chunks(2) {
                next_layer.push(H::hash_node(&chunk[0], &chunk[1]));
            }

            layers.push(next_layer.clone());
            current_layer = next_layer;
        }

        Ok(Self {
            leaves,
            layers,
            _hasher: PhantomData,
        })
    }

    /// Get the Merkle root.
    pub fn root(&self) -> Hash256 {
        self.layers
            .last()
            .and_then(|l| l.first().copied())
            .unwrap_or(Hash256::ZERO)
    }

    /// Get the number of leaves.
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get the depth of the tree.
    pub fn depth(&self) -> usize {
        if self.layers.is_empty() {
            0
        } else {
            self.layers.len() - 1
        }
    }

    /// Generate a Merkle proof for the leaf at the given index.
    pub fn proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut path_indices = Vec::new();
        let mut index = leaf_index;

        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_index = if index.is_multiple_of(2) {
                index + 1
            } else {
                index - 1
            };

            let sibling = if sibling_index < layer.len() {
                layer[sibling_index]
            } else {
                layer[index]
            };

            siblings.push(sibling);
            path_indices.push(!index.is_multiple_of(2));

            index /= 2;
        }

        Some(MerkleProof {
            leaf: self.layers[0][leaf_index],
            siblings,
            path_indices,
        })
    }

    /// Verify a leaf is included at the given index.
    pub fn verify_proof(&self, leaf_index: usize) -> bool {
        if let Some(proof) = self.proof(leaf_index) {
            proof.verify_with::<H>(&self.root())
        } else {
            false
        }
    }
}

/// SHA-256 specific methods (backward-compatible with existing callers).
impl MerkleTree<Sha256Hasher> {
    /// Build a Merkle tree from a list of leaf data.
    ///
    /// Each leaf is first hashed (plain SHA-256), then `from_hashes()` applies
    /// domain-separated hashing (0x00 prefix) to prevent second-preimage attacks.
    pub fn from_data(data: &[&[u8]]) -> Result<Self, MerkleError> {
        let leaves: Vec<Hash256> = data.iter().map(|d| Hasher::hash(d)).collect();
        Self::from_hashes(leaves)
    }
}

/// Poseidon2 specific methods.
impl MerkleTree<Poseidon2Hasher> {
    /// Build a Poseidon2 Merkle tree from raw data.
    ///
    /// Pre-hashes each element with Poseidon2, then builds the tree.
    pub fn from_data_poseidon2(data: &[&[u8]]) -> Result<Self, MerkleError> {
        let leaves: Vec<Hash256> = data.iter().map(|d| poseidon2_hash(d)).collect();
        Self::from_hashes(leaves)
    }
}

// ── Convenience Functions ───────────────────────────────────────────────────

/// Compute the Merkle root of a list of transaction hashes (SHA-256).
///
/// Used for batch commitment in the Dual-DA model.
pub fn compute_tx_root(tx_hashes: &[Hash256]) -> Hash256 {
    if tx_hashes.is_empty() {
        return Hash256::ZERO;
    }
    // SAFETY: Input bounded by caller; panics on > 16M leaves (should never happen for tx batches).
    MerkleTree::<Sha256Hasher>::from_hashes(tx_hashes.to_vec())
        .expect("tx batch exceeds 16M leaves")
        .root()
}

/// Compute the Merkle root using Poseidon2 (for ZK-internal use).
pub fn compute_poseidon2_root(hashes: &[Hash256]) -> Hash256 {
    if hashes.is_empty() {
        return Hash256::ZERO;
    }
    // SAFETY: Input bounded by caller; panics on > 16M leaves (should never happen for ZK batches).
    MerkleTree::<Poseidon2Hasher>::from_hashes(hashes.to_vec())
        .expect("hash batch exceeds 16M leaves")
        .root()
}

// ── Poseidon2MerkleTree type alias ──────────────────────────────────────────

/// Poseidon2 Merkle tree alias for convenience.
pub type Poseidon2MerkleTree = MerkleTree<Poseidon2Hasher>;

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── SHA-256 MerkleTree Tests (backward-compatible) ───

    #[test]
    fn test_empty_tree() {
        let tree = MerkleTree::from_data(&[]).unwrap();
        assert_eq!(tree.root(), Hash256::ZERO);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn test_single_leaf() {
        let tree = MerkleTree::from_data(&[b"single leaf"]).unwrap();
        assert_ne!(tree.root(), Hash256::ZERO);
        assert_eq!(tree.leaf_count(), 1);
        assert!(tree.verify_proof(0));
    }

    #[test]
    fn test_two_leaves() {
        let tree = MerkleTree::from_data(&[b"leaf A", b"leaf B"]).unwrap();
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.depth(), 1);

        assert!(tree.verify_proof(0));
        assert!(tree.verify_proof(1));

        // from_data: hash(raw) → from_hashes: hash_leaf(hash) → tree leaf
        let h_a = Hasher::hash_leaf(Hasher::hash(b"leaf A").as_bytes());
        let h_b = Hasher::hash_leaf(Hasher::hash(b"leaf B").as_bytes());
        let expected_root = Hasher::hash_node(&h_a, &h_b);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_four_leaves() {
        let data: Vec<&[u8]> = vec![b"tx1", b"tx2", b"tx3", b"tx4"];
        let tree = MerkleTree::from_data(&data).unwrap();
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.depth(), 2);

        for i in 0..4 {
            assert!(tree.verify_proof(i), "Proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_odd_number_of_leaves() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let tree = MerkleTree::from_data(&data).unwrap();
        assert_eq!(tree.leaf_count(), 3);

        for i in 0..3 {
            assert!(tree.verify_proof(i), "Proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_proof_verification_independent() {
        let data: Vec<&[u8]> = vec![b"tx1", b"tx2", b"tx3", b"tx4"];
        let tree = MerkleTree::from_data(&data).unwrap();
        let root = tree.root();

        let proof = tree.proof(2).unwrap();
        assert!(proof.verify(&root));
    }

    #[test]
    fn test_proof_fails_wrong_root() {
        let data: Vec<&[u8]> = vec![b"tx1", b"tx2"];
        let tree = MerkleTree::from_data(&data).unwrap();

        let proof = tree.proof(0).unwrap();
        let wrong_root = Hasher::hash(b"wrong root");
        assert!(!proof.verify(&wrong_root));
    }

    #[test]
    fn test_deterministic() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree1 = MerkleTree::from_data(&data).unwrap();
        let tree2 = MerkleTree::from_data(&data).unwrap();
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_data_different_root() {
        let tree1 = MerkleTree::from_data(&[b"a", b"b"]).unwrap();
        let tree2 = MerkleTree::from_data(&[b"c", b"d"]).unwrap();
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_order_matters() {
        let tree1 = MerkleTree::from_data(&[b"a", b"b"]).unwrap();
        let tree2 = MerkleTree::from_data(&[b"b", b"a"]).unwrap();
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_proof_size() {
        let data: Vec<[u8; 4]> = (0..1000u32).map(|i| i.to_le_bytes()).collect();
        let refs: Vec<&[u8]> = data.iter().map(|d| d.as_ref()).collect();
        let tree = MerkleTree::from_data(&refs).unwrap();

        let proof = tree.proof(500).unwrap();
        assert!(proof.size_bytes() < 1024);
        assert!(proof.verify(&tree.root()));
    }

    #[test]
    fn test_compute_tx_root_empty() {
        assert_eq!(compute_tx_root(&[]), Hash256::ZERO);
    }

    #[test]
    fn test_compute_tx_root() {
        let hashes = vec![
            Hasher::hash(b"tx1"),
            Hasher::hash(b"tx2"),
            Hasher::hash(b"tx3"),
        ];
        let root = compute_tx_root(&hashes);
        assert_ne!(root, Hash256::ZERO);
    }

    // ─── Poseidon2 MerkleTree Tests ───

    #[test]
    fn test_poseidon2_tree_basic() {
        let tree = Poseidon2MerkleTree::from_data_poseidon2(&[b"leaf A", b"leaf B"]).unwrap();
        assert_ne!(tree.root(), Hash256::ZERO);
        assert_eq!(tree.leaf_count(), 2);
        assert!(tree.verify_proof(0));
        assert!(tree.verify_proof(1));
    }

    #[test]
    fn test_poseidon2_tree_four_leaves() {
        let data: Vec<&[u8]> = vec![b"tx1", b"tx2", b"tx3", b"tx4"];
        let tree = Poseidon2MerkleTree::from_data_poseidon2(&data).unwrap();
        assert_eq!(tree.depth(), 2);

        for i in 0..4 {
            assert!(
                tree.verify_proof(i),
                "Poseidon2 proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_poseidon2_tree_odd_leaves() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let tree = Poseidon2MerkleTree::from_data_poseidon2(&data).unwrap();

        for i in 0..3 {
            assert!(
                tree.verify_proof(i),
                "Poseidon2 odd proof failed for leaf {}",
                i
            );
        }
    }

    #[test]
    fn test_poseidon2_proof_independent_verify() {
        let data: Vec<&[u8]> = vec![b"tx1", b"tx2", b"tx3", b"tx4"];
        let tree = Poseidon2MerkleTree::from_data_poseidon2(&data).unwrap();
        let root = tree.root();

        let proof = tree.proof(2).unwrap();
        // Must use verify_with::<Poseidon2Hasher>, not verify() (which uses SHA-256)
        assert!(proof.verify_with::<Poseidon2Hasher>(&root));
        // SHA-256 verify must FAIL (different hash function)
        assert!(!proof.verify(&root));
    }

    #[test]
    fn test_sha256_vs_poseidon2_different_roots() {
        let leaves = vec![Hasher::hash(b"tx1"), Hasher::hash(b"tx2")];

        let sha_root = compute_tx_root(&leaves);
        let p2_root = compute_poseidon2_root(&leaves);

        // Same input leaves must produce different roots with different hashers.
        assert_ne!(sha_root, p2_root);
        assert_ne!(sha_root, Hash256::ZERO);
        assert_ne!(p2_root, Hash256::ZERO);
    }

    #[test]
    fn test_poseidon2_deterministic() {
        let data: Vec<&[u8]> = vec![b"a", b"b", b"c", b"d"];
        let tree1 = Poseidon2MerkleTree::from_data_poseidon2(&data).unwrap();
        let tree2 = Poseidon2MerkleTree::from_data_poseidon2(&data).unwrap();
        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_poseidon2_order_matters() {
        let tree1 = Poseidon2MerkleTree::from_data_poseidon2(&[b"a", b"b"]).unwrap();
        let tree2 = Poseidon2MerkleTree::from_data_poseidon2(&[b"b", b"a"]).unwrap();
        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_compute_poseidon2_root_empty() {
        assert_eq!(compute_poseidon2_root(&[]), Hash256::ZERO);
    }
}
