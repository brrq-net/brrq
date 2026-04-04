//! Sparse Merkle Tree (SMT) implementation with pluggable hash backends.
//!
//! ## Design
//!
//! A Sparse Merkle Tree is a Merkle tree with exactly 2^256 leaves,
//! where most leaves are empty (default value). Only non-empty leaves
//! are actually stored, making it memory-efficient.
//!
//! Key properties:
//! - Fixed depth of 256 (one level per bit of hash key)
//! - Empty subtrees share a single pre-computed hash per level
//! - Supports proofs of inclusion AND exclusion
//! - Deterministic: same key-value set always produces same root
//!
//! ## Hash Backends
//!
//! - **SHA-256** (default): For L1-facing state commitments
//! - **Poseidon2**: For ZK-internal state trees (~90x fewer constraints in-circuit)
//!
//! ## Optimization
//!
//! We use path compression: if a subtree has only one leaf,
//! we store it directly instead of creating 256 levels of nodes.
//! This makes the practical depth O(log n) for n entries.

use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use brrq_crypto::hash::Hash256;
use brrq_crypto::merkle::{MerkleHasher, Poseidon2Hasher, Sha256Hasher};

/// Compute empty hashes for a given hasher.
/// `empty_hashes[0]` = Hash256::ZERO (empty leaf)
/// `empty_hashes[i]` = H::hash_node(empty_hashes[i-1], empty_hashes[i-1])
fn compute_empty_hashes<H: MerkleHasher>() -> Arc<[Hash256]> {
    let mut hashes = vec![Hash256::ZERO; 257];
    for i in 1..257 {
        hashes[i] = H::hash_node(&hashes[i - 1], &hashes[i - 1]);
    }
    Arc::from(hashes)
}

/// Cached SHA-256 empty hashes (shared across all SHA-256 SMT instances).
static SHA256_EMPTY_HASHES: std::sync::LazyLock<Arc<[Hash256]>> =
    std::sync::LazyLock::new(compute_empty_hashes::<Sha256Hasher>);

/// Cached Poseidon2 empty hashes (shared across all Poseidon2 SMT instances).
static POSEIDON2_EMPTY_HASHES: std::sync::LazyLock<Arc<[Hash256]>> =
    std::sync::LazyLock::new(compute_empty_hashes::<Poseidon2Hasher>);

/// Get cached empty hashes for known hasher types, or compute on the fly.
fn get_empty_hashes<H: MerkleHasher + 'static>() -> Arc<[Hash256]> {
    use std::any::TypeId;
    let tid = TypeId::of::<H>();
    if tid == TypeId::of::<Sha256Hasher>() {
        Arc::clone(&SHA256_EMPTY_HASHES)
    } else if tid == TypeId::of::<Poseidon2Hasher>() {
        Arc::clone(&POSEIDON2_EMPTY_HASHES)
    } else {
        compute_empty_hashes::<H>()
    }
}

// Domain separation tags for SMT leaf vs internal node hashing.
// Prepended at the SMT layer before data is passed to the underlying hasher,
// providing defense-in-depth on top of the hasher's own domain separation.
// This prevents second-preimage attacks where an attacker crafts a leaf
// whose hash collides with an internal node hash (or vice versa).
const SMT_LEAF_DOMAIN_TAG: u8 = 0x00;
#[allow(dead_code)] // Referenced in node_hash() comments; kept for auditability.
const SMT_INTERNAL_DOMAIN_TAG: u8 = 0x01;

/// A node in the Sparse Merkle Tree.
#[derive(Debug, Clone)]
enum SmtNode {
    /// Empty subtree (uses pre-computed hash).
    Empty,
    /// Leaf node with key and value.
    Leaf { key: Hash256, value: Hash256 },
    /// Internal node with left and right children.
    Internal {
        left: Box<SmtNode>,
        right: Box<SmtNode>,
    },
}

/// Generic Sparse Merkle Tree parameterized by hash backend.
///
/// Use `SparseMerkleTree` (SHA-256, default) for L1-facing state,
/// or `Poseidon2SparseMerkleTree` for ZK-internal state trees.
#[derive(Debug)]
pub struct SmtGeneric<H: MerkleHasher + 'static> {
    /// Root node.
    root: SmtNode,
    /// Number of non-empty leaves.
    size: usize,
    /// Cached root hash (invalidated on insert/remove).
    cached_root: Mutex<Option<Hash256>>,
    /// Pre-computed empty hashes for this hasher (shared via Arc).
    empty_hashes: Arc<[Hash256]>,
    /// Hash backend marker.
    _hasher: PhantomData<H>,
}

impl<H: MerkleHasher + 'static> Clone for SmtGeneric<H> {
    fn clone(&self) -> Self {
        Self {
            root: self.root.clone(),
            size: self.size,
            cached_root: Mutex::new(*self.cached_root.lock().unwrap_or_else(|e| e.into_inner())),
            empty_hashes: Arc::clone(&self.empty_hashes),
            _hasher: PhantomData,
        }
    }
}

/// Merkle proof for a key in the SMT.
#[derive(Debug, Clone)]
pub struct SmtProof {
    /// The key being proved.
    pub key: Hash256,
    /// The value (ZERO if non-membership proof).
    pub value: Hash256,
    /// Sibling hashes from leaf (bottom) to root (top).
    /// siblings[0] = sibling at level 1 (bottommost)
    /// siblings[255] = sibling at level 256 (just below root)
    pub siblings: Vec<Hash256>,
    /// Whether this is a membership proof (key exists).
    pub exists: bool,
}

impl<H: MerkleHasher + 'static> SmtGeneric<H> {
    /// Tree depth (256 bits).
    pub const DEPTH: usize = 256;

    /// Create a new empty SMT.
    pub fn new() -> Self {
        Self {
            root: SmtNode::Empty,
            size: 0,
            cached_root: Mutex::new(None),
            empty_hashes: get_empty_hashes::<H>(),
            _hasher: PhantomData,
        }
    }

    /// Get the root hash (cached — recomputed only after insert/remove).
    pub fn root(&self) -> Hash256 {
        let mut cache = self.cached_root.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cached) = *cache {
            return cached;
        }
        let hash = self.node_hash(&self.root, Self::DEPTH);
        *cache = Some(hash);
        hash
    }

    /// Number of non-empty entries.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Check if the tree is empty.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Get the value for a key, or None if not present.
    pub fn get(&self, key: &Hash256) -> Option<Hash256> {
        self.get_node(&self.root, key, Self::DEPTH)
    }

    /// Insert or update a key-value pair. Returns the old value if any.
    pub fn insert(&mut self, key: Hash256, value: Hash256) -> Option<Hash256> {
        let old = self.get(&key);
        let old_root = std::mem::replace(&mut self.root, SmtNode::Empty);
        let new_root = self.insert_node(old_root, &key, &value, Self::DEPTH);
        self.root = new_root;
        *self.cached_root.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if old.is_none() {
            self.size += 1;
        }
        old
    }

    /// Remove a key. Returns the old value if it existed.
    pub fn remove(&mut self, key: &Hash256) -> Option<Hash256> {
        let old = self.get(key);
        if old.is_some() {
            let old_root = std::mem::replace(&mut self.root, SmtNode::Empty);
            let new_root = self.remove_node(old_root, key, Self::DEPTH);
            self.root = new_root;
            *self.cached_root.lock().unwrap_or_else(|e| e.into_inner()) = None;
            self.size -= 1;
        }
        old
    }

    /// Collect all (key, value) pairs stored in the tree.
    ///
    /// Used by the persistence layer to serialize the tree to disk.
    /// The returned entries are in no particular order.
    pub fn entries(&self) -> Vec<(Hash256, Hash256)> {
        let mut result = Vec::with_capacity(self.size);
        Self::collect_entries(&self.root, &mut result);
        result
    }

    /// Generate a Merkle proof for a key.
    pub fn prove(&self, key: &Hash256) -> SmtProof {
        let mut siblings = Vec::with_capacity(Self::DEPTH);
        let (value, exists) = self.prove_node(&self.root, key, Self::DEPTH, &mut siblings);
        SmtProof {
            key: *key,
            value,
            siblings,
            exists,
        }
    }

    /// Verify a Merkle proof against an expected root.
    ///
    /// Proof siblings are ordered bottom-to-top:
    /// siblings[0] is at level 1, siblings[255] is at level 256.
    ///
    /// SECURITY: Requires exactly 256 siblings (one per tree level).
    /// Truncated proofs are rejected to prevent forgery.
    pub fn verify_proof(proof: &SmtProof, root: &Hash256) -> bool {
        if proof.siblings.len() != Self::DEPTH {
            return false;
        }

        let empty_hashes = get_empty_hashes::<H>();

        // Prepend SMT_LEAF_DOMAIN_TAG (0x00) to leaf data during proof
        // verification, matching the tag applied in node_hash() for consistency.
        let leaf_hash = if proof.exists {
            let mut buf = Vec::with_capacity(1 + 64);
            buf.push(SMT_LEAF_DOMAIN_TAG);
            buf.extend_from_slice(proof.key.as_bytes());
            buf.extend_from_slice(proof.value.as_bytes());
            H::hash_leaf(&buf)
        } else {
            empty_hashes[0]
        };

        let key_bytes = proof.key.as_bytes();
        let mut current = leaf_hash;

        for (i, sibling) in proof.siblings.iter().enumerate() {
            let bit_index = i;
            let byte_index = bit_index / 8;
            let bit_offset = 7 - (bit_index % 8);
            // SAFETY: i ∈ [0,256), byte_index = i/8 ∈ [0,32), key_bytes is Hash256 (32 bytes).
            // The DEPTH check above guarantees this is always in bounds.
            let bit = (key_bytes[byte_index] >> bit_offset) & 1;

            current = if bit == 0 {
                H::hash_node(&current, sibling)
            } else {
                H::hash_node(sibling, &current)
            };
        }

        current == *root
    }

    // --- Internal methods ---

    fn collect_entries(node: &SmtNode, result: &mut Vec<(Hash256, Hash256)>) {
        match node {
            SmtNode::Empty => {}
            SmtNode::Leaf { key, value } => {
                result.push((*key, *value));
            }
            SmtNode::Internal { left, right } => {
                Self::collect_entries(left, result);
                Self::collect_entries(right, result);
            }
        }
    }

    fn get_node(&self, node: &SmtNode, key: &Hash256, depth: usize) -> Option<Hash256> {
        match node {
            SmtNode::Empty => None,
            SmtNode::Leaf { key: k, value } => {
                if k == key {
                    Some(*value)
                } else {
                    None
                }
            }
            SmtNode::Internal { left, right } => {
                if depth == 0 {
                    return None;
                }
                if Self::get_bit(key, depth) == 0 {
                    self.get_node(left, key, depth - 1)
                } else {
                    self.get_node(right, key, depth - 1)
                }
            }
        }
    }

    fn insert_node(&self, node: SmtNode, key: &Hash256, value: &Hash256, depth: usize) -> SmtNode {
        match node {
            SmtNode::Empty => SmtNode::Leaf {
                key: *key,
                value: *value,
            },
            SmtNode::Leaf {
                key: existing_key,
                value: existing_value,
            } => {
                if existing_key == *key {
                    SmtNode::Leaf {
                        key: *key,
                        value: *value,
                    }
                } else if depth == 0 {
                    SmtNode::Leaf {
                        key: *key,
                        value: *value,
                    }
                } else {
                    let mut internal = SmtNode::Internal {
                        left: Box::new(SmtNode::Empty),
                        right: Box::new(SmtNode::Empty),
                    };
                    internal = self.insert_node(internal, &existing_key, &existing_value, depth);
                    internal = self.insert_node(internal, key, value, depth);
                    internal
                }
            }
            SmtNode::Internal { left, right } => {
                if depth == 0 {
                    return SmtNode::Leaf {
                        key: *key,
                        value: *value,
                    };
                }
                if Self::get_bit(key, depth) == 0 {
                    SmtNode::Internal {
                        left: Box::new(self.insert_node(*left, key, value, depth - 1)),
                        right,
                    }
                } else {
                    SmtNode::Internal {
                        left,
                        right: Box::new(self.insert_node(*right, key, value, depth - 1)),
                    }
                }
            }
        }
    }

    fn remove_node(&self, node: SmtNode, key: &Hash256, depth: usize) -> SmtNode {
        match node {
            SmtNode::Empty => SmtNode::Empty,
            SmtNode::Leaf { key: k, value: v } => {
                if k == *key {
                    SmtNode::Empty
                } else {
                    SmtNode::Leaf { key: k, value: v }
                }
            }
            SmtNode::Internal { left, right } => {
                if depth == 0 {
                    return SmtNode::Empty;
                }
                let (new_left, new_right) = if Self::get_bit(key, depth) == 0 {
                    (Box::new(self.remove_node(*left, key, depth - 1)), right)
                } else {
                    (left, Box::new(self.remove_node(*right, key, depth - 1)))
                };
                match (&*new_left, &*new_right) {
                    (SmtNode::Empty, SmtNode::Empty) => SmtNode::Empty,
                    (SmtNode::Leaf { key, value }, SmtNode::Empty)
                    | (SmtNode::Empty, SmtNode::Leaf { key, value }) => SmtNode::Leaf {
                        key: *key,
                        value: *value,
                    },
                    _ => SmtNode::Internal {
                        left: new_left,
                        right: new_right,
                    },
                }
            }
        }
    }

    fn prove_node(
        &self,
        node: &SmtNode,
        key: &Hash256,
        depth: usize,
        siblings: &mut Vec<Hash256>,
    ) -> (Hash256, bool) {
        match node {
            SmtNode::Empty => {
                for i in 0..depth {
                    siblings.push(self.empty_hashes[i]);
                }
                (Hash256::ZERO, false)
            }
            SmtNode::Leaf { key: k, value } => {
                if k == key {
                    for i in 0..depth {
                        siblings.push(self.empty_hashes[i]);
                    }
                    (*value, true)
                } else {
                    let mut divergence_level = 1;
                    for l in (1..=depth).rev() {
                        if Self::get_bit(key, l) != Self::get_bit(k, l) {
                            divergence_level = l;
                            break;
                        }
                    }

                    let existing_leaf = SmtNode::Leaf {
                        key: *k,
                        value: *value,
                    };
                    let existing_expanded = self.node_hash(&existing_leaf, divergence_level - 1);

                    for i in 0..depth {
                        let level = i + 1;
                        if level == divergence_level {
                            siblings.push(existing_expanded);
                        } else {
                            siblings.push(self.empty_hashes[i]);
                        }
                    }
                    (Hash256::ZERO, false)
                }
            }
            SmtNode::Internal { left, right } => {
                if depth == 0 {
                    return (Hash256::ZERO, false);
                }
                if Self::get_bit(key, depth) == 0 {
                    let sibling_hash = self.node_hash(right, depth - 1);
                    let (value, exists) = self.prove_node(left, key, depth - 1, siblings);
                    siblings.push(sibling_hash);
                    (value, exists)
                } else {
                    let sibling_hash = self.node_hash(left, depth - 1);
                    let (value, exists) = self.prove_node(right, key, depth - 1, siblings);
                    siblings.push(sibling_hash);
                    (value, exists)
                }
            }
        }
    }

    fn node_hash(&self, node: &SmtNode, depth: usize) -> Hash256 {
        match node {
            SmtNode::Empty => self.empty_hashes[depth],
            SmtNode::Leaf { key, value } => {
                // Prepend SMT_LEAF_DOMAIN_TAG (0x00) to leaf data before hashing.
                // This ensures leaf hashes are structurally distinct from internal node
                // hashes at the SMT layer, preventing second-preimage collisions.
                let mut buf = Vec::with_capacity(1 + 64);
                buf.push(SMT_LEAF_DOMAIN_TAG);
                buf.extend_from_slice(key.as_bytes());
                buf.extend_from_slice(value.as_bytes());
                let mut current = H::hash_leaf(&buf);
                for d in 1..=depth {
                    let bit = Self::get_bit(key, d);
                    if bit == 0 {
                        current = H::hash_node(&current, &self.empty_hashes[d - 1]);
                    } else {
                        current = H::hash_node(&self.empty_hashes[d - 1], &current);
                    }
                }
                current
            }
            SmtNode::Internal { left, right } => {
                // Internal nodes use H::hash_node which carries its own
                // domain tag (0x01) via the underlying hasher. The SMT_INTERNAL_DOMAIN_TAG
                // constant documents this contract for auditability.
                let left_hash = self.node_hash(left, depth - 1);
                let right_hash = self.node_hash(right, depth - 1);
                H::hash_node(&left_hash, &right_hash)
            }
        }
    }

    /// Get bit at position `depth` (1-indexed from bottom) of the key.
    /// depth=1 → bit_index=0, depth=256 → bit_index=255.
    fn get_bit(key: &Hash256, depth: usize) -> u8 {
        let bit_index = depth - 1;
        let byte_index = bit_index / 8;
        let bit_offset = 7 - (bit_index % 8);
        (key.as_bytes()[byte_index] >> bit_offset) & 1
    }
}

impl<H: MerkleHasher + 'static> Default for SmtGeneric<H> {
    fn default() -> Self {
        Self::new()
    }
}

// ── Type Aliases (backward-compatible) ──────────────────────────────────────

/// SHA-256 Sparse Merkle Tree — default for L1-facing state commitments.
pub type SparseMerkleTree = SmtGeneric<Sha256Hasher>;

/// Poseidon2 Sparse Merkle Tree — for ZK-internal state trees.
pub type Poseidon2SparseMerkleTree = SmtGeneric<Poseidon2Hasher>;

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;

    fn key(s: &str) -> Hash256 {
        Hasher::hash(s.as_bytes())
    }

    fn value(s: &str) -> Hash256 {
        Hasher::hash(s.as_bytes())
    }

    // ─── SHA-256 SMT Tests (backward-compatible) ───

    #[test]
    fn test_empty_tree() {
        let smt = SparseMerkleTree::new();
        assert!(smt.is_empty());
        assert_eq!(smt.len(), 0);
        let root = smt.root();
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_insert_and_get() {
        let mut smt = SparseMerkleTree::new();
        let k = key("alice");
        let v = value("100");
        smt.insert(k, v);

        assert_eq!(smt.len(), 1);
        assert_eq!(smt.get(&k), Some(v));
    }

    #[test]
    fn test_get_missing_key() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(key("alice"), value("100"));
        assert_eq!(smt.get(&key("bob")), None);
    }

    #[test]
    fn test_update_value() {
        let mut smt = SparseMerkleTree::new();
        let k = key("alice");
        smt.insert(k, value("100"));
        let old = smt.insert(k, value("200"));
        assert_eq!(old, Some(value("100")));
        assert_eq!(smt.get(&k), Some(value("200")));
        assert_eq!(smt.len(), 1);
    }

    #[test]
    fn test_remove() {
        let mut smt = SparseMerkleTree::new();
        let k = key("alice");
        smt.insert(k, value("100"));
        assert_eq!(smt.len(), 1);

        let old = smt.remove(&k);
        assert_eq!(old, Some(value("100")));
        assert_eq!(smt.get(&k), None);
        assert_eq!(smt.len(), 0);
    }

    #[test]
    fn test_remove_missing_key() {
        let mut smt = SparseMerkleTree::new();
        let old = smt.remove(&key("alice"));
        assert_eq!(old, None);
    }

    #[test]
    fn test_root_changes_on_insert() {
        let mut smt = SparseMerkleTree::new();
        let root0 = smt.root();
        smt.insert(key("alice"), value("100"));
        let root1 = smt.root();
        assert_ne!(root0, root1);

        smt.insert(key("bob"), value("200"));
        let root2 = smt.root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_deterministic_root() {
        let mut smt1 = SparseMerkleTree::new();
        smt1.insert(key("alice"), value("100"));
        smt1.insert(key("bob"), value("200"));

        let mut smt2 = SparseMerkleTree::new();
        smt2.insert(key("alice"), value("100"));
        smt2.insert(key("bob"), value("200"));

        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn test_insert_order_independent() {
        let mut smt1 = SparseMerkleTree::new();
        smt1.insert(key("alice"), value("100"));
        smt1.insert(key("bob"), value("200"));

        let mut smt2 = SparseMerkleTree::new();
        smt2.insert(key("bob"), value("200"));
        smt2.insert(key("alice"), value("100"));

        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn test_many_entries() {
        let mut smt = SparseMerkleTree::new();
        for i in 0..100 {
            let k = key(&format!("key_{}", i));
            let v = value(&format!("value_{}", i));
            smt.insert(k, v);
        }
        assert_eq!(smt.len(), 100);

        for i in 0..100 {
            let k = key(&format!("key_{}", i));
            let v = value(&format!("value_{}", i));
            assert_eq!(smt.get(&k), Some(v));
        }
    }

    #[test]
    fn test_root_after_remove_equals_before_insert() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(key("alice"), value("100"));
        let root_one_entry = smt.root();

        smt.insert(key("bob"), value("200"));
        assert_ne!(smt.root(), root_one_entry);

        smt.remove(&key("bob"));
        assert_eq!(smt.root(), root_one_entry);
    }

    #[test]
    fn test_proof_membership() {
        let mut smt = SparseMerkleTree::new();
        let k = key("alice");
        let v = value("100");
        smt.insert(k, v);

        let proof = smt.prove(&k);
        assert!(proof.exists);
        assert_eq!(proof.value, v);
        assert_eq!(proof.siblings.len(), SparseMerkleTree::DEPTH);
        assert!(SparseMerkleTree::verify_proof(&proof, &smt.root()));
    }

    #[test]
    fn test_proof_non_membership() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(key("alice"), value("100"));

        let proof = smt.prove(&key("bob"));
        assert!(!proof.exists);
        assert!(SparseMerkleTree::verify_proof(&proof, &smt.root()));
    }

    #[test]
    fn test_proof_with_multiple_entries() {
        let mut smt = SparseMerkleTree::new();
        smt.insert(key("alice"), value("100"));
        smt.insert(key("bob"), value("200"));
        smt.insert(key("carol"), value("300"));

        let root = smt.root();

        for (k, v) in [("alice", "100"), ("bob", "200"), ("carol", "300")] {
            let proof = smt.prove(&key(k));
            assert!(proof.exists);
            assert_eq!(proof.value, value(v));
            assert!(SparseMerkleTree::verify_proof(&proof, &root));
        }
    }

    // ─── Poseidon2 SMT Tests ───

    #[test]
    fn test_poseidon2_smt_empty() {
        let smt = Poseidon2SparseMerkleTree::new();
        assert!(smt.is_empty());
        let root = smt.root();
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_poseidon2_smt_insert_get() {
        let mut smt = Poseidon2SparseMerkleTree::new();
        let k = key("alice");
        let v = value("100");
        smt.insert(k, v);
        assert_eq!(smt.get(&k), Some(v));
        assert_eq!(smt.len(), 1);
    }

    #[test]
    fn test_poseidon2_smt_proof() {
        let mut smt = Poseidon2SparseMerkleTree::new();
        let k = key("alice");
        let v = value("100");
        smt.insert(k, v);

        let proof = smt.prove(&k);
        assert!(proof.exists);
        assert!(Poseidon2SparseMerkleTree::verify_proof(&proof, &smt.root()));
    }

    #[test]
    fn test_poseidon2_smt_multiple_proofs() {
        let mut smt = Poseidon2SparseMerkleTree::new();
        smt.insert(key("alice"), value("100"));
        smt.insert(key("bob"), value("200"));
        smt.insert(key("carol"), value("300"));

        let root = smt.root();
        for (k, v) in [("alice", "100"), ("bob", "200"), ("carol", "300")] {
            let proof = smt.prove(&key(k));
            assert!(proof.exists);
            assert_eq!(proof.value, value(v));
            assert!(Poseidon2SparseMerkleTree::verify_proof(&proof, &root));
        }
    }

    #[test]
    fn test_poseidon2_vs_sha256_different_roots() {
        let mut sha_smt = SparseMerkleTree::new();
        let mut p2_smt = Poseidon2SparseMerkleTree::new();

        let k = key("alice");
        let v = value("100");
        sha_smt.insert(k, v);
        p2_smt.insert(k, v);

        // Same data, different hashers → different roots.
        assert_ne!(sha_smt.root(), p2_smt.root());
    }

    #[test]
    fn test_poseidon2_smt_deterministic() {
        let mut smt1 = Poseidon2SparseMerkleTree::new();
        smt1.insert(key("alice"), value("100"));
        smt1.insert(key("bob"), value("200"));

        let mut smt2 = Poseidon2SparseMerkleTree::new();
        smt2.insert(key("alice"), value("100"));
        smt2.insert(key("bob"), value("200"));

        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn test_poseidon2_smt_remove_restores_root() {
        let mut smt = Poseidon2SparseMerkleTree::new();
        smt.insert(key("alice"), value("100"));
        let root_one = smt.root();

        smt.insert(key("bob"), value("200"));
        assert_ne!(smt.root(), root_one);

        smt.remove(&key("bob"));
        assert_eq!(smt.root(), root_one);
    }

    #[test]
    fn test_sha256_proof_fails_against_poseidon2_root() {
        let mut sha_smt = SparseMerkleTree::new();
        let mut p2_smt = Poseidon2SparseMerkleTree::new();

        let k = key("alice");
        let v = value("100");
        sha_smt.insert(k, v);
        p2_smt.insert(k, v);

        // SHA-256 proof should NOT verify against Poseidon2 root.
        let sha_proof = sha_smt.prove(&k);
        assert!(!Poseidon2SparseMerkleTree::verify_proof(
            &sha_proof,
            &p2_smt.root()
        ));
    }
}
