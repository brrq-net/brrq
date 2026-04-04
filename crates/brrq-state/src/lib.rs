//! Brrq state management — world state, account DB, Sparse Merkle Tree.
//!
//! ## Architecture (§4.5)
//!
//! The Brrq state layer uses a Sparse Merkle Tree (SMT) to provide:
//! - O(log n) proof of inclusion/exclusion for any key
//! - Deterministic state root after every block
//! - Efficient state diffs between blocks
//!
//! State is organized as:
//! - **Account trie**: Address → Account (balance, nonce, code_hash, storage_root)
//! - **Storage tries**: Per-contract key → value storage
//! - **Code store**: code_hash → bytecode

pub mod error;
pub mod persistent;
pub mod proofs;
pub mod smt;
pub mod state_db;
pub mod world_state;

pub use error::StateError;
pub use persistent::PersistentStore;
pub use proofs::{AccountProof, StorageProof};
pub use smt::{Poseidon2SparseMerkleTree, SmtGeneric, SmtProof, SparseMerkleTree};
pub use state_db::StateDb;
pub use world_state::{StateChange, WorldState};
