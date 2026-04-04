//! Library target for brrq-node — exposes genesis, da, and node types
//! for integration testing.

pub mod da;
pub mod genesis;
pub mod platform;

// Re-export NodeState from brrq-api so genesis module's `use crate::node::NodeState` works.
pub mod node {
    pub use brrq_api::state::{NodeState, SharedState, TxReceipt};
}
