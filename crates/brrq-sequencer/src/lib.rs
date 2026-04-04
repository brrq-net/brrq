//! Brrq sequencer — mempool, block building, dual signing.
//!
//! ## Architecture (§3.4, §3.6, §7.3)
//!
//! The sequencer is responsible for:
//! 1. **Mempool**: Accepting and ordering transactions
//! 2. **Block building**: Constructing blocks with gas limits
//! 3. **Execution**: Running transactions through the zkVM
//! 4. **Dual signing**: Signing blocks with both EOTS and SLH-DSA
//! 5. **State updates**: Committing state transitions
//!
//! ## MVP: Centralized Sequencer
//!
//! The sequencer starts centralized (single operator).
//! Multi-sequencer rotation is enabled via the `sequencer-rotation` feature.

pub mod block_builder;
pub mod error;
pub mod executor;
pub mod mempool;
pub mod traits;
#[cfg(feature = "mev-protection")]
pub mod mev;

pub use block_builder::{BlockBuilder, TxExecSummary};
pub use error::SequencerError;
pub use mempool::Mempool;
pub use traits::{ConsensusCtx, ConsensusState, NullifierStore, PortalState};
#[cfg(feature = "mev-protection")]
pub use mev::MevMempool;
