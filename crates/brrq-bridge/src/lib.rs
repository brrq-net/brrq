//! BitVM2 bridge between Bitcoin L1 and Brrq L2.
//!
//! ## Security
//!
//! - No brqBTC minted without SPV proof or federation attestation of real BTC deposit
//! - L2 challenge period prevents fraudulent withdrawals
//! - Federation signs only after challenge period expires
//! - State root binding prevents fabricated proofs
//! - STARK proof verification required for withdrawal completion
//! - Feature-gated SNARK simulation guards prevent simulated proofs in production

pub mod bridge;
pub mod challenge;
pub mod challenge_manager;
pub mod dispute_coordinator;
pub mod dispute_game;
pub mod error;
pub mod federation;
pub mod operator;
pub mod proof_store;
pub mod rate_limiter;
pub mod sequencer;
pub mod taproot;
pub mod bitvm_compiler;
pub mod backend;
pub mod types;
pub mod utxo_pool;
pub mod vm_state;

pub use bridge::{BridgeManager, BridgeStatus, ChallengeMode};
pub use challenge::{Challenge, ChallengeResponse, ChallengeStats, ChallengeStatus, ChallengeType};
pub use challenge_manager::ChallengeManager;
pub use dispute_game::{DisputeGameBuilder, DisputePhase, DisputeStep};
pub use error::BridgeError;
pub use federation::{
    FederationError, FederationManager, FederationMember, FederationStatus, Proposal,
    ProposalAction,
};
pub use operator::{
    BitVM2Bond, OperatorInfo, OperatorManager, Reimbursement, ReimbursementStatus,
    MAX_BONDS_PER_OPERATOR,
};
pub use proof_store::{ProofStore, StoredProof};
pub use sequencer::{
    CommittedTransaction, DaCommitment, SequencerError, SequencerInfo, SequencerManager,
    MIN_SEQUENCER_BOND,
};
pub use types::*;
pub use utxo_pool::{BridgeUtxo, UtxoStatus};
