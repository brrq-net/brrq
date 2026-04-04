use bincode::serialize;
use brrq_crypto::{Hash256, sha256};
use serde::{Deserialize, Serialize};

/// Represents the exhaustive internal state of a deterministic RV32I VM micro-cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmState {
    pub pc: u32,
    pub next_pc: u32,
    pub instruction: u32,
    pub registers: [u32; 32],
    pub memory_root: Hash256,
    pub step: u64,
    pub halted: bool,
}

impl VmState {
    pub fn new(memory_root: Hash256) -> Self {
        Self {
            pc: 0,
            next_pc: 4,
            instruction: 0,
            registers: [0; 32],
            memory_root,
            step: 0,
            halted: false,
        }
    }

    /// Computes the exact 32-byte deterministic hash of the entire VM State.
    pub fn commit(&self) -> Hash256 {
        let data = serialize(self).expect("VM State serialization failed");
        sha256::hash(&data)
    }
}
