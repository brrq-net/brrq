//! Execution trace recording for STARK proving.
//!
//! Every instruction executed by the VM is recorded as a trace step.
//! The STARK prover later uses this trace to generate a proof of
//! correct execution without re-executing.
//!
//! ## Trace Structure (§4.3)
//!
//! Each step captures the complete CPU + memory state transition:
//! - Pre-state (registers, PC)
//! - Instruction executed
//! - Post-state (registers, PC)
//! - Memory reads/writes

use crate::instruction::Instruction;

/// A single memory access recorded during execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryAccess {
    /// Memory address accessed.
    pub addr: u32,
    /// Value read or written.
    pub value: u32,
    /// Access type.
    pub kind: MemoryAccessKind,
}

/// Type of memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryAccessKind {
    /// Read from memory.
    Read,
    /// Write to memory.
    Write,
}

/// A single execution step in the trace.
#[derive(Debug, Clone)]
pub struct TraceStep {
    /// Step number (0-indexed).
    pub step: u64,
    /// Program counter before execution.
    pub pc: u32,
    /// Instruction that was executed.
    pub instruction: Instruction,
    /// Raw 32-bit instruction word.
    pub instruction_word: u32,
    /// Register file state BEFORE this instruction.
    pub regs_before: [u32; 32],
    /// Register file state AFTER this instruction.
    pub regs_after: [u32; 32],
    /// PC after this instruction.
    pub next_pc: u32,
    /// Memory accesses during this instruction.
    pub memory_accesses: Vec<MemoryAccess>,
    /// Gas consumed by this instruction.
    pub gas_cost: u64,
    /// Cumulative gas used after this instruction.
    pub gas_used: u64,
}

/// A trace step for SHA-256 compression coprocessor.
#[derive(Debug, Clone)]
pub struct Sha256TraceStep {
    pub input: [u8; 64],
    pub output: [u8; 32],
}

/// A trace step for Merkle path verification coprocessor.
#[derive(Debug, Clone)]
pub struct MerkleVerifyTraceStep {
    /// Expected root hash.
    pub root: [u8; 32],
    /// Leaf hash being proved.
    pub leaf: [u8; 32],
    /// Tree depth (number of siblings).
    pub depth: u32,
    /// Whether verification succeeded.
    pub verified: bool,
    /// Sibling hashes and canonicalized directions for full re-verification.
    /// Each entry is (sibling_hash, direction) where direction=0 means
    /// current is on the left (sibling right), direction=1 means current
    /// is on the right (sibling left). Required for prover re-verification.
    pub siblings: Vec<([u8; 32], u8)>,
}

/// A trace step for Schnorr signature verification coprocessor.
#[derive(Debug, Clone)]
pub struct SchnorrVerifyTraceStep {
    /// Message hash that was signed.
    pub msg_hash: [u8; 32],
    /// 64-byte Schnorr signature.
    pub signature: [u8; 64],
    /// 32-byte x-only public key.
    pub public_key: [u8; 32],
    /// Whether verification succeeded.
    pub verified: bool,
}

/// A trace step for SLH-DSA signature verification coprocessor.
#[derive(Debug, Clone)]
pub struct SlhDsaVerifyTraceStep {
    /// SHA-256 hash of the message (we don't store the full message).
    pub msg_hash: [u8; 32],
    /// 32-byte SLH-DSA public key.
    pub public_key: [u8; 32],
    /// Whether verification succeeded.
    pub verified: bool,
    /// Full message bytes for prover-side re-verification.
    /// Required for the prover to independently verify SLH-DSA correctness.
    pub message: Vec<u8>,
    /// Full SLH-DSA signature bytes (7,856 bytes) for re-verification.
    /// Stored in the local trace only (not transmitted). Required for the
    /// prover to independently confirm the verification result.
    pub signature_bytes: Vec<u8>,
}

/// A trace step for EMIT_LOG coprocessor.
#[derive(Debug, Clone)]
pub struct EmitLogTraceStep {
    /// Indexed topics (up to 4, each 32 bytes).
    pub topics: Vec<[u8; 32]>,
    /// SHA-256 hash of the non-indexed data payload.
    pub data_hash: [u8; 32],
}

/// Operations handled asynchronously by ZK Coprocessors.
///
/// Each precompile records its I/O here. The STARK prover verifies
/// correctness (re-computes the operation) and commits a Merkle root
/// of all coprocessor hashes into the proof's Fiat-Shamir transcript.
#[derive(Debug, Clone, Default)]
pub struct CoprocessorTrace {
    /// SHA-256 compression steps.
    pub sha256_steps: Vec<Sha256TraceStep>,
    /// Merkle path verification steps.
    pub merkle_steps: Vec<MerkleVerifyTraceStep>,
    /// Schnorr signature verification steps.
    pub schnorr_steps: Vec<SchnorrVerifyTraceStep>,
    /// SLH-DSA signature verification steps.
    pub slh_dsa_steps: Vec<SlhDsaVerifyTraceStep>,
    /// EMIT_LOG steps.
    pub emit_log_steps: Vec<EmitLogTraceStep>,
    /// CPU step index for each coprocessor operation, in order.
    /// Maps 1:1 with the flattened sequence (sha256, merkle, schnorr,
    /// slh_dsa, emit_log). Binds coprocessor results to their exact
    /// position in the CPU execution for verifier confirmation.
    pub cpu_steps: Vec<u64>,
}

impl CoprocessorTrace {
    /// Maximum total coprocessor trace entries.
    ///
    /// Mirrors `ExecutionTrace::MAX_TRACE_ROWS`. Without this cap a malicious
    /// contract could generate unbounded coprocessor entries (e.g., millions of
    /// SHA-256 calls) causing OOM in the prover.
    pub const MAX_COPROCESSOR_ROWS: usize = 1_000_000;

    /// Total number of coprocessor entries across all categories.
    pub fn total_len(&self) -> usize {
        self.sha256_steps.len()
            + self.merkle_steps.len()
            + self.schnorr_steps.len()
            + self.slh_dsa_steps.len()
            + self.emit_log_steps.len()
    }

    /// Extend this coprocessor trace with another, adjusting cpu_step offsets.
    ///
    /// The total entry count is capped at `MAX_COPROCESSOR_ROWS`.
    /// If extending would exceed the cap, entries from `other` are truncated
    /// proportionally (in insertion order across categories).
    pub fn extend(&mut self, other: &CoprocessorTrace, step_offset: u64) {
        let current = self.total_len();
        let available = Self::MAX_COPROCESSOR_ROWS.saturating_sub(current);
        let incoming = other.total_len();

        if incoming == 0 && other.cpu_steps.is_empty() {
            return;
        }

        // If everything fits, fast path — take all.
        if incoming <= available {
            self.sha256_steps.extend_from_slice(&other.sha256_steps);
            self.merkle_steps.extend(other.merkle_steps.iter().cloned());
            self.schnorr_steps.extend_from_slice(&other.schnorr_steps);
            self.slh_dsa_steps
                .extend(other.slh_dsa_steps.iter().cloned());
            self.emit_log_steps
                .extend(other.emit_log_steps.iter().cloned());
            for &cpu_step in &other.cpu_steps {
                self.cpu_steps.push(cpu_step + step_offset);
            }
            return;
        }

        // Slow path: budget-limited. Walk categories in order and consume
        // up to `available` total entries, tracking how many cpu_steps to take.
        let mut budget = available;
        let mut cpu_step_count = 0usize;

        let sha_take = other.sha256_steps.len().min(budget);
        self.sha256_steps
            .extend_from_slice(&other.sha256_steps[..sha_take]);
        budget -= sha_take;
        cpu_step_count += sha_take;

        let merkle_take = other.merkle_steps.len().min(budget);
        self.merkle_steps
            .extend(other.merkle_steps[..merkle_take].iter().cloned());
        budget -= merkle_take;
        cpu_step_count += merkle_take;

        let schnorr_take = other.schnorr_steps.len().min(budget);
        self.schnorr_steps
            .extend_from_slice(&other.schnorr_steps[..schnorr_take]);
        budget -= schnorr_take;
        cpu_step_count += schnorr_take;

        let slh_take = other.slh_dsa_steps.len().min(budget);
        self.slh_dsa_steps
            .extend(other.slh_dsa_steps[..slh_take].iter().cloned());
        budget -= slh_take;
        cpu_step_count += slh_take;

        let emit_take = other.emit_log_steps.len().min(budget);
        self.emit_log_steps
            .extend(other.emit_log_steps[..emit_take].iter().cloned());
        cpu_step_count += emit_take;

        // Take only the cpu_steps that correspond to the entries we kept.
        for &cpu_step in other.cpu_steps.iter().take(cpu_step_count) {
            self.cpu_steps.push(cpu_step + step_offset);
        }
    }
}

/// Execution trace — the full record of a program's execution.
#[derive(Debug, Clone)]
pub struct ExecutionTrace {
    /// All execution steps.
    pub steps: Vec<TraceStep>,
    /// Final PC when execution ended.
    pub final_pc: u32,
    /// Total gas consumed.
    pub total_gas: u64,
    /// Total steps executed.
    pub total_steps: u64,
    /// Whether execution completed normally (ECALL exit).
    pub completed: bool,
    /// Traces for operations offloaded to coprocessors (e.g., hashes).
    pub coprocessor: CoprocessorTrace,
    /// Step indices where a new transaction's trace begins (tx boundaries).
    /// Used by the STARK prover to relax PC flow and register continuity
    /// constraints at these points, since each tx starts with a fresh CPU.
    pub tx_boundaries: Vec<u64>,
}

impl ExecutionTrace {
    /// Create a new empty trace.
    pub fn new() -> Self {
        Self {
            steps: Vec::new(),
            final_pc: 0,
            total_gas: 0,
            total_steps: 0,
            completed: false,
            coprocessor: CoprocessorTrace::default(),
            tx_boundaries: Vec::new(),
        }
    }

    /// Create a new trace with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            steps: Vec::with_capacity(capacity),
            final_pc: 0,
            total_gas: 0,
            total_steps: 0,
            completed: false,
            coprocessor: CoprocessorTrace::default(),
            tx_boundaries: Vec::new(),
        }
    }

    /// Maximum trace rows per transaction.
    ///
    /// 1M rows × ~304 bytes/row ≈ 304 MB — fits in typical prover server RAM.
    /// Without this cap, a malicious contract with cheap opcodes in a tight loop
    /// could generate 100M+ rows, exhausting RAM and OOM-killing the prover.
    ///
    /// Gas limits alone don't protect because some opcodes are cheap in gas but
    /// expensive in trace rows (e.g., ADD = 1 gas but 1 trace row).
    pub const MAX_TRACE_ROWS: usize = 1_000_000;

    /// Record a step in the trace.
    ///
    /// Returns `Err(VmError::OutOfGas)` if trace capacity is exceeded.
    /// The caller (executor) treats this as a failed transaction — state is
    /// reverted and gas is consumed.
    pub fn record(&mut self, step: TraceStep) -> Result<(), crate::error::VmError> {
        if self.steps.len() >= Self::MAX_TRACE_ROWS {
            return Err(crate::error::VmError::TraceCapacityExceeded {
                rows: self.steps.len(),
                max: Self::MAX_TRACE_ROWS,
            });
        }
        self.total_gas = step.gas_used;
        self.total_steps = step.step + 1;
        self.final_pc = step.next_pc;
        self.steps.push(step);
        Ok(())
    }

    /// Mark execution as completed.
    pub fn mark_completed(&mut self) {
        self.completed = true;
    }

    /// Get the number of steps recorded.
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Check if the trace is empty.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Extend this trace by appending another trace's steps.
    ///
    /// PC bridging: the last step of `self` has its `next_pc` set to match
    /// the first step of `other`. Step indices in `other` are offset so they
    /// continue sequentially. Coprocessor traces are merged with adjusted
    /// `cpu_step` offsets.
    pub fn extend(&mut self, other: &ExecutionTrace) {
        if other.steps.is_empty() {
            return;
        }

        // Bridge PC: last step's next_pc → first step of other's pc
        if let (Some(last), Some(first)) = (self.steps.last_mut(), other.steps.first()) {
            last.next_pc = first.pc;
        }

        let step_offset = self.total_steps;

        // Record transaction boundary: the first step of the incoming trace
        // marks where a new transaction begins. The STARK prover uses this to
        // relax PC flow and register continuity constraints at this row.
        if !self.steps.is_empty() {
            self.tx_boundaries.push(step_offset);
        }

        // Adjust incoming trace's boundary indices relative to merged trace
        for &b in &other.tx_boundaries {
            self.tx_boundaries.push(b + step_offset);
        }
        let gas_offset = self.total_gas;

        // Verify gas continuity at boundary: the first step of the incoming trace
        // should start from its own gas_cost (its first step's gas), not exceed total_gas.
        debug_assert!(
            other.steps[0].gas_used <= other.total_gas,
            "extend: incoming trace first step gas_used ({}) > total_gas ({})",
            other.steps[0].gas_used,
            other.total_gas,
        );

        // Enforce MAX_TRACE_ROWS in extend() to prevent OOM
        let available = Self::MAX_TRACE_ROWS.saturating_sub(self.steps.len());
        let take_count = other.steps.len().min(available);
        for step in other.steps.iter().take(take_count) {
            let mut s = step.clone();
            s.step += step_offset;
            s.gas_used += gas_offset;
            self.steps.push(s);
        }

        self.total_gas += other.total_gas;
        self.total_steps += other.total_steps;
        self.final_pc = other.final_pc;
        if other.completed {
            self.completed = true;
        }

        // Merge coprocessor traces with adjusted cpu_step offsets
        self.coprocessor.extend(&other.coprocessor, step_offset);
    }

    /// Verify trace consistency (debug tool).
    ///
    /// Checks that each step's `regs_after` matches the next step's `regs_before`.
    pub fn verify_consistency(&self) -> bool {
        for window in self.steps.windows(2) {
            let prev = &window[0];
            let next = &window[1];
            // Post-state of step N should equal pre-state of step N+1
            if prev.regs_after != next.regs_before {
                return false;
            }
            // Next PC of step N should equal PC of step N+1
            if prev.next_pc != next.pc {
                return false;
            }
        }
        true
    }
}

impl Default for ExecutionTrace {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::{AluRegFunc, Instruction};

    fn make_step(step: u64, pc: u32, next_pc: u32) -> TraceStep {
        let mut regs_before = [0u32; 32];
        let mut regs_after = [0u32; 32];
        regs_before[1] = step as u32;
        regs_after[1] = step as u32 + 1;
        TraceStep {
            step,
            pc,
            instruction: Instruction::AluReg {
                func: AluRegFunc::Add,
                rd: 1,
                rs1: 1,
                rs2: 0,
            },
            instruction_word: 0x00008033,
            regs_before,
            regs_after,
            next_pc,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: step + 1,
        }
    }

    #[test]
    fn test_trace_record() {
        let mut trace = ExecutionTrace::new();
        assert!(trace.is_empty());

        trace.record(make_step(0, 0, 4)).unwrap();
        assert_eq!(trace.len(), 1);
        assert_eq!(trace.total_steps, 1);
        assert_eq!(trace.final_pc, 4);
    }

    #[test]
    fn test_trace_consistency_valid() {
        let mut trace = ExecutionTrace::new();
        let step0 = make_step(0, 0, 4);
        let mut step1 = make_step(1, 4, 8);
        // Make step1's regs_before match step0's regs_after
        step1.regs_before = step0.regs_after;
        trace.record(step0).unwrap();
        trace.record(step1).unwrap();
        assert!(trace.verify_consistency());
    }

    #[test]
    fn test_trace_consistency_invalid() {
        let mut trace = ExecutionTrace::new();
        let step0 = make_step(0, 0, 4);
        let mut step1 = make_step(1, 4, 8);
        // Deliberately make inconsistent
        step1.regs_before[5] = 0xDEAD;
        trace.record(step0).unwrap();
        trace.record(step1).unwrap();
        assert!(!trace.verify_consistency());
    }

    #[test]
    fn test_trace_with_capacity() {
        let trace = ExecutionTrace::with_capacity(1000);
        assert!(trace.is_empty());
        assert_eq!(trace.steps.capacity(), 1000);
    }

    // ── Coprocessor trace type tests ──────────────────────────────

    #[test]
    fn test_coprocessor_trace_default_empty() {
        let ct = CoprocessorTrace::default();
        assert!(ct.sha256_steps.is_empty());
        assert!(ct.merkle_steps.is_empty());
        assert!(ct.schnorr_steps.is_empty());
        assert!(ct.slh_dsa_steps.is_empty());
        assert!(ct.emit_log_steps.is_empty());
    }

    #[test]
    fn test_sha256_trace_step() {
        let step = Sha256TraceStep {
            input: [0xAB; 64],
            output: [0xCD; 32],
        };
        assert_eq!(step.input[0], 0xAB);
        assert_eq!(step.output[0], 0xCD);
    }

    #[test]
    fn test_merkle_verify_trace_step() {
        let step = MerkleVerifyTraceStep {
            root: [1u8; 32],
            leaf: [2u8; 32],
            depth: 20,
            verified: true,
            siblings: vec![],
        };
        assert_eq!(step.depth, 20);
        assert!(step.verified);
    }

    #[test]
    fn test_schnorr_verify_trace_step() {
        let step = SchnorrVerifyTraceStep {
            msg_hash: [0x11; 32],
            signature: [0x22; 64],
            public_key: [0x33; 32],
            verified: false,
        };
        assert!(!step.verified);
        assert_eq!(step.signature[0], 0x22);
    }

    #[test]
    fn test_slh_dsa_verify_trace_step() {
        let step = SlhDsaVerifyTraceStep {
            msg_hash: [0xAA; 32],
            public_key: [0xBB; 32],
            verified: true,
            message: vec![],
            signature_bytes: vec![],
        };
        assert!(step.verified);
    }

    #[test]
    fn test_emit_log_trace_step() {
        let step = EmitLogTraceStep {
            topics: vec![[0x01; 32], [0x02; 32]],
            data_hash: [0xFF; 32],
        };
        assert_eq!(step.topics.len(), 2);
        assert_eq!(step.data_hash[0], 0xFF);
    }

    #[test]
    fn test_coprocessor_trace_accumulate() {
        let mut ct = CoprocessorTrace::default();
        ct.sha256_steps.push(Sha256TraceStep {
            input: [0; 64],
            output: [0; 32],
        });
        ct.merkle_steps.push(MerkleVerifyTraceStep {
            root: [0; 32],
            leaf: [0; 32],
            depth: 10,
            verified: true,
            siblings: vec![],
        });
        ct.schnorr_steps.push(SchnorrVerifyTraceStep {
            msg_hash: [0; 32],
            signature: [0; 64],
            public_key: [0; 32],
            verified: true,
        });
        ct.slh_dsa_steps.push(SlhDsaVerifyTraceStep {
            msg_hash: [0; 32],
            public_key: [0; 32],
            verified: true,
            message: vec![],
            signature_bytes: vec![],
        });
        ct.emit_log_steps.push(EmitLogTraceStep {
            topics: vec![[0; 32]],
            data_hash: [0; 32],
        });

        assert_eq!(ct.sha256_steps.len(), 1);
        assert_eq!(ct.merkle_steps.len(), 1);
        assert_eq!(ct.schnorr_steps.len(), 1);
        assert_eq!(ct.slh_dsa_steps.len(), 1);
        assert_eq!(ct.emit_log_steps.len(), 1);
    }

    // ── extend() tests ──

    #[test]
    fn test_extend_empty_other() {
        let mut t1 = ExecutionTrace::new();
        t1.record(make_step(0, 0, 4)).unwrap();
        let t2 = ExecutionTrace::new();
        t1.extend(&t2);
        assert_eq!(t1.len(), 1);
        assert_eq!(t1.total_steps, 1);
    }

    #[test]
    fn test_extend_pc_bridging() {
        let mut t1 = ExecutionTrace::new();
        t1.record(make_step(0, 0, 4)).unwrap();
        t1.record(make_step(1, 4, 8)).unwrap();

        let mut t2 = ExecutionTrace::new();
        t2.record(make_step(0, 100, 104)).unwrap(); // starts at PC=100
        t2.record(make_step(1, 104, 108)).unwrap();

        t1.extend(&t2);

        // Total: 4 steps
        assert_eq!(t1.len(), 4);
        assert_eq!(t1.total_steps, 4);

        // PC bridging: t1's last pre-extend step (step 1) should have next_pc = 100
        assert_eq!(t1.steps[1].next_pc, 100);

        // Step offsets: steps from t2 should be 2, 3
        assert_eq!(t1.steps[2].step, 2);
        assert_eq!(t1.steps[3].step, 3);

        // PC preserved
        assert_eq!(t1.steps[2].pc, 100);
        assert_eq!(t1.steps[3].pc, 104);

        // Final PC
        assert_eq!(t1.final_pc, 108);
    }

    #[test]
    fn test_extend_gas_accumulation() {
        let mut t1 = ExecutionTrace::new();
        t1.record(make_step(0, 0, 4)).unwrap(); // gas_used=1
        t1.record(make_step(1, 4, 8)).unwrap(); // gas_used=2

        let mut t2 = ExecutionTrace::new();
        t2.record(make_step(0, 100, 104)).unwrap(); // gas_used=1
        t2.record(make_step(1, 104, 108)).unwrap(); // gas_used=2

        t1.extend(&t2);

        assert_eq!(t1.total_gas, 4); // 2 + 2
        // Gas offsets in extended steps
        assert_eq!(t1.steps[2].gas_used, 3); // 1 + 2 (offset)
        assert_eq!(t1.steps[3].gas_used, 4); // 2 + 2 (offset)
    }

    #[test]
    fn test_extend_coprocessor_cpu_steps_offset() {
        let mut t1 = ExecutionTrace::new();
        t1.record(make_step(0, 0, 4)).unwrap();
        t1.coprocessor.cpu_steps.push(0);

        let mut t2 = ExecutionTrace::new();
        t2.record(make_step(0, 100, 104)).unwrap();
        t2.coprocessor.cpu_steps.push(0);

        t1.extend(&t2);

        // t2's cpu_step 0 should become 1 (offset by t1.total_steps=1)
        assert_eq!(t1.coprocessor.cpu_steps, vec![0, 1]);
    }

    #[test]
    fn test_coprocessor_trace_extend_cap() {
        // Fill a CoprocessorTrace close to the cap, then extend with more
        // entries than fit. Only `available` entries should be accepted.
        let mut ct = CoprocessorTrace::default();

        // Pre-fill with MAX - 2 sha256 entries.
        let prefill = CoprocessorTrace::MAX_COPROCESSOR_ROWS - 2;
        for _ in 0..prefill {
            ct.sha256_steps.push(Sha256TraceStep {
                input: [0; 64],
                output: [0; 32],
            });
            ct.cpu_steps.push(0);
        }
        assert_eq!(ct.total_len(), prefill);

        // Build `other` with 5 entries (3 sha256 + 2 merkle).
        let mut other = CoprocessorTrace::default();
        for _ in 0..3 {
            other.sha256_steps.push(Sha256TraceStep {
                input: [1; 64],
                output: [1; 32],
            });
            other.cpu_steps.push(10);
        }
        for _ in 0..2 {
            other.merkle_steps.push(MerkleVerifyTraceStep {
                root: [0; 32],
                leaf: [0; 32],
                depth: 1,
                verified: true,
                siblings: vec![],
            });
            other.cpu_steps.push(20);
        }
        assert_eq!(other.total_len(), 5);

        ct.extend(&other, 100);

        // Only 2 entries should have been accepted (budget = MAX - prefill = 2).
        // Those 2 come from sha256 (first category walked).
        assert_eq!(ct.total_len(), CoprocessorTrace::MAX_COPROCESSOR_ROWS);
        assert_eq!(ct.sha256_steps.len(), prefill + 2);
        assert_eq!(ct.merkle_steps.len(), 0); // no budget left for merkle
        // cpu_steps: prefill original + 2 new
        assert_eq!(ct.cpu_steps.len(), prefill + 2);
    }

    #[test]
    fn test_coprocessor_trace_extend_no_cap_when_fits() {
        let mut ct = CoprocessorTrace::default();
        let mut other = CoprocessorTrace::default();
        other.sha256_steps.push(Sha256TraceStep {
            input: [0; 64],
            output: [0; 32],
        });
        other.merkle_steps.push(MerkleVerifyTraceStep {
            root: [0; 32],
            leaf: [0; 32],
            depth: 1,
            verified: true,
            siblings: vec![],
        });
        other.cpu_steps.push(0);
        other.cpu_steps.push(1);

        ct.extend(&other, 0);

        assert_eq!(ct.sha256_steps.len(), 1);
        assert_eq!(ct.merkle_steps.len(), 1);
        assert_eq!(ct.cpu_steps.len(), 2);
    }

    #[test]
    fn test_coprocessor_total_len() {
        let mut ct = CoprocessorTrace::default();
        assert_eq!(ct.total_len(), 0);
        ct.sha256_steps.push(Sha256TraceStep {
            input: [0; 64],
            output: [0; 32],
        });
        ct.schnorr_steps.push(SchnorrVerifyTraceStep {
            msg_hash: [0; 32],
            signature: [0; 64],
            public_key: [0; 32],
            verified: true,
        });
        assert_eq!(ct.total_len(), 2);
    }

    #[test]
    fn test_execution_trace_carries_coprocessor() {
        let mut trace = ExecutionTrace::new();
        trace.coprocessor.sha256_steps.push(Sha256TraceStep {
            input: [0; 64],
            output: [0; 32],
        });
        trace.coprocessor.merkle_steps.push(MerkleVerifyTraceStep {
            root: [0; 32],
            leaf: [0; 32],
            depth: 5,
            verified: true,
            siblings: vec![],
        });
        assert_eq!(trace.coprocessor.sha256_steps.len(), 1);
        assert_eq!(trace.coprocessor.merkle_steps.len(), 1);
    }
}
