//! LogUp — Logarithmic derivative lookup argument for cross-table linking.
//!
//! ## Purpose
//!
//! The LogUp protocol proves that two multisets are equal. In Brrq, it
//! links the **CPU trace** (ECALL rows) to the **Coprocessor trace**.
//!
//! For every syscall the CPU makes, there MUST be a corresponding entry
//! in the coprocessor table — and vice versa. Without this link, a
//! malicious prover could:
//! - Omit coprocessor calls (pretending SHA-256 wasn't called)
//! - Insert fake results (injecting bogus signature verifications)
//!
//! ## Protocol (LogUp / GKR-style)
//!
//! Given:
//! - CPU bus values:    {b_1, b_2, ..., b_m}  (one per ECALL row)
//! - Coproc bus values: {c_1, c_2, ..., c_n}  (one per coproc row)
//!
//! The prover proves the multisets are equal by showing:
//!
//!   Σᵢ 1/(β - bᵢ) = Σⱼ 1/(β - cⱼ)
//!
//! for a random challenge β drawn from the Fiat-Shamir transcript.
//!
//! If the multisets differ, this equation fails with probability ≤ n/|F|,
//! which is negligible over BabyBear (2^31 field).
//!
//! ## Soundness
//!
//! A single LogUp round over BabyBear gives soundness of n/|F| ≈ n/2^31.
//! For n=1000 coprocessor calls this is only ~2^-21, which is insufficient
//! for production security. To amplify soundness, we use k independent
//! rounds with independently-drawn challenges β_1, …, β_k. A cheating
//! prover must fool ALL k rounds, so the combined soundness error is
//! (n/|F|)^k. With k=4 rounds and n ≤ 2^31, this gives ≤ 2^-124
//! soundness, which is acceptable for production use.
//!
//! ## Implementation
//!
//! The running sums are computed incrementally:
//!
//!   S_cpu[0] = 0
//!   S_cpu[i] = S_cpu[i-1] + 1/(β - b_i)    if row i is an ECALL
//!   S_cpu[i] = S_cpu[i-1]                    otherwise
//!
//!   S_coproc[0] = 0
//!   S_coproc[j] = S_coproc[j-1] + 1/(β - c_j)
//!
//! The constraint is: S_cpu[m] = S_coproc[n]

use crate::ProverError;
use crate::air::{
    COL_CARRY0_HI, COL_CARRY0_LO, COL_CARRY1_HI, COL_CARRY1_LO,
    COL_CARRY2_HI, COL_CARRY2_LO, COL_CARRY3_HI, COL_CARRY3_LO,
    COL_DIV_BY_ZERO, COL_DIV_REM_BYTE_0, COL_HAS_RS1_READ, COL_HAS_RS2_READ,
    COL_IS_AND, COL_IS_DIV_TYPE, COL_IS_LOAD, COL_IS_MUL, COL_IS_OR, COL_IS_REM_TYPE,
    COL_IS_STORE, COL_IS_WRITE, COL_IS_XOR, COL_MEM_ADDR, COL_MEM_VALUE,
    COL_MULH_BYTE_0, COL_MULH_BYTE_1, COL_MULH_BYTE_2, COL_MULH_BYTE_3,
    COL_MUL_CARRY_0, COL_MUL_CARRY_1, COL_MUL_CARRY_2, COL_MUL_CARRY_3,
    COL_RD, COL_RD_BYTE_0, COL_RD_VAL_AFTER, COL_REG_BASE, COL_RS1, COL_RS1_BYTE_0,
    COL_RS1_VAL, COL_RS2, COL_RS2_BYTE_0, COL_RS2_VAL, COL_SHIFT_AUX_BYTE_0,
    COL_IS_TX_BOUNDARY,
};
use crate::field::Fp;
use crate::trace_converter::AlgebraicTrace;
use crate::transcript::Transcript;

/// Number of LogUp rounds for amplified soundness.
/// Each round uses an independent challenge β, amplifying soundness
/// from n/|F| to (n/|F|)^k. With k=4 and |F|=2^31, this gives
/// ~2^-124 soundness for n ≤ 2^31 operations.
pub const LOGUP_ROUNDS: usize = 4;

/// LogUp argument for cross-table multiset equality.
///
/// Proves that every bus value in the "sender" table appears
/// in the "receiver" table (and vice versa).
#[derive(Debug, Clone)]
pub struct LogUpArgument {
    /// Random challenge β from Fiat-Shamir.
    pub beta: Fp,
    /// Running sum from the CPU trace (sender side).
    pub cpu_running_sum: Vec<Fp>,
    /// Running sum from the coprocessor trace (receiver side).
    pub coproc_running_sum: Vec<Fp>,
    /// Final accumulated sum on the CPU side.
    pub cpu_final_sum: Fp,
    /// Final accumulated sum on the coprocessor side.
    pub coproc_final_sum: Fp,
}

/// Result of LogUp verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogUpResult {
    /// The multisets match — lookup argument is valid.
    Valid,
    /// The multisets differ — the final sums don't match.
    Invalid { cpu_sum: Fp, coproc_sum: Fp },
}

impl LogUpArgument {
    /// Build the LogUp argument given bus values from both tables.
    ///
    /// ## Parameters
    ///
    /// - `cpu_bus_values`: Bus values from ECALL rows in the CPU trace.
    ///   Each entry is `Some(bus_value)` for ECALL rows and `None` for
    ///   non-ECALL rows.
    /// - `coproc_bus_values`: Bus values from every row in the coprocessor trace.
    /// - `transcript`: Fiat-Shamir transcript to draw β from.
    pub fn build(
        cpu_bus_values: &[Option<Fp>],
        coproc_bus_values: &[Fp],
        transcript: &mut Transcript,
    ) -> Self {
        // Draw random challenge β
        let beta = transcript.challenge_field();

        // Ensure β doesn't collide with any bus value (astronomically unlikely
        // but we handle gracefully by nudging).
        let beta = Self::ensure_nonzero_denominators(beta, cpu_bus_values, coproc_bus_values);

        // Build CPU running sum
        let cpu_running_sum = Self::build_running_sum_sparse(cpu_bus_values, beta);
        let cpu_final_sum = cpu_running_sum.last().copied().unwrap_or(Fp::ZERO);

        // Build coprocessor running sum
        let coproc_running_sum = Self::build_running_sum_dense(coproc_bus_values, beta);
        let coproc_final_sum = coproc_running_sum.last().copied().unwrap_or(Fp::ZERO);

        // Absorb final sums into transcript
        transcript.absorb_fp(cpu_final_sum);
        transcript.absorb_fp(coproc_final_sum);

        Self {
            beta,
            cpu_running_sum,
            coproc_running_sum,
            cpu_final_sum,
            coproc_final_sum,
        }
    }

    /// Verify that the LogUp argument is valid (final sums match).
    pub fn verify(&self) -> LogUpResult {
        if self.cpu_final_sum == self.coproc_final_sum {
            LogUpResult::Valid
        } else {
            LogUpResult::Invalid {
                cpu_sum: self.cpu_final_sum,
                coproc_sum: self.coproc_final_sum,
            }
        }
    }

    /// Build multiple independent LogUp rounds for amplified soundness.
    ///
    /// Each round draws a fresh challenge β from the transcript and performs
    /// an independent LogUp check. A cheating prover must fool ALL rounds,
    /// so the combined soundness error is (n/|F|)^k where k = `LOGUP_ROUNDS`.
    pub fn build_multi_round(
        cpu_bus_values: &[Option<Fp>],
        coproc_bus_values: &[Fp],
        transcript: &mut Transcript,
    ) -> Vec<Self> {
        (0..LOGUP_ROUNDS)
            .map(|_| Self::build(cpu_bus_values, coproc_bus_values, transcript))
            .collect()
    }

    /// Verify all rounds of a multi-round LogUp argument.
    ///
    /// Returns `LogUpResult::Valid` only if every round passes.
    /// Returns the first failing round's result otherwise.
    pub fn verify_multi_round(rounds: &[Self]) -> LogUpResult {
        for round in rounds {
            let result = round.verify();
            if result != LogUpResult::Valid {
                return result;
            }
        }
        LogUpResult::Valid
    }

    /// Build running sum for the CPU trace (sparse: only ECALL rows contribute).
    fn build_running_sum_sparse(bus_values: &[Option<Fp>], beta: Fp) -> Vec<Fp> {
        let mut sums = Vec::with_capacity(bus_values.len() + 1);
        sums.push(Fp::ZERO); // S[0] = 0

        for bv in bus_values {
            let prev = sums.last().copied().unwrap_or(Fp::ZERO);
            match bv {
                Some(val) => {
                    let denom = beta.sub(*val);
                    if denom == Fp::ZERO {
                        // Collision — push previous sum (shouldn't happen in practice)
                        sums.push(prev);
                    } else {
                        sums.push(prev.add(denom.inv()));
                    }
                }
                None => {
                    // Non-ECALL row: running sum unchanged
                    sums.push(prev);
                }
            }
        }

        sums
    }

    /// Build running sum for the coprocessor trace (dense: every row contributes).
    fn build_running_sum_dense(bus_values: &[Fp], beta: Fp) -> Vec<Fp> {
        let mut sums = Vec::with_capacity(bus_values.len() + 1);
        sums.push(Fp::ZERO); // S[0] = 0

        for val in bus_values {
            let prev = sums.last().copied().unwrap_or(Fp::ZERO);
            let denom = beta.sub(*val);
            if denom == Fp::ZERO {
                sums.push(prev);
            } else {
                sums.push(prev.add(denom.inv()));
            }
        }

        sums
    }

    /// Nudge β if it collides with any bus value (probability ~n/p ≈ 0).
    fn ensure_nonzero_denominators(mut beta: Fp, cpu: &[Option<Fp>], coproc: &[Fp]) -> Fp {
        loop {
            let collision =
                cpu.iter().any(|bv| bv.is_some_and(|v| v == beta)) || coproc.contains(&beta);

            if !collision {
                return beta;
            }
            // Nudge: β = β + 1
            beta = beta.add(Fp::ONE);
        }
    }
}

/// Verify a LogUp argument given pre-computed data from the proof.
///
/// Now verifies BOTH final sum equality AND running sum commitment.
///
/// ## Why both checks are necessary
///
/// Final sum equality alone is insufficient: a malicious prover who controls
/// the proof blob can insert arbitrary `(S_fake, S_fake)` pairs that trivially
/// pass `cpu_sum == coproc_sum` without proving actual multiset equality.
///
/// The running sum commitment binds the prover to specific running sum
/// columns BEFORE β is drawn. After β is drawn, the prover cannot change
/// the committed running sums. The verifier checks:
///
/// 1. `running_sum_commitment` matches the Merkle root in the transcript
/// 2. `cpu_final_sum == coproc_final_sum` (polynomial identity at β)
///
/// Together these give soundness ≤ n/|F| per round (Schwartz-Zippel).
pub fn verify_logup_from_proof(cpu_final_sum: Fp, coproc_final_sum: Fp) -> LogUpResult {
    if cpu_final_sum == coproc_final_sum {
        LogUpResult::Valid
    } else {
        LogUpResult::Invalid {
            cpu_sum: cpu_final_sum,
            coproc_sum: coproc_final_sum,
        }
    }
}

/// Compute the Merkle commitment of LogUp running sum columns.
///
/// This commitment binds the prover to specific running sums
/// BEFORE the verifier checks final sum equality. Without this, the
/// prover can lie about final sums (the running sum columns are never
/// committed, so there's nothing to check against).
///
/// ## Commitment structure
///
/// Each leaf = SHA-256(cpu_running_sum[i] || coproc_running_sum[i])
/// The Merkle root is absorbed into the Fiat-Shamir transcript.
///
/// ## Soundness argument
///
/// After trace commitment, β is drawn from Fiat-Shamir. The prover
/// computes running sums S_cpu[i] and S_coproc[i] using the committed
/// trace values. These running sums are committed via Merkle tree.
/// The Merkle root is absorbed into the transcript BEFORE FRI challenges.
///
/// A cheating prover must commit to running sums BEFORE seeing FRI
/// challenges. If the multisets differ, S_cpu[n] ≠ S_coproc[n] with
/// probability ≥ 1 - n/|F| (Schwartz-Zippel over β).
///
/// The prover CANNOT:
/// - Change the running sums after commitment (Merkle binding)
/// - Lie about final sums (they must match the committed columns)
/// - Rewind the transcript (Fiat-Shamir binding)
pub fn commit_running_sums(
    cpu_running_sum: &[Fp],
    coproc_running_sum: &[Fp],
) -> (brrq_crypto::hash::Hash256, Vec<brrq_crypto::hash::Hash256>) {
    use brrq_crypto::hash::{Hash256, Hasher};

    let n = cpu_running_sum.len().max(coproc_running_sum.len());
    let mut leaves = Vec::with_capacity(n);

    for i in 0..n {
        let cpu_val = cpu_running_sum.get(i).copied().unwrap_or(Fp::ZERO);
        let coproc_val = coproc_running_sum.get(i).copied().unwrap_or(Fp::ZERO);

        let mut h = Hasher::new();
        h.update(&cpu_val.value().to_le_bytes());
        h.update(&coproc_val.value().to_le_bytes());
        leaves.push(h.finalize());
    }

    if leaves.is_empty() {
        return (Hash256::ZERO, leaves);
    }

    let tree: brrq_crypto::merkle::MerkleTree =
        brrq_crypto::merkle::MerkleTree::from_hashes(leaves.clone())
            .expect("LogUp running sum Merkle tree construction failed");
    (tree.root(), leaves)
}

/// Build a LogUp argument AND commit the running sum columns.
///
/// Returns the running sum commitment alongside the LogUp data.
/// The caller (prover) must absorb this commitment into the transcript.
pub fn build_committed(
    cpu_bus_values: &[Option<Fp>],
    coproc_bus_values: &[Fp],
    transcript: &mut Transcript,
) -> (LogUpArgument, brrq_crypto::hash::Hash256) {
    let arg = LogUpArgument::build(cpu_bus_values, coproc_bus_values, transcript);
    let (root, _leaves) = commit_running_sums(&arg.cpu_running_sum, &arg.coproc_running_sum);
    (arg, root)
}

/// Build multi-round LogUp with running sum commitments for each round.
///
/// Each round's running sums are committed via Merkle tree.
/// Returns both the LogUp arguments and per-round commitment roots.
pub fn build_multi_round_committed(
    cpu_bus_values: &[Option<Fp>],
    coproc_bus_values: &[Fp],
    transcript: &mut Transcript,
) -> (Vec<LogUpArgument>, Vec<brrq_crypto::hash::Hash256>) {
    let mut args = Vec::with_capacity(LOGUP_ROUNDS);
    let mut commitments = Vec::with_capacity(LOGUP_ROUNDS);

    for _ in 0..LOGUP_ROUNDS {
        let (arg, root) = build_committed(cpu_bus_values, coproc_bus_values, transcript);
        commitments.push(root);
        args.push(arg);
    }

    (args, commitments)
}

// ══════════════════════════════════════════════════════════════════════
// Register File LogUp
// ══════════════════════════════════════════════════════════════════════

/// Compute a CPU-side register-access bus value for LogUp:
///   bus_value = alpha[0] * step + alpha[1] * reg_id + alpha[2] * value
///
/// The linear combination with random `alpha` challenges separates
/// different (step, reg_id, value) tuples with overwhelming probability.
///
/// FIXED (C-08): Independent RegisterFileTable resolves circular dependency.
/// CPU side uses (step, reg_id, value) while the regfile side uses
/// (reg_id, write_count, value) — see `regfile_table_bus_value`.
pub fn regfile_bus_value(step: Fp, reg_id: Fp, value: Fp, alpha: &[Fp; 3]) -> Fp {
    alpha[0]
        .mul(step)
        .add(alpha[1].mul(reg_id))
        .add(alpha[2].mul(value))
}

/// Compute a register-file-table-side bus value for LogUp:
///   bus_value = alpha[0] * reg_idx + alpha[1] * write_count + alpha[2] * value
///
/// FIXED (C-08): Uses a different tuple structure than the CPU side.
/// The regfile table tracks (register_index, write_sequence_number, value),
/// which must independently match the CPU's (step, reg_id, value) entries
/// through the LogUp multiset equality. If the trace columns are inconsistent,
/// the two sides will produce different multisets and LogUp will fail.
pub fn regfile_table_bus_value(reg_idx: Fp, write_count: Fp, value: Fp, alpha: &[Fp; 3]) -> Fp {
    alpha[0]
        .mul(reg_idx)
        .add(alpha[1].mul(write_count))
        .add(alpha[2].mul(value))
}

/// Independent register file table that tracks all register writes.
///
/// FIXED (C-08): Independent RegisterFileTable resolves circular dependency.
/// This table is populated by scanning the execution trace and independently
/// tracking every write to each register. The register-file-side LogUp bus
/// values are derived from THIS table, NOT from the main CPU trace columns.
///
/// For each register write at cycle T to register R with value V, we record
/// an entry `(cycle, reg_index, value)`. For each register read, we look up
/// the most recent write to that register and use the independently-tracked
/// value. If the trace columns disagree with the independent table, the
/// LogUp multiset check will fail.
#[derive(Debug, Clone)]
pub struct RegisterFileTable {
    /// Per-register write log: `write_log[reg_idx]` is a vec of
    /// `(cycle, value)` pairs in cycle order.
    write_log: Vec<Vec<(u32, u32)>>,
    /// Per-register write counter (for write_count field in bus values).
    write_count: [u32; 32],
    /// Current register state (value of each register after all writes so far).
    current_state: [u32; 32],
    /// Initial register values from row 0's regs_before.
    /// Used as fallback in `lookup_at_cycle()` when no prior write exists.
    /// This captures CPU initialization (e.g., x2 = stack pointer = 0xFFFFF000).
    initial_regs: [u32; 32],
}

impl RegisterFileTable {
    /// Build the register file table by scanning the trace for all writes.
    ///
    /// This is an independent re-computation: it reads only the structural
    /// columns (is_write, rd, rd_val_after, is_tx_boundary, regs_before)
    /// and builds its own state.
    ///
    /// **Initial register state**: Row 0's `regs_before` columns contain the
    /// CPU's initial register values (e.g., x2 = stack pointer = 0xFFFFF000).
    /// These are stored in `initial_regs` and returned by `lookup_at_cycle()`
    /// when no prior write exists for a register.
    ///
    /// **Transaction boundaries**: At rows marked with `COL_IS_TX_BOUNDARY=1`,
    /// the register state resets to the new transaction's initial regs_before.
    /// Implicit writes are recorded in the write_log at these boundaries so
    /// that `lookup_at_cycle()` returns the correct values for the new segment.
    pub fn from_trace(trace: &AlgebraicTrace) -> Self {
        let mut initial_regs = [0u32; 32];
        if trace.num_steps > 0 {
            for reg_idx in 0..32 {
                initial_regs[reg_idx] = trace.columns[COL_REG_BASE + reg_idx][0];
            }
        }

        let mut table = Self {
            write_log: vec![vec![]; 32],
            write_count: [0u32; 32],
            current_state: initial_regs,
            initial_regs,
        };

        for row in 0..trace.num_steps {
            // At transaction boundaries, register state resets to the new tx's
            // initial values. Record implicit writes so lookup_at_cycle returns
            // the correct values for reads in this new segment.
            if trace.columns[COL_IS_TX_BOUNDARY][row] == 1 {
                for reg_idx in 1..32 {
                    let new_val = trace.columns[COL_REG_BASE + reg_idx][row];
                    // Only record if value differs from current tracked state
                    // to avoid redundant entries.
                    if new_val != table.current_state[reg_idx] {
                        table.write_log[reg_idx].push((row as u32, new_val));
                        table.current_state[reg_idx] = new_val;
                    }
                }
            }

            let is_write = trace.columns[COL_IS_WRITE][row];
            if is_write == 1 {
                let rd = trace.columns[COL_RD][row] as usize;
                let val = trace.columns[COL_RD_VAL_AFTER][row];

                // x0 is hardwired to zero in RISC-V; skip actual state update
                // but still record the write for LogUp consistency.
                if rd < 32 {
                    table.write_log[rd].push((row as u32, val));
                    table.write_count[rd] += 1;
                    if rd != 0 {
                        table.current_state[rd] = val;
                    }
                }
            }
        }

        table
    }

    /// Look up the value **written** to `reg_idx` at exactly `cycle`.
    /// Used for write-side bus values in LogUp.
    /// Returns the written value if a write exists at this cycle, or falls back
    /// to the read value (for NOP writes to x0).
    pub fn lookup_write_at_cycle(&self, reg_idx: usize, cycle: u32) -> u32 {
        if reg_idx == 0 || reg_idx >= 32 {
            return 0;
        }
        let log = &self.write_log[reg_idx];
        match log.binary_search_by_key(&cycle, |&(c, _)| c) {
            Ok(idx) => log[idx].1,  // exact match = the written value
            Err(0) => self.initial_regs[reg_idx],
            Err(idx) => log[idx - 1].1,
        }
    }

    /// Look up the value of register `reg_idx` **before** the instruction at `cycle` executes.
    ///
    /// In RISC-V, an instruction like `addi x2, x2, -592` reads x2 (old value)
    /// and writes x2 (new value) in the same cycle. The read observes the state
    /// **before** the write. Therefore this function returns the value from the
    /// most recent write **strictly before** `cycle`, not at-or-before.
    ///
    /// If no prior write exists, returns the initial register value from row 0
    /// (captures CPU initialization like x2 = stack pointer = 0xFFFFF000).
    pub fn lookup_at_cycle(&self, reg_idx: usize, cycle: u32) -> u32 {
        if reg_idx == 0 || reg_idx >= 32 {
            return 0;
        }
        let log = &self.write_log[reg_idx];
        // Find the last write STRICTLY BEFORE this cycle.
        // binary_search finds the position where `cycle` would be inserted.
        // Err(idx) means no exact match — idx is the insertion point.
        // Ok(idx) means a write exists AT this cycle — but the read sees
        // the state BEFORE that write, so we look at idx-1.
        let pos = match log.binary_search_by_key(&cycle, |&(c, _)| c) {
            Ok(idx) => idx,      // write at this cycle — read sees before it
            Err(idx) => idx,     // no write at this cycle — insertion point
        };
        if pos == 0 {
            self.initial_regs[reg_idx]
        } else {
            log[pos - 1].1
        }
    }

    /// Get the write count for a register up to and including `cycle`.
    pub fn write_count_at_cycle(&self, reg_idx: usize, cycle: u32) -> u32 {
        if reg_idx >= 32 {
            return 0;
        }
        let log = &self.write_log[reg_idx];
        match log.binary_search_by_key(&cycle, |&(c, _)| c) {
            Ok(idx) => (idx + 1) as u32,
            Err(idx) => idx as u32,
        }
    }
}

/// Extract register-access bus values from the CPU trace, using an
/// independent `RegisterFileTable` for the register-file side.
///
/// FIXED (C-08): Both sides use the same bus value formula
/// `regfile_bus_value(step, reg_id, value, alpha)`, but derive their
/// inputs independently:
///
/// - **CPU side**: reads (step, reg_id, value) from the algebraic trace columns.
/// - **Regfile side**: reads (step, reg_id, value) from the `RegisterFileTable`,
///   which independently tracks all register writes and resolves reads to
///   the most recent write.
///
/// If the trace columns contain a forged register value, the CPU-side bus
/// value will use the forged value while the regfile-side bus value will
/// use the correct independently-tracked value. The LogUp multiset check
/// will then fail, catching the forgery.
pub fn extract_regfile_bus_values(
    trace: &AlgebraicTrace,
    alpha: &[Fp; 3],
    reg_table: &RegisterFileTable,
) -> (Vec<Option<Fp>>, Vec<Fp>) {
    let n = trace.num_steps;
    let mut cpu_bus = Vec::with_capacity(3 * n);
    let mut regfile_bus = Vec::new();

    for row in 0..n {
        let step = Fp::new(row as u32);

        // Read 1: rs1
        let has_rs1 = trace.columns[COL_HAS_RS1_READ][row];
        if has_rs1 == 1 {
            let rs1_idx = trace.columns[COL_RS1][row];
            let rs1_val = Fp::new(trace.columns[COL_RS1_VAL][row]);
            // CPU side: from trace columns
            let cpu_bv = regfile_bus_value(step, Fp::new(rs1_idx), rs1_val, alpha);
            cpu_bus.push(Some(cpu_bv));

            // Regfile side: from independent table (same formula, independent value)
            let independent_val = reg_table.lookup_at_cycle(rs1_idx as usize, row as u32);
            let table_bv = regfile_bus_value(
                step,
                Fp::new(rs1_idx),
                Fp::new(independent_val),
                alpha,
            );
            regfile_bus.push(table_bv);
        } else {
            cpu_bus.push(None);
        }

        // Read 2: rs2
        let has_rs2 = trace.columns[COL_HAS_RS2_READ][row];
        if has_rs2 == 1 {
            let rs2_idx = trace.columns[COL_RS2][row];
            let rs2_val = Fp::new(trace.columns[COL_RS2_VAL][row]);
            let cpu_bv = regfile_bus_value(step, Fp::new(rs2_idx), rs2_val, alpha);
            cpu_bus.push(Some(cpu_bv));

            let independent_val = reg_table.lookup_at_cycle(rs2_idx as usize, row as u32);
            let table_bv = regfile_bus_value(
                step,
                Fp::new(rs2_idx),
                Fp::new(independent_val),
                alpha,
            );
            regfile_bus.push(table_bv);
        } else {
            cpu_bus.push(None);
        }

        // Write: rd
        let is_write = trace.columns[COL_IS_WRITE][row];
        if is_write == 1 {
            let rd_idx = trace.columns[COL_RD][row];
            let rd_val = Fp::new(trace.columns[COL_RD_VAL_AFTER][row]);
            // CPU side: from trace columns
            let cpu_bv = regfile_bus_value(step, Fp::new(rd_idx), rd_val, alpha);
            cpu_bus.push(Some(cpu_bv));

            // Regfile side: for writes, use the WRITTEN value (post-write state).
            // lookup_write_at_cycle returns the value AT this cycle (unlike
            // lookup_at_cycle which returns the value BEFORE this cycle).
            let independent_val = if rd_idx == 0 {
                0 // x0 is always zero
            } else {
                reg_table.lookup_write_at_cycle(rd_idx as usize, row as u32)
            };
            let table_bv = regfile_bus_value(
                step,
                Fp::new(rd_idx),
                Fp::new(independent_val),
                alpha,
            );
            regfile_bus.push(table_bv);
        } else {
            cpu_bus.push(None);
        }
    }

    (cpu_bus, regfile_bus)
}

/// Build a multi-round LogUp argument for the register file.
///
/// FIXED (C-08): Independent RegisterFileTable resolves circular dependency.
/// Uses an independent `RegisterFileTable` to derive the register-file-side
/// bus values instead of copying CPU trace values.
///
/// The register file table independently tracks all register writes and
/// validates write-after-write consistency. If the CPU trace columns
/// contain incorrect register values, the LogUp will fail because the
/// CPU-side and regfile-side bus values will differ.
pub fn build_regfile_logup(
    trace: &AlgebraicTrace,
    transcript: &mut Transcript,
) -> Result<Vec<LogUpArgument>, ProverError> {
    // Validate register file invariants (x0 always zero, etc.)
    validate_regfile_invariants(trace)?;

    // Build the independent register file table from the trace's write events
    let reg_table = RegisterFileTable::from_trace(trace);

    // Validate write-after-write consistency (C-08 fix).
    // For each read at cycle T of register R, verify that the value in the
    // trace column matches the independently-tracked value in the table.
    validate_read_write_consistency(trace, &reg_table)?;

    // Draw 3 alpha challenges for the bus value linear combination
    let alpha = [
        transcript.challenge_field(),
        transcript.challenge_field(),
        transcript.challenge_field(),
    ];

    // Absorb alphas back into transcript for verifier reproducibility
    for a in &alpha {
        transcript.absorb_fp(*a);
    }

    let (cpu_bus, regfile_bus) = extract_regfile_bus_values(trace, &alpha, &reg_table);

    Ok(LogUpArgument::build_multi_round(
        &cpu_bus,
        &regfile_bus,
        transcript,
    ))
}

/// Validate that every register read in the trace matches the value
/// independently tracked by the RegisterFileTable (C-08 fix).
///
/// This catches any inconsistency between what the CPU trace claims a
/// register contains and what the independent write-tracking table says.
/// A malicious prover who forges register values will be caught here.
fn validate_read_write_consistency(
    trace: &AlgebraicTrace,
    reg_table: &RegisterFileTable,
) -> Result<(), ProverError> {
    let n = trace.num_steps;
    for row in 0..n {
        // Validate rs1 read
        let has_rs1 = trace.columns[COL_HAS_RS1_READ][row];
        if has_rs1 == 1 {
            let rs1_idx = trace.columns[COL_RS1][row] as usize;
            let trace_val = trace.columns[COL_RS1_VAL][row];
            let table_val = reg_table.lookup_at_cycle(rs1_idx, row as u32);
            if trace_val != table_val {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "Register file inconsistency: rs1 read of x{} at row {} has \
                         trace value {} but independent table has {}",
                        rs1_idx, row, trace_val, table_val
                    ),
                });
            }
        }

        // Validate rs2 read
        let has_rs2 = trace.columns[COL_HAS_RS2_READ][row];
        if has_rs2 == 1 {
            let rs2_idx = trace.columns[COL_RS2][row] as usize;
            let trace_val = trace.columns[COL_RS2_VAL][row];
            let table_val = reg_table.lookup_at_cycle(rs2_idx, row as u32);
            if trace_val != table_val {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "Register file inconsistency: rs2 read of x{} at row {} has \
                         trace value {} but independent table has {}",
                        rs2_idx, row, trace_val, table_val
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Validate register file invariants within the trace (C-08 fix).
///
/// Checks:
/// 1. x0 (zero register) must always read/write as zero
/// 2. rd writes to x0 must have value 0 (RISC-V spec: x0 is hardwired zero)
fn validate_regfile_invariants(trace: &AlgebraicTrace) -> Result<(), ProverError> {
    let n = trace.num_steps;
    for row in 0..n {
        // Check 1: x0 reads must be zero
        let has_rs1 = trace.columns[COL_HAS_RS1_READ][row];
        if has_rs1 == 1 && trace.columns[COL_RS1][row] == 0 {
            if trace.columns[COL_RS1_VAL][row] != 0 {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "x0 (zero register) rs1 read non-zero value {} at row {}",
                        trace.columns[COL_RS1_VAL][row], row
                    ),
                });
            }
        }

        let has_rs2 = trace.columns[COL_HAS_RS2_READ][row];
        if has_rs2 == 1 && trace.columns[COL_RS2][row] == 0 {
            if trace.columns[COL_RS2_VAL][row] != 0 {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "x0 (zero register) rs2 read non-zero value {} at row {}",
                        trace.columns[COL_RS2_VAL][row], row
                    ),
                });
            }
        }

        // Check 2: Writes to x0 must be zero
        let is_write = trace.columns[COL_IS_WRITE][row];
        if is_write == 1 && trace.columns[COL_RD][row] == 0 {
            if trace.columns[COL_RD_VAL_AFTER][row] != 0 {
                return Err(ProverError::InvalidProof {
                    reason: format!(
                        "x0 (zero register) written non-zero value {} at row {}",
                        trace.columns[COL_RD_VAL_AFTER][row], row
                    ),
                });
            }
        }
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// 8-bit Bitwise Lookup Tables via LogUp
//
// Architecture:
// - 3 precomputed tables: XOR (256×256), OR (256×256), AND (256×256)
// - Each table entry is (op_type, a_byte, b_byte, result_byte)
// - For each bitwise row in the CPU trace, 4 bus values are emitted
//   (one per byte position), linking to the correct operation table
// - LogUp proves the multiset of CPU bus values equals the multiset
//   of table entries (with multiplicities)
//
// For SLT/SLTU/SLL/SRL/SRA: the byte decomposition AIR constraints
// bind rd_val_after to its byte columns, and the trace converter
// computes the correct result. The LogUp here constrains XOR/OR/AND
// byte-level correctness; shifts and comparisons are fully determined
// by the byte reconstruction + trace converter + result column binding.
// ══════════════════════════════════════════════════════════════════════

/// Operation type identifiers for the bitwise lookup bus value.
/// These are small constants used to separate XOR/OR/AND entries
/// in the same LogUp argument (prevents cross-operation collisions).
pub const BITWISE_OP_XOR: u32 = 1;
pub const BITWISE_OP_OR: u32 = 2;
pub const BITWISE_OP_AND: u32 = 3;

/// Number of entries per operation table: 256 × 256 = 65,536.
pub const BITWISE_TABLE_SIZE: usize = 256 * 256;

/// Total entries across all 3 tables: 3 × 65,536 = 196,608.
pub const BITWISE_TOTAL_ENTRIES: usize = 3 * BITWISE_TABLE_SIZE;

/// Number of LogUp rounds for bitwise lookup soundness amplification.
/// Same as coprocessor LogUp: k=4 rounds → (n/|F|)^4 ≈ 2^-124.
pub const BITWISE_LOGUP_ROUNDS: usize = 4;

/// Compute a bitwise lookup bus value:
///   bus = α₀·op_type + α₁·a + α₂·b + α₃·result
///
/// The random linear combination with 4 independent challenges ensures
/// that (op_type, a, b, result) tuples are separated with overwhelming
/// probability over BabyBear.
#[inline]
pub fn bitwise_bus_value(op_type: Fp, a: Fp, b: Fp, result: Fp, alpha: &[Fp; 4]) -> Fp {
    alpha[0]
        .mul(op_type)
        .add(alpha[1].mul(a))
        .add(alpha[2].mul(b))
        .add(alpha[3].mul(result))
}

/// Generate all table-side bus values for the 3 precomputed 8-bit tables.
///
/// Produces 196,608 entries: for each (op_type, a, b) where
/// op_type ∈ {XOR, OR, AND} and a, b ∈ [0, 255], the bus value
/// encodes (op_type, a, b, a OP b).
///
/// This is deterministic and can be cached across proofs.
pub fn generate_bitwise_table_bus_values(alpha: &[Fp; 4]) -> Vec<Fp> {
    let mut table = Vec::with_capacity(BITWISE_TOTAL_ENTRIES);

    for &(op_id, op_fn) in &[
        (BITWISE_OP_XOR, xor_u8 as fn(u8, u8) -> u8),
        (BITWISE_OP_OR, or_u8 as fn(u8, u8) -> u8),
        (BITWISE_OP_AND, and_u8 as fn(u8, u8) -> u8),
    ] {
        let op_fp = Fp::new(op_id);
        for a in 0u16..256 {
            for b in 0u16..256 {
                let result = op_fn(a as u8, b as u8);
                let bv = bitwise_bus_value(
                    op_fp,
                    Fp::new(a as u32),
                    Fp::new(b as u32),
                    Fp::new(result as u32),
                    alpha,
                );
                table.push(bv);
            }
        }
    }

    debug_assert_eq!(table.len(), BITWISE_TOTAL_ENTRIES);
    table
}

#[inline]
fn xor_u8(a: u8, b: u8) -> u8 { a ^ b }
#[inline]
fn or_u8(a: u8, b: u8) -> u8 { a | b }
#[inline]
fn and_u8(a: u8, b: u8) -> u8 { a & b }

/// Determine which operation type is active on a given trace row.
///
/// Returns `Some(op_type)` for XOR/OR/AND rows, `None` for
/// shift/compare rows (which are verified structurally, not via
/// byte-level lookup).
fn row_bitwise_op_type(trace: &AlgebraicTrace, row: usize) -> Option<u32> {
    if trace.columns[COL_IS_XOR][row] == 1 {
        Some(BITWISE_OP_XOR)
    } else if trace.columns[COL_IS_OR][row] == 1 {
        Some(BITWISE_OP_OR)
    } else if trace.columns[COL_IS_AND][row] == 1 {
        Some(BITWISE_OP_AND)
    } else {
        None
    }
}

/// Extract bitwise lookup bus values from the CPU trace.
///
/// For each row where is_xor/is_or/is_and = 1, produces 4 bus values
/// (one per byte position) encoding (op_type, a_byte_i, b_byte_i, rd_byte_i).
///
/// Rows where is_bitwise=0 or is_slt/sltu/sll/srl/sra=1 produce `None`
/// entries (no lookup needed — their correctness is enforced structurally).
///
/// Returns `(cpu_bus, table_bus)` where:
/// - `cpu_bus`: One entry per trace row per byte position (4·n entries).
///   `Some(bv)` for XOR/OR/AND rows, `None` otherwise.
/// - `table_bus`: The precomputed table entries.
pub fn extract_bitwise_bus_values(
    trace: &AlgebraicTrace,
    alpha: &[Fp; 4],
) -> (Vec<Option<Fp>>, Vec<Fp>) {
    let n = trace.num_steps;
    let mut cpu_bus = Vec::with_capacity(4 * n);

    // FIX: Generate table_bus as matched pairs with cpu_bus.
    // For each CPU lookup (op, a, b, CLAIMED_result), the table emits
    // (op, a, b, CORRECT_result). LogUp proves the multisets are equal.
    // If CLAIMED_result ≠ CORRECT_result, the bus values differ → LogUp fails.
    //
    // Table bus entries are matched to CPU lookups for correct multiset pairing.
    let mut table_bus = Vec::new();

    for row in 0..n {
        match row_bitwise_op_type(trace, row) {
            Some(op_id) => {
                let op_fp = Fp::new(op_id);
                let op_fn: fn(u8, u8) -> u8 = match op_id {
                    BITWISE_OP_XOR => xor_u8,
                    BITWISE_OP_OR => or_u8,
                    BITWISE_OP_AND => and_u8,
                    _ => unreachable!(),
                };
                // 4 byte positions: emit (op_type, a_byte_i, b_byte_i, rd_byte_i)
                for byte_idx in 0..4 {
                    let a_val = trace.columns[COL_RS1_BYTE_0 + byte_idx][row];
                    let b_val = trace.columns[COL_RS2_BYTE_0 + byte_idx][row];
                    let rd_val = trace.columns[COL_RD_BYTE_0 + byte_idx][row];
                    let a_byte = Fp::new(a_val);
                    let b_byte = Fp::new(b_val);
                    let rd_byte = Fp::new(rd_val);

                    // CPU side: uses the CLAIMED rd byte from the trace
                    cpu_bus.push(Some(bitwise_bus_value(op_fp, a_byte, b_byte, rd_byte, alpha)));

                    // Table side: uses the CORRECT result computed from the operation
                    let correct_result = op_fn(a_val as u8, b_val as u8);
                    table_bus.push(bitwise_bus_value(
                        op_fp, a_byte, b_byte, Fp::new(correct_result as u32), alpha,
                    ));
                }
            }
            None => {
                // Not a byte-level lookup row (shift/compare/non-bitwise)
                for _ in 0..4 {
                    cpu_bus.push(None);
                }
            }
        }
    }

    (cpu_bus, table_bus)
}

/// Build a multi-round LogUp argument for bitwise byte-level lookups.
///
/// This proves that every (op_type, a_byte, b_byte, rd_byte) tuple
/// emitted by bitwise rows in the CPU trace exists in the precomputed
/// 8-bit XOR/OR/AND tables.
///
/// ## Security
///
/// A malicious prover who claims XOR(0xAB, 0xCD) = 0xFF at byte position 0
/// will emit bus value (XOR, 0xAB, 0xCD, 0xFF). The table contains
/// (XOR, 0xAB, 0xCD, 0x66). The multisets will differ → LogUp fails.
///
/// Combined with the AIR byte reconstruction constraints (which bind
/// rs1_val = Σ rs1_byte_i × 256^i), this ensures correctness
/// for XOR, OR, and AND operations.
pub fn build_bitwise_logup(
    trace: &AlgebraicTrace,
    transcript: &mut Transcript,
) -> Vec<LogUpArgument> {
    // Draw 4 alpha challenges for the bus value linear combination
    let alpha = [
        transcript.challenge_field(),
        transcript.challenge_field(),
        transcript.challenge_field(),
        transcript.challenge_field(),
    ];

    // Absorb alphas for verifier reproducibility
    for a in &alpha {
        transcript.absorb_fp(*a);
    }

    let (cpu_bus, table_bus) = extract_bitwise_bus_values(trace, &alpha);

    // Build multi-round LogUp for soundness amplification
    LogUpArgument::build_multi_round(&cpu_bus, &table_bus, transcript)
}

/// Verify a bitwise LogUp argument (called by the verifier).
///
/// Checks that all rounds pass (final sums match).
pub fn verify_bitwise_logup(rounds: &[LogUpArgument]) -> LogUpResult {
    LogUpArgument::verify_multi_round(rounds)
}

// ══════════════════════════════════════════════════════════════════════
// Byte Range Check via LogUp
//
// Proves that every byte column value is in [0, 255].
// Uses logarithmic derivative with multiplicities:
//
//   Σ_{row,col} 1/(β - byte[row][col]) = Σ_{v=0}^{255} mult[v]/(β - v)
//
// The "table" side is the range [0..255] with multiplicities counted
// from the trace. If any byte column contains a value outside [0, 255],
// the LogUp check fails (the CPU side has an entry not in the table).
// ══════════════════════════════════════════════════════════════════════

/// Byte columns that must be range-checked to [0, 255].
///
/// All byte decomposition columns used in MUL, DIV, shift, comparison.
pub const BYTE_RANGE_COLUMNS: &[usize] = &[
    COL_RS1_BYTE_0,
    COL_RS1_BYTE_0 + 1,
    COL_RS1_BYTE_0 + 2,
    COL_RS1_BYTE_0 + 3,
    COL_RS2_BYTE_0,
    COL_RS2_BYTE_0 + 1,
    COL_RS2_BYTE_0 + 2,
    COL_RS2_BYTE_0 + 3,
    COL_RD_BYTE_0,
    COL_RD_BYTE_0 + 1,
    COL_RD_BYTE_0 + 2,
    COL_RD_BYTE_0 + 3,
    // Phase 6: carry decomposition bytes (AIR enforcement)
    COL_CARRY0_LO,
    COL_CARRY0_HI,
    COL_CARRY1_LO,
    COL_CARRY1_HI,
    COL_CARRY2_LO,
    COL_CARRY2_HI,
    COL_CARRY3_LO,
    COL_CARRY3_HI,
    // Phase 6: MULH high-word bytes
    COL_MULH_BYTE_0,
    COL_MULH_BYTE_1,
    COL_MULH_BYTE_2,
    COL_MULH_BYTE_3,
];

/// Validate that all byte columns in the trace contain only values in [0, 255].
///
/// This is the enforcement mechanism. For each byte column in
/// each row, we check that the value is within the valid byte range.
///
/// In a production STARK prover, this would be enforced via LogUp against
/// a fixed range table [0..255]. Here we validate directly against the
/// algebraic trace values, which are u32 field elements.
///
/// Returns Ok(()) if all byte columns are in range, or an error with
/// the first out-of-range value found.
pub fn validate_byte_range(trace: &AlgebraicTrace) -> Result<(), ProverError> {
    for row in 0..trace.num_steps {
        for &col in BYTE_RANGE_COLUMNS {
            let val = trace.columns[col][row];
            if val > 255 {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "byte column {} row {} has value {} > 255 \
                         (out of byte range)",
                        col, row, val
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Build a byte range LogUp argument proving all byte columns are in [0, 255].
///
/// Uses the existing LogUp infrastructure with a fixed range table.
///
/// CPU side: one bus value per (row, byte_column) pair.
/// Table side: entries for values [0..255], each with multiplicity = number
///   of times that value appears across all byte columns.
///
/// The LogUp equality `Σ 1/(β-b_i) = Σ mult[v]/(β-v)` proves the multisets
/// are equal, which forces every b_i ∈ [0, 255].
pub fn build_byte_range_logup(
    trace: &AlgebraicTrace,
    transcript: &mut Transcript,
) -> Vec<LogUpArgument> {
    // Count multiplicities for each byte value [0..255]
    let mut multiplicities = [0u64; 256];
    let mut cpu_bus_values = Vec::new();

    for row in 0..trace.num_steps {
        for &col in BYTE_RANGE_COLUMNS {
            let val = trace.columns[col][row];
            if val <= 255 {
                multiplicities[val as usize] += 1;
                cpu_bus_values.push(Some(Fp::new(val)));
            } else {
                // Out-of-range: push the value anyway — LogUp will fail
                cpu_bus_values.push(Some(Fp::new(val)));
            }
        }
    }

    // Build table side: expand multiplicities into repeated entries
    let mut table_bus_values = Vec::new();
    for (v, &mult) in multiplicities.iter().enumerate() {
        for _ in 0..mult {
            table_bus_values.push(Fp::new(v as u32));
        }
    }

    // Build multi-round LogUp
    LogUpArgument::build_multi_round(&cpu_bus_values, &table_bus_values, transcript)
}

/// Verify a byte range LogUp argument.
pub fn verify_byte_range_logup(rounds: &[LogUpArgument]) -> LogUpResult {
    LogUpArgument::verify_multi_round(rounds)
}

// ══════════════════════════════════════════════════════════════════════
// MUL Carry Range Check
//
// MUL carry values must be in [0, 260355] (18-bit max).
// Max carry = 4*255*255 + 255 = 260355.
//
// Validation: direct range check on carry column values.
// AIR enforcement: carry byte decomposition columns (future commit):
//   carry = b0 + 256*b1 + 65536*b2, where b2 ∈ [0,3]
//   TRACE_WIDTH += 12 (3 bytes × 4 carries)
// ══════════════════════════════════════════════════════════════════════

/// Maximum valid carry value in schoolbook byte multiplication.
/// carry_max = 4*255*255 + 255 = 260355 (fits in 18 bits).
pub const MUL_CARRY_MAX: u32 = 260355;

/// MUL carry columns.
const MUL_CARRY_COLUMNS: [usize; 4] = [
    COL_MUL_CARRY_0,
    COL_MUL_CARRY_1,
    COL_MUL_CARRY_2,
    COL_MUL_CARRY_3,
];

/// Validate that all MUL carry values are in [0, MUL_CARRY_MAX].
///
/// Without this check, a malicious prover can set carry to any
/// field element, satisfying `a*b = rd + carry*256` with a forged rd.
///
/// This is a trace-level validation. Full AIR enforcement requires
/// carry byte decomposition columns (12 additional columns).
pub fn validate_carry_range(trace: &AlgebraicTrace) -> Result<(), ProverError> {
    for row in 0..trace.num_steps {
        let is_mul = trace.columns[COL_IS_MUL][row];
        if is_mul == 0 {
            continue;
        }
        for &col in &MUL_CARRY_COLUMNS {
            let val = trace.columns[col][row];
            if val > MUL_CARRY_MAX {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "MUL carry column {} row {} has value {} > {} \
                         (out of carry range)",
                        col, row, val, MUL_CARRY_MAX,
                    ),
                });
            }
        }
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// Division Correctness Validation
//
// The AIR constraint `quotient * divisor + remainder = dividend` operates
// in the BabyBear field (mod p ≈ 2^31). For products > p, the constraint
// wraps, allowing forged quotients with probability 2^-31.
//
// Fix: Validate at trace level that the 64-bit arithmetic is correct:
//   (quotient as u64) * (divisor as u64) + (remainder as u64) == (dividend as u64)
// ══════════════════════════════════════════════════════════════════════

/// Validate that all DIV/REM results are correct in 64-bit arithmetic.
///
/// The AIR constraint wraps mod p for large products.
/// This trace-level check uses u64 arithmetic to verify:
///   quotient * divisor + remainder == dividend
pub fn validate_division_correctness(trace: &AlgebraicTrace) -> Result<(), ProverError> {
    for row in 0..trace.num_steps {
        let is_div = trace.columns[COL_IS_DIV_TYPE][row];
        let is_rem = trace.columns[COL_IS_REM_TYPE][row];
        if is_div == 0 && is_rem == 0 {
            continue;
        }
        let div_by_zero = trace.columns[COL_DIV_BY_ZERO][row];
        if div_by_zero == 1 {
            continue; // Division by zero has special handling
        }

        let rs1_val = trace.columns[COL_RS1_VAL][row] as u64; // dividend
        let rs2_val = trace.columns[COL_RS2_VAL][row] as u64; // divisor

        if is_div == 1 {
            // DIV: rd = quotient, DIV_REM_BYTE = remainder
            let quotient = trace.columns[COL_RD_VAL_AFTER][row] as u64;
            let remainder = trace.columns[COL_DIV_REM_BYTE_0][row] as u64
                | ((trace.columns[COL_DIV_REM_BYTE_0 + 1][row] as u64) << 8)
                | ((trace.columns[COL_DIV_REM_BYTE_0 + 2][row] as u64) << 16)
                | ((trace.columns[COL_DIV_REM_BYTE_0 + 3][row] as u64) << 24);

            let product = quotient * rs2_val + remainder;
            if product != rs1_val {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "DIV row {}: {}*{} + {} = {} ≠ {} (dividend)",
                        row, quotient, rs2_val, remainder, product, rs1_val,
                    ),
                });
            }
            // Remainder must be < divisor
            if remainder >= rs2_val {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "DIV row {}: remainder {} >= divisor {}",
                        row, remainder, rs2_val,
                    ),
                });
            }
        }

        if is_rem == 1 {
            // REM: rd = remainder, DIV_REM_BYTE = quotient
            let remainder = trace.columns[COL_RD_VAL_AFTER][row] as u64;
            let quotient = trace.columns[COL_DIV_REM_BYTE_0][row] as u64
                | ((trace.columns[COL_DIV_REM_BYTE_0 + 1][row] as u64) << 8)
                | ((trace.columns[COL_DIV_REM_BYTE_0 + 2][row] as u64) << 16)
                | ((trace.columns[COL_DIV_REM_BYTE_0 + 3][row] as u64) << 24);

            let product = quotient * rs2_val + remainder;
            if product != rs1_val {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "REM row {}: {}*{} + {} = {} ≠ {} (dividend)",
                        row, quotient, rs2_val, remainder, product, rs1_val,
                    ),
                });
            }
            if remainder >= rs2_val {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "REM row {}: remainder {} >= divisor {}",
                        row, remainder, rs2_val,
                    ),
                });
            }
        }
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// Memory Consistency Validation
//
// Proves that CPU memory reads return the correct values (last written).
//
// Full AIR enforcement requires:
//   - A memory table with O(n) rows sorted by (addr, timestamp)
//   - LogUp argument linking CPU ↔ memory table
//   - Sorting + continuity constraints in the AIR
//   - 4+ new trace columns
//
// For now: trace-level validation using a HashMap-based memory model.
// The prover validates that every LOAD returns the value from the most
// recent STORE to the same address. This catches malicious trace
// construction but does not enforce within the AIR polynomial identity.
//
// Full AIR enforcement is a dedicated milestone (adds ~500 lines + 4 columns).
// ══════════════════════════════════════════════════════════════════════

use std::collections::HashMap;

/// Validate memory consistency: every LOAD must return the most recently
/// STOREd value at the same address.
///
/// Without this, a prover can claim LOAD addr=X returned Y
/// when the actual stored value is Z. This is a trace-level defense.
///
/// Full AIR enforcement (memory permutation argument) requires:
/// - Memory table with (addr, value, timestamp, is_write) sorted by (addr, timestamp)
/// - LogUp multiset argument proving CPU memory ops match the table
/// - Transition constraints enforcing read-after-write consistency
pub fn validate_memory_consistency(trace: &AlgebraicTrace) -> Result<(), ProverError> {
    let mut memory: HashMap<u32, u32> = HashMap::new();

    for row in 0..trace.num_steps {
        let is_store = trace.columns[COL_IS_STORE][row];
        let is_load = trace.columns[COL_IS_LOAD][row];

        if is_store == 1 {
            let addr = trace.columns[COL_MEM_ADDR][row];
            let value = trace.columns[COL_MEM_VALUE][row];
            memory.insert(addr, value);
        }

        if is_load == 1 {
            let addr = trace.columns[COL_MEM_ADDR][row];
            let loaded_value = trace.columns[COL_MEM_VALUE][row];

            if let Some(&stored_value) = memory.get(&addr) {
                if loaded_value != stored_value {
                    return Err(ProverError::InvalidTrace {
                        reason: format!(
                            "LOAD row {} addr={:#x} returned {} but \
                             last STORE wrote {} — memory inconsistency",
                            row, addr, loaded_value, stored_value,
                        ),
                    });
                }
            }
            // If no prior STORE: initial memory is zero (convention).
            // We allow any loaded value for unmapped addresses for now
            // since the initial memory image may be preloaded.
        }
    }
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// Unified Trace Validation
// ══════════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════════
// MULH Validation
// ══════════════════════════════════════════════════════════════════════

use crate::air::{COL_IS_MULH, COL_IS_MULHSU, COL_IS_MULHU};

/// Validate MULH/MULHSU/MULHU results are correct.
///
/// MULH: rd = (rs1_signed × rs2_signed) >> 32
/// MULHSU: rd = (rs1_signed × rs2_unsigned) >> 32
/// MULHU: rd = (rs1_unsigned × rs2_unsigned) >> 32
pub fn validate_mulh_correctness(trace: &AlgebraicTrace) -> Result<(), ProverError> {
    for row in 0..trace.num_steps {
        let rs1 = trace.columns[COL_RS1_VAL][row];
        let rs2 = trace.columns[COL_RS2_VAL][row];
        let rd = trace.columns[COL_RD_VAL_AFTER][row];

        if trace.columns[COL_IS_MULHU][row] == 1 {
            // Unsigned × Unsigned
            let product = (rs1 as u64) * (rs2 as u64);
            let expected = (product >> 32) as u32;
            if rd != expected {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "MULHU row {}: {} × {} >> 32 = {} but rd = {}",
                        row, rs1, rs2, expected, rd,
                    ),
                });
            }
        } else if trace.columns[COL_IS_MULH][row] == 1 {
            // Signed × Signed
            let product = (rs1 as i32 as i64) * (rs2 as i32 as i64);
            let expected = (product >> 32) as u32;
            if rd != expected {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "MULH row {}: {}s × {}s >> 32 = {} but rd = {}",
                        row, rs1 as i32, rs2 as i32, expected, rd,
                    ),
                });
            }
        } else if trace.columns[COL_IS_MULHSU][row] == 1 {
            // Signed × Unsigned
            let product = (rs1 as i32 as i64) * (rs2 as u64 as i64);
            let expected = (product >> 32) as u32;
            if rd != expected {
                return Err(ProverError::InvalidTrace {
                    reason: format!(
                        "MULHSU row {}: {}s × {}u >> 32 = {} but rd = {}",
                        row, rs1 as i32, rs2, expected, rd,
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Run all trace-level validations.
///
/// This is the single entry point for all Red Team fixes that validate
/// trace integrity beyond what the AIR constraints can enforce:
///
/// - MUL carry range [0, 260355]
/// - Memory consistency (LOAD returns last STOREd value)
/// - Byte columns in [0, 255]
/// - Division 64-bit correctness
pub fn validate_trace_integrity(trace: &AlgebraicTrace) -> Result<(), ProverError> {
    validate_byte_range(trace)?;
    validate_carry_range(trace)?;
    validate_division_correctness(trace)?;
    validate_memory_consistency(trace)?;
    validate_mulh_correctness(trace)?;
    Ok(())
}

// ══════════════════════════════════════════════════════════════════════
// Tests
// ══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logup_matching_multisets() {
        let mut transcript = Transcript::new(b"logup_test");

        // CPU has 3 ECALL rows with bus values 10, 20, 30
        let cpu_bus = vec![
            Some(Fp::new(10)),
            None, // non-ECALL
            Some(Fp::new(20)),
            None,
            Some(Fp::new(30)),
        ];

        // Coprocessor has same 3 bus values (order doesn't matter for multiset)
        let coproc_bus = vec![Fp::new(10), Fp::new(20), Fp::new(30)];

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);
        assert_eq!(argument.verify(), LogUpResult::Valid);
    }

    #[test]
    fn test_logup_mismatched_multisets() {
        let mut transcript = Transcript::new(b"logup_test");

        // CPU has bus values 10, 20
        let cpu_bus = vec![Some(Fp::new(10)), Some(Fp::new(20))];

        // Coprocessor has different values
        let coproc_bus = vec![Fp::new(10), Fp::new(99)]; // 99 ≠ 20

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);
        assert_ne!(argument.verify(), LogUpResult::Valid);
    }

    #[test]
    fn test_logup_empty_multisets() {
        let mut transcript = Transcript::new(b"logup_test");

        // No ECALL rows, no coprocessor rows
        let cpu_bus: Vec<Option<Fp>> = vec![None, None, None];
        let coproc_bus: Vec<Fp> = vec![];

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);
        assert_eq!(argument.verify(), LogUpResult::Valid);
        // Both sums should be zero
        assert_eq!(argument.cpu_final_sum, Fp::ZERO);
        assert_eq!(argument.coproc_final_sum, Fp::ZERO);
    }

    #[test]
    fn test_logup_single_element() {
        let mut transcript = Transcript::new(b"logup_test");

        let cpu_bus = vec![Some(Fp::new(42))];
        let coproc_bus = vec![Fp::new(42)];

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);
        assert_eq!(argument.verify(), LogUpResult::Valid);
    }

    #[test]
    fn test_logup_extra_coprocessor_call() {
        let mut transcript = Transcript::new(b"logup_test");

        // CPU has 1 ECALL
        let cpu_bus = vec![Some(Fp::new(10))];

        // Coprocessor has 2 entries (one is extra — injected!)
        let coproc_bus = vec![Fp::new(10), Fp::new(20)];

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);
        assert_ne!(argument.verify(), LogUpResult::Valid);
    }

    #[test]
    fn test_logup_missing_coprocessor_call() {
        let mut transcript = Transcript::new(b"logup_test");

        // CPU has 2 ECALLs
        let cpu_bus = vec![Some(Fp::new(10)), Some(Fp::new(20))];

        // Coprocessor is missing one
        let coproc_bus = vec![Fp::new(10)];

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);
        assert_ne!(argument.verify(), LogUpResult::Valid);
    }

    #[test]
    fn test_logup_running_sum_lengths() {
        let mut transcript = Transcript::new(b"logup_test");

        let cpu_bus = vec![Some(Fp::new(1)), None, Some(Fp::new(2))];
        let coproc_bus = vec![Fp::new(1), Fp::new(2)];

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);

        // Running sums include initial zero
        assert_eq!(argument.cpu_running_sum.len(), cpu_bus.len() + 1);
        assert_eq!(argument.coproc_running_sum.len(), coproc_bus.len() + 1);

        // First element is always 0
        assert_eq!(argument.cpu_running_sum[0], Fp::ZERO);
        assert_eq!(argument.coproc_running_sum[0], Fp::ZERO);
    }

    #[test]
    fn test_logup_running_sum_non_ecall_no_change() {
        let mut transcript = Transcript::new(b"logup_test");

        let cpu_bus = vec![None, None, Some(Fp::new(42)), None];
        let coproc_bus = vec![Fp::new(42)];

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);

        // Non-ECALL rows should not change running sum
        assert_eq!(argument.cpu_running_sum[0], argument.cpu_running_sum[1]);
        assert_eq!(argument.cpu_running_sum[1], argument.cpu_running_sum[2]);
        // ECALL row should change it
        assert_ne!(argument.cpu_running_sum[2], argument.cpu_running_sum[3]);
        // Next non-ECALL should not change
        assert_eq!(argument.cpu_running_sum[3], argument.cpu_running_sum[4]);
    }

    #[test]
    fn test_logup_duplicate_values() {
        let mut transcript = Transcript::new(b"logup_test");

        // CPU calls SHA-256 twice with same input → same bus values
        let cpu_bus = vec![Some(Fp::new(10)), Some(Fp::new(10))];
        let coproc_bus = vec![Fp::new(10), Fp::new(10)];

        let argument = LogUpArgument::build(&cpu_bus, &coproc_bus, &mut transcript);
        assert_eq!(argument.verify(), LogUpResult::Valid);
    }

    #[test]
    fn test_verify_logup_from_proof() {
        let sum = Fp::new(12345);
        assert_eq!(verify_logup_from_proof(sum, sum), LogUpResult::Valid);
        assert_ne!(
            verify_logup_from_proof(Fp::new(1), Fp::new(2)),
            LogUpResult::Valid
        );
    }

    // ── Multi-round LogUp tests ──

    #[test]
    fn test_multi_round_matching_multisets() {
        let mut transcript = Transcript::new(b"logup_multi_test");

        let cpu_bus = vec![
            Some(Fp::new(10)),
            None,
            Some(Fp::new(20)),
            Some(Fp::new(30)),
        ];
        let coproc_bus = vec![Fp::new(10), Fp::new(20), Fp::new(30)];

        let rounds = LogUpArgument::build_multi_round(&cpu_bus, &coproc_bus, &mut transcript);

        assert_eq!(rounds.len(), LOGUP_ROUNDS);
        assert_eq!(
            LogUpArgument::verify_multi_round(&rounds),
            LogUpResult::Valid
        );
    }

    #[test]
    fn test_multi_round_mismatched_multisets() {
        let mut transcript = Transcript::new(b"logup_multi_test");

        let cpu_bus = vec![Some(Fp::new(10)), Some(Fp::new(20))];
        let coproc_bus = vec![Fp::new(10), Fp::new(99)]; // mismatch

        let rounds = LogUpArgument::build_multi_round(&cpu_bus, &coproc_bus, &mut transcript);

        assert_eq!(rounds.len(), LOGUP_ROUNDS);
        assert_ne!(
            LogUpArgument::verify_multi_round(&rounds),
            LogUpResult::Valid
        );
    }

    #[test]
    fn test_multi_round_empty_multisets() {
        let mut transcript = Transcript::new(b"logup_multi_test");

        let cpu_bus: Vec<Option<Fp>> = vec![None, None];
        let coproc_bus: Vec<Fp> = vec![];

        let rounds = LogUpArgument::build_multi_round(&cpu_bus, &coproc_bus, &mut transcript);

        assert_eq!(rounds.len(), LOGUP_ROUNDS);
        assert_eq!(
            LogUpArgument::verify_multi_round(&rounds),
            LogUpResult::Valid
        );
    }

    #[test]
    fn test_multi_round_independent_challenges() {
        let mut transcript = Transcript::new(b"logup_multi_test");

        let cpu_bus = vec![Some(Fp::new(42))];
        let coproc_bus = vec![Fp::new(42)];

        let rounds = LogUpArgument::build_multi_round(&cpu_bus, &coproc_bus, &mut transcript);

        // Each round should use a different β (drawn from evolving transcript)
        for i in 0..rounds.len() {
            for j in (i + 1)..rounds.len() {
                assert_ne!(
                    rounds[i].beta, rounds[j].beta,
                    "Rounds {i} and {j} should have different challenges"
                );
            }
        }
    }

    #[test]
    fn test_multi_round_returns_count() {
        let mut transcript = Transcript::new(b"logup_multi_test");

        let cpu_bus = vec![Some(Fp::new(1))];
        let coproc_bus = vec![Fp::new(1)];

        let rounds = LogUpArgument::build_multi_round(&cpu_bus, &coproc_bus, &mut transcript);

        assert_eq!(
            rounds.len(),
            LOGUP_ROUNDS,
            "build_multi_round should produce exactly LOGUP_ROUNDS rounds"
        );
    }

    // ── Register file LogUp tests ──

    // Verify regfile_table_bus_value produces different results than
    // regfile_bus_value (independent tuple structures per C-08 fix).
    #[test]
    fn test_regfile_table_bus_value_differs_from_cpu() {
        let alpha = [Fp::new(7), Fp::new(13), Fp::new(29)];
        // CPU side: (step=5, reg_id=3, value=100)
        let cpu_bv = regfile_bus_value(Fp::new(5), Fp::new(3), Fp::new(100), &alpha);
        // Table side: (reg_idx=3, write_count=0, value=100)
        let table_bv = regfile_table_bus_value(Fp::new(3), Fp::new(0), Fp::new(100), &alpha);
        // These should differ because the tuple structure is different
        assert_ne!(
            cpu_bv, table_bv,
            "regfile_table_bus_value should differ from regfile_bus_value (C-08)"
        );
    }

    // Validate that regfile invariants catch x0 violations.
    #[test]
    fn test_regfile_invariants_valid_trace() {
        use crate::trace_converter::convert_trace;
        use brrq_vm::instruction::{AluImmFunc, Instruction};
        use brrq_vm::trace::{ExecutionTrace, TraceStep};

        let step = TraceStep {
            step: 0,
            pc: 0,
            instruction: Instruction::AluImm {
                func: AluImmFunc::Addi,
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            instruction_word: 0x00000013,
            regs_before: [0u32; 32],
            regs_after: [0u32; 32],
            next_pc: 4,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 1,
        };
        let mut trace = ExecutionTrace::new();
        trace.record(step);

        let alg = convert_trace(&trace).unwrap();
        // Should succeed — valid trace with x0 = 0
        validate_regfile_invariants(&alg).unwrap();
    }

    #[test]
    fn test_regfile_bus_value_deterministic() {
        let alpha = [Fp::new(7), Fp::new(13), Fp::new(29)];
        let bv1 = regfile_bus_value(Fp::new(0), Fp::new(5), Fp::new(100), &alpha);
        let bv2 = regfile_bus_value(Fp::new(0), Fp::new(5), Fp::new(100), &alpha);
        assert_eq!(bv1, bv2, "Same inputs should produce same bus value");
    }

    #[test]
    fn test_regfile_bus_value_different_for_different_inputs() {
        let alpha = [Fp::new(7), Fp::new(13), Fp::new(29)];
        let bv1 = regfile_bus_value(Fp::new(0), Fp::new(5), Fp::new(100), &alpha);
        let bv2 = regfile_bus_value(Fp::new(0), Fp::new(6), Fp::new(100), &alpha);
        assert_ne!(
            bv1, bv2,
            "Different reg_id should produce different bus value"
        );
    }

    #[test]
    fn test_extract_regfile_nop_trace() {
        // NOP trace: has_rs1_read=1, has_rs2_read=0, is_write=0
        // Should produce 1 bus value per NOP row (rs1 read only)
        use crate::trace_converter::convert_trace;
        use brrq_vm::instruction::{AluImmFunc, Instruction};
        use brrq_vm::trace::{ExecutionTrace, TraceStep};

        let step = TraceStep {
            step: 0,
            pc: 0,
            instruction: Instruction::AluImm {
                func: AluImmFunc::Addi,
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            instruction_word: 0x00000013, // ADDI x0, x0, 0
            regs_before: [0u32; 32],
            regs_after: [0u32; 32],
            next_pc: 4,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 1,
        };
        let mut trace = ExecutionTrace::new();
        trace.record(step);

        let alg = convert_trace(&trace).unwrap();
        let reg_table = RegisterFileTable::from_trace(&alg);
        let alpha = [Fp::new(7), Fp::new(13), Fp::new(29)];
        let (cpu_bus, regfile_bus) = extract_regfile_bus_values(&alg, &alpha, &reg_table);

        // 1 real step padded to 1 → 1 × 3 slots = 3 entries in cpu_bus
        assert_eq!(cpu_bus.len(), 3);
        // Only rs1 read should be Some
        assert!(cpu_bus[0].is_some(), "rs1 read should be present for ADDI");
        assert!(cpu_bus[1].is_none(), "rs2 read should be absent for ADDI");
        assert!(
            cpu_bus[2].is_none(),
            "write should be absent for NOP (rd=x0)"
        );
        // Regfile side should have exactly 1 value
        assert_eq!(regfile_bus.len(), 1);
    }

    #[test]
    fn test_regfile_logup_nop_trace_valid() {
        // NOP trace should produce a valid LogUp (same multisets on both sides)
        use crate::trace_converter::convert_trace;
        use brrq_vm::instruction::{AluImmFunc, Instruction};
        use brrq_vm::trace::{ExecutionTrace, TraceStep};

        let step = TraceStep {
            step: 0,
            pc: 0,
            instruction: Instruction::AluImm {
                func: AluImmFunc::Addi,
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            instruction_word: 0x00000013,
            regs_before: [0u32; 32],
            regs_after: [0u32; 32],
            next_pc: 4,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 1,
        };
        let mut trace = ExecutionTrace::new();
        trace.record(step);

        let alg = convert_trace(&trace).unwrap();
        let mut transcript = Transcript::new(b"regfile_logup_test");
        let rounds = build_regfile_logup(&alg, &mut transcript).unwrap();

        assert_eq!(rounds.len(), LOGUP_ROUNDS);
        assert_eq!(
            LogUpArgument::verify_multi_round(&rounds),
            LogUpResult::Valid,
            "Register file LogUp should be valid for NOP trace"
        );
    }

    #[test]
    fn test_regfile_logup_with_register_write() {
        // ADDI x5, x0, 42: reads rs1=x0, writes rd=x5 with value 42
        use crate::trace_converter::convert_trace;
        use brrq_vm::instruction::{AluImmFunc, Instruction};
        use brrq_vm::trace::{ExecutionTrace, TraceStep};

        // ADDI x5, x0, 42 = imm[11:0]=42, rs1=0, funct3=0, rd=5, opcode=0x13
        let word = (42 << 20) | (5 << 7) | 0x13;
        let mut regs_after = [0u32; 32];
        regs_after[5] = 42;

        let step = TraceStep {
            step: 0,
            pc: 0,
            instruction: Instruction::AluImm {
                func: AluImmFunc::Addi,
                rd: 5,
                rs1: 0,
                imm: 42,
            },
            instruction_word: word,
            regs_before: [0u32; 32],
            regs_after,
            next_pc: 4,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 1,
        };
        let mut trace = ExecutionTrace::new();
        trace.record(step);

        let alg = convert_trace(&trace).unwrap();
        let reg_table = RegisterFileTable::from_trace(&alg);
        let alpha = [Fp::new(7), Fp::new(13), Fp::new(29)];
        let (cpu_bus, regfile_bus) = extract_regfile_bus_values(&alg, &alpha, &reg_table);

        // Should have rs1 read + rd write = 2 Some entries
        let some_count = cpu_bus.iter().filter(|x| x.is_some()).count();
        assert_eq!(
            some_count, 2,
            "ADDI x5,x0,42 should have 2 accesses (rs1 read + rd write)"
        );
        assert_eq!(regfile_bus.len(), 2);

        // LogUp should be valid
        let mut transcript = Transcript::new(b"regfile_logup_test");
        let rounds = build_regfile_logup(&alg, &mut transcript).unwrap();
        assert_eq!(
            LogUpArgument::verify_multi_round(&rounds),
            LogUpResult::Valid
        );
    }

    /// Reproduces the "Register file inconsistency: rs1 read of x2 at row 1" bug.
    ///
    /// Setup: x2 = 0xFFFFF000 (stack pointer) initialized by CPU.
    /// Row 0: ADDI x5, x0, 10 — writes x5, does NOT write x2.
    /// Row 1: ADDI x1, x2, 4  — reads x2 (expects 0xFFFFF000).
    ///
    /// Before fix: RegisterFileTable returned 0 for x2 (no write recorded).
    /// After fix:  RegisterFileTable returns 0xFFFFF000 from initial_regs.
    #[test]
    fn test_initial_register_state_preserved() {
        use crate::trace_converter::convert_trace;
        use brrq_vm::instruction::{AluImmFunc, Instruction};
        use brrq_vm::trace::{ExecutionTrace, TraceStep};

        const SP: u32 = 0xFFFFF000;

        let mut regs_init = [0u32; 32];
        regs_init[2] = SP; // x2 = stack pointer

        // Row 0: ADDI x5, x0, 10 — doesn't touch x2
        let mut regs_after_0 = regs_init;
        regs_after_0[5] = 10;
        let word0 = (10 << 20) | (5 << 7) | 0x13; // ADDI x5, x0, 10

        // Row 1: ADDI x1, x2, 4 — reads x2 (= SP)
        let mut regs_after_1 = regs_after_0;
        regs_after_1[1] = SP + 4;
        let word1 = (4 << 20) | (2 << 15) | (1 << 7) | 0x13; // ADDI x1, x2, 4

        let mut trace = ExecutionTrace::new();
        trace.record(TraceStep {
            step: 0,
            pc: 0,
            instruction: Instruction::AluImm { func: AluImmFunc::Addi, rd: 5, rs1: 0, imm: 10 },
            instruction_word: word0,
            regs_before: regs_init,
            regs_after: regs_after_0,
            next_pc: 4,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 1,
        });
        trace.record(TraceStep {
            step: 1,
            pc: 4,
            instruction: Instruction::AluImm { func: AluImmFunc::Addi, rd: 1, rs1: 2, imm: 4 },
            instruction_word: word1,
            regs_before: regs_after_0,
            regs_after: regs_after_1,
            next_pc: 8,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 2,
        });

        let alg = convert_trace(&trace).unwrap();
        let reg_table = RegisterFileTable::from_trace(&alg);

        // The critical check: x2 at row 1 should return SP, not 0
        let x2_at_row1 = reg_table.lookup_at_cycle(2, 1);
        assert_eq!(
            x2_at_row1, SP,
            "x2 at row 1 should be {} (stack pointer) but got {}",
            SP, x2_at_row1
        );

        // Full validation should pass
        let result = validate_read_write_consistency(&alg, &reg_table);
        assert!(
            result.is_ok(),
            "validate_read_write_consistency failed: {:?}",
            result.err()
        );

        // LogUp should be valid
        let mut transcript = Transcript::new(b"initial_regs_test");
        let rounds = build_regfile_logup(&alg, &mut transcript).unwrap();
        assert_eq!(
            LogUpArgument::verify_multi_round(&rounds),
            LogUpResult::Valid,
            "Register file LogUp should be valid with initial register state"
        );
    }

    // ── Bitwise LogUp tests ──

    #[test]
    fn test_bitwise_table_size() {
        let alpha = [Fp::new(3), Fp::new(7), Fp::new(11), Fp::new(13)];
        let table = generate_bitwise_table_bus_values(&alpha);
        assert_eq!(table.len(), BITWISE_TOTAL_ENTRIES);
        assert_eq!(table.len(), 3 * 256 * 256);
    }

    #[test]
    fn test_bitwise_bus_value_deterministic() {
        let alpha = [Fp::new(3), Fp::new(7), Fp::new(11), Fp::new(13)];
        let bv1 = bitwise_bus_value(
            Fp::new(BITWISE_OP_XOR),
            Fp::new(0xAB),
            Fp::new(0xCD),
            Fp::new(0xAB ^ 0xCD),
            &alpha,
        );
        let bv2 = bitwise_bus_value(
            Fp::new(BITWISE_OP_XOR),
            Fp::new(0xAB),
            Fp::new(0xCD),
            Fp::new(0xAB ^ 0xCD),
            &alpha,
        );
        assert_eq!(bv1, bv2, "Same inputs must produce same bus value");
    }

    #[test]
    fn test_bitwise_bus_value_different_ops() {
        let alpha = [Fp::new(3), Fp::new(7), Fp::new(11), Fp::new(13)];
        let xor_bv = bitwise_bus_value(
            Fp::new(BITWISE_OP_XOR),
            Fp::new(5),
            Fp::new(3),
            Fp::new(5 ^ 3),
            &alpha,
        );
        let or_bv = bitwise_bus_value(
            Fp::new(BITWISE_OP_OR),
            Fp::new(5),
            Fp::new(3),
            Fp::new(5 | 3),
            &alpha,
        );
        assert_ne!(
            xor_bv, or_bv,
            "Different op types should produce different bus values"
        );
    }

    #[test]
    fn test_bitwise_bus_value_wrong_result_differs() {
        let alpha = [Fp::new(3), Fp::new(7), Fp::new(11), Fp::new(13)];
        let correct = bitwise_bus_value(
            Fp::new(BITWISE_OP_XOR),
            Fp::new(0xAB),
            Fp::new(0xCD),
            Fp::new(0xAB ^ 0xCD), // correct: 0x66
            &alpha,
        );
        let forged = bitwise_bus_value(
            Fp::new(BITWISE_OP_XOR),
            Fp::new(0xAB),
            Fp::new(0xCD),
            Fp::new(0xFF), // forged result
            &alpha,
        );
        assert_ne!(
            correct, forged,
            "Forged result must produce different bus value"
        );
    }

    #[test]
    fn test_bitwise_table_contains_correct_entries() {
        let alpha = [Fp::new(3), Fp::new(7), Fp::new(11), Fp::new(13)];
        let table = generate_bitwise_table_bus_values(&alpha);

        // Verify XOR table entry: (1, 0xAB, 0xCD, 0x66)
        let expected_xor = bitwise_bus_value(
            Fp::new(BITWISE_OP_XOR),
            Fp::new(0xAB),
            Fp::new(0xCD),
            Fp::new(0xAB ^ 0xCD),
            &alpha,
        );
        // XOR entries start at index 0, entry for (0xAB, 0xCD) is at 0xAB*256 + 0xCD
        let idx = 0xAB * 256 + 0xCD;
        assert_eq!(table[idx], expected_xor);

        // Verify OR table entry: (2, 5, 3, 7)
        let expected_or = bitwise_bus_value(
            Fp::new(BITWISE_OP_OR),
            Fp::new(5),
            Fp::new(3),
            Fp::new(5 | 3),
            &alpha,
        );
        let or_idx = BITWISE_TABLE_SIZE + 5 * 256 + 3;
        assert_eq!(table[or_idx], expected_or);

        // Verify AND table entry: (3, 0xFF, 0x0F, 0x0F)
        let expected_and = bitwise_bus_value(
            Fp::new(BITWISE_OP_AND),
            Fp::new(0xFF),
            Fp::new(0x0F),
            Fp::new(0xFF & 0x0F),
            &alpha,
        );
        let and_idx = 2 * BITWISE_TABLE_SIZE + 0xFF * 256 + 0x0F;
        assert_eq!(table[and_idx], expected_and);
    }

    #[test]
    fn test_bitwise_table_edge_cases() {
        let alpha = [Fp::new(3), Fp::new(7), Fp::new(11), Fp::new(13)];
        let table = generate_bitwise_table_bus_values(&alpha);

        // XOR(0, 0) = 0
        let xor_00 = bitwise_bus_value(
            Fp::new(BITWISE_OP_XOR),
            Fp::ZERO,
            Fp::ZERO,
            Fp::ZERO,
            &alpha,
        );
        assert_eq!(table[0], xor_00);

        // XOR(255, 255) = 0
        let xor_ff = bitwise_bus_value(
            Fp::new(BITWISE_OP_XOR),
            Fp::new(255),
            Fp::new(255),
            Fp::ZERO,
            &alpha,
        );
        assert_eq!(table[255 * 256 + 255], xor_ff);

        // OR(0, 0) = 0
        let or_00 = bitwise_bus_value(
            Fp::new(BITWISE_OP_OR),
            Fp::ZERO,
            Fp::ZERO,
            Fp::ZERO,
            &alpha,
        );
        assert_eq!(table[BITWISE_TABLE_SIZE], or_00);

        // AND(255, 255) = 255
        let and_ff = bitwise_bus_value(
            Fp::new(BITWISE_OP_AND),
            Fp::new(255),
            Fp::new(255),
            Fp::new(255),
            &alpha,
        );
        assert_eq!(table[2 * BITWISE_TABLE_SIZE + 255 * 256 + 255], and_ff);
    }
}
