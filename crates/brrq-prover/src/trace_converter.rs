//! Converts zkVM execution traces into algebraic form for STARK proving.
//!
//! The execution trace from the VM has columns for:
//! - PC (program counter)
//! - Registers (x0-x31)
//! - Instruction opcode
//! - Memory address and value
//! - Gas consumed
//! - ECALL selector flag (for coprocessor linking)
//! - next_pc, instruction type selectors, decoded fields, opcode bits
//!
//! ## NOP Padding
//!
//! Traces are padded to the next power-of-2 length with ADDI x0,x0,0 (NOP)
//! rows that satisfy ALL AIR constraints. The prover's polynomial interpolation
//! requires power-of-2 domains, and zero-padding would violate selector_sum=1.

use brrq_crypto::hash::{Hash256, Hasher};
use brrq_crypto::merkle::MerkleTree;
use brrq_vm::decoder::{
    decode_b_immediate, decode_i_immediate, decode_j_immediate, decode_s_immediate,
    decode_u_immediate, opcodes,
};
use brrq_vm::trace::ExecutionTrace;

// Re-export TRACE_WIDTH for backward compatibility (batch.rs uses it).
use crate::air::{
    COL_BRANCH_TAKEN, COL_CMP_BORROW, COL_CMP_DIFF_BYTE_0, COL_DIV_BY_ZERO, COL_DIV_REM_BYTE_0,
    COL_FUNCT3, COL_FUNCT3_BIT_0, COL_FUNCT7_BIT5, COL_GAS, COL_HAS_RS1_READ,
    COL_HAS_RS2_READ, COL_IMM_VALUE, COL_INSTR, COL_IS_ADD, COL_IS_ADDI, COL_IS_ALU_IMM,
    COL_IS_ALU_REG, COL_IS_AND, COL_IS_AUIPC, COL_IS_BITWISE, COL_IS_BRANCH, COL_IS_DIV_TYPE,
    COL_IS_JAL, COL_IS_JAL_LINK, COL_IS_JALR, COL_IS_JALR_LINK, COL_IS_LOAD, COL_IS_LUI,
    COL_IS_M_EXT, COL_IS_MUL, COL_IS_OR, COL_IS_REM_TYPE, COL_IS_SLL, COL_IS_SLT, COL_IS_SLTU,
    COL_IS_SRA, COL_IS_SRL, COL_IS_STORE, COL_IS_SUB, COL_IS_WRITE, COL_IS_XOR, COL_MEM_ADDR,
    COL_MEM_VALUE, COL_MUL_CARRY_0, COL_MUL_CARRY_1, COL_MUL_CARRY_2, COL_NEXT_PC,
    COL_OPCODE_BIT_0, COL_OPCODE_BIT_6, COL_OPCODE_REMAINING, COL_PC, COL_POWER_OF_TWO, COL_RD,
    COL_RD_BYTE_0, COL_RD_VAL_AFTER, COL_REG_BASE, COL_RS1, COL_RS1_BYTE_0, COL_RS1_VAL, COL_RS2,
    COL_RS2_BYTE_0, COL_RS2_VAL, COL_SHIFT_AMOUNT, COL_SHIFT_AUX_BYTE_0, COL_SIGN_RS1,
    COL_SIGN_RS2,
    // Phase 4 columns
    COL_SHAMT_BIT_0, COL_SHAMT_BIT_1, COL_SHAMT_BIT_2, COL_SHAMT_BIT_3, COL_SHAMT_BIT_4,
    COL_POW_PARTIAL_01, COL_POW_PARTIAL_23, COL_POW_PARTIAL_0123,
    COL_MUL_CARRY_3, COL_IS_MULH, COL_IS_MULHSU, COL_IS_MULHU,
    // Phase 5 columns
    COL_OPCODE_UPPER, COL_SIGN_RS1_LOW7, COL_SIGN_RS2_LOW7,
    // Phase 6 columns
    COL_CARRY0_LO, COL_CARRY0_HI, COL_CARRY1_LO, COL_CARRY1_HI,
    COL_CARRY2_LO, COL_CARRY2_HI, COL_CARRY3_LO, COL_CARRY3_HI,
    COL_MULH_BYTE_0, COL_MULH_BYTE_1, COL_MULH_BYTE_2, COL_MULH_BYTE_3,
    COL_MEM_STEP, COL_MEM_PREV_VALUE,
};
pub use crate::air::{COL_IS_ECALL, ECALL_INSTRUCTION_WORD, TRACE_WIDTH};
use crate::error::ProverError;

/// NOP instruction word: ADDI x0, x0, 0 = 0x00000013.
const NOP_INSTRUCTION_WORD: u32 = 0x00000013;

/// Algebraic trace — the execution trace in column-major form.
#[derive(Debug, Clone)]
pub struct AlgebraicTrace {
    /// Column-major trace data. columns[i] has one entry per step.
    pub columns: Vec<Vec<u32>>,
    /// Number of execution steps (including NOP padding).
    pub num_steps: usize,
    /// Number of columns.
    pub width: usize,
}

/// Convert a VM execution trace to algebraic form.
///
/// Produces 98 columns (Phase 1A+1B+2) and pads to power-of-2 with NOP rows.
/// Phase 2 adds 22 columns for bitwise byte decomposition, sub-selectors,
/// and helper values. NOP rows have all Phase 2 columns = 0 (non-bitwise).
pub fn convert_trace(trace: &ExecutionTrace) -> Result<AlgebraicTrace, ProverError> {
    if trace.is_empty() {
        return Err(ProverError::EmptyTrace);
    }

    let real_steps = trace.len();
    let padded_steps = real_steps.next_power_of_two();
    let width = TRACE_WIDTH;
    let mut columns = vec![vec![0u32; padded_steps]; width];

    // ── Fill real execution rows ──

    for (row, step) in trace.steps.iter().enumerate() {
        let word = step.instruction_word;
        let opcode = word & 0x7F;

        // Column 0: PC
        columns[COL_PC][row] = step.pc;

        // Columns 1-32: Registers (before state)
        for (i, &reg) in step.regs_before.iter().enumerate() {
            columns[COL_REG_BASE + i][row] = reg;
        }

        // Column 33: Instruction word
        columns[COL_INSTR][row] = word;

        // Column 34: Memory address (first access, or 0)
        columns[COL_MEM_ADDR][row] = step.memory_accesses.first().map(|a| a.addr).unwrap_or(0);

        // Column 35: Memory value (first access, or 0)
        columns[COL_MEM_VALUE][row] = step.memory_accesses.first().map(|a| a.value).unwrap_or(0);

        // Phase 6: Memory permutation columns
        // mem_step = row index (monotonic counter for memory ordering)
        columns[COL_MEM_STEP][row] = row as u32;
        // mem_prev_value: for loads, this should be the last stored value at this address.
        // Filled as 0 here; the memory consistency LogUp validates correctness.
        // In a full implementation, this requires a sorted-by-address pass.
        columns[COL_MEM_PREV_VALUE][row] = 0;

        // Column 36: Cumulative gas BEFORE this instruction.
        // The AIR boundary constraint B3 requires gas=0 at row 0 (no gas consumed
        // before the first instruction). gas_used is cumulative AFTER, so subtract
        // this instruction's cost to get the pre-state.
        let gas_before = step.gas_used.saturating_sub(step.gas_cost);
        columns[COL_GAS][row] = u32::try_from(gas_before).unwrap_or(u32::MAX);

        // Column 37: ECALL selector (also serves as instruction type selector)
        columns[COL_IS_ECALL][row] = if opcode == opcodes::SYSTEM { 1 } else { 0 };

        // Column 38: next_pc
        columns[COL_NEXT_PC][row] = step.next_pc;

        // Columns 39-47: Instruction type selectors
        columns[COL_IS_BRANCH][row] = if opcode == opcodes::BRANCH { 1 } else { 0 };
        columns[COL_IS_JAL][row] = if opcode == opcodes::JAL { 1 } else { 0 };
        columns[COL_IS_JALR][row] = if opcode == opcodes::JALR { 1 } else { 0 };
        columns[COL_IS_LOAD][row] = if opcode == opcodes::LOAD { 1 } else { 0 };
        columns[COL_IS_STORE][row] = if opcode == opcodes::STORE { 1 } else { 0 };
        // is_alu_imm covers both OP_IMM (0x13) and FENCE (0x0F)
        columns[COL_IS_ALU_IMM][row] = if opcode == opcodes::OP_IMM || opcode == opcodes::FENCE {
            1
        } else {
            0
        };
        columns[COL_IS_LUI][row] = if opcode == opcodes::LUI { 1 } else { 0 };
        columns[COL_IS_AUIPC][row] = if opcode == opcodes::AUIPC { 1 } else { 0 };
        columns[COL_IS_ALU_REG][row] = if opcode == opcodes::OP { 1 } else { 0 };

        // Column 48: rd
        columns[COL_RD][row] = (word >> 7) & 0x1F;

        // Column 49: rs1
        columns[COL_RS1][row] = (word >> 15) & 0x1F;

        // Column 50: rs2
        columns[COL_RS2][row] = (word >> 20) & 0x1F;

        // Column 51: funct3
        columns[COL_FUNCT3][row] = (word >> 12) & 0x7;

        // Column 52: imm_value — format-specific immediate decode
        columns[COL_IMM_VALUE][row] = decode_immediate(word, opcode);

        // Columns 53-59: opcode bit decomposition (COL_OPCODE_BIT_0..=COL_OPCODE_BIT_6)
        for bit_col in COL_OPCODE_BIT_0..=COL_OPCODE_BIT_6 {
            let bit = bit_col - COL_OPCODE_BIT_0;
            columns[bit_col][row] = (opcode >> bit) & 1;
        }

        // Column 60: opcode_remaining = (instruction_word - opcode_7bit) / 128
        columns[COL_OPCODE_REMAINING][row] = (word - opcode) / 128;

        // Column 135: opcode_upper = (opcode_remaining - rd) / 32
        let opcode_remaining = (word - opcode) / 128;
        let rd_field = (word >> 7) & 0x1F;
        columns[COL_OPCODE_UPPER][row] = (opcode_remaining - rd_field) / 32;

        // ── Phase 1B columns (61-75) ──

        let rd_idx = (word >> 7) & 0x1F;
        let rs1_idx = (word >> 15) & 0x1F;
        let rs2_idx = (word >> 20) & 0x1F;
        let funct3 = (word >> 12) & 0x7;
        let funct7_bit5 = (word >> 30) & 1;

        // Column 61: rs1_val — regs_before[rs1]
        columns[COL_RS1_VAL][row] = step.regs_before[rs1_idx as usize];

        // Column 62: rs2_val — regs_before[rs2]
        columns[COL_RS2_VAL][row] = step.regs_before[rs2_idx as usize];

        // Column 63: rd_val_after — regs_after[rd]
        columns[COL_RD_VAL_AFTER][row] = step.regs_after[rd_idx as usize];

        // Column 64: is_write — 1 if instruction writes to rd
        // All except branch, store, ecall/system, fence (when rd=0).
        // For FENCE: rd is always 0 (encoding constraint), write suppressed.
        let is_write = match opcode {
            opcodes::BRANCH | opcodes::STORE | opcodes::SYSTEM | opcodes::FENCE => 0,
            _ => {
                if rd_idx != 0 {
                    1
                } else {
                    0
                }
            }
        };
        columns[COL_IS_WRITE][row] = is_write;

        // Column 65: funct7_bit5
        columns[COL_FUNCT7_BIT5][row] = funct7_bit5;

        // Columns 66-68: funct3 bit decomposition
        columns[COL_FUNCT3_BIT_0][row] = funct3 & 1;
        columns[COL_FUNCT3_BIT_0 + 1][row] = (funct3 >> 1) & 1;
        columns[COL_FUNCT3_BIT_0 + 2][row] = (funct3 >> 2) & 1;

        // Column 69: is_addi — is_alu_imm AND funct3=0
        let is_alu_imm = opcode == opcodes::OP_IMM || opcode == opcodes::FENCE;
        columns[COL_IS_ADDI][row] = if is_alu_imm && funct3 == 0 { 1 } else { 0 };

        // Column 70: is_add — is_alu_reg AND funct3=0 AND funct7_bit5=0
        let is_alu_reg = opcode == opcodes::OP;
        columns[COL_IS_ADD][row] = if is_alu_reg && funct3 == 0 && funct7_bit5 == 0 {
            1
        } else {
            0
        };

        // Column 71: is_sub — is_alu_reg AND funct3=0 AND funct7_bit5=1
        columns[COL_IS_SUB][row] = if is_alu_reg && funct3 == 0 && funct7_bit5 == 1 {
            1
        } else {
            0
        };

        // Column 72: is_jal_link — is_jal (JAL writes PC+4 to rd)
        columns[COL_IS_JAL_LINK][row] = if opcode == opcodes::JAL && rd_idx != 0 {
            1
        } else {
            0
        };

        // Column 73: is_jalr_link — is_jalr (JALR writes PC+4 to rd)
        columns[COL_IS_JALR_LINK][row] = if opcode == opcodes::JALR && rd_idx != 0 {
            1
        } else {
            0
        };

        // Column 74: has_rs1_read — instruction reads rs1
        // I-type (JALR, LOAD, OP_IMM), R-type (OP), branch, store all read rs1.
        let has_rs1 = matches!(
            opcode,
            opcodes::JALR
                | opcodes::LOAD
                | opcodes::OP_IMM
                | opcodes::OP
                | opcodes::BRANCH
                | opcodes::STORE
        );
        columns[COL_HAS_RS1_READ][row] = if has_rs1 { 1 } else { 0 };

        // Column 75: has_rs2_read — instruction reads rs2
        // R-type (OP), branch, store read rs2.
        let has_rs2 = matches!(opcode, opcodes::OP | opcodes::BRANCH | opcodes::STORE);
        columns[COL_HAS_RS2_READ][row] = if has_rs2 { 1 } else { 0 };

        // ── Phase 2 columns (76-97): bitwise byte decomposition ──

        // Determine if this is a bitwise/shift/compare instruction.
        // These are ALU instructions with specific funct3 values.
        let is_bitwise_op = (is_alu_imm || is_alu_reg) && matches!(funct3, 1..=7);
        // Exclude ADDI (funct3=0) which is already handled, and FENCE
        // which has opcode 0x0F (not a bitwise op despite being alu_imm).
        let is_bitwise_op = is_bitwise_op && opcode != opcodes::FENCE;

        if is_bitwise_op {
            let rs1_val = step.regs_before[rs1_idx as usize];
            let operand2 = if is_alu_reg {
                step.regs_before[rs2_idx as usize]
            } else {
                // I-type: the immediate value (sign-extended)
                decode_immediate(word, opcode)
            };
            let rd_val = step.regs_after[rd_idx as usize];

            // Byte decomposition: val = b0 + b1·256 + b2·65536 + b3·16777216
            columns[COL_RS1_BYTE_0][row] = rs1_val & 0xFF;
            columns[COL_RS1_BYTE_0 + 1][row] = (rs1_val >> 8) & 0xFF;
            columns[COL_RS1_BYTE_0 + 2][row] = (rs1_val >> 16) & 0xFF;
            columns[COL_RS1_BYTE_0 + 3][row] = (rs1_val >> 24) & 0xFF;

            columns[COL_RS2_BYTE_0][row] = operand2 & 0xFF;
            columns[COL_RS2_BYTE_0 + 1][row] = (operand2 >> 8) & 0xFF;
            columns[COL_RS2_BYTE_0 + 2][row] = (operand2 >> 16) & 0xFF;
            columns[COL_RS2_BYTE_0 + 3][row] = (operand2 >> 24) & 0xFF;

            columns[COL_RD_BYTE_0][row] = rd_val & 0xFF;
            columns[COL_RD_BYTE_0 + 1][row] = (rd_val >> 8) & 0xFF;
            columns[COL_RD_BYTE_0 + 2][row] = (rd_val >> 16) & 0xFF;
            columns[COL_RD_BYTE_0 + 3][row] = (rd_val >> 24) & 0xFF;

            // Sub-selectors: exactly one is 1 based on funct3 (and funct7_bit5)
            match funct3 {
                1 => columns[COL_IS_SLL][row] = 1,  // SLL/SLLI
                2 => columns[COL_IS_SLT][row] = 1,  // SLT/SLTI
                3 => columns[COL_IS_SLTU][row] = 1, // SLTU/SLTIU
                4 => columns[COL_IS_XOR][row] = 1,  // XOR/XORI
                5 => {
                    if funct7_bit5 == 0 {
                        columns[COL_IS_SRL][row] = 1; // SRL/SRLI
                    } else {
                        columns[COL_IS_SRA][row] = 1; // SRA/SRAI
                    }
                }
                6 => columns[COL_IS_OR][row] = 1,   // OR/ORI
                7 => columns[COL_IS_AND][row] = 1,  // AND/ANDI
                _ => {}
            }

            // is_bitwise = 1 (aggregate flag)
            columns[COL_IS_BITWISE][row] = 1;

            // shift_amount: lower 5 bits of operand2 (for shift ops)
            columns[COL_SHIFT_AMOUNT][row] = operand2 & 0x1F;
        }
        // For non-bitwise rows, columns 76-97 remain 0 (from vec init).

        // ── Phase 3 columns (98-122): ALU completion ──

        // ── Comparison columns (SLT/SLTU) ──
        if is_bitwise_op && matches!(funct3, 2 | 3) {
            // SLT (funct3=2) or SLTU (funct3=3)
            let rs1_val = step.regs_before[rs1_idx as usize];
            let rs2_or_imm = if is_alu_reg {
                step.regs_before[rs2_idx as usize]
            } else {
                decode_immediate(word, opcode)
            };

            if funct3 == 3 {
                // SLTU: unsigned comparison
                let borrow: u32 = if rs1_val < rs2_or_imm { 1 } else { 0 };
                let diff64 = rs1_val as u64 + (borrow as u64) * (1u64 << 32) - rs2_or_imm as u64;
                let diff = diff64 as u32;
                columns[COL_CMP_BORROW][row] = borrow;
                columns[COL_CMP_DIFF_BYTE_0][row] = diff & 0xFF;
                columns[COL_CMP_DIFF_BYTE_0 + 1][row] = (diff >> 8) & 0xFF;
                columns[COL_CMP_DIFF_BYTE_0 + 2][row] = (diff >> 16) & 0xFF;
                columns[COL_CMP_DIFF_BYTE_0 + 3][row] = (diff >> 24) & 0xFF;
            } else {
                // SLT: signed comparison via sign-flipped unsigned comparison
                // Flip sign bits: rs1_flipped = rs1 XOR 0x80000000
                let rs1_flipped = rs1_val ^ 0x80000000;
                let rs2_flipped = rs2_or_imm ^ 0x80000000;
                let borrow: u32 = if rs1_flipped < rs2_flipped { 1 } else { 0 };
                let diff64 = rs1_flipped as u64 + (borrow as u64) * (1u64 << 32) - rs2_flipped as u64;
                let diff = diff64 as u32;
                columns[COL_CMP_BORROW][row] = borrow;
                columns[COL_CMP_DIFF_BYTE_0][row] = diff & 0xFF;
                columns[COL_CMP_DIFF_BYTE_0 + 1][row] = (diff >> 8) & 0xFF;
                columns[COL_CMP_DIFF_BYTE_0 + 2][row] = (diff >> 16) & 0xFF;
                columns[COL_CMP_DIFF_BYTE_0 + 3][row] = (diff >> 24) & 0xFF;
            }

            // Sign bits (for SLT defense-in-depth)
            columns[COL_SIGN_RS1][row] = (step.regs_before[rs1_idx as usize] >> 31) & 1;
            let rs2_val_for_sign = if is_alu_reg {
                step.regs_before[rs2_idx as usize]
            } else {
                decode_immediate(word, opcode)
            };
            columns[COL_SIGN_RS2][row] = (rs2_val_for_sign >> 31) & 1;

            // sign_low7 = byte_3 & 0x7F (low 7 bits of MSB byte)
            columns[COL_SIGN_RS1_LOW7][row] = columns[COL_RS1_BYTE_0 + 3][row] & 0x7F;
            columns[COL_SIGN_RS2_LOW7][row] = columns[COL_RS2_BYTE_0 + 3][row] & 0x7F;
        }

        // ── Shift auxiliary columns (SLL/SRL/SRA) ──
        if is_bitwise_op && matches!(funct3, 1 | 5) {
            let rs1_val = step.regs_before[rs1_idx as usize];
            let rd_val = step.regs_after[rd_idx as usize];
            let shamt = columns[COL_SHIFT_AMOUNT][row]; // already set in Phase 2
            let power_of_two = 1u32.checked_shl(shamt).unwrap_or(0);
            columns[COL_POWER_OF_TWO][row] = power_of_two;

            // Phase 4: shamt bit decomposition for power_of_two verification
            columns[COL_SHAMT_BIT_0][row] = shamt & 1;
            columns[COL_SHAMT_BIT_1][row] = (shamt >> 1) & 1;
            columns[COL_SHAMT_BIT_2][row] = (shamt >> 2) & 1;
            columns[COL_SHAMT_BIT_3][row] = (shamt >> 3) & 1;
            columns[COL_SHAMT_BIT_4][row] = (shamt >> 4) & 1;

            // Phase 4: intermediate products for power chain
            let f0 = 1 + (shamt & 1);                         // 1 or 2
            let f1 = 1 + ((shamt >> 1) & 1) * 3;              // 1 or 4
            let f2 = 1 + ((shamt >> 2) & 1) * 15;             // 1 or 16
            let f3 = 1 + ((shamt >> 3) & 1) * 255;            // 1 or 256
            columns[COL_POW_PARTIAL_01][row] = f0 * f1;
            columns[COL_POW_PARTIAL_23][row] = f2 * f3;
            columns[COL_POW_PARTIAL_0123][row] = f0 * f1 * f2 * f3;

            if funct3 == 1 {
                // SLL: overflow = (rs1 * 2^shamt - rd) / 2^32
                let full_product = (rs1_val as u64) * (power_of_two as u64);
                let overflow = (full_product >> 32) as u32;
                columns[COL_SHIFT_AUX_BYTE_0][row] = overflow & 0xFF;
                columns[COL_SHIFT_AUX_BYTE_0 + 1][row] = (overflow >> 8) & 0xFF;
                columns[COL_SHIFT_AUX_BYTE_0 + 2][row] = (overflow >> 16) & 0xFF;
                columns[COL_SHIFT_AUX_BYTE_0 + 3][row] = (overflow >> 24) & 0xFF;
            } else {
                // SRL/SRA: remainder = rs1 - rd * 2^shamt
                let remainder = rs1_val.wrapping_sub(rd_val.wrapping_mul(power_of_two));
                columns[COL_SHIFT_AUX_BYTE_0][row] = remainder & 0xFF;
                columns[COL_SHIFT_AUX_BYTE_0 + 1][row] = (remainder >> 8) & 0xFF;
                columns[COL_SHIFT_AUX_BYTE_0 + 2][row] = (remainder >> 16) & 0xFF;
                columns[COL_SHIFT_AUX_BYTE_0 + 3][row] = (remainder >> 24) & 0xFF;
            }
        }

        // ── M-extension columns (MUL/MULH/DIV/REM) ──
        let funct7 = (word >> 25) & 0x7F;
        let is_m_ext = is_alu_reg && funct7 == 0x01;
        if is_m_ext {
            let rs1_val = step.regs_before[rs1_idx as usize];
            let rs2_val = step.regs_before[rs2_idx as usize];
            let rd_val = step.regs_after[rd_idx as usize];

            columns[COL_IS_M_EXT][row] = 1;

            // Also fill byte decomposition for M-ext (shared with bitwise)
            if !is_bitwise_op {
                columns[COL_RS1_BYTE_0][row] = rs1_val & 0xFF;
                columns[COL_RS1_BYTE_0 + 1][row] = (rs1_val >> 8) & 0xFF;
                columns[COL_RS1_BYTE_0 + 2][row] = (rs1_val >> 16) & 0xFF;
                columns[COL_RS1_BYTE_0 + 3][row] = (rs1_val >> 24) & 0xFF;

                columns[COL_RS2_BYTE_0][row] = rs2_val & 0xFF;
                columns[COL_RS2_BYTE_0 + 1][row] = (rs2_val >> 8) & 0xFF;
                columns[COL_RS2_BYTE_0 + 2][row] = (rs2_val >> 16) & 0xFF;
                columns[COL_RS2_BYTE_0 + 3][row] = (rs2_val >> 24) & 0xFF;

                columns[COL_RD_BYTE_0][row] = rd_val & 0xFF;
                columns[COL_RD_BYTE_0 + 1][row] = (rd_val >> 8) & 0xFF;
                columns[COL_RD_BYTE_0 + 2][row] = (rd_val >> 16) & 0xFF;
                columns[COL_RD_BYTE_0 + 3][row] = (rd_val >> 24) & 0xFF;

                // Set is_bitwise for byte reconstruction constraints
                columns[COL_IS_BITWISE][row] = 1;

                // Fill sign_low7 for M-ext non-bitwise rows (MUL funct3=0).
                // sign bits are 0 (not set here), so low7 = byte_3 & 0x7F.
                columns[COL_SIGN_RS1_LOW7][row] = (rs1_val >> 24) & 0x7F;
                columns[COL_SIGN_RS2_LOW7][row] = (rs2_val >> 24) & 0x7F;
            }

            match funct3 {
                0 => {
                    // MUL: rd = (rs1 * rs2)[31:0]
                    columns[COL_IS_MUL][row] = 1;

                    // Compute byte-level carries for schoolbook multiplication
                    let a0 = (rs1_val & 0xFF) as u64;
                    let a1 = ((rs1_val >> 8) & 0xFF) as u64;
                    let a2 = ((rs1_val >> 16) & 0xFF) as u64;
                    let a3 = ((rs1_val >> 24) & 0xFF) as u64;
                    let b0 = (rs2_val & 0xFF) as u64;
                    let b1 = ((rs2_val >> 8) & 0xFF) as u64;
                    let b2 = ((rs2_val >> 16) & 0xFF) as u64;
                    let b3 = ((rs2_val >> 24) & 0xFF) as u64;

                    let p0 = a0 * b0;
                    let carry0 = (p0 - (p0 & 0xFF)) / 256;
                    let p1 = a0 * b1 + a1 * b0 + carry0;
                    let carry1 = (p1 - (p1 & 0xFF)) / 256;
                    let p2 = a0 * b2 + a1 * b1 + a2 * b0 + carry1;
                    let carry2 = (p2 - (p2 & 0xFF)) / 256;
                    // Phase 4: compute carry3 for byte 3 constraint
                    let p3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + carry2;
                    let carry3 = (p3 - (p3 & 0xFF)) / 256;

                    columns[COL_MUL_CARRY_0][row] = carry0 as u32;
                    columns[COL_MUL_CARRY_1][row] = carry1 as u32;
                    columns[COL_MUL_CARRY_2][row] = carry2 as u32;
                    columns[COL_MUL_CARRY_3][row] = carry3 as u32;

                    // Phase 6: carry byte decomposition (AIR enforcement)
                    columns[COL_CARRY0_LO][row] = (carry0 & 0xFF) as u32;
                    columns[COL_CARRY0_HI][row] = (carry0 >> 8) as u32;
                    columns[COL_CARRY1_LO][row] = (carry1 & 0xFF) as u32;
                    columns[COL_CARRY1_HI][row] = (carry1 >> 8) as u32;
                    columns[COL_CARRY2_LO][row] = (carry2 & 0xFF) as u32;
                    columns[COL_CARRY2_HI][row] = (carry2 >> 8) as u32;
                    columns[COL_CARRY3_LO][row] = (carry3 & 0xFF) as u32;
                    columns[COL_CARRY3_HI][row] = (carry3 >> 8) as u32;
                }
                4 | 5 => {
                    // DIV/DIVU: rd = quotient
                    columns[COL_IS_DIV_TYPE][row] = 1;
                    if rs2_val == 0 {
                        columns[COL_DIV_BY_ZERO][row] = 1;
                        // remainder = rs1 for division by zero
                        columns[COL_DIV_REM_BYTE_0][row] = rs1_val & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 1][row] = (rs1_val >> 8) & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 2][row] = (rs1_val >> 16) & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 3][row] = (rs1_val >> 24) & 0xFF;
                    } else {
                        let remainder = if funct3 == 5 {
                            // DIVU: unsigned
                            rs1_val % rs2_val
                        } else {
                            // DIV: signed
                            let a = rs1_val as i32;
                            let b = rs2_val as i32;
                            (a.wrapping_rem(b)) as u32
                        };
                        columns[COL_DIV_REM_BYTE_0][row] = remainder & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 1][row] = (remainder >> 8) & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 2][row] = (remainder >> 16) & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 3][row] = (remainder >> 24) & 0xFF;
                    }
                }
                6 | 7 => {
                    // REM/REMU: rd = remainder
                    columns[COL_IS_REM_TYPE][row] = 1;
                    if rs2_val == 0 {
                        columns[COL_DIV_BY_ZERO][row] = 1;
                    }
                    // For REM: the quotient is stored in shift_aux for constraint
                    if rs2_val != 0 {
                        let quotient = if funct3 == 7 {
                            rs1_val / rs2_val // REMU: unsigned
                        } else {
                            let a = rs1_val as i32;
                            let b = rs2_val as i32;
                            (a.wrapping_div(b)) as u32
                        };
                        columns[COL_DIV_REM_BYTE_0][row] = quotient & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 1][row] = (quotient >> 8) & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 2][row] = (quotient >> 16) & 0xFF;
                        columns[COL_DIV_REM_BYTE_0 + 3][row] = (quotient >> 24) & 0xFF;
                    }
                }
                1 => {
                    // MULH: signed×signed high 32 bits
                    columns[COL_IS_MULH][row] = 1;
                    // Phase 6: fill MULH high-word bytes
                    let rd = step.regs_after[rd_idx as usize];
                    columns[COL_MULH_BYTE_0][row] = rd & 0xFF;
                    columns[COL_MULH_BYTE_1][row] = (rd >> 8) & 0xFF;
                    columns[COL_MULH_BYTE_2][row] = (rd >> 16) & 0xFF;
                    columns[COL_MULH_BYTE_3][row] = (rd >> 24) & 0xFF;
                }
                2 => {
                    // MULHSU: signed×unsigned high 32 bits
                    columns[COL_IS_MULHSU][row] = 1;
                    let rd = step.regs_after[rd_idx as usize];
                    columns[COL_MULH_BYTE_0][row] = rd & 0xFF;
                    columns[COL_MULH_BYTE_1][row] = (rd >> 8) & 0xFF;
                    columns[COL_MULH_BYTE_2][row] = (rd >> 16) & 0xFF;
                    columns[COL_MULH_BYTE_3][row] = (rd >> 24) & 0xFF;
                }
                3 => {
                    // MULHU: unsigned×unsigned high 32 bits
                    columns[COL_IS_MULHU][row] = 1;
                    let rd = step.regs_after[rd_idx as usize];
                    columns[COL_MULH_BYTE_0][row] = rd & 0xFF;
                    columns[COL_MULH_BYTE_1][row] = (rd >> 8) & 0xFF;
                    columns[COL_MULH_BYTE_2][row] = (rd >> 16) & 0xFF;
                    columns[COL_MULH_BYTE_3][row] = (rd >> 24) & 0xFF;
                }
                _ => {}
            }
        }

        // ── Branch comparison columns ──
        if opcode == opcodes::BRANCH {
            let rs1_val = step.regs_before[rs1_idx as usize];
            let rs2_val = step.regs_before[rs2_idx as usize];
            let imm = decode_immediate(word, opcode);
            let taken = step.next_pc == step.pc.wrapping_add(imm);
            columns[COL_BRANCH_TAKEN][row] = if taken { 1 } else { 0 };

            // Fill comparison diff/borrow for branch verification
            match funct3 {
                0 | 1 => {
                    // BEQ/BNE: equality comparison
                    // diff = rs1 - rs2 (unsigned)
                    let borrow = if rs1_val < rs2_val { 1u32 } else { 0 };
                    let diff64 = rs1_val as u64 + (borrow as u64) * (1u64 << 32) - rs2_val as u64;
                    let diff = diff64 as u32;
                    columns[COL_CMP_BORROW][row] = borrow;
                    columns[COL_CMP_DIFF_BYTE_0][row] = diff & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 1][row] = (diff >> 8) & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 2][row] = (diff >> 16) & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 3][row] = (diff >> 24) & 0xFF;
                }
                4 | 5 => {
                    // BLT/BGE: signed comparison
                    let rs1_f = rs1_val ^ 0x80000000;
                    let rs2_f = rs2_val ^ 0x80000000;
                    let borrow = if rs1_f < rs2_f { 1u32 } else { 0 };
                    let diff64 = rs1_f as u64 + (borrow as u64) * (1u64 << 32) - rs2_f as u64;
                    let diff = diff64 as u32;
                    columns[COL_CMP_BORROW][row] = borrow;
                    columns[COL_CMP_DIFF_BYTE_0][row] = diff & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 1][row] = (diff >> 8) & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 2][row] = (diff >> 16) & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 3][row] = (diff >> 24) & 0xFF;
                }
                6 | 7 => {
                    // BLTU/BGEU: unsigned comparison
                    let borrow = if rs1_val < rs2_val { 1u32 } else { 0 };
                    let diff64 = rs1_val as u64 + (borrow as u64) * (1u64 << 32) - rs2_val as u64;
                    let diff = diff64 as u32;
                    columns[COL_CMP_BORROW][row] = borrow;
                    columns[COL_CMP_DIFF_BYTE_0][row] = diff & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 1][row] = (diff >> 8) & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 2][row] = (diff >> 16) & 0xFF;
                    columns[COL_CMP_DIFF_BYTE_0 + 3][row] = (diff >> 24) & 0xFF;
                }
                _ => {}
            }
            // Sign bits for branch instructions
            columns[COL_SIGN_RS1][row] = (rs1_val >> 31) & 1;
            columns[COL_SIGN_RS2][row] = (rs2_val >> 31) & 1;

            // Fill rs1/rs2 byte_3 and sign_low7 for branch rows.
            // Byte_3 is the MSB byte; needed so the unguarded Phase 5 constraint
            // (byte_3 = sign*128 + low7) holds on branch rows too.
            columns[COL_RS1_BYTE_0 + 3][row] = (rs1_val >> 24) & 0xFF;
            columns[COL_RS2_BYTE_0 + 3][row] = (rs2_val >> 24) & 0xFF;
            columns[COL_SIGN_RS1_LOW7][row] = (rs1_val >> 24) & 0x7F;
            columns[COL_SIGN_RS2_LOW7][row] = (rs2_val >> 24) & 0x7F;
        }
        // For non-Phase3 rows, columns 98-122 remain 0 (from vec init).
    }

    // ── NOP padding to power-of-2 ──

    if padded_steps > real_steps {
        // Determine starting PC and gas for NOP rows.
        let last_real = &trace.steps[real_steps - 1];
        let mut nop_pc = last_real.next_pc;
        // NOP padding gas = cumulative gas after all real execution.
        // This equals gas_before of the first NOP (NOPs don't consume real gas).
        let final_gas = u32::try_from(last_real.gas_used).unwrap_or(u32::MAX);

        // NOP = ADDI x0,x0,0 = 0x00000013
        // opcode = 0x13, rd=0, rs1=0, rs2=0, funct3=0, imm=0
        // Opcode bits: 0x13 = 0b0010011 → bits [1,1,0,0,1,0,0]
        let nop_opcode_bits: [u32; 7] = [1, 1, 0, 0, 1, 0, 0];

        for row in real_steps..padded_steps {
            let next_pc = nop_pc.wrapping_add(4);

            columns[COL_PC][row] = nop_pc;
            // Registers: all zero (default from vec init)
            columns[COL_INSTR][row] = NOP_INSTRUCTION_WORD;
            // mem_addr, mem_value: 0 (default)
            columns[COL_GAS][row] = final_gas;
            // is_ecall: 0 (default)
            columns[COL_NEXT_PC][row] = next_pc;
            // Selectors: only is_alu_imm = 1
            columns[COL_IS_ALU_IMM][row] = 1;
            // rd, rs1, rs2, funct3, imm_value: 0 (default)
            // Opcode bits for 0x13
            for (bit, &val) in nop_opcode_bits.iter().enumerate() {
                columns[COL_OPCODE_BIT_0 + bit][row] = val;
            }
            // opcode_remaining = (0x13 - 0x13) / 128 = 0 (default)

            // Phase 1B NOP columns:
            // rs1_val=0, rs2_val=0, rd_val_after=0 (all regs=0, default)
            // is_write=0 (rd=x0, default)
            // funct7_bit5=0, funct3_bit_*=0 (default)
            // is_addi=1 (ADDI with funct3=0)
            columns[COL_IS_ADDI][row] = 1;
            // is_add=0, is_sub=0, is_jal_link=0, is_jalr_link=0 (default)
            // has_rs1_read=1 (ADDI reads rs1)
            columns[COL_HAS_RS1_READ][row] = 1;
            // has_rs2_read=0 (I-type, default)

            nop_pc = next_pc;
        }
    }

    Ok(AlgebraicTrace {
        columns,
        num_steps: padded_steps,
        width,
    })
}

/// Decode the immediate value from an instruction word based on its opcode.
///
/// Returns the immediate as `i32 as u32` (sign-extended, then reinterpreted).
/// This preserves the signed value in the BabyBear field via two's complement
/// modular arithmetic.
///
/// For FENCE: returns 0 regardless of the instruction bits, since FENCE
/// is grouped with is_alu_imm and must satisfy ADDI's ALU constraint
/// (rd_val = rs1_val + imm = 0 + 0 = 0) in Phase 1B.
fn decode_immediate(word: u32, opcode: u32) -> u32 {
    match opcode {
        opcodes::LUI | opcodes::AUIPC => {
            // U-type: upper 20 bits, already shifted
            decode_u_immediate(word)
        }
        opcodes::JAL => {
            // J-type: sign-extended 21-bit offset
            decode_j_immediate(word) as u32
        }
        opcodes::JALR | opcodes::LOAD | opcodes::OP_IMM => {
            // I-type: sign-extended 12-bit immediate
            decode_i_immediate(word) as u32
        }
        opcodes::STORE => {
            // S-type: sign-extended 12-bit immediate (split fields)
            decode_s_immediate(word) as u32
        }
        opcodes::BRANCH => {
            // B-type: sign-extended 13-bit offset (always even)
            decode_b_immediate(word) as u32
        }
        opcodes::FENCE => {
            // FENCE grouped with is_alu_imm: override imm to 0.
            // This ensures FENCE satisfies the ADDI ALU constraint in Phase 1B:
            // rd_val_after = rs1_val + imm = 0 + 0 = 0.
            0
        }
        opcodes::SYSTEM => {
            // ECALL/EBREAK: no meaningful immediate
            0
        }
        opcodes::OP => {
            // R-type: no immediate field
            0
        }
        _ => 0,
    }
}

/// Commit to the trace using Merkle tree.
///
/// Each row is hashed, and all row hashes form a Merkle tree.
pub fn commit_trace(trace: &AlgebraicTrace) -> (Hash256, MerkleTree) {
    use rayon::prelude::*;
    let row_hashes: Vec<Hash256> = (0..trace.num_steps)
        .into_par_iter()
        .map(|row| {
            let mut hasher = Hasher::new();
            for col in &trace.columns {
                hasher.update(&col[row].to_le_bytes());
            }
            hasher.finalize()
        })
        .collect();

    let tree = MerkleTree::from_hashes(row_hashes).expect("execution trace exceeds 16M rows");
    let root = tree.root();
    (root, tree)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::{Air, COL_X0, NUM_TRANSITION_CONSTRAINTS, RiscVAir, SELECTOR_COLUMNS};
    use crate::field::Fp;
    use crate::types::EvaluationFrame;
    use brrq_vm::instruction::{AluImmFunc, BranchFunc, Instruction, SystemFunc};
    use brrq_vm::trace::{ExecutionTrace, TraceStep};

    fn make_trace(num_steps: usize) -> ExecutionTrace {
        let mut trace = ExecutionTrace::new();
        for i in 0..num_steps {
            let mut regs = [0u32; 32];
            regs[1] = i as u32;
            trace.record(TraceStep {
                step: i as u64,
                pc: (i * 4) as u32,
                instruction: Instruction::AluImm {
                    func: AluImmFunc::Addi,
                    rd: 1,
                    rs1: 0,
                    imm: i as i32,
                },
                instruction_word: 0x00000013,
                regs_before: regs,
                regs_after: regs,
                next_pc: ((i + 1) * 4) as u32,
                memory_accesses: vec![],
                gas_cost: 1,
                gas_used: (i + 1) as u64,
            });
        }
        trace
    }

    /// Convert an AlgebraicTrace row to Fp for AIR evaluation.
    fn row_to_fp(trace: &AlgebraicTrace, row: usize) -> Vec<Fp> {
        trace.columns.iter().map(|col| Fp::new(col[row])).collect()
    }

    #[test]
    fn test_convert_trace_padded_size() {
        // 10 steps → padded to 16
        let trace = make_trace(10);
        let algebraic = convert_trace(&trace).unwrap();
        assert_eq!(algebraic.num_steps, 16);
        assert_eq!(algebraic.width, TRACE_WIDTH);
        assert_eq!(algebraic.columns.len(), TRACE_WIDTH);
        assert_eq!(algebraic.columns[0].len(), 16);
    }

    #[test]
    fn test_convert_power_of_2_no_extra_padding() {
        // 8 steps → stays 8
        let trace = make_trace(8);
        let algebraic = convert_trace(&trace).unwrap();
        assert_eq!(algebraic.num_steps, 8);
    }

    #[test]
    fn test_convert_empty_trace() {
        let trace = ExecutionTrace::new();
        let result = convert_trace(&trace);
        assert!(result.is_err());
    }

    #[test]
    fn test_selectors_exactly_one_per_row() {
        let trace = make_trace(10);
        let algebraic = convert_trace(&trace).unwrap();
        for row in 0..algebraic.num_steps {
            let sum: u32 = SELECTOR_COLUMNS
                .iter()
                .map(|&col| algebraic.columns[col][row])
                .sum();
            assert_eq!(sum, 1, "Row {row}: selector sum must be 1, got {sum}");
        }
    }

    #[test]
    fn test_opcode_reconstruction() {
        let trace = make_trace(4);
        let algebraic = convert_trace(&trace).unwrap();
        for row in 0..algebraic.num_steps {
            let word = algebraic.columns[COL_INSTR][row];
            // Reconstruct opcode from bits
            let mut opcode_from_bits = 0u32;
            for bit in 0..7 {
                opcode_from_bits |= algebraic.columns[COL_OPCODE_BIT_0 + bit][row] << bit;
            }
            let remaining = algebraic.columns[COL_OPCODE_REMAINING][row];
            let reconstructed = opcode_from_bits + remaining * 128;
            assert_eq!(
                reconstructed, word,
                "Row {row}: opcode reconstruction failed: {reconstructed} != {word}"
            );
        }
    }

    #[test]
    fn test_opcode_bits_are_boolean() {
        let trace = make_trace(10);
        let algebraic = convert_trace(&trace).unwrap();
        for row in 0..algebraic.num_steps {
            for bit_col in COL_OPCODE_BIT_0..=COL_OPCODE_BIT_6 {
                let val = algebraic.columns[bit_col][row];
                assert!(
                    val == 0 || val == 1,
                    "Row {row}, col {bit_col}: opcode bit = {val}"
                );
            }
        }
    }

    #[test]
    fn test_nop_padding_pc_sequential() {
        let trace = make_trace(5); // 5 → padded to 8
        let algebraic = convert_trace(&trace).unwrap();
        assert_eq!(algebraic.num_steps, 8);

        // Real rows: PC = 0, 4, 8, 12, 16; next_pc = 4, 8, 12, 16, 20
        // NOP rows: PC = 20, 24, 28; next_pc = 24, 28, 32
        for row in 0..algebraic.num_steps - 1 {
            let next_pc = algebraic.columns[COL_NEXT_PC][row];
            let next_row_pc = algebraic.columns[COL_PC][row + 1];
            assert_eq!(
                next_pc,
                next_row_pc,
                "Row {row}: next_pc ({next_pc}) != row {}'s PC ({next_row_pc})",
                row + 1
            );
        }
    }

    #[test]
    fn test_nop_padding_gas_constant() {
        let trace = make_trace(5); // gas_used: 1,2,3,4,5; gas_before: 0,1,2,3,4
        let algebraic = convert_trace(&trace).unwrap();
        // Last real row (step 4): gas_before = 5-1 = 4
        let last_real_gas = algebraic.columns[COL_GAS][4];
        assert_eq!(last_real_gas, 4);
        // NOP rows use final gas = gas_used of last step = 5
        for row in 5..8 {
            assert_eq!(
                algebraic.columns[COL_GAS][row], 5,
                "Row {row}: NOP gas should be 5 (final cumulative)"
            );
        }
    }

    #[test]
    fn test_nop_padding_x0_zero() {
        let trace = make_trace(5);
        let algebraic = convert_trace(&trace).unwrap();
        for row in 5..8 {
            assert_eq!(
                algebraic.columns[COL_X0][row], 0,
                "Row {row}: NOP x0 should be 0"
            );
        }
    }

    #[test]
    fn test_nop_padding_is_alu_imm() {
        let trace = make_trace(5);
        let algebraic = convert_trace(&trace).unwrap();
        for row in 5..8 {
            assert_eq!(algebraic.columns[COL_IS_ALU_IMM][row], 1);
            // All other selectors should be 0
            for &col in &SELECTOR_COLUMNS {
                if col != COL_IS_ALU_IMM {
                    assert_eq!(
                        algebraic.columns[col][row], 0,
                        "Row {row}, col {col}: NOP should have only is_alu_imm=1"
                    );
                }
            }
        }
    }

    #[test]
    fn test_nop_rows_satisfy_air_constraints() {
        let trace = make_trace(5); // padded to 8
        let algebraic = convert_trace(&trace).unwrap();
        let air = RiscVAir::new(Hash256::ZERO, Hash256::ZERO);

        // Check all transition constraints on NOP rows (rows 5-6: current=5,next=6 and 6,7)
        for row in 5..7 {
            let current = row_to_fp(&algebraic, row);
            let next = row_to_fp(&algebraic, row + 1);
            let frame = EvaluationFrame { current, next };
            let constraints = air.evaluate_transition(&frame);
            assert_eq!(constraints.len(), NUM_TRANSITION_CONSTRAINTS);
            for (i, c) in constraints.iter().enumerate() {
                assert_eq!(
                    c.value(),
                    0,
                    "NOP row {row}: transition constraint T{} = {} (should be 0)",
                    i + 1,
                    c.value()
                );
            }
        }
    }

    #[test]
    fn test_real_to_nop_transition_satisfies_constraints() {
        let trace = make_trace(5); // padded to 8
        let algebraic = convert_trace(&trace).unwrap();
        let air = RiscVAir::new(Hash256::ZERO, Hash256::ZERO);

        // Transition from last real row (4) to first NOP row (5)
        let current = row_to_fp(&algebraic, 4);
        let next = row_to_fp(&algebraic, 5);
        let frame = EvaluationFrame { current, next };
        let constraints = air.evaluate_transition(&frame);
        for (i, c) in constraints.iter().enumerate() {
            assert_eq!(
                c.value(),
                0,
                "Real-to-NOP transition: constraint T{} = {} (should be 0)",
                i + 1,
                c.value()
            );
        }
    }

    #[test]
    fn test_all_transitions_satisfy_constraints() {
        let trace = make_trace(5); // 5 real + 3 NOP = 8
        let algebraic = convert_trace(&trace).unwrap();
        let air = RiscVAir::new(Hash256::ZERO, Hash256::ZERO);

        for row in 0..algebraic.num_steps - 1 {
            let current = row_to_fp(&algebraic, row);
            let next = row_to_fp(&algebraic, row + 1);
            let frame = EvaluationFrame { current, next };
            let constraints = air.evaluate_transition(&frame);
            for (i, c) in constraints.iter().enumerate() {
                assert_eq!(
                    c.value(),
                    0,
                    "Row {row}: constraint T{} = {} (should be 0)",
                    i + 1,
                    c.value()
                );
            }
        }
    }

    #[test]
    fn test_boundary_constraints_satisfied() {
        let trace = make_trace(8);
        let algebraic = convert_trace(&trace).unwrap();
        let air = RiscVAir::new(Hash256::ZERO, Hash256::ZERO);
        let first_row = row_to_fp(&algebraic, 0);
        let constraints = air.evaluate_boundary_first(&first_row);
        for (i, c) in constraints.iter().enumerate() {
            assert_eq!(
                c.value(),
                0,
                "Boundary constraint B{} = {} (should be 0)",
                i + 1,
                c.value()
            );
        }
    }

    #[test]
    fn test_ecall_flag_non_ecall() {
        let trace = make_trace(4);
        let algebraic = convert_trace(&trace).unwrap();
        for row in 0..4 {
            assert_eq!(
                algebraic.columns[COL_IS_ECALL][row], 0,
                "Non-ECALL instruction should have is_ecall=0"
            );
        }
    }

    #[test]
    fn test_ecall_row() {
        let mut trace = ExecutionTrace::new();
        let regs = [0u32; 32];
        // Row 0: ADDI
        trace.record(TraceStep {
            step: 0,
            pc: 0,
            instruction: Instruction::AluImm {
                func: AluImmFunc::Addi,
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            instruction_word: 0x00000013,
            regs_before: regs,
            regs_after: regs,
            next_pc: 4,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 1,
        });
        // Row 1: ECALL
        trace.record(TraceStep {
            step: 1,
            pc: 4,
            instruction: Instruction::System {
                func: SystemFunc::Ecall,
            },
            instruction_word: ECALL_INSTRUCTION_WORD,
            regs_before: regs,
            regs_after: regs,
            next_pc: 8,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 2,
        });

        let algebraic = convert_trace(&trace).unwrap();
        assert_eq!(algebraic.columns[COL_IS_ECALL][0], 0, "ADDI row");
        assert_eq!(algebraic.columns[COL_IS_ECALL][1], 1, "ECALL row");
        assert_eq!(algebraic.columns[COL_IS_ALU_IMM][0], 1, "ADDI selector");
        assert_eq!(algebraic.columns[COL_IS_ALU_IMM][1], 0, "ECALL not alu_imm");
    }

    #[test]
    fn test_branch_immediate_decode() {
        let mut trace = ExecutionTrace::new();
        let regs = [0u32; 32];
        // BEQ x0, x0, +8 → always taken, next_pc = 8
        // Encode: B-type with imm=8, funct3=0 (BEQ)
        let imm = 8i32;
        let imm_u = imm as u32;
        let b_word = ((imm_u >> 12) & 1) << 31
            | ((imm_u >> 5) & 0x3F) << 25
            | (0u32 << 20) // rs2=0
            | (0u32 << 15) // rs1=0
            | (0u32 << 12) // funct3=0 (BEQ)
            | ((imm_u >> 1) & 0xF) << 8
            | ((imm_u >> 11) & 1) << 7
            | opcodes::BRANCH;
        trace.record(TraceStep {
            step: 0,
            pc: 0,
            instruction: Instruction::Branch {
                func: BranchFunc::Beq,
                rs1: 0,
                rs2: 0,
                offset: 8,
            },
            instruction_word: b_word,
            regs_before: regs,
            regs_after: regs,
            next_pc: 8,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 1,
        });
        // Row 1: NOP at PC=8
        trace.record(TraceStep {
            step: 1,
            pc: 8,
            instruction: Instruction::AluImm {
                func: AluImmFunc::Addi,
                rd: 0,
                rs1: 0,
                imm: 0,
            },
            instruction_word: 0x00000013,
            regs_before: regs,
            regs_after: regs,
            next_pc: 12,
            memory_accesses: vec![],
            gas_cost: 1,
            gas_used: 2,
        });

        let algebraic = convert_trace(&trace).unwrap();
        assert_eq!(algebraic.columns[COL_IS_BRANCH][0], 1);
        // Immediate should be 8 (as u32)
        assert_eq!(algebraic.columns[COL_IMM_VALUE][0], 8);
    }

    #[test]
    fn test_commit_trace() {
        let trace = make_trace(8);
        let algebraic = convert_trace(&trace).unwrap();
        let (root, _tree) = commit_trace(&algebraic);
        assert_ne!(root, Hash256::ZERO);
    }

    #[test]
    fn test_trace_deterministic() {
        let trace = make_trace(8);
        let a1 = convert_trace(&trace).unwrap();
        let a2 = convert_trace(&trace).unwrap();
        let (root1, _) = commit_trace(&a1);
        let (root2, _) = commit_trace(&a2);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_decoded_fields() {
        let trace = make_trace(1);
        let algebraic = convert_trace(&trace).unwrap();
        // ADDI x1, x0, 0 = 0x00000013
        // rd=0 from the instruction word (bits 11:7 = 0b00000 for 0x00000013)
        // Wait — 0x00000013 encodes: opcode=0x13, rd=0, funct3=0, rs1=0, imm=0
        // But make_trace uses rd:1 in the Instruction enum — the instruction_word
        // doesn't match. The trace_converter uses instruction_word, not the enum.
        // 0x00000013: rd = (0x13 >> 7) & 0x1F = 0
        assert_eq!(algebraic.columns[COL_RD][0], 0);
        assert_eq!(algebraic.columns[COL_RS1][0], 0);
        assert_eq!(algebraic.columns[COL_RS2][0], 0);
        assert_eq!(algebraic.columns[COL_FUNCT3][0], 0);
        assert_eq!(algebraic.columns[COL_IMM_VALUE][0], 0);
    }

    #[test]
    fn test_single_step_padded_to_one() {
        // 1 step → 1 is already power of 2
        let trace = make_trace(1);
        let algebraic = convert_trace(&trace).unwrap();
        assert_eq!(algebraic.num_steps, 1);
    }
}
