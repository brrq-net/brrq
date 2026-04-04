//! RISC-V RV32IM instruction definitions.
//!
//! Covers the base integer (I) and multiply (M) extensions.
//! Compressed (C) extension is intentionally NOT supported —
//! it complicates ZK circuit decoding without performance benefit.

/// Opcodes for RV32IM instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // RV32I Base
    Lui,    // Load Upper Immediate
    Auipc,  // Add Upper Immediate to PC
    Jal,    // Jump and Link
    Jalr,   // Jump and Link Register
    Branch, // Conditional branches (BEQ, BNE, BLT, BGE, BLTU, BGEU)
    Load,   // Load from memory (LB, LH, LW, LBU, LHU)
    Store,  // Store to memory (SB, SH, SW)
    OpImm,  // Register-immediate ALU (ADDI, SLTI, XORI, ORI, ANDI, SLLI, SRLI, SRAI)
    Op,     // Register-register ALU (ADD, SUB, SLL, SLT, SLTU, XOR, SRL, SRA, OR, AND)
    Fence,  // Memory ordering (treated as NOP in zkVM)
    System, // ECALL, EBREAK
}

/// Branch function codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchFunc {
    Beq,
    Bne,
    Blt,
    Bge,
    Bltu,
    Bgeu,
}

/// Load function codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadFunc {
    Lb,
    Lh,
    Lw,
    Lbu,
    Lhu,
}

/// Store function codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreFunc {
    Sb,
    Sh,
    Sw,
}

/// ALU immediate function codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluImmFunc {
    Addi,
    Slti,
    Sltiu,
    Xori,
    Ori,
    Andi,
    Slli,
    Srli,
    Srai,
}

/// ALU register-register function codes (includes M extension).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AluRegFunc {
    // RV32I
    Add,
    Sub,
    Sll,
    Slt,
    Sltu,
    Xor,
    Srl,
    Sra,
    Or,
    And,
    // RV32M (Multiply extension)
    Mul,
    Mulh,
    Mulhsu,
    Mulhu,
    Div,
    Divu,
    Rem,
    Remu,
}

/// System function codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemFunc {
    Ecall,
    Ebreak,
}

/// A decoded RISC-V instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Instruction {
    /// LUI rd, imm
    Lui { rd: u8, imm: u32 },
    /// AUIPC rd, imm
    Auipc { rd: u8, imm: u32 },
    /// JAL rd, offset
    Jal { rd: u8, offset: i32 },
    /// JALR rd, rs1, offset
    Jalr { rd: u8, rs1: u8, offset: i32 },
    /// Branch: BEQ/BNE/BLT/BGE/BLTU/BGEU
    Branch {
        func: BranchFunc,
        rs1: u8,
        rs2: u8,
        offset: i32,
    },
    /// Load: LB/LH/LW/LBU/LHU
    Load {
        func: LoadFunc,
        rd: u8,
        rs1: u8,
        offset: i32,
    },
    /// Store: SB/SH/SW
    Store {
        func: StoreFunc,
        rs1: u8,
        rs2: u8,
        offset: i32,
    },
    /// ALU immediate operations
    AluImm {
        func: AluImmFunc,
        rd: u8,
        rs1: u8,
        imm: i32,
    },
    /// ALU register-register operations (includes M extension)
    AluReg {
        func: AluRegFunc,
        rd: u8,
        rs1: u8,
        rs2: u8,
    },
    /// FENCE (memory ordering — NOP in zkVM)
    Fence,
    /// System calls
    System { func: SystemFunc },
}

impl Instruction {
    /// Get the destination register (if any).
    pub fn rd(&self) -> Option<u8> {
        match self {
            Self::Lui { rd, .. }
            | Self::Auipc { rd, .. }
            | Self::Jal { rd, .. }
            | Self::Jalr { rd, .. }
            | Self::Load { rd, .. }
            | Self::AluImm { rd, .. }
            | Self::AluReg { rd, .. } => Some(*rd),
            _ => None,
        }
    }

    /// Check if this is a multiply/divide instruction (M extension).
    pub fn is_m_extension(&self) -> bool {
        matches!(
            self,
            Self::AluReg {
                func: AluRegFunc::Mul
                    | AluRegFunc::Mulh
                    | AluRegFunc::Mulhsu
                    | AluRegFunc::Mulhu
                    | AluRegFunc::Div
                    | AluRegFunc::Divu
                    | AluRegFunc::Rem
                    | AluRegFunc::Remu,
                ..
            }
        )
    }
}
