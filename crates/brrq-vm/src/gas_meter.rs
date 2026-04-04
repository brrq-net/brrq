//! Gas metering for zkVM execution.
//!
//! Maps each RISC-V instruction to its gas cost based on STARK proving complexity.
//! Costs from whitepaper §4.4.

use crate::error::VmError;
use crate::instruction::*;

/// Gas cost table matching whitepaper §4.4.
pub mod costs {
    /// Simple arithmetic: ADD, SUB, AND, OR, XOR, SLT, SLTU
    pub const ALU_BASIC: u64 = 1;
    /// Shift operations: SLL, SRL, SRA, SLLI, SRLI, SRAI
    pub const ALU_SHIFT: u64 = 1;
    /// Immediate ALU: ADDI, SLTI, SLTIU, XORI, ORI, ANDI
    pub const ALU_IMM: u64 = 1;
    /// Multiply: MUL, MULH, MULHSU, MULHU
    pub const MUL: u64 = 2;
    /// Division: DIV, DIVU, REM, REMU
    pub const DIV: u64 = 3;
    /// Memory load: LB, LH, LW, LBU, LHU
    pub const LOAD: u64 = 5;
    /// Memory store: SB, SH, SW
    pub const STORE: u64 = 7;
    /// Branch (taken or not): BEQ, BNE, BLT, BGE, BLTU, BGEU
    pub const BRANCH: u64 = 2;
    /// Jump: JAL, JALR
    pub const JUMP: u64 = 2;
    /// LUI, AUIPC
    pub const UPPER_IMM: u64 = 1;
    /// ECALL, EBREAK
    pub const SYSTEM: u64 = 10;
    /// FENCE (NOP)
    pub const FENCE: u64 = 1;
}

/// Minimum gas limit for a transaction.
/// Transactions with a gas limit below this value can never execute even a
/// single meaningful instruction, wasting resources. Same as Ethereum's
/// intrinsic gas for a basic transfer.
pub const MIN_GAS_LIMIT: u64 = 21_000;

/// Validate that a gas limit meets the minimum requirement.
///
/// Call this before creating a `GasMeter` to reject transactions that would
/// immediately fail, avoiding wasted processing.
pub fn validate_gas_limit(limit: u64) -> Result<(), VmError> {
    if limit < MIN_GAS_LIMIT {
        return Err(VmError::GasLimitTooLow {
            limit,
            minimum: MIN_GAS_LIMIT,
        });
    }
    Ok(())
}

/// Gas meter tracks gas consumption during VM execution.
///
/// Supports gas refunds for operations like clearing a storage slot (writing
/// zero to a non-zero value). Refunds are capped at 50% of total gas used
/// and applied at the end of execution.
#[derive(Debug, Clone)]
pub struct GasMeter {
    /// Maximum gas allowed.
    limit: u64,
    /// Gas consumed so far.
    used: u64,
    /// Accumulated gas refund (applied at end of execution).
    refund: u64,
    /// EVM-style memory gas cost charged so far.
    pub memory_cost: u64,
}

impl GasMeter {
    /// Create a new gas meter with the given limit.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            refund: 0,
            memory_cost: 0,
        }
    }

    /// Create an unlimited gas meter (for testing).
    pub fn unlimited() -> Self {
        Self {
            limit: u64::MAX,
            used: 0,
            refund: 0,
            memory_cost: 0,
        }
    }

    /// Get the gas cost for an instruction.
    pub fn instruction_cost(inst: &Instruction) -> u64 {
        match inst {
            Instruction::Lui { .. } | Instruction::Auipc { .. } => costs::UPPER_IMM,

            Instruction::Jal { .. } | Instruction::Jalr { .. } => costs::JUMP,

            Instruction::Branch { .. } => costs::BRANCH,

            Instruction::Load { .. } => costs::LOAD,

            Instruction::Store { .. } => costs::STORE,

            Instruction::AluImm { func, .. } => match func {
                AluImmFunc::Slli | AluImmFunc::Srli | AluImmFunc::Srai => costs::ALU_SHIFT,
                _ => costs::ALU_IMM,
            },

            Instruction::AluReg { func, .. } => match func {
                AluRegFunc::Mul | AluRegFunc::Mulh | AluRegFunc::Mulhsu | AluRegFunc::Mulhu => {
                    costs::MUL
                }
                AluRegFunc::Div | AluRegFunc::Divu | AluRegFunc::Rem | AluRegFunc::Remu => {
                    costs::DIV
                }
                AluRegFunc::Sll | AluRegFunc::Srl | AluRegFunc::Sra => costs::ALU_SHIFT,
                _ => costs::ALU_BASIC,
            },

            Instruction::Fence => costs::FENCE,

            Instruction::System { .. } => costs::SYSTEM,
        }
    }

    /// Consume gas for an instruction. Returns error if out of gas.
    pub fn consume(&mut self, inst: &Instruction) -> Result<u64, VmError> {
        let cost = Self::instruction_cost(inst);
        self.consume_raw(cost)?;
        Ok(cost)
    }

    /// Consume a raw amount of gas (for precompiles, etc.).
    pub fn consume_raw(&mut self, amount: u64) -> Result<(), VmError> {
        let new_used = self.used.checked_add(amount).ok_or(VmError::OutOfGas {
            used: u64::MAX,
            limit: self.limit,
        })?;
        if new_used > self.limit {
            return Err(VmError::OutOfGas {
                used: new_used,
                limit: self.limit,
            });
        }
        self.used = new_used;
        Ok(())
    }

    /// Charge EVM-style memory expansion gas.
    /// `words` is the total number of 32-byte words active in memory.
    pub fn charge_memory_expansion(&mut self, words: u64) -> Result<(), VmError> {
        let words_squared = words.checked_mul(words).ok_or(VmError::OutOfGas {
            used: u64::MAX,
            limit: self.limit,
        })?;
        let linear = words.checked_mul(3).ok_or(VmError::OutOfGas {
            used: u64::MAX,
            limit: self.limit,
        })?;
        let total_cost = linear
            .checked_add(words_squared / 512)
            .ok_or(VmError::OutOfGas {
                used: u64::MAX,
                limit: self.limit,
            })?;
        if total_cost > self.memory_cost {
            let diff = total_cost - self.memory_cost;
            self.consume_raw(diff)?;
            self.memory_cost = total_cost;
        }
        Ok(())
    }

    /// Add a gas refund (e.g., for clearing a storage slot).
    ///
    /// Refunds accumulate and are applied at the end of execution,
    /// capped at 50% of total gas used.
    pub fn add_refund(&mut self, amount: u64) {
        self.refund = self.refund.saturating_add(amount);
    }

    /// Accumulated refund so far (before capping).
    pub fn refund(&self) -> u64 {
        self.refund
    }

    /// Compute the effective gas used after applying refunds.
    ///
    /// Refund is capped at 50% of gas used (same rule as Ethereum EIP-3529).
    pub fn effective_gas_used(&self) -> u64 {
        let max_refund = self.used / 2;
        let actual_refund = self.refund.min(max_refund);
        self.used.saturating_sub(actual_refund)
    }

    /// Gas remaining.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Gas consumed so far (before refunds).
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Gas limit.
    pub fn limit(&self) -> u64 {
        self.limit
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alu_basic_costs() {
        let add = Instruction::AluReg {
            func: AluRegFunc::Add,
            rd: 1,
            rs1: 2,
            rs2: 3,
        };
        assert_eq!(GasMeter::instruction_cost(&add), 1);
    }

    #[test]
    fn test_mul_costs() {
        let mul = Instruction::AluReg {
            func: AluRegFunc::Mul,
            rd: 1,
            rs1: 2,
            rs2: 3,
        };
        assert_eq!(GasMeter::instruction_cost(&mul), 2);
    }

    #[test]
    fn test_div_costs() {
        let div = Instruction::AluReg {
            func: AluRegFunc::Div,
            rd: 1,
            rs1: 2,
            rs2: 3,
        };
        assert_eq!(GasMeter::instruction_cost(&div), 3);
    }

    #[test]
    fn test_load_store_costs() {
        let load = Instruction::Load {
            func: LoadFunc::Lw,
            rd: 1,
            rs1: 2,
            offset: 0,
        };
        let store = Instruction::Store {
            func: StoreFunc::Sw,
            rs1: 1,
            rs2: 2,
            offset: 0,
        };
        assert_eq!(GasMeter::instruction_cost(&load), 5);
        assert_eq!(GasMeter::instruction_cost(&store), 7);
    }

    #[test]
    fn test_gas_meter_consume() {
        let mut meter = GasMeter::new(100);
        let add = Instruction::AluReg {
            func: AluRegFunc::Add,
            rd: 1,
            rs1: 2,
            rs2: 3,
        };
        // ADD costs 1 gas
        let cost = meter.consume(&add).unwrap();
        assert_eq!(cost, 1);
        assert_eq!(meter.used(), 1);
        assert_eq!(meter.remaining(), 99);
    }

    #[test]
    fn test_gas_meter_out_of_gas() {
        let mut meter = GasMeter::new(5);
        let load = Instruction::Load {
            func: LoadFunc::Lw,
            rd: 1,
            rs1: 2,
            offset: 0,
        };
        // First LOAD costs 5, uses all gas
        meter.consume(&load).unwrap();
        // Second LOAD should fail
        let result = meter.consume(&load);
        assert!(result.is_err());
    }

    #[test]
    fn test_gas_meter_unlimited() {
        let mut meter = GasMeter::unlimited();
        for _ in 0..1000 {
            let add = Instruction::AluReg {
                func: AluRegFunc::Add,
                rd: 1,
                rs1: 2,
                rs2: 3,
            };
            meter.consume(&add).unwrap();
        }
        assert_eq!(meter.used(), 1000);
    }

    #[test]
    fn test_gas_meter_raw_consume() {
        let mut meter = GasMeter::new(1000);
        meter.consume_raw(500).unwrap();
        assert_eq!(meter.remaining(), 500);
        meter.consume_raw(500).unwrap();
        assert_eq!(meter.remaining(), 0);
        assert!(meter.consume_raw(1).is_err());
    }

    // ── Gas refund tests ───────────────────────────────────────────

    #[test]
    fn test_refund_basic() {
        let mut meter = GasMeter::new(100_000);
        meter.consume_raw(20_000).unwrap(); // SSTORE init
        meter.add_refund(4_800); // SSTORE clear refund

        assert_eq!(meter.refund(), 4_800);
        assert_eq!(meter.used(), 20_000);
        // Effective: 20_000 - min(4_800, 20_000/2) = 20_000 - 4_800 = 15_200
        assert_eq!(meter.effective_gas_used(), 15_200);
    }

    #[test]
    fn test_refund_capped_at_50_percent() {
        let mut meter = GasMeter::new(100_000);
        meter.consume_raw(10_000).unwrap();
        meter.add_refund(9_000); // More than 50% of used

        // Cap: min(9_000, 10_000/2) = 5_000
        assert_eq!(meter.effective_gas_used(), 5_000);
    }

    #[test]
    fn test_refund_accumulates() {
        let mut meter = GasMeter::new(100_000);
        meter.consume_raw(50_000).unwrap();
        meter.add_refund(4_800);
        meter.add_refund(4_800);

        assert_eq!(meter.refund(), 9_600);
        // Effective: 50_000 - min(9_600, 25_000) = 40_400
        assert_eq!(meter.effective_gas_used(), 40_400);
    }

    #[test]
    fn test_refund_zero_when_none() {
        let meter = GasMeter::new(100_000);
        assert_eq!(meter.refund(), 0);
        assert_eq!(meter.effective_gas_used(), 0);
    }

    // ── Minimum gas limit tests ───────────────────────────────────

    #[test]
    fn test_validate_gas_limit_below_minimum() {
        let result = validate_gas_limit(0);
        assert!(result.is_err(), "Gas limit of 0 must be rejected");

        let result = validate_gas_limit(MIN_GAS_LIMIT - 1);
        assert!(result.is_err(), "Gas limit below minimum must be rejected");
    }

    #[test]
    fn test_validate_gas_limit_at_minimum() {
        let result = validate_gas_limit(MIN_GAS_LIMIT);
        assert!(
            result.is_ok(),
            "Gas limit at exactly minimum should be accepted"
        );
    }

    #[test]
    fn test_validate_gas_limit_above_minimum() {
        let result = validate_gas_limit(MIN_GAS_LIMIT + 1);
        assert!(result.is_ok(), "Gas limit above minimum should be accepted");

        let result = validate_gas_limit(1_000_000);
        assert!(result.is_ok(), "Large gas limit should be accepted");
    }
}
