//! CPU state for the RISC-V zkVM.
//!
//! ## Registers
//!
//! RV32I has 32 general-purpose 32-bit registers (x0-x31):
//! - x0 (zero): Hardwired to 0 — writes are ignored
//! - x1 (ra): Return address (convention)
//! - x2 (sp): Stack pointer (convention)
//! - x3-x31: General purpose
//!
//! ## Program Counter
//!
//! 32-bit PC, always 4-byte aligned (no compressed instructions).

/// Number of general-purpose registers.
pub const NUM_REGISTERS: usize = 32;

/// Default stack pointer start (top of 4 GB address space, aligned).
pub const DEFAULT_SP: u32 = 0xFFFFF000;

/// CPU state: registers + program counter.
#[derive(Clone)]
pub struct Cpu {
    /// General-purpose registers x0-x31.
    regs: [u32; NUM_REGISTERS],
    /// Program counter.
    pub pc: u32,
    /// Total instructions executed (for step limiting).
    pub cycle_count: u64,
}

impl Cpu {
    /// Create a new CPU with zeroed registers and PC at given entry point.
    pub fn new(entry_pc: u32) -> Self {
        let mut cpu = Self {
            regs: [0u32; NUM_REGISTERS],
            pc: entry_pc,
            cycle_count: 0,
        };
        // Initialize stack pointer
        cpu.regs[2] = DEFAULT_SP;
        cpu
    }

    /// Read a register. x0 always returns 0.
    #[inline]
    pub fn read_reg(&self, reg: u8) -> u32 {
        if reg == 0 { 0 } else { self.regs[reg as usize] }
    }

    /// Write to a register. Writes to x0 are silently ignored.
    #[inline]
    pub fn write_reg(&mut self, reg: u8, value: u32) {
        if reg != 0 {
            self.regs[reg as usize] = value;
        }
    }

    /// Get all register values (for tracing/debugging).
    pub fn registers(&self) -> &[u32; NUM_REGISTERS] {
        &self.regs
    }

    /// Advance PC by 4 bytes (normal sequential execution).
    #[inline]
    pub fn advance_pc(&mut self) {
        self.pc = self.pc.wrapping_add(4);
    }

    /// Set PC to an absolute address. Returns error if not 4-byte aligned.
    #[inline]
    pub fn set_pc(&mut self, addr: u32) -> Result<(), crate::error::VmError> {
        if addr & 3 != 0 {
            return Err(crate::error::VmError::UnalignedAccess { addr });
        }
        self.pc = addr;
        Ok(())
    }

    /// Increment the cycle counter.
    #[inline]
    pub fn tick(&mut self) {
        self.cycle_count += 1;
    }

    /// Get stack pointer (x2).
    pub fn sp(&self) -> u32 {
        self.regs[2]
    }

    /// Get return address (x1).
    pub fn ra(&self) -> u32 {
        self.regs[1]
    }
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new(0)
    }
}

impl std::fmt::Debug for Cpu {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "CPU State:")?;
        writeln!(f, "  PC: 0x{:08x}  cycles: {}", self.pc, self.cycle_count)?;
        for i in (0..32).step_by(4) {
            writeln!(
                f,
                "  x{:02}: 0x{:08x}  x{:02}: 0x{:08x}  x{:02}: 0x{:08x}  x{:02}: 0x{:08x}",
                i,
                self.regs[i],
                i + 1,
                self.regs[i + 1],
                i + 2,
                self.regs[i + 2],
                i + 3,
                self.regs[i + 3],
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x0_always_zero() {
        let mut cpu = Cpu::new(0);
        cpu.write_reg(0, 0xDEADBEEF);
        assert_eq!(cpu.read_reg(0), 0);
    }

    #[test]
    fn test_register_read_write() {
        let mut cpu = Cpu::new(0);
        for i in 1..32u8 {
            cpu.write_reg(i, i as u32 * 100);
        }
        for i in 1..32u8 {
            assert_eq!(cpu.read_reg(i), i as u32 * 100);
        }
    }

    #[test]
    fn test_initial_state() {
        let cpu = Cpu::new(0x1000);
        assert_eq!(cpu.pc, 0x1000);
        assert_eq!(cpu.read_reg(0), 0); // x0 = 0
        assert_eq!(cpu.sp(), DEFAULT_SP); // x2 = stack pointer
        assert_eq!(cpu.cycle_count, 0);
    }

    #[test]
    fn test_advance_pc() {
        let mut cpu = Cpu::new(0);
        assert_eq!(cpu.pc, 0);
        cpu.advance_pc();
        assert_eq!(cpu.pc, 4);
        cpu.advance_pc();
        assert_eq!(cpu.pc, 8);
    }

    #[test]
    fn test_set_pc() {
        let mut cpu = Cpu::new(0);
        cpu.set_pc(0x2000).unwrap();
        assert_eq!(cpu.pc, 0x2000);
    }

    #[test]
    fn test_set_pc_misaligned() {
        let mut cpu = Cpu::new(0);
        assert!(cpu.set_pc(0x2001).is_err());
        assert!(cpu.set_pc(0x2002).is_err());
        assert!(cpu.set_pc(0x2003).is_err());
        assert_eq!(cpu.pc, 0); // unchanged
    }

    #[test]
    fn test_tick() {
        let mut cpu = Cpu::new(0);
        cpu.tick();
        cpu.tick();
        cpu.tick();
        assert_eq!(cpu.cycle_count, 3);
    }

    #[test]
    fn test_pc_wrapping() {
        let mut cpu = Cpu::new(0xFFFFFFFC);
        cpu.advance_pc();
        assert_eq!(cpu.pc, 0); // wraps around
    }

    #[test]
    fn test_debug_format() {
        let cpu = Cpu::new(0x1000);
        let debug_str = format!("{:?}", cpu);
        assert!(debug_str.contains("PC: 0x00001000"));
        assert!(debug_str.contains("x00: 0x00000000"));
    }
}
