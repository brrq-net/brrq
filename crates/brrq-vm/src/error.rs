//! VM error types.

use thiserror::Error;

/// Errors that can occur during VM execution.
#[derive(Debug, Error)]
pub enum VmError {
    #[error("invalid instruction at PC=0x{pc:08x}: 0x{word:08x}")]
    InvalidInstruction { pc: u32, word: u32 },

    #[error("unaligned memory access at address 0x{addr:08x}")]
    UnalignedAccess { addr: u32 },

    #[error("memory access out of bounds: address 0x{addr:08x}")]
    MemoryOutOfBounds { addr: u32 },

    #[error("out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },

    #[error("invalid syscall number: {number}")]
    InvalidSyscall { number: u32 },

    /// Trace exceeded MAX_TRACE_ROWS.
    /// Treated as OutOfGas — transaction is reverted, gas consumed.
    #[error("trace capacity exceeded ({rows} rows, max {max})")]
    TraceCapacityExceeded { rows: usize, max: usize },

    #[error("write to read-only code segment at 0x{addr:08x}")]
    WriteToCode { addr: u32 },

    #[error("precompile error: {msg}")]
    PrecompileError { msg: String },

    #[error("execution step limit exceeded: {limit}")]
    StepLimitExceeded { limit: u64 },

    /// Gas limit is below the minimum required for any transaction.
    #[error("gas limit too low: {limit} (minimum {minimum})")]
    GasLimitTooLow { limit: u64, minimum: u64 },

    /// Invalid register index in public API.
    #[error("invalid register index: {reg} (must be 0-31)")]
    InvalidRegister { reg: u8 },

    /// Read from address that was never written in strict mode.
    /// Detects write-before-read violations that could allow memory injection attacks.
    #[error("uninitialized memory read at address 0x{addr:08x} (strict mode)")]
    UninitializedRead { addr: u32 },

    /// Invalid Merkle proof direction byte (must be 0 or 1).
    #[error("invalid Merkle direction byte: {value} (expected 0 or 1)")]
    InvalidMerkleDirection { value: u8 },

    /// Total output size exceeded the allowed cap.
    #[error("output limit exceeded (max 10 MB)")]
    OutputLimitExceeded,
}
