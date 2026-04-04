//! # brrq-vm
//!
//! RISC-V zkVM (RV32IM) execution environment for Brrq smart contracts.
//!
//! ## Architecture (§4.3)
//!
//! | Spec              | Value                    |
//! |-------------------|--------------------------|
//! | ISA               | RV32IM (32-bit + Multiply)|
//! | Addressable Memory| 4 GB (2^32 bytes)        |
//! | Memory Model      | Harvard-style (read-only code)|
//! | Gas Metering      | Per-instruction cost     |
//!
//! ## Modules
//!
//! - `instruction`: RISC-V instruction definitions
//! - `decoder`: Instruction decoder (binary → structured)
//! - `memory`: Harvard-style memory subsystem
//! - `cpu`: CPU state (registers, PC)
//! - `executor`: Instruction execution engine
//! - `gas_meter`: Gas consumption tracking
//! - `precompiles`: Accelerated crypto operations
//! - `trace`: Execution trace for STARK proving

pub mod cpu;
pub mod decoder;
pub mod error;
pub mod executor;
pub mod gas_meter;
pub mod instruction;
pub mod memory;
pub mod precompiles;
pub mod trace;

pub use cpu::Cpu;
pub use error::VmError;
pub use executor::{Executor, StorageProvider};
pub use memory::Memory;
