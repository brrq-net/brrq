//! RISC-V RV32IM instruction executor.
//!
//! The executor is the core of the zkVM. It:
//! 1. Fetches the next instruction from memory
//! 2. Decodes it into a structured Instruction
//! 3. Records pre-state for the trace
//! 4. Executes the instruction (modifying CPU/memory)
//! 5. Records post-state for the trace
//! 6. Metering gas consumption
//!
//! ## Correctness guarantees
//!
//! - x0 is always 0 (writes silently ignored)
//! - Division by zero returns defined values (RISC-V spec)
//! - All arithmetic is wrapping 32-bit

use crate::cpu::Cpu;
use crate::decoder;
use crate::error::VmError;
use crate::gas_meter::GasMeter;
use crate::instruction::*;
use crate::memory::Memory;
use crate::precompiles::{self, PrecompileResult};
use crate::trace::{ExecutionTrace, MemoryAccess, MemoryAccessKind, TraceStep};

/// Trait for providing persistent contract storage to the VM.
///
/// Implemented by the sequencer to bridge VM ↔ WorldState.
/// The VM itself knows nothing about the state layer; it only
/// calls `storage_get`/`storage_set` through this trait.
pub trait StorageProvider {
    /// Read a 32-byte value from storage by key. Returns `None` if slot is empty.
    fn storage_get(&self, key: &brrq_crypto::hash::Hash256) -> Option<brrq_crypto::hash::Hash256>;
    /// Write a 32-byte value to storage by key.
    fn storage_set(&mut self, key: brrq_crypto::hash::Hash256, value: brrq_crypto::hash::Hash256);
    /// Drain all buffered writes. Returns (key, value) pairs.
    fn drain_writes(&mut self) -> Vec<(brrq_crypto::hash::Hash256, brrq_crypto::hash::Hash256)>;
}

/// Execution result after running to completion.
#[derive(Debug)]
pub struct ExecutionResult {
    /// Exit code (from HALT syscall, or 0 if step limit reached).
    pub exit_code: u32,
    /// Execution trace (if recording was enabled).
    pub trace: ExecutionTrace,
    /// Total gas consumed (before refunds).
    pub gas_used: u64,
    /// Gas refund accumulated (e.g., from storage clearing).
    pub gas_refund: u64,
    /// Effective gas after applying refunds (capped at 50% of gas_used).
    pub effective_gas_used: u64,
    /// Total instructions executed.
    pub steps: u64,
    /// Output bytes written via WRITE_OUTPUT syscall.
    pub output: Vec<u8>,
    /// Event logs emitted via EMIT_LOG syscall.
    pub logs: Vec<brrq_types::Log>,
}

/// The result of executing a single VM step.
pub enum StepResult {
    /// The VM halted normally with an exit code.
    Halted(u32),
    /// The VM yielded execution to perform an external contract call.
    YieldContractCall {
        to: brrq_types::Address,
        value: u64,
        calldata: Vec<u8>,
    },
    /// The VM yielded execution to perform a delegate call (preserves caller context and storage).
    YieldDelegateCall {
        to: brrq_types::Address,
        calldata: Vec<u8>,
    },
}

/// Represents the current execution state of the VM.
pub enum ExecutionState {
    /// The VM has halted execution normally.
    Halted(ExecutionResult),
    /// The VM yielded execution to perform an external contract call.
    YieldContractCall {
        to: brrq_types::Address,
        value: u64,
        calldata: Vec<u8>,
    },
    /// The VM yielded execution to perform a delegate call (preserves caller context and storage).
    YieldDelegateCall {
        to: brrq_types::Address,
        calldata: Vec<u8>,
    },
}

/// The RISC-V zkVM executor.
///
/// All fields are private (or `pub(crate)` for crate-internal testing).
/// External access is through the public getter methods below.
pub struct Executor {
    /// CPU state (crate-visible for trace/test access).
    pub(crate) cpu: Cpu,
    /// Memory subsystem (crate-visible for trace/test access).
    pub(crate) memory: Memory,
    /// Gas meter (crate-visible for trace/test access).
    pub(crate) gas: GasMeter,
    /// Whether to record execution trace.
    record_trace: bool,
    /// Maximum number of steps before halting.
    step_limit: u64,
    /// Output buffer (from WRITE_OUTPUT syscalls).
    output: Vec<u8>,
    /// Event logs emitted via EMIT_LOG syscall.
    logs: Vec<brrq_types::Log>,
    /// Contract address (set by the sequencer for log attribution).
    contract_address: Option<brrq_types::Address>,
    /// Optional storage provider for SLOAD/SSTORE syscalls.
    storage: Option<Box<dyn StorageProvider>>,
    /// Coprocessor trace accumulator
    pub(crate) coprocessor_trace: crate::trace::CoprocessorTrace,
    /// Caller address (msg.sender)
    caller: Option<brrq_types::Address>,
    /// Call value in native BRC (msg.value)
    msg_value: u64,
    /// Block height
    block_height: u64,
    /// Block timestamp
    block_timestamp: u64,
    /// Buffered native transfers (to, amount)
    native_transfers: Vec<(brrq_types::Address, u64)>,
    /// Buffer for the return data of the last external call
    return_data: Vec<u8>,
    /// Accumulated execution trace
    trace: crate::trace::ExecutionTrace,
}

impl Executor {
    /// Create a new executor.
    ///
    /// - `code`: RISC-V binary to execute
    /// - `gas_limit`: Maximum gas allowed
    /// - `step_limit`: Maximum instructions to execute (safety bound)
    pub fn new(code: &[u8], gas_limit: u64, step_limit: u64) -> Result<Self, VmError> {
        // Note: MIN_GAS_LIMIT validation is intentionally NOT done here.
        // The Executor receives post-intrinsic gas from the sequencer (e.g.
        // tx.gas_limit - 21_000). Enforcing MIN_GAS_LIMIT at the VM level
        // would reject valid transactions where most gas went to intrinsic
        // cost. Use gas_meter::validate_gas_limit() at the transaction
        // validation layer instead.

        let mut memory = Memory::new();
        memory.load_code(code)?;
        Ok(Self {
            cpu: Cpu::new(0),
            memory,
            gas: GasMeter::new(gas_limit),
            record_trace: false,
            step_limit,
            output: Vec::new(),
            logs: Vec::new(),
            contract_address: None,
            storage: None,
            coprocessor_trace: Default::default(),
            caller: None,
            msg_value: 0,
            block_height: 0,
            block_timestamp: 0,
            native_transfers: Vec::new(),
            return_data: Vec::new(),
            trace: crate::trace::ExecutionTrace::new(),
        })
    }

    /// Enable execution trace recording.
    pub fn enable_trace(&mut self) {
        self.record_trace = true;
    }

    /// Set the contract address for log attribution.
    ///
    /// When a contract emits logs via EMIT_LOG, this address is used
    /// as the `log.address` field. Should be called by the sequencer
    /// before executing a contract call.
    pub fn set_contract_address(&mut self, address: brrq_types::Address) {
        self.contract_address = Some(address);
    }

    /// Set caller context
    pub fn set_caller(&mut self, caller: brrq_types::Address) {
        self.caller = Some(caller);
    }

    /// Set message value context
    pub fn set_msg_value(&mut self, value: u64) {
        self.msg_value = value;
    }

    /// Set block context
    pub fn set_block_context(&mut self, height: u64, timestamp: u64) {
        self.block_height = height;
        self.block_timestamp = timestamp;
    }

    /// Retrieve and clear buffered native transfers
    pub fn take_native_transfers(&mut self) -> Vec<(brrq_types::Address, u64)> {
        std::mem::take(&mut self.native_transfers)
    }

    /// Set the storage provider for SLOAD/SSTORE syscalls.
    ///
    /// The provider bridges VM storage operations to the world state.
    /// Should be called by the sequencer before executing a contract call.
    pub fn set_storage(&mut self, provider: Box<dyn StorageProvider>) {
        self.storage = Some(provider);
    }

    /// Take the storage provider back from the executor.
    ///
    /// Used after `run()` completes to retrieve buffered storage writes
    /// for application to the world state.
    pub fn take_storage(&mut self) -> Option<Box<dyn StorageProvider>> {
        self.storage.take()
    }

    /// Set initial register values (e.g., function arguments).
    ///
    /// Returns error if `reg >= 32` instead of panicking.
    pub fn set_reg(&mut self, reg: u8, value: u32) -> Result<(), VmError> {
        if reg >= 32 {
            return Err(VmError::InvalidRegister { reg });
        }
        self.cpu.write_reg(reg, value);
        Ok(())
    }

    /// Get the total gas used so far.
    pub fn gas_used(&self) -> u64 {
        self.gas.used()
    }

    /// Consume raw gas units (used by sequencer for sub-call accounting).
    pub fn consume_gas(&mut self, amount: u64) -> Result<(), VmError> {
        self.gas.consume_raw(amount)
    }

    /// Get a reference to the CPU state (read-only).
    pub fn cpu(&self) -> &Cpu {
        &self.cpu
    }

    /// Get a reference to the coprocessor trace (read-only).
    pub fn coprocessor_trace(&self) -> &crate::trace::CoprocessorTrace {
        &self.coprocessor_trace
    }

    /// Get the caller address.
    pub fn caller(&self) -> Option<brrq_types::Address> {
        self.caller
    }

    /// Get the message value.
    pub fn msg_value(&self) -> u64 {
        self.msg_value
    }

    /// Get the block height.
    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Get the block timestamp.
    pub fn block_timestamp(&self) -> u64 {
        self.block_timestamp
    }

    /// Get a reference to native transfers.
    pub fn native_transfers(&self) -> &[(brrq_types::Address, u64)] {
        &self.native_transfers
    }

    /// Get a reference to the return data buffer.
    pub fn return_data(&self) -> &[u8] {
        &self.return_data
    }

    /// Get a reference to the execution trace.
    pub fn trace(&self) -> &crate::trace::ExecutionTrace {
        &self.trace
    }

    /// Write data to memory at the given address.
    pub fn write_memory(&mut self, addr: u32, data: &[u8]) -> Result<(), VmError> {
        for (i, &byte) in data.iter().enumerate() {
            self.memory.write_byte(addr.wrapping_add(i as u32), byte)?;
        }
        Ok(())
    }

    /// Run the VM until halt, out of gas, or step limit.
    ///
    /// # Rollback Requirement
    /// Any `VmError` returned from this method means the instruction's side effects
    /// (register writes, memory writes) may have already occurred. The caller MUST
    /// discard all state changes on error. This is by design: memory expansion cost
    /// cannot be known until after the instruction executes.
    pub fn run(&mut self) -> Result<ExecutionState, VmError> {
        // We accumulate into self.trace instead of a local variable
        if self.record_trace && self.trace.steps.capacity() == 0 {
            self.trace =
                crate::trace::ExecutionTrace::with_capacity(self.step_limit.min(1_024) as usize);
        }

        loop {
            // Check step limit
            if self.cpu.cycle_count >= self.step_limit {
                return Err(VmError::StepLimitExceeded {
                    limit: self.step_limit,
                });
            }

            // Fetch
            let pc = self.cpu.pc;
            let word = self.memory.fetch_instruction(pc)?;

            // Decode
            let inst = decoder::decode(word, pc)?;

            // Gas check — skip base charge for ECALL/System instructions since
            // syscall handlers (handle_sload, handle_sstore, etc.) charge their own gas.
            if !matches!(inst, Instruction::System { .. }) {
                self.gas.consume(&inst)?;
            }

            // Record pre-state
            let regs_before = if self.record_trace {
                *self.cpu.registers()
            } else {
                [0u32; 32]
            };

            let step_num = self.cpu.cycle_count;

            // Execute
            let mut mem_accesses = Vec::new();
            let result = self.execute_instruction(&inst, &mut mem_accesses)?;

            // Charge EVM-style memory expansion gas (Quadratic)
            let words = self.memory.active_data_words();
            self.gas.charge_memory_expansion(words)?;

            // Record post-state
            if self.record_trace {
                let gas_cost = if matches!(inst, Instruction::System { .. }) {
                    0 // syscall handlers charge their own gas
                } else {
                    GasMeter::instruction_cost(&inst)
                };
                // record() returns Err if trace capacity
                // exceeded. Treat as OutOfGas — halt VM, revert state, burn gas.
                if let Err(_) = self.trace.record(TraceStep {
                    step: step_num,
                    pc,
                    instruction: inst,
                    instruction_word: word,
                    regs_before,
                    regs_after: *self.cpu.registers(),
                    next_pc: self.cpu.pc,
                    memory_accesses: mem_accesses,
                    gas_cost,
                    gas_used: self.gas.used(),
                }) {
                    self.trace.mark_completed();
                    return Err(VmError::TraceCapacityExceeded {
                        rows: self.trace.len(),
                        max: ExecutionTrace::MAX_TRACE_ROWS,
                    });
                }
            }

            self.cpu.tick();

            if let Some(step_result) = result {
                self.trace.mark_completed();
                if self.record_trace {
                    self.trace.coprocessor = std::mem::take(&mut self.coprocessor_trace);
                }

                match step_result {
                    StepResult::Halted(exit_code) => {
                        return Ok(ExecutionState::Halted(ExecutionResult {
                            exit_code,
                            trace: std::mem::take(&mut self.trace),
                            gas_used: self.gas.used(),
                            gas_refund: self.gas.refund(),
                            effective_gas_used: self.gas.effective_gas_used(),
                            steps: self.cpu.cycle_count,
                            output: std::mem::take(&mut self.output),
                            logs: std::mem::take(&mut self.logs),
                        }));
                    }
                    StepResult::YieldContractCall {
                        to,
                        value,
                        calldata,
                    } => {
                        return Ok(ExecutionState::YieldContractCall {
                            to,
                            value,
                            calldata,
                        });
                    }
                    StepResult::YieldDelegateCall { to, calldata } => {
                        return Ok(ExecutionState::YieldDelegateCall {
                            to,
                            calldata,
                        });
                    }
                }
            }
        }
    }

    /// Resume the VM after an external contract call yields.
    /// `success` is true if the sub-call passed without reverting.
    /// `return_data` is the output data of the sub-contract, which can be queried.
    pub fn resume(
        &mut self,
        success: bool,
        return_data: Vec<u8>,
        sub_trace: Option<crate::trace::ExecutionTrace>,
    ) -> Result<ExecutionState, VmError> {
        if let Some(st) = sub_trace {
            if self.record_trace {
                self.trace.extend(&st);
            }
        }
        // Store the return data so SYS_RETURN_DATA_SIZE and SYS_RETURN_DATA_COPY can access it
        self.return_data = return_data;
        // The return value of SYS_CALL is the success flag
        let result = if success { 1u32 } else { 0u32 };
        self.cpu.write_reg(10, result);
        self.cpu.advance_pc();
        // Since we resumed, we must execute the next step right away to pick
        // up exactly where the CPU left off.
        self.run()
    }

    /// Handle SLOAD syscall: read a storage slot.
    ///
    /// ## Calling Convention
    ///
    /// - a0 (x10) = key_ptr (32 bytes in memory)
    /// - a1 (x11) = output_ptr (32 bytes output buffer)
    /// - Returns: a0 = 1 if slot exists, 0 if empty
    fn handle_sload(&mut self) -> Result<(), VmError> {
        self.gas.consume_raw(precompiles::precompile_gas::SLOAD)?;

        let key_ptr = self.cpu.read_reg(10);
        let out_ptr = self.cpu.read_reg(11);

        // Read 32-byte key from memory
        let mut key_bytes = [0u8; 32];
        for (i, byte) in key_bytes.iter_mut().enumerate() {
            *byte = self.memory.read_byte(key_ptr.wrapping_add(i as u32))?;
        }
        let key = brrq_crypto::hash::Hash256::from_bytes(key_bytes);

        // Query storage provider
        let (value, exists) = if let Some(storage) = &self.storage {
            match storage.storage_get(&key) {
                Some(v) => (v, 1u32),
                None => (brrq_crypto::hash::Hash256::ZERO, 0u32),
            }
        } else {
            (brrq_crypto::hash::Hash256::ZERO, 0u32)
        };

        // Write 32-byte value to output memory
        for (i, &b) in value.as_bytes().iter().enumerate() {
            self.memory.write_byte(out_ptr.wrapping_add(i as u32), b)?;
        }

        self.cpu.write_reg(10, exists);
        self.cpu.advance_pc();
        Ok(())
    }

    /// Handle SSTORE syscall: write a storage slot.
    ///
    /// ## Calling Convention
    ///
    /// - a0 (x10) = key_ptr (32 bytes in memory)
    /// - a1 (x11) = value_ptr (32 bytes in memory)
    /// - Returns: a0 = 0 on success
    ///
    /// ## Gas Model
    ///
    /// - New slot (init):      20,000 gas
    /// - Overwrite existing:    5,000 gas
    /// - Clear (write zero to non-zero): 5,000 gas + 4,800 refund
    ///
    /// Refunds are capped at 50% of total gas used at execution end (EIP-3529 style).
    fn handle_sstore(&mut self) -> Result<(), VmError> {
        let key_ptr = self.cpu.read_reg(10);
        let val_ptr = self.cpu.read_reg(11);

        // Read 32-byte key from memory
        let mut key_bytes = [0u8; 32];
        for (i, byte) in key_bytes.iter_mut().enumerate() {
            *byte = self.memory.read_byte(key_ptr.wrapping_add(i as u32))?;
        }

        // Read 32-byte value from memory
        let mut val_bytes = [0u8; 32];
        for (i, byte) in val_bytes.iter_mut().enumerate() {
            *byte = self.memory.read_byte(val_ptr.wrapping_add(i as u32))?;
        }

        let key = brrq_crypto::hash::Hash256::from_bytes(key_bytes);
        let value = brrq_crypto::hash::Hash256::from_bytes(val_bytes);
        let is_zero_value = value == brrq_crypto::hash::Hash256::ZERO;

        // Charge minimum gas BEFORE the storage read side-effect (match handle_sload pattern).
        // This prevents an attacker from causing storage reads without paying gas.
        self.gas
            .consume_raw(precompiles::precompile_gas::SSTORE_OVERWRITE_GAS)?;

        // Query existing value for refund calculation
        let existing = if let Some(storage) = &self.storage {
            storage.storage_get(&key)
        } else {
            None
        };

        let is_new_slot = existing.is_none();

        // Charge additional gas for new slot initialization
        if is_new_slot {
            let extra =
                precompiles::precompile_gas::SSTORE_INIT_GAS - precompiles::precompile_gas::SSTORE_OVERWRITE_GAS;
            self.gas.consume_raw(extra)?;
        }

        // Grant refund if clearing an existing non-zero slot
        if !is_new_slot
            && is_zero_value
            && existing.is_some_and(|v| v != brrq_crypto::hash::Hash256::ZERO)
        {
            self.gas
                .add_refund(precompiles::precompile_gas::SSTORE_CLEAR_REFUND);
        }

        // Write to storage provider
        if let Some(storage) = &mut self.storage {
            storage.storage_set(key, value);
        }

        self.cpu.write_reg(10, 0); // success
        self.cpu.advance_pc();
        Ok(())
    }

    /// Handle ECALL (system call) instruction dispatch.
    ///
    /// Routes the syscall number (a7/x17) to the appropriate handler:
    /// built-in storage/environment syscalls, or general precompile dispatch.
    fn handle_ecall(&mut self) -> Result<Option<StepResult>, VmError> {
        let syscall_num = self.cpu.read_reg(17); // a7

        // Handle storage syscalls (need &mut self.storage,
        // so they're handled here rather than in precompiles)
        // Each syscall charges its own gas *before* execution.
        // System instructions are excluded from the base gas charge
        // to avoid double-charging; all gas is metered within each handler.
        match syscall_num {
            precompiles::syscalls::SLOAD => {
                self.handle_sload()?;
                return Ok(None);
            }
            precompiles::syscalls::SSTORE => {
                self.handle_sstore()?;
                return Ok(None);
            }
            0x200 => {
                // SYS_BLOCK_HEIGHT (DEPRECATED — truncates u64 to u32)
                // Use SYS_BLOCK_HEIGHT_64 (0x208) for full 64-bit value.
                // 100 gas for environment read.
                self.gas.consume_raw(100)?;
                self.cpu.write_reg(10, self.block_height as u32);
                self.cpu.advance_pc();
                return Ok(None);
            }
            0x201 => {
                // SYS_BLOCK_TIMESTAMP (DEPRECATED — truncates u64 to u32)
                // Use SYS_BLOCK_TIMESTAMP_64 (0x209) for full 64-bit value.
                // 100 gas for environment read.
                self.gas.consume_raw(100)?;
                self.cpu.write_reg(10, self.block_timestamp as u32);
                self.cpu.advance_pc();
                return Ok(None);
            }
            0x208 => {
                // SYS_BLOCK_HEIGHT_64: preferred replacement for 0x200.
                // Writes full u64 block height to memory (little-endian).
                // a0 = destination pointer (8 bytes). Returns: a0 = 0.
                self.gas.consume_raw(100)?;
                let dest_ptr = self.cpu.read_reg(10);
                self.memory
                    .write_bytes(dest_ptr, &self.block_height.to_le_bytes())?;
                self.cpu.write_reg(10, 0);
                self.cpu.advance_pc();
                return Ok(None);
            }
            0x209 => {
                // SYS_BLOCK_TIMESTAMP_64: preferred replacement for 0x201.
                // Writes full u64 block timestamp to memory (little-endian).
                // a0 = destination pointer (8 bytes). Returns: a0 = 0.
                self.gas.consume_raw(100)?;
                let dest_ptr = self.cpu.read_reg(10);
                self.memory
                    .write_bytes(dest_ptr, &self.block_timestamp.to_le_bytes())?;
                self.cpu.write_reg(10, 0);
                self.cpu.advance_pc();
                return Ok(None);
            }
            0x20A => {
                // SYS_DELEGATE_CALL: call another contract preserving caller context and storage.
                // a0 = to_ptr (20 bytes), a1 = calldata_ptr, a2 = calldata_len.
                let to_ptr = self.cpu.read_reg(10);
                let calldata_ptr = self.cpu.read_reg(11);
                let calldata_len = self.cpu.read_reg(12).min(1024 * 1024) as usize;

                let calldata_words = ((calldata_len as u64) + 31) / 32;
                let call_gas = 700u64 + calldata_words.saturating_mul(3);
                self.gas.consume_raw(call_gas)?;

                let mut to_bytes = [0u8; 20];
                self.memory.read_bytes(to_ptr, &mut to_bytes)?;
                let to = brrq_types::Address::from_bytes(to_bytes);

                let mut calldata = vec![0u8; calldata_len];
                self.memory.read_bytes(calldata_ptr, &mut calldata)?;

                return Ok(Some(StepResult::YieldDelegateCall { to, calldata }));
            }
            0x202 => {
                // SYS_CALLER: writes 20-byte caller address to memory.
                // If no caller is set (e.g. top-level transaction), writes
                // 20 zero bytes. Gas: 100 (environment read + memory write).
                self.gas.consume_raw(100)?;
                let dest_ptr = self.cpu.read_reg(10);
                match self.caller {
                    Some(caller) => self.memory.write_bytes(dest_ptr, caller.as_bytes())?,
                    None => self.memory.write_bytes(dest_ptr, &[0u8; 20])?,
                }
                self.cpu.advance_pc();
                return Ok(None);
            }
            0x203 => {
                // SYS_MSG_VALUE
                // 100 gas for environment read + 8-byte memory write.
                self.gas.consume_raw(100)?;
                let dest_ptr = self.cpu.read_reg(10);
                self.memory
                    .write_bytes(dest_ptr, &self.msg_value.to_le_bytes())?;
                self.cpu.advance_pc();
                return Ok(None);
            }
            0x204 => {
                // SYS_NATIVE_TRANSFER
                // 2300 gas (Ethereum CALL stipend); value transfers
                // are expensive state-mutating operations.
                self.gas.consume_raw(2300)?;
                let to_ptr = self.cpu.read_reg(10);
                let amt_ptr = self.cpu.read_reg(11);
                let mut to_bytes = [0u8; 20];
                self.memory.read_bytes(to_ptr, &mut to_bytes)?;
                let mut amt_bytes = [0u8; 8];
                self.memory.read_bytes(amt_ptr, &mut amt_bytes)?;
                let amt = u64::from_le_bytes(amt_bytes);
                let to = brrq_types::Address::from_bytes(to_bytes);
                self.native_transfers.push((to, amt));
                self.cpu.advance_pc();
                return Ok(None);
            }
            0x205 => {
                // SYS_CALL
                let to_ptr = self.cpu.read_reg(10);
                let val_ptr = self.cpu.read_reg(11);
                let calldata_ptr = self.cpu.read_reg(12);
                let calldata_len = self.cpu.read_reg(13).min(1024 * 1024) as usize;

                // 700 base gas + 3 gas per 32-byte word of calldata.
                // Cross-contract calls are expensive; calldata copy scales linearly.
                let calldata_words = ((calldata_len as u64) + 31) / 32;
                let call_gas = 700u64 + calldata_words.saturating_mul(3);
                self.gas.consume_raw(call_gas)?;

                let mut to_bytes = [0u8; 20];
                self.memory.read_bytes(to_ptr, &mut to_bytes)?;
                let to = brrq_types::Address::from_bytes(to_bytes);

                let mut val_bytes = [0u8; 8];
                self.memory.read_bytes(val_ptr, &mut val_bytes)?;
                let value = u64::from_le_bytes(val_bytes);

                let mut calldata = vec![0u8; calldata_len];
                self.memory.read_bytes(calldata_ptr, &mut calldata)?;

                return Ok(Some(StepResult::YieldContractCall {
                    to,
                    value,
                    calldata,
                }));
            }
            0x206 => {
                // SYS_RETURN_DATA_SIZE
                // 100 gas for lightweight metadata query.
                self.gas.consume_raw(100)?;
                self.cpu.write_reg(10, self.return_data.len() as u32);
                self.cpu.advance_pc();
                return Ok(None);
            }
            0x207 => {
                // SYS_RETURN_DATA_COPY
                let dest_ptr = self.cpu.read_reg(10);
                let len = self.cpu.read_reg(11) as usize;
                // 3 gas per 32-byte word copied (like RETURNDATACOPY).
                let copy_words = ((len as u64) + 31) / 32;
                let copy_gas = copy_words.saturating_mul(3);
                self.gas.consume_raw(copy_gas)?;
                // We copy at most `return_data.len()` bytes, capping at `len` parameter.
                let copy_len = len.min(self.return_data.len());
                if copy_len > 0 {
                    self.memory
                        .write_bytes(dest_ptr, &self.return_data[..copy_len])?;
                }
                self.cpu.advance_pc();
                return Ok(None);
            }
            _ => {} // Fall through to precompile dispatch
        }

        // Pass current CPU step counter to bind coprocessor
        // operations to their execution point.
        let cpu_step = self.cpu.cycle_count;
        let result = precompiles::execute_precompile(
            syscall_num,
            &mut self.cpu,
            &mut self.memory,
            &mut self.gas,
            &mut self.output,
            &mut self.coprocessor_trace,
            cpu_step,
        )?;
        match result {
            PrecompileResult::Continue => {
                self.cpu.advance_pc();
            }
            PrecompileResult::Halt(exit_code) => {
                return Ok(Some(StepResult::Halted(exit_code)));
            }
            PrecompileResult::EmitLog(mut log) => {
                // Set the contract address if available
                if let Some(addr) = self.contract_address {
                    log.address = addr;
                }
                self.logs.push(log);
                self.cpu.advance_pc();
            }
        }
        Ok(None)
    }

    /// Execute a single instruction. Returns Some(StepResult) if halted or yielded.
    fn execute_instruction(
        &mut self,
        inst: &Instruction,
        mem_accesses: &mut Vec<MemoryAccess>,
    ) -> Result<Option<StepResult>, VmError> {
        match *inst {
            // --- U-type ---
            Instruction::Lui { rd, imm } => {
                self.cpu.write_reg(rd, imm);
                self.cpu.advance_pc();
            }

            Instruction::Auipc { rd, imm } => {
                let result = self.cpu.pc.wrapping_add(imm);
                self.cpu.write_reg(rd, result);
                self.cpu.advance_pc();
            }

            // --- J-type ---
            Instruction::Jal { rd, offset } => {
                let return_addr = self.cpu.pc.wrapping_add(4);
                self.cpu.write_reg(rd, return_addr);
                let target = (self.cpu.pc as i32).wrapping_add(offset) as u32;
                self.cpu.set_pc(target)?;
            }

            // --- I-type (JALR) ---
            // Verified correct per RISC-V ISA §2.5: JALR computes (rs1 + imm)
            // with bit 0 cleared (&!1), then set_pc() enforces 4-byte alignment
            // (no C extension). Misaligned targets raise UnalignedAccess.
            Instruction::Jalr { rd, rs1, offset } => {
                let return_addr = self.cpu.pc.wrapping_add(4);
                let base = self.cpu.read_reg(rs1) as i32;
                // RISC-V ISA §2.5: Set lowest bit to 0.
                let target = (base.wrapping_add(offset) as u32) & !1;
                // set_pc enforces 4-byte alignment (no C extension).
                // Validate alignment BEFORE writing rd so that a misaligned
                // target does not corrupt the return-address register.
                self.cpu.set_pc(target)?;
                self.cpu.write_reg(rd, return_addr);
            }

            // --- B-type ---
            Instruction::Branch {
                func,
                rs1,
                rs2,
                offset,
            } => {
                let v1 = self.cpu.read_reg(rs1);
                let v2 = self.cpu.read_reg(rs2);
                let taken = match func {
                    BranchFunc::Beq => v1 == v2,
                    BranchFunc::Bne => v1 != v2,
                    BranchFunc::Blt => (v1 as i32) < (v2 as i32),
                    BranchFunc::Bge => (v1 as i32) >= (v2 as i32),
                    BranchFunc::Bltu => v1 < v2,
                    BranchFunc::Bgeu => v1 >= v2,
                };
                if taken {
                    let target = (self.cpu.pc as i32).wrapping_add(offset) as u32;
                    self.cpu.set_pc(target)?;
                } else {
                    self.cpu.advance_pc();
                }
            }

            // --- Load ---
            Instruction::Load {
                func,
                rd,
                rs1,
                offset,
            } => {
                let base = self.cpu.read_reg(rs1) as i32;
                let addr = base.wrapping_add(offset) as u32;
                let value = match func {
                    LoadFunc::Lb => {
                        let b = self.memory.read_byte(addr)?;
                        (b as i8) as i32 as u32 // sign-extend
                    }
                    LoadFunc::Lh => {
                        let h = self.memory.read_halfword(addr)?;
                        (h as i16) as i32 as u32 // sign-extend
                    }
                    LoadFunc::Lw => self.memory.read_word(addr)?,
                    LoadFunc::Lbu => self.memory.read_byte(addr)? as u32,
                    LoadFunc::Lhu => self.memory.read_halfword(addr)? as u32,
                };
                mem_accesses.push(MemoryAccess {
                    addr,
                    value,
                    kind: MemoryAccessKind::Read,
                });
                self.cpu.write_reg(rd, value);
                self.cpu.advance_pc();
            }

            // --- Store ---
            Instruction::Store {
                func,
                rs1,
                rs2,
                offset,
            } => {
                let base = self.cpu.read_reg(rs1) as i32;
                let addr = base.wrapping_add(offset) as u32;
                let value = self.cpu.read_reg(rs2);
                match func {
                    StoreFunc::Sb => {
                        self.memory.write_byte(addr, value as u8)?;
                    }
                    StoreFunc::Sh => {
                        self.memory.write_halfword(addr, value as u16)?;
                    }
                    StoreFunc::Sw => {
                        self.memory.write_word(addr, value)?;
                    }
                }
                mem_accesses.push(MemoryAccess {
                    addr,
                    value,
                    kind: MemoryAccessKind::Write,
                });
                self.cpu.advance_pc();
            }

            // --- ALU Immediate ---
            Instruction::AluImm { func, rd, rs1, imm } => {
                let src = self.cpu.read_reg(rs1);
                let result = match func {
                    AluImmFunc::Addi => src.wrapping_add(imm as u32),
                    AluImmFunc::Slti => {
                        if (src as i32) < imm {
                            1
                        } else {
                            0
                        }
                    }
                    AluImmFunc::Sltiu => {
                        if src < (imm as u32) {
                            1
                        } else {
                            0
                        }
                    }
                    AluImmFunc::Xori => src ^ (imm as u32),
                    AluImmFunc::Ori => src | (imm as u32),
                    AluImmFunc::Andi => src & (imm as u32),
                    AluImmFunc::Slli => src << (imm as u32 & 0x1F),
                    AluImmFunc::Srli => src >> (imm as u32 & 0x1F),
                    AluImmFunc::Srai => ((src as i32) >> (imm as u32 & 0x1F)) as u32,
                };
                self.cpu.write_reg(rd, result);
                self.cpu.advance_pc();
            }

            // --- ALU Register ---
            Instruction::AluReg { func, rd, rs1, rs2 } => {
                let v1 = self.cpu.read_reg(rs1);
                let v2 = self.cpu.read_reg(rs2);
                let result = match func {
                    // RV32I base
                    AluRegFunc::Add => v1.wrapping_add(v2),
                    AluRegFunc::Sub => v1.wrapping_sub(v2),
                    AluRegFunc::Sll => v1 << (v2 & 0x1F),
                    AluRegFunc::Slt => {
                        if (v1 as i32) < (v2 as i32) {
                            1
                        } else {
                            0
                        }
                    }
                    AluRegFunc::Sltu => {
                        if v1 < v2 {
                            1
                        } else {
                            0
                        }
                    }
                    AluRegFunc::Xor => v1 ^ v2,
                    AluRegFunc::Srl => v1 >> (v2 & 0x1F),
                    AluRegFunc::Sra => ((v1 as i32) >> (v2 & 0x1F)) as u32,
                    AluRegFunc::Or => v1 | v2,
                    AluRegFunc::And => v1 & v2,

                    // RV32M extension
                    AluRegFunc::Mul => v1.wrapping_mul(v2),
                    AluRegFunc::Mulh => {
                        let result = (v1 as i32 as i64).wrapping_mul(v2 as i32 as i64);
                        (result >> 32) as u32
                    }
                    AluRegFunc::Mulhsu => {
                        let result = (v1 as i32 as i64).wrapping_mul(v2 as u64 as i64);
                        (result >> 32) as u32
                    }
                    AluRegFunc::Mulhu => {
                        let result = (v1 as u64).wrapping_mul(v2 as u64);
                        (result >> 32) as u32
                    }
                    AluRegFunc::Div => {
                        if v2 == 0 {
                            // RISC-V spec: div by zero returns -1 (all ones)
                            u32::MAX
                        } else if v1 as i32 == i32::MIN && v2 as i32 == -1 {
                            // Overflow: MIN / -1
                            v1
                        } else {
                            ((v1 as i32).wrapping_div(v2 as i32)) as u32
                        }
                    }
                    #[allow(clippy::manual_checked_ops)]
                    AluRegFunc::Divu => {
                        // RISC-V spec: divu by zero returns u32::MAX.
                        if v2 == 0 { u32::MAX } else { v1 / v2 }
                    }
                    AluRegFunc::Rem => {
                        if v2 == 0 {
                            // RISC-V spec: rem by zero returns dividend
                            v1
                        } else if v1 as i32 == i32::MIN && v2 as i32 == -1 {
                            0
                        } else {
                            ((v1 as i32).wrapping_rem(v2 as i32)) as u32
                        }
                    }
                    AluRegFunc::Remu => {
                        if v2 == 0 {
                            v1
                        } else {
                            v1 % v2
                        }
                    }
                };
                self.cpu.write_reg(rd, result);
                self.cpu.advance_pc();
            }

            // --- FENCE (NOP in zkVM) ---
            Instruction::Fence => {
                self.cpu.advance_pc();
            }

            // --- System ---
            Instruction::System { func } => {
                match func {
                    SystemFunc::Ecall => {
                        return self.handle_ecall();
                    }
                    SystemFunc::Ebreak => {
                        // EBREAK: halt with special code
                        self.gas
                            .consume_raw(precompiles::precompile_gas::EBREAK)?;
                        return Ok(Some(StepResult::Halted(0xFFFFFFFF)));
                    }
                }
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
impl Executor {
    pub fn run_to_halt(&mut self) -> Result<ExecutionResult, VmError> {
        match self.run()? {
            ExecutionState::Halted(res) => Ok(res),
            ExecutionState::YieldContractCall { .. }
            | ExecutionState::YieldDelegateCall { .. } => {
                panic!("Expected Halted but got YieldContractCall/YieldDelegateCall")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: encode an R-type instruction.
    fn r_type(funct7: u32, rs2: u32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    /// Helper: encode an I-type instruction.
    fn i_type(imm: i32, rs1: u32, funct3: u32, rd: u32, opcode: u32) -> u32 {
        (((imm as u32) & 0xFFF) << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode
    }

    /// Helper: encode a U-type instruction.
    fn u_type(imm: u32, rd: u32, opcode: u32) -> u32 {
        (imm & 0xFFFFF000) | (rd << 7) | opcode
    }

    /// Helper: encode a system instruction.
    fn sys_type(imm: u32) -> u32 {
        (imm << 20) | 0b1110011
    }

    /// Helper: assemble instruction words into bytes.
    fn assemble(instructions: &[u32]) -> Vec<u8> {
        instructions.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    const OP_IMM: u32 = 0b0010011;
    const OP: u32 = 0b0110011;
    const LUI: u32 = 0b0110111;

    #[test]
    fn test_addi() {
        // ADDI x1, x0, 42
        // ECALL (HALT with a0=x1 value... we need to set a7=0 for halt)
        // Actually: ADDI x10, x0, 42 → set a0
        // ADDI x17, x0, 0 → set a7 = HALT
        // ECALL
        let code = assemble(&[
            i_type(42, 0, 0b000, 10, OP_IMM), // ADDI x10, x0, 42
            i_type(0, 0, 0b000, 17, OP_IMM),  // ADDI x17, x0, 0 (HALT syscall)
            sys_type(0),                      // ECALL
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 42); // HALT returns a0=42
    }

    #[test]
    fn test_add_two_registers() {
        // ADDI x1, x0, 10
        // ADDI x2, x0, 20
        // ADD  x10, x1, x2  → x10 = 30
        // ADDI x17, x0, 0   → HALT
        // ECALL
        let code = assemble(&[
            i_type(10, 0, 0b000, 1, OP_IMM), // ADDI x1, x0, 10
            i_type(20, 0, 0b000, 2, OP_IMM), // ADDI x2, x0, 20
            r_type(0, 2, 1, 0b000, 10, OP),  // ADD x10, x1, x2
            i_type(0, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0
            sys_type(0),                     // ECALL
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 30);
    }

    #[test]
    fn test_sub() {
        // ADDI x1, x0, 100
        // ADDI x2, x0, 37
        // SUB  x10, x1, x2  → x10 = 63
        // ADDI x17, x0, 0
        // ECALL
        let code = assemble(&[
            i_type(100, 0, 0b000, 1, OP_IMM),
            i_type(37, 0, 0b000, 2, OP_IMM),
            r_type(0b0100000, 2, 1, 0b000, 10, OP), // SUB
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 63);
    }

    #[test]
    fn test_lui() {
        // LUI x10, 0x12345000
        // ADDI x17, x0, 0
        // ECALL
        let code = assemble(&[
            u_type(0x12345000, 10, LUI),
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0x12345000);
    }

    #[test]
    fn test_mul() {
        // ADDI x1, x0, 7
        // ADDI x2, x0, 6
        // MUL  x10, x1, x2  → x10 = 42
        // ADDI x17, x0, 0
        // ECALL
        let code = assemble(&[
            i_type(7, 0, 0b000, 1, OP_IMM),
            i_type(6, 0, 0b000, 2, OP_IMM),
            r_type(0b0000001, 2, 1, 0b000, 10, OP), // MUL
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 42);
    }

    #[test]
    fn test_div_by_zero() {
        // ADDI x1, x0, 42
        // ADDI x2, x0, 0
        // DIV  x10, x1, x2  → x10 = 0xFFFFFFFF (RISC-V spec)
        // ADDI x17, x0, 0
        // ECALL
        let code = assemble(&[
            i_type(42, 0, 0b000, 1, OP_IMM),
            i_type(0, 0, 0b000, 2, OP_IMM),
            r_type(0b0000001, 2, 1, 0b100, 10, OP), // DIV
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0xFFFFFFFF);
    }

    #[test]
    fn test_x0_immutable() {
        // ADDI x0, x0, 42  → x0 stays 0
        // ADD  x10, x0, x0 → x10 = 0
        // ADDI x17, x0, 0
        // ECALL
        let code = assemble(&[
            i_type(42, 0, 0b000, 0, OP_IMM), // ADDI x0, x0, 42 → ignored
            r_type(0, 0, 0, 0b000, 10, OP),  // ADD x10, x0, x0 → 0
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn test_logical_ops() {
        // ADDI x1, x0, 0xFF
        // ANDI x10, x1, 0x0F → x10 = 0x0F = 15
        // ADDI x17, x0, 0
        // ECALL
        let code = assemble(&[
            i_type(0xFF, 0, 0b000, 1, OP_IMM),  // ADDI x1, x0, 0xFF
            i_type(0x0F, 1, 0b111, 10, OP_IMM), // ANDI x10, x1, 0x0F
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 15);
    }

    #[test]
    fn test_shift_left() {
        // ADDI x1, x0, 1
        // SLLI x10, x1, 4  → x10 = 16
        // ADDI x17, x0, 0
        // ECALL
        let code = assemble(&[
            i_type(1, 0, 0b000, 1, OP_IMM),
            r_type(0b0000000, 4, 1, 0b001, 10, OP_IMM), // SLLI
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 16);
    }

    #[test]
    fn test_gas_tracking() {
        // Two ADDIs + ECALL
        let code = assemble(&[
            i_type(42, 0, 0b000, 10, OP_IMM),
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.gas_used, 428);
        assert_eq!(result.exit_code, 42);
    }

    #[test]
    fn test_out_of_gas() {
        // Many ADDIs, very low gas limit
        let code = assemble(&[
            i_type(1, 0, 0b000, 1, OP_IMM),
            i_type(1, 0, 0b000, 1, OP_IMM),
            i_type(1, 0, 0b000, 1, OP_IMM),
            i_type(1, 0, 0b000, 1, OP_IMM),
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 3, 100).unwrap();
        let result = exec.run_to_halt();
        assert!(result.is_err(), "Should fail with out-of-gas error");
    }

    #[test]
    fn test_trace_recording() {
        let code = assemble(&[
            i_type(42, 0, 0b000, 10, OP_IMM),
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        exec.enable_trace();
        let result = exec.run_to_halt().unwrap();
        assert!(result.trace.completed);
        assert_eq!(result.trace.len(), 3); // 2 ADDIs + ECALL
        assert!(result.trace.verify_consistency());
        assert_eq!(result.exit_code, 42);
    }

    #[test]
    fn test_ebreak_halts() {
        let code = assemble(&[
            i_type(42, 0, 0b000, 10, OP_IMM),
            sys_type(1), // EBREAK
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0xFFFFFFFF);
    }

    #[test]
    fn test_write_output() {
        // Store "Hi" to memory, then write_output syscall
        // We'll use set_reg and write_memory directly
        let code = assemble(&[
            // Set a7=1 (WRITE_OUTPUT), a0=addr, a1=len
            i_type(1, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 1 (WRITE_OUTPUT)
            // We'll set a0 and a1 via set_reg before run
            sys_type(0),                     // ECALL
            i_type(0, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0 (HALT)
            sys_type(0),                     // ECALL
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        // Write "Hi" to data memory (after code)
        let data_addr = (code.len() as u32 + 3) & !3; // align
        exec.write_memory(data_addr, b"Hi").unwrap();
        exec.set_reg(10, data_addr).unwrap(); // a0 = buffer address
        exec.set_reg(11, 2).unwrap(); // a1 = length
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.output, b"Hi");
    }

    // ── SLOAD/SSTORE tests ──────────────────────────────────────────

    /// Simple in-memory storage provider for testing.
    struct TestStorageProvider {
        data: std::collections::HashMap<brrq_crypto::hash::Hash256, brrq_crypto::hash::Hash256>,
    }

    impl TestStorageProvider {
        fn new() -> Self {
            Self {
                data: std::collections::HashMap::new(),
            }
        }

        fn with_entry(
            mut self,
            key: brrq_crypto::hash::Hash256,
            value: brrq_crypto::hash::Hash256,
        ) -> Self {
            self.data.insert(key, value);
            self
        }
    }

    impl StorageProvider for TestStorageProvider {
        fn storage_get(
            &self,
            key: &brrq_crypto::hash::Hash256,
        ) -> Option<brrq_crypto::hash::Hash256> {
            self.data.get(key).copied()
        }

        fn storage_set(
            &mut self,
            key: brrq_crypto::hash::Hash256,
            value: brrq_crypto::hash::Hash256,
        ) {
            self.data.insert(key, value);
        }

        fn drain_writes(
            &mut self,
        ) -> Vec<(brrq_crypto::hash::Hash256, brrq_crypto::hash::Hash256)> {
            self.data.drain().collect()
        }
    }

    #[test]
    fn test_sload_empty_storage() {
        // SLOAD with no storage provider → a0=0 (not found)
        // Set a7=0x105 (SLOAD), a0=key_ptr, a1=out_ptr, then HALT
        let code = assemble(&[
            i_type(0x105, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0x105 (SLOAD)
            // a0, a1 set via set_reg
            sys_type(0), // ECALL (SLOAD)
            // a0 now holds result (0 = not found)
            i_type(0, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0 (HALT)
            sys_type(0),                     // ECALL (HALT)
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let key_addr = 0x10000u32;
        let out_addr = 0x20000u32;
        // Write a 32-byte key to memory
        let key = brrq_crypto::hash::Hasher::hash(b"test_key");
        exec.write_memory(key_addr, key.as_bytes()).unwrap();
        exec.set_reg(10, key_addr).unwrap(); // a0 = key_ptr
        exec.set_reg(11, out_addr).unwrap(); // a1 = out_ptr

        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0); // SLOAD returns 0 in a0 (not found), then halt returns a0=0
    }

    #[test]
    fn test_sload_existing_key() {
        // SLOAD with a storage provider that has a pre-populated key
        let code = assemble(&[
            i_type(0x105, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0x105 (SLOAD)
            sys_type(0),                         // ECALL (SLOAD)
            // a0 = exists (1)
            i_type(0, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0 (HALT)
            sys_type(0),                     // ECALL (HALT) — exit code = a0
        ]);
        let key = brrq_crypto::hash::Hasher::hash(b"slot_0");
        let value = brrq_crypto::hash::Hasher::hash(b"value_0");

        let storage = TestStorageProvider::new().with_entry(key, value);

        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        exec.set_storage(Box::new(storage));

        let key_addr = 0x10000u32;
        let out_addr = 0x20000u32;
        exec.write_memory(key_addr, key.as_bytes()).unwrap();
        exec.set_reg(10, key_addr).unwrap();
        exec.set_reg(11, out_addr).unwrap();

        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 1); // exists = 1

        // Verify the output memory contains the correct value
        let mut read_value = [0u8; 32];
        for (i, byte) in read_value.iter_mut().enumerate() {
            *byte = exec.memory.read_byte(out_addr + i as u32).unwrap();
        }
        assert_eq!(read_value, *value.as_bytes());
    }

    #[test]
    fn test_sload_nonexistent_key() {
        let code = assemble(&[
            i_type(0x105, 0, 0b000, 17, OP_IMM), // SLOAD
            sys_type(0),
            i_type(0, 0, 0b000, 17, OP_IMM), // HALT
            sys_type(0),
        ]);
        // Storage with one key, but we query a different one
        let stored_key = brrq_crypto::hash::Hasher::hash(b"stored_key");
        let stored_val = brrq_crypto::hash::Hasher::hash(b"stored_val");
        let query_key = brrq_crypto::hash::Hasher::hash(b"missing_key");

        let storage = TestStorageProvider::new().with_entry(stored_key, stored_val);

        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        exec.set_storage(Box::new(storage));

        let key_addr = 0x10000u32;
        let out_addr = 0x20000u32;
        exec.write_memory(key_addr, query_key.as_bytes()).unwrap();
        exec.set_reg(10, key_addr).unwrap();
        exec.set_reg(11, out_addr).unwrap();

        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0); // not found → a0=0
    }

    #[test]
    fn test_sstore_write() {
        // SSTORE, then HALT. Check storage provider received the write.
        let code = assemble(&[
            i_type(0x106, 0, 0b000, 17, OP_IMM), // ADDI x17, x0, 0x106 (SSTORE)
            sys_type(0),                         // ECALL (SSTORE)
            i_type(0, 0, 0b000, 17, OP_IMM),     // HALT
            sys_type(0),
        ]);
        let storage = TestStorageProvider::new();
        let mut exec = Executor::new(&code, 50_000, 100).unwrap();
        exec.set_storage(Box::new(storage));

        let key = brrq_crypto::hash::Hasher::hash(b"write_key");
        let value = brrq_crypto::hash::Hasher::hash(b"write_value");

        let key_addr = 0x10000u32;
        let val_addr = 0x20000u32;
        exec.write_memory(key_addr, key.as_bytes()).unwrap();
        exec.write_memory(val_addr, value.as_bytes()).unwrap();
        exec.set_reg(10, key_addr).unwrap();
        exec.set_reg(11, val_addr).unwrap();

        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0); // success

        // Drain writes and verify
        let mut storage = exec.take_storage().unwrap();
        let writes = storage.drain_writes();
        assert_eq!(writes.len(), 1);
        let (k, v) = &writes[0];
        assert_eq!(*k, key);
        assert_eq!(*v, value);
    }

    #[test]
    fn test_sstore_then_sload() {
        // SSTORE(key, value), then SLOAD(key) → should return value
        let code = assemble(&[
            // SSTORE
            i_type(0x106, 0, 0b000, 17, OP_IMM), // a7 = SSTORE
            sys_type(0),                         // ECALL
            // Now set up for SLOAD: a0=key_ptr, a1=out_ptr, a7=SLOAD
            i_type(0x105, 0, 0b000, 17, OP_IMM), // a7 = SLOAD
            // a0 still has key_ptr from SSTORE (but SSTORE set a0=0 on success!)
            // We need to reload a0 with key address
            // Use LUI + ADDI to build 0x10000
            u_type(0x10000, 10, LUI), // LUI x10, 0x10000
            // a1 = output ptr (0x30000)
            u_type(0x30000, 11, LUI), // LUI x11, 0x30000
            sys_type(0),              // ECALL (SLOAD)
            // a0 = exists (should be 1)
            i_type(0, 0, 0b000, 17, OP_IMM), // a7 = HALT
            sys_type(0),                     // ECALL (HALT)
        ]);
        let storage = TestStorageProvider::new();
        let mut exec = Executor::new(&code, 50_000, 200).unwrap();
        exec.set_storage(Box::new(storage));

        let key = brrq_crypto::hash::Hasher::hash(b"rw_key");
        let value = brrq_crypto::hash::Hasher::hash(b"rw_value");

        let key_addr = 0x10000u32;
        let val_addr = 0x20000u32;
        exec.write_memory(key_addr, key.as_bytes()).unwrap();
        exec.write_memory(val_addr, value.as_bytes()).unwrap();
        exec.set_reg(10, key_addr).unwrap();
        exec.set_reg(11, val_addr).unwrap();

        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 1); // SLOAD found it → a0=1

        // Check value was read correctly at out_ptr (0x30000)
        let mut read_value = [0u8; 32];
        for (i, byte) in read_value.iter_mut().enumerate() {
            *byte = exec.memory.read_byte(0x30000 + i as u32).unwrap();
        }
        assert_eq!(read_value, *value.as_bytes());
    }

    #[test]
    fn test_sload_gas_cost() {
        let code = assemble(&[
            i_type(0x105, 0, 0b000, 17, OP_IMM), // a7 = SLOAD
            sys_type(0),                         // ECALL
            i_type(0, 0, 0b000, 17, OP_IMM),     // HALT
            sys_type(0),
        ]);
        let storage = TestStorageProvider::new();
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        exec.set_storage(Box::new(storage));
        exec.set_reg(10, 0x10000).unwrap();
        exec.set_reg(11, 0x20000).unwrap();

        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.gas_used, 1108);
    }

    #[test]
    fn test_sstore_gas_cost() {
        let code = assemble(&[
            i_type(0x106, 0, 0b000, 17, OP_IMM), // a7 = SSTORE
            sys_type(0),                         // ECALL
            u_type(0x10000, 10, LUI),            // LUI x10, 0x10000 (reload key ptr)
            u_type(0x20000, 11, LUI),            // LUI x11, 0x20000 (reload val ptr)
            i_type(0x106, 0, 0b000, 17, OP_IMM), // a7 = SSTORE
            sys_type(0),                         // ECALL (overwrite)
            i_type(0, 0, 0b000, 17, OP_IMM),     // HALT
            sys_type(0),
        ]);
        let storage = TestStorageProvider::new();
        // Give enough gas for INIT (20k) + OVERWRITE (5k) + overhead
        let mut exec = Executor::new(&code, 50_000, 100).unwrap();
        exec.set_storage(Box::new(storage));
        exec.set_reg(10, 0x10000).unwrap();
        exec.set_reg(11, 0x20000).unwrap();

        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.gas_used, 25431);
    }

    #[test]
    fn test_sload_out_of_gas() {
        let code = assemble(&[
            i_type(0x105, 0, 0b000, 17, OP_IMM), // a7 = SLOAD
            sys_type(0),                         // ECALL
        ]);
        let mut exec = Executor::new(&code, 50, 100).unwrap();
        let result = exec.run_to_halt();
        // SLOAD costs 2100 gas but we only have 50, so VM runs out of gas
        assert!(result.is_err(), "Should fail with out-of-gas error");
    }

    // ══════════════════════════════════════════════════════════════
    // Adversarial / Edge-Case VM Tests
    // ══════════════════════════════════════════════════════════════

    #[test]
    fn adversarial_add_overflow_wraps() {
        // ADD u32::MAX + 1 should wrap to 0 (RISC-V wrapping semantics)
        let code = assemble(&[
            i_type(-1, 0, 0b000, 1, OP_IMM), // ADDI x1, x0, -1 → x1 = 0xFFFFFFFF
            i_type(1, 0, 0b000, 2, OP_IMM),  // ADDI x2, x0, 1
            r_type(0, 2, 1, 0b000, 10, OP),  // ADD x10, x1, x2 → 0xFFFFFFFF + 1 = 0
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0, "ADD overflow must wrap to 0");
    }

    #[test]
    fn adversarial_sub_underflow_wraps() {
        // SUB 0 - 1 should wrap to 0xFFFFFFFF
        let code = assemble(&[
            i_type(1, 0, 0b000, 2, OP_IMM),         // ADDI x2, x0, 1
            r_type(0b0100000, 2, 0, 0b000, 10, OP), // SUB x10, x0, x2 → 0 - 1
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0xFFFFFFFF, "SUB underflow must wrap");
    }

    #[test]
    fn adversarial_div_min_by_minus_one() {
        // DIV: i32::MIN / -1 = overflow → RISC-V says return dividend
        let code = assemble(&[
            // Load i32::MIN (0x80000000) into x1
            u_type(0x80000000, 1, LUI),             // LUI x1, 0x80000
            i_type(-1, 0, 0b000, 2, OP_IMM),        // ADDI x2, x0, -1
            r_type(0b0000001, 2, 1, 0b100, 10, OP), // DIV x10, x1, x2
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(
            result.exit_code, 0x80000000,
            "DIV MIN/-1 must return dividend"
        );
    }

    #[test]
    fn adversarial_rem_by_zero() {
        // REM x / 0 → returns x (RISC-V spec)
        let code = assemble(&[
            i_type(42, 0, 0b000, 1, OP_IMM),        // ADDI x1, x0, 42
            r_type(0b0000001, 0, 1, 0b110, 10, OP), // REM x10, x1, x0 → 42 % 0 = 42
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 42, "REM by zero must return dividend");
    }

    #[test]
    fn adversarial_remu_by_zero() {
        // REMU x / 0 → returns x
        let code = assemble(&[
            i_type(99, 0, 0b000, 1, OP_IMM),
            r_type(0b0000001, 0, 1, 0b111, 10, OP), // REMU x10, x1, x0
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 99, "REMU by zero must return dividend");
    }

    #[test]
    fn adversarial_divu_by_zero() {
        // DIVU x / 0 → returns u32::MAX
        let code = assemble(&[
            i_type(42, 0, 0b000, 1, OP_IMM),
            r_type(0b0000001, 0, 1, 0b101, 10, OP), // DIVU x10, x1, x0
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, u32::MAX, "DIVU by zero must return MAX");
    }

    #[test]
    fn adversarial_step_limit_enforcement() {
        // Infinite loop with very low step limit
        // JAL x0, 0 (jump to self → infinite loop)
        let jal_self = {
            // J-type encoding: offset=0 → jump to same PC
            // imm[20|10:1|11|19:12] rd opcode
            (0 << 31) | (0 << 21) | (0 << 20) | (0 << 12) | (0 << 7) | 0b1101111
        };
        let code = assemble(&[jal_self]);
        let mut exec = Executor::new(&code, u64::MAX, 5).unwrap(); // Only 5 steps allowed
        let result = exec.run_to_halt();
        assert!(
            result.is_err(),
            "Infinite loop must be caught by step limit"
        );
    }

    #[test]
    fn adversarial_gas_exact_boundary() {
        // Program needs 12 gas total (1 ADDI + 1 ADDI + 10 ECALL).
        // Give exactly 12 gas — should succeed.
        let code = assemble(&[
            i_type(42, 0, 0b000, 10, OP_IMM),
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 428, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 42);
        assert_eq!(result.gas_used, 428);
    }

    #[test]
    fn adversarial_gas_one_short() {
        // Program needs 12 gas. Give 11 — should halt with out-of-gas.
        let code = assemble(&[
            i_type(42, 0, 0b000, 10, OP_IMM),
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 427, 100).unwrap();
        let result = exec.run_to_halt();
        assert!(result.is_err(), "Should fail with out-of-gas error");
    }

    #[test]
    fn adversarial_x0_immutable_across_all_writes() {
        // Multiple attempts to write x0 → all should be silently ignored
        let code = assemble(&[
            i_type(100, 0, 0b000, 0, OP_IMM), // ADDI x0, x0, 100 → ignored
            u_type(0xDEAD0000, 0, LUI),       // LUI x0, 0xDEAD → ignored
            r_type(0, 0, 0, 0b000, 10, OP),   // ADD x10, x0, x0 → 0
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(
            result.exit_code, 0,
            "x0 must remain 0 after all write attempts"
        );
    }

    #[test]
    fn adversarial_mul_overflow() {
        // MUL: 0x10000 × 0x10000 → lower 32 bits = 0 (overflow)
        let code = assemble(&[
            u_type(0x10000, 1, LUI),                // LUI x1, 0x10 → x1 = 0x10000
            u_type(0x10000, 2, LUI),                // LUI x2, 0x10 → x2 = 0x10000
            r_type(0b0000001, 2, 1, 0b000, 10, OP), // MUL x10, x1, x2
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        // 0x10000 * 0x10000 = 0x100000000 → lower 32 bits = 0
        assert_eq!(
            result.exit_code, 0,
            "MUL overflow must wrap to lower 32 bits"
        );
    }

    #[test]
    fn adversarial_mulh_high_bits() {
        // MULH: signed upper 32 bits of multiplication
        // (-1) * (-1) = 1, MULH returns upper 32 bits of 64-bit result
        let code = assemble(&[
            i_type(-1, 0, 0b000, 1, OP_IMM),        // x1 = -1
            i_type(-1, 0, 0b000, 2, OP_IMM),        // x2 = -1
            r_type(0b0000001, 2, 1, 0b001, 10, OP), // MULH x10, x1, x2
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        // (-1i32 as i64) * (-1i32 as i64) = 1i64 → upper 32 bits = 0
        assert_eq!(result.exit_code, 0, "MULH(-1, -1) upper bits must be 0");
    }

    #[test]
    fn adversarial_shift_by_31() {
        // SLL by 31: 1 << 31 = 0x80000000 (sign bit)
        let code = assemble(&[
            i_type(1, 0, 0b000, 1, OP_IMM),
            r_type(0b0000000, 31, 1, 0b001, 10, OP_IMM), // SLLI x10, x1, 31
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0x80000000, "1 << 31 must set sign bit");
    }

    #[test]
    fn adversarial_sra_sign_extension() {
        // SRA: arithmetic right shift preserves sign
        // 0x80000000 >> 1 = 0xC0000000 (sign extended)
        let code = assemble(&[
            u_type(0x80000000, 1, LUI),             // LUI x1, 0x80000 → 0x80000000
            i_type(1, 0, 0b000, 2, OP_IMM),         // x2 = 1
            r_type(0b0100000, 2, 1, 0b101, 10, OP), // SRA x10, x1, x2
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(result.exit_code, 0xC0000000, "SRA must preserve sign bit");
    }

    #[test]
    fn adversarial_trace_consistency_check() {
        // Complex program: verify trace records correct register transitions
        let code = assemble(&[
            i_type(10, 0, 0b000, 1, OP_IMM),        // x1 = 10
            i_type(20, 0, 0b000, 2, OP_IMM),        // x2 = 20
            r_type(0, 2, 1, 0b000, 3, OP),          // x3 = x1 + x2 = 30
            r_type(0b0000001, 3, 1, 0b000, 10, OP), // x10 = x3 * x1 = 300
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        exec.enable_trace();
        let result = exec.run_to_halt().unwrap();

        let exit_expected = (300u64 & 0xFFFFFFFF) as u32;
        assert_eq!(result.exit_code, exit_expected);
        assert!(
            result.trace.verify_consistency(),
            "Trace must be consistent"
        );
        assert_eq!(result.trace.len(), 6); // 4 ALU + ADDI + ECALL
    }

    // ── JALR alignment tests (verified correct per RISC-V ISA §2.5) ──

    const JALR: u32 = 0b1100111;

    #[test]
    fn m09_jalr_odd_immediate_jumps_to_even_address() {
        // JALR with odd immediate should clear bit 0 (verified per ISA §2.5).
        // Set x1 = 16 (aligned base), then JALR x0, x1, 1 → target = 16 + 1 = 17,
        // after &!1 → 16. At address 16, we place the halt sequence.
        //
        // Memory layout:
        //   0x00: ADDI x1, x0, 16      (x1 = 16)
        //   0x04: JALR x0, x1, 1       (target = 17 & !1 = 16)
        //   0x08: NOP (padding)
        //   0x0C: NOP (padding)
        //   0x10: ADDI x10, x0, 42     (set exit code)
        //   0x14: ADDI x17, x0, 0      (HALT syscall number)
        //   0x18: ECALL
        let code = assemble(&[
            i_type(16, 0, 0b000, 1, OP_IMM),  // 0x00: ADDI x1, x0, 16
            i_type(1, 1, 0b000, 0, JALR),     // 0x04: JALR x0, x1, 1  (odd imm!)
            i_type(0, 0, 0b000, 0, OP_IMM),   // 0x08: NOP (should be skipped)
            i_type(0, 0, 0b000, 0, OP_IMM),   // 0x0C: NOP (should be skipped)
            i_type(42, 0, 0b000, 10, OP_IMM), // 0x10: ADDI x10, x0, 42
            i_type(0, 0, 0b000, 17, OP_IMM),  // 0x14: ADDI x17, x0, 0
            sys_type(0),                      // 0x18: ECALL (HALT)
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(
            result.exit_code, 42,
            "M-09: JALR with odd immediate must jump to even (aligned) address"
        );
    }

    #[test]
    fn m09_jalr_aligned_address_unchanged() {
        // JALR with already-aligned address should work unchanged.
        // Set x1 = 16, JALR x0, x1, 0 → target = 16 (already aligned).
        let code = assemble(&[
            i_type(16, 0, 0b000, 1, OP_IMM),  // 0x00: ADDI x1, x0, 16
            i_type(0, 1, 0b000, 0, JALR),     // 0x04: JALR x0, x1, 0
            i_type(0, 0, 0b000, 0, OP_IMM),   // 0x08: NOP (skipped)
            i_type(0, 0, 0b000, 0, OP_IMM),   // 0x0C: NOP (skipped)
            i_type(99, 0, 0b000, 10, OP_IMM), // 0x10: ADDI x10, x0, 99
            i_type(0, 0, 0b000, 17, OP_IMM),  // 0x14: ADDI x17, x0, 0
            sys_type(0),                      // 0x18: ECALL (HALT)
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(
            result.exit_code, 99,
            "M-09: JALR with aligned address must work unchanged"
        );
    }

    #[test]
    fn m09_jalr_saves_return_address() {
        // JALR rd, rs1, imm should save PC+4 into rd.
        // Set x1 = 12, JALR x5, x1, 0 → jumps to 12, saves return (8) in x5.
        // At address 12, copy x5 to x10 and halt.
        let code = assemble(&[
            i_type(12, 0, 0b000, 1, OP_IMM), // 0x00: ADDI x1, x0, 12
            i_type(0, 1, 0b000, 5, JALR),    // 0x04: JALR x5, x1, 0 → x5 = 8
            i_type(0, 0, 0b000, 0, OP_IMM),  // 0x08: NOP (skipped)
            r_type(0, 0, 5, 0b000, 10, OP),  // 0x0C: ADD x10, x5, x0 → x10 = x5
            i_type(0, 0, 0b000, 17, OP_IMM), // 0x10: ADDI x17, x0, 0
            sys_type(0),                     // 0x14: ECALL (HALT)
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt().unwrap();
        assert_eq!(
            result.exit_code, 8,
            "M-09: JALR must save PC+4 (return address) in rd"
        );
    }

    #[test]
    fn m09_jalr_bit1_set_raises_misaligned() {
        // If C extension is not supported, JALR target with
        // bit 1 set (but bit 0 cleared by &!1) results in a 2-byte-aligned
        // but not 4-byte-aligned address → set_pc raises UnalignedAccess.
        // base=2, imm=0 → target = 2 & !1 = 2, set_pc(2) → error (2 & 3 != 0).
        let code = assemble(&[
            i_type(2, 0, 0b000, 1, OP_IMM), // ADDI x1, x0, 2
            i_type(0, 1, 0b000, 0, JALR),   // JALR x0, x1, 0 → target=2 → misaligned
            i_type(0, 0, 0b000, 17, OP_IMM),
            sys_type(0),
        ]);
        let mut exec = Executor::new(&code, 21_000, 100).unwrap();
        let result = exec.run_to_halt();
        assert!(
            result.is_err(),
            "M-09: JALR to 2-byte-aligned (not 4-byte) address must raise misaligned error"
        );
    }
}
