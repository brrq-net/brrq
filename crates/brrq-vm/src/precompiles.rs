//! Precompiled (accelerated) operations for the zkVM.
//!
//! ## Precompiles (§4.3)
//!
//! These operations are too expensive to implement in RISC-V instructions
//! alone. The zkVM recognizes them as special ECALL sequences and replaces
//! them with optimized STARK circuits.
//!
//! | Precompile        | Syscall # | Gas   | Description              |
//! |-------------------|-----------|-------|--------------------------|
//! | SHA256_COMPRESS   | 0x100     | 50    | SHA-256 compression      |
//! | MERKLE_VERIFY     | 0x101     | 30+   | Merkle path verification |
//! | SLH_DSA_VERIFY    | 0x102     | 50000+| SLH-DSA sig verification |
//! | SCHNORR_VERIFY    | 0x103     | 100   | Schnorr sig verification |
//! | EMIT_LOG          | 0x104     | 20+   | Emit structured log      |
//! | SLOAD             | 0x105     | 200   | Storage read             |
//! | SSTORE (init)     | 0x106     | 20000 | Storage write (new slot) |
//! | SSTORE (overwrite)| 0x106     | 5000  | Storage write (existing) |
//! | SSTORE (clear)    | 0x106     | 5000  | Write zero + 4800 refund |

use crate::cpu::Cpu;
use crate::error::VmError;
use crate::gas_meter::GasMeter;
use crate::memory::Memory;

/// Precompile syscall numbers.
pub mod syscalls {
    /// SHA-256 compression function.
    pub const SHA256_COMPRESS: u32 = 0x100;
    /// Merkle path verification.
    pub const MERKLE_VERIFY: u32 = 0x101;
    /// SLH-DSA signature verification.
    pub const SLH_DSA_VERIFY: u32 = 0x102;
    /// Schnorr signature verification.
    pub const SCHNORR_VERIFY: u32 = 0x103;
    /// Emit a structured event log.
    pub const EMIT_LOG: u32 = 0x104;
    /// Read a value from contract storage.
    pub const SLOAD: u32 = 0x105;
    /// Write a value to contract storage.
    pub const SSTORE: u32 = 0x106;
    /// Halt execution (normal exit).
    pub const HALT: u32 = 0x000;
    /// Write output (for debugging / return data).
    pub const WRITE_OUTPUT: u32 = 0x001;
}

/// Gas costs for precompile operations.
pub mod precompile_gas {
    pub const SHA256_COMPRESS: u64 = 50;
    pub const MERKLE_VERIFY_BASE: u64 = 30;
    pub const MERKLE_VERIFY_PER_LEVEL: u64 = 5;
    /// Gas cost reflects cryptographic verification complexity.
    pub const SLH_DSA_VERIFY: u64 = 50_000;
    pub const SCHNORR_VERIFY: u64 = 100;
    /// Base gas cost for EMIT_LOG.
    pub const EMIT_LOG_BASE: u64 = 20;
    /// Additional gas per indexed topic.
    pub const EMIT_LOG_PER_TOPIC: u64 = 10;
    /// Additional gas per byte of non-indexed data.
    pub const EMIT_LOG_PER_DATA_BYTE: u64 = 1;
    /// Gas cost for SLOAD (storage read).
    pub const SLOAD: u64 = 200;
    /// Gas cost for initializing a new storage slot.
    pub const SSTORE_INIT_GAS: u64 = 20000;
    /// Gas cost for overwriting an existing storage slot.
    pub const SSTORE_OVERWRITE_GAS: u64 = 5000;
    /// Gas refund for clearing a storage slot (writing zero to a non-zero value).
    /// Capped at 50% of total gas used at execution end (EIP-3529 style).
    pub const SSTORE_CLEAR_REFUND: u64 = 4800;
    /// Gas cost for HALT syscall.
    pub const HALT: u64 = 10;
    /// Gas cost for EBREAK.
    pub const EBREAK: u64 = 10;
}

/// Result of executing a precompile.
pub enum PrecompileResult {
    /// Normal completion, continue execution.
    Continue,
    /// Halt execution with exit code.
    Halt(u32),
    /// Emit a structured event log.
    EmitLog(brrq_types::Log),
}

/// Execute a precompile (syscall handler).
///
/// ## Calling Convention
///
/// - a7 (x17): Syscall number
/// - a0-a6 (x10-x16): Arguments
/// - a0 (x10): Return value (0 = success)
pub fn execute_precompile(
    syscall: u32,
    cpu: &mut Cpu,
    memory: &mut Memory,
    gas: &mut GasMeter,
    output: &mut Vec<u8>,
    coprocessor: &mut crate::trace::CoprocessorTrace,
    // CPU step counter at the time of this ECALL.
    // Recorded in the coprocessor trace to bind each coprocessor
    // result to its exact position in the CPU execution.
    cpu_step: u64,
) -> Result<PrecompileResult, VmError> {
    match syscall {
        syscalls::HALT => {
            gas.consume_raw(precompile_gas::HALT)?;
            let exit_code = cpu.read_reg(10); // a0
            Ok(PrecompileResult::Halt(exit_code))
        }

        syscalls::WRITE_OUTPUT => {
            // a0 = buffer address, a1 = length
            let addr = cpu.read_reg(10);
            let len = cpu.read_reg(11);
            let len = len.min(1024 * 1024); // cap at 1 MB

            // Charge gas proportional to output length: 1 gas per 32-byte
            // word (rounded up), minimum 1 gas for any non-zero write.
            if len > 0 {
                let words = (len as u64).div_ceil(32);
                gas.consume_raw(words.max(1))?;
            }

            const MAX_TOTAL_OUTPUT: usize = 10 * 1024 * 1024; // 10 MB
            if output.len() + len as usize > MAX_TOTAL_OUTPUT {
                return Err(VmError::OutputLimitExceeded);
            }

            for i in 0..len {
                let byte = memory.read_byte(addr.wrapping_add(i))?;
                output.push(byte);
            }
            cpu.write_reg(10, 0); // success
            Ok(PrecompileResult::Continue)
        }

        syscalls::SHA256_COMPRESS => {
            gas.consume_raw(precompile_gas::SHA256_COMPRESS)?;
            // a0 = input ptr (64 bytes: 32-byte state + 32-byte block)
            // a1 = output ptr (32 bytes: new state)
            let input_ptr = cpu.read_reg(10);
            let output_ptr = cpu.read_reg(11);

            // Read input
            let mut input = [0u8; 64];
            memory.read_bytes(input_ptr, &mut input)?;

            // Compute SHA-256 compression (using our crypto crate at runtime)
            let hash = brrq_crypto::hash::Hasher::hash(&input);
            let hash_bytes = hash.as_bytes();

            let mut output_arr = [0u8; 32];
            output_arr.copy_from_slice(hash_bytes);
            memory.write_bytes(output_ptr, &output_arr)?;

            coprocessor
                .sha256_steps
                .push(crate::trace::Sha256TraceStep {
                    input,
                    output: output_arr,
                });
            coprocessor.cpu_steps.push(cpu_step);

            cpu.write_reg(10, 0); // success
            Ok(PrecompileResult::Continue)
        }

        syscalls::MERKLE_VERIFY => {
            // a0 = root_ptr (32 bytes)
            // a1 = leaf_ptr (32 bytes)
            // a2 = proof_ptr (siblings array)
            // a3 = depth
            let depth = cpu.read_reg(13);

            // Bound Merkle proof depth to prevent OOM. 256 levels is
            // sufficient for any practical Merkle tree (2^256 leaves).
            const MAX_MERKLE_DEPTH: u32 = 256;
            if depth > MAX_MERKLE_DEPTH {
                return Err(VmError::InvalidSyscall { number: syscall });
            }

            let gas_cost = precompile_gas::MERKLE_VERIFY_BASE
                + (depth as u64) * precompile_gas::MERKLE_VERIFY_PER_LEVEL;
            gas.consume_raw(gas_cost)?;

            let root_ptr = cpu.read_reg(10);
            let leaf_ptr = cpu.read_reg(11);
            let proof_ptr = cpu.read_reg(12);

            // Read root hash
            let mut root = [0u8; 32];
            memory.read_bytes(root_ptr, &mut root)?;

            // Read leaf hash
            let mut leaf = [0u8; 32];
            memory.read_bytes(leaf_ptr, &mut leaf)?;

            // Walk the proof: for each level, read 32-byte sibling + 1-byte
            // canonicalized direction (0=current left, 1=current right).
            // Siblings are recorded for prover re-verification.
            let mut current = brrq_crypto::hash::Hash256::from_bytes(leaf);
            let mut siblings = Vec::with_capacity(depth as usize);
            for level in 0..depth {
                let sibling_offset = proof_ptr.wrapping_add(level * 33); // 32 bytes + 1 byte direction
                let mut sibling = [0u8; 32];
                memory.read_bytes(sibling_offset, &mut sibling)?;
                let direction = memory.read_byte(sibling_offset.wrapping_add(32))?;
                if direction > 1 {
                    return Err(VmError::InvalidMerkleDirection { value: direction });
                }
                siblings.push((sibling, direction));
                let sibling_hash = brrq_crypto::hash::Hash256::from_bytes(sibling);

                // Use hash_node (0x01 domain separation) to match MerkleTree implementation
                current = if direction == 0 {
                    brrq_crypto::hash::Hasher::hash_node(&current, &sibling_hash)
                } else {
                    brrq_crypto::hash::Hasher::hash_node(&sibling_hash, &current)
                };
            }

            let expected_root = brrq_crypto::hash::Hash256::from_bytes(root);
            let verified = current == expected_root;
            let result: u32 = if verified { 1 } else { 0 };

            coprocessor
                .merkle_steps
                .push(crate::trace::MerkleVerifyTraceStep {
                    root,
                    leaf,
                    depth,
                    verified,
                    siblings,
                });
            coprocessor.cpu_steps.push(cpu_step);

            cpu.write_reg(10, result);
            Ok(PrecompileResult::Continue)
        }

        syscalls::SCHNORR_VERIFY => {
            // Architectural note on PHA compliance.
            //
            // This precompile uses secp256k1 elliptic curve math at *runtime*
            // for Bitcoin compatibility. This is intentional and correct.
            //
            // For STARK proving, the Schnorr verification is treated as an
            // *opaque coprocessor*: the STARK circuit does NOT re-execute the
            // EC arithmetic. Instead, it verifies a hash commitment to the
            // (msg_hash, signature, public_key, result) tuple recorded in the
            // coprocessor trace. The prover independently re-executes the
            // Schnorr verification and commits the result into the Fiat-Shamir
            // transcript via a Merkle root of all coprocessor hashes.
            //
            // This means the STARK proof system remains purely hash-based (PHA),
            // while the runtime correctly uses secp256k1 for execution.
            gas.consume_raw(precompile_gas::SCHNORR_VERIFY)?;
            // a0 = msg_ptr (32 bytes hash), a1 = sig_ptr (64 bytes), a2 = pubkey_ptr (32 bytes)
            let msg_ptr = cpu.read_reg(10);
            let sig_ptr = cpu.read_reg(11);
            let pk_ptr = cpu.read_reg(12);

            // Read message hash (32 bytes)
            let mut msg_hash = [0u8; 32];
            memory.read_bytes(msg_ptr, &mut msg_hash)?;

            // Read signature (64 bytes)
            let mut sig_bytes = [0u8; 64];
            memory.read_bytes(sig_ptr, &mut sig_bytes)?;

            // Read public key (32 bytes x-only)
            let mut pk_bytes = [0u8; 32];
            memory.read_bytes(pk_ptr, &mut pk_bytes)?;

            let pk = brrq_crypto::schnorr::SchnorrPublicKey::from_bytes(pk_bytes);
            let hash = brrq_crypto::hash::Hash256::from_bytes(msg_hash);
            let sig = match brrq_crypto::schnorr::SchnorrSignature::from_slice(&sig_bytes) {
                Ok(s) => s,
                Err(_) => {
                    coprocessor
                        .schnorr_steps
                        .push(crate::trace::SchnorrVerifyTraceStep {
                            msg_hash,
                            signature: sig_bytes,
                            public_key: pk_bytes,
                            verified: false,
                        });
                    coprocessor.cpu_steps.push(cpu_step);
                    cpu.write_reg(10, 0); // verification failed
                    return Ok(PrecompileResult::Continue);
                }
            };

            let verified = brrq_crypto::schnorr::verify(&pk, &hash, &sig).is_ok();
            let result = if verified { 1u32 } else { 0u32 };

            coprocessor
                .schnorr_steps
                .push(crate::trace::SchnorrVerifyTraceStep {
                    msg_hash,
                    signature: sig_bytes,
                    public_key: pk_bytes,
                    verified,
                });
            coprocessor.cpu_steps.push(cpu_step);

            cpu.write_reg(10, result);
            Ok(PrecompileResult::Continue)
        }

        syscalls::SLH_DSA_VERIFY => {
            // a0 = msg_ptr, a1 = msg_len, a2 = sig_ptr (7856 bytes), a3 = pubkey_ptr (32 bytes)
            let msg_ptr = cpu.read_reg(10);
            // Cap message size to 64KB to bound trace size.
            let msg_len = cpu.read_reg(11).min(65_536) as usize;

            // SLH-DSA-REPRICING: Charge per-byte gas proportional to message size.
            // Cost: 50,000 base + msg_len gas (1 gas per byte — reflects prover re-hashing cost).
            let per_byte_gas = msg_len as u64;
            gas.consume_raw(precompile_gas::SLH_DSA_VERIFY + per_byte_gas)?;
            let sig_ptr = cpu.read_reg(12);
            let pk_ptr = cpu.read_reg(13);

            // Read message
            let mut msg = vec![0u8; msg_len];
            memory.read_bytes(msg_ptr, &mut msg)?;

            // Read signature (7856 bytes)
            let sig_size = brrq_crypto::slh_dsa::SLH_DSA_SIGNATURE_SIZE;
            let mut sig_bytes = vec![0u8; sig_size];
            memory.read_bytes(sig_ptr, &mut sig_bytes)?;

            // Read public key (32 bytes)
            let mut pk_bytes = vec![0u8; brrq_crypto::slh_dsa::SLH_DSA_PUBLIC_KEY_SIZE];
            memory.read_bytes(pk_ptr, &mut pk_bytes)?;

            // Hash the message for the trace record (don't store full message)
            let msg_hash_for_trace = brrq_crypto::hash::Hasher::hash(&msg);

            // Convert pk_bytes to fixed-size array for trace
            let mut pk_trace = [0u8; 32];
            pk_trace.copy_from_slice(&pk_bytes[..32.min(pk_bytes.len())]);

            let pk = match brrq_crypto::slh_dsa::SlhDsaPublicKey::from_bytes(pk_bytes) {
                Ok(pk) => pk,
                Err(_) => {
                    coprocessor
                        .slh_dsa_steps
                        .push(crate::trace::SlhDsaVerifyTraceStep {
                            msg_hash: *msg_hash_for_trace.as_bytes(),
                            public_key: pk_trace,
                            verified: false,
                            message: msg.clone(),
                            signature_bytes: sig_bytes.clone(),
                        });
                    coprocessor.cpu_steps.push(cpu_step);
                    cpu.write_reg(10, 0);
                    return Ok(PrecompileResult::Continue);
                }
            };
            let sig = match brrq_crypto::slh_dsa::SlhDsaSignature::from_bytes(sig_bytes.clone()) {
                Ok(s) => s,
                Err(_) => {
                    coprocessor
                        .slh_dsa_steps
                        .push(crate::trace::SlhDsaVerifyTraceStep {
                            msg_hash: *msg_hash_for_trace.as_bytes(),
                            public_key: pk_trace,
                            verified: false,
                            message: msg.clone(),
                            signature_bytes: sig_bytes,
                        });
                    coprocessor.cpu_steps.push(cpu_step);
                    cpu.write_reg(10, 0);
                    return Ok(PrecompileResult::Continue);
                }
            };

            let verified = brrq_crypto::slh_dsa::verify(&pk, &msg, &sig).is_ok();
            let result = if verified { 1u32 } else { 0u32 };

            coprocessor
                .slh_dsa_steps
                .push(crate::trace::SlhDsaVerifyTraceStep {
                    msg_hash: *msg_hash_for_trace.as_bytes(),
                    public_key: pk_trace,
                    verified,
                    message: msg,
                    signature_bytes: sig.as_bytes().to_vec(),
                });
            coprocessor.cpu_steps.push(cpu_step);

            cpu.write_reg(10, result);
            Ok(PrecompileResult::Continue)
        }

        syscalls::EMIT_LOG => {
            // a0 = num_topics (0-4), a1 = topics_ptr, a2 = data_ptr, a3 = data_len
            let num_topics = cpu.read_reg(10).min(brrq_types::log::MAX_LOG_TOPICS as u32) as usize;
            let topics_ptr = cpu.read_reg(11);
            let data_ptr = cpu.read_reg(12);
            let data_len = cpu
                .read_reg(13)
                .min(brrq_types::log::MAX_LOG_DATA_SIZE as u32) as usize;

            // Compute and charge gas
            let gas_cost = precompile_gas::EMIT_LOG_BASE
                + (num_topics as u64) * precompile_gas::EMIT_LOG_PER_TOPIC
                + (data_len as u64) * precompile_gas::EMIT_LOG_PER_DATA_BYTE;
            gas.consume_raw(gas_cost)?;

            // Read topics (32 bytes each) from memory
            let mut topics = Vec::with_capacity(num_topics);
            for t in 0..num_topics {
                let offset = topics_ptr.wrapping_add((t * 32) as u32);
                let mut topic_bytes = [0u8; 32];
                memory.read_bytes(offset, &mut topic_bytes)?;
                topics.push(brrq_crypto::hash::Hash256::from_bytes(topic_bytes));
            }

            // Read data bytes from memory
            let mut data = vec![0u8; data_len];
            memory.read_bytes(data_ptr, &mut data)?;

            // Record to coprocessor trace
            let topic_arrays: Vec<[u8; 32]> = topics.iter().map(|t| *t.as_bytes()).collect();
            let data_hash = brrq_crypto::hash::Hasher::hash(&data);
            coprocessor
                .emit_log_steps
                .push(crate::trace::EmitLogTraceStep {
                    topics: topic_arrays,
                    data_hash: *data_hash.as_bytes(),
                });
            coprocessor.cpu_steps.push(cpu_step);

            cpu.write_reg(10, 0); // success
            let log = brrq_types::Log::new(
                brrq_types::Address::ZERO, // Will be set by the executor
                topics,
                data,
            )
            .ok_or_else(|| VmError::PrecompileError {
                msg: "log exceeds limits".into(),
            })?;
            Ok(PrecompileResult::EmitLog(log))
        }

        _ => Err(VmError::InvalidSyscall { number: syscall }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Cpu, Memory, GasMeter, Vec<u8>) {
        let cpu = Cpu::new(0);
        let mem = Memory::new();
        let gas = GasMeter::new(10_000);
        let output = Vec::new();
        (cpu, mem, gas, output)
    }

    #[test]
    fn test_halt_syscall() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        cpu.write_reg(10, 42); // exit code = 42
        let result = execute_precompile(
            syscalls::HALT,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();
        match result {
            PrecompileResult::Halt(code) => assert_eq!(code, 42),
            _ => panic!("expected halt"),
        }
    }

    #[test]
    fn test_write_output_syscall() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        // Write "hello" to memory
        let data = b"hello";
        let addr = 0x10000u32;
        for (i, &b) in data.iter().enumerate() {
            mem.write_byte(addr + i as u32, b).unwrap();
        }
        cpu.write_reg(10, addr); // a0 = buffer addr
        cpu.write_reg(11, 5); // a1 = length

        let result = execute_precompile(
            syscalls::WRITE_OUTPUT,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();
        assert!(matches!(result, PrecompileResult::Continue));
        assert_eq!(&output, b"hello");
        assert_eq!(cpu.read_reg(10), 0); // success
    }

    #[test]
    fn test_sha256_precompile() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        // Write 64 bytes of input
        let input_addr = 0x10000u32;
        let output_addr = 0x20000u32;
        for i in 0..64u32 {
            mem.write_byte(input_addr + i, i as u8).unwrap();
        }
        cpu.write_reg(10, input_addr);
        cpu.write_reg(11, output_addr);

        let result = execute_precompile(
            syscalls::SHA256_COMPRESS,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();
        assert!(matches!(result, PrecompileResult::Continue));
        assert_eq!(cpu.read_reg(10), 0); // success

        // Verify output is non-zero (actual hash)
        let mut all_zero = true;
        for i in 0..32u32 {
            if mem.read_byte(output_addr + i).unwrap() != 0 {
                all_zero = false;
                break;
            }
        }
        assert!(!all_zero);

        // Check gas was consumed
        assert_eq!(gas.used(), precompile_gas::SHA256_COMPRESS);
    }

    #[test]
    fn test_invalid_syscall() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        let result = execute_precompile(
            0xFFFF,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_precompile_gas_exhaustion() {
        let (mut cpu, mut mem, _, mut output) = setup();
        let mut gas_low = GasMeter::new(10); // Only 10 gas
        let result = execute_precompile(
            syscalls::SHA256_COMPRESS,
            &mut cpu,
            &mut mem,
            &mut gas_low,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        );
        assert!(result.is_err()); // SHA256 costs 50 gas
    }

    #[test]
    fn test_schnorr_verify_valid() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();

        // Generate a real keypair and signature
        let kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let msg_hash = brrq_crypto::hash::Hasher::hash(b"test schnorr precompile");
        let sig = kp.sign(&msg_hash).unwrap();

        // Write msg_hash to memory at 0x10000
        let msg_ptr = 0x10000u32;
        for (i, &b) in msg_hash.as_bytes().iter().enumerate() {
            mem.write_byte(msg_ptr + i as u32, b).unwrap();
        }

        // Write signature to memory at 0x20000
        let sig_ptr = 0x20000u32;
        for (i, &b) in sig.as_bytes().iter().enumerate() {
            mem.write_byte(sig_ptr + i as u32, b).unwrap();
        }

        // Write public key to memory at 0x30000
        let pk_ptr = 0x30000u32;
        for (i, &b) in kp.public_key().as_bytes().iter().enumerate() {
            mem.write_byte(pk_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, msg_ptr);
        cpu.write_reg(11, sig_ptr);
        cpu.write_reg(12, pk_ptr);

        let result = execute_precompile(
            syscalls::SCHNORR_VERIFY,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();
        assert!(matches!(result, PrecompileResult::Continue));
        assert_eq!(cpu.read_reg(10), 1); // valid signature
    }

    #[test]
    fn test_schnorr_verify_invalid() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();

        // Generate a real keypair
        let kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let msg_hash = brrq_crypto::hash::Hasher::hash(b"test schnorr precompile");
        let sig = kp.sign(&msg_hash).unwrap();

        // Write WRONG msg_hash to memory
        let wrong_hash = brrq_crypto::hash::Hasher::hash(b"wrong message");
        let msg_ptr = 0x10000u32;
        for (i, &b) in wrong_hash.as_bytes().iter().enumerate() {
            mem.write_byte(msg_ptr + i as u32, b).unwrap();
        }

        let sig_ptr = 0x20000u32;
        for (i, &b) in sig.as_bytes().iter().enumerate() {
            mem.write_byte(sig_ptr + i as u32, b).unwrap();
        }

        let pk_ptr = 0x30000u32;
        for (i, &b) in kp.public_key().as_bytes().iter().enumerate() {
            mem.write_byte(pk_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, msg_ptr);
        cpu.write_reg(11, sig_ptr);
        cpu.write_reg(12, pk_ptr);

        let result = execute_precompile(
            syscalls::SCHNORR_VERIFY,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();
        assert!(matches!(result, PrecompileResult::Continue));
        assert_eq!(cpu.read_reg(10), 0); // invalid signature
    }

    #[test]
    fn test_slh_dsa_verify_valid() {
        let (mut cpu, mut mem, _gas, mut output) = setup();
        let mut gas = GasMeter::new(100_000); // SLH-DSA needs 500 gas

        let kp = brrq_crypto::slh_dsa::SlhDsaKeyPair::generate().unwrap();
        let msg = b"test slh-dsa precompile";
        let sig = kp.sign(msg).unwrap();

        // Write message to memory at 0x10000
        let msg_ptr = 0x10000u32;
        for (i, &b) in msg.iter().enumerate() {
            mem.write_byte(msg_ptr + i as u32, b).unwrap();
        }

        // Write signature (7856 bytes) to memory at 0x20000
        let sig_ptr = 0x20000u32;
        for (i, &b) in sig.as_bytes().iter().enumerate() {
            mem.write_byte(sig_ptr + i as u32, b).unwrap();
        }

        // Write public key (32 bytes) to memory at 0x40000
        let pk_ptr = 0x40000u32;
        for (i, &b) in kp.public_key().as_bytes().iter().enumerate() {
            mem.write_byte(pk_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, msg_ptr);
        cpu.write_reg(11, msg.len() as u32);
        cpu.write_reg(12, sig_ptr);
        cpu.write_reg(13, pk_ptr);

        let result = execute_precompile(
            syscalls::SLH_DSA_VERIFY,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();
        assert!(matches!(result, PrecompileResult::Continue));
        assert_eq!(cpu.read_reg(10), 1); // valid signature
    }

    #[test]
    fn test_slh_dsa_verify_invalid() {
        let (mut cpu, mut mem, _gas, mut output) = setup();
        let mut gas = GasMeter::new(100_000);

        let kp = brrq_crypto::slh_dsa::SlhDsaKeyPair::generate().unwrap();
        let msg = b"test slh-dsa precompile";
        let sig = kp.sign(msg).unwrap();

        // Write DIFFERENT message to memory
        let wrong_msg = b"wrong message for slh-dsa";
        let msg_ptr = 0x10000u32;
        for (i, &b) in wrong_msg.iter().enumerate() {
            mem.write_byte(msg_ptr + i as u32, b).unwrap();
        }

        let sig_ptr = 0x20000u32;
        for (i, &b) in sig.as_bytes().iter().enumerate() {
            mem.write_byte(sig_ptr + i as u32, b).unwrap();
        }

        let pk_ptr = 0x40000u32;
        for (i, &b) in kp.public_key().as_bytes().iter().enumerate() {
            mem.write_byte(pk_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, msg_ptr);
        cpu.write_reg(11, wrong_msg.len() as u32);
        cpu.write_reg(12, sig_ptr);
        cpu.write_reg(13, pk_ptr);

        let result = execute_precompile(
            syscalls::SLH_DSA_VERIFY,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();
        assert!(matches!(result, PrecompileResult::Continue));
        assert_eq!(cpu.read_reg(10), 0); // invalid signature
    }

    #[test]
    fn test_emit_log_syscall() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();

        // Write 2 topics (32 bytes each) at 0x10000
        let topics_ptr = 0x10000u32;
        let topic1 = brrq_crypto::hash::Hasher::hash(b"Transfer");
        let topic2 = brrq_crypto::hash::Hasher::hash(b"from_addr");
        for (i, &b) in topic1.as_bytes().iter().enumerate() {
            mem.write_byte(topics_ptr + i as u32, b).unwrap();
        }
        for (i, &b) in topic2.as_bytes().iter().enumerate() {
            mem.write_byte(topics_ptr + 32 + i as u32, b).unwrap();
        }

        // Write 4 bytes of data at 0x20000
        let data_ptr = 0x20000u32;
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        for (i, &b) in data.iter().enumerate() {
            mem.write_byte(data_ptr + i as u32, b).unwrap();
        }

        // Set up registers: a0=num_topics, a1=topics_ptr, a2=data_ptr, a3=data_len
        cpu.write_reg(10, 2); // 2 topics
        cpu.write_reg(11, topics_ptr); // topics pointer
        cpu.write_reg(12, data_ptr); // data pointer
        cpu.write_reg(13, 4); // data length

        let result = execute_precompile(
            syscalls::EMIT_LOG,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();

        match result {
            PrecompileResult::EmitLog(log) => {
                assert_eq!(log.topics.len(), 2);
                assert_eq!(log.topics[0], topic1);
                assert_eq!(log.topics[1], topic2);
                assert_eq!(log.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                assert_eq!(log.address, brrq_types::Address::ZERO);
            }
            _ => panic!("expected EmitLog result"),
        }
        assert_eq!(cpu.read_reg(10), 0); // success
    }

    #[test]
    fn test_emit_log_gas() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();

        // No topics, 10 bytes of data
        let data_ptr = 0x10000u32;
        for i in 0..10 {
            mem.write_byte(data_ptr + i, i as u8).unwrap();
        }

        cpu.write_reg(10, 0); // 0 topics
        cpu.write_reg(11, 0); // no topics ptr needed
        cpu.write_reg(12, data_ptr); // data ptr
        cpu.write_reg(13, 10); // 10 bytes

        let gas_before = gas.used();
        let _result = execute_precompile(
            syscalls::EMIT_LOG,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut crate::trace::CoprocessorTrace::default(),
            0,
        )
        .unwrap();

        let gas_consumed = gas.used() - gas_before;
        // Expected: BASE(20) + 0*TOPIC(10) + 10*BYTE(1) = 30
        assert_eq!(gas_consumed, 30);
    }

    // ── Coprocessor trace recording tests ──────────────────────────

    #[test]
    fn test_sha256_records_to_coprocessor_trace() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        let mut coproc = crate::trace::CoprocessorTrace::default();

        let input_addr = 0x10000u32;
        let output_addr = 0x20000u32;
        for i in 0..64u32 {
            mem.write_byte(input_addr + i, i as u8).unwrap();
        }
        cpu.write_reg(10, input_addr);
        cpu.write_reg(11, output_addr);

        let _result = execute_precompile(
            syscalls::SHA256_COMPRESS,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut coproc,
            0,
        )
        .unwrap();

        assert_eq!(coproc.sha256_steps.len(), 1);
        assert_eq!(coproc.sha256_steps[0].input[0], 0);
        assert_eq!(coproc.sha256_steps[0].input[63], 63);
        // Output should be non-zero (actual hash)
        assert_ne!(coproc.sha256_steps[0].output, [0u8; 32]);
    }

    #[test]
    fn test_schnorr_valid_records_to_coprocessor_trace() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        let mut coproc = crate::trace::CoprocessorTrace::default();

        let kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let msg_hash = brrq_crypto::hash::Hasher::hash(b"coprocessor test");
        let sig = kp.sign(&msg_hash).unwrap();

        let msg_ptr = 0x10000u32;
        for (i, &b) in msg_hash.as_bytes().iter().enumerate() {
            mem.write_byte(msg_ptr + i as u32, b).unwrap();
        }
        let sig_ptr = 0x20000u32;
        for (i, &b) in sig.as_bytes().iter().enumerate() {
            mem.write_byte(sig_ptr + i as u32, b).unwrap();
        }
        let pk_ptr = 0x30000u32;
        for (i, &b) in kp.public_key().as_bytes().iter().enumerate() {
            mem.write_byte(pk_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, msg_ptr);
        cpu.write_reg(11, sig_ptr);
        cpu.write_reg(12, pk_ptr);

        let _result = execute_precompile(
            syscalls::SCHNORR_VERIFY,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut coproc,
            0,
        )
        .unwrap();

        assert_eq!(coproc.schnorr_steps.len(), 1);
        assert!(coproc.schnorr_steps[0].verified);
        assert_eq!(coproc.schnorr_steps[0].msg_hash, *msg_hash.as_bytes());
    }

    #[test]
    fn test_schnorr_invalid_records_to_coprocessor_trace() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        let mut coproc = crate::trace::CoprocessorTrace::default();

        let kp = brrq_crypto::schnorr::SchnorrKeyPair::generate();
        let msg_hash = brrq_crypto::hash::Hasher::hash(b"correct message");
        let sig = kp.sign(&msg_hash).unwrap();
        let wrong_hash = brrq_crypto::hash::Hasher::hash(b"wrong message");

        let msg_ptr = 0x10000u32;
        for (i, &b) in wrong_hash.as_bytes().iter().enumerate() {
            mem.write_byte(msg_ptr + i as u32, b).unwrap();
        }
        let sig_ptr = 0x20000u32;
        for (i, &b) in sig.as_bytes().iter().enumerate() {
            mem.write_byte(sig_ptr + i as u32, b).unwrap();
        }
        let pk_ptr = 0x30000u32;
        for (i, &b) in kp.public_key().as_bytes().iter().enumerate() {
            mem.write_byte(pk_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, msg_ptr);
        cpu.write_reg(11, sig_ptr);
        cpu.write_reg(12, pk_ptr);

        let _result = execute_precompile(
            syscalls::SCHNORR_VERIFY,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut coproc,
            0,
        )
        .unwrap();

        assert_eq!(coproc.schnorr_steps.len(), 1);
        assert!(!coproc.schnorr_steps[0].verified);
    }

    #[test]
    fn test_slh_dsa_records_to_coprocessor_trace() {
        let (mut cpu, mut mem, _gas, mut output) = setup();
        let mut gas = GasMeter::new(100_000);
        let mut coproc = crate::trace::CoprocessorTrace::default();

        let kp = brrq_crypto::slh_dsa::SlhDsaKeyPair::generate().unwrap();
        let msg = b"slh-dsa coprocessor test";
        let sig = kp.sign(msg).unwrap();

        let msg_ptr = 0x10000u32;
        for (i, &b) in msg.iter().enumerate() {
            mem.write_byte(msg_ptr + i as u32, b).unwrap();
        }
        let sig_ptr = 0x20000u32;
        for (i, &b) in sig.as_bytes().iter().enumerate() {
            mem.write_byte(sig_ptr + i as u32, b).unwrap();
        }
        let pk_ptr = 0x40000u32;
        for (i, &b) in kp.public_key().as_bytes().iter().enumerate() {
            mem.write_byte(pk_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, msg_ptr);
        cpu.write_reg(11, msg.len() as u32);
        cpu.write_reg(12, sig_ptr);
        cpu.write_reg(13, pk_ptr);

        let _result = execute_precompile(
            syscalls::SLH_DSA_VERIFY,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut coproc,
            0,
        )
        .unwrap();

        assert_eq!(coproc.slh_dsa_steps.len(), 1);
        assert!(coproc.slh_dsa_steps[0].verified);
        // msg_hash should be SHA256(msg)
        let expected_hash = brrq_crypto::hash::Hasher::hash(msg);
        assert_eq!(coproc.slh_dsa_steps[0].msg_hash, *expected_hash.as_bytes());
    }

    #[test]
    fn test_emit_log_records_to_coprocessor_trace() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        let mut coproc = crate::trace::CoprocessorTrace::default();

        let topics_ptr = 0x10000u32;
        let topic1 = brrq_crypto::hash::Hasher::hash(b"Transfer");
        for (i, &b) in topic1.as_bytes().iter().enumerate() {
            mem.write_byte(topics_ptr + i as u32, b).unwrap();
        }

        let data_ptr = 0x20000u32;
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        for (i, &b) in data.iter().enumerate() {
            mem.write_byte(data_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, 1); // 1 topic
        cpu.write_reg(11, topics_ptr);
        cpu.write_reg(12, data_ptr);
        cpu.write_reg(13, 4); // 4 bytes data

        let _result = execute_precompile(
            syscalls::EMIT_LOG,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut coproc,
            0,
        )
        .unwrap();

        assert_eq!(coproc.emit_log_steps.len(), 1);
        assert_eq!(coproc.emit_log_steps[0].topics.len(), 1);
        assert_eq!(coproc.emit_log_steps[0].topics[0], *topic1.as_bytes());
        // data_hash should be SHA256([0xDE, 0xAD, 0xBE, 0xEF])
        let expected_data_hash = brrq_crypto::hash::Hasher::hash(&data);
        assert_eq!(
            coproc.emit_log_steps[0].data_hash,
            *expected_data_hash.as_bytes()
        );
    }

    #[test]
    fn test_merkle_records_to_coprocessor_trace() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        let mut coproc = crate::trace::CoprocessorTrace::default();

        // Set up a simple Merkle verification (depth=0, root==leaf)
        let leaf = brrq_crypto::hash::Hasher::hash(b"leaf_data");
        let root_ptr = 0x10000u32;
        for (i, &b) in leaf.as_bytes().iter().enumerate() {
            mem.write_byte(root_ptr + i as u32, b).unwrap();
        }
        let leaf_ptr = 0x20000u32;
        for (i, &b) in leaf.as_bytes().iter().enumerate() {
            mem.write_byte(leaf_ptr + i as u32, b).unwrap();
        }

        cpu.write_reg(10, root_ptr);
        cpu.write_reg(11, leaf_ptr);
        cpu.write_reg(12, 0x30000); // proof ptr (unused for depth=0)
        cpu.write_reg(13, 0); // depth = 0

        let _result = execute_precompile(
            syscalls::MERKLE_VERIFY,
            &mut cpu,
            &mut mem,
            &mut gas,
            &mut output,
            &mut coproc,
            0,
        )
        .unwrap();

        assert_eq!(coproc.merkle_steps.len(), 1);
        assert!(coproc.merkle_steps[0].verified);
        assert_eq!(coproc.merkle_steps[0].root, *leaf.as_bytes());
        assert_eq!(coproc.merkle_steps[0].depth, 0);
    }

    #[test]
    fn test_multiple_precompile_ops_accumulate() {
        let (mut cpu, mut mem, mut gas, mut output) = setup();
        let mut coproc = crate::trace::CoprocessorTrace::default();

        // Run SHA256 twice
        for _ in 0..2 {
            for i in 0..64u32 {
                mem.write_byte(0x10000 + i, i as u8).unwrap();
            }
            cpu.write_reg(10, 0x10000);
            cpu.write_reg(11, 0x20000);
            let _r = execute_precompile(
                syscalls::SHA256_COMPRESS,
                &mut cpu,
                &mut mem,
                &mut gas,
                &mut output,
                &mut coproc,
                0,
            )
            .unwrap();
        }

        assert_eq!(coproc.sha256_steps.len(), 2);
    }
}
