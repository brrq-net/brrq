//! Brrq Smart Contract SDK
//!
//! Runtime library for writing smart contracts that execute on the Brrq zkVM.
//! Contracts compile to `riscv32im-unknown-none-elf` and interact with the VM
//! through ECALL syscalls.
//!
//! ## Quick Start
//!
//! ```rust,ignore (requires riscv32im-unknown-none-elf target with no_std/no_main)
//! #![no_std]
//! #![no_main]
//!
//! use brrq_contract_sdk::*;
//!
//! #[no_mangle]
//! pub extern "C" fn _start() {
//!     // Read calldata (function selector + arguments)
//!     let selector = calldata_selector();
//!     match selector {
//!         0x01 => handle_transfer(),
//!         0x02 => handle_balance_of(),
//!         _ => halt(1), // unknown function
//!     }
//!     halt(0);
//! }
//! ```
//!
//! ## Syscall Reference
//!
//! | Syscall        | Number | Description                    |
//! |----------------|--------|--------------------------------|
//! | HALT           | 0x000  | Stop execution with exit code  |
//! | WRITE_OUTPUT   | 0x001  | Write return data              |
//! | SHA256_COMPRESS| 0x100  | SHA-256 hash compression       |
//! | MERKLE_VERIFY  | 0x101  | Merkle proof verification      |
//! | SLH_DSA_VERIFY | 0x102  | SLH-DSA signature verification |
//! | SCHNORR_VERIFY | 0x103  | Schnorr signature verification |
//! | EMIT_LOG       | 0x104  | Emit structured event log      |
//! | SLOAD          | 0x105  | Read from persistent storage   |
//! | SSTORE         | 0x106  | Write to persistent storage    |
//! | BLOCK_HEIGHT_64| 0x208  | 64-bit block height            |
//! | BLOCK_TIMESTAMP_64| 0x209 | 64-bit block timestamp       |
//! | DELEGATE_CALL  | 0x20A  | Delegate call to contract      |

#![no_std]

#[cfg(target_arch = "riscv32")]
use core::panic::PanicInfo;

// ── Syscall Numbers ─────────────────────────────────────────────────────────

pub const SYS_HALT: u32 = 0x000;
pub const SYS_WRITE_OUTPUT: u32 = 0x001;
pub const SYS_SHA256: u32 = 0x100;
pub const SYS_MERKLE_VERIFY: u32 = 0x101;
pub const SYS_SLH_DSA_VERIFY: u32 = 0x102;
pub const SYS_SCHNORR_VERIFY: u32 = 0x103;
pub const SYS_EMIT_LOG: u32 = 0x104;
pub const SYS_SLOAD: u32 = 0x105;
pub const SYS_SSTORE: u32 = 0x106;
pub const SYS_BLOCK_HEIGHT: u32 = 0x200;
pub const SYS_BLOCK_TIMESTAMP: u32 = 0x201;
pub const SYS_CALLER: u32 = 0x202;
pub const SYS_MSG_VALUE: u32 = 0x203;
pub const SYS_NATIVE_TRANSFER: u32 = 0x204;
pub const SYS_CALL: u32 = 0x205;
pub const SYS_RETURN_DATA_SIZE: u32 = 0x206;
pub const SYS_RETURN_DATA_COPY: u32 = 0x207;
pub const SYS_BLOCK_HEIGHT_64: u32 = 0x208;
pub const SYS_BLOCK_TIMESTAMP_64: u32 = 0x209;
pub const SYS_DELEGATE_CALL: u32 = 0x20A;
// ── Raw Syscall Interface ───────────────────────────────────────────────────

/// Execute an ECALL with up to 7 arguments.
///
/// Calling convention: a7 = syscall number, a0-a6 = arguments, a0 = return value.
#[inline(always)]
unsafe fn ecall(
    syscall: u32,
    a0: u32,
    a1: u32,
    a2: u32,
    a3: u32,
) -> u32 {
    #[cfg(target_arch = "riscv32")]
    {
        let ret: u32;
        core::arch::asm!(
            "ecall",
            in("x17") syscall,
            inlateout("x10") a0 => ret,
            in("x11") a1,
            in("x12") a2,
            in("x13") a3,
            options(nostack)
        );
        ret
    }
    #[cfg(not(target_arch = "riscv32"))]
    {
        let _ = (syscall, a0, a1, a2, a3);
        0
    }
}

// ── Storage ─────────────────────────────────────────────────────────────────

/// A 32-byte storage key.
pub type StorageKey = [u8; 32];
/// A 32-byte storage value.
pub type StorageValue = [u8; 32];

/// Read a 32-byte value from persistent contract storage.
///
/// Returns `(value, exists)` where `exists` is true if the slot was populated.
///
/// Gas cost: 200
pub fn sload(key: &StorageKey) -> (StorageValue, bool) {
    let mut value = [0u8; 32];
    let exists = unsafe {
        ecall(
            SYS_SLOAD,
            key.as_ptr() as u32,
            value.as_mut_ptr() as u32,
            0,
            0,
        )
    };
    (value, exists != 0)
}

/// Write a 32-byte value to persistent contract storage.
///
/// Gas cost: 20,000 (new slot) or 5,000 (existing slot).
/// Writing zero to a non-zero slot grants a 4,800 gas refund.
pub fn sstore(key: &StorageKey, value: &StorageValue) {
    unsafe {
        ecall(
            SYS_SSTORE,
            key.as_ptr() as u32,
            value.as_ptr() as u32,
            0,
            0,
        );
    }
}

// ── Execution Control ───────────────────────────────────────────────────────

/// Halt execution with the given exit code.
///
/// Exit code 0 = success, non-zero = revert.
pub fn halt(code: u32) -> ! {
    unsafe {
        ecall(SYS_HALT, code, 0, 0, 0);
    }
    // Safety: HALT never returns
    #[allow(clippy::empty_loop)]
    loop {}
}

/// Write output (return data) to the caller.
///
/// This data is returned to the transaction sender.
pub fn write_output(data: &[u8]) {
    unsafe {
        ecall(
            SYS_WRITE_OUTPUT,
            data.as_ptr() as u32,
            data.len() as u32,
            0,
            0,
        );
    }
}

// ── Cryptographic Precompiles ───────────────────────────────────────────────

/// Compute SHA-256 compression: `output = SHA256(input)`.
///
/// `input` must be exactly 64 bytes (32-byte state + 32-byte block).
/// `output` receives the 32-byte result.
///
/// Gas cost: 50
pub fn sha256_compress(input: &[u8; 64], output: &mut [u8; 32]) {
    unsafe {
        ecall(
            SYS_SHA256,
            input.as_ptr() as u32,
            output.as_mut_ptr() as u32,
            0,
            0,
        );
    }
}

/// Verify a Schnorr (BIP-340) signature.
///
/// Returns `true` if the signature is valid.
///
/// Gas cost: 100
pub fn schnorr_verify(msg_hash: &[u8; 32], signature: &[u8; 64], pubkey: &[u8; 32]) -> bool {
    let result = unsafe {
        ecall(
            SYS_SCHNORR_VERIFY,
            msg_hash.as_ptr() as u32,
            signature.as_ptr() as u32,
            pubkey.as_ptr() as u32,
            0,
        )
    };
    result != 0
}

/// Verify an SLH-DSA (FIPS 205) signature.
///
/// Returns `true` if the signature is valid.
///
/// Gas cost: 50,000 + 1 per message byte
pub fn slh_dsa_verify(msg: &[u8], signature: &[u8], pubkey: &[u8; 32]) -> bool {
    // Pack (msg_ptr, msg_len) and (sig_ptr, sig_len) into the available registers.
    // The VM uses a0=msg_ptr, a1=msg_len, a2=sig_ptr, a3=sig_len+pubkey_ptr packed.
    // We pass sig_len via the high bits of a3 and pubkey_ptr separately.
    //
    // Revised calling convention for 5-arg syscalls on RV32:
    //   a0 = msg_ptr
    //   a1 = msg_len | (sig_len << 16)   — both fit in 16 bits
    //   a2 = sig_ptr
    //   a3 = pubkey_ptr
    let len_packed = (msg.len() as u32) | ((signature.len() as u32) << 16);
    let result = unsafe {
        ecall(
            SYS_SLH_DSA_VERIFY,
            msg.as_ptr() as u32,
            len_packed,
            signature.as_ptr() as u32,
            pubkey.as_ptr() as u32,
        )
    };
    result != 0
}

/// Verify a Merkle proof.
///
/// Returns `true` if `leaf` belongs to the tree with `root`.
///
/// Gas cost: 30 + 5 per level
pub fn merkle_verify(root: &[u8; 32], leaf: &[u8; 32], proof: &[u8], depth: u32) -> bool {
    let result = unsafe {
        ecall(
            SYS_MERKLE_VERIFY,
            root.as_ptr() as u32,
            leaf.as_ptr() as u32,
            proof.as_ptr() as u32,
            depth,
        )
    };
    result != 0
}

// ── Event Logging ───────────────────────────────────────────────────────────

/// Emit a structured event log.
///
/// `topics`: 0-4 indexed 32-byte topics (for filtering).
/// `data`: Non-indexed data bytes.
///
/// Gas cost: 20 + 10 per topic + 1 per data byte.
pub fn emit_log(topics: &[[u8; 32]], data: &[u8]) {
    let num_topics = topics.len().min(4) as u32;
    unsafe {
        ecall(
            SYS_EMIT_LOG,
            num_topics,
            topics.as_ptr() as u32,
            data.as_ptr() as u32,
            data.len() as u32,
        );
    }
}

// ── Environment Queries ────────────────────────────────────────────────────

/// Get the current block height from the VM environment.
///
/// MUST be used instead of reading block height from calldata to prevent
/// callers from spoofing the current block height.
///
/// Gas cost: 100
pub fn block_height() -> u64 {
    let mut buf = [0u8; 8];
    unsafe {
        ecall(SYS_BLOCK_HEIGHT_64, buf.as_mut_ptr() as u32, 0, 0, 0);
    }
    u64::from_le_bytes(buf)
}

/// Get the current block timestamp from the VM environment (Unix seconds).
///
/// Gas cost: 100
pub fn block_timestamp() -> u64 {
    let mut buf = [0u8; 8];
    unsafe {
        ecall(SYS_BLOCK_TIMESTAMP_64, buf.as_mut_ptr() as u32, 0, 0, 0);
    }
    u64::from_le_bytes(buf)
}

/// Get the address of the caller (msg.sender) from the VM environment.
///
/// MUST be used instead of reading caller from calldata to prevent
/// callers from spoofing their identity.
///
/// Gas cost: 2
pub fn msg_sender() -> [u8; 20] {
    let mut addr = [0u8; 20];
    unsafe {
        ecall(SYS_CALLER, addr.as_mut_ptr() as u32, 0, 0, 0);
    }
    addr
}

/// Get the value (in native BRC tokens) sent with the transaction (msg.value).
pub fn msg_value() -> u64 {
    let mut val = [0u8; 8];
    unsafe {
        ecall(SYS_MSG_VALUE, val.as_mut_ptr() as u32, 0, 0, 0);
    }
    u64::from_le_bytes(val)
}

/// Transfer native BRC tokens from the contract to a recipient address.
pub fn transfer_native(to: &[u8; 20], amount: u64) {
    let amount_bytes = amount.to_le_bytes();
    unsafe {
        ecall(
            SYS_NATIVE_TRANSFER,
            to.as_ptr() as u32,
            amount_bytes.as_ptr() as u32,
            0,
            0,
        );
    }
}

/// Call another contract synchronously.
///
/// Returns `true` if the call succeeded, `false` otherwise (e.g., revert or out of gas).
pub fn call_contract(to: &[u8; 20], value: u64, calldata: &[u8]) -> bool {
    let value_bytes = value.to_le_bytes();
    let result = unsafe {
        ecall(
            SYS_CALL,
            to.as_ptr() as u32,
            value_bytes.as_ptr() as u32,
            calldata.as_ptr() as u32,
            calldata.len() as u32,
        )
    };
    result != 0
}

/// Call another contract via delegate call, retaining the caller's context and storage.
///
/// Returns `true` if the call succeeded, `false` otherwise (e.g., revert or out of gas).
pub fn delegate_call_contract(to: &[u8; 20], calldata: &[u8]) -> bool {
    let result = unsafe {
        ecall(
            SYS_DELEGATE_CALL,
            to.as_ptr() as u32,
            calldata.as_ptr() as u32,
            calldata.len() as u32,
            0,
        )
    };
    result != 0
}

/// Get the size of the return data from the last external contract call.
pub fn return_data_size() -> usize {
    let size = unsafe {
        ecall(SYS_RETURN_DATA_SIZE, 0, 0, 0, 0)
    };
    size as usize
}

/// Copy the return data from the last external contract call into a buffer.
/// `dest` should be pre-allocated to the appropriate size.
pub fn return_data_copy(dest: &mut [u8]) {
    unsafe {
        ecall(
            SYS_RETURN_DATA_COPY,
            dest.as_mut_ptr() as u32,
            dest.len() as u32,
            0,
            0,
        );
    }
}

// ── Reentrancy Guard ────────────────────────────────────────────────────────

const REENTRANCY_LOCK_KEY: [u8; 32] = {
    let mut key = [0u8; 32];
    key[0] = b'R';
    key[1] = b'L';
    key[2] = b'O';
    key[3] = b'C';
    key[4] = b'K';
    key
};

/// Enter a reentrancy guard. Halts execution if the guard is already locked.
pub fn enter_reentrancy_lock() {
    let (locked, _) = sload(&REENTRANCY_LOCK_KEY);
    if locked[0] == 1 {
        // Reentrancy detected
        crate::halt(3); // Reentrancy error code
    }
    let mut lock = [0u8; 32];
    lock[0] = 1;
    sstore(&REENTRANCY_LOCK_KEY, &lock);
}

/// Release the reentrancy guard.
pub fn exit_reentrancy_lock() {
    let mut lock = [0u8; 32];
    lock[0] = 0;
    sstore(&REENTRANCY_LOCK_KEY, &lock);
}

// ── ABI Helpers ─────────────────────────────────────────────────────────────

/// Storage key derivation.
///
/// Used to map logical storage slots to 32-byte keys.
/// For example: `storage_slot(0, address_bytes)` → the balance slot for an address.
///
/// Keys ≤ 28 bytes are packed directly: `[prefix:4][key][padding]`.
/// Keys > 28 bytes are hashed via `sha256_compress` to avoid truncation collisions.
pub fn storage_slot(prefix: u32, key: &[u8]) -> StorageKey {
    let prefix_bytes = prefix.to_le_bytes();

    // Reject keys longer than 92 bytes to prevent silent truncation.
    // Two compression rounds support: 28 + 32 + 32 = 92 bytes max.
    if key.len() > 92 {
        halt(0xFD); // Storage key too long — would silently truncate
    }

    if key.len() <= 28 {
        // Short key: pack directly (no collision risk)
        let mut slot = [0u8; 32];
        slot[0..4].copy_from_slice(&prefix_bytes);
        slot[4..4 + key.len()].copy_from_slice(key);
        slot
    } else {
        // Long key: hash to prevent truncation collisions.
        // Input block: [prefix:4][key[0..28]] ++ [key[28..] padded to 32]
        let mut block = [0u8; 64];
        block[0..4].copy_from_slice(&prefix_bytes);
        block[4..32].copy_from_slice(&key[..28]);
        let remaining = &key[28..];
        let copy_len = remaining.len().min(32);
        block[32..32 + copy_len].copy_from_slice(&remaining[..copy_len]);

        let mut result = [0u8; 32];
        sha256_compress(&block, &mut result);

        // Chain another compression if key > 60 bytes
        if key.len() > 60 {
            let mut block2 = [0u8; 64];
            block2[0..32].copy_from_slice(&result);
            let extra = &key[60..];
            let extra_len = extra.len().min(32);
            block2[32..32 + extra_len].copy_from_slice(&extra[..extra_len]);
            sha256_compress(&block2, &mut result);
        }

        result
    }
}

/// Encode a u64 value as a 32-byte storage value (little-endian).
pub fn u64_to_value(val: u64) -> StorageValue {
    let mut v = [0u8; 32];
    v[0..8].copy_from_slice(&val.to_le_bytes());
    v
}

/// Decode a u64 from a 32-byte storage value (little-endian).
pub fn value_to_u64(val: &StorageValue) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&val[0..8]);
    u64::from_le_bytes(bytes)
}

/// Encode a u128 value as a 32-byte storage value (little-endian).
pub fn u128_to_value(val: u128) -> StorageValue {
    let mut v = [0u8; 32];
    v[0..16].copy_from_slice(&val.to_le_bytes());
    v
}

/// Decode a u128 from a 32-byte storage value (little-endian).
pub fn value_to_u128(val: &StorageValue) -> u128 {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&val[0..16]);
    u128::from_le_bytes(bytes)
}

/// Encode a 20-byte address as a 32-byte storage value (left-padded with zeros).
pub fn address_to_value(addr: &[u8; 20]) -> StorageValue {
    let mut v = [0u8; 32];
    v[0..20].copy_from_slice(addr);
    v
}

/// Decode a 20-byte address from a 32-byte storage value.
pub fn value_to_address(val: &StorageValue) -> [u8; 20] {
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&val[0..20]);
    addr
}

// ── Calldata Helpers ────────────────────────────────────────────────────────

/// Calldata is passed to contracts via registers and memory.
///
/// The sequencer places calldata at a fixed memory address (0x80000000).
/// Layout: [4-byte selector][arguments...]
const CALLDATA_BASE: u32 = 0x8000_0000;

/// Maximum calldata size (16 KB — enough for any realistic contract call).
const CALLDATA_MAX_SIZE: u32 = 16_384;

/// Read the 4-byte function selector from calldata.
///
/// The selector is the first 4 bytes, interpreted as a little-endian u32.
pub fn calldata_selector() -> u32 {
    unsafe {
        let ptr = CALLDATA_BASE as *const u32;
        core::ptr::read_volatile(ptr)
    }
}

/// Read `len` bytes from calldata starting at `offset`.
///
/// `offset` is relative to the start of calldata (after selector, use offset=4).
/// Halts with code 0xFE if the read would exceed the calldata bounds.
pub fn calldata_read(offset: u32, buf: &mut [u8]) {
    // Bounds check: prevent reading garbage beyond calldata region
    let end = offset.saturating_add(buf.len() as u32);
    if end > CALLDATA_MAX_SIZE {
        halt(0xFE); // calldata out of bounds
    }
    for (i, byte) in buf.iter_mut().enumerate() {
        unsafe {
            let ptr = (CALLDATA_BASE + offset + i as u32) as *const u8;
            *byte = core::ptr::read_volatile(ptr);
        }
    }
}

/// Read a u64 from calldata at `offset` (little-endian).
pub fn calldata_u64(offset: u32) -> u64 {
    let mut bytes = [0u8; 8];
    calldata_read(offset, &mut bytes);
    u64::from_le_bytes(bytes)
}

/// Read a 20-byte address from calldata at `offset`.
pub fn calldata_address(offset: u32) -> [u8; 20] {
    let mut addr = [0u8; 20];
    calldata_read(offset, &mut addr);
    addr
}

/// Read a 32-byte hash from calldata at `offset`.
pub fn calldata_hash(offset: u32) -> [u8; 32] {
    let mut hash = [0u8; 32];
    calldata_read(offset, &mut hash);
    hash
}

// ── Event Topic Helpers ─────────────────────────────────────────────────────

/// Well-known event topic: Transfer(from, to, amount)
pub const TOPIC_TRANSFER: [u8; 32] = [
    0x54, 0x72, 0x61, 0x6E, 0x73, 0x66, 0x65, 0x72,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Well-known event topic: Approval(owner, spender, amount)
pub const TOPIC_APPROVAL: [u8; 32] = [
    0x41, 0x70, 0x70, 0x72, 0x6F, 0x76, 0x61, 0x6C,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// ── Panic Handler ───────────────────────────────────────────────────────────

#[cfg(target_arch = "riscv32")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt(0xFF) // Revert with error code 255
}
