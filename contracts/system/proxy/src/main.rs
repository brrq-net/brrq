#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use brrq_contract_sdk::*;

// ── Bump allocator for alloc (single-threaded VM, never frees) ─────────────
struct BumpAlloc;

static mut HEAP_POS: usize = 0x4000_0000;

unsafe impl core::alloc::GlobalAlloc for BumpAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        let align = layout.align();
        let aligned = (HEAP_POS + align - 1) & !(align - 1);
        HEAP_POS = aligned + layout.size();
        aligned as *mut u8
    }
    unsafe fn dealloc(&self, _: *mut u8, _: core::alloc::Layout) {}
}

#[global_allocator]
static ALLOC: BumpAlloc = BumpAlloc;

// Deterministic key for the implementation address.
const IMPL_SLOT_KEY: [u8; 32] = [
    0x36, 0x08, 0x94, 0xa1, 0x3b, 0xa1, 0xa3, 0x21, 0x06, 0x67, 0xc8, 0x28, 0x49, 0x2d, 0xb9, 0x8d,
    0xca, 0x3e, 0x20, 0x76, 0xcc, 0x37, 0x35, 0xa9, 0x20, 0xa3, 0xca, 0x50, 0x5d, 0x38, 0x2b, 0xbc,
];

// Deterministic key for the proxy admin/owner.
const ADMIN_SLOT_KEY: [u8; 32] = [
    0xb5, 0x31, 0x27, 0x68, 0x4a, 0x56, 0x8b, 0x31, 0x73, 0xae, 0x13, 0xb9, 0xf8, 0xa6, 0x01, 0x6e,
    0x24, 0x3e, 0x63, 0xb6, 0xe8, 0xee, 0x11, 0x78, 0xd6, 0xa7, 0x17, 0x85, 0x0b, 0x5d, 0x61, 0x03,
];

// Pending admin for two-step transfer.
const PENDING_ADMIN_SLOT_KEY: [u8; 32] = [
    0xd1, 0x42, 0x8e, 0x33, 0x7a, 0x6f, 0x12, 0x55, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
    0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0xaa, 0xbb, 0xcc, 0xdd,
];

// Paused flag — admin can freeze the proxy.
const PAUSED_SLOT_KEY: [u8; 32] = [
    0xe2, 0x53, 0x9f, 0x44, 0x8b, 0x70, 0x23, 0x66, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78,
    0x9a, 0xbc, 0xde, 0xf0, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0xbb, 0xcc, 0xdd, 0xee,
];

/// Helper: load admin and verify caller is admin. Halts on failure.
fn require_admin() -> [u8; 20] {
    let (admin_val, exists) = sload(&ADMIN_SLOT_KEY);
    if !exists {
        halt(2); // Not initialized
    }
    let mut admin = [0u8; 20];
    admin.copy_from_slice(&admin_val[..20]);
    let caller = msg_sender();
    if caller != admin {
        halt(4); // Unauthorized
    }
    admin
}

#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn _start(calldata_ptr: *const u8, calldata_len: usize) {
    // Bounds check before raw pointer dereference.
    if calldata_len == 0 {
        halt(5); // Empty calldata
    }
    if calldata_len > 16_384 {
        halt(0xFE); // Calldata exceeds max size
    }
    let call_data = unsafe { core::slice::from_raw_parts(calldata_ptr, calldata_len) };

    match call_data[0] {
        // 0xF0: Init proxy (21 bytes: selector + 20-byte impl)
        // Admin is set to msg_sender() — only the deployer
        // (who sends the init transaction) becomes admin. This prevents front-running
        // because the attacker's msg_sender() would set themselves as admin of their
        // own init call, but the legitimate deployer's transaction will fail (already
        // initialized) if the attacker's went first — making the attack detectable.
        0xF0 if call_data.len() == 21 => {
            let (existing, exists) = sload(&IMPL_SLOT_KEY);
            if exists && existing != [0u8; 32] {
                halt(1); // Already initialized
            }
            let mut new_impl = [0u8; 32];
            new_impl[..20].copy_from_slice(&call_data[1..21]);
            sstore(&IMPL_SLOT_KEY, &new_impl);

            // Admin = caller (deployer). Cannot be front-run to set a different admin.
            let caller = msg_sender();
            let mut admin = [0u8; 32];
            admin[..20].copy_from_slice(&caller);
            sstore(&ADMIN_SLOT_KEY, &admin);

            halt(0);
        }

        // 0xF1: Upgrade implementation (21 bytes: selector + 20-byte new impl)
        0xF1 if call_data.len() == 21 => {
            require_admin();

            let mut new_impl = [0u8; 32];
            new_impl[..20].copy_from_slice(&call_data[1..21]);
            sstore(&IMPL_SLOT_KEY, &new_impl);
            halt(0);
        }

        // 0xF2 — Propose new admin (two-step transfer)
        // 21 bytes: selector + 20-byte proposed admin
        0xF2 if call_data.len() == 21 => {
            require_admin();

            let mut pending = [0u8; 32];
            pending[..20].copy_from_slice(&call_data[1..21]);
            sstore(&PENDING_ADMIN_SLOT_KEY, &pending);
            halt(0);
        }

        // 0xF3 — Accept admin transfer
        // 1 byte: selector only. Must be called by the pending admin.
        0xF3 if call_data.len() == 1 => {
            let (pending_val, exists) = sload(&PENDING_ADMIN_SLOT_KEY);
            if !exists || pending_val == [0u8; 32] {
                halt(6); // No pending admin
            }
            let mut pending_admin = [0u8; 20];
            pending_admin.copy_from_slice(&pending_val[..20]);
            let caller = msg_sender();
            if caller != pending_admin {
                halt(4); // Unauthorized — only pending admin can accept
            }

            // Transfer admin
            let mut new_admin = [0u8; 32];
            new_admin[..20].copy_from_slice(&pending_admin);
            sstore(&ADMIN_SLOT_KEY, &new_admin);

            // Clear pending
            sstore(&PENDING_ADMIN_SLOT_KEY, &[0u8; 32]);
            halt(0);
        }

        // 0xF4 — Pause/unpause proxy (emergency stop)
        // 2 bytes: selector + 0x01 (pause) or 0x00 (unpause)
        0xF4 if call_data.len() == 2 => {
            require_admin();

            let mut paused = [0u8; 32];
            paused[0] = call_data[1]; // 0x01 = paused, 0x00 = unpaused
            sstore(&PAUSED_SLOT_KEY, &paused);
            halt(0);
        }

        // Standard fallback: Delegate call to the implementation.
        _ => {
            // Check if proxy is paused
            let (paused_val, paused_exists) = sload(&PAUSED_SLOT_KEY);
            if paused_exists && paused_val[0] == 0x01 {
                halt(7); // Proxy is paused
            }

            let (impl_val, exists) = sload(&IMPL_SLOT_KEY);
            if !exists {
                halt(2); // Not initialized
            }

            let mut target = [0u8; 20];
            target.copy_from_slice(&impl_val[..20]);

            // Delegate call
            if delegate_call_contract(&target, call_data) {
                let size = return_data_size();
                let mut ret = vec![0u8; size];
                return_data_copy(&mut ret);
                write_output(&ret);
                halt(0);
            } else {
                let size = return_data_size();
                let mut ret = vec![0u8; size];
                return_data_copy(&mut ret);
                write_output(&ret);
                halt(3); // Call failed
            }
        }
    }
}
