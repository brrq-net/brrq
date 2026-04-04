//! Test harness for running compiled contracts in the brrq-vm executor.

use brrq_crypto::hash::Hash256;
use brrq_vm::executor::{ExecutionResult, Executor, StorageProvider};
use std::collections::HashMap;

// Compiled contract binaries (extracted from ELF by build.rs).
// Contracts are linked with link.ld which places .text at address 0.
pub const PROXY_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/proxy.bin"));
pub const TREASURY_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/treasury.bin"));
pub const WBRC_CODE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/wbrc.bin"));

/// Fixed calldata address matching the SDK's CALLDATA_BASE.
const CALLDATA_BASE: u32 = 0x8000_0000;

/// Default gas and step limits for tests.
const TEST_GAS_LIMIT: u64 = 10_000_000;
const TEST_STEP_LIMIT: u64 = 10_000_000;

// ── Storage ────────────────────────────────────────────────────────────────

/// Persistent storage shared across calls in a test session.
pub struct Storage {
    pub data: HashMap<Hash256, Hash256>,
}

impl Storage {
    pub fn new() -> Self {
        Self { data: HashMap::new() }
    }
}

/// Internal storage provider that tracks writes for recovery.
struct Provider {
    data: HashMap<Hash256, Hash256>,
    writes: Vec<(Hash256, Hash256)>,
}

impl StorageProvider for Provider {
    fn storage_get(&self, key: &Hash256) -> Option<Hash256> {
        self.data.get(key).copied()
    }

    fn storage_set(&mut self, key: Hash256, value: Hash256) {
        self.data.insert(key, value);
        self.writes.push((key, value));
    }

    fn drain_writes(&mut self) -> Vec<(Hash256, Hash256)> {
        std::mem::take(&mut self.writes)
    }
}

// ── Contract execution ─────────────────────────────────────────────────────

/// Execute a contract call, updating storage in-place. Returns the VM result.
pub fn run(
    code: &[u8],
    storage: &mut Storage,
    calldata: &[u8],
    caller: &[u8; 20],
    msg_value: u64,
    block_timestamp: u64,
) -> ExecutionResult {
    let mut executor =
        Executor::new(code, TEST_GAS_LIMIT, TEST_STEP_LIMIT).expect("create executor");

    executor.set_contract_address(make_addr("contract"));
    executor.set_caller(brrq_types::Address(*caller));
    executor.set_msg_value(msg_value);
    executor.set_block_context(1, block_timestamp);
    executor.set_storage(Box::new(Provider {
        data: storage.data.clone(),
        writes: Vec::new(),
    }));

    if !calldata.is_empty() {
        executor.write_memory(CALLDATA_BASE, calldata).expect("write calldata");
    }
    // a0 = calldata ptr, a1 = calldata len (proxy's _start(ptr, len) convention)
    executor.set_reg(10, CALLDATA_BASE).expect("set a0");
    executor.set_reg(11, calldata.len() as u32).expect("set a1");

    match executor.run().expect("VM error") {
        brrq_vm::executor::ExecutionState::Halted(result) => {
            // Recover storage writes and apply to shared storage
            if let Some(mut prov) = executor.take_storage() {
                for (k, v) in prov.drain_writes() {
                    storage.data.insert(k, v);
                }
            }
            result
        }
        brrq_vm::executor::ExecutionState::YieldContractCall { .. } => {
            panic!("delegate_call/cross-contract calls not supported in test harness");
        }
    }
}

// ── Address helpers ────────────────────────────────────────────────────────

/// Deterministic test address from a name string.
pub fn addr(name: &str) -> [u8; 20] {
    let hash = brrq_crypto::hash::Hasher::hash(name.as_bytes());
    let mut a = [0u8; 20];
    a.copy_from_slice(&hash.as_bytes()[..20]);
    a
}

fn make_addr(name: &str) -> brrq_types::Address {
    brrq_types::Address(addr(name))
}

// ── Calldata builders ──────────────────────────────────────────────────────

/// 4-byte LE selector only.
pub fn sel(s: u32) -> Vec<u8> {
    s.to_le_bytes().to_vec()
}

/// Selector + 20-byte address.
pub fn sel_addr(s: u32, a: &[u8; 20]) -> Vec<u8> {
    let mut cd = s.to_le_bytes().to_vec();
    cd.extend_from_slice(a);
    cd
}

/// Selector + 20-byte address + u64 amount.
pub fn sel_addr_u64(s: u32, a: &[u8; 20], amount: u64) -> Vec<u8> {
    let mut cd = s.to_le_bytes().to_vec();
    cd.extend_from_slice(a);
    cd.extend_from_slice(&amount.to_le_bytes());
    cd
}

/// Selector + u64.
pub fn sel_u64(s: u32, val: u64) -> Vec<u8> {
    let mut cd = s.to_le_bytes().to_vec();
    cd.extend_from_slice(&val.to_le_bytes());
    cd
}

/// Selector + addr + addr + u64.
pub fn sel_addr_addr_u64(s: u32, a1: &[u8; 20], a2: &[u8; 20], amount: u64) -> Vec<u8> {
    let mut cd = s.to_le_bytes().to_vec();
    cd.extend_from_slice(a1);
    cd.extend_from_slice(a2);
    cd.extend_from_slice(&amount.to_le_bytes());
    cd
}

/// Selector + two addresses (for allowance query).
pub fn sel_addr_addr(s: u32, a1: &[u8; 20], a2: &[u8; 20]) -> Vec<u8> {
    let mut cd = s.to_le_bytes().to_vec();
    cd.extend_from_slice(a1);
    cd.extend_from_slice(a2);
    cd
}

// ── Proxy-specific calldata (1-byte selector, not 4-byte) ──────────────────

/// Proxy calldata: 1-byte selector + 20-byte address.
pub fn proxy_sel_addr(s: u8, a: &[u8; 20]) -> Vec<u8> {
    let mut cd = vec![s];
    cd.extend_from_slice(a);
    cd
}

/// Proxy calldata: 1-byte selector only.
pub fn proxy_sel(s: u8) -> Vec<u8> {
    vec![s]
}

/// Proxy calldata: 1-byte selector + 1-byte flag.
pub fn proxy_sel_flag(s: u8, flag: u8) -> Vec<u8> {
    vec![s, flag]
}

// ── Output decoders ────────────────────────────────────────────────────────

/// Decode output as little-endian u64.
pub fn output_u64(result: &ExecutionResult) -> u64 {
    assert!(result.output.len() >= 8, "output too short for u64");
    u64::from_le_bytes(result.output[..8].try_into().unwrap())
}

/// Decode output as 20-byte address.
pub fn output_addr(result: &ExecutionResult) -> [u8; 20] {
    assert!(result.output.len() >= 20, "output too short for address");
    result.output[..20].try_into().unwrap()
}
