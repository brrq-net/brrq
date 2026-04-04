//! Harvard-style memory subsystem for the RISC-V zkVM.
//!
//! ## Design (§4.3)
//!
//! - 4 GB addressable space (32-bit)
//! - Code segment is read-only after loading
//! - Data segment is read-write
//! - Stack grows downward from high addresses
//! - Heap grows upward from after data
//!
//! ## Memory Layout
//!
//! ```text
//! 0x00000000 ┌───────────────┐
//!            │  Code (R/O)   │
//! code_end   ├───────────────┤
//!            │  Data (R/W)   │
//! data_end   ├───────────────┤
//!            │  Heap ↓       │
//!            │               │
//!            │  Stack ↑      │
//! 0xFFFFFFFF └───────────────┘
//! ```
//!
//! Memory is stored in sparse pages to avoid allocating 4 GB upfront.

use crate::error::VmError;
use std::collections::{BTreeMap, HashSet};

/// Page size: 4 KB (4096 bytes).
const PAGE_SIZE: usize = 4096;
const PAGE_MASK: u32 = (PAGE_SIZE - 1) as u32;

/// Maximum memory pages = 16,384 × 4 KB = 64 MB (strict).
///
/// Memory page limit aligned with whitepaper specification.
/// Math: 16,384 pages × 4,096 bytes/page = 67,108,864 bytes = 64 MiB exactly.
pub const DEFAULT_MAX_PAGES: u32 = 16_384;

/// Sparse memory — only pages that are accessed get allocated.
#[derive(Clone)]
pub struct Memory {
    /// Sparse page storage: page_number → page_data.
    /// Uses BTreeMap (not HashMap) for deterministic iteration order,
    /// which is required for reproducible STARK proof generation.
    pages: BTreeMap<u32, Box<[u8; PAGE_SIZE]>>,
    /// End of code segment (exclusive). Writes below this address are forbidden.
    code_end: u32,
    /// Total bytes read (for tracing/gas).
    pub reads: u64,
    /// Total bytes written (for tracing/gas).
    pub writes: u64,
    /// Maximum number of pages that can be allocated.
    /// Prevents unbounded memory growth from malicious programs.
    max_pages: u32,
    /// Set of page numbers that have been written to (including code load).
    /// Used in strict mode to detect reads from uninitialized memory, which could
    /// allow an attacker to inject values via the default-zero assumption.
    initialized_pages: HashSet<u32>,
    /// When true, reading from a page that was never written to returns
    /// an error instead of zero. This catches write-before-read violations that
    /// could be exploited via memory access pattern injection.
    strict_mode: bool,
    /// Highest data address accessed (for EVM-style memory gas).
    pub highest_data_address: u32,
}

impl Memory {
    /// Create an empty memory with the default maximum page limit (64 MB).
    pub fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            code_end: 0,
            reads: 0,
            writes: 0,
            max_pages: DEFAULT_MAX_PAGES,
            initialized_pages: HashSet::new(),
            strict_mode: false,
            highest_data_address: 0,
        }
    }

    /// Create an empty memory with a custom maximum page limit.
    ///
    /// Each page is 4 KB, so `max_pages = 1024` would allow up to 4 MB.
    pub fn new_with_max_pages(max_pages: u32) -> Self {
        // Clamp to DEFAULT_MAX_PAGES to prevent caller bypassing memory limit
        let clamped = max_pages.min(DEFAULT_MAX_PAGES);
        Self {
            pages: BTreeMap::new(),
            code_end: 0,
            reads: 0,
            writes: 0,
            max_pages: clamped,
            initialized_pages: HashSet::new(),
            strict_mode: false,
            highest_data_address: 0,
        }
    }

    /// Track the highest accessed data address for memory gas calculation.
    fn track_data_access(&mut self, _addr: u32, _size: u32) {
        // No-op: Since we use a sparse page model, active memory gas is now
        // calculated directly from `self.pages.len()` to properly account
        // for both heap and stack allocations without artificial linear bounds.
    }

    /// Calculate the number of 32-byte words currently active in the data segment.
    pub fn active_data_words(&self) -> u64 {
        // Each 4KB page contains 128 32-byte EVM words.
        // This accurately meters both stack and heap usage in our sparse model.
        (self.pages.len() as u64) * (PAGE_SIZE as u64 / 32)
    }

    /// Enable strict mode to detect write-before-read violations.
    ///
    /// In strict mode, reading from a page that was never written to
    /// (or loaded as code) will return `VmError::UninitializedRead`
    /// instead of silently returning zero.
    pub fn enable_strict_mode(&mut self) {
        self.strict_mode = true;
    }

    /// Check if strict mode is enabled.
    pub fn is_strict_mode(&self) -> bool {
        self.strict_mode
    }

    /// Ensure a page is allocated, returning a mutable reference to it.
    /// Returns an error if the allocation would exceed the maximum page limit.
    fn ensure_page(&mut self, page_num: u32) -> Result<&mut Box<[u8; PAGE_SIZE]>, VmError> {
        if !self.pages.contains_key(&page_num) {
            if self.pages.len() as u32 >= self.max_pages {
                // Convert page number back to an address for the error message
                return Err(VmError::MemoryOutOfBounds {
                    addr: page_num.wrapping_mul(PAGE_SIZE as u32),
                });
            }
            self.pages.insert(page_num, Box::new([0u8; PAGE_SIZE]));
        }
        // The key was just inserted above, so this should always succeed,
        // but we use fallible error instead of unwrap to avoid panics in production.
        self.pages
            .get_mut(&page_num)
            .ok_or(VmError::MemoryOutOfBounds {
                addr: page_num.wrapping_mul(PAGE_SIZE as u32),
            })
    }

    /// Load code into memory starting at address 0.
    ///
    /// After loading, the code region [0, code.len()) is marked read-only.
    /// Also marks all code pages as initialized for strict mode.
    pub fn load_code(&mut self, code: &[u8]) -> Result<(), VmError> {
        let len = code.len();
        for (i, &byte) in code.iter().enumerate() {
            let addr = i as u32;
            let page_num = addr / PAGE_SIZE as u32;
            let offset = (addr & PAGE_MASK) as usize;
            let page = self.ensure_page(page_num)?;
            page[offset] = byte;
            // Mark code pages as initialized for strict mode
            self.initialized_pages.insert(page_num);
        }
        // Explicit bounds check for code length truncation.
        // On 64-bit systems, Vec<u8> could theoretically exceed u32::MAX,
        // though the page limit would reject it first.
        if len > u32::MAX as usize {
            return Err(VmError::MemoryOutOfBounds { addr: u32::MAX });
        }
        self.code_end = len as u32;
        Ok(())
    }

    /// Read a single byte.
    ///
    /// In strict mode, returns error for reads from uninitialized pages.
    pub fn read_byte(&mut self, addr: u32) -> Result<u8, VmError> {
        self.track_data_access(addr, 1);
        self.reads += 1;
        let page_num = addr / PAGE_SIZE as u32;
        let offset = (addr & PAGE_MASK) as usize;
        if let Some(page) = self.pages.get(&page_num) {
            Ok(page[offset])
        } else if self.strict_mode && !self.initialized_pages.contains(&page_num) {
            Err(VmError::UninitializedRead { addr })
        } else {
            Ok(0)
        }
    }

    /// Read a 16-bit halfword (little-endian). Must be 2-byte aligned.
    ///
    /// Optimized: single page lookup for both bytes (aligned access guarantees same page).
    /// In strict mode, returns error for reads from uninitialized pages.
    pub fn read_halfword(&mut self, addr: u32) -> Result<u16, VmError> {
        if addr & 1 != 0 {
            return Err(VmError::UnalignedAccess { addr });
        }
        self.track_data_access(addr, 2);
        self.reads += 2;
        let page_num = addr / PAGE_SIZE as u32;
        let offset = (addr & PAGE_MASK) as usize;
        if let Some(page) = self.pages.get(&page_num) {
            Ok(u16::from_le_bytes([page[offset], page[offset + 1]]))
        } else if self.strict_mode && !self.initialized_pages.contains(&page_num) {
            Err(VmError::UninitializedRead { addr })
        } else {
            Ok(0)
        }
    }

    /// Read a 32-bit word (little-endian). Must be 4-byte aligned.
    ///
    /// Optimized: single page lookup for all 4 bytes (aligned access guarantees same page).
    /// In strict mode, returns error for reads from uninitialized pages.
    pub fn read_word(&mut self, addr: u32) -> Result<u32, VmError> {
        if addr & 3 != 0 {
            return Err(VmError::UnalignedAccess { addr });
        }
        self.track_data_access(addr, 4);
        self.reads += 4;
        let page_num = addr / PAGE_SIZE as u32;
        let offset = (addr & PAGE_MASK) as usize;
        if let Some(page) = self.pages.get(&page_num) {
            Ok(u32::from_le_bytes([
                page[offset],
                page[offset + 1],
                page[offset + 2],
                page[offset + 3],
            ]))
        } else if self.strict_mode && !self.initialized_pages.contains(&page_num) {
            Err(VmError::UninitializedRead { addr })
        } else {
            Ok(0)
        }
    }

    /// Fetch a 32-bit instruction from the code segment.
    ///
    /// Uses separate read counter tracking for code fetches.
    /// Optimized: single page lookup for all 4 bytes.
    pub fn fetch_instruction(&mut self, pc: u32) -> Result<u32, VmError> {
        if pc & 3 != 0 {
            return Err(VmError::UnalignedAccess { addr: pc });
        }
        // Instructions can only be fetched from code region
        // Use checked_add to prevent wrapping past 0xFFFFFFFF
        if pc.checked_add(4).is_none_or(|end| end > self.code_end) {
            return Err(VmError::MemoryOutOfBounds { addr: pc });
        }
        // Read without incrementing the data reads counter
        let page_num = pc / PAGE_SIZE as u32;
        let offset = (pc & PAGE_MASK) as usize;
        if let Some(page) = self.pages.get(&page_num) {
            Ok(u32::from_le_bytes([
                page[offset],
                page[offset + 1],
                page[offset + 2],
                page[offset + 3],
            ]))
        } else {
            Ok(0)
        }
    }

    /// Write a single byte. Fails if writing to code segment or exceeding memory limit.
    /// Marks the page as initialized for strict mode tracking.
    pub fn write_byte(&mut self, addr: u32, value: u8) -> Result<(), VmError> {
        if addr < self.code_end {
            return Err(VmError::WriteToCode { addr });
        }
        self.track_data_access(addr, 1);
        self.writes += 1;
        let page_num = addr / PAGE_SIZE as u32;
        let offset = (addr & PAGE_MASK) as usize;
        let page = self.ensure_page(page_num)?;
        page[offset] = value;
        self.initialized_pages.insert(page_num);
        Ok(())
    }

    /// Write a 16-bit halfword (little-endian). Must be 2-byte aligned.
    ///
    /// Optimized: single page lookup for both bytes.
    /// Marks the page as initialized for strict mode tracking.
    pub fn write_halfword(&mut self, addr: u32, value: u16) -> Result<(), VmError> {
        if addr & 1 != 0 {
            return Err(VmError::UnalignedAccess { addr });
        }
        if addr < self.code_end {
            return Err(VmError::WriteToCode { addr });
        }
        self.track_data_access(addr, 2);
        self.writes += 2;
        let page_num = addr / PAGE_SIZE as u32;
        let offset = (addr & PAGE_MASK) as usize;
        let page = self.ensure_page(page_num)?;
        let bytes = value.to_le_bytes();
        page[offset] = bytes[0];
        page[offset + 1] = bytes[1];
        self.initialized_pages.insert(page_num);
        Ok(())
    }

    /// Write a 32-bit word (little-endian). Must be 4-byte aligned.
    ///
    /// Optimized: single page lookup for all 4 bytes.
    /// Marks the page as initialized for strict mode tracking.
    pub fn write_word(&mut self, addr: u32, value: u32) -> Result<(), VmError> {
        if addr & 3 != 0 {
            return Err(VmError::UnalignedAccess { addr });
        }
        if addr < self.code_end {
            return Err(VmError::WriteToCode { addr });
        }
        self.track_data_access(addr, 4);
        self.writes += 4;
        let page_num = addr / PAGE_SIZE as u32;
        let offset = (addr & PAGE_MASK) as usize;
        let page = self.ensure_page(page_num)?;
        let bytes = value.to_le_bytes();
        page[offset] = bytes[0];
        page[offset + 1] = bytes[1];
        page[offset + 2] = bytes[2];
        page[offset + 3] = bytes[3];
        self.initialized_pages.insert(page_num);
        Ok(())
    }

    /// Number of allocated pages.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Code segment size in bytes.
    pub fn code_size(&self) -> u32 {
        self.code_end
    }

    /// Maximum number of pages allowed.
    pub fn max_pages(&self) -> u32 {
        self.max_pages
    }

    /// Read a contiguous block of bytes from memory.
    ///
    /// Optimized: performs page lookups per-page rather than per-byte, copying chunks at a time.
    /// In strict mode, returns error for reads from uninitialized pages.
    pub fn read_bytes(&mut self, start_addr: u32, out: &mut [u8]) -> Result<(), VmError> {
        if out.len() > u32::MAX as usize {
            return Err(VmError::MemoryOutOfBounds { addr: start_addr });
        }
        if start_addr.checked_add(out.len() as u32).is_none() {
            return Err(VmError::MemoryOutOfBounds { addr: start_addr });
        }
        self.track_data_access(start_addr, out.len() as u32);
        let mut current_addr = start_addr;
        let mut bytes_left = out.len();
        let mut out_offset = 0;

        while bytes_left > 0 {
            let page_num = current_addr / PAGE_SIZE as u32;
            let page_offset = (current_addr & PAGE_MASK) as usize;
            let space_in_page = PAGE_SIZE - page_offset;
            let to_read = bytes_left.min(space_in_page);

            self.reads += to_read as u64;

            if let Some(page) = self.pages.get(&page_num) {
                out[out_offset..out_offset + to_read]
                    .copy_from_slice(&page[page_offset..page_offset + to_read]);
            } else if self.strict_mode && !self.initialized_pages.contains(&page_num) {
                return Err(VmError::UninitializedRead { addr: current_addr });
            } else {
                out[out_offset..out_offset + to_read].fill(0);
            }

            current_addr = current_addr.wrapping_add(to_read as u32);
            out_offset += to_read;
            bytes_left -= to_read;
        }
        Ok(())
    }

    /// Write a contiguous block of bytes into data memory.
    ///
    /// Optimized: performs page lookups per-page rather than per-byte, copying chunks at a time.
    pub fn write_bytes(&mut self, start_addr: u32, data: &[u8]) -> Result<(), VmError> {
        if start_addr < self.code_end {
            return Err(VmError::WriteToCode { addr: start_addr });
        }
        if data.len() > u32::MAX as usize {
            return Err(VmError::MemoryOutOfBounds { addr: start_addr });
        }
        let end_addr = start_addr.wrapping_add(data.len() as u32);
        // Comprehensive wrap-around check.
        // If the write wraps around the address space (end_addr < start_addr),
        // it will touch addresses [start_addr..0xFFFFFFFF] ∪ [0..end_addr],
        // potentially overwriting the code segment at low addresses.
        if end_addr < start_addr && self.code_end > 0 {
            return Err(VmError::WriteToCode { addr: 0 });
        }
        if end_addr > start_addr && end_addr <= self.code_end {
            return Err(VmError::WriteToCode { addr: start_addr });
        }

        self.track_data_access(start_addr, data.len() as u32);
        let mut current_addr = start_addr;
        let mut bytes_left = data.len();
        let mut data_offset = 0;

        while bytes_left > 0 {
            let page_num = current_addr / PAGE_SIZE as u32;
            let page_offset = (current_addr & PAGE_MASK) as usize;
            let space_in_page = PAGE_SIZE - page_offset;
            let to_write = bytes_left.min(space_in_page);

            self.writes += to_write as u64;

            let page = self.ensure_page(page_num)?;

            page[page_offset..page_offset + to_write]
                .copy_from_slice(&data[data_offset..data_offset + to_write]);
            // Mark written pages as initialized for strict mode
            self.initialized_pages.insert(page_num);

            current_addr = current_addr.wrapping_add(to_write as u32);
            data_offset += to_write;
            bytes_left -= to_write;
        }
        Ok(())
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Memory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Memory")
            .field("pages", &self.pages.len())
            .field("code_end", &format!("0x{:08x}", self.code_end))
            .field("reads", &self.reads)
            .field("writes", &self.writes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_memory_reads_zero() {
        let mut mem = Memory::new();
        assert_eq!(mem.read_byte(0x1000).unwrap(), 0);
        assert_eq!(mem.read_byte(0xFFFFFFFF).unwrap(), 0);
    }

    #[test]
    fn test_load_code() {
        let mut mem = Memory::new();
        let code = vec![0x13, 0x00, 0x00, 0x00]; // NOP (ADDI x0, x0, 0)
        mem.load_code(&code).unwrap();
        assert_eq!(mem.code_size(), 4);
        assert_eq!(mem.read_byte(0).unwrap(), 0x13);
        assert_eq!(mem.read_byte(1).unwrap(), 0x00);
        assert_eq!(mem.read_byte(2).unwrap(), 0x00);
        assert_eq!(mem.read_byte(3).unwrap(), 0x00);
    }

    #[test]
    fn test_write_byte_data_region() {
        let mut mem = Memory::new();
        mem.load_code(&[0; 16]).unwrap(); // 16 bytes of code
        // Write to data region (after code)
        mem.write_byte(16, 0xAB).unwrap();
        assert_eq!(mem.read_byte(16).unwrap(), 0xAB);
    }

    #[test]
    fn test_write_to_code_fails() {
        let mut mem = Memory::new();
        mem.load_code(&[0; 16]).unwrap();
        let result = mem.write_byte(8, 0xFF);
        assert!(result.is_err());
    }

    #[test]
    fn test_word_read_write() {
        let mut mem = Memory::new();
        // No code loaded, so code_end = 0, all writable
        mem.write_word(0x1000, 0xDEADBEEF).unwrap();
        let val = mem.read_word(0x1000).unwrap();
        assert_eq!(val, 0xDEADBEEF);
    }

    #[test]
    fn test_halfword_read_write() {
        let mut mem = Memory::new();
        mem.write_halfword(0x2000, 0xCAFE).unwrap();
        let val = mem.read_halfword(0x2000).unwrap();
        assert_eq!(val, 0xCAFE);
    }

    #[test]
    fn test_unaligned_word_fails() {
        let mut mem = Memory::new();
        let result = mem.read_word(0x1001);
        assert!(result.is_err());
    }

    #[test]
    fn test_unaligned_halfword_fails() {
        let mut mem = Memory::new();
        let result = mem.read_halfword(0x1001);
        assert!(result.is_err());
    }

    #[test]
    fn test_fetch_instruction() {
        let mut mem = Memory::new();
        // ADDI x0, x0, 0 → 0x00000013
        let code = 0x00000013u32.to_le_bytes();
        mem.load_code(&code).unwrap();
        let inst = mem.fetch_instruction(0).unwrap();
        assert_eq!(inst, 0x00000013);
    }

    #[test]
    fn test_sparse_allocation() {
        let mut mem = Memory::new();
        // Write to two far-apart addresses
        mem.write_byte(0x00001000, 1).unwrap();
        mem.write_byte(0x10001000, 2).unwrap();
        // Should only allocate 2 pages
        assert_eq!(mem.page_count(), 2);
        assert_eq!(mem.read_byte(0x00001000).unwrap(), 1);
        assert_eq!(mem.read_byte(0x10001000).unwrap(), 2);
    }

    #[test]
    fn test_little_endian_word() {
        let mut mem = Memory::new();
        // Write bytes individually
        mem.write_byte(0x1000, 0x78).unwrap();
        mem.write_byte(0x1001, 0x56).unwrap();
        mem.write_byte(0x1002, 0x34).unwrap();
        mem.write_byte(0x1003, 0x12).unwrap();
        // Read as word should be little-endian
        let val = mem.read_word(0x1000).unwrap();
        assert_eq!(val, 0x12345678);
    }

    #[test]
    fn test_read_write_counters() {
        let mut mem = Memory::new();
        mem.write_byte(0x1000, 0xAA).unwrap();
        mem.write_byte(0x1001, 0xBB).unwrap();
        assert_eq!(mem.writes, 2);
        let _ = mem.read_byte(0x1000);
        let _ = mem.read_byte(0x1001);
        let _ = mem.read_byte(0x1002);
        assert_eq!(mem.reads, 3);
    }

    // ── Memory bounds / max_pages tests ──────────────────────────

    #[test]
    fn test_max_pages_default() {
        let mem = Memory::new();
        assert_eq!(mem.max_pages(), DEFAULT_MAX_PAGES);
    }

    #[test]
    fn test_max_pages_custom() {
        let mem = Memory::new_with_max_pages(10);
        assert_eq!(mem.max_pages(), 10);
    }

    #[test]
    fn test_write_within_page_limit() {
        // Allow only 2 pages (8 KB)
        let mut mem = Memory::new_with_max_pages(2);
        // Write to two different pages (page 0 and page 1)
        mem.write_byte(0, 0xAA).unwrap();
        mem.write_byte(PAGE_SIZE as u32, 0xBB).unwrap();
        assert_eq!(mem.page_count(), 2);
        assert_eq!(mem.read_byte(0).unwrap(), 0xAA);
        assert_eq!(mem.read_byte(PAGE_SIZE as u32).unwrap(), 0xBB);
    }

    #[test]
    fn test_write_exceeds_page_limit() {
        // Allow only 2 pages
        let mut mem = Memory::new_with_max_pages(2);
        // Fill up 2 pages
        mem.write_byte(0, 0xAA).unwrap(); // page 0
        mem.write_byte(PAGE_SIZE as u32, 0xBB).unwrap(); // page 1
        // Third page should fail
        let result = mem.write_byte(PAGE_SIZE as u32 * 2, 0xCC);
        assert!(
            result.is_err(),
            "writing to a 3rd page when max_pages=2 must fail"
        );
    }

    #[test]
    fn test_write_word_exceeds_page_limit() {
        let mut mem = Memory::new_with_max_pages(1);
        // First write goes to page 0
        mem.write_word(0, 0xDEADBEEF).unwrap();
        // Writing to a different page should fail
        let result = mem.write_word(PAGE_SIZE as u32, 0xCAFEBABE);
        assert!(
            result.is_err(),
            "write_word to a new page beyond limit must fail"
        );
    }

    #[test]
    fn test_write_halfword_exceeds_page_limit() {
        let mut mem = Memory::new_with_max_pages(1);
        mem.write_halfword(0, 0xBEEF).unwrap();
        let result = mem.write_halfword(PAGE_SIZE as u32, 0xCAFE);
        assert!(
            result.is_err(),
            "write_halfword to a new page beyond limit must fail"
        );
    }

    #[test]
    fn test_write_bytes_exceeds_page_limit() {
        let mut mem = Memory::new_with_max_pages(1);
        // Write within page 0 — should succeed
        mem.write_bytes(0, &[1, 2, 3, 4]).unwrap();
        // Write spanning into page 1 — should fail
        let data = vec![0xABu8; PAGE_SIZE + 1];
        let result = mem.write_bytes(0, &data);
        assert!(
            result.is_err(),
            "write_bytes spanning beyond page limit must fail"
        );
    }

    #[test]
    fn test_load_code_exceeds_page_limit() {
        let mut mem = Memory::new_with_max_pages(1);
        // Code that fits in 1 page (4096 bytes) should succeed
        let small_code = vec![0x13u8; PAGE_SIZE];
        assert!(mem.load_code(&small_code).is_ok());

        // Code that needs 2 pages should fail
        let mut mem2 = Memory::new_with_max_pages(1);
        let big_code = vec![0x13u8; PAGE_SIZE + 1];
        assert!(
            mem2.load_code(&big_code).is_err(),
            "load_code exceeding page limit must fail"
        );
    }

    #[test]
    fn test_rewrite_same_page_does_not_count_new() {
        // Rewriting within the same page should not allocate new pages
        let mut mem = Memory::new_with_max_pages(1);
        mem.write_byte(0, 0xAA).unwrap();
        mem.write_byte(1, 0xBB).unwrap();
        mem.write_byte(100, 0xCC).unwrap();
        assert_eq!(
            mem.page_count(),
            1,
            "all writes to same page should reuse it"
        );
    }

    #[test]
    fn test_reads_from_unallocated_pages_return_zero_without_allocating() {
        // Reading from an unallocated page should return 0 and NOT allocate
        let mut mem = Memory::new_with_max_pages(0); // No pages allowed
        assert_eq!(mem.read_byte(0x1000).unwrap(), 0);
        assert_eq!(mem.read_word(0x1000).unwrap(), 0);
        assert_eq!(mem.page_count(), 0, "reads should not allocate pages");
    }
}
