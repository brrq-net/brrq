use object::{Object, ObjectSegment};
use std::path::{Path, PathBuf};
use std::process::Command;

const TARGET: &str = "riscv32im-unknown-none-elf";

/// Contracts to compile (package name, source dir).
const CONTRACTS: &[(&str, &str)] = &[
    ("proxy", "contracts/system/proxy"),
    ("treasury", "contracts/system/treasury"),
    ("wbrc", "contracts/system/wbrc"),
];

fn main() {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();

    for &(_, src_dir) in CONTRACTS {
        println!(
            "cargo:rerun-if-changed={}/{}/src",
            workspace_root.display(),
            src_dir
        );
    }
    println!(
        "cargo:rerun-if-changed={}/contracts/brrq-contract-sdk/src",
        workspace_root.display()
    );

    for &(name, src_dir) in CONTRACTS {
        let contract_dir = workspace_root.join(src_dir);
        compile_contract(name, &contract_dir, &out_dir);
    }
}

fn compile_contract(name: &str, contract_dir: &Path, out_dir: &Path) {
    let status = Command::new("cargo")
        .args([
            "build",
            "--release",
            "--target",
            TARGET,
            "--manifest-path",
            &contract_dir.join("Cargo.toml").to_string_lossy(),
        ])
        .status()
        .unwrap_or_else(|e| panic!("failed to run cargo build for {}: {}", name, e));

    if !status.success() {
        panic!("cargo build failed for contract '{}'", name);
    }

    let elf_path = contract_dir
        .join("target")
        .join(TARGET)
        .join("release")
        .join(name);

    if !elf_path.exists() {
        panic!("compiled ELF not found at: {}", elf_path.display());
    }

    let elf_data = std::fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("failed to read ELF {}: {}", elf_path.display(), e));

    let binary = elf_to_vm_binary(&elf_data, name);

    let bin_path = out_dir.join(format!("{}.bin", name));
    std::fs::write(&bin_path, &binary)
        .unwrap_or_else(|e| panic!("failed to write {}: {}", bin_path.display(), e));

    eprintln!("contract '{}': {} bytes", name, binary.len());
}

/// Convert an ELF to a flat binary suitable for brrq-vm.
///
/// The VM loads code at address 0 and starts at PC=0.
/// Strategy: extract all LOAD segments into a flat image,
/// then prepend a JAL instruction at address 0 that jumps to the entry point.
fn elf_to_vm_binary(elf_data: &[u8], name: &str) -> Vec<u8> {
    let file = object::File::parse(elf_data)
        .unwrap_or_else(|e| panic!("failed to parse ELF for '{}': {}", name, e));

    let entry = file.entry() as u32;

    // Collect LOAD segments
    let mut segments: Vec<(u32, Vec<u8>, u32)> = Vec::new();
    for segment in file.segments() {
        let data = segment.data().unwrap_or(&[]);
        if data.is_empty() {
            continue;
        }
        let vaddr = segment.address() as u32;
        let memsz = segment.size() as u32;
        segments.push((vaddr, data.to_vec(), memsz));
    }

    if segments.is_empty() {
        panic!("no segments in ELF for '{}'", name);
    }

    let base = segments.iter().map(|(a, _, _)| *a).min().unwrap();
    let end = segments.iter().map(|(a, _, m)| a + m).max().unwrap();

    // Build flat image from base to end
    let total_size = (end - base) as usize;
    let mut image = vec![0u8; total_size];

    for (vaddr, data, _) in &segments {
        let off = (*vaddr - base) as usize;
        let len = data.len().min(image.len() - off);
        image[off..off + len].copy_from_slice(&data[..len]);
    }

    // The VM starts at PC=0. We need the image to start at address 0.
    // If base > 0, prepend padding + a JAL instruction at offset 0 to jump to entry.
    if base == 0 {
        // Code is already at address 0
        return image;
    }

    // Prepend: the final binary maps address 0..end
    let full_size = end as usize;
    let mut binary = vec![0u8; full_size];

    // Copy the image at its correct position
    binary[base as usize..base as usize + image.len()].copy_from_slice(&image);

    // At address 0, place a JAL x0, entry (unconditional jump to entry point).
    // RISC-V JAL encoding: imm[20|10:1|11|19:12] rd opcode
    // JAL x0, offset: rd=0, opcode=0b1101111
    let offset = entry as i32; // Jump target relative to PC=0
    let jal = encode_jal(0, offset);
    binary[0..4].copy_from_slice(&jal.to_le_bytes());

    eprintln!(
        "  base=0x{:x} entry=0x{:x} jal=0x{:08x}",
        base, entry, jal
    );

    binary
}

/// Encode a RISC-V JAL instruction.
/// JAL rd, imm - Jump and link (imm is a signed 21-bit offset, bit 0 always 0).
fn encode_jal(rd: u32, offset: i32) -> u32 {
    let imm = offset as u32;
    // JAL encoding: imm[20] | imm[10:1] | imm[11] | imm[19:12] | rd | 1101111
    let bit20 = (imm >> 20) & 1;
    let bits10_1 = (imm >> 1) & 0x3FF;
    let bit11 = (imm >> 11) & 1;
    let bits19_12 = (imm >> 12) & 0xFF;

    (bit20 << 31) | (bits10_1 << 21) | (bit11 << 20) | (bits19_12 << 12) | (rd << 7) | 0b1101111
}
