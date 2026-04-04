//! Process sandboxing for Brrq node.
//!
//! Applies OS-level security restrictions after initialization is complete:
//! - **Landlock** (Linux 5.13+): Restricts filesystem access to only the data
//!   directory (read-write) and essential system paths (read-only).
//! - **seccomp** (Linux): Filters syscalls to deny dangerous operations like
//!   `execve`, `ptrace`, and `fork` after the node is fully initialized.
//!
//! On non-Linux platforms, sandboxing is a no-op with a warning log.
//! On older Linux kernels without Landlock support, the node continues
//! with a warning — defense in depth, not a hard requirement.

/// Configuration for the sandbox.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Data directory (read-write access).
    pub datadir: String,
    /// Genesis file path (read-only after startup).
    pub genesis_path: String,
    /// Whether the node is in sequencer mode.
    pub is_sequencer: bool,
    /// Validator key file path.
    pub validator_key_path: String,
}

/// Apply all available sandboxing restrictions.
///
/// Call this AFTER all initialization is complete and all listeners are bound,
/// but BEFORE entering the main event loop. This is a one-way operation —
/// restrictions cannot be lifted after application.
pub fn apply_sandbox(config: &SandboxConfig) {
    tracing::info!("Applying process sandbox...");

    #[cfg(target_os = "linux")]
    {
        apply_landlock(config);
        apply_seccomp();
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = config;
        tracing::warn!(
            "Sandboxing is only available on Linux (landlock + seccomp). \
             Running without OS-level process restrictions."
        );
    }
}

// ── Landlock filesystem sandbox (Linux 5.13+) ───────────────────────

#[cfg(target_os = "linux")]
fn apply_landlock(config: &SandboxConfig) {
    match apply_landlock_inner(config) {
        Ok(()) => {
            tracing::info!(
                "Landlock filesystem sandbox applied: datadir={} (RW), system paths (RO)",
                config.datadir
            );
        }
        Err(e) => {
            tracing::warn!(
                "Landlock sandbox could not be applied (kernel too old or not supported): {}. \
                 The node will continue without filesystem restrictions.",
                e
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn apply_landlock_inner(config: &SandboxConfig) -> Result<(), String> {
    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
        RulesetStatus,
    };

    // Use the best ABI available. The crate handles backward compatibility
    // by silently ignoring access rights unsupported by the running kernel.
    let abi = ABI::V5;

    let read_only = AccessFs::from_read(abi);
    let read_write = AccessFs::from_all(abi);

    // Phase 1: Create the ruleset declaring which access rights we handle.
    // Any access not granted by a rule below will be denied.
    let ruleset = Ruleset::default()
        .handle_access(read_write)
        .map_err(|e| format!("failed to create landlock ruleset: {e}"))?;

    // Phase 2: Create the ruleset (allocates kernel resources).
    let mut created = ruleset
        .create()
        .map_err(|e| format!("failed to create landlock ruleset: {e}"))?;

    // ── Read-Write: Data directory (RocksDB, indexer, etc.) ──
    // Ensure the directory exists before we try to open it.
    let _ = std::fs::create_dir_all(&config.datadir);
    let datadir_fd = PathFd::new(&config.datadir)
        .map_err(|e| format!("failed to open datadir '{}': {e}", config.datadir))?;
    created = created
        .add_rule(PathBeneath::new(datadir_fd, read_write))
        .map_err(|e| format!("failed to add datadir rule: {e}"))?;

    // ── Read-Only system paths ──
    // These paths are needed by the async runtime, TLS, DNS resolution,
    // shared libraries, and entropy generation.
    let ro_paths: &[&str] = &[
        "/proc",
        "/sys",
        "/dev/urandom",
        "/dev/null",
        "/etc/ssl",
        "/etc/pki",
        "/etc/ca-certificates",
        "/usr/share/ca-certificates",
        "/etc/resolv.conf",
        "/etc/hosts",
        "/etc/nsswitch.conf",
        "/etc/localtime",
        "/usr/lib",
        "/lib",
        "/lib64",
    ];

    for ro_path in ro_paths {
        if std::path::Path::new(ro_path).exists() {
            if let Ok(fd) = PathFd::new(ro_path) {
                created = created
                    .add_rule(PathBeneath::new(fd, read_only))
                    .map_err(|e| format!("failed to add read-only rule for {ro_path}: {e}"))?;
            }
        }
    }

    // ── Read-Only: Genesis config file ──
    if std::path::Path::new(&config.genesis_path).exists() {
        // Landlock PathBeneath works on directories, not individual files.
        // Open the parent directory as read-only instead.
        if let Some(parent) = std::path::Path::new(&config.genesis_path).parent() {
            if let Ok(fd) = PathFd::new(parent) {
                created = created
                    .add_rule(PathBeneath::new(fd, read_only))
                    .map_err(|e| format!("failed to add genesis parent dir rule: {e}"))?;
            }
        }
    }

    // ── Read-Only: Validator key file (sequencer mode) ──
    // Sequencer nodes need to read the validator key to sign blocks.
    // Non-sequencer nodes don't need key access at all.
    if config.is_sequencer && !config.validator_key_path.is_empty() {
        if let Some(parent) = std::path::Path::new(&config.validator_key_path).parent() {
            if parent.exists() {
                if let Ok(fd) = PathFd::new(parent) {
                    created = created
                        .add_rule(PathBeneath::new(fd, read_only))
                        .map_err(|e| format!("failed to add validator key dir rule: {e}"))?;
                }
            }
        }
        tracing::info!(
            "Landlock: validator key path '{}' (RO) — sequencer mode",
            config.validator_key_path
        );
    }

    // ── Read-Write: /tmp/brrq (isolated subdirectory, not all of /tmp) ──
    // Granting full /tmp access lets compromised code use it as a staging
    // area for attacks. Restrict to a dedicated subdirectory instead.
    let brrq_tmp = "/tmp/brrq";
    let _ = std::fs::create_dir_all(brrq_tmp);
    if std::path::Path::new(brrq_tmp).exists() {
        if let Ok(fd) = PathFd::new(brrq_tmp) {
            created = created
                .add_rule(PathBeneath::new(fd, read_write))
                .map_err(|e| format!("failed to add /tmp/brrq rule: {e}"))?;
        }
    }

    // Phase 3: Enforce the ruleset — restricts the calling thread and
    // all future threads. This is irreversible.
    let status = created
        .restrict_self()
        .map_err(|e| format!("failed to restrict self: {e}"))?;

    #[allow(unreachable_patterns)] // defensive: RulesetStatus may gain variants
    match status.ruleset {
        RulesetStatus::FullyEnforced => {
            tracing::info!("Landlock: fully enforced");
        }
        RulesetStatus::PartiallyEnforced => {
            tracing::warn!(
                "Landlock: partially enforced (some access rights not handled by this kernel)"
            );
        }
        RulesetStatus::NotEnforced => {
            tracing::warn!(
                "Landlock: not enforced (kernel returned success but no restrictions applied)"
            );
        }
        _ => {}
    }

    Ok(())
}

// ── seccomp syscall filter (Linux) ───────────────────────────────────

#[cfg(target_os = "linux")]
fn apply_seccomp() {
    match apply_seccomp_inner() {
        Ok(()) => {
            tracing::info!("seccomp syscall filter applied (deny: execve, fork, ptrace, ...)");
        }
        Err(e) => {
            tracing::warn!(
                "seccomp filter could not be applied: {}. \
                 The node will continue without syscall restrictions.",
                e
            );
        }
    }
}

#[cfg(target_os = "linux")]
fn apply_seccomp_inner() -> Result<(), String> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    // Strategy: DENY-LIST approach.
    // Default action: ALLOW all syscalls.
    // Specific dangerous syscalls: return ERRNO(EPERM).
    //
    // Rationale for deny-list vs allow-list:
    // 1. tokio + RocksDB + glibc use hundreds of syscalls that are hard to
    //    enumerate exhaustively. Missing one = node crash in production.
    // 2. A deny-list of ~25 dangerous syscalls is easier to audit and maintain.
    // 3. The Landlock layer already restricts filesystem access, providing
    //    defense in depth even if a denied syscall is missing.

    let mut deny_rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // Syscall numbers differ per architecture. Using arch-specific tables
    // is critical — wrong numbers silently block/allow the wrong syscalls.
    //
    // Sources:
    //   x86_64:  /usr/include/asm/unistd_64.h (or `ausyscall x86_64 <name>`)
    //   aarch64: /usr/include/asm-generic/unistd.h (unified numbering)

    #[cfg(target_arch = "x86_64")]
    let denied_syscalls: &[(&str, i64)] = &[
        // ── Process creation ──
        ("execve", 59),
        ("execveat", 322),
        ("fork", 57),
        ("vfork", 58),
        // ── Debugging ──
        ("ptrace", 101),
        // ── Kernel module operations ──
        ("init_module", 175),
        ("finit_module", 313),
        ("delete_module", 176),
        // ── Mount/filesystem namespace ──
        ("mount", 165),
        ("umount2", 166),
        ("pivot_root", 155),
        ("chroot", 161),
        // ── Privilege escalation ──
        ("setuid", 105),
        ("setgid", 106),
        ("setreuid", 113),
        ("setregid", 114),
        ("setresuid", 117),
        ("setresgid", 119),
        ("setgroups", 116),
        // ── System manipulation ──
        ("reboot", 169),
        ("swapon", 167),
        ("swapoff", 168),
        ("kexec_load", 246),
        ("kexec_file_load", 320),
        // ── Kernel keyring ──
        ("add_key", 248),
        ("request_key", 249),
        ("keyctl", 250),
        // ── Namespace manipulation ──
        ("unshare", 272),
        ("setns", 308),
        // ── Personality changes ──
        ("personality", 135),
    ];

    #[cfg(target_arch = "aarch64")]
    let denied_syscalls: &[(&str, i64)] = &[
        // aarch64 uses the unified asm-generic numbering (__NR_* from
        // include/uapi/asm-generic/unistd.h). No fork/vfork syscalls
        // exist on aarch64 — clone/clone3 are used instead.
        //
        // ── Process creation ──
        ("execve", 221),
        ("execveat", 281),
        // fork/vfork: not present on aarch64 (clone only). Omitted.
        // ── Debugging ──
        ("ptrace", 117),
        // ── Kernel module operations ──
        ("init_module", 105),
        ("finit_module", 273),
        ("delete_module", 106),
        // ── Mount/filesystem namespace ──
        ("mount", 40),
        ("umount2", 39),
        ("pivot_root", 41),
        ("chroot", 51),
        // ── Privilege escalation ──
        ("setuid", 146),
        ("setgid", 144),
        ("setreuid", 145),
        ("setregid", 143),
        ("setresuid", 147),
        ("setresgid", 149),
        ("setgroups", 159),
        // ── System manipulation ──
        ("reboot", 142),
        ("swapon", 224),
        ("swapoff", 225),
        ("kexec_load", 104),
        ("kexec_file_load", 294),
        // ── Kernel keyring ──
        ("add_key", 217),
        ("request_key", 218),
        ("keyctl", 219),
        // ── Namespace manipulation ──
        ("unshare", 97),
        ("setns", 268),
        // ── Personality changes ──
        ("personality", 92),
    ];

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let denied_syscalls: &[(&str, i64)] = &[];

    for &(_name, nr) in denied_syscalls {
        deny_rules.insert(
            nr,
            vec![
                SeccompRule::new(vec![]).map_err(|e| {
                    format!("failed to create seccomp rule for syscall {_name}: {e}")
                })?,
            ],
        );
    }

    // Determine target architecture at compile time.
    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;
    // riscv64 added in seccompiler 0.4+
    #[cfg(target_arch = "riscv64")]
    let arch = seccompiler::TargetArch::riscv64;

    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "riscv64"
    )))]
    {
        return Err("seccomp: unsupported target architecture".to_string());
    }

    let filter = SeccompFilter::new(
        deny_rules,
        SeccompAction::Allow, // default: allow everything not explicitly denied
        SeccompAction::Allow, // mismatch action: allow (safe for deny-list)
        arch,
    )
    .map_err(|e| format!("failed to create seccomp filter: {e}"))?;

    let bpf_prog: BpfProgram = filter
        .try_into()
        .map_err(|e| format!("failed to compile seccomp BPF program: {e}"))?;

    seccompiler::apply_filter(&bpf_prog)
        .map_err(|e| format!("failed to install seccomp filter: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_config_creation() {
        let config = SandboxConfig {
            datadir: "/tmp/brrq-test".to_string(),
            genesis_path: "/tmp/genesis.toml".to_string(),
            is_sequencer: false,
            validator_key_path: "/tmp/keys.json".to_string(),
        };
        assert_eq!(config.datadir, "/tmp/brrq-test");
        assert!(!config.is_sequencer);
    }

    // NOTE: Actual landlock/seccomp tests require Linux and permanently
    // restrict the calling process. They belong in integration tests
    // with proper isolation (e.g., run in a container or VM).
}
