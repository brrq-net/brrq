//! OS-level platform abstractions for the Brrq node.
//!
//! - **`file_ops`**: Async file I/O with io_uring backend on Linux
//! - **`sandbox`**: Landlock filesystem + seccomp syscall sandboxing
//! - **`metrics`**: Production metrics with eBPF kernel probes on Linux

pub mod file_ops;
pub mod metrics;
pub mod sandbox;

pub use file_ops::{FileOps, StdFileOps, select_file_ops};
pub use metrics::{Counter, EbpfMonitor, Gauge, LatencyHistogram, NodeMetrics};
pub use sandbox::{SandboxConfig, apply_sandbox};
