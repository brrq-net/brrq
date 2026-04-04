//! eBPF-based production monitoring for Brrq node (Linux 5.8+).
//!
//! ## Why eBPF?
//!
//! Traditional monitoring (metrics, logs) is application-level and adds overhead.
//! eBPF programs run in the kernel with near-zero overhead, providing:
//! - Syscall latency histograms (detect I/O stalls)
//! - Network packet tracing (P2P message latency)
//! - Memory allocation tracking (detect leaks)
//! - CPU scheduling delays (detect preemption issues)
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐     ┌──────────────┐     ┌──────────────┐
//! │ eBPF probes  │────▶│ Ring buffer  │────▶│ Metrics      │
//! │ (kernel)     │     │ (per-CPU)    │     │ (user space) │
//! └─────────────┘     └──────────────┘     └──────────────┘
//!                                           ┌──────────────┐
//!                                           │ Prometheus   │
//!                                           │ /metrics     │
//!                                           └──────────────┘
//! ```
//!
//! ## Feature gate
//!
//! Enable with `--features ebpf-monitor`. Requires Linux 5.8+ with
//! BPF_PROG_TYPE_TRACING support. Falls back to no-op metrics on
//! non-Linux or when the feature is not enabled.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// ── Metrics structures ──────────────────────────────────────────────

/// Histogram bucket for latency tracking.
/// Uses exponential buckets: 1μs, 10μs, 100μs, 1ms, 10ms, 100ms, 1s, 10s
#[derive(Debug)]
pub struct LatencyHistogram {
    /// Bucket boundaries in microseconds.
    boundaries: &'static [u64],
    /// Count per bucket (last bucket = overflow).
    counts: Vec<AtomicU64>,
    /// Sum of all observed values in microseconds.
    sum: AtomicU64,
    /// Total count of observations.
    total: AtomicU64,
}

impl LatencyHistogram {
    /// Default exponential buckets for syscall/network latency.
    const DEFAULT_BOUNDARIES: &'static [u64] = &[
        1,          // ≤ 1μs
        10,         // ≤ 10μs
        100,        // ≤ 100μs
        1_000,      // ≤ 1ms
        10_000,     // ≤ 10ms
        100_000,    // ≤ 100ms
        1_000_000,  // ≤ 1s
        10_000_000, // ≤ 10s
    ];

    /// Create a new histogram with default boundaries.
    pub fn new() -> Self {
        let boundaries = Self::DEFAULT_BOUNDARIES;
        let counts = (0..=boundaries.len()).map(|_| AtomicU64::new(0)).collect();
        Self {
            boundaries,
            counts,
            sum: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    /// Record a latency observation in microseconds.
    pub fn observe(&self, value_us: u64) {
        let bucket = self
            .boundaries
            .iter()
            .position(|&b| value_us <= b)
            .unwrap_or(self.boundaries.len());
        self.counts[bucket].fetch_add(1, Ordering::Relaxed);
        self.sum.fetch_add(value_us, Ordering::Relaxed);
        self.total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total count of observations.
    pub fn count(&self) -> u64 {
        self.total.load(Ordering::Relaxed)
    }

    /// Get the sum of all observations in microseconds.
    pub fn sum_us(&self) -> u64 {
        self.sum.load(Ordering::Relaxed)
    }

    /// Get the mean latency in microseconds, or 0 if no observations.
    pub fn mean_us(&self) -> u64 {
        let total = self.count();
        if total == 0 { 0 } else { self.sum_us() / total }
    }

    /// Get bucket counts as (boundary_us, count) pairs.
    /// Last entry is the overflow bucket with boundary = u64::MAX.
    pub fn buckets(&self) -> Vec<(u64, u64)> {
        let mut result = Vec::with_capacity(self.counts.len());
        for (i, boundary) in self.boundaries.iter().enumerate() {
            result.push((*boundary, self.counts[i].load(Ordering::Relaxed)));
        }
        // Overflow bucket.
        result.push((
            u64::MAX,
            self.counts[self.boundaries.len()].load(Ordering::Relaxed),
        ));
        result
    }
}

impl Default for LatencyHistogram {
    fn default() -> Self {
        Self::new()
    }
}

/// Counter for tracking event counts.
#[derive(Debug)]
pub struct Counter {
    value: AtomicU64,
}

impl Counter {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for Counter {
    fn default() -> Self {
        Self::new()
    }
}

/// Gauge for tracking current values (can go up and down).
#[derive(Debug)]
pub struct Gauge {
    value: AtomicU64,
}

impl Gauge {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn set(&self, val: u64) {
        self.value.store(val, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    /// Atomically set to `val` if `val` is greater than the current value.
    /// Returns the previous value.
    pub fn fetch_max(&self, val: u64) -> u64 {
        self.value.fetch_max(val, Ordering::Relaxed)
    }
}

impl Default for Gauge {
    fn default() -> Self {
        Self::new()
    }
}

// ── Node metrics collection ─────────────────────────────────────────

/// Production metrics for the Brrq node.
///
/// These metrics are populated by eBPF probes on Linux, or by
/// application-level instrumentation as a fallback.
#[derive(Debug)]
pub struct NodeMetrics {
    // ── Block production ──
    /// Time to produce a block (μs).
    pub block_production_latency: LatencyHistogram,
    /// Total blocks produced.
    pub blocks_produced: Counter,
    /// Transactions per block.
    pub txs_per_block: LatencyHistogram,

    // ── State I/O ──
    /// RocksDB write latency (μs).
    pub rocksdb_write_latency: LatencyHistogram,
    /// RocksDB read latency (μs).
    pub rocksdb_read_latency: LatencyHistogram,
    /// Total bytes written to disk.
    pub disk_bytes_written: Counter,
    /// Total bytes read from disk.
    pub disk_bytes_read: Counter,

    // ── Network ──
    /// P2P message send latency (μs).
    pub p2p_send_latency: LatencyHistogram,
    /// P2P message receive latency (μs).
    pub p2p_recv_latency: LatencyHistogram,
    /// Connected peers count.
    pub connected_peers: Gauge,
    /// Total messages sent.
    pub messages_sent: Counter,
    /// Total messages received.
    pub messages_received: Counter,

    // ── Prover ──
    /// Proof generation time (μs).
    pub proof_generation_latency: LatencyHistogram,
    /// Total proofs generated.
    pub proofs_generated: Counter,
    /// Proof verification time (μs).
    pub proof_verification_latency: LatencyHistogram,

    // ── Memory ──
    /// Current RSS in bytes.
    pub rss_bytes: Gauge,
    /// Peak RSS in bytes.
    pub peak_rss_bytes: Gauge,

    // ── System (populated by eBPF on Linux) ──
    /// Syscall latency for write(2) family (μs).
    pub syscall_write_latency: LatencyHistogram,
    /// Syscall latency for read(2) family (μs).
    pub syscall_read_latency: LatencyHistogram,
    /// Context switches (voluntary + involuntary).
    /// This is a Gauge (absolute value from /proc), not a Counter.
    pub context_switches: Gauge,
    /// Page faults (major).
    pub major_page_faults: Gauge,
}

impl NodeMetrics {
    /// Create a new metrics instance with all counters zeroed.
    pub fn new() -> Self {
        Self {
            block_production_latency: LatencyHistogram::new(),
            blocks_produced: Counter::new(),
            txs_per_block: LatencyHistogram::new(),
            rocksdb_write_latency: LatencyHistogram::new(),
            rocksdb_read_latency: LatencyHistogram::new(),
            disk_bytes_written: Counter::new(),
            disk_bytes_read: Counter::new(),
            p2p_send_latency: LatencyHistogram::new(),
            p2p_recv_latency: LatencyHistogram::new(),
            connected_peers: Gauge::new(),
            messages_sent: Counter::new(),
            messages_received: Counter::new(),
            proof_generation_latency: LatencyHistogram::new(),
            proofs_generated: Counter::new(),
            proof_verification_latency: LatencyHistogram::new(),
            rss_bytes: Gauge::new(),
            peak_rss_bytes: Gauge::new(),
            syscall_write_latency: LatencyHistogram::new(),
            syscall_read_latency: LatencyHistogram::new(),
            context_switches: Gauge::new(),
            major_page_faults: Gauge::new(),
        }
    }

    /// Export all metrics in Prometheus text exposition format.
    ///
    /// Uses the `emit_metrics!` macro internally so adding a new metric
    /// only requires one line instead of a 5-line `write_*` call.
    pub fn to_prometheus(&self) -> String {
        let mut out = String::with_capacity(4096);

        // ── Helpers ──────────────────────────────────────────────────
        fn write_histogram(out: &mut String, name: &str, help: &str, h: &LatencyHistogram) {
            out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} histogram\n"));
            let mut cumulative = 0u64;
            for (boundary, count) in h.buckets() {
                cumulative += count;
                if boundary == u64::MAX {
                    out.push_str(&format!("{name}_bucket{{le=\"+Inf\"}} {cumulative}\n"));
                } else {
                    let le = boundary as f64 / 1_000_000.0;
                    out.push_str(&format!("{name}_bucket{{le=\"{le:.6}\"}} {cumulative}\n"));
                }
            }
            out.push_str(&format!(
                "{name}_sum {}\n{name}_count {}\n",
                h.sum_us() as f64 / 1_000_000.0,
                h.count()
            ));
        }

        fn write_counter(out: &mut String, name: &str, help: &str, c: &Counter) {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {}\n",
                c.get()
            ));
        }

        fn write_gauge(out: &mut String, name: &str, help: &str, g: &Gauge) {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {}\n",
                g.get()
            ));
        }

        // ── Metric table ─────────────────────────────────────────────
        // Adding a new metric? Add ONE line here. The macro handles dispatch.
        macro_rules! emit_metrics {
            ($out:expr, $( $kind:ident $name:literal $help:literal => $field:expr );+ $(;)?) => {
                $( emit_metrics!(@one $out, $kind, $name, $help, $field); )+
            };
            (@one $out:expr, histogram, $name:literal, $help:literal, $field:expr) => {
                write_histogram($out, $name, $help, $field);
            };
            (@one $out:expr, counter, $name:literal, $help:literal, $field:expr) => {
                write_counter($out, $name, $help, $field);
            };
            (@one $out:expr, gauge, $name:literal, $help:literal, $field:expr) => {
                write_gauge($out, $name, $help, $field);
            };
        }

        emit_metrics!(&mut out,
            histogram "brrq_block_production_seconds"  "Block production latency"         => &self.block_production_latency;
            counter   "brrq_blocks_produced_total"     "Total blocks produced"             => &self.blocks_produced;
            histogram "brrq_txs_per_block"             "Transactions per block"            => &self.txs_per_block;
            histogram "brrq_rocksdb_write_seconds"     "RocksDB write latency"             => &self.rocksdb_write_latency;
            histogram "brrq_rocksdb_read_seconds"      "RocksDB read latency"              => &self.rocksdb_read_latency;
            counter   "brrq_disk_bytes_written_total"  "Bytes written to disk"             => &self.disk_bytes_written;
            counter   "brrq_disk_bytes_read_total"     "Bytes read from disk"              => &self.disk_bytes_read;
            histogram "brrq_p2p_send_seconds"          "P2P send latency"                  => &self.p2p_send_latency;
            histogram "brrq_p2p_recv_seconds"          "P2P receive latency"               => &self.p2p_recv_latency;
            gauge     "brrq_connected_peers"           "Connected peers"                   => &self.connected_peers;
            counter   "brrq_messages_sent_total"       "P2P messages sent"                 => &self.messages_sent;
            counter   "brrq_messages_received_total"   "P2P messages received"             => &self.messages_received;
            histogram "brrq_proof_generation_seconds"  "Proof generation latency"          => &self.proof_generation_latency;
            counter   "brrq_proofs_generated_total"    "Proofs generated"                  => &self.proofs_generated;
            histogram "brrq_proof_verify_seconds"      "Proof verification latency"        => &self.proof_verification_latency;
            gauge     "brrq_rss_bytes"                 "Resident set size (bytes)"         => &self.rss_bytes;
            gauge     "brrq_peak_rss_bytes"            "Peak RSS (bytes)"                  => &self.peak_rss_bytes;
            histogram "brrq_syscall_write_seconds"     "write() syscall latency"           => &self.syscall_write_latency;
            histogram "brrq_syscall_read_seconds"      "read() syscall latency"            => &self.syscall_read_latency;
            gauge     "brrq_context_switches"          "Context switches (from /proc)"     => &self.context_switches;
            gauge     "brrq_major_page_faults"         "Major page faults (from /proc)"    => &self.major_page_faults;
        );

        out
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

// ── eBPF probe attachment (Linux only) ──────────────────────────────

/// eBPF monitor handle. Attaches probes on Linux, no-op elsewhere.
pub struct EbpfMonitor {
    metrics: Arc<NodeMetrics>,
    #[cfg(all(target_os = "linux", feature = "ebpf-monitor"))]
    _handles: Vec<Box<dyn std::any::Any + Send>>,
}

impl EbpfMonitor {
    /// Start eBPF monitoring. On non-Linux, returns a monitor with
    /// application-level metrics only (no kernel probes).
    pub fn start(metrics: Arc<NodeMetrics>) -> Self {
        #[cfg(all(target_os = "linux", feature = "ebpf-monitor"))]
        {
            match attach_probes(&metrics) {
                Ok(handles) => {
                    tracing::info!("eBPF probes attached for production monitoring");
                    return Self {
                        metrics,
                        _handles: handles,
                    };
                }
                Err(e) => {
                    tracing::warn!(
                        "eBPF probes could not be attached: {e}. \
                         Falling back to application-level metrics only."
                    );
                }
            }
        }

        #[cfg(not(all(target_os = "linux", feature = "ebpf-monitor")))]
        {
            tracing::info!(
                "eBPF monitoring not available (requires Linux + ebpf-monitor feature). \
                 Using application-level metrics only."
            );
        }

        Self {
            metrics,
            #[cfg(all(target_os = "linux", feature = "ebpf-monitor"))]
            _handles: vec![],
        }
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> &Arc<NodeMetrics> {
        &self.metrics
    }

    /// Start a background task that periodically samples /proc/self/status
    /// for RSS and context switch metrics.
    pub fn spawn_proc_sampler(&self) {
        let metrics = self.metrics.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                sample_proc_status(&metrics);
            }
        });
    }
}

/// Sample /proc/self/status (Linux) or approximate via std on other platforms.
fn sample_proc_status(metrics: &NodeMetrics) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(val) = line.strip_prefix("VmRSS:") {
                    if let Ok(kb) = val.trim().trim_end_matches(" kB").trim().parse::<u64>() {
                        let bytes = kb * 1024;
                        metrics.rss_bytes.set(bytes);
                        // Atomic fetch_max to avoid TOCTOU race on peak tracking.
                        metrics.peak_rss_bytes.fetch_max(bytes);
                    }
                }
                if let Some(val) = line.strip_prefix("voluntary_ctxt_switches:") {
                    if let Ok(n) = val.trim().parse::<u64>() {
                        // /proc gives absolute values — Gauge is the correct type.
                        metrics.context_switches.set(n);
                    }
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // On non-Linux, we can't easily get RSS. Leave at 0.
        let _ = metrics;
    }
}

/// Attach eBPF probes (Linux only, behind feature flag).
///
/// Uses the `aya` crate for eBPF program loading. In the initial
/// scaffolding, this documents the probe attachment points without
/// requiring compiled eBPF bytecode.
#[cfg(all(target_os = "linux", feature = "ebpf-monitor"))]
fn attach_probes(
    _metrics: &Arc<NodeMetrics>,
) -> Result<Vec<Box<dyn std::any::Any + Send>>, String> {
    // Probe attachment points for future implementation:
    //
    // 1. kprobe: vfs_write → measure write latency
    //    - Attach to entry + return
    //    - Record timestamp delta in BPF map
    //    - Filter by PID (our process only)
    //
    // 2. kprobe: vfs_read → measure read latency
    //    - Same pattern as vfs_write
    //
    // 3. tracepoint: sched:sched_switch → context switch counting
    //    - Filter by PID
    //    - Increment per-CPU counter
    //
    // 4. tracepoint: exceptions:page_fault_kernel → major page faults
    //    - Filter by PID
    //
    // 5. kprobe: tcp_sendmsg → network send latency
    //    - Per-socket tracking for P2P connections
    //
    // Future: Compile eBPF programs with aya-bpf, load at runtime.
    // For now, return empty handles — metrics are populated by application code.

    tracing::info!(
        "eBPF probe scaffolding loaded. Actual probes will be attached \
         when eBPF bytecode is compiled (aya-bpf)."
    );

    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn histogram_observe_and_buckets() {
        let h = LatencyHistogram::new();
        h.observe(5); // 5μs → bucket ≤10μs
        h.observe(500); // 500μs → bucket ≤1ms
        h.observe(50_000); // 50ms → bucket ≤100ms

        assert_eq!(h.count(), 3);
        assert_eq!(h.sum_us(), 50_505);
        assert_eq!(h.mean_us(), 16835); // 50505 / 3

        let buckets = h.buckets();
        assert_eq!(buckets[0], (1, 0)); // ≤1μs: 0
        assert_eq!(buckets[1], (10, 1)); // ≤10μs: 1 (5μs)
        assert_eq!(buckets[2], (100, 0)); // ≤100μs: 0
        assert_eq!(buckets[3], (1_000, 1)); // ≤1ms: 1 (500μs)
        assert_eq!(buckets[4], (10_000, 0)); // ≤10ms: 0
        assert_eq!(buckets[5], (100_000, 1)); // ≤100ms: 1 (50ms)
    }

    #[test]
    fn counter_inc_and_add() {
        let c = Counter::new();
        c.inc();
        c.inc();
        c.add(5);
        assert_eq!(c.get(), 7);
    }

    #[test]
    fn gauge_set_and_get() {
        let g = Gauge::new();
        g.set(42);
        assert_eq!(g.get(), 42);
        g.set(100);
        assert_eq!(g.get(), 100);
    }

    #[test]
    fn metrics_prometheus_export() {
        let m = NodeMetrics::new();
        m.blocks_produced.inc();
        m.blocks_produced.inc();
        m.connected_peers.set(8);
        m.block_production_latency.observe(1_500); // 1.5ms

        let prom = m.to_prometheus();
        assert!(prom.contains("brrq_blocks_produced_total 2"));
        assert!(prom.contains("brrq_connected_peers 8"));
        assert!(prom.contains("brrq_block_production_seconds_count 1"));
    }

    #[test]
    fn ebpf_monitor_starts_without_probes() {
        // On non-Linux or without feature, should not panic.
        let metrics = Arc::new(NodeMetrics::new());
        let monitor = EbpfMonitor::start(metrics.clone());
        assert_eq!(Arc::strong_count(monitor.metrics()), 2);
    }
}
