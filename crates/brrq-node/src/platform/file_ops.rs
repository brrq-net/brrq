//! io_uring async I/O acceleration for Brrq node (Linux 5.1+).
//!
//! ## Why io_uring?
//!
//! Standard POSIX `read`/`write` syscalls require a context switch per operation.
//! io_uring uses a shared submission/completion ring buffer between user space and
//! kernel, allowing batched I/O with zero or minimal syscalls.
//!
//! For a blockchain node, this matters in two hot paths:
//! 1. **Block persistence**: Writing state diffs to RocksDB (WAL + SST flushes)
//! 2. **State loading**: Reading accounts/storage during block validation
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────┐     ┌──────────────┐     ┌────────────┐
//! │ Tokio Tasks   │────▶│ UringFileOps │────▶│ io_uring   │
//! │ (async)       │     │ (Linux)      │     │ (kernel)   │
//! └──────────────┘     └──────────────┘     └────────────┘
//!                       ┌──────────────┐
//!                       │ StdFileOps   │ (fallback on non-Linux)
//!                       └──────────────┘
//! ```
//!
//! ## Feature gate
//!
//! Enable with `--features io-uring`. Falls back to standard `tokio::fs`
//! on non-Linux or when the feature is not enabled.

use std::path::PathBuf;

/// Result type for file operations.
pub type IoResult<T> = std::io::Result<T>;

// ── FileOps trait ───────────────────────────────────────────────────

/// Async file operations abstraction.
///
/// Implemented by both the io_uring backend (Linux) and the standard
/// tokio::fs fallback. This trait allows the node to transparently
/// use the fastest available I/O path.
///
/// Object-safe via `dyn FileOps`. We use `PathBuf` parameters to avoid
/// lifetime issues with `dyn` dispatch.
pub trait FileOps: Send + Sync {
    /// Backend name for diagnostics.
    fn name(&self) -> &str;

    /// Whether this backend uses io_uring.
    fn is_io_uring(&self) -> bool;

    /// Read an entire file into a byte vector.
    fn read_file(
        &self,
        path: PathBuf,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<Vec<u8>>> + Send + '_>>;

    /// Write bytes to a file atomically (write to temp, fsync, rename).
    fn write_file_atomic(
        &self,
        path: PathBuf,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>>;

    /// Append bytes to a file.
    fn append_file(
        &self,
        path: PathBuf,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>>;

    /// Sync a directory (ensures rename durability on Linux).
    fn sync_dir(
        &self,
        path: PathBuf,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>>;

    /// Read a specific byte range from a file.
    fn read_range(
        &self,
        path: PathBuf,
        offset: u64,
        len: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<Vec<u8>>> + Send + '_>>;
}

// ── Standard (fallback) backend ─────────────────────────────────────

/// Standard file operations using tokio::fs.
/// Available on all platforms.
pub struct StdFileOps;

impl FileOps for StdFileOps {
    fn name(&self) -> &str {
        "tokio-fs"
    }

    fn is_io_uring(&self) -> bool {
        false
    }

    fn read_file(
        &self,
        path: PathBuf,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<Vec<u8>>> + Send + '_>> {
        Box::pin(async move { tokio::fs::read(&path).await })
    }

    fn write_file_atomic(
        &self,
        path: PathBuf,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move {
            let tmp = path.with_extension("tmp");
            tokio::fs::write(&tmp, &data).await?;
            // fsync the file to ensure data is on disk before rename.
            // Must open with write access — Windows denies FlushFileBuffers
            // on read-only handles (os error 5: Access denied).
            {
                let file = tokio::fs::OpenOptions::new().write(true).open(&tmp).await?;
                file.sync_all().await?;
                // Drop the file handle before rename — Windows requires
                // the file to have no open handles for rename to succeed.
                drop(file);
            }
            // On Windows, rename fails if the destination exists.
            // Remove it first (not atomic, but acceptable for scaffolding).
            #[cfg(target_os = "windows")]
            {
                let _ = tokio::fs::remove_file(&path).await;
            }
            tokio::fs::rename(&tmp, &path).await?;
            Ok(())
        })
    }

    fn append_file(
        &self,
        path: PathBuf,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move {
            use tokio::io::AsyncWriteExt;
            let mut file = tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .await?;
            file.write_all(&data).await?;
            file.flush().await?;
            Ok(())
        })
    }

    fn sync_dir(
        &self,
        path: PathBuf,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let dir = std::fs::File::open(&path)?;
                dir.sync_all()
            })
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
        })
    }

    fn read_range(
        &self,
        path: PathBuf,
        offset: u64,
        len: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<Vec<u8>>> + Send + '_>> {
        Box::pin(async move {
            use tokio::io::{AsyncReadExt, AsyncSeekExt};
            let mut file = tokio::fs::File::open(&path).await?;
            file.seek(std::io::SeekFrom::Start(offset)).await?;
            let mut buf = vec![0u8; len];
            file.read_exact(&mut buf).await?;
            Ok(buf)
        })
    }
}

// ── io_uring backend (Linux only, behind feature flag) ──────────────

/// Dedicated-thread file operations with io_uring initialization.
///
/// **Current state**: Initializes an io_uring ring to verify kernel support,
/// but I/O operations use `std::fs` on the dedicated thread. This is a
/// scaffolding stub — actual SQE/CQE submission replaces `std::fs` calls
/// in the production implementation.
///
/// Despite the name, this is effectively `DedicatedThreadFileOps` until
/// the io_uring SQE path is implemented. The name is kept to match the
/// feature gate (`--features io-uring`).
#[cfg(all(target_os = "linux", feature = "io-uring"))]
pub struct UringFileOps {
    /// Sender to dispatch I/O requests to the uring thread.
    tx: tokio::sync::mpsc::Sender<UringRequest>,
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
enum UringOp {
    ReadFile {
        path: PathBuf,
    },
    WriteFileAtomic {
        path: PathBuf,
        data: Vec<u8>,
    },
    AppendFile {
        path: PathBuf,
        data: Vec<u8>,
    },
    SyncDir {
        path: PathBuf,
    },
    ReadRange {
        path: PathBuf,
        offset: u64,
        len: usize,
    },
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
struct UringRequest {
    op: UringOp,
    reply: tokio::sync::oneshot::Sender<IoResult<Vec<u8>>>,
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
impl UringFileOps {
    /// Initialize the io_uring backend.
    ///
    /// Spawns a dedicated OS thread that owns the io_uring instance.
    /// Returns `None` if the kernel doesn't support io_uring.
    pub fn try_new() -> Option<Self> {
        use std::sync::mpsc as std_mpsc;

        let (init_tx, init_rx) = std_mpsc::channel::<bool>();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<UringRequest>(256);

        std::thread::Builder::new()
            .name("brrq-uring".to_string())
            .spawn(move || {
                let ring = match io_uring::IoUring::new(256) {
                    Ok(r) => {
                        let _ = init_tx.send(true);
                        r
                    }
                    Err(e) => {
                        tracing::warn!("io_uring initialization failed: {e}");
                        let _ = init_tx.send(false);
                        return;
                    }
                };

                tracing::info!("io_uring backend initialized (sq_size=256)");

                // Process requests. Initial implementation uses synchronous
                // file I/O on the dedicated uring thread. A full io_uring
                // implementation would use SQE/CQE for true zero-copy async I/O.
                //
                // Future: Replace std::fs calls with actual
                // io_uring SQE submissions for read/write/fsync.
                let _ = ring; // Reserved for full implementation.

                while let Some(req) = rx.blocking_recv() {
                    let result = match req.op {
                        UringOp::ReadFile { path } => std::fs::read(&path),
                        UringOp::WriteFileAtomic { path, data } => {
                            let tmp = path.with_extension("tmp");
                            (|| -> IoResult<Vec<u8>> {
                                std::fs::write(&tmp, &data)?;
                                let f = std::fs::File::open(&tmp)?;
                                f.sync_all()?;
                                std::fs::rename(&tmp, &path)?;
                                Ok(vec![])
                            })()
                        }
                        UringOp::AppendFile { path, data } => {
                            use std::io::Write;
                            (|| -> IoResult<Vec<u8>> {
                                let mut f = std::fs::OpenOptions::new()
                                    .create(true)
                                    .append(true)
                                    .open(&path)?;
                                f.write_all(&data)?;
                                f.flush()?;
                                Ok(vec![])
                            })()
                        }
                        UringOp::SyncDir { path } => (|| -> IoResult<Vec<u8>> {
                            let d = std::fs::File::open(&path)?;
                            d.sync_all()?;
                            Ok(vec![])
                        })(),
                        UringOp::ReadRange { path, offset, len } => {
                            use std::io::{Read, Seek};
                            (|| -> IoResult<Vec<u8>> {
                                let mut f = std::fs::File::open(&path)?;
                                f.seek(std::io::SeekFrom::Start(offset))?;
                                let mut buf = vec![0u8; len];
                                f.read_exact(&mut buf)?;
                                Ok(buf)
                            })()
                        }
                    };
                    let _ = req.reply.send(result);
                }

                tracing::info!("io_uring thread shutting down");
            })
            .ok()?;

        match init_rx.recv() {
            Ok(true) => Some(Self { tx }),
            _ => None,
        }
    }

    async fn send_op(&self, op: UringOp) -> IoResult<Vec<u8>> {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(UringRequest {
                op,
                reply: reply_tx,
            })
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "uring thread gone")
            })?;
        reply_rx.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "uring reply dropped")
        })?
    }
}

#[cfg(all(target_os = "linux", feature = "io-uring"))]
impl FileOps for UringFileOps {
    fn name(&self) -> &str {
        // Honest name: io_uring ring is initialized but I/O uses std::fs.
        "io-uring-stub"
    }

    fn is_io_uring(&self) -> bool {
        // Not truly using io_uring SQEs yet — kernel support is verified
        // but actual I/O goes through std::fs on a dedicated thread.
        false
    }

    fn read_file(
        &self,
        path: PathBuf,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<Vec<u8>>> + Send + '_>> {
        Box::pin(self.send_op(UringOp::ReadFile { path }))
    }

    fn write_file_atomic(
        &self,
        path: PathBuf,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.send_op(UringOp::WriteFileAtomic { path, data })
                .await
                .map(|_| ())
        })
    }

    fn append_file(
        &self,
        path: PathBuf,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move {
            self.send_op(UringOp::AppendFile { path, data })
                .await
                .map(|_| ())
        })
    }

    fn sync_dir(
        &self,
        path: PathBuf,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<()>> + Send + '_>> {
        Box::pin(async move { self.send_op(UringOp::SyncDir { path }).await.map(|_| ()) })
    }

    fn read_range(
        &self,
        path: PathBuf,
        offset: u64,
        len: usize,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = IoResult<Vec<u8>>> + Send + '_>> {
        Box::pin(self.send_op(UringOp::ReadRange { path, offset, len }))
    }
}

// ── Backend selection ───────────────────────────────────────────────

/// Select the best available file I/O backend.
///
/// On Linux with `io-uring` feature: attempts io_uring, falls back to tokio::fs.
/// On all other platforms: uses tokio::fs directly.
pub fn select_file_ops() -> Box<dyn FileOps> {
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        if let Some(uring) = UringFileOps::try_new() {
            tracing::info!("File I/O backend: io_uring");
            return Box::new(uring);
        }
        tracing::warn!("io_uring not available on this kernel, falling back to tokio::fs");
    }

    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        tracing::info!("File I/O backend: tokio::fs (io-uring feature not enabled or not Linux)");
    }

    Box::new(StdFileOps)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a test directory under the current directory (avoids Windows temp permission issues).
    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::current_dir()
            .unwrap_or_else(|_| std::env::temp_dir())
            .join("target")
            .join("test-scratch")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[tokio::test]
    async fn std_backend_read_write() {
        let dir = test_dir("fileops-rw");

        let ops = StdFileOps;
        assert_eq!(ops.name(), "tokio-fs");
        assert!(!ops.is_io_uring());

        let test_file = dir.join("test.dat");
        let data = b"hello io_uring test";

        // Write atomically.
        ops.write_file_atomic(test_file.clone(), data.to_vec())
            .await
            .unwrap();

        // Read back.
        let read = ops.read_file(test_file.clone()).await.unwrap();
        assert_eq!(read, data);

        // Read range.
        let range = ops.read_range(test_file.clone(), 6, 8).await.unwrap();
        assert_eq!(&range, b"io_uring");

        // Append.
        ops.append_file(test_file.clone(), b" appended".to_vec())
            .await
            .unwrap();
        let full = ops.read_file(test_file.clone()).await.unwrap();
        assert_eq!(&full, b"hello io_uring test appended");

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn select_returns_fallback_on_non_linux() {
        let ops = select_file_ops();
        // On Windows/macOS or without the feature, always tokio-fs.
        #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
        assert_eq!(ops.name(), "tokio-fs");
    }

    #[tokio::test]
    async fn atomic_write_survives_no_tmp_leak() {
        let dir = test_dir("fileops-atomic");

        let ops = StdFileOps;
        let path = dir.join("atomic.dat");

        ops.write_file_atomic(path.clone(), b"version1".to_vec())
            .await
            .unwrap();
        ops.write_file_atomic(path.clone(), b"version2".to_vec())
            .await
            .unwrap();

        let data = ops.read_file(path.clone()).await.unwrap();
        assert_eq!(&data, b"version2");

        // No .tmp file left behind.
        assert!(!path.with_extension("tmp").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
