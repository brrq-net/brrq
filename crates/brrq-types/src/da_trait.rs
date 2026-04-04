//! Data Availability client trait for testability.
//!
//! Defines the interface for DA layer submission, enabling swapping
//! between the real `HttpDaClient` and the mock `MockDaClient` in tests.

use std::future::Future;
use std::pin::Pin;

use crate::block::LightBlock;

/// Trait abstracting DA layer submission for testability.
///
/// The synchronous `submit()` is used for in-process simulation (`MockDaClient`).
/// The async `submit_awaitable()` blocks until DA confirms or fails, and is
/// used in production to enforce DA-finality before P2P broadcast.
pub trait DaSubmit: Send + Sync {
    /// Submit a light block to the DA layer (fire-and-forget).
    /// Returns Ok(()) on success, Err(message) on failure.
    fn submit(&self, light_block: &LightBlock) -> Result<(), String>;

    /// Number of blocks submitted so far (for test assertions).
    fn submitted_count(&self) -> usize;

    /// Async submit — blocks until DA confirms or all retries exhausted.
    ///
    /// Production (`HttpDaClient`) overrides this to call `submit_block_sync()`
    /// with retry + exponential backoff. The default wraps `submit()` for
    /// `MockDaClient` compatibility.
    fn submit_awaitable(
        &self,
        light_block: LightBlock,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + '_>> {
        let result = self.submit(&light_block);
        Box::pin(async move { result })
    }
}
