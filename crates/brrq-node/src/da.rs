//! Data Availability (DA) pipeline architecture.
//!
//! Provides `HttpDaClient`, an asynchronous background worker that submits
//! `LightBlock`s (compressed representations dropping SLH-DSA signatures)
//! to a modular DA layer (e.g., Celestia) using HTTP.
//!
//! The MPSC-based design ensures the hot-path Sequencer is never blocked
//! by slow DA submission network requests.

use std::time::Duration;
use tokio::time::sleep;

use brrq_types::block::LightBlock;

/// The configuration for the HTTP DA Client.
#[derive(Clone, Debug)]
pub struct DaConfig {
    /// The API endpoint of the DA layer (e.g. `http://localhost:26659/submit_pfd`).
    pub endpoint: String,
    /// The Celestia namespace ID (8 bytes in hex format).
    pub namespace_id: String,
    /// Max retries with exponential backoff.
    pub max_retries: u32,
    /// Base delay for exponential backoff (ms).
    pub backoff_base_ms: u64,
}

impl Default for DaConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:26659/submit_pfd".to_string(),
            // Mock namespace
            namespace_id: "00000000000000000000000000000000000000000000brrq".to_string(),
            max_retries: 5,
            backoff_base_ms: 500,
        }
    }
}

/// A handle to the DA provider.
///
/// Two submission modes:
/// - `submit_block_sync()`: Awaitable — blocks until DA confirms or retries exhaust.
/// - `submit_block()` / `DaSubmit::submit()`: Fire-and-forget via `tokio::spawn`.
///   Current MVP uses this mode; DA failures are logged but don't block chain progress.
///
/// **Note:** The current MVP uses fire-and-forget DA submission intentionally.
/// Before mainnet, callers should migrate to `submit_block_sync()` for hard
/// DA-finality coupling, ensuring DA availability before P2P broadcast.
#[derive(Clone)]
pub struct HttpDaClient {
    client: reqwest::Client,
    config: DaConfig,
}

impl HttpDaClient {
    /// Creates a new `HttpDaClient`.
    pub fn new(config: DaConfig) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self { client, config }
    }

    /// Submit a `LightBlock` to the DA layer asynchronously but awaitably.
    ///
    /// The sequencer MUST await this function after producing a block and BEFORE
    /// broadcasting `Message::BlockProposal` to the P2P network. This enforces hard
    /// DA-Finality coupling and eliminates DA withholding split-brains.
    pub async fn submit_block_sync(&self, light_block: LightBlock) -> Result<(), String> {
        // Skip DA submission when BRRQ_DA_DISABLED is set.
        // Allows testnet operation without a Celestia node.
        if std::env::var("BRRQ_DA_DISABLED").map(|v| v == "true").unwrap_or(false) {
            tracing::debug!("DA submission skipped (BRRQ_DA_DISABLED=true) for block {}", light_block.header.height);
            return Ok(());
        }
        let height = light_block.header.height;
        let mut attempt = 0;

        let blob = match bincode::serialize(&light_block) {
            Ok(b) => b,
            Err(e) => {
                let err = format!("Failed to serialize LightBlock {}: {}", height, e);
                tracing::error!("{}", err);
                return Err(err);
            }
        };
        let blob_hex = hex::encode(&blob);

        tracing::debug!(
            "Submitting LightBlock {} to DA ({} bytes)",
            height,
            blob.len()
        );

        while attempt < self.config.max_retries {
            attempt += 1;

            let req_body = serde_json::json!({
                "namespace_id": self.config.namespace_id,
                "data": blob_hex,
                "gas_limit": 80000,
                "fee": 2000
            });

            match self
                .client
                .post(&self.config.endpoint)
                .json(&req_body)
                .send()
                .await
            {
                Ok(response) => {
                    if response.status().is_success() {
                        tracing::info!("LightBlock {} successfully committed to DA", height);
                        return Ok(());
                    } else {
                        let status_code = response.status();
                        let error_text = response.text().await.unwrap_or_default();
                        tracing::warn!(
                            "DA submission failed for block {} (Attempt {}/{}): HTTP {} {}",
                            height,
                            attempt,
                            self.config.max_retries,
                            status_code,
                            error_text
                        );
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "DA submission request error for block {} (Attempt {}/{}): {}",
                        height,
                        attempt,
                        self.config.max_retries,
                        e
                    );
                }
            }

            // Exponential backoff
            let delay = self.config.backoff_base_ms * (1 << (attempt - 1));
            sleep(Duration::from_millis(delay)).await;
        }

        let err_msg = format!(
            "CRITICAL: Failed to submit LightBlock {} to DA after {} retries. State root {} irrecoverable.",
            height, self.config.max_retries, light_block.header.state_root
        );
        tracing::error!("{}", err_msg);
        Err(err_msg)
    }

    /// Legacy fire-and-forget wrapper for older code if necessary.
    pub fn submit_block(&self, light_block: LightBlock) {
        let client = self.clone();
        tokio::spawn(async move {
            let _ = client.submit_block_sync(light_block).await;
        });
    }
}

/// `DaSubmit` implementation for `HttpDaClient`.
///
/// `submit()` is the legacy fire-and-forget path.
/// `submit_awaitable()` overrides the default to call `submit_block_sync()`
/// with retry + exponential backoff, enforcing DA-finality before P2P broadcast.
impl brrq_types::DaSubmit for HttpDaClient {
    fn submit(&self, light_block: &LightBlock) -> Result<(), String> {
        self.submit_block(light_block.clone());
        Ok(())
    }

    fn submitted_count(&self) -> usize {
        0 // Not tracked for the real HTTP client
    }

    fn submit_awaitable(
        &self,
        light_block: LightBlock,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(self.submit_block_sync(light_block))
    }
}

/// No-op DA client for standalone testnet operation without external DA layer.
/// Blocks are committed without DA submission — suitable for local development.
pub struct NoopDaClient;

impl brrq_types::DaSubmit for NoopDaClient {
    fn submit(&self, _light_block: &LightBlock) -> Result<(), String> {
        Ok(())
    }

    fn submitted_count(&self) -> usize {
        0
    }

    fn submit_awaitable(
        &self,
        _light_block: LightBlock,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }
}
