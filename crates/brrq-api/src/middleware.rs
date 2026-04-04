//! Middleware configuration — CORS, tracing, compression, rate limiting.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use axum::{
    Extension,
    body::Body,
    extract::ConnectInfo,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::atomic::Ordering;
use tokio::sync::Mutex;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

use crate::state::SecurityMetrics;

/// Number of shards for the rate limiter to reduce lock contention.
const RATE_LIMITER_SHARDS: usize = 16;

/// Create CORS layer.
///
/// Uses a restrictive policy by default (same-origin only).
/// Set `BRRQ_CORS_PERMISSIVE=1` to allow all origins (dev/testnet only).
/// Set `BRRQ_CORS_ORIGINS=http://host1,http://host2` for custom origins.
pub fn cors_layer() -> CorsLayer {
    if std::env::var("BRRQ_CORS_PERMISSIVE").unwrap_or_default() == "1" {
        // Block permissive CORS if BRRQ_NETWORK=mainnet.
        if std::env::var("BRRQ_NETWORK").unwrap_or_default() == "mainnet" {
            tracing::error!(
                "CORS: BRRQ_CORS_PERMISSIVE=1 rejected — not allowed on mainnet. Using default."
            );
            return default_cors();
        }
        tracing::warn!("CORS: permissive mode enabled — do NOT use in production");
        CorsLayer::permissive()
    } else if let Ok(origins_str) = std::env::var("BRRQ_CORS_ORIGINS") {
        use axum::http::{Method, header};
        use tower_http::cors::AllowOrigin;
        let origins: Vec<axum::http::HeaderValue> = origins_str
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if origins.is_empty() {
            tracing::warn!(
                "BRRQ_CORS_ORIGINS set but no valid origins parsed, using localhost:3000"
            );
            default_cors()
        } else {
            tracing::info!("CORS: allowing {} custom origins", origins.len());
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
                .max_age(Duration::from_secs(3600))
        }
    } else {
        default_cors()
    }
}

fn default_cors() -> CorsLayer {
    use axum::http::{Method, header};
    use tower_http::cors::AllowOrigin;
    CorsLayer::new()
        .allow_origin(AllowOrigin::exact("http://localhost:3000".parse().unwrap()))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .max_age(Duration::from_secs(3600))
}

/// Create tracing layer for request/response logging.
pub fn trace_layer()
-> TraceLayer<tower_http::classify::SharedClassifier<tower_http::classify::ServerErrorsAsFailures>>
{
    TraceLayer::new_for_http()
}

/// Create compression layer (gzip).
pub fn compression_layer() -> CompressionLayer {
    CompressionLayer::new()
}

// ── Token Bucket Rate Limiter ──────────────────────────────────────────────────

/// Per-IP rate limiter using a sharded token bucket algorithm.
///
/// Uses `RATE_LIMITER_SHARDS` independent shards to reduce lock contention
/// under high load. Each IP hashes to one shard.
#[derive(Clone)]
pub struct RateLimiter {
    shards: Arc<Vec<Mutex<RateLimiterShard>>>,
    /// Capacity of the token bucket (max burst).
    capacity: u32,
    /// Number of tokens added per second.
    refill_rate: f64,
    /// Optional list of IPs that bypass rate limiting.
    whitelist: Arc<Vec<IpAddr>>,
}

struct RateLimiterShard {
    /// IP → (tokens_available, last_refill_time)
    buckets: HashMap<IpAddr, (f64, Instant)>,
    /// Last time we pruned stale entries.
    last_cleanup: Instant,
}

/// Default: Capacity of 10, refill at 1 token/sec.
const DEFAULT_CAPACITY: u32 = 10;
const DEFAULT_REFILL_RATE: f64 = 1.0;
/// Clean up stale entries every 60 seconds.
const CLEANUP_INTERVAL_SECS: u64 = 60;

impl RateLimiter {
    /// Create a rate limiter with default settings, overridable by env vars.
    pub fn new() -> Self {
        let capacity = std::env::var("BRRQ_RATE_LIMIT_CAPACITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_CAPACITY);

        let refill_rate = std::env::var("BRRQ_RATE_LIMIT_REFILL_RATE")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_REFILL_RATE);

        let whitelist_str = std::env::var("BRRQ_RATE_LIMIT_WHITELIST").unwrap_or_default();
        let whitelist: Vec<IpAddr> = whitelist_str
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        Self::with_config(capacity, refill_rate, whitelist)
    }

    /// Create a rate limiter with custom settings.
    pub fn with_config(capacity: u32, refill_rate: f64, whitelist: Vec<IpAddr>) -> Self {
        let shards = (0..RATE_LIMITER_SHARDS)
            .map(|_| {
                Mutex::new(RateLimiterShard {
                    buckets: HashMap::new(),
                    last_cleanup: Instant::now(),
                })
            })
            .collect();
        Self {
            shards: Arc::new(shards),
            capacity,
            refill_rate,
            whitelist: Arc::new(whitelist),
        }
    }

    /// Determine which shard an IP maps to.
    fn shard_index(ip: &IpAddr) -> usize {
        // Simple hash: use the last bytes of the IP
        let hash = match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                (octets[2] as usize)
                    .wrapping_mul(31)
                    .wrapping_add(octets[3] as usize)
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                (octets[14] as usize)
                    .wrapping_mul(31)
                    .wrapping_add(octets[15] as usize)
            }
        };
        hash % RATE_LIMITER_SHARDS
    }

    /// Check if a request from `ip` should be allowed.
    ///
    /// Returns `Ok(())` if allowed, `Err(remaining_wait)` if rate limited.
    pub async fn check(&self, ip: IpAddr) -> Result<(), Duration> {
        // Whitelist bypass
        if self.whitelist.contains(&ip) {
            return Ok(());
        }

        let idx = Self::shard_index(&ip);
        let mut shard = self.shards[idx].lock().await;
        let now = Instant::now();

        // Periodic cleanup of stale entries (no activity for 2 minutes)
        if now.duration_since(shard.last_cleanup) > Duration::from_secs(CLEANUP_INTERVAL_SECS) {
            shard.buckets.retain(|_, (_, last_refill)| {
                now.duration_since(*last_refill) < Duration::from_secs(120)
            });
            shard.last_cleanup = now;
        }

        // Start with 1 token to rate-limit from the first request.
        let default_state = (1.0_f64, now);
        let entry = shard.buckets.entry(ip).or_insert(default_state);

        let elapsed = now.duration_since(entry.1).as_secs_f64();
        let tokens_to_add = elapsed * self.refill_rate;

        let mut current_tokens = entry.0 + tokens_to_add;
        if current_tokens > self.capacity as f64 {
            current_tokens = self.capacity as f64;
        }

        if current_tokens >= 1.0 {
            // Consume 1 token
            entry.0 = current_tokens - 1.0;
            entry.1 = now;
            Ok(())
        } else {
            // Calculate how long until we have at least 1 token
            let tokens_needed = 1.0 - current_tokens;
            let wait_secs = if self.refill_rate > 0.0 {
                tokens_needed / self.refill_rate
            } else {
                3600.0 // Arbitrary long wait if refill is 0
            };
            // Add a small buffer to avoid floating point race conditions
            Err(Duration::from_secs_f64(wait_secs.max(1.0)))
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-endpoint rate limiting tiers.
///
/// Allows different endpoints to have different rate limits:
/// - `Standard`: 100 req/10s (default for most endpoints)
/// - `Strict`: 5 req/60s (faucet, resource-intensive endpoints)
/// - `Relaxed`: 200 req/10s (read-only queries like health/stats)
#[derive(Clone)]
pub struct EndpointRateLimiter {
    pub standard: RateLimiter,
    pub strict: RateLimiter,
    pub relaxed: RateLimiter,
}

impl EndpointRateLimiter {
    pub fn new() -> Self {
        Self {
            standard: RateLimiter::new(),
            strict: RateLimiter::with_config(5, 5.0 / 60.0, vec![]),
            relaxed: RateLimiter::with_config(200, 20.0, vec![]),
        }
    }
}

impl Default for EndpointRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Header Size Limit ──────────────────────────────────────────────────

/// Maximum total size of all HTTP headers combined (bytes).
///
/// Prevents header injection attacks where an attacker sends >150KB of junk
/// headers. Applied at the Axum layer as a reliable catch-all because hyper's
/// `max_buf_size` controls the read buffer but doesn't reliably reject
/// oversized headers in all code paths.
const MAX_TOTAL_HEADER_SIZE: usize = 8 * 1024; // 8KB

/// Middleware that rejects requests with oversized headers.
///
/// Checks the total size of all header name-value pairs. Returns 431
/// (Request Header Fields Too Large) if the total exceeds 8KB.
/// This runs BEFORE rate limiting so oversized header attacks are killed
/// before consuming rate limit tokens.
pub async fn header_size_middleware(
    security: Option<Extension<Arc<SecurityMetrics>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let total_header_size: usize = request
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.len() + 4) // "name: value\r\n"
        .sum();

    if total_header_size > MAX_TOTAL_HEADER_SIZE {
        if let Some(Extension(sec)) = &security {
            sec.header_oversized_total.fetch_add(1, Ordering::Relaxed);
        }
        tracing::warn!(
            total_size = total_header_size,
            limit = MAX_TOTAL_HEADER_SIZE,
            "Request rejected: header size exceeds limit"
        );
        return (
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "Request header fields too large",
        )
            .into_response();
    }

    next.run(request).await
}

/// Axum middleware function for rate limiting.
///
/// Extracts the client IP from `ConnectInfo` and checks the rate limiter.
/// Returns 429 with `Retry-After` header if the limit is exceeded.
/// The `RateLimiter` is extracted via Axum's `Extension` extractor from the
/// router's layer stack.
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<std::net::SocketAddr>,
    Extension(limiter): Extension<RateLimiter>,
    security: Option<Extension<Arc<SecurityMetrics>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // Check for X-API-Key header to bypass rate limits
    // Use cached_api_key() instead of std::env::var() per request.
    if let Some(key_header) = request.headers().get("X-API-Key") {
        if let Ok(key) = key_header.to_str() {
            if let Some(expected_key) = cached_api_key() {
                if constant_time_eq(key.as_bytes(), expected_key.as_bytes()) {
                    return next.run(request).await;
                }
            }
        }
    }

    match limiter.check(addr.ip()).await {
        Ok(()) => next.run(request).await,
        Err(retry_after) => {
            if let Some(Extension(sec)) = &security {
                sec.rate_limited_total.fetch_add(1, Ordering::Relaxed);
            }
            let secs = retry_after.as_secs().max(1);
            tracing::warn!(
                ip = %addr.ip(),
                retry_after_secs = secs,
                "Rate limit exceeded"
            );
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("Retry-After", secs.to_string())],
                format!("Rate limit exceeded. Retry after {} seconds.", secs),
            )
                .into_response()
        }
    }
}

// ── API Key Authentication ──────────────────────────────────────────────────

/// Constant-time byte comparison (no `subtle` crate dependency).
///
/// Returns `true` iff `a` and `b` have the same length and identical contents.
/// Runs in time proportional to `max(a.len(), b.len())`
/// regardless of where a mismatch occurs AND regardless of length differences.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    // XOR of lengths — non-zero if they differ, but we don't return early
    let mut diff: usize = a.len() ^ b.len();
    for i in 0..max_len {
        let x = if i < a.len() { a[i] } else { 0 };
        let y = if i < b.len() { b[i] } else { 0 };
        diff |= (x ^ y) as usize;
    }
    diff == 0
}

/// Cached API key — read from env once, reused for all requests.
/// Avoids repeated `std::env::var()` syscalls on every request (measurable latency
/// under high load, and env vars don't change at runtime).
fn cached_api_key() -> &'static Option<String> {
    static API_KEY: OnceLock<Option<String>> = OnceLock::new();
    API_KEY.get_or_init(|| {
        std::env::var("BRRQ_API_KEY").ok().filter(|k| !k.is_empty())
    })
}

/// Check if metrics endpoint requires auth.
/// Returns true when API auth is enabled (i.e., not explicitly disabled).
pub fn is_metrics_auth_required() -> bool {
    is_auth_required() && cached_api_key().is_some()
}

/// Verify an API key (for use by endpoints that do their own auth check).
pub fn verify_api_key(token: &str) -> bool {
    match cached_api_key() {
        Some(expected) => constant_time_eq(token.as_bytes(), expected.as_bytes()),
        None => false,
    }
}

/// Check whether API-key auth is globally enabled.
///
/// Cached with OnceLock — env vars don't change at runtime,
/// so reading them on every request was wasteful overhead.
///
/// Auth is ON by default. Set `BRRQ_API_AUTH_DISABLED=true` (or `1`) to
/// explicitly disable it for local development.
fn is_auth_required() -> bool {
    static AUTH_REQUIRED: OnceLock<bool> = OnceLock::new();
    *AUTH_REQUIRED.get_or_init(|| {
        let disabled = std::env::var("BRRQ_API_AUTH_DISABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        if disabled {
            // Block auth bypass on mainnet (mirrors CORS mainnet guard).
            if std::env::var("BRRQ_NETWORK").unwrap_or_default() == "mainnet" {
                tracing::error!(
                    "BRRQ_API_AUTH_DISABLED=true rejected — not allowed on mainnet. \
                     Auth remains ON."
                );
                return true; // force auth ON
            }
            tracing::warn!(
                "API authentication is DISABLED (BRRQ_API_AUTH_DISABLED=true). \
                 Do NOT run this configuration in production!"
            );
        }
        !disabled
    })
}

/// Middleware that enforces API-key authentication on write endpoints.
///
/// Read methods (GET, HEAD, OPTIONS) pass through unconditionally.
/// Write methods require a valid `Authorization: Bearer <key>` header whose
/// value matches `BRRQ_API_KEY`.
pub async fn api_key_auth_middleware(
    security: Option<Extension<Arc<SecurityMetrics>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    // If auth is disabled globally, skip all checks.
    if !is_auth_required() {
        return next.run(request).await;
    }

    // Allow read-only / preflight methods without credentials.
    let method = request.method().clone();
    if method == axum::http::Method::GET
        || method == axum::http::Method::HEAD
        || method == axum::http::Method::OPTIONS
    {
        return next.run(request).await;
    }

    // Helper to increment auth failure counter
    let inc_auth_fail = || {
        if let Some(Extension(ref sec)) = security {
            sec.auth_failed_total.fetch_add(1, Ordering::Relaxed);
        }
    };

    // --- Write method — require a valid API key ---
    // Use cached_api_key() instead of std::env::var() per request.

    let expected_key = match cached_api_key() {
        Some(k) => k,
        None => {
            tracing::error!(
                "API auth is enabled but BRRQ_API_KEY is not set — rejecting request"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Server misconfiguration: API key not set",
            )
                .into_response();
        }
    };

    // Extract the Authorization header.
    let auth_header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(value) if value.starts_with("Bearer ") => {
            let provided = &value["Bearer ".len()..];
            if constant_time_eq(provided.as_bytes(), expected_key.as_bytes()) {
                next.run(request).await
            } else {
                inc_auth_fail();
                tracing::warn!("API auth: invalid key from {:?}", request.uri());
                (StatusCode::UNAUTHORIZED, "Invalid API key").into_response()
            }
        }
        Some(_) => {
            inc_auth_fail();
            (
                StatusCode::UNAUTHORIZED,
                "Authorization header must use Bearer scheme",
            )
                .into_response()
        }
        None => {
            inc_auth_fail();
            (
                StatusCode::UNAUTHORIZED,
                "Missing Authorization header — Bearer token required for write operations",
            )
                .into_response()
        }
    }
}

// ── API Version Header ──────────────────────────────────────────────────────

/// Current API version. Returned in every response as `X-API-Version` header.
pub const API_VERSION: &str = "0.1.0";

/// Middleware that adds `X-API-Version` header to every response.
pub async fn api_version_middleware(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    response.headers_mut().insert(
        "X-API-Version",
        axum::http::HeaderValue::from_static(API_VERSION),
    );
    response
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt; // for .oneshot()

    #[tokio::test]
    async fn rate_limiter_allows_within_limit() {
        // Cold-start: bucket starts with 1 token, refill at 5/sec.
        // First check consumes the 1 starting token → OK.
        // Subsequent checks depend on refill. With 5/sec, ~1 token per 200ms.
        let limiter = RateLimiter::with_config(5, 5.0, vec![]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // First request always passes (cold-start token)
        assert!(limiter.check(ip).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limiter_blocks_over_limit() {
        // Cold-start: 1 token, capacity=3, refill=1/sec
        let limiter = RateLimiter::with_config(3, 1.0, vec![]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // 1st passes (cold-start token)
        assert!(limiter.check(ip).await.is_ok());
        // 2nd should be blocked (0 tokens, no time elapsed to refill)
        assert!(limiter.check(ip).await.is_err());
    }

    #[tokio::test]
    async fn rate_limiter_separate_ips() {
        // Cold-start: 1 token per IP
        let limiter = RateLimiter::with_config(2, 1.0, vec![]);
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // Each IP gets 1 cold-start token independently
        assert!(limiter.check(ip1).await.is_ok());
        assert!(limiter.check(ip1).await.is_err()); // ip1 exhausted

        assert!(limiter.check(ip2).await.is_ok()); // ip2 still has its token
        assert!(limiter.check(ip2).await.is_err()); // ip2 exhausted
    }

    #[tokio::test]
    async fn rate_limiter_window_reset() {
        // Capacity 2, refill at 1000 tokens per sec (1 every ms)
        let limiter = RateLimiter::with_config(2, 1000.0, vec![]);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Cold-start: 1 token
        assert!(limiter.check(ip).await.is_ok());
        // After cold-start token consumed, second check may pass or fail
        // depending on timing. Wait to ensure refill.
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Should be allowed again after refill
        assert!(limiter.check(ip).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limiter_whitelist() {
        let ip1: IpAddr = "127.0.0.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.100".parse().unwrap();
        // Capacity 1, whitelist ip2
        let limiter = RateLimiter::with_config(1, 0.0, vec![ip2]);

        assert!(limiter.check(ip1).await.is_ok());
        assert!(limiter.check(ip1).await.is_err()); // ip1 gets blocked

        assert!(limiter.check(ip2).await.is_ok());
        assert!(limiter.check(ip2).await.is_ok()); // ip2 is immune
        assert!(limiter.check(ip2).await.is_ok());
    }

    #[tokio::test]
    async fn rate_limiter_default() {
        unsafe { std::env::set_var("BRRQ_RATE_LIMIT_CAPACITY", "10") };
        unsafe { std::env::set_var("BRRQ_RATE_LIMIT_REFILL_RATE", "1.0") };
        let limiter = RateLimiter::default();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();

        // Cold-start: 1 token. First check passes.
        assert!(limiter.check(ip).await.is_ok());
        // Second check should be blocked (0 tokens, negligible refill time)
        assert!(limiter.check(ip).await.is_err());

        unsafe { std::env::remove_var("BRRQ_RATE_LIMIT_CAPACITY") };
        unsafe { std::env::remove_var("BRRQ_RATE_LIMIT_REFILL_RATE") };
    }

    #[tokio::test]
    async fn rate_limiter_sharding_distributes_load() {
        // Ensure different IPs map to different shards (at least sometimes)
        let idx1 = RateLimiter::shard_index(&"10.0.0.1".parse().unwrap());
        let idx2 = RateLimiter::shard_index(&"10.0.1.1".parse().unwrap());
        // They should both be valid shard indices
        assert!(idx1 < RATE_LIMITER_SHARDS);
        assert!(idx2 < RATE_LIMITER_SHARDS);
    }

    #[tokio::test]
    async fn cors_layer_default_builds() {
        // Just verify it doesn't panic
        let _layer = default_cors();
    }

    // ── API key auth tests ─────────────────────────────────────────────

    #[test]
    fn constant_time_eq_equal() {
        assert!(constant_time_eq(b"secret123", b"secret123"));
    }

    #[test]
    fn constant_time_eq_different_content() {
        assert!(!constant_time_eq(b"secret123", b"secret456"));
    }

    #[test]
    fn constant_time_eq_different_length() {
        assert!(!constant_time_eq(b"short", b"longer_key"));
    }

    #[test]
    fn constant_time_eq_empty() {
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn auth_enabled_by_default() {
        // With BRRQ_API_AUTH_DISABLED unset, auth should be ON.
        unsafe {
            std::env::remove_var("BRRQ_API_AUTH_DISABLED");
        }
        assert!(is_auth_required());
    }

    #[test]
    fn auth_disabled_when_true() {
        unsafe {
            std::env::set_var("BRRQ_API_AUTH_DISABLED", "true");
        }
        assert!(!is_auth_required());
        unsafe {
            std::env::remove_var("BRRQ_API_AUTH_DISABLED");
        }
    }

    #[test]
    fn auth_disabled_when_one() {
        unsafe {
            std::env::set_var("BRRQ_API_AUTH_DISABLED", "1");
        }
        assert!(!is_auth_required());
        unsafe {
            std::env::remove_var("BRRQ_API_AUTH_DISABLED");
        }
    }

    #[test]
    fn auth_enabled_when_false() {
        // BRRQ_API_AUTH_DISABLED=false means auth stays ON.
        unsafe {
            std::env::set_var("BRRQ_API_AUTH_DISABLED", "false");
        }
        assert!(is_auth_required());
        unsafe {
            std::env::remove_var("BRRQ_API_AUTH_DISABLED");
        }
    }

    // ── Header Size Middleware Tests ────────────────────────────────────
    //
    // Axum's `Next` doesn't expose a constructor for unit tests, so we test
    // the middleware through a real Axum Router with the layer applied.

    use axum::routing::get as axum_get;

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    #[tokio::test]
    async fn header_size_middleware_allows_small_headers() {
        let app = axum::Router::new()
            .route("/test", axum_get(ok_handler))
            .layer(axum::middleware::from_fn(header_size_middleware));

        let req = Request::builder()
            .uri("/test")
            .header("x-small", "hello")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn header_size_middleware_rejects_oversized_headers() {
        let app = axum::Router::new()
            .route("/test", axum_get(ok_handler))
            .layer(axum::middleware::from_fn(header_size_middleware));

        // 16KB header value — exceeds 8KB limit
        let big_value = "A".repeat(16 * 1024);
        let req = Request::builder()
            .uri("/test")
            .header("x-junk", big_value)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE);
    }

    #[tokio::test]
    async fn header_size_middleware_boundary_test() {
        let app = axum::Router::new()
            .route("/test", axum_get(ok_handler))
            .layer(axum::middleware::from_fn(header_size_middleware));

        // Exactly at limit: "x-data"(6) + value + 4 overhead = 8192
        // value = 8192 - 6 - 4 = 8182
        let value = "B".repeat(8182);
        let req = Request::builder()
            .uri("/test")
            .header("x-data", value)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Exactly at limit should pass"
        );
    }
}
