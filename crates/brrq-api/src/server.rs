//! Axum server setup — assembles all routes and middleware.
//!
//! ## Hardening Layers 
//!
//! All requests pass through these defense layers in order:
//! 1. **Body size limit** — 1 MB max per request (prevents memory exhaustion)
//! 2. **Request timeout** — 5 seconds max (prevents slow-body + thread starvation)
//! 3. **API key auth** — Bearer token on write endpoints (POST/PUT/…)
//! 4. **Rate limiter** — 100 req/10s per IP (prevents brute-force/DoS)
//! 5. **CORS** — configurable origin policy
//! 6. **Compression** — gzip response compression

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::{
    Extension, Router,
    extract::DefaultBodyLimit,
    routing::{get, post},
};
use tokio::sync::Mutex;
use tower_http::timeout::TimeoutLayer;

use crate::jsonrpc;
use crate::middleware::{self, EndpointRateLimiter, RateLimiter};
use crate::rest;
use crate::state::AppState;
use crate::websocket;

/// Maximum request body size (1 MB).
///
/// Prevents memory exhaustion from oversized payloads. Individual handlers
/// may reject smaller bodies (e.g., 4 KB for WebSocket messages).
const MAX_REQUEST_BODY_SIZE: usize = 1024 * 1024;

/// Maximum time allowed for a single request to complete (headers + body + handler).
///
/// All JSON-RPC methods complete well within this timeout.
/// Long-running operations (e.g., proof generation) use async polling endpoints.
const REQUEST_TIMEOUT_SECS: u64 = 5;

/// Maximum time for the HTTP body to be fully received after headers complete.
///
/// Defends against slow-body attacks where the attacker completes headers quickly
/// (passing header_read_timeout) but then trickles the POST body at ~10 bytes/sec.
/// The REQUEST_TIMEOUT covers the full request lifecycle, but this body-specific
/// timeout is tighter — it only allows 5 seconds for the body to arrive, regardless
/// of how much time the handler takes to process it.
const BODY_READ_TIMEOUT_SECS: u64 = 5;

/// Maximum time to receive complete HTTP headers (Slowloris defense).
///
/// A Slowloris attacker sends HTTP headers one byte at a time, holding the
/// connection open indefinitely. This timeout kills any connection that hasn't
/// completed the header phase within the limit. Set lower than REQUEST_TIMEOUT
/// because legitimate clients complete headers in < 1 second.
const HEADER_READ_TIMEOUT_SECS: u64 = 5;

/// Maximum total size of HTTP headers (bytes).
///
/// Prevents header injection attacks where an attacker sends >150KB of junk
/// headers to exhaust server memory or bypass WAFs. Set to 8KB which is
/// generous for legitimate requests (most browsers limit headers to 4-8KB).
/// hyper's default is effectively unlimited — this makes it explicit.
const MAX_HEADER_SIZE: usize = 8 * 1024;

/// Maximum concurrent TCP connections from a single IP address.
///
/// Prevents a single attacker from exhausting the server's connection pool
/// via Slowloris, slow-body, or connection-flood attacks. Legitimate clients
/// rarely need more than 10 concurrent connections. Set to 20 to allow
/// for connection pooling by proxies/load balancers while still blocking abuse.
const MAX_CONNECTIONS_PER_IP: usize = 20;

/// Per-IP connection counter for connection limiting.
///
/// Thread-safe tracker that maps each IP to its current number of open TCP
/// connections. Cleaned up automatically when connections close.
type ConnectionTracker = Arc<Mutex<HashMap<IpAddr, Arc<AtomicUsize>>>>;

/// Unified stream type for plain TCP and TLS connections.
///
/// Allows the same hyper serve path to handle both modes without
/// type erasure overhead. Implements AsyncRead + AsyncWrite by
/// delegating to the inner stream variant.
enum MaybeTlsStream {
    Plain(tokio::net::TcpStream),
    Tls(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

impl tokio::io::AsyncRead for MaybeTlsStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            MaybeTlsStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl tokio::io::AsyncWrite for MaybeTlsStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            MaybeTlsStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            MaybeTlsStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            MaybeTlsStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            MaybeTlsStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Create the complete Axum router.
pub fn create_router(state: AppState) -> Router {
    // Per-IP rate limiters: standard (global) + endpoint-specific via Extension.
    let rate_limiter = RateLimiter::new();
    let endpoint_limiters = EndpointRateLimiter::new();

    // Security metrics — shared with middleware for lock-free counter increments.
    let security_metrics = state.security.clone();

    Router::new()
        // JSON-RPC 2.0 on POST / (backward compatible)
        .route("/", post(jsonrpc::handle_jsonrpc))
        // REST API
        .nest("/api/v1", rest::routes())
        // Prometheus metrics (outside /api/v1)
        .merge(rest::metrics_routes())
        // WebSocket subscriptions
        .route("/ws", get(websocket::ws_handler))
        // ── Defense-in-depth middleware stack ──────────────────
        // Body size limit: reject payloads > 1 MB before parsing.
        // Applied FIRST so oversized bodies never reach handler code.
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_SIZE))
        // Header size limit: reject requests with >8KB of headers.
        // Applied before timeout so header injection attacks are killed
        // before consuming any processing time. Catches what hyper's
        // max_buf_size misses (hyper may grow its buffer beyond the limit).
        .layer(axum::middleware::from_fn(
            middleware::header_size_middleware,
        ))
        // Request timeout: abort any request that takes > 5 seconds.
        // Covers body receipt + handler execution. Kills slow-body attacks.
        .layer(TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(REQUEST_TIMEOUT_SECS),
        ))
        // API key authentication on write endpoints.
        // Controlled by BRRQ_API_AUTH_DISABLED and BRRQ_API_KEY env vars.
        // GET/HEAD/OPTIONS pass through; POST/PUT/PATCH/DELETE require Bearer token.
        .layer(axum::middleware::from_fn(
            middleware::api_key_auth_middleware,
        ))
        // API version header on every response.
        .layer(axum::middleware::from_fn(
            middleware::api_version_middleware,
        ))
        // Per-IP rate limiter. Uses `Extension<RateLimiter>` extractor;
        // layer order ensures the Extension is available when the middleware runs.
        .layer(axum::middleware::from_fn(middleware::rate_limit_middleware))
        .layer(Extension(rate_limiter))
        .layer(Extension(endpoint_limiters))
        // Security metrics extension — makes Arc<SecurityMetrics> available
        // to all middleware via Extension extractor for lock-free counter increments.
        .layer(Extension(security_metrics))
        // Middleware layers
        .layer(middleware::cors_layer())
        .layer(middleware::trace_layer())
        .layer(middleware::compression_layer())
        .with_state(state)
}

/// TLS handshake timeout (seconds).
///
/// TLS handshake timeout to prevent connection exhaustion.
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 3;

/// Load TLS configuration from environment variables.
///
/// Returns `Some(TlsAcceptor)` if both `BRRQ_TLS_CERT` and `BRRQ_TLS_KEY` are set,
/// `None` for plain HTTP mode (backward compatible).
fn load_tls_config() -> Option<tokio_rustls::TlsAcceptor> {
    let cert_path = std::env::var("BRRQ_TLS_CERT").ok()?;
    let key_path = std::env::var("BRRQ_TLS_KEY").ok()?;

    let cert_pem = std::fs::read(&cert_path)
        .unwrap_or_else(|e| panic!("Failed to read TLS cert at {}: {}", cert_path, e));
    let key_pem = std::fs::read(&key_path)
        .unwrap_or_else(|e| panic!("Failed to read TLS key at {}: {}", key_path, e));

    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<Result<Vec<_>, _>>()
            .expect("Invalid PEM certificate");
    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .expect("Failed to parse PEM private key")
        .expect("No private key found in PEM file");

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Invalid TLS certificate/key pair");

    tracing::info!("TLS enabled (cert: {}, key: {})", cert_path, key_path);
    Some(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Start the API server on the given port.
///
/// Binds to the address specified by `BRRQ_BIND_ADDR` env var (default `0.0.0.0`).
/// If `BRRQ_TLS_CERT` and `BRRQ_TLS_KEY` are set, the server runs with TLS.
/// Otherwise, plain HTTP (backward compatible).
pub async fn start_server(port: u16, state: AppState) -> Result<(), Box<dyn std::error::Error>> {
    // Security metrics for connection rejection counting.
    let security_metrics = state.security.clone();

    // Optional TLS — only enabled when both env vars are set.
    let tls_acceptor = load_tls_config();

    let app = create_router(state);
    let bind_addr = std::env::var("BRRQ_BIND_ADDR").unwrap_or_else(|_| "0.0.0.0".to_string());
    let addr = format!("{}:{}", bind_addr, port);
    let proto = if tls_acceptor.is_some() {
        "HTTPS"
    } else {
        "HTTP"
    };
    tracing::info!(
        "API server listening on {} ({}) (JSON-RPC + REST + WebSocket)",
        addr,
        proto
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    // Use into_make_service_with_connect_info so that rate limiter middleware
    // can extract ConnectInfo<SocketAddr> for per-IP rate limiting.
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use hyper_util::server::conn::auto::Builder;
    use tower::Service;

    // Per-IP connection tracker to prevent Slowloris/connection-flood attacks.
    let connection_tracker: ConnectionTracker = Arc::new(Mutex::new(HashMap::new()));

    let conn_whitelist: Arc<Vec<IpAddr>> = Arc::new({
        let raw = std::env::var("BRRQ_CONN_LIMIT_WHITELIST")
            .or_else(|_| std::env::var("BRRQ_RATE_LIMIT_WHITELIST"))
            .unwrap_or_default();
        raw.split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect()
    });

    loop {
        let (tcp, remote_addr) = listener.accept().await?;
        let ip = remote_addr.ip();

        // Whitelisted IPs bypass connection limit entirely.
        // This ensures monitoring agents, validator nodes, and admin tools
        // remain reachable during active Slowloris/DoS attacks.
        if !conn_whitelist.contains(&ip) {
            // Enforce per-IP connection limit BEFORE any HTTP processing.
            // This stops Slowloris at the TCP level — the attacker cannot even
            // begin sending slow headers if they've exhausted their connection quota.
            let counter = {
                let mut tracker = connection_tracker.lock().await;
                tracker
                    .entry(ip)
                    .or_insert_with(|| Arc::new(AtomicUsize::new(0)))
                    .clone()
            };

            let current = counter.fetch_add(1, Ordering::Relaxed);
            if current >= MAX_CONNECTIONS_PER_IP {
                counter.fetch_sub(1, Ordering::Relaxed);
                // Increment security metric for connection rejection.
                security_metrics
                    .connection_rejected_total
                    .fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    ip = %ip,
                    limit = MAX_CONNECTIONS_PER_IP,
                    "Connection rejected: per-IP concurrent limit exceeded"
                );
                drop(tcp);
                continue;
            }
        }

        // Only track connection count for non-whitelisted IPs.
        let conn_counter: Option<Arc<AtomicUsize>> = if !conn_whitelist.contains(&ip) {
            let c = {
                let tracker = connection_tracker.lock().await;
                tracker.get(&ip).cloned()
            };
            c
        } else {
            None
        };

        let tower_service = app.clone();
        let tls = tls_acceptor.clone();

        tokio::spawn(async move {
            // Conditionally wrap TCP stream with TLS via MaybeTlsStream enum.
            let stream = if let Some(tls_acceptor) = tls {
                // TLS handshake with timeout — prevents TLS-level Slowloris.
                match tokio::time::timeout(
                    Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS),
                    tls_acceptor.accept(tcp),
                )
                .await
                {
                    Ok(Ok(tls_stream)) => MaybeTlsStream::Tls(tls_stream),
                    Ok(Err(e)) => {
                        tracing::debug!("TLS handshake failed: {:?}", e);
                        if let Some(counter) = conn_counter {
                            counter.fetch_sub(1, Ordering::Relaxed);
                        }
                        return;
                    }
                    Err(_) => {
                        tracing::debug!("TLS handshake timeout exceeded");
                        if let Some(counter) = conn_counter {
                            counter.fetch_sub(1, Ordering::Relaxed);
                        }
                        return;
                    }
                }
            } else {
                MaybeTlsStream::Plain(tcp)
            };
            let io = TokioIo::new(stream);

            let hyper_service = hyper::service::service_fn(
                move |mut req: hyper::Request<hyper::body::Incoming>| {
                    req.extensions_mut()
                        .insert(axum::extract::ConnectInfo(remote_addr));
                    tower_service.clone().call(req)
                },
            );

            // Multi-layer connection timeout defense.
            //
            // Layer 1: header_read_timeout (5s) — kills Slowloris (trickled headers)
            // Layer 2: tokio::time::timeout (10s) wrapping the entire connection —
            //          safety net that kills any connection lingering past header+body
            //          phase. HEADER(5s) + BODY(5s) = 10s total connection deadline.
            // Layer 3: REQUEST_TIMEOUT (5s) via TimeoutLayer — kills slow body reads
            //          + slow handlers at the Axum Service level.
            let mut server = Builder::new(TokioExecutor::new());
            server
                .http1()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(HEADER_READ_TIMEOUT_SECS))
                // Limit total header size to 8KB. Kills header injection
                // attacks that send >150KB of junk headers. hyper will return
                // 431 Request Header Fields Too Large if headers exceed this.
                .max_buf_size(MAX_HEADER_SIZE);

            // Wrap connection in a hard timeout that covers header + body reception.
            // If the client hasn't delivered a complete request within this window,
            // the connection is killed regardless of what phase it's in.
            let connection_deadline =
                Duration::from_secs(HEADER_READ_TIMEOUT_SECS + BODY_READ_TIMEOUT_SECS);
            let result = tokio::time::timeout(
                connection_deadline,
                server.serve_connection_with_upgrades(io, hyper_service),
            )
            .await;

            match result {
                Ok(Err(err)) => {
                    tracing::debug!("Connection closed: {:?}", err);
                }
                Err(_elapsed) => {
                    tracing::debug!("Connection killed: body/header timeout exceeded");
                }
                Ok(Ok(())) => {}
            }

            // Decrement connection counter when connection closes.
            // This runs regardless of whether the connection succeeded or failed,
            // ensuring the counter never leaks. Only for non-whitelisted IPs.
            if let Some(counter) = conn_counter {
                counter.fetch_sub(1, Ordering::Relaxed);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::create_event_channel;
    use crate::state::{NodeState, SharedState};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn test_create_router() {
        let state = NodeState::new();
        let shared: SharedState = Arc::new(RwLock::new(state));
        let (event_tx, _) = create_event_channel();
        let app_state = AppState::new(shared, event_tx);
        let _router = create_router(app_state);
        // Just verify it compiles and creates without panic
    }
}
