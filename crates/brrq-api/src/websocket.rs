//! WebSocket subscriptions via Axum.
//!
//! ## WebSocket Hardening
//!
//! - **Connection limit**: max 1024 concurrent connections (RAII guard)
//! - **Incoming message size**: max 4 KB per message
//! - **Outgoing message size**: max 64 KB per event (drop oversized events)
//! - **Subscription cap**: max 16 topics per connection
//! - **Broadcast lag**: logged when subscriber falls behind

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::response::IntoResponse;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;

use crate::events::{NodeEvent, SubscriptionTopic};
use crate::state::AppState;

/// Maximum concurrent WebSocket connections allowed (global).
const MAX_WS_CONNECTIONS: usize = 1024;

/// Maximum WebSocket connections per IP address.
/// Prevents a single IP from exhausting all 1024 global slots.
const MAX_WS_PER_IP: usize = 16;

/// Per-IP WebSocket connection tracker.
static WS_PER_IP: OnceLock<Mutex<HashMap<IpAddr, usize>>> = OnceLock::new();

fn ws_per_ip_tracker() -> &'static Mutex<HashMap<IpAddr, usize>> {
    WS_PER_IP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Idle timeout for WebSocket connections (seconds).
/// Connections that receive no client messages and no broadcast events
/// within this window are terminated to prevent resource exhaustion
/// from abandoned or zombie connections.
const WS_IDLE_TIMEOUT_SECS: u64 = 300; // 5 minutes

/// Maximum size of a single incoming WebSocket text message (bytes).
const MAX_WS_MESSAGE_SIZE: usize = 4096;

/// Maximum size of a single outgoing serialized event (bytes).
/// Events larger than this are dropped to prevent memory spikes on broadcast.
/// 64 KB is generous for any single event — governance proposals are the largest.
const MAX_WS_OUTGOING_SIZE: usize = 65_536;

/// Maximum number of subscription topics per connection.
/// There are currently 7 topic types; 16 provides headroom for future expansion.
const MAX_SUBSCRIPTION_TOPICS: usize = 16;

/// Global counter for active WebSocket connections.
static WS_CONNECTION_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Get the current number of active WebSocket connections.
pub fn active_ws_connections() -> usize {
    WS_CONNECTION_COUNT.load(Ordering::Relaxed)
}

/// RAII guard that decrements the connection count on drop.
struct WsConnectionGuard {
    /// Track client IP for per-IP limit enforcement.
    ip: Option<IpAddr>,
}

impl WsConnectionGuard {
    fn try_acquire(ip: IpAddr) -> Option<Self> {
        // Check per-IP limit first.
        {
            let mut per_ip = ws_per_ip_tracker().lock().unwrap_or_else(|e| e.into_inner());
            let count = per_ip.entry(ip).or_insert(0);
            if *count >= MAX_WS_PER_IP {
                tracing::warn!(%ip, "WebSocket per-IP limit reached ({MAX_WS_PER_IP})");
                return None;
            }
            *count += 1;
        }
        // Check global limit.
        let prev = WS_CONNECTION_COUNT.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_WS_CONNECTIONS {
            WS_CONNECTION_COUNT.fetch_sub(1, Ordering::AcqRel);
            // Undo per-IP increment.
            let mut per_ip = ws_per_ip_tracker().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = per_ip.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 { per_ip.remove(&ip); }
            }
            None
        } else {
            Some(Self { ip: Some(ip) })
        }
    }
}

impl Drop for WsConnectionGuard {
    fn drop(&mut self) {
        WS_CONNECTION_COUNT.fetch_sub(1, Ordering::AcqRel);
        // Decrement per-IP counter.
        if let Some(ip) = self.ip {
            let mut per_ip = ws_per_ip_tracker().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(count) = per_ip.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 { per_ip.remove(&ip); }
            }
        }
    }
}

/// Client subscription request.
#[derive(serde::Deserialize)]
struct SubscribeRequest {
    subscribe: Vec<SubscriptionTopic>,
}

/// Client unsubscribe request.
#[derive(serde::Deserialize)]
struct UnsubscribeRequest {
    unsubscribe: Vec<SubscriptionTopic>,
}

/// Combined client message (try subscribe first, then unsubscribe).
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum ClientMessage {
    Subscribe(SubscribeRequest),
    Unsubscribe(UnsubscribeRequest),
}

// Validate the Origin header to prevent Cross-Site WebSocket Hijacking (CSWSH).
// Allowed origins are localhost variants plus any additional origins specified in
// the `BRRQ_WS_ALLOWED_ORIGINS` environment variable (comma-separated).
fn is_origin_allowed(origin: &str) -> bool {
    let origin_lower = origin.to_ascii_lowercase();
    // Always allow localhost variants.
    if origin_lower == "http://localhost"
        || origin_lower.starts_with("http://localhost:")
        || origin_lower == "http://127.0.0.1"
        || origin_lower.starts_with("http://127.0.0.1:")
        || origin_lower == "http://[::1]"
        || origin_lower.starts_with("http://[::1]:")
    {
        return true;
    }
    // Cache allowlist with OnceLock — env vars don't change at runtime.
    static WS_ALLOWED_ORIGINS: OnceLock<Vec<String>> = OnceLock::new();
    let allowed = WS_ALLOWED_ORIGINS.get_or_init(|| {
        std::env::var("BRRQ_WS_ALLOWED_ORIGINS")
            .unwrap_or_default()
            .split(',')
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect()
    });
    allowed.iter().any(|entry| origin_lower == *entry)
}

/// WebSocket upgrade handler.
pub async fn ws_handler(
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    State(app): State<AppState>,
) -> impl IntoResponse {
    // Reject upgrades whose Origin is missing or not in the allowlist (CSWSH defence).
    if let Some(origin) = headers.get(axum::http::header::ORIGIN) {
        match origin.to_str() {
            Ok(o) if is_origin_allowed(o) => { /* allowed */ }
            _ => {
                tracing::warn!("WebSocket upgrade rejected: disallowed Origin header");
                return axum::http::Response::builder()
                    .status(axum::http::StatusCode::FORBIDDEN)
                    .body(axum::body::Body::from("Forbidden: invalid Origin"))
                    .expect("static HTTP response construction cannot fail")
                    .into_response();
            }
        }
    } else {
        // Missing Origin — likely a non-browser client (CLI, monitoring, server-to-server).
        // Allow if configured, reject by default for CSWSH protection.
        let allow_no_origin = std::env::var("BRRQ_WS_ALLOW_NO_ORIGIN")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);
        if !allow_no_origin {
            tracing::warn!("WebSocket upgrade rejected: missing Origin header (set BRRQ_WS_ALLOW_NO_ORIGIN=true to allow)");
            return axum::http::Response::builder()
                .status(axum::http::StatusCode::FORBIDDEN)
                .body(axum::body::Body::from("Forbidden: missing Origin (set BRRQ_WS_ALLOW_NO_ORIGIN=true for non-browser clients)"))
                .expect("static HTTP response construction cannot fail")
                .into_response();
        }
    }

    // Enforce connection limit before upgrade (global + per-IP).
    let guard = match WsConnectionGuard::try_acquire(addr.ip()) {
        Some(g) => Arc::new(g),
        None => {
            return axum::http::Response::builder()
                .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
                .header("Retry-After", "5")
                .body(axum::body::Body::from("Too many WebSocket connections"))
                .expect("static HTTP response construction cannot fail")
                .into_response();
        }
    };

    let rx = app.event_tx.subscribe();
    ws.on_upgrade(move |socket| handle_ws(socket, rx, guard))
        .into_response()
}

/// Handle a WebSocket connection.
async fn handle_ws(
    socket: WebSocket,
    mut rx: broadcast::Receiver<NodeEvent>,
    _guard: Arc<WsConnectionGuard>,
) {
    let (mut sender, mut receiver): (SplitSink<WebSocket, Message>, SplitStream<WebSocket>) =
        socket.split();
    let mut subscriptions: HashSet<SubscriptionTopic> = HashSet::new();

    // Idle timeout — kill connections with no activity.
    let idle_timeout = tokio::time::Duration::from_secs(WS_IDLE_TIMEOUT_SECS);
    let idle_deadline = tokio::time::sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    loop {
        tokio::select! {
            // Idle timeout — terminate zombie connections.
            _ = &mut idle_deadline => {
                tracing::info!("WebSocket idle timeout ({WS_IDLE_TIMEOUT_SECS}s) — closing connection");
                let _ = sender.send(Message::Close(None)).await;
                break;
            }
            client_msg = receiver.next() => {
                // Reset idle timer on any client activity.
                idle_deadline.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                match client_msg {
                    Some(Ok(Message::Text(ref text))) => {
                        // Enforce maximum incoming message size
                        if text.len() > MAX_WS_MESSAGE_SIZE {
                            let err = serde_json::json!({
                                "error": "message too large",
                                "max_size": MAX_WS_MESSAGE_SIZE,
                            });
                            let msg = Message::Text(err.to_string().into());
                            let _ = sender.send(msg).await;
                            break;
                        }
                        if let Ok(client_msg) = serde_json::from_str::<ClientMessage>(text) {
                            match client_msg {
                                ClientMessage::Subscribe(req) => {
                                    // Cap subscription topic count.
                                    if req.subscribe.len() > MAX_SUBSCRIPTION_TOPICS {
                                        let err = serde_json::json!({
                                            "error": "too many subscription topics",
                                            "max_topics": MAX_SUBSCRIPTION_TOPICS,
                                        });
                                        let msg = Message::Text(err.to_string().into());
                                        let _ = sender.send(msg).await;
                                        continue;
                                    }
                                    subscriptions.clear();
                                    for topic in req.subscribe {
                                        subscriptions.insert(topic);
                                    }
                                    let confirm = serde_json::json!({
                                        "status": "subscribed",
                                        "topics": subscriptions.iter().collect::<Vec<_>>(),
                                    });
                                    let msg = Message::Text(confirm.to_string().into());
                                    if sender.send(msg).await.is_err() {
                                        break;
                                    }
                                }
                                ClientMessage::Unsubscribe(req) => {
                                    for topic in &req.unsubscribe {
                                        subscriptions.remove(topic);
                                    }
                                    let confirm = serde_json::json!({
                                        "status": "unsubscribed",
                                        "removed": req.unsubscribe,
                                        "remaining": subscriptions.iter().collect::<Vec<_>>(),
                                    });
                                    let msg = Message::Text(confirm.to_string().into());
                                    if sender.send(msg).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    #[allow(clippy::collapsible_match)]
                    Some(Ok(Message::Ping(data))) => {
                        if sender.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {}
                }
            }
            event = rx.recv() => {
                // Reset idle timer on broadcast activity too.
                idle_deadline.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
                match event {
                    Ok(ref ev) => {
                        let should_send = match ev {
                            NodeEvent::NewBlock { .. } => subscriptions.contains(&SubscriptionTopic::NewBlocks),
                            NodeEvent::PendingTransaction { .. } => subscriptions.contains(&SubscriptionTopic::PendingTxs),
                            NodeEvent::NewProof { .. } => subscriptions.contains(&SubscriptionTopic::NewProofs),
                            NodeEvent::L1Anchor { .. } | NodeEvent::L1StatusChanged { .. } => {
                                subscriptions.contains(&SubscriptionTopic::L1Events)
                            }
                            NodeEvent::ChallengeSubmitted { .. }
                            | NodeEvent::ChallengeResolved { .. }
                            | NodeEvent::WithdrawalCompleted { .. }
                            | NodeEvent::ProofStored { .. } => {
                                subscriptions.contains(&SubscriptionTopic::BridgeEvents)
                            }
                            NodeEvent::GovernanceProposalSubmitted { .. }
                            | NodeEvent::GovernanceVoteCast { .. }
                            | NodeEvent::GovernanceProposalFinalized { .. }
                            | NodeEvent::SequencerRegistered { .. }
                            | NodeEvent::StakeDelegated { .. }
                            | NodeEvent::StakeUndelegated { .. } => {
                                subscriptions.contains(&SubscriptionTopic::Governance)
                            }
                            #[cfg(feature = "prover-pools")]
                            NodeEvent::ProverPoolCreated { .. }
                            | NodeEvent::ProverPoolJoined { .. } => {
                                subscriptions.contains(&SubscriptionTopic::Governance)
                            }
                            NodeEvent::MevPhaseChanged { .. } => {
                                subscriptions.contains(&SubscriptionTopic::MevEvents)
                            }
                            // ── Portal events ──
                            NodeEvent::PortalLockCreated { .. }
                            | NodeEvent::PortalLockSettled { .. }
                            | NodeEvent::PortalLockExpired { .. }
                            | NodeEvent::PortalLockCancelled { .. }
                            | NodeEvent::PortalBatchSettled { .. } => {
                                subscriptions.contains(&SubscriptionTopic::PortalEvents)
                            }
                            // Emergency events — always broadcast
                            NodeEvent::ProverStrikeDetected { .. } => true,
                        };
                        if should_send
                            && let Ok(json) = serde_json::to_string(ev) {
                                // Drop oversized events to prevent memory spikes.
                                if json.len() > MAX_WS_OUTGOING_SIZE {
                                    tracing::warn!(
                                        "Dropping oversized WS event ({} bytes, max {})",
                                        json.len(), MAX_WS_OUTGOING_SIZE,
                                    );
                                    continue;
                                }
                                let msg = Message::Text(json.into());
                                if sender.send(msg).await.is_err() {
                                    break;
                                }
                            }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Log lag events for monitoring — indicates
                        // subscriber is too slow or event rate is too high.
                        tracing::warn!("WebSocket subscriber lagged by {} events", n);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }
}
