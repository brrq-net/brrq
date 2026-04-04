//! API error types.
//!
//! ## Error Message Sanitization
//!
//! Internal errors are logged server-side but the client only receives
//! a generic "Internal server error" message. This prevents leaking
//! implementation details (stack traces, file paths, serde internals)
//! that an attacker could use for reconnaissance.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

// ── JSON-RPC 2.0 Error Codes ────────────────────────────────────────────
//
// Standard JSON-RPC 2.0 errors:

/// Parse error: Invalid JSON was received.
pub const RPC_PARSE_ERROR: i32 = -32700;

/// Invalid Request: The JSON sent is not a valid Request object.
pub const RPC_INVALID_REQUEST: i32 = -32600;

/// Method not found: The method does not exist / is not available.
pub const RPC_METHOD_NOT_FOUND: i32 = -32601;

/// Invalid params: Invalid method parameter(s).
pub const RPC_INVALID_PARAMS: i32 = -32602;

// Brrq-specific server errors (-32000 to -32099):

/// Server error: Generic application-level error (insufficient balance,
/// faucet depleted, proposal failed, etc.).
pub const RPC_SERVER_ERROR: i32 = -32000;

/// Server error: Authentication/authorization failure.
pub const RPC_UNAUTHORIZED: i32 = -32001;

/// Server error: Resource temporarily unavailable (rate limited, syncing).
pub const RPC_RESOURCE_UNAVAILABLE: i32 = -32003;

/// Server error: Requested data not found (block, proof, etc.).
pub const RPC_NOT_FOUND: i32 = -32002;

/// API error type.
#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    /// Request failed signature verification or authorization check.
    Unauthorized(String),
    NotFound(String),
    Internal(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            // Never expose internal error details to clients.
            // Log the real error server-side for debugging.
            ApiError::Internal(msg) => {
                tracing::error!("Internal API error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}
