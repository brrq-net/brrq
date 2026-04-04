//! Brrq Web API — Axum HTTP + JSON-RPC 2.0 + REST + WebSocket.
//!
//! ## Architecture
//!
//! This crate provides the web API layer for the Brrq node:
//! - **JSON-RPC 2.0** on `POST /` (backward compatible with existing clients)
//! - **REST API** on `/api/v1/*` (for web frontends and explorers)
//! - **WebSocket** on `/ws` (real-time event subscriptions)
//!
//! The API does not own node state. It receives `Arc<RwLock<NodeState>>`
//! from the node binary and provides HTTP access to it.

pub mod error;
pub mod events;
pub mod jsonrpc;
pub mod middleware;
pub mod portal;
pub mod rest;
pub mod server;
pub mod services;
pub mod state;
pub mod websocket;

pub use events::{NodeEvent, SubscriptionTopic, create_event_channel};
pub use server::start_server;
pub use state::{AppState, MevActivationMode, NodeState, SharedState, SyntheticDeposit, TxReceipt};
