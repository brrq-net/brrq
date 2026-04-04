//! Brrq developer SDK — client, wallet, contract tools.
//!
//! ## Components
//!
//! - **Wallet**: Key management, transaction signing (Schnorr + SLH-DSA)
//! - **Client**: JSON-RPC client for node interaction
//! - **Contract**: Smart contract deployment and interaction helpers

pub mod client;
pub mod error;
#[cfg(feature = "light-client")]
pub mod light_client;
pub mod wallet;
pub mod bps1;

pub use client::BrrqClient;
pub use error::SdkError;
#[cfg(feature = "light-client")]
pub use light_client::LightClient;
pub use wallet::Wallet;
