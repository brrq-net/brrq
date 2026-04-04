//! Bitcoin integration errors.

use thiserror::Error;

/// Errors from Bitcoin L1 operations.
#[derive(Debug, Error)]
pub enum BitcoinError {
    /// Failed to establish RPC connection to bitcoind.
    #[error("RPC connection failed: {0}")]
    RpcConnectionFailed(String),

    /// An RPC call to bitcoind returned an error.
    #[error("RPC call failed: {0}")]
    RpcCallFailed(String),

    /// Requested Bitcoin block not found at the given height.
    #[error("block not found at height {0}")]
    BlockNotFound(u64),

    /// Failed to broadcast a transaction to the Bitcoin network.
    #[error("transaction broadcast failed: {0}")]
    BroadcastFailed(String),

    /// Invalid anchor data (bad magic, wrong size, etc.).
    #[error("invalid anchor data: {0}")]
    InvalidAnchorData(String),

    /// Bitcoin address could not be parsed.
    #[error("invalid Bitcoin address: {0}")]
    AddressParseError(String),

    /// Operation requires an active Bitcoin connection.
    #[error("not connected to Bitcoin node")]
    NotConnected,

    /// Transaction signing failed.
    #[error("transaction signing failed: {0}")]
    SigningFailed(String),

    /// Invalid configuration (unknown network, bad parameters, etc.).
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// RPC URL points to a remote (non-localhost) host.
    ///
    /// `bitcoincore-rpc` uses `minreq` without TLS, so all RPC traffic is
    /// plaintext HTTP.  Allowing remote URLs would send wallet credentials
    /// and raw transactions in the clear.  Set `BRRQ_ALLOW_REMOTE_RPC=true`
    /// to override this safety check (NOT recommended for production).
    #[error("remote Bitcoin RPC rejected: {0} (set BRRQ_ALLOW_REMOTE_RPC=true to override)")]
    RemoteRpcNotAllowed(String),

    /// Chain reorganization detected — known height reverted.
    #[error("chain reorganization detected: expected height >= {expected}, got {actual}")]
    ChainReorg { expected: u64, actual: u64 },

    /// Duplicate anchor posting attempt (already posted for this L2 height).
    #[error("anchor already posted for L2 height {0}")]
    DuplicateAnchor(u64),

    /// SPV proof verification failed.
    #[error("SPV proof verification failed: {0}")]
    SpvVerificationFailed(String),
}
