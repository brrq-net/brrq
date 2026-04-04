//! # brrq-types
//!
//! Core data types for the Brrq protocol.
//!
//! This crate defines the fundamental structures:
//! - **Addresses**: Brrq account addresses (derived from public keys)
//! - **Accounts**: Balance + nonce + optional contract state
//! - **Transactions**: Signed operations (Schnorr or SLH-DSA)
//! - **Blocks**: Ordered batches of transactions with dual signatures
//! - **Gas**: Fuel metering for zkVM execution

pub mod account;
pub mod address;
pub mod block;
pub mod da_trait;
pub mod gas;
pub mod log;
pub mod mev;
pub mod signature;
pub mod transaction;

pub use account::Account;
pub use address::{Address, AddressChecksumError};
pub use block::Block;
pub use da_trait::DaSubmit;
pub use gas::Gas;
pub use log::{Log, LogFilter};
pub use mev::{EncryptedEnvelope, MevEncryptor, MevMetadata};
pub use signature::{PublicKey, Signature, SignatureType};
pub use transaction::{
    PortalSettlementClaim, SyntheticDeposit, Transaction, TransactionBody, TransactionKind,
};
