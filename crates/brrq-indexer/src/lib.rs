//! Brrq blockchain indexer — SQLite-based block and transaction indexing.
//!
//! Provides queryable storage for block explorer and REST API endpoints.
//! Listens to node events and indexes blocks/transactions into SQLite.

pub mod db;
pub mod indexer;
pub mod models;
pub mod queries;
pub mod schema;

pub use db::Database;
pub use indexer::Indexer;
pub use models::{IndexedBlock, IndexedTransaction};
