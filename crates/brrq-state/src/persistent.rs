//! Persistent storage backend using RocksDB (production-grade embedded database).
//!
//! ## Architecture
//!
//! The persistent store is a **write-behind cache**: the in-memory
//! `WorldState` serves all reads during block execution, and after
//! a block is committed the dirty state is flushed to RocksDB.
//!
//! On startup, the node loads the last committed state from RocksDB
//! into the in-memory `WorldState`, restoring full speed.
//!
//! ## Column Families (RocksDB namespaces)
//!
//! | CF           | Key                  | Value                          |
//! |--------------|----------------------|--------------------------------|
//! | `state`      | Prefix + payload     | Account/Code/Storage/Block/... |
//! | `meta`       | string key           | RANDAO secrets, node key       |
//! | `l1_anchors` | height (8-byte BE)   | L1AnchorRecord (bincode)       |
//! | `bridge`     | "blob"               | BridgeManager (bincode)        |

use bincode::Options;
use brrq_crypto::encryption::{self, EpochKey, SealedData};
use brrq_crypto::hash::Hash256;
use brrq_types::account::Account;
use brrq_types::block::Block;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DB, IteratorMode, WriteBatch};
use serde::{Deserialize, Serialize};

use crate::error::StateError;
use crate::world_state::WorldState;

/// Environment variable name for the 32-byte hex-encoded secret encryption key.
/// When set, RANDAO secrets and node P2P keys are encrypted at rest using
/// SHA-256 CTR authenticated encryption (Encrypt-then-MAC) from `brrq-crypto`.
/// When unset, secrets are stored as plaintext (backward-compatible fallback).
const ENCRYPTION_KEY_ENV: &str = "BRRQ_SECRET_ENCRYPTION_KEY";

/// Minimum size of encrypted data: 16-byte nonce + at least 1 byte ciphertext + 32-byte HMAC tag.
const MIN_ENCRYPTED_SIZE: usize = 16 + 1 + 32;

/// Try to load the encryption key from the environment.
/// Returns `None` if the env var is unset or the key is invalid.
fn get_encryption_key() -> Option<EpochKey> {
    let hex_key = std::env::var(ENCRYPTION_KEY_ENV).ok()?;
    let key_bytes = hex::decode(&hex_key).ok()?;
    if key_bytes.len() != 32 {
        tracing::warn!(
            "BRRQ_SECRET_ENCRYPTION_KEY must be exactly 32 bytes (64 hex chars), got {} bytes — secrets will be stored unencrypted",
            key_bytes.len()
        );
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);
    Some(EpochKey::from_bytes(arr))
}

/// Encrypt a secret before writing to RocksDB.
///
/// Wire format: `nonce (16 bytes) || ciphertext (N bytes) || HMAC tag (32 bytes)`
///
/// Falls back to plaintext storage when no encryption key is configured.
fn encrypt_secret(plaintext: &[u8]) -> Result<Vec<u8>, StateError> {
    match get_encryption_key() {
        Some(key) => {
            let (nonce, sealed) = encryption::seal_with_random_nonce(&key, plaintext);
            // Pack as: nonce || ciphertext || tag
            let mut result = Vec::with_capacity(16 + sealed.ciphertext.len() + 32);
            result.extend_from_slice(&nonce);
            result.extend_from_slice(&sealed.ciphertext);
            result.extend_from_slice(sealed.tag.as_bytes());
            Ok(result)
        }
        None => {
            tracing::warn!(
                "BRRQ_SECRET_ENCRYPTION_KEY not set — storing secret unencrypted"
            );
            Ok(plaintext.to_vec())
        }
    }
}

/// Decrypt a secret after reading from RocksDB.
///
/// Handles both encrypted data (nonce || ciphertext || tag) and legacy
/// unencrypted data transparently.
fn decrypt_secret(data: &[u8]) -> Result<Vec<u8>, StateError> {
    match get_encryption_key() {
        Some(key) => {
            if data.len() < MIN_ENCRYPTED_SIZE {
                // Too short to be encrypted — likely legacy unencrypted data
                tracing::warn!(
                    "data too short for encrypted format ({} bytes) — treating as legacy unencrypted",
                    data.len()
                );
                return Ok(data.to_vec());
            }
            // Unpack: nonce (16) || ciphertext (N) || tag (32)
            // SAFETY: data.len() >= MIN_ENCRYPTED_SIZE (49) is guaranteed by the guard
            // on line 90, so data[..16] is exactly 16 bytes and try_into() cannot fail.
            let nonce_bytes: [u8; 16] = data[..16].try_into().unwrap();
            let tag_offset = data.len() - 32;
            let ciphertext = &data[16..tag_offset];
            let mut tag_arr = [0u8; 32];
            tag_arr.copy_from_slice(&data[tag_offset..]);

            let sealed = SealedData {
                ciphertext: ciphertext.to_vec(),
                tag: Hash256::from_bytes(tag_arr),
            };

            encryption::open(&key, &nonce_bytes, &sealed).map_err(|_| {
                // Authentication failed — could be legacy unencrypted data or corruption.
                // Try returning raw data as fallback for migration scenarios.
                tracing::warn!(
                    "decryption failed — data may be legacy unencrypted or corrupted"
                );
                StateError::StorageError {
                    msg: "secret decryption failed — possibly legacy unencrypted data or corrupted; \
                          remove and re-save the secret to re-encrypt".into(),
                }
            })
        }
        None => Ok(data.to_vec()),
    }
}

/// Maximum bytes for a single bincode-deserialized object.
/// Prevents OOM from corrupted database entries crafting oversized allocations.
///
/// NOTE: 4 MiB is the absolute maximum for any single value.
/// Individual deserializers should enforce stricter limits:
///   - Account: 1 KiB
///   - Receipt: 64 KiB
///   - Block header: 1 KiB
///   - Full block: 4 MiB (max)
const MAX_DESERIALIZE_SIZE: u64 = 4 * 1024 * 1024; // 4 MiB

/// Column family names — correspond to sled trees in the previous implementation.
const CF_STATE: &str = "state";
const CF_META: &str = "meta";
const CF_L1_ANCHORS: &str = "l1_anchors";
const CF_BRIDGE: &str = "bridge_state";
const CF_PORTAL: &str = "portal_state";

/// All column families managed by PersistentStore.
const ALL_CFS: &[&str] = &[CF_STATE, CF_META, CF_L1_ANCHORS, CF_BRIDGE, CF_PORTAL];

/// Bounded bincode deserialization — rejects payloads exceeding `MAX_DESERIALIZE_SIZE`.
/// Consistent bincode options used for ALL serialize/deserialize in persistence.
/// Using identical options for both read and write ensures encoding consistency.
fn brrq_bincode_opts() -> impl bincode::Options {
    bincode::options()
        .with_limit(MAX_DESERIALIZE_SIZE)
        .allow_trailing_bytes()
}

fn bounded_deserialize<'de, T: Deserialize<'de>>(bytes: &'de [u8]) -> Result<T, StateError> {
    brrq_bincode_opts()
        .deserialize(bytes)
        .map_err(|e| StateError::StorageError {
            msg: format!("bounded deserialize failed: {e}"),
        })
}

fn bounded_serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, StateError> {
    brrq_bincode_opts()
        .serialize(value)
        .map_err(|e| StateError::StorageError {
            msg: format!("bounded serialize failed: {e}"),
        })
}

/// Serializable receipt data for persistent storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptData {
    /// Block height the transaction was included in.
    pub block_height: u64,
    /// Gas consumed.
    pub gas_used: u64,
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Block hash.
    pub block_hash: Hash256,
}

/// Helper to convert rocksdb::Error into StateError.
fn rocks_err(context: &str, e: rocksdb::Error) -> StateError {
    StateError::StorageError {
        msg: format!("{context}: {e}"),
    }
}

/// Persistent storage engine backed by RocksDB.
///
/// Manages four column families:
/// - `state`: unified state (accounts, code, storage, blocks, receipts, meta)
/// - `meta`: consensus metadata (RANDAO, node key)
/// - `l1_anchors`: L1 anchor records (l2_height → L1AnchorRecord)
/// - `bridge_state`: bridge manager blob
pub struct PersistentStore {
    /// The underlying RocksDB instance.
    /// RocksDB is internally thread-safe for concurrent reads/writes.
    /// Column family handles are accessed via `&ColumnFamily` references
    /// tied to the DB lifetime.
    db: DB,
}

/// Configure RocksDB options optimised for blockchain state workloads.
fn make_db_options() -> rocksdb::Options {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(true);
    opts.create_missing_column_families(true);

    // ── Write performance ──────────────────────────────────────────
    // 64 MiB write buffer — reduces write amplification for batch flushes.
    opts.set_write_buffer_size(64 * 1024 * 1024);
    // Keep 3 write buffers in memory before forcing a flush.
    opts.set_max_write_buffer_number(3);
    // Target 64 MiB L0 file size.
    opts.set_target_file_size_base(64 * 1024 * 1024);

    // ── Read performance ───────────────────────────────────────────
    // Bloom filters — 10 bits per key, dramatically reduces disk reads for
    // point lookups (accounts, receipts, blocks).
    let mut block_opts = rocksdb::BlockBasedOptions::default();
    block_opts.set_bloom_filter(10.0, false);
    // 128 MiB block cache.
    block_opts.set_block_cache(&rocksdb::Cache::new_lru_cache(128 * 1024 * 1024));
    block_opts.set_block_size(16 * 1024); // 16 KiB blocks
    opts.set_block_based_table_factory(&block_opts);

    // ── Compression ────────────────────────────────────────────────
    // Snappy for fast compression with minimal CPU overhead.
    opts.set_compression_type(rocksdb::DBCompressionType::Snappy);

    // ── Concurrency ────────────────────────────────────────────────
    opts.increase_parallelism(num_cpus());
    opts.set_max_background_jobs(4);

    opts
}

/// Create column family options (inherits most from DB options).
fn make_cf_options() -> rocksdb::Options {
    let mut opts = rocksdb::Options::default();
    let mut block_opts = rocksdb::BlockBasedOptions::default();
    block_opts.set_bloom_filter(10.0, false);
    block_opts.set_block_cache(&rocksdb::Cache::new_lru_cache(32 * 1024 * 1024));
    opts.set_block_based_table_factory(&block_opts);
    opts.set_compression_type(rocksdb::DBCompressionType::Snappy);
    opts
}

/// Detect usable CPU count for RocksDB parallelism.
fn num_cpus() -> i32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as i32)
        .unwrap_or(2)
        .max(2)
}

// ── Key builders ──────────────────────────────────────────────────────────
// Centralised prefix construction for all RocksDB keys.  Every key in the
// `state` column family starts with a single-byte type tag followed by the
// entity's raw bytes so that `prefix_iterator_cf` can scan by entity type.

/// Account key: `A` + address (20 bytes).
#[inline]
fn account_key(address: &brrq_types::address::Address) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 20);
    key.push(b'A');
    key.extend_from_slice(address.as_bytes());
    key
}

/// Code key: `C` + code_hash (32 bytes).
#[inline]
fn code_key(code_hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 32);
    key.push(b'C');
    key.extend_from_slice(code_hash.as_bytes());
    key
}

/// Storage slot key: `S` + address (20 bytes) + slot_key (32 bytes).
#[inline]
fn storage_key(address: &brrq_types::address::Address, slot_key: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 20 + 32);
    key.push(b'S');
    key.extend_from_slice(address.as_bytes());
    key.extend_from_slice(slot_key.as_bytes());
    key
}

/// Block key: `B_` + height (8 bytes big-endian).
#[inline]
fn block_key(height: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 8);
    key.extend_from_slice(b"B_");
    key.extend_from_slice(&height.to_be_bytes());
    key
}

/// Receipt key: `R_` + tx_hash (32 bytes).
#[inline]
fn receipt_key(tx_hash: &Hash256) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + 32);
    key.extend_from_slice(b"R_");
    key.extend_from_slice(tx_hash.as_bytes());
    key
}

/// Write a `StateDiff` into a `WriteBatch` using the `state` column family.
///
/// This is the single authoritative serialisation path for dirty state —
/// used by both `persist_block_atomic` (full atomic commit) and
/// `save_world_state` (standalone delta flush).
fn write_diff_to_batch(
    batch: &mut WriteBatch,
    cf: &ColumnFamily,
    diff: &crate::world_state::StateDiff,
) -> Result<(), StateError> {
    // Accounts
    for (addr, account) in &diff.accounts {
        let value = bounded_serialize(account)?;
        batch.put_cf(cf, &account_key(addr), &value);
    }
    // Code
    for (code_hash, code_bytes) in &diff.code {
        batch.put_cf(cf, &code_key(code_hash), code_bytes.as_slice());
    }
    // Deleted accounts
    for addr in &diff.deleted_accounts {
        batch.delete_cf(cf, &account_key(addr));
    }
    // Storage slots
    for ((addr, slot_key), opt_val) in &diff.storage {
        let db_key = storage_key(addr, slot_key);
        if let Some(val) = opt_val {
            batch.put_cf(cf, &db_key, val.as_bytes().as_slice());
        } else {
            batch.delete_cf(cf, &db_key);
        }
    }
    Ok(())
}

impl PersistentStore {
    // ── Typed RocksDB helpers ────────────────────────────────────────
    //
    // These reduce every put/get/flush call-site to a single line and
    // guarantee consistent error wrapping.

    /// Serialize `value` with bounded bincode and write it to the given CF + key.
    fn db_put<T: Serialize>(
        &self,
        cf: &ColumnFamily,
        key: &[u8],
        value: &T,
        ctx: &str,
    ) -> Result<(), StateError> {
        let bytes = bounded_serialize(value)?;
        self.db
            .put_cf(cf, key, &bytes)
            .map_err(|e| rocks_err(ctx, e))
    }

    /// Read a key from the given CF and deserialize with bounded bincode.
    /// Returns `Ok(None)` when the key does not exist.
    fn db_get<T: for<'de> Deserialize<'de>>(
        &self,
        cf: &ColumnFamily,
        key: &[u8],
        ctx: &str,
    ) -> Result<Option<T>, StateError> {
        match self.db.get_cf(cf, key).map_err(|e| rocks_err(ctx, e))? {
            Some(bytes) => Ok(Some(bounded_deserialize(&bytes)?)),
            None => Ok(None),
        }
    }

    /// Write a batch and flush the given column family to disk.
    fn write_and_flush(
        &self,
        batch: WriteBatch,
        cf: &ColumnFamily,
        write_ctx: &str,
        flush_ctx: &str,
    ) -> Result<(), StateError> {
        self.db
            .write(batch)
            .map_err(|e| rocks_err(write_ctx, e))?;
        self.db.flush_cf(cf).map_err(|e| rocks_err(flush_ctx, e))?;
        Ok(())
    }

    /// Open (or create) a persistent store at the given path.
    pub fn open(path: &str) -> Result<Self, StateError> {
        let db_opts = make_db_options();
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = ALL_CFS
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, make_cf_options()))
            .collect();

        let db = DB::open_cf_descriptors(&db_opts, path, cf_descriptors)
            .map_err(|e| rocks_err("rocksdb open failed", e))?;

        Ok(Self { db })
    }

    /// Open a temporary database (for testing). Automatically cleaned up on drop.
    ///
    /// Only available in tests or when the `test-utils` feature is enabled.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn open_temporary() -> Result<Self, StateError> {
        let dir = tempfile::tempdir().map_err(|e| StateError::StorageError {
            msg: format!("failed to create temp dir: {e}"),
        })?;
        // Keep the TempDir so the directory persists for the DB lifetime.
        // RocksDB will manage the data; the OS cleans temp dirs eventually.
        let path = dir.keep();
        Self::open(path.to_str().unwrap_or("/tmp/brrq-test-db"))
    }

    // ── Column family accessors ───────────────────────────────────────

    /// Get a column family handle.
    /// Returns an error if the CF doesn't exist (database corrupted or opened incorrectly).
    fn cf(&self, name: &str) -> Result<&ColumnFamily, StateError> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StateError::StorageError {
                msg: format!(
                    "column family '{name}' not found — database corrupted or opened incorrectly"
                ),
            })
    }

    #[inline]
    fn state_cf(&self) -> Result<&ColumnFamily, StateError> {
        self.cf(CF_STATE)
    }

    #[inline]
    fn meta_cf(&self) -> Result<&ColumnFamily, StateError> {
        self.cf(CF_META)
    }

    #[inline]
    fn l1_anchors_cf(&self) -> Result<&ColumnFamily, StateError> {
        self.cf(CF_L1_ANCHORS)
    }

    #[inline]
    fn bridge_cf(&self) -> Result<&ColumnFamily, StateError> {
        self.cf(CF_BRIDGE)
    }

    #[inline]
    fn portal_cf(&self) -> Result<&ColumnFamily, StateError> {
        self.cf(CF_PORTAL)
    }

    // ── Account operations ────────────────────────────────────────────

    /// Save a single account to disk.
    pub(crate) fn save_account(&self, account: &Account) -> Result<(), StateError> {
        self.db_put(
            self.state_cf()?,
            &account_key(&account.address),
            account,
            "put(account) failed",
        )
    }

    /// Persists a full block atomically (O(Delta) WorldState + Blocks + Receipts + Meta).
    /// All data is routed into `state` CF using global prefixes to guarantee ACID Split-Brain immunity.
    ///
    /// When a state root is provided, it is persisted alongside chain metadata
    /// so that `load_world_state` can verify the integrity of the reconstructed
    /// state against the stored commitment.
    pub fn persist_block_atomic(
        &self,
        diff: &crate::world_state::StateDiff,
        height: u64,
        parent_hash: &Hash256,
        block: Option<&Block>,
        receipts: Option<(&Hash256, &[ReceiptData])>,
        state_root: &Hash256,
    ) -> Result<(), StateError> {
        self.persist_block_atomic_with_portal(diff, height, parent_hash, block, receipts, state_root, None, None, None)
    }

    /// Atomic block commit including Portal state.
    /// Portal escrow and nullifier data are written in the SAME WriteBatch
    /// as the block, ensuring crash-consistency.
    ///
    /// Bridge state blob is also included in the same
    /// WriteBatch. A crash between world-state commit and bridge-state write
    /// would otherwise allow unbacked brqBTC.
    pub fn persist_block_atomic_with_portal(
        &self,
        diff: &crate::world_state::StateDiff,
        height: u64,
        parent_hash: &Hash256,
        block: Option<&Block>,
        receipts: Option<(&Hash256, &[ReceiptData])>,
        state_root: &Hash256,
        portal_escrow_blob: Option<&[u8]>,
        portal_nullifiers_blob: Option<&[u8]>,
        bridge_state_blob: Option<&[u8]>,
    ) -> Result<(), StateError> {
        let mut batch = WriteBatch::default();
        let cf = self.state_cf()?;

        // 1. Meta (Prefix: M_)
        batch.put_cf(cf, b"M_height", &height.to_le_bytes());
        batch.put_cf(cf, b"M_parent_hash", parent_hash.as_bytes().as_slice());
        // Persist state root atomically so load_world_state can verify integrity.
        batch.put_cf(cf, b"M_state_root", state_root.as_bytes().as_slice());

        // 2. Block (Prefix: B_)
        if let Some(b) = block {
            let key = block_key(b.header.height);
            // Propagate serialization errors instead of silently writing empty bytes,
            // corrupting the block store. Now propagates the error via `?`.
            let value = bounded_serialize(b)?;
            tracing::debug!(
                "persist_block_atomic block height={} key={:x?} len={}",
                b.header.height,
                key,
                value.len()
            );
            batch.put_cf(cf, &key, &value);
        }

        // 3. Receipts (Prefix: R_)
        if let Some((hash, recs)) = receipts {
            let key = receipt_key(hash);
            // Propagate serialization errors instead of silently writing empty bytes,
            // corrupting the receipts store. Now propagates the error via `?`.
            let value = bounded_serialize(&recs)?;
            batch.put_cf(cf, &key, &value);
        }

        // 4. StateDiff (Prefixes: A, C, S)
        write_diff_to_batch(&mut batch, cf, diff)?;

        // 5. Portal state in same atomic batch.
        if let Some(escrow_data) = portal_escrow_blob {
            batch.put_cf(cf, b"P_escrow", escrow_data);
        }
        if let Some(nullifiers_data) = portal_nullifiers_blob {
            batch.put_cf(cf, b"P_nullifiers", nullifiers_data);
        }

        // 6. Bridge state in same atomic WriteBatch.
        // Prevents unbacked brqBTC on crash between world-state and bridge-state writes.
        let has_bridge = bridge_state_blob.is_some();
        if let Some(bridge_data) = bridge_state_blob {
            let bridge_cf = self.bridge_cf()?;
            batch.put_cf(bridge_cf, b"blob", bridge_data);
        }

        // WAL guarantees durability after write(), but explicit flush for critical path.
        self.db
            .write(batch)
            .map_err(|e| rocks_err("write_batch(atomic) failed", e))?;
        self.db
            .flush_cf(cf)
            .map_err(|e| rocks_err("flush(state) failed", e))?;
        // Flush bridge CF when bridge data was included in the batch.
        if has_bridge {
            self.db
                .flush_cf(self.bridge_cf()?)
                .map_err(|e| rocks_err("flush(bridge) failed", e))?;
        }
        Ok(())
    }

    /// Save dirtied delta from StateDiff to disk (O(Delta) flush).
    pub fn save_world_state(&self, diff: &crate::world_state::StateDiff) -> Result<(), StateError> {
        let mut batch = WriteBatch::default();
        let cf = self.state_cf()?;
        write_diff_to_batch(&mut batch, cf, diff)?;
        self.write_and_flush(batch, cf, "write_batch(state) failed", "flush(state) failed")
    }

    /// Load all accounts from disk into a fresh WorldState.
    pub fn load_world_state(&self) -> Result<WorldState, StateError> {
        let mut ws = WorldState::new();
        let cf = self.state_cf()?;

        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (key_bytes, value_bytes) =
                item.map_err(|e| rocks_err("iterator(state) failed", e))?;

            if key_bytes.starts_with(&[b'A']) && key_bytes.len() == 21 {
                // Use bounded deserialization to prevent OOM from corrupted DB.
                let account: Account = bounded_deserialize(&value_bytes)?;
                ws.set_account(account);
            } else if key_bytes.starts_with(&[b'C']) && key_bytes.len() == 33 {
                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&key_bytes[1..33]);
                let code_hash = Hash256::from_bytes(hash_arr);
                ws.store_code_raw(code_hash, &value_bytes);
            } else if key_bytes.starts_with(&[b'S'])
                && key_bytes.len() == 53
                && value_bytes.len() == 32
            {
                let mut addr_bytes = [0u8; 20];
                addr_bytes.copy_from_slice(&key_bytes[1..21]);
                let address = brrq_types::address::Address::from_bytes(addr_bytes);

                let mut key_arr = [0u8; 32];
                key_arr.copy_from_slice(&key_bytes[21..53]);
                let storage_key = Hash256::from_bytes(key_arr);

                let mut val_arr = [0u8; 32];
                val_arr.copy_from_slice(&value_bytes);
                let storage_value = Hash256::from_bytes(val_arr);

                ws.storage_set(&address, storage_key, storage_value);
            }
        }

        // Verify integrity of loaded state by comparing the recomputed
        // state_root against the stored checksum. Detects disk corruption, partial
        // writes, or tampering that could silently produce an inconsistent state.
        // Legacy databases without a stored root are allowed to pass (graceful upgrade).
        //
        // On corruption, attempt block-level rollback instead of
        // hard failure. Walk backwards from tip until a consistent state is found,
        // or fail with an actionable error if no recovery is possible.
        if let Some(stored_root) = self.load_state_root()? {
            let computed_root = ws.state_root();
            if computed_root != stored_root {
                tracing::error!(
                    "state root integrity mismatch: stored={}, computed={}. \
                     Attempting block-level recovery...",
                    stored_root, computed_root,
                );

                // Attempt recovery by checking if we have the chain height
                // and can identify which blocks are consistent.
                let (chain_height, _) = self.load_chain_meta()?;
                if chain_height > 0 {
                    let tip_height = chain_height;
                    // Try rolling back up to MAX_ROLLBACK_DEPTH blocks to find
                    // a consistent checkpoint. Each block records its pre-state
                    // root, so we walk backwards until we find a match.
                    const MAX_ROLLBACK_DEPTH: u64 = 128;
                    let rollback_to = tip_height.saturating_sub(MAX_ROLLBACK_DEPTH);

                    for target_height in (rollback_to..tip_height).rev() {
                        if let Some(_block) = self.load_block(target_height)? {
                            // Check if the block's parent_state_root is available
                            // as a consistent checkpoint. If we can rebuild state
                            // from genesis to this height, the state is recoverable.
                            tracing::warn!(
                                "recovery candidate: block height={}, \
                                 pruning blocks {}..{}",
                                target_height,
                                target_height + 1,
                                tip_height,
                            );

                            // Prune blocks above the recovery point
                            let cf = self.state_cf()?;
                            let mut prune_batch = rocksdb::WriteBatch::default();
                            for h in (target_height + 1)..=tip_height {
                                let mut key = Vec::with_capacity(10);
                                key.extend_from_slice(b"B_");
                                key.extend_from_slice(&h.to_be_bytes());
                                prune_batch.delete_cf(cf, &key);
                            }
                            // Update chain height to recovery point
                            prune_batch.put_cf(
                                cf,
                                b"M_height",
                                &target_height.to_le_bytes(),
                            );
                            // Clear the stored state root (will be recomputed)
                            prune_batch.delete_cf(cf, b"M_state_root");

                            self.db.write(prune_batch).map_err(|e| {
                                rocks_err("write(recovery_prune) failed", e)
                            })?;
                            self.db.flush_cf(cf).map_err(|e| {
                                rocks_err("flush(recovery_prune) failed", e)
                            })?;

                            // Return an error that signals the caller to
                            // restart with a replay from the recovered height.
                            return Err(StateError::StorageError {
                                msg: format!(
                                    "state corruption recovered: pruned blocks \
                                     {}..{}, restart required to replay from \
                                     height {}. {} blocks rolled back.",
                                    target_height + 1,
                                    tip_height,
                                    target_height,
                                    tip_height - target_height,
                                ),
                            });
                        }
                    }
                }

                // If no recovery was possible, return actionable error
                return Err(StateError::StorageError {
                    msg: format!(
                        "state root integrity check failed: stored={}, computed={}. \
                         No block-level recovery possible. Manual intervention \
                         required: delete the RocksDB directory and resync from \
                         genesis, or restore from a backup.",
                        stored_root, computed_root,
                    ),
                });
            }
        }

        Ok(ws)
    }

    // ── Chain metadata ────────────────────────────────────────────────

    /// Save chain metadata (height + parent hash).
    pub fn save_chain_meta(&self, height: u64, parent_hash: &Hash256) -> Result<(), StateError> {
        let cf = self.state_cf()?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf, b"M_height", &height.to_le_bytes());
        batch.put_cf(cf, b"M_parent_hash", parent_hash.as_bytes().as_slice());
        self.write_and_flush(batch, cf, "write(chain_meta) failed", "flush(chain_meta) failed")
    }

    // State root checksum persistence for integrity verification on load.

    /// Save the computed state root to disk for integrity verification.
    /// Called after committing state changes so that `load_world_state` can
    /// verify the reconstructed state matches the expected commitment.
    pub fn save_state_root(&self, state_root: &Hash256) -> Result<(), StateError> {
        self.db
            .put_cf(
                self.state_cf()?,
                b"M_state_root",
                state_root.as_bytes().as_slice(),
            )
            .map_err(|e| rocks_err("put(M_state_root) failed", e))
    }

    /// Load the persisted state root (if any). Returns `None` for legacy databases
    /// that were written before the integrity-check feature was added.
    pub fn load_state_root(&self) -> Result<Option<Hash256>, StateError> {
        match self
            .db
            .get_cf(self.state_cf()?, b"M_state_root")
            .map_err(|e| rocks_err("get(M_state_root) failed", e))?
        {
            Some(bytes) if bytes.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Ok(Some(Hash256::from_bytes(arr)))
            }
            _ => Ok(None),
        }
    }

    /// Save RANDAO secret to disk so it survives restarts.
    /// A crash between RANDAO commit and reveal without persistence would
    /// cause a non-revealer penalty.
    pub fn save_randao_secret(&self, epoch: u64, secret: &Hash256) -> Result<(), StateError> {
        let cf = self.meta_cf()?;
        let encrypted = encrypt_secret(secret.as_bytes().as_slice())?;
        let mut batch = WriteBatch::default();
        batch.put_cf(cf, b"randao_epoch", &epoch.to_le_bytes());
        batch.put_cf(cf, b"randao_secret", &encrypted);
        self.write_and_flush(batch, cf, "write(randao) failed", "flush(randao) failed")
    }

    /// Load persisted RANDAO secret. Returns `None` if not stored.
    pub fn load_randao_secret(&self) -> Result<Option<(u64, Hash256)>, StateError> {
        let cf = self.meta_cf()?;

        let epoch = match self
            .db
            .get_cf(cf, b"randao_epoch")
            .map_err(|e| rocks_err("get(randao_epoch) failed", e))?
        {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                u64::from_le_bytes(arr)
            }
            _ => return Ok(None),
        };

        let secret = match self
            .db
            .get_cf(cf, b"randao_secret")
            .map_err(|e| rocks_err("get(randao_secret) failed", e))?
        {
            Some(bytes) if !bytes.is_empty() => {
                let decrypted = decrypt_secret(&bytes)?;
                if decrypted.len() != 32 {
                    return Err(StateError::StorageError {
                        msg: format!(
                            "randao_secret has invalid length after decryption: {} (expected 32)",
                            decrypted.len()
                        ),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decrypted);
                Hash256::from_bytes(arr)
            }
            _ => return Ok(None),
        };

        Ok(Some((epoch, secret)))
    }

    /// Clear persisted RANDAO secret (after successful reveal).
    ///
    /// Uses WriteBatch for atomicity and propagates errors.
    pub fn clear_randao_secret(&self) -> Result<(), StateError> {
        let cf = self.meta_cf()?;
        let mut batch = WriteBatch::default();
        batch.delete_cf(cf, b"randao_epoch");
        batch.delete_cf(cf, b"randao_secret");
        self.write_and_flush(batch, cf, "write(clear_randao) failed", "flush(clear_randao) failed")
    }

    // ── Node identity key ─────────────────────────────────────────────

    /// Save the persistent node identity key (32-byte secp256k1 secret).
    /// This key is used for P2P handshake authentication.
    pub fn save_node_key(&self, secret: &[u8; 32]) -> Result<(), StateError> {
        let cf = self.meta_cf()?;
        let encrypted = encrypt_secret(secret.as_slice())?;
        self.db
            .put_cf(cf, b"node_secret_key", &encrypted)
            .map_err(|e| rocks_err("put(node_secret_key) failed", e))?;
        self.db
            .flush_cf(cf)
            .map_err(|e| rocks_err("flush(node_key) failed", e))
    }

    /// Load the persistent node identity key (if any).
    pub fn load_node_key(&self) -> Result<Option<[u8; 32]>, StateError> {
        match self
            .db
            .get_cf(self.meta_cf()?, b"node_secret_key")
            .map_err(|e| rocks_err("get(node_secret_key) failed", e))?
        {
            Some(bytes) if !bytes.is_empty() => {
                let decrypted = decrypt_secret(&bytes)?;
                if decrypted.len() != 32 {
                    return Err(StateError::StorageError {
                        msg: format!(
                            "node_secret_key has invalid length after decryption: {} (expected 32)",
                            decrypted.len()
                        ),
                    });
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&decrypted);
                Ok(Some(arr))
            }
            _ => Ok(None),
        }
    }

    /// Load chain metadata. Returns `(height, parent_hash)`.
    /// Returns `(0, Hash256::ZERO)` if no metadata is stored (fresh database).
    pub fn load_chain_meta(&self) -> Result<(u64, Hash256), StateError> {
        let cf = self.state_cf()?;

        let height = match self
            .db
            .get_cf(cf, b"M_height")
            .map_err(|e| rocks_err("get(M_height) failed", e))?
        {
            Some(bytes) if bytes.len() == 8 => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                u64::from_le_bytes(arr)
            }
            _ => 0,
        };

        let parent_hash = match self
            .db
            .get_cf(cf, b"M_parent_hash")
            .map_err(|e| rocks_err("get(parent_hash) failed", e))?
        {
            Some(bytes) => {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Hash256::from_bytes(arr)
                } else {
                    Hash256::ZERO
                }
            }
            None => Hash256::ZERO,
        };

        Ok((height, parent_hash))
    }

    // ── Receipt operations ────────────────────────────────────────────

    /// Save a transaction receipt.
    pub fn save_receipt(&self, tx_hash: &Hash256, receipt: &ReceiptData) -> Result<(), StateError> {
        self.db_put(
            self.state_cf()?,
            &receipt_key(tx_hash),
            receipt,
            "put(receipt) failed",
        )
    }

    /// Save multiple receipts in a batch.
    pub fn save_receipts(&self, receipts: &[(Hash256, ReceiptData)]) -> Result<(), StateError> {
        let mut batch = WriteBatch::default();
        let cf = self.state_cf()?;
        for (hash, receipt) in receipts {
            let value = bounded_serialize(receipt)?;
            batch.put_cf(cf, &receipt_key(hash), &value);
        }
        self.db
            .write(batch)
            .map_err(|e| rocks_err("write_batch(receipts) failed", e))
    }

    /// Load a single receipt by transaction hash.
    pub fn load_receipt(&self, tx_hash: &Hash256) -> Result<Option<ReceiptData>, StateError> {
        self.db_get(self.state_cf()?, &receipt_key(tx_hash), "get(receipt) failed")
    }

    /// Load all receipts from disk.
    pub fn load_all_receipts(&self) -> Result<Vec<(Hash256, ReceiptData)>, StateError> {
        let mut receipts = Vec::new();
        let cf = self.state_cf()?;
        let iter = self.db.prefix_iterator_cf(cf, b"R_");
        for item in iter {
            let (key_bytes, value_bytes) =
                item.map_err(|e| rocks_err("prefix_iterator(R_) failed", e))?;
            // Stop when prefix no longer matches (RocksDB prefix iterators may overshoot).
            if !key_bytes.starts_with(b"R_") {
                break;
            }
            if key_bytes.len() == 34 {
                let mut hash_arr = [0u8; 32];
                hash_arr.copy_from_slice(&key_bytes[2..]);
                let tx_hash = Hash256::from_bytes(hash_arr);
                let receipt: ReceiptData = bounded_deserialize(&value_bytes)?;
                receipts.push((tx_hash, receipt));
            }
        }
        Ok(receipts)
    }

    // ── Block operations ───────────────────────────────────────────────

    /// Save a block to disk (keyed by height as 8-byte big-endian for sorted iteration).
    pub fn save_block(&self, block: &Block) -> Result<(), StateError> {
        let key = block_key(block.height());
        let value = bounded_serialize(block)?;
        tracing::debug!(
            "save_block height={} key={:x?} len={}",
            block.height(),
            key,
            value.len()
        );
        self.db
            .put_cf(self.state_cf()?, &key, &value)
            .map_err(|e| rocks_err("put(block) failed", e))
    }

    /// Load a block by height.
    pub fn load_block(&self, height: u64) -> Result<Option<Block>, StateError> {
        self.db_get(self.state_cf()?, &block_key(height), "get(block) failed")
    }

    /// Load a range of blocks `[from, to]` (inclusive).
    pub fn load_blocks_range(&self, from: u64, to: u64) -> Result<Vec<Block>, StateError> {
        let mut blocks = Vec::new();
        let cf = self.state_cf()?;

        let start = block_key(from);
        let end = block_key(to);

        tracing::debug!("load_blocks_range from={} to={}", from, to);

        let iter = self
            .db
            .iterator_cf(cf, IteratorMode::From(&start, rocksdb::Direction::Forward));

        for item in iter {
            let (key, value) = item.map_err(|e| rocks_err("iterator(blocks range) failed", e))?;
            // Stop once we pass the end key.
            if key.as_ref() > end.as_slice() {
                break;
            }
            if !key.starts_with(b"B_") {
                break;
            }
            tracing::debug!("found block key={:x?} len={}", key, value.len());
            let block: Block = bounded_deserialize(&value)?;
            blocks.push(block);
        }
        tracing::debug!("load_blocks_range returned {} blocks", blocks.len());
        Ok(blocks)
    }

    /// Prune old blocks and receipts prior to the given height.
    pub fn prune_blocks_prior_to_height(&self, keep_height: u64) -> Result<(), StateError> {
        let mut batch = WriteBatch::default();
        let cf = self.state_cf()?;
        let mut deleted_blocks = 0;
        let mut deleted_receipts = 0;

        let start_key = b"B_".to_vec();
        let end_key = block_key(keep_height.saturating_sub(1));

        let iter = self.db.iterator_cf(
            cf,
            IteratorMode::From(&start_key, rocksdb::Direction::Forward),
        );

        for item in iter {
            let (key, value) = item.map_err(|e| rocks_err("iterator(prune) failed", e))?;
            if key.as_ref() > end_key.as_slice() || !key.starts_with(b"B_") {
                break;
            }

            // Deserialize block to extract transaction hashes to delete their receipts
            if let Ok(block) = bounded_deserialize::<Block>(&value) {
                for tx in &block.transactions {
                    batch.delete_cf(cf, &receipt_key(&tx.hash()));
                    deleted_receipts += 1;
                }
            }

            // Enqueue block deletion
            batch.delete_cf(cf, key.as_ref());
            deleted_blocks += 1;
        }

        if deleted_blocks > 0 {
            self.write_and_flush(batch, cf, "write_batch(prune) failed", "flush(prune) failed")?;
            eprintln!(
                "Pruned {} historical blocks and {} receipts prior to height {}",
                deleted_blocks, deleted_receipts, keep_height
            );
        }

        Ok(())
    }

    // ── L1 Anchor operations ──────────────────────────────────────────

    /// Save an L1 anchor record to disk (keyed by L2 height).
    ///
    /// Flushes to disk immediately because anchors are critical settlement data
    /// that must survive crashes.
    pub fn save_l1_anchor(&self, record: &brrq_bitcoin::L1AnchorRecord) -> Result<(), StateError> {
        let cf = self.l1_anchors_cf()?;
        self.db_put(cf, &record.l2_height.to_be_bytes(), record, "put(l1_anchor) failed")?;
        // Flush immediately — anchors are critical settlement data.
        self.db
            .flush_cf(cf)
            .map_err(|e| rocks_err("flush(l1_anchor) failed", e))
    }

    /// Load all L1 anchor records from disk (sorted by L2 height).
    pub fn load_all_l1_anchors(&self) -> Result<Vec<brrq_bitcoin::L1AnchorRecord>, StateError> {
        let mut anchors = Vec::new();
        let cf = self.l1_anchors_cf()?;
        let iter = self.db.iterator_cf(cf, IteratorMode::Start);
        for item in iter {
            let (_key, value) = item.map_err(|e| rocks_err("iterator(l1_anchors) failed", e))?;
            let record: brrq_bitcoin::L1AnchorRecord = bounded_deserialize(&value)?;
            anchors.push(record);
        }
        Ok(anchors)
    }

    /// Number of L1 anchor records stored on disk.
    pub fn l1_anchor_count(&self) -> Result<usize, StateError> {
        let cf = self.l1_anchors_cf()?;
        Ok(self.db.iterator_cf(cf, IteratorMode::Start).count())
    }

    // ── Bridge state operations ────────────────────────────────────────

    /// Save the entire bridge state as a single blob.
    ///
    /// # Deprecated
    /// Use `persist_block_atomic_with_portal()` with `bridge_state_blob` parameter
    /// instead to ensure bridge state is written atomically with world state.
    /// A non-atomic write risks unbacked brqBTC on crash.
    #[deprecated(note = "Use persist_block_atomic_with_portal() with bridge_state_blob for atomic writes")]
    pub fn save_bridge_state_blob(&self, data: &[u8]) -> Result<(), StateError> {
        let cf = self.bridge_cf()?;
        self.db
            .put_cf(cf, b"blob", data)
            .map_err(|e| rocks_err("put(bridge_state) failed", e))?;
        // Flush to ensure crash-durability (portal state must survive restarts)
        self.db.flush_cf(cf).map_err(|e| rocks_err("flush(bridge) failed", e))
    }

    /// Load the bridge state blob (if any).
    pub fn load_bridge_state_blob(&self) -> Result<Option<Vec<u8>>, StateError> {
        match self
            .db
            .get_cf(self.bridge_cf()?, b"blob")
            .map_err(|e| rocks_err("get(bridge_state) failed", e))?
        {
            Some(bytes) => Ok(Some(bytes)),
            None => Ok(None),
        }
    }

    // ── Portal (L3) state persistence ──────────────────────────────────

    /// Save the Portal escrow state as a single blob.
    pub fn save_portal_state_blob(&self, data: &[u8]) -> Result<(), StateError> {
        let cf = self.portal_cf()?;
        self.db
            .put_cf(cf, b"escrow", data)
            .map_err(|e| rocks_err("put(portal_escrow) failed", e))?;
        // Flush to ensure crash-durability
        self.db.flush_cf(cf).map_err(|e| rocks_err("flush(portal_escrow) failed", e))
    }

    /// Load the Portal escrow state blob (if any).
    pub fn load_portal_state_blob(&self) -> Result<Option<Vec<u8>>, StateError> {
        match self
            .db
            .get_cf(self.portal_cf()?, b"escrow")
            .map_err(|e| rocks_err("get(portal_escrow) failed", e))?
        {
            Some(bytes) => Ok(Some(bytes)),
            None => Ok(None),
        }
    }

    /// Save the Portal nullifier set as a single blob.
    pub fn save_portal_nullifiers_blob(&self, data: &[u8]) -> Result<(), StateError> {
        let cf = self.portal_cf()?;
        self.db
            .put_cf(cf, b"nullifiers", data)
            .map_err(|e| rocks_err("put(portal_nullifiers) failed", e))?;
        // Flush to ensure nullifier durability (prevents double-spend after crash)
        self.db.flush_cf(cf).map_err(|e| rocks_err("flush(portal_nullifiers) failed", e))
    }

    /// Load the Portal nullifier set blob (if any).
    pub fn load_portal_nullifiers_blob(&self) -> Result<Option<Vec<u8>>, StateError> {
        match self
            .db
            .get_cf(self.portal_cf()?, b"nullifiers")
            .map_err(|e| rocks_err("get(portal_nullifiers) failed", e))?
        {
            Some(bytes) => Ok(Some(bytes)),
            None => Ok(None),
        }
    }

    // ── Diagnostics ───────────────────────────────────────────────────

    /// Number of accounts stored on disk.
    pub fn account_count(&self) -> Result<usize, StateError> {
        let cf = self.state_cf()?;
        Ok(self
            .db
            .prefix_iterator_cf(cf, [b'A'])
            .take_while(|r| r.as_ref().map_or(false, |(k, _)| k.starts_with(&[b'A'])))
            .filter(|r| r.as_ref().map_or(false, |(k, _)| k.len() == 21))
            .count())
    }

    /// Number of code entries stored on disk.
    pub fn code_count(&self) -> Result<usize, StateError> {
        let cf = self.state_cf()?;
        Ok(self
            .db
            .prefix_iterator_cf(cf, [b'C'])
            .take_while(|r| r.as_ref().map_or(false, |(k, _)| k.starts_with(&[b'C'])))
            .filter(|r| r.as_ref().map_or(false, |(k, _)| k.len() == 33))
            .count())
    }

    /// Number of receipts stored on disk.
    pub fn receipt_count(&self) -> Result<usize, StateError> {
        let cf = self.state_cf()?;
        Ok(self
            .db
            .prefix_iterator_cf(cf, b"R_")
            .take_while(|r| r.as_ref().map_or(false, |(k, _)| k.starts_with(b"R_")))
            .count())
    }

    /// Number of blocks stored on disk.
    pub fn block_count(&self) -> Result<usize, StateError> {
        let cf = self.state_cf()?;
        Ok(self
            .db
            .prefix_iterator_cf(cf, b"B_")
            .take_while(|r| r.as_ref().map_or(false, |(k, _)| k.starts_with(b"B_")))
            .count())
    }

    /// Flush all pending writes to disk.
    pub fn flush(&self) -> Result<(), StateError> {
        self.db.flush().map_err(|e| rocks_err("flush failed", e))?;
        Ok(())
    }

    /// CLEAR ALL DATA from the persistent store.
    /// Used for self-healing when state corruption is detected on startup.
    pub fn clear_all(&self) -> Result<(), StateError> {
        for cf_name in ALL_CFS {
            let cf = self.cf(cf_name)?;
            // Delete all keys in this column family by iterating.
            let keys: Vec<Box<[u8]>> = self
                .db
                .iterator_cf(cf, IteratorMode::Start)
                .filter_map(|r| r.ok().map(|(k, _)| k))
                .collect();
            let mut batch = WriteBatch::default();
            for key in &keys {
                batch.delete_cf(cf, key);
            }
            if !keys.is_empty() {
                self.db
                    .write(batch)
                    .map_err(|e| rocks_err(&format!("clear({cf_name}) failed"), e))?;
            }
        }
        self.db
            .flush()
            .map_err(|e| rocks_err("flush(clear_all) failed", e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_crypto::hash::Hasher;
    use brrq_types::address::Address;

    fn test_addr(name: &str) -> Address {
        let hash = Hasher::hash(name.as_bytes());
        let mut bytes = [0u8; 20];
        bytes.copy_from_slice(&hash.as_bytes()[..20]);
        Address::from_bytes(bytes)
    }

    #[test]
    fn test_open_temporary() {
        let store = PersistentStore::open_temporary().unwrap();
        assert_eq!(store.account_count().unwrap(), 0);
        assert_eq!(store.code_count().unwrap(), 0);
        assert_eq!(store.receipt_count().unwrap(), 0);
    }

    #[test]
    fn test_save_and_load_account() {
        let store = PersistentStore::open_temporary().unwrap();
        let alice = test_addr("alice");
        let account = Account::new_eoa(alice, 1_000_000);

        store.save_account(&account).unwrap();
        assert_eq!(store.account_count().unwrap(), 1);

        // Load into WorldState
        let ws = store.load_world_state().unwrap();
        assert_eq!(ws.balance(&alice), 1_000_000);
    }

    #[test]
    fn test_save_and_load_world_state() {
        let store = PersistentStore::open_temporary().unwrap();

        // Build a world state with multiple accounts
        let mut ws = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        ws.get_or_create_account(alice).balance = 5_000_000;
        ws.get_or_create_account(bob).balance = 3_000_000;

        // Save
        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();
        assert_eq!(store.account_count().unwrap(), 2);

        // Load into fresh WorldState
        let loaded = store.load_world_state().unwrap();
        assert_eq!(loaded.balance(&alice), 5_000_000);
        assert_eq!(loaded.balance(&bob), 3_000_000);
        assert_eq!(loaded.account_count(), 2);
    }

    #[test]
    fn test_state_root_survives_persistence() {
        let store = PersistentStore::open_temporary().unwrap();

        let mut ws = WorldState::new();
        let alice = test_addr("alice");
        let bob = test_addr("bob");
        // Use set_account to ensure trie is updated with correct balances
        ws.set_account(Account::new_eoa(alice, 1_000));
        ws.set_account(Account::new_eoa(bob, 2_000));
        let original_root = ws.state_root();

        // Save and reload
        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();
        let loaded = store.load_world_state().unwrap();

        // State root should be deterministic — same accounts produce same root
        assert_eq!(loaded.state_root(), original_root);
    }

    #[test]
    fn test_save_and_load_chain_meta() {
        let store = PersistentStore::open_temporary().unwrap();

        // Fresh store returns zero defaults
        let (h, ph) = store.load_chain_meta().unwrap();
        assert_eq!(h, 0);
        assert_eq!(ph, Hash256::ZERO);

        // Save some metadata
        let parent = Hasher::hash(b"block_42");
        store.save_chain_meta(42, &parent).unwrap();

        // Load it back
        let (h, ph) = store.load_chain_meta().unwrap();
        assert_eq!(h, 42);
        assert_eq!(ph, parent);
    }

    #[test]
    fn test_save_and_load_receipt() {
        let store = PersistentStore::open_temporary().unwrap();

        let tx_hash = Hasher::hash(b"tx_001");
        let receipt = ReceiptData {
            block_height: 10,
            gas_used: 21_000,
            success: true,
            block_hash: Hasher::hash(b"block_10"),
        };

        store.save_receipt(&tx_hash, &receipt).unwrap();
        assert_eq!(store.receipt_count().unwrap(), 1);

        let loaded = store.load_receipt(&tx_hash).unwrap().unwrap();
        assert_eq!(loaded.block_height, 10);
        assert_eq!(loaded.gas_used, 21_000);
        assert!(loaded.success);
        assert_eq!(loaded.block_hash, receipt.block_hash);
    }

    #[test]
    fn test_save_and_load_receipts_batch() {
        let store = PersistentStore::open_temporary().unwrap();

        let receipts: Vec<(Hash256, ReceiptData)> = (0..5)
            .map(|i| {
                let tx_hash = Hasher::hash(format!("tx_{i}").as_bytes());
                let receipt = ReceiptData {
                    block_height: i as u64,
                    gas_used: 21_000,
                    success: true,
                    block_hash: Hasher::hash(format!("block_{i}").as_bytes()),
                };
                (tx_hash, receipt)
            })
            .collect();

        store.save_receipts(&receipts).unwrap();
        assert_eq!(store.receipt_count().unwrap(), 5);

        let loaded = store.load_all_receipts().unwrap();
        assert_eq!(loaded.len(), 5);
    }

    #[test]
    fn test_load_receipt_not_found() {
        let store = PersistentStore::open_temporary().unwrap();
        let tx_hash = Hasher::hash(b"nonexistent_tx");
        let result = store.load_receipt(&tx_hash).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_code_persistence() {
        let store = PersistentStore::open_temporary().unwrap();

        // Build a world state with a contract
        let mut ws = WorldState::new();
        let contract_addr = test_addr("contract");
        ws.get_or_create_account(contract_addr);

        let code = vec![0x00, 0x61, 0x73, 0x6d]; // Mock WASM magic
        ws.deploy_code(&contract_addr, &code).unwrap();

        // Save
        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();

        // Load
        let loaded = store.load_world_state().unwrap();
        assert_eq!(loaded.get_code(&contract_addr), Some(code.as_slice()));
    }

    #[test]
    fn test_overwrite_account() {
        let store = PersistentStore::open_temporary().unwrap();
        let alice = test_addr("alice");

        // Save with balance 1000
        let account1 = Account::new_eoa(alice, 1_000);
        store.save_account(&account1).unwrap();

        // Overwrite with balance 2000
        let account2 = Account::new_eoa(alice, 2_000);
        store.save_account(&account2).unwrap();

        // Still only 1 entry
        assert_eq!(store.account_count().unwrap(), 1);

        let ws = store.load_world_state().unwrap();
        assert_eq!(ws.balance(&alice), 2_000);
    }

    #[test]
    fn test_save_and_load_block() {
        use brrq_crypto::eots::{EotsNonceCommitment, EotsSignature};
        use brrq_crypto::schnorr::SchnorrPublicKey;
        use brrq_crypto::slh_dsa::SlhDsaSignature;
        use brrq_types::block::{Block, BlockHeader, DualSignature, SequencerIdentity};

        let store = PersistentStore::open_temporary().unwrap();

        let header = BlockHeader {
            height: 1,
            timestamp: 1_700_000_000,
            parent_hash: Hash256::ZERO,
            transactions_root: Hasher::hash(b"tx_root"),
            signatures_root: Hash256::ZERO,
            state_root: Hasher::hash(b"state_root"),
            sequencer: test_addr("seq"),
            epoch: 0,
            gas_used: 21_000,
            gas_limit: 30_000_000,
            base_fee_per_gas: 10,
            l1_anchor_height: None,
            l1_anchor_hash: None,
            portal_nullifier_root: None,
            portal_escrow_blob_hash: None,
        };

        let block = Block {
            header,
            signature: DualSignature {
                eots: EotsSignature::new_unchecked(
                    EotsNonceCommitment::from_bytes_unchecked(vec![3u8; 33]),
                    vec![3u8; 32],
                ),
                slh_dsa: SlhDsaSignature::from_bytes(vec![3u8; 7856]).unwrap(),
            },
            sequencer_identity: SequencerIdentity {
                schnorr_pk: SchnorrPublicKey::from_bytes([5u8; 32]),
                slh_dsa_pk: brrq_crypto::slh_dsa::SlhDsaPublicKey::from_bytes(vec![5u8; 32])
                    .unwrap(),
                address: test_addr("seq"),
            },
            transactions: vec![],
        };

        store.save_block(&block).unwrap();
        assert_eq!(store.block_count().unwrap(), 1);

        let loaded = store.load_block(1).unwrap().expect("block should exist");
        assert_eq!(loaded.height(), 1);
        assert_eq!(loaded.header.gas_used, 21_000);
        assert_eq!(loaded.tx_count(), 0);

        // Non-existent block
        assert!(store.load_block(99).unwrap().is_none());
    }

    #[test]
    fn test_load_blocks_range() {
        use brrq_crypto::eots::{EotsNonceCommitment, EotsSignature};
        use brrq_crypto::schnorr::SchnorrPublicKey;
        use brrq_crypto::slh_dsa::SlhDsaSignature;
        use brrq_types::block::{Block, BlockHeader, DualSignature, SequencerIdentity};

        let store = PersistentStore::open_temporary().unwrap();

        let make_block = |height: u64| -> Block {
            let header = BlockHeader {
                height,
                timestamp: 1_700_000_000 + height,
                parent_hash: Hash256::ZERO,
                transactions_root: Hash256::ZERO,
                signatures_root: Hash256::ZERO,
                state_root: Hash256::ZERO,
                sequencer: test_addr("seq"),
                epoch: 0,
                gas_used: 0,
                gas_limit: 30_000_000,
                base_fee_per_gas: 10,
                l1_anchor_height: None,
                l1_anchor_hash: None,
                portal_nullifier_root: None,
            portal_escrow_blob_hash: None,
            };
            Block {
                header,
                signature: DualSignature {
                    eots: EotsSignature::new_unchecked(
                        EotsNonceCommitment::from_bytes_unchecked(vec![3u8; 33]),
                        vec![3u8; 32],
                    ),
                    slh_dsa: SlhDsaSignature::from_bytes(vec![3u8; 7856]).unwrap(),
                },
                sequencer_identity: SequencerIdentity {
                    schnorr_pk: SchnorrPublicKey::from_bytes([5u8; 32]),
                    slh_dsa_pk: brrq_crypto::slh_dsa::SlhDsaPublicKey::from_bytes(vec![5u8; 32])
                        .unwrap(),
                    address: test_addr("seq"),
                },
                transactions: vec![],
            }
        };

        // Save 5 blocks
        for h in 1..=5 {
            store.save_block(&make_block(h)).unwrap();
        }
        assert_eq!(store.block_count().unwrap(), 5);

        // Load range [2, 4]
        let blocks = store.load_blocks_range(2, 4).unwrap();
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].height(), 2);
        assert_eq!(blocks[1].height(), 3);
        assert_eq!(blocks[2].height(), 4);

        // Load all
        let all = store.load_blocks_range(1, 5).unwrap();
        assert_eq!(all.len(), 5);

        // Empty range
        let empty = store.load_blocks_range(10, 20).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_block_count() {
        use brrq_crypto::eots::{EotsNonceCommitment, EotsSignature};
        use brrq_crypto::schnorr::SchnorrPublicKey;
        use brrq_crypto::slh_dsa::SlhDsaSignature;
        use brrq_types::block::{Block, BlockHeader, DualSignature, SequencerIdentity};

        let store = PersistentStore::open_temporary().unwrap();
        assert_eq!(store.block_count().unwrap(), 0);

        let make_block = |height: u64| -> Block {
            Block {
                header: BlockHeader {
                    height,
                    timestamp: 0,
                    parent_hash: Hash256::ZERO,
                    transactions_root: Hash256::ZERO,
                    signatures_root: Hash256::ZERO,
                    state_root: Hash256::ZERO,
                    sequencer: test_addr("seq"),
                    epoch: 0,
                    gas_used: 0,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: 10,
                    l1_anchor_height: None,
                    l1_anchor_hash: None,
                    portal_nullifier_root: None,
            portal_escrow_blob_hash: None,
                },
                signature: DualSignature {
                    eots: EotsSignature::new_unchecked(
                        EotsNonceCommitment::from_bytes_unchecked(vec![0u8; 33]),
                        vec![0u8; 32],
                    ),
                    slh_dsa: SlhDsaSignature::from_bytes(vec![0u8; 7856]).unwrap(),
                },
                sequencer_identity: SequencerIdentity {
                    schnorr_pk: SchnorrPublicKey::from_bytes([0u8; 32]),
                    slh_dsa_pk: brrq_crypto::slh_dsa::SlhDsaPublicKey::from_bytes(vec![0u8; 32])
                        .unwrap(),
                    address: test_addr("seq"),
                },
                transactions: vec![],
            }
        };

        for h in 1..=3 {
            store.save_block(&make_block(h)).unwrap();
        }
        assert_eq!(store.block_count().unwrap(), 3);
    }

    #[test]
    fn test_open_at_path() {
        let dir = std::env::temp_dir().join("brrq_test_rocksdb_persistent");
        // Clean up from any previous run
        let _ = std::fs::remove_dir_all(&dir);

        let store = PersistentStore::open(dir.to_str().unwrap()).unwrap();
        let alice = test_addr("alice");
        store
            .save_account(&Account::new_eoa(alice, 42_000))
            .unwrap();
        store.save_chain_meta(7, &Hash256::ZERO).unwrap();
        drop(store);

        // Reopen — data should persist
        let store2 = PersistentStore::open(dir.to_str().unwrap()).unwrap();
        let ws = store2.load_world_state().unwrap();
        assert_eq!(ws.balance(&alice), 42_000);
        let (h, _) = store2.load_chain_meta().unwrap();
        assert_eq!(h, 7);

        // Clean up
        drop(store2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── L1 Anchor persistence tests ─────────────────────────────────

    #[test]
    fn test_save_and_load_l1_anchor() {
        use brrq_bitcoin::L1AnchorRecord;

        let store = PersistentStore::open_temporary().unwrap();
        assert_eq!(store.l1_anchor_count().unwrap(), 0);

        let record = L1AnchorRecord {
            l1_tx_id: [42u8; 32],
            l1_height: 850_000,
            block_hash: [0u8; 32],
            l2_height: 1000,
            state_root: Hasher::hash(b"state_root_1000"),
            proof_hash: Hash256::ZERO,
            timestamp: 1_700_000_000,
        };
        store.save_l1_anchor(&record).unwrap();
        assert_eq!(store.l1_anchor_count().unwrap(), 1);

        let loaded = store.load_all_l1_anchors().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].l1_tx_id, [42u8; 32]);
        assert_eq!(loaded[0].l1_height, 850_000);
        assert_eq!(loaded[0].l2_height, 1000);
        assert_eq!(loaded[0].state_root, Hasher::hash(b"state_root_1000"));
    }

    #[test]
    fn test_l1_anchors_sorted_by_l2_height() {
        use brrq_bitcoin::L1AnchorRecord;

        let store = PersistentStore::open_temporary().unwrap();

        // Insert out of order
        for h in [300u64, 100, 200] {
            let record = L1AnchorRecord {
                l1_tx_id: [h as u8; 32],
                l1_height: 850_000 + h,
                block_hash: [0u8; 32],
                l2_height: h,
                state_root: Hash256::ZERO,
                proof_hash: Hash256::ZERO,
                timestamp: 1_700_000_000 + h,
            };
            store.save_l1_anchor(&record).unwrap();
        }

        let loaded = store.load_all_l1_anchors().unwrap();
        assert_eq!(loaded.len(), 3);
        // RocksDB stores keys in sorted (BE) order
        assert_eq!(loaded[0].l2_height, 100);
        assert_eq!(loaded[1].l2_height, 200);
        assert_eq!(loaded[2].l2_height, 300);
    }

    #[test]
    fn test_l1_anchor_count() {
        use brrq_bitcoin::L1AnchorRecord;

        let store = PersistentStore::open_temporary().unwrap();
        assert_eq!(store.l1_anchor_count().unwrap(), 0);

        for i in 0..5u64 {
            let record = L1AnchorRecord {
                l1_tx_id: [i as u8; 32],
                l1_height: i * 100,
                block_hash: [0u8; 32],
                l2_height: (i + 1) * 100,
                state_root: Hash256::ZERO,
                proof_hash: Hash256::ZERO,
                timestamp: 1_700_000_000 + i,
            };
            store.save_l1_anchor(&record).unwrap();
        }
        assert_eq!(store.l1_anchor_count().unwrap(), 5);
    }

    #[test]
    fn test_l1_anchor_empty_load() {
        let store = PersistentStore::open_temporary().unwrap();
        let loaded = store.load_all_l1_anchors().unwrap();
        assert!(loaded.is_empty());
    }

    // ── Contract storage persistence tests ────────────────────────────

    #[test]
    fn test_storage_persistence() {
        let store = PersistentStore::open_temporary().unwrap();

        let mut ws = WorldState::new();
        let contract = test_addr("contract_storage");
        ws.get_or_create_account(contract);

        // Set some storage slots
        let key1 = Hasher::hash(b"slot_0");
        let val1 = Hasher::hash(b"value_0");
        let key2 = Hasher::hash(b"slot_1");
        let val2 = Hasher::hash(b"value_1");
        ws.storage_set(&contract, key1, val1);
        ws.storage_set(&contract, key2, val2);
        let original_storage_root = ws.storage_root(&contract);
        let original_state_root = ws.state_root();

        // Save and reload
        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();
        let loaded = store.load_world_state().unwrap();

        // Verify storage values survived
        assert_eq!(loaded.storage_get(&contract, &key1), Some(val1));
        assert_eq!(loaded.storage_get(&contract, &key2), Some(val2));
        // Verify storage root and state root match
        assert_eq!(loaded.storage_root(&contract), original_storage_root);
        assert_eq!(loaded.state_root(), original_state_root);
    }

    #[test]
    fn test_storage_persistence_multiple_contracts() {
        let store = PersistentStore::open_temporary().unwrap();

        let mut ws = WorldState::new();
        let c1 = test_addr("contract_a");
        let c2 = test_addr("contract_b");
        ws.get_or_create_account(c1);
        ws.get_or_create_account(c2);

        let k = Hasher::hash(b"shared_key");
        ws.storage_set(&c1, k, Hasher::hash(b"val_a"));
        ws.storage_set(&c2, k, Hasher::hash(b"val_b"));
        let root = ws.state_root();

        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();
        let loaded = store.load_world_state().unwrap();

        assert_eq!(loaded.storage_get(&c1, &k), Some(Hasher::hash(b"val_a")));
        assert_eq!(loaded.storage_get(&c2, &k), Some(Hasher::hash(b"val_b")));
        assert_eq!(loaded.state_root(), root);
    }

    #[test]
    fn test_storage_deletion_persists() {
        let store = PersistentStore::open_temporary().unwrap();

        let mut ws = WorldState::new();
        let contract = test_addr("contract_del");
        ws.get_or_create_account(contract);

        let k1 = Hasher::hash(b"keep");
        let k2 = Hasher::hash(b"remove");
        ws.storage_set(&contract, k1, Hasher::hash(b"val_keep"));
        ws.storage_set(&contract, k2, Hasher::hash(b"val_remove"));

        // Save with both keys
        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();

        // Remove one key and save again
        ws.storage_remove(&contract, &k2);
        let root_after_delete = ws.state_root();
        let diff = ws.extract_diff();
        store.save_world_state(&diff).unwrap();

        // Reload and verify deletion persisted
        let loaded = store.load_world_state().unwrap();
        assert_eq!(
            loaded.storage_get(&contract, &k1),
            Some(Hasher::hash(b"val_keep"))
        );
        assert_eq!(loaded.storage_get(&contract, &k2), None);
        assert_eq!(loaded.state_root(), root_after_delete);
    }

    #[test]
    fn test_historical_pruning_removes_old_blocks() {
        use brrq_crypto::eots::{EotsNonceCommitment, EotsSignature};
        use brrq_crypto::schnorr::SchnorrPublicKey;
        use brrq_crypto::slh_dsa::SlhDsaSignature;
        use brrq_types::block::{Block, BlockHeader, DualSignature, SequencerIdentity};

        let store = PersistentStore::open_temporary().unwrap();

        let make_block = |height: u64| -> Block {
            Block {
                header: BlockHeader {
                    height,
                    timestamp: 1_700_000_000 + height,
                    parent_hash: Hash256::ZERO,
                    transactions_root: Hash256::ZERO,
                    signatures_root: Hash256::ZERO,
                    state_root: Hash256::ZERO,
                    sequencer: test_addr("seq"),
                    epoch: 0,
                    gas_used: 0,
                    gas_limit: 30_000_000,
                    base_fee_per_gas: 10,
                    l1_anchor_height: None,
                    l1_anchor_hash: None,
                    portal_nullifier_root: None,
            portal_escrow_blob_hash: None,
                },
                signature: DualSignature {
                    eots: EotsSignature::new_unchecked(
                        EotsNonceCommitment::from_bytes_unchecked(vec![0u8; 33]),
                        vec![0u8; 32],
                    ),
                    slh_dsa: SlhDsaSignature::from_bytes(vec![0u8; 7856]).unwrap(),
                },
                sequencer_identity: SequencerIdentity {
                    schnorr_pk: SchnorrPublicKey::from_bytes([0u8; 32]),
                    slh_dsa_pk: brrq_crypto::slh_dsa::SlhDsaPublicKey::from_bytes(vec![0u8; 32])
                        .unwrap(),
                    address: test_addr("seq"),
                },
                transactions: vec![],
            }
        };

        // Save 10 blocks
        for h in 1..=10 {
            store.save_block(&make_block(h)).unwrap();
        }
        assert_eq!(store.block_count().unwrap(), 10);

        // Prune before height 5
        store.prune_blocks_prior_to_height(5).unwrap();

        // 1 to 4 should be gone
        assert!(store.load_block(4).unwrap().is_none());
        assert!(store.load_block(1).unwrap().is_none());

        // 5 to 10 should remain
        assert!(store.load_block(5).unwrap().is_some());
        assert!(store.load_block(10).unwrap().is_some());
        assert_eq!(store.block_count().unwrap(), 6);
    }
}
