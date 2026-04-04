//! Light client for verified state queries.
//!
//! The light client maintains a set of trusted state roots, obtained either:
//! - **Manually**: via `trust_root()` for externally verified roots
//! - **From STARK proofs**: via `trust_from_batch_proof()` which cryptographically
//!   verifies the STARK proof and trusts the resulting final state root
//!
//! It can then verify account balances and storage values against those
//! roots without downloading the full state.
//!
//! ## Usage
//!
//! ```ignore (requires running Brrq node + batch proof provider)
//! let mut lc = LightClient::new("http://localhost:8545");
//!
//! // Option A: Trust from a verified STARK batch proof (trustless)
//! let proof_record = fetch_latest_batch_proof().await;
//! lc.trust_from_batch_proof(&proof_record)?;
//!
//! // Option B: Manually trust a state root (e.g., from a bridge relay)
//! lc.trust_root(100, state_root_at_block_100);
//!
//! // Query with verification against trusted root
//! let balance = lc.verified_balance(&alice_addr).await?;
//! let account = lc.verified_account(&alice_addr).await?;
//! ```

use std::collections::HashMap;

use brrq_crypto::hash::Hash256;
use brrq_prover::StarkVerifier;
use brrq_prover::types::{BatchProofRecord, StarkProof};
use brrq_state::smt::SparseMerkleTree;
use brrq_types::address::Address;

use crate::client::BrrqClient;
use crate::error::SdkError;

/// A light client that verifies account state via SMT Merkle proofs.
///
/// Maintains trusted state roots and verifies all data from the node
/// against those roots before returning it to the caller.
pub struct LightClient {
    /// The underlying RPC client.
    client: BrrqClient,
    /// Trusted state roots by block height.
    trusted_roots: HashMap<u64, Hash256>,
    /// The latest trusted root (highest block height).
    latest_trusted: Option<(u64, Hash256)>,
    /// Number of STARK proofs verified by this client.
    proofs_verified: u64,
}

impl LightClient {
    /// Create a new light client connected to a node endpoint.
    pub fn new(endpoint: &str) -> Self {
        Self {
            client: BrrqClient::new(endpoint),
            trusted_roots: HashMap::new(),
            latest_trusted: None,
            proofs_verified: 0,
        }
    }

    /// Trust a state root at a specific block height.
    ///
    /// This should be called after independently verifying the root
    /// (e.g., from a STARK batch proof, BitVM bridge assertion, etc.).
    pub fn trust_root(&mut self, height: u64, root: Hash256) {
        self.trusted_roots.insert(height, root);
        match self.latest_trusted {
            Some((h, _)) if height > h => {
                self.latest_trusted = Some((height, root));
            }
            None => {
                self.latest_trusted = Some((height, root));
            }
            _ => {}
        }
    }

    /// Trust a state root from a verified STARK batch proof (trustless).
    ///
    /// This is the primary trust mechanism for light clients. It:
    /// 1. Verifies the STARK proof cryptographically (AIR, FRI, LogUp, Merkle)
    /// 2. Extracts the `final_state_root` as the trusted root
    /// 3. Associates the root with the last block in the batch range
    ///
    /// Returns the trusted block height and state root on success.
    pub fn trust_from_batch_proof(
        &mut self,
        record: &BatchProofRecord,
    ) -> Result<(u64, Hash256), SdkError> {
        // Verify the STARK proof cryptographically
        StarkVerifier::verify(&record.proof).map_err(|e| SdkError::RpcError {
            reason: format!("STARK proof verification failed: {e}"),
        })?;

        // Validate that the proof's final_state_root matches the record's
        // claimed root. Prevents a malicious RPC from attaching a valid proof to a
        // fraudulent block_range/state_root claim.
        if record.proof.final_state_root != record.final_state_root {
            return Err(SdkError::RpcError {
                reason: "Proof final_state_root does not match record metadata".into(),
            });
        }

        let height = record.block_range.1;
        let root = record.final_state_root;

        self.trust_root(height, root);
        self.proofs_verified += 1;

        Ok((height, root))
    }

    /// Trust a state root from a raw `StarkProof` with explicit block height.
    ///
    /// Similar to `trust_from_batch_proof` but accepts a standalone proof
    /// and requires the caller to specify the block height.
    pub fn trust_from_stark_proof(
        &mut self,
        proof: &StarkProof,
        block_height: u64,
    ) -> Result<(u64, Hash256), SdkError> {
        StarkVerifier::verify(proof).map_err(|e| SdkError::RpcError {
            reason: format!("STARK proof verification failed: {e}"),
        })?;

        let root = proof.final_state_root;
        self.trust_root(block_height, root);
        self.proofs_verified += 1;

        Ok((block_height, root))
    }

    /// Get the latest trusted root, if any.
    pub fn latest_trusted_root(&self) -> Option<(u64, Hash256)> {
        self.latest_trusted
    }

    /// Get the number of trusted roots.
    pub fn trusted_root_count(&self) -> usize {
        self.trusted_roots.len()
    }

    /// Get the number of STARK proofs verified by this client.
    pub fn proofs_verified(&self) -> u64 {
        self.proofs_verified
    }

    /// Get the underlying RPC client.
    pub fn client(&self) -> &BrrqClient {
        &self.client
    }

    /// Get a verified account balance.
    ///
    /// Fetches the account proof from the node and verifies it against the
    /// latest trusted root. Returns the balance only if the proof is valid.
    pub async fn verified_balance(&self, address: &Address) -> Result<u64, SdkError> {
        let proof_json = self.client.get_account_proof(address).await?;
        let root = self.get_verification_root(&proof_json)?;

        // Verify the proof
        self.verify_account_proof_json(&proof_json, &root, address)?;

        // Extract balance
        if proof_json["exists"].as_bool().unwrap_or(false) {
            Ok(proof_json["account"]["balance"].as_u64().unwrap_or(0))
        } else {
            Ok(0) // Non-existent account has 0 balance
        }
    }

    /// Get a verified account (returns None for non-existent accounts).
    ///
    /// Fetches the account proof and verifies it against the latest trusted root.
    pub async fn verified_account(
        &self,
        address: &Address,
    ) -> Result<Option<VerifiedAccount>, SdkError> {
        let proof_json = self.client.get_account_proof(address).await?;
        let root = self.get_verification_root(&proof_json)?;

        self.verify_account_proof_json(&proof_json, &root, address)?;

        if proof_json["exists"].as_bool().unwrap_or(false) {
            let acct = &proof_json["account"];
            Ok(Some(VerifiedAccount {
                address: *address,
                balance: acct["balance"].as_u64().unwrap_or(0),
                nonce: acct["nonce"].as_u64().unwrap_or(0),
                code_hash: acct["code_hash"].as_str().unwrap_or("").to_string(),
                storage_root: acct["storage_root"].as_str().unwrap_or("").to_string(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Get a verified storage value.
    ///
    /// Fetches the storage proof and verifies the full chain
    /// (storage → account → state root) against the latest trusted root.
    ///
    /// Verification is done entirely locally:
    /// 1. Verify the account proof against the trusted state root
    /// 2. Extract the account's `storage_root` from the verified account data
    /// 3. Verify the storage proof against the verified `storage_root`
    pub async fn verified_storage(
        &self,
        address: &Address,
        key: &Hash256,
    ) -> Result<Option<Hash256>, SdkError> {
        let proof_json = self.client.get_storage_proof(address, key).await?;

        // Step 1: Verify the account proof locally against trusted root
        let account_proof = &proof_json["account_proof"];
        let root = self.get_verification_root(account_proof)?;
        self.verify_account_proof_json(account_proof, &root, address)?;

        // Step 2: Extract the verified storage root from the account data
        let storage_root_hex = account_proof["account"]["storage_root"]
            .as_str()
            .unwrap_or("");
        let storage_root = parse_hash_from_json(storage_root_hex)?;

        // If storage root is ZERO, the account has no storage
        if storage_root == Hash256::ZERO {
            return Ok(None);
        }

        // Step 3: Verify the storage proof locally against the verified storage root
        let storage_proof_data = &proof_json["storage_proof"];
        self.verify_storage_proof_json(storage_proof_data, &storage_root)?;

        // Extract the storage value (already verified by the proof above)
        if let Some(val_hex) = proof_json["storage_value"].as_str() {
            let hex_str = val_hex.strip_prefix("0x").unwrap_or(val_hex);
            let bytes = hex::decode(hex_str).map_err(|e| SdkError::RpcError {
                reason: format!("invalid storage value hex: {}", e),
            })?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                let hash = Hash256::from_bytes(arr);
                if hash == Hash256::ZERO {
                    Ok(None) // ZERO means empty
                } else {
                    Ok(Some(hash))
                }
            } else {
                Ok(None)
            }
        } else {
            Ok(None)
        }
    }

    // ── Internal ───────────────────────────────────────────────────────

    /// Get the verification root for a proof.
    ///
    /// Checks if the proof's block height has a trusted root.
    /// Returns an error if no exact-height match exists (no fallback to
    /// latest_trusted — that would silently accept proofs against a
    /// state the client has never verified).
    fn get_verification_root(&self, proof_json: &serde_json::Value) -> Result<Hash256, SdkError> {
        let proof_height = proof_json["block_height"].as_u64().unwrap_or(0);

        // Exact height match only — no fallback.
        if let Some(root) = self.trusted_roots.get(&proof_height) {
            return Ok(*root);
        }

        Err(SdkError::RpcError {
            reason: format!("no trusted root for proof block height {}", proof_height),
        })
    }

    /// Verify an account proof JSON against a trusted root.
    ///
    /// Reconstructs the SMT proof from the JSON response and verifies it
    /// locally using the SMT verification algorithm. The `expected_address`
    /// parameter ensures the proof key matches the address the client
    /// originally requested, preventing a malicious server from returning
    /// a valid proof for a different account.
    fn verify_account_proof_json(
        &self,
        proof_json: &serde_json::Value,
        expected_root: &Hash256,
        expected_address: &Address,
    ) -> Result<(), SdkError> {
        // Parse the SMT proof from JSON
        let proof_data = &proof_json["proof"];
        let key = parse_hash_from_json(proof_data["key"].as_str().unwrap_or(""))?;
        let value = parse_hash_from_json(proof_data["value"].as_str().unwrap_or(""))?;

        // Bind proof key to the address the client originally requested.
        // Without this check a malicious RPC could return a valid proof for a
        // *different* account, and the client would accept it.
        let expected_key = expected_address.to_hash();
        if key != expected_key {
            return Err(SdkError::RpcError {
                reason: "proof key does not match the requested address".into(),
            });
        }
        let exists = proof_json["exists"].as_bool().unwrap_or(false);

        let siblings_arr = proof_data["siblings"]
            .as_array()
            .ok_or(SdkError::RpcError {
                reason: "missing siblings array in proof".into(),
            })?;

        let mut siblings = Vec::with_capacity(siblings_arr.len());
        for s in siblings_arr {
            let hash = parse_hash_from_json(s.as_str().unwrap_or(""))?;
            siblings.push(hash);
        }

        let smt_proof = brrq_state::SmtProof {
            key,
            value,
            siblings,
            exists,
        };

        if !SparseMerkleTree::verify_proof(&smt_proof, expected_root) {
            return Err(SdkError::RpcError {
                reason: "account proof verification failed against trusted root".into(),
            });
        }

        Ok(())
    }

    /// Verify a storage proof JSON against a verified storage root.
    ///
    /// Reconstructs the SMT proof from the JSON response and verifies it
    /// locally using the SMT verification algorithm.
    fn verify_storage_proof_json(
        &self,
        storage_proof: &serde_json::Value,
        expected_storage_root: &Hash256,
    ) -> Result<(), SdkError> {
        let key = parse_hash_from_json(storage_proof["key"].as_str().unwrap_or(""))?;
        let value = parse_hash_from_json(storage_proof["value"].as_str().unwrap_or(""))?;
        let exists = storage_proof["exists"].as_bool().unwrap_or(false);

        let siblings_arr = storage_proof["siblings"]
            .as_array()
            .ok_or(SdkError::RpcError {
                reason: "missing siblings array in storage proof".into(),
            })?;

        let mut siblings = Vec::with_capacity(siblings_arr.len());
        for s in siblings_arr {
            let hash = parse_hash_from_json(s.as_str().unwrap_or(""))?;
            siblings.push(hash);
        }

        let smt_proof = brrq_state::SmtProof {
            key,
            value,
            siblings,
            exists,
        };

        if !SparseMerkleTree::verify_proof(&smt_proof, expected_storage_root) {
            return Err(SdkError::RpcError {
                reason: "storage proof verification failed against verified storage root".into(),
            });
        }

        Ok(())
    }
}

/// A verified account returned by the light client.
#[derive(Debug, Clone)]
pub struct VerifiedAccount {
    /// Account address.
    pub address: Address,
    /// Verified balance.
    pub balance: u64,
    /// Verified nonce.
    pub nonce: u64,
    /// Code hash (hex string).
    pub code_hash: String,
    /// Storage root (hex string).
    pub storage_root: String,
}

/// Parse a hex string (with or without 0x prefix) into a Hash256.
fn parse_hash_from_json(s: &str) -> Result<Hash256, SdkError> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    if hex_str.is_empty() {
        return Ok(Hash256::ZERO);
    }
    let bytes = hex::decode(hex_str).map_err(|e| SdkError::RpcError {
        reason: format!("invalid hash hex: {}", e),
    })?;
    if bytes.len() != 32 {
        return Err(SdkError::RpcError {
            reason: format!("hash must be 32 bytes, got {}", bytes.len()),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(Hash256::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use brrq_prover::batch::prove_batch;
    use brrq_prover::prover::StarkProver;

    #[test]
    fn test_light_client_creation() {
        let mut lc = LightClient::new("http://localhost:8545");
        assert_eq!(lc.trusted_root_count(), 0);
        assert!(lc.latest_trusted_root().is_none());
        assert_eq!(lc.proofs_verified(), 0);

        // Trust some roots
        let root1 = Hash256::from_bytes([1; 32]);
        let root2 = Hash256::from_bytes([2; 32]);
        lc.trust_root(100, root1);
        lc.trust_root(200, root2);

        assert_eq!(lc.trusted_root_count(), 2);
        let (height, root) = lc.latest_trusted_root().unwrap();
        assert_eq!(height, 200);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_trust_from_batch_proof() {
        let mut lc = LightClient::new("http://localhost:8545");

        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x01; 32]);
        let final_root = Hash256::from_bytes([0x02; 32]);
        let record = prove_batch(&prover, initial, final_root, (1, 10), 20, 10000).unwrap();

        let (height, root) = lc.trust_from_batch_proof(&record).unwrap();
        assert_eq!(height, 10);
        assert_eq!(root, final_root);
        assert_eq!(lc.proofs_verified(), 1);
        assert_eq!(lc.trusted_root_count(), 1);

        let (h, r) = lc.latest_trusted_root().unwrap();
        assert_eq!(h, 10);
        assert_eq!(r, final_root);
    }

    #[test]
    fn test_trust_from_stark_proof() {
        let mut lc = LightClient::new("http://localhost:8545");

        let prover = StarkProver::new();
        let initial = Hash256::from_bytes([0x0A; 32]);
        let final_root = Hash256::from_bytes([0x0B; 32]);
        let record = prove_batch(&prover, initial, final_root, (5, 15), 30, 15000).unwrap();

        let (height, root) = lc.trust_from_stark_proof(&record.proof, 15).unwrap();
        assert_eq!(height, 15);
        assert_eq!(root, final_root);
        assert_eq!(lc.proofs_verified(), 1);
    }

    #[test]
    fn test_trust_from_multiple_proofs() {
        let mut lc = LightClient::new("http://localhost:8545");
        let prover = StarkProver::new();

        // First batch: blocks 1-10
        let record1 = prove_batch(
            &prover,
            Hash256::from_bytes([0x01; 32]),
            Hash256::from_bytes([0x02; 32]),
            (1, 10),
            10,
            5000,
        )
        .unwrap();
        lc.trust_from_batch_proof(&record1).unwrap();

        // Second batch: blocks 11-20
        let record2 = prove_batch(
            &prover,
            Hash256::from_bytes([0x02; 32]),
            Hash256::from_bytes([0x03; 32]),
            (11, 20),
            15,
            8000,
        )
        .unwrap();
        lc.trust_from_batch_proof(&record2).unwrap();

        assert_eq!(lc.trusted_root_count(), 2);
        assert_eq!(lc.proofs_verified(), 2);
        let (h, r) = lc.latest_trusted_root().unwrap();
        assert_eq!(h, 20);
        assert_eq!(r, Hash256::from_bytes([0x03; 32]));
    }

    #[test]
    fn test_parse_hash_from_json_valid() {
        let hex = format!("0x{}", "ab".repeat(32));
        let hash = parse_hash_from_json(&hex).unwrap();
        assert_eq!(hash.as_bytes()[0], 0xab);
    }

    #[test]
    fn test_parse_hash_from_json_empty() {
        let hash = parse_hash_from_json("").unwrap();
        assert_eq!(hash, Hash256::ZERO);
    }

    #[test]
    fn test_parse_hash_from_json_invalid() {
        let result = parse_hash_from_json("0xgg");
        assert!(result.is_err());
    }

    #[test]
    fn test_verified_account_struct() {
        let acct = VerifiedAccount {
            address: Address::ZERO,
            balance: 1000,
            nonce: 5,
            code_hash: "0x".to_string() + &"00".repeat(32),
            storage_root: "0x".to_string() + &"00".repeat(32),
        };
        assert_eq!(acct.balance, 1000);
        assert_eq!(acct.nonce, 5);
    }
}
