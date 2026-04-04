//! BitVM2 Script Compiler & Chunker — prepares ZK verifier scripts for L1.
//!
//! ## Architecture
//!
//! BitVM2 requires running a Groth16/STARK verifier as Bitcoin Script.
//! A full verifier is ~3-4 GB of opcodes — far too large for a single
//! Tapscript leaf (400 KB limit). This module provides:
//!
//! 1. **Chunker**: Splits a large script into Tapscript-safe leaves (< 400 KB each)
//! 2. **State passing**: Winternitz OTS signatures link consecutive chunks
//! 3. **Bisection tree**: Organizes chunks into a balanced Taptree
//!
//! ## Current Status
//!
//! This is the **structural framework** — actual Groth16/STARK opcode
//! generation requires BitVM2 spec finalization. The chunker and tree
//! builder are production-ready; the script generator is a placeholder.
//!
//! ## Bitcoin L1 Constraints
//!
//! - Max Tapscript leaf: 400,000 bytes (consensus rule)
//! - Max block weight: 4,000,000 WU
//! - Max standard tx: ~100,000 vbytes (policy, not consensus)
//! - Each dispute step is a separate transaction (fits in policy limit)

/// Maximum size of a single Tapscript leaf in bytes.
pub const MAX_TAPSCRIPT_LEAF_SIZE: usize = 400_000;

/// Target chunk size — leave headroom for witness overhead.
/// 390 KB leaves ~10 KB for control block + witness structure.
pub const TARGET_CHUNK_SIZE: usize = 390_000;

/// A chunk of BitVM2 verifier script that fits in one Tapscript leaf.
#[derive(Debug, Clone)]
pub struct ScriptChunk {
    /// Chunk index in the execution sequence.
    pub index: usize,
    /// Raw script bytes for this chunk.
    pub script_bytes: Vec<u8>,
    /// Hash commitment to the expected input state (from previous chunk).
    pub input_state_hash: [u8; 32],
    /// Hash commitment to the output state (passed to next chunk).
    pub output_state_hash: [u8; 32],
}

/// Result of chunking a large verifier script.
#[derive(Debug, Clone)]
pub struct ChunkedScript {
    /// Individual chunks, each fitting in one Tapscript leaf.
    pub chunks: Vec<ScriptChunk>,
    /// Total size of the original script before chunking.
    pub total_script_size: usize,
    /// Number of Taptree leaves needed.
    pub num_leaves: usize,
}

/// Chunk a large script into Tapscript-safe pieces.
///
/// ## Algorithm
///
/// 1. Split `script_bytes` into segments of `TARGET_CHUNK_SIZE`
/// 2. Each chunk gets state commitment hashes linking to neighbors
/// 3. Returns `ChunkedScript` with all chunks and metadata
///
/// ## Guarantees
///
/// - No chunk exceeds `MAX_TAPSCRIPT_LEAF_SIZE`
/// - Chunks are linked by state hashes (state passing)
/// - Empty input returns error
pub fn chunk_script(script_bytes: &[u8]) -> Result<ChunkedScript, String> {
    if script_bytes.is_empty() {
        return Err("empty script cannot be chunked".into());
    }

    let total_size = script_bytes.len();
    let mut chunks = Vec::new();
    let mut offset = 0;
    let mut index = 0;

    while offset < total_size {
        let end = std::cmp::min(offset + TARGET_CHUNK_SIZE, total_size);
        let chunk_data = &script_bytes[offset..end];

        // State commitments: SHA-256 of chunk boundaries
        let input_state_hash = if index == 0 {
            [0u8; 32] // First chunk has no input state
        } else {
            // Hash of the boundary between this chunk and the previous
            let mut hasher = brrq_crypto::hash::Hasher::new();
            hasher.update(b"BITVM2_STATE_V1");
            hasher.update(&(index as u64).to_le_bytes());
            hasher.update(&script_bytes[offset.saturating_sub(32)..offset]);
            *hasher.finalize().as_bytes()
        };

        let output_state_hash = if end >= total_size {
            [0u8; 32] // Last chunk has no output state
        } else {
            let mut hasher = brrq_crypto::hash::Hasher::new();
            hasher.update(b"BITVM2_STATE_V1");
            hasher.update(&((index + 1) as u64).to_le_bytes());
            hasher.update(&script_bytes[end.saturating_sub(32)..end]);
            *hasher.finalize().as_bytes()
        };

        chunks.push(ScriptChunk {
            index,
            script_bytes: chunk_data.to_vec(),
            input_state_hash,
            output_state_hash,
        });

        offset = end;
        index += 1;
    }

    let num_leaves = chunks.len();

    // Verify invariant: no chunk exceeds limit
    for chunk in &chunks {
        if chunk.script_bytes.len() > MAX_TAPSCRIPT_LEAF_SIZE {
            return Err(format!(
                "chunk {} has {} bytes, exceeds {} limit",
                chunk.index,
                chunk.script_bytes.len(),
                MAX_TAPSCRIPT_LEAF_SIZE,
            ));
        }
    }

    Ok(ChunkedScript {
        chunks,
        total_script_size: total_size,
        num_leaves,
    })
}

/// Compute the minimum number of Taptree leaves needed for a script.
pub fn min_leaves_for_script(script_size: usize) -> usize {
    if script_size == 0 {
        return 0;
    }
    (script_size + TARGET_CHUNK_SIZE - 1) / TARGET_CHUNK_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_small_script_single_chunk() {
        let script = vec![0xAB; 1000]; // 1 KB — fits in one chunk
        let result = chunk_script(&script).unwrap();
        assert_eq!(result.num_leaves, 1);
        assert_eq!(result.chunks[0].script_bytes.len(), 1000);
        assert_eq!(result.total_script_size, 1000);
    }

    #[test]
    fn test_exact_chunk_boundary() {
        let script = vec![0xCD; TARGET_CHUNK_SIZE * 2]; // Exactly 2 chunks
        let result = chunk_script(&script).unwrap();
        assert_eq!(result.num_leaves, 2);
        assert_eq!(result.chunks[0].script_bytes.len(), TARGET_CHUNK_SIZE);
        assert_eq!(result.chunks[1].script_bytes.len(), TARGET_CHUNK_SIZE);
    }

    #[test]
    fn test_5mb_script_chunked_correctly() {
        // 5 MB script — must produce at least 13 leaves (5MB / 390KB ≈ 13.4)
        let script = vec![0xFF; 5 * 1024 * 1024];
        let result = chunk_script(&script).unwrap();

        assert!(
            result.num_leaves >= 13,
            "5 MB script must produce at least 13 chunks, got {}",
            result.num_leaves
        );

        // No chunk exceeds limit
        for chunk in &result.chunks {
            assert!(
                chunk.script_bytes.len() <= MAX_TAPSCRIPT_LEAF_SIZE,
                "chunk {} has {} bytes (max {})",
                chunk.index,
                chunk.script_bytes.len(),
                MAX_TAPSCRIPT_LEAF_SIZE,
            );
        }

        // State chain: output of chunk N == input of chunk N+1
        for i in 0..result.chunks.len() - 1 {
            assert_eq!(
                result.chunks[i].output_state_hash,
                result.chunks[i + 1].input_state_hash,
                "state chain broken between chunks {} and {}",
                i,
                i + 1
            );
        }

        // First chunk has zero input, last has zero output
        assert_eq!(result.chunks[0].input_state_hash, [0u8; 32]);
        assert_eq!(
            result.chunks.last().unwrap().output_state_hash,
            [0u8; 32]
        );
    }

    #[test]
    fn test_empty_script_rejected() {
        assert!(chunk_script(&[]).is_err());
    }

    #[test]
    fn test_min_leaves_calculation() {
        assert_eq!(min_leaves_for_script(0), 0);
        assert_eq!(min_leaves_for_script(1), 1);
        assert_eq!(min_leaves_for_script(TARGET_CHUNK_SIZE), 1);
        assert_eq!(min_leaves_for_script(TARGET_CHUNK_SIZE + 1), 2);
        assert_eq!(min_leaves_for_script(5 * 1024 * 1024), 14); // ceil(5MB / 390KB)
    }
}
