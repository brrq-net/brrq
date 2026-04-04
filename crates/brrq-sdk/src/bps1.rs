//! BPS-1: Post-Quantum Payment Transport Protocol.
//!
//! SLH-DSA signatures are ~7.8 KB — too large for a single QR code.
//! This module provides three transport mechanisms:
//!
//! 1. **QR Pointer + HTTP POST** (recommended): Small QR with callback URL,
//!    full payload sent via local network (WiFi/LAN).
//! 2. **Animated QR (chunked)**: For air-gapped wallets — splits payload
//!    into small chunks displayed as animated QR frames.
//! 3. **NFC/BLE interface**: Trait for platform-specific implementations.
//!
//! ## Why not one big QR?
//!
//! QR Version 40 Level L (max capacity) holds ~4,296 bytes in binary mode.
//! SLH-DSA signature alone is 7,836 bytes. With tx envelope: ~8-9 KB.
//! **Physically impossible** to encode in one QR code.

use brrq_crypto::hash::{Hash256, Hasher};

/// Maximum payload size for a single QR chunk (binary mode, Version 20 L).
/// Version 20 L ≈ 1000 bytes — reliably scannable by all smartphone cameras.
pub const MAX_QR_CHUNK_BYTES: usize = 900;

/// Header size per chunk (index + total + checksum).
const CHUNK_HEADER_SIZE: usize = 8; // 2 (index) + 2 (total) + 4 (crc32)

/// Usable data per chunk after header.
const CHUNK_DATA_SIZE: usize = MAX_QR_CHUNK_BYTES - CHUNK_HEADER_SIZE;

/// A single chunk of an animated QR sequence.
#[derive(Debug, Clone)]
pub struct QrChunk {
    /// Chunk index (0-based).
    pub index: u16,
    /// Total number of chunks.
    pub total: u16,
    /// Raw data for this chunk.
    pub data: Vec<u8>,
    /// CRC32 checksum of `data` for integrity verification.
    pub checksum: u32,
}

impl QrChunk {
    /// Serialize this chunk into bytes for QR encoding.
    ///
    /// Format: [index: 2 LE] [total: 2 LE] [crc32: 4 LE] [data: variable]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CHUNK_HEADER_SIZE + self.data.len());
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&self.total.to_le_bytes());
        out.extend_from_slice(&self.checksum.to_le_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Deserialize a chunk from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < CHUNK_HEADER_SIZE {
            return None;
        }
        let index = u16::from_le_bytes([bytes[0], bytes[1]]);
        let total = u16::from_le_bytes([bytes[2], bytes[3]]);
        let checksum = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let data = bytes[CHUNK_HEADER_SIZE..].to_vec();

        // Verify checksum
        let computed = crc32_simple(&data);
        if computed != checksum {
            return None; // Corrupted chunk
        }

        Some(Self {
            index,
            total,
            data,
            checksum,
        })
    }
}

/// Encode a large payload into animated QR chunks.
///
/// Each chunk fits in a QR Version 20 Level L (~900 bytes).
/// The wallet displays chunks as animation; the POS camera captures all frames.
pub fn encode_animated_qr(payload: &[u8]) -> Vec<QrChunk> {
    if payload.is_empty() {
        return vec![];
    }

    let num_chunks = (payload.len() + CHUNK_DATA_SIZE - 1) / CHUNK_DATA_SIZE;
    // Prevent silent u16 truncation for payloads > 58MB
    if num_chunks > u16::MAX as usize {
        return vec![]; // Payload too large for QR chunking
    }
    let total = num_chunks as u16;
    let mut chunks = Vec::with_capacity(num_chunks);

    for (i, chunk_data) in payload.chunks(CHUNK_DATA_SIZE).enumerate() {
        let checksum = crc32_simple(chunk_data);
        chunks.push(QrChunk {
            index: i as u16,
            total,
            data: chunk_data.to_vec(),
            checksum,
        });
    }

    chunks
}

/// Decode animated QR chunks back into the original payload.
///
/// Handles out-of-order arrival (sorts by index).
/// Returns `None` if chunks are missing or corrupted.
pub fn decode_animated_qr(chunks: &[QrChunk]) -> Option<Vec<u8>> {
    if chunks.is_empty() {
        return None;
    }

    let total = chunks[0].total as usize;
    if total == 0 {
        return None;
    }

    // Verify all chunks claim the same total
    if chunks.iter().any(|c| c.total as usize != total) {
        return None;
    }

    // Check we have all chunks
    if chunks.len() != total {
        return None;
    }

    // Sort by index and verify continuity
    let mut sorted: Vec<&QrChunk> = chunks.iter().collect();
    sorted.sort_by_key(|c| c.index);

    for (i, chunk) in sorted.iter().enumerate() {
        if chunk.index as usize != i {
            return None; // Missing or duplicate index
        }
        // Re-verify checksum
        if crc32_simple(&chunk.data) != chunk.checksum {
            return None;
        }
    }

    // Reassemble
    let mut payload = Vec::new();
    for chunk in &sorted {
        payload.extend_from_slice(&chunk.data);
    }

    Some(payload)
}

/// Generate a QR pointer URI for HTTP callback transport.
///
/// The QR code is tiny (<200 bytes) and contains only the callback URL.
/// The wallet scans this, signs locally, and POSTs the full payload.
pub fn generate_qr_pointer(
    merchant_address: &str,
    amount: u64,
    invoice_id: &str,
    callback_url: &str,
) -> String {
    format!(
        "brrq://pay?merchant={}&amount={}&id={}&callback={}",
        merchant_address, amount, invoice_id, callback_url,
    )
}

/// Simple CRC32 (IEEE) for chunk integrity.
fn crc32_simple(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// NFC/BLE transport trait — implemented by platform-specific code.
///
/// Android: Kotlin/NFC API
/// iOS: Swift/CoreNFC
/// HarmonyOS: ArkTS/NFC
pub trait NearFieldTransport {
    /// Send payload via NFC/BLE to the POS terminal.
    fn send_payload(&self, payload: &[u8]) -> Result<(), String>;
    /// Receive payload from a customer wallet.
    fn receive_payload(&self, timeout_ms: u64) -> Result<Vec<u8>, String>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip_8kb() {
        // Simulate SLH-DSA signed transaction (~8 KB)
        let payload: Vec<u8> = (0..8000).map(|i| (i % 256) as u8).collect();
        let chunks = encode_animated_qr(&payload);

        // Must produce ~9 chunks (8000 / 892 ≈ 8.97)
        assert!(chunks.len() >= 9, "8KB payload needs ≥9 chunks, got {}", chunks.len());

        // Each chunk must fit in QR
        for chunk in &chunks {
            let bytes = chunk.to_bytes();
            assert!(
                bytes.len() <= MAX_QR_CHUNK_BYTES,
                "chunk {} has {} bytes (max {})",
                chunk.index, bytes.len(), MAX_QR_CHUNK_BYTES,
            );
        }

        // Decode must recover exact payload
        let recovered = decode_animated_qr(&chunks).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_chunk_serialization_roundtrip() {
        let chunk = QrChunk {
            index: 3,
            total: 10,
            data: vec![0xAB, 0xCD, 0xEF],
            checksum: crc32_simple(&[0xAB, 0xCD, 0xEF]),
        };
        let bytes = chunk.to_bytes();
        let restored = QrChunk::from_bytes(&bytes).unwrap();
        assert_eq!(restored.index, 3);
        assert_eq!(restored.total, 10);
        assert_eq!(restored.data, vec![0xAB, 0xCD, 0xEF]);
    }

    #[test]
    fn test_corrupted_chunk_rejected() {
        let mut bytes = vec![0, 0, 1, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xAB]; // Bad checksum
        let result = QrChunk::from_bytes(&bytes);
        assert!(result.is_none(), "corrupted chunk must be rejected");
    }

    #[test]
    fn test_missing_chunk_detected() {
        let payload = vec![0u8; 2000];
        let mut chunks = encode_animated_qr(&payload);
        chunks.remove(1); // Remove chunk #1
        assert!(decode_animated_qr(&chunks).is_none(), "missing chunk must fail decode");
    }

    #[test]
    fn test_out_of_order_chunks_handled() {
        let payload: Vec<u8> = (0..3000).map(|i| (i % 256) as u8).collect();
        let mut chunks = encode_animated_qr(&payload);
        chunks.reverse(); // Reverse order
        let recovered = decode_animated_qr(&chunks).unwrap();
        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_qr_pointer_format() {
        let uri = generate_qr_pointer("0xABCD", 50000, "INV-42", "http://192.168.1.5:8080/submit");
        assert!(uri.starts_with("brrq://pay?"));
        assert!(uri.contains("merchant=0xABCD"));
        assert!(uri.contains("amount=50000"));
        assert!(uri.contains("callback="));
        assert!(uri.len() < 200, "QR pointer must be small: {} bytes", uri.len());
    }

    #[test]
    fn test_empty_payload() {
        assert!(encode_animated_qr(&[]).is_empty());
        assert!(decode_animated_qr(&[]).is_none());
    }
}
