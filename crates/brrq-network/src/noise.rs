//! Noise Protocol Framework for P2P transport security.
//!
//! Implements the Noise_XK handshake pattern for authenticated encrypted
//! channels between peers, following the Noise Protocol Framework specification.
//!
//! ## Pattern: Noise_XK
//!
//! ```text
//!   <- s            (responder's static key known in advance via Nostr)
//!   -> e, es        (initiator sends ephemeral, DH with responder static)
//!   <- e, ee        (responder sends ephemeral, DH ephemeral-ephemeral)
//!   -> s, se        (initiator sends static, DH static-ephemeral)
//! ```
//!
//! ## State Machine
//!
//! `Init -> Handshake1 -> Handshake2 -> Transport`
//!
//! ## Crypto Primitives
//!
//! - **X25519**: Diffie-Hellman key agreement
//! - **HKDF-SHA256**: Key derivation
//! - **ChaCha20-Poly1305**: AEAD transport encryption (IETF variant)

use std::fmt;

use chacha20poly1305::{
    ChaCha20Poly1305, Nonce as AeadNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::error::NetworkError;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Noise protocol name for domain separation.
const NOISE_PROTOCOL_NAME: &[u8] = b"Noise_XK_25519_ChaChaPoly_SHA256";

/// X25519 key length in bytes.
const DH_LEN: usize = 32;

/// SHA-256 hash output length.
const HASH_LEN: usize = 32;

/// ChaCha20-Poly1305 AEAD tag length.
const AEAD_TAG_LEN: usize = 16;

/// Maximum transport payload size (64 KB minus AEAD overhead).
const MAX_TRANSPORT_PAYLOAD: usize = 65535 - AEAD_TAG_LEN;

// ═══════════════════════════════════════════════════════════════
// Handshake State Machine
// ═══════════════════════════════════════════════════════════════

/// Handshake progression states.
///
/// The state machine enforces correct message ordering:
/// `Init -> Handshake1 -> Handshake2 -> Transport`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoiseHandshakeState {
    /// Initial state — handshake not yet started.
    Init,
    /// Initiator has sent message 1 (-> e, es). Awaiting message 2.
    Handshake1,
    /// Responder has sent message 2 (<- e, ee). Awaiting message 3.
    Handshake2,
    /// Handshake complete — transport-mode encryption active.
    Transport,
    /// Error — handshake failed, channel must be discarded.
    Error,
}

impl fmt::Display for NoiseHandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Init => write!(f, "INIT"),
            Self::Handshake1 => write!(f, "HANDSHAKE_1"),
            Self::Handshake2 => write!(f, "HANDSHAKE_2"),
            Self::Transport => write!(f, "TRANSPORT"),
            Self::Error => write!(f, "ERROR"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Noise Transport Security State
// ═══════════════════════════════════════════════════════════════

/// Noise_XK transport security state.
///
/// Encapsulates all cryptographic state for a single peer connection.
/// One instance per peer, created during connection setup.
///
/// ## Security Properties
///
/// - **Mutual authentication**: Both peers prove possession of their static keys.
/// - **Forward secrecy**: Ephemeral keys are used for each session;
///   compromising long-term keys does not reveal past session data.
/// - **Replay protection**: Monotonic nonce counters prevent message replay.
/// - **Transcript binding**: The handshake hash (h) is used as AAD for
///   transport messages, binding them to the specific handshake.
pub struct NoiseState {
    /// Current handshake state.
    pub handshake_state: NoiseHandshakeState,

    /// Whether we initiated the connection.
    is_initiator: bool,

    // ── Static identity keys (long-term) ──────────────────────────
    /// Our static X25519 secret key.
    local_static_sk: [u8; DH_LEN],
    /// Our static X25519 public key.
    local_static_pk: [u8; DH_LEN],
    /// Remote peer's static X25519 public key (known via Nostr/out-of-band).
    remote_static_pk: [u8; DH_LEN],

    // ── Ephemeral keys (per-handshake) ────────────────────────────
    /// Our ephemeral X25519 secret key (generated per handshake).
    local_eph_sk: [u8; DH_LEN],
    /// Our ephemeral X25519 public key.
    local_eph_pk: [u8; DH_LEN],
    /// Remote peer's ephemeral X25519 public key.
    remote_eph_pk: [u8; DH_LEN],

    // ── Chaining key and handshake hash ───────────────────────────
    /// Chaining key — evolves with each DH via HKDF.
    ck: [u8; HASH_LEN],
    /// Handshake hash — transcript binding.
    h: [u8; HASH_LEN],

    // ── Transport keys (derived after handshake) ──────────────────
    /// Send encryption key (ChaCha20-Poly1305).
    send_key: [u8; DH_LEN],
    /// Receive decryption key (ChaCha20-Poly1305).
    recv_key: [u8; DH_LEN],
    /// Send nonce counter (monotonic, never reuse).
    send_nonce: u64,
    /// Receive nonce counter (monotonic, anti-replay).
    recv_nonce: u64,
}

impl Drop for NoiseState {
    /// Securely wipe all key material on drop.
    ///
    /// Use `black_box` to prevent the compiler from optimizing
    /// away these writes. Without the barrier, the compiler may elide the zeroing
    /// because the values are never read after drop.
    fn drop(&mut self) {
        self.local_static_sk = [0u8; DH_LEN];
        self.local_eph_sk = [0u8; DH_LEN];
        self.send_key = [0u8; DH_LEN];
        self.recv_key = [0u8; DH_LEN];
        self.ck = [0u8; HASH_LEN];
        self.h = [0u8; HASH_LEN];
        // Compiler barrier: force the zeroing writes to be observable.
        core::hint::black_box(&self.local_static_sk);
        core::hint::black_box(&self.local_eph_sk);
        core::hint::black_box(&self.send_key);
        core::hint::black_box(&self.recv_key);
        core::hint::black_box(&self.ck);
        core::hint::black_box(&self.h);
    }
}

impl NoiseState {
    /// Create a new Noise_XK state.
    ///
    /// # Arguments
    ///
    /// * `local_static_sk` - Our long-term X25519 secret key (32 bytes).
    /// * `local_static_pk` - Our long-term X25519 public key (32 bytes).
    /// * `remote_static_pk` - Peer's static key, known in advance via Nostr.
    /// * `is_initiator` - `true` if we are initiating the connection.
    pub fn new(
        local_static_sk: [u8; DH_LEN],
        local_static_pk: [u8; DH_LEN],
        remote_static_pk: [u8; DH_LEN],
        is_initiator: bool,
    ) -> Self {
        // h = SHA-256(protocol_name)
        let h = sha256(NOISE_PROTOCOL_NAME);

        // ck = h
        let ck = h;

        // In the XK pattern, the responder's static key is pre-shared.
        // Both sides must mix in the RESPONDER's static key — the key
        // of the side that is NOT the initiator.
        let responder_static_pk = if is_initiator {
            remote_static_pk // initiator: remote is the responder
        } else {
            local_static_pk // responder: we are the responder
        };
        let h = sha256_two(&h, &responder_static_pk);

        Self {
            handshake_state: NoiseHandshakeState::Init,
            is_initiator,
            local_static_sk,
            local_static_pk,
            remote_static_pk,
            local_eph_sk: [0u8; DH_LEN],
            local_eph_pk: [0u8; DH_LEN],
            remote_eph_pk: [0u8; DH_LEN],
            ck,
            h,
            send_key: [0u8; DH_LEN],
            recv_key: [0u8; DH_LEN],
            send_nonce: 0,
            recv_nonce: 0,
        }
    }

    /// Initiator — generate handshake message 1 (-> e, es).
    ///
    /// Generates an ephemeral X25519 keypair, performs DH(e, rs),
    /// and returns the ephemeral public key as message 1.
    ///
    /// State: `Init` -> `Handshake1`
    pub fn handshake_initiate(&mut self) -> Result<Vec<u8>, NetworkError> {
        if self.handshake_state != NoiseHandshakeState::Init || !self.is_initiator {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: handshake_initiate requires Init state and initiator role".into(),
            });
        }

        // Generate ephemeral X25519 keypair
        let (eph_sk, eph_pk) = generate_x25519_keypair();
        self.local_eph_sk = eph_sk;
        self.local_eph_pk = eph_pk;

        // -> e: mix ephemeral into h
        self.mix_hash(&eph_pk);

        // es: DH(local_eph, remote_static)
        self.dh_and_mix(&self.local_eph_sk.clone(), &self.remote_static_pk.clone())?;

        self.handshake_state = NoiseHandshakeState::Handshake1;
        Ok(eph_pk.to_vec())
    }

    /// Responder — process message 1, generate message 2 (<- e, ee).
    ///
    /// State: `Init` -> `Handshake2`
    pub fn handshake_respond(&mut self, msg1: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if self.handshake_state != NoiseHandshakeState::Init || self.is_initiator {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: handshake_respond requires Init state and responder role".into(),
            });
        }
        if msg1.len() != DH_LEN {
            return Err(NetworkError::InvalidMessage {
                reason: format!("M-03: message 1 must be {} bytes", DH_LEN),
            });
        }

        // Store initiator's ephemeral
        self.remote_eph_pk.copy_from_slice(msg1);

        // Mix initiator's ephemeral into h
        self.mix_hash(msg1);

        // es: DH(local_static, remote_eph) — same DH from the other side
        self.dh_and_mix(&self.local_static_sk.clone(), &self.remote_eph_pk.clone())?;

        // Generate our ephemeral keypair
        let (eph_sk, eph_pk) = generate_x25519_keypair();
        self.local_eph_sk = eph_sk;
        self.local_eph_pk = eph_pk;

        // <- e: mix our ephemeral into h
        self.mix_hash(&eph_pk);

        // ee: DH(local_eph, remote_eph)
        self.dh_and_mix(&self.local_eph_sk.clone(), &self.remote_eph_pk.clone())?;

        self.handshake_state = NoiseHandshakeState::Handshake2;
        Ok(eph_pk.to_vec())
    }

    /// Initiator — process message 2, generate message 3 (-> s, se).
    ///
    /// After this call, transport keys are derived and the channel is ready.
    ///
    /// State: `Handshake1` -> `Transport`
    pub fn handshake_finalize(&mut self, msg2: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if self.handshake_state != NoiseHandshakeState::Handshake1 || !self.is_initiator {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: handshake_finalize requires Handshake1 state and initiator role"
                    .into(),
            });
        }
        if msg2.len() != DH_LEN {
            return Err(NetworkError::InvalidMessage {
                reason: format!("M-03: message 2 must be {} bytes", DH_LEN),
            });
        }

        // Store responder's ephemeral
        self.remote_eph_pk.copy_from_slice(msg2);
        self.mix_hash(msg2);

        // ee: DH(local_eph, remote_eph)
        self.dh_and_mix(&self.local_eph_sk.clone(), &self.remote_eph_pk.clone())?;

        // -> s: Send our static key AEAD-encrypted under the current cipher state.
        // The static key is encrypted with a temporary key derived from the
        // chaining key, preventing it from being sent as plaintext.
        let temp_key = hmac_sha256(&self.ck, &[0x03]);
        let nonce = [0u8; 12]; // zero nonce is fine: temp_key is single-use
        let encrypted_s =
            chacha20poly1305_encrypt(&temp_key, &nonce, &self.h, &self.local_static_pk)?;
        self.mix_hash(&encrypted_s);
        let msg3 = encrypted_s;

        // se: DH(local_static, remote_eph)
        self.dh_and_mix(&self.local_static_sk.clone(), &self.remote_eph_pk.clone())?;

        // Derive transport keys
        self.derive_transport_keys(true)?;

        // Wipe ephemeral secret
        self.local_eph_sk = [0u8; DH_LEN];

        self.handshake_state = NoiseHandshakeState::Transport;
        Ok(msg3)
    }

    /// Responder — process message 3 and complete handshake.
    ///
    /// State: `Handshake2` -> `Transport`
    pub fn handshake_complete(&mut self, msg3: &[u8]) -> Result<(), NetworkError> {
        if self.handshake_state != NoiseHandshakeState::Handshake2 || self.is_initiator {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: handshake_complete requires Handshake2 state and responder role"
                    .into(),
            });
        }
        // Message 3 is AEAD-encrypted (32-byte key + 16-byte tag).
        if msg3.len() != DH_LEN + AEAD_TAG_LEN {
            return Err(NetworkError::InvalidMessage {
                reason: format!("M-03: message 3 must be {} bytes", DH_LEN + AEAD_TAG_LEN),
            });
        }

        // Decrypt the initiator's static key from message 3.
        let temp_key = hmac_sha256(&self.ck, &[0x03]);
        let nonce = [0u8; 12];
        let remote_static = chacha20poly1305_decrypt(&temp_key, &nonce, &self.h, msg3)?;
        self.remote_static_pk.copy_from_slice(&remote_static);
        // Mix the encrypted form into h (must match what initiator mixed)
        self.mix_hash(msg3);

        // se: DH(local_eph, remote_static) — from the other side
        self.dh_and_mix(&self.local_eph_sk.clone(), &self.remote_static_pk.clone())?;

        // Derive transport keys (reversed for responder)
        self.derive_transport_keys(false)?;

        // Wipe ephemeral secret
        self.local_eph_sk = [0u8; DH_LEN];

        self.handshake_state = NoiseHandshakeState::Transport;
        Ok(())
    }

    /// Encrypt a transport message with ChaCha20-Poly1305.
    ///
    /// Uses monotonic nonce counter to prevent replay. The handshake hash
    /// is bound as AAD so messages cannot be replayed across sessions.
    pub fn encrypt_message(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if self.handshake_state != NoiseHandshakeState::Transport {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: encrypt requires Transport state".into(),
            });
        }
        if plaintext.len() > MAX_TRANSPORT_PAYLOAD {
            return Err(NetworkError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_TRANSPORT_PAYLOAD,
            });
        }
        if self.send_nonce == u64::MAX {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: nonce exhausted — must re-key".into(),
            });
        }

        // Construct 12-byte nonce: 4 zero bytes || 8-byte LE counter
        let nonce = self.make_nonce(self.send_nonce);

        // ChaCha20-Poly1305 encrypt with h as AAD
        let ciphertext = chacha20poly1305_encrypt(&self.send_key, &nonce, &self.h, plaintext)?;

        self.send_nonce += 1;
        Ok(ciphertext)
    }

    /// Decrypt a transport message with ChaCha20-Poly1305.
    ///
    /// Enforces monotonic nonce ordering for replay protection.
    pub fn decrypt_message(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NetworkError> {
        if self.handshake_state != NoiseHandshakeState::Transport {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: decrypt requires Transport state".into(),
            });
        }
        if ciphertext.len() <= AEAD_TAG_LEN {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: ciphertext too short".into(),
            });
        }
        if self.recv_nonce == u64::MAX {
            return Err(NetworkError::InvalidMessage {
                reason: "M-03: nonce exhausted — must re-key".into(),
            });
        }

        let nonce = self.make_nonce(self.recv_nonce);

        let plaintext = chacha20poly1305_decrypt(&self.recv_key, &nonce, &self.h, ciphertext)?;

        self.recv_nonce += 1;
        Ok(plaintext)
    }

    /// Check if transport-mode encryption is ready.
    pub fn is_transport_ready(&self) -> bool {
        self.handshake_state == NoiseHandshakeState::Transport
    }

    // ── Internal helpers ──────────────────────────────────────────

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = sha256_two(&self.h, data);
    }

    fn mix_key(&mut self, ikm: &[u8]) -> Result<(), NetworkError> {
        // HKDF-Extract: PRK = HMAC-SHA256(ck, ikm)
        let prk = hmac_sha256(&self.ck, ikm);
        // HKDF-Expand: new ck = HMAC-SHA256(PRK, 0x01)
        self.ck = hmac_sha256(&prk, &[0x01]);
        Ok(())
    }

    fn dh_and_mix(&mut self, sk: &[u8; DH_LEN], pk: &[u8; DH_LEN]) -> Result<(), NetworkError> {
        let shared = x25519(sk, pk)?;
        self.mix_key(&shared)?;
        Ok(())
    }

    fn derive_transport_keys(&mut self, is_initiator: bool) -> Result<(), NetworkError> {
        // Derive 64 bytes from ck for send + recv keys
        let k1 = hmac_sha256(&self.ck, &[0x01]);
        let k2 = hmac_sha256(&self.ck, &[0x02]);

        if is_initiator {
            self.send_key = k1;
            self.recv_key = k2;
        } else {
            self.recv_key = k1;
            self.send_key = k2;
        }

        self.send_nonce = 0;
        self.recv_nonce = 0;
        Ok(())
    }

    fn make_nonce(&self, counter: u64) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}

// ═══════════════════════════════════════════════════════════════
// Cryptographic Primitives (Thin Wrappers)
// ═══════════════════════════════════════════════════════════════
//
// These wrap the brrq-crypto crate's verified implementations.

/// SHA-256 hash of a single input.
fn sha256(data: &[u8]) -> [u8; HASH_LEN] {
    brrq_crypto::sha256::hash(data).0
}

/// SHA-256(a || b).
fn sha256_two(a: &[u8], b: &[u8]) -> [u8; HASH_LEN] {
    use brrq_crypto::hash::Hasher;
    let mut h = Hasher::new();
    h.update(a);
    h.update(b);
    h.finalize().0
}

/// HMAC-SHA256(key, data).
fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; HASH_LEN] {
    brrq_crypto::sha256::hmac_sha256(key, data).0
}

/// Generate an X25519 keypair using a CSPRNG (OsRng).
fn generate_x25519_keypair() -> ([u8; DH_LEN], [u8; DH_LEN]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    let sk: [u8; DH_LEN] = secret.to_bytes();
    let pk: [u8; DH_LEN] = public.to_bytes();
    (sk, pk)
}

/// X25519 Diffie-Hellman: shared_secret = sk * pk.
///
/// Rejects low-order points that produce an all-zero shared secret,
/// which would allow an attacker to force a known key state.
fn x25519(sk: &[u8; DH_LEN], pk: &[u8; DH_LEN]) -> Result<[u8; DH_LEN], NetworkError> {
    let secret = StaticSecret::from(*sk);
    let public = PublicKey::from(*pk);
    let shared = secret.diffie_hellman(&public);
    let bytes = shared.to_bytes();
    // Reject low-order points that produce all-zero shared secrets
    if bytes.iter().all(|&b| b == 0) {
        return Err(NetworkError::InvalidMessage {
            reason: "low-order point detected: X25519 shared secret is all zeros".into(),
        });
    }
    Ok(bytes)
}

/// ChaCha20-Poly1305 AEAD encrypt.
fn chacha20poly1305_encrypt(
    key: &[u8; DH_LEN],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let aead_nonce = AeadNonce::from_slice(nonce);
    cipher
        .encrypt(
            aead_nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| NetworkError::InvalidMessage {
            reason: "M-03: ChaCha20-Poly1305 encryption failed".into(),
        })
}

/// ChaCha20-Poly1305 AEAD decrypt.
fn chacha20poly1305_decrypt(
    key: &[u8; DH_LEN],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NetworkError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let aead_nonce = AeadNonce::from_slice(nonce);
    cipher
        .decrypt(
            aead_nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| NetworkError::InvalidMessage {
            reason: "M-03: AEAD authentication failed".into(),
        })
}

// SHA-256 primitives now delegate to brrq-crypto (sha2 crate backend).
// Custom Sha256State removed — ~120 LOC of unaudited crypto eliminated.

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create a test keypair (deterministic for testing).
    fn test_keypair(seed: u8) -> ([u8; DH_LEN], [u8; DH_LEN]) {
        let sk_bytes = [seed; DH_LEN];
        let secret = StaticSecret::from(sk_bytes);
        let public = PublicKey::from(&secret);
        (sk_bytes, public.to_bytes())
    }

    #[test]
    fn test_noise_handshake_state_machine() {
        // Verify state machine transitions
        let (init_sk, init_pk) = test_keypair(0x01);
        let (resp_sk, resp_pk) = test_keypair(0x02);

        let mut initiator = NoiseState::new(init_sk, init_pk, resp_pk, true);
        let mut responder = NoiseState::new(resp_sk, resp_pk, init_pk, false);

        assert_eq!(initiator.handshake_state, NoiseHandshakeState::Init);
        assert_eq!(responder.handshake_state, NoiseHandshakeState::Init);

        // Message 1: Initiator -> Responder
        let msg1 = initiator.handshake_initiate().unwrap();
        assert_eq!(initiator.handshake_state, NoiseHandshakeState::Handshake1);

        // Message 2: Responder -> Initiator
        let msg2 = responder.handshake_respond(&msg1).unwrap();
        assert_eq!(responder.handshake_state, NoiseHandshakeState::Handshake2);

        // Message 3: Initiator -> Responder
        let msg3 = initiator.handshake_finalize(&msg2).unwrap();
        assert_eq!(initiator.handshake_state, NoiseHandshakeState::Transport);

        // Complete: Responder processes message 3
        responder.handshake_complete(&msg3).unwrap();
        assert_eq!(responder.handshake_state, NoiseHandshakeState::Transport);

        assert!(initiator.is_transport_ready());
        assert!(responder.is_transport_ready());
    }

    #[test]
    fn test_noise_transport_encrypt_decrypt_cross_party() {
        // Test full cross-party encrypt/decrypt round-trips.
        let (init_sk, init_pk) = test_keypair(0x11);
        let (resp_sk, resp_pk) = test_keypair(0x22);

        let mut initiator = NoiseState::new(init_sk, init_pk, resp_pk, true);
        let mut responder = NoiseState::new(resp_sk, resp_pk, init_pk, false);

        // Complete handshake
        let msg1 = initiator.handshake_initiate().unwrap();
        let msg2 = responder.handshake_respond(&msg1).unwrap();
        let msg3 = initiator.handshake_finalize(&msg2).unwrap();
        responder.handshake_complete(&msg3).unwrap();

        assert!(initiator.is_transport_ready());
        assert!(responder.is_transport_ready());

        // Initiator encrypts, responder decrypts
        let plaintext = b"Hello from initiator via Noise_XK";
        let ciphertext = initiator.encrypt_message(plaintext).unwrap();
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + AEAD_TAG_LEN,
            "ciphertext should include AEAD tag overhead"
        );
        let decrypted = responder.decrypt_message(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Responder encrypts, initiator decrypts
        let plaintext2 = b"Hello from responder";
        let ct2 = responder.encrypt_message(plaintext2).unwrap();
        let decrypted2 = initiator.decrypt_message(&ct2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_noise_wrong_state_rejected() {
        // Verify state machine enforcement
        let (sk, pk) = test_keypair(0x33);
        let (_, rpk) = test_keypair(0x44);

        let mut state = NoiseState::new(sk, pk, rpk, true);

        // Cannot respond as initiator
        assert!(state.handshake_respond(&[0u8; DH_LEN]).is_err());

        // Cannot finalize before handshake_initiate
        assert!(state.handshake_finalize(&[0u8; DH_LEN]).is_err());

        // Cannot encrypt before transport
        assert!(state.encrypt_message(b"test").is_err());
    }

    #[test]
    fn test_noise_nonce_monotonic() {
        // Verify nonce counter increments
        let (init_sk, init_pk) = test_keypair(0x55);
        let (resp_sk, resp_pk) = test_keypair(0x66);

        let mut initiator = NoiseState::new(init_sk, init_pk, resp_pk, true);
        let mut responder = NoiseState::new(resp_sk, resp_pk, init_pk, false);

        let msg1 = initiator.handshake_initiate().unwrap();
        let msg2 = responder.handshake_respond(&msg1).unwrap();
        let msg3 = initiator.handshake_finalize(&msg2).unwrap();
        responder.handshake_complete(&msg3).unwrap();

        assert_eq!(initiator.send_nonce, 0);
        initiator.encrypt_message(b"msg1").unwrap();
        assert_eq!(initiator.send_nonce, 1);
        initiator.encrypt_message(b"msg2").unwrap();
        assert_eq!(initiator.send_nonce, 2);
    }

    #[test]
    fn test_noise_tampered_message_rejected() {
        // Verify ChaCha20-Poly1305 AEAD detects tampering.
        let (init_sk, init_pk) = test_keypair(0x77);
        let (resp_sk, resp_pk) = test_keypair(0x88);

        let mut initiator = NoiseState::new(init_sk, init_pk, resp_pk, true);
        let mut responder = NoiseState::new(resp_sk, resp_pk, init_pk, false);

        // Complete handshake
        let msg1 = initiator.handshake_initiate().unwrap();
        let msg2 = responder.handshake_respond(&msg1).unwrap();
        let msg3 = initiator.handshake_finalize(&msg2).unwrap();
        responder.handshake_complete(&msg3).unwrap();

        // Encrypt a message
        let ciphertext = initiator.encrypt_message(b"secret data").unwrap();

        // Tamper with ciphertext — should be detected by AEAD tag
        let mut tampered = ciphertext.clone();
        if !tampered.is_empty() {
            tampered[0] ^= 0xFF;
        }
        assert!(
            responder.decrypt_message(&tampered).is_err(),
            "M-03: tampered ciphertext should be rejected"
        );

        // Untampered should decrypt successfully
        let decrypted = responder.decrypt_message(&ciphertext).unwrap();
        assert_eq!(decrypted, b"secret data");
    }
}
