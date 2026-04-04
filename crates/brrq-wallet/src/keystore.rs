//! Keystore — persistent wallet key storage with encryption.
//!
//! Stores keypair information in JSON files with encrypted secret keys.
//! Uses SHA-256 CTR mode with HMAC-SHA256 authentication (same crypto
//! primitives as the rest of Brrq's Hash-First Architecture).
//!
//! ## Encryption
//!
//! - **Key derivation**: `tagged_hash("BRRQ_KEYSTORE_KDF", password ∥ salt)`
//! - **Encryption**: SHA-256 CTR mode (via `brrq_crypto::encryption::seal`)
//! - **Authentication**: HMAC-SHA256 Encrypt-then-MAC
//!
//! ## File Format
//!
//! ```json
//! {
//!     "address": "0x...",
//!     "public_key": "0x...",
//!     "secret_key_encrypted": "0x...",  // hex(salt ∥ nonce ∥ ciphertext ∥ tag)
//!     "encrypted": true
//! }
//! ```

use brrq_crypto::encryption::{EpochKey, SealedData};
use brrq_crypto::hash::Hash256;
use brrq_crypto::sha256::tagged_hash;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Salt length for key derivation (16 bytes).
const SALT_LEN: usize = 16;

/// Nonce length for encryption (16 bytes).
const NONCE_LEN: usize = 16;

// By default, saving a key without a password emits a loud warning to
// stderr.  Set the environment variable `BRRQ_ALLOW_UNENCRYPTED_KEYS=true`
// to silence the warning (e.g. in CI / test harnesses).
/// Whether to warn when keys are stored without encryption.
const WARN_UNENCRYPTED: bool = true;

/// Name of the environment variable that explicitly permits unencrypted key
/// storage, suppressing the runtime warning.
const ENV_ALLOW_UNENCRYPTED: &str = "BRRQ_ALLOW_UNENCRYPTED_KEYS";

/// Persistent key file format.
#[derive(Debug, Serialize, Deserialize)]
pub struct KeyFile {
    /// Brrq address (hex with 0x prefix).
    pub address: String,
    /// Public key (hex with 0x prefix).
    pub public_key: String,
    /// Secret key (encrypted: hex-encoded salt ∥ nonce ∥ ciphertext ∥ tag).
    pub secret_key_encrypted: String,
    /// Whether the secret key is actually encrypted.
    #[serde(default)]
    pub encrypted: bool,
    /// KDF version: 1 = iterated HMAC-SHA256 (legacy), 2 = balloon-hash + HMAC-SHA256.
    /// Defaults to 1 for backward compatibility with existing keystores.
    #[serde(default = "default_kdf_version")]
    pub kdf_version: u8,
}

fn default_kdf_version() -> u8 {
    1
}

/// Number of PBKDF2-style iterations for password stretching.
const KDF_ITERATIONS: u32 = 100_000;

/// Number of 32-byte blocks for balloon-hash memory expansion (32 KB).
const BALLOON_BLOCKS: usize = 1024;

/// Current KDF version for newly created keystores.
const CURRENT_KDF_VERSION: u8 = 2;

/// Build the length-prefixed password||salt data buffer (shared by both KDF versions).
fn build_kdf_data(password: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + password.len() + salt.len());
    data.extend_from_slice(&(password.len() as u32).to_le_bytes());
    data.extend_from_slice(password);
    data.extend_from_slice(salt);
    data
}

/// Derive an encryption key from a password and salt (version 1: legacy).
///
/// Uses iterated HMAC-SHA256 (PBKDF2-style) for key stretching.
fn derive_key_v1(password: &[u8], salt: &[u8]) -> EpochKey {
    let data = build_kdf_data(password, salt);
    let mut key = tagged_hash("BRRQ_KEYSTORE_KDF", &data);
    for _ in 0..KDF_ITERATIONS {
        key = brrq_crypto::sha256::hmac_sha256(key.as_bytes(), &data);
    }
    EpochKey::from_bytes(*key.as_bytes())
}

/// Derive an encryption key from a password and salt (version 2: memory-hard).
///
/// Uses balloon-hashing with SHA-256 (32 KB memory) followed by iterated
/// HMAC-SHA256. This resists GPU/ASIC attacks by requiring sequential
/// memory access patterns that cannot be parallelized.
///
/// Hash-First Architecture compliant: uses only SHA-256 primitives.
fn derive_key_v2(password: &[u8], salt: &[u8]) -> EpochKey {
    let data = build_kdf_data(password, salt);
    let initial = tagged_hash("BRRQ_KEYSTORE_KDF_V2", &data);

    // Phase 1: Balloon expansion — fill 1024 blocks (32 KB) with hash chain.
    let mut buf = vec![[0u8; 32]; BALLOON_BLOCKS];
    buf[0] = *initial.as_bytes();
    for i in 1..BALLOON_BLOCKS {
        let mut hasher = brrq_crypto::hash::Hasher::new();
        hasher.update(&buf[i - 1]);
        hasher.update(&(i as u32).to_le_bytes());
        let h = hasher.finalize();
        buf[i] = *h.as_bytes();
    }

    // Phase 2: Balloon mixing — forward references resist time-memory tradeoffs.
    for i in 0..BALLOON_BLOCKS {
        let prev = if i == 0 { BALLOON_BLOCKS - 1 } else { i - 1 };
        let ref_idx = u32::from_le_bytes([buf[i][0], buf[i][1], buf[i][2], buf[i][3]]) as usize
            % BALLOON_BLOCKS;
        let mut hasher = brrq_crypto::hash::Hasher::new();
        hasher.update(&buf[prev]);
        hasher.update(&buf[ref_idx]);
        hasher.update(&(i as u32).to_le_bytes());
        let h = hasher.finalize();
        buf[i] = *h.as_bytes();
    }

    // Phase 3: Final HMAC chain on the last block.
    let mut key = Hash256::from_bytes(buf[BALLOON_BLOCKS - 1]);
    for _ in 0..KDF_ITERATIONS {
        key = brrq_crypto::sha256::hmac_sha256(key.as_bytes(), &data);
    }

    // Zeroize the balloon buffer — key material must not linger.
    for block in buf.iter_mut() {
        zeroize::Zeroize::zeroize(block.as_mut_slice());
    }

    EpochKey::from_bytes(*key.as_bytes())
}

/// Derive a key using the specified KDF version.
///
/// Returns an error for unknown KDF versions.
fn derive_key(password: &[u8], salt: &[u8], kdf_version: u8) -> Result<EpochKey, String> {
    match kdf_version {
        1 => Ok(derive_key_v1(password, salt)),
        2 => Ok(derive_key_v2(password, salt)),
        v => Err(format!("unsupported KDF version: {v} (supported: 1, 2)")),
    }
}

/// Generate a cryptographically random salt using OS entropy.
fn generate_salt(_secret: &[u8; 32]) -> [u8; SALT_LEN] {
    brrq_crypto::encryption::generate_nonce()
}

/// Return the current OS username (Windows only, used for ACL grants).
#[cfg(windows)]
fn whoami() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "CURRENT_USER".to_string())
}

/// Save a key file to disk with mandatory password encryption.
///
/// The password MUST be non-empty. Encryption uses balloon-hash KDF v2
/// with SHA-256 CTR + HMAC-SHA256 (Encrypt-then-MAC).
///
/// To store keys without encryption (NOT recommended), use
/// [`save_keyfile_plaintext`] which requires both an explicit opt-in flag
/// and the `BRRQ_ALLOW_UNENCRYPTED_KEYS` environment variable.
pub fn save_keyfile(
    path: &str,
    secret: &[u8; 32],
    address: &str,
    public_key: &str,
    password: &[u8],
) -> Result<(), String> {
    if password.is_empty() {
        return Err(
            "password must not be empty — encryption is mandatory. \
             Use save_keyfile_plaintext() with --plaintext flag for \
             unencrypted storage (deprecated, will be removed)."
                .to_string(),
        );
    }

    let (encrypted_hex, is_encrypted, kdf_ver) = {
        // Encrypt with SHA-256 CTR + HMAC using memory-hard KDF v2.
        let salt = generate_salt(secret);
        let key = derive_key(password, &salt, CURRENT_KDF_VERSION)
            .map_err(|e| format!("KDF error: {e}"))?;
        let nonce: [u8; NONCE_LEN] = brrq_crypto::encryption::generate_nonce();
        let sealed = brrq_crypto::encryption::seal(&key, &nonce, secret);

        // Pack: salt (16) ∥ nonce (16) ∥ ciphertext (32) ∥ tag (32) = 96 bytes
        let mut packed = Vec::with_capacity(SALT_LEN + NONCE_LEN + sealed.ciphertext.len() + 32);
        packed.extend_from_slice(&salt);
        packed.extend_from_slice(&nonce);
        packed.extend_from_slice(&sealed.ciphertext);
        packed.extend_from_slice(sealed.tag.as_bytes());
        (
            format!("0x{}", hex::encode(&packed)),
            true,
            CURRENT_KDF_VERSION,
        )
    };

    let keyfile = KeyFile {
        address: address.to_string(),
        public_key: public_key.to_string(),
        secret_key_encrypted: encrypted_hex,
        encrypted: is_encrypted,
        kdf_version: kdf_ver,
    };

    let json = serde_json::to_string_pretty(&keyfile)
        .map_err(|e| format!("failed to serialize keyfile: {e}"))?;

    // Write the keyfile with restricted permissions (0600 on Unix) to
    // prevent other users on the system from reading private key material.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("failed to create keyfile {path}: {e}"))?;
        use std::io::Write;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("failed to write keyfile {path}: {e}"))?;
    }
    // Windows lacks POSIX mode bits.  We use the platform ACL APIs to
    // remove inherited ACEs and grant access only to the current user.
    // If the ACL call fails we still proceed but emit a clear warning so
    // the operator is aware the keyfile may be world-readable.
    #[cfg(windows)]
    {
        std::fs::write(path, &json)
            .map_err(|e| format!("failed to write keyfile to {path}: {e}"))?;

        // Try to restrict the file to the current user via icacls.
        // This is a best-effort mitigation — production deployments
        // should verify file ACLs independently.
        let restrict_result = std::process::Command::new("icacls")
            .args([
                path,
                "/inheritance:r",
                "/grant:r",
                &format!("{}:F", whoami()),
            ])
            .output();

        match restrict_result {
            Ok(output) if output.status.success() => { /* ACL locked down */ }
            Ok(output) => {
                eprintln!(
                    "WARNING [brrq-wallet/keystore]: failed to restrict permissions \
                     on \"{}\": {}  — the keyfile may be readable by other users.",
                    path,
                    String::from_utf8_lossy(&output.stderr).trim(),
                );
            }
            Err(e) => {
                eprintln!(
                    "WARNING [brrq-wallet/keystore]: could not run icacls to \
                     restrict permissions on \"{}\": {e}  — the keyfile may be \
                     readable by other users.",
                    path,
                );
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::write(path, json)
            .map_err(|e| format!("failed to write keyfile to {path}: {e}"))?;
        // No permission restriction available on this platform.
        eprintln!(
            "WARNING [brrq-wallet/keystore]: file permissions for \"{}\" could \
             not be restricted on this platform — verify manually.",
            path,
        );
    }

    Ok(())
}

/// **DEPRECATED** — Save a key file WITHOUT encryption (plaintext).
///
/// This function exists solely for backward compatibility and CI/test use.
/// It will be **removed in a future release**. All production key storage
/// should use [`save_keyfile`] with a non-empty password.
///
/// # Requirements
///
/// Both conditions must be met or the call returns an error:
/// 1. The caller must pass `plaintext_flag = true` (maps to `--plaintext` CLI flag).
/// 2. The environment variable `BRRQ_ALLOW_UNENCRYPTED_KEYS` must be set to `"true"` or `"1"`.
pub fn save_keyfile_plaintext(
    path: &str,
    secret: &[u8; 32],
    address: &str,
    public_key: &str,
    plaintext_flag: bool,
) -> Result<(), String> {
    if !plaintext_flag {
        return Err(
            "plaintext storage requires the --plaintext flag. \
             Encryption is mandatory by default."
                .to_string(),
        );
    }

    let allowed = std::env::var(ENV_ALLOW_UNENCRYPTED)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    if !allowed {
        return Err(format!(
            "plaintext storage requires {ENV_ALLOW_UNENCRYPTED}=true in the environment. \
             This is a safety measure — storing private keys unencrypted is dangerous."
        ));
    }

    eprintln!(
        "\x1b[1;33mWARNING [brrq-wallet/keystore]: saving key to \"{}\" WITHOUT encryption.\x1b[0m",
        path,
    );
    eprintln!(
        "\x1b[1;33m  Plaintext key storage is DEPRECATED and will be removed in a future release.\x1b[0m"
    );
    eprintln!(
        "\x1b[1;33m  Use a password to encrypt your keyfile instead.\x1b[0m"
    );

    let encrypted_hex = format!("0x{}", hex::encode(secret));
    let keyfile = KeyFile {
        address: address.to_string(),
        public_key: public_key.to_string(),
        secret_key_encrypted: encrypted_hex,
        encrypted: false,
        kdf_version: 1,
    };

    let json = serde_json::to_string_pretty(&keyfile)
        .map_err(|e| format!("failed to serialize keyfile: {e}"))?;

    // Write with restricted permissions (same logic as save_keyfile).
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("failed to create keyfile {path}: {e}"))?;
        use std::io::Write;
        file.write_all(json.as_bytes())
            .map_err(|e| format!("failed to write keyfile {path}: {e}"))?;
    }
    #[cfg(windows)]
    {
        std::fs::write(path, &json)
            .map_err(|e| format!("failed to write keyfile to {path}: {e}"))?;
        let restrict_result = std::process::Command::new("icacls")
            .args([
                path,
                "/inheritance:r",
                "/grant:r",
                &format!("{}:F", whoami()),
            ])
            .output();
        match restrict_result {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                eprintln!(
                    "WARNING [brrq-wallet/keystore]: failed to restrict permissions \
                     on \"{}\": {}",
                    path,
                    String::from_utf8_lossy(&output.stderr).trim(),
                );
            }
            Err(e) => {
                eprintln!(
                    "WARNING [brrq-wallet/keystore]: could not run icacls on \"{}\": {e}",
                    path,
                );
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::write(path, json)
            .map_err(|e| format!("failed to write keyfile to {path}: {e}"))?;
        eprintln!(
            "WARNING [brrq-wallet/keystore]: file permissions for \"{}\" could \
             not be restricted on this platform.",
            path,
        );
    }

    Ok(())
}

/// Load a key file from disk.
pub fn load_keyfile(path: &str) -> Result<KeyFile, String> {
    if !Path::new(path).exists() {
        return Err(format!("keyfile not found: {path}"));
    }

    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("failed to read {path}: {e}"))?;

    serde_json::from_str::<KeyFile>(&contents)
        .map_err(|e| format!("failed to parse keyfile {path}: {e}"))
}

/// Extract the 32-byte secret key from a keyfile.
///
/// For encrypted keyfiles, the password is required.
/// For legacy unencrypted keyfiles, simply parses hex (but emits a
/// deprecation warning encouraging re-encryption).
pub fn extract_secret(
    keyfile: &KeyFile,
    password: &[u8],
) -> Result<[u8; 32], String> {
    if keyfile.encrypted && password.is_empty() {
        return Err(
            "this keyfile is encrypted — a password is required to unlock it.".to_string(),
        );
    }
    if !keyfile.encrypted {
        eprintln!(
            "\x1b[1;33mWARNING [brrq-wallet/keystore]: this keyfile is stored in PLAINTEXT.\x1b[0m"
        );
        eprintln!(
            "\x1b[1;33m  Re-encrypt it with: brrq-wallet import-key <secret> --output <path>\x1b[0m"
        );
    }
    extract_secret_inner(keyfile, password)
}

/// Inner extraction logic shared by public API.
fn extract_secret_inner(
    keyfile: &KeyFile,
    password: &[u8],
) -> Result<[u8; 32], String> {
    let hex_str = keyfile
        .secret_key_encrypted
        .strip_prefix("0x")
        .unwrap_or(&keyfile.secret_key_encrypted);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid secret hex: {e}"))?;

    if !keyfile.encrypted {
        // Legacy unencrypted format
        if bytes.len() != 32 {
            return Err(format!(
                "invalid secret key length: {} (expected 32)",
                bytes.len()
            ));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        return Ok(arr);
    }

    // Encrypted format: salt (16) ∥ nonce (16) ∥ ciphertext (32) ∥ tag (32) = 96 bytes
    let expected_len = SALT_LEN + NONCE_LEN + 32 + 32;
    if bytes.len() != expected_len {
        return Err(format!(
            "invalid encrypted data length: {} (expected {})",
            bytes.len(),
            expected_len
        ));
    }

    let salt = &bytes[..SALT_LEN];
    let nonce: [u8; NONCE_LEN] = bytes[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().unwrap();
    let ciphertext = &bytes[SALT_LEN + NONCE_LEN..SALT_LEN + NONCE_LEN + 32];
    let tag_bytes: [u8; 32] = bytes[SALT_LEN + NONCE_LEN + 32..].try_into().unwrap();

    let key = derive_key(password, salt, keyfile.kdf_version)
        .map_err(|e| format!("cannot decrypt keyfile: {e}"))?;
    let sealed = SealedData {
        ciphertext: ciphertext.to_vec(),
        tag: Hash256::from_bytes(tag_bytes),
    };

    let mut plaintext = brrq_crypto::encryption::open(&key, &nonce, &sealed)
        .map_err(|_| "decryption failed: wrong password or corrupted keyfile".to_string())?;

    if plaintext.len() != 32 {
        return Err(format!(
            "decrypted key has wrong length: {} (expected 32)",
            plaintext.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&plaintext);
    // Zeroize the plaintext buffer — keys must never linger in memory.
    plaintext.fill(0);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_save_and_load_keyfile_encrypted() {
        let dir = std::env::temp_dir();
        let path = dir.join("brrq_test_keyfile.json");
        let path_str = path.to_str().unwrap();

        let secret = [42u8; 32];
        let address = "0xaabbccdd00112233445566778899aabbccddeeff";
        let public_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let password = b"test-password-42";

        // Save (encrypted — now mandatory)
        save_keyfile(path_str, &secret, address, public_key, password).unwrap();

        // Load
        let loaded = load_keyfile(path_str).unwrap();
        assert_eq!(loaded.address, address);
        assert_eq!(loaded.public_key, public_key);
        assert!(loaded.encrypted);

        // Extract secret with password
        let extracted = extract_secret(&loaded, password).unwrap();
        assert_eq!(extracted, secret);

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_save_keyfile_rejects_empty_password() {
        let secret = [42u8; 32];
        let address = "0xaabbccdd00112233445566778899aabbccddeeff";
        let public_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";

        let result = save_keyfile("/tmp/brrq_test_reject.json", &secret, address, public_key, b"");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("password must not be empty"));
    }

    #[test]
    fn test_encrypted_keyfile_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("brrq_test_encrypted_keyfile.json");
        let path_str = path.to_str().unwrap();

        let secret = [0x42u8; 32];
        let address = "0xaabbccdd00112233445566778899aabbccddeeff";
        let public_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let password = b"strong-password-123";

        // Save with encryption
        save_keyfile(path_str, &secret, address, public_key, password).unwrap();

        // Load
        let loaded = load_keyfile(path_str).unwrap();
        assert!(loaded.encrypted);
        // Encrypted data should NOT contain the plaintext secret
        assert!(!loaded.secret_key_encrypted.contains(&hex::encode(secret)));

        // Extract with correct password
        let extracted = extract_secret(&loaded, password).unwrap();
        assert_eq!(extracted, secret);

        // Extract with wrong password should fail
        let result = extract_secret(&loaded, b"wrong-password");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("wrong password"));

        // Cleanup
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_load_nonexistent_keyfile() {
        let result = load_keyfile("/tmp/brrq_nonexistent_keyfile_xyz.json");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    #[test]
    fn test_extract_secret_invalid() {
        let keyfile = KeyFile {
            address: "0x00".into(),
            public_key: "0x00".into(),
            secret_key_encrypted: "0xaabb".into(), // Too short
            encrypted: false,
            kdf_version: 1,
        };
        let result = extract_secret(&keyfile, b"");
        assert!(result.is_err());
    }

    #[test]
    fn test_kdf_domain_separation_no_collision() {
        // password="abc", salt="def" must NOT produce the same key as
        // password="abcd", salt="ef" (domain separation test).
        let key1 = derive_key(b"abc", b"def", 1).unwrap();
        let key2 = derive_key(b"abcd", b"ef", 1).unwrap();
        assert_ne!(
            key1.as_bytes(),
            key2.as_bytes(),
            "KDF domain separation failed: different password/salt pairs produced identical keys"
        );
    }

    #[test]
    fn test_kdf_v2_domain_separation() {
        let key1 = derive_key(b"abc", b"def", 2).unwrap();
        let key2 = derive_key(b"abcd", b"ef", 2).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_kdf_v1_v2_produce_different_keys() {
        // KDF v1 and v2 must produce different keys for the same inputs
        // (ensuring upgrade isolation).
        let key1 = derive_key(b"password", b"salt1234salt1234", 1).unwrap();
        let key2 = derive_key(b"password", b"salt1234salt1234", 2).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_kdf_v2_encrypted_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("brrq_test_kdf_v2_roundtrip.json");
        let path_str = path.to_str().unwrap();

        let secret = [0x77u8; 32];
        let address = "0xaabbccdd00112233445566778899aabbccddeeff";
        let public_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let password = b"balloon-hash-test";

        save_keyfile(path_str, &secret, address, public_key, password).unwrap();
        let loaded = load_keyfile(path_str).unwrap();
        assert_eq!(loaded.kdf_version, CURRENT_KDF_VERSION);
        let extracted = extract_secret(&loaded, password).unwrap();
        assert_eq!(extracted, secret);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_encrypted_roundtrip_after_kdf_fix() {
        // Verify that encrypt -> decrypt roundtrip works correctly.
        let dir = std::env::temp_dir();
        let path = dir.join("brrq_test_kdf_fix_roundtrip.json");
        let path_str = path.to_str().unwrap();

        let secret = [0x99u8; 32];
        let address = "0xaabbccdd00112233445566778899aabbccddeeff";
        let public_key = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let password = b"test-password";

        save_keyfile(path_str, &secret, address, public_key, password).unwrap();
        let loaded = load_keyfile(path_str).unwrap();
        let extracted = extract_secret(&loaded, password).unwrap();
        assert_eq!(extracted, secret);

        let _ = std::fs::remove_file(&path);
    }
}
