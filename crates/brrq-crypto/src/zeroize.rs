//! Secure memory zeroing for secret key material.
//!
//! Uses `write_volatile` to prevent the compiler from optimizing away
//! the zeroing operation. This ensures secret keys don't linger in memory
//! after they're no longer needed.
//!
//! ## Usage
//!
//! Implement `Drop` for any type that holds secret key material:
//!
//! ```
//! use brrq_crypto::zeroize::zeroize_bytes;
//!
//! struct MySecretKey {
//!     secret: [u8; 32],
//! }
//!
//! impl Drop for MySecretKey {
//!     fn drop(&mut self) {
//!         zeroize_bytes(&mut self.secret);
//!     }
//! }
//!
//! let key = MySecretKey { secret: [0xAB; 32] };
//! drop(key); // secret is zeroed on drop
//! ```

/// Securely zero a byte slice using volatile writes.
///
/// The `write_volatile` operation is guaranteed not to be elided by
/// the compiler, unlike a normal memset which may be optimized away
/// if the buffer isn't read afterwards.
pub fn zeroize_bytes(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}
