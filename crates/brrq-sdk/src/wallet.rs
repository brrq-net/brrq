//! Wallet: key management and transaction signing.
//!
//! Supports three signing modes:
//! - **Schnorr** (default): fast, compact signatures for everyday transactions.
//! - **SLH-DSA**: hash-based post-quantum signatures for high-value vaults.
//! - **Dual**: both Schnorr + SLH-DSA (maximum security, larger tx size).

use brrq_crypto::schnorr::SchnorrKeyPair;
use brrq_crypto::slh_dsa::SlhDsaKeyPair;
use brrq_types::transaction::chain_id;
use brrq_types::{Address, PublicKey, Signature, Transaction, TransactionBody, TransactionKind};

use crate::error::SdkError;

/// Signing mode for the wallet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningMode {
    /// Schnorr only (64-byte sig, fast, default for everyday use).
    Schnorr,
    /// SLH-DSA only (hash-based, post-quantum, larger sig ~7KB).
    SlhDsa,
}

/// Key material held by the wallet.
enum WalletKeys {
    /// Schnorr-only wallet (most users).
    Schnorr(SchnorrKeyPair),
    /// SLH-DSA-only wallet (high-security vaults).
    SlhDsa(SlhDsaKeyPair),
    /// Dual-key wallet: Schnorr for speed, SLH-DSA for quantum resistance.
    /// The user chooses which to use per-transaction via `signing_mode`.
    Dual {
        schnorr: SchnorrKeyPair,
        slh_dsa: SlhDsaKeyPair,
    },
}

/// Wallet for managing keys and signing transactions.
///
/// Supports Schnorr, SLH-DSA, or dual-key operation. The signing mode
/// determines which key is used for `build_and_sign`.
pub struct Wallet {
    keys: WalletKeys,
    /// Which signature scheme to use when signing.
    signing_mode: SigningMode,
    /// Wallet address (derived from the primary key).
    address: Address,
    /// Current nonce (for building transactions).
    nonce: u64,
    /// Highest nonce ever signed by this wallet.
    /// Acts as a software watchdog independent of hardware TEE.
    /// If `nonce` ever goes below `high_watermark`, the wallet locks.
    nonce_high_watermark: u64,
    /// Whether the wallet is in fatal lockdown (hardware fault detected).
    locked: bool,
    /// Chain ID for replay protection.
    chain_id: u64,
}

impl Wallet {
    // ── Constructors ──────────────────────────────────────────────────

    /// Create a new Schnorr-only wallet (defaults to TESTNET).
    ///
    /// **Test convenience**. Production code should use
    /// [`new_for_chain`](Self::new_for_chain).
    pub fn new() -> Self {
        Self::new_for_chain(chain_id::TESTNET)
    }

    /// Create a new Schnorr-only wallet for the given chain.
    pub fn new_for_chain(chain_id: u64) -> Self {
        let keys = SchnorrKeyPair::generate();
        let address = Address::from_public_key(keys.public_key().as_bytes());
        Self {
            keys: WalletKeys::Schnorr(keys),
            signing_mode: SigningMode::Schnorr,
            address,
            nonce: 0,
            nonce_high_watermark: 0,
            locked: false,
            chain_id,
        }
    }

    /// Create a new SLH-DSA-only wallet (post-quantum vault).
    pub fn new_slh_dsa(chain_id: u64) -> Result<Self, SdkError> {
        let keys = SlhDsaKeyPair::generate().map_err(|e| SdkError::KeyGenerationFailed {
            reason: format!("SLH-DSA keygen: {e}"),
        })?;
        let address = Address::from_public_key(keys.public_key().as_bytes());
        Ok(Self {
            keys: WalletKeys::SlhDsa(keys),
            signing_mode: SigningMode::SlhDsa,
            address,
            nonce: 0,
            nonce_high_watermark: 0,
            locked: false,
            chain_id,
        })
    }

    /// Create a dual-key wallet (Schnorr + SLH-DSA).
    ///
    /// Address is derived from Schnorr key (for compatibility).
    /// Use `set_signing_mode` to switch between Schnorr and SLH-DSA per-tx.
    pub fn new_dual(chain_id: u64) -> Result<Self, SdkError> {
        let schnorr = SchnorrKeyPair::generate();
        let slh_dsa = SlhDsaKeyPair::generate().map_err(|e| SdkError::KeyGenerationFailed {
            reason: format!("SLH-DSA keygen: {e}"),
        })?;
        let address = Address::from_public_key(schnorr.public_key().as_bytes());
        Ok(Self {
            keys: WalletKeys::Dual { schnorr, slh_dsa },
            signing_mode: SigningMode::Schnorr, // Default to Schnorr for speed
            address,
            nonce: 0,
            nonce_high_watermark: 0,
            locked: false,
            chain_id,
        })
    }

    /// Create from an existing Schnorr secret key (defaults to TESTNET).
    pub fn from_secret(secret: &[u8; 32]) -> Result<Self, SdkError> {
        Self::from_secret_for_chain(secret, chain_id::TESTNET)
    }

    /// Create from an existing Schnorr secret key for the given chain.
    pub fn from_secret_for_chain(secret: &[u8; 32], chain_id: u64) -> Result<Self, SdkError> {
        let keys = SchnorrKeyPair::from_secret_bytes(secret).map_err(|e| {
            SdkError::KeyGenerationFailed {
                reason: format!("{e}"),
            }
        })?;
        let address = Address::from_public_key(keys.public_key().as_bytes());
        Ok(Self {
            keys: WalletKeys::Schnorr(keys),
            signing_mode: SigningMode::Schnorr,
            address,
            nonce: 0,
            nonce_high_watermark: 0,
            locked: false,
            chain_id,
        })
    }

    // ── Accessors ─────────────────────────────────────────────────────

    /// Set the chain ID (for mainnet/testnet selection).
    pub fn set_chain_id(&mut self, id: u64) {
        self.chain_id = id;
    }

    /// Set the signing mode (Schnorr or SLH-DSA).
    ///
    /// For Schnorr-only wallets, setting SLH-DSA mode returns an error.
    /// For SLH-DSA-only wallets, setting Schnorr mode returns an error.
    /// Dual wallets accept either mode.
    pub fn set_signing_mode(&mut self, mode: SigningMode) -> Result<(), SdkError> {
        match (&self.keys, mode) {
            (WalletKeys::Schnorr(_), SigningMode::SlhDsa) => {
                return Err(SdkError::KeyGenerationFailed {
                    reason: "Schnorr-only wallet cannot sign with SLH-DSA".into(),
                });
            }
            (WalletKeys::SlhDsa(_), SigningMode::Schnorr) => {
                return Err(SdkError::KeyGenerationFailed {
                    reason: "SLH-DSA-only wallet cannot sign with Schnorr".into(),
                });
            }
            _ => {}
        }
        self.signing_mode = mode;
        Ok(())
    }

    /// Get the current signing mode.
    pub fn signing_mode(&self) -> SigningMode {
        self.signing_mode
    }

    /// Get the wallet address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Get the public key bytes (for the active signing mode).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        match (&self.keys, self.signing_mode) {
            (WalletKeys::Schnorr(kp), _) => kp.public_key().as_bytes().to_vec(),
            (WalletKeys::SlhDsa(kp), _) => kp.public_key().as_bytes().to_vec(),
            (WalletKeys::Dual { schnorr, .. }, SigningMode::Schnorr) => {
                schnorr.public_key().as_bytes().to_vec()
            }
            (WalletKeys::Dual { slh_dsa, .. }, SigningMode::SlhDsa) => {
                slh_dsa.public_key().as_bytes().to_vec()
            }
        }
    }

    /// Get the Schnorr keypair (if available).
    pub fn schnorr_keys(&self) -> Option<&SchnorrKeyPair> {
        match &self.keys {
            WalletKeys::Schnorr(kp) => Some(kp),
            WalletKeys::Dual { schnorr, .. } => Some(schnorr),
            WalletKeys::SlhDsa(_) => None,
        }
    }

    /// Set the nonce (from chain state).
    ///
    /// If the new nonce is below the high watermark,
    /// this indicates a potential TEE reset or hardware fault. The wallet
    /// enters fatal lockdown to prevent double-spend.
    pub fn set_nonce(&mut self, nonce: u64) -> Result<(), SdkError> {
        if nonce < self.nonce_high_watermark {
            self.locked = true;
            return Err(SdkError::TransactionBuildFailed {
                reason: format!(
                    "HARDWARE FAULT: nonce {} < high_watermark {}. \
                     Wallet locked — possible TEE reset or replay attack. \
                     Re-sync nonce from network before unlocking.",
                    nonce, self.nonce_high_watermark,
                ),
            });
        }
        self.nonce = nonce;
        Ok(())
    }

    /// Check if the wallet is in lockdown.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    /// Force-unlock after manual verification (e.g., nonce re-synced from chain).
    ///
    /// The caller MUST verify the nonce from the L2 chain state before unlocking.
    /// Returns an error if `verified_nonce` is below the current nonce to prevent
    /// accidental nonce reuse.
    pub fn force_unlock(&mut self, verified_nonce: u64) -> Result<(), SdkError> {
        if verified_nonce < self.nonce {
            return Err(SdkError::TransactionBuildFailed {
                reason: format!(
                    "force_unlock nonce {} < current nonce {}. \
                     Refusing to move nonce backwards to prevent nonce reuse.",
                    verified_nonce, self.nonce,
                ),
            });
        }
        self.nonce = verified_nonce;
        self.nonce_high_watermark = verified_nonce;
        self.locked = false;
        Ok(())
    }

    // ── Transaction Builders ──────────────────────────────────────────

    /// Build and sign a transfer transaction.
    pub fn transfer(
        &mut self,
        to: Address,
        amount: u64,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
        gas_limit: u64,
    ) -> Result<Transaction, SdkError> {
        if amount == 0 {
            return Err(SdkError::TransactionBuildFailed {
                reason: "transfer amount must be greater than zero".into(),
            });
        }
        if to == *self.address() {
            return Err(SdkError::TransactionBuildFailed {
                reason: "cannot transfer to self".into(),
            });
        }
        let kind = TransactionKind::Transfer { to, amount };
        self.build_and_sign(kind, max_fee_per_gas, max_priority_fee_per_gas, gas_limit)
    }

    /// Maximum contract code size (256 KB).
    const MAX_CODE_SIZE: usize = 256 * 1024;

    /// Build and sign a contract deployment transaction.
    pub fn deploy(
        &mut self,
        code: Vec<u8>,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
        gas_limit: u64,
    ) -> Result<Transaction, SdkError> {
        if code.is_empty() {
            return Err(SdkError::TransactionBuildFailed {
                reason: "contract code must not be empty".into(),
            });
        }
        if code.len() > Self::MAX_CODE_SIZE {
            return Err(SdkError::TransactionBuildFailed {
                reason: format!(
                    "contract code size {} exceeds maximum {} bytes",
                    code.len(),
                    Self::MAX_CODE_SIZE
                ),
            });
        }
        let kind = TransactionKind::Deploy { code };
        self.build_and_sign(kind, max_fee_per_gas, max_priority_fee_per_gas, gas_limit)
    }

    /// Maximum calldata size (64 KB).
    const MAX_CALLDATA_SIZE: usize = 64 * 1024;

    /// Build and sign a contract call transaction.
    pub fn call_contract(
        &mut self,
        to: Address,
        data: Vec<u8>,
        value: u64,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
        gas_limit: u64,
    ) -> Result<Transaction, SdkError> {
        if data.len() > Self::MAX_CALLDATA_SIZE {
            return Err(SdkError::TransactionBuildFailed {
                reason: format!(
                    "calldata size {} exceeds maximum {} bytes",
                    data.len(),
                    Self::MAX_CALLDATA_SIZE
                ),
            });
        }
        let kind = TransactionKind::ContractCall { to, data, value };
        self.build_and_sign(kind, max_fee_per_gas, max_priority_fee_per_gas, gas_limit)
    }

    // ── Core Signing ──────────────────────────────────────────────────

    /// Build a transaction body and sign it with the active key.
    fn build_and_sign(
        &mut self,
        kind: TransactionKind,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
        gas_limit: u64,
    ) -> Result<Transaction, SdkError> {
        // Refuse to sign if wallet is locked.
        if self.locked {
            return Err(SdkError::TransactionBuildFailed {
                reason: "wallet is in LOCKDOWN — possible hardware fault. \
                         Call force_unlock() with verified nonce to recover."
                    .into(),
            });
        }

        let nonce = self.nonce;

        let body = TransactionBody {
            from: self.address,
            kind,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            chain_id: self.chain_id,
        };

        let tx_hash = body.hash();

        let (signature, public_key) = match (&self.keys, self.signing_mode) {
            // Schnorr-only wallet
            (WalletKeys::Schnorr(kp), _) => {
                let sig = kp.sign(&tx_hash).map_err(|e| SdkError::SigningFailed {
                    reason: format!("{e}"),
                })?;
                (Signature::Schnorr(sig), PublicKey::Schnorr(*kp.public_key()))
            }
            // SLH-DSA-only wallet
            (WalletKeys::SlhDsa(kp), _) => {
                let sig = kp
                    .sign(tx_hash.as_bytes())
                    .map_err(|e| SdkError::SigningFailed {
                        reason: format!("SLH-DSA: {e}"),
                    })?;
                (
                    Signature::SlhDsa(sig),
                    PublicKey::SlhDsa(kp.public_key().clone()),
                )
            }
            // Dual wallet — Schnorr mode
            (WalletKeys::Dual { schnorr, .. }, SigningMode::Schnorr) => {
                let sig = schnorr
                    .sign(&tx_hash)
                    .map_err(|e| SdkError::SigningFailed {
                        reason: format!("{e}"),
                    })?;
                (
                    Signature::Schnorr(sig),
                    PublicKey::Schnorr(*schnorr.public_key()),
                )
            }
            // Dual wallet — SLH-DSA mode
            (WalletKeys::Dual { slh_dsa, .. }, SigningMode::SlhDsa) => {
                let sig = slh_dsa
                    .sign(tx_hash.as_bytes())
                    .map_err(|e| SdkError::SigningFailed {
                        reason: format!("SLH-DSA: {e}"),
                    })?;
                (
                    Signature::SlhDsa(sig),
                    PublicKey::SlhDsa(slh_dsa.public_key().clone()),
                )
            }
        };

        let tx = Transaction {
            body,
            signature,
            public_key,
        };

        // Only increment nonce after signing succeeds — a failed sign
        // must not create a gap in the nonce sequence.
        self.nonce += 1;
        // Update high watermark — this is the software defense layer
        if self.nonce > self.nonce_high_watermark {
            self.nonce_high_watermark = self.nonce;
        }

        Ok(tx)
    }

    // ── Merchant Self-Relay ──────────────────

    /// Build a BatchSettlePortal transaction for direct submission (no relayer).
    ///
    /// This is the merchant's "nuclear option" against relayer cartels.
    /// Instead of paying a relayer fee (0.1-1%), the merchant pays L2 gas
    /// directly (~0.01%) and submits the settlement themselves.
    ///
    /// Build and sign a CreatePortalLock transaction.
    pub fn create_portal_lock(
        &mut self,
        amount: u64,
        condition_hash: brrq_crypto::hash::Hash256,
        nullifier_hash: brrq_crypto::hash::Hash256,
        timeout_l2_block: u64,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
    ) -> Result<Transaction, SdkError> {
        if amount == 0 {
            return Err(SdkError::TransactionBuildFailed {
                reason: "lock amount must be > 0".into(),
            });
        }
        let kind = TransactionKind::CreatePortalLock {
            amount,
            condition_hash,
            nullifier_hash,
            timeout_l2_block,
        };
        self.build_and_sign(kind, max_fee_per_gas, max_priority_fee_per_gas, 50_000)
    }

    /// Build and sign an UpdateLockCondition transaction.
    pub fn update_lock_condition(
        &mut self,
        lock_id: brrq_crypto::hash::Hash256,
        condition_hash: brrq_crypto::hash::Hash256,
        nullifier_hash: brrq_crypto::hash::Hash256,
        merchant_address: Address,
        merchant_pubkey: [u8; 32],
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
    ) -> Result<Transaction, SdkError> {
        let kind = TransactionKind::UpdateLockCondition {
            lock_id,
            condition_hash,
            nullifier_hash,
            merchant_address,
            merchant_pubkey,
        };
        self.build_and_sign(kind, max_fee_per_gas, max_priority_fee_per_gas, 30_000)
    }

    /// Build and sign a SettlePortalLock transaction.
    pub fn settle_portal_lock(
        &mut self,
        lock_id: brrq_crypto::hash::Hash256,
        merchant_secret: Vec<u8>,
        portal_signature: Vec<u8>,
        nullifier: brrq_crypto::hash::Hash256,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
    ) -> Result<Transaction, SdkError> {
        let kind = TransactionKind::SettlePortalLock {
            lock_id,
            merchant_secret,
            portal_signature,
            nullifier,
        };
        self.build_and_sign(kind, max_fee_per_gas, max_priority_fee_per_gas, 50_000)
    }

    /// Build and sign a CancelPortalLock transaction.
    pub fn cancel_portal_lock(
        &mut self,
        lock_id: brrq_crypto::hash::Hash256,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
    ) -> Result<Transaction, SdkError> {
        let kind = TransactionKind::CancelPortalLock { lock_id };
        self.build_and_sign(kind, max_fee_per_gas, max_priority_fee_per_gas, 30_000)
    }

    /// ## Game Theory
    ///
    /// The existence of this function keeps relayer fees low:
    /// - Relayer asks 5% → merchant self-relays at 0.01% → relayer gets $0
    /// - Relayer asks 0.1% → merchant uses relayer (convenience) → relayer profits
    /// - Equilibrium: relayer fees converge to ~0.1% (just above self-relay cost)
    pub fn merchant_self_settle(
        &mut self,
        claims: Vec<brrq_types::transaction::PortalSettlementClaim>,
        max_fee_per_gas: u64,
        max_priority_fee_per_gas: u64,
    ) -> Result<Transaction, SdkError> {
        if claims.is_empty() {
            return Err(SdkError::TransactionBuildFailed {
                reason: "no claims to settle".into(),
            });
        }
        if claims.len() > 100 {
            return Err(SdkError::TransactionBuildFailed {
                reason: format!("too many claims: {} (max 100)", claims.len()),
            });
        }

        // Estimate gas: base 21K + ~30K per claim (dynamic pricing)
        let estimated_gas = 21_000u64 + (claims.len() as u64) * 30_000;

        let kind = TransactionKind::BatchSettlePortal { claims };
        self.build_and_sign(kind, max_fee_per_gas, max_priority_fee_per_gas, estimated_gas)
    }
}

impl Default for Wallet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_creation() {
        let wallet = Wallet::new();
        assert!(!wallet.address().is_zero());
    }

    #[test]
    fn test_wallet_deterministic() {
        let secret = [42u8; 32];
        let w1 = Wallet::from_secret(&secret).unwrap();
        let w2 = Wallet::from_secret(&secret).unwrap();
        assert_eq!(w1.address(), w2.address());
    }

    #[test]
    fn test_transfer() {
        let mut wallet = Wallet::new();
        let to = Address::from_bytes([1u8; 20]);
        let tx = wallet.transfer(to, 1000, 10, 10, 21000).unwrap();

        assert_eq!(tx.body.from, *wallet.address());
        assert_eq!(tx.body.nonce, 0);
        assert_eq!(tx.body.max_fee_per_gas, 10);
        assert_eq!(tx.body.chain_id, chain_id::TESTNET);
    }

    #[test]
    fn test_chain_id_configurable() {
        let mut wallet = Wallet::new();
        wallet.set_chain_id(chain_id::MAINNET);
        let to = Address::from_bytes([1u8; 20]);
        let tx = wallet.transfer(to, 100, 1, 1, 21000).unwrap();
        assert_eq!(tx.body.chain_id, chain_id::MAINNET);
    }

    #[test]
    fn test_nonce_increments() {
        let mut wallet = Wallet::new();
        let to = Address::from_bytes([1u8; 20]);

        let tx1 = wallet.transfer(to, 100, 1, 1, 21000).unwrap();
        let tx2 = wallet.transfer(to, 200, 1, 1, 21000).unwrap();

        assert_eq!(tx1.body.nonce, 0);
        assert_eq!(tx2.body.nonce, 1);
    }

    #[test]
    fn test_deploy() {
        let mut wallet = Wallet::new();
        let tx = wallet
            .deploy(vec![0x00, 0x61, 0x73, 0x6d], 10, 10, 100000)
            .unwrap();
        match tx.body.kind {
            TransactionKind::Deploy { ref code } => {
                assert_eq!(code.len(), 4);
            }
            _ => panic!("expected Deploy"),
        }
    }

    #[test]
    fn test_contract_call() {
        let mut wallet = Wallet::new();
        let to = Address::from_bytes([2u8; 20]);
        let tx = wallet
            .call_contract(to, vec![0xAB, 0xCD], 500, 5, 5, 50000)
            .unwrap();
        match tx.body.kind {
            TransactionKind::ContractCall {
                to: t,
                ref data,
                value,
            } => {
                assert_eq!(t, to);
                assert_eq!(data.len(), 2);
                assert_eq!(value, 500);
            }
            _ => panic!("expected ContractCall"),
        }
    }

    // ── SLH-DSA Tests ─────────────────────────────────────────────────

    #[test]
    fn test_slh_dsa_wallet() {
        let mut wallet = Wallet::new_slh_dsa(chain_id::TESTNET).unwrap();
        assert!(!wallet.address().is_zero());
        assert_eq!(wallet.signing_mode(), SigningMode::SlhDsa);

        let to = Address::from_bytes([1u8; 20]);
        let tx = wallet.transfer(to, 1000, 10, 10, 21000).unwrap();
        assert!(matches!(tx.signature, Signature::SlhDsa(_)));
        assert!(matches!(tx.public_key, PublicKey::SlhDsa(_)));
    }

    #[test]
    fn test_slh_dsa_wallet_cannot_use_schnorr() {
        let mut wallet = Wallet::new_slh_dsa(chain_id::TESTNET).unwrap();
        assert!(wallet.set_signing_mode(SigningMode::Schnorr).is_err());
    }

    #[test]
    fn test_schnorr_wallet_cannot_use_slh_dsa() {
        let mut wallet = Wallet::new();
        assert!(wallet.set_signing_mode(SigningMode::SlhDsa).is_err());
    }

    // ── Dual Wallet Tests ─────────────────────────────────────────────

    #[test]
    fn test_dual_wallet_schnorr_mode() {
        let mut wallet = Wallet::new_dual(chain_id::TESTNET).unwrap();
        assert_eq!(wallet.signing_mode(), SigningMode::Schnorr);

        let to = Address::from_bytes([1u8; 20]);
        let tx = wallet.transfer(to, 1000, 10, 10, 21000).unwrap();
        assert!(matches!(tx.signature, Signature::Schnorr(_)));
    }

    #[test]
    fn test_dual_wallet_slh_dsa_mode() {
        let mut wallet = Wallet::new_dual(chain_id::TESTNET).unwrap();
        wallet.set_signing_mode(SigningMode::SlhDsa).unwrap();

        let to = Address::from_bytes([1u8; 20]);
        let tx = wallet.transfer(to, 1000, 10, 10, 21000).unwrap();
        assert!(matches!(tx.signature, Signature::SlhDsa(_)));
        assert!(matches!(tx.public_key, PublicKey::SlhDsa(_)));
    }

    #[test]
    fn test_dual_wallet_switch_modes() {
        let mut wallet = Wallet::new_dual(chain_id::TESTNET).unwrap();
        let to = Address::from_bytes([1u8; 20]);

        // First tx: Schnorr (default)
        let tx1 = wallet.transfer(to, 100, 1, 1, 21000).unwrap();
        assert!(matches!(tx1.signature, Signature::Schnorr(_)));

        // Switch to SLH-DSA
        wallet.set_signing_mode(SigningMode::SlhDsa).unwrap();
        let tx2 = wallet.transfer(to, 200, 1, 1, 21000).unwrap();
        assert!(matches!(tx2.signature, Signature::SlhDsa(_)));

        // Nonces still increment correctly
        assert_eq!(tx1.body.nonce, 0);
        assert_eq!(tx2.body.nonce, 1);
    }

    // ── Nonce High-Watermark & Lockdown Tests ─────────────────────

    #[test]
    fn test_nonce_watermark_tracks_highest() {
        let mut wallet = Wallet::new();
        let to = Address::from_bytes([1u8; 20]);

        // Sign 3 transactions — watermark should be 3
        wallet.transfer(to, 100, 1, 1, 21000).unwrap();
        wallet.transfer(to, 200, 1, 1, 21000).unwrap();
        wallet.transfer(to, 300, 1, 1, 21000).unwrap();

        assert_eq!(wallet.nonce, 3);
        assert_eq!(wallet.nonce_high_watermark, 3);
        assert!(!wallet.is_locked());
    }

    #[test]
    fn test_hardware_fault_lockdown() {
        // Simulate: wallet signs up to nonce 8, then TEE resets and
        // reports nonce 3. The software watchdog MUST detect this
        // and lock the wallet to prevent double-spend.
        let mut wallet = Wallet::new();
        let to = Address::from_bytes([1u8; 20]);

        // Sign 8 transactions → watermark = 8
        for _ in 0..8 {
            wallet.transfer(to, 100, 1, 1, 21000).unwrap();
        }
        assert_eq!(wallet.nonce_high_watermark, 8);

        // Simulate TEE reset: external system tries to set nonce back to 3
        let result = wallet.set_nonce(3);
        assert!(result.is_err(), "HARDWARE FAULT: set_nonce(3) must fail when watermark=8");
        assert!(wallet.is_locked(), "wallet must be in LOCKDOWN after nonce regression");

        // All signing must be blocked while locked
        let tx_result = wallet.transfer(to, 500, 1, 1, 21000);
        assert!(tx_result.is_err(), "LOCKDOWN: signing must be impossible");
        assert!(
            tx_result.unwrap_err().to_string().contains("LOCKDOWN"),
            "error message must indicate lockdown"
        );
    }

    #[test]
    fn test_force_unlock_recovery() {
        let mut wallet = Wallet::new();
        let to = Address::from_bytes([1u8; 20]);

        // Sign 5 txs → watermark = 5
        for _ in 0..5 {
            wallet.transfer(to, 100, 1, 1, 21000).unwrap();
        }

        // Simulate fault → lockdown
        let _ = wallet.set_nonce(2); // triggers lockdown
        assert!(wallet.is_locked());

        // Recovery: re-sync from network, verified nonce = 5
        wallet.force_unlock(5).unwrap();
        assert!(!wallet.is_locked());
        assert_eq!(wallet.nonce, 5);
        assert_eq!(wallet.nonce_high_watermark, 5);

        // Can sign again
        let tx = wallet.transfer(to, 100, 1, 1, 21000);
        assert!(tx.is_ok());
        assert_eq!(tx.unwrap().body.nonce, 5);
    }

    #[test]
    fn test_force_unlock_rejects_backward_nonce() {
        let mut wallet = Wallet::new();
        let to = Address::from_bytes([1u8; 20]);

        // Sign 5 txs → nonce = 5, watermark = 5
        for _ in 0..5 {
            wallet.transfer(to, 100, 1, 1, 21000).unwrap();
        }

        // Simulate fault → lockdown
        let _ = wallet.set_nonce(2);
        assert!(wallet.is_locked());

        // Attempt force_unlock with nonce < current nonce (5) — must fail
        let result = wallet.force_unlock(3);
        assert!(result.is_err(), "force_unlock must reject nonce below current nonce");
        assert!(wallet.is_locked(), "wallet must remain locked after rejected force_unlock");

        // force_unlock with nonce >= current nonce succeeds
        wallet.force_unlock(5).unwrap();
        assert!(!wallet.is_locked());
    }

    #[test]
    fn test_set_nonce_forward_works() {
        let mut wallet = Wallet::new();
        let to = Address::from_bytes([1u8; 20]);

        // Sign 2 txs → watermark = 2
        wallet.transfer(to, 100, 1, 1, 21000).unwrap();
        wallet.transfer(to, 200, 1, 1, 21000).unwrap();

        // Network says nonce is 5 (some txs confirmed elsewhere)
        assert!(wallet.set_nonce(5).is_ok());
        assert_eq!(wallet.nonce, 5);
        assert!(!wallet.is_locked());

        // Next tx uses nonce 5
        let tx = wallet.transfer(to, 300, 1, 1, 21000).unwrap();
        assert_eq!(tx.body.nonce, 5);
    }
}
