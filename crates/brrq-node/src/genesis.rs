//! Genesis configuration — deterministic initial state from TOML file.
//!
//! All nodes loading the same genesis file MUST arrive at the same initial
//! `WorldState` with an identical state root. To ensure this, accounts and
//! validators are sorted by address before application.

use std::path::Path;

use brrq_types::account::Account;
use brrq_types::address::Address;
use serde::Deserialize;

use crate::node::NodeState;

/// Top-level genesis configuration parsed from TOML.
#[derive(Debug, Clone, Deserialize)]
pub struct GenesisConfig {
    /// Chain parameters.
    pub chain: ChainConfig,
    /// Initial validator set.
    #[serde(default)]
    pub validators: Vec<ValidatorConfig>,
    /// Pre-funded accounts.
    #[serde(default)]
    pub accounts: Vec<AccountConfig>,
    /// Testnet faucet configuration.
    pub faucet: Option<FaucetConfig>,
    /// Bootstrap node addresses for P2P discovery.
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,
    /// Protocol treasury configuration.
    pub treasury: Option<TreasuryConfig>,
    /// Prover pool address — receives 40% proof share of transaction fees (§9.4).
    pub prover_pool: Option<FeeRecipientConfig>,
    /// DA reserve address — receives 20% data availability share (§9.4).
    pub da_reserve: Option<FeeRecipientConfig>,
}

/// Protocol treasury configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct TreasuryConfig {
    /// Treasury account address (receives protocol share + funds bootstrap rewards).
    pub address: String,
    /// Initial treasury balance in satoshis (pre-funded at genesis).
    #[serde(default)]
    pub initial_balance: u64,
}

/// Fee recipient configuration (prover pool, DA reserve).
#[derive(Debug, Clone, Deserialize)]
pub struct FeeRecipientConfig {
    /// Recipient address (hex-encoded, 0x-prefixed).
    pub address: String,
}

/// Chain-level parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct ChainConfig {
    /// Chain ID (e.g., 0xB77C0001 for testnet).
    pub chain_id: u64,
    /// Block production interval in seconds.
    #[serde(default = "default_block_time")]
    pub block_time_secs: u64,
    /// Blocks per epoch.
    #[serde(default = "default_epoch_length")]
    pub epoch_length: u64,
    /// Maximum gas per block.
    #[serde(default = "default_block_gas_limit")]
    pub block_gas_limit: u64,
    /// Initial stake cap in satoshis.
    #[serde(default = "default_stake_cap")]
    pub initial_stake_cap: u64,
    /// Bitcoin L1 network: "mainnet", "testnet", "regtest" (None = no L1 connection).
    #[serde(default)]
    pub l1_network: Option<String>,
    /// L2 blocks between L1 anchor postings (default: 100).
    #[serde(default = "default_checkpoint_interval")]
    pub l1_checkpoint_interval: u64,
    /// Bitcoin address for the bridge (Taproot P2TR recommended).
    #[serde(default)]
    pub bridge_address: Option<String>,
    /// MEV protection mode: "disabled", "centralized_bypass", "decentralized".
    #[serde(default)]
    pub mev_mode: Option<String>,
    /// Enable multi-sequencer rotation. Default: false.
    /// Consumed at runtime when `sequencer-rotation` feature is active.
    #[serde(default)]
    #[allow(dead_code)] // read via serde deserialization; used by sequencer-rotation feature
    pub rotation_enabled: bool,
    /// Enable dynamic fee market (EIP-1559 style). Default: false.
    #[serde(default)]
    pub fee_market_enabled: bool,
}

fn default_block_time() -> u64 {
    3
}
fn default_epoch_length() -> u64 {
    7_200
}
fn default_block_gas_limit() -> u64 {
    30_000_000
}
fn default_stake_cap() -> u64 {
    10_000_000_000
} // 100 BTC
fn default_checkpoint_interval() -> u64 {
    100
}

/// Validator entry in genesis.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidatorConfig {
    /// Hex-encoded 20-byte address (with or without 0x prefix).
    pub address: String,
    /// Stake amount in satoshis.
    pub stake: u64,
    /// Hex-encoded EOTS public key (32 bytes Schnorr x-only).
    /// Required on mainnet; empty string accepted on testnet.
    #[serde(default)]
    pub eots_pubkey: String,
    /// Hex-encoded SLH-DSA public key (post-quantum).
    /// Required on mainnet; empty string accepted on testnet.
    #[serde(default)]
    pub slh_dsa_pubkey: String,
}

/// Pre-funded account entry.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountConfig {
    /// Hex-encoded 20-byte address (with or without 0x prefix).
    pub address: String,
    /// Initial balance in satoshis.
    pub balance: u64,
}

/// Faucet configuration (testnet only).
#[derive(Debug, Clone, Deserialize)]
pub struct FaucetConfig {
    /// Faucet account address.
    pub address: String,
    /// Amount dispensed per request (satoshis).
    #[serde(default = "default_drip_amount")]
    pub drip_amount: u64,
    /// Cooldown per address in seconds.
    #[serde(default = "default_cooldown")]
    pub cooldown_secs: u64,
}

fn default_drip_amount() -> u64 {
    100_000_000
} // 1 BTC
fn default_cooldown() -> u64 {
    3600
} // 1 hour

/// Parse a hex address string (with or without "0x" prefix) into an Address.
/// Public variant for use by main.rs.
pub fn parse_address_pub(hex_str: &str) -> Result<Address, String> {
    parse_address(hex_str)
}

fn parse_address(hex_str: &str) -> Result<Address, String> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex address: {}", e))?;
    if bytes.len() != 20 {
        return Err(format!("address must be 20 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(Address::from_bytes(arr))
}

impl GenesisConfig {
    /// Load genesis configuration from a TOML file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read genesis file {:?}: {}", path, e))?;
        toml::from_str(&content).map_err(|e| format!("failed to parse genesis TOML: {}", e))
    }

    /// Apply this genesis configuration to a fresh NodeState.
    ///
    /// Accounts and validators are sorted by address to ensure deterministic
    /// state root computation across all nodes.
    pub fn apply(&self, ns: &mut NodeState) -> Result<(), String> {
        // Validate critical parameters that would cause division-by-zero or broken consensus
        if self.chain.epoch_length == 0 {
            return Err("genesis: epoch_length must be > 0 (would cause division-by-zero)".into());
        }
        if self.chain.block_time_secs == 0 {
            return Err(
                "genesis: block_time_secs must be > 0 (would cause division-by-zero)".into(),
            );
        }
        if self.chain.initial_stake_cap == 0 {
            return Err("genesis: initial_stake_cap must be > 0".into());
        }

        // Configure chain ID and consensus parameters from genesis
        ns.chain_id = self.chain.chain_id;
        ns.staking = brrq_consensus::StakingState::new(self.chain.initial_stake_cap);
        ns.epoch = brrq_consensus::EpochState::new(self.chain.epoch_length);

        // Apply pre-funded accounts (sorted for determinism)
        let mut accounts: Vec<(Address, u64)> = self
            .accounts
            .iter()
            .map(|a| Ok((parse_address(&a.address)?, a.balance)))
            .collect::<Result<Vec<_>, String>>()?;
        accounts.sort_by_key(|(addr, _)| *addr);

        for (addr, balance) in &accounts {
            let account = Account::new_eoa(*addr, *balance);
            ns.state.set_account(account);
        }

        // Register validators (sorted for determinism)
        // Mainnet chain_id: 0xB77C0008. Testnet: 0xB77C0001.
        let is_mainnet = self.chain.chain_id == 0xB77C0008;

        let mut validators: Vec<(Address, u64, String, String)> = self
            .validators
            .iter()
            .map(|v| {
                Ok((
                    parse_address(&v.address)?,
                    v.stake,
                    v.eots_pubkey.clone(),
                    v.slh_dsa_pubkey.clone(),
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        validators.sort_by_key(|(addr, _, _, _)| *addr);

        for (addr, stake, eots, slh_dsa) in &validators {
            // Validate key format, not just emptiness.
            if is_mainnet {
                if eots.is_empty() || slh_dsa.is_empty() {
                    return Err(format!(
                        "validator {} has empty keys — eots_pubkey and slh_dsa_pubkey \
                         are required on mainnet. Use keygen to generate keys first.",
                        addr,
                    ));
                }
                // Validate EOTS pubkey: must be valid 32-byte hex (x-only Schnorr)
                let eots_bytes = hex::decode(eots.strip_prefix("0x").unwrap_or(eots))
                    .map_err(|_| format!("validator {} eots_pubkey is not valid hex", addr))?;
                if eots_bytes.len() != 32 {
                    return Err(format!(
                        "validator {} eots_pubkey must be 32 bytes (got {})",
                        addr,
                        eots_bytes.len(),
                    ));
                }
                // Validate SLH-DSA pubkey: must be valid hex, at least 32 bytes
                let slh_bytes =
                    hex::decode(slh_dsa.strip_prefix("0x").unwrap_or(slh_dsa)).map_err(|_| {
                        format!("validator {} slh_dsa_pubkey is not valid hex", addr)
                    })?;
                if slh_bytes.len() < 32 {
                    return Err(format!(
                        "validator {} slh_dsa_pubkey too short ({} bytes, need >= 32)",
                        addr,
                        slh_bytes.len(),
                    ));
                }
                tracing::info!(
                    %addr,
                    eots_len = eots_bytes.len(),
                    slh_dsa_len = slh_bytes.len(),
                    "Mainnet validator keys validated",
                );
            }
            ns.staking
                .register_validator(*addr, *stake)
                .map_err(|e| format!("failed to register validator {}: {}", addr, e))?;
        }

        // Store faucet config address for later use
        if let Some(ref faucet) = self.faucet {
            let faucet_addr = parse_address(&faucet.address)?;
            // Ensure faucet account exists (may already be in accounts list)
            if ns.state.get_account(&faucet_addr).is_none() {
                let account = Account::new_eoa(faucet_addr, 0);
                ns.state.set_account(account);
            }
        }

        // Apply L1 network configuration from genesis
        if let Some(ref l1_net) = self.chain.l1_network {
            ns.l1_network = Some(l1_net.clone());
            tracing::info!("  L1 network: {}", l1_net);
        }

        // Apply protocol treasury configuration
        if let Some(ref treasury) = self.treasury {
            let treasury_addr = parse_address(&treasury.address)?;
            if treasury.initial_balance > 0 {
                let account = Account::new_eoa(treasury_addr, treasury.initial_balance);
                ns.state.set_account(account);
            } else if ns.state.get_account(&treasury_addr).is_none() {
                let account = Account::new_eoa(treasury_addr, 0);
                ns.state.set_account(account);
            }
            ns.protocol_treasury_address = Some(treasury_addr);
            tracing::info!(
                "  Treasury: {} (initial balance: {} sat)",
                treasury.address,
                treasury.initial_balance,
            );
        }

        // Apply prover pool address (receives 40% proof share)
        if let Some(ref prover_pool) = self.prover_pool {
            let prover_addr = parse_address(&prover_pool.address)?;
            if ns.state.get_account(&prover_addr).is_none() {
                let account = Account::new_eoa(prover_addr, 0);
                ns.state.set_account(account);
            }
            ns.prover_pool_address = Some(prover_addr);
            tracing::info!("  Prover pool: {}", prover_pool.address);
        }

        // Apply DA reserve address (receives 20% DA share)
        if let Some(ref da_reserve) = self.da_reserve {
            let da_addr = parse_address(&da_reserve.address)?;
            if ns.state.get_account(&da_addr).is_none() {
                let account = Account::new_eoa(da_addr, 0);
                ns.state.set_account(account);
            }
            ns.da_reserve_address = Some(da_addr);
            tracing::info!("  DA reserve: {}", da_reserve.address);
        }

        // Apply MEV protection mode
        if let Some(ref mode) = self.chain.mev_mode {
            ns.mev_mode = match mode.as_str() {
                "centralized_bypass" => {
                    tracing::info!("  MEV protection: CentralizedBypass (commit-reveal active)");
                    brrq_api::MevActivationMode::CentralizedBypass
                }
                "decentralized" => {
                    tracing::info!("  MEV protection: Decentralized (two-block commit-reveal)");
                    brrq_api::MevActivationMode::Decentralized
                }
                "disabled" | "" => {
                    tracing::info!("  MEV protection: Disabled");
                    brrq_api::MevActivationMode::Disabled
                }
                other => {
                    return Err(format!(
                        "unknown mev_mode '{}' (expected: disabled, centralized_bypass, decentralized)",
                        other
                    ));
                }
            };
        }

        // Apply rotation and fee market settings from genesis
        #[cfg(feature = "sequencer-rotation")]
        if self.chain.rotation_enabled {
            ns.rotation_enabled = true;
            tracing::info!("  Rotation: enabled (multi-sequencer mode)");
        }
        if self.chain.fee_market_enabled {
            ns.fee_market = brrq_consensus::fee_market::FeeMarket::new();
            tracing::info!("  Fee market: enabled (EIP-1559 dynamic base fee)");
        }

        tracing::info!(
            "Genesis applied: {} accounts, {} validators, stake_cap={}, epoch_length={}, gas_limit={}",
            accounts.len(),
            validators.len(),
            self.chain.initial_stake_cap,
            self.chain.epoch_length,
            self.chain.block_gas_limit,
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_genesis_toml() {
        let toml_str = r#"
bootstrap_nodes = ["seed1.brrq.net:30303"]

[chain]
chain_id = 3078356993
block_time_secs = 3
epoch_length = 7200
block_gas_limit = 30000000
initial_stake_cap = 10000000000

[[validators]]
address = "0x0000000000000000000000000000000000000001"
stake = 100000000

[[accounts]]
address = "0x0000000000000000000000000000000000000099"
balance = 2100000000000000

[faucet]
address = "0x0000000000000000000000000000000000000099"
drip_amount = 100000000
cooldown_secs = 3600
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.chain.chain_id, 0xB77C_0001);
        assert_eq!(config.chain.block_time_secs, 3);
        assert_eq!(config.validators.len(), 1);
        assert_eq!(config.accounts.len(), 1);
        assert!(config.faucet.is_some());
        assert_eq!(config.bootstrap_nodes.len(), 1);
    }

    #[test]
    fn parse_address_with_prefix() {
        let addr = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(addr.as_bytes()[19], 1);
    }

    #[test]
    fn parse_address_without_prefix() {
        let addr = parse_address("0000000000000000000000000000000000000001").unwrap();
        assert_eq!(addr.as_bytes()[19], 1);
    }

    #[test]
    fn parse_address_invalid_length() {
        assert!(parse_address("0x0001").is_err());
    }

    #[test]
    fn apply_genesis_to_node_state() {
        let toml_str = r#"
[chain]
chain_id = 3078356993
epoch_length = 100
initial_stake_cap = 5000000000

[[accounts]]
address = "0x0000000000000000000000000000000000000001"
balance = 1000000

[[accounts]]
address = "0x0000000000000000000000000000000000000002"
balance = 2000000

[[validators]]
address = "0x0000000000000000000000000000000000000001"
stake = 100000000
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();

        // Check accounts were created
        let addr1 = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        let addr2 = parse_address("0x0000000000000000000000000000000000000002").unwrap();
        assert_eq!(ns.state.get_account(&addr1).unwrap().balance, 1000000);
        assert_eq!(ns.state.get_account(&addr2).unwrap().balance, 2000000);

        // Check validator was registered
        assert!(ns.staking.validators.contains_key(&addr1));

        // Check epoch length
        assert_eq!(ns.epoch.epoch_length, 100);
    }

    // ══════════════════════════════════════════════════════════════════
    // Microscopic Genesis Tests
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn parse_address_invalid_hex_chars() {
        // Non-hex characters should fail
        assert!(parse_address("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG").is_err());
    }

    #[test]
    fn parse_address_empty_string() {
        assert!(parse_address("").is_err());
    }

    #[test]
    fn parse_address_only_prefix() {
        assert!(parse_address("0x").is_err());
    }

    #[test]
    fn parse_address_too_long() {
        // 21 bytes = 42 hex chars
        assert!(parse_address("0x000000000000000000000000000000000000000001").is_err());
    }

    #[test]
    fn parse_address_exact_20_bytes() {
        let addr = parse_address("0xaabbccddee00112233445566778899aabbccddee").unwrap();
        assert_eq!(addr.as_bytes()[0], 0xaa);
        assert_eq!(addr.as_bytes()[1], 0xbb);
        assert_eq!(addr.as_bytes()[19], 0xee);
    }

    #[test]
    fn parse_address_pub_delegates_correctly() {
        let a1 = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        let a2 = parse_address_pub("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(a1, a2);
    }

    #[test]
    fn parse_address_pub_error_propagation() {
        assert!(parse_address_pub("invalid").is_err());
    }

    #[test]
    fn genesis_minimal_chain_only() {
        // Minimum valid genesis: only [chain] section
        let toml_str = r#"
[chain]
chain_id = 1
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.chain.chain_id, 1);
        assert!(config.validators.is_empty());
        assert!(config.accounts.is_empty());
        assert!(config.faucet.is_none());
        assert!(config.bootstrap_nodes.is_empty());
    }

    #[test]
    fn genesis_default_values() {
        // Verify all defaults are applied when fields are omitted
        let toml_str = r#"
[chain]
chain_id = 42
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.chain.block_time_secs, 3); // default_block_time
        assert_eq!(config.chain.epoch_length, 7200); // default_epoch_length
        assert_eq!(config.chain.block_gas_limit, 30_000_000); // default_block_gas_limit
        assert_eq!(config.chain.initial_stake_cap, 10_000_000_000); // default_stake_cap
    }

    #[test]
    fn genesis_faucet_defaults() {
        let toml_str = r#"
[chain]
chain_id = 1

[faucet]
address = "0x0000000000000000000000000000000000000099"
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let faucet = config.faucet.unwrap();
        assert_eq!(faucet.drip_amount, 100_000_000); // default 1 BTC
        assert_eq!(faucet.cooldown_secs, 3600); // default 1 hour
    }

    #[test]
    fn genesis_multiple_validators() {
        let toml_str = r#"
[chain]
chain_id = 1
initial_stake_cap = 50000000000

[[validators]]
address = "0x0000000000000000000000000000000000000001"
stake = 100000000

[[validators]]
address = "0x0000000000000000000000000000000000000002"
stake = 200000000

[[validators]]
address = "0x0000000000000000000000000000000000000003"
stake = 300000000
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.validators.len(), 3);
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();
        assert_eq!(ns.staking.validators.len(), 3);
    }

    #[test]
    fn genesis_multiple_accounts() {
        let toml_str = r#"
[chain]
chain_id = 1

[[accounts]]
address = "0x0000000000000000000000000000000000000001"
balance = 100

[[accounts]]
address = "0x0000000000000000000000000000000000000002"
balance = 200

[[accounts]]
address = "0x0000000000000000000000000000000000000003"
balance = 300
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();

        let addr1 = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        let addr2 = parse_address("0x0000000000000000000000000000000000000002").unwrap();
        let addr3 = parse_address("0x0000000000000000000000000000000000000003").unwrap();
        assert_eq!(ns.state.balance(&addr1), 100);
        assert_eq!(ns.state.balance(&addr2), 200);
        assert_eq!(ns.state.balance(&addr3), 300);
    }

    #[test]
    fn genesis_apply_deterministic_order() {
        // Accounts in reverse order should produce the same state as forward order
        let toml1 = r#"
[chain]
chain_id = 1

[[accounts]]
address = "0x0000000000000000000000000000000000000001"
balance = 100

[[accounts]]
address = "0x0000000000000000000000000000000000000002"
balance = 200
"#;
        let toml2 = r#"
[chain]
chain_id = 1

[[accounts]]
address = "0x0000000000000000000000000000000000000002"
balance = 200

[[accounts]]
address = "0x0000000000000000000000000000000000000001"
balance = 100
"#;
        let config1: GenesisConfig = toml::from_str(toml1).unwrap();
        let config2: GenesisConfig = toml::from_str(toml2).unwrap();

        let mut ns1 = NodeState::new();
        let mut ns2 = NodeState::new();
        config1.apply(&mut ns1).unwrap();
        config2.apply(&mut ns2).unwrap();

        // Both should have same state root (deterministic regardless of order)
        assert_eq!(ns1.state.state_root(), ns2.state.state_root());
    }

    #[test]
    fn genesis_invalid_validator_address() {
        let toml_str = r#"
[chain]
chain_id = 1

[[validators]]
address = "0xINVALID"
stake = 100
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        assert!(config.apply(&mut ns).is_err());
    }

    #[test]
    fn genesis_invalid_account_address() {
        let toml_str = r#"
[chain]
chain_id = 1

[[accounts]]
address = "0xNOTHEX"
balance = 100
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        assert!(config.apply(&mut ns).is_err());
    }

    #[test]
    fn genesis_faucet_account_auto_created() {
        // Faucet address NOT in accounts list → should be auto-created with 0 balance
        let toml_str = r#"
[chain]
chain_id = 1

[faucet]
address = "0x00000000000000000000000000000000deadfacc"
drip_amount = 100
cooldown_secs = 60
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();

        let faucet_addr = parse_address("0x00000000000000000000000000000000deadfacc").unwrap();
        let account = ns.state.get_account(&faucet_addr);
        assert!(account.is_some(), "faucet account should be auto-created");
        assert_eq!(account.unwrap().balance, 0);
    }

    #[test]
    fn genesis_faucet_already_in_accounts() {
        // Faucet address IS in accounts list → should NOT override existing balance
        let toml_str = r#"
[chain]
chain_id = 1

[[accounts]]
address = "0x00000000000000000000000000000000deadfacc"
balance = 999999

[faucet]
address = "0x00000000000000000000000000000000deadfacc"
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();

        let faucet_addr = parse_address("0x00000000000000000000000000000000deadfacc").unwrap();
        assert_eq!(ns.state.balance(&faucet_addr), 999999);
    }

    #[test]
    fn genesis_bootstrap_nodes_parsed() {
        let toml_str = r#"
bootstrap_nodes = ["seed1:30303", "seed2:30304", "seed3:30305"]

[chain]
chain_id = 1
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.bootstrap_nodes.len(), 3);
        assert_eq!(config.bootstrap_nodes[0], "seed1:30303");
        assert_eq!(config.bootstrap_nodes[2], "seed3:30305");
    }

    #[test]
    fn genesis_load_nonexistent_file() {
        let result = GenesisConfig::load(Path::new("/nonexistent/genesis.toml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("failed to read genesis file"));
    }

    #[test]
    fn genesis_invalid_toml_syntax() {
        let toml_str = r#"
[chain
chain_id = broken
"#;
        let result: Result<GenesisConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn genesis_missing_chain_section() {
        let toml_str = r#"
bootstrap_nodes = []
"#;
        let result: Result<GenesisConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err(), "chain section is required");
    }

    #[test]
    fn genesis_missing_chain_id() {
        let toml_str = r#"
[chain]
block_time_secs = 5
"#;
        let result: Result<GenesisConfig, _> = toml::from_str(toml_str);
        assert!(result.is_err(), "chain_id is required");
    }

    #[test]
    fn genesis_zero_balance_account() {
        let toml_str = r#"
[chain]
chain_id = 1

[[accounts]]
address = "0x0000000000000000000000000000000000000001"
balance = 0
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();

        let addr = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(ns.state.balance(&addr), 0);
    }

    #[test]
    fn genesis_large_balance() {
        let toml_str = r#"
[chain]
chain_id = 1

[[accounts]]
address = "0x0000000000000000000000000000000000000001"
balance = 2100000000000000
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();

        let addr = parse_address("0x0000000000000000000000000000000000000001").unwrap();
        assert_eq!(ns.state.balance(&addr), 2_100_000_000_000_000); // 21M BTC
    }

    #[test]
    fn genesis_stake_cap_applied() {
        let toml_str = r#"
[chain]
chain_id = 1
initial_stake_cap = 5000000000

[[validators]]
address = "0x0000000000000000000000000000000000000001"
stake = 100000000
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();
        // StakingState should use the genesis stake cap
        assert_eq!(ns.staking.stake_cap, 5_000_000_000);
    }

    #[test]
    fn genesis_epoch_length_applied() {
        let toml_str = r#"
[chain]
chain_id = 1
epoch_length = 500
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();
        assert_eq!(ns.epoch.epoch_length, 500);
    }

    #[test]
    fn genesis_custom_block_time() {
        let toml_str = r#"
[chain]
chain_id = 1
block_time_secs = 10
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.chain.block_time_secs, 10);
    }

    #[test]
    fn genesis_custom_gas_limit() {
        let toml_str = r#"
[chain]
chain_id = 1
block_gas_limit = 50000000
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.chain.block_gas_limit, 50_000_000);
    }

    #[test]
    fn genesis_testnet_genesis_toml_loadable() {
        // Verify the actual testnet-genesis.toml is parseable
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap() // crates/
            .parent()
            .unwrap() // brrq/
            .join("testnet-genesis.toml");
        if path.exists() {
            let config = GenesisConfig::load(&path).unwrap();
            assert_eq!(config.chain.chain_id, 0xB77C_0001);
            assert_eq!(config.chain.block_time_secs, 3);
            assert_eq!(config.chain.epoch_length, 7200);
            assert_eq!(config.validators.len(), 2);
            assert_eq!(config.accounts.len(), 1);
            assert!(config.faucet.is_some());

            // Verify it can be applied
            let mut ns = NodeState::new();
            config.apply(&mut ns).unwrap();
            assert!(ns.staking.validators.len() >= 1);
        }
    }

    #[test]
    fn test_genesis_apply_sets_l1_network() {
        let toml_str = r#"
[chain]
chain_id = 1
l1_network = "regtest"
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        config.apply(&mut ns).unwrap();

        assert_eq!(ns.l1_network, Some("regtest".into()));
    }

    // ══════════════════════════════════════════════════════════════════
    // Zero-value validation tests
    // ══════════════════════════════════════════════════════════════════

    #[test]
    fn genesis_rejects_zero_epoch_length() {
        let toml_str = r#"
[chain]
chain_id = 1
epoch_length = 0
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        let err = config.apply(&mut ns).unwrap_err();
        assert!(err.contains("epoch_length"), "error should mention epoch_length: {}", err);
    }

    #[test]
    fn genesis_rejects_zero_block_time_secs() {
        let toml_str = r#"
[chain]
chain_id = 1
block_time_secs = 0
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        let err = config.apply(&mut ns).unwrap_err();
        assert!(
            err.contains("block_time_secs"),
            "error should mention block_time_secs: {}",
            err,
        );
    }

    #[test]
    fn genesis_rejects_zero_initial_stake_cap() {
        let toml_str = r#"
[chain]
chain_id = 1
initial_stake_cap = 0
"#;
        let config: GenesisConfig = toml::from_str(toml_str).unwrap();
        let mut ns = NodeState::new();
        let err = config.apply(&mut ns).unwrap_err();
        assert!(
            err.contains("initial_stake_cap"),
            "error should mention initial_stake_cap: {}",
            err,
        );
    }
}
