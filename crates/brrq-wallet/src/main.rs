//! Brrq CLI wallet and developer tools.
//!
//! A standalone command-line application for managing Brrq wallets,
//! sending transactions, and inspecting chain state.
//!
//! ## Usage
//!
//! ```bash
//! # Create a new wallet
//! brrq-wallet create-account --output wallet.json
//!
//! # Check balance
//! brrq-wallet balance 0x1234...
//!
//! # Send transfer
//! brrq-wallet send --keyfile wallet.json --to 0xabcd... --amount 1000 --gas-price 1
//!
//! # Query chain
//! brrq-wallet chain-info
//! brrq-wallet block-info latest
//! ```

mod display;
mod keystore;

use clap::{Parser, Subcommand};

use brrq_crypto::schnorr::SchnorrKeyPair;
use brrq_sdk::{BrrqClient, Wallet};
use brrq_types::address::Address;

use crate::display::*;
use crate::keystore::*;

/// Brrq CLI wallet & developer tools.
#[derive(Parser)]
#[command(
    name = "brrq-wallet",
    version,
    about = "Brrq CLI wallet & developer tools"
)]
struct Cli {
    /// RPC endpoint URL.
    #[arg(long, default_value = "http://localhost:8545")]
    rpc: String,

    /// Subcommand to execute.
    #[command(subcommand)]
    command: Commands,
}

/// Available CLI commands.
#[derive(Subcommand)]
enum Commands {
    /// Create a new wallet with a random keypair.
    CreateAccount {
        /// Output keyfile path.
        #[arg(long, default_value = "wallet.json")]
        output: String,

        /// Store private key WITHOUT encryption (dangerous, deprecated).
        /// Requires BRRQ_ALLOW_UNENCRYPTED_KEYS=true env var.
        #[arg(long, default_value_t = false)]
        plaintext: bool,
    },

    /// Import an existing secret key into a keyfile.
    ImportKey {
        /// Hex-encoded 32-byte secret key (with or without 0x prefix).
        secret: String,

        /// Output keyfile path.
        #[arg(long, default_value = "wallet.json")]
        output: String,

        /// Store private key WITHOUT encryption (dangerous, deprecated).
        /// Requires BRRQ_ALLOW_UNENCRYPTED_KEYS=true env var.
        #[arg(long, default_value_t = false)]
        plaintext: bool,
    },

    /// Show the address from a keyfile.
    ShowAddress {
        /// Path to the keyfile.
        #[arg(long, default_value = "wallet.json")]
        keyfile: String,
    },

    /// Query the balance of an address.
    Balance {
        /// Brrq address (hex with 0x prefix).
        address: String,
    },

    /// Send a transfer transaction.
    Send {
        /// Path to the sender's keyfile.
        #[arg(long, default_value = "wallet.json")]
        keyfile: String,

        /// Recipient address (hex).
        #[arg(long)]
        to: String,

        /// Amount in satoshis.
        #[arg(long)]
        amount: u64,

        /// Gas price in satoshis.
        /// Max fee per gas in satoshis.
        #[arg(long, default_value = "1")]
        max_fee_per_gas: u64,

        /// Max priority fee per gas in satoshis.
        #[arg(long, default_value = "1")]
        max_priority_fee_per_gas: u64,

        /// Gas limit.
        #[arg(long, default_value = "21000")]
        gas_limit: u64,
    },

    /// Deploy a smart contract.
    Deploy {
        /// Path to the sender's keyfile.
        #[arg(long, default_value = "wallet.json")]
        keyfile: String,

        /// Path to the binary contract code file.
        #[arg(long)]
        code_file: String,

        /// Gas price in satoshis.
        /// Max fee per gas in satoshis.
        #[arg(long, default_value = "1")]
        max_fee_per_gas: u64,

        /// Max priority fee per gas in satoshis.
        #[arg(long, default_value = "1")]
        max_priority_fee_per_gas: u64,

        /// Gas limit.
        #[arg(long, default_value = "500000")]
        gas_limit: u64,
    },

    /// Call a smart contract.
    Call {
        /// Path to the sender's keyfile.
        #[arg(long, default_value = "wallet.json")]
        keyfile: String,

        /// Contract address (hex).
        #[arg(long)]
        to: String,

        /// Hex-encoded calldata.
        #[arg(long, default_value = "")]
        data: String,

        /// Value to send (satoshis).
        #[arg(long, default_value = "0")]
        value: u64,

        /// Gas price in satoshis.
        /// Max fee per gas in satoshis.
        #[arg(long, default_value = "1")]
        max_fee_per_gas: u64,

        /// Max priority fee per gas in satoshis.
        #[arg(long, default_value = "1")]
        max_priority_fee_per_gas: u64,

        /// Gas limit.
        #[arg(long, default_value = "100000")]
        gas_limit: u64,
    },

    /// Get a transaction receipt by hash.
    GetReceipt {
        /// Transaction hash (hex with 0x prefix).
        tx_hash: String,
    },

    /// Get block information by height or "latest".
    BlockInfo {
        /// Block height or "latest".
        height: String,
    },

    /// Get account information.
    AccountInfo {
        /// Account address (hex).
        address: String,
    },

    /// Get the current state root.
    StateRoot,

    /// Get chain information (height, chain ID, validators).
    ChainInfo,

    /// Get a Merkle proof for an account.
    GetProof {
        /// Account address (hex).
        address: String,
    },

    /// Query event logs with filters.
    GetLogs {
        /// Start block height.
        #[arg(long, default_value = "1")]
        from_block: u64,

        /// End block height (0 = latest).
        #[arg(long, default_value = "0")]
        to_block: u64,

        /// Filter by contract address (hex, optional).
        #[arg(long)]
        address: Option<String>,

        /// Filter by topic (hex, optional).
        #[arg(long)]
        topic: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = BrrqClient::new(&cli.rpc);

    match cli.command {
        Commands::CreateAccount { output, plaintext } => cmd_create_account(&output, plaintext),
        Commands::ImportKey {
            secret,
            output,
            plaintext,
        } => cmd_import_key(&secret, &output, plaintext),
        Commands::ShowAddress { keyfile } => cmd_show_address(&keyfile),
        Commands::Balance { address } => cmd_balance(&client, &address).await,
        Commands::Send {
            keyfile,
            to,
            amount,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            gas_limit,
        } => {
            cmd_send(
                &client,
                &keyfile,
                &to,
                amount,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                gas_limit,
            )
            .await
        }
        Commands::Deploy {
            keyfile,
            code_file,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            gas_limit,
        } => {
            cmd_deploy(
                &client,
                &keyfile,
                &code_file,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                gas_limit,
            )
            .await
        }
        Commands::Call {
            keyfile,
            to,
            data,
            value,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            gas_limit,
        } => {
            cmd_call(
                &client,
                &keyfile,
                &to,
                &data,
                value,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                gas_limit,
            )
            .await
        }
        Commands::GetReceipt { tx_hash } => cmd_get_receipt(&client, &tx_hash).await,
        Commands::BlockInfo { height } => cmd_block_info(&client, &height).await,
        Commands::AccountInfo { address } => cmd_account_info(&client, &address).await,
        Commands::StateRoot => cmd_state_root(&client).await,
        Commands::ChainInfo => cmd_chain_info(&client).await,
        Commands::GetProof { address } => cmd_get_proof(&client, &address).await,
        Commands::GetLogs {
            from_block,
            to_block,
            address,
            topic,
        } => cmd_get_logs(&client, from_block, to_block, address, topic).await,
    }
}

// ── Password Prompting ───────────────────────────────────────────────────

/// Name of the environment variable for non-interactive password supply.
const ENV_WALLET_PASSWORD: &str = "BRRQ_WALLET_PASSWORD";

/// Prompt the user for an encryption password (with confirmation).
///
/// Reads from `BRRQ_WALLET_PASSWORD` env var if set (for CI / scripts),
/// otherwise uses `rpassword` to read from the terminal without echo.
/// Returns `None` only if the user explicitly cancels (Ctrl-C is handled
/// by the OS signal).
fn prompt_password_with_confirm() -> Result<Vec<u8>, String> {
    // 1. Check environment variable first (CI / non-interactive mode).
    if let Ok(pw) = std::env::var(ENV_WALLET_PASSWORD) {
        if pw.is_empty() {
            return Err(format!(
                "{ENV_WALLET_PASSWORD} is set but empty — provide a non-empty password."
            ));
        }
        return Ok(pw.into_bytes());
    }

    // 2. Interactive terminal prompt.
    let pw1 = rpassword::prompt_password("Enter encryption password: ")
        .map_err(|e| format!("failed to read password: {e}"))?;
    if pw1.is_empty() {
        return Err("password must not be empty — encryption is mandatory.".to_string());
    }

    if pw1.len() < 8 {
        eprintln!("WARNING: Password is shorter than 8 characters. Consider using a stronger password.");
    }

    let pw2 = rpassword::prompt_password("Confirm encryption password: ")
        .map_err(|e| format!("failed to read password confirmation: {e}"))?;
    if pw1 != pw2 {
        return Err("passwords do not match.".to_string());
    }

    Ok(pw1.into_bytes())
}

/// Prompt the user for a decryption password (no confirmation needed).
fn prompt_password_decrypt() -> Result<Vec<u8>, String> {
    if let Ok(pw) = std::env::var(ENV_WALLET_PASSWORD) {
        if pw.is_empty() {
            return Err(format!(
                "{ENV_WALLET_PASSWORD} is set but empty — provide a non-empty password."
            ));
        }
        return Ok(pw.into_bytes());
    }

    let pw = rpassword::prompt_password("Enter keyfile password: ")
        .map_err(|e| format!("failed to read password: {e}"))?;
    Ok(pw.into_bytes())
}

// ── Command Implementations ──────────────────────────────────────────────

fn cmd_create_account(output: &str, plaintext: bool) {
    let keys = SchnorrKeyPair::generate();
    let address = Address::from_public_key(keys.public_key().as_bytes());
    // SecretBytes auto-zeroizes on drop — no manual wipe needed
    let secret = keys.secret_bytes();
    let addr_hex = format!("0x{}", hex::encode(address.as_bytes()));
    let pk_hex = format!("0x{}", hex::encode(keys.public_key().as_bytes()));

    let result = if plaintext {
        save_keyfile_plaintext(output, &secret, &addr_hex, &pk_hex, true)
    } else {
        let password = match prompt_password_with_confirm() {
            Ok(pw) => pw,
            Err(e) => {
                eprintln!("Error: {e}");
                return;
            }
        };
        save_keyfile(output, &secret, &addr_hex, &pk_hex, &password)
    };

    match result {
        Ok(()) => {
            println!("Wallet created successfully!");
            println!("  Address:    {addr_hex}");
            println!("  Public Key: {pk_hex}");
            println!("  Saved to:   {output}");
            if !plaintext {
                println!("  Encrypted:  yes (balloon-hash KDF v2)");
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
    // `secret` dropped here → auto-zeroized
}

fn cmd_import_key(secret_hex: &str, output: &str, plaintext: bool) {
    let hex_str = secret_hex.strip_prefix("0x").unwrap_or(secret_hex);
    let mut bytes = match hex::decode(hex_str) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            eprintln!("Error: invalid secret key (expected 32-byte hex)");
            return;
        }
    };

    let wallet = match Wallet::from_secret(&bytes) {
        Ok(w) => w,
        Err(e) => {
            bytes.fill(0);
            eprintln!("Error: failed to create wallet: {e}");
            return;
        }
    };

    let addr_hex = format!("0x{}", hex::encode(wallet.address().as_bytes()));
    let pk_hex = format!("0x{}", hex::encode(wallet.public_key_bytes()));

    let result = if plaintext {
        save_keyfile_plaintext(output, &bytes, &addr_hex, &pk_hex, true)
    } else {
        let password = match prompt_password_with_confirm() {
            Ok(pw) => pw,
            Err(e) => {
                bytes.fill(0);
                eprintln!("Error: {e}");
                return;
            }
        };
        save_keyfile(output, &bytes, &addr_hex, &pk_hex, &password)
    };

    match result {
        Ok(()) => {
            bytes.fill(0);
            println!("Key imported successfully!");
            println!("  Address: {addr_hex}");
            println!("  Saved to: {output}");
            if !plaintext {
                println!("  Encrypted: yes (balloon-hash KDF v2)");
            }
        }
        Err(e) => {
            bytes.fill(0);
            eprintln!("Error: {e}");
        }
    }
}

fn cmd_show_address(keyfile: &str) {
    match load_keyfile(keyfile) {
        Ok(kf) => {
            println!("Address:    {}", kf.address);
            println!("Public Key: {}", kf.public_key);
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}

async fn cmd_balance(client: &BrrqClient, address_hex: &str) {
    let address = match parse_cli_address(address_hex) {
        Some(a) => a,
        None => {
            eprintln!("Error: invalid address format");
            return;
        }
    };

    match client.get_balance(&address).await {
        Ok(balance) => {
            let addr = format_hash(address_hex);
            println!("Balance of {addr}: {}", format_balance(balance));
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}

async fn cmd_send(
    client: &BrrqClient,
    keyfile: &str,
    to_hex: &str,
    amount: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
) {
    let kf = match load_keyfile(keyfile) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("Error loading keyfile: {e}");
            return;
        }
    };

    let password = if kf.encrypted {
        match prompt_password_decrypt() {
            Ok(pw) => pw,
            Err(e) => {
                eprintln!("Error: {e}");
                return;
            }
        }
    } else {
        Vec::new()
    };

    let mut secret = match extract_secret(&kf, &password) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            return;
        }
    };

    let mut wallet = match Wallet::from_secret(&secret) {
        Ok(w) => w,
        Err(e) => {
            secret.fill(0);
            eprintln!("Error creating wallet: {e}");
            return;
        }
    };

    // Secret consumed by wallet — zeroize immediately.
    secret.fill(0);

    let to = match parse_cli_address(to_hex) {
        Some(a) => a,
        None => {
            eprintln!("Error: invalid 'to' address");
            return;
        }
    };

    // Fetch current nonce
    match client.get_nonce(wallet.address()).await {
        Ok(nonce) => { let _ = wallet.set_nonce(nonce); },
        Err(e) => {
            eprintln!("Error fetching nonce: {e}");
            return;
        }
    }

    // Build and sign transaction
    let tx = match wallet.transfer(
        to,
        amount,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Error building transaction: {e}");
            return;
        }
    };

    // Send
    match client.send_transaction(&tx).await {
        Ok(hash) => {
            let hash_hex = format!("0x{}", hex::encode(hash.as_bytes()));
            println!("Transaction sent!");
            println!("  Hash:   {hash_hex}");
            println!("  From:   {}", kf.address);
            println!("  To:     {to_hex}");
            println!("  Amount: {}", format_balance(amount));
        }
        Err(e) => eprintln!("Error sending transaction: {e}"),
    }
}

async fn cmd_deploy(
    client: &BrrqClient,
    keyfile: &str,
    code_file: &str,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
) {
    let kf = match load_keyfile(keyfile) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("Error loading keyfile: {e}");
            return;
        }
    };

    let password = if kf.encrypted {
        match prompt_password_decrypt() {
            Ok(pw) => pw,
            Err(e) => {
                eprintln!("Error: {e}");
                return;
            }
        }
    } else {
        Vec::new()
    };

    let mut secret = match extract_secret(&kf, &password) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            return;
        }
    };

    let mut wallet = match Wallet::from_secret(&secret) {
        Ok(w) => w,
        Err(e) => {
            secret.fill(0);
            eprintln!("Error creating wallet: {e}");
            return;
        }
    };

    // Secret consumed by wallet — zeroize immediately.
    secret.fill(0);

    // Read contract code from file
    let code = match std::fs::read(code_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading code file {code_file}: {e}");
            return;
        }
    };

    // Fetch nonce
    match client.get_nonce(wallet.address()).await {
        Ok(nonce) => { let _ = wallet.set_nonce(nonce); },
        Err(e) => {
            eprintln!("Error fetching nonce: {e}");
            return;
        }
    }

    let tx = match wallet.deploy(
        code.clone(),
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Error building deploy transaction: {e}");
            return;
        }
    };

    match client.send_transaction(&tx).await {
        Ok(hash) => {
            let hash_hex = format!("0x{}", hex::encode(hash.as_bytes()));
            println!("Contract deployment submitted!");
            println!("  Hash:      {hash_hex}");
            println!("  From:      {}", kf.address);
            println!("  Code Size: {} bytes", code.len());
        }
        Err(e) => eprintln!("Error deploying contract: {e}"),
    }
}

async fn cmd_call(
    client: &BrrqClient,
    keyfile: &str,
    to_hex: &str,
    data_hex: &str,
    value: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
) {
    let kf = match load_keyfile(keyfile) {
        Ok(kf) => kf,
        Err(e) => {
            eprintln!("Error loading keyfile: {e}");
            return;
        }
    };

    let password = if kf.encrypted {
        match prompt_password_decrypt() {
            Ok(pw) => pw,
            Err(e) => {
                eprintln!("Error: {e}");
                return;
            }
        }
    } else {
        Vec::new()
    };

    let mut secret = match extract_secret(&kf, &password) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: {e}");
            return;
        }
    };

    let mut wallet = match Wallet::from_secret(&secret) {
        Ok(w) => w,
        Err(e) => {
            secret.fill(0);
            eprintln!("Error creating wallet: {e}");
            return;
        }
    };

    // Secret consumed by wallet — zeroize immediately.
    secret.fill(0);

    let to = match parse_cli_address(to_hex) {
        Some(a) => a,
        None => {
            eprintln!("Error: invalid contract address");
            return;
        }
    };

    let data_clean = data_hex.strip_prefix("0x").unwrap_or(data_hex);
    let data = if data_clean.is_empty() {
        Vec::new()
    } else {
        match hex::decode(data_clean) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Error: invalid calldata hex: {e}");
                return;
            }
        }
    };

    match client.get_nonce(wallet.address()).await {
        Ok(nonce) => { let _ = wallet.set_nonce(nonce); },
        Err(e) => {
            eprintln!("Error fetching nonce: {e}");
            return;
        }
    }

    let tx = match wallet.call_contract(
        to,
        data,
        value,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("Error building contract call: {e}");
            return;
        }
    };

    match client.send_transaction(&tx).await {
        Ok(hash) => {
            let hash_hex = format!("0x{}", hex::encode(hash.as_bytes()));
            println!("Contract call submitted!");
            println!("  Hash: {hash_hex}");
            println!("  To:   {to_hex}");
        }
        Err(e) => eprintln!("Error calling contract: {e}"),
    }
}

async fn cmd_get_receipt(client: &BrrqClient, hash_hex: &str) {
    let hash = match parse_cli_hash(hash_hex) {
        Some(h) => h,
        None => {
            eprintln!("Error: invalid transaction hash");
            return;
        }
    };

    match client.get_transaction_receipt(&hash).await {
        Ok(Some(receipt)) => {
            let json = serde_json::json!({
                "block_height": receipt.block_height,
                "gas_used": receipt.gas_used,
                "success": receipt.success,
                "block_hash": "unknown",
            });
            println!("{}", format_receipt(&json));
        }
        Ok(None) => println!("Receipt not found for {hash_hex}"),
        Err(e) => eprintln!("Error: {e}"),
    }
}

async fn cmd_block_info(client: &BrrqClient, height_str: &str) {
    let result = if height_str == "latest" {
        client.get_latest_block().await
    } else {
        match height_str.parse::<u64>() {
            Ok(h) => client.get_block(h).await,
            Err(_) => {
                eprintln!("Error: invalid block height (expected number or 'latest')");
                return;
            }
        }
    };

    match result {
        Ok(Some(block)) => println!("{}", format_block_info(&block)),
        Ok(None) => println!("Block not found"),
        Err(e) => eprintln!("Error: {e}"),
    }
}

async fn cmd_account_info(client: &BrrqClient, address_hex: &str) {
    let address = match parse_cli_address(address_hex) {
        Some(a) => a,
        None => {
            eprintln!("Error: invalid address format");
            return;
        }
    };

    match client.get_account(&address).await {
        Ok(Some(account)) => println!("{}", format_account_info(&account)),
        Ok(None) => println!("Account not found: {address_hex}"),
        Err(e) => eprintln!("Error: {e}"),
    }
}

async fn cmd_state_root(client: &BrrqClient) {
    match client.get_state_root().await {
        Ok(root) => println!("State Root: {root}"),
        Err(e) => eprintln!("Error: {e}"),
    }
}

async fn cmd_chain_info(client: &BrrqClient) {
    // Fetch height, chain_id, and validators in parallel
    let height = client.get_block_height().await;
    let chain_id = client.get_chain_id().await;
    let epoch = client.get_epoch_info().await;

    println!("Chain Info");
    match height {
        Ok(h) => println!("  Height:   {h}"),
        Err(e) => println!("  Height:   Error ({e})"),
    }
    match chain_id {
        Ok(id) => println!("  Chain ID: {id:#X}"),
        Err(e) => println!("  Chain ID: Error ({e})"),
    }
    match epoch {
        Ok(info) => {
            let epoch_num = info["current_epoch"].as_u64().unwrap_or(0);
            let epoch_len = info["epoch_length"].as_u64().unwrap_or(0);
            println!("  Epoch:    {epoch_num} (length: {epoch_len})");
        }
        Err(e) => println!("  Epoch:    Error ({e})"),
    }
}

async fn cmd_get_proof(client: &BrrqClient, address_hex: &str) {
    let address = match parse_cli_address(address_hex) {
        Some(a) => a,
        None => {
            eprintln!("Error: invalid address format");
            return;
        }
    };

    match client.get_account_proof(&address).await {
        Ok(proof) => {
            println!("Account Proof for {}", format_hash(address_hex));
            let exists = proof["exists"].as_bool().unwrap_or(false);
            println!("  Exists:     {exists}");
            println!(
                "  State Root: {}",
                proof["state_root"].as_str().unwrap_or("unknown")
            );
            if let Some(siblings) = proof["proof"]["siblings"].as_array() {
                println!("  Siblings:   {} nodes", siblings.len());
            }
        }
        Err(e) => eprintln!("Error: {e}"),
    }
}

async fn cmd_get_logs(
    _client: &BrrqClient,
    from_block: u64,
    to_block: u64,
    address: Option<String>,
    topic: Option<String>,
) {
    let mut params = serde_json::Map::new();
    params.insert("from_block".into(), serde_json::json!(from_block));
    if to_block > 0 {
        params.insert("to_block".into(), serde_json::json!(to_block));
    }
    if let Some(addr) = &address {
        params.insert("address".into(), serde_json::json!(addr));
    }
    if let Some(t) = &topic {
        params.insert("topics".into(), serde_json::json!([t]));
    }

    // Use raw RPC call for getLogs
    println!(
        "Querying logs from block {from_block} to {}",
        if to_block > 0 {
            format!("{to_block}")
        } else {
            "latest".to_string()
        }
    );
    if let Some(addr) = &address {
        println!("  Address filter: {addr}");
    }
    if let Some(t) = &topic {
        println!("  Topic filter:   {t}");
    }
    println!("  (Use RPC endpoint directly for full log query support)");
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Parse a hex address string to an Address.
fn parse_cli_address(s: &str) -> Option<Address> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Some(Address::from_bytes(arr))
}

/// Parse a hex hash string to a Hash256.
fn parse_cli_hash(s: &str) -> Option<brrq_crypto::hash::Hash256> {
    let hex_str = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(brrq_crypto::hash::Hash256::from_bytes(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parse_balance() {
        // Verify that the Balance subcommand parses correctly
        let cli = Cli::parse_from([
            "brrq-wallet",
            "balance",
            "0xaabbccdd00112233445566778899aabbccddeeff",
        ]);

        match cli.command {
            Commands::Balance { address } => {
                assert_eq!(address, "0xaabbccdd00112233445566778899aabbccddeeff");
            }
            _ => panic!("expected Balance command"),
        }
    }

    #[test]
    fn test_cli_parse_send() {
        let cli = Cli::parse_from([
            "brrq-wallet",
            "send",
            "--to",
            "0xaabbccdd00112233445566778899aabbccddeeff",
            "--amount",
            "50000",
            "--max-fee-per-gas",
            "2",
        ]);

        match cli.command {
            Commands::Send {
                to,
                amount,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                gas_limit,
                keyfile,
            } => {
                assert_eq!(to, "0xaabbccdd00112233445566778899aabbccddeeff");
                assert_eq!(amount, 50000);
                assert_eq!(max_fee_per_gas, 2);
                assert_eq!(max_priority_fee_per_gas, 1);
                assert_eq!(gas_limit, 21000); // default
                assert_eq!(keyfile, "wallet.json"); // default
            }
            _ => panic!("expected Send command"),
        }
    }

    #[test]
    fn test_cli_parse_create_account() {
        let cli = Cli::parse_from([
            "brrq-wallet",
            "create-account",
            "--output",
            "my_wallet.json",
        ]);
        match cli.command {
            Commands::CreateAccount { output, plaintext } => {
                assert_eq!(output, "my_wallet.json");
                assert!(!plaintext);
            }
            _ => panic!("expected CreateAccount command"),
        }
    }

    #[test]
    fn test_parse_cli_address_valid() {
        let addr = parse_cli_address("0xaabbccdd00112233445566778899aabbccddeeff");
        assert!(addr.is_some());
    }

    #[test]
    fn test_parse_cli_address_invalid() {
        let addr = parse_cli_address("0xaabb");
        assert!(addr.is_none());
    }

    #[test]
    fn test_parse_cli_hash_valid() {
        let hash_hex = "0x".to_string() + &"ab".repeat(32);
        let hash = parse_cli_hash(&hash_hex);
        assert!(hash.is_some());
    }
}
