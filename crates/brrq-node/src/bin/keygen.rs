//! Key generation utility for Brrq validators.
//!
//! Generates a new set of validator keys (Schnorr, EOTS, SLH-DSA) and prints
//! them in a format suitable for `mainnet-genesis.toml` and `validator-keys.json`.
//!
//! Usage:
//!   cargo run --bin keygen --features dev-mode -p brrq-node

use brrq_sequencer::block_builder::SequencerKeys;

fn main() {
    let keys = SequencerKeys::generate().expect("key generation failed");

    let address = keys.address;
    let eots_pubkey = hex::encode(keys.eots_key.public_key().as_bytes());
    let slh_dsa_pubkey = hex::encode(keys.slh_dsa.public_key().as_bytes());
    let secret = keys.main_key.secret_bytes();
    let main_secret = hex::encode(&*secret);

    println!("# Brrq Validator Keys");
    println!("# WARNING: Keep main_key_secret SAFE. Anyone with it controls your validator.");
    println!();
    println!("address = \"{}\"", address);
    println!("eots_pubkey = \"{}\"", eots_pubkey);
    println!("slh_dsa_pubkey = \"{}\"", slh_dsa_pubkey);
    println!();
    println!("# For validator-keys.json (DO NOT share):");
    println!(
        "# {{\"main_key_secret\": \"{}\", \"address\": \"{}\"}}",
        main_secret, address
    );
}
