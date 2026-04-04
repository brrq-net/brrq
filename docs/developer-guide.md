# Brrq Developer Guide

Complete guide for building on Brrq — a Bitcoin L2 with Hash-First Architecture.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Running a Node](#2-running-a-node)
3. [Using the TypeScript SDK](#3-using-the-typescript-sdk)
4. [Using the Rust SDK](#4-using-the-rust-sdk)
5. [Writing Smart Contracts](#5-writing-smart-contracts)
6. [Contract SDK Reference](#6-contract-sdk-reference)
7. [API Reference](#7-api-reference)
8. [WebSocket Events](#8-websocket-events)
9. [Gas & Fees](#9-gas--fees)
10. [Architecture Overview](#10-architecture-overview)

---

## 1. Getting Started

### Prerequisites

- **Rust** 1.88.0 (pinned in `rust-toolchain.toml`, installed automatically by `rustup`)
- **Node.js** 22+ (for TypeScript SDK)
- **Docker** (optional, for multi-node testnet)

### Quick Start

```bash
# Clone and build
git clone https://github.com/brrq-net/brrq.git
cd brrq
cargo build --release

# Start a testnet node
./target/release/brrq-node \
  --network testnet \
  --sequencer \
  --rpc-port 8545 \
  --p2p-port 30303 \
  --datadir ./data \
  --genesis testnet-genesis.toml

# Get testnet tokens
curl -X POST http://localhost:8545/api/v1/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "0x<your-address>"}'
```

### Testnet Parameters

| Parameter          | Value                          |
|--------------------|--------------------------------|
| Chain ID           | `0xB77C0001` (3078356993)      |
| Block Time         | 3 seconds                      |
| Epoch Length        | 7,200 blocks (~6 hours)        |
| Faucet Drip        | 1 BTC (100,000,000 satoshis)   |
| Faucet Cooldown    | 1 hour per address             |
| Max Contract Size  | 24 KB                          |
| Max Calldata       | 128 KB                         |

---

## 2. Running a Node

### Single Node (Development)

```bash
./target/release/brrq-node \
  --network testnet \
  --sequencer \
  --rpc-port 8545 \
  --p2p-port 30303 \
  --datadir ./data \
  --genesis testnet-genesis.toml
```

### Multi-Node Testnet (Docker)

```bash
docker compose -f docker/docker-compose.testnet.yml up
```

This starts 3 nodes:
- **node-0** (sequencer): `http://localhost:8545`
- **node-1** (follower): `http://localhost:8546`
- **node-2** (follower): `http://localhost:8547`

### Node Health Check

```bash
curl http://localhost:8545/api/v1/health
# {"status":"ok","height":42,"peer_count":2}
```

---

## 3. Using the TypeScript SDK

### Installation

```bash
# Copy SDK from the repository
cp -r packages/brrq-sdk-ts /path/to/your-project/brrq-sdk
```

### Create a Wallet

```typescript
import { Wallet, BrrqClient } from '@brrq/sdk';

// Generate a new wallet
const wallet = Wallet.generate();
console.log('Address:', wallet.address);
console.log('Public Key:', wallet.publicKey);

// Or restore from secret key
const restored = Wallet.fromSecret(secretBytes);
```

### Send a Transfer

```typescript
const client = new BrrqClient('http://localhost:8545');

// Get testnet tokens first
await client.faucetDrip(wallet.address);

// Wait for faucet TX to be mined (~3 seconds)
await new Promise(r => setTimeout(r, 4000));

// Check balance
const balance = await client.getBalance(wallet.address);
console.log('Balance:', balance, 'satoshis');

// Send 1000 satoshis
const tx = wallet.transfer(recipientAddress, 1000n, {
  maxFeePerGas: 1n,
  gasLimit: 21000n,
});

const txHash = await client.sendTransaction(tx);
console.log('TX Hash:', txHash);
```

### Deploy a Contract

```typescript
// Read compiled RISC-V binary
const code = fs.readFileSync('contract.bin');

const deployTx = wallet.deploy(code, {
  maxFeePerGas: 1n,
  gasLimit: 500000n,
});

const deployHash = await client.sendTransaction(deployTx);
// Contract address = SHA-256(deployer || nonce)[0..20]
```

### Call a Contract

```typescript
// Build calldata: [selector:4][args...]
const calldata = new Uint8Array([
  0x02, 0x00, 0x00, 0x00,  // selector: balance_of
  ...addressBytes,           // 20-byte address argument
]);

const callTx = wallet.callContract(contractAddress, calldata, 0n, {
  maxFeePerGas: 1n,
  gasLimit: 100000n,
});

const callHash = await client.sendTransaction(callTx);
```

### WebSocket Subscriptions

```typescript
import { WebSocketClient } from '@brrq/sdk';

const ws = new WebSocketClient('ws://localhost:8545/ws');

// Subscribe to new blocks
ws.subscribe('newBlocks', (block) => {
  console.log('New block:', block.height, 'txs:', block.transactions.length);
});

// Subscribe to pending transactions
ws.subscribe('pendingTxs', (tx) => {
  console.log('Pending TX:', tx.hash);
});

// Subscribe to new STARK proofs
ws.subscribe('newProofs', (proof) => {
  console.log('New proof for blocks:', proof.startHeight, '-', proof.endHeight);
});
```

---

## 4. Using the Rust SDK

### Add Dependency

```toml
[dependencies]
brrq-sdk = { git = "https://github.com/brrq-net/brrq.git" }
```

### Create and Send Transactions

```rust
use brrq_sdk::{Wallet, Client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create wallet
    let mut wallet = Wallet::new();
    println!("Address: {}", wallet.address());

    // Connect to node
    let client = Client::new("127.0.0.1:8545");

    // Get balance
    let balance = client.get_balance(wallet.address()).await?;
    println!("Balance: {} satoshis", balance);

    // Send transfer
    wallet.set_nonce(client.get_nonce(wallet.address()).await?);
    let tx = wallet.transfer(
        recipient,
        1000,   // amount in satoshis
        1,      // max_fee_per_gas
        21_000, // gas_limit
    )?;

    let hash = client.send_transaction(&tx).await?;
    println!("TX: {:?}", hash);

    Ok(())
}
```

### Deploy a Contract

```rust
let code = std::fs::read("contract.bin")?;
let tx = wallet.deploy(code, 1, 500_000)?; // (code, max_fee_per_gas, gas_limit)
let hash = client.send_transaction(&tx).await?;
```

### Call a Contract

```rust
// Build calldata
let mut calldata = vec![0x01, 0x00, 0x00, 0x00]; // selector
calldata.extend_from_slice(&recipient_address);    // to
calldata.extend_from_slice(&amount.to_le_bytes()); // amount

let tx = wallet.call_contract(
    contract_address,
    calldata,
    0,       // value
    1,       // max_fee_per_gas
    100_000, // gas_limit
)?;
```

---

## 5. Writing Smart Contracts

Brrq smart contracts are **RISC-V 32-bit binaries** (RV32IM instruction set) that run on the Brrq zkVM. Contracts are written in Rust, compiled to `riscv32im-unknown-none-elf`, and deployed as raw bytecode.

> **Note:** Smart contract deployment is available on testnet. No production contracts have been deployed yet. The contract SDK is functional but should be considered experimental.

### Project Setup

```bash
# Install RISC-V target
rustup target add riscv32im-unknown-none-elf

# Create new contract project
cargo new --bin my-contract
cd my-contract
```

**Cargo.toml:**
```toml
[package]
name = "my-contract"
version = "0.1.0"
edition = "2024"

[dependencies]
brrq-contract-sdk = { path = "../brrq/contracts/brrq-contract-sdk" }

[profile.release]
opt-level = "s"      # Optimize for size (24 KB limit)
lto = true
panic = "abort"
strip = true
```

### Minimal Contract

```rust
#![no_std]
#![no_main]

use brrq_contract_sdk::*;

#[no_mangle]
pub extern "C" fn _start() {
    let selector = calldata_selector();

    match selector {
        // store(key: [u8;32], value: [u8;32])
        0x01 => {
            let key = calldata_hash(4);
            let value = calldata_hash(36);
            sstore(&key, &value);
            halt(0);
        }

        // load(key: [u8;32]) -> [u8;32]
        0x02 => {
            let key = calldata_hash(4);
            let (value, _exists) = sload(&key);
            write_output(&value);
            halt(0);
        }

        _ => halt(1), // Unknown function
    }
}
```

### Build & Deploy

```bash
# Build for RISC-V
cargo build --release --target riscv32im-unknown-none-elf

# Extract raw binary (strip ELF headers)
llvm-objcopy -O binary \
  target/riscv32im-unknown-none-elf/release/my-contract \
  my-contract.bin

# Check size (must be < 24 KB)
ls -la my-contract.bin

# Deploy via SDK
```

### Calldata Convention

Calldata is mapped to a fixed memory region accessible via the SDK:

```
[4 bytes: function selector (LE u32)]
[variable: function arguments]
[20 bytes: msg.sender (appended by sequencer)]
```

The function selector is a little-endian `u32` identifying which function to call. Arguments follow in a packed format (no padding between fields).

### Storage Model

Each contract has its own isolated key-value storage (Sparse Merkle Tree):
- **Keys**: 32 bytes (derived using `storage_slot(prefix, key)`)
- **Values**: 32 bytes
- **Gas**: 200 for reads (SLOAD), 5,000-20,000 for writes (SSTORE)

Use the `storage_slot()` helper to derive unique storage keys:

```rust
// Balance mapping: slot_prefix=0, key=address
let key = storage_slot(0, &user_address);
let (balance_bytes, exists) = sload(&key);
let balance = value_to_u64(&balance_bytes);
```

### Event Logging

Contracts can emit structured events (similar to Ethereum logs):

```rust
// Transfer event with 3 indexed topics + data
let mut from_topic = [0u8; 32];
from_topic[0..20].copy_from_slice(&from_address);

let mut to_topic = [0u8; 32];
to_topic[0..20].copy_from_slice(&to_address);

emit_log(
    &[TOPIC_TRANSFER, from_topic, to_topic],  // 0-4 indexed topics
    &amount.to_le_bytes(),                      // non-indexed data
);
```

### Exit Codes

| Code | Meaning            |
|------|--------------------|
| 0    | Success            |
| 1    | Unknown function   |
| 2    | Unauthorized       |
| 3    | Insufficient funds |
| 4    | Invalid argument   |
| 0xFF | Panic (abort)      |

---

## 6. Contract SDK Reference

### Storage

| Function                          | Gas    | Description                    |
|-----------------------------------|--------|--------------------------------|
| `sload(key) -> (value, exists)`   | 200    | Read 32-byte storage slot      |
| `sstore(key, value)`             | 5K-20K | Write 32-byte storage slot     |
| `storage_slot(prefix, key) -> key`| 0      | Derive storage key             |

### Execution

| Function              | Description                          |
|-----------------------|--------------------------------------|
| `halt(code)`          | Stop execution (0=success)           |
| `write_output(data)`  | Return data to caller                |

### Cryptography

| Function                                | Gas  | Description                 |
|-----------------------------------------|------|-----------------------------|
| `sha256_compress(input, output)`        | 50   | SHA-256 compression         |
| `schnorr_verify(msg, sig, pk) -> bool`  | 100  | BIP-340 Schnorr verify      |
| `slh_dsa_verify(msg, sig, pk) -> bool`  | 500  | FIPS 205 SLH-DSA verify     |
| `merkle_verify(root,leaf,proof,d)->bool`| 30+5d| Merkle proof verify         |

### Events

| Function                     | Gas         | Description            |
|------------------------------|-------------|------------------------|
| `emit_log(topics, data)`     | 20+10t+1d   | Emit event (t=topics)  |

### ABI Helpers

| Function                    | Description                        |
|-----------------------------|------------------------------------|
| `calldata_selector() -> u32`| Read 4-byte function selector      |
| `calldata_read(offset, buf)`| Read bytes from calldata           |
| `calldata_u64(offset) -> u64`| Read u64 from calldata            |
| `calldata_address(offset)`  | Read 20-byte address               |
| `calldata_hash(offset)`     | Read 32-byte hash                  |
| `u64_to_value(val)`         | Encode u64 as storage value        |
| `value_to_u64(val)`         | Decode u64 from storage value      |
| `address_to_value(addr)`    | Encode address as storage value    |
| `value_to_address(val)`     | Decode address from storage value  |

---

## 7. API Reference

### JSON-RPC 2.0 (POST http://localhost:8545)

```json
{"jsonrpc":"2.0","method":"brrq_blockHeight","params":[],"id":1}
```

| Method                    | Params                     | Returns              |
|---------------------------|----------------------------|----------------------|
| `brrq_blockHeight`        | —                          | `u64`                |
| `brrq_getBalance`         | `[address]`                | `u64` (satoshis)     |
| `brrq_getNonce`           | `[address]`                | `u64`                |
| `brrq_chainId`            | —                          | `{ chain_id: number }`|
| `brrq_getAccount`         | `[address]`                | `Account \| null`    |
| `brrq_getBlock`           | `[height]`                 | `Block \| null`      |
| `brrq_getBlockByHash`     | `[hash]`                   | `Block \| null`      |
| `brrq_getTransaction`     | `[hash]`                   | `Transaction \| null`|
| `brrq_sendTransaction`    | `[signed_tx]`              | `hash`               |
| `brrq_getCode`            | `[address]`                | `hex \| null`        |
| `brrq_getStorageAt`       | `[address, key]`           | `hex \| null`        |
| `brrq_getStateRoot`       | —                          | `hash`               |
| `brrq_faucetDrip`         | `[address]`                | `hash`               |

### REST API

| Endpoint                         | Method | Description              |
|----------------------------------|--------|--------------------------|
| `/api/v1/health`                 | GET    | Node health status       |
| `/api/v1/stats`                  | GET    | Network statistics       |
| `/api/v1/blocks?offset=0&limit=20` | GET | List blocks (paginated)  |
| `/api/v1/blocks/{height}`        | GET    | Get block by height      |
| `/api/v1/transactions/{hash}`    | GET    | Get transaction          |
| `/api/v1/accounts/{address}`     | GET    | Get account info         |
| `/api/v1/accounts/{address}/balance` | GET | Get balance          |
| `/api/v1/validators`             | GET    | List validators          |
| `/api/v1/faucet`                 | POST   | Request testnet tokens   |

### Example: Get Network Stats

```bash
curl http://localhost:8545/api/v1/stats
```

```json
{
  "block_height": 1234,
  "transaction_count": 5678,
  "validator_count": 3,
  "total_stake": 10000000000,
  "mempool_size": 12,
  "proof_count": 41
}
```

---

## 8. WebSocket Events

Connect to `ws://localhost:8545/ws` and subscribe to topics:

```json
{"subscribe":["newBlocks"]}
```

### Topics

| Topic                | Payload                                        |
|----------------------|------------------------------------------------|
| `newBlocks`          | `{height, hash, tx_count, gas_used, timestamp}`|
| `pendingTxs`         | `{tx_hash, from, to, value, nonce}`             |
| `newProofs`          | `{proof_id, start_height, end_height, root}`   |

---

## 9. Gas & Fees

### Transaction Gas

| Operation           | Gas Cost  |
|---------------------|-----------|
| Transfer (base)     | 21,000    |
| Contract deploy     | 32,000 + 200/byte |
| Contract call       | 21,000 + execution |
| Calldata byte       | 16 (non-zero), 4 (zero) |

### VM Instruction Gas

| Instruction Type         | Cost |
|--------------------------|------|
| ALU (ADD, SUB, AND, OR)  | 1    |
| Multiply (MUL, MULH)     | 2    |
| Division (DIV, REM)      | 3    |
| Load (LW, LH, LB)       | 5    |
| Store (SW, SH, SB)       | 7    |
| Branch / Jump            | 2    |
| System call (ECALL)      | 10   |

### Precompile Gas

| Precompile     | Gas Cost                    |
|----------------|-----------------------------|
| SHA256         | 50                          |
| Merkle Verify  | 30 + 5 per level            |
| Schnorr Verify | 100                         |
| SLH-DSA Verify | 500                         |
| SLOAD          | 200                         |
| SSTORE (new)   | 20,000                      |
| SSTORE (update)| 5,000                       |
| SSTORE (clear) | 5,000 (+ 4,800 refund)     |
| EMIT_LOG       | 20 + 10/topic + 1/data byte|

### Fee Formula

```
fee = gas_used * max_fee_per_gas (satoshis)
```

Max fee per gas is set by the transaction sender. Minimum: 1 satoshi/gas.

---

## 10. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Bitcoin L1 (Mainchain)                │
│  OP_RETURN anchors │ Peg-in deposits │ STARK proofs     │
└────────┬────────────┴────────┬────────┴─────────────────┘
         │                     │
┌────────▼─────────────────────▼──────────────────────────┐
│                     Brrq Bridge                          │
│  BTC→brqBTC (peg-in) │ brqBTC→BTC (peg-out)          │
│  BitVM2 bridge         │ Challenge period (2016 blocks)  │
└────────┬────────────────────────────────────────────────┘
         │
┌────────▼────────────────────────────────────────────────┐
│                     Brrq L2 Node                         │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐              │
│  │ Sequencer│  │ Consensus│  │  Prover  │              │
│  │ (mempool,│  │ (PoS,    │  │ (STARK + │              │
│  │  blocks) │  │  epochs) │  │  SNARK)  │              │
│  └────┬─────┘  └──────────┘  └──────────┘              │
│       │                                                  │
│  ┌────▼─────┐  ┌──────────┐  ┌──────────┐              │
│  │   zkVM   │  │  State   │  │ Network  │              │
│  │ (RV32IM) │  │  (SMT)   │  │ (gossip) │              │
│  └──────────┘  └──────────┘  └──────────┘              │
│                                                          │
│  API: JSON-RPC 2.0 │ REST │ WebSocket                   │
└─────────────────────────────────────────────────────────┘
         │
┌────────▼────────────────────────────────────────────────┐
│                    Developer Tools                        │
│  Rust SDK │ TypeScript SDK │ Block Explorer │ Faucet     │
└─────────────────────────────────────────────────────────┘
```

### Cryptographic Stack (Hash-First Architecture)

| Layer              | Algorithm       | Purpose                    |
|--------------------|-----------------|----------------------------|
| Signatures         | SLH-DSA (FIPS 205) | Quantum-resistant signing |
| Classical Sigs     | Schnorr (BIP-340)  | Bitcoin-compatible        |
| Proofs             | ZK-STARKs          | Validity proofs           |
| SNARK Wrapper      | Groth16 (transitional) | Compact L1 verification |
| State              | SHA-256 Merkle     | State commitments         |
| Fraud Detection    | EOTS               | Equivocation proofs       |
| MEV Protection     | Authenticated encryption | MEV protection    |

### Transaction Lifecycle

1. User dual-signs transaction with Schnorr (BIP-340) + SLH-DSA (FIPS 205)
2. Transaction enters mempool (with MEV commit-reveal encryption)
3. Sequencer builds block (3-second intervals)
4. zkVM executes each transaction, generating execution trace
5. State root updated in Sparse Merkle Tree
6. STARK proof generated over execution traces
7. STARK proof wrapped in Groth16 SNARK (transitional, for compact L1 verification)
8. Block anchored to Bitcoin L1 via OP_RETURN

---

## Example Contracts

See the `contracts/system/` directory for system contract implementations:

- **`treasury/`** — Protocol treasury with timelocked withdrawals
- **`wbrc/`** — Wrapped BRC token (deposit/withdraw)
- **`proxy/`** — Upgradeable proxy with two-step admin transfer
