# Brrq Testnet Guide

## Overview

Brrq Testnet is a multi-node test environment for the Brrq Bitcoin L2 network.
This guide covers running a single node locally, multi-node Docker deployment,
and interacting with the testnet APIs.

**Chain ID:** `0xB77C0001` (3078356993)
**Block Time:** 3 seconds
**Epoch Length:** 7200 blocks (~6 hours)

---

## 1. Single Node (Local)

### Build

```bash
cd brrq
cargo build --release
```

### Run

```bash
./target/release/brrq-node \
  --network testnet \
  --sequencer \
  --rpc-port 8545 \
  --p2p-port 30303 \
  --datadir ./data \
  --genesis testnet-genesis.toml
```

### CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--network` | `testnet` | Network name |
| `--sequencer` | off | Enable block production |
| `--rpc-port` | `8545` | JSON-RPC & REST API port |
| `--p2p-port` | `30303` | P2P networking port |
| `--datadir` | `./data` | Data directory (RocksDB) |
| `--genesis` | `testnet-genesis.toml` | Genesis config file |
| `--bootstrap` | none | Comma-separated bootstrap peers (e.g. `host1:30303,host2:30303`) |
| `--validator-key` | none | Path to validator key file (auto-generated if missing) |
| `--batch-size` | `10` | Blocks per STARK proof batch |
| `--mev-mode` | from genesis | MEV protection: `disabled`, `centralized_bypass`, `decentralized` |
| `--l1-rpc-url` | none | Bitcoin RPC URL (enables L1 integration) |
| `--l1-rpc-user` | none | Bitcoin RPC username |
| `--l1-rpc-pass` | none | Bitcoin RPC password |
| `--bridge-address` | none | Bitcoin bridge address (Taproot/P2TR) |

---

## 2. Multi-Node Docker Deployment

### Prerequisites

- Docker & Docker Compose v2+

### Start 3-Node Testnet

```bash
docker compose -f docker/docker-compose.testnet.yml up --build
```

This starts:

| Node | Role | API Port | P2P Port |
|------|------|----------|----------|
| `seed-node` | Sequencer + Bootstrap | 8545 | 30303 |
| `validator-2` | Sequencer | 8547 | 30304 |
| `full-node` | Read-only | 8546 | 30305 |

### Stop

```bash
docker compose -f docker/docker-compose.testnet.yml down
```

### Reset Data

```bash
docker compose -f docker/docker-compose.testnet.yml down -v
```

---

## 3. API Reference

### Health Check

```bash
curl http://localhost:8545/api/v1/health
```

Response:
```json
{
  "status": "ok",
  "version": "0.1.0",
  "height": 42,
  "epoch": 0,
  "validator_count": 1,
  "mempool_size": 0,
  "syncing": false
}
```

### Faucet (Get Testnet Tokens)

```bash
curl -X POST http://localhost:8545/api/v1/faucet \
  -H "Content-Type: application/json" \
  -d '{"address": "0x<your_address_hex>"}'
```

Response:
```json
{
  "tx_hash": "faucet_direct_credit",
  "amount": 100000000,
  "recipient": "0x..."
}
```

Cooldown: 1 hour per address. Drip amount: 1 BTC (100,000,000 satoshis).

### JSON-RPC Faucet

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"brrq_faucetDrip","params":["0x<address>"],"id":1}'
```

### Check Balance

```bash
curl http://localhost:8545/api/v1/accounts/0x<address>/balance
```

### Get Block

```bash
curl http://localhost:8545/api/v1/blocks/1
```

### List Blocks (Paginated)

```bash
curl "http://localhost:8545/api/v1/blocks?limit=10&offset=0"
```

### Network Stats

```bash
curl http://localhost:8545/api/v1/stats
```

### Prometheus Metrics

```bash
curl http://localhost:8545/metrics
```

Returns plain text in Prometheus exposition format:
```
brrq_block_height 42
brrq_peer_count 0
brrq_mempool_size 0
brrq_validator_count 1
brrq_epoch 0
brrq_blocks_produced_total 42
brrq_tx_total 15
```

### Submit Transaction (JSON-RPC)

```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "brrq_sendTransaction",
    "params": [{
      "from": "0x...",
      "to": "0x...",
      "amount": 1000,
      "nonce": 0,
      "gas_limit": 21000,
      "max_fee_per_gas": 1,
      "tx_type": "transfer",
      "signature": "0x...",
      "public_key": "0x..."
    }],
    "id": 1
  }'
```

### Submit Transaction (REST)

```bash
curl -X POST http://localhost:8545/api/v1/transactions \
  -H "Content-Type: application/json" \
  -d '{
    "from": "0x...",
    "to": "0x...",
    "amount": 1000,
    "nonce": 0,
    "gas_limit": 21000,
    "max_fee_per_gas": 1,
    "tx_type": "transfer",
    "signature": "0x...",
    "public_key": "0x..."
  }'
```

---

## 4. Genesis Configuration

The default genesis file (`testnet-genesis.toml`) defines:

```toml
bootstrap_nodes = []

[chain]
chain_id = 3078356993    # 0xB77C0001
block_time_secs = 3
epoch_length = 7200
block_gas_limit = 30000000
initial_stake_cap = 10000000000  # 100 BTC
mev_mode = "decentralized"       # two-block commit-reveal MEV protection

[[accounts]]
address = "0x00000000000000000000000000000000deadfacc"
balance = 2100000000000000  # 21M BTC (faucet)

[[validators]]
address = "0x000000000000000000000000000000000000ee01"
stake = 100000000  # 1 BTC

[[validators]]
address = "0x000000000000000000000000000000000000ee02"
stake = 100000000  # 1 BTC

[treasury]
address = "0x00000000000000000000000000000000000b77c0"
initial_balance = 52560000000    # 525.6 BTC (bootstrap rewards fund)

[faucet]
address = "0x00000000000000000000000000000000deadfacc"
drip_amount = 100000000    # 1 BTC per request
cooldown_secs = 3600       # 1 hour
```

### Custom Genesis

Create your own TOML file with different validators, accounts, or faucet settings,
then pass it via `--genesis your-genesis.toml`.

---

## 5. Wallet CLI

```bash
# Create a new account
cargo run --bin brrq-wallet -- create-account

# Check balance
cargo run --bin brrq-wallet -- balance --address 0x... --rpc http://localhost:8545

# Send transfer
cargo run --bin brrq-wallet -- send \
  --to 0x... \
  --amount 1000 \
  --keyfile wallet.json \
  --rpc http://localhost:8545
```

---

## 6. Architecture

```
┌─────────────────────────────────────────────┐
│                 brrq-node                   │
│                                             │
│  ┌─────────┐  ┌──────────┐  ┌───────────┐  │
│  │  REST   │  │ JSON-RPC │  │ WebSocket │  │
│  │ /api/v1 │  │  POST /  │  │   /ws     │  │
│  └────┬────┘  └────┬─────┘  └─────┬─────┘  │
│       └────────────┼───────────────┘        │
│               ┌────┴────┐                   │
│               │  State  │ (SharedState)     │
│               └────┬────┘                   │
│    ┌───────┬───────┼───────┬────────┐       │
│    │Sequencer│ VM  │ State │Consensus│      │
│    │(blocks)│(exec)│(SMT)  │(PoS)   │      │
│    └───────┘└─────┘└──────┘└────────┘       │
│               ┌────┴────┐                   │
│               │ Network │ (P2P TCP)         │
│               └─────────┘                   │
└─────────────────────────────────────────────┘
```

Block pruning keeps recent blocks cached in memory for fast access.

---

## 7. Complete JSON-RPC Reference

All methods use `POST /` with standard JSON-RPC 2.0 format.

### Chain State

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_blockHeight` | `[]` | `u64` | Current chain height |
| `brrq_getBalance` | `["0xaddr"]` | `u64` | Account balance (satoshis) |
| `brrq_getNonce` | `["0xaddr"]` | `u64` | Account nonce |
| `brrq_getBlock` | `[height]` or `["latest"]` | Block object | Block by height |
| `brrq_getBlockByHash` | `["0xhash"]` | Block object | Block by hash |
| `brrq_getStateRoot` | `[]` | `"0xhash"` | Current state root |
| `brrq_chainId` | `[]` | `{ chain_id: number }` | Chain ID (0xB77C0001) |
| `brrq_getCode` | `["0xaddr"]` | `"0xbytecode"` | Contract bytecode |
| `brrq_getStorageAt` | `["0xaddr", "0xkey"]` | `"0xvalue"` | Storage slot value |

### Transactions

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_sendTransaction` | `[{tx_object}]` | `"0xtx_hash"` | Submit signed transaction |
| `brrq_getTransaction` | `["0xtx_hash"]` | Tx object | Get transaction by hash |
| `brrq_getReceipt` | `["0xtx_hash"]` | Receipt object | Get transaction receipt |
| `brrq_getLogs` | `[{fromBlock, toBlock, address}]` | `[Log]` | Query event logs |

### Transaction Object (sendTransaction)

```json
{
  "from": "0x<sender_address>",
  "to": "0x<recipient_address>",
  "amount": 1000,
  "nonce": 0,
  "gas_limit": 21000,
  "max_fee_per_gas": 1,
  "chain_id": 3078356993,
  "tx_type": "transfer",
  "signature": "0x<schnorr_signature_hex>",
  "public_key": "0x<schnorr_pubkey_hex>"
}
```

Supported `tx_type` values: `"transfer"`, `"deploy"`, `"contract_call"`, `"register_validator"`, `"add_stake"`, `"begin_unbonding"`, `"submit_equivocation_proof"`.

### Validators & Consensus

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_getValidators` | `[]` or `["0xaddr"]` | Validator(s) | Get validator info |
| `brrq_getEpochInfo` | `[]` | Epoch object | Current epoch state |

### Proofs

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_getLatestProof` | `[]` | Proof object | Latest batch STARK proof |
| `brrq_getProofByIndex` | `[index]` | Proof object | Proof by index |
| `brrq_getProofCount` | `[]` | `u64` | Total proof count |
| `brrq_submitProof` | `[{proof}]` | `"ok"` | Submit external proof |
| `brrq_verifyProof` | `[{proof}]` | `bool` | Verify a STARK proof |

### Merkle Proofs

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_getAccountProof` | `["0xaddr"]` | AccountProof | Merkle inclusion proof |
| `brrq_getStorageProof` | `["0xaddr", "0xkey"]` | StorageProof | Storage Merkle proof |

### Bridge

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_bridgeDeposit` | `[{btc_tx_id, vout, amount, recipient, confirmations}]` | `"ok"` | Process peg-in |
| `brrq_bridgeWithdraw` | `[{sender, amount, btc_destination}]` | `"0xwithdrawal_id"` | Initiate peg-out |
| `brrq_bridgeStatus` | `["0xwithdrawal_id"]` | Status object | Check withdrawal status |
| `brrq_bridgeChallenge` | `[{challenger, challenge_type, ...}]` | `"0xchallenge_id"` | Submit fraud proof challenge |
| `brrq_bridgeResolve` | `[{withdrawal_id, proof_payload}]` | Resolution | Resolve a challenge |
| `brrq_bridgeChallengeList` | `[limit, offset]` | `[Challenge]` | List active challenges |

### MEV Protection

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_mevSubmit` | `[{envelope_hex}]` | `"0xhash"` | Submit encrypted envelope |
| `brrq_mevStatus` | `[]` | MEV phase info | Current MEV mempool state |

### Governance

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_submitProposal` | `[{proposer, proposal_type, ...}]` | `"0xproposal_id"` | Create governance proposal |
| `brrq_voteProposal` | `[{proposal_id, voter, vote, chamber}]` | `"ok"` | Cast vote |
| `brrq_getProposals` | `[]` | `[Proposal]` | List all proposals |

### Sequencer Management

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_registerSequencer` | `[{address, self_stake, region, commission_bp}]` | `"ok"` | Register as sequencer |
| `brrq_delegateStake` | `[{delegator, sequencer, amount}]` | `"ok"` | Delegate stake |
| `brrq_undelegateStake` | `[{delegator, sequencer}]` | `"ok"` | Undelegate stake |
| `brrq_getSequencers` | `[]` | `[Sequencer]` | List registered sequencers |

### Prover Pools

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_createProverPool` | `[{coordinator, name, fee_bp}]` | `"0xpool_id"` | Create prover pool |
| `brrq_joinProverPool` | `[{pool_id, member, weight}]` | `"ok"` | Join a pool |
| `brrq_getProverPools` | `[]` | `[Pool]` | List prover pools |

### Faucet (Testnet Only)

| Method | Params | Returns | Description |
|--------|--------|---------|-------------|
| `brrq_faucetDrip` | `["0xaddr"]` | `{amount, recipient}` | Receive testnet BTC |

### Error Codes

| Code | Message | Cause |
|------|---------|-------|
| -32600 | Invalid Request | Malformed JSON-RPC |
| -32601 | Method not found | Unknown method name |
| -32602 | Invalid params | Missing or wrong param types |
| -32000 | Transaction error | Signature invalid, nonce wrong, insufficient balance |
| -32001 | Not found | Block/tx/account doesn't exist |
| -32002 | Rate limited | Faucet cooldown not expired |

---

## 8. REST API Reference

All REST endpoints are under `/api/v1/`.

### Core Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Node health + version + height |
| GET | `/stats` | Network statistics |
| GET | `/blocks?limit=N&offset=M` | Paginated block list |
| GET | `/blocks/{height}` | Block by height |
| POST | `/transactions` | Submit signed transaction |
| GET | `/transactions/{hash}` | Transaction + receipt |
| GET | `/accounts/{address}` | Full account info |
| GET | `/accounts/{address}/balance` | Balance only |
| GET | `/validators` | Validator list |
| GET | `/epoch` | Current epoch state |

### Bridge Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/bridge/status` | Bridge state (deposits, withdrawals) |
| GET | `/bridge/challenges` | Active fraud proof challenges |
| POST | `/bridge/challenges/submit` | Submit a challenge |
| GET | `/bridge/operators` | Bridge operators |

### Proof Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/proofs` | List all batch STARK proofs |
| GET | `/proofs/latest` | Latest proof |
| GET | `/proofs/height/{height}` | Proof by L2 height |

### L1 Integration

| Method | Path | Description |
|--------|------|-------------|
| GET | `/l1/status` | Bitcoin L1 connection status |
| GET | `/l1/anchors` | L1 anchor records |
| GET | `/l1/anchors/{height}` | Anchor by L2 height |

### MEV Protection

| Method | Path | Description |
|--------|------|-------------|
| POST | `/mev/submit` | Submit encrypted envelope |
| GET | `/mev/status` | MEV mempool phase status |
| GET | `/mev/epoch_key` | Current epoch encryption key |

### Governance

| Method | Path | Description |
|--------|------|-------------|
| POST | `/governance/proposals/submit` | Submit proposal |
| POST | `/governance/proposals/vote` | Cast vote |
| GET | `/governance/stats` | Governance statistics |

### Decentralized Sequencers

| Method | Path | Description |
|--------|------|-------------|
| POST | `/sequencers/register` | Register as sequencer |
| GET | `/sequencers` | List sequencers |
| POST | `/sequencers/delegate` | Delegate stake |
| POST | `/sequencers/undelegate` | Undelegate stake |
| GET | `/sequencers/regions` | Sequencer geographic distribution |

### Prover Pools

| Method | Path | Description |
|--------|------|-------------|
| POST | `/prover-pools/create` | Create prover pool |
| POST | `/prover-pools/{id}/join` | Join a pool |
| GET | `/prover-pools` | List pools |
| GET | `/prover-pools/stats` | Pool statistics |

### Monitoring

| Method | Path | Description |
|--------|------|-------------|
| GET | `/metrics` | Prometheus metrics |
| POST | `/faucet` | Testnet faucet (REST) |

---

## 9. WebSocket Subscriptions

Connect to `ws://localhost:8545/ws` (integrated) or `ws://localhost:8546` (standalone).

### Subscribe

```json
{"subscribe": ["newBlocks", "pendingTxs"]}
```

### Available Topics

| Topic | Event | Fields |
|-------|-------|--------|
| `newBlocks` | New block produced | `height`, `hash`, `tx_count`, `timestamp`, `gas_used` |
| `pendingTxs` | Transaction submitted | `tx_hash`, `from`, `to`, `value`, `nonce` |
| `l1Events` | Bitcoin L1 event | `type`, `height`, `hash` |

### Example (JavaScript)

```javascript
const ws = new WebSocket('ws://localhost:8545/ws');
ws.onopen = () => ws.send(JSON.stringify({subscribe: ['newBlocks']}));
ws.onmessage = (e) => console.log(JSON.parse(e.data));
```

---

## 10. Multi-Node Testing

```bash
# Start 3-node testnet
docker compose -f docker/docker-compose.testnet.yml up --build -d

# Verify all nodes are healthy
curl http://localhost:8545/api/v1/health
curl http://localhost:8546/api/v1/health
curl http://localhost:8547/api/v1/health

# Stop testnet
docker compose -f docker/docker-compose.testnet.yml down
```

---

## 11. Bitcoin L1 Integration

### Connect to Bitcoin Regtest

```bash
./target/release/brrq-node \
  --sequencer \
  --l1-rpc-url http://localhost:18443 \
  --l1-rpc-user user \
  --l1-rpc-pass pass \
  --bridge-address "bcrt1p..." \
  --genesis testnet-genesis.toml
```

### L1 Features

- **OP_RETURN Anchors**: L2 state roots posted to Bitcoin every N blocks
- **Deposit Watching**: Monitors bridge address for incoming BTC (6 confirmations)
- **Block Monitoring**: Tracks Bitcoin block height and detects reorgs
- **Graceful Degradation**: L1 connectivity monitoring with automatic recovery

### Environment Variables (Alternative to CLI Flags)

| Variable | Description |
|----------|-------------|
| `BRQ_L1_RPC_USER` | Bitcoin RPC username |
| `BRQ_L1_RPC_PASS` | Bitcoin RPC password |
