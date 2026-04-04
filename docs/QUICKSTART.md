# Brrq Testnet — Quickstart

Connect to the Brrq L2 testnet in 5 minutes.
> **Current testnet:** Contact the team for the testnet IP address, or run your own node (see section 8).


## 1. Clone the Repository

```bash
git clone https://github.com/brrq-net/brrq.git && cd brrq
```

## 2. Check the Network

```bash
curl -s http://TESTNET_IP:8545 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"brrq_blockHeight","params":[],"id":1}'
```

Expected: `{"result": 1107}` (or higher)

## 3. Get Testnet brqBTC

```bash
# Replace with your address
curl -s http://TESTNET_IP:8545 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"brrq_faucetDrip","params":["0xYOUR_ADDRESS"],"id":1}'
```

Returns 1 BTC (100,000,000 satoshis). Cooldown: 1 hour.

## 4. Check Balance

```bash
curl -s http://TESTNET_IP:8545 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"brrq_getBalance","params":["0xYOUR_ADDRESS"],"id":1}'
```

## 5. TypeScript SDK

```bash
# From the cloned brrq repo root, copy SDK to your project
cp -r packages/brrq-sdk-ts /path/to/my-project/brrq-sdk
```

```typescript
import { BrrqClient } from "@brrq/sdk";

const client = new BrrqClient("http://TESTNET_IP:8545");

const height = await client.getBlockHeight();
console.log("Block height:", height);

const balance = await client.getBalance("0xYOUR_ADDRESS");
console.log("Balance:", balance, "sats");

const epoch = await client.getEpochInfo();
console.log("Epoch:", epoch.currentEpoch, "length:", epoch.epochLength);

const portal = await client.getPortalStats();
console.log("Portal locks:", portal.active_locks);
```

## 6. Portal Payment (Merchant Integration)

### Step 1: Create a Portal Lock
```bash
# Send signed CreatePortalLock transaction
curl -s http://TESTNET_IP:8545 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"brrq_sendTransaction","params":[{
    "from": "0xUSER_ADDRESS",
    "tx_type": "create_portal_lock",
    "amount": 50000000,
    "condition_hash": "0xHASH_OF_MERCHANT_SECRET",
    "nullifier_hash": "0xCOMPUTED_NULLIFIER",
    "timeout_l2_block": 130000,
    "nonce": 0,
    "gas_limit": 50000,
    "max_fee_per_gas": 100,
    "max_priority_fee_per_gas": 1,
    "signature": "0xSCHNORR_SIGNATURE",
    "public_key": "0xPUBLIC_KEY",
    "chain_id": 3078356993
  }],"id":1}'
```

### Step 2: Check Lock Status
```bash
curl -s http://TESTNET_IP:8545 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"brrq_getPortalStats","params":[],"id":1}'
```

### Step 3: Generate Portal Key (off-chain, in wallet)
The wallet generates a Schnorr signature over `(lock_id || condition_hash || timeout)`.

### Step 4: Merchant Settles
```bash
curl -s http://TESTNET_IP:8545 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"brrq_sendTransaction","params":[{
    "from": "0xMERCHANT_ADDRESS",
    "tx_type": "settle_portal_lock",
    "lock_id": "0xLOCK_ID",
    "merchant_secret": "0xSECRET_PREIMAGE",
    "portal_signature": "0xPORTAL_KEY_SIGNATURE",
    "nullifier": "0xNULLIFIER",
    "nonce": 0,
    "gas_limit": 50000,
    "max_fee_per_gas": 100,
    "max_priority_fee_per_gas": 1,
    "signature": "0xMERCHANT_SIGNATURE",
    "public_key": "0xMERCHANT_PUBKEY",
    "chain_id": 3078356993
  }],"id":1}'
```

## 7. WebSocket (Real-time Events)

```javascript
const ws = new WebSocket("ws://TESTNET_IP:8545/ws");
ws.onopen = () => ws.send(JSON.stringify({
  subscribe: ["newBlocks", "pendingTxs"]
}));
ws.onmessage = (e) => console.log("Event:", JSON.parse(e.data));
```

## 8. Run Your Own Node

```bash
# Download binary or build from source
cargo build --release -p brrq-node \
  --features testnet

# Start as follower
./target/release/brrq-node \
  --network testnet \
  --rpc-port 8545 \
  --p2p-port 30303 \
  --datadir ./brrq-data \
  --genesis testnet-genesis.toml \
  --bootstrap "TESTNET_IP:30303"
```

## Network Info

| Parameter | Value |
|-----------|-------|
| Chain ID | 3078356993 |
| Block time | 3 seconds |
| Epoch length | 7200 blocks (~6 hours) |
| Native token | brqBTC (1:1 with BTC) |
| Faucet | 1 BTC per drip, 1h cooldown |
| RPC | JSON-RPC 2.0 on port 8545 |
| P2P | TCP port 30303 |
| WebSocket | ws://host:8545/ws |
