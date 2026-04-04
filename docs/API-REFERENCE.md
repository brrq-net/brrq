# Brrq L2 — API Reference

**Protocol:** JSON-RPC 2.0 over HTTP
**Default Port:** 8545
**WebSocket:** `ws://host:8545/ws`

## Quick Start

```bash
curl -s http://localhost:8545 -X POST \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"brrq_blockHeight","params":[],"id":1}'
```

---

## Chain & State

### brrq_blockHeight
Returns the current L2 block height.

**Params:** none
**Returns:** `number`

```json
{"jsonrpc":"2.0","method":"brrq_blockHeight","params":[],"id":1}
// → {"result": 1107}
```

### brrq_chainId
Returns the chain identifier.

**Params:** none
**Returns:** `{ chain_id: number }`

```json
{"jsonrpc":"2.0","method":"brrq_chainId","params":[],"id":1}
// → {"result": {"chain_id": 3078356993}}
```

### brrq_getStateRoot
Returns the current Merkle state root hash.

**Params:** none
**Returns:** `string` (hex)

### brrq_getEpochInfo
Returns epoch information.

**Params:** none
**Returns:** `{ current_epoch, epoch_length, epoch_start_height }`

```json
// → {"result": {"current_epoch": 0, "epoch_length": 7200, "epoch_start_height": 0}}
```

---

## Accounts

### brrq_getBalance
**Params:** `[address: string]`
**Returns:** `number` (satoshis)

```json
{"jsonrpc":"2.0","method":"brrq_getBalance","params":["0x..."],"id":1}
// → {"result": 100000000}
```

### brrq_getNonce
**Params:** `[address: string]`
**Returns:** `number`

### brrq_getAccount
**Params:** `[address: string]`
**Returns:** `{ address, balance, nonce, code_hash, storage_root }`

### brrq_getAccountAtHeight
**Params:** `[address: string, height: number]`
**Returns:** same as getAccount (at specific block height)

---

## Blocks & Transactions

### brrq_getBlock
**Params:** `[height: number]`
**Returns:** Block object with header, transactions, signatures

### brrq_getBlockByHash
**Params:** `[hash: string]`
**Returns:** Block object

### brrq_getTransaction
**Params:** `[tx_hash: string]`
**Returns:** Transaction object

### brrq_getTransactionsByAddress
**Params:** `[address: string, page?: number, limit?: number]`
**Returns:** `Transaction[]`

### brrq_getReceipt
**Params:** `[tx_hash: string]`
**Returns:** `{ block_height, gas_used, success, block_hash }`

### brrq_getLogs
**Params:** `[{ from_block?, to_block?, address?, topics? }]`
**Returns:** `Log[]`

---

## Transactions

### brrq_sendTransaction
Send a signed transaction to the mempool.

**Params:** `[{ from, tx_type, nonce, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, signature, public_key, chain_id, ... }]`

**tx_type values:**
| Type | Additional Fields |
|------|-------------------|
| `transfer` | `to`, `amount` |
| `deploy` | `code` (hex) |
| `contract_call` | `to`, `call_data` (hex), `value` |
| `create_portal_lock` | `amount`, `condition_hash`, `nullifier_hash`, `timeout_l2_block` |
| `settle_portal_lock` | `lock_id`, `merchant_secret`, `portal_signature`, `nullifier` |
| `cancel_portal_lock` | `lock_id` |
| `update_lock_condition` | `lock_id`, `condition_hash`, `nullifier_hash` |
| `create_lock_pool` | `slot_amounts[]`, `timeout_l2_block` |
| `batch_settle_portal` | `claims[]` |

**Returns:** `string` (tx hash hex)

### brrq_sendEncryptedTx
Submit an encrypted transaction (MEV protection).

**Params:** `[encrypted_tx_hex: string]`
**Returns:** `string` (commitment hash)

---

## Portal (L3)

### brrq_getPortalStats
**Params:** none
**Returns:** `{ active_locks, total_escrowed, nullifiers_consumed }`

```json
// → {"result": {"active_locks": 1, "total_escrowed": 50000000, "nullifiers_consumed": 0}}
```

### brrq_getPortalLock
**Params:** `[lock_id: string]` (64 hex chars)
**Returns:** `{ lock_id, owner, amount, condition_hash, nullifier_hash, timeout_l2_block, status, created_at_block }`

### brrq_checkNullifier
**Params:** `[nullifier: string]` (64 hex chars)
**Returns:** `{ nullifier, consumed, pending_settlement, safe }`

### brrq_checkPortalSafety
**Params:** `[lock_id: string, nullifier: string]`
**Returns:** `{ lock_id, status, pending_cancel, safe_to_accept }`

---

## Bridge (L1 ↔ L2)

### brrq_bridgeStatus
**Params:** none
**Returns:** Bridge status object

### brrq_getL1Status
**Params:** none
**Returns:** `{ connected, l1_height, network, anchor_count, last_anchor_l2_height }`

```json
// → {"result": {"connected": true, "l1_height": 216, "network": "regtest", "anchor_count": 5}}
```

### brrq_bridgeDeposit
Initiate a BTC → brqBTC deposit.

**Params:** `[{ btc_tx_id, recipient, amount, btc_vout }]`
**Returns:** deposit confirmation

### brrq_bridgeWithdraw
Initiate a brqBTC → BTC withdrawal.

**Params:** `[{ amount, btc_address }]`
**Returns:** withdrawal request ID

### brrq_getL1Anchors
**Params:** `[page?: number, limit?: number]`
**Returns:** `L1AnchorRecord[]`

---

## Staking & Consensus

### brrq_getValidators
**Params:** `[page?: number, limit?: number]`
**Returns:** `Validator[]`

### brrq_getStakingInfo
**Params:** `[address: string]`
**Returns:** `{ stake, is_active, rewards }`

### brrq_getSequencers
**Params:** none
**Returns:** `Sequencer[]`

### brrq_registerSequencer
**Params:** `[{ stake }]` (requires signed tx)

### brrq_delegateStake / brrq_undelegateStake
**Params:** `[{ validator, amount }]`

---

## Governance

### brrq_submitProposal
**Params:** `[proposal_json]`

### brrq_voteOnProposal
**Params:** `[{ proposal_id, vote }]`

### brrq_getProposals
**Params:** `[page?: number, limit?: number]`

### brrq_getGovernanceStats
**Params:** none

---

## Proofs (ZK-STARK)

### brrq_getProofs / brrq_getProof / brrq_getLatestProof
**Params:** varies
**Returns:** proof data

### brrq_getProofByHeight
**Params:** `[height: number]`

### brrq_getProofCount
**Params:** none
**Returns:** `number`

### brrq_verifyProof
**Params:** `[proof_data]`
**Returns:** `{ valid: boolean }`

### brrq_getAccountProof / brrq_getStorageProof
Merkle inclusion proofs for light clients.

---

## MEV Protection

### brrq_getMevStatus
**Params:** none
**Returns:** MEV epoch status

### brrq_getMevEpochKey
**Params:** none
**Returns:** current epoch encryption key

### brrq_submitMevTransaction
Submit encrypted tx for fair ordering.

---

## Prover Pools

### brrq_getProverPools
**Params:** none

### brrq_createProverPool / brrq_joinProverPool
Pool management for proof generation.

---

## Testnet

### brrq_faucetDrip
Request testnet brqBTC.

**Params:** `[address: string, amount?: number]`
**Returns:** `{ tx_hash, amount, recipient }`

```json
{"jsonrpc":"2.0","method":"brrq_faucetDrip","params":["0x...", 100000000],"id":1}
// → {"result": {"tx_hash": "0x...", "amount": 100000000, "recipient": "0x..."}}
```

**Limits:** 1 BTC max per drip, 1 hour cooldown per address.

---

## WebSocket Subscriptions

Connect to `ws://host:8545/ws` and send:

```json
{"subscribe": ["newBlocks", "pendingTxs", "portalEvents"]}
```

**Topics:**
| Topic | Events |
|-------|--------|
| `newBlocks` | New block produced |
| `pendingTxs` | Transaction entered mempool |
| `portalEvents` | PortalLockCreated, Settled, Cancelled, Expired, BatchSettled |
| `l1Events` | L1 anchor, status change |
| `bridgeEvents` | Challenge, withdrawal, proof |
| `governance` | Proposal, vote, finalized |
| `mevEvents` | MEV phase changes |

---

## Error Codes

| Code | Meaning |
|------|---------|
| -32601 | Method not found |
| -32602 | Invalid params |
| -32000 | Internal server error |
| -32002 | Rate limit exceeded |

## Rate Limits

| Tier | Methods | Limit |
|------|---------|-------|
| Relaxed | Read queries (getBalance, blockHeight, etc.) | 200 req/10s |
| Strict | Write ops (sendTransaction, faucetDrip, etc.) | 5 req/60s |
