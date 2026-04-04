# Portal Protocol — Merchant Integration Guide

## Overview

Portal enables instant off-chain payments settled on Brrq L2:

```
User                    Merchant               Brrq L2
  │                        │                      │
  ├─ CreatePortalLock ────────────────────────────►│  Lock funds
  │                        │                      │
  ├─ Generate Portal Key ──►│                      │  Off-chain verification (<1ms local, settlement in next L2 block ~3s)
  │                        │                      │
  │                        ├─ Verify Key           │  Local check
  │                        ├─ Deliver goods        │
  │                        │                      │
  │                        ├─ SettlePortalLock ────►│  Claim funds
  │                        │                      │
```

## Step 1: User Creates Lock

The user's wallet creates a lock on L2, escrowing funds:

```
TransactionKind: CreatePortalLock
  amount:           50,000,000 sats (0.5 BTC)
  condition_hash:   SHA-256(merchant_secret)
  nullifier_hash:   derived from user key material and lock parameters
  timeout_l2_block: current_height + 28,800 (~24 hours)
```

After inclusion in a block, the lock is `Active` and funds are escrowed.

## Step 2: User Generates Portal Key

Off-chain, the wallet creates a Portal Key:

```
Portal Key = {
  protocol:      "Brrq_L3_Portal_v4"
  signature:     cryptographic proof binding user authorization to lock parameters
  nullifier:     derived from user key material and lock parameters
  lock_id:       from Step 1
  public_inputs: { owner, pubkey, amount, condition_hash, timeout }
}
```

This is sent to the merchant (QR code, BLE, NFC, or network).

## Step 3: Merchant Verifies

The merchant verifies locally (< 1ms local verification):

1. Schnorr signature valid
2. Lock exists and is `Active` (query `brrq_getPortalLock`)
3. Nullifier not consumed (query `brrq_checkNullifier`)
4. Lock not expired (timeout > current_block)
5. Amount matches

```typescript
// TypeScript SDK
const lock = await client.getPortalLock(portalKey.lock_id);
const nullifier = await client.checkNullifier(portalKey.nullifier);

if (lock.status === "Active" && nullifier.safe && lock.amount >= expectedAmount) {
  // Accept payment, deliver goods
}
```

## Step 4: Merchant Settles

The merchant submits a settlement transaction to claim the funds:

```
TransactionKind: SettlePortalLock
  lock_id:          from Portal Key
  merchant_secret:  preimage of condition_hash
  portal_signature: from Portal Key
  nullifier:        from Portal Key
```

The L2 sequencer:
1. Verifies `SHA-256(merchant_secret) == lock.condition_hash`
2. Verifies Schnorr signature
3. Consumes nullifier (prevents double-spend)
4. Transfers funds: lock owner → merchant

## Step 5: Batch Settlement (Optional)

For high-volume merchants, settle up to 100 payments in one transaction:

```
TransactionKind: BatchSettlePortal
  claims: [
    { lock_id, merchant_secret, portal_signature, nullifier },
    { lock_id, merchant_secret, portal_signature, nullifier },
    ...
  ]
```

Gas savings: ~40-100x compared to individual settlements.

## Lock Pools (Pre-funded Denominations)

For frequent payers, create multiple locks in one transaction:

```
TransactionKind: CreateLockPool
  slot_amounts:     [100000, 200000, 500000, 1000000]  // denominations
  timeout_l2_block: current + 200000  // ~1 week
```

Before using a slot, update its condition:

```
TransactionKind: UpdateLockCondition
  lock_id:        slot's lock_id
  condition_hash: SHA-256(new_merchant_secret)
  nullifier_hash: keyed hash function(user_sk, lock_id || condition_hash)
```

## Security Properties

| Property | Mechanism |
|----------|-----------|
| No double-spend | Nullifier consumed on settlement |
| No front-running | merchant_address bound in lock |
| No cancel after payment | Cancel blocked after condition_hash set |
| Timeout refund | Auto-refund after timeout_l2_block |
| Batch atomicity | Failed claims don't affect others |

## API Endpoints

| Method | Purpose |
|--------|---------|
| `brrq_getPortalStats` | Active locks, escrowed amount |
| `brrq_getPortalLock` | Lock details by ID |
| `brrq_checkNullifier` | Check if nullifier consumed |
| `brrq_checkPortalSafety` | Combined lock + cancel check |

## WebSocket Events

Subscribe to `portalEvents`:

```json
{"subscribe": ["portalEvents"]}
```

Events: `PortalLockCreated`, `PortalLockSettled`, `PortalLockCancelled`, `PortalLockExpired`, `PortalBatchSettled`
