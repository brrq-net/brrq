# Brrq Portal: Instant Payments on Bitcoin L2

**Website:** https://brrq.net
**Source:** https://github.com/brrq-net/brrq

---

## 1. Abstract

Brrq Portal is an SDK standard for instant payments on the Brrq L2. It is not a network — it is a protocol that any application integrates via HTTP, NFC, or QR code.

The user locks BTC from their L2 balance into an escrow, generates a cryptographic Portal Key, and sends it to the merchant. The merchant verifies locally (sub-second) and delivers goods immediately. Settlement occurs later in batches — up to 100 payments per L2 transaction — reducing per-payment settlement gas by 15x.

Portal requires no payment channels, no routing, no liquidity management, and no blockchain knowledge from the merchant.

---

## 2. Protocol

### How It Works

```
User                        L2                     Merchant
  |                          |                        |
  | (1) create_lock_pool ------>                      |
  |   balance -= total       |                        |
  |                          |                        |
  | (2) update_lock_condition -->                     |
  |   slot.cond = H(secret)  |                        |
  |                          |                        |
  | (3) sign Portal Key locally                       |
  | (4) send Portal Key -------------------------------->
  |                          |  verify + query lock   |
  |                          |  deliver goods         |
  |                          |                        |
  |                          |  (5) batch_settle(N) ->|
```

**Step 1 — Lock Pool (one-time):** The user creates a pool of pre-funded locks in a single L2 transaction. Each lock holds a fixed denomination with `condition_hash = 0` (unclaimed).

**Step 2 — Assign Lock:** When paying, the wallet sets `condition_hash = SHA-256(merchant_secret)` and computes a deterministic nullifier: `N = HMAC-SHA256(sk, lock_id || condition_hash)`. This is one lightweight L2 transaction.

**Step 3-4 — Portal Key:** The wallet signs a Schnorr authorization (0.05ms) binding the lock parameters and sends it to the merchant. The merchant verifies the signature, queries L2 for lock status and nullifier safety, and accepts payment — all in ~50-200ms.

**Step 5 — Batch Settlement:** The merchant accumulates claims and settles up to 100 in a single L2 transaction. Failed claims do not affect successful ones.

### Security

**Double-spend prevention:** Each lock has exactly one valid nullifier, derived deterministically from the user's secret key and the lock+merchant parameters. The nullifier is consumed on settlement. Sending the same Portal Key to two merchants produces two settlement attempts with the same nullifier — the second fails.

**Mempool awareness:** The sequencer tracks pending nullifiers and pending cancellations. Merchants query `safe: true/false` before accepting, closing the double-spend window to the L2 block time (~3 seconds).

**Settlement priority:** If a settlement and a cancellation for the same lock arrive in the same block, settlement executes first — the user authorized payment by issuing the Portal Key.

**Timeout protection:** Every lock has a mandatory timeout (minimum 24 hours). Unsettled locks automatically refund to the user's balance. Once the user sets a `condition_hash`, the lock cannot be cancelled — protecting the merchant.

**TEE is auxiliary:** Private keys may be protected by hardware security modules where available. The protocol does not depend on them — security rests entirely on on-chain escrow locks and cryptographic nullifiers.

---

## 3. Scaling

### Batch Settlement

| Without Portal | With Portal |
|---|---|
| 10M individual settlements/day | 100K batch transactions/day |
| ~60,500 gas per payment | ~3,950 gas per claim (batch) |
| — | **99% fewer settlement transactions, 15x cheaper per claim** |

Each payment still requires one lightweight `UpdateLockCondition` (33,100 gas — no signature verification), but the expensive settlement step is amortized across up to 100 claims.

### Lock Pools

Users pre-fund a pool of locks in a single transaction instead of creating one lock per payment. A pool with 5 denomination slots replaces ~10 daily lock transactions with one weekly pool creation.

### Prepaid Cards

A single large lock supports multiple partial payments via monotonically increasing signed receipts. The merchant settles only the last receipt — one L2 transaction regardless of how many payments occurred.

### Performance

| Operation | Throughput |
|-----------|-----------|
| Portal Key verification | 7,821/sec |
| Batch settlement (100 claims) | 5,294 claims/sec |

---

## 4. Ecosystem Standards

**BPS-1 — Universal URI Scheme:**
`brrq://pay?v=1&chain=mainnet&amount=50000&cond=0xABC...&timeout=200000`
Encodes payment parameters for QR, NFC, and deep linking. `lock_id` is excluded to prevent identity tracking.

**BPS-2 — Delegated Session Keys:**
For games, streaming, and AI inference. The user delegates a temporary signing key with a strict spending cap and expiry. The merchant settles the last cumulative receipt.

**BPS-3 — Gasless Relayers:**
Merchants delegate settlement to relayers who pay gas in exchange for a fee (max 1%). The merchant receives funds without holding BTC for gas.

**BPS-4 — Proof of Purchase:**
A self-contained cryptographic receipt: the revealed `merchant_secret` (proving payment) plus the user's Schnorr signature (proving authorization). Independently verifiable without querying any third party.

---

## 5. Comparison and Status

| Criterion | Brrq Portal | Lightning | Ark/Arkade | Spark | Cashu |
|-----------|-------------|-----------|------------|-------|-------|
| Requires channel? | No | Yes | No | No | No |
| Routing problem? | No | Yes | No | No | No |
| Trust model | Trustless | Trustless | Trust-minimized | Trustless | Custodial |
| Settlement gas savings | 15x (batch) | N/A | N/A | N/A | N/A |
| Prepaid payments | Yes | No | No | No | Yes |
| Gasless for merchant | Yes | No | No | No | No |
| Session keys | Yes | No | Intents | No | No |
| Proof of purchase | Yes | Preimage | No | No | No |
| Acceptance time | Sub-second | Sub-second | Sub-second | Sub-second | Instant |

### Status

**Completed:** Escrow locks, nullifier set, Portal Key generation and verification, individual and batch settlement, lock pools, prepaid cards, sequencer and API integration, RocksDB persistence, mempool-aware safety checks, gasless relayers, session keys, proof of purchase, URI scheme.

**Upcoming:** Public testnet with real wallets and merchants. Independent security audit. Mainnet launch.

