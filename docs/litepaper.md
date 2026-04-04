# Brrq — Bitcoin's Hash-First Layer 2

*A Bitcoin execution layer built entirely on hash functions.*

---

## The Problem

Bitcoin processes approximately 3-7 transactions per second with no support for smart contracts beyond basic scripting. Several Layer 2 (L2) solutions exist — Lightning Network, Liquid, Stacks, Citrea, BOB — but they all share a critical structural weakness: every one of them depends on elliptic curve cryptography at its core.

Elliptic curve cryptography is vulnerable to quantum computers. Shor's algorithm can break it completely — not weaken it, but eliminate it. In Q1 2026, three independent research efforts — from Google Quantum AI, Caltech/Oratomic, and Iceberg Quantum — reduced the estimated resources for breaking Bitcoin's secp256k1 curve by up to two orders of magnitude, with one study showing as few as 26,000 physical qubits may suffice. Error-corrected quantum machines with 50 logical qubits are already being delivered to customers. The question is no longer whether quantum computers will break elliptic curves, but when within this decade. Every L2 built on elliptic curves will need a fundamental redesign — under time pressure.

Additionally, some L2s introduce their own governance tokens (separate from BTC), creating conflicts of interest between token holders and actual network users. And none of the current Bitcoin L2s offer built-in protection against MEV — the practice where transaction orderers extract profit by reordering, front-running, or censoring user transactions.

---

## The Solution

Brrq is built on a single design principle: **Hash-First Architecture**. Every cryptographic component in the protocol is built on hash functions — the most studied, most battle-tested cryptographic primitive available.

Hash functions degrade gracefully under quantum attack (Grover's algorithm halves the bit-security from 256 to 128 bits), unlike elliptic curves which break entirely (Shor's algorithm). A system built on hash functions doesn't need to be redesigned when quantum computers arrive — it's already prepared.

**Four properties flow naturally from this decision:**

1. **Quantum resistance** — Post-quantum signatures (SLH-DSA) available from day one. ZK-STARK proofs and SHA-256 Merkle trees are already hash-based.

2. **Trustless bridge** — BitVM2 technology enables permissionless verification of deposits and withdrawals. Any observer can challenge fraud — no trusted committee required.

3. **BTC-native economics** — No governance token. No new coin. BTC is the only currency for fees, staking, and collateral.

4. **Structural fairness** — Mathematical mechanisms prevent any single party from gaining outsized control, including a square-root stake cap that limits whale influence.

---

## How It Works

```
  User                Sequencer            STARK Prover          Bitcoin L1
   |                     |                     |                     |
   |-- Transaction ----> |                     |                     |
   |   (Schnorr or       |-- Execute in -----> |                     |
   |    SLH-DSA signed)  |   RISC-V zkVM       |                     |
   |                     |                     |-- Generate proof -> |
   |                     |                     |   (ZK-STARK)        |
   |                     |                     |                     |
   |                     |                     |-- Anchor on L1 ---> |
   |                     |                     |   (<400 bytes)      |
   |                     |                     |                     |
```

**Step by step:**

- **Users** send transactions signed with Schnorr (fast, 64 bytes) or SLH-DSA (quantum-resistant, 7,856 bytes) — their choice.

- **Sequencers** collect transactions, verify signatures, and execute them in a RISC-V virtual machine. They produce a new block every 3 seconds. Every block is signed twice — once with EOTS (for immediate fraud detection) and once with SLH-DSA (for quantum-resistant fraud detection).

- **STARK Provers** generate cryptographic proofs that all transactions were executed correctly. These proofs rely only on hash functions — no trusted setup required.

- **Bitcoin L1** receives a compact proof (<400 bytes per batch) anchoring the L2 state. Anyone can verify correctness by checking the proof against Bitcoin.

**Bridge (BTC to brqBTC):**
- Deposit: Send BTC to a special Taproot address. After 6 confirmations, brqBTC is minted 1:1 on L2. No sequencer can mint without cryptographic proof from Bitcoin.
- Withdraw: Burn brqBTC on L2. A liquidity operator pays you BTC immediately. A ~2 week challenge period protects against fraud. Your BTC is never at risk — it remains on Bitcoin L1.
- Operators can register up to 4 independent bonds for dispute isolation. Each withdrawal is capped at 50% of the smallest bond, ensuring economic security even with varied bond sizes.

**MEV Protection:**
Transactions are encrypted before the sequencer sees them using a production-safe `MevEncryptor` with monotonic nonce counters. The sequencer orders by gas price without knowing what the transactions do. Only after ordering is locked does decryption happen. The epoch decryption key is distributed via Shamir Secret Sharing — validators collectively reconstruct it only after ordering is finalized. No front-running, no sandwich attacks.

---

## Comparison

|  | **Brrq** | **Citrea** | **Stacks** | **Lightning** | **Liquid** |
|---|---|---|---|---|---|
| **Type** | ZK Rollup | ZK Rollup | Bitcoin Layer (PoX) | Payment Channels | Federated Sidechain |
| **Quantum-safe** | Yes | No | No | No | No |
| **Bridge** | BitVM2 (trustless) | Clementine (BitVM2) | sBTC (threshold) | Native (HTLC) | Federation (11-of-15) |
| **Governance token** | None (BTC only) | None | STX | None | None |
| **Smart contracts** | Yes (Rust) | Yes (Solidity zkEVM) | Yes (Clarity) | No | Yes (Simplicity) |
| **MEV protection** | Yes | No | Partial | N/A | No |
| **Target TPS** | 200-500 (target) | — | ~50-100 | 1,000+ | ~1,000 |
*Comparison based on publicly available documentation. Projects evolve — verify current status independently.*

Brrq is not the fastest option — Lightning handles simple payments faster. Brrq is designed for users and institutions that need smart contracts, quantum-resistant security, and trustless bridging on Bitcoin.

---

## Components

- L2 node (16 Rust crates): block production, STARK prover, consensus, BitVM2 bridge
- Portal (L3): instant payments via escrow locks + batch settlement — sub-second merchant acceptance, 15x gas savings
- API gateway: REST, JSON-RPC, WebSocket
- Post-quantum cryptography: SLH-DSA dual signing
- TypeScript SDK and block explorer

---

## Learn More

- **Whitepaper:** Full protocol specification with mathematical definitions, security analysis, and formal threat model — [whitepaper.md](whitepaper.md)

---

**Website:** https://brrq.net | **Contact:** brrq@brrq.net | **Source:** https://github.com/brrq-net/brrq

*Brrq*
