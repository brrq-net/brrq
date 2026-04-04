# Brrq: A Hash-First Execution Layer for Bitcoin

**Website:** https://brrq.net
**Contact:** brrq@brrq.net
**Source:** https://github.com/brrq-net/brrq

---

## Abstract

We propose Brrq, a Bitcoin Layer 2 execution environment built on a Hash-First Architecture (HFA) in which every cryptographic layer is designed around hash functions rather than elliptic curves. Existing Bitcoin L2 solutions — Lightning, Liquid, Stacks, Citrea, BOB — all depend on elliptic curve assumptions (ECDSA, Schnorr, BN254) that are vulnerable to Shor's algorithm on a sufficiently powerful quantum computer. Brrq structures its protocol across five cryptographic layers — signatures, proofs, state, fraud detection, and settlement — such that at launch two layers operate on pure hash functions (ZK-STARKs and SHA-256 Merkle trees), two have a hash-based path available (SLH-DSA signatures and equivocation detection), and the remaining layer (settlement) uses a transitional SNARK wrapper with three independent removal paths. The protocol employs BTC as its sole collateral and fee currency with no governance token, uses a BitVM2 bridge for trustless deposits and withdrawals, and enforces structural fairness through nine mathematical mechanisms against centralization.

---

## 1. Introduction

Bitcoin [1] processes approximately 3-7 transactions per second (depending on transaction size) with limited programmability beyond its native Script language. This throughput limitation has driven the development of Layer 2 (L2) solutions: Lightning Network for payment channels [2], Liquid as a federated sidechain with Simplicity smart contracts [3][48], Stacks with its Clarity smart contracts [4], Citrea as a ZK rollup [5], and BOB using the OP Stack [6].

All of these systems share a common structural property: their cryptographic foundations depend on elliptic curve assumptions. Lightning and Liquid use ECDSA and Schnorr signatures on secp256k1. Stacks relies on ECDSA for transaction signing. Citrea uses RISC Zero with Groth16 proofs over BN254. BOB inherits Ethereum's ECDSA infrastructure. These assumptions — specifically the hardness of the Elliptic Curve Discrete Logarithm Problem — are known to be solvable in polynomial time by Shor's algorithm [7] given a sufficiently large quantum computer.

The timeline for such a computer remains uncertain but is accelerating rapidly. As of early 2026, IBM's Condor processor contains 1,121 physical qubits, Quantinuum's Helios system has demonstrated 48 error-corrected logical qubits [8], and Gidney's 2025 paper reduced the estimated resources for breaking RSA-2048 by 95% — from 20 million to under one million noisy physical qubits [9]. Breaking secp256k1 requires approximately 2,000-2,500 logical qubits; the Global Risk Institute estimated a 17-34% probability of a cryptographically relevant quantum computer by 2034 [10]. Google's Willow processor [44], Microsoft and Atom Computing's 24 entangled logical qubit demonstration [45], and IonQ's target of 1,600 logical qubits by 2028 [49] suggested in 2025 that the gap was closing faster than expected.

Three developments in Q1 2026 have dramatically compressed this timeline — described by quantum computing researcher Scott Aaronson as "quantum computing bombshells" [53]:

1. **Iceberg Quantum (February 2026):** The Pinnacle architecture using quantum low-density parity-check (QLDPC) codes demonstrated that RSA-2048 factoring could be achieved with fewer than 100,000 physical qubits [50] — a further 10x reduction below Gidney's estimate.

2. **Google Quantum AI (March 2026):** A whitepaper co-authored with the Ethereum Foundation and Stanford University presented optimized quantum circuits for solving ECDLP-256 specifically on the secp256k1 curve — the curve securing Bitcoin and most L2 systems. The result: fewer than 1,200 logical qubits and fewer than 500,000 physical qubits, a 20x reduction from prior estimates. Google employed zero-knowledge proofs for responsible disclosure, verifying resource claims without revealing attack circuits [51].

3. **Caltech/Oratomic (March 2026):** John Preskill, Manuel Endres, Hsin-Yuan Huang, and Dolev Bluvstein demonstrated that Shor's algorithm could be executed on as few as 10,000 reconfigurable atomic qubits. Their analysis shows that a system with approximately 26,000 physical qubits could break ECC-256 in roughly 10 days, and 102,000 qubits could factor RSA-2048 in three months [52].

On the hardware side, error-corrected machines are now being delivered to customers: Microsoft and Atom Computing's Magne system provides 50 logical qubits from 1,200 physical qubits, with delivery to Denmark scheduled for early 2027 [54]. QuEra has delivered a 37-logical-qubit machine to Japan's National Institute of Advanced Industrial Science and Technology (AIST), available to global customers in 2026 [55]. Advances in fault-tolerant quantum computation — notably Williamson and Yoder's gauge-theoretic error correction method published in Nature Physics [56] — further reduce the overhead required for large-scale quantum computers. The previous estimate of 10^5 to 10^6 physical qubits for breaking secp256k1 now appears conservative; 10^4 may suffice within this decade.

Hash functions face a fundamentally different threat model. Grover's algorithm [11] provides only a quadratic speedup against hash preimage search, degrading SHA-256 from 256-bit to an effective 128-bit preimage resistance — a level that remains computationally infeasible. (Quantum collision finding via the BHT algorithm theoretically reduces collision resistance to ~85 bits, but requires impractical amounts of quantum memory.)

We present Brrq, the first Bitcoin L2 designed from day one around what we call a Hash-First Architecture: every cryptographic component is built on hash functions or has a defined migration path to hash-based alternatives. This single design decision yields four natural properties:

1. **Quantum resistance** through hash-based cryptographic primitives across all protocol layers
2. **Trustless bridging** via BitVM2 [12] with permissionless verification on Bitcoin L1
3. **BTC-native economics** with no governance token — Bitcoin is the sole collateral and fee currency
4. **Structural fairness** through nine mathematical mechanisms that bound centralization

| Property | Brrq | Citrea | Stacks | Lightning | Liquid |
|---|---|---|---|---|---|
| Type | ZK Rollup | ZK Rollup | Bitcoin Layer (PoX) | Payment Channels | Federated Sidechain |
| Quantum-resistant design | Yes (Hash-First) | No | No | No | No |
| Bridge trust model | BitVM2 (permissionless) | Clementine (BitVM2) | sBTC (threshold) | Native (HTLC) | Federation (11-of-15) |
| Governance token | None (BTC only) | None | STX | None | None |
| Smart contracts | Yes (Rust on RISC-V) | Yes (Solidity zkEVM) | Yes (Clarity) | No | Yes (Simplicity) |
| MEV protection | Yes (Commit-Reveal) | No | Partial | N/A | No |

---

## 2. Hash-First Architecture

We define the Hash-First Architecture (HFA) as a protocol design in which every cryptographic operation relies solely on the security of hash functions — no elliptic curve assumptions, no algebraic group structure, and no trusted setup.

The protocol is structured into five cryptographic layers:

```
+--------------------+  +--------------------+  +------------------------+
| Layer 1            |  | Layer 2            |  | Layer 3                |
| SIGNATURES         |  | PROOFS             |  | STATE DATA             |
| SLH-DSA (FIPS 205) |  | ZK-STARKs (FRI)    |  | SHA-256 Merkle Trees   |
| Hash-based         |  | Hash-based         |  | Hash-based             |
+--------------------+  +--------------------+  +------------------------+

+------------------------+  +------------------------------------+
| Layer 4                |  | Layer 5                            |
| FRAUD DETECTION        |  | SETTLEMENT                         |
| SLH-DSA Equivocation   |  | STARK Verifier in BitVM (target)   |
| Hash-based             |  | Groth16 SNARK wrap (transitional)  |
+------------------------+  +------------------------------------+
```

At launch, Layers 2 and 3 operate on pure hash functions. Layers 1 and 4 have a hash-based path available (SLH-DSA is implemented alongside the default Schnorr signatures). Layer 5 uses a transitional SNARK wrapper — the internal proof is a hash-based STARK, but it is wrapped in a ~300-byte SNARK (Groth16 over BN254) for efficient on-chain verification. Three independent paths exist for removing this wrapper: (a) a native STARK verifier implemented in Bitcoin Script via BitVM2 sub-programs [36], (b) maturation of quantum-resistant SNARK constructions (lattice-based or hash-based), and (c) a Bitcoin soft fork enabling OP_CAT for direct STARK verification. Any single path suffices.

The security argument for hash functions is straightforward. Shor's algorithm breaks the discrete logarithm problem underlying all elliptic curve cryptography — rendering ECDSA, Schnorr, and pairing-based systems (BN254, BLS12-381) completely insecure. Grover's algorithm, by contrast, provides only a square-root speedup against hash pre-image search, degrading SHA-256 from 256-bit to 128-bit effective preimage security. A system built on hash functions degrades gracefully under quantum attack rather than catastrophically. Google's March 2026 paper [51] makes this distinction concrete: optimized quantum circuits now target the specific secp256k1 curve used by Bitcoin, reducing the resources needed to break it by 20x — while hash-based primitives remain entirely unaffected by these advances.

---

## 3. Transactions and Signatures

Brrq offers two signature schemes operating in parallel:

| Mode | Scheme | Standard | Signature Size | Verification Time | Use Case |
|---|---|---|---|---|---|
| Classical (default) | Schnorr | BIP-340 | 64 bytes | ~0.05 ms | Daily transactions |
| Post-quantum (optional) | SLH-DSA-SHA2-128s | FIPS 205 | 7,856 bytes | ~0.23-0.30 ms | Institutional vaults, long-term storage |

SLH-DSA (formerly SPHINCS+) is a stateless hash-based signature scheme standardized by NIST in 2024 [13][31]. Hardware acceleration techniques using SHA-NI and AVX2 instructions can improve SLH-DSA performance by 10-100x [35]. It constructs signatures entirely from Merkle trees and hash function evaluations — no elliptic curves, no lattice assumptions. The choice of SLH-DSA over alternatives is constrained:

- **ML-DSA-65 (Dilithium)** offers smaller signatures (3,309 bytes) but is built on lattice assumptions, violating the Hash-First Architecture.
- **XMSS [32] and LMS [33]** are hash-based and compact (~1.5-2.5 KB) but are stateful — reusing a one-time signature index breaks security entirely. In a decentralized environment where wallets may be replicated across devices, stateful schemes are unacceptable.
- **SLH-DSA-SHA2-128s** is the only scheme that satisfies all three requirements: hash-based (HFA-compliant), stateless (safe under replication), and standardized (FIPS 205). The Open Quantum Safe project provides reference implementations [34], and the choice between 128s (small, slower) and 128f (fast, larger) parameter sets is analyzed in [40].

The transition from Schnorr to SLH-DSA follows a milestone-driven schedule rather than fixed calendar dates: Stage 1 (launch) makes SLH-DSA available as a user-selectable option; Stage 2 (triggered by concrete quantum hardware advances) makes SLH-DSA the default for new wallets; Stage 3 (triggered by an imminent quantum threat) makes SLH-DSA mandatory for all new transactions.

On L2, Brrq uses an account model rather than Bitcoin's UTXO model, as it better supports stateful smart contracts. Each account consists of a 20-byte address derived from SHA-256 of the public key, a balance denominated in brqBTC (1:1 pegged to BTC), a nonce for replay protection, a code hash (for contract accounts), and a storage root (Merkle root of contract state).

---

## 4. Execution Environment

Transactions on Brrq are executed within a zero-knowledge virtual machine (zkVM) implementing the RISC-V RV32IM instruction set — a 32-bit base integer ISA with the multiplication extension. The choice of RISC-V is motivated by its adoption across production zkVMs: SP1 Hypercube (Succinct) [14], R0VM 2.0 (RISC Zero) [15], and Airbender (ZKsync) [16]. An alternative approach using binary fields (Binius [37]) is under consideration for future optimization. The VM provides 64 MB of addressable memory in a Harvard-style architecture where code is read-only.

Gas metering is tied directly to the cost of generating a STARK proof for each operation, ensuring that fees reflect actual computational burden rather than arbitrary units:

| Operation | Gas Cost | Rationale |
|---|---|---|
| Arithmetic (ADD, MUL) | 1-3 | Single RISC-V cycle |
| Memory access (LOAD, STORE) | 5-10 | Requires memory access proof |
| SHA-256 precompile | 50 | Hardware-accelerated |
| Schnorr verification precompile | 100 | Single curve operation |
| SLH-DSA verification precompile | 500 | Large signature, many hash evaluations |
| Merkle path verification precompile | 30-60 | Depth-dependent |

The execution engine implements what we call Bifurcated State Logging to eliminate free-riding denial-of-service attacks. Every transaction's effects are internally divided into intrinsic changes (gas payment and nonce update) and execution changes (contract state modifications). If a transaction fails during execution — due to gas exhaustion, a revert, or a runtime error — the execution changes are rolled back but the intrinsic changes are committed. This guarantees that an attacker cannot consume sequencer resources without paying the full economic cost of gas, eliminating costless mempool spam.

---

## 5. Proof System

Brrq generates validity proofs using ZK-STARKs (Zero-Knowledge Scalable Transparent Arguments of Knowledge) [17]. The construction, building on the SP1 prover architecture [14], proceeds as follows:

1. **Execution trace:** The zkVM records every state transition during transaction execution as a 152-column trace table (76 base execution columns plus auxiliary columns for bitwise operations, memory permutations, and cross-table arguments) over the BabyBear prime field (p = 2^31 - 2^27 + 1). Base columns capture the program counter, general-purpose registers, memory operations, ALU results, and control flags.

2. **Algebraic Intermediate Representation (AIR):** Polynomial constraints encode the correctness rules — each valid state transition satisfies a set of low-degree polynomial equations over the trace columns. Invalid execution violates at least one constraint.

3. **FRI commitment:** The trace polynomials are committed using the Fast Reed-Solomon Interactive Oracle Proof (FRI) protocol [18], which reduces polynomial evaluation claims to Merkle tree path checks. Domain-separated SHA-256 commitments provide 128-bit security via 64 FRI queries.

4. **Fiat-Shamir transform:** Interactive verifier challenges are replaced by domain-keyed SHA-256 hashes of the transcript, producing a non-interactive proof. Poseidon2 [20] is used for FRI commitment Merkle trees in the SNARK wrapping layer, not for Fiat-Shamir challenges.

The protocol uses a dual hash system optimized for different contexts:

- **SHA-256** for all L1-facing data: state roots registered on Bitcoin, inclusion proofs, and bridge commitments. This provides compatibility with Bitcoin's native hash function and benefits from SHA-NI hardware acceleration.
- **Poseidon2** [20] for zkVM-internal computations: state trees within smart contracts and proof transcript hashing. Poseidon2 is an algebraic hash function (not an elliptic curve construction) that is significantly more efficient than SHA-256 inside arithmetic circuits. Its security degrades under Grover's algorithm identically to SHA-256 — it remains HFA-compliant. Ongoing cryptanalysis efforts [42][43] have not found practical attacks on Poseidon2, though its shorter track record relative to SHA-256 motivates its restriction to internal-only use.

Recursive proof aggregation [39] combines multiple batch proofs into a single composite proof, reducing L1 settlement frequency from approximately 20 per hour to 1-3 per hour — a 7-20x reduction in on-chain cost.

The transitional SNARK wrapping compresses a STARK proof (10-100 KB) into a ~300-byte SNARK for efficient Bitcoin L1 verification. Importantly, the internal proof is always a hash-based STARK; only the final L1 verification step relies on the BN254 curve. This wrapping is explicitly temporary, with three independent removal paths defined in Section 2.

---

## 6. Data Availability

Brrq employs a dual data availability model:

**L1 anchoring:** Each batch posts less than 400 bytes to Bitcoin: a 32-byte state root (SHA-256 Merkle root [38] of the full L2 state), a ~300-byte wrapped SNARK proof, and a 32-byte batch fingerprint. This is sufficient to verify correctness and prove account balances.

**Full node network:** Complete state diffs and compressed transaction data are maintained by the network of full nodes. Sequencers are required to store and serve this data as a precondition for consensus participation — failure to provide data availability disqualifies a sequencer from earning rewards. Provers require full transaction data to generate STARK proofs, creating a natural economic incentive for data retention.

Light clients can verify their balances by requesting a Merkle inclusion proof (~1 KB) and checking it against the state root anchored on Bitcoin L1. This requires no trust in any L2 participant — only trust in Bitcoin's own consensus.

DAS integration is a research direction for enhanced data availability. A hybrid on-chain/off-chain DA model (volition) as proposed by StarkWare [47] is another viable direction.

---

## 7. Bridge

The Brrq bridge enables trustless transfer of BTC between Bitcoin L1 and the Brrq L2, producing a 1:1 pegged asset called brqBTC.

### 7.1 BitVM2

The bridge uses BitVM2 [12], which reduces the challenge-response dispute protocol to three on-chain transactions (compared to dozens in BitVM1), limits the on-chain footprint to less than 4 MB, and enables permissionless challenging — any observer can submit a dispute, not just a designated set. Early implementations of BitVM2 bridges include Bitlayer's mainnet beta [28] and Citrea's Clementine design [46]. The GOAT Network BitVM2 whitepaper [29] and Fidelity Digital Assets' analysis [30] provide additional context on bridge economics and trust assumptions.

### 7.2 Deposits (Peg-in)

A user deposits BTC by sending it to a Taproot address encumbered with BitVM2 conditions. After six L1 confirmations, the deposit is verified by a Zero-Trust SPV Enclave embedded in the consensus engine. No sequencer can mint brqBTC without a cryptographic proof derived directly from Bitcoin block headers — the sequencer submits a synthetic deposit transaction, and the bridge manager verifies the existence of a valid SPV Merkle proof before authorizing minting. A dedicated Merkle tree of processed deposits prevents replay attacks. Daily deposit limits provide an additional safety margin against zero-day exploits.

```
User                          Bitcoin L1                  Brrq L2
  |                              |                          |
  |-- BTC to Taproot address --> |                          |
  |   (BitVM2 conditions)        |                          |
  |                              |-- 6 confirmations -----> |
  |                              |                   [SPV Verification]
  |                              |                   [No mint without]
  |                              |                   [L1 proof      ]
  |                              |                          |
  |<----------- brqBTC minted (1:1) in user's L2 wallet --|
```

### 7.3 Withdrawals (Peg-out)

Withdrawal follows a four-step process:

1. The user burns brqBTC on L2 and specifies a Bitcoin destination address.
2. A liquidity operator immediately pays BTC to the user from the operator's own funds.
3. The operator publishes a Kickoff transaction on Bitcoin L1, opening an approximately two-week challenge window.
4. If no valid Disprove transaction is submitted during the challenge period, the operator claims their bond via a Take transaction. If a challenger proves the operator's claim was fraudulent (via a Disprove transaction), the operator forfeits their bond.

Each operator may register up to 4 independent BitVM2 bonds (`MAX_BONDS_PER_OPERATOR = 4`), each with its own `verified_onchain` status. This multi-bond architecture isolates disputes — a challenge against one bond does not affect the operator's other bonds. The exposure cap for any single withdrawal is bounded by `smallest_bond × 50%` (not total bond value), ensuring economic security even when bond values vary. The global verification flag is set only when all of an operator's bonds have been individually verified on-chain.

The trust model requires only a 1-of-N honest assumption among the initial signer committee (for covenant simulation until Bitcoin natively supports covenants) and permits fully permissionless challenging. One honest observer is sufficient to prevent fraud.

### 7.4 Failure Recovery

If BitVM2 proves unable to achieve the required security guarantees, the bridge can fall back to a federated model with a 12-of-15 threshold — a higher security threshold than Liquid's 11-of-15 [3]. This fallback includes a mandatory sunset timer enforced in code: the federated mode automatically expires, forcing a transition back to permissionless verification when BitVM2 or its successors mature. The fallback is strictly an emergency measure, not a design target. In the worst case, withdrawals are delayed but funds are never lost — user BTC remains locked in UTXOs on Bitcoin L1.

---

## 8. Consensus and Slashing

Brrq uses a Proof-of-Stake consensus mechanism with BTC as the sole collateral asset, drawing on Bitcoin staking constructions from Babylon Labs [23][24]. There is no separate staking token.

### 8.1 Network Roles

**Sequencers** receive transactions, verify signatures, order them into blocks (produced every 3 seconds), and sign each block. They must lock BTC in a Taproot UTXO on Bitcoin L1 as collateral.

**Provers** generate STARK proofs for transaction batches. They operate in a competitive market — the fastest valid proof earns the proving reward. No collateral is required. Prover pools allow participants with modest hardware (4 GB GPU VRAM minimum) to contribute collectively.

### 8.2 Dual Signing

Every sequencer signs each block with two independent signatures:

**(a) Schnorr/EOTS (Extractable One-Time Signature):** The sequencer derives a deterministic nonce from `HMAC-SHA256(sk, "EOTS_NONCE" || height || epoch)`. If a sequencer equivocates — signing two different blocks at the same height — the two signatures with the same nonce allow anyone to extract the sequencer's private key via `sk = (s1 - s2) / (e1 - e2) mod n`. The extracted key enables immediate, self-enforcing slashing with no committee or governance vote required.

**(b) SLH-DSA equivocation:** The sequencer also signs each block with their SLH-DSA key. Two different SLH-DSA signatures at the same block height constitute a mathematical proof of equivocation — verifiable by anyone using only hash function computations. This mechanism is quantum-resistant by construction.

Either mechanism alone provides equivocation detection. Together they provide defense in depth: even if a quantum computer breaks the Schnorr-based EOTS, the SLH-DSA equivocation proof remains valid. The protocol plans to retire EOTS once the SLH-DSA path is fully operational, achieving pure hash-based fraud detection.

### 8.3 Key Isolation

Each sequencer maintains three cryptographically independent keys to limit exposure:

- **main_key** (Schnorr, secp256k1): Identity key that controls the main UTXO holding 66.67% of the sequencer's stake. Never used for block signing.
- **eots_key** (EOTS, secp256k1): Signs blocks for EOTS equivocation detection. Controls the bond UTXO holding 33.33% of the stake. Derived deterministically from the epoch seed and rotated every epoch — old keys are destroyed.
- **slh_dsa_key** (SLH-DSA, FIPS 205): Signs blocks for hash-based equivocation detection. Quantum-resistant. Never exposed even under equivocation (SLH-DSA does not have the extractability property of EOTS).

This isolation ensures that equivocation exposes at most the bond UTXO (33.33%), not the full stake.

### 8.4 Graduated Slashing

| Offense | Penalty | Trigger |
|---|---|---|
| Extended downtime (>10 timeouts in 24 hours) | 5% of bond | Non-adversarial — may be a technical failure |
| Proven deliberate delay (repeated pattern) | 15% of bond | Requires 60% sequencer vote + on-chain evidence |
| Equivocation (two blocks at same height) | 33.33% of bond | Automatic — mathematical proof, no committee |

Slashed funds are distributed: 70% burned, 20% to the challenger who detected the offense, 10% to the community fund. The challenger reward creates a positive economic incentive for network monitoring.

The slashing mechanism is formally verified through model checking, ensuring that equivocation is always attributable and no honest validator can be falsely slashed. Core safety properties — including uniqueness of finalization at each height, finalization stability, and quorum requirements — are verified alongside slashing completeness.

Additionally, the simulation framework includes Byzantine fault injection testing that intercepts messages from designated Byzantine nodes and applies mutation strategies including equivocation, liveness attacks, timeout testing, verification testing, and replay protection testing. This enables systematic Byzantine fault injection testing across the full consensus pipeline.

### 8.5 Effective Stake Cap

To prevent plutocratic control, voting power (effective stake) is bounded by a sublinear function:

```
f(s) = s                        if s <= Cap
f(s) = Cap + sqrt(s - Cap)      if s > Cap
```

where `Cap = 3 * TWAP_30d(median(active_stakes))` is a dynamic threshold calculated as three times the 30-day time-weighted average price of the median active stake. Under this formula, a sequencer with 500 BTC in a network where the cap is 100 BTC has an effective stake of only 120 BTC — a 76% reduction in influence. Meanwhile, a small sequencer with 15 BTC retains their full 15 BTC effective stake.

Leader election is weighted by effective stake using rejection sampling to ensure unbiased selection.

### 8.6 Time Protection and Secure Unbonding

The protocol does not rely on local system clocks to avoid fork-inducing time disagreements. Instead, block timestamps must exceed the Median Time Past (MTP) of the previous 11 blocks, with a bounded future drift allowance — following Bitcoin's own MTP rule. This deterministic time model ensures that STARK proofs can be generated without depending on non-deterministic external inputs.

Stake withdrawal follows a mandatory 28-day unbonding period. This duration is deliberately set to exceed the BitVM2 challenge period (approximately 14 days) by a factor of two, ensuring that a sequencer cannot initiate unbonding and escape with their stake before a pending fraud challenge can be resolved.

### 8.7 Liveness Recovery (U-ZKHR)

Standard L2 protocols face a fundamental paradox: if 34% of validators halt the network, no new blocks can be produced through which to remove the halted validators. Brrq resolves this with the Unbonded Zero-Knowledge Liveness Recovery (U-ZKHR) protocol:

1. **Bitcoin as clock:** If 144 Bitcoin blocks (~24 hours) pass with no new L2 block registered on L1, a liveness fault is declared. Bitcoin L1 serves as an unforgeable external clock that cannot be halted.

2. **L1 anchor transaction:** A coalition holding >50% of the remaining effective stake publishes an L1ZklaAnchor transaction (OP_RETURN, ~300 bytes) containing: (a) the last agreed L2 state root, (b) public keys of non-producing sequencers, (c) a STARK proof that these sequencers failed to produce blocks during the 144-block window, and (d) signatures from the >50% coalition.

3. **Force unbond:** L2 nodes that observe the anchor transaction verify the STARK proof and signatures, then execute a forced unbond of the non-producing sequencers. The quorum is recalculated over the remaining set. Crucially, no funds are slashed — downtime is not proof of malice (it could result from an eclipse attack isolating honest nodes). Unbonded funds enter the standard 28-day withdrawal queue.

### 8.8 Game-Theoretic Analysis

Honest sequencing is a Nash equilibrium under the protocol's incentive structure:

| Strategy | Expected Outcome | Profitable? |
|---|---|---|
| Honest sequencing | Retain full bond + earn transaction fees | Yes |
| Equivocation | Lose 33.33% of bond (automatic) | No |
| Transaction censorship | Challenged via forced inclusion; no profit | No |
| Collusion to frame competitor | Impossible — equivocation requires two valid signatures from the target's own key | Impossible |
| Network monitoring | Earn 20% of any slashing detected | Yes |

The penalty for equivocation (33.33% bond loss) exceeds any realistic profit from double-spending, and the 20% challenger reward ensures that monitoring is economically rational.

---

## 9. MEV Protection

Maximal Extractable Value (MEV) — profit extracted by reordering, inserting, or censoring transactions — is a structural problem in most L2 systems where the sequencer sees transaction contents before ordering them.

Brrq implements a Commit-Reveal scheme similar in spirit to Shutter Network's encrypted mempool [25] and Chainlink's Fair Sequencing Services [26], but using an epoch key derived entirely from hash functions:

1. **Commit phase:** Each transaction is submitted as an encrypted envelope via `MevEncryptor`, a production-safe wrapper that uses a monotonic `NonceCounter` (format: `node_id[8] || counter_be[8]`) to guarantee nonce uniqueness across blocks and epochs. The transaction kind (transfer, contract call, deposit, withdrawal) is encrypted using HMAC-SHA-256 in counter mode (CTR) with the epoch key — using HMAC rather than raw SHA-256 to prevent length-extension attacks inherent in Merkle-Damgard constructions. Transaction metadata — sender address, gas price, and nonce — remains in cleartext to allow ordering. The sequencer orders transactions by gas price without knowing their contents. The `MevEncryptor` supports state recovery after node restart via `new_recovering(node_id, last_block_in_epoch, max_txs_per_block)`.

2. **Lock:** The ordering is cryptographically committed and cannot be changed.

3. **Reveal phase:** The sequencer publishes the epoch key, all transactions are decrypted, and execution proceeds in the committed order.

**Epoch key distribution** uses Shamir Secret Sharing: at each epoch transition, the epoch key is split into shares and distributed to validators via `ShareDistribution` network messages. Each message contains the epoch number, share index, 32-byte share data, recipient address, sender address, and a cryptographic signature. Receiving nodes collect shares in a `PendingShares` accumulator; once the threshold is reached, the epoch key is reconstructed automatically. Shares from non-validators or wrong epochs are rejected.

The epoch key is derived deterministically from the epoch seed: `epoch_key = tagged_hash("BRRQ_EPOCH_KEY", epoch_seed || epoch_number)`. No intermediaries or elliptic curves are involved — the entire scheme uses SHA-256, maintaining HFA compliance. The use of authenticated encryption rather than AES or ChaCha20 is deliberate: it keeps the protocol's cryptographic surface area to a single well-studied primitive.

Within each batch, transactions are ordered by a deterministic hash: `order = SHA-256(tx_data || block_hash)`, which produces a pseudo-random ordering that no party can predict or manipulate. Recent work on batched threshold encryption [27] suggests further improvements to commit-reveal schemes that may be incorporated in future protocol versions.

---

## 10. Governance and Structural Fairness

### 10.1 Immutable Laws

Three constitutional laws are enforced automatically by a DoctrineFirewall — a filter implemented at the node level that rejects violating proposals before they reach a vote:

1. **Key sovereignty:** No entity — including sequencers, operators, and developers — may access or block user private keys.
2. **Hash-First Architecture:** No new elliptic curve primitives may be introduced as permanent replacements in the protocol's cryptographic stack.
3. **Unconditional exit right:** Every user's right to withdraw brqBTC to Bitcoin L1 via the bridge may never be suspended or delayed by any governance vote, protocol update, or declared emergency.

Any proposal that violates these laws is auto-rejected with a logged reason. No vote threshold can override them.

### 10.2 Three-Chamber Governance

Governance decisions require approval from up to three chambers depending on the decision type:

**Sequencer Chamber:** Every registered sequencer with locked BTC. Votes are weighted by effective stake (after the square-root cap). Approval threshold: 67% of total effective stake.

**User Chamber:** Any user meeting triple Sybil resistance criteria: at least 10 real transactions in the past 90 days, a minimum balance of 0.01 BTC maintained during voting, and an account age of at least 60 days. Votes are weighted by the square root of the user's balance in satoshis — a form of quadratic voting that limits the influence of large holders. Approval threshold: 51% of participating votes. The User Chamber holds absolute veto power over proposals affecting consensus or bridge parameters.

**Technical Council:** Seven elected members — three security auditors, two core protocol developers, and two cryptographers — nominated by the Sequencer Chamber and confirmed by 67% of the User Chamber. Terms are six months, non-consecutively renewable, with a maximum of one member per organization. The Council holds a security veto (30-day pause for audit) and must produce a mandatory technical report before voting begins on any technical or constitutional proposal. The Council cannot propose legislation.

| Proposal Type | Sequencer Chamber | User Chamber | Technical Council | Time-lock |
|---|---|---|---|---|
| Technical Update | 67% | — | Mandatory report | 7 days |
| Fee Change | 67% | 51% | — | 3 days |
| Slashing Change | 67% | 75% | Mandatory report | 14 days |
| Bridge Update | 67% | 75% | Security veto + report | 28 days |
| Consensus Change | 80% | 80% | Mandatory report | 28 days |
| Constitutional | 90% | 90% | Security veto + report | 56 days |
| Emergency Patch | 80% | — | 5-of-7 approval | 72 hours |

### 10.3 Rage Quit

During any time-lock period, users may execute a Rage Quit — withdrawing their full brqBTC balance to Bitcoin L1 in protest. Rage Quit withdrawals are fee-exempt and processed with highest priority. If cumulative Rage Quit withdrawals exceed 33% of total brqBTC supply, the triggering proposal is automatically cancelled (VetoedByExodus). Time-lock durations are set to at least twice the BitVM2 challenge period (~28 days) to ensure users have sufficient time to exit.

### 10.4 Nine Mechanisms Against Centralization

The protocol enforces structural fairness through nine protocol-level mechanisms, each implemented in code rather than social norms:

1. **Effective stake cap** (square-root function above dynamic threshold)
2. **Three-chamber governance** (sequencers, users, and technical council)
3. **Triple Sybil resistance** (activity, balance, and account age requirements)
4. **Elected covenant committee** (9 members with geographic and institutional diversity constraints)
5. **Delegated staking** (small holders participate without running infrastructure)
6. **Progressive fee schedule** (larger transactions pay proportionally higher protocol fees)
7. **Temporal fairness** (no early-mover advantage — reputation considers only the last 6 months)
8. **Geographic fairness** (no more than 33% of sequencers from any single geographic region)
9. **Guaranteed exit rights** (28-day unbonding period; unconditional withdrawal at any time)

---

## 11. Incentives

The total fee for each transaction is: `TotalFee = BaseFee + PriorityFee + ProtocolFee`.

The base fee follows an EIP-1559-adapted mechanism [22]: it increases by up to 12.5% when blocks exceed 50% gas utilization and decreases symmetrically when below. Base fees are burned — reducing the circulating brqBTC supply — with a cumulative burn cap of 5% of initial supply and a per-epoch rate limit of 0.1% to prevent deflationary spirals. Once caps are reached, excess burns redirect to the protocol treasury.

The priority fee (tip) is paid to the block-producing sequencer. The protocol fee is a fixed 10% share of each transaction's fee, allocated as: 40% development and maintenance, 25% security fund (audits and bug bounties), 20% ecosystem fund (developer grants and education), and 15% emergency reserve.

No governance token exists. BTC, in the form of brqBTC, is the sole currency for all fees, collateral, and staking. Target transaction costs are 100-400 satoshis for Schnorr-signed transfers and 400-1,000 satoshis for SLH-DSA-signed transfers. Brrq does not aim to be the cheapest Bitcoin L2 — Lightning is cheaper for simple payments — but rather the most structurally secure.

---

## 12. Security Analysis

### 12.1 Threat Model

We assume an attacker with the following capabilities:

| Capability | Bound |
|---|---|
| Financial resources | Controls up to 30% of total stake |
| Computational resources | Can run full nodes and provers |
| Collusion | Can coordinate with up to f < N/3 sequencers |
| Network | Can delay messages but not permanently partition the network |
| Quantum (future) | Possesses a quantum computer capable of breaking elliptic curve cryptography |

### 12.2 Protected Objectives

1. **Fund safety:** It must be impossible to mint brqBTC without a corresponding BTC deposit or to steal existing brqBTC balances.
2. **State integrity:** No invalid state transition can be registered on Bitcoin L1.
3. **Censorship resistance:** Any valid transaction must be included within a bounded time period.
4. **Exit guarantee:** A user must always be able to withdraw their BTC from L2, even if the L2 network halts entirely.

### 12.3 Quantum Security Assessment

| Layer | Primitive | Quantum-Safe | Analysis |
|---|---|---|---|
| Signatures | SLH-DSA (FIPS 205) | Yes | Built entirely on hash function evaluations |
| Proofs | ZK-STARKs (FRI) | Yes | Hash-based polynomial commitments, no curves |
| State data | SHA-256 Merkle trees | Yes | Grover degrades to 128-bit — computationally safe |
| Fraud detection | SLH-DSA equivocation | Yes | Hash-based signature comparison |
| Settlement (target) | STARK verifier in BitVM | Yes | Hash computations in Bitcoin Script |
| Settlement (transitional) | Groth16 over BN254 | **No** | Pairing-based; removal scheduled via three paths |
| Bitcoin L1 | ECDSA / Schnorr | **No** | Outside Brrq's control — Bitcoin community's responsibility |

Brrq directly controls five cryptographic layers. At launch, two layers are pure hash-based, two have hash-based alternatives available, and one is transitional. The design target is 5/5 hash-based — achievable through any one of the three SNARK wrapper removal paths.

### 12.3.1 Updated Threat Assessment (Q1 2026)

Three independent research efforts published between February and March 2026 have dramatically reduced the estimated quantum resources required to break elliptic curve cryptography:

| Estimate | Whitepaper Baseline | Google March 2026 [51] | Caltech/Oratomic March 2026 [52] |
|---|---|---|---|
| Target | secp256k1 (ECDLP-256) | secp256k1 (ECDLP-256) | P-256 / secp256k1 |
| Logical qubits | 2,000-2,500 | < 1,200 | ~1,000 (estimated) |
| Physical qubits | 10^5 - 10^6 | < 500,000 | ~26,000 |
| Time to break | — | Minutes | ~10 days |

These results represent a cumulative reduction of approximately two orders of magnitude in physical qubit requirements compared to estimates available as recently as mid-2025. The Caltech/Oratomic result is particularly significant: 26,000 reconfigurable atomic qubits is within the hardware scaling trajectory that both QuEra and Atom Computing have publicly committed to achieving within the next few years [54][55].

NIST IR 8547 [57] now establishes a formal deprecation timeline for classical cryptographic algorithms vulnerable to quantum attack, with NSA requiring compliance for national security systems by January 2027. The "harvest now, decrypt later" threat — adversaries capturing encrypted traffic today for future quantum decryption — is assessed as an active operational risk by multiple intelligence agencies, making the migration timeline urgent even before a cryptographically relevant quantum computer is built.

Concurrently, BIP-360 (Pay-to-Merkle-Root) was merged into the official BIP repository on February 11, 2026 [58], laying the structural foundation for future post-quantum signature schemes on Bitcoin L1 — though actual deployment remains 5-10 years away. On the sidechain front, Blockstream demonstrated quantum-resistant transaction signing on Liquid in March 2026 using Simplicity smart contracts and a custom SHRINCS signature scheme [59] — the first post-quantum spending condition executed on a production Bitcoin sidechain. However, this remains an opt-in spending condition on a federated sidechain (11-of-15), not a full L2 with native post-quantum security across all protocol layers.

Hardware acceleration of SLH-DSA is materializing: SPHINCSLET [60] provides the first fully standard-compliant FPGA implementation (AMD Artix-7, <10.8K LUTs), and the SLotH project offers open-source Verilog for both FPGA and ASIC flows — validating Brrq's choice of SLH-DSA as a production-viable signature scheme.

For Brrq, these developments confirm that Hash-First Architecture is not merely a precautionary design choice but an operational necessity. The availability of SLH-DSA as an opt-in signature scheme from launch (Stage 1) positions Brrq users to transition to quantum-resistant signatures before the threat materializes, rather than requiring an emergency protocol upgrade under time pressure. The urgency of removing the transitional Groth16 SNARK wrapper (Layer 5) has increased correspondingly — the BN254 pairing curve underlying Groth16 faces the same class of quantum attack as secp256k1.

### 12.4 Bridge Security

The Zero-Trust SPV Enclave ensures that no brqBTC can be minted without a valid Bitcoin block header proof. The BitVM2 dispute game ensures that fraudulent withdrawals are caught by any honest observer within the challenge period. In the worst case (complete L2 failure), user BTC remains locked in UTXOs on Bitcoin L1 — delayed but never lost.

---

## 13. Conclusion

Brrq introduces Hash-First Architecture as a design principle for Bitcoin Layer 2 systems: the systematic construction of every protocol layer around hash function security. This approach provides a natural path to quantum resistance without requiring a complete protocol redesign when quantum computers become practical. The dual signing mechanism (EOTS + SLH-DSA) provides defense-in-depth fraud detection, the BitVM2 bridge enables trustless operation, the absence of a governance token aligns economic incentives with Bitcoin's ethos, and nine mathematical mechanisms enforce structural fairness against centralization.

The Q1 2026 quantum computing developments — a 20x reduction in resources for breaking secp256k1 [51], a demonstration that Shor's algorithm may require as few as 26,000 physical qubits [52], and NIST's formal deprecation timeline for vulnerable algorithms [57] — confirm that Hash-First Architecture is not a conservative hedge but an engineering necessity for any Bitcoin infrastructure intended to operate beyond this decade.

Research Directions:

- **Native STARK verification in Bitcoin Script:** A complete STARK verifier within BitVM2's computational model would eliminate the SNARK wrapping layer entirely.
- **Data Availability Sampling:** DAS integration would strengthen data availability guarantees across the full node network.
- **Solidity-to-Rust transpilation:** A source-level transpiler would enable Ethereum developers to deploy existing Solidity contracts on Brrq's RISC-V zkVM, broadening the developer ecosystem.
- **Privacy:** Zero-knowledge proofs for transaction privacy, allowing users to transact without revealing amounts or counterparties on the public L2 state.
- **Portal (L3 instant payments):** The Pragmatic Portal Protocol extends Brrq with an escrow-lock-based payment layer that enables sub-second merchant acceptance and batch settlement (up to 100 claims per L2 transaction). See the Portal Whitepaper for the full specification.

---

## References

### Post-Quantum Cryptography

[1] S. Nakamoto, "Bitcoin: A Peer-to-Peer Electronic Cash System," 2008.

[2] J. Poon and T. Dryja, "The Bitcoin Lightning Network: Scalable Off-Chain Instant Payments," 2016.

[3] Blockstream, "Liquid Network Technical Overview," 2018. Updated: Simplicity Smart Contracts Launch, July 2025.

[4] Stacks Foundation, "Stacks: A Bitcoin Layer for Smart Contracts — Nakamoto Upgrade and sBTC," 2024.

[5] Citrea, "Bitcoin's First ZK Rollup — Mainnet Launch," January 27, 2026. (Clementine BitVM2 bridge live with real funds.)

[6] BOB (Build on Bitcoin), "BOB Documentation — OP Stack Hybrid L2," 2025.

[7] P. W. Shor, "Polynomial-Time Algorithms for Prime Factorization and Discrete Logarithms on a Quantum Computer," SIAM Journal on Computing, vol. 26, no. 5, pp. 1484-1509, 1997.

[8] Quantinuum, "Helios: 48 Error-Corrected Logical Qubits," November 2025.

[9] C. Gidney, "How to Factor 2048-bit RSA Integers with Less Than a Million Noisy Qubits," arXiv:2505.15917, 2025. (Supersedes the 2019 estimate of 20 million qubits.)

[10] Global Risk Institute, "Quantum Threat Timeline: 17-34% Probability of Cryptographically Relevant Quantum Computer by 2034," 2024.

[11] L. K. Grover, "A Fast Quantum Mechanical Algorithm for Database Search," Proceedings of the 28th Annual ACM Symposium on Theory of Computing, pp. 212-219, 1996.

[12] R. Linus, "BitVM2: Permissionless Verification on Bitcoin," 2024.

[13] NIST, "FIPS 205 — Stateless Hash-Based Digital Signature Standard (SLH-DSA)," 2024.

### Zero-Knowledge Proofs

[14] Succinct Labs, "SP1 Hypercube: Multilinear Polynomial Proof System," 2025-2026.

[15] RISC Zero, "R0VM 2.0: 47x Speedup for Ethereum Block Proving," 2025.

[16] ZKsync, "Airbender: 21.8M cycles/sec Open-Source RISC-V zkVM," June 2025.

[17] E. Ben-Sasson, I. Bentov, Y. Horesh, and M. Riabzev, "Scalable Zero Knowledge with No Trusted Setup," Advances in Cryptology — CRYPTO 2019.

[18] E. Ben-Sasson, I. Bentov, Y. Horesh, and M. Riabzev, "Fast Reed-Solomon Interactive Oracle Proofs of Proximity," Proceedings of the 45th ICALP, 2018.

[19] L. Grassi, D. Khovratovich, C. Rechberger, A. Roy, and M. Schofnegger, "Poseidon: A New Hash Function for Zero-Knowledge Proof Systems," USENIX Security Symposium, 2021.

[20] L. Grassi, D. Khovratovich, and M. Schofnegger, "Poseidon2: A Faster Version of the Poseidon Hash Function," AFRICACRYPT, 2023.

### Data Availability

[21] Celestia, "Blob Economics and Data Availability Costs," 2024.

### Ethereum Fee Market

[22] V. Buterin, E. Conner, R. Dudley, M. Slipper, I. Norden, and A. Bakhta, "EIP-1559: Fee Market Change for ETH 1.0 Chain," 2019.

### Proof of Stake and Bitcoin Staking

[23] Babylon Labs, "Bitcoin Staking Protocol Specification," 2024.

[24] Babylon Labs, "Bitcoin Staking Scripts (Taproot) and EOTS," 2024.

### MEV Protection

[25] Shutter Network, "Threshold Encrypted Mempool on Gnosis Chain," Live July 2024.

[26] Chainlink, "Fair Sequencing Services (FSS)," 2021.

[27] BEAST-MEV, "Batched Threshold Encryption," ePrint 2025/1419.

### Competitive Analysis

[28] Bitlayer, "BitVM Bridge Mainnet Beta," July 2025.

[29] GOAT Network, "BitVM2 Whitepaper 1.0," 2024.

[30] Fidelity Digital Assets, "Overview of BitVM," 2025.

### Hash Architecture and Cryptographic Foundations

[31] NIST, "Post-Quantum Cryptography Standardization Process — Final Standards," 2024.

[32] RFC 8391, "XMSS: eXtended Merkle Signature Scheme," 2018.

[33] RFC 8554, "Leighton-Micali Hash-Based Signatures (LMS)," 2019.

[34] Open Quantum Safe Project, "liboqs SLH-DSA Implementation," 2024.

[35] conduition.io, "Making SLH-DSA 10x-100x Faster with SHA-NI, AVX2, and GPU Acceleration," 2025.

[36] StarkWare and Bitcoin Wildlife Sanctuary, "ColliderVM and Circle STARK Verifier for Bitcoin Script," 2025.

### Implementation Techniques

[37] B. Diamond and J. Posen, "Binius: Efficient Proofs over Binary Fields," 2024.

[38] R. Dahlberg, T. Pulls, and R. Peeters, "Efficient Sparse Merkle Trees: Caching Strategies and Secure (Non-)Membership Proofs," ePrint 2016/683, 2016.

[39] B. Bunz, A. Chiesa, P. Mishra, and N. Spooner, "Recursive Proof Composition from Accumulation Schemes," TCC 2020, ePrint 2020/499.

[40] NIST, "FIPS 205 — Stateless Hash-Based Digital Signature Standard," Section 10: Parameter Sets, 2024.

### Recent Research (2025-2026)

[41] StarkWare, "Stwo Prover (Circle STARK, Mersenne Prime Field)," 2025.

[42] L. Grassi et al., "Poseidon and Neptune: Groebner Basis Cryptanalysis," IACR ToSC, 2025.

[43] Ethereum Foundation, "Poseidon Cryptanalysis Initiative," 2024-2026.

[44] Google Quantum AI, "Willow: Below Surface Code Threshold," Nature, 2025.

[45] Microsoft and Atom Computing, "24 Entangled Logical Qubits (Computation on 28 Logical Qubits)," 2025.

[46] Citrea, "R&D for Clementine v2: Garbled SNARK Verifiers + TOOP," 2025.

[47] StarkWare, "Volition: Hybrid Data Availability (Proposed Design)," 2024. (Not yet deployed on Starknet mainnet as of April 2026.)

[48] Blockstream, "Simplicity Smart Contracts Launch on Liquid," July 2025.

[49] IonQ, "1,600 Logical Qubits by 2028 Roadmap," 2025.

### Quantum Threat Acceleration (2026)

[50] Iceberg Quantum, "Pinnacle Architecture: RSA-2048 Factoring with Fewer Than 100,000 Physical Qubits Using QLDPC Codes," February 2026.

[51] Google Quantum AI, E. Gidney et al., "Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations," March 2026. (Co-authored with Ethereum Foundation and Stanford University.)

[52] J. Preskill, M. Endres, H.-Y. Huang, D. Bluvstein et al. (Caltech/Oratomic), "Shor's Algorithm Is Possible with as Few as 10,000 Reconfigurable Atomic Qubits," arXiv:2603.28627, March 2026.

[53] E. Gibney, "'It's a Real Shock': Quantum-Computing Breakthroughs Pose Imminent Risks to Cybersecurity," Nature, April 2026.

[54] Microsoft and Atom Computing, "Magne: 50 Error-Corrected Logical Qubits from 1,200 Physical Qubits," 2026.

[55] QuEra, "37 Logical Qubit Error-Corrected Machine Delivered to AIST Japan," 2026.

[56] D. J. Williamson and T. J. Yoder, "Low-Overhead Fault-Tolerant Quantum Computation by Gauging Logical Operators," Nature Physics, 2026.

[57] NIST, "IR 8547: Transition to Post-Quantum Cryptography Standards," 2026.

[58] BIP-360, "Pay-to-Merkle-Root (P2MR): Structural Foundation for Post-Quantum Signatures on Bitcoin L1," Merged February 11, 2026.

[59] Blockstream Research, "Quantum-Resistant Transaction Signing on Liquid Using Simplicity Smart Contracts and SHRINCS," March 2026.

[60] SPHINCSLET, "First Fully Standard-Compliant Area-Efficient FPGA Implementation of SLH-DSA," ePrint 2025/621, 2025.
