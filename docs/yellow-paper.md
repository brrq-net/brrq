# Brrq: A Sovereign Layer-2 Protocol on Bitcoin

### Yellow Paper
> This Yellow Paper accompanies the Whitepaper. It provides the mathematical specification for the Brrq protocol.

**Engineering Doctrine:** Absolute mathematical security, and deterministic individual accountability through cryptoeconomics.

---

## 1. Abstract

This paper defines the mathematical and protocol specification for the Brrq network. Due to the current inability of Bitcoin (L1) to directly verify zero-knowledge proofs (ZK-STARKs), the protocol adopts in its first phase a "Cryptoeconomic Bridge" architecture. We reject signature aggregation mechanisms (such as FROST) and delegation systems (DPoS) as they break individual accountability and create unjustified complexity. Instead, we adopt a strict deterministic model: an M-of-N consensus committee built on direct individual Extractable One-Time Signatures (EOTS), where the committee is treated as a "temporary interpreter" governed by financial death penalties, pending replacement by optimistic verification mechanisms (BitVM2).

---

## 2. Cryptographic State Machine

The Brrq network is represented as a deterministic transition function $\Upsilon$ that takes state $\sigma_i$ and a set of transactions $T$ to produce state $\sigma_{i+1}$ paired with a proof $\pi$.

### 2.1 Extension Field & OOD Resistance

To prevent Out-of-Domain forgery attacks, Fiat-Shamir challenges are drawn from the degree-4 extension field $\mathbb{F}_{p^4}$ based on the BabyBear base field with characteristic $p = 15 \times 2^{27} + 1$. This guarantees a minimum collision space of $2^{-102}$.

### 2.2 LogUp Commitments

Non-algebraic operations (such as SHA-256 hashing) are constrained via lookup tables supported by the LogUp protocol. The equivalence between a log column $f$ (of length $N$) and lookup table $t$ (of length $M$) is defined by:

$$\sum_{i=0}^{N-1} \frac{m_i}{X - f_i} = \sum_{j=0}^{M-1} \frac{1}{X - t_j} \pmod{p}$$

where $m_i$ represents multiplicities and $X \in \mathbb{F}_{p^4}$ is a random challenge.

---

## 3. Strict Individual Consensus Bridge

To preserve individual slashability (Individual Accountability), the use of any signature aggregation protocol is prohibited. Each validator is an independent entity cryptographically responsible for its own signature.

### 3.1 Extractable One-Time Signatures (EOTS)

Individual validator balances are locked in separate leaves within a MAST tree of a Taproot (P2TR) contract on L1. To attest to the validity of proof $\pi$ and state transition to $\sigma_{final}$, validator $k$ produces a Schnorr signature bound to a unique nonce $R_k$ for that round. The valid signature equation for $s_k$ on message $m$:

$$s_k \cdot G = R_k + e_k \cdot P_k$$

where the challenge $e_k = H(R_k \parallel P_k \parallel m)$.

### 3.2 Permissionless Slashing

The protocol adopts the principle of "guilty until proven innocent." No validator has immunity. If validator $k$ signs two contradictory messages $m_1 \neq m_2$ (a valid state transition and a malicious one) with the same nonce $R_k$, their cryptographic protection collapses immediately.

Any observer (Fisherman) can extract the private key $x_k$ by solving the linear equation:

$$x_k = \frac{s_1 - s_2}{H(R_k \parallel P_k \parallel m_2) - H(R_k \parallel P_k \parallel m_1)} \pmod{q}$$

Once $x_k$ is extracted, the Slashing Script on L1 is activated, stripping the validator of their bond UTXO (33.33% of total stake — see Whitepaper §8.3 Key Isolation for the main/bond UTXO separation).

### 3.3 Threat Model

The protocol defines its adversary explicitly to delineate what can and cannot be guaranteed:

**Assumed Adversary Capabilities:**
- Controls less than $\frac{2}{3}$ of total stake (honest majority).
- Can create multiple identities (Sybil) but is capital-constrained.
- Can delay network messages (but not prevent them indefinitely).
- Can bribe individual validators (but the cost of bribing $\frac{2}{3}$ exceeds the profit).

**Protocol Guarantees (when $> \frac{1}{3}$ honest):**
- **State Integrity:** No invalid state transition is accepted.
- **Individual Accountability:** Every traitor is punished individually via EOTS.
- **Deposit Recovery:** Users recover their original deposit via pre-signed transaction (Section 4.4).

**Initial Phase Limitations (explicit):**
- **No Absolute Censorship Resistance:** If $\frac{2}{3}$ refuse to sign, they cannot be forced (EOTS punishes double-signing only, not abstention). The only recourse: original deposit recovery.
- **No Protection Against $\frac{2}{3}+$ Collusion:** If the supermajority colludes on a single decision (one message, one nonce each), no double-signing occurs and no key is extracted. The only deterrent: economic bond loss.

---

## 4. Economic Bounds & Withdrawal

### 4.1 Plutocratic Weight Cap

The protocol acknowledges that the only Sybil-resistant resource in a non-custodial network is capital (BTC). To prevent a single entity from capturing the bridge, maximum weight per node is capped at $33\%$.

For a stable security equilibrium, the following mathematical requirement is enforced:

$$\frac{2}{3} \times \sum \text{Stake} > 1.5 \times \text{TVL}$$

### 4.2 Economic Accountability Bond

To make betrayal economically irrational even without double-signing, each validator is required to deposit a bond proportional to the protected value. The required bond per validator:

$$\text{Bond}_k \geq \max\left(\text{MIN\_BOND},\ \frac{\text{TVL} \times 1.5}{\text{threshold}}\right)$$

where $\text{MIN\_BOND} = 1\ \text{BTC}$ (absolute floor) and $\text{threshold}$ is the quorum count. This guarantees:

$$\text{threshold} \times \text{Bond} \geq 1.5 \times \text{TVL}$$

The minimum cost of collusion (losing all bonds) always exceeds $1.5\times$ the maximum profit (stealing TVL). Upon bond seizure: $70\%$ is burned (deflation), $20\%$ is awarded to the fraud prover, and $10\%$ to the community fund.

### 4.3 Hybrid AND-Conjunction Gate

No withdrawal transaction from L2 to L1 can execute unless ALL of the following conditions are simultaneously satisfied:

1. **Mathematical Verification:** A valid proof $\pi$ exists proving $\Upsilon(\sigma_i, T) = \sigma_{i+1}$.
2. **Data Availability & Consensus:** Aggregation of individual valid EOTS signatures from validators representing $\ge \frac{2}{3}$ of total staked weight.
3. **Dual Deterministic Binding:**
   - Continuity binding: $\pi.\text{initial\_state\_root} == \text{committed\_state\_roots}[\text{height}]$ (proves the proof starts from a known state).
   - Commitment binding: $\pi.\text{final\_state\_root}$ is recorded as the authoritative state root (the network recognizes the new state).
   - No-op rejection: $\pi.\text{initial\_state\_root} \neq \pi.\text{final\_state\_root}$ (rejects "nothing happened" proofs).
4. **Challenge Period:** After conditions 1-3 are met, withdrawal execution is suspended for $\Delta_c$ blocks ($\Delta_c = 2016$ L1 blocks $\approx$ 14 days). During this period, any Fisherman may submit an Equivocation Proof against any signing validator. If no proof is submitted within $\Delta_c$, the withdrawal executes automatically.

### 4.4 Sovereign Deposit Recovery

To protect users against total censorship (committee refusing to sign), a pre-signed refund script is embedded in every deposit (Peg-in) transaction:

Upon deposit: the user sends $x$ BTC to the bridge address (P2TR). The committee pre-signs a timelocked refund transaction:

$$\text{Refund}_{tx}: \text{OP\_CLTV}(\text{current\_height} + 2016) \rightarrow \text{user\_address}$$

The user retains the signed transaction. If all else fails (censorship, committee disappearance), the user broadcasts the refund transaction after $2016$ L1 blocks ($\approx$ 2 weeks) and recovers their original deposit.

**Explicit Constraint:** This recovers the original deposit only, not any subsequent L2 state (profits, transactions). Full exit of arbitrary L2 state requires committee cooperation initially, or BitVM2 after integration.

---

## 5. Sequencer & Data Availability

### 5.1 Sequencer

The Sequencer is the entity that collects user transactions, orders them into L2 blocks, executes them on the RISC-V virtual machine, and produces a STARK proof for the resulting transition.

**Fundamental Distinction from the Committee:**
- The Sequencer produces state transitions (Block Producer).
- The Committee validates state transitions (Validator).
- No single entity performs both roles.

**Sequencer Constraints:**
- **Cannot forge proofs:** STARK detects any incorrect state transition.
- **Can censor (refuse to include a transaction):** Mitigation: multiple sequencers with rotation policy. Definitive solution: Forced Inclusion on L1 via BitVM2.
- **Can reorder (MEV):** Mitigated via Commit-Reveal: transactions are encrypted before ordering, so the Sequencer cannot see transaction content until after committing to the order.

### 5.2 Data Availability

To ensure any party can reconstruct and verify L2 state, block data is published via:

1. **Primary Publication (Mandatory):** The Sequencer publishes a summary of each block (block header + Merkle root of transactions) within `OP_RETURN` on L1. This anchors an immutable commitment on Bitcoin.
2. **Full Publication (P2P Network):** Complete transaction data is broadcast via the Brrq P2P network (with Dandelion++ for privacy). Any full node retains the complete record.
3. **Retention Rule:** Full nodes retain the last $N$ blocks ($N \geq 10{,}080$ $\approx$ 1 week). Older data is archived but not deleted from the network (Archive Nodes).

**No external DA layer** (such as Celestia or EigenDA) is used, preserving sovereignty. The only dependencies are Bitcoin L1 (for commitment) and the Brrq P2P network (for full publication).

### 5.3 Security Hardening

The following security mechanisms are enforced:

**Sequencer Enforcement:**
- `validate_block_producer()`: mandatory gate rejecting blocks from unauthorized sequencers.
- Minimum sequencer bond: 1 BTC (`MIN_SEQUENCER_BOND`).

**Challenge Protocol Hardening:**
- Challenge bond: 0.01 BTC (`CHALLENGE_BOND`) — returned if fraud proven, forfeited if dismissed.
- Challenge ID excludes block height — prevents re-submission of dismissed challenges.
- Proof range contiguity enforced — no gaps in provable history.

**Federation Hardening:**
- EOTS proof validation: nonce non-zero + challenge hash consistency.
- Key rotation: new key requires maturity period before active participation.
- Slash target excluded from voting on own SlashBond proposals.
- Bond withdrawal deactivates member.
- Nonce commitments and extraction proofs persist across restarts.
- `DepositStatus` state machine: one-way transitions only (Pending→Confirmed→Finalized).

**Prover Hardening:**
- The prover enforces arithmetic correctness, instruction decoding integrity, and memory consistency through algebraic constraints verified by the STARK verifier.

---

## 6. The Obsolescence Roadmap

The committee defined in this paper is an "Architectural Patch" for Bitcoin's limitations, not a permanent feature. The ultimate goal of the Brrq protocol is to completely remove the human element from the consensus loop.

* **Cryptoeconomic Phase:** M-of-N consensus via strict individual EOTS. Mathematical security for users (STARK), deterministic slashing for traitors (EOTS), and economic bonds for accountability (Bond). **Explicit constraint:** the committee retains censorship power (can refuse to sign) — the only deterrents are bond loss and user deposit recovery.

* **BitVM2 Integration:** Transition to Optimistic Fraud Proofs. The committee loses co-signing authority and becomes merely a state proposer that can be challenged by anyone on L1. Forced Inclusion is added: users can submit their transactions directly to L1, and the Sequencer is obligated to include them. System trust moves from "$\frac{2}{3}$ honest" to "one honest observer suffices" (1-of-N).

* **Sovereign Goal:** Direct ZK proof verification on L1 via additions such as `OP_CAT`. Complete elimination of the committee, staking, and voting. Security becomes $100\%$ computational-mathematical.

---
*(End of Yellow Paper)*
