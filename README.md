# Brrq

**Bitcoin L2 with Hash-First Architecture**

A Bitcoin Layer 2 built entirely on hash functions. 4 of 5 cryptographic layers operate on pure hash-based primitives: signatures (SLH-DSA), proofs (STARKs), state (SHA-256 Merkle), and equivocation detection (SLH-DSA dual signing).

## Architecture

```
brrq-node (entry point)
 |- brrq-sequencer    Block building + transaction ordering
 |  \- brrq-vm        RISC-V zkVM (RV32IM) with gas metering
 |     \- brrq-prover STARK proof generation (BabyBear + FRI)
 |- brrq-consensus    Staking, epochs, slashing, leader election
 |- brrq-state        Sparse Merkle Tree (SHA-256 + Poseidon2)
 |- brrq-crypto       Schnorr, SLH-DSA, EOTS, MuSig2, ECVRF
 |- brrq-network      P2P gossip, sync, peer reputation
 |- brrq-bridge       BitVM2 peg-in/peg-out, federation
 |- brrq-portal       L3 instant payments (escrow, nullifiers)
 |- brrq-api          JSON-RPC, REST, WebSocket
 |- brrq-indexer      SQLite blockchain indexing
 |- brrq-bitcoin      L1 RPC client, SPV verification
 |- brrq-sdk          Rust wallet SDK
 |- brrq-wallet       CLI wallet
 \- brrq-types        Shared types (Block, Transaction, Address)
```

## Quick Start

### Prerequisites

- **Rust 1.88.0** 
- **Node.js 22+** (for web explorer and SDK)

### Build

```bash
cargo build --release
```

### Run Tests

```bash
cargo test --workspace
```

### Run a Local Node

```bash
cargo run --release --bin brrq-node -- \
  --genesis testnet-genesis.toml \
  --sequencer \
  --rpc-port 8545
```

### Docker

```bash
cd docker
docker compose up -d
```

## Key Design Decisions

- **Hash-First**: Post-quantum safe by construction, not by retrofit
- **Dual Signing**: Every block signed with both EOTS (Schnorr) + SLH-DSA
- **STARK Proofs**: Transparent setup (no trusted ceremony), BabyBear field
- **BitVM2 Bridge**: Trustless peg-in/peg-out via on-chain dispute game
- **sqrt(x) Stake Cap**: Prevents plutocratic control of validation
- **MEV Protection**: Commit-reveal with epoch key encryption
- **No Governance Token**: BTC is the only collateral

## Documentation

- [Whitepaper](docs/whitepaper.md) - Full technical specification
- [Litepaper](docs/litepaper.md) - Non-technical overview
- [Yellow Paper](docs/yellow-paper.md) - Mathematical specification
- [Quickstart](docs/QUICKSTART.md) - Get started in 5 minutes
- [Developer Guide](docs/developer-guide.md) - Building on Brrq
- [API Reference](docs/API-REFERENCE.md) - JSON-RPC and REST endpoints
- [Portal Whitepaper](docs/portal-whitepaper.md) - L3 instant payments specification
- [Portal Guide](docs/PORTAL-GUIDE.md) - Merchant integration guide
- [Testnet Guide](docs/testnet-guide.md) - Running a testnet node
- [Economic Specification](docs/BRRQ_ECONOMIC_SPECIFICATION.md) - Tokenomics and fee model

## Project Status

**Pre-mainnet** — Testnet: [node.brrq.net](https://node.brrq.net)

## Community

- [X (Twitter)](https://x.com/BrrqNetwork)
- [GitHub Issues](https://github.com/brrq-net/brrq/issues)
- **Contact:** brrq@brrq.net

## License

Licensed under the [MIT License](LICENSE).

