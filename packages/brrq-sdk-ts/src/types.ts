/**
 * Brrq TypeScript SDK — Core Types
 *
 * These types mirror the Rust types defined in `brrq-types` and the
 * JSON shapes returned by `brrq-api` (JSON-RPC + REST).
 *
 * NOTE (W50 — bigint / u64 serialization):
 * Rust uses u64 for amount fields. The JSON-RPC layer serializes u64 as a
 * JSON **string** (not a JSON number) to avoid JavaScript IEEE-754 precision
 * loss for values > 2^53. The SDK's JSON reviver converts those strings to
 * `bigint` automatically. This is the standard pattern used by Ethereum
 * JSON-RPC and other blockchain APIs.
 */

// ────────────────────────────────────────────────────────────────────
// Blockchain primitives
// ────────────────────────────────────────────────────────────────────

/** A Brrq block as returned by the API. */
export interface Block {
  /** Block height (sequential, starts at 0). */
  height: number;
  /** Block header hash (hex with 0x prefix). */
  hash: string;
  /** Hash of the previous block header (hex with 0x prefix). */
  parentHash: string;
  /** Timestamp in Unix seconds. */
  timestamp: number;
  /** Number of transactions in the block. */
  txCount: number;
  /** Total gas consumed by all transactions. */
  gasUsed: number;
  /** Maximum gas allowed in this block. */
  gasLimit: number;
  /** State root after executing all transactions (hex with 0x prefix). */
  stateRoot: string;
  /** Sequencer address that produced this block (hex with 0x prefix). */
  sequencer: string;
  /** Epoch number. */
  epoch: number;
}

/** Transaction kinds supported by Brrq, matching the Rust TransactionKind enum. */
export type TransactionKind =
  | "transfer"
  | "deploy"
  | "contract_call"
  | "register_validator"
  | "add_stake"
  | "begin_unbonding"
  | "finish_unbonding"
  | "submit_equivocation_proof"
  | "deposit_synthetic"
  | "l1_zkla_anchor"
  | "create_portal_lock"
  | "update_lock_condition"
  | "settle_portal_lock"
  | "cancel_portal_lock"
  | "batch_settle_portal";

/** A Brrq transaction as returned by the API.
 *
 * Added EIP-1559 fee fields (maxFeePerGas, maxPriorityFeePerGas)
 * to match Rust TransactionBody. Legacy `gasPrice` retained for backward compat.
 */
export interface Transaction {
  /** Transaction hash (hex with 0x prefix). */
  hash: string;
  /** Sender address (hex with 0x prefix). */
  from: string;
  /** Sender nonce. */
  nonce: number;
  /** Gas limit for this transaction. */
  gasLimit: number;
  /** @deprecated Use maxFeePerGas instead. Legacy flat gas price. */
  gasPrice: number;
  /** EIP-1559: Maximum total fee per gas unit (base fee + priority fee). */
  maxFeePerGas: number;
  /** EIP-1559: Maximum priority fee (tip) per gas unit. */
  maxPriorityFeePerGas: number;
  /** Block height where this transaction was included. */
  blockHeight: number;
}

/** A Brrq account. */
export interface Account {
  /** Account address (hex with 0x prefix). */
  address: string;
  /** Balance in satoshis (brqBTC, 1:1 with BTC). */
  balance: bigint;
  /** Transaction nonce. */
  nonce: number;
  /** Contract code hash (hex, zero for EOA). */
  codeHash?: string;
  /** Storage root (hex, zero for EOA). */
  storageRoot?: string;
}

/** Transaction receipt returned after a tx is included in a block. */
export interface TxReceipt {
  /** Block height where the transaction was included. */
  blockHeight: number;
  /** Actual gas consumed by execution. */
  gasUsed: number;
  /** Whether the transaction executed successfully. */
  success: boolean;
  /** Hash of the block containing this transaction (hex with 0x prefix). */
  blockHash: string;
}

// ────────────────────────────────────────────────────────────────────
// Consensus & Staking
// ────────────────────────────────────────────────────────────────────

/** Validator status (mirrors Rust ValidatorStatus, PascalCase from `format!("{:?}", status)`). */
export type ValidatorStatus = "Active" | "Suspended" | "Unbonding" | "Removed";

/** Validator information. */
export interface Validator {
  /** Validator address (hex with 0x prefix). */
  address: string;
  /** Validator's own stake in satoshis. */
  stake: bigint;
  /** Total stake (own + delegated) in satoshis. */
  totalStake: bigint;
  /** Current validator status. */
  status: ValidatorStatus;
}

/** Epoch information. */
export interface EpochInfo {
  /** Current epoch number. */
  currentEpoch: number;
  /** Block height at which the current epoch started. */
  epochStartHeight: number;
  /** Number of blocks per epoch. */
  epochLength: number;
}

// ────────────────────────────────────────────────────────────────────
// Bridge
// ────────────────────────────────────────────────────────────────────

/** Bridge status for BTC peg-in/peg-out. */
export interface BridgeStatus {
  /** Total BTC locked in the bridge (satoshis). */
  totalLocked: bigint;
  /** Total brqBTC minted (satoshis). */
  totalMinted: bigint;
  /** Number of pending deposit requests. */
  pendingDeposits: number;
  /** Number of pending withdrawal requests. */
  pendingWithdrawals: number;
  /** Whether the bridge is paused. */
  paused: boolean;
}

// ────────────────────────────────────────────────────────────────────
// Proofs
// ────────────────────────────────────────────────────────────────────

/** A batch STARK proof record. */
export interface BatchProof {
  /** First block height in the proved range. */
  blockRangeStart: number;
  /** Last block height in the proved range. */
  blockRangeEnd: number;
  /** Whether the proof was verified. */
  verified: boolean;
}

// ────────────────────────────────────────────────────────────────────
// Network / Stats
// ────────────────────────────────────────────────────────────────────

/** Network statistics (from REST /api/v1/stats). */
export interface NetworkStats {
  /** Current block height. */
  blockHeight: number;
  /** Total number of transactions. */
  txCount: number;
  /** Total number of blocks. */
  blockCount: number;
  /** Number of active validators. */
  validatorCount: number;
  /** Total stake across all validators (satoshis). */
  totalStake: bigint;
  /** Number of transactions in the mempool. */
  mempoolSize: number;
  /** Total number of STARK proofs generated. */
  proofCount: number;
}

// ────────────────────────────────────────────────────────────────────
// Transaction logs & Merkle proofs
// ────────────────────────────────────────────────────────────────────

/** Transaction receipt with logs. */
export interface TxLog {
  address: string;
  topics: string[];
  data: string;
}

/** Account Merkle proof. */
export interface AccountProof {
  address: string;
  proof: string[];
  balance: bigint;
  nonce: number;
  codeHash: string;
  storageRoot: string;
}

/** Storage Merkle proof. */
export interface StorageProof {
  address: string;
  key: string;
  value: string;
  proof: string[];
}

// ────────────────────────────────────────────────────────────────────
// MEV protection
// ────────────────────────────────────────────────────────────────────

/** MEV mempool status. */
export interface MevStatus {
  mode: string;
  phase: string;
  pendingCount: number;
  byteUsage: number;
}

// ────────────────────────────────────────────────────────────────────
// Governance
// ────────────────────────────────────────────────────────────────────

/** Governance proposal. */
export interface GovernanceProposal {
  id: number;
  proposer: string;
  proposalType: string;
  status: string;
  yesVotes: number;
  noVotes: number;
  abstainVotes: number;
  createdAt: number;
}

/** Governance stats. */
export interface GovernanceStats {
  totalProposals: number;
  activeProposals: number;
  passedProposals: number;
  rejectedProposals: number;
}

// ────────────────────────────────────────────────────────────────────
// Sequencer
// ────────────────────────────────────────────────────────────────────

/** Sequencer info. */
export interface SequencerInfo {
  address: string;
  selfStake: bigint;
  totalStake: bigint;
  region: string;
  commissionBp: number;
  status: string;
}

// ────────────────────────────────────────────────────────────────────
// Bridge challenges
// ────────────────────────────────────────────────────────────────────

/** Bridge challenge. */
export interface BridgeChallenge {
  id: string;
  challenger: string;
  challengeType: string;
  status: string;
  createdAt: number;
}

// ────────────────────────────────────────────────────────────────────
// Prover pools
// ────────────────────────────────────────────────────────────────────

/** Prover pool. */
export interface ProverPool {
  id: string;
  members: string[];
  totalStake: bigint;
}

// ────────────────────────────────────────────────────────────────────
// Portal (L3) types
// ────────────────────────────────────────────────────────────────────

/** Portal lock status. */
export type PortalLockStatus = "Active" | "Settled" | "Expired" | "Cancelled";

/** A Portal escrow lock on L2. */
export interface PortalLock {
  /** Unique lock identifier (hex). */
  lock_id: string;
  /** Lock owner's L2 address. */
  owner: string;
  /** Owner's Schnorr public key (hex) — needed for local signature verification. */
  owner_pubkey: string;
  /** Amount locked in satoshis. Use bigint to safely represent u64 values. */
  amount: bigint;
  /** H(merchant_secret) — settlement condition (hex). */
  condition_hash: string;
  /** Pre-computed nullifier hash (hex). */
  nullifier_hash: string;
  /** L2 block height at which the lock expires. */
  timeout_l2_block: number;
  /** Current lock status. */
  status: PortalLockStatus;
  /** L2 block height when this lock was created. */
  created_at_block: number;
  /** Merchant L2 address bound during UpdateLockCondition (hex). Anti-front-running. */
  merchant_address: string;
  /** Merchant Schnorr public key (hex). */
  merchant_pubkey: string;
}

/** Portal statistics. */
export interface PortalStats {
  /** Number of active (unsettled, unexpired) locks. */
  active_locks: number;
  /** Total amount held in escrow (satoshis). */
  total_escrowed: number;
  /** Number of consumed nullifiers. */
  nullifiers_consumed: number;
}

/** Nullifier status check result. */
export interface NullifierStatus {
  /** The nullifier hex. */
  nullifier: string;
  /** Whether the nullifier has been consumed (double-spend check). */
  consumed: boolean;
}

/** Portal Key — the off-chain payment instrument sent to merchants. */
export interface PortalKeyPayload {
  /** Protocol version ("Brrq_L3_Portal_v4"). */
  protocol: string;
  /** Schnorr signature (hex). */
  signature: string;
  /** Extended deterministic nullifier (hex). */
  nullifier: string;
  /** Reference to the lock on L2 (hex). */
  lock_id: string;
  /** Public inputs visible to the merchant. */
  public_inputs: {
    owner: string;
    /** Owner's Schnorr public key (hex) — for local signature verification. */
    owner_pubkey: string;
    asset_id: string;
    /** Amount in satoshis. Use bigint for u64 safety. */
    amount: bigint;
    condition_hash: string;
    timeout_l2_block: number;
  };
}

/** Portal WebSocket events. */
export interface PortalLockCreatedEvent {
  type: "PortalLockCreated";
  lock_id: string;
  owner: string;
  amount: number;
  timeout_l2_block: number;
}

export interface PortalLockSettledEvent {
  type: "PortalLockSettled";
  lock_id: string;
  merchant: string;
  amount: number;
}

export interface PortalBatchSettledEvent {
  type: "PortalBatchSettled";
  succeeded: number;
  failed: number;
  total: number;
}

/**
 * W50: Type alias for compatibility with Rust's `PortalKey`.
 * The TS SDK originally named this `PortalKeyPayload`; Rust uses `PortalKey`.
 * Both names now work.
 */
export type PortalKey = PortalKeyPayload;

/**
 * A settlement claim submitted by a merchant to settle a Portal lock.
 * Mirrors Rust `SettlementClaim` in `brrq-portal`.
 */
export interface PortalSettlementClaim {
  /** The lock being settled (hex). */
  lock_id: string;
  /** Merchant L2 address (hex with 0x prefix). */
  merchant_address: string;
  /** Merchant Schnorr public key (hex). */
  merchant_pubkey: string;
  /** Pre-image of the condition hash (hex). */
  secret: string;
  /** Schnorr signature over the claim by the merchant (hex). */
  signature: string;
}

/**
 * Result of a batch settlement operation.
 * Mirrors Rust `BatchResult` in `brrq-portal`.
 */
export interface BatchResult {
  /** Number of locks successfully settled. */
  succeeded: number;
  /** Number of locks that failed settlement. */
  failed: number;
  /** Per-lock results: lock_id and either success or error message. */
  results: Array<{
    lock_id: string;
    success: boolean;
    error?: string;
  }>;
}

// ────────────────────────────────────────────────────────────────────
// JSON-RPC 2.0 types
// ────────────────────────────────────────────────────────────────────

/** JSON-RPC 2.0 request object. */
export interface JsonRpcRequest {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
  id: number | string;
}

/** JSON-RPC 2.0 error object. */
export interface JsonRpcError {
  code: number;
  message: string;
  data?: unknown;
}

/** JSON-RPC 2.0 response object. */
export interface JsonRpcResponse<T = unknown> {
  jsonrpc: "2.0";
  result?: T;
  error?: JsonRpcError;
  id: number | string;
}

// ────────────────────────────────────────────────────────────────────
// Transaction construction types (used by Wallet.transfer)
// ────────────────────────────────────────────────────────────────────

/** Options for creating a transfer transaction. */
export interface TransferOptions {
  /** Sender nonce (must match on-chain nonce). */
  nonce: number;
  /** Gas limit (defaults to 21000 for simple transfers). */
  gasLimit?: number;
  /** @deprecated Use maxFeePerGas instead. Legacy flat gas price. */
  gasPrice?: number;
  /** EIP-1559: Maximum total fee per gas unit. */
  maxFeePerGas?: number;
  /** EIP-1559: Maximum priority fee (tip) per gas unit. */
  maxPriorityFeePerGas?: number;
  /** Chain ID (defaults to TESTNET). */
  chainId?: number;
}

/** A signed transaction ready to be submitted to the network. */
export interface SignedTransaction {
  /** Sender address (hex with 0x prefix). */
  from: string;
  /** Recipient address (hex with 0x prefix). */
  to: string;
  /** Amount in satoshis. */
  amount: bigint;
  /** Transaction kind. */
  kind: TransactionKind;
  /** Sender nonce. */
  nonce: number;
  /** Gas limit. */
  gasLimit: number;
  /** @deprecated Use maxFeePerGas instead. */
  gasPrice: number;
  /** EIP-1559: Maximum total fee per gas unit. */
  maxFeePerGas: number;
  /** EIP-1559: Maximum priority fee (tip) per gas unit. */
  maxPriorityFeePerGas: number;
  /** Chain ID. */
  chainId: number;
  /** Schnorr signature (hex). */
  signature: string;
  /** Public key (hex, 32 bytes x-only). */
  publicKey: string;
}

// ────────────────────────────────────────────────────────────────────
// WebSocket event types
// ────────────────────────────────────────────────────────────────────

/** WebSocket subscription topics matching the Rust SubscriptionTopic enum. */
export type SubscriptionTopic = "newBlocks" | "pendingTxs" | "newProofs";

/** New block event from WebSocket. */
export interface NewBlockEvent {
  type: "NewBlock";
  height: number;
  hash: string;
  tx_count: number;
  timestamp: number;
  gas_used: number;
}

/** Pending transaction event from WebSocket. */
export interface PendingTransactionEvent {
  type: "PendingTransaction";
  hash: string;
  from: string;
  kind: string;
}

/** New proof event from WebSocket. */
export interface NewProofEvent {
  type: "NewProof";
  block_range_start: number;
  block_range_end: number;
  verified: boolean;
  generation_time_ms: number;
}

/** Any event that can arrive over the WebSocket. */
export type NodeEvent = NewBlockEvent | PendingTransactionEvent | NewProofEvent;

// ────────────────────────────────────────────────────────────────────
// Chain IDs (matching Rust chain_id module)
// ────────────────────────────────────────────────────────────────────

export const CHAIN_ID = {
  /** Mainnet: 0xB77C0008 (must match mainnet-genesis.toml) */
  MAINNET: 0xb77c_0008,
  /** Testnet: 0xB77C0001 */
  TESTNET: 0xb77c_0001,
  /** Signet (development): 0xB77C0002 */
  SIGNET: 0xb77c_0002,
  /** Local development: 0xB77CFFFF */
  LOCAL: 0xb77c_ffff,
} as const;
