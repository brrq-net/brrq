/**
 * @brrq/sdk — TypeScript SDK for the Brrq Bitcoin L2 network.
 *
 * Provides a typed client for JSON-RPC 2.0 and REST APIs,
 * a Schnorr wallet for signing transactions, and a WebSocket
 * client for real-time event subscriptions.
 *
 * @example
 * ```ts
 * import { BrrqClient, Wallet, BrrqWebSocket, CHAIN_ID } from "@brrq/sdk";
 *
 * // Create client and wallet
 * const client = new BrrqClient("http://localhost:8545");
 * const wallet = Wallet.generate();
 *
 * // Check balance
 * const balance = await client.getBalance(wallet.address);
 *
 * // Send a transfer
 * const nonce = await client.getNonce(wallet.address);
 * const tx = wallet.transfer("0xrecipient...", 100000n, { nonce });
 * const hash = await client.sendTransaction(tx);
 *
 * // Subscribe to events
 * const ws = new BrrqWebSocket("ws://localhost:8545/ws");
 * ws.on("newBlock", (block) => console.log("Block:", block.height));
 * await ws.connect();
 * ws.subscribe(["newBlocks"]);
 * ```
 */

// Client
export { BrrqClient, RpcError } from "./client.js";

// Wallet
export { Wallet } from "./wallet.js";

// WebSocket
export { BrrqWebSocket } from "./websocket.js";
export type { EventCallbacks } from "./websocket.js";

// Types
export type {
  Account,
  AccountProof,
  BatchProof,
  Block,
  BridgeChallenge,
  BridgeStatus,
  EpochInfo,
  GovernanceProposal,
  GovernanceStats,
  JsonRpcError,
  JsonRpcRequest,
  JsonRpcResponse,
  MevStatus,
  NetworkStats,
  NewBlockEvent,
  NewProofEvent,
  NodeEvent,
  NullifierStatus,
  PendingTransactionEvent,
  PortalBatchSettledEvent,
  PortalKeyPayload,
  PortalLock,
  PortalLockCreatedEvent,
  PortalLockSettledEvent,
  PortalLockStatus,
  PortalStats,
  ProverPool,
  SequencerInfo,
  SignedTransaction,
  StorageProof,
  SubscriptionTopic,
  Transaction,
  TransactionKind,
  TransferOptions,
  TxLog,
  TxReceipt,
  Validator,
  ValidatorStatus,
} from "./types.js";
export { CHAIN_ID } from "./types.js";

// Portal (L3) SDK
export {
  BrrqPortal,
  parsePaymentUri,
  createPaymentUri,
  createBpop,
  computeBpopPayload,
  validateBeforeSigning,
  verifyBpop,
  verifyBpopSecret,
  serializeBpop,
  deserializeBpop,
  computeConditionHash,
  computeNullifier,
  computePortalKeyPayload,
  SettlementQueue,
  NullifierGuard,
  URI_VERSION,
  DOMAIN_TAGS as PORTAL_DOMAIN_TAGS,
} from "./portal.js";
export type {
  BrrqChain as PortalChain,
  BrrqPaymentUri,
  ProofOfPurchase,
  PendingSettlement,
} from "./portal.js";

// Merchant Server
export { MerchantServer } from "./merchant-server.js";
export type { MerchantServerConfig, PaymentRequest, PaymentResult } from "./merchant-server.js";

// Relayer Bot
export { RelayerBot } from "./relayer-bot.js";
export type { RelayerBotConfig, RelayResult } from "./relayer-bot.js";

// Utilities
export {
  bytesToHex,
  DOMAIN_TAGS,
  formatSatoshis,
  hexToBytes,
  isValidAddress,
  normalizeAddress,
  shortenHash,
  sleep,
} from "./utils.js";
