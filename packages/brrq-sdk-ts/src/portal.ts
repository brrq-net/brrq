/**
 * Brrq Portal SDK — merchant and wallet integration for L3 payments.
 *
 * Implements:
 * - BPS-1: URI Scheme (parse + generate)
 * - BPS-4: Proof of Purchase (create + verify)
 * - Portal Key local verification
 * - Settlement queue management
 *
 * @example
 * ```ts
 * import { BrrqPortal } from "@brrq/sdk";
 *
 * // Parse a payment QR code
 * const request = BrrqPortal.parseUri("brrq://pay?v=1&chain=mainnet&amount=50000&cond=0x...&timeout=200000");
 *
 * // Verify a Portal Key locally (0ms)
 * const isValid = BrrqPortal.verifySignature(portalKey);
 *
 * // Check lock safety via L2 (includes mempool awareness)
 * const lock = await client.getPortalLock(portalKey.lock_id);
 * if (lock.safe_to_accept) { provideService(); }
 *
 * // Queue settlement for batching
 * BrrqPortal.queueSettlement(portalKey, merchantSecret);
 * ```
 */

import { createHash, createHmac } from "crypto";
import { schnorr } from "@noble/curves/secp256k1.js";

// ══════════════════════════════════════════════════════════════════
//  BPS-1: Universal URI Scheme
// ══════════════════════════════════════════════════════════════════

export type BrrqChain = "mainnet" | "testnet";

export const URI_VERSION = 1;

/** Parsed Brrq payment URI. */
export interface BrrqPaymentUri {
  version: number;
  chain: BrrqChain;
  /** Amount in satoshis. */
  amount: bigint;
  /** Merchant condition hash (0x-prefixed hex, 64 chars). */
  conditionHash: string;
  /** L2 block height deadline. */
  timeout: number;
  /** Optional webhook URL for Portal Key delivery. */
  callback?: string;
  /** Optional human-readable memo. */
  memo?: string;
  /** Asset identifier (default: "BTC"). */
  asset: string;
}

/** Strict hex validation regex (0x-prefixed, exactly 64 hex chars). */
const HEX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;

/** Safe URL schemes for callback (prevent javascript: injection). */
const SAFE_CALLBACK_RE = /^https?:\/\//;

/** Allowed characters for asset identifiers. */
const ASSET_RE = /^[A-Z0-9_]{1,10}$/;

/** Require a parameter from URLSearchParams, throwing if absent. */
function requireParam(params: URLSearchParams, key: string): string {
  const val = params.get(key);
  if (val === null) throw new Error(`Missing required parameter: ${key}`);
  return val;
}

/** Parse and validate the required URI parameters (version, chain, amount, cond, timeout). */
function parseRequiredParams(params: URLSearchParams): {
  version: number; chain: BrrqChain; amount: bigint; conditionHash: string; timeout: number;
} {
  // Version (must be integer)
  const vStr = requireParam(params, "v");
  const version = Number(vStr);
  if (!Number.isInteger(version) || version !== URI_VERSION) {
    throw new Error(`Unsupported URI version: ${vStr} (expected ${URI_VERSION})`);
  }

  // Chain (strict whitelist)
  const chainStr = requireParam(params, "chain");
  if (chainStr !== "mainnet" && chainStr !== "testnet") {
    throw new Error(`Invalid chain: ${chainStr}`);
  }

  // Amount (must be positive integer, no decimals, no negative)
  const amountStr = requireParam(params, "amount");
  if (!/^\d+$/.test(amountStr)) {
    throw new Error(`Invalid amount: must be a positive integer, got '${amountStr}'`);
  }
  const amount = BigInt(amountStr);
  if (amount <= 0n) throw new Error("Amount must be > 0");

  // Condition hash (strict hex validation — prevents XSS/injection)
  const cond = requireParam(params, "cond");
  const condClean = cond.startsWith("0x") ? cond : `0x${cond}`;
  if (!HEX_HASH_RE.test(condClean)) {
    throw new Error(`Invalid condition hash: must be 0x + 64 hex chars, got '${condClean.slice(0, 20)}...'`);
  }

  // Timeout (must be positive integer)
  const timeoutStr = requireParam(params, "timeout");
  const timeout = Number(timeoutStr);
  if (!Number.isInteger(timeout) || timeout <= 0) {
    throw new Error(`Invalid timeout: must be positive integer, got '${timeoutStr}'`);
  }

  return { version, chain: chainStr as BrrqChain, amount, conditionHash: condClean, timeout };
}

/** Parse and validate optional URI parameters (asset, callback, memo). */
function parseOptionalParams(params: URLSearchParams): {
  asset: string; callback?: string; memo?: string;
} {
  // Asset (optional, strict alphanumeric)
  const assetRaw = params.get("asset") ?? "BTC";
  if (!ASSET_RE.test(assetRaw)) {
    throw new Error(`Invalid asset: must be 1-10 uppercase alphanumeric chars, got '${assetRaw}'`);
  }

  // Callback (optional, must be https:// — prevents javascript: injection)
  const callbackRaw = params.get("callback") ?? undefined;
  if (callbackRaw !== undefined && !SAFE_CALLBACK_RE.test(callbackRaw)) {
    throw new Error(`Invalid callback: must start with https:// or http://, got '${callbackRaw.slice(0, 20)}...'`);
  }

  // Memo (optional, strict sanitization — only allow printable ASCII, no HTML)
  const memoRaw = params.get("memo") ?? undefined;
  const memo = memoRaw !== undefined
    ? memoRaw
        .replace(/[^ -~]/g, "")           // Only printable ASCII (0x20-0x7E)
        .replace(/[<>&"'`\\]/g, "")       // Strip all HTML-dangerous chars
        .slice(0, 200)
    : undefined;

  return { asset: assetRaw, callback: callbackRaw, memo };
}

/** Parse a `brrq://pay?...` URI string with strict input validation. */
export function parsePaymentUri(uri: string): BrrqPaymentUri {
  if (typeof uri !== "string" || !uri.startsWith("brrq://pay?")) {
    throw new Error("Invalid URI scheme: must start with brrq://pay?");
  }
  // SEC: Limit URI length to prevent DoS via huge strings
  if (uri.length > 2048) {
    throw new Error("URI too long (max 2048 chars)");
  }

  const query = uri.slice("brrq://pay?".length);
  const params = new URLSearchParams(query);

  const required = parseRequiredParams(params);
  const optional = parseOptionalParams(params);

  return { ...required, ...optional };
}

/** Generate a `brrq://pay?...` URI string. */
export function createPaymentUri(req: BrrqPaymentUri): string {
  const parts = [
    `v=${req.version}`,
    `chain=${req.chain}`,
    `amount=${req.amount}`,
    `cond=${req.conditionHash}`,
    `timeout=${req.timeout}`,
  ];
  if (req.asset !== "BTC") parts.push(`asset=${req.asset}`);
  if (req.callback) parts.push(`callback=${encodeURIComponent(req.callback)}`);
  if (req.memo) parts.push(`memo=${encodeURIComponent(req.memo)}`);
  return `brrq://pay?${parts.join("&")}`;
}

// ══════════════════════════════════════════════════════════════════
//  BPS-4: Proof of Purchase (BPoP)
// ══════════════════════════════════════════════════════════════════

const BPOP_DOMAIN = "BRRQ_PROOF_OF_PURCHASE_V1";

/** Cryptographic proof of purchase — unforgeable payment receipt. */
export interface ProofOfPurchase {
  /** Original payment URI from the merchant. */
  paymentUri: string;
  /** Amount paid in satoshis. */
  amount: bigint;
  /** Merchant condition hash. */
  conditionHash: string;
  /** User's Schnorr signature (hex). */
  portalSignature: string;
  /** User's public key (hex). */
  ownerPubkey: string;
  /** Merchant's revealed secret (hex). */
  merchantSecret: string;
  /** L2 block where settlement confirmed. */
  settledAtBlock?: number;
  /** Unix timestamp of payment. */
  timestamp: number;
  /** Chain identifier signed in payload. */
  chain: BrrqChain;
  /** Asset identifier signed in payload. */
  asset: string;
}

/** Verify that merchant_secret hashes to condition_hash. */
export function verifyBpopSecret(bpop: ProofOfPurchase): boolean {
  const secretBytes = Buffer.from(bpop.merchantSecret, "hex");
  const hash = createHash("sha256").update(secretBytes).digest("hex");
  const expected = bpop.conditionHash.startsWith("0x")
    ? bpop.conditionHash.slice(2)
    : bpop.conditionHash;
  return hash === expected;
}

/** Verify BPoP internal consistency (secret + URI match). */
export function verifyBpop(bpop: ProofOfPurchase): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  // 1. Timestamp
  if (bpop.timestamp <= 0) errors.push("invalid timestamp");

  // 2. Parse URI and check consistency
  try {
    const uri = parsePaymentUri(bpop.paymentUri);
    if (uri.amount !== bpop.amount) {
      errors.push(`amount mismatch: receipt=${bpop.amount}, uri=${uri.amount}`);
    }
    // Verify chain + asset match URI (prevent cross-asset replay)
    if (uri.chain !== bpop.chain) {
      errors.push(`chain mismatch: receipt='${bpop.chain}', uri='${uri.chain}'`);
    }
    if (uri.asset !== bpop.asset) {
      errors.push(`asset mismatch: receipt='${bpop.asset}', uri='${uri.asset}'`);
    }
    if (uri.conditionHash !== bpop.conditionHash) {
      errors.push("condition hash mismatch between receipt and URI");
    }
  } catch (e: unknown) {
    errors.push(`URI parse error: ${e instanceof Error ? e.message : String(e)}`);
  }

  // 3. Verify secret → condition hash
  if (!verifyBpopSecret(bpop)) {
    errors.push("merchant_secret does not hash to condition_hash");
  }

  // 4. Verify TEE Schnorr signature over BPoP payload.
  // Without this, a malicious merchant can send a garbage signature and
  // the wallet would save it as "valid". When the user needs to present
  // the receipt, the signature fails and the user loses their proof.
  try {
    const payloadHex = computeBpopPayload(
      bpop.conditionHash,
      bpop.amount,
      bpop.timestamp,
      bpop.chain,
      bpop.asset,
    );
    const payloadBytes = Buffer.from(payloadHex.replace("0x", ""), "hex");
    const sigBytes = Buffer.from(bpop.portalSignature.replace("0x", ""), "hex");
    const pubkeyBytes = Buffer.from(bpop.ownerPubkey.replace("0x", ""), "hex");

    if (sigBytes.length !== 64) {
      errors.push(`invalid signature length: ${sigBytes.length} (expected 64)`);
    } else if (pubkeyBytes.length !== 32) {
      errors.push(`invalid pubkey length: ${pubkeyBytes.length} (expected 32)`);
    } else {
      const isValid = schnorr.verify(sigBytes, payloadBytes, pubkeyBytes);
      if (!isValid) {
        errors.push("TEE signature verification failed — receipt may be forged");
      }
    }
  } catch (e: unknown) {
    errors.push(`signature verification error: ${e instanceof Error ? e.message : String(e)}`);
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Create a BPoP with mandatory secret verification.
 *
 * The wallet MUST call this when the merchant reveals their secret.
 * Rejects the receipt if the secret doesn't match the condition hash,
 * preventing the merchant from tricking the wallet into storing a
 * useless receipt.
 */
/**
 * Compute the BPoP signing payload (matches Rust compute_bpop_payload exactly).
 *
 * payload = SHA-256(BRRQ_PROOF_OF_PURCHASE_V1 || condition_hash || amount_LE || timestamp_LE || chain || asset)
 *
 * This uses BPOP_DOMAIN, NOT PORTAL_KEY_SIG_V1.
 * The wallet must sign this payload separately for BPoP — reusing the
 * Portal Key signature will fail verification on the Rust side.
 */
export function computeBpopPayload(
  conditionHash: string,
  amount: bigint,
  timestamp: number,
  chain: string,
  asset: string,
): string {
  const domain = Buffer.from(BPOP_DOMAIN);
  const condBuf = Buffer.from(conditionHash.replace("0x", ""), "hex");
  const amountBuf = Buffer.alloc(8);
  amountBuf.writeBigUInt64LE(amount);
  const timestampBuf = Buffer.alloc(8);
  timestampBuf.writeBigUInt64LE(BigInt(timestamp));
  // Length-prefix chain and asset strings with 4-byte LE u32,
  // matching Rust compute_bpop_payload() which uses (chain.len() as u32).to_le_bytes().
  // Without this, the hash payload differs and cross-language signature verification fails.
  const chainBytes = Buffer.from(chain);
  const chainLen = Buffer.alloc(4);
  chainLen.writeUInt32LE(chainBytes.length);
  const assetBytes = Buffer.from(asset);
  const assetLen = Buffer.alloc(4);
  assetLen.writeUInt32LE(assetBytes.length);
  const data = Buffer.concat([domain, condBuf, amountBuf, timestampBuf, chainLen, chainBytes, assetLen, assetBytes]);
  return "0x" + createHash("sha256").update(data).digest("hex");
}

/**
 * Create a BPoP receipt with mandatory secret verification.
 *
 * `bpopSignature` MUST be a Schnorr signature over the BPoP payload
 * (computed by computeBpopPayload), NOT the Portal Key signature.
 * Using the Portal Key signature will fail Rust-side verification because
 * they use different domain tags (PORTAL_KEY_SIG_V1 vs BPOP_DOMAIN).
 *
 * The wallet signs the BPoP payload separately via TEE after the merchant
 * reveals their secret.
 */
export function createBpop(params: {
  paymentUri: string;
  /** MUST be signature over computeBpopPayload(), NOT the Portal Key signature. */
  bpopSignature: string;
  ownerPubkey: string;
  merchantSecret: string;
  settledAtBlock?: number;
}): ProofOfPurchase {
  const uri = parsePaymentUri(params.paymentUri);

  // CRITICAL: Verify secret BEFORE creating the receipt
  const secretHash = computeConditionHash(params.merchantSecret);
  if (secretHash !== uri.conditionHash) {
    throw new Error(
      `Merchant secret does not match condition hash! ` +
      `Expected ${uri.conditionHash}, got ${secretHash}. ` +
      `The merchant may be trying to give you a fake receipt.`
    );
  }

  const timestamp = Math.floor(Date.now() / 1000);

  // The expected payload for verification is:
  // SHA-256(BPOP_DOMAIN || condition_hash || amount_LE || timestamp_LE || chain || asset)
  // Caller must sign THIS payload, not the Portal Key payload.

  return {
    paymentUri: params.paymentUri,
    amount: uri.amount,
    conditionHash: uri.conditionHash,
    portalSignature: params.bpopSignature,
    ownerPubkey: params.ownerPubkey,
    merchantSecret: params.merchantSecret,
    settledAtBlock: params.settledAtBlock,
    timestamp,
    chain: uri.chain,
    asset: uri.asset,
  };
}

/** Serialize BPoP to JSON for storage. */
export function serializeBpop(bpop: ProofOfPurchase): string {
  return JSON.stringify({
    ...bpop,
    amount: bpop.amount.toString(),
  }, null, 2);
}

/** Deserialize BPoP from JSON. */
export function deserializeBpop(json: string): ProofOfPurchase {
  const obj = JSON.parse(json);
  return { ...obj, amount: BigInt(obj.amount) };
}

// ══════════════════════════════════════════════════════════════════
//  Local Nullifier Guard (merchant-side deduplication)
// ══════════════════════════════════════════════════════════════════

/**
 * Prevents the TOCTOU race where 100 concurrent requests with the same
 * Portal Key all pass the L2 nullifier check before any settlement lands.
 *
 * The merchant MUST call `guard.tryAccept(nullifier)` before delivering
 * goods/services. Returns false if the nullifier is already being processed.
 *
 * This is a LOCAL mutex — it does NOT replace L2 nullifier checking.
 * Both are needed: local guard for instant dedup, L2 check for finality.
 */
export class NullifierGuard {
  private readonly pending = new Set<string>();
  private readonly settled = new Set<string>();

  /**
   * Try to accept a payment with this nullifier.
   * Returns true if accepted (first time seen), false if duplicate.
   *
   * Thread-safe in Node.js single-threaded event loop.
   * For multi-process deployments, use Redis SET NX instead.
   */
  tryAccept(nullifier: string): boolean {
    if (this.pending.has(nullifier) || this.settled.has(nullifier)) {
      return false; // DUPLICATE — reject immediately
    }
    this.pending.add(nullifier);
    return true;
  }

  /** Mark a nullifier as settled (after L2 confirmation). */
  markSettled(nullifier: string): void {
    this.pending.delete(nullifier);
    this.settled.add(nullifier);
  }

  /** Release a nullifier (settlement failed — allow retry). */
  release(nullifier: string): void {
    this.pending.delete(nullifier);
  }

  /** Check if a nullifier is currently pending or settled. */
  isKnown(nullifier: string): boolean {
    return this.pending.has(nullifier) || this.settled.has(nullifier);
  }

  /** Number of pending (unconfirmed) nullifiers. */
  get pendingCount(): number { return this.pending.size; }

  /** Number of settled (confirmed) nullifiers. */
  get settledCount(): number { return this.settled.size; }
}

// ══════════════════════════════════════════════════════════════════
//  Settlement Queue (merchant-side batch accumulator)
// ══════════════════════════════════════════════════════════════════

export interface PendingSettlement {
  lockId: string;
  merchantSecret: string;
  portalSignature: string;
  nullifier: string;
  amount: bigint;
  addedAt: number;
}

/** Gas cost estimate per claim (in satoshis, conservative). */
const ESTIMATED_GAS_PER_CLAIM_SATS = 30n; // ~30,000 gas at 1 sat/1000 gas

/**
 * Settlement queue with profitability protection for relayers.
 *
 * Rejects dust claims that cost more in gas than the
 * relayer would earn in fees, preventing economic griefing attacks.
 */
export class SettlementQueue {
  private queue: PendingSettlement[] = [];
  private readonly maxBatchSize: number;
  /** Minimum individual claim amount to be profitable for relayer. */
  private readonly minClaimAmount: bigint;

  /**
   * @param maxBatchSize Maximum claims per batch (default: 100)
   * @param relayFeeBps Relay fee in basis points (default: 100 = 1%)
   */
  constructor(maxBatchSize = 100, relayFeeBps = 100) {
    this.maxBatchSize = maxBatchSize;
    // Compute minimum profitable claim amount.
    // relayer_fee = amount * fee_bps / 10000
    // Must be > gas cost: amount * fee_bps / 10000 > ESTIMATED_GAS_PER_CLAIM
    // → amount > ESTIMATED_GAS * 10000 / fee_bps
    this.minClaimAmount = relayFeeBps > 0
      ? (ESTIMATED_GAS_PER_CLAIM_SATS * 10_000n) / BigInt(relayFeeBps)
      : 0n;
  }

  /** Add a settlement claim to the queue. Rejects unprofitable dust. */
  add(claim: PendingSettlement): boolean {
    if (claim.amount < this.minClaimAmount) {
      return false; // GAS-DRAIN: Claim too small to cover gas costs
    }
    this.queue.push(claim);
    return true;
  }

  /** Get current queue size. */
  get size(): number {
    return this.queue.length;
  }

  /** Check if queue is ready for batch submission. */
  get isReady(): boolean {
    return this.queue.length >= this.maxBatchSize;
  }

  /** Total pending amount in satoshis. */
  get totalAmount(): bigint {
    return this.queue.reduce((sum, c) => sum + c.amount, 0n);
  }

  /** Drain the queue and return claims for batch_settle. */
  drain(): PendingSettlement[] {
    const batch = this.queue.splice(0, this.maxBatchSize);
    return batch;
  }

  /** Drain all regardless of batch size. */
  drainAll(): PendingSettlement[] {
    const all = [...this.queue];
    this.queue = [];
    return all;
  }

  /**
   * Pre-validate claims against L2 state before submission.
   *
   * Removes stale claims (expired locks, consumed nullifiers, settled locks)
   * to avoid paying gas for guaranteed-to-fail settlements.
   *
   * @param rpcClient - BrrqClient instance for L2 queries
   * @returns Number of claims removed as stale
   */
  async preValidate(rpcClient: {
    getPortalLock: (id: string) => Promise<{ status: string; pending_cancel?: boolean } | null>;
    checkNullifier: (n: string) => Promise<{ consumed?: boolean; pending_settlement?: boolean }>;
  }): Promise<number> {
    const valid: PendingSettlement[] = [];
    let removed = 0;

    for (const claim of this.queue) {
      try {
        const [lock, nullStatus] = await Promise.all([
          rpcClient.getPortalLock(claim.lockId),
          rpcClient.checkNullifier(claim.nullifier),
        ]);

        // Skip if lock is not Active or has pending cancel
        if (!lock || lock.status !== "Active" || lock.pending_cancel) {
          removed++;
          continue;
        }

        // Skip if nullifier already consumed or has pending settlement
        if (nullStatus.consumed || nullStatus.pending_settlement) {
          removed++;
          continue;
        }

        valid.push(claim);
      } catch {
        // RPC error — keep claim (conservative: don't drop on network failure)
        valid.push(claim);
      }
    }

    this.queue = valid;
    return removed;
  }
}

// ══════════════════════════════════════════════════════════════════
//  Portal Key Helpers
// ══════════════════════════════════════════════════════════════════

// ══════════════════════════════════════════════════════════════════
//  Invoice Secret Derivation
// ══════════════════════════════════════════════════════════════════

/**
 * Derive a unique invoice secret from merchant master secret + invoice ID.
 *
 * Prevents merchant_secret reuse across invoices.
 * Even if the merchant uses the same master_secret forever, each invoice
 * gets a unique derived secret via HMAC-SHA256.
 *
 * secret = HMAC-SHA256(master_secret, "BRRQ_INVOICE_V1" || invoice_id || timestamp)
 *
 * @param masterSecret - Merchant's master secret (hex string, should be stored securely)
 * @param invoiceId - Unique invoice identifier (e.g., UUID, order number)
 * @param timestamp - Invoice creation timestamp (Unix seconds)
 * @returns Derived secret as hex string (32 bytes)
 */
export function deriveInvoiceSecret(
  masterSecret: string,
  invoiceId: string,
  timestamp: number,
): string {
  const key = Buffer.from(masterSecret, "hex");
  const domain = Buffer.from("BRRQ_INVOICE_V1");
  const idBuf = Buffer.from(invoiceId, "utf8");
  const tsBuf = Buffer.alloc(8);
  tsBuf.writeBigUInt64LE(BigInt(timestamp));
  const message = Buffer.concat([domain, idBuf, tsBuf]);
  return createHmac("sha256", key).update(message).digest("hex");
}

/**
 * Create a complete invoice with derived secret and condition hash.
 *
 * This is the RECOMMENDED merchant entry point — prevents secret reuse.
 *
 * @param masterSecret - Merchant's master secret (hex, 32 bytes)
 * @param invoiceId - Unique invoice ID
 * @param amount - Amount in satoshis
 * @param chain - "mainnet" or "testnet"
 * @param timeout - Lock timeout (L2 block height)
 * @returns { secret, conditionHash, paymentUri }
 */
export function createInvoice(params: {
  masterSecret: string;
  invoiceId: string;
  amount: bigint;
  chain: BrrqChain;
  timeout: number;
  asset?: string;
}): { secret: string; conditionHash: string; paymentUri: string } {
  const timestamp = Math.floor(Date.now() / 1000);
  const secret = deriveInvoiceSecret(params.masterSecret, params.invoiceId, timestamp);
  const conditionHash = computeConditionHash(secret);
  const paymentUri = createPaymentUri({
    version: URI_VERSION,
    chain: params.chain,
    amount: params.amount,
    conditionHash,
    timeout: params.timeout,
    asset: params.asset ?? "BTC",
  });
  return { secret, conditionHash, paymentUri };
}

/** Compute condition hash from merchant secret. */
export function computeConditionHash(merchantSecret: Buffer | string): string {
  const buf = typeof merchantSecret === "string"
    ? Buffer.from(merchantSecret, "hex")
    : merchantSecret;
  return "0x" + createHash("sha256").update(buf).digest("hex");
}

/** Compute extended nullifier (for verification only — actual signing is TEE-side). */
export function computeNullifier(
  secretKey: Buffer,
  lockId: string,
  conditionHash: string,
): string {
  const domain = Buffer.from("BRRQ_PORTAL_NULLIFIER_V1");
  const lockBuf = Buffer.from(lockId.replace("0x", ""), "hex");
  const condBuf = Buffer.from(conditionHash.replace("0x", ""), "hex");
  const data = Buffer.concat([domain, lockBuf, condBuf]);
  return "0x" + createHmac("sha256", secretKey).update(data).digest("hex");
}

// ══════════════════════════════════════════════════════════════════
//  Portal Key Payload (match Rust compute_portal_key_payload)
// ══════════════════════════════════════════════════════════════════

/** Domain tags — must match Rust brrq_crypto::domain_tags exactly. */
export const DOMAIN_TAGS = {
  PORTAL_KEY_SIG_V1: "BRRQ_PORTAL_KEY_SIG_V1",
  PORTAL_NULLIFIER_V1: "BRRQ_PORTAL_NULLIFIER_V1",
  BPOP_V1: "BRRQ_PROOF_OF_PURCHASE_V1",
} as const;

/**
 * Compute the Portal Key signature payload (matches Rust exactly).
 *
 * payload = SHA-256(BRRQ_PORTAL_KEY_SIG_V1 || lock_id [32B] || condition_hash [32B] || timeout [u64 LE])
 */
export function computePortalKeyPayload(
  lockId: string,
  conditionHash: string,
  timeoutBlock: number,
): string {
  const domain = Buffer.from(DOMAIN_TAGS.PORTAL_KEY_SIG_V1);
  const lockBuf = Buffer.from(lockId.replace("0x", ""), "hex");
  const condBuf = Buffer.from(conditionHash.replace("0x", ""), "hex");
  const timeoutBuf = Buffer.alloc(8);
  timeoutBuf.writeBigUInt64LE(BigInt(timeoutBlock));
  const data = Buffer.concat([domain, lockBuf, condBuf, timeoutBuf]);
  return "0x" + createHash("sha256").update(data).digest("hex");
}

// ══════════════════════════════════════════════════════════════════
//  Convenience namespace
// ══════════════════════════════════════════════════════════════════

/**
 * Validate that the signing payload matches the displayed URI.
 *
 * The wallet MUST call this before sending the payload to TEE for signing.
 * Ensures the user is not tricked into signing a different condition_hash
 * than what was shown in the QR/deep-link.
 *
 * @param displayedUri - The URI the user saw and approved
 * @param signingConditionHash - The condition_hash about to be signed
 * @param signingAmount - The lock amount (must match URI)
 * @returns true if safe to sign, throws on mismatch
 */
export function validateBeforeSigning(
  displayedUri: string,
  signingConditionHash: string,
  signingAmount: bigint,
): boolean {
  const uri = parsePaymentUri(displayedUri);

  if (uri.conditionHash !== signingConditionHash) {
    throw new Error(
      `BLIND SIGNING ATTACK DETECTED: condition_hash mismatch! ` +
      `Displayed: ${uri.conditionHash}, Signing: ${signingConditionHash}`
    );
  }

  if (uri.amount !== signingAmount) {
    throw new Error(
      `BLIND SIGNING ATTACK DETECTED: amount mismatch! ` +
      `Displayed: ${uri.amount}, Signing: ${signingAmount}`
    );
  }

  return true;
}

/** BrrqPortal — convenience namespace for Portal operations. */
export const BrrqPortal = {
  parseUri: parsePaymentUri,
  createUri: createPaymentUri,
  createBpop,
  computeBpopPayload,
  computeConditionHash,
  computeNullifier,
  computePortalKeyPayload,
  validateBeforeSigning,
  verifyBpop,
  verifyBpopSecret,
  serializeBpop,
  deserializeBpop,
  SettlementQueue,
  NullifierGuard,
  DOMAIN_TAGS,
} as const;
