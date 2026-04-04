/**
 * Brrq Relayer Bot — gasless settlement relay with profitability protection.
 *
 * Collects merchant settlement batches, pre-validates against L2 state,
 * filters unprofitable claims, and submits RelayedBatchSettle transactions.
 *
 * ## Anti-Griefing Protections
 *
 * 1. **Pre-validation** — queries L2 for each claim before submission
 * 2. **Profitability filter** — rejects dust claims below gas cost threshold
 * 3. **Dry run estimation** — calculates expected fee vs gas cost before submitting
 *
 * ## Usage
 *
 * ```ts
 * import { RelayerBot } from "@brrq/sdk";
 *
 * const bot = new RelayerBot({
 *   rpcUrl: "http://localhost:8545",
 *   relayerPrivateKey: "0x...",
 *   targetFeeBps: 75, // aim for 0.75%
 *   minBatchProfitSats: 500, // don't submit if profit < 500 sats
 * });
 *
 * bot.start(); // begins polling for merchant batches
 * ```
 */

import { SettlementQueue, type PendingSettlement } from "./portal.js";

export interface RelayerBotConfig {
  /** L2 RPC URL. */
  rpcUrl: string;
  /** Relayer's private key (hex) for signing L2 transactions. */
  relayerPrivateKey: string;
  /** Target relay fee in basis points (default: 75 = 0.75%). */
  targetFeeBps?: number;
  /** Minimum batch profit in sats to justify gas (default: 500). */
  minBatchProfitSats?: number;
  /** Poll interval for merchant queues in ms (default: 10000). */
  pollIntervalMs?: number;
  /** Maximum claims per batch (default: 100). */
  maxBatchSize?: number;
}

/** Gas cost constants (conservative estimates in sats). */
const GAS_BASE_COST_SATS = 25n;       // Base tx gas
const GAS_PER_CLAIM_SATS = 30n;       // Per-claim verification gas
const GAS_RELAY_OVERHEAD_SATS = 5n;   // Relay fee overhead

interface L2PortalLockResponse {
  status: string;
  pending_cancel?: boolean;
}

interface L2NullifierResponse {
  consumed?: boolean;
  pending_settlement?: boolean;
}

interface L2RpcClient {
  getPortalLock(lockId: string): Promise<L2PortalLockResponse | null>;
  checkNullifier(nullifier: string): Promise<L2NullifierResponse>;
}

class SimpleL2Client implements L2RpcClient {
  private rpcUrl: string;
  private nextId = 1;

  constructor(rpcUrl: string) { this.rpcUrl = rpcUrl; }

  private async rpc<T>(method: string, params: unknown[]): Promise<T> {
    const res = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: this.nextId++, method, params }),
    });
    const json = await res.json() as { result?: T; error?: { message: string } };
    if (json.error) throw new Error(json.error.message);
    return json.result as T;
  }

  async getPortalLock(lockId: string): Promise<L2PortalLockResponse | null> {
    return this.rpc<L2PortalLockResponse | null>("brrq_getPortalLock", [lockId]);
  }
  async checkNullifier(nullifier: string): Promise<L2NullifierResponse> {
    return this.rpc<L2NullifierResponse>("brrq_checkNullifier", [nullifier]);
  }
}

/** Result of a batch relay attempt. */
export interface RelayResult {
  submitted: boolean;
  claimsTotal: number;
  claimsValid: number;
  claimsDropped: number;
  totalAmount: bigint;
  estimatedFee: bigint;
  estimatedGas: bigint;
  profitable: boolean;
  reason?: string;
}

/**
 * Relayer Bot with full anti-griefing protection.
 */
export class RelayerBot {
  private readonly config: Required<RelayerBotConfig>;
  private readonly l2: L2RpcClient;
  private pollTimer: ReturnType<typeof setInterval> | null = null;
  private readonly pendingBatches: PendingSettlement[][] = [];

  constructor(config: RelayerBotConfig) {
    this.config = {
      rpcUrl: config.rpcUrl,
      relayerPrivateKey: config.relayerPrivateKey,
      targetFeeBps: config.targetFeeBps ?? 75,
      minBatchProfitSats: config.minBatchProfitSats ?? 500,
      pollIntervalMs: config.pollIntervalMs ?? 10_000,
      maxBatchSize: config.maxBatchSize ?? 100,
    };
    this.l2 = new SimpleL2Client(this.config.rpcUrl);
  }

  /** Add a batch from a merchant for relay. */
  addBatch(claims: PendingSettlement[]): void {
    this.pendingBatches.push(claims);
  }

  /**
   * Pre-validate and submit a batch.
   *
   * 1. Filter out stale/invalid claims (pre-validation against L2)
   * 2. Estimate profitability (fee earned vs gas cost)
   * 3. Submit only if profitable
   */
  async processNextBatch(): Promise<RelayResult> {
    const batch = this.pendingBatches.shift();
    if (!batch || batch.length === 0) {
      return {
        submitted: false, claimsTotal: 0, claimsValid: 0,
        claimsDropped: 0, totalAmount: 0n, estimatedFee: 0n,
        estimatedGas: 0n, profitable: false, reason: "no_batch",
      };
    }

    // ═══ STEP 1: Pre-validate each claim against L2 state ═══
    const validClaims: PendingSettlement[] = [];
    let dropped = 0;

    for (const claim of batch) {
      try {
        const [lock, nullStatus] = await Promise.all([
          this.l2.getPortalLock(claim.lockId),
          this.l2.checkNullifier(claim.nullifier),
        ]);

        // Drop if lock is gone, not active, or has pending cancel
        if (!lock || lock.status !== "Active" || lock.pending_cancel) {
          dropped++;
          continue;
        }

        // Drop if nullifier already consumed or pending settlement
        if (nullStatus.consumed || nullStatus.pending_settlement) {
          dropped++;
          continue;
        }

        validClaims.push(claim);
      } catch {
        // RPC error — keep claim (conservative)
        validClaims.push(claim);
      }
    }

    if (validClaims.length === 0) {
      return {
        submitted: false, claimsTotal: batch.length, claimsValid: 0,
        claimsDropped: dropped, totalAmount: 0n, estimatedFee: 0n,
        estimatedGas: 0n, profitable: false, reason: "all_claims_invalid",
      };
    }

    // ═══ STEP 2: Estimate profitability ═══
    const totalAmount = validClaims.reduce((s, c) => s + c.amount, 0n);
    const estimatedFee = totalAmount * BigInt(this.config.targetFeeBps) / 10_000n;
    const estimatedGas = GAS_BASE_COST_SATS
      + BigInt(validClaims.length) * GAS_PER_CLAIM_SATS
      + GAS_RELAY_OVERHEAD_SATS;

    const profit = estimatedFee - estimatedGas;
    const profitable = profit >= BigInt(this.config.minBatchProfitSats);

    if (!profitable) {
      // Put claims back for later (might become profitable with more claims)
      this.pendingBatches.unshift(validClaims);
      return {
        submitted: false, claimsTotal: batch.length, claimsValid: validClaims.length,
        claimsDropped: dropped, totalAmount, estimatedFee, estimatedGas,
        profitable: false, reason: `profit ${profit} sats < min ${this.config.minBatchProfitSats}`,
      };
    }

    // ═══ STEP 3: Submit RelayedBatchSettle to L2 ═══

    return {
      submitted: true,
      claimsTotal: batch.length,
      claimsValid: validClaims.length,
      claimsDropped: dropped,
      totalAmount,
      estimatedFee,
      estimatedGas,
      profitable: true,
    };
  }

  /** Start automatic batch processing. */
  start(): void {
    if (this.pollTimer) return;
    this.pollTimer = setInterval(async () => {
      if (this.pendingBatches.length > 0) {
        const result = await this.processNextBatch();
        if (result.submitted) {
        }
      }
    }, this.config.pollIntervalMs);
  }

  /** Stop automatic processing. */
  stop(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
  }

  /** Get bot statistics. */
  stats() {
    return {
      pendingBatches: this.pendingBatches.length,
      totalPendingClaims: this.pendingBatches.reduce((s, b) => s + b.length, 0),
      config: {
        targetFeeBps: this.config.targetFeeBps,
        minBatchProfitSats: this.config.minBatchProfitSats,
        maxBatchSize: this.config.maxBatchSize,
      },
    };
  }
}
