/**
 * Brrq Merchant API Server — production-grade payment acceptance.
 *
 * Integrates NullifierGuard (local dedup) + L2 verification + SettlementQueue.
 *
 * ## Security Model
 *
 * 1. **NullifierGuard** — instant local rejection of duplicate Portal Keys (0ms)
 * 2. **L2 Query** — check lock status + nullifier + pending_cancel + pending_settlement
 * 3. **SettlementQueue** — batch accumulation with profitability filtering
 *
 * ## Usage
 *
 * ```ts
 * import { MerchantServer } from "@brrq/sdk";
 *
 * const server = new MerchantServer({
 *   rpcUrl: "http://localhost:8545",
 *   settlementIntervalMs: 60_000, // batch every 60s
 *   relayFeeBps: 50,
 * });
 *
 * // In your Express/Fastify handler:
 * app.post("/pay", async (req, res) => {
 *   const result = await server.acceptPayment({
 *     portalKey: req.body.portalKey,
 *     merchantSecret: mySecret,
 *   });
 *   if (result.accepted) {
 *     deliverGoods();
 *     res.json({ success: true, secret: mySecret.toString("hex") });
 *   } else {
 *     res.status(403).json({ error: result.reason });
 *   }
 * });
 * ```
 */

import { createHash } from "crypto";
import {
  NullifierGuard,
  SettlementQueue,
  parsePaymentUri,
  computeConditionHash,
} from "./portal.js";

export interface MerchantServerConfig {
  /** L2 RPC URL. */
  rpcUrl: string;
  /** Settlement batch interval in milliseconds (default: 60000 = 1 min). */
  settlementIntervalMs?: number;
  /** Relay fee in basis points for gasless settlement (default: 50 = 0.5%). */
  relayFeeBps?: number;
  /** Maximum pending payments before forcing a batch (default: 100). */
  maxBatchSize?: number;
}

export interface PortalKeyPayload {
  protocol: string;
  signature: string;
  nullifier: string;
  lock_id: string;
  public_inputs: {
    owner: string;
    owner_pubkey: string;
    asset_id: string;
    amount: number;
    condition_hash: string;
    timeout_l2_block: number;
  };
}

export interface PaymentRequest {
  /** The Portal Key received from the customer. */
  portalKey: PortalKeyPayload;
  /** Merchant's secret for this payment. */
  merchantSecret: string;
}

export interface PaymentResult {
  accepted: boolean;
  reason?: string;
  lockId?: string;
  amount?: number;
}

interface L2PortalLockResponse {
  status: string;
  safe_to_accept?: boolean;
  amount: number;
}

interface L2NullifierResponse {
  safe: boolean;
  consumed?: boolean;
  pending_settlement?: boolean;
}

interface L2RpcClient {
  getPortalLock(lockId: string): Promise<L2PortalLockResponse | null>;
  checkNullifier(nullifier: string): Promise<L2NullifierResponse>;
}

/** Simple JSON-RPC client for L2 queries. */
class SimpleL2Client implements L2RpcClient {
  private rpcUrl: string;
  private nextId = 1;

  constructor(rpcUrl: string) {
    this.rpcUrl = rpcUrl;
  }

  private async rpc<T>(method: string, params: unknown[]): Promise<T> {
    const res = await fetch(this.rpcUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: this.nextId++,
        method,
        params,
      }),
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

/**
 * Production Merchant Server with full TOCTOU protection.
 *
 * Handles the complete payment acceptance flow:
 * 1. Local nullifier dedup (NullifierGuard — prevents 100-concurrent-request attack)
 * 2. L2 state verification (lock active + nullifier safe + no pending cancel)
 * 3. Settlement queuing with profitability filtering
 */
export class MerchantServer {
  private readonly guard: NullifierGuard;
  private readonly queue: SettlementQueue;
  private readonly l2: L2RpcClient;
  private readonly config: Required<MerchantServerConfig>;
  private batchTimer: ReturnType<typeof setInterval> | null = null;

  constructor(config: MerchantServerConfig) {
    this.config = {
      rpcUrl: config.rpcUrl,
      settlementIntervalMs: config.settlementIntervalMs ?? 60_000,
      relayFeeBps: config.relayFeeBps ?? 50,
      maxBatchSize: config.maxBatchSize ?? 100,
    };
    this.guard = new NullifierGuard();
    this.queue = new SettlementQueue(this.config.maxBatchSize, this.config.relayFeeBps);
    this.l2 = new SimpleL2Client(this.config.rpcUrl);
  }

  /**
   * Accept or reject a payment.
   *
   * This is the ONLY method merchants should call. It handles:
   * - Local dedup (NullifierGuard)
   * - L2 state check (lock + nullifier + mempool awareness)
   * - Settlement queuing
   */
  async acceptPayment(req: PaymentRequest): Promise<PaymentResult> {
    const { portalKey, merchantSecret } = req;
    const nullifier = portalKey.nullifier;
    const lockId = portalKey.lock_id;

    // ═══ STEP 1: Local dedup (instant, 0ms) ═══
    // This is the TOCTOU fix — rejects duplicates before any RPC call
    if (!this.guard.tryAccept(nullifier)) {
      return { accepted: false, reason: "duplicate_nullifier" };
    }

    try {
      // ═══ STEP 2: Verify condition hash matches merchant secret ═══
      const expectedCond = computeConditionHash(merchantSecret);
      if (expectedCond !== portalKey.public_inputs.condition_hash) {
        this.guard.release(nullifier);
        return { accepted: false, reason: "condition_hash_mismatch" };
      }

      // ═══ STEP 3: L2 state verification ═══
      const [lock, nullStatus] = await Promise.all([
        this.l2.getPortalLock(lockId),
        this.l2.checkNullifier(nullifier),
      ]);

      // Check lock exists and is active
      if (!lock || lock.status !== "Active") {
        this.guard.release(nullifier);
        return { accepted: false, reason: "lock_not_active" };
      }

      // Check safe_to_accept (includes pending_cancel check)
      if (lock.safe_to_accept === false) {
        this.guard.release(nullifier);
        return { accepted: false, reason: "lock_pending_cancel" };
      }

      // Check amount
      if (lock.amount < portalKey.public_inputs.amount) {
        this.guard.release(nullifier);
        return { accepted: false, reason: "insufficient_lock_amount" };
      }

      // Check nullifier safe (includes pending_settlement check)
      if (nullStatus.safe === false) {
        this.guard.release(nullifier);
        return { accepted: false, reason: "nullifier_unsafe" };
      }

      // ═══ STEP 4: Queue for settlement ═══
      const added = this.queue.add({
        lockId,
        merchantSecret,
        portalSignature: portalKey.signature,
        nullifier,
        amount: BigInt(portalKey.public_inputs.amount),
        addedAt: Date.now(),
      });

      if (!added) {
        this.guard.release(nullifier);
        return { accepted: false, reason: "claim_below_profitability_threshold" };
      }

      return {
        accepted: true,
        lockId,
        amount: portalKey.public_inputs.amount,
      };
    } catch (err: unknown) {
      // RPC failure — release guard so payment can be retried
      const message = err instanceof Error ? err.message : String(err);
      this.guard.release(nullifier);
      return { accepted: false, reason: `rpc_error: ${message}` };
    }
  }

  /** Start periodic batch settlement. */
  startBatching(): void {
    if (this.batchTimer) return;
    this.batchTimer = setInterval(() => {
      if (this.queue.isReady || this.queue.size > 0) {
        const batch = this.queue.drain();
        if (batch.length > 0) {
          for (const claim of batch) {
            this.guard.markSettled(claim.nullifier);
          }
        }
      }
    }, this.config.settlementIntervalMs);
  }

  /** Stop periodic batching. */
  stopBatching(): void {
    if (this.batchTimer) {
      clearInterval(this.batchTimer);
      this.batchTimer = null;
    }
  }

  /** Get server statistics. */
  stats() {
    return {
      pendingNullifiers: this.guard.pendingCount,
      settledNullifiers: this.guard.settledCount,
      queueSize: this.queue.size,
      queueAmount: this.queue.totalAmount,
    };
  }
}
