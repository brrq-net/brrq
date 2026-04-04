/**
 * Brrq TypeScript SDK — Client
 *
 * The main entry point for interacting with a Brrq node.
 * Provides typed methods for both JSON-RPC 2.0 and REST endpoints.
 */

import type {
  Account,
  BatchProof,
  Block,
  BridgeStatus,
  EpochInfo,
  GovernanceProposal,
  GovernanceStats,
  JsonRpcRequest,
  JsonRpcResponse,
  MevStatus,
  NetworkStats,
  SequencerInfo,
  SignedTransaction,
  Transaction,
  TxReceipt,
  Validator,
} from "./types.js";

/** Error thrown when a JSON-RPC call returns an error response. */
export class RpcError extends Error {
  constructor(
    public readonly code: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(message);
    this.name = "RpcError";
  }
}

/**
 * Brrq JSON-RPC + REST client.
 *
 * Communicates with a Brrq node over HTTP using:
 * - `POST /` for JSON-RPC 2.0 calls (brrq_* methods)
 * - `GET /api/v1/*` for REST endpoints (stats, block lists, etc.)
 *
 * @example
 * ```ts
 * const client = new BrrqClient("http://localhost:8545");
 * const height = await client.getBlockHeight();
 * const balance = await client.getBalance("0xabc...");
 * ```
 */
export class BrrqClient {
  /** Base URL of the Brrq node (no trailing slash). */
  private readonly endpoint: string;
  /** Auto-incrementing JSON-RPC request ID (wraps at MAX_SAFE_INTEGER). */
  private nextId = 1;
  /** Request timeout in milliseconds (default: 30 seconds). */
  private readonly timeoutMs: number;

  /**
   * Create a new BrrqClient.
   *
   * @param endpoint - The base URL of the Brrq node (e.g. "http://localhost:8545")
   * @param options - Optional configuration
   */
  constructor(endpoint: string, options?: { timeoutMs?: number }) {
    // Strip trailing slash
    this.endpoint = endpoint.endsWith("/") ? endpoint.slice(0, -1) : endpoint;
    this.timeoutMs = options?.timeoutMs ?? 30_000;
  }

  // ──────────────────────────────────────────────────────────────────
  // JSON-RPC transport
  // ──────────────────────────────────────────────────────────────────

  /**
   * Send a raw JSON-RPC 2.0 request.
   *
   * @param method - The RPC method name (e.g. "brrq_blockHeight")
   * @param params - Optional parameters
   * @returns The `result` field of the JSON-RPC response
   * @throws {RpcError} If the response contains an error object
   */
  private async rpc<T = unknown>(method: string, params?: unknown): Promise<T> {
    const id = this.nextId;
    this.nextId = this.nextId >= Number.MAX_SAFE_INTEGER ? 1 : this.nextId + 1;
    const body: JsonRpcRequest = {
      jsonrpc: "2.0",
      method,
      params: params ?? null,
      id,
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await fetch(this.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new RpcError(-1, `RPC request timed out after ${this.timeoutMs}ms`);
      }
      throw err;
    }
    clearTimeout(timer);

    if (!response.ok) {
      throw new RpcError(-1, `HTTP ${response.status}: ${response.statusText}`);
    }

    const json = (await response.json()) as JsonRpcResponse<T>;

    if (json.error) {
      throw new RpcError(
        json.error.code,
        json.error.message,
        json.error.data,
      );
    }

    return json.result as T;
  }

  /**
   * Send a GET request to the REST API.
   *
   * @param path - Path relative to /api/v1 (e.g. "/stats")
   * @returns Parsed JSON response
   */
  private async rest<T = unknown>(path: string): Promise<T> {
    const url = `${this.endpoint}/api/v1${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response: Response;
    try {
      response = await fetch(url, {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      if (err instanceof DOMException && err.name === "AbortError") {
        throw new Error(`REST request timed out after ${this.timeoutMs}ms`);
      }
      throw err;
    }
    clearTimeout(timer);

    if (!response.ok) {
      throw new Error(`REST ${response.status}: ${response.statusText}`);
    }

    return (await response.json()) as T;
  }

  // ──────────────────────────────────────────────────────────────────
  // Chain state
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get the current block height.
   *
   * JSON-RPC: `brrq_blockHeight`
   */
  async getBlockHeight(): Promise<number> {
    return this.rpc<number>("brrq_blockHeight");
  }

  /**
   * Get the balance of an address in satoshis.
   *
   * JSON-RPC: `brrq_getBalance`
   *
   * @param address - Account address (hex with 0x prefix)
   * @returns Balance in satoshis as bigint
   */
  async getBalance(address: string): Promise<bigint> {
    const result = await this.rpc<number | string>("brrq_getBalance", [address]);
    return BigInt(result);
  }

  /**
   * Get the nonce of an address.
   *
   * JSON-RPC: `brrq_getNonce`
   *
   * @param address - Account address (hex with 0x prefix)
   * @returns Current nonce
   */
  async getNonce(address: string): Promise<number> {
    return this.rpc<number>("brrq_getNonce", [address]);
  }

  /**
   * Get the chain ID.
   *
   * JSON-RPC: `brrq_chainId`
   *
   * @returns Chain ID number
   */
  async getChainId(): Promise<number> {
    return this.rpc<number>("brrq_chainId");
  }

  // ──────────────────────────────────────────────────────────────────
  // Accounts
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get full account information.
   *
   * JSON-RPC: `brrq_getAccount`
   *
   * @param address - Account address (hex with 0x prefix)
   * @returns Account info or null if not found
   */
  async getAccount(address: string): Promise<Account | null> {
    const raw = await this.rpc<Record<string, unknown> | null>(
      "brrq_getAccount",
      [address],
    );
    if (!raw) return null;
    return {
      address: raw.address as string,
      balance: BigInt((raw.balance as number | string) ?? 0),
      nonce: (raw.nonce as number) ?? 0,
      codeHash: raw.code_hash as string | undefined,
      storageRoot: raw.storage_root as string | undefined,
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // Blocks
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get a block by height.
   *
   * JSON-RPC: `brrq_getBlock`
   *
   * @param height - Block height
   * @returns Block or null if not found
   */
  async getBlock(height: number): Promise<Block | null> {
    const raw = await this.rpc<Record<string, unknown> | null>(
      "brrq_getBlock",
      [height],
    );
    return raw ? this.parseBlock(raw) : null;
  }

  /**
   * Get a block by its hash.
   *
   * JSON-RPC: `brrq_getBlockByHash`
   *
   * @param hash - Block hash (hex with 0x prefix)
   * @returns Block or null if not found
   */
  async getBlockByHash(hash: string): Promise<Block | null> {
    const raw = await this.rpc<Record<string, unknown> | null>(
      "brrq_getBlockByHash",
      [hash],
    );
    return raw ? this.parseBlock(raw) : null;
  }

  /**
   * Get the latest block.
   *
   * JSON-RPC: `brrq_getBlock` with height = current height
   *
   * @returns Latest block or null if chain is empty
   */
  async getLatestBlock(): Promise<Block | null> {
    const height = await this.getBlockHeight();
    if (height === 0) return null;
    return this.getBlock(height);
  }

  /**
   * List blocks with pagination (latest first).
   *
   * REST: `GET /api/v1/blocks?limit={limit}&offset={offset}`
   *
   * @param page - Page number (1-indexed, default 1)
   * @param limit - Blocks per page (default 20)
   * @returns Array of blocks
   */
  async getBlocks(page: number = 1, limit: number = 20): Promise<Block[]> {
    const offset = (page - 1) * limit;
    const data = await this.rest<{ blocks: Record<string, unknown>[] }>(
      `/blocks?limit=${limit}&offset=${offset}`,
    );
    return (data.blocks ?? []).map((b) => this.parseBlock(b));
  }

  // ──────────────────────────────────────────────────────────────────
  // Transactions
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get a transaction by hash.
   *
   * JSON-RPC: `brrq_getTransaction`
   *
   * @param hash - Transaction hash (hex with 0x prefix)
   * @returns Transaction or null if not found
   */
  async getTransaction(hash: string): Promise<Transaction | null> {
    const raw = await this.rpc<Record<string, unknown> | null>(
      "brrq_getTransaction",
      [hash],
    );
    if (!raw) return null;
    return {
      hash: raw.hash as string,
      from: raw.from as string,
      nonce: (raw.nonce as number) ?? 0,
      gasLimit: (raw.gas_limit as number) ?? 0,
      gasPrice: (raw.gas_price as number) ?? 0,
      blockHeight: (raw.block_height as number) ?? 0,
    };
  }

  /**
   * Get the receipt of a transaction.
   *
   * JSON-RPC: `brrq_getReceipt`
   *
   * @param hash - Transaction hash (hex with 0x prefix)
   * @returns Receipt or null if the transaction is not yet included
   */
  async getReceipt(hash: string): Promise<TxReceipt | null> {
    const raw = await this.rpc<Record<string, unknown> | null>(
      "brrq_getReceipt",
      [hash],
    );
    if (!raw) return null;
    return {
      blockHeight: raw.block_height as number,
      gasUsed: raw.gas_used as number,
      success: raw.success as boolean,
      blockHash: raw.block_hash as string,
    };
  }

  /**
   * Submit a signed transaction to the mempool.
   *
   * JSON-RPC: `brrq_sendTransaction`
   *
   * @param tx - A signed transaction (from Wallet.transfer())
   * @returns Transaction hash
   */
  async sendTransaction(tx: SignedTransaction): Promise<string> {
    const params: Record<string, unknown> = {
      from: tx.from,
      to: tx.to,
      amount: tx.amount.toString(),
      tx_type: tx.kind,
      nonce: tx.nonce,
      gas_limit: tx.gasLimit,
      gas_price: tx.gasPrice,
      chain_id: tx.chainId,
      signature: tx.signature,
      public_key: tx.publicKey,
    };
    return this.rpc<string>("brrq_sendTransaction", [params]);
  }

  // ──────────────────────────────────────────────────────────────────
  // Consensus / Staking
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get the list of validators.
   *
   * JSON-RPC: `brrq_getValidators`
   *
   * @returns Array of validators
   */
  async getValidators(): Promise<Validator[]> {
    const raw = await this.rpc<Record<string, unknown>[]>("brrq_getValidators");
    return (raw ?? []).map((v) => ({
      address: v.address as string,
      stake: BigInt((v.stake as number | string) ?? 0),
      totalStake: BigInt((v.total_stake as number | string) ?? 0),
      status: (v.status as Validator["status"]) ?? "Active",
    }));
  }

  /**
   * Get current epoch information.
   *
   * JSON-RPC: `brrq_getEpochInfo`
   *
   * @returns Epoch info
   */
  async getEpochInfo(): Promise<EpochInfo> {
    const raw = await this.rpc<Record<string, unknown>>("brrq_getEpochInfo");
    return {
      currentEpoch: (raw.current_epoch as number) ?? 0,
      epochStartHeight: (raw.epoch_start_height as number) ?? 0,
      epochLength: (raw.epoch_length as number) ?? 0,
    };
  }

  /**
   * Get staking information for a specific validator address.
   *
   * JSON-RPC: `brrq_getStakingInfo`
   *
   * @param address - Validator address (hex with 0x prefix)
   * @returns Staking information object
   */
  async getStakingInfo(
    address: string,
  ): Promise<Record<string, unknown> | null> {
    return this.rpc<Record<string, unknown> | null>("brrq_getStakingInfo", [
      address,
    ]);
  }

  // ──────────────────────────────────────────────────────────────────
  // Bridge
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get bridge status (deposits, withdrawals, federation).
   *
   * JSON-RPC: `brrq_bridgeStatus`
   *
   * @returns Bridge status
   */
  async bridgeStatus(): Promise<BridgeStatus> {
    const raw = await this.rpc<Record<string, unknown>>("brrq_bridgeStatus");
    return {
      totalLocked: BigInt((raw.total_locked as number | string) ?? 0),
      totalMinted: BigInt((raw.total_minted as number | string) ?? 0),
      pendingDeposits: (raw.pending_deposits as number) ?? 0,
      pendingWithdrawals: (raw.pending_withdrawals as number) ?? 0,
      paused: (raw.paused as boolean) ?? false,
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // Proofs
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get the latest batch STARK proof.
   *
   * JSON-RPC: `brrq_getLatestProof`
   *
   * @returns Latest proof or null if no proofs exist
   */
  async getLatestProof(): Promise<BatchProof | null> {
    const raw = await this.rpc<Record<string, unknown> | null>(
      "brrq_getLatestProof",
    );
    if (!raw) return null;
    return {
      blockRangeStart: (raw.block_range_start as number) ?? 0,
      blockRangeEnd: (raw.block_range_end as number) ?? 0,
      verified: (raw.verified as boolean) ?? false,
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // REST-only endpoints
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get network statistics.
   *
   * REST: `GET /api/v1/stats`
   *
   * @returns Network stats
   */
  async getStats(): Promise<NetworkStats> {
    const raw = await this.rest<Record<string, unknown>>("/stats");
    return {
      blockHeight: (raw.block_height as number) ?? 0,
      txCount: (raw.tx_count as number) ?? 0,
      blockCount: (raw.block_count as number) ?? 0,
      validatorCount: (raw.validator_count as number) ?? 0,
      totalStake: BigInt((raw.total_stake as number | string) ?? 0),
      mempoolSize: (raw.mempool_size as number) ?? 0,
      proofCount: (raw.proof_count as number) ?? 0,
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // Account queries
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get all transactions for an address.
   *
   * JSON-RPC: `brrq_getTransactionsByAddress`
   *
   * @param address - Account address (hex with 0x prefix)
   * @returns Array of transactions
   */
  async getTransactionsByAddress(address: string): Promise<Transaction[]> {
    const raw = await this.rpc<Record<string, unknown>[]>("brrq_getTransactionsByAddress", [address]);
    return (raw ?? []).map((r) => ({
      hash: r.hash as string,
      from: r.from as string,
      nonce: (r.nonce as number) ?? 0,
      gasLimit: (r.gas_limit as number) ?? 0,
      gasPrice: (r.gas_price as number) ?? 0,
      blockHeight: (r.block_height as number) ?? 0,
    }));
  }

  /**
   * Get account state at a specific block height.
   *
   * JSON-RPC: `brrq_getAccountAtHeight`
   *
   * @param address - Account address (hex with 0x prefix)
   * @param height - Block height to query
   * @returns Account info at that height, or null
   */
  async getAccountAtHeight(address: string, height: number): Promise<Account | null> {
    const raw = await this.rpc<Record<string, unknown> | null>("brrq_getAccountAtHeight", [address, height]);
    if (!raw) return null;
    return {
      address: raw.address as string,
      balance: BigInt((raw.balance as number | string) ?? 0),
      nonce: (raw.nonce as number) ?? 0,
      codeHash: raw.code_hash as string | undefined,
      storageRoot: raw.storage_root as string | undefined,
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // Contract state
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get the bytecode deployed at an address.
   *
   * JSON-RPC: `brrq_getCode`
   *
   * @param address - Contract address (hex with 0x prefix)
   * @returns Hex-encoded bytecode, or null if no code
   */
  async getCode(address: string): Promise<string | null> {
    return this.rpc<string | null>("brrq_getCode", [address]);
  }

  /**
   * Get a storage value at a given key for a contract.
   *
   * JSON-RPC: `brrq_getStorageAt`
   *
   * @param address - Contract address (hex with 0x prefix)
   * @param key - Storage key (hex with 0x prefix)
   * @returns Storage value, or null
   */
  async getStorageAt(address: string, key: string): Promise<string | null> {
    return this.rpc<string | null>("brrq_getStorageAt", [address, key]);
  }

  /**
   * Get the current global state root.
   *
   * JSON-RPC: `brrq_getStateRoot`
   *
   * @returns State root hash (hex with 0x prefix)
   */
  async getStateRoot(): Promise<string> {
    return this.rpc<string>("brrq_getStateRoot");
  }

  // ──────────────────────────────────────────────────────────────────
  // Merkle proofs
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get a Merkle proof for an account.
   *
   * JSON-RPC: `brrq_getAccountProof`
   *
   * @param address - Account address (hex with 0x prefix)
   * @returns Raw proof object, or null
   */
  async getAccountProof(address: string): Promise<Record<string, unknown> | null> {
    return this.rpc<Record<string, unknown> | null>("brrq_getAccountProof", [address]);
  }

  /**
   * Get a Merkle proof for a storage slot.
   *
   * JSON-RPC: `brrq_getStorageProof`
   *
   * @param address - Contract address (hex with 0x prefix)
   * @param key - Storage key (hex with 0x prefix)
   * @returns Raw proof object, or null
   */
  async getStorageProof(address: string, key: string): Promise<Record<string, unknown> | null> {
    return this.rpc<Record<string, unknown> | null>("brrq_getStorageProof", [address, key]);
  }

  // ──────────────────────────────────────────────────────────────────
  // Logs
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get event logs matching a filter.
   *
   * JSON-RPC: `brrq_getLogs`
   *
   * @param filter - Log filter object (address, topics, block range, etc.)
   * @returns Array of log objects
   */
  async getLogs(filter: Record<string, unknown>): Promise<Record<string, unknown>[]> {
    return this.rpc<Record<string, unknown>[]>("brrq_getLogs", [filter]) ?? [];
  }

  // ──────────────────────────────────────────────────────────────────
  // Bridge operations
  // ──────────────────────────────────────────────────────────────────

  /**
   * Initiate a bridge deposit (BTC -> brqBTC).
   *
   * JSON-RPC: `brrq_bridgeDeposit`
   *
   * @param params - Deposit parameters
   * @returns Deposit transaction hash
   */
  async bridgeDeposit(params: {
    btcTxId: string;
    vout: number;
    amount: bigint;
    recipient: string;
    confirmations?: number;
  }): Promise<string> {
    return this.rpc<string>("brrq_bridgeDeposit", [{
      btc_tx_id: params.btcTxId,
      vout: params.vout,
      amount: params.amount.toString(),
      recipient: params.recipient,
      confirmations: params.confirmations,
    }]);
  }

  /**
   * Initiate a bridge withdrawal (brqBTC -> BTC).
   *
   * JSON-RPC: `brrq_bridgeWithdraw`
   *
   * @param params - Withdrawal parameters
   * @returns Withdrawal ID
   */
  async bridgeWithdraw(params: {
    sender: string;
    amount: bigint;
    btcDestination: string;
  }): Promise<string> {
    return this.rpc<string>("brrq_bridgeWithdraw", [{
      sender: params.sender,
      amount: params.amount.toString(),
      btc_destination: params.btcDestination,
    }]);
  }

  /**
   * Verify that a withdrawal has been completed on the Bitcoin side.
   *
   * JSON-RPC: `brrq_bridgeVerifyWithdrawal`
   *
   * @param withdrawalId - The withdrawal ID to verify
   * @returns Whether the withdrawal is verified
   */
  async bridgeVerifyWithdrawal(withdrawalId: string): Promise<boolean> {
    const raw = await this.rpc<Record<string, unknown>>("brrq_bridgeVerifyWithdrawal", [{ withdrawal_id: withdrawalId }]);
    return (raw.verified as boolean) ?? false;
  }

  /**
   * Complete a verified withdrawal.
   *
   * JSON-RPC: `brrq_bridgeCompleteWithdrawal`
   *
   * @param withdrawalId - The withdrawal ID to complete
   * @returns Completion transaction hash
   */
  async bridgeCompleteWithdrawal(withdrawalId: string): Promise<string> {
    return this.rpc<string>("brrq_bridgeCompleteWithdrawal", [{ withdrawal_id: withdrawalId }]);
  }

  /**
   * Initiate a permissionless withdrawal (BitVM2 path).
   *
   * JSON-RPC: `brrq_permissionlessWithdraw`
   *
   * @param params - Withdrawal parameters
   * @returns Withdrawal transaction hash
   */
  async permissionlessWithdraw(params: Record<string, unknown>): Promise<string> {
    return this.rpc<string>("brrq_permissionlessWithdraw", [params]);
  }

  // ──────────────────────────────────────────────────────────────────
  // Proofs (extended)
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get a specific proof by its hash.
   *
   * JSON-RPC: `brrq_getProof`
   *
   * @param proofHash - Proof hash (hex)
   * @returns Batch proof or null
   */
  async getProof(proofHash: string): Promise<BatchProof | null> {
    const raw = await this.rpc<Record<string, unknown> | null>("brrq_getProof", [proofHash]);
    if (!raw) return null;
    return {
      blockRangeStart: (raw.block_range_start as number) ?? 0,
      blockRangeEnd: (raw.block_range_end as number) ?? 0,
      verified: (raw.verified as boolean) ?? false,
    };
  }

  /**
   * Get the total number of proofs generated.
   *
   * JSON-RPC: `brrq_getProofCount`
   *
   * @returns Proof count
   */
  async getProofCount(): Promise<number> {
    return this.rpc<number>("brrq_getProofCount");
  }

  /**
   * Get all proofs.
   *
   * JSON-RPC: `brrq_getProofs`
   *
   * @returns Array of batch proofs
   */
  async getProofs(): Promise<BatchProof[]> {
    const raw = await this.rpc<Record<string, unknown>[]>("brrq_getProofs");
    return (raw ?? []).map((r) => ({
      blockRangeStart: (r.block_range_start as number) ?? 0,
      blockRangeEnd: (r.block_range_end as number) ?? 0,
      verified: (r.verified as boolean) ?? false,
    }));
  }

  /**
   * Get the proof that covers a specific block height.
   *
   * JSON-RPC: `brrq_getProofByHeight`
   *
   * @param height - Block height
   * @returns Batch proof or null
   */
  async getProofByHeight(height: number): Promise<BatchProof | null> {
    const raw = await this.rpc<Record<string, unknown> | null>("brrq_getProofByHeight", [height]);
    if (!raw) return null;
    return {
      blockRangeStart: (raw.block_range_start as number) ?? 0,
      blockRangeEnd: (raw.block_range_end as number) ?? 0,
      verified: (raw.verified as boolean) ?? false,
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // MEV protection
  // ──────────────────────────────────────────────────────────────────

  /**
   * Submit a MEV-protected transaction via commit-reveal.
   *
   * JSON-RPC: `brrq_submitMevTransaction`
   *
   * @param params - MEV transaction parameters
   * @returns Transaction hash
   */
  async submitMevTransaction(params: Record<string, unknown>): Promise<string> {
    return this.rpc<string>("brrq_submitMevTransaction", [params]);
  }

  /**
   * Get the current MEV protection status.
   *
   * JSON-RPC: `brrq_getMevStatus`
   *
   * @returns MEV status
   */
  async getMevStatus(): Promise<MevStatus> {
    const raw = await this.rpc<Record<string, unknown>>("brrq_getMevStatus");
    return {
      mode: (raw.mode as string) ?? "disabled",
      phase: (raw.phase as string) ?? "unknown",
      pendingCount: (raw.pending_count as number) ?? 0,
      byteUsage: (raw.byte_usage as number) ?? 0,
    };
  }

  /**
   * Get the current epoch encryption key for MEV commit-reveal.
   *
   * JSON-RPC: `brrq_getMevEpochKey`
   *
   * @returns Epoch key (hex)
   */
  async getMevEpochKey(): Promise<string> {
    return this.rpc<string>("brrq_getMevEpochKey");
  }

  // ──────────────────────────────────────────────────────────────────
  // Governance
  // ──────────────────────────────────────────────────────────────────

  /**
   * Submit a governance proposal.
   *
   * JSON-RPC: `brrq_submitProposal`
   *
   * @param params - Proposal parameters
   * @returns Proposal ID
   */
  async submitProposal(params: {
    proposer: string;
    proposalType: string;
    params: Record<string, unknown>;
  }): Promise<number> {
    return this.rpc<number>("brrq_submitProposal", [{
      proposer: params.proposer,
      proposal_type: params.proposalType,
      params: params.params,
    }]);
  }

  /**
   * Vote on a governance proposal.
   *
   * JSON-RPC: `brrq_voteOnProposal`
   *
   * @param params - Vote parameters
   * @returns Whether the vote was accepted
   */
  async voteOnProposal(params: {
    proposalId: number;
    voter: string;
    vote: "Yes" | "No" | "Abstain";
    chamber?: string;
  }): Promise<boolean> {
    return this.rpc<boolean>("brrq_voteOnProposal", [{
      proposal_id: params.proposalId,
      voter: params.voter,
      vote: params.vote,
      chamber: params.chamber,
    }]);
  }

  /**
   * Get all governance proposals.
   *
   * JSON-RPC: `brrq_getProposals`
   *
   * @returns Array of proposals
   */
  async getProposals(): Promise<GovernanceProposal[]> {
    const raw = await this.rpc<Record<string, unknown>[]>("brrq_getProposals");
    return (raw ?? []).map((r) => ({
      id: (r.id as number) ?? 0,
      proposer: (r.proposer as string) ?? "",
      proposalType: (r.proposal_type as string) ?? "",
      status: (r.status as string) ?? "",
      yesVotes: (r.yes_votes as number) ?? 0,
      noVotes: (r.no_votes as number) ?? 0,
      abstainVotes: (r.abstain_votes as number) ?? 0,
      createdAt: (r.created_at as number) ?? 0,
    }));
  }

  /**
   * Get governance statistics.
   *
   * JSON-RPC: `brrq_getGovernanceStats`
   *
   * @returns Governance stats
   */
  async getGovernanceStats(): Promise<GovernanceStats> {
    const raw = await this.rpc<Record<string, unknown>>("brrq_getGovernanceStats");
    return {
      totalProposals: (raw.total_proposals as number) ?? 0,
      activeProposals: (raw.active_proposals as number) ?? 0,
      passedProposals: (raw.passed_proposals as number) ?? 0,
      rejectedProposals: (raw.rejected_proposals as number) ?? 0,
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // Sequencer registration
  // ──────────────────────────────────────────────────────────────────

  /**
   * Register a new sequencer.
   *
   * JSON-RPC: `brrq_registerSequencer`
   *
   * @param params - Sequencer registration parameters
   * @returns Whether registration succeeded
   */
  async registerSequencer(params: {
    address: string;
    selfStake: bigint;
    region: string;
    commissionBp: number;
  }): Promise<boolean> {
    return this.rpc<boolean>("brrq_registerSequencer", [{
      address: params.address,
      self_stake: params.selfStake.toString(),
      region: params.region,
      commission_bp: params.commissionBp,
    }]);
  }

  /**
   * Get the list of registered sequencers.
   *
   * JSON-RPC: `brrq_getSequencers`
   *
   * @returns Array of sequencer info
   */
  async getSequencers(): Promise<SequencerInfo[]> {
    const raw = await this.rpc<Record<string, unknown>[]>("brrq_getSequencers");
    return (raw ?? []).map((r) => ({
      address: (r.address as string) ?? "",
      selfStake: BigInt((r.self_stake as number | string) ?? 0),
      totalStake: BigInt((r.total_stake as number | string) ?? 0),
      region: (r.region as string) ?? "",
      commissionBp: (r.commission_bp as number) ?? 0,
      status: (r.status as string) ?? "",
    }));
  }

  /**
   * Delegate stake to a sequencer.
   *
   * JSON-RPC: `brrq_delegateStake`
   *
   * @param delegator - Delegator address
   * @param sequencer - Sequencer address
   * @param amount - Amount to delegate in satoshis
   * @returns Whether delegation succeeded
   */
  async delegateStake(delegator: string, sequencer: string, amount: bigint): Promise<boolean> {
    return this.rpc<boolean>("brrq_delegateStake", [{
      delegator, sequencer, amount: amount.toString(),
    }]);
  }

  /**
   * Undelegate stake from a sequencer.
   *
   * JSON-RPC: `brrq_undelegateStake`
   *
   * @param delegator - Delegator address
   * @param sequencer - Sequencer address
   * @param amount - Amount to undelegate in satoshis
   * @returns Whether undelegation succeeded
   */
  async undelegateStake(delegator: string, sequencer: string, amount: bigint): Promise<boolean> {
    return this.rpc<boolean>("brrq_undelegateStake", [{
      delegator, sequencer, amount: amount.toString(),
    }]);
  }

  // ──────────────────────────────────────────────────────────────────
  // Prover pools
  // ──────────────────────────────────────────────────────────────────

  /**
   * Create a new prover pool.
   *
   * JSON-RPC: `brrq_createProverPool`
   *
   * @param params - Pool creation parameters
   * @returns Pool ID
   */
  async createProverPool(params: Record<string, unknown>): Promise<string> {
    return this.rpc<string>("brrq_createProverPool", [params]);
  }

  /**
   * Join an existing prover pool.
   *
   * JSON-RPC: `brrq_joinProverPool`
   *
   * @param poolId - Pool ID to join
   * @param address - Prover address
   * @returns Whether join succeeded
   */
  async joinProverPool(poolId: string, address: string): Promise<boolean> {
    return this.rpc<boolean>("brrq_joinProverPool", [{ pool_id: poolId, address }]);
  }

  /**
   * Get all prover pools.
   *
   * JSON-RPC: `brrq_getProverPools`
   *
   * @returns Array of prover pool objects
   */
  async getProverPools(): Promise<Record<string, unknown>[]> {
    return this.rpc<Record<string, unknown>[]>("brrq_getProverPools") ?? [];
  }

  // ──────────────────────────────────────────────────────────────────
  // Faucet
  // ──────────────────────────────────────────────────────────────────

  /**
   * Request testnet tokens from the faucet.
   *
   * JSON-RPC: `brrq_faucetDrip`
   *
   * @param address - Recipient address
   * @returns Faucet transaction hash
   */
  async faucetDrip(address: string): Promise<string> {
    return this.rpc<string>("brrq_faucetDrip", [address]);
  }

  // ──────────────────────────────────────────────────────────────────
  // Challenges
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get all active bridge challenges.
   *
   * JSON-RPC: `brrq_getChallenges`
   *
   * @returns Array of challenge objects
   */
  async getChallenges(): Promise<Record<string, unknown>[]> {
    return this.rpc<Record<string, unknown>[]>("brrq_getChallenges") ?? [];
  }

  /**
   * Submit a bridge challenge (BitVM2 dispute).
   *
   * JSON-RPC: `brrq_submitChallenge`
   *
   * @param params - Challenge parameters
   * @returns Challenge ID
   */
  async submitChallenge(params: {
    challenger: string;
    challengeType: string;
    params: Record<string, unknown>;
  }): Promise<string> {
    return this.rpc<string>("brrq_submitChallenge", [{
      challenger: params.challenger,
      challenge_type: params.challengeType,
      params: params.params,
    }]);
  }

  // ──────────────────────────────────────────────────────────────────
  // Portal (L3) — Escrow Locks & Payments
  // ──────────────────────────────────────────────────────────────────

  /**
   * Get a Portal lock by its ID.
   *
   * @param lockId - Lock identifier (hex string)
   * @returns The Portal lock details
   *
   * @example
   * ```ts
   * const lock = await client.getPortalLock("abcd1234...");
   * console.log(lock.status, lock.amount);
   * ```
   */
  async getPortalLock(lockId: string): Promise<import("./types.js").PortalLock> {
    return this.rpc("brrq_getPortalLock", [lockId]);
  }

  /**
   * Check if a nullifier has been consumed (double-spend check).
   *
   * @param nullifier - Nullifier hash (hex string)
   * @returns Whether the nullifier has been consumed
   *
   * @example
   * ```ts
   * const status = await client.checkNullifier("99b2...e41c");
   * if (status.consumed) console.log("Already spent!");
   * ```
   */
  async checkNullifier(nullifier: string): Promise<import("./types.js").NullifierStatus> {
    return this.rpc("brrq_checkNullifier", [nullifier]);
  }

  /**
   * Get Portal protocol statistics.
   *
   * @returns Active locks count, total escrowed amount, nullifiers consumed
   *
   * @example
   * ```ts
   * const stats = await client.getPortalStats();
   * console.log(`${stats.active_locks} active locks, ${stats.total_escrowed} sats escrowed`);
   * ```
   */
  async getPortalStats(): Promise<import("./types.js").PortalStats> {
    return this.rpc("brrq_getPortalStats", []);
  }

  /**
   * Get a Portal lock via REST API.
   *
   * @param lockId - Lock identifier (hex string)
   */
  async getPortalLockRest(lockId: string): Promise<import("./types.js").PortalLock> {
    return this.rest(`/portal/locks/${lockId}`);
  }

  /**
   * Check nullifier status via REST API.
   *
   * @param nullifier - Nullifier hash (hex string)
   */
  async checkNullifierRest(nullifier: string): Promise<import("./types.js").NullifierStatus> {
    return this.rest(`/portal/nullifiers/${nullifier}`);
  }

  /**
   * Get Portal stats via REST API.
   */
  async getPortalStatsRest(): Promise<import("./types.js").PortalStats> {
    return this.rest("/portal/stats");
  }

  // ──────────────────────────────────────────────────────────────────
  // Internal helpers
  // ──────────────────────────────────────────────────────────────────

  /**
   * Parse a raw JSON block object into a typed Block.
   */
  private parseBlock(raw: Record<string, unknown>): Block {
    return {
      height: (raw.height as number) ?? 0,
      hash: (raw.hash as string) ?? "",
      parentHash: (raw.parent_hash as string) ?? "",
      timestamp: (raw.timestamp as number) ?? 0,
      txCount: (raw.tx_count as number) ?? 0,
      gasUsed: (raw.gas_used as number) ?? 0,
      gasLimit: (raw.gas_limit as number) ?? 0,
      stateRoot: (raw.state_root as string) ?? "",
      sequencer: (raw.sequencer as string) ?? "",
      epoch: (raw.epoch as number) ?? 0,
    };
  }
}
