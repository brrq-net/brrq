/**
 * Brrq TypeScript SDK — WebSocket Client
 *
 * Provides real-time event subscriptions to a Brrq node over WebSocket.
 * Supports the three subscription topics defined in the Rust SubscriptionTopic enum:
 * - `newBlocks`  — emitted when a new block is produced
 * - `pendingTxs` — emitted when a transaction enters the mempool
 * - `newProofs`  — emitted when a new STARK batch proof is generated
 *
 * Includes automatic reconnection with exponential backoff.
 */

import type {
  NewBlockEvent,
  NewProofEvent,
  NodeEvent,
  PendingTransactionEvent,
  SubscriptionTopic,
} from "./types.js";
import { sleep } from "./utils.js";

/** Callback types for each event kind. */
export type EventCallbacks = {
  newBlock: (event: NewBlockEvent) => void;
  pendingTx: (event: PendingTransactionEvent) => void;
  newProof: (event: NewProofEvent) => void;
  connected: () => void;
  disconnected: (reason: string) => void;
  error: (error: Error) => void;
};

/** Extract one callback type by name. */
type EventCallback<K extends keyof EventCallbacks> = EventCallbacks[K];

/**
 * WebSocket client for real-time Brrq node events.
 *
 * @example
 * ```ts
 * const ws = new BrrqWebSocket("ws://localhost:8545/ws");
 * ws.on("newBlock", (block) => console.log("New block:", block.height));
 * ws.on("pendingTx", (tx) => console.log("Pending:", tx.hash));
 * await ws.connect();
 * ws.subscribe(["newBlocks", "pendingTxs"]);
 * ```
 */
export class BrrqWebSocket {
  /** WebSocket URL. */
  private readonly wsUrl: string;
  /** Underlying WebSocket instance. */
  private ws: WebSocket | null = null;
  /** Event listeners. */
  private listeners: { [K in keyof EventCallbacks]?: EventCallback<K>[] } = {};
  /** Topics to subscribe to on (re)connect. */
  private topics: SubscriptionTopic[] = [];
  /** Whether the client has been intentionally closed. */
  private closed = false;
  /** Current reconnection attempt number. */
  private reconnectAttempt = 0;
  /** Maximum reconnection attempts before giving up (0 = unlimited). */
  private maxReconnectAttempts: number;
  /** Base delay for exponential backoff in ms. */
  private reconnectBaseDelay: number;
  /** Maximum allowed message size in bytes (default: 1 MB). */
  private maxMessageSize: number;

  /**
   * Create a new BrrqWebSocket.
   *
   * @param wsUrl - WebSocket URL (e.g. "ws://localhost:8545/ws")
   * @param options - Optional configuration
   */
  constructor(
    wsUrl: string,
    options?: {
      maxReconnectAttempts?: number;
      reconnectBaseDelay?: number;
      maxMessageSize?: number;
    },
  ) {
    this.wsUrl = wsUrl;
    this.maxReconnectAttempts = options?.maxReconnectAttempts ?? 10;
    this.reconnectBaseDelay = options?.reconnectBaseDelay ?? 1000;
    this.maxMessageSize = options?.maxMessageSize ?? 1_048_576; // 1 MB
  }

  /**
   * Connect to the WebSocket server.
   *
   * Resolves when the connection is established.
   * If topics were previously set via subscribe(), they are
   * automatically re-subscribed on connect.
   *
   * @returns Promise that resolves once connected
   */
  connect(): Promise<void> {
    this.closed = false;
    return new Promise<void>((resolve, reject) => {
      let settled = false;

      try {
        this.ws = new WebSocket(this.wsUrl);
      } catch (err) {
        reject(err);
        return;
      }

      this.ws.onopen = () => {
        settled = true;
        this.reconnectAttempt = 0;
        this.emit("connected");
        // Re-subscribe to topics if any were set before connect
        if (this.topics.length > 0) {
          this.sendSubscribe(this.topics);
        }
        resolve();
      };

      this.ws.onmessage = (event: MessageEvent) => {
        this.handleMessage(event.data as string);
      };

      this.ws.onclose = (event: CloseEvent) => {
        const reason = event.reason || `code ${event.code}`;
        if (!settled) {
          settled = true;
          reject(new Error(`Connection closed before open: ${reason}`));
          return;
        }
        this.emit("disconnected", reason);
        if (!this.closed) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = () => {
        const error = new Error(`WebSocket error connecting to ${this.wsUrl}`);
        if (!settled) {
          settled = true;
          reject(error);
          return;
        }
        this.emit("error", error);
        // onclose will fire after onerror — reconnection handled there
      };
    });
  }

  /**
   * Subscribe to one or more event topics.
   *
   * If already connected, sends the subscribe message immediately.
   * The topics are remembered and re-sent on reconnection.
   *
   * @param topics - Array of subscription topics
   */
  subscribe(topics: SubscriptionTopic[]): void {
    this.topics = [...new Set([...this.topics, ...topics])];
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.sendSubscribe(this.topics);
    }
  }

  /**
   * Unsubscribe from specific topics.
   *
   * Removes the topics from the tracked list and re-sends the
   * subscription with the remaining topics.
   *
   * @param topics - Topics to unsubscribe from
   */
  unsubscribe(topics: SubscriptionTopic[]): void {
    const removeSet = new Set(topics);
    this.topics = this.topics.filter((t) => !removeSet.has(t));
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.sendSubscribe(this.topics);
    }
  }

  /**
   * Register an event listener.
   *
   * Supported events:
   * - `newBlock` — fired when a new block is produced
   * - `pendingTx` — fired when a transaction enters the mempool
   * - `newProof` — fired when a STARK proof is generated
   * - `connected` — fired when the WebSocket connects
   * - `disconnected` — fired when the WebSocket disconnects
   * - `error` — fired on WebSocket errors
   *
   * @param event - Event name
   * @param callback - Handler function
   */
  on<K extends keyof EventCallbacks>(
    event: K,
    callback: EventCallback<K>,
  ): void {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    (this.listeners[event] as EventCallback<K>[]).push(callback);
  }

  /**
   * Remove an event listener.
   *
   * @param event - Event name
   * @param callback - The same function reference passed to on()
   */
  off<K extends keyof EventCallbacks>(
    event: K,
    callback: EventCallback<K>,
  ): void {
    const list = this.listeners[event] as EventCallback<K>[] | undefined;
    if (!list) return;
    const idx = list.indexOf(callback);
    if (idx !== -1) {
      list.splice(idx, 1);
    }
  }

  /**
   * Close the WebSocket connection.
   * Prevents automatic reconnection.
   */
  close(): void {
    this.closed = true;
    if (this.ws) {
      this.ws.close(1000, "Client closed");
      this.ws = null;
    }
  }

  /**
   * Whether the WebSocket is currently connected.
   */
  get connected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }

  // ──────────────────────────────────────────────────────────────────
  // Internal
  // ──────────────────────────────────────────────────────────────────

  /** Send the subscribe command to the server. */
  private sendSubscribe(topics: SubscriptionTopic[]): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    const msg = JSON.stringify({ subscribe: topics });
    this.ws.send(msg);
  }

  /** Handle an incoming WebSocket message. */
  private handleMessage(data: string): void {
    // Reject oversized messages to prevent OOM from malicious server
    if (data.length > this.maxMessageSize) {
      return;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      return; // Ignore non-JSON messages (e.g. subscription confirmations)
    }

    // Validate the parsed message has the expected structure
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      !("type" in parsed) ||
      typeof (parsed as Record<string, unknown>).type !== "string"
    ) {
      return; // Ignore messages without a valid type field
    }

    const event = parsed as NodeEvent;
    switch (event.type) {
      case "NewBlock":
        this.emit("newBlock", event as NewBlockEvent);
        break;
      case "PendingTransaction":
        this.emit("pendingTx", event as PendingTransactionEvent);
        break;
      case "NewProof":
        this.emit("newProof", event as NewProofEvent);
        break;
    }
  }

  /** Emit an event to all registered listeners. */
  private emit<K extends keyof EventCallbacks>(
    event: K,
    ...args: Parameters<EventCallbacks[K]> extends [] ? [] : [Parameters<EventCallbacks[K]>[0]]
  ): void {
    const list = this.listeners[event] as ((...a: unknown[]) => void)[] | undefined;
    if (!list) return;
    for (const cb of list) {
      try {
        cb(...args);
      } catch {
        // Listener errors should not crash the WS client
      }
    }
  }

  /** Schedule a reconnection attempt with exponential backoff. */
  private async scheduleReconnect(): Promise<void> {
    if (this.closed) return;
    if (
      this.maxReconnectAttempts > 0 &&
      this.reconnectAttempt >= this.maxReconnectAttempts
    ) {
      this.emit(
        "error",
        new Error(
          `Max reconnection attempts (${this.maxReconnectAttempts}) reached`,
        ),
      );
      return;
    }

    this.reconnectAttempt++;
    // Exponential backoff: base * 2^(attempt-1), capped at 30s
    const delay = Math.min(
      this.reconnectBaseDelay * Math.pow(2, this.reconnectAttempt - 1),
      30_000,
    );
    await sleep(delay);

    if (this.closed) return;

    try {
      await this.connect();
    } catch {
      // connect() failed — onclose handler will trigger another attempt
    }
  }
}
