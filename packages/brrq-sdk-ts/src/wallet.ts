/**
 * Brrq TypeScript SDK — Wallet
 *
 * A Schnorr (BIP-340) wallet for signing Brrq transactions.
 * Uses @noble/secp256k1 for key generation and Schnorr signing,
 * and @noble/hashes for SHA-256 address derivation.
 *
 * Address derivation matches the Rust implementation:
 *   Address = SHA-256("BRRQ_ADDR_V1" || x-only_public_key)[0..20]
 */

import { schnorr } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { bytesToHex, hexToBytes, DOMAIN_TAGS } from "./utils.js";
import type { SignedTransaction, TransferOptions } from "./types.js";
import { CHAIN_ID } from "./types.js";

/**
 * A Brrq wallet backed by a secp256k1 Schnorr keypair.
 *
 * The wallet can:
 * - Generate random keypairs
 * - Derive the Brrq address (SHA-256 with BRRQ_ADDR_V1 domain tag)
 * - Sign transfer transactions using BIP-340 Schnorr
 *
 * **Security**: Call {@link destroy} when you are finished with the wallet to
 * zeroize private key material in memory. You can also use the `using`
 * declaration (TypeScript 5.2+) which calls `destroy()` automatically:
 *
 * @example
 * ```ts
 * // Manual cleanup
 * const wallet = Wallet.generate();
 * try {
 *   const tx = wallet.transfer("0xrecipient...", 100000n, { nonce: 0 });
 *   const hash = await client.sendTransaction(tx);
 * } finally {
 *   wallet.destroy();
 * }
 *
 * // Automatic cleanup with `using` (TS 5.2+)
 * using wallet = Wallet.generate();
 * const tx = wallet.transfer("0xrecipient...", 100000n, { nonce: 0 });
 * ```
 */
export class Wallet {
  /** 32-byte secret key (zeroed on {@link destroy}). */
  private readonly secret: Uint8Array;
  /** 32-byte x-only public key (BIP-340). */
  private readonly pubkey: Uint8Array;
  /** Whether {@link destroy} has been called. */
  private _destroyed = false;

  private constructor(secret: Uint8Array) {
    if (secret.length !== 32) {
      throw new Error(`Secret key must be 32 bytes, got ${secret.length}`);
    }
    // Validate key is in valid secp256k1 range: 0 < key < curve order
    const SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
    let val = 0n;
    for (let i = 0; i < 32; i++) {
      val = (val << 8n) | BigInt(secret[i]);
    }
    if (val === 0n || val >= SECP256K1_ORDER) {
      throw new Error("Secret key is not a valid secp256k1 scalar");
    }
    this.secret = secret;
    // schnorr.getPublicKey returns the 32-byte x-only pubkey
    this.pubkey = schnorr.getPublicKey(secret);
  }

  /**
   * Generate a new random wallet.
   *
   * Uses a cryptographically secure random number generator via
   * @noble/secp256k1 utils.
   *
   * @returns A new Wallet instance with a random keypair
   */
  static generate(): Wallet {
    const secret = randomBytes(32);
    return new Wallet(secret);
  }

  /**
   * Restore a wallet from a 32-byte secret key.
   *
   * @param secret - 32-byte secret key
   * @returns A Wallet instance for the given secret
   * @throws If the secret is not exactly 32 bytes
   */
  static fromSecret(secret: Uint8Array): Wallet {
    return new Wallet(new Uint8Array(secret));
  }

  /**
   * Brrq address derived from the public key.
   *
   * Matches the Rust derivation: `SHA-256("BRRQ_ADDR_V1" || pubkey)[0..20]`
   * returned as a hex string with 0x prefix (40 hex chars).
   */
  get address(): string {
    const tagged = new Uint8Array(DOMAIN_TAGS.ADDR_V1.length + this.pubkey.length);
    tagged.set(DOMAIN_TAGS.ADDR_V1, 0);
    tagged.set(this.pubkey, DOMAIN_TAGS.ADDR_V1.length);
    const hash = sha256(tagged);
    const addrBytes = hash.slice(0, 20);
    return `0x${bytesToHex(addrBytes)}`;
  }

  /**
   * The 32-byte x-only public key as a hex string.
   */
  get publicKey(): string {
    return bytesToHex(this.pubkey);
  }

  /**
   * The 32-byte secret key as a Uint8Array.
   * Handle with care - exposure compromises the wallet.
   *
   * @throws If the wallet has been destroyed
   */
  get secretKey(): Uint8Array {
    this.assertNotDestroyed();
    return new Uint8Array(this.secret);
  }

  /**
   * Whether this wallet has been destroyed and can no longer sign.
   */
  get destroyed(): boolean {
    return this._destroyed;
  }

  /**
   * Zeroize the private key material and mark the wallet as destroyed.
   *
   * After calling this method the wallet can no longer sign transactions or
   * expose the secret key.  This is a best-effort mitigation — JavaScript
   * runtimes may still hold copies in optimised JIT buffers, but clearing
   * the authoritative `Uint8Array` removes the most accessible copy.
   */
  destroy(): void {
    this.secret.fill(0);
    this._destroyed = true;
  }

  /**
   * Supports the TC39 Explicit Resource Management proposal (`using`).
   * Automatically calls {@link destroy} when the wallet goes out of scope.
   */
  [Symbol.dispose](): void {
    this.destroy();
  }

  /**
   * Create and sign a transfer transaction.
   *
   * The signing follows the Brrq transaction body hashing scheme:
   * 1. Hash the transaction body fields with SHA-256 (matching Rust's TransactionBody::hash)
   * 2. Sign the resulting 32-byte hash with BIP-340 Schnorr
   *
   * @param to - Recipient address (hex with 0x prefix)
   * @param amount - Amount to transfer in satoshis
   * @param opts - Transaction options (nonce is required)
   * @returns A signed transaction ready for submission
   */
  transfer(
    to: string,
    amount: bigint,
    opts: TransferOptions,
  ): SignedTransaction {
    // Validate recipient address: must be 0x + 40 hex chars (20 bytes)
    const normalized = to.startsWith("0x") ? to : `0x${to}`;
    if (!/^0x[a-fA-F0-9]{40}$/.test(normalized)) {
      throw new Error(`Invalid recipient address: expected 0x + 40 hex chars, got "${to}"`);
    }
    if (amount < 0n) {
      throw new Error("Transfer amount must be non-negative");
    }

    const gasLimit = opts.gasLimit ?? 21_000;
    const gasPrice = opts.gasPrice ?? 1;
    const chainId = opts.chainId ?? CHAIN_ID.TESTNET;

    // Hash the transaction body — must match the Rust TransactionBody::hash() exactly.
    // Rust order: BRRQ_TX_BODY_V1 || from || nonce || gas_limit || gas_price || chain_id || 0x01 || to || amount
    // All integers are little-endian u64 (8 bytes).
    const bodyBytes = this.buildTransferBodyBytes(to, amount, opts.nonce, gasLimit, gasPrice, chainId);
    const bodyHash = sha256(bodyBytes);

    // BIP-340 Schnorr sign the body hash
    const sig = this.sign(bodyHash);

    return {
      from: this.address,
      to: normalized,
      amount,
      kind: "transfer",
      nonce: opts.nonce,
      gasLimit,
      gasPrice,
      chainId,
      signature: bytesToHex(sig),
      publicKey: this.publicKey,
    };
  }

  // ──────────────────────────────────────────────────────────────────
  // Private helpers
  // ──────────────────────────────────────────────────────────────────

  /**
   * Build the byte representation of a transfer transaction body.
   * Mirrors the Rust TransactionBody::hash() hashing order exactly:
   *   BRRQ_TX_BODY_V1(15) || from(20) || nonce(8 LE) || gas_limit(8 LE) || gas_price(8 LE) || chain_id(8 LE) || 0x01 || to(20) || amount(8 LE)
   */
  private buildTransferBodyBytes(
    to: string,
    amount: bigint,
    nonce: number,
    gasLimit: number,
    gasPrice: number,
    chainId: number,
  ): Uint8Array {
    const tag = DOMAIN_TAGS.TX_BODY_V1;
    const fromBytes = hexToBytes(this.address);   // 20 bytes (strips 0x)
    const toBytes = hexToBytes(to);                // 20 bytes (strips 0x)

    // Total: 15 + 20 + 8 + 8 + 8 + 8 + 1 + 20 + 8 = 96 bytes
    const buf = new Uint8Array(tag.length + 81);
    const view = new DataView(buf.buffer);
    let offset = 0;

    // Domain tag (15 bytes)
    buf.set(tag, offset);
    offset += tag.length;

    // from (20 bytes)
    buf.set(fromBytes, offset);
    offset += 20;

    // nonce (u64 LE)
    view.setBigUint64(offset, BigInt(nonce), true);
    offset += 8;

    // gas_limit (u64 LE)
    view.setBigUint64(offset, BigInt(gasLimit), true);
    offset += 8;

    // gas_price (u64 LE)
    view.setBigUint64(offset, BigInt(gasPrice), true);
    offset += 8;

    // chain_id (u64 LE)
    view.setBigUint64(offset, BigInt(chainId), true);
    offset += 8;

    // Type tag for Transfer = 0x01
    buf[offset] = 0x01;
    offset += 1;

    // to (20 bytes)
    buf.set(toBytes, offset);
    offset += 20;

    // amount (u64 LE)
    view.setBigUint64(offset, amount, true);

    return buf;
  }

  /**
   * Throw if the wallet has already been destroyed.
   */
  private assertNotDestroyed(): void {
    if (this._destroyed) {
      throw new Error("Wallet has been destroyed. Private key material has been cleared.");
    }
  }

  /**
   * Sign arbitrary data using BIP-340 Schnorr.
   *
   * @param data - 32-byte message to sign
   * @returns 64-byte Schnorr signature
   * @throws If the wallet has been destroyed
   */
  private sign(data: Uint8Array): Uint8Array {
    this.assertNotDestroyed();
    return schnorr.sign(data, this.secret);
  }
}
