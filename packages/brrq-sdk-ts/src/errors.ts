/**
 * Brrq TypeScript SDK — Typed Error Classes
 *
 * Replaces string-based error messages with structured, catchable error types.
 * Each error class carries domain-specific metadata for programmatic handling.
 */

// ────────────────────────────────────────────────────────────────────
// Base
// ────────────────────────────────────────────────────────────────────

/** Base class for all Brrq SDK errors. */
export class BrrqError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrrqError";
  }
}

// ────────────────────────────────────────────────────────────────────
// Hex / Encoding
// ────────────────────────────────────────────────────────────────────

/** Thrown when a hex string is malformed (odd length, non-hex chars). */
export class HexDecodeError extends BrrqError {
  constructor(
    public readonly reason: "odd_length" | "invalid_chars",
    public readonly input: string,
  ) {
    const msg =
      reason === "odd_length"
        ? `Hex string must have even length, got ${input.length}`
        : "Hex string contains non-hex characters";
    super(msg);
    this.name = "HexDecodeError";
  }
}

// ────────────────────────────────────────────────────────────────────
// Address
// ────────────────────────────────────────────────────────────────────

/** Thrown when an address fails validation. */
export class InvalidAddressError extends BrrqError {
  constructor(public readonly address: string) {
    super(`Invalid Brrq address: ${address}`);
    this.name = "InvalidAddressError";
  }
}

// ────────────────────────────────────────────────────────────────────
// Wallet
// ────────────────────────────────────────────────────────────────────

/** Thrown when the wallet secret key is invalid. */
export class InvalidSecretKeyError extends BrrqError {
  constructor(
    public readonly reason: "wrong_length" | "out_of_range",
    detail?: string,
  ) {
    const msg =
      reason === "wrong_length"
        ? `Secret key must be 32 bytes${detail ? `, got ${detail}` : ""}`
        : "Secret key is not a valid secp256k1 scalar";
    super(msg);
    this.name = "InvalidSecretKeyError";
  }
}

/** Thrown when trying to use a destroyed wallet. */
export class WalletDestroyedError extends BrrqError {
  constructor() {
    super("Wallet has been destroyed. Private key material has been cleared.");
    this.name = "WalletDestroyedError";
  }
}

/** Thrown when a transfer recipient address is invalid. */
export class InvalidRecipientError extends BrrqError {
  constructor(public readonly address: string) {
    super(
      `Invalid recipient address: expected 0x + 40 hex chars, got "${address}"`,
    );
    this.name = "InvalidRecipientError";
  }
}

/** Thrown when a transfer amount is negative. */
export class NegativeAmountError extends BrrqError {
  constructor() {
    super("Transfer amount must be non-negative");
    this.name = "NegativeAmountError";
  }
}

// ────────────────────────────────────────────────────────────────────
// RPC / REST (re-exported from client.ts for back-compat)
// ────────────────────────────────────────────────────────────────────

/** Thrown when a JSON-RPC call returns an error response. */
export class RpcError extends BrrqError {
  constructor(
    public readonly code: number,
    message: string,
    public readonly data?: unknown,
  ) {
    super(message);
    this.name = "RpcError";
  }
}

/** Thrown when a REST API request fails. */
export class RestError extends BrrqError {
  constructor(
    public readonly statusCode: number,
    public readonly statusText: string,
  ) {
    super(`REST ${statusCode}: ${statusText}`);
    this.name = "RestError";
  }
}

/** Thrown when a request times out. */
export class TimeoutError extends BrrqError {
  constructor(
    public readonly timeoutMs: number,
    public readonly requestType: "rpc" | "rest",
  ) {
    super(`${requestType.toUpperCase()} request timed out after ${timeoutMs}ms`);
    this.name = "TimeoutError";
  }
}

// ────────────────────────────────────────────────────────────────────
// Portal / Payment URI
// ────────────────────────────────────────────────────────────────────

/** Thrown when a brrq://pay URI is malformed. */
export class PaymentUriError extends BrrqError {
  constructor(
    public readonly reason: string,
  ) {
    super(reason);
    this.name = "PaymentUriError";
  }
}

/** Thrown when a merchant secret does not match the expected condition hash. */
export class ConditionHashMismatchError extends BrrqError {
  constructor(
    public readonly expected: string,
    public readonly actual: string,
  ) {
    super(
      `Merchant secret does not match condition hash! ` +
      `Expected ${expected}, got ${actual}. ` +
      `The merchant may be trying to give you a fake receipt.`,
    );
    this.name = "ConditionHashMismatchError";
  }
}

/** Thrown when a blind signing attack is detected. */
export class BlindSigningError extends BrrqError {
  constructor(
    public readonly field: "condition_hash" | "amount",
    public readonly displayed: string,
    public readonly signing: string,
  ) {
    super(
      `BLIND SIGNING ATTACK DETECTED: ${field} mismatch! ` +
      `Displayed: ${displayed}, Signing: ${signing}`,
    );
    this.name = "BlindSigningError";
  }
}
