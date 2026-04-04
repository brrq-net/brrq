/**
 * Brrq TypeScript SDK — Utility Functions
 *
 * Hex encoding/decoding, satoshi formatting, address validation, etc.
 */

import { HexDecodeError, InvalidAddressError } from "./errors.js";

// ────────────────────────────────────────────────────────────────────
// Hex <-> Bytes
// ────────────────────────────────────────────────────────────────────

/**
 * Convert a hex string to a Uint8Array.
 * Accepts optional "0x" prefix.
 *
 * @param hex - Hex-encoded string (with or without 0x prefix)
 * @returns Decoded byte array
 * @throws {HexDecodeError} If the string length is odd or contains non-hex characters
 */
export function hexToBytes(hex: string): Uint8Array {
  const cleaned = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (cleaned.length % 2 !== 0) {
    throw new HexDecodeError("odd_length", cleaned);
  }
  if (!/^[0-9a-fA-F]*$/.test(cleaned)) {
    throw new HexDecodeError("invalid_chars", cleaned);
  }
  const bytes = new Uint8Array(cleaned.length / 2);
  for (let i = 0; i < cleaned.length; i += 2) {
    bytes[i / 2] = parseInt(cleaned.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Convert a Uint8Array to a hex string (lowercase, no prefix).
 *
 * @param bytes - Byte array to encode
 * @returns Hex-encoded string without 0x prefix
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ────────────────────────────────────────────────────────────────────
// Satoshi formatting
// ────────────────────────────────────────────────────────────────────

/** One BTC expressed in satoshis. */
const SATS_PER_BTC = 100_000_000n;

/**
 * Format a satoshi amount as a human-readable BTC string.
 *
 * Examples:
 *   formatSatoshis(100000000n) → "1.00000000"
 *   formatSatoshis(50000n)     → "0.00050000"
 *   formatSatoshis(0n)         → "0.00000000"
 *
 * @param sats - Amount in satoshis (bigint)
 * @returns BTC-formatted string with 8 decimal places
 */
export function formatSatoshis(sats: bigint): string {
  const negative = sats < 0n;
  const absSats = negative ? -sats : sats;
  const whole = absSats / SATS_PER_BTC;
  const frac = absSats % SATS_PER_BTC;
  const fracStr = frac.toString().padStart(8, "0");
  return `${negative ? "-" : ""}${whole}.${fracStr}`;
}

// ────────────────────────────────────────────────────────────────────
// Hash display
// ────────────────────────────────────────────────────────────────────

/**
 * Shorten a hex hash for display purposes.
 *
 * Examples:
 *   shortenHash("0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
 *   → "0xabcd...7890"
 *
 * @param hash - Full hash string
 * @param chars - Number of characters to show on each side (default 4)
 * @returns Shortened hash string
 */
export function shortenHash(hash: string, chars: number = 4): string {
  if (hash.length <= chars * 2 + 5) {
    return hash;
  }
  const prefix = hash.startsWith("0x") ? "0x" : "";
  const clean = hash.startsWith("0x") ? hash.slice(2) : hash;
  return `${prefix}${clean.slice(0, chars)}...${clean.slice(-chars)}`;
}

// ────────────────────────────────────────────────────────────────────
// Address validation
// ────────────────────────────────────────────────────────────────────

/**
 * Validate a Brrq address string.
 *
 * A valid Brrq address is exactly 20 bytes (40 hex chars), optionally
 * prefixed with "0x". The address "brrq:..." format is also accepted
 * (used by the Rust Address::to_brrq_hex() method).
 *
 * @param address - Address string to validate
 * @returns true if the address is a valid 20-byte hex string
 */
export function isValidAddress(address: string): boolean {
  let hex: string;
  if (address.startsWith("brrq:")) {
    hex = address.slice(5);
  } else if (address.startsWith("0x")) {
    hex = address.slice(2);
  } else {
    hex = address;
  }
  if (hex.length !== 40) {
    return false;
  }
  return /^[0-9a-fA-F]{40}$/.test(hex);
}

/**
 * Normalize an address to lowercase hex with 0x prefix.
 *
 * Accepts "0x...", "brrq:...", or raw hex.
 *
 * @param address - Address in any supported format
 * @returns Normalized address with 0x prefix, lowercase
 * @throws If the address is invalid
 */
export function normalizeAddress(address: string): string {
  if (!isValidAddress(address)) {
    throw new InvalidAddressError(address);
  }
  let hex: string;
  if (address.startsWith("brrq:")) {
    hex = address.slice(5);
  } else if (address.startsWith("0x")) {
    hex = address.slice(2);
  } else {
    hex = address;
  }
  return `0x${hex.toLowerCase()}`;
}

/**
 * Sleep for a specified number of milliseconds.
 * Useful for retry delays and polling.
 *
 * @param ms - Milliseconds to sleep
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ────────────────────────────────────────────────────────────────────
// Domain separation tags
// ────────────────────────────────────────────────────────────────────

const encoder = new TextEncoder();

/**
 * Domain separation tags matching Rust `brrq_crypto::domain_tags`.
 * These MUST be kept in sync with the Rust definitions.
 */
export const DOMAIN_TAGS = {
  ADDR_V1: encoder.encode("BRRQ_ADDR_V1"),
  TX_BODY_V1: encoder.encode("BRRQ_TX_BODY_V1"),
  TX_FULL_V1: encoder.encode("BRRQ_TX_FULL_V1"),
  TX_LIGHT_V1: encoder.encode("BRRQ_TX_LIGHT_V1"),
  ACCOUNT_V1: encoder.encode("BRRQ_ACCOUNT_V1"),
} as const;
