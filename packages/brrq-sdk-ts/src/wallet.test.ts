import { describe, it, expect } from "vitest";
import { Wallet } from "./wallet.js";

describe("Wallet", () => {
  it("generates a random wallet with valid address", () => {
    const w = Wallet.generate();
    expect(w.address).toMatch(/^0x[0-9a-f]{40}$/);
    expect(w.publicKey).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces deterministic address from same secret", () => {
    const secret = new Uint8Array(32);
    secret[31] = 1;
    const w1 = Wallet.fromSecret(secret);
    const w2 = Wallet.fromSecret(secret);
    expect(w1.address).toBe(w2.address);
    expect(w1.publicKey).toBe(w2.publicKey);
  });

  it("different secrets produce different addresses", () => {
    const s1 = new Uint8Array(32);
    s1[31] = 1;
    const s2 = new Uint8Array(32);
    s2[31] = 2;
    expect(Wallet.fromSecret(s1).address).not.toBe(Wallet.fromSecret(s2).address);
  });

  it("rejects zero secret key", () => {
    expect(() => Wallet.fromSecret(new Uint8Array(32))).toThrow("not a valid secp256k1 scalar");
  });

  it("rejects wrong-length secret key", () => {
    expect(() => Wallet.fromSecret(new Uint8Array(16))).toThrow("must be 32 bytes");
  });

  it("rejects secret key >= curve order", () => {
    const order = new Uint8Array([
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
      0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
      0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
      0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
    ]);
    expect(() => Wallet.fromSecret(order)).toThrow("not a valid secp256k1 scalar");
  });

  it("destroy zeroes secret and marks destroyed", () => {
    const w = Wallet.generate();
    expect(w.destroyed).toBe(false);
    w.destroy();
    expect(w.destroyed).toBe(true);
  });

  it("signs a transfer transaction with valid signature", () => {
    const w = Wallet.generate();
    const tx = w.transfer("0x" + "ab".repeat(20), 50000n, { nonce: 0 });
    expect(tx.signature).toMatch(/^[0-9a-f]{128}$/);
    expect(tx.publicKey).toBe(w.publicKey);
    expect(tx.kind).toBe("transfer");
  });

  it("transfer with different nonces produces different signatures", () => {
    const w = Wallet.generate();
    const to = "0x" + "cd".repeat(20);
    const tx1 = w.transfer(to, 1000n, { nonce: 0 });
    const tx2 = w.transfer(to, 1000n, { nonce: 1 });
    expect(tx1.signature).not.toBe(tx2.signature);
  });

  it("rejects invalid recipient address", () => {
    const w = Wallet.generate();
    expect(() => w.transfer("0xshort", 1000n, { nonce: 0 })).toThrow("Invalid recipient");
  });
});
