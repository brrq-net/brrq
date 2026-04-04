import { describe, it, expect } from "vitest";
import { parsePaymentUri, computeConditionHash, validateBeforeSigning, NullifierGuard, SettlementQueue } from "./portal.js";

describe("BPS-1: URI Scheme", () => {
  const cond = "ab".repeat(32);
  const validUri = `brrq://pay?v=1&chain=testnet&amount=50000&cond=0x${cond}&timeout=200000`;

  it("parses a valid URI", () => {
    const req = parsePaymentUri(validUri);
    expect(req.version).toBe(1);
    expect(req.chain).toBe("testnet");
    expect(req.amount).toBe(50000n);
  });

  it("rejects invalid scheme", () => {
    expect(() => parsePaymentUri(`http://pay?v=1&chain=testnet&amount=1&cond=0x${cond}&timeout=1`)).toThrow();
  });

  it("rejects zero amount", () => {
    expect(() => parsePaymentUri(`brrq://pay?v=1&chain=testnet&amount=0&cond=0x${cond}&timeout=1`)).toThrow();
  });

  it("rejects missing required params", () => {
    expect(() => parsePaymentUri("brrq://pay?v=1&chain=testnet")).toThrow();
  });

  it("rejects short condition hash", () => {
    expect(() => parsePaymentUri("brrq://pay?v=1&chain=testnet&amount=1&cond=0xabcd&timeout=1")).toThrow();
  });

  it("rejects javascript: callback", () => {
    expect(() => parsePaymentUri(validUri + "&callback=javascript:alert(1)")).toThrow();
  });

  it("accepts https callback", () => {
    const req = parsePaymentUri(validUri + "&callback=https://merchant.com/hook");
    expect(req.callback).toBe("https://merchant.com/hook");
  });
});

describe("Condition Hash", () => {
  it("produces hex hash with 0x prefix", () => {
    // Input must be hex-encoded bytes (merchant secret is a byte string)
    const hash = computeConditionHash("deadbeef");
    expect(hash).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it("is deterministic", () => {
    expect(computeConditionHash("aabb")).toBe(computeConditionHash("aabb"));
  });

  it("different secrets produce different hashes", () => {
    expect(computeConditionHash("aabb")).not.toBe(computeConditionHash("ccdd"));
  });
});

describe("Blind Signing Protection", () => {
  const cond = "ab".repeat(32);
  const uri = `brrq://pay?v=1&chain=testnet&amount=50000&cond=0x${cond}&timeout=200000`;

  it("passes when params match (with 0x prefix)", () => {
    expect(validateBeforeSigning(uri, `0x${cond}`, 50000n)).toBe(true);
  });

  it("throws on amount mismatch", () => {
    expect(() => validateBeforeSigning(uri, `0x${cond}`, 99999n)).toThrow("BLIND SIGNING");
  });

  it("throws on condition hash mismatch", () => {
    expect(() => validateBeforeSigning(uri, "0x" + "cd".repeat(32), 50000n)).toThrow("BLIND SIGNING");
  });
});

describe("NullifierGuard", () => {
  it("accepts first nullifier", () => {
    const guard = new NullifierGuard();
    expect(guard.tryAccept("null_1")).toBe(true);
  });

  it("rejects duplicate nullifier", () => {
    const guard = new NullifierGuard();
    guard.tryAccept("null_1");
    expect(guard.tryAccept("null_1")).toBe(false);
  });

  it("tracks settled nullifiers", () => {
    const guard = new NullifierGuard();
    guard.tryAccept("null_1");
    guard.markSettled("null_1");
    expect(guard.tryAccept("null_1")).toBe(false);
  });
});

describe("SettlementQueue", () => {
  it("adds claims within limits", () => {
    const queue = new SettlementQueue(100, 0);
    expect(queue.add({ lockId: "l1", nullifier: "n1", merchantSecret: "s", signature: "sig", amount: 1000n })).toBe(true);
  });

  it("drains batch", () => {
    const queue = new SettlementQueue(100, 0);
    queue.add({ lockId: "l1", nullifier: "n1", merchantSecret: "s", signature: "sig", amount: 1000n });
    queue.add({ lockId: "l2", nullifier: "n2", merchantSecret: "s", signature: "sig", amount: 2000n });
    const batch = queue.drain(10);
    expect(batch.length).toBe(2);
  });
});
