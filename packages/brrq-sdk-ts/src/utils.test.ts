import { describe, it, expect } from "vitest";
import { hexToBytes, bytesToHex, formatSatoshis } from "./utils.js";

describe("hexToBytes", () => {
  it("decodes valid hex", () => {
    expect(hexToBytes("deadbeef")).toEqual(new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
  });

  it("strips 0x prefix", () => {
    expect(hexToBytes("0xabcd")).toEqual(new Uint8Array([0xab, 0xcd]));
  });

  it("throws on odd-length hex", () => {
    expect(() => hexToBytes("abc")).toThrow();
  });

  it("throws on invalid characters", () => {
    expect(() => hexToBytes("gggg")).toThrow();
  });

  it("handles empty string", () => {
    expect(hexToBytes("")).toEqual(new Uint8Array(0));
  });
});

describe("bytesToHex", () => {
  it("encodes bytes to lowercase hex", () => {
    expect(bytesToHex(new Uint8Array([0xde, 0xad]))).toBe("dead");
  });

  it("pads single-digit bytes", () => {
    expect(bytesToHex(new Uint8Array([0x01, 0x0a]))).toBe("010a");
  });
});

describe("formatSatoshis", () => {
  it("formats 100000000 as 1.00000000 BTC", () => {
    expect(formatSatoshis(100_000_000n)).toBe("1.00000000");
  });

  it("formats 1 sat", () => {
    expect(formatSatoshis(1n)).toBe("0.00000001");
  });

  it("formats 0", () => {
    expect(formatSatoshis(0n)).toBe("0.00000000");
  });
});
