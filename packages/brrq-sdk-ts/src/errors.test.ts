import { describe, it, expect } from "vitest";
import { HexDecodeError, InvalidSecretKeyError, WalletDestroyedError, InvalidAddressError, BlindSigningError } from "./errors.js";

describe("Error classes", () => {
  it("HexDecodeError has correct name", () => {
    const err = new HexDecodeError("odd_length", "abc");
    expect(err.name).toBe("HexDecodeError");
    expect(err.message).toBeTruthy();
  });

  it("InvalidSecretKeyError is throwable", () => {
    expect(() => { throw new InvalidSecretKeyError(); }).toThrow();
  });

  it("WalletDestroyedError is throwable", () => {
    expect(() => { throw new WalletDestroyedError(); }).toThrow();
  });

  it("InvalidAddressError includes address", () => {
    const err = new InvalidAddressError("0xshort");
    expect(err.message).toContain("0xshort");
  });

  it("BlindSigningError is throwable", () => {
    expect(() => { throw new BlindSigningError("mismatch"); }).toThrow("mismatch");
  });
});
