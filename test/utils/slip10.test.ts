import { describe, it, expect } from "vitest";
import {
  HARDENED_OFFSET,
  getMasterKeyFromSeed,
  deriveHDKey,
  deriveHDChild,
  hardenedIndex,
  isHardenedIndex,
  formatIndex,
} from "../../src/utils/slip10";
import { hexToBytes } from "@noble/hashes/utils.js";

describe("SLIP-0010 Utils", () => {
  // Test vector from SLIP-0010 (ed25519)
  const testSeed = hexToBytes("000102030405060708090a0b0c0d0e0f");

  it("creates a master key from seed", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);
    const privateKey: Uint8Array = masterKey.privateKey;
    const derivedKey: typeof masterKey = masterKey.derive("m/0'");
    expect(Buffer.from(privateKey).toString("hex")).toBe(
      "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
    );
    expect(Buffer.from(masterKey.publicKey).toString("hex")).toBe(
      "00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed",
    );
    expect(Buffer.from(masterKey.chainCode).toString("hex")).toBe(
      "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb",
    );
    expect(derivedKey.privateKey).toBeInstanceOf(Uint8Array);
    // @ts-expect-error SLIP-10 keys must reject unknown properties.
    expect(masterKey.privKey).toBeUndefined();
  });

  it("derives child keys using path", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);

    // Test vector from SLIP-0010
    const child1 = deriveHDKey(masterKey, "m/0'");
    expect(Buffer.from(child1.privateKey).toString("hex")).toBe(
      "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
    );
    expect(Buffer.from(child1.publicKey).toString("hex")).toBe(
      "008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c",
    );

    // Test vector from SLIP-0010
    const child2 = deriveHDKey(masterKey, "m/0'/1'");
    expect(Buffer.from(child2.privateKey).toString("hex")).toBe(
      "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
    );
    expect(Buffer.from(child2.publicKey).toString("hex")).toBe(
      "001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187",
    );
  });

  it("derives child key at specific index", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);
    const hardened0 = deriveHDChild(masterKey, HARDENED_OFFSET);

    expect(Buffer.from(hardened0.privateKey).toString("hex")).toBe(
      "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
    );
  });

  it("creates hardened index", () => {
    expect(hardenedIndex(0)).toBe(0x80_00_00_00);
    expect(hardenedIndex(44)).toBe(0x80_00_00_2c);
  });

  it("checks if index is hardened", () => {
    expect(isHardenedIndex(0)).toBe(false);
    expect(isHardenedIndex(HARDENED_OFFSET)).toBe(true);
  });

  it("formats index correctly", () => {
    expect(formatIndex(0)).toBe("0");
    expect(formatIndex(44)).toBe("44");
    expect(formatIndex(HARDENED_OFFSET)).toBe("0'");
    expect(formatIndex(HARDENED_OFFSET + 44)).toBe("44'");
  });

  it("fails on non-hardened derivation with ed25519", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);

    // SLIP-0010 doesn't allow non-hardened derivation for ed25519
    expect(() => deriveHDKey(masterKey, "m/0", false)).toThrow();

    // But with forceHardened it should work by treating all indices as hardened
    const childForced = deriveHDKey(masterKey, "m/0", true);
    expect(childForced).toBeDefined();
  });
});
