import { describe, it, expect } from "vitest";
import {
  HARDENED_OFFSET,
  getMasterKeyFromSeed,
  getHDKeyFromExtended,
  deriveHDKey,
  deriveHDChild,
  hardenedIndex,
  isHardenedIndex,
  formatIndex,
} from "../../src/utils/bip32";
import { hexToBytes } from "@noble/hashes/utils.js";

describe("BIP32 Utils", () => {
  // Vector 1 from BIP32 test vectors
  const testSeed = hexToBytes("000102030405060708090a0b0c0d0e0f");
  const expectedMasterKey =
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

  it("creates a master key from seed", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);
    expect(masterKey.privateExtendedKey).toBe(expectedMasterKey);
  });

  it("creates HDKey from extended key", () => {
    const hdkey = getHDKeyFromExtended(expectedMasterKey);
    expect(hdkey.privateExtendedKey).toBe(expectedMasterKey);
  });

  it("derives child keys using path", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);

    // Test vector 1 - m/0'
    const child1 = deriveHDKey(masterKey, "m/0'");
    expect(child1.privateExtendedKey).toBe(
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    );
    expect(child1.publicExtendedKey).toBe(
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    );

    // Test vector 1 - m/0'/1
    const child2 = deriveHDKey(masterKey, "m/0'/1");
    expect(child2.privateExtendedKey).toBe(
      "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
    );
    expect(child2.publicExtendedKey).toBe(
      "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    );
  });

  it("derives child key at specific index", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);
    const hardened0 = deriveHDChild(masterKey, HARDENED_OFFSET);

    expect(hardened0.privateExtendedKey).toBe(
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    );
  });

  it("creates hardened index", () => {
    expect(hardenedIndex(0)).toBe(0x80_00_00_00);
    expect(hardenedIndex(44)).toBe(0x80_00_00_2c);
    expect(hardenedIndex(0x7f_ff_ff_ff)).toBe(0xff_ff_ff_ff);
  });

  it.each([-1, 0.5, 0x80_00_00_00, Number.NaN, Infinity, -Infinity])(
    "rejects invalid index %s before hardening",
    (index) => {
      expect(() => hardenedIndex(index)).toThrow(RangeError);
    },
  );

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
});
