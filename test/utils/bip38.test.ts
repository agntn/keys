import { hex } from "@agntn/encodings/hex";
import { describe, expect, it } from "vite-plus/test";
import {
  BIP38PassphraseError,
  decrypt as decryptBIP38,
  inspect as inspectBIP38,
} from "../../src/utils/bip38/index.ts";
import { decodeBase58Check, encodeBase58Check } from "../../src/utils/encoding.ts";
import { decode as decodeWIF } from "../../src/utils/wif/index.ts";
import { bip38Vectors } from "../fixtures.ts";

const [nonEc, , ecMultiply, lotSequence] = bip38Vectors;

/**
 * Re-encode a spec vector with one byte changed and a valid checksum.
 * @param encrypted - BIP38 key from the fixtures
 * @param index - Byte to replace
 * @param value - New byte value
 * @returns {string} Base58Check key with the edited payload
 */
function withByte(encrypted: string, index: number, value: number): string {
  const payload = decodeBase58Check(encrypted);
  payload[index] = value;
  return encodeBase58Check(payload);
}

describe("bip38 inspect", () => {
  it.each(bip38Vectors)("reads the header of $encrypted", ({ encrypted, inspection }) => {
    expect(inspectBIP38(encrypted)).toEqual(inspection);
  });

  it.each(bip38Vectors.filter((vector) => vector.address !== undefined))(
    "matches the spec address of $encrypted",
    ({ encrypted, address, inspection }) => {
      expect(inspectBIP38(encrypted, { address })).toEqual({
        ...inspection,
        addressMatches: true,
      });
    },
  );

  it("reports an address whose hash differs", () => {
    expect(
      inspectBIP38(ecMultiply.encrypted, { address: lotSequence.address }).addressMatches,
    ).toBe(false);
  });

  it("splits lot and sequence as lotnumber * 4096 + sequencenumber", () => {
    const flagged = withByte(ecMultiply.encrypted, 2, 0x04);
    expect(inspectBIP38(flagged)).toMatchObject({
      hasLotSequence: true,
      ownerSalt: "a50dba67",
      lot: 0x72cb9,
      sequence: 0x383,
    });
  });

  it("rejects a broken checksum without echoing the key", () => {
    const broken = nonEc.encrypted.slice(0, -1) + "m";
    expect(() => inspectBIP38(broken)).toThrow("Invalid BIP38 base58 encoding or checksum");
    try {
      inspectBIP38(broken);
    } catch (error) {
      expect(String(error)).not.toContain(broken);
    }
  });

  it("rejects keys that are not BIP38", () => {
    expect(() => inspectBIP38("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn")).toThrow(
      "Invalid BIP38 payload length",
    );
    expect(() => inspectBIP38(withByte(nonEc.encrypted, 1, 0x44))).toThrow(
      "Not a BIP38 key: expected prefix 0x0142 or 0x0143",
    );
    expect(() => inspectBIP38("")).toThrow("non-empty string");
    expect(() => inspectBIP38("6P".repeat(33))).toThrow("Invalid BIP38 key length");
  });

  it.each([
    ["non-EC without the two high bits", nonEc.encrypted, 0x20],
    ["non-EC with the lot and sequence bit", nonEc.encrypted, 0xc4],
    ["non-EC with a reserved bit", nonEc.encrypted, 0xc8],
    ["EC multiply with the high bits", ecMultiply.encrypted, 0xc0],
    ["EC multiply with a reserved bit", ecMultiply.encrypted, 0x10],
  ])("rejects a flag byte for %s", (_name, encrypted, flagByte) => {
    expect(() => inspectBIP38(withByte(encrypted, 2, flagByte))).toThrow("BIP38");
  });

  it("rejects an empty address", () => {
    expect(() => inspectBIP38(nonEc.encrypted, { address: "" })).toThrow(
      "BIP38 address must be a non-empty string",
    );
  });
});

describe("bip38 decrypt", () => {
  it.each(bip38Vectors)(
    "opens $encrypted with the spec passphrase",
    ({ encrypted, passphrase, wif, address, inspection }) => {
      const decrypted = decryptBIP38(encrypted, passphrase);
      expect(decrypted.wif).toBe(wif);
      expect(hex.encode(decrypted.privateKey)).toBe(
        decodeWIF(wif, { chain: "bitcoin" }).privateKey,
      );
      expect(decrypted.compressed).toBe(inspection.compressed);
      if (address !== undefined) expect(decrypted.address).toBe(address);
      expect(inspectBIP38(encrypted, { address: decrypted.address }).addressMatches).toBe(true);
    },
    20_000,
  );

  it("normalizes the passphrase to NFC", () => {
    expect(decryptBIP38(nonEc.encrypted, nonEc.passphrase.normalize("NFC")).wif).toBe(nonEc.wif);
  }, 20_000);

  it.each([nonEc, ecMultiply, lotSequence])(
    "refuses a wrong passphrase for $encrypted without echoing it",
    ({ encrypted }) => {
      const passphrase = "not the passphrase";
      expect(() => decryptBIP38(encrypted, passphrase)).toThrow(BIP38PassphraseError);
      try {
        decryptBIP38(encrypted, passphrase);
      } catch (error) {
        expect(String(error)).not.toContain(passphrase);
        expect(String(error)).not.toContain(encrypted);
      }
    },
    20_000,
  );

  it("rejects a malformed key before any scrypt run", () => {
    expect(() => decryptBIP38(nonEc.encrypted.slice(0, -1) + "m", "x")).toThrow(
      "Invalid BIP38 base58 encoding or checksum",
    );
    expect(() => decryptBIP38(withByte(nonEc.encrypted, 2, 0xc8), "x")).toThrow("BIP38");
  });

  it("rejects a passphrase that is not a string", () => {
    // @ts-expect-error passphrase must be a string
    expect(() => decryptBIP38(nonEc.encrypted, 42)).toThrow("BIP38 passphrase must be a string");
  });
});
