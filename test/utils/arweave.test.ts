import { describe, expect, it } from "vite-plus/test";
import { base64 } from "@agntn/encodings/base64";
import { getAddress, validateAddress } from "../../src/utils/arweave/index.ts";
import { arweaveVectors } from "../fixtures.ts";

const [first] = arweaveVectors;
const DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/* Sets the lowest bit of the last digit, which a canonical encoding leaves at zero. */
const strayBit = (text: string) =>
  text.slice(0, -1) + DIGITS.charAt(DIGITS.indexOf(text.slice(-1)) | 1);

describe("Arweave address", () => {
  it.each(arweaveVectors)("hashes the owner of $transaction to $address", ({ n, address }) => {
    expect(getAddress(n)).toBe(address);
    expect(getAddress({ kty: "RSA", e: "AQAB", n })).toBe(address);
  });

  it("reads only n from a whole keyfile", () => {
    const keyfile = { kty: "RSA", n: first.n, e: "AQAB", d: "secret", p: "p", q: "q" } as const;
    expect(getAddress(keyfile)).toBe(first.address);
  });

  it("keeps a 32-byte legacy owner as its own address, like the node", () => {
    const owner = base64.encode(new Uint8Array(32).fill(7), { alphabet: "url", padding: false });
    expect(getAddress(owner)).toBe(owner);
  });

  it.each([
    ["padding", `${first.n}=`],
    ["the standard alphabet", first.n.replace("-", "+")],
    ["stray bits in the last digit", strayBit(first.n)],
    ["a dangling digit", "AQABA"],
    ["an empty string", ""],
  ])("refuses a modulus with %s", (_, n) => {
    expect(() => getAddress(n)).toThrow("Arweave modulus must be unpadded base64url");
  });

  it("refuses a modulus longer than Arweave lets an owner be", () => {
    const n = base64.encode(new Uint8Array(513).fill(1), { alphabet: "url", padding: false });
    expect(() => getAddress(n)).toThrow("Arweave modulus must not exceed 512 bytes");
  });

  it("refuses a JWK that isn't RSA, without quoting its private members", () => {
    const ec = { kty: "EC", crv: "secp256k1", d: "hidden-scalar" };
    /* @ts-expect-error an EC key is wrong on purpose */
    expect(() => getAddress(ec)).toThrow("Arweave key must be an RSA JWK or its modulus n");
    /* @ts-expect-error n missing on purpose */
    expect(() => getAddress({ kty: "RSA", d: "hidden-scalar" })).toThrow(
      "Arweave JWK must carry its modulus n",
    );
    /* @ts-expect-error an EC key is wrong on purpose */
    expect(() => getAddress(ec)).not.toThrow(/hidden/);
  });
});

describe("Arweave address validation", () => {
  it.each(arweaveVectors)("accepts $address", ({ address }) => {
    expect(validateAddress(address)).toBe(true);
  });

  it.each([
    ["42 characters", first.address.slice(1)],
    ["a checksum suffix", `${first.address}:AAAAAA`],
    ["the standard alphabet", "+".repeat(42) + "A"],
    ["stray bits in the last digit", strayBit(first.address)],
  ])("refuses %s", (_, address) => {
    expect(validateAddress(address)).toBe(false);
  });
});
