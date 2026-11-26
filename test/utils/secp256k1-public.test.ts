import { hex } from "@agntn/encodings/hex";
import { sha256 } from "@agntn/hashes";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { describe, expect, it } from "vite-plus/test";
import XRPL from "../../src/blockchains/xrpl.ts";
import { verifyMessage } from "../../src/utils/signing.ts";
import {
  readStrictDer,
  tweakPublicKey,
  verifyEcdsaDigest,
} from "../../src/utils/secp256k1/public.ts";
import { secp256k1TestVectors } from "../fixtures.ts";

const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
const digest = sha256(new TextEncoder().encode("public input"));
const low = secp256k1.Signature.fromBytes(
  secp256k1.sign(digest, hex.decode(privateKey), { prehash: false }),
);
const high = new secp256k1.Signature(low.r, secp256k1.Point.Fn.neg(low.s));
const publicKey = hex.decode(publicKeyCompressed);

/* Wraps integers in a DER sequence, padded or not as given. */
function der(...integers: readonly Uint8Array[]): Uint8Array {
  const body = integers.flatMap((value) => [0x02, value.length, ...value]);
  return Uint8Array.of(0x30, body.length, ...body);
}

describe("secp256k1 public input", () => {
  it("takes high s only when the caller allows it", () => {
    const signature = high.toBytes("compact");
    expect(verifyEcdsaDigest(signature, { digest, publicKey, lowS: false })).toBe(true);
    expect(verifyEcdsaDigest(signature, { digest, publicKey, lowS: true })).toBe(false);
  });

  it("refuses high s in a plain secp256k1 message signature", () => {
    const options = { publicKey: publicKeyCompressed, hash: false } as const;
    expect(verifyMessage(digest, { ...options, signature: hex.encode(low.toBytes()) })).toBe(true);
    expect(verifyMessage(digest, { ...options, signature: hex.encode(high.toBytes()) })).toBe(
      false,
    );
  });

  it("leaves a key as it is under a zero tweak, which BIP341 allows", () => {
    expect(tweakPublicKey(publicKey, { tweak: 0n })).toEqual(publicKey);
    const uncompressed = secp256k1.Point.fromBytes(publicKey).toBytes(false);
    expect(tweakPublicKey(publicKey, { tweak: 0n, compressed: false })).toEqual(uncompressed);
    expect(() => tweakPublicKey(publicKey, { tweak: secp256k1.Point.Fn.ORDER })).toThrow(
      RangeError,
    );
  });

  it("reads strict DER back to r and s", () => {
    expect(readStrictDer(low.toBytes("der"))).toEqual(low.toBytes("compact"));
  });

  it.each([
    ["an r padded with a zero it doesn't need", der(Uint8Array.of(0, 1), Uint8Array.of(1))],
    ["a negative s", der(Uint8Array.of(1), Uint8Array.of(0x80))],
    ["an empty r", der(new Uint8Array(), Uint8Array.of(1))],
    ["an r longer than 32 bytes", der(Uint8Array.of(1, ...new Uint8Array(32)), Uint8Array.of(1))],
    ["a byte after s inside the sequence", Uint8Array.of(0x30, 7, 2, 1, 1, 2, 1, 1, 0)],
    ["a byte after the sequence", Uint8Array.of(...der(Uint8Array.of(1), Uint8Array.of(1)), 0)],
    ["a sequence length one short", Uint8Array.of(0x30, 5, 2, 1, 1, 2, 1, 1)],
    ["a long form length", Uint8Array.of(0x30, 0x81, 6, 2, 1, 1, 2, 1, 1)],
  ])("refuses DER with %s", (_name, bytes) => {
    expect(readStrictDer(bytes)).toBeUndefined();
  });

  it("refuses an XRPL signature with high s or loose DER", () => {
    const xrpl = new XRPL();
    const message = "public input";
    const signature = xrpl.signMessage(message, { privateKey });
    const parsed = secp256k1.Signature.fromBytes(hex.decode(signature), "der");
    const flipped = new secp256k1.Signature(parsed.r, secp256k1.Point.Fn.neg(parsed.s));
    const [r = new Uint8Array(), s = new Uint8Array()] = [parsed.r, parsed.s].map((value) =>
      hex.decode(value.toString(16).padStart(64, "0")),
    );
    const padded = der(Uint8Array.of(0, 0, ...r), s);
    const verify = (candidate: string): boolean =>
      xrpl.verifyMessage(message, { signature: candidate, publicKey: publicKeyCompressed });
    expect(verify(signature)).toBe(true);
    expect(verify(hex.encode(flipped.toBytes("der")))).toBe(false);
    expect(verify(hex.encode(padded))).toBe(false);
  });
});
