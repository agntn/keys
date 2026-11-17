import { hex } from "@agntn/encodings/hex";
import { sha256 } from "@agntn/hashes";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { describe, expect, it } from "vite-plus/test";
import { recoverKnownNonce, recoverReusedNonce } from "../../src/utils/secp256k1/index.ts";
import { extractSignatures } from "../../src/utils/transaction/index.ts";
import { knownNonceVectors, reusedNonceVector, transactionVectors } from "../fixtures.ts";

const { Fn } = secp256k1.Point;
const { r, first, second } = reusedNonceVector;

/* A scalar as the 64 hex digits the recovery writes. */
const padded = (value: string): string => value.padStart(64, "0");

/* Two BIP340 signatures of one key over two messages with one nonce, built by hand. */
const schnorrPair = (
  messages: readonly Uint8Array[] = ["one", "two"].map((label) =>
    sha256(new TextEncoder().encode(label)),
  ),
): {
  publicKey: string;
  privateKey: bigint;
  signatures: { r: string; s: string; z: string }[];
} => {
  const secret = 0xc0ffee_1234n;
  const point = secp256k1.Point.BASE.multiply(secret);
  const privateKey = point.y % 2n === 0n ? secret : Fn.neg(secret);
  const publicKey = hex.encode(schnorr.getPublicKey(Fn.toBytes(privateKey)));
  const nonce = secp256k1.Point.BASE.multiply(0xbad_cafen);
  const k = nonce.y % 2n === 0n ? 0xbad_cafen : Fn.neg(0xbad_cafen);
  const rx = Fn.toBytes(nonce.x);
  const signatures = messages.map((message) => {
    const challenge = schnorr.utils.taggedHash(
      "BIP0340/challenge",
      rx,
      hex.decode(publicKey),
      message,
    );
    const e = Fn.create(BigInt(`0x${hex.encode(challenge)}`));
    const s = Fn.toBytes(Fn.add(k, Fn.mul(e, privateKey)));
    expect(schnorr.verify(Uint8Array.from([...rx, ...s]), message, hex.decode(publicKey))).toBe(
      true,
    );
    return { r: hex.encode(rx), s: hex.encode(s), z: hex.encode(message) };
  });
  return { publicKey, privateKey, signatures };
};

describe("recoverReusedNonce", () => {
  it("solves the ECDSA vector of agntn/keys#196 for d and k", () => {
    expect(
      recoverReusedNonce([
        { r, ...first },
        { r, ...second },
      ]),
    ).toEqual({
      privateKey: padded(reusedNonceVector.privateKey),
      nonce: padded(reusedNonceVector.nonce),
      publicKey: hex.encode(secp256k1.getPublicKey(Fn.toBytes(0x1234567890abcdefn))),
    });
  });

  it("takes s negated to the other half and still finds the key", () => {
    const high = Fn.toBytes(Fn.neg(BigInt(`0x${second.s}`)));
    const recovered = recoverReusedNonce([
      { r, ...first },
      { r, s: hex.encode(high), z: second.z },
    ]);
    expect(recovered.privateKey).toBe(padded(reusedNonceVector.privateKey));
  });

  it("recovers the key of the 2012 transaction from extractSignatures as it is", () => {
    const { transaction, spent, publicKey } = transactionVectors.reusedNonce2012;
    const [a, b] = [0, 1].flatMap((index) => extractSignatures(transaction, { index, spent }));
    if (a === undefined || b === undefined) throw new Error("missing signature");
    const recovered = recoverReusedNonce([a, b]);
    const derived = secp256k1.getPublicKey(hex.decode(recovered.privateKey), false);
    expect(hex.encode(derived)).toBe(publicKey);
    const compressed = secp256k1.Point.fromBytes(hex.decode(publicKey)).toBytes(true);
    expect(recovered.publicKey).toBe(hex.encode(compressed));
  });

  it("solves BIP340 with the x-only key and returns the even y scalar", () => {
    const { publicKey, privateKey, signatures } = schnorrPair();
    const [a, b] = signatures;
    if (a === undefined || b === undefined) throw new Error("missing signature");
    const recovered = recoverReusedNonce(
      [
        { ...a, type: "schnorr" },
        { ...b, type: "schnorr" },
      ],
      { publicKey },
    );
    expect(recovered.privateKey).toBe(hex.encode(Fn.toBytes(privateKey)));
    expect(recovered.publicKey).toBe(publicKey);
    expect(() =>
      recoverReusedNonce([
        { ...a, type: "schnorr" },
        { ...b, type: "schnorr" },
      ]),
    ).toThrow(/x-only public key/u);
  });

  it("tells apart Schnorr messages that differ by the curve order", () => {
    const low = hex.decode(`${"00".repeat(31)}01`);
    const high = hex.decode((1n + Fn.ORDER).toString(16).padStart(64, "0"));
    const { publicKey, privateKey, signatures } = schnorrPair([low, high]);
    const [a, b] = signatures;
    if (a === undefined || b === undefined) throw new Error("missing signature");
    const recovered = recoverReusedNonce(
      [
        { ...a, type: "schnorr" },
        { ...b, type: "schnorr" },
      ],
      { publicKey },
    );
    expect(recovered.privateKey).toBe(hex.encode(Fn.toBytes(privateKey)));
  });

  it("reads Schnorr r as an x coordinate below the field prime, not a scalar", () => {
    const { publicKey, signatures } = schnorrPair();
    const [a, b] = signatures;
    if (a === undefined || b === undefined) throw new Error("missing signature");
    const recover = (r: bigint): unknown =>
      recoverReusedNonce(
        [
          { ...a, r: r.toString(16), type: "schnorr" },
          { ...b, r: r.toString(16), type: "schnorr" },
        ],
        { publicKey },
      );
    expect(() => recover(Fn.ORDER)).toThrow(/does not match publicKey/u);
    expect(() => recover(secp256k1.Point.Fp.ORDER)).toThrow(/field prime/u);
  });

  it("refuses pairs that leak nothing or disagree", () => {
    const one = { r, ...first };
    const two = { r, ...second };
    expect(() => recoverReusedNonce([one, { ...two, r: "01" }])).toThrow(/different r/u);
    expect(() => recoverReusedNonce([one, { ...two, z: first.z }])).toThrow(/same digest/u);
    const wrapped = (1n + Fn.ORDER).toString(16);
    expect(() =>
      recoverReusedNonce([
        { ...one, z: "1" },
        { ...two, z: wrapped },
      ]),
    ).toThrow(/same digest/u);
    expect(() => recoverReusedNonce([one, { ...two, type: "schnorr" }])).toThrow(TypeError);
    expect(() => recoverReusedNonce([one, { ...two, s: "0" }])).toThrow(/from 1/u);
    expect(() => recoverReusedNonce([one, { ...two, s: "0x1" }])).toThrow(TypeError);
    const other = hex.encode(secp256k1.getPublicKey(Fn.toBytes(2n)));
    expect(() => recoverReusedNonce([one, two], { publicKey: other })).toThrow(/does not match/u);
    expect(() =>
      recoverReusedNonce([{ ...one, publicKey: other }, two], { publicKey: one.r }),
    ).toThrow(TypeError);
    expect(() => recoverReusedNonce([one, { ...two, s: first.s }])).toThrow(/No key verifies/u);
  });
});

describe("recoverKnownNonce", () => {
  const { asSigned, flipped } = knownNonceVectors;

  /* r, s and z of a vector, the part a signature carries. */
  const signed = (
    vector: Readonly<{ r: string; s: string; z: string }>,
  ): { r: string; s: string; z: string } => ({ r: vector.r, s: vector.s, z: vector.z });

  it("recovers btcd's key from its RFC 6979 nonce, s as given first", () => {
    const keys = recoverKnownNonce(signed(asSigned), { nonce: asSigned.nonce });
    expect(keys).toHaveLength(2);
    expect(keys[0]).toEqual({
      privateKey: asSigned.privateKey,
      nonce: asSigned.nonce,
      publicKey: asSigned.publicKey,
      flipped: false,
    });
    expect(keys[1]?.flipped).toBe(true);
    expect(keys[1]?.publicKey).not.toBe(asSigned.publicKey);
  });

  it("finds key 1 behind the signature btcd lowered, as the flipped reading", () => {
    const keys = recoverKnownNonce(signed(flipped), { nonce: flipped.nonce });
    expect(keys.map((key) => key.flipped)).toEqual([false, true]);
    expect(keys[1]).toEqual({
      privateKey: flipped.privateKey,
      nonce: hex.encode(Fn.toBytes(Fn.neg(BigInt(`0x${flipped.nonce}`)))),
      publicKey: flipped.publicKey,
      flipped: true,
    });
    const high = hex.encode(Fn.toBytes(Fn.neg(BigInt(`0x${flipped.s}`))));
    const [original] = recoverKnownNonce({ ...signed(flipped), s: high }, { nonce: flipped.nonce });
    expect(original).toMatchObject({ privateKey: flipped.privateKey, flipped: false });
  });

  it("takes extractSignatures output as it is, its public key settling the reading", () => {
    const { transaction, spent } = transactionVectors.reusedNonce2012;
    const [a, b] = [0, 1].flatMap((index) => extractSignatures(transaction, { index, spent }));
    if (a === undefined || b === undefined) throw new Error("missing signature");
    const { privateKey, nonce } = recoverReusedNonce([a, b]);
    const keys = recoverKnownNonce(a, { nonce });
    expect(keys.map((key) => key.privateKey)).toEqual([privateKey]);
  });

  it("lets publicKey settle the reading, compressed or not", () => {
    const uncompressed = hex.encode(secp256k1.Point.fromHex(flipped.publicKey).toBytes(false));
    for (const publicKey of [flipped.publicKey, uncompressed]) {
      const keys = recoverKnownNonce(signed(flipped), { nonce: flipped.nonce, publicKey });
      expect(keys).toHaveLength(1);
      expect(keys[0]?.privateKey).toBe(flipped.privateKey);
    }
    expect(() =>
      recoverKnownNonce(signed(flipped), { nonce: flipped.nonce, publicKey: asSigned.publicKey }),
    ).toThrow(new RangeError("Neither key the nonce gives matches publicKey"));
  });

  it("refuses a nonce that does not give r, reversed bytes included", () => {
    const reversed = hex.encode(Uint8Array.from([...hex.decode(asSigned.nonce)].reverse()));
    for (const nonce of [reversed, flipped.nonce, "02"]) {
      expect(() => recoverKnownNonce(signed(asSigned), { nonce })).toThrow(
        new RangeError("The nonce does not give r, so it is not the nonce of this signature"),
      );
    }
  });

  it("refuses scalars out of range and malformed hex", () => {
    const order = Fn.ORDER.toString(16);
    for (const nonce of ["0", order]) {
      expect(() => recoverKnownNonce(signed(asSigned), { nonce })).toThrow(/from 1 to the curve/u);
    }
    for (const part of ["r", "s"] as const) {
      expect(() =>
        recoverKnownNonce({ ...signed(asSigned), [part]: order }, { nonce: asSigned.nonce }),
      ).toThrow(/from 1 to the curve/u);
    }
    for (const nonce of [`0x${asSigned.nonce}`, `${asSigned.nonce}00`, "", "zz"]) {
      expect(() => recoverKnownNonce(signed(asSigned), { nonce })).toThrow(
        new TypeError("nonce must be hex without 0x, up to 64 digits"),
      );
    }
    expect(() =>
      recoverKnownNonce({ ...signed(asSigned), type: "schnorr" }, { nonce: asSigned.nonce }),
    ).toThrow(new TypeError("recoverKnownNonce solves ECDSA only"));
  });

  it("refuses a call without the options object", () => {
    const usage = "recoverKnownNonce(signature, { nonce, publicKey })";
    expect(() => {
      Reflect.apply(recoverKnownNonce, undefined, [signed(asSigned)]);
    }).toThrow(new TypeError(`Pass one signature and the nonce in the options: ${usage}`));
    expect(() => {
      Reflect.apply(recoverKnownNonce, undefined, [[signed(asSigned)], { nonce: asSigned.nonce }]);
    }).toThrow(new TypeError(`Pass one signature and the nonce in the options: ${usage}`));
    expect(() => {
      Reflect.apply(recoverKnownNonce, undefined, [signed(asSigned), asSigned.nonce]);
    }).toThrow(new TypeError(`Pass the options as an object: ${usage}`));
    expect(() => {
      Reflect.apply(recoverKnownNonce, undefined, [signed(asSigned), { nonce: 5 }]);
    }).toThrow(TypeError);
  });
});
