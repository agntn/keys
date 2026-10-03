import { base64 } from "@agntn/encodings/base64";
import { hex } from "@agntn/encodings/hex";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { describe, expect, it } from "vite-plus/test";
import { Bitcoin } from "../../src/blockchains/bitcoin.ts";
import { sign, verify } from "../../src/utils/bip322/index.ts";
import { hash160, taggedHash } from "../../src/utils/address.ts";
import {
  challengeOf,
  messageHash,
  p2pkhScript,
  toSign,
  toSpend,
} from "../../src/utils/bip322/challenge.ts";
import { readPushes } from "../../src/utils/bip322/script.ts";
import { segwitSighash, taprootSighash } from "../../src/utils/bip322/sighash.ts";
import {
  decodeTransaction,
  decodeWitness,
  encodeWitness,
  serializeTransaction,
  transactionId,
} from "../../src/utils/bip322/transaction.ts";
import { decode as decodeWIF } from "../../src/utils/wif/index.ts";
import { bip322Vectors, secp256k1TestVectors } from "../fixtures.ts";

/* An explorer prints a txid reversed against the bytes an outpoint holds. */
const displayed = (bytes: Uint8Array): string => hex.encode(Uint8Array.from(bytes).reverse());

/* The private key behind a vector's WIF, as hex. */
const keyOf = (wif: string): string => decodeWIF(wif, { chain: "bitcoin" }).privateKey;

/* Base64 of a full signature with its to_sign rewritten. */
const rewritten = (signature: string, edit: (bytes: Uint8Array) => Uint8Array): string =>
  `ful${base64.encode(edit(base64.decode(signature.slice(3))))}`;

describe("bip322 virtual transactions", () => {
  it.each(bip322Vectors.hashes)(
    "hashes $message and builds to_spend and to_sign as the BIP does",
    ({ message, address, messageHash: hashed, toSpend: spendId, toSign: signId }) => {
      const spend = toSpend(message, challengeOf(address, "mainnet"));
      expect(hex.encode(messageHash(message))).toBe(hashed);
      expect(displayed(transactionId(spend))).toBe(spendId);
      expect(displayed(transactionId(toSign(spend)))).toBe(signId);
    },
  );

  it("reads back the transaction it writes, witness included", () => {
    const spend = toSpend("round trip", challengeOf(bip322Vectors.unprefixed.address, "mainnet"));
    const signed = toSign(spend, { witness: [Uint8Array.of(1, 2), new Uint8Array(0)] });
    expect(decodeTransaction(serializeTransaction(signed, true))).toEqual(signed);
    expect(decodeTransaction(serializeTransaction(spend, false))).toEqual(spend);
  });
});

describe("bip322 script and transaction reading", () => {
  it("splits pushes and refuses the ones MINIMALDATA forbids", () => {
    const data = new Uint8Array(80).fill(7);
    expect(readPushes(Uint8Array.of(0x00, 0x4f, 0x51, 0x60, 0x02, 1, 2))).toEqual({
      pushes: [
        new Uint8Array(0),
        Uint8Array.of(0x81),
        Uint8Array.of(1),
        Uint8Array.of(16),
        Uint8Array.of(1, 2),
      ],
    });
    expect(readPushes(Uint8Array.of(0x4c, 80, ...data))).toEqual({ pushes: [data] });
    expect(readPushes(Uint8Array.of(0x4d, 80, 0, ...data))).toMatchObject({ state: "invalid" });
    expect(readPushes(Uint8Array.of(0x4c, 2, 1, 2))).toMatchObject({ state: "invalid" });
    expect(readPushes(Uint8Array.of(0x05, 1, 2))).toMatchObject({
      state: "invalid",
      reason: "scriptSig ends inside a push",
    });
    expect(readPushes(Uint8Array.of(0x4e, 1))).toMatchObject({ state: "invalid" });
    expect(readPushes(Uint8Array.of(0x76))).toMatchObject({ state: "inconclusive" });
  });

  it("refuses transaction bytes that break the encoding", () => {
    const spend = toSpend("bytes", challengeOf(bip322Vectors.unprefixed.address, "mainnet"));
    const bytes = serializeTransaction(toSign(spend, { witness: [Uint8Array.of(1)] }), true);
    expect(() => decodeTransaction(Uint8Array.of(...bytes, 0))).toThrow("has bytes past its end");
    expect(() => decodeTransaction(bytes.subarray(0, 20))).toThrow("ends early");
    const flagged = Uint8Array.from(bytes);
    flagged[5] = 2;
    expect(() => decodeTransaction(flagged)).toThrow("has an unknown witness flag");
    const empty = serializeTransaction(toSign(spend), false);
    const marked = Uint8Array.of(
      ...empty.subarray(0, 4),
      0,
      1,
      ...empty.subarray(4, -4),
      0,
      0,
      0,
      0,
      0,
    );
    expect(() => decodeTransaction(marked)).toThrow("has a witness marker without witnesses");
    expect(() => decodeWitness(Uint8Array.of(0xfd, 1, 0))).toThrow("non-canonical");
    expect(() => decodeWitness(Uint8Array.of(0, 0))).toThrow("has bytes past its end");
    expect(() => decodeTransaction(Uint8Array.of(2, 0, 0, 0, 0, 0, 0, 0, 0, 0))).toThrow();
  });
});

describe("bip322 verify", () => {
  it.each([...bip322Vectors.simple, ...bip322Vectors.full])(
    "accepts the $addressType vector for $message",
    ({ address, message, signature, addressType }) => {
      const result = verify(address, message, signature);
      expect(result).toMatchObject({ state: "valid", addressType });
      expect(result.reason).toBeUndefined();
    },
  );

  it("reads time and age off a full signature, and nothing off a simple one", () => {
    const [legacy] = bip322Vectors.full;
    expect(verify(legacy.address, legacy.message, legacy.signature)).toMatchObject({
      format: "full",
      lockTime: 2016,
      sequence: 2016,
    });
    const [segwit] = bip322Vectors.simple;
    expect(verify(segwit.address, segwit.message, segwit.signature)).toMatchObject({
      format: "simple",
      lockTime: 0,
      sequence: 0,
    });
  });

  it("reads an unprefixed signature as simple and refuses it for another message", () => {
    const { address, message, signature } = bip322Vectors.unprefixed;
    expect(verify(address, message, signature)).toEqual({
      state: "valid",
      format: "simple",
      addressType: "segwit",
      publicKey: "02c7f12003196442943d8588e01aee840423cc54fc1521526a3b85c2b0cbd58872",
      lockTime: 0,
      sequence: 0,
    });
    expect(verify(address, `${message}s`, signature)).toMatchObject({
      state: "invalid",
      reason: "ECDSA signature does not verify",
    });
  });

  it.each(bip322Vectors.invalid)(
    "never accepts $description",
    ({ address, message, signature }) => {
      const { state, addressType } = verify(address, message, signature);
      expect(state).toBe(addressType === "p2wsh" ? "inconclusive" : "invalid");
    },
  );

  it.each(bip322Vectors.inconclusive)(
    "answers inconclusive for a $addressType script it cannot run",
    ({ address, message, signature }) => {
      expect(verify(address, message, signature).state).toBe("inconclusive");
    },
  );

  it("answers inconclusive for a proof of funds", () => {
    const { address, message } = bip322Vectors.full[1];
    expect(verify(address, message, "pofcHNidP8B").reason).toBe(
      "Proof of funds PSBTs are not read",
    );
  });

  it("answers inconclusive for a valid spend in a to_sign of version 3", () => {
    const key = hex.decode(secp256k1TestVectors.privateKey);
    const publicKey = secp256k1.getPublicKey(key, true);
    const address = new Bitcoin().getAddress(hex.encode(publicKey), "segwit");
    const spend = toSpend("v3", challengeOf(address, "mainnet"));
    const unsigned = toSign(spend, { version: 3 });
    const digest = segwitSighash(unsigned, 0, p2pkhScript(hash160(publicKey)), 0n);
    const der = secp256k1.sign(digest, key, { prehash: false, format: "der" });
    const witness = [Uint8Array.of(...der, 1), publicKey];
    const signed = toSign(spend, { version: 3, witness });
    const signature = `ful${base64.encode(serializeTransaction(signed, true))}`;
    expect(verify(address, "v3", signature)).toMatchObject({
      state: "inconclusive",
      reason: "to_sign version must be 0 or 2",
    });
  });

  it("refuses a full signature with a second output", () => {
    const key = secp256k1TestVectors.privateKey;
    const address = new Bitcoin().getAddress(new Bitcoin().getKeyPublic(key), "legacy");
    const full = sign("two outputs", key, "legacy");
    const changed = rewritten(full, (bytes) => {
      const transaction = decodeTransaction(bytes);
      const outputs = [...transaction.outputs, ...transaction.outputs];
      return serializeTransaction({ ...transaction, outputs }, true);
    });
    expect(verify(address, "two outputs", changed).reason).toBe(
      "Transaction must have one output paying nothing to OP_RETURN",
    );
  });

  it("checks Core's legacy signature for P2PKH only", () => {
    const bitcoin = new Bitcoin();
    const key = secp256k1TestVectors.privateKey;
    const legacy = bitcoin.getAddress(bitcoin.getKeyPublic(key), "legacy");
    const segwit = bitcoin.getAddress(bitcoin.getKeyPublic(key), "segwit");
    const signature = bitcoin.signMessage("core", key, { recovered: true });
    expect(verify(legacy, "core", signature)).toMatchObject({ state: "valid", format: "legacy" });
    expect(verify(legacy, "other", signature).state).toBe("invalid");
    expect(verify(segwit, "core", signature).reason).toBe(
      "BIP322 takes a legacy signature for a P2PKH address only",
    );
  });

  it("refuses a P2WPKH witness with a hash type other than SIGHASH_ALL", () => {
    const { address, message, signature } = bip322Vectors.unprefixed;
    const witness = base64.decode(signature);
    witness[1 + (witness[1] ?? 0)] = 0x03;
    const edited = base64.encode(witness);
    expect(verify(address, message, edited).reason).toBe("Signature must use SIGHASH_ALL");
  });

  it("throws on an address of another network and an unknown network", () => {
    const { address, message, signature } = bip322Vectors.unprefixed;
    expect(() => verify(address, message, signature, { network: "testnet" })).toThrow(
      "Address is not a valid bitcoin testnet address",
    );
    // @ts-expect-error a network the type does not take
    expect(() => verify(address, message, signature, { network: "regtest" })).toThrow(RangeError);
  });
});

describe("bip322 sign", () => {
  it.each(bip322Vectors.simple.filter((vector) => vector.addressType === "segwit"))(
    "writes the exact P2WPKH vector for $message",
    ({ message }) => {
      const signatures = bip322Vectors.simple
        .filter((vector) => vector.addressType === "segwit" && vector.message === message)
        .map((vector) => vector.signature);
      expect(signatures).toContain(sign(message, keyOf(bip322Vectors.segwitKey), "segwit"));
    },
  );

  it.each(["legacy", "p2sh", "segwit", "taproot"] as const)(
    "round trips a %s signature on mainnet and testnet",
    (addressType) => {
      const key = secp256k1TestVectors.privateKey;
      for (const network of ["mainnet", "testnet"] as const) {
        const bitcoin = new Bitcoin({ network });
        const address = bitcoin.getAddress(bitcoin.getKeyPublic(key), addressType);
        const signature = sign("disposable", key, addressType, { network });
        expect(signature.slice(0, 3)).toBe(
          addressType === "segwit" || addressType === "taproot" ? "smp" : "ful",
        );
        expect(verify(address, "disposable", signature, { network }).state).toBe("valid");
        expect(verify(address, "tampered", signature, { network }).state).toBe("invalid");
      }
    },
  );

  it("takes a Taproot signature with an explicit SIGHASH_ALL byte, not with 0x00", () => {
    const { Fn } = secp256k1.Point;
    const key = hex.decode(secp256k1TestVectors.privateKey);
    const point = secp256k1.Point.BASE.multiply(Fn.fromBytes(key));
    const internal = point.toBytes(true);
    const even = internal[0] === 2 ? Fn.fromBytes(key) : Fn.neg(Fn.fromBytes(key));
    const tweaked = Fn.add(even, Fn.fromBytes(taggedHash("TapTweak", internal.subarray(1))));
    const address = new Bitcoin().getAddress(hex.encode(internal), "taproot");
    const challenge = challengeOf(address, "mainnet");
    const spend = toSpend("all", challenge);
    const spent = [{ value: 0n, script: challenge.script }];
    const digest = taprootSighash(toSign(spend), 0, spent, 1);
    const signature = schnorr.sign(digest, Fn.toBytes(tweaked));
    const withType = (type: number): string =>
      `smp${base64.encode(encodeWitness([Uint8Array.of(...signature, type)]))}`;
    expect(verify(address, "all", withType(1)).state).toBe("valid");
    expect(verify(address, "all", withType(0)).reason).toBe(
      "Signature must use SIGHASH_DEFAULT or SIGHASH_ALL",
    );
  });

  it("signs for the uncompressed P2PKH address on request", () => {
    const key = secp256k1TestVectors.privateKey;
    const bitcoin = new Bitcoin();
    const address = bitcoin.getAddress(bitcoin.getKeyPublic(key, { compressed: false }), "legacy");
    const signature = sign("old wallet", key, "legacy", { compressed: false });
    expect(verify(address, "old wallet", signature).state).toBe("valid");
  });

  it("writes a simple signature as one witness stack", () => {
    const key = secp256k1TestVectors.privateKey;
    const signature = sign("stack", key, "taproot");
    const stack = base64.decode(signature.slice(3));
    expect(stack).toHaveLength(66);
    expect(hex.encode(encodeWitness([stack.subarray(2)]))).toBe(hex.encode(stack));
  });

  it("refuses an address type it cannot sign for", () => {
    // @ts-expect-error a type outside the four
    expect(() => sign("x", secp256k1TestVectors.privateKey, "p2wsh")).toThrow(RangeError);
  });
});
