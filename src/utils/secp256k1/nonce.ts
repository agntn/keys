import { sha256 } from "@agntn/hashes";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { concatBytes } from "../bytes.ts";

const { Point } = secp256k1;
const { Fn } = Point;

/** One signature with the digest it signs, as `extractSignatures` gives it. */
export interface NonceSignature {
  /** ECDSA unless set; Schnorr is BIP340 as Taproot signs. */
  readonly type?: "ecdsa" | "schnorr";
  /** Hex, up to 64 digits; for Schnorr the x coordinate of R. */
  readonly r: string;
  readonly s: string;
  /** The signed digest as hex, up to 64 digits; for Schnorr the message BIP340 signs. */
  readonly z: string;
  /** The signer's key, SEC1 hex, or x-only for Schnorr. */
  readonly publicKey?: string;
}

/** Options for `recoverReusedNonce`. */
export interface NonceRecoveryOptions {
  /** The key the result must match; Schnorr needs one here or on a signature. */
  readonly publicKey?: string;
}

/** A private key and the nonce two of its signatures shared. */
export interface RecoveredNonceKey {
  /** 64 hex digits. For Schnorr the scalar of the even y key, the one Taproot signs with. */
  readonly privateKey: string;
  readonly nonce: string;
  /** Compressed SEC1 hex for ECDSA, x-only for Schnorr. */
  readonly publicKey: string;
}

const SAME_DIGEST = "Both signatures sign the same digest, which leaves the nonce unknown";

/** The two signatures read as numbers. */
interface Pair {
  readonly r: bigint;
  readonly s: readonly [bigint, bigint];
  readonly z: readonly [bigint, bigint];
}

/**
 * Reads hex up to 64 digits as a number.
 * @param value - Hex without 0x
 * @param name - What the error calls it
 * @returns {bigint} The number
 * @throws {TypeError} When the value is no such hex
 */
function readHex(value: unknown, name: string): bigint {
  if (typeof value !== "string" || !/^[0-9a-f]{1,64}$/iu.test(value)) {
    throw new TypeError(`${name} must be hex without 0x, up to 64 digits`);
  }
  return BigInt(`0x${value}`);
}

/**
 * Writes a digest back as the 32 bytes it was, without reducing it.
 * @param digest - Digest as a number
 * @returns {Uint8Array} 32 bytes, big endian
 */
function digestBytes(digest: bigint): Uint8Array {
  return Uint8Array.fromHex(digest.toString(16).padStart(64, "0"));
}

/**
 * Reads r and s from 1 to n minus 1 and the digests, refusing two signatures that leak nothing.
 * @param first - One signature
 * @param second - The other
 * @returns {Pair} The numbers, digests as given
 * @throws {RangeError} When r or s is out of range, the r values differ or the digests match
 */
function readPair(first: Readonly<NonceSignature>, second: Readonly<NonceSignature>): Pair {
  const r = readHex(first.r, "r");
  const s: [bigint, bigint] = [readHex(first.s, "s"), readHex(second.s, "s")];
  const z: [bigint, bigint] = [readHex(first.z, "z"), readHex(second.z, "z")];
  if (![r, ...s].every((value) => Fn.isValidNot0(value))) {
    throw new RangeError("r and s must run from 1 to the curve order minus 1");
  }
  if (readHex(second.r, "r") !== r) {
    throw new RangeError("The two signatures have different r, so they did not share a nonce");
  }
  if (z[0] === z[1]) throw new RangeError(SAME_DIGEST);
  return { r, s, z };
}

/**
 * Checks an ECDSA signature against a key, taking either s.
 * @param key - Public key bytes
 * @param r - r
 * @param s - s
 * @param z - Digest
 * @returns {boolean} Whether it verifies
 */
function verifiesEcdsa(key: Uint8Array, r: bigint, s: bigint, z: bigint): boolean {
  const signature = concatBytes(Fn.toBytes(r), Fn.toBytes(s));
  const options = { prehash: false, lowS: false, format: "compact" } as const;
  return secp256k1.verify(signature, digestBytes(z), key, options);
}

/**
 * Reads the key a recovery must match: SEC1 for ECDSA, x-only or SEC1 for Schnorr.
 * @param value - Hex
 * @param xOnly - Whether the comparison is by x alone
 * @returns {string | undefined} The key as the result writes it, undefined when none was given
 * @throws {TypeError} When the value is no public key
 */
function readExpectedKey(value: unknown, xOnly: boolean): string | undefined {
  if (value === undefined) return undefined;
  const hex = typeof value === "string" ? value.toLowerCase() : "";
  try {
    if (xOnly && hex.length === 64)
      return Point.fromBytes(Uint8Array.fromHex(`02${hex}`))
        .toBytes(true)
        .subarray(1)
        .toHex();
    const point = Point.fromBytes(Uint8Array.fromHex(hex));
    return xOnly ? point.toBytes(true).subarray(1).toHex() : point.toBytes(true).toHex();
  } catch {
    throw new TypeError("publicKey must be a SEC1 public key as hex, or x-only for Schnorr");
  }
}

/**
 * Picks the key the caller named, refusing two that disagree.
 * @param keys - Keys from the options and both signatures
 * @param xOnly - Whether keys compare by x alone
 * @returns {string | undefined} The key, undefined when none was named
 * @throws {RangeError} When the named keys differ
 */
function expectedKey(keys: readonly unknown[], xOnly: boolean): string | undefined {
  const named = [
    ...new Set(keys.map((key) => readExpectedKey(key, xOnly)).filter((key) => key !== undefined)),
  ];
  if (named.length > 1)
    throw new RangeError("The signatures and options name different public keys");
  return named[0];
}

/**
 * Solves ECDSA by k = (z1 - z2) / (s1 - s2), or s1 + s2 when one s was flipped to low form.
 * @param pair - The signatures
 * @param expected - Compressed key the result must match
 * @returns {RecoveredNonceKey} The key whose public key verifies both signatures
 * @throws {RangeError} When the digests match mod n, no candidate verifies both, or none matches
 */
function recoverEcdsa(pair: Readonly<Pair>, expected: string | undefined): RecoveredNonceKey {
  const { r, s, z } = pair;
  const difference = Fn.sub(z[0], z[1]);
  if (Fn.is0(difference)) throw new RangeError(SAME_DIGEST);
  for (const denominator of [Fn.sub(s[0], s[1]), Fn.add(s[0], s[1])]) {
    if (Fn.is0(denominator)) continue;
    const nonce = Fn.div(difference, denominator);
    const privateKey = Fn.div(Fn.sub(Fn.mul(s[0], nonce), Fn.create(z[0])), Fn.create(r));
    if (!Fn.isValidNot0(privateKey)) continue;
    const key = Point.BASE.multiply(privateKey).toBytes(true);
    const verified = s.every((each, index) => verifiesEcdsa(key, r, each, z[index] ?? 0n));
    if (verified && (expected === undefined || expected === key.toHex())) {
      return {
        privateKey: Fn.toBytes(privateKey).toHex(),
        nonce: Fn.toBytes(nonce).toHex(),
        publicKey: key.toHex(),
      };
    }
  }
  throw new RangeError(
    expected === undefined
      ? "No key verifies both signatures, so they do not share a nonce under one key"
      : "The key both signatures share does not match publicKey",
  );
}

/**
 * Solves BIP340 by d = (s1 - s2) / (e1 - e2), e being the challenge hash of each message.
 * @param pair - The signatures, z holding the messages
 * @param publicKey - x-only key both signed with
 * @returns {RecoveredNonceKey} The even y key and its nonce
 * @throws {RangeError} When the solved key does not verify both signatures
 */
function recoverSchnorr(pair: Readonly<Pair>, publicKey: string): RecoveredNonceKey {
  const { r, s, z } = pair;
  const tag = sha256(new TextEncoder().encode("BIP0340/challenge"));
  const prefix = concatBytes(tag, tag, Fn.toBytes(r), Uint8Array.fromHex(publicKey));
  const [e1, e2] = z.map((message) =>
    Fn.create(BigInt(`0x${sha256(concatBytes(prefix, digestBytes(message))).toHex()}`)),
  );
  const privateKey = Fn.div(Fn.sub(s[0], s[1]), Fn.sub(e1 ?? 0n, e2 ?? 0n));
  const nonce = Fn.sub(s[0], Fn.mul(e1 ?? 0n, privateKey));
  const key = Fn.isValidNot0(privateKey) ? schnorr.getPublicKey(Fn.toBytes(privateKey)) : undefined;
  const signatures = s.map((each) => concatBytes(Fn.toBytes(r), Fn.toBytes(each)));
  const verified = signatures.every((signature, index) =>
    schnorr.verify(signature, digestBytes(z[index] ?? 0n), Uint8Array.fromHex(publicKey)),
  );
  if (key?.toHex() !== publicKey || !verified) {
    throw new RangeError("The key both signatures share does not match publicKey");
  }
  return {
    privateKey: Fn.toBytes(privateKey).toHex(),
    nonce: Fn.toBytes(nonce).toHex(),
    publicKey,
  };
}

/**
 * Recovers the key behind two signatures with one r, once its public key verifies both.
 * @param first - One signature with its digest
 * @param second - The other
 * @param options - The key the result must match
 * @returns {RecoveredNonceKey} The private key, the shared nonce and the public key
 * @throws {TypeError} When a value is no hex or the signatures disagree on type
 * @throws {RangeError} When r differs, the digests match, Schnorr has no key, or nothing verifies
 */
export function recoverReusedNonce(
  first: Readonly<NonceSignature>,
  second: Readonly<NonceSignature>,
  options: Readonly<NonceRecoveryOptions> = {},
): RecoveredNonceKey {
  const type = first.type ?? "ecdsa";
  if ((second.type ?? "ecdsa") !== type || (type !== "ecdsa" && type !== "schnorr")) {
    throw new TypeError("Both signatures must be ecdsa or both schnorr");
  }
  const pair = readPair(first, second);
  const expected = expectedKey(
    [options.publicKey, first.publicKey, second.publicKey],
    type === "schnorr",
  );
  if (type === "ecdsa") return recoverEcdsa(pair, expected);
  if (expected === undefined)
    throw new RangeError("Schnorr needs the x-only public key both signed with");
  return recoverSchnorr(pair, expected);
}
