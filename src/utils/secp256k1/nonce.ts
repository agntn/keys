import {
  invertScalar,
  multiplyGenerator,
  multiplyScalars,
  secp256k1 as curve,
  subtractScalars,
} from "@agntn/curves/secp256k1";
import { sha256 } from "@agntn/hashes";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { concatBytes } from "../bytes.ts";
import { assertOptions } from "../options.ts";

const { Point } = secp256k1;
const { Fn, Fp } = Point;

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

/** The two signatures `recoverReusedNonce` takes, sharing one r. */
export type NonceSignaturePair = readonly [Readonly<NonceSignature>, Readonly<NonceSignature>];

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

/** One ECDSA signature as numbers, over the digest it signs. */
interface EcdsaSignature {
  readonly r: bigint;
  readonly s: bigint;
  readonly z: bigint;
}

const PAIR_USAGE = "recoverReusedNonce([first, second], { publicKey })";

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
 * Reads s from 1 to n minus 1, r as a scalar for ECDSA or an x coordinate below p for Schnorr, and the digests, refusing two signatures that leak nothing.
 * @param signatures - The two signatures
 * @param schnorr - Whether r is the x coordinate BIP340 signs with
 * @returns {Pair} The numbers, digests as given
 * @throws {RangeError} When r or s is out of range, the r values differ or the digests match
 */
function readPair(signatures: NonceSignaturePair, schnorr: boolean): Pair {
  const [first, second] = signatures;
  const r = readHex(first.r, "r");
  const s: [bigint, bigint] = [readHex(first.s, "s"), readHex(second.s, "s")];
  const z: [bigint, bigint] = [readHex(first.z, "z"), readHex(second.z, "z")];
  if (!s.every((value) => Fn.isValidNot0(value))) {
    throw new RangeError("s must run from 1 to the curve order minus 1");
  }
  if (schnorr ? !Fp.isValidNot0(r) : !Fn.isValidNot0(r)) {
    throw new RangeError(
      schnorr
        ? "Schnorr r must run from 1 to the field prime minus 1"
        : "r must run from 1 to the curve order minus 1",
    );
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
 * @param numbers - r, s and the digest z
 * @returns {boolean} Whether it verifies
 */
function verifiesEcdsa(key: Uint8Array, numbers: EcdsaSignature): boolean {
  const { r, s, z } = numbers;
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
    const verified = s.every((each, index) =>
      verifiesEcdsa(key, { r, s: each, z: z[index] ?? 0n }),
    );
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

/** Options for `recoverKnownNonce`. */
export interface KnownNonceOptions {
  /** The nonce k as hex, big endian, up to 64 digits. */
  readonly nonce: string;
  /** The key the result must match, which also settles how s reads. */
  readonly publicKey?: string;
}

/** One key a known nonce gives, under one reading of s. */
export interface KnownNonceKey {
  readonly privateKey: string;
  /** The nonce that signs s as given under this key: k, or n minus k when flipped. */
  readonly nonce: string;
  /** Compressed SEC1 hex. */
  readonly publicKey: string;
  /** Whether k signed n minus s, as when a wallet lowered s afterwards. */
  readonly flipped: boolean;
}

/** One signature as numbers, with the nonce the caller knows. */
interface KnownNumbers extends EcdsaSignature {
  readonly k: bigint;
}

const KNOWN_USAGE = "recoverKnownNonce(signature, { nonce, publicKey })";

/**
 * Refuses a call without one signature object and an options object.
 * @param signature - What the caller passed as the signature
 * @param options - What the caller passed as options
 * @throws {TypeError} When either has the wrong shape
 */
function assertKnownCall(signature: unknown, options: unknown): void {
  const loose = typeof signature !== "object" || signature === null || Array.isArray(signature);
  if (loose || options === undefined) {
    throw new TypeError(`Pass one signature and the nonce in the options: ${KNOWN_USAGE}`);
  }
  assertOptions(options, KNOWN_USAGE);
}

/**
 * Reads r, s and the nonce from 1 to n minus 1, and checks that the nonce's point has r as its x.
 * @param signature - The signature with its digest
 * @param nonce - k as hex, read as written
 * @returns {KnownNumbers} The numbers
 * @throws {RangeError} When a scalar is out of range or the nonce gives another r
 */
function readKnown(signature: Readonly<NonceSignature>, nonce: unknown): KnownNumbers {
  const r = readHex(signature.r, "r");
  const s = readHex(signature.s, "s");
  const z = readHex(signature.z, "z");
  const k = readHex(nonce, "nonce");
  if (![r, s, k].every((value) => value > 0n && value < curve.n)) {
    throw new RangeError("r, s and nonce must run from 1 to the curve order minus 1");
  }
  if (BigInt(`0x${multiplyGenerator(k).slice(2)}`) % curve.n !== r) {
    throw new RangeError("The nonce does not give r, so it is not the nonce of this signature");
  }
  return { r, s, z, k };
}

/**
 * Solves d = (s k - z) / r for s as given, and for s negated with n minus k.
 * @param numbers - r, s, the digest z and the nonce k
 * @returns {KnownNonceKey[]} The keys the signature verifies under, s as given first
 */
function knownNonceKeys(numbers: KnownNumbers): KnownNonceKey[] {
  const { r, s, z, k } = numbers;
  const inverse = invertScalar(r);
  return [false, true].flatMap((flipped) => {
    const nonce = subtractScalars(flipped ? 0n : k, flipped ? k : 0n);
    const privateKey = multiplyScalars(
      subtractScalars(multiplyScalars(s, nonce), z % curve.n),
      inverse,
    );
    if (/^0+$/u.test(privateKey)) return [];
    const publicKey = multiplyGenerator(privateKey);
    if (!verifiesEcdsa(Uint8Array.fromHex(publicKey), numbers)) return [];
    return [{ privateKey, nonce, publicKey, flipped }];
  });
}

/**
 * Recovers the key behind one ECDSA signature whose nonce is known.
 * @param signature - r, s and the digest z
 * @param options - The nonce, and the key the result must match
 * @returns {readonly KnownNonceKey[]} One key with a public key to match, else up to two
 * @throws {TypeError} When the call has another shape, a value is no hex or the type is schnorr
 * @throws {RangeError} When a scalar is out of range, the nonce gives another r or no key matches
 */
export function recoverKnownNonce(
  signature: Readonly<NonceSignature>,
  options: Readonly<KnownNonceOptions>,
): readonly KnownNonceKey[] {
  assertKnownCall(signature, options);
  if ((signature.type ?? "ecdsa") !== "ecdsa") {
    throw new TypeError("recoverKnownNonce solves ECDSA only");
  }
  const expected = expectedKey([options.publicKey, signature.publicKey], false);
  const keys = knownNonceKeys(readKnown(signature, options.nonce));
  const matching = keys.filter((key) => expected === undefined || key.publicKey === expected);
  if (matching.length === 0) {
    throw new RangeError("Neither key the nonce gives matches publicKey");
  }
  return matching;
}

/**
 * Refuses the old call shape: two loose signatures instead of a pair, or options that aren't one.
 * @param signatures - What the caller passed as the pair
 * @param options - What the caller passed as options
 * @throws {TypeError} When either has the wrong shape
 */
function assertPairCall(signatures: unknown, options: unknown): void {
  if (!Array.isArray(signatures) || signatures.length !== 2) {
    throw new TypeError(`Pass the two signatures as a pair: ${PAIR_USAGE}`);
  }
  assertOptions(options, PAIR_USAGE);
}

/**
 * Recovers the key behind two signatures with one r, once its public key verifies both.
 * @param signatures - The two signatures, each with its digest
 * @param options - The key the result must match
 * @returns {RecoveredNonceKey} The private key, the shared nonce and the public key
 * @throws {TypeError} When the signatures are not a pair, a value is no hex or the signatures
 * disagree on type
 * @throws {RangeError} When r differs, the digests match, Schnorr has no key, or nothing verifies
 */
export function recoverReusedNonce(
  signatures: NonceSignaturePair,
  options: Readonly<NonceRecoveryOptions> = {},
): RecoveredNonceKey {
  assertPairCall(signatures, options);
  const [first, second] = signatures;
  const type = first.type ?? "ecdsa";
  if ((second.type ?? "ecdsa") !== type || (type !== "ecdsa" && type !== "schnorr")) {
    throw new TypeError("Both signatures must be ecdsa or both schnorr");
  }
  const pair = readPair(signatures, type === "schnorr");
  const expected = expectedKey(
    [options.publicKey, first.publicKey, second.publicKey],
    type === "schnorr",
  );
  if (type === "ecdsa") return recoverEcdsa(pair, expected);
  if (expected === undefined)
    throw new RangeError("Schnorr needs the x-only public key both signed with");
  return recoverSchnorr(pair, expected);
}
