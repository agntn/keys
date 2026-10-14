import { secp256k1 } from "@noble/curves/secp256k1.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@agntn/hashes";
import { concatBytes } from "./bytes.ts";
import { decodeKeyPrivate } from "./secp256k1/decode.ts";
import type { SigningOptions } from "../types.ts";

export type { SigningOptions } from "../types.ts";

/** Ethereum writes the recovery bit as 27 or 28; `personal_sign` inherited the offset from Bitcoin. */
const RECOVERY_BYTE_OFFSET = 27;

/** Bytes in a compact `r||s` secp256k1 signature. */
const COMPACT_SIGNATURE_LENGTH = 64;

/**
 * Read the recovery flag from options a caller may have built without types.
 * @param options - Signing or verification options
 * @returns {boolean} Whether the caller asked for the recovery byte
 */
export function readRecoveredFlag(options: SigningOptions = {}): boolean {
  /** Read as unknown: untyped callers can pass anything, and `null` must not pass as false. */
  const recovered: unknown = options.recovered;
  if (recovered === undefined) {
    return false;
  }
  if (typeof recovered !== "boolean") {
    throw new TypeError("Recovered must be a boolean");
  }
  return recovered;
}

/**
 * Reject the recovery byte where the chain's native signature has no `r||s||v` form,
 * instead of handing back 65 bytes that its tooling reads as something else.
 * @param options - Options the chain received
 * @param nativeFormat - What that chain's tooling expects instead
 * @returns {void} Nothing; it throws when the flag is set
 */
export function assertNoRecoveryByte(
  options: SigningOptions | undefined,
  nativeFormat: string,
): void {
  if (options !== undefined && readRecoveredFlag(options)) {
    throw new Error(`Recovered signatures are not supported here: ${nativeFormat}`);
  }
}

/**
 * Tell an `r||s||v` signature from a compact one, for chains that accept only their own format.
 * @param signature - Signature as hex
 * @returns {boolean} True when the signature carries a trailing recovery byte
 */
export function hasRecoveryByte(signature: string): boolean {
  try {
    return Uint8Array.fromHex(signature).length === COMPACT_SIGNATURE_LENGTH + 1;
  } catch {
    return false;
  }
}

/**
 * Sign a prepared digest with `prehash: false`, or noble v2 would hash it a second time.
 * noble puts the recovery byte first; Ethereum wants it last, as `v`.
 * @param messageHash - The digest to sign
 * @param keyPrivateBytes - The private key bytes
 * @param recovered - Append the recovery byte as 27 or 28
 * @returns {string} 64 bytes of `r||s`, or 65 bytes of `r||s||v`, as hex
 */
function signSecp256k1(
  messageHash: Uint8Array,
  keyPrivateBytes: Uint8Array,
  recovered: boolean,
): string {
  if (!recovered) {
    return secp256k1.sign(messageHash, keyPrivateBytes, { prehash: false }).toHex();
  }
  const signature = secp256k1.sign(messageHash, keyPrivateBytes, {
    prehash: false,
    format: "recovered",
  });
  const recoveryByte = signature[0];
  if (recoveryByte === undefined) {
    throw new Error("Missing recovery byte");
  }
  return concatBytes(
    signature.subarray(1),
    Uint8Array.of(RECOVERY_BYTE_OFFSET + recoveryByte),
  ).toHex();
}

/**
 * Read `v` as Ethereum's 27 or 28 or the bare 0 or 1 some libraries emit.
 * @param recoveryByte - Last byte of an `r||s||v` signature
 * @returns {number | undefined} The recovery bit, or undefined for any other value
 */
function recoveryBit(recoveryByte: number | undefined): number | undefined {
  if (recoveryByte === undefined) return undefined;
  const recovery =
    recoveryByte >= RECOVERY_BYTE_OFFSET ? recoveryByte - RECOVERY_BYTE_OFFSET : recoveryByte;
  return recovery === 0 || recovery === 1 ? recovery : undefined;
}

/**
 * Recover the key behind `r||s||v` over a digest, as `ecrecover` does. Any input gives some key.
 * @param messageHash - The 32-byte digest that was signed
 * @param signature - 65 bytes of `r||s||v` as hex, `v` as 27, 28, 0 or 1
 * @returns {string} The uncompressed SEC1 public key as hex
 * @throws {TypeError} When the digest or signature has the wrong length or `v` is out of range
 * @throws {RangeError} When `r` and `s` recover no key
 */
export function recoverSecp256k1Signer(messageHash: Uint8Array, signature: string): string {
  if (messageHash.length !== 32) throw new TypeError("Digest must be 32 bytes");
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.fromHex(signature);
  } catch {
    bytes = new Uint8Array();
  }
  if (bytes.length !== COMPACT_SIGNATURE_LENGTH + 1) {
    throw new TypeError("Signature must be 65 bytes of r||s||v as hex without 0x");
  }
  const recovery = recoveryBit(bytes[COMPACT_SIGNATURE_LENGTH]);
  if (recovery === undefined) throw new TypeError("Signature v must be 27, 28, 0 or 1");
  try {
    return secp256k1.Signature.fromBytes(bytes.subarray(0, COMPACT_SIGNATURE_LENGTH), "compact")
      .addRecoveryBit(recovery)
      .recoverPublicKey(messageHash)
      .toBytes(false)
      .toHex();
  } catch {
    throw new RangeError("Signature recovers no public key");
  }
}

/**
 * Check an `r||s||v` signature by recovering the signer from `v` and comparing keys,
 * so a signature carrying the wrong `v` fails instead of passing on `r||s` alone.
 * @param signatureBytes - 65 signature bytes
 * @param messageHash - The digest that was signed
 * @param keyPublicBytes - The public key to check against, SEC1
 * @returns {boolean} True when the signature and its recovery byte both match the key
 */
function verifyRecoveredSignature(
  signatureBytes: Uint8Array,
  messageHash: Uint8Array,
  keyPublicBytes: Uint8Array,
): boolean {
  const recovery = recoveryBit(signatureBytes[COMPACT_SIGNATURE_LENGTH]);
  if (recovery === undefined) {
    return false;
  }
  const compact = signatureBytes.subarray(0, COMPACT_SIGNATURE_LENGTH);
  if (!secp256k1.verify(compact, messageHash, keyPublicBytes, { prehash: false })) {
    return false;
  }
  const recoveredKey = secp256k1.Signature.fromBytes(compact, "compact")
    .addRecoveryBit(recovery)
    .recoverPublicKey(messageHash);
  return equalBytes(
    recoveredKey.toBytes(true),
    secp256k1.Point.fromBytes(keyPublicBytes).toBytes(true),
  );
}

/**
 * Encode a string message as UTF-8; bytes pass through untouched.
 * @param message - The message as text or bytes
 * @returns {Uint8Array} The message bytes
 */
function messageBytes(message: string | Uint8Array): Uint8Array {
  return typeof message === "string" ? new TextEncoder().encode(message) : message;
}

/**
 * The digest secp256k1 signs: SHA-256 of the message, or the bytes as given under `hash: false`.
 * @param message - The message, or a digest the caller already built
 * @param options - Signing options, read for `hash`
 * @returns {Uint8Array} The digest
 */
function secp256k1Digest(message: string | Uint8Array, options: SigningOptions): Uint8Array {
  const bytes = messageBytes(message);
  return options.hash === false ? bytes : sha256(bytes);
}

/**
 * Sign a message: secp256k1 over its SHA-256 unless `hash` is false, ed25519 over the raw bytes.
 * @param message - The message to sign as a string or Uint8Array
 * @param keyPrivate - The private key as a hex string
 * @param options - Curve, hashing and recovery byte
 * @returns {string} The signature as a hex string
 */
export function signMessage(
  message: string | Uint8Array,
  keyPrivate: string,
  options: SigningOptions = {},
): string {
  /** Read as plain string: untyped callers can pass anything, the final throw guards them. */
  const curve: string = options.curve || "secp256k1";
  const recovered = readRecoveredFlag(options);
  if (curve === "secp256k1") {
    return signSecp256k1(
      secp256k1Digest(message, options),
      decodeKeyPrivate(keyPrivate),
      recovered,
    );
  }
  if (curve === "ed25519") {
    if (recovered) throw new Error("Recovered signatures are secp256k1 only");
    return ed25519.sign(messageBytes(message), Uint8Array.fromHex(keyPrivate)).toHex();
  }
  throw new Error(`Unsupported curve: ${curve}`);
}

/**
 * Check a signature of either length: 64 bytes on `r||s`, 65 bytes through the recovery byte.
 * @param signature - Signature as hex
 * @param messageHash - The digest that was signed
 * @param keyPublic - Public key as hex
 * @returns {boolean} Whether the signature matches the key
 */
function verifySecp256k1(signature: string, messageHash: Uint8Array, keyPublic: string): boolean {
  try {
    const keyPublicBytes = Uint8Array.fromHex(keyPublic);
    const signatureBytes = Uint8Array.fromHex(signature);
    if (signatureBytes.length === COMPACT_SIGNATURE_LENGTH + 1) {
      return verifyRecoveredSignature(signatureBytes, messageHash, keyPublicBytes);
    }
    return secp256k1.verify(signatureBytes, messageHash, keyPublicBytes, { prehash: false });
  } catch {
    return false;
  }
}

/**
 * Check an ed25519 signature, where bad hex is a failed check, not an error.
 * @param signature - Signature as hex
 * @param message - The signed bytes
 * @param keyPublic - Public key as hex
 * @returns {boolean} Whether the signature matches the key
 */
function verifyEd25519(signature: string, message: Uint8Array, keyPublic: string): boolean {
  try {
    const keyPublicBytes = Uint8Array.fromHex(keyPublic);
    return ed25519.verify(Uint8Array.fromHex(signature), message, keyPublicBytes);
  } catch {
    return false;
  }
}

/**
 * Verify a signature over the same bytes `signMessage` signs for that curve and `hash` setting.
 * @param message - The original message as a string or Uint8Array
 * @param signature - The signature as a hex string
 * @param keyPublic - The public key as a hex string
 * @param options - Curve and hashing, as given to `signMessage`
 * @returns {boolean} True if the signature is valid, false otherwise
 */
export function verifyMessage(
  message: string | Uint8Array,
  signature: string,
  keyPublic: string,
  options: SigningOptions = {},
): boolean {
  /** Read as plain string: untyped callers can pass anything, the final throw guards them. */
  const curve: string = options.curve || "secp256k1";
  if (curve === "secp256k1") {
    return verifySecp256k1(signature, secp256k1Digest(message, options), keyPublic);
  }
  if (curve === "ed25519") return verifyEd25519(signature, messageBytes(message), keyPublic);
  throw new Error(`Unsupported curve: ${curve}`);
}
