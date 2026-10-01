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
 * Sign a prepared digest, with or without the recovery byte Ethereum writes as `v`.
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
    // In @noble/curves v2, sign() returns Uint8Array directly (compact format)
    return secp256k1.sign(messageHash, keyPrivateBytes, { prehash: false }).toHex();
  }
  // v2 puts the recovery byte first; Ethereum, TRON and ecrecover want it last, as 27 or 28.
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
 * Signs a message using the appropriate elliptic curve
 * `@noble/curves` v2 hashes by default, so the digest built here goes in with `prehash: false`.
 *
 * @param message - The message to sign as a string or Uint8Array
 * @param keyPrivate - The private key as a hex string
 * @param options - Options for signature generation including curve type
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

  // Convert message to Uint8Array if it's a string
  let messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

  // Different handling based on curve type
  if (curve === "secp256k1") {
    // For secp256k1, we typically hash the message first with SHA-256
    // Unless options.hash is explicitly set to false
    if (options.hash !== false) {
      messageBytes = sha256(messageBytes);
    }

    return signSecp256k1(messageBytes, decodeKeyPrivate(keyPrivate), recovered);
  } else if (curve === "ed25519") {
    if (recovered) {
      throw new Error("Recovered signatures are secp256k1 only");
    }

    // Ed25519 doesn't typically prehash the message
    const signature = ed25519.sign(messageBytes, Uint8Array.fromHex(keyPrivate));
    return signature.toHex();
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
    // In @noble/curves v2, verify() accepts Uint8Array signature directly
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
 * Verifies a signature using the appropriate elliptic curve
 * Passes `prehash: false` like `signMessage`, so the bytes are checked exactly as hashed here.
 *
 * @param message - The original message as a string or Uint8Array
 * @param signature - The signature as a hex string
 * @param keyPublic - The public key as a hex string
 * @param options - Options for signature verification including curve type
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

  // Convert message to Uint8Array if it's a string
  let messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;

  // Different handling based on curve type
  if (curve === "secp256k1") {
    // For secp256k1, we typically hash the message first with SHA-256
    // Unless options.hash is explicitly set to false
    if (options.hash !== false) {
      messageBytes = sha256(messageBytes);
    }

    return verifySecp256k1(signature, messageBytes, keyPublic);
  } else if (curve === "ed25519") {
    // Ed25519 doesn't typically prehash the message
    try {
      const keyPublicBytes = Uint8Array.fromHex(keyPublic);
      return ed25519.verify(Uint8Array.fromHex(signature), messageBytes, keyPublicBytes);
    } catch {
      return false;
    }
  }

  throw new Error(`Unsupported curve: ${curve}`);
}
