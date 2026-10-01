import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import type { MessageSigner } from "../../types.ts";
import { concatBytes } from "../bytes.ts";
import { decodeKeyPrivate, decodePublicPoint } from "./decode.ts";

/** Header byte plus 32 bytes each of `r` and `s`. */
const SIGNATURE_LENGTH = 65;

/** Core's header for an uncompressed key is 27 plus the recovery id. */
const HEADER_BASE = 27;

/** A compressed key adds 4 to the header. */
const HEADER_COMPRESSED = 4;

/** BIP137 headers for P2SH-P2WPKH, then P2WPKH; both keys are compressed. */
const HEADER_P2SH_P2WPKH = 35;
const HEADER_P2WPKH = 39;

/** Last BIP137 header, P2WPKH with recovery id 3. */
const HEADER_LAST = 42;

const SIGNATURE_SHAPE = "Message signature must be 65 bytes of base64: a header byte, then r and s";

/**
 * Tell Core's base64 signature from the hex forms, so callers can route it before decoding.
 * @param signature - Signature as the caller passed it
 * @returns {boolean} True when the text is base64 of exactly 65 bytes
 */
export function isCompactSignature(signature: string): boolean {
  try {
    return Uint8Array.fromBase64(signature).length === SIGNATURE_LENGTH;
  } catch {
    return false;
  }
}

/**
 * Sign a prepared digest the way `signmessage` in Bitcoin Core, dcrd and their forks does.
 * @param messageHash - The digest to sign
 * @param keyPrivate - The private key as hex
 * @param compressed - Whether the header names the compressed key and its address
 * @returns {string} Base64 of the header byte, then `r` and `s`
 */
export function signCompact(
  messageHash: Uint8Array,
  keyPrivate: string,
  compressed: boolean,
): string {
  const signature = secp256k1.sign(messageHash, decodeKeyPrivate(keyPrivate), {
    prehash: false,
    format: "recovered",
  });
  const recovery = signature[0];
  if (recovery === undefined) throw new Error("Missing recovery byte");
  const header = HEADER_BASE + recovery + (compressed ? HEADER_COMPRESSED : 0);
  return concatBytes(Uint8Array.of(header), signature.subarray(1)).toBase64();
}

/**
 * Recover the key and address type a Core style signature's header names.
 * Any well formed signature recovers some key, so compare it with the expected one.
 * @param messageHash - The digest that was signed
 * @param signature - Base64 of the header byte, then `r` and `s`
 * @returns {MessageSigner} The recovered key and the address type of the header
 * @throws {TypeError} When the signature is not 65 bytes of base64 or its header is out of range
 * @throws {RangeError} When `r` and `s` recover no key
 */
export function recoverCompact(messageHash: Uint8Array, signature: string): MessageSigner {
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.fromBase64(signature);
  } catch {
    throw new TypeError(SIGNATURE_SHAPE);
  }
  const header = bytes[0];
  if (bytes.length !== SIGNATURE_LENGTH || header === undefined)
    throw new TypeError(SIGNATURE_SHAPE);
  if (header < HEADER_BASE || header > HEADER_LAST) {
    throw new TypeError(
      `Message signature header must be ${HEADER_BASE} to ${HEADER_LAST}, as Core and BIP137 write it`,
    );
  }
  const compressed = header >= HEADER_BASE + HEADER_COMPRESSED;
  let point: ReturnType<typeof secp256k1.Point.fromBytes>;
  try {
    point = secp256k1.Signature.fromBytes(bytes.subarray(1), "compact")
      .addRecoveryBit((header - HEADER_BASE) % HEADER_COMPRESSED)
      .recoverPublicKey(messageHash);
  } catch {
    throw new RangeError("Message signature recovers no public key");
  }
  const addressType =
    header >= HEADER_P2WPKH ? "segwit" : header >= HEADER_P2SH_P2WPKH ? "p2sh" : "legacy";
  return { publicKey: point.toBytes(compressed).toHex(), addressType };
}

/**
 * Check a Core style signature by recovering its key and comparing points with `keyPublic`.
 * @param messageHash - The digest that was signed
 * @param signature - Base64 of the header byte, then `r` and `s`
 * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
 * @returns {boolean} True when the signature recovers that key; false for any unreadable input
 */
export function verifyCompact(
  messageHash: Uint8Array,
  signature: string,
  keyPublic: string,
): boolean {
  try {
    const signer = recoverCompact(messageHash, signature);
    return equalBytes(
      decodePublicPoint(signer.publicKey).toBytes(true),
      decodePublicPoint(keyPublic).toBytes(true),
    );
  } catch {
    return false;
  }
}
