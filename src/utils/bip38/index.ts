import { sha256 } from "@agntn/hashes";
import { equalBytes } from "@noble/curves/utils.js";
import { decodeBase58Check } from "../encoding.ts";

/** How the key was encrypted: from a private key, or from an owner's intermediate code. */
export type BIP38Mode = "non-ec" | "ec-multiply";

/** What a BIP38 key tells without its passphrase. */
export interface BIP38Inspection {
  readonly mode: BIP38Mode;
  /** The raw flag byte, reserved bits already checked. */
  readonly flagByte: number;
  /** Whether the address uses the compressed public key. */
  readonly compressed: boolean;
  /** Whether the owner entropy carries a lot and sequence number (EC multiply only). */
  readonly hasLotSequence: boolean;
  /** First four bytes of SHA256(SHA256(address)) as hex, also the scrypt salt. */
  readonly addressHash: string;
  /** EC multiply only: owner salt plus lot and sequence, or eight bytes of salt. */
  readonly ownerEntropy?: string;
  readonly ownerSalt?: string;
  readonly lot?: number;
  readonly sequence?: number;
  /** Set when an address was given: whether its hash equals `addressHash`. */
  readonly addressMatches?: boolean;
}

/** Longer than any 39 byte payload in base58 with its checksum. */
const MAX_BIP38_LENGTH = 64;

const NON_EC_PREFIX = 0x42;
const EC_MULTIPLY_PREFIX = 0x43;
const COMPRESSED = 0x20;
const LOT_SEQUENCE = 0x04;

/**
 * First four bytes of the double SHA-256 of an address string, as BIP38 stores it.
 * @param address - Address text, hashed as ASCII
 * @returns {Uint8Array} Four byte address hash
 */
function addressHashOf(address: string): Uint8Array {
  return sha256(sha256(new TextEncoder().encode(address))).slice(0, 4);
}

/**
 * Read the flag byte, rejecting bits BIP38 reserves for its mode.
 * @param mode - Mode from the prefix
 * @param flagByte - Flag byte after the prefix
 * @returns {boolean} Whether the owner entropy holds a lot and sequence number
 */
function readFlags(mode: BIP38Mode, flagByte: number): boolean {
  if (mode === "non-ec") {
    if ((flagByte & ~COMPRESSED) !== 0xc0) {
      throw new Error("BIP38 non-EC flag byte must be 0xc0 or 0xe0");
    }
    return false;
  }
  if ((flagByte & ~(COMPRESSED | LOT_SEQUENCE)) !== 0) {
    throw new Error("BIP38 EC multiply flag byte sets reserved bits");
  }
  return (flagByte & LOT_SEQUENCE) !== 0;
}

/**
 * Decode the Base58Check payload and check its length and prefix, without echoing the key.
 * @param encrypted - BIP38 key starting with `6P`
 * @returns {Uint8Array} The 39 byte payload
 */
function readPayload(encrypted: string): Uint8Array {
  if (typeof encrypted !== "string" || encrypted.length === 0) {
    throw new Error("BIP38 key must be a non-empty string");
  }
  if (encrypted.length > MAX_BIP38_LENGTH) {
    throw new Error("Invalid BIP38 key length");
  }
  let payload: Uint8Array;
  try {
    payload = decodeBase58Check(encrypted);
  } catch {
    throw new Error("Invalid BIP38 base58 encoding or checksum");
  }
  if (payload.length !== 39) {
    throw new Error("Invalid BIP38 payload length");
  }
  if (payload[0] !== 0x01 || (payload[1] !== NON_EC_PREFIX && payload[1] !== EC_MULTIPLY_PREFIX)) {
    throw new Error("Not a BIP38 key: expected prefix 0x0142 or 0x0143");
  }
  return payload;
}

/**
 * Compare an address with the stored hash.
 * @param address - Address text
 * @param addressHash - Four bytes from the key
 * @returns {boolean} Whether the address hashes to the stored bytes
 */
function matchesAddress(address: unknown, addressHash: Uint8Array): boolean {
  if (typeof address !== "string" || address.length === 0) {
    throw new Error("BIP38 address must be a non-empty string");
  }
  return equalBytes(addressHashOf(address), addressHash);
}

/**
 * Read a BIP38 encrypted private key without its passphrase. Nothing here decrypts: the result
 * holds only the public header, and an address check compares the stored address hash.
 * @param encrypted - BIP38 key starting with `6P`
 * @param options - An address to check against the stored address hash
 * @returns {BIP38Inspection} Mode, flags, address hash and, for EC multiply, owner entropy
 */
export function inspect(
  encrypted: string,
  options: { readonly address?: string } = {},
): BIP38Inspection {
  const payload = readPayload(encrypted);
  const mode: BIP38Mode = payload[1] === NON_EC_PREFIX ? "non-ec" : "ec-multiply";
  const flagByte = payload[2] ?? 0;
  const hasLotSequence = readFlags(mode, flagByte);
  const addressHash = payload.slice(3, 7);
  const inspection: BIP38Inspection = {
    mode,
    flagByte,
    compressed: (flagByte & COMPRESSED) !== 0,
    hasLotSequence,
    addressHash: addressHash.toHex(),
    ...(mode === "ec-multiply" ? readOwnerEntropy(payload.slice(7, 15), hasLotSequence) : {}),
  };
  if (options.address === undefined) return inspection;
  return { ...inspection, addressMatches: matchesAddress(options.address, addressHash) };
}

/**
 * Split EC multiply owner entropy into salt and, when flagged, lot and sequence.
 * @param ownerEntropy - Eight bytes after the address hash
 * @param hasLotSequence - Flag bit 0x04
 * @returns {object} Owner entropy, salt, and the lot and sequence numbers when present
 */
function readOwnerEntropy(ownerEntropy: Uint8Array, hasLotSequence: boolean) {
  if (!hasLotSequence) {
    return { ownerEntropy: ownerEntropy.toHex(), ownerSalt: ownerEntropy.toHex() };
  }
  const lotSequence = new DataView(ownerEntropy.buffer, ownerEntropy.byteOffset + 4, 4).getUint32(
    0,
  );
  return {
    ownerEntropy: ownerEntropy.toHex(),
    ownerSalt: ownerEntropy.slice(0, 4).toHex(),
    lot: Math.floor(lotSequence / 4096),
    sequence: lotSequence % 4096,
  };
}
