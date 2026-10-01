import { ecb } from "@agntn/ciphers/aes";
import { create, sha256, type ScryptOptions } from "@agntn/hashes";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes } from "@noble/curves/utils.js";
import { generateAddressLegacy } from "../address.ts";
import { concatBytes } from "../bytes.ts";
import { decodeBase58Check } from "../encoding.ts";
import { encode as encodeWIF } from "../wif/index.ts";

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

/** A BIP38 key opened with its passphrase: the private key and the Bitcoin wallet it stands for. */
export interface DecryptedBIP38 {
  readonly privateKey: Uint8Array;
  readonly compressed: boolean;
  /** Mainnet WIF, compressed when the key says so. */
  readonly wif: string;
  /** Mainnet P2PKH address, the one the stored address hash belongs to. */
  readonly address: string;
}

/** The passphrase does not open the key: the address it gives misses the stored address hash. */
export class BIP38PassphraseError extends Error {
  constructor() {
    super("Wrong BIP38 passphrase: the address hash does not match");
    this.name = "BIP38PassphraseError";
  }
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

/**
 * scrypt with the costs BIP38 fixes for each step.
 * @param password - Passphrase or passpoint bytes
 * @param salt - Salt bytes
 * @param cost - N, r and p
 * @param keyLength - Output length in bytes
 * @returns {Uint8Array} The derived bytes
 */
function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  cost: { readonly N: number; readonly r: number; readonly p: number },
  keyLength: number,
): Uint8Array {
  const options: ScryptOptions = { salt, ...cost, keyLength, encoding: "binary" };
  const { digest } = create("scrypt").hash(password, options);
  if (!(digest instanceof Uint8Array)) throw new TypeError("scrypt returned text, not bytes");
  return digest;
}

/**
 * XOR of two byte arrays, as long as the first.
 * @param left - First bytes
 * @param right - Second bytes
 * @returns {Uint8Array} A new array
 */
function xor(left: Uint8Array, right: Uint8Array): Uint8Array {
  return left.map((byte, index) => byte ^ (right[index] ?? 0));
}

/**
 * Non-EC key: AES with the second half of the scrypt output, then XOR with the first.
 * @param payload - The 39 byte payload
 * @param passphrase - NFC passphrase as UTF-8
 * @returns {Uint8Array} 32 key bytes
 */
function decryptNonEc(payload: Uint8Array, passphrase: Uint8Array): Uint8Array {
  const derived = scrypt(passphrase, payload.slice(3, 7), { N: 16_384, r: 8, p: 8 }, 64);
  const halves = ecb(payload.slice(7, 39), derived.slice(32), "decrypt");
  return xor(halves, derived.slice(0, 32));
}

/**
 * EC multiply key: the passfactor times `factorb`, the double SHA-256 of the hidden seed.
 * @param payload - The 39 byte payload
 * @param passphrase - NFC passphrase as UTF-8
 * @param hasLotSequence - Flag bit 0x04
 * @returns {Uint8Array} 32 key bytes
 */
function decryptEcMultiply(
  payload: Uint8Array,
  passphrase: Uint8Array,
  hasLotSequence: boolean,
): Uint8Array {
  const ownerEntropy = payload.slice(7, 15);
  const ownerSalt = hasLotSequence ? ownerEntropy.slice(0, 4) : ownerEntropy;
  const prefactor = scrypt(passphrase, ownerSalt, { N: 16_384, r: 8, p: 8 }, 32);
  const passfactor = hasLotSequence
    ? sha256(sha256(concatBytes(prefactor, ownerEntropy)))
    : prefactor;
  if (!secp256k1.utils.isValidSecretKey(passfactor)) throw new BIP38PassphraseError();
  const passpoint = secp256k1.getPublicKey(passfactor, true);
  const derived = scrypt(passpoint, payload.slice(3, 15), { N: 1024, r: 1, p: 1 }, 64);
  const key = derived.slice(32);
  const part2 = xor(ecb(payload.slice(23, 39), key, "decrypt"), derived.slice(16, 32));
  const part1 = xor(
    ecb(concatBytes(payload.slice(15, 23), part2.slice(0, 8)), key, "decrypt"),
    derived.slice(0, 16),
  );
  const factorb = sha256(sha256(concatBytes(part1, part2.slice(8))));
  const { Fn } = secp256k1.Point;
  return Fn.toBytes(Fn.mul(Fn.fromBytes(passfactor), Fn.create(Fn.fromBytes(factorb, true))));
}

/**
 * Open a BIP38 key in either mode, NFC passphrase, checked by the address hash it stores.
 * @param encrypted - BIP38 key starting with `6P`
 * @param passphrase - Passphrase, any string, empty included
 * @returns {DecryptedBIP38} Private key, compression, mainnet WIF and P2PKH address
 * @throws {BIP38PassphraseError} When the passphrase is wrong
 */
export function decrypt(encrypted: string, passphrase: string): DecryptedBIP38 {
  const payload = readPayload(encrypted);
  if (typeof passphrase !== "string") throw new TypeError("BIP38 passphrase must be a string");
  const mode: BIP38Mode = payload[1] === NON_EC_PREFIX ? "non-ec" : "ec-multiply";
  const flagByte = payload[2] ?? 0;
  const hasLotSequence = readFlags(mode, flagByte);
  const compressed = (flagByte & COMPRESSED) !== 0;
  const password = new TextEncoder().encode(passphrase.normalize("NFC"));
  const privateKey =
    mode === "non-ec"
      ? decryptNonEc(payload, password)
      : decryptEcMultiply(payload, password, hasLotSequence);
  if (!secp256k1.utils.isValidSecretKey(privateKey)) throw new BIP38PassphraseError();
  const publicKey = secp256k1.getPublicKey(privateKey, compressed).toHex();
  const address = generateAddressLegacy(publicKey, { bytesVersion: 0x00 });
  if (!equalBytes(addressHashOf(address), payload.slice(3, 7))) throw new BIP38PassphraseError();
  return {
    privateKey,
    compressed,
    wif: encodeWIF(privateKey.toHex(), { chain: "bitcoin", compressed }),
    address,
  };
}
