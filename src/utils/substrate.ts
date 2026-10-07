import { Sha512Hasher, blake2b, pbkdf2 } from "@agntn/hashes";
import { concatBytes } from "./bytes.ts";

/** A Substrate derivation path: `//hard` and `/soft` junctions, nothing else. */
const JUNCTIONS = /^(?:\/\/?[^/]+)+$/u;

/** One junction of a path, its slashes captured apart from its name. */
const JUNCTION = /\/(\/?)([^/]+)/gu;

/** A junction name both subkey and polkadot.js read as a number. */
const NUMBER = /^\d+$/u;

/** A junction polkadot.js decodes as hex, while subkey hashes the same text as a name. */
const HEX = /^0x(?:[0-9a-fA-F]{2})*$/u;

/** Largest number a junction holds; subkey reads a bigger one as text, polkadot.js as 256 bits. */
const MAX_JUNCTION_NUMBER = 2n ** 64n - 1n;

/** Bytes of a chain code, the space a junction fills or hashes down to. */
const CHAIN_CODE_BYTES = 32;

/**
 * SCALE's compact length prefix for the byte counts a path can hold.
 * @param length - Byte count, below 2^30
 * @returns {Uint8Array} One, two or four prefix bytes
 */
function compactLength(length: number): Uint8Array {
  if (length < 64) return Uint8Array.of(length << 2);
  if (length < 16_384) return Uint8Array.of(((length << 2) | 1) & 0xff, length >> 6);
  const value = (length << 2) | 2;
  return Uint8Array.of(value & 0xff, (value >> 8) & 0xff, (value >> 16) & 0xff, value >>> 24);
}

/**
 * Text as SCALE encodes it: the compact byte length, then the UTF-8 bytes.
 * @param text - The text
 * @returns {Uint8Array} The encoded text
 */
function scaleText(text: string): Uint8Array {
  const bytes = new TextEncoder().encode(text);
  return concatBytes(compactLength(bytes.length), bytes);
}

/** What ed25519 hard derivation hashes in front of the parent seed. */
const ED25519_HDKD = scaleText("Ed25519HDKD");

/**
 * A number junction as its 8 little-endian bytes, the u64 subkey encodes.
 * @param value - The number, at most 2^64 - 1
 * @returns {Uint8Array} 8 bytes, low byte first
 */
function u64Bytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, value, true);
  return bytes;
}

/**
 * The chain code of one junction: a number as u64, a name as SCALE text, hashed when too long.
 * @param name - The junction without its slashes
 * @returns {Uint8Array} The 32-byte chain code
 * @throws {RangeError} For a junction subkey and polkadot.js would read apart
 */
function chainCode(name: string): Uint8Array {
  if (HEX.test(name)) {
    throw new RangeError(
      "A 0x junction is hex to polkadot.js and a name to subkey, so it has no one key",
    );
  }
  const number = NUMBER.test(name) ? BigInt(name) : undefined;
  if (number !== undefined && number > MAX_JUNCTION_NUMBER) {
    throw new RangeError(
      "A number junction must fit 64 bits; polkadot.js and subkey read a bigger one apart",
    );
  }
  const bytes = number === undefined ? scaleText(name) : u64Bytes(number);
  if (bytes.length > CHAIN_CODE_BYTES) return blake2b(bytes, CHAIN_CODE_BYTES);
  const code = new Uint8Array(CHAIN_CODE_BYTES);
  code.set(bytes);
  return code;
}

/**
 * Splits a Substrate path into chain codes, refusing the soft junctions ed25519 cannot walk.
 * @param path - `//hard` junctions such as `//polkadot//0`; empty or `m` for the root key
 * @returns {Uint8Array[]} One chain code per junction, in order
 * @throws {RangeError} When the path is malformed, holds a soft junction or a `///password`
 */
export function parseHardJunctions(path: string): Uint8Array[] {
  if (path === "" || path === "m") return [];
  if (path.includes("///")) {
    throw new RangeError("Pass the ///password part of a Substrate URI as the passphrase instead");
  }
  if (!JUNCTIONS.test(path)) {
    throw new RangeError(
      "A Substrate path is junctions such as //polkadot//0, or m for the root key",
    );
  }
  return Array.from(path.matchAll(JUNCTION), ([, hard, name = ""]) => {
    if (hard !== "/") {
      throw new RangeError("A soft /junction needs sr25519; ed25519 derives hard //junctions only");
    }
    return chainCode(name);
  });
}

/**
 * The mini secret Substrate keys start from: PBKDF2 over the mnemonic entropy, not the BIP39 seed.
 * @param entropy - Entropy behind the mnemonic
 * @param password - The password of the Substrate URI, which takes the place of a BIP39 passphrase
 * @returns {Uint8Array} The 32-byte mini secret
 */
export function miniSecret(entropy: Uint8Array, password = ""): Uint8Array {
  const salt = new TextEncoder().encode(`mnemonic${password}`);
  return pbkdf2(() => new Sha512Hasher(), entropy, salt, 2048, 64).slice(0, 32);
}

/**
 * Walks an ed25519 seed down hard junctions the way subkey and polkadot.js do.
 * @param seed - The 32-byte parent seed, the mini secret at the root
 * @param chainCodes - Chain codes from `parseHardJunctions`
 * @returns {Uint8Array} The 32-byte seed of the child key
 */
export function deriveEd25519Hard(seed: Uint8Array, chainCodes: readonly Uint8Array[]): Uint8Array {
  return chainCodes.reduce(
    (parent, code) => blake2b(concatBytes(ED25519_HDKD, parent, code), 32),
    seed,
  );
}
