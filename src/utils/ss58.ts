import { blake2b } from "@agntn/hashes";
import { base58 } from "@agntn/encodings/base58";
import { concatBytes } from "./bytes.ts";

/** Highest network prefix SS58 fits in its two byte form. */
export const MAX_SS58_PREFIX = 16_383;

/** Prefixes the SS58 registry reserves, which no address may carry. */
const RESERVED_PREFIXES: readonly number[] = [46, 47];

/** What every SS58 checksum hashes in front of the prefix and the account. */
const CHECKSUM_CONTEXT = new TextEncoder().encode("SS58PRE");

/** Bytes of an account ID, which is the ed25519 or sr25519 public key itself. */
const ACCOUNT_BYTES = 32;

/** Checksum bytes SS58 keeps after a 32-byte account. */
const CHECKSUM_BYTES = 2;

/**
 * Checks that a network prefix fits SS58 and is not one of the reserved two.
 * @param prefix - Network prefix, such as 0 for Polkadot or 42 for a generic Substrate chain
 * @returns {boolean} Whether an address may carry it
 */
export function isSS58Prefix(prefix: number): boolean {
  return (
    Number.isInteger(prefix) &&
    prefix >= 0 &&
    prefix <= MAX_SS58_PREFIX &&
    !RESERVED_PREFIXES.includes(prefix)
  );
}

/**
 * Writes the prefix the way SS58 does: one byte below 64, two bytes with the flag bit above.
 * @param prefix - Network prefix up to 16383
 * @returns {Uint8Array} One or two prefix bytes
 */
function prefixBytes(prefix: number): Uint8Array {
  if (prefix < 64) return Uint8Array.of(prefix);
  return Uint8Array.of(
    ((prefix & 0b1111_1100) >> 2) | 0b0100_0000,
    (prefix >> 8) | ((prefix & 0b11) << 6),
  );
}

/**
 * Reads the prefix back from the first two bytes of a decoded address.
 * @param first - First byte of the address
 * @param second - Second byte, read only in the two byte form
 * @returns {{ prefix: number; length: number } | undefined} The prefix and its byte length, undefined for a first byte of 128 or more
 */
function readPrefix(first: number, second: number): { prefix: number; length: number } | undefined {
  if (first < 64) return { prefix: first, length: 1 };
  if (first >= 128) return undefined;
  const lower = ((first & 0b0011_1111) << 2) | (second >> 6);
  return { prefix: lower | ((second & 0b0011_1111) << 8), length: 2 };
}

/**
 * The two checksum bytes of a prefix and an account.
 * @param body - Prefix bytes followed by the account
 * @returns {Uint8Array} The first two bytes of blake2b-512 over the context and the body
 */
function checksum(body: Uint8Array): Uint8Array {
  return blake2b(concatBytes(CHECKSUM_CONTEXT, body), 64).subarray(0, CHECKSUM_BYTES);
}

/**
 * Encodes a 32-byte account ID as an SS58 address.
 * @param account - The account ID, a 32-byte public key
 * @param prefix - Network prefix: 0 Polkadot, 2 Kusama, 42 any Substrate chain
 * @returns {string} The base58 address
 * @throws {RangeError} When the account is not 32 bytes or the prefix does not fit
 */
export function encodeSS58(account: Uint8Array, prefix: number): string {
  if (account.length !== ACCOUNT_BYTES) throw new RangeError("An SS58 account must be 32 bytes");
  if (!isSS58Prefix(prefix)) {
    throw new RangeError(`SS58 prefix must be 0 to ${MAX_SS58_PREFIX}, but not 46 or 47`);
  }
  const body = concatBytes(prefixBytes(prefix), account);
  return base58.encode(concatBytes(body, checksum(body)));
}

/**
 * Decodes an SS58 address that carries a 32-byte account, the form every key derives.
 * @param address - The base58 address
 * @returns {{ prefix: number; account: Uint8Array } | undefined} Prefix and account, undefined when the address is malformed or its checksum fails
 */
export function decodeSS58(address: string): { prefix: number; account: Uint8Array } | undefined {
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(address);
  } catch {
    return undefined;
  }
  const read = readPrefix(bytes[0] ?? 128, bytes[1] ?? 0);
  if (read === undefined || bytes.length !== read.length + ACCOUNT_BYTES + CHECKSUM_BYTES) {
    return undefined;
  }
  const body = bytes.subarray(0, read.length + ACCOUNT_BYTES);
  const expected = checksum(body);
  const given = bytes.subarray(body.length);
  if (expected[0] !== given[0] || expected[1] !== given[1] || !isSS58Prefix(read.prefix)) {
    return undefined;
  }
  return { prefix: read.prefix, account: body.slice(read.length) };
}
