import { bech32 } from "@scure/base";

const ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
/** A version byte and the largest hash the spec defines, 64 bytes, fill 104 digits, the checksum 8 more. */
const MAX_PAYLOAD_DIGITS = 112;

/** What a CashAddr payload carries once its checksum holds and its version byte agrees with it. */
export interface CashAddrContent {
  /** Type field of the version byte: 0 pay-to-pubkey-hash, 1 pay-to-script-hash, and so on. */
  readonly type: number;
  readonly hash: Uint8Array;
}

/**
 * The CashAddr polymod, on BigInt because its 40-bit residue outgrows number's bitwise operators.
 * @param prefix - Lowercase prefix the checksum is taken under
 * @param digits - Payload digits, with the checksum or with eight zero digits in its place
 * @returns {bigint} Zero when the checksum holds
 */
function polymod(prefix: string, digits: readonly number[]): bigint {
  const prefixDigits = Array.from(prefix, (character) => (character.codePointAt(0) ?? 0) & 31);
  let checksum = 1n;
  for (const value of [...prefixDigits, 0, ...digits]) {
    const top = checksum >> 35n;
    checksum = ((checksum & 0x07ffffffffn) << 5n) ^ BigInt(value);
    for (const [bit, generator] of GENERATORS.entries()) {
      if ((top >> BigInt(bit)) & 1n) checksum ^= generator;
    }
  }
  return checksum ^ 1n;
}

/**
 * The version byte for a hash: type in bits 3 to 6, the size code in bits 0 to 2.
 * @param type - Address type, 0 to 15
 * @param length - Hash length in bytes
 * @returns {number} The version byte
 */
function versionByte(type: number, length: number): number {
  const size = [20, 24, 28, 32, 40, 48, 56, 64].indexOf(length);
  if (!Number.isInteger(type) || type < 0 || type > 15 || size === -1) {
    throw new RangeError(`CashAddr has no version for type ${type} over ${length} bytes`);
  }
  return (type << 3) | size;
}

/**
 * Encodes a hash as CashAddr with its prefix written out.
 * @param prefix - Lowercase network prefix, such as `bitcoincash` or `bchtest`
 * @param type - Address type, 0 for pay-to-pubkey-hash
 * @param hash - The hash the address pays to
 * @returns {string} The address, such as `bitcoincash:qz3yjg59ypg6jqpwhaxgvjj44jm4hdx0w5wsxw2qez`
 */
export function encodeCashAddr(prefix: string, type: number, hash: Uint8Array): string {
  const payload = bech32.toWords(Uint8Array.of(versionByte(type, hash.length), ...hash));
  const checksum = polymod(prefix, [...payload, 0, 0, 0, 0, 0, 0, 0, 0]);
  const checksumDigits = Array.from({ length: 8 }, (_, index) =>
    Number((checksum >> BigInt(5 * (7 - index))) & 31n),
  );
  return `${prefix}:${Array.from([...payload, ...checksumDigits], (digit) => ALPHABET[digit]).join("")}`;
}

/**
 * Payload digits behind an optional prefix, case judged over the whole string as the spec does.
 * @param address - Candidate address
 * @param prefix - Lowercase network prefix the address may carry
 * @returns {number[] | undefined} Payload digits including the checksum, or undefined
 */
function payloadDigits(address: string, prefix: string): number[] | undefined {
  const lower = address.toLowerCase();
  if (address !== lower && address !== address.toUpperCase()) return undefined;
  const payload = lower.startsWith(`${prefix}:`) ? lower.slice(prefix.length + 1) : lower;
  if (payload.length <= 8 || payload.length > MAX_PAYLOAD_DIGITS) return undefined;
  const digits = Array.from(payload, (character) => ALPHABET.indexOf(character));
  return digits.includes(-1) ? undefined : digits;
}

/**
 * Regroups the digits into the version byte and hash, as long as the padding is zero and the
 * version byte, with its reserved top bit clear, gives the hash the length it has.
 * @param digits - Payload digits without the checksum
 * @returns {CashAddrContent | undefined} Type and hash, or undefined
 */
function versionedHash(digits: readonly number[]): CashAddrContent | undefined {
  let bytes: Uint8Array;
  try {
    bytes = bech32.fromWords([...digits]);
  } catch {
    return undefined;
  }
  const version = bytes[0] ?? 0x80;
  if (version & 0x80) return undefined;
  const size = (20 + 4 * (version & 0x03)) * (version & 0x04 ? 2 : 1);
  return bytes.length === size + 1 ? { type: version >> 3, hash: bytes.subarray(1) } : undefined;
}

/**
 * Decodes CashAddr under one prefix, written or not, as Bitcoin Cash Node does: one case over the
 * whole string, checksum verified, padding zero, version byte in agreement with the hash length.
 * Which types and hash lengths a chain pays to is the caller's.
 * @param address - Candidate address
 * @param prefix - Lowercase network prefix the checksum is taken under
 * @returns {CashAddrContent | undefined} Type and hash, or undefined for anything else
 */
export function decodeCashAddr(address: string, prefix: string): CashAddrContent | undefined {
  const digits = payloadDigits(address, prefix);
  if (digits === undefined || polymod(prefix, digits) !== 0n) return undefined;
  return versionedHash(digits.slice(0, -8));
}
