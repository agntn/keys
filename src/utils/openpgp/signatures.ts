import { concatBytes } from "../bytes.ts";
import { hashAlgorithm, hashName, saltSize } from "./algorithms.ts";
import { type Reader, createReader, type Subpacket, bigEndian, readSubpackets } from "./packets.ts";

/** A version 4 or 6 signature packet, RFC 9580 §5.2.3, with the subpackets this module reads. */
export interface Signature {
  readonly version: 4 | 6;
  /** Signature Type ID: 0x01 for text, 0x13 for a user ID, 0x18 for a subkey binding and so on. */
  readonly type: number;
  readonly algorithm: number;
  readonly hashId: number;
  /** The packet from its version through the hashed subpackets, which the trailer repeats. */
  readonly hashedBody: Uint8Array;
  readonly left16: Uint8Array;
  readonly salt: Uint8Array;
  /** Algorithm-specific signature value. */
  readonly value: Uint8Array;
  /** Creation time in seconds since 1970, from the hashed area. */
  readonly created: number;
  readonly issuerFingerprint?: Uint8Array;
  readonly issuerKeyId?: Uint8Array;
  /** Seconds after creation the signature stops being valid, from subpacket 3. */
  readonly expiresAfter?: number;
  /** Seconds after the key's creation it expires, from subpacket 9 of a self-signature. */
  readonly keyExpiresAfter?: number;
  /** First byte of the key flags, subpacket 27. */
  readonly keyFlags?: number;
  readonly primaryUserId: boolean;
  /** Reason for revocation, subpacket 29: its code byte. */
  readonly revocationCode?: number;
  /** Embedded signature bodies, subpacket 32, where a signing subkey keeps its back signature. */
  readonly embedded: readonly Uint8Array[];
  /** Type of a hashed subpacket marked critical that this module doesn't know. */
  readonly unknownCritical?: number;
}

/** Subpacket types this module knows, critical or not: RFC 9580 Table 5 minus notations. */
const KNOWN_SUBPACKETS = new Set([
  2, 3, 4, 5, 7, 9, 11, 12, 16, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 39,
]);

/**
 * Reads a 4-byte time or duration.
 * @param body - Subpacket body
 * @returns {number} Seconds
 * @throws {TypeError} When the body isn't 4 bytes
 */
function seconds(body: Uint8Array): number {
  if (body.length !== 4) throw new TypeError("OpenPGP time subpacket must be 4 bytes");
  return new DataView(body.buffer, body.byteOffset).getUint32(0);
}

/**
 * Finds the first subpacket of a type.
 * @param subpackets - Subpackets to search
 * @param type - Subpacket type
 * @returns {Uint8Array | undefined} Its body
 */
function find(subpackets: readonly Subpacket[], type: number): Uint8Array | undefined {
  return subpackets.find((subpacket) => subpacket.type === type)?.body;
}

/**
 * Reads the issuer subpackets from either area, since GnuPG puts the key ID in the unhashed one.
 * @param all - Hashed then unhashed subpackets
 * @param version - Signature version, which the fingerprint's version byte must repeat
 * @returns {Pick<Signature, "issuerFingerprint" | "issuerKeyId">} Whatever the signature names
 * @throws {TypeError} When the issuer fingerprint names another key version
 */
function issuerOf(
  all: readonly Subpacket[],
  version: number,
): Pick<Signature, "issuerFingerprint" | "issuerKeyId"> {
  const fingerprint = find(all, 33);
  const keyId = find(all, 16);
  if (fingerprint !== undefined && fingerprint[0] !== version) {
    throw new TypeError("OpenPGP issuer fingerprint version must match the signature version");
  }
  return {
    ...(fingerprint === undefined ? {} : { issuerFingerprint: fingerprint.slice(1) }),
    ...(keyId?.length === 8 ? { issuerKeyId: keyId } : {}),
  };
}

/**
 * Reads the optional numbers of the hashed area.
 * @param hashed - Hashed subpackets
 * @returns {Partial<Signature>} Expirations, flags and revocation code that are present
 */
function hashedFields(hashed: readonly Subpacket[]): Partial<Signature> {
  const expires = find(hashed, 3);
  const keyExpires = find(hashed, 9);
  const flags = find(hashed, 27)?.[0];
  const reason = find(hashed, 29)?.[0];
  return {
    ...(expires === undefined ? {} : { expiresAfter: seconds(expires) }),
    ...(keyExpires === undefined ? {} : { keyExpiresAfter: seconds(keyExpires) }),
    ...(flags === undefined ? {} : { keyFlags: flags }),
    ...(reason === undefined ? {} : { revocationCode: reason }),
  };
}

/**
 * Reads the salt of a version 6 signature, whose size the hash fixes.
 * @param reader - Reader past the left 16 bits
 * @param version - Signature version
 * @param hashId - The signature's hash ID
 * @returns {Uint8Array} The salt, empty for version 4
 * @throws {TypeError} When the salt size doesn't fit the hash
 */
function readSalt(reader: Reader, version: 4 | 6, hashId: number): Uint8Array {
  if (version === 4) return new Uint8Array(0);
  const expected = saltSize(hashId);
  if (expected === 0)
    throw new TypeError(`OpenPGP version 6 signatures can't use ${hashName(hashId)}`);
  const size = reader.byte();
  if (size !== expected) {
    throw new TypeError(`OpenPGP ${hashName(hashId)} signature salt must be ${expected} bytes`);
  }
  return reader.read(size);
}

/**
 * Reads a version 4 or 6 Signature packet body.
 * @param body - Packet body
 * @returns {Signature} The parsed signature
 * @throws {RangeError} For another version or a hash RFC 9580 doesn't define
 * @throws {TypeError} When the packet is malformed or has no creation time
 */
export function readSignature(body: Uint8Array): Signature {
  const reader = createReader(body);
  const version = reader.byte();
  if (version !== 4 && version !== 6)
    throw new RangeError(`OpenPGP signature version ${version} isn't supported`);
  const width = version === 4 ? 2 : 4;
  const [type, algorithm, hashId] = [reader.byte(), reader.byte(), reader.byte()];
  const hashed = readSubpackets(reader.read(reader.uint(width)));
  const hashedBody = body.slice(0, reader.offset());
  const unhashed = readSubpackets(reader.read(reader.uint(width)));
  const left16 = reader.read(2);
  const salt = readSalt(reader, version, hashId);
  const created = find(hashed, 2);
  if (created === undefined) throw new TypeError("OpenPGP signature has no hashed creation time");
  const unknown = hashed.find(
    (subpacket) => subpacket.critical && !KNOWN_SUBPACKETS.has(subpacket.type),
  );
  return {
    version,
    type,
    algorithm,
    hashId,
    hashedBody,
    left16,
    salt,
    value: reader.rest(),
    created: seconds(created),
    ...issuerOf([...hashed, ...unhashed], version),
    ...hashedFields(hashed),
    primaryUserId: find(hashed, 25)?.[0] === 1,
    embedded: [...hashed, ...unhashed]
      .filter((subpacket) => subpacket.type === 32)
      .map((s) => s.body),
    ...(unknown === undefined ? {} : { unknownCritical: unknown.type }),
  };
}

/**
 * Reads a signature, undefined when it can't: RFC 9580 §5.2.5 ignores those instead of failing.
 * @param body - Signature packet body
 * @returns {Signature | undefined} The signature
 */
export function tryReadSignature(body: Uint8Array): Signature | undefined {
  try {
    return readSignature(body);
  } catch {
    return undefined;
  }
}

/**
 * Hashes the signed data with the signature's trailer, RFC 9580 §5.2.4.
 * @param signature - The signature
 * @param data - What it signs: canonical text, or framed keys and user IDs
 * @returns {Uint8Array} The digest the signature value covers
 * @throws {RangeError} When the hash isn't one this module computes
 */
export function signatureDigest(signature: Signature, data: Uint8Array): Uint8Array {
  const trailer = concatBytes(
    signature.hashedBody,
    Uint8Array.of(signature.version, 0xff),
    bigEndian(signature.hashedBody.length, 4),
  );
  return hashAlgorithm(signature.hashId).digest(concatBytes(signature.salt, data, trailer));
}
