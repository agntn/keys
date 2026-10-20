import { sha1, sha256 } from "@agntn/hashes";
import { concatBytes } from "../bytes.ts";
import { type KeyMaterial, readKeyMaterial } from "./algorithms.ts";
import {
  type Packet,
  type Reader,
  createReader,
  bigEndian,
  isIgnorable,
  readPackets,
} from "./packets.ts";
import { type Signature, tryReadSignature } from "./signatures.ts";

/** A version 4 or 6 public key or subkey packet, RFC 9580 §5.5.2. */
export interface PublicKey {
  readonly version: 4 | 6;
  /** Creation time in seconds since 1970. */
  readonly created: number;
  readonly algorithm: number;
  readonly body: Uint8Array;
  readonly material: KeyMaterial;
  readonly fingerprint: Uint8Array;
  readonly keyId: Uint8Array;
}

/** A user ID with the signatures that follow it. */
export interface UserId {
  readonly id: Uint8Array;
  readonly signatures: readonly Signature[];
}

/** A subkey with the signatures that follow it. */
export interface Subkey {
  readonly key: PublicKey;
  readonly signatures: readonly Signature[];
}

/** A Transferable Public Key, RFC 9580 §10.1, with the signatures each part carries. */
export interface Certificate {
  readonly primary: PublicKey;
  /** Direct key signatures and key revocations right after the primary key. */
  readonly direct: readonly Signature[];
  readonly userIds: readonly UserId[];
  /** User Attributes, a photo ID say, which certify the key the same way a user ID does. */
  readonly userAttributes: readonly UserId[];
  readonly subkeys: readonly Subkey[];
}

/** Packet tags of Secret Key and Secret Subkey. */
const SECRET_TAGS = new Set([5, 7]);

/** Trust and Marker packets, which carry nothing a verifier reads. */
const SKIPPED_TAGS = new Set([10, 12]);

/**
 * Frames a key body for hashing: 0x99 and a 2-byte length for version 4, 0x9B and 4 bytes for 6.
 * @param version - Key version
 * @param body - Key packet body
 * @returns {Uint8Array} The framed body
 */
function frameBody(version: 4 | 6, body: Uint8Array): Uint8Array {
  return version === 4
    ? concatBytes(Uint8Array.of(0x99), bigEndian(body.length, 2), body)
    : concatBytes(Uint8Array.of(0x9b), bigEndian(body.length, 4), body);
}

/**
 * Frames a key the way signatures over keys hash it, RFC 9580 §5.2.4.
 * @param key - The key
 * @returns {Uint8Array} The framed body
 */
export function frameKey(key: PublicKey): Uint8Array {
  return frameBody(key.version, key.body);
}

/**
 * Frames a user ID for a version 4 or 6 certification: 0xB4 and a 4-byte length.
 * @param id - User ID bytes
 * @returns {Uint8Array} The framed user ID
 */
export function frameUserId(id: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(0xb4), bigEndian(id.length, 4), id);
}

/**
 * Frames a User Attribute for a certification: 0xD1 and a 4-byte length, RFC 9580 §5.2.4.
 * @param attribute - User Attribute packet body
 * @returns {Uint8Array} The framed attribute
 */
export function frameUserAttribute(attribute: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(0xd1), bigEndian(attribute.length, 4), attribute);
}

/**
 * Reads the material field of a key body, length-prefixed in version 6.
 * @param reader - Reader past the algorithm byte
 * @param version - Key version
 * @returns {Uint8Array} Material bytes
 * @throws {TypeError} When a version 6 count disagrees with the packet
 */
function readMaterialBytes(reader: Reader, version: 4 | 6): Uint8Array {
  if (version === 4) return reader.rest();
  const material = reader.read(reader.uint(4));
  if (!reader.done()) throw new TypeError("OpenPGP version 6 key material count is wrong");
  return material;
}

/**
 * Reads a Public Key or Public Subkey packet body and computes its fingerprint, RFC 9580 §5.5.4.
 * @param body - Packet body
 * @returns {PublicKey} The key
 * @throws {RangeError} For a key version other than 4 or 6, or numbers past the size cap
 * @throws {TypeError} When the material is malformed, or a version 6 key uses a legacy algorithm
 */
export function readPublicKey(body: Uint8Array): PublicKey {
  const reader = createReader(body);
  const version = reader.byte();
  if (version !== 4 && version !== 6)
    throw new RangeError(`OpenPGP key version ${version} isn't supported`);
  const created = reader.uint(4);
  const algorithm = reader.byte();
  if (version === 6 && algorithm === 22) {
    throw new TypeError("OpenPGP version 6 keys must not use EdDSALegacy");
  }
  const material = readKeyMaterial(algorithm, readMaterialBytes(reader, version));
  const framed = frameBody(version, body);
  const fingerprint = version === 4 ? sha1(framed) : sha256(framed);
  const keyId = version === 4 ? fingerprint.slice(12) : fingerprint.slice(0, 8);
  return { version, created, algorithm, body, material, fingerprint, keyId };
}

/** Collects the parts of a key block as its packets arrive. */
class CertificateBuilder {
  readonly #direct: Signature[] = [];
  readonly #userIds: { id: Uint8Array; signatures: Signature[] }[] = [];
  readonly #userAttributes: { id: Uint8Array; signatures: Signature[] }[] = [];
  readonly #subkeys: { key: PublicKey; signatures: Signature[] }[] = [];
  #primary: PublicKey | undefined;
  #target: Signature[] = this.#direct;

  /**
   * Takes the next packet.
   * @param packet - One packet of the block
   * @throws {TypeError} For a secret key, a second key or a packet a key block can't hold
   */
  add(packet: Packet): void {
    if (SECRET_TAGS.has(packet.tag)) {
      throw new TypeError("This is a private key block. Pass the public key only");
    }
    if (SKIPPED_TAGS.has(packet.tag) || isIgnorable(packet.tag)) return;
    if (this.#primary === undefined) {
      if (packet.tag !== 6) throw new TypeError("OpenPGP key block must start with a public key");
      this.#primary = readPublicKey(packet.body);
      return;
    }
    this.#addPart(packet);
  }

  /**
   * Takes a packet after the primary key.
   * @param packet - One packet of the block
   * @throws {TypeError} For a second primary key or an unknown packet
   */
  #addPart(packet: Packet): void {
    switch (packet.tag) {
      case 2: {
        const signature = tryReadSignature(packet.body);
        if (signature !== undefined) this.#target.push(signature);
        return;
      }
      case 13:
        this.#target = [];
        this.#userIds.push({ id: packet.body, signatures: this.#target });
        return;
      case 14:
        this.#target = [];
        this.#subkeys.push({ key: readPublicKey(packet.body), signatures: this.#target });
        return;
      case 17:
        this.#target = [];
        this.#userAttributes.push({ id: packet.body, signatures: this.#target });
        return;
      case 6:
        throw new TypeError("OpenPGP key block holds more than one key. Pass one");
      default:
        throw new TypeError(`OpenPGP key block holds a packet of type ${packet.tag}`);
    }
  }

  /**
   * The finished certificate.
   * @returns {Certificate} Primary key, user IDs and subkeys with their signatures
   * @throws {TypeError} When no packet came in
   */
  build(): Certificate {
    if (this.#primary === undefined) throw new TypeError("OpenPGP key block holds no key");
    return {
      primary: this.#primary,
      direct: this.#direct,
      userIds: this.#userIds,
      userAttributes: this.#userAttributes,
      subkeys: this.#subkeys,
    };
  }
}

/**
 * Splits a dearmored key block into its key, user IDs and subkeys.
 * @param bytes - Dearmored packets
 * @returns {Certificate} The certificate, signatures not yet checked
 * @throws {TypeError} When the block is malformed, private or holds more than one key
 */
export function readCertificate(bytes: Uint8Array): Certificate {
  const builder = new CertificateBuilder();
  for (const packet of readPackets(bytes)) builder.add(packet);
  return builder.build();
}
