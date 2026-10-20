import { md5, ripemd160, sha1, sha256, sha3_256, sha512 } from "@agntn/hashes";
import { invert, pow } from "@noble/curves/abstract/modular.js";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToNumberBE, equalBytes, numberToBytesBE } from "@noble/curves/utils.js";
import { concatBytes } from "../bytes.ts";
import { type Reader, createReader } from "./packets.ts";

/** One hash from RFC 9580 Table 23 that this module can compute. */
export interface HashAlgorithm {
  /** Text name, as in a `Hash:` header. */
  readonly name: string;
  readonly digest: (data: Uint8Array) => Uint8Array;
  /** DER prefix for EMSA-PKCS1-v1_5, RFC 9580 Table 24. */
  readonly prefix: Uint8Array;
  /** Salt size of a version 6 signature, 0 where version 6 can't use the hash. */
  readonly salt: number;
  /** MD5, SHA-1 and RIPEMD-160, which RFC 9580 §9.5 tells verifiers not to accept. */
  readonly weak: boolean;
}

/** Public key material, read per algorithm, RFC 9580 §5.5.5. */
export type KeyMaterial =
  | { readonly kind: "rsa"; readonly n: bigint; readonly e: bigint; readonly bits: number }
  | {
      readonly kind: "dsa";
      readonly p: bigint;
      readonly q: bigint;
      readonly g: bigint;
      readonly y: bigint;
      readonly bits: number;
    }
  | { readonly kind: "ecdsa"; readonly curve: string; readonly point: Uint8Array }
  | { readonly kind: "eddsa"; readonly point: Uint8Array }
  | { readonly kind: "none"; readonly curve?: string; readonly bits?: number };

const HASHES: Readonly<Record<number, HashAlgorithm>> = {
  1: {
    name: "MD5",
    digest: md5,
    prefix: hex("3020300c06082a864886f70d020505000410"),
    salt: 0,
    weak: true,
  },
  2: {
    name: "SHA1",
    digest: sha1,
    prefix: hex("3021300906052b0e03021a05000414"),
    salt: 0,
    weak: true,
  },
  3: {
    name: "RIPEMD160",
    digest: ripemd160,
    prefix: hex("3021300906052b2403020105000414"),
    salt: 0,
    weak: true,
  },
  8: {
    name: "SHA256",
    digest: sha256,
    prefix: hex("3031300d060960864801650304020105000420"),
    salt: 16,
    weak: false,
  },
  10: {
    name: "SHA512",
    digest: sha512,
    prefix: hex("3051300d060960864801650304020305000440"),
    salt: 32,
    weak: false,
  },
  12: {
    name: "SHA3-256",
    digest: sha3_256,
    prefix: hex("3031300d060960864801650304020805000420"),
    salt: 16,
    weak: false,
  },
};

/** Hashes RFC 9580 defines that `@agntn/hashes` doesn't export yet, with their salt sizes. */
const MISSING_HASHES: Readonly<Record<number, { readonly name: string; readonly salt: number }>> = {
  9: { name: "SHA384", salt: 24 },
  11: { name: "SHA224", salt: 16 },
  14: { name: "SHA3-512", salt: 32 },
};

/** Text names of every hash in RFC 9580 Table 23, which a `Hash:` header may list. */
export const HASH_NAMES: ReadonlySet<string> = new Set(
  [...Object.values(HASHES), ...Object.values(MISSING_HASHES)].map((hash) => hash.name),
);

/** Curve OIDs from RFC 9580 Table 19, as hex, with the names it gives them. */
const CURVES: Readonly<Record<string, string>> = {
  "2a8648ce3d030107": "NIST P-256",
  "2b81040022": "NIST P-384",
  "2b81040023": "NIST P-521",
  "2b8104000a": "secp256k1",
  "2b2403030208010107": "brainpoolP256r1",
  "2b240303020801010b": "brainpoolP384r1",
  "2b240303020801010d": "brainpoolP512r1",
  "2b06010401da470f01": "Ed25519Legacy",
  "2b060104019755010501": "Curve25519Legacy",
};

/** Public key algorithm names, RFC 9580 Table 18. */
const ALGORITHMS: Readonly<Record<number, string>> = {
  1: "RSA",
  2: "RSA",
  3: "RSA",
  16: "Elgamal",
  17: "DSA",
  18: "ECDH",
  19: "ECDSA",
  22: "EdDSALegacy",
  25: "X25519",
  26: "X448",
  27: "Ed25519",
  28: "Ed448",
};

/** Largest RSA modulus and DSA prime read, in bits, so one call can't run for seconds. */
const MAX_MODULUS_BITS = 8192;

/** Largest DSA prime read, the top size FIPS 186-4 allows. */
const MAX_DSA_BITS = 3072;

/** Largest RSA exponent read. GnuPG uses 65537; an 8192-bit one costs half a second a check. */
const MAX_EXPONENT_BITS = 64;

/**
 * Turns hex into bytes, for the constant tables above.
 * @param text - Lowercase hex
 * @returns {Uint8Array} The bytes
 */
function hex(text: string): Uint8Array {
  return Uint8Array.fromHex(text);
}

/**
 * Looks up a hash by its ID, refusing the ones this module can't compute.
 * @param id - Hash algorithm ID
 * @returns {HashAlgorithm} The hash
 * @throws {RangeError} For a hash that isn't supported here
 */
export function hashAlgorithm(id: number): HashAlgorithm {
  const hash = Object.hasOwn(HASHES, id) ? HASHES[id] : undefined;
  if (hash !== undefined) return hash;
  throw new RangeError(`OpenPGP signatures over ${hashName(id)} aren't supported yet`);
}

/**
 * Any hash RFC 9580 defines, computable here or not.
 * @param id - Hash algorithm ID
 * @returns {{ name: string; salt: number } | undefined} Its name and version 6 salt size
 */
function hashInfo(id: number): { readonly name: string; readonly salt: number } | undefined {
  if (Object.hasOwn(HASHES, id)) return HASHES[id];
  return Object.hasOwn(MISSING_HASHES, id) ? MISSING_HASHES[id] : undefined;
}

/**
 * Names a hash, including the ones this module can't compute.
 * @param id - Hash algorithm ID
 * @returns {string} Its text name, or the ID for an unknown one
 */
export function hashName(id: number): string {
  return hashInfo(id)?.name ?? `hash ${id}`;
}

/**
 * Salt size a version 6 signature must use with the hash, RFC 9580 Table 23.
 * @param id - Hash algorithm ID
 * @returns {number} Salt bytes, 0 for hashes version 6 can't use
 * @throws {RangeError} For a hash ID RFC 9580 doesn't define
 */
export function saltSize(id: number): number {
  const info = hashInfo(id);
  if (info === undefined) throw new RangeError(`OpenPGP hash algorithm ${id} is unknown`);
  return info.salt;
}

/**
 * Names a public key algorithm.
 * @param id - Public key algorithm ID
 * @returns {string} Its RFC 9580 name, or the ID for an unknown one
 */
export function algorithmName(id: number): string {
  return (Object.hasOwn(ALGORITHMS, id) ? ALGORITHMS[id] : undefined) ?? `algorithm ${id}`;
}

/**
 * Reads a curve OID field: a length byte, then the truncated DER OID.
 * @param reader - Reader at the field
 * @returns {string} The curve name, or its OID in hex when RFC 9580 doesn't name it
 */
function readCurve(reader: Reader): string {
  const length = reader.byte();
  if (length === 0 || length === 0xff) throw new TypeError("OpenPGP curve OID length is reserved");
  const oid = reader.read(length).toHex();
  return (Object.hasOwn(CURVES, oid) ? CURVES[oid] : undefined) ?? `curve ${oid}`;
}

/**
 * Reads an MPI as a number, refusing one past the size cap.
 * @param reader - Reader at the MPI
 * @returns {{ value: bigint; bits: number }} The number and its bit length
 * @throws {RangeError} When it is longer than 8192 bits
 */
function readBig(reader: Reader): { value: bigint; bits: number } {
  const bytes = reader.mpi();
  const value = bytesToNumberBE(bytes);
  const bits = value.toString(2).length;
  if (bits > MAX_MODULUS_BITS) {
    throw new RangeError(`OpenPGP key numbers longer than ${MAX_MODULUS_BITS} bits aren't read`);
  }
  return { value, bits };
}

/**
 * Reads RSA `n` and `e`.
 * @param reader - Reader at the material
 * @returns {KeyMaterial} RSA material
 * @throws {RangeError} When `e` is longer than 64 bits
 */
function readRsa(reader: Reader): KeyMaterial {
  const n = readBig(reader);
  const e = readBig(reader);
  if (e.bits > MAX_EXPONENT_BITS) {
    throw new RangeError(`OpenPGP RSA exponents longer than ${MAX_EXPONENT_BITS} bits aren't read`);
  }
  return { kind: "rsa", n: n.value, e: e.value, bits: n.bits };
}

/**
 * Reads DSA `p`, `q`, `g` and `y`.
 * @param reader - Reader at the material
 * @returns {KeyMaterial} DSA material
 * @throws {RangeError} When `p` is longer than 3072 bits
 */
function readDsa(reader: Reader): KeyMaterial {
  const p = readBig(reader);
  if (p.bits > MAX_DSA_BITS) {
    throw new RangeError(`OpenPGP DSA primes longer than ${MAX_DSA_BITS} bits aren't read`);
  }
  const [q, g, y] = [readBig(reader), readBig(reader), readBig(reader)];
  return { kind: "dsa", p: p.value, q: q.value, g: g.value, y: y.value, bits: p.bits };
}

/**
 * Reads an ECDSA key. Only secp256k1 gets checked, the rest stays a name.
 * @param reader - Reader at the material
 * @returns {KeyMaterial} ECDSA material, or a named curve this module can't check
 */
function readEcdsa(reader: Reader): KeyMaterial {
  const curve = readCurve(reader);
  const point = reader.mpi();
  return curve === "secp256k1" ? { kind: "ecdsa", curve, point } : { kind: "none", curve };
}

/**
 * Reads an EdDSALegacy key, whose point carries a 0x40 prefix, RFC 9580 §11.2.2.
 * @param reader - Reader at the material
 * @returns {KeyMaterial} Ed25519 material, or a named curve this module can't check
 */
function readEdDsaLegacy(reader: Reader): KeyMaterial {
  const curve = readCurve(reader);
  const point = reader.mpi();
  if (curve !== "Ed25519Legacy") return { kind: "none", curve };
  if (point.length !== 33 || point[0] !== 0x40) {
    throw new TypeError("OpenPGP Ed25519Legacy key must be 0x40 and 32 bytes");
  }
  return { kind: "eddsa", point: point.slice(1) };
}

/**
 * Reads the curve of an ECDH key for display. Its KDF fields are never needed here.
 * @param reader - Reader at the material
 * @returns {KeyMaterial} A curve name and nothing to verify with
 */
function readEcdh(reader: Reader): KeyMaterial {
  return { kind: "none", curve: readCurve(reader) };
}

/** Material readers by public key algorithm ID. */
const MATERIAL_READERS: Readonly<Record<number, (reader: Reader) => KeyMaterial>> = {
  1: readRsa,
  2: readRsa,
  3: readRsa,
  16: (reader) => ({ kind: "none", bits: readBig(reader).bits }),
  17: readDsa,
  18: readEcdh,
  19: readEcdsa,
  22: readEdDsaLegacy,
  27: (reader) => ({ kind: "eddsa", point: reader.read(32) }),
};

/**
 * Reads the public key material of one algorithm.
 * @param algorithm - Public key algorithm ID
 * @param material - Material bytes
 * @returns {KeyMaterial} What verification needs, or `none` for keys that can't sign here
 */
export function readKeyMaterial(algorithm: number, material: Uint8Array): KeyMaterial {
  const read = Object.hasOwn(MATERIAL_READERS, algorithm) ? MATERIAL_READERS[algorithm] : undefined;
  return read === undefined ? { kind: "none" } : read(createReader(material));
}

/**
 * Builds EMSA-PKCS1-v1_5, RFC 9580 §12.1.3.
 * @param digest - The hash
 * @param prefix - The hash's DER prefix
 * @param length - Modulus length in bytes
 * @returns {Uint8Array | undefined} The encoded message, undefined when the modulus is too short
 */
function pkcs1(digest: Uint8Array, prefix: Uint8Array, length: number): Uint8Array | undefined {
  const padding = length - prefix.length - digest.length - 3;
  if (padding < 8) return undefined;
  return concatBytes(
    Uint8Array.of(0, 1),
    new Uint8Array(padding).fill(0xff),
    Uint8Array.of(0),
    prefix,
    digest,
  );
}

/**
 * Checks an RSA signature: `s^e mod n` against the PKCS#1 encoding of the digest.
 * @param key - RSA material
 * @param reader - Reader at the signature MPI
 * @param digest - The hash
 * @param hash - Which hash it is
 * @returns {boolean} Whether it matches
 */
function verifyRsa(
  key: Extract<KeyMaterial, { kind: "rsa" }>,
  reader: Reader,
  digest: Uint8Array,
  hash: HashAlgorithm,
): boolean {
  const signature = bytesToNumberBE(reader.mpi());
  if (signature >= key.n || key.e < 3n) return false;
  const length = Math.ceil(key.bits / 8);
  const expected = pkcs1(digest, hash.prefix, length);
  return (
    expected !== undefined &&
    equalBytes(numberToBytesBE(pow(signature, key.e, key.n), length), expected)
  );
}

/**
 * Checks a DSA signature, FIPS 186-4 §4.7, with the digest cut to the bits of `q`.
 * @param key - DSA material
 * @param reader - Reader at `r` and `s`
 * @param digest - The hash
 * @returns {boolean} Whether it matches
 */
function verifyDsa(
  key: Extract<KeyMaterial, { kind: "dsa" }>,
  reader: Reader,
  digest: Uint8Array,
): boolean {
  const r = bytesToNumberBE(reader.mpi());
  const s = bytesToNumberBE(reader.mpi());
  const qBits = key.q.toString(2).length;
  if (r <= 0n || s <= 0n || r >= key.q || s >= key.q || digest.length * 8 < qBits) return false;
  const z = bytesToNumberBE(digest) >> BigInt(digest.length * 8 - qBits);
  const w = invert(s, key.q);
  const v = (pow(key.g, (z * w) % key.q, key.p) * pow(key.y, (r * w) % key.q, key.p)) % key.p;
  return v % key.q === r;
}

/**
 * Pads an MPI to a fixed width, since MPIs drop leading zero bytes.
 * @param bytes - MPI bytes
 * @param width - Wanted length
 * @returns {Uint8Array} The padded bytes
 * @throws {TypeError} When the MPI is longer than the width
 */
function pad(bytes: Uint8Array, width: number): Uint8Array {
  if (bytes.length > width) throw new TypeError("OpenPGP signature value is too long");
  return concatBytes(new Uint8Array(width - bytes.length), bytes);
}

/**
 * Checks an ECDSA signature on secp256k1 over the digest as given, no second hash.
 * @param key - secp256k1 material
 * @param reader - Reader at `r` and `s`
 * @param digest - The hash
 * @returns {boolean} Whether it matches
 */
function verifyEcdsa(
  key: Extract<KeyMaterial, { kind: "ecdsa" }>,
  reader: Reader,
  digest: Uint8Array,
): boolean {
  if (digest.length < 32) return false;
  const signature = concatBytes(pad(reader.mpi(), 32), pad(reader.mpi(), 32));
  return secp256k1.verify(signature, digest, key.point, { prehash: false, lowS: false });
}

/**
 * Checks an Ed25519 signature over the digest, RFC 9580 §12.7. Legacy keys split it into two MPIs.
 * @param key - Ed25519 material
 * @param reader - Reader at the signature
 * @param digest - The hash
 * @param legacy - Whether the signature comes as two MPIs, algorithm 22
 * @returns {boolean} Whether it matches
 */
function verifyEdDsa(
  key: Extract<KeyMaterial, { kind: "eddsa" }>,
  reader: Reader,
  digest: Uint8Array,
  legacy: boolean,
): boolean {
  if (digest.length < 32) return false;
  const signature = legacy
    ? concatBytes(pad(reader.mpi(), 32), pad(reader.mpi(), 32))
    : reader.read(64);
  return ed25519.verify(signature, digest, key.point, { zip215: false });
}

/**
 * Runs the math of one signature. A value that doesn't parse is a signature that doesn't verify.
 * @param key - The signer's material
 * @param algorithm - Algorithm ID on the signature
 * @param value - Algorithm-specific signature bytes
 * @param digest - Hash of the signed data
 * @param hash - Which hash it is
 * @returns {boolean} Whether the signature checks out
 */
export function checkMath(
  key: KeyMaterial,
  algorithm: number,
  value: Uint8Array,
  digest: Uint8Array,
  hash: HashAlgorithm,
): boolean {
  const reader = createReader(value);
  try {
    const valid = mathOf(key, algorithm, reader, digest, hash);
    return valid && reader.done();
  } catch {
    return false;
  }
}

/**
 * Picks the check for the key kind. The caller already matched the algorithm ID to the key.
 * @param key - The signer's material
 * @param algorithm - Algorithm ID on the signature
 * @param reader - Reader at the signature value
 * @param digest - Hash of the signed data
 * @param hash - Which hash it is
 * @returns {boolean} Whether the signature checks out
 */
function mathOf(
  key: KeyMaterial,
  algorithm: number,
  reader: Reader,
  digest: Uint8Array,
  hash: HashAlgorithm,
): boolean {
  switch (key.kind) {
    case "rsa":
      return verifyRsa(key, reader, digest, hash);
    case "dsa":
      return verifyDsa(key, reader, digest);
    case "ecdsa":
      return verifyEcdsa(key, reader, digest);
    case "eddsa":
      return verifyEdDsa(key, reader, digest, algorithm === 22);
    default:
      return false;
  }
}
