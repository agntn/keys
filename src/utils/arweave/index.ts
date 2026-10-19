import { sha256 } from "@agntn/hashes";
import { base64 } from "@agntn/encodings/base64";

/** An Arweave keyfile as an RSA JWK. Only `n` counts, the private members are never read. */
export interface ArweaveJWK {
  readonly kty: "RSA";
  /** Modulus as unpadded base64url, 683 characters for a 4096-bit key. */
  readonly n: string;
  readonly e?: string;
}

/** Arweave caps a transaction owner at 512 bytes, a 4096-bit modulus. */
const MAX_MODULUS_BYTES = 512;

/** Unpadded base64url, the encoding of every JWK member and Arweave address. */
const BASE64URL = /^[A-Za-z0-9_-]+$/u;

/** 43 characters of a 32-byte hash, so the last digit keeps its two low bits at zero. */
const ADDRESS = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u;

const URL_ALPHABET = { alphabet: "url" } as const;
const UNPADDED = { alphabet: "url", padding: false } as const;

/**
 * Reads canonical unpadded base64url only, so stray bits can't hash to a second address.
 * @param text - Modulus `n`.
 * @returns {Uint8Array} Modulus bytes.
 */
function decodeModulus(text: string): Uint8Array {
  const bytes =
    BASE64URL.test(text) && text.length % 4 !== 1 ? base64.decode(text, URL_ALPHABET) : null;
  if (bytes === null || base64.encode(bytes, UNPADDED) !== text) {
    throw new TypeError("Arweave modulus must be unpadded base64url");
  }
  if (bytes.length > MAX_MODULUS_BYTES) {
    throw new RangeError(`Arweave modulus must not exceed ${MAX_MODULUS_BYTES} bytes`);
  }
  return bytes;
}

/**
 * Takes `n` out of a JWK without reading or echoing its private members.
 * @param key - Modulus `n` or the keyfile JWK.
 * @returns {string} Modulus `n`.
 */
function modulusOf(key: string | Readonly<ArweaveJWK>): string {
  if (typeof key === "string") return key;
  if (typeof key !== "object" || key === null || key.kty !== "RSA") {
    throw new TypeError("Arweave key must be an RSA JWK or its modulus n");
  }
  if (typeof key.n !== "string") throw new TypeError("Arweave JWK must carry its modulus n");
  return key.n;
}

/**
 * Base64url of SHA-256 over the RSA modulus. A 32-byte legacy owner is its own, as in the node.
 * @param key - Keyfile JWK, or just its modulus `n` as base64url.
 * @returns {string} 43-character address.
 * @throws {TypeError} When the key isn't an RSA JWK or `n` isn't canonical base64url.
 * @throws {RangeError} When the modulus is longer than 512 bytes.
 * @example
 * getAddress(JSON.parse(keyfile)); // "PbdTDYikdddWfNFlDt2aZokALXKe1mJVSC9TALUBNv8"
 */
export function getAddress(key: string | Readonly<ArweaveJWK>): string {
  const modulus = decodeModulus(modulusOf(key));
  return base64.encode(modulus.length === 32 ? modulus : sha256(modulus), UNPADDED);
}

/**
 * Checks the canonical 43-character form, without a `:checksum` suffix. Says nothing about owners.
 * @param address - Candidate address.
 * @returns {boolean} Whether the address is well formed.
 */
export function validateAddress(address: string): boolean {
  return typeof address === "string" && ADDRESS.test(address);
}
