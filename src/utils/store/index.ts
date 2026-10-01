import { ecb } from "@agntn/ciphers/aes";
import { Sha256Hasher, create, keccak256, pbkdf2, type ScryptOptions } from "@agntn/hashes";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { equalBytes, randomBytes } from "@noble/curves/utils.js";
import { concatBytes } from "../bytes.ts";
import { generateAddress, toChecksumAddress } from "../evm-address.ts";

/** Key derivation of a keystore, with the cost parameters the file names. */
export type KeystoreKDF =
  | { readonly kdf: "scrypt"; readonly n: number; readonly r: number; readonly p: number }
  | { readonly kdf: "pbkdf2"; readonly c: number };

/** A Web3 Secret Storage file, version 3, as geth, ethers and MyEtherWallet write it. */
export interface Keystore {
  readonly version: 3;
  readonly id: string;
  /** Lowercase hex without 0x. Optional in the definition, written by geth and ethers. */
  readonly address?: string;
  readonly crypto: {
    readonly cipher: "aes-128-ctr";
    readonly cipherparams: { readonly iv: string };
    readonly ciphertext: string;
    readonly kdf: "scrypt" | "pbkdf2";
    readonly kdfparams:
      | {
          readonly dklen: number;
          readonly n: number;
          readonly r: number;
          readonly p: number;
          readonly salt: string;
        }
      | {
          readonly dklen: number;
          readonly c: number;
          readonly prf: "hmac-sha256";
          readonly salt: string;
        };
    readonly mac: string;
  };
}

/** What a keystore tells without its password. */
export type KeystoreInspection = KeystoreKDF & {
  readonly version: 3;
  readonly id?: string;
  /** EIP-55 address the file stores, when it stores one. */
  readonly address?: string;
  readonly cipher: "aes-128-ctr";
  /** Derived key length in bytes, 32 or more. */
  readonly dklen: number;
  readonly salt: Uint8Array;
  readonly iv: Uint8Array;
  readonly ciphertext: Uint8Array;
  readonly mac: Uint8Array;
};

/** Options of `encrypt`; salt, IV and id are random unless given. */
export interface KeystoreEncryptOptions {
  /** Default: scrypt with n 262144, r 8, p 1, geth's standard cost. */
  readonly kdf?: KeystoreKDF;
  /** Default: 32 random bytes. */
  readonly salt?: Uint8Array;
  /** Default: 16 random bytes. */
  readonly iv?: Uint8Array;
  /** Default: a random UUID v4. */
  readonly id?: string;
}

/** The password does not open the keystore: the MAC it derives differs from the stored one. */
export class KeystorePasswordError extends Error {
  constructor() {
    super("Wrong keystore password: the MAC does not match");
    this.name = "KeystorePasswordError";
  }
}

const STANDARD_SCRYPT: KeystoreKDF = { kdf: "scrypt", n: 262_144, r: 8, p: 1 };
const DKLEN = 32;
const BLOCK = 16;
const encoder = new TextEncoder();

/**
 * Reads a JSON object out of a parsed or textual keystore.
 * @param value - The keystore or one of its nested objects
 * @param name - Field name for the error
 * @returns {Readonly<Record<string, unknown>>} The object
 */
function object(value: unknown, name: string): Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`Keystore ${name} must be an object`);
  }
  return Object.fromEntries(Object.entries(value));
}

/**
 * Reads a hex field, with or without 0x, of an exact or minimum length.
 * @param value - Raw field
 * @param name - Field name for the error
 * @param length - Byte length the field must have, or undefined for any non-empty length
 * @returns {Uint8Array} The bytes
 */
function bytes(value: unknown, name: string, length?: number): Uint8Array {
  const text = typeof value === "string" ? value.replace(/^0x/iu, "") : "";
  if (!/^(?:[0-9a-f]{2})+$/iu.test(text)) {
    throw new TypeError(`Keystore ${name} must be hex digit pairs`);
  }
  const decoded = Uint8Array.fromHex(text);
  if (length !== undefined && decoded.length !== length) {
    throw new RangeError(`Keystore ${name} must be ${length} bytes`);
  }
  return decoded;
}

/**
 * Reads a positive integer field.
 * @param value - Raw field
 * @param name - Field name for the error
 * @returns {number} The integer
 */
function integer(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new RangeError(`Keystore ${name} must be a positive integer`);
  }
  return value;
}

/**
 * Reads the KDF and its parameters, refusing a PRF or shape the definition does not name.
 * @param crypto - The `crypto` object of the file
 * @returns {KeystoreKDF & { dklen: number; salt: Uint8Array }} KDF, costs, length and salt
 */
function readKDF(crypto: Readonly<Record<string, unknown>>): KeystoreKDF & {
  dklen: number;
  salt: Uint8Array;
} {
  const params = object(crypto["kdfparams"], "kdfparams");
  const dklen = integer(params["dklen"], "dklen");
  if (dklen < DKLEN) throw new RangeError(`Keystore dklen must be at least ${DKLEN}`);
  const salt = bytes(params["salt"], "salt");
  if (crypto["kdf"] === "scrypt") {
    const n = integer(params["n"], "n");
    if (n < 2 || (n & (n - 1)) !== 0) throw new RangeError("Keystore n must be a power of 2");
    return {
      kdf: "scrypt",
      n,
      r: integer(params["r"], "r"),
      p: integer(params["p"], "p"),
      dklen,
      salt,
    };
  }
  if (crypto["kdf"] === "pbkdf2") {
    if (params["prf"] !== "hmac-sha256") throw new RangeError("Keystore prf must be hmac-sha256");
    return { kdf: "pbkdf2", c: integer(params["c"], "c"), dklen, salt };
  }
  throw new RangeError("Keystore kdf must be scrypt or pbkdf2");
}

/**
 * Reads a version 3 keystore without its password: KDF, costs, cipher and the stored address.
 * Older files write the `crypto` object as `Crypto`; both are read.
 * @param keystore - The file as JSON text or as a parsed object
 * @returns {KeystoreInspection} Every field the decryption needs, decoded
 * @throws {TypeError | RangeError} When the file is not a version 3 keystore this module can open
 */
export function inspect(keystore: string | object): KeystoreInspection {
  let parsed: unknown = keystore;
  if (typeof keystore === "string") {
    try {
      parsed = JSON.parse(keystore);
    } catch {
      throw new TypeError("Keystore must be valid JSON");
    }
  }
  const file = object(parsed, "file");
  if (file["version"] !== 3) throw new RangeError("Keystore version must be 3");
  const crypto = object(file["crypto"] ?? file["Crypto"], "crypto");
  if (crypto["cipher"] !== "aes-128-ctr")
    throw new RangeError("Keystore cipher must be aes-128-ctr");
  const iv = bytes(object(crypto["cipherparams"], "cipherparams")["iv"], "iv", BLOCK);
  const ciphertext = bytes(crypto["ciphertext"], "ciphertext");
  if (ciphertext.length > DKLEN)
    throw new RangeError("Keystore ciphertext must be at most 32 bytes");
  const mac = bytes(crypto["mac"], "mac", DKLEN);
  const id = file["id"];
  const address = file["address"];
  return {
    version: 3,
    ...(typeof id === "string" ? { id } : {}),
    ...(address === undefined ? {} : { address: storedAddress(address) }),
    ...readKDF(crypto),
    cipher: "aes-128-ctr",
    iv,
    ciphertext,
    mac,
  };
}

/**
 * Checksums the address a file stores, in whatever case it was written.
 * @param value - Raw `address` field, 20 bytes of hex with or without 0x
 * @returns {string} The EIP-55 address
 */
function storedAddress(value: unknown): string {
  return `0x${toChecksumAddress(bytes(value, "address", 20).toHex())}`;
}

/**
 * Runs the KDF over the password.
 * @param password - Password as UTF-8 bytes
 * @param kdf - KDF and costs
 * @param salt - Salt bytes
 * @param dklen - Output length
 * @returns {Uint8Array} The derived key
 */
function deriveKey(
  password: Uint8Array,
  kdf: KeystoreKDF,
  salt: Uint8Array,
  dklen: number,
): Uint8Array {
  if (kdf.kdf === "pbkdf2") return pbkdf2(() => new Sha256Hasher(), password, salt, kdf.c, dklen);
  const options: ScryptOptions = {
    salt,
    N: kdf.n,
    r: kdf.r,
    p: kdf.p,
    keyLength: dklen,
    encoding: "binary",
  };
  const { digest } = create("scrypt").hash(password, options);
  if (!(digest instanceof Uint8Array)) throw new TypeError("scrypt returned text, not bytes");
  return digest;
}

/**
 * AES-128-CTR with the whole IV as a big-endian counter, the keystream from AES-ECB over the
 * counter blocks. Encryption and decryption are the same step.
 * @param data - Any number of bytes
 * @param key - 16 key bytes
 * @param iv - 16-byte initial counter block
 * @returns {Uint8Array} As many bytes as came in
 */
function aes128Ctr(data: Uint8Array, key: Uint8Array, iv: Uint8Array): Uint8Array {
  const blocks = Math.ceil(data.length / BLOCK);
  const counters = new Uint8Array(blocks * BLOCK);
  const counter = iv.slice();
  for (let block = 0; block < blocks; block++) {
    counters.set(counter, block * BLOCK);
    for (let i = BLOCK - 1; i >= 0 && ++counter[i]! === 256; i--) counter[i] = 0;
  }
  const keystream = ecb(counters, key, "encrypt");
  return data.map((byte, i) => byte ^ keystream[i]!);
}

/**
 * MAC of the definition: Keccak-256 of the second 16 bytes of the derived key and the ciphertext.
 * @param derivedKey - KDF output
 * @param ciphertext - Encrypted key
 * @returns {Uint8Array} 32-byte MAC
 */
function macOf(derivedKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  return keccak256(concatBytes(derivedKey.slice(16, 32), ciphertext));
}

/**
 * Ethereum address of a private key, EIP-55.
 * @param privateKey - 32-byte secp256k1 key
 * @returns {string} The address
 */
function addressOf(privateKey: Uint8Array): string {
  return generateAddress(secp256k1.getPublicKey(privateKey, false).toHex());
}

/**
 * Decrypts a version 3 keystore. The password is hashed as UTF-8 without normalization, as geth
 * does. A plaintext shorter than 32 bytes, from early geth that dropped leading zeros, is padded
 * back. When the file stores an address, the key must give it.
 * @param keystore - The file as JSON text or as a parsed object
 * @param password - The password
 * @returns {Uint8Array} 32-byte secp256k1 private key
 * @throws {KeystorePasswordError} When the password does not give the stored MAC
 * @throws {Error} When the key is not a secp256k1 scalar or not the key of the stored address
 */
export function decrypt(keystore: string | object, password: string): Uint8Array {
  const file = inspect(keystore);
  const derivedKey = deriveKey(encoder.encode(password), file, file.salt, file.dklen);
  if (!equalBytes(macOf(derivedKey, file.ciphertext), file.mac)) throw new KeystorePasswordError();
  const plaintext = aes128Ctr(file.ciphertext, derivedKey.slice(0, 16), file.iv);
  const privateKey = new Uint8Array(DKLEN);
  privateKey.set(plaintext, DKLEN - plaintext.length);
  if (!secp256k1.utils.isValidSecretKey(privateKey)) {
    throw new RangeError("Keystore holds no valid secp256k1 private key");
  }
  if (file.address !== undefined && addressOf(privateKey) !== file.address) {
    throw new Error("Keystore address is not the address of its key");
  }
  return privateKey;
}

/**
 * Formats 16 random bytes as a UUID version 4.
 * @param random - 16 bytes
 * @returns {string} The UUID
 */
function uuid(random: Uint8Array): string {
  const id = random.slice();
  id[6] = (id[6]! & 0x0f) | 0x40;
  id[8] = (id[8]! & 0x3f) | 0x80;
  const hex = id.toHex();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Takes the salt and IV the options give, or draws them.
 * @param options - Options of `encrypt`
 * @returns {{ salt: Uint8Array; iv: Uint8Array }} A non-empty salt and a 16-byte IV
 */
function randomInputs(options: KeystoreEncryptOptions): { salt: Uint8Array; iv: Uint8Array } {
  const salt = options.salt ?? randomBytes(32);
  const iv = options.iv ?? randomBytes(BLOCK);
  if (salt.length === 0) throw new RangeError("Salt must not be empty");
  if (iv.length !== BLOCK) throw new RangeError(`IV must be ${BLOCK} bytes`);
  return { salt, iv };
}

/**
 * Encrypts a private key as a version 3 keystore with AES-128-CTR, the address included.
 * @param privateKey - 32-byte secp256k1 private key
 * @param password - Password, hashed as UTF-8 without normalization
 * @param options - KDF and costs, plus fixed salt, IV or id for reproducible files
 * @returns {Keystore} The file as an object, ready for `JSON.stringify`
 * @throws {RangeError} When the key is not a secp256k1 scalar or the salt or IV is the wrong size
 */
export function encrypt(
  privateKey: Uint8Array,
  password: string,
  options: KeystoreEncryptOptions = {},
): Keystore {
  if (privateKey.length !== DKLEN || !secp256k1.utils.isValidSecretKey(privateKey)) {
    throw new RangeError("Private key must be a 32-byte secp256k1 scalar");
  }
  const kdf = options.kdf ?? STANDARD_SCRYPT;
  const { salt, iv } = randomInputs(options);
  const derivedKey = deriveKey(encoder.encode(password), kdf, salt, DKLEN);
  const ciphertext = aes128Ctr(privateKey, derivedKey.slice(0, 16), iv);
  const kdfparams =
    kdf.kdf === "scrypt"
      ? { dklen: DKLEN, n: kdf.n, r: kdf.r, p: kdf.p, salt: salt.toHex() }
      : { dklen: DKLEN, c: kdf.c, prf: "hmac-sha256" as const, salt: salt.toHex() };
  return {
    version: 3,
    id: options.id ?? uuid(randomBytes(16)),
    address: addressOf(privateKey).slice(2).toLowerCase(),
    crypto: {
      cipher: "aes-128-ctr",
      cipherparams: { iv: iv.toHex() },
      ciphertext: ciphertext.toHex(),
      kdf: kdf.kdf,
      kdfparams,
      mac: macOf(derivedKey, ciphertext).toHex(),
    },
  };
}
