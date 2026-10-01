import {
  Sha256Hasher,
  Sha512Hasher,
  create,
  keccak256,
  pbkdf2,
  sha256,
  type ScryptOptions,
} from "@agntn/hashes";
import { concatBytes } from "../bytes.ts";

/** Key derivation a salted brainwallet runs the passphrase through, with its cost parameters. */
export type BrainwalletKDF =
  | { readonly kdf: "scrypt"; readonly N: number; readonly r: number; readonly p: number }
  | { readonly kdf: "pbkdf2"; readonly iterations: number; readonly digest: "sha256" | "sha512" };

/** Recipe of a salted brainwallet: the KDF, its salt and what SHA-256 hashes afterwards. */
export type BrainwalletOptions = BrainwalletKDF & {
  /** Salt as bytes, or text read as UTF-8. */
  readonly salt: Uint8Array | string;
  /** SHA-256 input after the KDF: its raw bytes, or their lowercase hex as text. */
  readonly hashed: "bytes" | "hex";
  /** KDF output length in bytes. Default: 32. */
  readonly keyLength?: number;
};

/** Recipe of a plain brainwallet: the passphrase hashed straight into the key, no salt or KDF. */
export interface PlainBrainwalletOptions {
  /** sha256 for the brainwallet.org scheme, keccak256 for Ethereum brainwallets. */
  readonly kdf: "sha256" | "keccak256";
  /** How many times the digest runs, each round over the previous 32 bytes. Default: 1. */
  readonly iterations?: number;
}

/** Recipe of a WarpWallet: scrypt and PBKDF2 at the costs WarpWallet fixed, XORed into the key. */
export interface WarpWalletOptions {
  readonly kdf: "warpwallet";
  /** Salt as bytes, or text read as UTF-8. WarpWallet asks for an email; empty for none. */
  readonly salt: Uint8Array | string;
}

/** Any recipe `derive` takes, salted, plain or WarpWallet. */
export type BrainwalletRecipe = BrainwalletOptions | PlainBrainwalletOptions | WarpWalletOptions;

const encoder = new TextEncoder();

/** scrypt cost WarpWallet runs, 256 MiB of memory. */
const WARP_SCRYPT = { N: 2 ** 18, r: 8, p: 1 } as const;

/** PBKDF2-HMAC-SHA256 rounds WarpWallet runs. */
const WARP_PBKDF2_ITERATIONS = 2 ** 16;

/**
 * Hashes the passphrase bytes into a key, round after round.
 * @param password - Passphrase as UTF-8 bytes
 * @param options - Digest and round count
 * @returns {Uint8Array} 32-byte digest of the last round
 */
function digestRounds(password: Uint8Array, options: PlainBrainwalletOptions): Uint8Array {
  const iterations = options.iterations ?? 1;
  if (!Number.isSafeInteger(iterations) || iterations < 1) {
    throw new RangeError("iterations must be a positive integer");
  }
  const digest = options.kdf === "keccak256" ? keccak256 : sha256;
  let key = password;
  for (let round = 0; round < iterations; round++) key = digest(key);
  return key;
}

/**
 * Runs the KDF the recipe names over the passphrase bytes.
 * @param password - Passphrase as UTF-8 bytes
 * @param salt - Salt bytes
 * @param options - KDF, cost parameters and output length
 * @returns {Uint8Array} The KDF output
 */
function stretch(password: Uint8Array, salt: Uint8Array, options: BrainwalletOptions): Uint8Array {
  const keyLength = options.keyLength ?? 32;
  if (options.kdf === "pbkdf2") {
    const hasher = options.digest === "sha512" ? Sha512Hasher : Sha256Hasher;
    return pbkdf2(() => new hasher(), password, salt, options.iterations, keyLength);
  }
  return scrypt(password, salt, options, keyLength);
}

/**
 * Runs scrypt over the passphrase bytes.
 * @param password - Passphrase bytes
 * @param salt - Salt bytes
 * @param cost - N, r and p
 * @param keyLength - Output length in bytes
 * @returns {Uint8Array} The scrypt output
 */
function scrypt(
  password: Uint8Array,
  salt: Uint8Array,
  cost: { readonly N: number; readonly r: number; readonly p: number },
  keyLength: number,
): Uint8Array {
  const { N, r, p } = cost;
  const options: ScryptOptions = { salt, N, r, p, keyLength, encoding: "binary" };
  const { digest } = create("scrypt").hash(password, options);
  if (!(digest instanceof Uint8Array)) throw new TypeError("scrypt returned text, not bytes");
  return digest;
}

/**
 * WarpWallet key: scrypt over the inputs suffixed 0x01, XOR PBKDF2 over them suffixed 0x02.
 * @param password - Passphrase as UTF-8 bytes
 * @param salt - Salt bytes
 * @returns {Uint8Array} 32-byte secp256k1 private key
 */
function warp(password: Uint8Array, salt: Uint8Array): Uint8Array {
  const tagged = (bytes: Uint8Array, tag: number) => concatBytes(bytes, Uint8Array.of(tag));
  const s1 = scrypt(tagged(password, 1), tagged(salt, 1), WARP_SCRYPT, 32);
  const s2 = pbkdf2(
    () => new Sha256Hasher(),
    tagged(password, 2),
    tagged(salt, 2),
    WARP_PBKDF2_ITERATIONS,
    32,
  );
  return s1.map((byte, index) => byte ^ (s2[index] ?? 0));
}

/**
 * Tells a plain recipe from a salted one by its digest.
 * @param options - Any recipe `derive` takes
 * @returns {boolean} True for sha256 and keccak256
 */
function isPlain(options: BrainwalletRecipe): options is PlainBrainwalletOptions {
  return options.kdf === "sha256" || options.kdf === "keccak256";
}

/**
 * Derives a brainwallet key: SHA-256 of the KDF output, the plain passphrase digest or WarpWallet.
 * @param passphrase - Passphrase, hashed as UTF-8 without trimming or normalization
 * @param options - Salted recipe, the digest and rounds of a plain one, or WarpWallet with its salt
 * @returns {Uint8Array} 32-byte secp256k1 private key
 */
export function derive(passphrase: string, options: BrainwalletRecipe): Uint8Array {
  if (isPlain(options)) {
    return digestRounds(encoder.encode(passphrase), options);
  }
  const salt = typeof options.salt === "string" ? encoder.encode(options.salt) : options.salt;
  if (options.kdf === "warpwallet") return warp(encoder.encode(passphrase), salt);
  const stretched = stretch(encoder.encode(passphrase), salt, options);
  return sha256(options.hashed === "hex" ? encoder.encode(stretched.toHex()) : stretched);
}
