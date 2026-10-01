import {
  Sha256Hasher,
  Sha512Hasher,
  create,
  keccak256,
  pbkdf2,
  sha256,
  type ScryptOptions,
} from "@agntn/hashes";

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

/** Any recipe `derive` takes, salted or plain. */
export type BrainwalletRecipe = BrainwalletOptions | PlainBrainwalletOptions;

const encoder = new TextEncoder();

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
  const { N, r, p } = options;
  const scrypt: ScryptOptions = { salt, N, r, p, keyLength, encoding: "binary" };
  const { digest } = create("scrypt").hash(password, scrypt);
  if (!(digest instanceof Uint8Array)) throw new TypeError("scrypt returned text, not bytes");
  return digest;
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
 * Derives a brainwallet key: SHA-256 of the KDF output, or the plain passphrase digest.
 * @param passphrase - Passphrase, hashed as UTF-8 without trimming or normalization
 * @param options - Salted recipe, or the digest and rounds of a plain one
 * @returns {Uint8Array} 32-byte secp256k1 private key
 */
export function derive(passphrase: string, options: BrainwalletRecipe): Uint8Array {
  if (isPlain(options)) {
    return digestRounds(encoder.encode(passphrase), options);
  }
  const salt = typeof options.salt === "string" ? encoder.encode(options.salt) : options.salt;
  const stretched = stretch(encoder.encode(passphrase), salt, options);
  return sha256(options.hashed === "hex" ? encoder.encode(stretched.toHex()) : stretched);
}
