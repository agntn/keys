import {
  Sha256Hasher,
  Sha512Hasher,
  create,
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

const encoder = new TextEncoder();

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
 * Derives the private key of a salted brainwallet, SHA-256 over the KDF output.
 * @param passphrase - Passphrase, hashed as UTF-8 without trimming or normalization
 * @param options - KDF, cost parameters, salt and the form SHA-256 reads
 * @returns {Uint8Array} 32-byte secp256k1 private key
 */
export function derive(passphrase: string, options: BrainwalletOptions): Uint8Array {
  const salt = typeof options.salt === "string" ? encoder.encode(options.salt) : options.salt;
  const stretched = stretch(encoder.encode(passphrase), salt, options);
  return sha256(options.hashed === "hex" ? encoder.encode(stretched.toHex()) : stretched);
}
