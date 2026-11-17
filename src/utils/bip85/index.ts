import { base64 } from "@agntn/encodings/base64";
import { base85 } from "@agntn/encodings/base85";
import { bech32 } from "@agntn/encodings/bech32";
import { Sha512Hasher, hmac, shake256 } from "@agntn/hashes";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { HDKey } from "@scure/bip32";
import { entropyToMnemonic, loadWordlist } from "../bip39/index.ts";
import { type BIP39Language, isBIP39Language } from "../bip39/languages.ts";
import { KEY_OFFSET, decodeExtendedKey, extendedKeyVersion } from "../extended-key.ts";
import { normalizeDerivationPath } from "../hd-index.ts";
import { assertOptions } from "../options.ts";
import { encode as encodeWIF } from "../wif/index.ts";

/** The first level of every BIP85 path, `SEED` in ASCII codes. */
export const BIP85_PURPOSE = 83696968;

/** HMAC key that turns the derived key into entropy. */
const ENTROPY_KEY = new TextEncoder().encode("bip-entropy-from-k");

/** Network of a root key: xprv is mainnet, tprv testnet. */
export type BIP85Network = "mainnet" | "testnet";

/** BIP32 versions of a root key and their network. */
interface RootFormat {
  readonly network: BIP85Network;
  readonly versions: { readonly private: number; readonly public: number };
}

/** xprv and tprv, the only roots BIP85 takes. */
const ROOT_FORMATS: readonly RootFormat[] = [
  { network: "mainnet", versions: { private: 0x0488ade4, public: 0x0488b21e } },
  { network: "testnet", versions: { private: 0x04358394, public: 0x043587cf } },
];

/** Language codes of application 39, from the BIP85 table. */
const LANGUAGE_CODES: Readonly<Record<BIP39Language, number>> = {
  english: 0,
  japanese: 1,
  korean: 2,
  spanish: 3,
  "simplified-chinese": 4,
  "traditional-chinese": 5,
  french: 6,
  italian: 7,
  czech: 8,
  portuguese: 9,
};

/** Entropy bytes for each word count of application 39. */
const WORD_BYTES: Readonly<Record<number, number>> = { 12: 16, 15: 20, 18: 24, 21: 28, 24: 32 };

/** Most rolls one call returns, far below what the spec allows. */
const MAX_ROLLS = 65536;

/** Largest number a hardened path level holds. */
const MAX_LEVEL = 0x7fffffff;

/** A checked root key and its network. */
interface Root {
  readonly key: HDKey;
  readonly network: BIP85Network;
}

/**
 * Finds the format of a private version.
 * @param version - Private version bytes
 * @returns {RootFormat} Network and versions
 * @throws {RangeError} For yprv, zprv and every other prefix
 */
function formatOf(version: number): RootFormat {
  const format = ROOT_FORMATS.find((candidate) => candidate.versions.private === version);
  if (format === undefined) throw new RangeError("A BIP85 root key is an xprv or a tprv");
  return format;
}

/**
 * Reads a master key without echoing it.
 * @param root - xprv, tprv or a node from `@agntn/keys/bip32`
 * @returns {Root} The node and its network
 * @throws {Error} For a bad encoding, a public key or a key below depth 0
 */
function readRoot(root: string | HDKey): Root {
  const key = typeof root === "string" ? parseRoot(root) : root;
  if (!(key instanceof HDKey)) {
    throw new TypeError("A BIP85 root key must be an xprv string or an HDKey");
  }
  if (key.privateKey === null) throw new TypeError("A BIP85 root key must be a private key");
  if (key.depth !== 0) {
    throw new RangeError(`BIP85 starts from the master key at depth 0, not depth ${key.depth}`);
  }
  return { key, network: formatOf(key.versions.private).network };
}

/**
 * Decodes an xprv or tprv with its own versions.
 * @param root - Base58Check extended key
 * @returns {HDKey} The node
 * @throws {Error} For a bad encoding or checksum, or a public key
 */
function parseRoot(root: string): HDKey {
  const bytes = decodeExtendedKey(root, "BIP85 root key");
  if (bytes[KEY_OFFSET] !== 0) {
    throw new TypeError("A BIP85 root key must be a private key, not an xpub");
  }
  return HDKey.fromExtendedKey(root, formatOf(extendedKeyVersion(bytes)).versions);
}

/**
 * Checks a path is fully hardened under the BIP85 purpose.
 * @param path - Derivation path, `'` or `h` for hardened
 * @returns {string} The path with `'` on every level
 * @throws {RangeError} For a normal level or another purpose
 */
function bip85Path(path: string): string {
  const normalized = normalizeDerivationPath(path);
  const levels = normalized.split("/").slice(1);
  const normal = levels.findIndex((level) => !level.endsWith("'"));
  if (normal !== -1) {
    throw new RangeError(`BIP85 walks hardened levels only, and level ${normal + 1} isn't one`);
  }
  if (levels[0] !== `${BIP85_PURPOSE}'`) {
    throw new RangeError(`A BIP85 path starts with m/${BIP85_PURPOSE}'`);
  }
  return normalized;
}

/**
 * The 64 bytes of BIP85 entropy at a path, which every application starts from.
 * @param root - Master xprv or tprv, or a depth 0 node from `@agntn/keys/bip32`
 * @param path - Fully hardened path under `m/83696968'`, such as `m/83696968'/0'/0'`
 * @returns {Uint8Array} 64 bytes of entropy
 * @throws {RangeError} For a key below the master, another prefix, or a path BIP85 doesn't walk
 * @throws {TypeError} For a public key
 * @example
 * deriveEntropy(xprv, "m/83696968'/0'/0'"); // efecfbcc..., test case 1 of BIP85
 */
export function deriveEntropy(root: string | HDKey, path: string): Uint8Array {
  return entropyAt(readRoot(root).key, bip85Path(path));
}

/**
 * Turns the key at a checked path into entropy.
 * @param key - Master node with its private key
 * @param path - Checked BIP85 path
 * @returns {Uint8Array} 64 bytes of entropy
 */
function entropyAt(key: HDKey, path: string): Uint8Array {
  const { privateKey } = key.derive(path);
  if (privateKey === null) throw new Error(`No private key at ${path}`);
  return hmac(() => new Sha512Hasher(), ENTROPY_KEY, privateKey);
}

/**
 * Reads a child index, 0 by default.
 * @param index - Caller's index
 * @returns {number} An index below 2^31
 * @throws {RangeError} For anything but an integer from 0 to 2147483647
 */
function childIndex(index: number = 0): number {
  if (!Number.isSafeInteger(index) || index < 0 || index > 0x7fffffff) {
    throw new RangeError("BIP85 index must be an integer between 0 and 2147483647");
  }
  return index;
}

/** Which child an application derives. */
export interface BIP85IndexOptions {
  /** Child index, the last level of the path. Default: 0 */
  readonly index?: number;
}

/** Entropy an application took, and the path it came from. */
export interface BIP85Entropy {
  /** The path, `'` on every level. */
  readonly path: string;
  /** The bytes the application kept, the leading ones of the 64. */
  readonly entropy: Uint8Array;
}

/** What `deriveMnemonic` writes and where. */
export interface BIP85MnemonicOptions extends BIP85IndexOptions {
  /** 12, 15, 18, 21 or 24. Default: 12 */
  readonly words?: number;
  /** Word list, which is also a level of the path. Default: english */
  readonly language?: BIP39Language;
}

/** A child mnemonic, application 39. */
export interface BIP85Mnemonic extends BIP85Entropy {
  readonly mnemonic: string;
}

/**
 * A child BIP39 mnemonic, application 39: `m/83696968'/39'/{language}'/{words}'/{index}'`.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Word count, word list and index
 * @returns {Promise<BIP85Mnemonic>} The mnemonic, its entropy and path
 * @throws {RangeError} For a word count, language or index outside the BIP85 tables
 * @example
 * (await deriveMnemonic(xprv)).mnemonic; // 'girl mad pet galaxy egg matter ...'
 */
export async function deriveMnemonic(
  root: string | HDKey,
  options: BIP85MnemonicOptions = {},
): Promise<BIP85Mnemonic> {
  assertOptions(options, "deriveMnemonic(root, { words, language, index })");
  const { words = 12, language = "english" } = options;
  if (typeof words !== "number" || !Object.hasOwn(WORD_BYTES, words)) {
    throw new RangeError("BIP85 mnemonics have 12, 15, 18, 21 or 24 words");
  }
  if (!isBIP39Language(language)) throw new RangeError("Unknown BIP39 language");
  const path = `m/${BIP85_PURPOSE}'/39'/${LANGUAGE_CODES[language]}'/${words}'/${childIndex(options.index)}'`;
  const { key } = readRoot(root);
  const entropy = entropyAt(key, path).slice(0, WORD_BYTES[words]);
  const wordlist = await loadWordlist(language);
  return { path, entropy, mnemonic: entropyToMnemonic(entropy, { wordlist }) };
}

/**
 * Takes the leading 32 bytes as a secp256k1 key.
 * @param entropy - 64 bytes of BIP85 entropy
 * @param path - Where it came from, for the error
 * @returns {Uint8Array} The 32-byte key
 * @throws {RangeError} When the bytes are zero or not below the curve order
 */
function secretKey(entropy: Uint8Array, path: string): Uint8Array {
  const key = entropy.slice(0, 32);
  if (!secp256k1.utils.isValidSecretKey(key)) {
    throw new RangeError(`The entropy at ${path} is no secp256k1 key; take the next index`);
  }
  return key;
}

/** An HD seed WIF, application 2. */
export interface BIP85Wif extends BIP85Entropy {
  /** Compressed WIF, testnet when the root is a tprv. */
  readonly wif: string;
}

/**
 * A WIF for the `hdseed` of a Bitcoin Core wallet, application 2: `m/83696968'/2'/{index}'`.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Index
 * @returns {BIP85Wif} The WIF, its 32 bytes of entropy and the path
 * @throws {RangeError} For a bad index, or entropy that is no secp256k1 key
 * @example
 * deriveWif(xprv).wif; // 'Kzyv4uF39d4Jrw2W7UryTHwZr1zQVNk4dAFyqE6BuMrMh1Za7uhp'
 */
export function deriveWif(root: string | HDKey, options: BIP85IndexOptions = {}): BIP85Wif {
  assertOptions(options, "deriveWif(root, { index })");
  const path = `m/${BIP85_PURPOSE}'/2'/${childIndex(options.index)}'`;
  const { key, network } = readRoot(root);
  const entropy = secretKey(entropyAt(key, path), path);
  return { path, entropy, wif: encodeWIF(entropy.toHex(), { chain: "bitcoin", network }) };
}

/** A child extended private key, application 32. */
export interface BIP85Xprv extends BIP85Entropy {
  /** xprv, or tprv when the root is one, at depth 0. */
  readonly extendedPrivateKey: string;
}

/**
 * A child master key, application 32, chain code first and key last, the reverse of BIP32.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Index
 * @returns {BIP85Xprv} The extended key, its 64 bytes of entropy and the path
 * @throws {RangeError} For a bad index, or a key half that is no secp256k1 key
 * @example
 * deriveXprv(xprv).extendedPrivateKey; // 'xprv9s21ZrQH143K2srSbCSg4m4kLvPMzcWydgmKEnMm...'
 */
export function deriveXprv(root: string | HDKey, options: BIP85IndexOptions = {}): BIP85Xprv {
  assertOptions(options, "deriveXprv(root, { index })");
  const path = `m/${BIP85_PURPOSE}'/32'/${childIndex(options.index)}'`;
  const { key } = readRoot(root);
  const entropy = entropyAt(key, path);
  const child = new HDKey({
    versions: key.versions,
    chainCode: entropy.slice(0, 32),
    privateKey: secretKey(entropy.slice(32), path),
  });
  return { path, entropy, extendedPrivateKey: child.privateExtendedKey };
}

/** How many bytes `deriveHex` keeps. */
export interface BIP85HexOptions extends BIP85IndexOptions {
  /** 16 to 64. Default: 64 */
  readonly bytes?: number;
}

/**
 * Raw entropy, application 128169: `m/83696968'/128169'/{bytes}'/{index}'`.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Byte count and index
 * @returns {BIP85Entropy} The leading bytes and the path
 * @throws {RangeError} For a byte count outside 16 to 64, or a bad index
 * @example
 * deriveHex(xprv).entropy.toHex(); // '492db4698cf3b73a...'
 */
export function deriveHex(root: string | HDKey, options: BIP85HexOptions = {}): BIP85Entropy {
  assertOptions(options, "deriveHex(root, { bytes, index })");
  const { bytes = 64 } = options;
  if (!Number.isSafeInteger(bytes) || bytes < 16 || bytes > 64) {
    throw new RangeError("BIP85 hex takes 16 to 64 bytes");
  }
  const path = `m/${BIP85_PURPOSE}'/128169'/${bytes}'/${childIndex(options.index)}'`;
  return { path, entropy: entropyAt(readRoot(root).key, path).slice(0, bytes) };
}

/**
 * BIP85-DRNG-SHAKE256, for applications that want more than 64 bytes.
 * @param entropy - The 64 bytes `deriveEntropy` returns
 * @param bytes - How many bytes of the stream to read
 * @returns {Uint8Array} The leading bytes of the stream
 * @throws {RangeError} For a seed that isn't 64 bytes, or a count that isn't a whole number
 * @example
 * drng(deriveEntropy(xprv, "m/83696968'/0'/0'"), 80).toHex(); // 'b78b1ee6b345eae6...'
 */
export function drng(entropy: Uint8Array, bytes: number): Uint8Array {
  if (!(entropy instanceof Uint8Array) || entropy.length !== 64) {
    throw new RangeError("The BIP85 DRNG is seeded with exactly 64 bytes of entropy");
  }
  if (!Number.isSafeInteger(bytes) || bytes < 0) {
    throw new RangeError("The BIP85 DRNG reads a whole number of bytes");
  }
  return shake256(entropy, bytes);
}

/**
 * Reads a number an application writes into its path.
 * @param value - Caller's number
 * @param range - Smallest and largest value, and the error for anything else
 * @returns {number} The number
 * @throws {RangeError} Outside the range
 */
function levelIn(
  value: unknown,
  range: { readonly from: number; readonly to: number; readonly message: string },
): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value)) {
    throw new RangeError(range.message);
  }
  if (value < range.from || value > range.to) throw new RangeError(range.message);
  return value;
}

/** How long a password comes out. */
export interface BIP85PasswordOptions extends BIP85IndexOptions {
  /** Characters to keep: 20 to 86 for base64, 10 to 80 for base85. */
  readonly length: number;
}

/** A child password, application 707764 or 707785. */
export interface BIP85Password extends BIP85Entropy {
  readonly password: string;
}

/** One password application: its number, its lengths and its alphabet. */
interface PasswordFormat {
  readonly name: string;
  readonly application: number;
  readonly from: number;
  readonly to: number;
  readonly encode: (entropy: Uint8Array) => string;
}

/**
 * Encodes all 64 bytes and keeps the leading characters.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Length and index
 * @param format - Which password application
 * @returns {BIP85Password} The password, its 64 bytes of entropy and the path
 * @throws {RangeError} For a length the application doesn't take, or a bad index
 */
function passwordOf(
  root: string | HDKey,
  options: BIP85PasswordOptions,
  format: PasswordFormat,
): BIP85Password {
  const { name, application, from, to } = format;
  assertOptions(options, `derive${name}Password(root, { length, index })`);
  const { length, index } = { ...options };
  const message = `A BIP85 ${name.toLowerCase()} password has ${from} to ${to} characters`;
  const kept = levelIn(length, { from, to, message });
  const path = `m/${BIP85_PURPOSE}'/${application}'/${kept}'/${childIndex(index)}'`;
  const entropy = entropyAt(readRoot(root).key, path);
  return { path, entropy, password: format.encode(entropy).slice(0, kept) };
}

/**
 * A base64 password, application 707764: `m/83696968'/707764'/{length}'/{index}'`.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Length, 20 to 86, and index
 * @returns {BIP85Password} The password, its 64 bytes of entropy and the path
 * @throws {RangeError} For a length outside 20 to 86, or a bad index
 * @example
 * deriveBase64Password(xprv, { length: 21 }).password; // 'dKLoepugzdVJvdL56ogNV'
 */
export function deriveBase64Password(
  root: string | HDKey,
  options: BIP85PasswordOptions,
): BIP85Password {
  return passwordOf(root, options, {
    name: "Base64",
    application: 707764,
    from: 20,
    to: 86,
    encode: (entropy) => base64.encode(entropy),
  });
}

/**
 * A base85 password in RFC 1924's alphabet, application 707785.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Length, 10 to 80, and index
 * @returns {BIP85Password} The password, its 64 bytes of entropy and the path
 * @throws {RangeError} For a length outside 10 to 80, or a bad index
 * @example
 * deriveBase85Password(xprv, { length: 12 }).password; // '_s`{TW89)i4`'
 */
export function deriveBase85Password(
  root: string | HDKey,
  options: BIP85PasswordOptions,
): BIP85Password {
  return passwordOf(root, options, {
    name: "Base85",
    application: 707785,
    from: 10,
    to: 80,
    encode: (entropy) => base85.encode(entropy),
  });
}

/** The die and how often it's thrown. */
export interface BIP85DiceOptions extends BIP85IndexOptions {
  /** Sides of the die, 2 to 2147483647. */
  readonly sides: number;
  /** How many rolls, 1 to 65536. */
  readonly rolls: number;
}

/** Dice rolls, application 89101. */
export interface BIP85Dice extends BIP85Entropy {
  /** Each roll from 0 to `sides - 1`, as the spec counts them. */
  readonly rolls: readonly number[];
}

/**
 * Throws the die on the DRNG, skipping every trial at or past the number of sides.
 * @param entropy - 64 bytes of BIP85 entropy
 * @param sides - Sides of the die
 * @param count - How many rolls to keep
 * @returns {number[]} The rolls
 */
function roll(entropy: Uint8Array, sides: number, count: number): number[] {
  const bits = 32 - Math.clz32(sides - 1);
  const width = Math.ceil(bits / 8);
  const excess = 2 ** (8 * width - bits);
  const rolls: number[] = [];
  let stream = drng(entropy, width * count);
  for (let offset = 0; rolls.length < count; offset += width) {
    if (offset === stream.length) stream = drng(entropy, stream.length * 2);
    const read = stream.subarray(offset, offset + width).reduce((sum, byte) => sum * 256 + byte, 0);
    const trial = Math.floor(read / excess);
    if (trial < sides) rolls.push(trial);
  }
  return rolls;
}

/**
 * Dice rolls, application 89101: `m/83696968'/89101'/{sides}'/{rolls}'/{index}'`.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Sides, rolls and index
 * @returns {BIP85Dice} The rolls from 0, their 64 bytes of entropy and the path
 * @throws {RangeError} For sides or rolls outside their range, or a bad index
 * @example
 * deriveDice(xprv, { sides: 6, rolls: 10 }).rolls; // [1, 0, 0, 2, 0, 1, 5, 5, 2, 4]
 */
export function deriveDice(root: string | HDKey, options: BIP85DiceOptions): BIP85Dice {
  assertOptions(options, "deriveDice(root, { sides, rolls, index })");
  const { sides, rolls, index } = { ...options };
  const faces = levelIn(sides, {
    from: 2,
    to: MAX_LEVEL,
    message: `BIP85 dice have 2 to ${MAX_LEVEL} sides`,
  });
  const count = levelIn(rolls, {
    from: 1,
    to: MAX_ROLLS,
    message: `BIP85 dice roll 1 to ${MAX_ROLLS} times a call`,
  });
  const path = `m/${BIP85_PURPOSE}'/89101'/${faces}'/${count}'/${childIndex(index)}'`;
  const entropy = entropyAt(readRoot(root).key, path);
  return { path, entropy, rolls: roll(entropy, faces, count) };
}

/** Which Nostr key to derive. */
export interface BIP85NostrOptions {
  /** Key namespace, from 1. Default: 1 */
  readonly identity?: number;
  /** Account within the identity, the last level of the path, from 1. Default: 1 */
  readonly index?: number;
}

/** A Nostr secret key, application 128002. */
export interface BIP85Nostr extends BIP85Entropy {
  /** The key in bech32, as NIP-19 writes it. */
  readonly nsec: string;
}

/**
 * A Nostr secret key, application 128002: `m/83696968'/128002'/{identity}'/{index}'`.
 * @param root - Master xprv or tprv, or a depth 0 node
 * @param options - Identity and account index, both from 1
 * @returns {BIP85Nostr} The nsec, its 32 bytes of entropy and the path
 * @throws {RangeError} For an identity or index of 0, which BIP85 reserves, or a bad one
 * @example
 * deriveNostr(xprv).nsec; // 'nsec1lahtplxlrmu852sxkrtcsn2ftdyx6ra2yy8flq8j8ltyn4hpznfq23uvqz'
 */
export function deriveNostr(root: string | HDKey, options: BIP85NostrOptions = {}): BIP85Nostr {
  assertOptions(options, "deriveNostr(root, { identity, index })");
  const { identity = 1, index = 1 } = options;
  const level = (value: number, name: string): number =>
    levelIn(value, {
      from: 1,
      to: MAX_LEVEL,
      message: `A Nostr ${name} runs from 1 to ${MAX_LEVEL}; BIP85 keeps 0 for later`,
    });
  const path = `m/${BIP85_PURPOSE}'/128002'/${level(identity, "identity")}'/${level(index, "index")}'`;
  const entropy = secretKey(entropyAt(readRoot(root).key, path), path);
  return { path, entropy, nsec: bech32.encode("nsec", entropy) };
}
