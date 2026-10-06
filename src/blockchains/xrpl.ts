import { base58 } from "@agntn/encodings/base58";
import { sha512 } from "@agntn/hashes";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hash160 } from "../utils/address.ts";
import { BIP44Change } from "../utils/bip44/paths.ts";
import { concatBytes } from "../utils/bytes.ts";
import { AbstractDualCurveBlockchain } from "../utils/dual-curve.ts";
import { generateKeyPublic as getEd25519KeyPublic } from "../utils/ed25519.ts";
import { convertPublicKey } from "../utils/secp256k1/index.ts";
import { decodeKeyPrivate } from "../utils/secp256k1/decode.ts";
import { generateKeyPublic as getSecp256k1KeyPublic } from "../utils/secp256k1/keys.ts";
import { assertNoRecoveryByte } from "../utils/signing.ts";
import type {
  AddressType,
  Curve,
  HDWalletOptions,
  KeyOptions,
  SigningOptions,
  Wallet,
} from "../types.ts";

/** secp256k1 first: rippled's `wallet_propose` default, and the only curve BIP39 words reach. */
const CURVES = ["secp256k1", "ed25519"] as const;

/** Version byte of a classic address, the one that makes it start with `r`. */
const ACCOUNT_VERSION = 0x00;

/** Version bytes of a family seed: `s...` for secp256k1, `sEd...` for ed25519. */
const SEED_VERSIONS: Readonly<Record<Curve, Uint8Array>> = {
  secp256k1: Uint8Array.of(0x21),
  ed25519: Uint8Array.of(0x01, 0xe1, 0x4b),
};

/** A family seed carries 16 bytes of entropy under its version. */
const SEED_ENTROPY_BYTES = 16;

/** XRPL writes an ed25519 key as 33 bytes, this byte and the 32 the curve gives. */
const ED25519_KEY_PREFIX = 0xed;

/** Classic addresses in XRPL's base58 alphabet, which has Bitcoin's characters in another order. */
const CLASSIC_ADDRESS = /^r[1-9A-HJ-NP-Za-km-z]{24,34}$/u;

const { Fn } = secp256k1.Point;

/**
 * SHA-512Half, the first 32 bytes of SHA-512, which XRPL uses wherever it needs 256 bits.
 * @param data - Bytes to hash
 * @returns {Uint8Array} The 32-byte digest
 */
function sha512Half(data: Uint8Array): Uint8Array {
  return sha512(data).slice(0, 32);
}

/**
 * Writes a number as four big-endian bytes, the way rippled feeds counters into its hashes.
 * @param value - Unsigned 32-bit value
 * @returns {Uint8Array} The four bytes
 */
function uint32(value: number): Uint8Array {
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value);
  return bytes;
}

/**
 * Hashes the input with a growing counter until SHA-512Half lands in 1 to n minus 1, as rippled
 * does for both halves of a secp256k1 family key.
 * @param input - Seed entropy, or the root public key followed by the account index
 * @returns {bigint} The first scalar in range
 * @throws {RangeError} When no counter gives one, which no input is known to do
 */
function deriveScalar(input: Uint8Array): bigint {
  for (let sequence = 0; sequence <= 0xff_ff_ff_ff; sequence++) {
    const scalar = BigInt(`0x${sha512Half(concatBytes(input, uint32(sequence))).toHex()}`);
    if (scalar > 0n && scalar < Fn.ORDER) return scalar;
  }
  throw new RangeError("No secp256k1 scalar comes out of this seed");
}

/**
 * The secp256k1 key of account 0 in a family: a root key from the seed, plus a scalar hashed from
 * the root's public key, mod n.
 * @param entropy - The 16 bytes of a family seed
 * @returns {string} The private key as 64 hex digits
 */
function deriveSecp256k1Key(entropy: Uint8Array): string {
  const root = deriveScalar(entropy);
  const rootPublic = secp256k1.Point.BASE.multiply(root).toBytes(true);
  const intermediate = deriveScalar(concatBytes(rootPublic, uint32(0)));
  return Fn.add(root, intermediate).toString(16).padStart(64, "0");
}

/**
 * Reads a family seed into its entropy and the curve its version names.
 * @param seed - Family seed, `s...` or `sEd...`
 * @returns {{ entropy: Uint8Array; curve: Curve }} The 16 bytes of entropy and the curve
 * @throws {RangeError} When the text is not base58, the checksum misses, or the version is unknown
 */
function decodeSeed(seed: string): { readonly entropy: Uint8Array; readonly curve: Curve } {
  let bytes: Uint8Array;
  try {
    bytes = base58.decode(seed, { alphabet: "ripple", check: true });
  } catch {
    throw new RangeError(
      "Family seed is not XRPL base58 with a valid checksum; look for a mistyped character",
    );
  }
  for (const curve of CURVES) {
    const version = SEED_VERSIONS[curve];
    const body = bytes.subarray(version.length);
    if (body.length === SEED_ENTROPY_BYTES && version.every((byte, i) => bytes[i] === byte)) {
      return { entropy: body, curve };
    }
  }
  throw new RangeError("Family seed version is neither secp256k1 (s...) nor ed25519 (sEd...)");
}

/**
 * Reads an ed25519 public key as XRPL writes it, 33 bytes behind `ED`, or as the bare 32.
 * @param keyPublic - Public key as hex
 * @returns {Uint8Array} The 33 bytes XRPL hashes into an account ID
 * @throws {RangeError} When the key is neither shape
 */
function decodeEd25519Key(keyPublic: string): Uint8Array {
  const bytes = Uint8Array.fromHex(keyPublic);
  if (bytes.length === 33 && bytes[0] === ED25519_KEY_PREFIX) return bytes;
  if (bytes.length === 32) return concatBytes(Uint8Array.of(ED25519_KEY_PREFIX), bytes);
  throw new RangeError("XRPL ed25519 public key must be 32 bytes, or 33 starting with ED");
}

/**
 * Tells the curve from the key itself: XRPL marks ed25519 keys with a leading `ED` byte, and no
 * SEC1 key is 32 bytes long.
 * @param keyPublic - Public key as hex
 * @returns {Curve} ed25519 for 32 bytes or 33 starting with `ED`, secp256k1 otherwise
 */
function keyCurve(keyPublic: string): Curve {
  return /^(?:ed)?[0-9a-f]{64}$/iu.test(keyPublic) ? "ed25519" : "secp256k1";
}

/**
 * Turns a message into bytes, UTF-8 for text.
 * @param message - Text or bytes
 * @returns {Uint8Array} The message bytes
 */
function messageBytes(message: string | Uint8Array): Uint8Array {
  return typeof message === "string" ? new TextEncoder().encode(message) : message;
}

/**
 * XRP Ledger implementation. secp256k1 by default and ed25519 on request, the scheme riding in
 * the address type as on Sui. Mainnet, testnet and devnet share one address format.
 */
export class XRPL extends AbstractDualCurveBlockchain {
  override readonly name = "xrpl";
  override readonly curve = CURVES;
  override readonly bip44 = 144;

  /**
   * secp256k1, the scheme rippled proposes unless told otherwise.
   * @returns {AddressType} `secp256k1`
   */
  override get defaultAddressType(): AddressType {
    return "secp256k1";
  }

  /**
   * XRPL account IDs hash the compressed secp256k1 key.
   * @returns {"compressed"} The form the address hashes
   */
  protected override get addressKeyForm(): "compressed" {
    return "compressed";
  }

  /**
   * BIP44 at `m/44'/144'/account'/change/index`, secp256k1 only like every XRPL wallet that
   * takes BIP39 words.
   * @param account - Account index
   * @param change - Change branch
   * @param addressIndex - Address index
   * @param options - Key options; an ed25519 scheme is refused
   * @returns {string} The BIP44 path
   */
  override getDerivationPath(
    account = 0,
    change: number = BIP44Change.EXTERNAL,
    addressIndex = 0,
    options?: KeyOptions,
  ): string {
    this.refuseEd25519HD(options?.scheme);
    return super.getDerivationPath(account, change, addressIndex, options);
  }

  override deriveHDWallet(
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: AddressType,
  ): Wallet {
    this.refuseEd25519HD(addressType ?? options?.scheme);
    return super.deriveHDWallet(mnemonic, path, options, addressType);
  }

  /**
   * Derives the wallet behind a family seed, the `s...` secret XRPL wallets print. Its version
   * picks the curve, and an address type overrides it like `deriveKeypair` in ripple-keypairs.
   * @param seed - Family seed, `s...` for secp256k1 or `sEd...` for ed25519
   * @param options - Key options of the wallet
   * @param addressType - Scheme that wins over the one the seed names
   * @returns {Wallet} The private key, the public key and the classic address of account 0
   */
  override deriveSeedWallet(seed: string, options?: KeyOptions, addressType?: AddressType): Wallet {
    const { entropy, curve: seedCurve } = decodeSeed(seed);
    const scheme = addressType ?? options?.scheme ?? seedCurve;
    const curve = this.resolveCurve({ scheme });
    const keyPrivate =
      curve === "ed25519" ? sha512Half(entropy).toHex() : deriveSecp256k1Key(entropy);
    return this.deriveWallet(keyPrivate, options, curve);
  }

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    if (this.resolveCurve(options) === "ed25519") {
      return `ed${getEd25519KeyPublic(keyPrivate)}`;
    }
    return getSecp256k1KeyPublic(keyPrivate, { compressed: true });
  }

  /**
   * Writes the classic address: the hash160 of the key in XRPL's base58 with a checksum.
   * @param keyPublic - SEC1 key, or an ed25519 key with or without its `ED` byte
   * @param type - `secp256k1` or `ed25519`; read from the key when left out
   * @returns {string} The `r...` address
   */
  override getAddress(keyPublic: string, type?: AddressType): string {
    const scheme = type?.toLowerCase() ?? keyCurve(keyPublic);
    if (scheme !== "ed25519" && scheme !== "secp256k1") {
      throw new RangeError(
        `Address type ${JSON.stringify(type)} is not supported for xrpl. Supported: secp256k1, ed25519`,
      );
    }
    if (scheme === "secp256k1" && keyCurve(keyPublic) === "ed25519") {
      throw new RangeError(
        "This is an ed25519 key, which no secp256k1 address hashes; pass ed25519 as the address type",
      );
    }
    const keyBytes =
      scheme === "ed25519"
        ? decodeEd25519Key(keyPublic)
        : Uint8Array.fromHex(convertPublicKey(keyPublic));
    const payload = concatBytes(Uint8Array.of(ACCOUNT_VERSION), hash160(keyBytes));
    return base58.encode(payload, { alphabet: "ripple", check: true });
  }

  override validateAddress(address: string): boolean {
    if (!CLASSIC_ADDRESS.test(address)) return false;
    try {
      const bytes = base58.decode(address, { alphabet: "ripple", check: true });
      return bytes.length === 21 && bytes[0] === ACCOUNT_VERSION;
    } catch {
      return false;
    }
  }

  /**
   * Signs like `sign` in ripple-keypairs: secp256k1 as DER over the SHA-512Half of the message,
   * ed25519 over the message itself.
   * @param message - The message to sign
   * @param keyPrivate - The private key as hex
   * @param options - Key options; `scheme` picks the curve, secp256k1 by default
   * @returns {string} A DER signature on secp256k1, 64 bytes on ed25519, as hex
   */
  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ): string {
    assertNoRecoveryByte(options, "XRPL signs secp256k1 as DER, with no recovery byte");
    const bytes = messageBytes(message);
    if (this.resolveCurve(options) === "ed25519") {
      return ed25519.sign(bytes, Uint8Array.fromHex(keyPrivate)).toHex();
    }
    return secp256k1
      .sign(sha512Half(bytes), decodeKeyPrivate(keyPrivate), { prehash: false, format: "der" })
      .toHex();
  }

  /**
   * Checks a signature the way `verify` in ripple-keypairs does, with the curve read from the key
   * unless the options name it.
   * @param message - The signed message
   * @param signature - DER on secp256k1, 64 bytes on ed25519, as hex
   * @param keyPublic - SEC1 key, or an ed25519 key with or without its `ED` byte
   * @param options - Key options that may name the scheme
   * @returns {boolean} Whether the signature matches
   */
  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    const curve = options?.scheme === undefined ? keyCurve(keyPublic) : this.resolveCurve(options);
    const bytes = messageBytes(message);
    try {
      const signatureBytes = Uint8Array.fromHex(signature);
      if (curve === "ed25519") {
        return ed25519.verify(signatureBytes, bytes, decodeEd25519Key(keyPublic).subarray(1));
      }
      const keyBytes = Uint8Array.fromHex(convertPublicKey(keyPublic));
      return secp256k1.verify(signatureBytes, sha512Half(bytes), keyBytes, {
        prehash: false,
        format: "der",
      });
    } catch {
      return false;
    }
  }

  /**
   * Stops ed25519 before a BIP39 walk: xrpl.js derives those keys over BIP32 on secp256k1 only.
   * @param scheme - Scheme the caller asked for
   * @throws {RangeError} When the scheme is ed25519
   */
  private refuseEd25519HD(scheme: string | undefined): void {
    if (scheme === undefined || this.resolveCurve({ scheme }) !== "ed25519") return;
    throw new RangeError(
      "XRPL wallets derive BIP39 keys on secp256k1 only; use a family seed (sEd...) for ed25519",
    );
  }
}

export default XRPL;
