import { BIP44 } from "../utils/bip44/index.ts";
import { concatBytes } from "../utils/bytes.ts";
import { AbstractDualCurveBlockchain, withScheme } from "../utils/dual-curve.ts";
import { decodeKeyPublic, generateKeyPublic as getEd25519KeyPublic } from "../utils/ed25519.ts";
import { deriveMnemonicEntropy } from "../utils/hd.ts";
import { assertSignOptions, assertVerifyOptions } from "../utils/options.ts";
import { signMessage, verifyMessage } from "../utils/signing.ts";
import { generateKeyPublic as getSr25519KeyPublic } from "../utils/sr25519.ts";
import { decodeSS58, encodeSS58, isSS58Prefix, MAX_SS58_PREFIX } from "../utils/ss58.ts";
import { deriveEd25519, deriveSr25519, miniSecret, parseJunctions } from "../utils/substrate.ts";
import type {
  AddressType,
  HDWalletOptions,
  KeyOptions,
  Options,
  SignMessageOptions,
  VerifyMessageOptions,
  Wallet,
} from "../types.ts";

/** sr25519 first: subkey and the wallets start new accounts on it. */
const SCHEMES = ["sr25519", "ed25519"] as const;

/** Polkadot's own prefix, written on mainnet unless the options name another. */
const POLKADOT_PREFIX = 0;

/** The generic Substrate prefix, which Westend and Paseo addresses carry. */
const SUBSTRATE_PREFIX = 42;

/** What the polkadot.js extension wraps around a message before `signRaw` signs it. */
const WRAP_OPEN = new TextEncoder().encode("<Bytes>");
const WRAP_CLOSE = new TextEncoder().encode("</Bytes>");

/**
 * Checks whether bytes already start with `<Bytes>` and end with `</Bytes>`.
 * @param bytes - The bytes to check
 * @returns {boolean} Whether both markers are in place
 */
function isWrapped(bytes: Uint8Array): boolean {
  if (bytes.length < WRAP_OPEN.length + WRAP_CLOSE.length) return false;
  const tail = bytes.subarray(bytes.length - WRAP_CLOSE.length);
  return (
    WRAP_OPEN.every((byte, at) => bytes[at] === byte) &&
    WRAP_CLOSE.every((byte, at) => tail[at] === byte)
  );
}

/**
 * Wraps a message in `<Bytes>` the way polkadot.js `u8aWrapBytes` does, once and no more.
 * @param message - The message as text or bytes
 * @returns {Uint8Array} The wrapped bytes a wallet signs
 */
function wrapBytes(message: string | Uint8Array): Uint8Array {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  return isWrapped(bytes) ? bytes : concatBytes(WRAP_OPEN, bytes, WRAP_CLOSE);
}

/**
 * Refuses the 64-byte sr25519 secret where an ed25519 seed belongs, before noble names a length.
 * @param keyPrivate - The private key as hex
 * @throws {RangeError} When the key is 64 bytes
 */
function assertEd25519Seed(keyPrivate: string): void {
  if (keyPrivate.length !== 128) return;
  throw new RangeError(
    "A 64-byte secret is an sr25519 key; ed25519 takes the 32-byte seed, so drop the ed25519 scheme",
  );
}

/** Polkadot and any Substrate chain: sr25519 as the wallets make it, ed25519 on request. */
export class Polkadot extends AbstractDualCurveBlockchain {
  override readonly name = "polkadot";
  override readonly curve = SCHEMES;
  override readonly bip44 = BIP44.POLKADOT;
  /** SS58 network prefix every address of this instance carries. */
  readonly ss58Prefix: number;

  constructor(options?: Options) {
    super(options);
    const prefix =
      options?.ss58Prefix ?? (this.network === "testnet" ? SUBSTRATE_PREFIX : POLKADOT_PREFIX);
    if (!isSS58Prefix(prefix)) {
      throw new RangeError(`An SS58 prefix is 0 to ${MAX_SS58_PREFIX}, but not 46 or 47`);
    }
    this.ss58Prefix = prefix;
  }

  /**
   * sr25519, the scheme Polkadot wallets pick unless told otherwise.
   * @returns {AddressType} `sr25519`
   */
  override get defaultAddressType(): AddressType {
    return "sr25519";
  }

  /**
   * Substrate wallets walk `//hard` junctions, not BIP44, so there is no path to build here.
   * @returns {string} Never returns
   * @throws {RangeError} Always, naming the path shape to use instead
   */
  override getDerivationPath(): string {
    throw new RangeError(
      "Polkadot derives Substrate junctions such as //0 from the mnemonic, not BIP44 paths",
    );
  }

  /**
   * Derives like subkey and polkadot.js: the mini secret from the entropy, then the junctions.
   * @param mnemonic - BIP39 words
   * @param options - The path, `//hard` and `/soft` junctions such as `//polkadot/0` or empty or
   * `m` for the root key, the scheme as `addressType`, then checksum override, word list and the
   * `///password` passphrase; `coleman` throws, and so does a soft junction on ed25519
   * @returns {Wallet} The wallet at the path
   */
  override deriveHDWallet(mnemonic: string, options: HDWalletOptions): Wallet {
    const { path, passphrase, allowInvalidChecksum, wordlist, coleman, ...walletOptions } =
      withScheme(options);
    if (coleman !== undefined && coleman !== false) {
      throw new Error(
        "Polkadot reads BIP39 lengths only, as subkey and polkadot.js do; drop coleman",
      );
    }
    const curve = this.resolveCurve(walletOptions);
    const junctions = parseJunctions(path);
    const { entropy, checksumValid } = deriveMnemonicEntropy(mnemonic, {
      allowInvalidChecksum,
      wordlist,
    });
    const seed = miniSecret(entropy, passphrase);
    const keyPrivate =
      curve === "ed25519" ? deriveEd25519(seed, junctions).toHex() : deriveSr25519(seed, junctions);
    const wallet = this.deriveWallet(keyPrivate, walletOptions);
    if (checksumValid) return wallet;
    return {
      ...wallet,
      warnings: [
        "BIP39 checksum is invalid. Derived from the supplied words without repairing the checksum.",
      ],
    };
  }

  /**
   * The public key under the scheme in the options, sr25519 by default.
   * @param keyPrivate - An ed25519 seed, or on sr25519 the mini secret or the 64-byte secret
   * @param options - Key options that may carry the scheme
   * @returns {string} The 32-byte public key as hex
   */
  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    if (this.resolveCurve(options) === "sr25519") return getSr25519KeyPublic(keyPrivate);
    assertEd25519Seed(keyPrivate);
    return getEd25519KeyPublic(keyPrivate);
  }

  /**
   * Writes the SS58 address under this prefix. Both schemes share it, so the type just names one.
   * @param keyPublic - The 32-byte public key as hex
   * @param type - `sr25519` or `ed25519`; anything else throws
   * @returns {string} The SS58 address
   */
  override getAddress(keyPublic: string, type?: AddressType): string {
    if (type !== undefined) this.resolveCurve({ scheme: type });
    return encodeSS58(decodeKeyPublic(keyPublic, "Polkadot"), this.ss58Prefix);
  }

  /**
   * Checks the checksum, a 32-byte account and the prefix of this instance.
   * @param address - The SS58 address to check
   * @returns {boolean} Whether a chain with this prefix takes it
   */
  override validateAddress(address: string): boolean {
    return decodeSS58(address)?.prefix === this.ss58Prefix;
  }

  /**
   * Signs the message wrapped in `<Bytes>`, as the polkadot.js extension does in `signRaw`.
   * @param message - The message to sign
   * @param options - The private key as hex and the scheme, sr25519 by default
   * @returns {string} The 64-byte signature as hex; random on sr25519, so it differs every time
   */
  override signMessage(message: string | Uint8Array, options: SignMessageOptions): string {
    assertSignOptions(options);
    const curve = this.resolveCurve(options);
    if (curve === "ed25519") assertEd25519Seed(options.privateKey);
    return signMessage(wrapBytes(message), { ...options, curve });
  }

  /**
   * Checks the wrapped or raw message like polkadot.js `signatureVerify`, on either scheme.
   * @param message - The signed message
   * @param options - The signature, the public key as hex, and the scheme if it is known
   * @returns {boolean} Whether the signature is valid, false for a malformed key too
   */
  override verifyMessage(message: string | Uint8Array, options: VerifyMessageOptions): boolean {
    assertVerifyOptions(options);
    const curves = options.scheme === undefined ? this.curve : [this.resolveCurve(options)];
    return curves.some((curve) =>
      [wrapBytes(message), message].some((signed) => verifyMessage(signed, { ...options, curve })),
    );
  }
}

export default Polkadot;
