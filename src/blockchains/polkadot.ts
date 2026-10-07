import { AbstractBlockchain } from "../blockchain.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { concatBytes } from "../utils/bytes.ts";
import { decodeKeyPublic, generateKeyPublic } from "../utils/ed25519.ts";
import { ed25519SignMessage, ed25519VerifyMessage } from "../utils/ed25519-chains.ts";
import { deriveMnemonicEntropy } from "../utils/hd.ts";
import { decodeSS58, encodeSS58, isSS58Prefix, MAX_SS58_PREFIX } from "../utils/ss58.ts";
import { deriveEd25519Hard, miniSecret, parseHardJunctions } from "../utils/substrate.ts";
import type {
  AddressType,
  Curve,
  HDWalletOptions,
  KeyOptions,
  Options,
  SigningOptions,
  Wallet,
} from "../types.ts";

/** Polkadot's own prefix, written on mainnet unless the options name another. */
const POLKADOT_PREFIX = 0;

/** The generic Substrate prefix, which Westend and Paseo addresses carry. */
const SUBSTRATE_PREFIX = 42;

/** What the polkadot.js extension wraps around a message before `signRaw` signs it. */
const WRAP_OPEN = new TextEncoder().encode("<Bytes>");
const WRAP_CLOSE = new TextEncoder().encode("</Bytes>");

/**
 * Checks whether bytes start and end with the given markers.
 * @param bytes - The bytes to check
 * @param open - Expected first bytes
 * @param close - Expected last bytes
 * @returns {boolean} Whether both markers are in place
 */
function isWrapped(bytes: Uint8Array, open: Uint8Array, close: Uint8Array): boolean {
  if (bytes.length < open.length + close.length) return false;
  const tail = bytes.subarray(bytes.length - close.length);
  return (
    open.every((byte, at) => bytes[at] === byte) && close.every((byte, at) => tail[at] === byte)
  );
}

/**
 * Wraps a message in `<Bytes>` the way polkadot.js `u8aWrapBytes` does, once and no more.
 * @param message - The message as text or bytes
 * @returns {Uint8Array} The wrapped bytes a wallet signs
 */
function wrapBytes(message: string | Uint8Array): Uint8Array {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  return isWrapped(bytes, WRAP_OPEN, WRAP_CLOSE)
    ? bytes
    : concatBytes(WRAP_OPEN, bytes, WRAP_CLOSE);
}

/** Polkadot and any Substrate chain on ed25519 accounts. sr25519, the wallet default, waits. */
export class Polkadot extends AbstractBlockchain {
  override readonly name = "polkadot";
  override readonly curve: Curve = "ed25519";
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

  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate);
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
   * Derives like subkey and polkadot.js: the mini secret from the entropy, then hard junctions.
   * @param mnemonic - BIP39 words
   * @param path - `//hard` junctions such as `//polkadot//0`, or empty or `m` for the root key
   * @param options - Checksum override, word list and passphrase, the `///password` of a Substrate URI
   * @param addressType - Any type throws, Polkadot has one address format
   * @returns {Wallet} The wallet at the path
   */
  override deriveHDWallet(
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: AddressType,
  ): Wallet {
    this.refuseAddressType(addressType);
    const { passphrase, allowInvalidChecksum, wordlist, ...keyOptions } = options ?? {};
    const junctions = parseHardJunctions(path);
    const { entropy, checksumValid } = deriveMnemonicEntropy(
      mnemonic,
      allowInvalidChecksum,
      wordlist,
    );
    const seed = deriveEd25519Hard(miniSecret(entropy, passphrase), junctions);
    const wallet = this.deriveWallet(seed.toHex(), keyOptions);
    if (checksumValid) return wallet;
    return {
      ...wallet,
      warnings: [
        "BIP39 checksum is invalid. Derived from the supplied words without repairing the checksum.",
      ],
    };
  }

  /**
   * Writes the public key as an SS58 address under this instance's prefix.
   * @param keyPublic - The 32-byte ed25519 public key as hex
   * @param type - Any type throws, Polkadot has one address format
   * @returns {string} The SS58 address
   */
  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
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
   * @param keyPrivate - The 32-byte ed25519 seed as hex
   * @param options - Key options
   * @returns {string} The 64-byte ed25519 signature as hex
   */
  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ): string {
    return ed25519SignMessage(wrapBytes(message), keyPrivate, options);
  }

  /**
   * Checks ed25519 over the wrapped message, or the raw one as polkadot.js `signatureVerify` does.
   * @param message - The signed message
   * @param signature - The signature as hex
   * @param keyPublic - The public key as hex
   * @param options - Key options
   * @returns {boolean} Whether the signature is valid, false for a malformed key too
   */
  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: SigningOptions,
  ): boolean {
    return (
      ed25519VerifyMessage(wrapBytes(message), signature, keyPublic, options) ||
      ed25519VerifyMessage(message, signature, keyPublic, options)
    );
  }
}

export default Polkadot;
