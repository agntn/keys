import { BIP44 } from "../utils/bip44/index.ts";
import { concatBytes } from "../utils/bytes.ts";
import { decodeKeyPublic } from "../utils/ed25519.ts";
import { AbstractEd25519Blockchain } from "../utils/ed25519-chains.ts";
import { deriveMnemonicEntropy } from "../utils/hd.ts";
import { decodeSS58, encodeSS58, isSS58Prefix, MAX_SS58_PREFIX } from "../utils/ss58.ts";
import { deriveEd25519Hard, miniSecret, parseHardJunctions } from "../utils/substrate.ts";
import type {
  AddressType,
  HDWalletOptions,
  Options,
  SignMessageOptions,
  VerifyMessageOptions,
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

/** Polkadot and any Substrate chain on ed25519 accounts. sr25519, the wallet default, waits. */
export class Polkadot extends AbstractEd25519Blockchain {
  override readonly name = "polkadot";
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
   * @param options - The path, `//hard` junctions such as `//polkadot//0` or empty or `m` for the
   * root key, then checksum override, word list and the `///password` passphrase; `coleman` and
   * any address type throw, Polkadot has one address format
   * @returns {Wallet} The wallet at the path
   */
  override deriveHDWallet(mnemonic: string, options: HDWalletOptions): Wallet {
    const {
      path,
      passphrase,
      allowInvalidChecksum,
      wordlist,
      coleman,
      addressType,
      ...keyOptions
    } = options;
    this.refuseAddressType(addressType);
    if (coleman !== undefined && coleman !== false) {
      throw new Error(
        "Polkadot reads BIP39 lengths only, as subkey and polkadot.js do; drop coleman",
      );
    }
    const junctions = parseHardJunctions(path);
    const { entropy, checksumValid } = deriveMnemonicEntropy(mnemonic, {
      allowInvalidChecksum,
      wordlist,
    });
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
   * @param options - The 32-byte ed25519 seed as hex
   * @returns {string} The 64-byte ed25519 signature as hex
   */
  override signMessage(message: string | Uint8Array, options: SignMessageOptions): string {
    return super.signMessage(wrapBytes(message), options);
  }

  /**
   * Checks ed25519 over the wrapped message, or the raw one as polkadot.js `signatureVerify` does.
   * @param message - The signed message
   * @param options - The signature and the public key as hex
   * @returns {boolean} Whether the signature is valid, false for a malformed key too
   */
  override verifyMessage(message: string | Uint8Array, options: VerifyMessageOptions): boolean {
    return (
      super.verifyMessage(wrapBytes(message), options) || super.verifyMessage(message, options)
    );
  }
}

export default Polkadot;
