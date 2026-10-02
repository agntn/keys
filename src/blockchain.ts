import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { BIP44Change, getPath } from "./utils/bip44/index.ts";
import {
  deriveExtendedPublicChild,
  SLIP132_FORMATS,
  type ExtendedKeyFormats,
} from "./utils/extended-key.ts";
import { deriveMnemonicKey } from "./utils/hd.ts";
import type {
  AddressType,
  Blockchain,
  Curve,
  HDWalletOptions,
  KeyOptions,
  Keys,
  MessageSigner,
  Options,
  SigningOptions,
  Wallet,
  XpubWallet,
} from "./types.ts";

/**
 * Shared blockchain behavior. Concrete chains provide key, address, and signing rules.
 */
export abstract class AbstractBlockchain implements Blockchain {
  abstract readonly name: string;
  abstract readonly curve: Curve | readonly Curve[];
  abstract readonly bip44: number;

  readonly network: string;

  constructor(options?: Options) {
    this.network = options?.network || "mainnet";
  }

  /**
   * SLIP-0044 coin type the chain's wallets write on this network.
   * @returns {number} The coin type
   */
  get coinType(): number {
    return this.bip44;
  }

  abstract getKeyPublic(keyPrivate: string, options?: KeyOptions): string;
  abstract getAddress(keyPublic: string, type?: string): string;
  abstract validateAddress(address: string): boolean;
  abstract signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ): string;
  abstract verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: SigningOptions,
  ): boolean;

  generateKeyPrivate(): string {
    const curve = this.curve.includes("secp256k1") ? secp256k1 : ed25519;

    return curve.utils.randomSecretKey().toHex();
  }

  generateKeys(options?: KeyOptions): Keys {
    const privateKey = this.generateKeyPrivate();
    const publicKey = this.getKeyPublic(privateKey, options);

    return {
      keys: {
        private: privateKey,
        public: publicKey,
      },
    };
  }

  /**
   * Address type written when none is given, on chains that write more than one.
   * @returns {AddressType | undefined} The default type, or undefined on chains with one format
   */
  get defaultAddressType(): AddressType | undefined {
    return undefined;
  }

  /**
   * Public key form the chain's address hashes whatever form the key comes in.
   * @returns {"compressed" | "uncompressed" | undefined} The fixed form, undefined where the address follows the key
   */
  protected get addressKeyForm(): "compressed" | "uncompressed" | undefined {
    return undefined;
  }

  /**
   * Refuses any address type on a chain with one format, instead of writing it on the wallet.
   * @param type - Address type the caller asked for
   * @throws {RangeError} When any type is given
   */
  protected refuseAddressType(type: AddressType | undefined): void {
    if (type === undefined) return;
    throw new RangeError(
      `Address type ${JSON.stringify(type)} is not supported for ${this.name}, which has one address format. Omit addressType`,
    );
  }

  /**
   * Refuses a `compressed` that changes neither the public key nor the address.
   * @param options - Key options of the wallet
   * @throws {RangeError} When `compressed` changes neither the public key nor the address
   */
  protected checkCompressed(options?: KeyOptions): void {
    const compressed = options?.compressed;
    if (compressed === undefined) return;
    const curve = this.resolveCurve(options);
    if (curve === "ed25519") {
      throw new RangeError(`${this.name} ed25519 keys take no compressed`);
    }
    const form = this.addressKeyForm;
    if (form === undefined || compressed !== (form === "uncompressed")) return;
    const label = typeof this.curve === "string" ? this.name : `${this.name} ${curve}`;
    throw new RangeError(
      `${label} addresses hash the ${form} key, so compressed: ${String(compressed)} does not apply`,
    );
  }

  deriveWallet(keyPrivate: string, options?: KeyOptions, addressType?: AddressType): Wallet {
    this.checkCompressed(options);
    const keyPublic = this.getKeyPublic(keyPrivate, options);
    const type = addressType ?? this.defaultAddressType;

    return {
      keys: {
        private: keyPrivate,
        public: keyPublic,
      },
      address: this.getAddress(keyPublic, type),
      ...(type === undefined ? {} : { addressType: type }),
    };
  }

  generateWallet(options?: KeyOptions, addressType?: AddressType): Wallet {
    this.checkCompressed(options);
    const keys = this.generateKeys(options);
    const type = addressType ?? this.defaultAddressType;

    return {
      ...keys,
      address: this.getAddress(keys.keys.public, type),
      ...(type === undefined ? {} : { addressType: type }),
    };
  }

  /**
   * Picks the curve a derivation walks: chains with two curves read `options.scheme`, the rest ignore it.
   * @param options - Key options that may carry a signature scheme
   * @returns {Curve} The curve to derive on, the first declared one when no scheme is given
   * @throws {RangeError} When the scheme names none of the chain's curves
   */
  protected resolveCurve(options?: KeyOptions): Curve {
    if (typeof this.curve === "string") {
      return this.curve;
    }
    const [fallback] = this.curve;
    if (fallback === undefined) {
      throw new Error(`${this.name} declares no curve`);
    }
    if (options?.scheme === undefined) {
      return fallback;
    }
    const scheme = options.scheme.toLowerCase();
    const curve = this.curve.find((candidate) => candidate === scheme);
    if (curve === undefined) {
      throw new RangeError(
        `Scheme ${JSON.stringify(options.scheme)} is not supported for ${this.name}. Supported: ${this.curve.join(", ")}`,
      );
    }
    return curve;
  }

  /**
   * Builds the derivation path the chain's wallets use for an account. BIP44 by default,
   * `m/44'/coin'/account'/change/index`; chains whose wallets walk another shape override it.
   * @param account - Account index
   * @param change - 0 for the external branch, 1 for the internal one
   * @param addressIndex - Address index
   * @param _options - Key options, read by chains whose path depends on the scheme
   * @returns {string} The derivation path
   */
  getDerivationPath(
    account = 0,
    change: number = BIP44Change.EXTERNAL,
    addressIndex = 0,
    _options?: KeyOptions,
  ): string {
    return getPath(this.coinType, account, change, addressIndex);
  }

  deriveHDWallet(
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: AddressType,
  ): Wallet {
    const { passphrase, allowInvalidChecksum, wordlist, ...keyOptions } = options ?? {};
    const { privateKey, checksumValid } = deriveMnemonicKey(
      mnemonic,
      path,
      this.resolveCurve(keyOptions),
      passphrase,
      allowInvalidChecksum,
      wordlist,
    );

    const wallet = this.deriveWallet(privateKey, keyOptions, addressType);
    return checksumValid
      ? wallet
      : {
          ...wallet,
          warnings: [
            ...(wallet.warnings ?? []),
            "BIP39 checksum is invalid. Derived from the supplied words without repairing the checksum.",
          ],
        };
  }

  /**
   * Extended public key prefixes this chain takes on its network. Wallets export BIP32 keys
   * of every secp256k1 chain as `xpub`, and `tpub` on testnet; Bitcoin adds SLIP-0132's.
   * @returns {ExtendedKeyFormats} Accepted prefixes and the address type each stands for
   */
  protected get extendedKeyFormats(): ExtendedKeyFormats {
    return this.network === "testnet"
      ? { tpub: { version: SLIP132_FORMATS.tpub.version } }
      : { xpub: { version: SLIP132_FORMATS.xpub.version } };
  }

  /**
   * Derives a watch-only wallet from an extended public key, such as an account `xpub`.
   * Only normal levels can be walked without the private key.
   * @param extendedKey - Base58Check extended public key
   * @param path - Normal levels below the key, such as `m/0/5`
   * @param addressType - Explicit address type that wins over the one the prefix stands for
   * @returns {XpubWallet} The public key and address at the path
   */
  deriveXpubWallet(extendedKey: string, path: string, addressType?: AddressType): XpubWallet {
    if (this.curve !== "secp256k1") {
      throw new Error(`${this.name} does not derive from extended public keys`);
    }
    const child = deriveExtendedPublicChild(
      extendedKey,
      path,
      this.extendedKeyFormats,
      `${this.name} ${this.network}`,
    );
    const type = addressType ?? child.addressType ?? this.defaultAddressType;
    return {
      keys: { public: child.publicKey },
      address: this.getAddress(child.publicKey, type),
      prefix: child.prefix,
      ...(type === undefined ? {} : { addressType: type }),
    };
  }

  /**
   * Recover the signer of a message signature, which the Bitcoin family, Decred, EVM chains and
   * TRON write in a recoverable form.
   * @param _message - The signed message
   * @param _signature - The signature in the chain's recoverable form
   * @returns {MessageSigner} The recovered public key and the address type the header names
   */
  recoverMessageSigner(_message: string | Uint8Array, _signature: string): MessageSigner {
    throw new Error(
      `${this.name} does not write recoverable message signatures, so it has no signer to recover`,
    );
  }

  /**
   * Recover the signer of an `r||s||v` signature over a digest, which EVM chains and TRON write.
   * @param _digest - The signed 32-byte digest
   * @param _signature - 65 bytes of `r||s||v` as hex
   * @returns {MessageSigner} The recovered public key
   */
  recoverDigestSigner(_digest: Uint8Array, _signature: string): MessageSigner {
    throw new Error(
      `${this.name} does not sign digests as r||s||v, so it has no digest signer to recover`,
    );
  }
}

/**
 * Returns a concrete blockchain instance through the unified public API.
 * @param blockchain - The concrete blockchain instance to expose
 * @returns {T} The same blockchain instance
 */
export function useBlockchain<T extends AbstractBlockchain>(blockchain: T): T {
  return blockchain;
}

/** The part of a blockchain that decides its derivation paths. */
export interface PathSource {
  readonly bip44: number;
  readonly getDerivationPath?: (
    account?: number,
    change?: number,
    addressIndex?: number,
    options?: KeyOptions,
  ) => string;
}

/**
 * Get the derivation path a blockchain's wallets use for an account: the chain's own shape when
 * it declares one, BIP44 from its coin type otherwise.
 *
 * @param blockchain - The blockchain implementation interface
 * @param account - Account index (defaults to 0)
 * @param change - 0 for external chain (receive addresses), 1 for internal chain (change addresses)
 * @param addressIndex - Address index (defaults to 0)
 * @param options - Key options, the scheme on chains with two curves
 * @returns {string} Derivation path string
 */
export function getBlockchainPath(
  blockchain: PathSource,
  account = 0,
  change: number = BIP44Change.EXTERNAL,
  addressIndex = 0,
  options?: KeyOptions,
): string {
  if (blockchain.getDerivationPath === undefined) {
    return getPath(blockchain.bip44, account, change, addressIndex);
  }
  return blockchain.getDerivationPath(account, change, addressIndex, options);
}
