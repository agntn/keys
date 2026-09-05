import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { deriveKeyPrivateFromMnemonic } from "./utils/hd.ts";
import type {
  AddressType,
  Blockchain,
  Curve,
  HDWalletOptions,
  KeyOptions,
  Keys,
  Options,
  SigningOptions,
  Wallet,
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
    const keyPrivateBytes = this.curve.includes("secp256k1")
      ? secp256k1.utils.randomSecretKey()
      : globalThis.crypto.getRandomValues(new Uint8Array(32));

    return bytesToHex(keyPrivateBytes);
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

  deriveWallet(keyPrivate: string, options?: KeyOptions, addressType?: AddressType): Wallet {
    const keyPublic = this.getKeyPublic(keyPrivate, options);

    return {
      keys: {
        private: keyPrivate,
        public: keyPublic,
      },
      address: this.getAddress(keyPublic, addressType),
    };
  }

  generateWallet(options?: KeyOptions, addressType?: AddressType): Wallet {
    const keys = this.generateKeys(options);
    const address = this.getAddress(keys.keys.public, addressType);

    return {
      ...keys,
      address,
    };
  }

  /**
   * Picks the curve a derivation walks: chains with two curves read `options.scheme`, the rest ignore it.
   * @param options - Key options that may carry a signature scheme
   * @returns {Curve} The curve to derive on
   */
  protected resolveCurve(options?: KeyOptions): Curve {
    if (typeof this.curve === "string") {
      return this.curve;
    }
    const scheme = options?.scheme?.toLowerCase();
    const [fallback] = this.curve;
    if (fallback === undefined) {
      throw new Error(`${this.name} declares no curve`);
    }
    return this.curve.find((curve) => curve === scheme) ?? fallback;
  }

  deriveHDWallet(
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: AddressType,
  ): Wallet {
    const { passphrase, ...keyOptions } = options ?? {};
    const keyPrivate = deriveKeyPrivateFromMnemonic(
      mnemonic,
      path,
      this.resolveCurve(keyOptions),
      passphrase,
    );

    return this.deriveWallet(keyPrivate, keyOptions, addressType);
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
