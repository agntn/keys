import { webcrypto } from "node:crypto";
import { bytesToHex } from "@noble/hashes/utils.js";
import type { AddressType, Blockchain, Curve, KeyOptions, Keys, Options, Wallet } from "./types.ts";

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
    options?: KeyOptions,
  ): string;
  abstract verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean;

  generateKeyPrivate(): string {
    const keyPrivateBytes = webcrypto.getRandomValues(new Uint8Array(32));
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

  generateWallet(options?: KeyOptions, addressType?: AddressType): Wallet {
    const keys = this.generateKeys(options);
    const address = this.getAddress(keys.keys.public, addressType);

    return {
      ...keys,
      address,
    };
  }
}

/**
 * Returns a concrete blockchain instance through the unified public API.
 */
export function useBlockchain<T extends AbstractBlockchain>(blockchain: T): T {
  return blockchain;
}
