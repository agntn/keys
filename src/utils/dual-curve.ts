import { AbstractBlockchain } from "../blockchain.ts";
import type {
  ElectrumSeed,
  ElectrumWalletOptions,
  HDWalletOptions,
  Wallet,
  WalletOptions,
} from "../types.ts";

/**
 * Lets the address type name the signature scheme, so one option drives key, address, and curve.
 * @param options - Wallet options that may carry a scheme, an address type, or both
 * @returns {T} The options with the address type as the scheme, or the scheme as the address type
 */
export function withScheme<T extends WalletOptions>(options: T): T {
  if (options.addressType === undefined) {
    return { ...options, addressType: options.scheme };
  }
  return { ...options, scheme: options.addressType };
}

/**
 * Chain with two curves whose address type is the signature scheme, as on Sui and the XRP Ledger.
 * The scheme in the options and the address type are one choice, so either one picks the curve.
 */
export abstract class AbstractDualCurveBlockchain extends AbstractBlockchain {
  override deriveWallet(keyPrivate: string, options: WalletOptions = {}): Wallet {
    return super.deriveWallet(keyPrivate, withScheme(options));
  }

  override deriveHDWallet(mnemonic: string, options: HDWalletOptions): Wallet {
    return super.deriveHDWallet(mnemonic, withScheme(options));
  }

  override deriveElectrumWallet(seed: ElectrumSeed, options: ElectrumWalletOptions): Wallet {
    return super.deriveElectrumWallet(seed, withScheme(options));
  }

  override generateWallet(options: WalletOptions = {}): Wallet {
    return super.generateWallet(withScheme(options));
  }
}
