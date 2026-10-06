import { AbstractBlockchain } from "../blockchain.ts";
import type { AddressType, HDWalletOptions, KeyOptions, Wallet } from "../types.ts";

/**
 * Lets the address type name the signature scheme, so one argument drives key, address, and curve.
 * @param options - Key options that may already carry a scheme
 * @param addressType - Scheme given as the address type, if any
 * @returns {{ scheme: string | undefined; keyOptions: HDWalletOptions | undefined }} The scheme to use and options carrying it
 */
export function withScheme(
  options: HDWalletOptions | undefined,
  addressType?: AddressType,
): { readonly scheme: string | undefined; readonly keyOptions: HDWalletOptions | undefined } {
  if (addressType === undefined) {
    return { scheme: options?.scheme, keyOptions: options };
  }
  return { scheme: addressType, keyOptions: { ...options, scheme: addressType } };
}

/**
 * Chain with two curves whose address type is the signature scheme, as on Sui and the XRP Ledger.
 * The scheme in the options and the address type are one choice, so either one picks the curve.
 */
export abstract class AbstractDualCurveBlockchain extends AbstractBlockchain {
  override deriveWallet(
    keyPrivate: string,
    options?: KeyOptions,
    addressType?: AddressType,
  ): Wallet {
    const { scheme, keyOptions } = withScheme(options, addressType);
    return super.deriveWallet(keyPrivate, keyOptions, scheme);
  }

  override deriveHDWallet(
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: AddressType,
  ): Wallet {
    const { scheme, keyOptions } = withScheme(options, addressType);
    return super.deriveHDWallet(mnemonic, path, keyOptions, scheme);
  }

  override generateWallet(options?: KeyOptions, addressType?: AddressType): Wallet {
    const { scheme, keyOptions } = withScheme(options, addressType);
    return super.generateWallet(keyOptions, scheme);
  }
}
