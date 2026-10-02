import { base58 } from "@agntn/encodings/base58";
import { AbstractBlockchain } from "../blockchain.ts";
import { decodeKeyPublic, generateKeyPublic } from "../utils/ed25519.ts";
import { ed25519SignMessage, ed25519VerifyMessage } from "../utils/ed25519-chains.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { BIP44Change, getHardenedPath } from "../utils/bip44/paths.ts";
import type { Curve, KeyOptions } from "../types.ts";

/** Solana blockchain implementation. */
export class Solana extends AbstractBlockchain {
  override readonly name = "solana";
  override readonly curve: Curve = "ed25519";
  override readonly bip44 = BIP44.SOLANA;

  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate);
  }

  /**
   * Phantom and the Solana CLI put account `a` at `m/44'/501'/a'/change'`, every level hardened
   * and nothing below the change branch, so an address index has nowhere to go.
   * @param account - Account index
   * @param change - Change branch, 0 in every wallet
   * @param addressIndex - Must stay 0
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(
    account = 0,
    change: number = BIP44Change.EXTERNAL,
    addressIndex = 0,
  ): string {
    if (addressIndex !== 0) {
      throw new RangeError("Solana paths end at the change branch, so addressIndex must be 0");
    }
    return getHardenedPath(this.bip44, [account, change]);
  }

  override getAddress(keyPublic: string): string {
    return base58.encode(decodeKeyPublic(keyPublic, "Solana"));
  }

  override validateAddress(address: string): boolean {
    try {
      return base58.decode(address).length === 32;
    } catch {
      return false;
    }
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: KeyOptions,
  ): string {
    return ed25519SignMessage(message, keyPrivate, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    try {
      return ed25519VerifyMessage(message, signature, keyPublic, options);
    } catch {
      return false;
    }
  }
}

export default Solana;
