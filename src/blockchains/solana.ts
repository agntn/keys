import { hexToBytes } from "@noble/hashes/utils.js";
import { base58 } from "@scure/base";
import { AbstractBlockchain } from "../blockchain.ts";
import { generateKeyPublic } from "../utils/ed25519.ts";
import { ed25519SignMessage, ed25519VerifyMessage } from "../utils/ed25519-chains.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import type { Curve, KeyOptions, SigningOptions } from "../types.ts";

/** Solana blockchain implementation. */
export class Solana extends AbstractBlockchain {
  override readonly name = "solana";
  override readonly curve: Curve = "ed25519";
  override readonly bip44 = BIP44.SOLANA;

  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate);
  }

  override getAddress(keyPublic: string): string {
    return base58.encode(hexToBytes(keyPublic));
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
    options?: SigningOptions,
  ): string {
    return ed25519SignMessage(message, keyPrivate, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: SigningOptions,
  ): boolean {
    try {
      return ed25519VerifyMessage(message, signature, keyPublic, options);
    } catch {
      return false;
    }
  }
}

export default Solana;
