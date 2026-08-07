import { hexToBytes } from "@noble/hashes/utils.js";
import { base58 } from "@scure/base";
import { AbstractBlockchain } from "../blockchain.ts";
import { generateKeyPublic } from "../utils/ed25519.ts";
import { solanaSignMessage, solanaVerifyMessage } from "../utils/ed25519-chains.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import type { Curve, KeyOptions } from "../types.ts";

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
    _options?: KeyOptions,
  ): string {
    return solanaSignMessage(message, keyPrivate);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    _options?: KeyOptions,
  ): boolean {
    return solanaVerifyMessage(message, signature, keyPublic);
  }
}

export default Solana;
