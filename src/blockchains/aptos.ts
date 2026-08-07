import { sha3_256 } from "@noble/hashes/sha3.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { addSchemeByte, createPrefixedAddress, validateAddressHex } from "../utils/address.ts";
import { generateKeyPublic } from "../utils/ed25519.ts";
import { ed25519SignMessage, ed25519VerifyMessage } from "../utils/ed25519-chains.ts";
import type { Curve, KeyOptions } from "../types.ts";

/** Aptos blockchain implementation. */
export class Aptos extends AbstractBlockchain {
  override readonly name = "aptos";
  override readonly curve: Curve = "ed25519";
  override readonly bip44 = 637;

  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate);
  }

  override getAddress(keyPublic: string): string {
    const keyPublicBytes = hexToBytes(keyPublic);
    const dataToHash = addSchemeByte(keyPublicBytes, 0x00, false);
    return createPrefixedAddress(sha3_256(dataToHash));
  }

  override validateAddress(address: string): boolean {
    try {
      return validateAddressHex(address, {
        prefix: "0x",
        length: 64,
        caseSensitive: false,
      });
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
    return ed25519VerifyMessage(message, signature, keyPublic, options);
  }
}

export default Aptos;
