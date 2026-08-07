import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { addSchemeByte } from "../utils/address.ts";
import { encodeBase58Check, validateBase58Check } from "../utils/encoding.ts";
import { evmSignMessage, evmVerifyMessage } from "../utils/evm.ts";
import { generateKeyPublic } from "../utils/secp256k1.ts";
import type { Curve, KeyOptions } from "../types.ts";

const NETWORK_PARAMS = {
  mainnet: { prefixByte: 0x41, prefixChar: "T" },
  testnet: { prefixByte: 0xa0, prefixChar: "A" },
} as const;

/** TRON blockchain implementation. */
export class Tron extends AbstractBlockchain {
  override readonly name = "tron";
  override readonly curve: Curve = "secp256k1";
  override readonly bip44 = 195;

  private get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate, options);
  }

  override getAddress(keyPublic: string): string {
    const keyPublicBytes = hexToBytes(keyPublic);
    let keyBytesForHashing: Uint8Array;

    if (keyPublicBytes.length === 33) {
      keyBytesForHashing = secp256k1.Point.fromBytes(keyPublicBytes).toBytes(false).slice(1);
    } else if (keyPublicBytes.length === 65) {
      keyBytesForHashing = keyPublicBytes.slice(1);
    } else {
      throw new Error(`Invalid public key length: ${keyPublicBytes.length} bytes`);
    }

    const addressBytes = keccak_256(keyBytesForHashing).slice(-20);
    return encodeBase58Check(addSchemeByte(addressBytes, this.params.prefixByte, true));
  }

  override validateAddress(address: string): boolean {
    return validateBase58Check(address, this.params.prefixByte, this.params.prefixChar);
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: KeyOptions,
  ): string {
    return evmSignMessage(message, keyPrivate, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    return evmVerifyMessage(message, signature, keyPublic, options);
  }
}

export default Tron;
