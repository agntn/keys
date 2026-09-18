import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { addSchemeByte } from "../utils/address.ts";
import { encodeBase58Check, validateBase58Check } from "../utils/encoding.ts";
import { hashWithPreamble } from "../utils/evm.ts";
import { generateKeyPublic } from "../utils/secp256k1.ts";
import { signMessage, verifyMessage } from "../utils/signing.ts";
import type { Curve, KeyOptions } from "../types.ts";

const ADDRESS_PREFIX_BYTE = 0x41;
const ADDRESS_PREFIX_CHAR = "T";
/** TIP-191 preamble, the one TronWeb's `signMessageV2` and TronLink hash under. */
const MESSAGE_PREAMBLE = "\u0019TRON Signed Message:\n";

/** TRON blockchain implementation. */
export class Tron extends AbstractBlockchain {
  override readonly name = "tron";
  override readonly curve: Curve = "secp256k1";
  override readonly bip44 = 195;

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate, options);
  }

  override getAddress(keyPublic: string): string {
    const keyPublicBytes = hexToBytes(keyPublic);
    const keyBytesForHashing = secp256k1.Point.fromBytes(keyPublicBytes).toBytes(false).slice(1);

    const addressBytes = keccak_256(keyBytesForHashing).slice(-20);
    return encodeBase58Check(addSchemeByte(addressBytes, ADDRESS_PREFIX_BYTE, true));
  }

  override validateAddress(address: string): boolean {
    return validateBase58Check(address, ADDRESS_PREFIX_BYTE, ADDRESS_PREFIX_CHAR);
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: KeyOptions,
  ): string {
    return signMessage(hashWithPreamble(message, MESSAGE_PREAMBLE), keyPrivate, {
      ...options,
      curve: "secp256k1",
      hash: false,
    });
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    return verifyMessage(hashWithPreamble(message, MESSAGE_PREAMBLE), signature, keyPublic, {
      ...options,
      curve: "secp256k1",
      hash: false,
    });
  }
}

export default Tron;
