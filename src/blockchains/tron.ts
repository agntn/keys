import { secp256k1 } from "@noble/curves/secp256k1.js";
import { keccak_256 } from "@noble/hashes/sha3.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { addSchemeByte } from "../utils/address.ts";
import { encodeBase58Check, validateBase58Check } from "../utils/encoding.ts";
import { evmSignMessage, evmVerifyMessage } from "../utils/evm.ts";
import { generateKeyPublic } from "../utils/secp256k1.ts";
import type { Curve, KeyOptions } from "../types.ts";

const ADDRESS_PREFIX_BYTE = 0x41;
const ADDRESS_PREFIX_CHAR = "T";

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
