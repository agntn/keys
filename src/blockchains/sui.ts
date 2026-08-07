import { blake2b } from "@noble/hashes/blake2.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { addSchemeByte, createPrefixedAddress, validateAddressHex } from "../utils/address.ts";
import { generateKeyPublic as getEd25519KeyPublic } from "../utils/ed25519.ts";
import { ed25519SignMessage, ed25519VerifyMessage } from "../utils/ed25519-chains.ts";
import { evmSignMessage, evmVerifyMessage } from "../utils/evm.ts";
import { generateKeyPublic as getSecp256k1KeyPublic } from "../utils/secp256k1.ts";
import type { KeyOptions } from "../types.ts";

const CURVES = ["ed25519", "secp256k1"] as const;
const SIGNATURE_SCHEME_FLAGS = {
  ED25519: 0x00,
  SECP256K1: 0x01,
  SECP256R1: 0x02,
  MULTISIG: 0x03,
} as const;

/** Sui blockchain implementation. */
export class Sui extends AbstractBlockchain {
  override readonly name = "sui";
  override readonly curve = CURVES;
  override readonly bip44 = 784;

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    const scheme = options?.scheme ?? "ed25519";
    if (scheme.toLowerCase() === "secp256k1") {
      return getSecp256k1KeyPublic(keyPrivate, { compressed: true });
    }
    return getEd25519KeyPublic(keyPrivate);
  }

  override getAddress(keyPublic: string, type?: string): string {
    const keyPublicBytes = hexToBytes(keyPublic);
    const flagByte =
      type?.toLowerCase() === "secp256k1"
        ? SIGNATURE_SCHEME_FLAGS.SECP256K1
        : SIGNATURE_SCHEME_FLAGS.ED25519;
    const input = addSchemeByte(keyPublicBytes, flagByte, true);
    return createPrefixedAddress(blake2b(input, { dkLen: 32 }));
  }

  override validateAddress(address: string): boolean {
    return validateAddressHex(address, {
      prefix: "0x",
      length: 64,
      caseSensitive: false,
    });
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: KeyOptions,
  ): string {
    const scheme = options?.scheme ?? "ed25519";
    return scheme.toLowerCase() === "secp256k1"
      ? evmSignMessage(message, keyPrivate, options)
      : ed25519SignMessage(message, keyPrivate, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    const scheme = options?.scheme ?? "ed25519";
    return scheme.toLowerCase() === "secp256k1"
      ? evmVerifyMessage(message, signature, keyPublic, options)
      : ed25519VerifyMessage(message, signature, keyPublic, options);
  }
}

export default Sui;
