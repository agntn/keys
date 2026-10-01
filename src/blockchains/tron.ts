import { keccak256 } from "@agntn/hashes";
import { AbstractBlockchain } from "../blockchain.ts";
import { addSchemeByte } from "../utils/address.ts";
import { encodeBase58Check, validateBase58Check } from "../utils/encoding.ts";
import { hashWithPreamble } from "../utils/evm.ts";
import { decodePublicPoint } from "../utils/secp256k1/decode.ts";
import { generateKeyPublic } from "../utils/secp256k1/keys.ts";
import { recoverSecp256k1Signer, signMessage, verifyMessage } from "../utils/signing.ts";
import type { Curve, KeyOptions, MessageSigner, RecoverableSigningOptions } from "../types.ts";

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
    const keyBytesForHashing = decodePublicPoint(keyPublic).toBytes(false).slice(1);

    const addressBytes = keccak256(keyBytesForHashing).slice(-20);
    return encodeBase58Check(addSchemeByte(addressBytes, ADDRESS_PREFIX_BYTE, true));
  }

  override validateAddress(address: string): boolean {
    return validateBase58Check(address, ADDRESS_PREFIX_BYTE, ADDRESS_PREFIX_CHAR);
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: RecoverableSigningOptions,
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
    options?: RecoverableSigningOptions,
  ): boolean {
    return verifyMessage(hashWithPreamble(message, MESSAGE_PREAMBLE), signature, keyPublic, {
      ...options,
      curve: "secp256k1",
      hash: false,
    });
  }

  /**
   * Recover the signer of a TIP-191 message signature.
   * @param message - The signed message
   * @param signature - 65 bytes of `r||s||v` as hex without 0x
   * @returns {MessageSigner} The uncompressed public key
   */
  override recoverMessageSigner(message: string | Uint8Array, signature: string): MessageSigner {
    return {
      publicKey: recoverSecp256k1Signer(hashWithPreamble(message, MESSAGE_PREAMBLE), signature),
    };
  }

  /**
   * Recover the signer of an `r||s||v` signature over a 32-byte digest.
   * @param digest - The signed digest
   * @param signature - 65 bytes of `r||s||v` as hex without 0x
   * @returns {MessageSigner} The uncompressed public key
   */
  override recoverDigestSigner(digest: Uint8Array, signature: string): MessageSigner {
    return { publicKey: recoverSecp256k1Signer(digest, signature) };
  }
}

export default Tron;
