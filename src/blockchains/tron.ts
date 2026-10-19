import { keccak256 } from "@agntn/hashes";
import { AbstractBlockchain } from "../blockchain.ts";
import { addSchemeByte } from "../utils/address.ts";
import { encodeBase58Check, validateBase58Check } from "../utils/encoding.ts";
import { hashWithPreamble } from "../utils/evm.ts";
import { assertSignOptions, assertVerifyOptions } from "../utils/options.ts";
import { decodePublicPoint } from "../utils/secp256k1/decode.ts";
import { generateKeyPublic } from "../utils/secp256k1/keys.ts";
import { recoverSecp256k1Signer, signMessage, verifyMessage } from "../utils/signing.ts";
import type {
  AddressType,
  Curve,
  KeyOptions,
  MessageSigner,
  RecoverableSigningOptions,
  SignMessageOptions,
  VerifyMessageOptions,
} from "../types.ts";

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

  /**
   * TRON addresses take the Keccak-256 of the uncompressed point, as on Ethereum.
   * @returns {"uncompressed"} The form the address hashes
   */
  protected override get addressKeyForm(): "uncompressed" {
    return "uncompressed";
  }

  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
    const keyBytesForHashing = decodePublicPoint(keyPublic).toBytes(false).slice(1);

    const addressBytes = keccak256(keyBytesForHashing).slice(-20);
    return encodeBase58Check(addSchemeByte(addressBytes, { schemeByte: ADDRESS_PREFIX_BYTE }));
  }

  override validateAddress(address: string): boolean {
    return validateBase58Check(address, {
      bytesVersion: ADDRESS_PREFIX_BYTE,
      prefix: ADDRESS_PREFIX_CHAR,
    });
  }

  override signMessage(
    message: string | Uint8Array,
    options: SignMessageOptions<RecoverableSigningOptions>,
  ): string {
    assertSignOptions(options);
    const { privateKey, ...signingOptions } = options;
    return signMessage(hashWithPreamble(message, MESSAGE_PREAMBLE), privateKey, {
      ...signingOptions,
      curve: "secp256k1",
      hash: false,
    });
  }

  override verifyMessage(
    message: string | Uint8Array,
    options: VerifyMessageOptions<RecoverableSigningOptions>,
  ): boolean {
    assertVerifyOptions(options);
    const { signature, publicKey, ...signingOptions } = options;
    return verifyMessage(hashWithPreamble(message, MESSAGE_PREAMBLE), signature, publicKey, {
      ...signingOptions,
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
