import { blake2b } from "@noble/hashes/blake2.js";
import { concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { addSchemeByte, createPrefixedAddress, validateAddressHex } from "../utils/address.ts";
import { BIP44Change, getBIP32Path, getHardenedPath } from "../utils/bip44/index.ts";
import { generateKeyPublic as getEd25519KeyPublic } from "../utils/ed25519.ts";
import { generateKeyPublic as getSecp256k1KeyPublic } from "../utils/secp256k1.ts";
import {
  assertNoRecoveryByte,
  hasRecoveryByte,
  signMessage,
  verifyMessage,
} from "../utils/signing.ts";
import type { AddressType, HDWalletOptions, KeyOptions, Wallet } from "../types.ts";

const CURVES = ["ed25519", "secp256k1"] as const;
const SIGNATURE_SCHEME_FLAGS = {
  ED25519: 0x00,
  SECP256K1: 0x01,
  SECP256R1: 0x02,
  MULTISIG: 0x03,
} as const;

/** Purpose level of the BIP32 path the Sui SDK walks for secp256k1 keys. */
const SECP256K1_PURPOSE = 54;

/** BCS intent of a personal message: scope `PersonalMessage`, version `V0`, app id `Sui`. */
const PERSONAL_MESSAGE_INTENT = new Uint8Array([0x03, 0x00, 0x00]);

/**
 * Encodes a length as unsigned LEB128, the prefix BCS puts in front of a vector.
 * @param value - The length to encode
 * @returns {Uint8Array} The ULEB128 bytes
 */
function encodeUleb128(value: number): Uint8Array {
  const bytes: number[] = [];
  let remaining = value;
  while (remaining >= 0x80) {
    bytes.push((remaining & 0x7f) | 0x80);
    remaining >>>= 7;
  }
  bytes.push(remaining);
  return Uint8Array.from(bytes);
}

/**
 * Digests a message the way `signPersonalMessage` does in the Sui SDK: the intent, the message as a
 * BCS byte vector, blake2b-256 over both. Every Sui signer signs this digest, not the message.
 * @param message - The message to digest
 * @returns {Uint8Array} The 32-byte personal message digest
 */
function hashPersonalMessage(message: string | Uint8Array): Uint8Array {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  return blake2b(concatBytes(PERSONAL_MESSAGE_INTENT, encodeUleb128(bytes.length), bytes), {
    dkLen: 32,
  });
}

/**
 * Lets the address type name the signature scheme, so one argument drives key, address, and curve.
 * @param options - Key options that may already carry a scheme
 * @param addressType - Scheme given as the address type, if any
 * @returns {{ scheme: string | undefined; keyOptions: HDWalletOptions | undefined }} The scheme to use and options carrying it
 */
function withScheme(
  options: HDWalletOptions | undefined,
  addressType?: AddressType,
): { readonly scheme: string | undefined; readonly keyOptions: HDWalletOptions | undefined } {
  if (addressType === undefined) {
    return { scheme: options?.scheme, keyOptions: options };
  }
  return { scheme: addressType, keyOptions: { ...options, scheme: addressType } };
}

/** Sui blockchain implementation. */
export class Sui extends AbstractBlockchain {
  override readonly name = "sui";
  override readonly curve = CURVES;
  override readonly bip44 = 784;

  override deriveWallet(
    keyPrivate: string,
    options?: KeyOptions,
    addressType?: AddressType,
  ): Wallet {
    const { scheme, keyOptions } = withScheme(options, addressType);
    return super.deriveWallet(keyPrivate, keyOptions, scheme);
  }

  /**
   * The Sui SDK walks `m/44'/784'/account'/change'/index'` for ed25519 and
   * `m/54'/784'/account'/change/index` for secp256k1; the scheme in the options picks one.
   * @param account - Account index
   * @param change - Change branch
   * @param addressIndex - Address index
   * @param options - Key options that may carry the scheme
   * @returns {string} The path for that scheme
   */
  override getDerivationPath(
    account = 0,
    change: number = BIP44Change.EXTERNAL,
    addressIndex = 0,
    options?: KeyOptions,
  ): string {
    if (this.resolveCurve(options) === "secp256k1") {
      return getBIP32Path(SECP256K1_PURPOSE, this.bip44, account, change, addressIndex);
    }
    return getHardenedPath(this.bip44, [account, change, addressIndex]);
  }

  override deriveHDWallet(
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: AddressType,
  ): Wallet {
    const { scheme, keyOptions } = withScheme(options, addressType);
    return super.deriveHDWallet(mnemonic, path, keyOptions, scheme);
  }

  override generateWallet(options?: KeyOptions, addressType?: AddressType): Wallet {
    const { scheme, keyOptions } = withScheme(options, addressType);
    return super.generateWallet(keyOptions, scheme);
  }

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

  /**
   * Signs the personal message digest: ed25519 takes it raw, secp256k1 signs its sha256 like the SDK.
   * @param message - The message to sign
   * @param keyPrivate - The private key as hex
   * @param options - Key options; `scheme` picks the curve, ed25519 by default
   * @returns {string} The 64-byte signature as hex, without the scheme flag
   */
  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: KeyOptions,
  ): string {
    assertNoRecoveryByte(
      options,
      "Sui serializes a signature as flag||signature||publicKey, with no recovery byte",
    );
    return signMessage(hashPersonalMessage(message), keyPrivate, {
      ...options,
      curve: this.resolveCurve(options),
      hash: true,
    });
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    if (hasRecoveryByte(signature)) {
      return false;
    }
    return verifyMessage(hashPersonalMessage(message), signature, keyPublic, {
      ...options,
      curve: this.resolveCurve(options),
      hash: true,
    });
  }
}

export default Sui;
