import { keccak256 } from "@agntn/hashes";
import { AbstractBlockchain } from "../blockchain.ts";
import { generateAddress, validateAddress } from "./evm-address.ts";
import { generateKeyPublic as getSecp256k1KeyPublic } from "./secp256k1/keys.ts";
import { signMessage, verifyMessage } from "./signing.ts";
import type { KeyOptions, RecoverableSigningOptions } from "../types.ts";

export { generateAddress, toChecksumAddress, validateAddress } from "./evm-address.ts";

/** EIP-191 `personal_sign` preamble; TIP-191 frames TRON messages the same way under its own. */
const ETHEREUM_MESSAGE_PREAMBLE = "\u0019Ethereum Signed Message:\n";

/**
 * Hashes a message with keccak256 after the preamble and its decimal byte length.
 *
 * @param message - The message to hash
 * @param preamble - The chain's signed message preamble, Ethereum's by default
 * @returns {Uint8Array} The keccak256 hash of the prefixed message
 */
export function hashWithPreamble(
  message: string | Uint8Array,
  preamble: string = ETHEREUM_MESSAGE_PREAMBLE,
): Uint8Array {
  const messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  const preambleBytes = new TextEncoder().encode(preamble + messageBytes.length.toString());
  const fullMessage = new Uint8Array(preambleBytes.length + messageBytes.length);
  fullMessage.set(preambleBytes);
  fullMessage.set(messageBytes, preambleBytes.length);
  return keccak256(fullMessage);
}

/**
 * Signs a message using secp256k1 for EVM chains
 * For Ethereum, generally uses the keccak256 hash and a specific preamble
 *
 * @param message - The message to sign
 * @param keyPrivate - The private key
 * @param options - Optional parameters; `recovered` appends `v`, the form ethers and viem read
 * @returns {string} The signature as hex, 65 bytes of `r||s||v` when recovered
 */
export function evmSignMessage(
  message: string | Uint8Array,
  keyPrivate: string,
  options: RecoverableSigningOptions = {},
): string {
  const hash = hashWithPreamble(message);

  return signMessage(hash, keyPrivate, {
    ...options,
    curve: "secp256k1",
    hash: false,
  });
}

/**
 * Verifies a message signature for EVM chains
 *
 * @param message - The original message
 * @param signature - The signature to verify
 * @param keyPublic - The public key
 * @param options - Optional parameters
 * @returns {boolean} Whether the signature is valid; a 65-byte signature must carry the right `v`
 */
export function evmVerifyMessage(
  message: string | Uint8Array,
  signature: string,
  keyPublic: string,
  options: RecoverableSigningOptions = {},
): boolean {
  const hash = hashWithPreamble(message);

  try {
    return verifyMessage(hash, signature, keyPublic, {
      ...options,
      curve: "secp256k1",
      hash: false,
    });
  } catch {
    return false;
  }
}

/**
 * Shared implementation for EVM-compatible blockchains.
 */
export abstract class AbstractEVMBlockchain extends AbstractBlockchain {
  override readonly curve = "secp256k1";

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    return getSecp256k1KeyPublic(keyPrivate, options);
  }

  override getAddress(keyPublic: string): string {
    return generateAddress(keyPublic);
  }

  override validateAddress(address: string): boolean {
    return validateAddress(address);
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: RecoverableSigningOptions,
  ): string {
    return evmSignMessage(message, keyPrivate, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: RecoverableSigningOptions,
  ): boolean {
    return evmVerifyMessage(message, signature, keyPublic, options);
  }
}
