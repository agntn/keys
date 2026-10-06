import { base58 } from "@agntn/encodings/base58";
import { AbstractBlockchain } from "../blockchain.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { getHardenedPath } from "../utils/bip44/paths.ts";
import { decodeKeyPublic, generateKeyPublic } from "../utils/ed25519.ts";
import { ed25519SignMessage, ed25519VerifyMessage } from "../utils/ed25519-chains.ts";
import type { AddressType, Curve, KeyOptions } from "../types.ts";

/** Prefix NEAR writes in front of a base58 ed25519 key, as in `ed25519:6j4b6z...`. */
const KEY_PREFIX = "ed25519:";

/** An implicit account ID: the public key as 64 lowercase hex characters, nothing else. */
const IMPLICIT_ACCOUNT = /^[0-9a-f]{64}$/;

/**
 * Reads a public key as hex, or as the `ed25519:` and base58 form NEAR wallets and RPC print.
 * @param keyPublic - The ed25519 public key in either form
 * @returns {Uint8Array} The 32 key bytes
 * @throws {RangeError} When the key is not 32 bytes
 */
function readKeyPublic(keyPublic: string): Uint8Array {
  if (!keyPublic.startsWith(KEY_PREFIX)) return decodeKeyPublic(keyPublic, "NEAR");
  const bytes = base58.decode(keyPublic.slice(KEY_PREFIX.length));
  if (bytes.length !== 32) throw new RangeError("NEAR public key must be 32 bytes");
  return bytes;
}

/** NEAR, where the address is the implicit account: the public key itself, in hex. */
export class Near extends AbstractBlockchain {
  override readonly name = "near";
  override readonly curve: Curve = "ed25519";
  override readonly bip44 = BIP44.NEAR;

  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate);
  }

  /**
   * near-seed-phrase stops at `m/44'/397'/0'`, so account `a` is `m/44'/397'/a'`, no deeper.
   * @param account - Account index
   * @param change - Must stay 0
   * @param addressIndex - Must stay 0
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(account = 0, change = 0, addressIndex = 0): string {
    if (change !== 0 || addressIndex !== 0) {
      throw new RangeError("NEAR paths end at the account, so change and addressIndex must be 0");
    }
    return getHardenedPath(this.bip44, [account]);
  }

  /**
   * Writes the implicit account ID, which is just the public key in lowercase hex.
   * @param keyPublic - The ed25519 public key as hex, or as `ed25519:` and base58
   * @param type - Any type throws, NEAR has one address format
   * @returns {string} The 64-character implicit account ID
   */
  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
    return readKeyPublic(keyPublic).toHex();
  }

  /**
   * Implicit accounts only, since no ed25519 key leads to a named or `0x` account.
   * @param address - The account ID to check
   * @returns {boolean} Whether it is 64 lowercase hex characters
   */
  override validateAddress(address: string): boolean {
    return IMPLICIT_ACCOUNT.test(address);
  }

  /**
   * Raw ed25519 over the message bytes, not the NEP-413 payload wallets sign.
   * @param message - The message to sign
   * @param keyPrivate - The private key as hex
   * @param options - Key options
   * @returns {string} The 64-byte ed25519 signature as hex
   */
  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: KeyOptions,
  ): string {
    return ed25519SignMessage(message, keyPrivate, options);
  }

  /**
   * Checks a raw ed25519 signature over the message bytes.
   * @param message - The signed message
   * @param signature - The signature as hex
   * @param keyPublic - The public key as hex, or as `ed25519:` and base58
   * @param options - Key options
   * @returns {boolean} Whether the signature is valid, false for a malformed key too
   */
  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    try {
      return ed25519VerifyMessage(message, signature, readKeyPublic(keyPublic).toHex(), options);
    } catch {
      return false;
    }
  }
}

export default Near;
