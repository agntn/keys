import { base58 } from "@agntn/encodings/base58";
import { BIP44 } from "../utils/bip44/index.ts";
import { getHardenedPath } from "../utils/bip44/paths.ts";
import { decodeKeyPublic } from "../utils/ed25519.ts";
import { AbstractEd25519Blockchain } from "../utils/ed25519-chains.ts";
import { assertVerifyOptions, readPathOptions } from "../utils/options.ts";
import type {
  AddressType,
  DerivationPathOptions,
  KeyOptions,
  VerifyMessageOptions,
} from "../types.ts";

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

/**
 * NEAR, where the address is the implicit account: the public key itself, in hex.
 * Messages get raw ed25519 over their bytes, not the NEP-413 payload wallets sign.
 */
export class Near extends AbstractEd25519Blockchain {
  override readonly name = "near";
  override readonly bip44 = BIP44.NEAR;

  /**
   * near-seed-phrase stops at `m/44'/397'/0'`, so account `a` is `m/44'/397'/a'`, no deeper.
   * @param options - Account; `change` and `addressIndex` must stay 0
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(options?: DerivationPathOptions): string {
    const { account = 0, change = 0, addressIndex = 0 } = readPathOptions(options);
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
   * Checks a raw ed25519 signature over the message bytes.
   * @param message - The signed message
   * @param options - The signature as hex, and the public key as hex or as `ed25519:` and base58
   * @returns {boolean} Whether the signature is valid, false for a malformed key too
   */
  override verifyMessage(
    message: string | Uint8Array,
    options: VerifyMessageOptions<KeyOptions>,
  ): boolean {
    assertVerifyOptions(options);
    try {
      return super.verifyMessage(message, {
        ...options,
        publicKey: readKeyPublic(options.publicKey).toHex(),
      });
    } catch {
      return false;
    }
  }
}

export default Near;
