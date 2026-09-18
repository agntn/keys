import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { base32nopad } from "@scure/base";
import { AbstractBlockchain } from "../blockchain.ts";
import { BIP44, getHardenedPath } from "../utils/bip44/index.ts";
import { generateKeyPublic } from "../utils/ed25519.ts";
import { signMessage, verifyMessage } from "../utils/signing.ts";
import type { Curve, KeyOptions } from "../types.ts";

/** SEP-23 StrKey address types: the version byte and the decoded length, checksum included. */
const STRKEY_TYPES: Readonly<
  Partial<Record<string, { readonly version: number; readonly bytes: number }>>
> = {
  G: { version: 6 << 3, bytes: 35 },
  M: { version: 12 << 3, bytes: 43 },
  C: { version: 2 << 3, bytes: 35 },
};

const ACCOUNT_VERSION = 6 << 3;

/** SEP-53 prefix, the one `Keypair.signMessage` in the Stellar SDK hashes under. */
const MESSAGE_PREFIX = new TextEncoder().encode("Stellar Signed Message:\n");

/**
 * Computes the CRC16-XModem checksum a StrKey carries in its last two bytes.
 * @param payload - The version byte and the key
 * @returns {number} The unsigned 16-bit checksum
 */
function crc16Xmodem(payload: Uint8Array): number {
  let checksum = 0;
  for (const byte of payload) {
    checksum ^= byte << 8;
    for (let bit = 0; bit < 8; bit++) {
      checksum = checksum & 0x8000 ? ((checksum << 1) ^ 0x1021) & 0xffff : (checksum << 1) & 0xffff;
    }
  }
  return checksum;
}

/**
 * Encodes a version byte and a payload as a StrKey: base32 without padding over the bytes and
 * their little-endian CRC16-XModem checksum.
 * @param version - The StrKey version byte
 * @param payload - The key bytes
 * @returns {string} The StrKey
 */
function encodeStrKey(version: number, payload: Uint8Array): string {
  const data = concatBytes(Uint8Array.from([version]), payload);
  const checksum = crc16Xmodem(data);
  return base32nopad.encode(concatBytes(data, Uint8Array.from([checksum & 0xff, checksum >> 8])));
}

/**
 * Digests a message the way SEP-53 does: SHA-256 over the prefix and the message bytes.
 * @param message - The message to digest
 * @returns {Uint8Array} The 32-byte digest every Stellar signer signs
 */
function hashMessage(message: string | Uint8Array): Uint8Array {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  return sha256(concatBytes(MESSAGE_PREFIX, bytes));
}

/**
 * Stellar blockchain implementation. Addresses are the same on pubnet and testnet, so the
 * network option changes nothing here.
 */
export class Stellar extends AbstractBlockchain {
  override readonly name = "stellar";
  override readonly curve: Curve = "ed25519";
  override readonly bip44 = BIP44.STELLAR;

  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate);
  }

  /**
   * SEP-0005 puts account `x` at `m/44'/148'/x'` and stops there, so neither a change branch nor
   * an address index has a level to land on.
   * @param account - Account index
   * @param change - Must stay 0
   * @param addressIndex - Must stay 0
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(account = 0, change = 0, addressIndex = 0): string {
    if (change !== 0 || addressIndex !== 0) {
      throw new RangeError(
        "Stellar paths end at the account, so change and addressIndex must be 0",
      );
    }
    return getHardenedPath(this.bip44, [account]);
  }

  /**
   * Encodes the public key as an account StrKey, the `G` address wallets show.
   * @param keyPublic - The ed25519 public key as hex
   * @returns {string} The 56-character StrKey
   */
  override getAddress(keyPublic: string): string {
    const keyPublicBytes = hexToBytes(keyPublic);
    if (keyPublicBytes.length !== 32) {
      throw new RangeError("Stellar public key must be 32 bytes");
    }
    return encodeStrKey(ACCOUNT_VERSION, keyPublicBytes);
  }

  /**
   * Accepts account (`G`), muxed account (`M`) and contract (`C`) StrKeys with a valid checksum.
   * Secret seeds (`S`) are not addresses and fail.
   * @param address - The address to check
   * @returns {boolean} Whether the address is a canonical StrKey
   */
  override validateAddress(address: string): boolean {
    const type = STRKEY_TYPES[address[0] ?? ""];
    if (!type || address.length !== Math.ceil((type.bytes * 8) / 5)) return false;

    let decoded: Uint8Array;
    try {
      decoded = base32nopad.decode(address);
    } catch {
      return false;
    }
    if (decoded.length !== type.bytes || decoded[0] !== type.version) return false;

    const checksum = crc16Xmodem(decoded.subarray(0, -2));
    return (
      decoded[type.bytes - 2] === (checksum & 0xff) && decoded[type.bytes - 1] === checksum >> 8
    );
  }

  /**
   * Signs the SEP-53 digest of the message, what the Stellar SDK's `signMessage` signs.
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
    return signMessage(hashMessage(message), keyPrivate, { ...options, curve: "ed25519" });
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    return verifyMessage(hashMessage(message), signature, keyPublic, {
      ...options,
      curve: "ed25519",
    });
  }
}

export default Stellar;
