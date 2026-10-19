import { crc16Xmodem, sha256 } from "@agntn/hashes";
import { concatBytes } from "../utils/bytes.ts";
import { base32 } from "@agntn/encodings/base32";
import { BIP44 } from "../utils/bip44/index.ts";
import { getHardenedPath } from "../utils/bip44/paths.ts";
import { decodeKeyPublic } from "../utils/ed25519.ts";
import { AbstractEd25519Blockchain } from "../utils/ed25519-chains.ts";
import { readPathOptions } from "../utils/options.ts";
import type {
  AddressType,
  DerivationPathOptions,
  KeyOptions,
  SignMessageOptions,
  VerifyMessageOptions,
} from "../types.ts";

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
 * Computes the CRC16-XModem checksum a StrKey carries in its last two bytes, little-endian.
 * @param payload - The version byte and the key
 * @returns {Uint8Array} The two checksum bytes, low byte first
 */
function strKeyChecksum(payload: Uint8Array): Uint8Array {
  return crc16Xmodem(payload).toReversed();
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
  return base32.encode(concatBytes(data, strKeyChecksum(data)), { padding: false });
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
export class Stellar extends AbstractEd25519Blockchain {
  override readonly name = "stellar";
  override readonly bip44 = BIP44.STELLAR;

  /**
   * SEP-0005 puts account `x` at `m/44'/148'/x'` and stops there, so neither a change branch nor
   * an address index has a level to land on.
   * @param options - Account; `change` and `addressIndex` must stay 0
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(options?: DerivationPathOptions): string {
    const { account = 0, change = 0, addressIndex = 0 } = readPathOptions(options);
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
   * @param type - Any type throws, Stellar has one address format
   * @returns {string} The 56-character StrKey
   */
  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
    return encodeStrKey(ACCOUNT_VERSION, decodeKeyPublic(keyPublic, "Stellar"));
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
      decoded = base32.decode(address);
    } catch {
      return false;
    }
    if (decoded.length !== type.bytes || decoded[0] !== type.version) return false;
    if (base32.encode(decoded, { padding: false }) !== address) return false;

    const [low, high] = strKeyChecksum(decoded.subarray(0, -2));
    return decoded[type.bytes - 2] === low && decoded[type.bytes - 1] === high;
  }

  /**
   * Signs the SEP-53 digest of the message, what the Stellar SDK's `signMessage` signs.
   * @param message - The message to sign
   * @param options - The private key as hex
   * @returns {string} The 64-byte ed25519 signature as hex
   */
  override signMessage(
    message: string | Uint8Array,
    options: SignMessageOptions<KeyOptions>,
  ): string {
    return super.signMessage(hashMessage(message), options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    options: VerifyMessageOptions<KeyOptions>,
  ): boolean {
    return super.verifyMessage(hashMessage(message), options);
  }
}

export default Stellar;
