import { keccak256 } from "@agntn/hashes";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, equalBytes } from "@noble/curves/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { concatBytes } from "../utils/bytes.ts";
import { decodeMoneroBase58, encodeMoneroBase58 } from "../utils/monero-base58.ts";
import { decodeMoneroSeed } from "../utils/monero-seed.ts";
import type { AddressType, Curve, KeyOptions, Options, Wallet } from "../types.ts";

const { Point } = ed25519;

/** Network byte in front of a standard address, one per network Monero runs. */
const ADDRESS_PREFIXES: Readonly<Record<string, number>> = {
  mainnet: 18,
  testnet: 53,
  stagenet: 24,
};

/** Bytes of the keccak256 checksum at the end of an address. */
const CHECKSUM_BYTES = 4;

/** Bytes of a standard address: network byte, spend key, view key and checksum. */
const ADDRESS_BYTES = 1 + 32 + 32 + CHECKSUM_BYTES;

/**
 * Reduces 32 little-endian bytes mod l, as Monero's `sc_reduce32` does before a key is used.
 * @param bytes - 32 bytes read as a little-endian number
 * @returns {bigint} The scalar
 */
function reduceScalar(bytes: Uint8Array): bigint {
  return Point.Fn.create(bytesToNumberLE(bytes));
}

/**
 * Reads a private key, reduced to the spend key Monero would keep for those bytes.
 * @param keyPrivate - 32 bytes as hex
 * @returns {bigint} The private spend key
 * @throws {RangeError} When the key is not 32 bytes or reduces to zero
 */
function spendScalar(keyPrivate: string): bigint {
  const bytes = Uint8Array.fromHex(keyPrivate);
  if (bytes.length !== 32) throw new RangeError("Monero private key must be 32 bytes");
  const scalar = reduceScalar(bytes);
  if (scalar === 0n) throw new RangeError("Monero private key reduces to zero mod l");
  return scalar;
}

/**
 * The private view key a deterministic wallet derives: keccak256 of the spend key, mod l.
 * @param spend - The private spend key
 * @returns {bigint} The private view key
 */
function viewScalar(spend: bigint): bigint {
  return reduceScalar(keccak256(Point.Fn.toBytes(spend)));
}

/**
 * Splits the 64-byte public key into its spend and view halves, each one a point on the curve.
 * @param keyPublic - Public spend key then public view key, as hex
 * @returns {readonly [Uint8Array, Uint8Array]} The spend and view keys
 * @throws {RangeError} When the key is not 64 bytes or either half is no curve point
 */
function splitKeyPublic(keyPublic: string): readonly [Uint8Array, Uint8Array] {
  const bytes = Uint8Array.fromHex(keyPublic);
  if (bytes.length !== 64) {
    throw new RangeError("Monero public key must be 64 bytes: the spend key, then the view key");
  }
  const spend = bytes.slice(0, 32);
  const view = bytes.slice(32);
  try {
    Point.fromBytes(spend);
    Point.fromBytes(view);
  } catch {
    throw new RangeError("Monero public spend and view keys must be points on ed25519");
  }
  return [spend, view];
}

/**
 * Monero standard addresses. The public key is the spend key then the view key, both halves of the
 * address; the private key is the spend key alone. No subaddresses or message signatures yet.
 */
export class Monero extends AbstractBlockchain {
  override readonly name = "monero";
  override readonly curve: Curve = "ed25519";
  override readonly bip44 = BIP44.MONERO;
  /** Network byte every address of this instance starts with. */
  readonly addressPrefix: number;

  constructor(options?: Options) {
    super(options);
    const prefix = Object.hasOwn(ADDRESS_PREFIXES, this.network)
      ? ADDRESS_PREFIXES[this.network]
      : undefined;
    if (prefix === undefined) {
      throw new RangeError(
        `Monero networks are mainnet, testnet and stagenet, not ${JSON.stringify(this.network)}`,
      );
    }
    this.addressPrefix = prefix;
  }

  /**
   * Draws a spend key the way monero-wallet-cli does: 32 random bytes, reduced mod l.
   * @returns {string} The private spend key as hex
   */
  override generateKeyPrivate(): string {
    return Point.Fn.toBytes(spendScalar(ed25519.utils.randomSecretKey().toHex())).toHex();
  }

  /**
   * Both public keys of the wallet behind a spend key: spend key times G, then the view key's.
   * @param keyPrivate - The private spend key as hex, reduced mod l when it is not already
   * @param _options - Unused, Monero keys have one form
   * @returns {string} 64 bytes of hex, the public spend key and then the public view key
   */
  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    const spend = spendScalar(keyPrivate);
    return concatBytes(
      Point.BASE.multiply(spend).toBytes(),
      Point.BASE.multiply(viewScalar(spend)).toBytes(),
    ).toHex();
  }

  /**
   * The private view key of the wallet behind a spend key, which a view only wallet needs.
   * @param keyPrivate - The private spend key as hex
   * @returns {string} The private view key as hex
   */
  getViewKey(keyPrivate: string): string {
    return Point.Fn.toBytes(viewScalar(spendScalar(keyPrivate))).toHex();
  }

  /**
   * Writes the wallet with the spend key reduced, the key a Monero wallet would show for it.
   * @param keyPrivate - The private spend key as hex
   * @param options - Key options
   * @param addressType - Any type throws, only standard addresses are written
   * @returns {Wallet} The wallet with its standard address
   */
  override deriveWallet(
    keyPrivate: string,
    options?: KeyOptions,
    addressType?: AddressType,
  ): Wallet {
    const spend = Point.Fn.toBytes(spendScalar(keyPrivate)).toHex();
    return super.deriveWallet(spend, options, addressType);
  }

  /**
   * Restores a wallet from its seed words, as monero-wallet-cli `--restore-deterministic-wallet`.
   * @param seed - 25 English seed words, or the 24 without the checksum word
   * @param options - Key options
   * @param addressType - Any type throws, only standard addresses are written
   * @returns {Wallet} The wallet of the seed, the reduced spend key as its private key
   */
  override deriveSeedWallet(seed: string, options?: KeyOptions, addressType?: AddressType): Wallet {
    return this.deriveWallet(decodeMoneroSeed(seed).toHex(), options, addressType);
  }

  /**
   * Monero wallets restore from their own seed words, so there is no BIP44 path to build.
   * @returns {string} Never returns
   * @throws {RangeError} Always, naming what to use instead
   */
  override getDerivationPath(): string {
    throw new RangeError("Monero wallets restore from their 25-word seed, not a BIP44 path");
  }

  /**
   * BIP39 words make no Monero wallet any of the official ones would restore.
   * @returns {Wallet} Never returns
   * @throws {Error} Always, pointing at the seed words instead
   */
  override deriveHDWallet(): Wallet {
    throw new Error(
      "Monero does not derive from BIP39 words; restore the wallet from its 25-word seed instead",
    );
  }

  /**
   * Writes the standard address: network byte, both public keys and four bytes of keccak256.
   * @param keyPublic - The public spend key then the public view key, 64 bytes of hex
   * @param type - Any type throws, only standard addresses are written
   * @returns {string} The 95-character address
   */
  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
    const [spend, view] = splitKeyPublic(keyPublic);
    const body = concatBytes(Uint8Array.of(this.addressPrefix), spend, view);
    return encodeMoneroBase58(concatBytes(body, keccak256(body).subarray(0, CHECKSUM_BYTES)));
  }

  /**
   * Checks a standard address on this network: block base58, checksum and both keys on the curve.
   * @param address - The address to check
   * @returns {boolean} Whether a wallet on this network would pay to it
   */
  override validateAddress(address: string): boolean {
    let bytes: Uint8Array;
    try {
      bytes = decodeMoneroBase58(address);
    } catch {
      return false;
    }
    if (bytes.length !== ADDRESS_BYTES || bytes[0] !== this.addressPrefix) return false;
    const body = bytes.subarray(0, ADDRESS_BYTES - CHECKSUM_BYTES);
    if (!equalBytes(keccak256(body).subarray(0, CHECKSUM_BYTES), bytes.subarray(body.length))) {
      return false;
    }
    try {
      splitKeyPublic(body.subarray(1).toHex());
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Monero signs messages with its own SigV2 scheme, which this package does not write yet.
   * @returns {string} Never returns
   * @throws {Error} Always
   */
  override signMessage(): string {
    throw new Error("Monero message signatures (SigV2) are not supported yet");
  }

  /**
   * Monero signs messages with its own SigV2 scheme, which this package does not check yet.
   * @returns {boolean} Never returns
   * @throws {Error} Always
   */
  override verifyMessage(): boolean {
    throw new Error("Monero message signatures (SigV2) are not supported yet");
  }
}

export default Monero;
