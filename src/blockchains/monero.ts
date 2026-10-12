import { keccak256 } from "@agntn/hashes";
import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToNumberLE, equalBytes } from "@noble/curves/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { concatBytes } from "../utils/bytes.ts";
import { decodeMoneroBase58, encodeMoneroBase58 } from "../utils/monero-base58.ts";
import { decodeMoneroSeed } from "../utils/monero-seed.ts";
import type {
  AddressType,
  Curve,
  KeyOptions,
  MoneroSigningKey,
  Options,
  SigningOptions,
  Wallet,
} from "../types.ts";

const { Point } = ed25519;

/** Network bytes of the three address kinds, one set per network Monero runs. */
interface AddressPrefixes {
  readonly standard: number;
  readonly integrated: number;
  readonly subaddress: number;
}

const ADDRESS_PREFIXES: Readonly<Record<string, AddressPrefixes>> = {
  mainnet: { standard: 18, integrated: 19, subaddress: 42 },
  testnet: { standard: 53, integrated: 54, subaddress: 63 },
  stagenet: { standard: 24, integrated: 25, subaddress: 36 },
};

/** The largest multiple of l that fits in 32 bytes; draws at or above it would bias the key. */
const DRAW_LIMIT = 15n * Point.Fn.ORDER;

/** Bytes of the keccak256 checksum at the end of an address. */
const CHECKSUM_BYTES = 4;

/** Bytes of a standard address or a subaddress: network byte, spend key, view key and checksum. */
const ADDRESS_BYTES = 1 + 32 + 32 + CHECKSUM_BYTES;

/** Bytes of the payment ID an integrated address carries after both keys. */
const PAYMENT_ID_BYTES = 8;

/** Bytes of an integrated address: a standard one with the payment ID before the checksum. */
const INTEGRATED_ADDRESS_BYTES = ADDRESS_BYTES + PAYMENT_ID_BYTES;

/** The largest account or address index, since wallet2 keeps both as uint32. */
const MAX_SUBADDRESS_INDEX = 0xffffffff;

/** Domain tag wallet2 hashes in front of the view key for every subaddress. */
const SUBADDRESS_TAG = new TextEncoder().encode("SubAddr\0");

/** Domain tag `get_message_hash` opens every SigV2 digest with, the NUL included. */
const MESSAGE_TAG = new TextEncoder().encode("MoneroMessageSignature\0");

/** The mode byte SigV2 hashes, so a signature by one key never passes as the other's. */
const SIGNING_MODES: Readonly<Record<MoneroSigningKey, number>> = { spend: 0, view: 1 };

/** Header of the signatures wallet2 writes today, bound to both keys and the mode. */
const SIGNATURE_V2 = "SigV2";

/** Header of the older signatures over the bare keccak256 of the message, still read by wallets. */
const SIGNATURE_V1 = "SigV1";

/** Bytes of a signature: the challenge `c`, then the response `r`. */
const SIGNATURE_BYTES = 64;

/**
 * Reduces 32 little-endian bytes mod l, as Monero's `sc_reduce32` does before a key is used.
 * @param bytes - 32 bytes read as a little-endian number
 * @returns {bigint} The scalar
 */
function reduceScalar(bytes: Uint8Array): bigint {
  return Point.Fn.create(bytesToNumberLE(bytes));
}

/**
 * Draws a scalar like Monero's `random32_unbiased`: below 15l, reduced mod l, never zero.
 * @returns {bigint} The scalar
 */
function randomScalar(): bigint {
  for (;;) {
    const draw = bytesToNumberLE(ed25519.utils.randomSecretKey());
    const scalar = Point.Fn.create(draw);
    if (draw < DRAW_LIMIT && scalar !== 0n) return scalar;
  }
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
 * Monero's `check_address` on one key: a point, not the identity, in the main subgroup.
 * @param key - 32 bytes of a public key
 * @returns {boolean} Whether a Monero wallet would pay to it
 */
function isAddressKey(key: Uint8Array): boolean {
  try {
    const point = Point.fromBytes(key);
    return !point.is0() && point.isTorsionFree();
  } catch {
    return false;
  }
}

/**
 * Splits the 64-byte public key into its spend and view halves, both checked like `check_address`.
 * @param keyPublic - Public spend key then public view key, as hex
 * @returns {readonly [Uint8Array, Uint8Array]} The spend and view keys
 * @throws {RangeError} When the key is not 64 bytes or either half is no key Monero pays to
 */
function splitKeyPublic(keyPublic: string): readonly [Uint8Array, Uint8Array] {
  const bytes = Uint8Array.fromHex(keyPublic);
  if (bytes.length !== 64) {
    throw new RangeError("Monero public key must be 64 bytes: the spend key, then the view key");
  }
  const spend = bytes.slice(0, 32);
  const view = bytes.slice(32);
  if (!isAddressKey(spend) || !isAddressKey(view)) {
    throw new RangeError(
      "Monero public keys must be ed25519 points in the main subgroup, not identity",
    );
  }
  return [spend, view];
}

/**
 * Reads a private view key that belongs to the public view key it is given with.
 * @param viewKey - The private view key, 32 bytes of hex, reduced mod l like every wallet keeps it
 * @param publicView - The public view key from the same wallet
 * @returns {Uint8Array} The view key bytes, the exact ones wallet2 hashes for a subaddress
 * @throws {RangeError} When the key is not a reduced scalar or not the one behind `publicView`
 */
function viewKeyBytes(viewKey: string, publicView: ArrayLike<number>): Uint8Array {
  const bytes = Uint8Array.fromHex(viewKey);
  if (bytes.length !== 32) throw new RangeError("Monero view key must be 32 bytes");
  const scalar = bytesToNumberLE(bytes);
  if (scalar === 0n || scalar >= Point.Fn.ORDER) {
    throw new RangeError("Monero view key must be a nonzero scalar below l, as wallets keep it");
  }
  if (!equalBytes(Point.BASE.multiply(scalar).toBytes(), Uint8Array.from(publicView))) {
    throw new RangeError("Monero view key does not belong to the public view key it came with");
  }
  return bytes;
}

/**
 * Writes an account or address index as the four little-endian bytes wallet2 hashes.
 * @param value - The index
 * @param name - What the index is, for the error
 * @returns {Uint8Array} Four bytes
 * @throws {RangeError} When the index is not an integer from 0 to 2^32 - 1
 */
function indexBytes(value: number, name: string): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > MAX_SUBADDRESS_INDEX) {
    throw new RangeError(`Monero ${name} must be an integer from 0 to ${MAX_SUBADDRESS_INDEX}`);
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, true);
  return bytes;
}

/**
 * Appends four bytes of keccak256 and writes the result in Monero's block base58.
 * @param body - Network byte and everything the address carries before its checksum
 * @returns {string} The address
 */
function encodeAddress(body: ArrayLike<number>): string {
  const bytes = Uint8Array.from(body);
  return encodeMoneroBase58(concatBytes(bytes, keccak256(bytes).subarray(0, CHECKSUM_BYTES)));
}

/**
 * Refuses an address type for a whole wallet, whose own address is always the standard one.
 * @param type - The type the caller asked for
 * @throws {RangeError} When any type is given
 */
function refuseWalletAddressType(type: AddressType | undefined): void {
  if (type === undefined) return;
  throw new RangeError(
    `A Monero wallet writes its standard address, not ${JSON.stringify(type)}; pick a subaddress by its account and index instead`,
  );
}

/**
 * The bytes a wallet signs: a string as UTF-8, bytes as they are.
 * @param message - The message
 * @returns {Uint8Array} Its bytes
 */
function messageBytes(message: string | Uint8Array): Uint8Array {
  return typeof message === "string" ? new TextEncoder().encode(message) : message;
}

/**
 * Writes a length the way Monero's `write_varint` does: seven bits a byte, low bits first.
 * @param value - The length
 * @returns {Uint8Array} One byte below 128, more above it
 */
function varint(value: number): Uint8Array {
  const bytes: number[] = [];
  let rest = value;
  while (rest >= 0x80) {
    bytes.push((rest % 0x80) | 0x80);
    rest = Math.floor(rest / 0x80);
  }
  bytes.push(rest);
  return Uint8Array.from(bytes);
}

/**
 * The SigV2 digest of `get_message_hash`: the tag, both public keys, the mode and the message.
 * @param message - The message bytes
 * @param spend - The public spend key of the address
 * @param view - The public view key of the address
 * @param mode - 0 when the spend key signs, 1 when the view key does
 * @returns {Uint8Array} 32 bytes of keccak256
 */
function messageHash(
  message: Uint8Array,
  spend: Uint8Array,
  view: Uint8Array,
  mode: number,
): Uint8Array {
  return keccak256(
    concatBytes(MESSAGE_TAG, spend, view, Uint8Array.of(mode), varint(message.length), message),
  );
}

/**
 * The challenge of `generate_signature`: keccak256 of digest, key and commitment, mod l.
 * @param hash - The signed digest
 * @param key - The public key that signs
 * @param commitment - The nonce point, as 32 bytes
 * @returns {bigint} The scalar `c`
 */
function challenge(hash: Uint8Array, key: Uint8Array, commitment: Uint8Array): bigint {
  return reduceScalar(keccak256(concatBytes(hash, key, commitment)));
}

/**
 * Monero's `generate_signature`: a fresh nonce k, then `c` over kG and `r = k - c * secret`.
 * @param hash - The digest to sign
 * @param key - The public key of `secret`
 * @param secret - The private key
 * @returns {Uint8Array} 64 bytes, `c` then `r`, both little endian
 */
function schnorrSign(hash: Uint8Array, key: Uint8Array, secret: bigint): Uint8Array {
  for (;;) {
    const nonce = randomScalar();
    const c = challenge(hash, key, Point.BASE.multiply(nonce).toBytes());
    const r = Point.Fn.sub(nonce, Point.Fn.mul(c, secret));
    if (c !== 0n && r !== 0n) return concatBytes(Point.Fn.toBytes(c), Point.Fn.toBytes(r));
  }
}

/**
 * Monero's `check_signature`: canonical scalars, a commitment that isn't the identity, same `c`.
 * @param hash - The signed digest
 * @param key - The public key, already checked to be a point
 * @param signature - 64 bytes, `c` then `r`
 * @returns {boolean} Whether `key` signed `hash`
 */
function schnorrCheck(hash: Uint8Array, key: Uint8Array, signature: Uint8Array): boolean {
  const c = bytesToNumberLE(signature.subarray(0, 32));
  const r = bytesToNumberLE(signature.subarray(32));
  if (c === 0n || c >= Point.Fn.ORDER || r >= Point.Fn.ORDER) return false;
  const commitment = Point.fromBytes(key).multiplyUnsafe(c).add(Point.BASE.multiplyUnsafe(r));
  return !commitment.is0() && challenge(hash, key, commitment.toBytes()) === c;
}

/**
 * Reads the mode byte of the key the caller picked, refusing a name that is neither key.
 * @param signingKey - `spend`, `view` or left out for the spend key
 * @returns {number} The mode byte
 * @throws {RangeError} When the name is neither `spend` nor `view`
 */
function signingMode(signingKey: MoneroSigningKey | undefined): number {
  const name = signingKey ?? "spend";
  if (!Object.hasOwn(SIGNING_MODES, name)) {
    throw new RangeError(
      `A Monero message is signed by the spend or the view key, not ${JSON.stringify(name)}`,
    );
  }
  return SIGNING_MODES[name];
}

/**
 * Splits a signature into its version and bytes, refusing text no wallet would print.
 * @param signature - `SigV1` or `SigV2`, then 64 bytes in Monero's block base58
 * @returns {Readonly<{ v2: boolean; bytes: Uint8Array }>} Whether it is V2, and `c` then `r`
 * @throws {RangeError} On another header, text off the alphabet or a length other than 64 bytes
 */
function readSignature(signature: string): Readonly<{ v2: boolean; bytes: Uint8Array }> {
  const header = signature.slice(0, SIGNATURE_V2.length);
  if (header !== SIGNATURE_V2 && header !== SIGNATURE_V1) {
    throw new RangeError("A Monero signature starts with SigV2 or SigV1, as wallets print it");
  }
  const bytes = decodeMoneroBase58(signature.slice(header.length));
  if (bytes.length !== SIGNATURE_BYTES) {
    throw new RangeError("A Monero signature holds 64 bytes after its header: c, then r");
  }
  return { v2: header === SIGNATURE_V2, bytes };
}

/** Monero standard, sub and integrated addresses; the private key is the spend key alone. */
export class Monero extends AbstractBlockchain {
  override readonly name = "monero";
  override readonly curve: Curve = "ed25519";
  override readonly bip44 = BIP44.MONERO;
  /** Network byte every standard address of this instance starts with. */
  readonly addressPrefix: number;
  /** Network byte of a subaddress on this network. */
  readonly subaddressPrefix: number;
  /** Network byte of an integrated address on this network. */
  readonly integratedAddressPrefix: number;

  constructor(options?: Options) {
    super(options);
    const prefixes = Object.hasOwn(ADDRESS_PREFIXES, this.network)
      ? ADDRESS_PREFIXES[this.network]
      : undefined;
    if (prefixes === undefined) {
      throw new RangeError(
        `Monero networks are mainnet, testnet and stagenet, not ${JSON.stringify(this.network)}`,
      );
    }
    this.addressPrefix = prefixes.standard;
    this.subaddressPrefix = prefixes.subaddress;
    this.integratedAddressPrefix = prefixes.integrated;
  }

  /**
   * Draws a spend key like Monero's `random32_unbiased`: below 15l, reduced mod l, never zero.
   * @returns {string} The private spend key as hex
   */
  override generateKeyPrivate(): string {
    return Point.Fn.toBytes(randomScalar()).toHex();
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
   * @param addressType - Any type throws, the wallet writes its standard address
   * @returns {Wallet} The wallet with its standard address
   */
  override deriveWallet(
    keyPrivate: string,
    options?: KeyOptions,
    addressType?: AddressType,
  ): Wallet {
    refuseWalletAddressType(addressType);
    const spend = Point.Fn.toBytes(spendScalar(keyPrivate)).toHex();
    return super.deriveWallet(spend, options);
  }

  /**
   * Draws a new wallet and writes its standard address.
   * @param options - Key options
   * @param addressType - Any type throws, the wallet writes its standard address
   * @returns {Wallet} The new wallet
   */
  override generateWallet(options?: KeyOptions, addressType?: AddressType): Wallet {
    refuseWalletAddressType(addressType);
    return super.generateWallet(options);
  }

  /**
   * Restores a wallet from its seed words, as monero-wallet-cli `--restore-deterministic-wallet`.
   * @param seed - 25 English seed words, or the 24 without the checksum word
   * @param options - Key options
   * @param addressType - Any type throws, the wallet writes its standard address
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
   * Writes the address of a key pair: network byte, both public keys and four bytes of keccak256.
   * @param keyPublic - The public spend key then the public view key, 64 bytes of hex
   * @param type - `subaddress` for the pair of a subaddress, as `getSubaddressKeyPublic` gives it;
   * left out for the standard address
   * @returns {string} The 95-character address
   * @throws {RangeError} When the type is neither left out nor `subaddress`
   */
  override getAddress(keyPublic: string, type?: AddressType): string {
    if (type !== undefined && type !== "subaddress") {
      throw new RangeError(
        `Monero writes standard addresses and subaddresses, not ${JSON.stringify(type)}; an integrated address comes from getIntegratedAddress`,
      );
    }
    const prefix = type === undefined ? this.addressPrefix : this.subaddressPrefix;
    const [spend, view] = splitKeyPublic(keyPublic);
    return encodeAddress(concatBytes(Uint8Array.of(prefix), spend, view));
  }

  /**
   * Both public keys of a subaddress as wallet2 derives them; a view key is the only secret needed.
   * @param keyPublic - The wallet's public spend key then public view key, 64 bytes of hex
   * @param viewKey - The wallet's private view key, 32 bytes of hex
   * @param account - The account, the major index
   * @param index - The address within the account, the minor index
   * @returns {string} 64 bytes of hex; account 0, index 0 is the wallet's own pair
   * @throws {RangeError} When a key is malformed, the view key is not the wallet's, or an index
   * falls outside 0 to 2^32 - 1
   */
  getSubaddressKeyPublic(
    keyPublic: string,
    viewKey: string,
    account: number,
    index: number,
  ): string {
    const [spend, view] = splitKeyPublic(keyPublic);
    const secret = viewKeyBytes(viewKey, view);
    const indices = concatBytes(indexBytes(account, "account"), indexBytes(index, "address index"));
    if (account === 0 && index === 0) return concatBytes(spend, view).toHex();
    const m = reduceScalar(keccak256(concatBytes(SUBADDRESS_TAG, secret, indices)));
    const subSpend = Point.fromBytes(spend).add(Point.BASE.multiply(m));
    const subView = subSpend.multiply(bytesToNumberLE(secret));
    return concatBytes(subSpend.toBytes(), subView.toBytes()).toHex();
  }

  /**
   * The address monero-wallet-cli lists at an account and index, the standard one at 0/0.
   * @param keyPublic - The wallet's public spend key then public view key, 64 bytes of hex
   * @param viewKey - The wallet's private view key, 32 bytes of hex
   * @param account - The account, the major index
   * @param index - The address within the account, the minor index
   * @returns {string} The 95-character address
   * @throws {RangeError} Like `getSubaddressKeyPublic`
   */
  getSubaddress(keyPublic: string, viewKey: string, account: number, index: number): string {
    const pair = this.getSubaddressKeyPublic(keyPublic, viewKey, account, index);
    return this.getAddress(pair, account === 0 && index === 0 ? undefined : "subaddress");
  }

  /**
   * The standard address with an 8-byte payment ID inside, as `integrated_address` writes it.
   * @param keyPublic - The wallet's public spend key then public view key, 64 bytes of hex
   * @param paymentId - The payment ID, 8 bytes of hex
   * @returns {string} The 106-character address
   * @throws {RangeError} When a key is malformed or the payment ID is not 8 bytes
   */
  getIntegratedAddress(keyPublic: string, paymentId: string): string {
    const [spend, view] = splitKeyPublic(keyPublic);
    const id = /^[0-9a-f]{16}$/iu.test(paymentId) ? Uint8Array.fromHex(paymentId) : undefined;
    if (id === undefined) throw new RangeError("Monero payment ID must be 8 bytes of hex");
    return encodeAddress(concatBytes(Uint8Array.of(this.integratedAddressPrefix), spend, view, id));
  }

  /**
   * Checks any of the three kinds on this network like `check_address`: checksum and both keys.
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
    if (!this.hasAddressLayout(bytes)) return false;
    const body = bytes.subarray(0, bytes.length - CHECKSUM_BYTES);
    if (!equalBytes(keccak256(body).subarray(0, CHECKSUM_BYTES), bytes.subarray(body.length))) {
      return false;
    }
    try {
      splitKeyPublic(body.subarray(1, ADDRESS_BYTES - CHECKSUM_BYTES).toHex());
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Whether the network byte and the length agree on one of the three kinds of this network.
   * @param bytes - The decoded address
   * @returns {boolean} Whether the layout is one a wallet here writes
   */
  private hasAddressLayout(bytes: ArrayLike<number>): boolean {
    const prefix = bytes[0];
    if (bytes.length === INTEGRATED_ADDRESS_BYTES) return prefix === this.integratedAddressPrefix;
    if (bytes.length !== ADDRESS_BYTES) return false;
    return prefix === this.addressPrefix || prefix === this.subaddressPrefix;
  }

  /**
   * Signs a message like `monero-wallet-cli sign`: SigV2 for the standard address of the wallet.
   * @param message - The message, UTF-8 when it is a string
   * @param keyPrivate - The private spend key as hex; the view key comes from it
   * @param options - `signingKey: "view"` signs with the view key, as `sign --view` does
   * @returns {string} `SigV2` and 88 characters of block base58
   * @throws {RangeError} When the key is malformed or `signingKey` names neither key
   */
  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ): string {
    const mode = signingMode(options?.signingKey);
    const spend = spendScalar(keyPrivate);
    const view = viewScalar(spend);
    const spendKey = Point.BASE.multiply(spend).toBytes();
    const viewKey = Point.BASE.multiply(view).toBytes();
    const hash = messageHash(messageBytes(message), spendKey, viewKey, mode);
    const signature =
      mode === SIGNING_MODES.view
        ? schnorrSign(hash, viewKey, view)
        : schnorrSign(hash, spendKey, spend);
    return SIGNATURE_V2 + encodeMoneroBase58(signature);
  }

  /**
   * Checks a SigV2 or SigV1 signature like `monero-wallet-cli verify`, under either key.
   * @param message - The message, UTF-8 when it is a string
   * @param signature - The signature as the wallet printed it
   * @param keyPublic - The public spend key then the public view key of the address, 64 bytes of
   * hex; a subaddress signature checks against the pair of that subaddress
   * @returns {boolean} Whether the spend or the view key of the address signed the message
   * @throws {RangeError} When the signature or the key cannot be read, so it never reads as invalid
   */
  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
  ): boolean {
    const { v2, bytes } = readSignature(signature);
    const [spend, view] = splitKeyPublic(keyPublic);
    const data = messageBytes(message);
    const digest = (mode: number): Uint8Array =>
      v2 ? messageHash(data, spend, view, mode) : keccak256(data);
    return (
      schnorrCheck(digest(SIGNING_MODES.spend), spend, bytes) ||
      schnorrCheck(digest(SIGNING_MODES.view), view, bytes)
    );
  }
}

export default Monero;
