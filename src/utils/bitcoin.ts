import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { AbstractBlockchain } from "../blockchain.ts";
import {
  generateAddressLegacy,
  generateAddressP2SH,
  generateAddressSegWit,
  validateAddressLegacy,
  validateAddressP2SH,
  validateAddressSegWit,
  hash160,
} from "./address.ts";
import { decodeCashAddr, encodeCashAddr } from "./cashaddr.ts";
import { generateKeyPublic } from "./secp256k1.ts";
import {
  assertNoRecoveryByte,
  hasRecoveryByte,
  signMessage as genericSignMessage,
  verifyMessage as genericVerifyMessage,
} from "./signing.ts";
import type {
  AddressType,
  BitcoinAddressType,
  Curve,
  HDWalletOptions,
  KeyOptions,
  Options,
  SigningOptions,
  Wallet,
} from "../types.ts";

/** BIP43 purpose levels and the address format each one stands for. */
const PURPOSE_ADDRESS_TYPES: Readonly<Record<string, BitcoinAddressType>> = {
  "44": "legacy",
  "49": "p2sh",
  "84": "segwit",
  "86": "taproot",
};

/** One byte base58 versions of a chain that writes P2PKH only. */
interface P2PKHNetworkParams {
  readonly bytesVersionP2PKH: number;
  /** Absent when the chain refuses payments to P2SH, as Bitcoin SV does since Genesis. */
  readonly bytesVersionP2SH?: number;
}

/** How a CashAddr chain spells its prefixes and which payloads its node pays to. */
interface CashAddrParams {
  /** Lowercase prefix for each network. */
  readonly prefixes: Readonly<Record<"mainnet" | "testnet", string>>;
  /** Hash lengths the node turns into a destination, indexed by address type. */
  readonly hashLengths: readonly (readonly number[])[];
}

interface NetworkParams {
  readonly hrpSegWit: string;
  readonly prefixSegWitV1: string;
  readonly bytesVersionP2PKH: number;
  readonly bytesVersionP2SH: number;
}

/**
 * Validates a bech32 address as taproot (v1) or SegWit v0, dispatched on its prefix.
 * @param address - The bech32 address to validate
 * @param params - Network parameters providing the human readable part and v1 prefix
 * @returns {boolean} Whether the address is a valid SegWit v0 or v1 address
 */
function validateAddressBech32(address: string, params: NetworkParams): boolean {
  if (address.toLowerCase().startsWith(params.prefixSegWitV1)) {
    return validateAddressSegWit(address, {
      hrp: params.hrpSegWit,
      witnessVersion: 1,
    });
  }
  return validateAddressSegWit(address, {
    hrp: params.hrpSegWit,
    witnessVersion: 0,
  });
}

/**
 * Validates a base58 mainnet address as P2SH ("3") or legacy P2PKH ("1").
 * @param address - The base58 address to validate
 * @param params - Network parameters providing the version bytes
 * @returns {boolean} Whether the address is a valid mainnet P2SH or legacy address
 */
function validateAddressBase58Mainnet(address: string, params: NetworkParams): boolean {
  if (address.startsWith("3")) {
    return validateAddressP2SH(address, { bytesVersion: params.bytesVersionP2SH });
  }
  if (address.startsWith("1")) {
    return validateAddressLegacy(address, { bytesVersion: params.bytesVersionP2PKH });
  }
  return false;
}

/**
 * Validates a base58 testnet address as P2SH ("2") or legacy P2PKH ("m"/"n").
 * @param address - The base58 address to validate
 * @param params - Network parameters providing the version bytes
 * @returns {boolean} Whether the address is a valid testnet P2SH or legacy address
 */
function validateAddressBase58Testnet(address: string, params: NetworkParams): boolean {
  if (address.startsWith("2")) {
    return validateAddressP2SH(address, { bytesVersion: params.bytesVersionP2SH });
  }
  if (address.startsWith("m") || address.startsWith("n")) {
    return validateAddressLegacy(address, { bytesVersion: params.bytesVersionP2PKH });
  }
  return false;
}

export function encodeCompactSize(value: number): Uint8Array {
  if (value < 0xfd) return new Uint8Array([value]);
  if (value <= 0xffff) {
    const buffer = new Uint8Array(3);
    buffer[0] = 0xfd;
    buffer[1] = value & 0xff;
    buffer[2] = (value >> 8) & 0xff;
    return buffer;
  }

  const buffer = new Uint8Array(5);
  buffer[0] = 0xfe;
  buffer[1] = value & 0xff;
  buffer[2] = (value >> 8) & 0xff;
  buffer[3] = (value >> 16) & 0xff;
  buffer[4] = (value >> 24) & 0xff;
  return buffer;
}

/** Keys and signed messages the Bitcoin way, for chains whose address formats differ from it. */
export abstract class AbstractBitcoinMessageBlockchain extends AbstractBlockchain {
  override readonly curve: Curve = "secp256k1";
  protected abstract readonly messagePreamble: string;

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate, options);
  }

  protected hashWithMessagePreamble(message: string | Uint8Array): Uint8Array {
    const preambleBytes = new TextEncoder().encode(this.messagePreamble);
    const messageBytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
    const messageLength = encodeCompactSize(messageBytes.length);
    const fullMessage = new Uint8Array(
      preambleBytes.length + messageLength.length + messageBytes.length,
    );
    fullMessage.set(preambleBytes);
    fullMessage.set(messageLength, preambleBytes.length);
    fullMessage.set(messageBytes, preambleBytes.length + messageLength.length);
    return sha256(sha256(fullMessage));
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ): string {
    assertNoRecoveryByte(
      options,
      "Core encodes its recoverable signature as base64 of header||r||s, not r||s||v",
    );
    const hash = this.hashWithMessagePreamble(message);
    return genericSignMessage(hash, keyPrivate, {
      ...options,
      curve: "secp256k1",
      hash: false,
    });
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: SigningOptions,
  ): boolean {
    if (hasRecoveryByte(signature)) {
      return false;
    }
    const hash = this.hashWithMessagePreamble(message);
    try {
      return genericVerifyMessage(hash, signature, keyPublic, {
        ...options,
        curve: "secp256k1",
        hash: false,
      });
    } catch {
      return false;
    }
  }
}

/** Shared transparent address and HD behavior for Bitcoin, Litecoin and Bitcoin Gold. */
export abstract class AbstractBitcoinBlockchain extends AbstractBitcoinMessageBlockchain {
  protected abstract get params(): NetworkParams;

  override getAddress(keyPublic: string, type = "legacy"): string {
    if (["segwit", "p2wsh", "taproot"].includes(type)) {
      const segwitOptions = {
        hrp: this.params.hrpSegWit,
        witnessVersion: type === "taproot" ? 1 : 0,
      };
      const segwitType = type === "p2wsh" ? "p2wsh" : "p2wpkh";
      return generateAddressSegWit(keyPublic, segwitOptions, segwitType);
    }

    if (type === "p2sh") {
      return generateAddressP2SH(keyPublic, {
        bytesVersion: this.params.bytesVersionP2SH,
      });
    }

    return generateAddressLegacy(keyPublic, {
      bytesVersion: this.params.bytesVersionP2PKH,
    });
  }

  /**
   * Path purpose selects the address format unless a type is provided.
   * @param mnemonic - English BIP39 mnemonic
   * @param path - Derivation path such as `m/84'/0'/0'/0/0`
   * @param options - Key options plus an optional BIP39 passphrase
   * @param addressType - Explicit address type that wins over the purpose
   * @returns {Wallet} The wallet at the path
   */
  override deriveHDWallet(
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: AddressType,
  ): Wallet {
    const purpose = /^[mM]'?\/(\d+)'/u.exec(path)?.[1];
    const inferredType = purpose === undefined ? undefined : PURPOSE_ADDRESS_TYPES[Number(purpose)];
    return super.deriveHDWallet(mnemonic, path, options, addressType ?? inferredType);
  }

  override validateAddress(address: string): boolean {
    const segwitPrefix = this.params.hrpSegWit + "1";
    if (address.toLowerCase().startsWith(segwitPrefix)) {
      return validateAddressBech32(address, this.params);
    }

    if (this.network === "mainnet") {
      return validateAddressBase58Mainnet(address, this.params);
    }
    if (this.network === "testnet") {
      return validateAddressBase58Testnet(address, this.params);
    }
    return false;
  }
}

/**
 * Base58 P2PKH wallets on mainnet and testnet, for chains without SegWit that keep Bitcoin's
 * keys and one byte version prefixes: Bitcoin SV, Dash and Dogecoin. The shared `p2sh` type
 * wraps P2WPKH, which anyone could spend on such a chain, so `legacy` is the only type written.
 * Validation accepts P2SH when the network table gives its version byte, since multisig pays there.
 */
export abstract class AbstractBitcoinP2PKHBlockchain extends AbstractBitcoinMessageBlockchain {
  private readonly label: string;
  private readonly params: P2PKHNetworkParams;

  /**
   * @param options - Chain options; the network must be `mainnet` or `testnet`
   * @param label - Chain name as error messages spell it, such as `Bitcoin SV`
   * @param networks - Version bytes for each network
   */
  constructor(
    options: Options | undefined,
    label: string,
    networks: Readonly<Record<"mainnet" | "testnet", P2PKHNetworkParams>>,
  ) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError(`${label} supports mainnet and testnet only`);
    }
    this.label = label;
    this.params = networks[this.network];
  }

  /**
   * The P2PKH address in base58 under this network's version byte.
   * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
   * @param type - `legacy`, the only type, meaning pay-to-pubkey-hash
   * @returns {string} The address
   */
  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError(`${this.label} supports legacy P2PKH only`);
    return generateAddressLegacy(keyPublic, { bytesVersion: this.params.bytesVersionP2PKH });
  }

  /**
   * Base58 P2PKH, or P2SH where the chain pays to it, under this network's version bytes.
   * @param address - Candidate address
   * @returns {boolean} Whether the address can receive the chain's coin on this network
   */
  override validateAddress(address: string): boolean {
    const { bytesVersionP2PKH, bytesVersionP2SH } = this.params;
    return (
      validateAddressLegacy(address, { bytesVersion: bytesVersionP2PKH }) ||
      (bytesVersionP2SH !== undefined &&
        validateAddressP2SH(address, { bytesVersion: bytesVersionP2SH }))
    );
  }
}

/**
 * P2PKH wallets in CashAddr on mainnet and testnet, for chains that keep Bitcoin's keys and
 * hash but write addresses under their own prefix: Bitcoin Cash and eCash. There is no SegWit,
 * and the shared `p2sh` type would nest one, so `legacy` is the only type written. The base58
 * form of the same hash is Bitcoin's legacy address, so it is neither written nor accepted.
 */
export abstract class AbstractCashAddrBlockchain extends AbstractBitcoinMessageBlockchain {
  private readonly label: string;
  private readonly prefix: string;
  private readonly hashLengths: readonly (readonly number[])[];

  /**
   * @param options - Chain options; the network must be `mainnet` or `testnet`
   * @param label - Chain name as error messages spell it, such as `Bitcoin Cash`
   * @param params - Prefixes for each network and the payloads the node pays to
   */
  constructor(options: Options | undefined, label: string, params: CashAddrParams) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError(`${label} supports mainnet and testnet only`);
    }
    this.label = label;
    this.prefix = params.prefixes[this.network];
    this.hashLengths = params.hashLengths;
  }

  /**
   * The P2PKH address in CashAddr, prefix written out.
   * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
   * @param type - `legacy`, the only type, meaning pay-to-pubkey-hash
   * @returns {string} The address, such as `bitcoincash:qz3yjg59ypg6jqpwhaxgvjj44jm4hdx0w5wsxw2qez`
   */
  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError(`${this.label} supports legacy P2PKH only`);
    const bytesKeyPublic = hexToBytes(keyPublic);
    secp256k1.Point.fromBytes(bytesKeyPublic);
    return encodeCashAddr(this.prefix, 0, hash160(bytesKeyPublic));
  }

  /**
   * CashAddr under this network's prefix, written or not, with a type and hash length the
   * chain's node pays to.
   * @param address - Candidate address
   * @returns {boolean} Whether the address can receive the chain's coin on this network
   */
  override validateAddress(address: string): boolean {
    const content = decodeCashAddr(address, this.prefix);
    return (
      content !== undefined &&
      this.hashLengths[content.type]?.includes(content.hash.length) === true
    );
  }
}
