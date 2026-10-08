import { base64 } from "@agntn/encodings/base64";
import { bech32 } from "@agntn/encodings/bech32";
import { AbstractBlockchain } from "../blockchain.ts";
import { hash160 } from "../utils/address.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { COSMOS_PREFIX_PATTERN } from "../utils/cosmos-prefix.ts";
import { HARDENED_OFFSET } from "../utils/hd-index.ts";
import { decodePublicPoint } from "../utils/secp256k1/decode.ts";
import { generateKeyPublic } from "../utils/secp256k1/keys.ts";
import {
  assertNoRecoveryByte,
  hasRecoveryByte,
  signMessage,
  verifyMessage,
} from "../utils/signing.ts";
import type { AddressType, Curve, KeyOptions, Options, SigningOptions } from "../types.ts";

/** Prefix of the Cosmos Hub, used when the options name no other chain. */
const DEFAULT_PREFIX = "cosmos";

const PREFIX = new RegExp(COSMOS_PREFIX_PATTERN, "u");

/**
 * The `slip44` that cosmos/chain-registry gives each mainnet prefix, where it isn't 118. Chains on
 * Ethereum style keys stay out, since no coin type fixes their hash. Last synced 2026-10-08.
 */
const COIN_TYPES: Readonly<Record<string, number>> = {
  agoric: 564,
  axm: 546,
  band: 494,
  bitsong: 639,
  bluzelle: 483,
  core: 990,
  cro: 394,
  desmos: 852,
  dh: 10111,
  "did:com:": 701,
  firma: 7777777,
  fury: 459,
  gonka: 1200,
  hippo: 0,
  kava: 459,
  link: 438,
  lum: 880,
  maya: 931,
  panacea: 371,
  pb: 505,
  secret: 529,
  star: 234,
  taketitan: 1179993421,
  terra: 330,
  thor: 931,
  und: 5555,
  vdl: 370,
};

/** Most bytes an address may carry, `MaxAddrLen` in the SDK's default address verifier. */
const MAX_ADDRESS_BYTES = 255;

/** Longest bech32 string the SDK decodes, the limit its `DecodeAndConvert` passes. */
const MAX_BECH32_LENGTH = 1023;

/**
 * Looks the prefix up in the registry table, with an own-key check so `constructor` stays a prefix.
 * @param prefix - Bech32 prefix of the chain
 * @returns {number} Its coin type, or the Hub's 118 for a prefix the table doesn't list
 */
function knownCoinType(prefix: string): number {
  return Object.hasOwn(COIN_TYPES, prefix) ? (COIN_TYPES[prefix] ?? BIP44.COSMOS) : BIP44.COSMOS;
}

/**
 * The ADR-036 sign doc Keplr's `signArbitrary` signs: amino JSON with sorted keys and zeroed fields.
 * @param signer - Bech32 address of the signing key
 * @param message - The message, carried as base64 in `data`
 * @returns {Uint8Array} The JSON bytes whose SHA-256 gets signed
 */
function signDoc(signer: string, message: string | Uint8Array): Uint8Array {
  const data = base64.encode(
    typeof message === "string" ? new TextEncoder().encode(message) : message,
  );
  const doc = {
    account_number: "0",
    chain_id: "",
    fee: { amount: [], gas: "0" },
    memo: "",
    msgs: [{ type: "sign/MsgSignData", value: { data, signer } }],
    sequence: "0",
  };
  return new TextEncoder().encode(JSON.stringify(doc));
}

/** Cosmos SDK chains in one class: same keys, the prefix moves and the coin type follows it. */
export class Cosmos extends AbstractBlockchain {
  override readonly name = "cosmos";
  override readonly curve: Curve = "secp256k1";
  override readonly bip44 = BIP44.COSMOS;
  /** Human readable part every address of this instance carries. */
  readonly prefix: string;
  private readonly chainCoinType: number;

  constructor(options?: Options) {
    super(options);
    const prefix = options?.prefix ?? DEFAULT_PREFIX;
    if (!PREFIX.test(prefix)) {
      throw new RangeError(
        "A Cosmos prefix is 1 to 83 printable ASCII characters without uppercase, like osmo or fren-1",
      );
    }
    this.prefix = prefix;
    const coinType = options?.coinType ?? knownCoinType(prefix);
    if (!Number.isInteger(coinType) || coinType < 0 || coinType >= HARDENED_OFFSET) {
      throw new RangeError("A coin type is an integer from 0 to 2147483647, like 330 for Terra");
    }
    this.chainCoinType = coinType;
  }

  /**
   * The coin type passed in, else the one the chain registry gives this prefix, else the Hub's 118.
   * @returns {number} The coin type the path walks
   */
  override get coinType(): number {
    return this.chainCoinType;
  }

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate, options);
  }

  /**
   * Cosmos hashes the compressed key, whatever form it comes in.
   * @returns {"compressed"} The form the address hashes
   */
  protected override get addressKeyForm(): "compressed" {
    return "compressed";
  }

  /**
   * Writes bech32 over the hash160 of the compressed key, under this instance's prefix.
   * @param keyPublic - The secp256k1 public key as SEC1 hex, compressed or not
   * @param type - Any type throws, Cosmos has one address format
   * @returns {string} The bech32 address
   */
  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
    const hash = hash160(decodePublicPoint(keyPublic).toBytes(true));
    return bech32.encode(this.prefix, hash, MAX_BECH32_LENGTH);
  }

  /**
   * Checks the checksum, the prefix of this instance and a payload the SDK's default verifier takes.
   * @param address - The address to check
   * @returns {boolean} Whether a Cosmos SDK chain with this prefix takes it
   */
  override validateAddress(address: string): boolean {
    try {
      const { prefix, bytes } = bech32.decode(address, MAX_BECH32_LENGTH);
      return prefix === this.prefix && bytes.length > 0 && bytes.length <= MAX_ADDRESS_BYTES;
    } catch {
      return false;
    }
  }

  /**
   * Signs like Keplr's `signArbitrary`: ADR-036 sign doc, SHA-256, 64 bytes of `r||s`.
   * @param message - The message to sign
   * @param keyPrivate - The private key as hex
   * @param options - Key options
   * @returns {string} The 64-byte signature as hex
   */
  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ): string {
    assertNoRecoveryByte(
      options,
      "Cosmos signs ADR-036 as 64 bytes of r||s, with no recovery byte",
    );
    const signer = this.getAddress(generateKeyPublic(keyPrivate));
    return signMessage(signDoc(signer, message), keyPrivate, {
      ...options,
      curve: "secp256k1",
      hash: true,
    });
  }

  /**
   * Checks an ADR-036 signature, with the signer address taken from the key and this prefix.
   * @param message - The signed message
   * @param signature - The signature as hex
   * @param keyPublic - The public key as SEC1 hex
   * @param options - Key options
   * @returns {boolean} Whether the signature is valid, false for a malformed key too
   */
  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: SigningOptions,
  ): boolean {
    if (hasRecoveryByte(signature)) return false;
    try {
      return verifyMessage(signDoc(this.getAddress(keyPublic), message), signature, keyPublic, {
        ...options,
        curve: "secp256k1",
        hash: true,
      });
    } catch {
      return false;
    }
  }
}

export default Cosmos;
