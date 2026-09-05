import { sha256 } from "@noble/hashes/sha2.js";
import { AbstractBlockchain } from "../blockchain.ts";
import {
  generateAddressLegacy,
  generateAddressP2SH,
  generateAddressSegWit,
  validateAddressLegacy,
  validateAddressP2SH,
  validateAddressSegWit,
} from "../utils/address.ts";
import { generateKeyPublic } from "../utils/secp256k1.ts";
import {
  signMessage as genericSignMessage,
  verifyMessage as genericVerifyMessage,
} from "../utils/signing.ts";
import type {
  AddressType,
  BitcoinAddressType,
  Curve,
  HDWalletOptions,
  KeyOptions,
  Wallet,
} from "../types.ts";

/** BIP43 purpose levels and the address format each one stands for. */
const PURPOSE_ADDRESS_TYPES: Readonly<Record<string, BitcoinAddressType>> = {
  "44": "legacy",
  "49": "p2sh",
  "84": "segwit",
  "86": "taproot",
};

const NETWORK_PARAMS = {
  mainnet: {
    hrpSegWit: "bc",
    prefixSegWitV1: "bc1p",
    bytesVersionP2PKH: 0x00,
    bytesVersionP2SH: 0x05,
  },
  testnet: {
    hrpSegWit: "tb",
    prefixSegWitV1: "tb1p",
    bytesVersionP2PKH: 0x6f,
    bytesVersionP2SH: 0xc4,
  },
} as const;

type NetworkParams = (typeof NETWORK_PARAMS)[keyof typeof NETWORK_PARAMS];

/**
 * Validates a bech32 address as taproot (v1) or SegWit v0, dispatched on its prefix.
 * @param address - The bech32 address to validate
 * @param params - Network parameters providing the human-readable part and v1 prefix
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

function encodeCompactSize(value: number): Uint8Array {
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

/** Bitcoin blockchain implementation. */
export class Bitcoin extends AbstractBlockchain {
  override readonly name = "bitcoin";
  override readonly curve: Curve = "secp256k1";
  override readonly bip44 = 0;

  private get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate, options);
  }

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
   * Without an explicit type the path purpose picks the format, so `m/84'/...` lands on bc1q, not on a legacy `1`.
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

  private hashWithBitcoinPreamble(message: string | Uint8Array): Uint8Array {
    const preambleBytes = new TextEncoder().encode("\u0018Bitcoin Signed Message:\n");
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
    options?: KeyOptions,
  ): string {
    const hash = this.hashWithBitcoinPreamble(message);
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
    options?: KeyOptions,
  ): boolean {
    const hash = this.hashWithBitcoinPreamble(message);
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

export default Bitcoin;
