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
import type { Curve, KeyOptions, SigningOptions } from "../types.ts";

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

  override validateAddress(address: string): boolean {
    const segwitPrefix = this.params.hrpSegWit + "1";
    if (address.startsWith(segwitPrefix)) {
      if (address.startsWith(this.params.prefixSegWitV1)) {
        return validateAddressSegWit(address, {
          hrp: this.params.hrpSegWit,
          witnessVersion: 1,
        });
      }
      return validateAddressSegWit(address, {
        hrp: this.params.hrpSegWit,
        witnessVersion: 0,
      });
    }

    if (this.network === "mainnet" && address.startsWith("3")) {
      return validateAddressP2SH(address, { bytesVersion: this.params.bytesVersionP2SH });
    }
    if (this.network === "testnet" && address.startsWith("2")) {
      return validateAddressP2SH(address, { bytesVersion: this.params.bytesVersionP2SH });
    }
    if (this.network === "mainnet" && address.startsWith("1")) {
      return validateAddressLegacy(address, { bytesVersion: this.params.bytesVersionP2PKH });
    }
    if (this.network === "testnet" && (address.startsWith("m") || address.startsWith("n"))) {
      return validateAddressLegacy(address, { bytesVersion: this.params.bytesVersionP2PKH });
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
    options?: SigningOptions,
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
    options?: SigningOptions,
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
