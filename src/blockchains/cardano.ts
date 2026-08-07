import { blake2b } from "@noble/hashes/blake2.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";
import { AbstractBlockchain } from "../blockchain.ts";
import { generateKeyPublic as getEd25519KeyPublic } from "../utils/ed25519.ts";
import { ed25519SignMessage, ed25519VerifyMessage } from "../utils/ed25519-chains.ts";
import type { Curve, KeyOptions } from "../types.ts";

const ADDRESS_TYPE = {
  BASE_PAYMENT: 0,
  ENTERPRISE_KEY: 6,
  REWARD_KEY: 14,
} as const;

const NETWORK_PARAMS = {
  mainnet: {
    hrpAddress: "addr",
    hrpStake: "stake",
    networkId: 1,
  },
  testnet: {
    hrpAddress: "addr_test",
    hrpStake: "stake_test",
    networkId: 0,
  },
} as const;

/** Cardano blockchain implementation. */
export class Cardano extends AbstractBlockchain {
  override readonly name = "cardano";
  override readonly curve: Curve = "ed25519";
  override readonly bip44 = 1815;

  private get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  override getKeyPublic(keyPrivate: string, _options?: KeyOptions): string {
    return getEd25519KeyPublic(keyPrivate);
  }

  private getKeyHash(keyPublic: string): Uint8Array {
    return blake2b(hexToBytes(keyPublic), { dkLen: 28 });
  }

  private encodeAddress(hrp: string, header: number, payload: Uint8Array): string {
    const bytes = new Uint8Array(1 + payload.length);
    bytes[0] = header;
    bytes.set(payload, 1);
    return bech32.encode(hrp, bech32.toWords(bytes), false);
  }

  private header(addressType: number): number {
    return (addressType << 4) | this.params.networkId;
  }

  override getAddress(keyPublic: string, type?: string): string {
    const keyHash = this.getKeyHash(keyPublic);

    if (type === "stake") {
      return this.encodeAddress(
        this.params.hrpStake,
        this.header(ADDRESS_TYPE.REWARD_KEY),
        keyHash,
      );
    }

    if (type === "enterprise") {
      return this.encodeAddress(
        this.params.hrpAddress,
        this.header(ADDRESS_TYPE.ENTERPRISE_KEY),
        keyHash,
      );
    }

    const basePayload = new Uint8Array(keyHash.length * 2);
    basePayload.set(keyHash);
    basePayload.set(keyHash, keyHash.length);
    return this.encodeAddress(
      this.params.hrpAddress,
      this.header(ADDRESS_TYPE.BASE_PAYMENT),
      basePayload,
    );
  }

  override validateAddress(address: string): boolean {
    try {
      const decoded = bech32.decode(address, false);
      const bytes = bech32.fromWords(decoded.words);
      const headerByte = bytes[0];
      if (headerByte === undefined) return false;

      const expectedNetwork = this.params.networkId;
      const addressNetwork = headerByte & 0x0f;
      const addressType = headerByte >> 4;
      if (addressNetwork !== expectedNetwork) return false;

      if (decoded.prefix === this.params.hrpStake) {
        return addressType === ADDRESS_TYPE.REWARD_KEY && bytes.length === 29;
      }
      if (decoded.prefix !== this.params.hrpAddress) {
        return false;
      }
      if (addressType === ADDRESS_TYPE.BASE_PAYMENT) return bytes.length === 57;
      if (addressType === ADDRESS_TYPE.ENTERPRISE_KEY) return bytes.length === 29;
      return false;
    } catch {
      return false;
    }
  }

  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: KeyOptions,
  ): string {
    return ed25519SignMessage(message, keyPrivate, options);
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: KeyOptions,
  ): boolean {
    return ed25519VerifyMessage(message, signature, keyPublic, options);
  }
}

export default Cardano;
