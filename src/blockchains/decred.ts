import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake256 } from "@noble/hashes/blake1.js";
import { ripemd160 } from "@noble/hashes/legacy.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { base58check } from "@scure/base";
import { AbstractBlockchain } from "../blockchain.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { encodeCompactSize } from "../utils/bitcoin.ts";
import { generateKeyPublic } from "../utils/secp256k1.ts";
import type { Curve, KeyOptions, Options, Wallet } from "../types.ts";

const codec = base58check(blake256);
const messagePreamble = new TextEncoder().encode("Decred Signed Message:\n");

/** ECDSA P2PKH prefixes from dcrd chaincfg, mainnet and testnet3. */
const NETWORK_PREFIXES = {
  mainnet: new Uint8Array([0x07, 0x3f]),
  testnet: new Uint8Array([0x0f, 0x21]),
};

function hashMessage(message: string | Uint8Array): Uint8Array {
  const bytes = typeof message === "string" ? new TextEncoder().encode(message) : message;
  return blake256(
    concatBytes(
      encodeCompactSize(messagePreamble.length),
      messagePreamble,
      encodeCompactSize(bytes.length),
      bytes,
    ),
  );
}

/** Decred ECDSA P2PKH wallets. Other address and signature schemes are not supported. */
export class Decred extends AbstractBlockchain {
  override readonly name = "decred";
  override readonly curve: Curve = "secp256k1";
  override readonly bip44 = BIP44.DECRED;

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError("Decred supports mainnet and testnet only");
    }
  }

  private get prefix(): Uint8Array {
    return this.network === "testnet" ? NETWORK_PREFIXES.testnet : NETWORK_PREFIXES.mainnet;
  }

  override getKeyPublic(keyPrivate: string, options?: KeyOptions): string {
    return generateKeyPublic(keyPrivate, options);
  }

  /** Decred strips leading zeros during HD derivation, unlike standard BIP32. */
  override deriveHDWallet(): Wallet {
    throw new Error("Decred HD derivation is not supported");
  }

  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError("Decred supports legacy ECDSA P2PKH only");
    secp256k1.Point.fromHex(keyPublic);
    return codec.encode(concatBytes(this.prefix, ripemd160(blake256(hexToBytes(keyPublic)))));
  }

  override validateAddress(address: string): boolean {
    if (address.length > 54) return false;
    try {
      const payload = codec.decode(address);
      return (
        payload.length === 22 && payload[0] === this.prefix[0] && payload[1] === this.prefix[1]
      );
    } catch {
      return false;
    }
  }

  override signMessage(message: string | Uint8Array, keyPrivate: string): string {
    return bytesToHex(
      secp256k1.sign(hashMessage(message), hexToBytes(keyPrivate), { prehash: false }),
    );
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
  ): boolean {
    try {
      return secp256k1.verify(hexToBytes(signature), hashMessage(message), hexToBytes(keyPublic), {
        prehash: false,
      });
    } catch {
      return false;
    }
  }
}

export default Decred;
