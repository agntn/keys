import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake256, ripemd160 } from "@agntn/hashes";
import { concatBytes } from "../utils/bytes.ts";
import { base58check } from "@scure/base";
import { AbstractBlockchain } from "../blockchain.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import { encodeCompactSize } from "../utils/bitcoin.ts";
import {
  isCompactSignature,
  recoverCompact,
  signCompact,
  verifyCompact,
} from "../utils/secp256k1/compact-signature.ts";
import { decodeKeyPrivate, decodePublicPoint } from "../utils/secp256k1/decode.ts";
import { generateKeyPublic } from "../utils/secp256k1/keys.ts";
import { hasRecoveryByte, readRecoveredFlag } from "../utils/signing.ts";
import type {
  Curve,
  KeyOptions,
  MessageSigner,
  Options,
  SigningOptions,
  Wallet,
  XpubWallet,
} from "../types.ts";

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

  /**
   * Coin type 1 on testnet, the `SLIP0044CoinType` of dcrd's testnet3 parameters.
   * @returns {number} The coin type
   */
  override get coinType(): number {
    return this.network === "testnet" ? BIP44.TESTNET : this.bip44;
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

  /** Decred wallets export `dpub` keys, and its HD derivation is not supported here. */
  override deriveXpubWallet(): XpubWallet {
    throw new Error("Decred HD derivation is not supported");
  }

  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError("Decred supports legacy ECDSA P2PKH only");
    decodePublicPoint(keyPublic);
    return codec.encode(
      concatBytes(this.prefix, ripemd160(blake256(Uint8Array.fromHex(keyPublic)))),
    );
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

  /**
   * Sign as 64 bytes of `r||s` hex, or with `recovered` as the base64 dcrd's `signmessage` prints.
   * @param message - The message to sign
   * @param keyPrivate - The private key as hex
   * @param options - `recovered` for dcrd's base64 form, `compressed` for its header
   * @returns {string} The signature
   */
  override signMessage(
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ): string {
    if (readRecoveredFlag(options)) {
      return signCompact(hashMessage(message), keyPrivate, options?.compressed !== false);
    }
    return secp256k1
      .sign(hashMessage(message), decodeKeyPrivate(keyPrivate), { prehash: false })
      .toHex();
  }

  override verifyMessage(
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
  ): boolean {
    if (hasRecoveryByte(signature)) {
      return false;
    }
    if (isCompactSignature(signature)) {
      return verifyCompact(hashMessage(message), signature, keyPublic);
    }
    try {
      return secp256k1.verify(
        Uint8Array.fromHex(signature),
        hashMessage(message),
        Uint8Array.fromHex(keyPublic),
        {
          prehash: false,
        },
      );
    } catch {
      return false;
    }
  }

  /**
   * Recover the signer of a dcrd base64 signature; dcrd reads headers 27 to 34 only.
   * @param message - The signed message
   * @param signature - Base64 of the header byte, then `r` and `s`
   * @returns {MessageSigner} The recovered key, always for a `legacy` P2PKH address
   */
  override recoverMessageSigner(message: string | Uint8Array, signature: string): MessageSigner {
    const signer = recoverCompact(hashMessage(message), signature);
    if (signer.addressType !== "legacy") {
      throw new TypeError("Decred message signature header must be 27 to 34, as dcrd writes it");
    }
    return signer;
  }
}

export default Decred;
