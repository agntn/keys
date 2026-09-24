import { secp256k1 } from "@noble/curves/secp256k1.js";
import { concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { bech32m } from "@scure/base";
import { BIP44 } from "../utils/bip44/index.ts";
import { hash160 } from "../utils/address.ts";
import { AbstractBitcoinMessageBlockchain } from "../utils/bitcoin.ts";
import { decodeBase58Check, encodeBase58Check } from "../utils/encoding.ts";
import type { Options } from "../types.ts";

/**
 * zcashd v6.20.0 src/chainparams.cpp. Transparent addresses carry a two byte version, so they
 * don't fit the one byte helpers in `utils/address.ts`. Regtest shares the testnet base58 bytes
 * but has a TEX prefix of its own.
 */
const NETWORK_PARAMS = {
  mainnet: {
    prefixP2PKH: new Uint8Array([0x1c, 0xb8]),
    prefixP2SH: new Uint8Array([0x1c, 0xbd]),
    hrpTEX: "tex",
  },
  testnet: {
    prefixP2PKH: new Uint8Array([0x1d, 0x25]),
    prefixP2SH: new Uint8Array([0x1c, 0xba]),
    hrpTEX: "textest",
  },
} as const;

/**
 * Whether a base58check string decodes to a 20 byte hash behind the given two byte version.
 * @param address - Candidate address
 * @param prefix - The two version bytes
 * @returns {boolean} Whether the address carries that version
 */
function hasTransparentPrefix(address: string, prefix: Uint8Array): boolean {
  if (address.length > 36) return false;
  try {
    const payload = decodeBase58Check(address);
    return payload.length === 22 && payload[0] === prefix[0] && payload[1] === prefix[1];
  } catch {
    return false;
  }
}

/**
 * Transparent Zcash wallets: P2PKH in base58 under a two byte version, and zcashd message
 * signatures, which hash the Bitcoin way under Zcash's own preamble. Sapling, Orchard and
 * unified addresses are shielded and out of scope, so `validateAddress` refuses them.
 * Zcash has no SegWit, and the library's `p2sh` type wraps P2WPKH, which anyone could spend
 * there, so `legacy` is the only type it writes.
 */
export class Zcash extends AbstractBitcoinMessageBlockchain {
  override readonly name = "zcash";
  override readonly bip44 = BIP44.ZCASH;
  protected override readonly messagePreamble = "\u0016Zcash Signed Message:\n";

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError("Zcash supports mainnet and testnet only");
    }
  }

  private get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  /**
   * The transparent P2PKH address in base58 under Zcash's two version bytes.
   * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
   * @param type - `legacy`, the only type, meaning pay-to-pubkey-hash
   * @returns {string} The address, such as `t1h8SqgtM3QM5e2M8EzhhT1yL2PXXtA6oqe`
   */
  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError("Zcash supports transparent P2PKH only");
    secp256k1.Point.fromHex(keyPublic);
    return encodeBase58Check(concatBytes(this.params.prefixP2PKH, hash160(hexToBytes(keyPublic))));
  }

  /**
   * Transparent P2PKH (`t1`, testnet `tm`), P2SH (`t3`, testnet `t2`) or a ZIP-320 TEX address
   * (`tex1`, testnet `textest1`), which is a P2PKH hash in bech32m for senders that must spend
   * transparent funds only. P2SH and TEX are accepted because they receive Zcash; this library
   * just never writes them. Shielded and unified addresses return false.
   * @param address - Candidate address
   * @returns {boolean} Whether the address is a transparent Zcash destination on this network
   */
  override validateAddress(address: string): boolean {
    const { prefixP2PKH, prefixP2SH, hrpTEX } = this.params;
    if (hasTransparentPrefix(address, prefixP2PKH) || hasTransparentPrefix(address, prefixP2SH)) {
      return true;
    }
    const decoded = bech32m.decodeUnsafe(address);
    return (
      decoded !== undefined &&
      decoded.prefix === hrpTEX &&
      bech32m.fromWordsUnsafe(decoded.words)?.length === 20
    );
  }
}

export default Zcash;
