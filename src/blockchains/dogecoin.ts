import { BIP44 } from "../utils/bip44/index.ts";
import {
  generateAddressLegacy,
  validateAddressLegacy,
  validateAddressP2SH,
} from "../utils/address.ts";
import { AbstractBitcoinMessageBlockchain } from "../utils/bitcoin.ts";
import type { Options } from "../types.ts";

/** Dogecoin Core v1.14.9 src/chainparams.cpp; regtest borrows Bitcoin's bytes and is not offered. */
const NETWORK_PARAMS = {
  mainnet: { bytesVersionP2PKH: 0x1e, bytesVersionP2SH: 0x16 },
  testnet: { bytesVersionP2PKH: 0x71, bytesVersionP2SH: 0xc4 },
} as const;

/**
 * Dogecoin P2PKH wallets in base58 and Core message signatures under its own preamble.
 * Dogecoin never activated SegWit, so it has no bech32, and the library's `p2sh` type, which
 * wraps P2WPKH, would be anyone can spend there. `legacy` is the only type it writes.
 */
export class Dogecoin extends AbstractBitcoinMessageBlockchain {
  override readonly name = "dogecoin";
  override readonly bip44 = BIP44.DOGECOIN;
  protected override readonly messagePreamble = "\u0019Dogecoin Signed Message:\n";

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError("Dogecoin supports mainnet and testnet only");
    }
  }

  private get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  /**
   * The P2PKH address in base58 under Dogecoin's version byte.
   * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
   * @param type - `legacy`, the only type, meaning pay-to-pubkey-hash
   * @returns {string} The address, such as `DSpgzjPyfQB6ZzeSbMWpaZiTTxGf2oBCs4`
   */
  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError("Dogecoin supports legacy P2PKH only");
    return generateAddressLegacy(keyPublic, { bytesVersion: this.params.bytesVersionP2PKH });
  }

  /**
   * Base58 P2PKH (`D`) or P2SH (`9` and `A`) under this network's version bytes. P2SH is
   * accepted because multisig pays to it; this library just never writes one.
   * @param address - Candidate address
   * @returns {boolean} Whether the address can receive Dogecoin on this network
   */
  override validateAddress(address: string): boolean {
    return (
      validateAddressLegacy(address, { bytesVersion: this.params.bytesVersionP2PKH }) ||
      validateAddressP2SH(address, { bytesVersion: this.params.bytesVersionP2SH })
    );
  }
}

export default Dogecoin;
