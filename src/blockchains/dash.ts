import { BIP44 } from "../utils/bip44/index.ts";
import {
  generateAddressLegacy,
  validateAddressLegacy,
  validateAddressP2SH,
} from "../utils/address.ts";
import { AbstractBitcoinMessageBlockchain } from "../utils/bitcoin.ts";
import type { Options } from "../types.ts";

/** Dash Core v23.1.8 src/chainparams.cpp; devnet and regtest share the testnet bytes. */
const NETWORK_PARAMS = {
  mainnet: { bytesVersionP2PKH: 0x4c, bytesVersionP2SH: 0x10 },
  testnet: { bytesVersionP2PKH: 0x8c, bytesVersionP2SH: 0x13 },
} as const;

/**
 * Dash P2PKH wallets in base58 and Core message signatures under the preamble Dash kept from
 * its DarkCoin days. Dash never adopted SegWit, so it has no bech32, and the library's `p2sh`
 * type, which wraps P2WPKH, would be anyone can spend there. `legacy` is the only type it writes.
 */
export class Dash extends AbstractBitcoinMessageBlockchain {
  override readonly name = "dash";
  override readonly bip44 = BIP44.DASH;
  protected override readonly messagePreamble = "\u0019DarkCoin Signed Message:\n";

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError("Dash supports mainnet and testnet only");
    }
  }

  private get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  /**
   * The P2PKH address in base58 under Dash's version byte.
   * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
   * @param type - `legacy`, the only type, meaning pay-to-pubkey-hash
   * @returns {string} The address, such as `Xywgfc872nn5CKtpATCoAjZCc4v96pJczy`
   */
  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError("Dash supports legacy P2PKH only");
    return generateAddressLegacy(keyPublic, { bytesVersion: this.params.bytesVersionP2PKH });
  }

  /**
   * Base58 P2PKH (`X`, testnet `y`) or P2SH (`7`, testnet `8` and `9`) under this network's
   * version bytes. P2SH is accepted because multisig pays to it; this library just never writes one.
   * @param address - Candidate address
   * @returns {boolean} Whether the address can receive Dash on this network
   */
  override validateAddress(address: string): boolean {
    return (
      validateAddressLegacy(address, { bytesVersion: this.params.bytesVersionP2PKH }) ||
      validateAddressP2SH(address, { bytesVersion: this.params.bytesVersionP2SH })
    );
  }
}

export default Dash;
