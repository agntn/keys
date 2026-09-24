import { BIP44 } from "../utils/bip44/index.ts";
import { generateAddressLegacy, validateAddressLegacy } from "../utils/address.ts";
import { AbstractBitcoinMessageBlockchain } from "../utils/bitcoin.ts";
import type { Options } from "../types.ts";

/** P2PKH version bytes from Bitcoin SV src/chainparams.cpp; testnet, STN and regtest share one. */
const NETWORK_VERSIONS = {
  mainnet: 0x00,
  testnet: 0x6f,
} as const;

/**
 * Bitcoin SV P2PKH wallets in base58. Keys, version bytes and signed messages are Bitcoin's,
 * preamble included, so a key gives the same `1` address on both chains. There is no SegWit,
 * and since Genesis the node rejects any transaction paying to P2SH (`bad-txns-vout-p2sh`),
 * so `legacy` is the only address type.
 */
export class BitcoinSV extends AbstractBitcoinMessageBlockchain {
  override readonly name = "bitcoinsv";
  override readonly bip44 = BIP44.BITCOIN_SV;
  protected override readonly messagePreamble = "\u0018Bitcoin Signed Message:\n";

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError("Bitcoin SV supports mainnet and testnet only");
    }
  }

  private get bytesVersion(): number {
    return this.network === "testnet" ? NETWORK_VERSIONS.testnet : NETWORK_VERSIONS.mainnet;
  }

  /**
   * The P2PKH address in base58, the same bytes Bitcoin writes for the key.
   * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
   * @param type - `legacy`, the only type, meaning pay-to-pubkey-hash
   * @returns {string} The address, such as `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`
   */
  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type !== "legacy") throw new RangeError("Bitcoin SV supports legacy P2PKH only");
    return generateAddressLegacy(keyPublic, { bytesVersion: this.bytesVersion });
  }

  /**
   * Base58 P2PKH under this network's version byte. P2SH decodes in the node, but a payment to
   * it fails consensus since Genesis, so it is refused along with bech32 and CashAddr.
   * @param address - Candidate address
   * @returns {boolean} Whether the address can receive Bitcoin SV on this network
   */
  override validateAddress(address: string): boolean {
    return validateAddressLegacy(address, { bytesVersion: this.bytesVersion });
  }
}

export default BitcoinSV;
