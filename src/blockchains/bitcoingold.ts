import { AbstractBitcoinBlockchain } from "../utils/bitcoin.ts";
import { validateAddressLegacy, validateAddressP2SH } from "../utils/address.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import type { Options } from "../types.ts";

/** Bitcoin Gold v0.21.3 src/chainparams.cpp; testnet, signet and regtest share Bitcoin's bytes. */
const NETWORK_PARAMS = {
  mainnet: {
    hrpSegWit: "btg",
    prefixSegWitV1: "btg1p",
    bytesVersionP2PKH: 0x26,
    bytesVersionP2SH: 0x17,
  },
  testnet: {
    hrpSegWit: "tbtg",
    prefixSegWitV1: "tbtg1p",
    bytesVersionP2PKH: 0x6f,
    bytesVersionP2SH: 0xc4,
  },
} as const;

/**
 * Bitcoin Gold transparent addresses and message signatures. The chain kept SegWit from before
 * the fork, but its Taproot deployment timed out in August 2021, before any Bitcoin Gold release
 * could signal it, so a witness v1 output there is spendable by anyone and `taproot` is refused.
 */
export class BitcoinGold extends AbstractBitcoinBlockchain {
  override readonly name = "bitcoingold";
  override readonly bip44 = BIP44.BITCOIN_GOLD;
  protected override readonly messagePreamble = "\u001DBitcoin Gold Signed Message:\n";

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError("Bitcoin Gold supports mainnet and testnet only");
    }
  }

  protected override get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  /**
   * Bitcoin's formats under Bitcoin Gold's version bytes and `btg` prefix, Taproot excluded.
   * @param keyPublic - Compressed or uncompressed SEC1 public key as hex
   * @param type - `legacy`, `p2sh`, `segwit` or `p2wsh`
   * @returns {string} The address, such as `GUHcigT74ggLsmbxHFTLfn2ZUNJUWiXaMG`
   */
  override getAddress(keyPublic: string, type = "legacy"): string {
    if (type === "taproot") {
      throw new RangeError("Bitcoin Gold never activated Taproot");
    }
    return super.getAddress(keyPublic, type);
  }

  /**
   * Base58 P2PKH (`G`) and P2SH (`A`), or SegWit v0 in bech32. Witness v1 is refused.
   * @param address - Candidate address
   * @returns {boolean} Whether the address can safely receive Bitcoin Gold on this network
   */
  override validateAddress(address: string): boolean {
    const lower = address.toLowerCase();
    if (lower.startsWith(this.params.prefixSegWitV1)) {
      return false;
    }
    if (lower.startsWith(this.params.hrpSegWit + "1")) {
      return super.validateAddress(address);
    }
    return (
      validateAddressLegacy(address, { bytesVersion: this.params.bytesVersionP2PKH }) ||
      validateAddressP2SH(address, { bytesVersion: this.params.bytesVersionP2SH })
    );
  }
}

export default BitcoinGold;
