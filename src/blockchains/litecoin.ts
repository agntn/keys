import { AbstractBitcoinBlockchain } from "../utils/bitcoin.ts";
import { validateAddressLegacy, validateAddressP2SH } from "../utils/address.ts";
import { BIP44 } from "../utils/bip44/index.ts";
import type { Options } from "../types.ts";

/** Litecoin Core v0.21.4 src/chainparams.cpp, including the newer P2SH prefixes. */
const NETWORK_PARAMS = {
  mainnet: {
    hrpSegWit: "ltc",
    prefixSegWitV1: "ltc1p",
    bytesVersionP2PKH: 0x30,
    bytesVersionP2SH: 0x32,
  },
  testnet: {
    hrpSegWit: "tltc",
    prefixSegWitV1: "tltc1p",
    bytesVersionP2PKH: 0x6f,
    bytesVersionP2SH: 0x3a,
  },
} as const;

/** Litecoin transparent addresses and message signatures. MWEB is not supported. */
export class Litecoin extends AbstractBitcoinBlockchain {
  override readonly name = "litecoin";
  override readonly bip44 = BIP44.LITECOIN;
  protected override readonly messagePreamble = "\u0019Litecoin Signed Message:\n";

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError("Litecoin supports mainnet and testnet only");
    }
  }

  protected override get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  override validateAddress(address: string): boolean {
    if (address.toLowerCase().startsWith(this.params.hrpSegWit + "1")) {
      return super.validateAddress(address);
    }
    return (
      validateAddressLegacy(address, { bytesVersion: this.params.bytesVersionP2PKH }) ||
      validateAddressP2SH(address, { bytesVersion: this.params.bytesVersionP2SH }) ||
      validateAddressP2SH(address, {
        bytesVersion: this.network === "testnet" ? 0xc4 : 0x05,
      })
    );
  }
}

export default Litecoin;
