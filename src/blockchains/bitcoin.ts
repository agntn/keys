import { AbstractBitcoinBlockchain } from "../utils/bitcoin.ts";

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

/** Bitcoin blockchain implementation. */
export class Bitcoin extends AbstractBitcoinBlockchain {
  override readonly name = "bitcoin";
  override readonly bip44 = 0;
  protected override readonly messagePreamble = "\u0018Bitcoin Signed Message:\n";

  protected override get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }
}

export default Bitcoin;
