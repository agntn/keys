import { BIP44 } from "../utils/bip44/index.ts";
import { AbstractBitcoinP2PKHBlockchain } from "../utils/bitcoin.ts";
import type { Options } from "../types.ts";

/** Dogecoin Core v1.14.9 src/chainparams.cpp; regtest borrows Bitcoin's bytes and is not offered. */
const NETWORK_PARAMS = {
  mainnet: { bytesVersionP2PKH: 0x1e, bytesVersionP2SH: 0x16 },
  testnet: { bytesVersionP2PKH: 0x71, bytesVersionP2SH: 0xc4 },
} as const;

/**
 * Dogecoin P2PKH wallets in base58, such as `DSpgzjPyfQB6ZzeSbMWpaZiTTxGf2oBCs4`, and Core
 * message signatures under its own preamble. Dogecoin never activated SegWit, so it has no
 * bech32 and `legacy` is the only type it writes. Validation accepts P2PKH (`D`) and P2SH
 * (`9` and `A`).
 */
export class Dogecoin extends AbstractBitcoinP2PKHBlockchain {
  override readonly name = "dogecoin";
  override readonly bip44 = BIP44.DOGECOIN;
  protected override readonly messagePreamble = "\u0019Dogecoin Signed Message:\n";

  constructor(options?: Options) {
    super(options, "Dogecoin", NETWORK_PARAMS);
  }
}

export default Dogecoin;
