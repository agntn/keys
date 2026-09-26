import { BIP44 } from "../utils/bip44/index.ts";
import { AbstractBitcoinP2PKHBlockchain } from "../utils/bitcoin.ts";
import type { Options } from "../types.ts";

/** Dash Core v23.1.8 src/chainparams.cpp; devnet and regtest share the testnet bytes. */
const NETWORK_PARAMS = {
  mainnet: { bytesVersionP2PKH: 0x4c, bytesVersionP2SH: 0x10 },
  testnet: { bytesVersionP2PKH: 0x8c, bytesVersionP2SH: 0x13 },
} as const;

/**
 * Dash P2PKH wallets in base58, such as `Xywgfc872nn5CKtpATCoAjZCc4v96pJczy`, and Core message
 * signatures under the preamble Dash kept from its DarkCoin days. Dash never adopted SegWit, so
 * it has no bech32 and `legacy` is the only type it writes. Validation accepts P2PKH (`X`,
 * testnet `y`) and P2SH (`7`, testnet `8` and `9`).
 */
export class Dash extends AbstractBitcoinP2PKHBlockchain {
  override readonly name = "dash";
  override readonly bip44 = BIP44.DASH;
  protected override readonly messagePreamble = "\u0019DarkCoin Signed Message:\n";

  constructor(options?: Options) {
    super(options, "Dash", NETWORK_PARAMS);
  }
}

export default Dash;
