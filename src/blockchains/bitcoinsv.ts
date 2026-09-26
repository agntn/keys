import { BIP44 } from "../utils/bip44/index.ts";
import { AbstractBitcoinP2PKHBlockchain } from "../utils/bitcoin.ts";
import type { Options } from "../types.ts";

/**
 * P2PKH version bytes from Bitcoin SV src/chainparams.cpp; testnet, STN and regtest share one.
 * P2SH has none: it decodes in the node, but a payment to it fails consensus since Genesis.
 */
const NETWORK_PARAMS = {
  mainnet: { bytesVersionP2PKH: 0x00 },
  testnet: { bytesVersionP2PKH: 0x6f },
} as const;

/**
 * Bitcoin SV P2PKH wallets in base58. Keys, version bytes and signed messages are Bitcoin's,
 * preamble included, so a key gives the same `1` address on both chains, such as
 * `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`. There is no SegWit, and since Genesis the node rejects
 * any transaction paying to P2SH (`bad-txns-vout-p2sh`), so `legacy` is the only address type
 * and validation refuses P2SH along with bech32 and CashAddr.
 */
export class BitcoinSV extends AbstractBitcoinP2PKHBlockchain {
  override readonly name = "bitcoinsv";
  override readonly bip44 = BIP44.BITCOIN_SV;
  protected override readonly messagePreamble = "\u0018Bitcoin Signed Message:\n";

  constructor(options?: Options) {
    super(options, "Bitcoin SV", NETWORK_PARAMS);
  }
}

export default BitcoinSV;
