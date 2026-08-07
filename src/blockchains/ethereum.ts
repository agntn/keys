import { AbstractEVMBlockchain } from "../utils/evm.ts";
import { BIP44 } from "../utils/bip44/index.ts";

/** Ethereum blockchain implementation. */
export class Ethereum extends AbstractEVMBlockchain {
  override readonly name = "ethereum";
  override readonly bip44 = BIP44.ETHEREUM;
}

export default Ethereum;
