import { AbstractEVMBlockchain } from "../utils/evm.ts";
import { BIP44 } from "../utils/bip44/index.ts";

/** Base blockchain implementation. */
export class Base extends AbstractEVMBlockchain {
  override readonly name = "base";
  override readonly bip44 = BIP44.ETHEREUM;
}

export default Base;
