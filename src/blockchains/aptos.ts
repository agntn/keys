import { sha3_256 } from "@agntn/hashes";
import { addSchemeByte, createPrefixedAddress, validateAddressHex } from "../utils/address.ts";
import { BIP44Change, getHardenedPath } from "../utils/bip44/paths.ts";
import { decodeKeyPublic } from "../utils/ed25519.ts";
import { AbstractEd25519Blockchain } from "../utils/ed25519-chains.ts";
import type { AddressType } from "../types.ts";

/** Aptos blockchain implementation. */
export class Aptos extends AbstractEd25519Blockchain {
  override readonly name = "aptos";
  override readonly bip44 = 637;

  /**
   * Petra and the Aptos SDK derive at `m/44'/637'/account'/change'/addressIndex'`, all five levels
   * hardened, which is what the SDK's `isValidHardenedPath` accepts.
   * @param account - Account index
   * @param change - Change branch
   * @param addressIndex - Address index
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(
    account = 0,
    change: number = BIP44Change.EXTERNAL,
    addressIndex = 0,
  ): string {
    return getHardenedPath(this.bip44, [account, change, addressIndex]);
  }

  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
    const dataToHash = addSchemeByte(decodeKeyPublic(keyPublic, "Aptos"), 0x00, false);
    return createPrefixedAddress(sha3_256(dataToHash));
  }

  override validateAddress(address: string): boolean {
    try {
      return (
        /^0x[0-9a-fA-F]$/.test(address) ||
        validateAddressHex(address, {
          prefix: "0x",
          length: 64,
          caseSensitive: false,
        })
      );
    } catch {
      return false;
    }
  }
}

export default Aptos;
