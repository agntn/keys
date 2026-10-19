import { sha3_256 } from "@agntn/hashes";
import { addSchemeByte, createPrefixedAddress, validateAddressHex } from "../utils/address.ts";
import { BIP44Change, getHardenedPath } from "../utils/bip44/paths.ts";
import { decodeKeyPublic } from "../utils/ed25519.ts";
import { AbstractEd25519Blockchain } from "../utils/ed25519-chains.ts";
import { readPathOptions } from "../utils/options.ts";
import type { AddressType, DerivationPathOptions } from "../types.ts";

/** Aptos blockchain implementation. */
export class Aptos extends AbstractEd25519Blockchain {
  override readonly name = "aptos";
  override readonly bip44 = 637;

  /**
   * Petra and the Aptos SDK derive at `m/44'/637'/account'/change'/addressIndex'`, all five levels
   * hardened, which is what the SDK's `isValidHardenedPath` accepts.
   * @param options - Account, change branch and address index
   * @returns {string} The SLIP-10 path
   */
  override getDerivationPath(options?: DerivationPathOptions): string {
    const {
      account = 0,
      change = BIP44Change.EXTERNAL,
      addressIndex = 0,
    } = readPathOptions(options);
    return getHardenedPath(this.bip44, [account, change, addressIndex]);
  }

  override getAddress(keyPublic: string, type?: AddressType): string {
    this.refuseAddressType(type);
    const dataToHash = addSchemeByte(decodeKeyPublic(keyPublic, "Aptos"), {
      schemeByte: 0x00,
      prepend: false,
    });
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
