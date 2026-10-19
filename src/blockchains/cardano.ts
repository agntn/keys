import { blake2b } from "@agntn/hashes";
import { bech32 } from "@agntn/encodings/bech32";
import { getBIP32Path } from "../utils/bip44/paths.ts";
import { decodeKeyPublic } from "../utils/ed25519.ts";
import { AbstractEd25519Blockchain } from "../utils/ed25519-chains.ts";
import { readPathOptions } from "../utils/options.ts";
import type { CardanoAddressType, DerivationPathOptions, Options, Wallet } from "../types.ts";

const ADDRESS_TYPE = {
  BASE_PAYMENT: 0,
  ENTERPRISE_KEY: 6,
  REWARD_KEY: 14,
} as const;

/** `payment` is the base address, the default. */
const ADDRESS_TYPES: ReadonlySet<string> = new Set<CardanoAddressType>([
  "payment",
  "stake",
  "enterprise",
]);

/** CIP-1852 purpose; `44'` on Cardano marks a Byron wallet. */
const CIP1852_PURPOSE = 1852;

/** Highest CIP-1852 role: 0 external, 1 internal, 2 staking, 3 DRep, 4 and 5 committee keys. */
const CIP1852_MAX_ROLE = 5;

const NETWORK_PARAMS = {
  mainnet: {
    hrpAddress: "addr",
    hrpStake: "stake",
    networkId: 1,
  },
  testnet: {
    hrpAddress: "addr_test",
    hrpStake: "stake_test",
    networkId: 0,
  },
} as const;

/** Cardano blockchain implementation. */
export class Cardano extends AbstractEd25519Blockchain {
  override readonly name = "cardano";
  override readonly bip44 = 1815;

  constructor(options?: Options) {
    super(options);
    if (this.network !== "mainnet" && this.network !== "testnet") {
      throw new RangeError(
        "Cardano supports mainnet and testnet only; preprod and preview are testnet",
      );
    }
  }

  private get params() {
    return this.network === "testnet" ? NETWORK_PARAMS.testnet : NETWORK_PARAMS.mainnet;
  }

  /**
   * Shelley wallets sit at `m/1852'/1815'/account'/role/index` per CIP-1852, the change branch
   * being the role. Right for Cardano tooling even though `deriveHDWallet` here can't walk it.
   * @param options - Account, address index, and `change` as the CIP-1852 role: 0 external,
   * 1 internal, 2 staking, up to 5
   * @returns {string} The CIP-1852 path
   */
  override getDerivationPath(options?: DerivationPathOptions): string {
    const { account = 0, change: role = 0, addressIndex = 0 } = readPathOptions(options);
    return getBIP32Path(CIP1852_PURPOSE, {
      coinType: this.bip44,
      account,
      change: role,
      addressIndex,
      maxChange: CIP1852_MAX_ROLE,
    });
  }

  /** CIP-1852 roots come from the mnemonic entropy, not the BIP39 seed, so the shared SLIP-10 walk would give a wrong address. */
  override deriveHDWallet(): Wallet {
    throw new Error("Cardano CIP-1852 derivation is not supported");
  }

  private getKeyHash(keyPublic: string): Uint8Array {
    return blake2b(decodeKeyPublic(keyPublic, "Cardano"), 28);
  }

  private encodeAddress(
    payload: Uint8Array,
    prefix: { readonly hrp: string; readonly header: number },
  ): string {
    const { hrp, header } = prefix;
    const bytes = new Uint8Array(1 + payload.length);
    bytes[0] = header;
    bytes.set(payload, 1);
    return bech32.encode(hrp, bytes, Number.POSITIVE_INFINITY);
  }

  private header(addressType: number): number {
    return (addressType << 4) | this.params.networkId;
  }

  /**
   * Base address, with the key hash as both its payment and its stake part.
   * @returns {CardanoAddressType} `payment`
   */
  override get defaultAddressType(): CardanoAddressType {
    return "payment";
  }

  override getAddress(keyPublic: string, type: string = this.defaultAddressType): string {
    if (!ADDRESS_TYPES.has(type)) {
      throw new RangeError(
        `Address type ${JSON.stringify(type)} is not supported for cardano. Supported: ${[...ADDRESS_TYPES].join(", ")}`,
      );
    }
    const keyHash = this.getKeyHash(keyPublic);

    if (type === "stake") {
      return this.encodeAddress(keyHash, {
        hrp: this.params.hrpStake,
        header: this.header(ADDRESS_TYPE.REWARD_KEY),
      });
    }

    if (type === "enterprise") {
      return this.encodeAddress(keyHash, {
        hrp: this.params.hrpAddress,
        header: this.header(ADDRESS_TYPE.ENTERPRISE_KEY),
      });
    }

    const basePayload = new Uint8Array(keyHash.length * 2);
    basePayload.set(keyHash);
    basePayload.set(keyHash, keyHash.length);
    return this.encodeAddress(basePayload, {
      hrp: this.params.hrpAddress,
      header: this.header(ADDRESS_TYPE.BASE_PAYMENT),
    });
  }

  override validateAddress(address: string): boolean {
    try {
      const { prefix, bytes } = bech32.decode(address, Number.POSITIVE_INFINITY);
      const headerByte = bytes[0];
      if (headerByte === undefined) return false;

      const expectedNetwork = this.params.networkId;
      const addressNetwork = headerByte & 0x0f;
      const addressType = headerByte >> 4;
      if (addressNetwork !== expectedNetwork) return false;

      if (prefix === this.params.hrpStake) {
        return addressType === ADDRESS_TYPE.REWARD_KEY && bytes.length === 29;
      }
      if (prefix !== this.params.hrpAddress) {
        return false;
      }
      if (addressType === ADDRESS_TYPE.BASE_PAYMENT) return bytes.length === 57;
      if (addressType === ADDRESS_TYPE.ENTERPRISE_KEY) return bytes.length === 29;
      return false;
    } catch {
      return false;
    }
  }
}

export default Cardano;
