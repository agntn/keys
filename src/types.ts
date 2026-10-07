/**
 * Cryptographic curve type
 */
export type Curve = "ed25519" | "secp256k1";

/**
 * Common address formats for various blockchains
 */
export type AddressFormat = string;

/**
 * Represents a pair of cryptographic keys
 */
export interface Keys {
  /**
   * Cryptographic keys
   */
  keys: {
    /**
     * Private key as a hex string
     */
    private: string;

    /**
     * Public key as a hex string
     */
    public: string;
  };
}

/**
 * Represents a complete wallet with keys and address
 */
export interface Wallet extends Keys {
  /**
   * Blockchain address derived from the public key
   */
  address: AddressFormat;
  /** Address type written, when the chain has more than one */
  addressType?: AddressType;
  /** Present when HD derivation explicitly accepts an invalid mnemonic checksum. */
  warnings?: readonly string[];
}

/**
 * Watch-only wallet derived from an extended public key: an address and its key, never a secret.
 */
export interface XpubWallet {
  keys: {
    /** Compressed public key as a hex string */
    public: string;
  };
  address: AddressFormat;
  /** Prefix of the extended key, such as `xpub` or `zpub` */
  prefix: string;
  /** Address type written, when the chain has more than one */
  addressType?: AddressType;
}

/**
 * Signer recovered from a message signature: its key and the address type the signature names.
 */
export interface MessageSigner {
  /** SEC1 public key as hex: as the Core header says, uncompressed from an `r||s||v` signature */
  publicKey: string;
  /** `legacy`, `p2sh` or `segwit` as the Core or BIP137 header says; absent on EVM and TRON */
  addressType?: AddressType;
}

/**
 * Bitcoin address types
 */
export type BitcoinAddressType = "legacy" | "p2sh" | "segwit" | "p2wsh" | "taproot";

/**
 * Cardano address types
 */
export type CardanoAddressType = "payment" | "stake" | "enterprise";

/**
 * All blockchain address types.
 * Known values are {@link BitcoinAddressType} and {@link CardanoAddressType};
 * any other chain-specific address type string is accepted as well.
 */
export type AddressType = string;

/**
 * Specific options for key derivation
 */
export interface KeyOptions {
  readonly compressed?: boolean;
  readonly encoding?: "hex" | "base64" | "binary";
  readonly scheme?: string; // For blockchain implementations that support multiple signature schemes
  // Extend with more specific options as needed
}

/**
 * Options for deriving a wallet from a BIP39 mnemonic.
 */
export interface HDWalletOptions extends KeyOptions {
  readonly passphrase?: string;
  /** Skip only the checksum. Words from the list and a BIP39 length stay required. Default: false. */
  readonly allowInvalidChecksum?: boolean;
  /** Word list of the mnemonic, from `loadWordlist` in `@agntn/keys/bip39`. Default: English. */
  readonly wordlist?: readonly string[];
}

/**
 * Options for a chain that fixes its own curve and digest but can still append the recovery byte.
 */
export interface RecoverableSigningOptions extends KeyOptions {
  /**
   * Append the recovery byte as Ethereum's `v`, so the signature becomes 65 bytes of `r||s||v`.
   * secp256k1 only, and only on chains whose native signature carries `v` that way:
   * Ethereum, Base and TRON. Default: false.
   */
  readonly recovered?: boolean;
}

/**
 * Options for message signing and verification.
 */
export interface SigningOptions extends RecoverableSigningOptions {
  readonly curve?: Curve;
  readonly hash?: boolean;
}

/**
 * Network type.
 * Known values are `"mainnet"` and `"testnet"`. A chain whose addresses depend on the
 * network throws on any other name; the rest ignore it.
 */
export type NetworkType = string;

/**
 * Common blockchain options interface
 */
export interface Options {
  readonly network?: NetworkType;
  /** Bech32 prefix of a Cosmos SDK chain, such as `osmo`; `cosmos` by default, other chains ignore it. */
  readonly prefix?: string;
  /** SS58 network prefix of a Polkadot address: 0 Polkadot, 2 Kusama, 42 any Substrate chain. */
  readonly ss58Prefix?: number;
  // Add more common options as needed
}

/**
 * Base blockchain implementation interface
 */
export interface BlockchainImplementation {
  /**
   * The name of the blockchain.
   */
  name: string;

  /**
   * The cryptographic curve(s) used by the blockchain.
   * Some blockchains (like SUI) support multiple curves.
   */
  curve: Curve | readonly Curve[];

  /**
   * The network type (mainnet, testnet, etc.).
   */
  network?: string;

  /**
   * The BIP44 coin type (SLIP-0044) used for derivation paths.
   * Each blockchain must have a registered index in SLIP-0044.
   */
  bip44: number;

  /**
   * Gets a public key derived from a private key
   */
  getKeyPublic: (keyPrivate: string, options?: KeyOptions) => string;

  /**
   * Gets a public address derived from a public key
   */
  getAddress: (keyPublic: string, type?: string) => string;

  /**
   * Validates a blockchain address
   */
  validateAddress?: (address: string) => boolean;

  /**
   * Signs a message using a private key
   * @param message - The message to sign (string or Uint8Array)
   * @param keyPrivate - The private key as a hex string
   * @param options - Optional parameters for signing
   * @returns The signature as a hex string
   */
  signMessage: (
    message: string | Uint8Array,
    keyPrivate: string,
    options?: SigningOptions,
  ) => string;

  /**
   * Verifies a message signature
   * @param message - The original message (string or Uint8Array)
   * @param signature - The signature as a hex string
   * @param keyPublic - The public key as a hex string
   * @param options - Optional parameters for verification
   * @returns Whether the signature is valid
   */
  verifyMessage: (
    message: string | Uint8Array,
    signature: string,
    keyPublic: string,
    options?: SigningOptions,
  ) => boolean;

  /**
   * Recovers the signer of a message signature: Core's base64 on the Bitcoin family and Decred,
   * `r||s||v` hex over the chain's message preamble on EVM chains and TRON
   * @param message - The signed message (string or Uint8Array)
   * @param signature - The signature in the chain's recoverable form
   * @returns The recovered public key and, on the Core family, the address type the header names
   */
  recoverMessageSigner?: (message: string | Uint8Array, signature: string) => MessageSigner;

  /**
   * Recovers the signer of an `r||s||v` signature over a 32-byte digest, as `ecrecover` does
   * @param digest - The signed digest, such as the output of `hashTypedData`
   * @param signature - 65 bytes of `r||s||v` as hex
   * @returns The recovered public key
   */
  recoverDigestSigner?: (digest: Uint8Array, signature: string) => MessageSigner;
}

/**
 * Unified blockchain interface that allows you to generate keys or addresses
 */
export interface Blockchain extends BlockchainImplementation {
  /**
   * Generates a cryptographically secure random private key
   * Common implementation for all blockchains - 32 bytes (256 bits)
   */
  generateKeyPrivate: () => string;

  /**
   * Generates a key pair (private and public keys)
   * This is a convenience function that combines generateKeyPrivate and getKeyPublic
   */
  generateKeys: (options?: KeyOptions) => Keys;

  /**
   * Derives a complete wallet from an existing private key.
   */
  deriveWallet?: (keyPrivate: string, options?: KeyOptions, addressType?: string) => Wallet;

  /**
   * Builds the derivation path the chain's wallets use for an account.
   */
  getDerivationPath?: (
    account?: number,
    change?: number,
    addressIndex?: number,
    options?: KeyOptions,
  ) => string;

  /**
   * Derives a complete wallet from a BIP39 mnemonic and derivation path.
   */
  deriveHDWallet?: (
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: string,
  ) => Wallet;

  /**
   * Derives a watch-only wallet from an extended public key and normal levels below it.
   */
  deriveXpubWallet?: (extendedKey: string, path: string, addressType?: string) => XpubWallet;

  /**
   * Derives a wallet from a chain's own seed string, such as an XRPL family seed (`s...`).
   */
  deriveSeedWallet?: (seed: string, options?: KeyOptions, addressType?: string) => Wallet;

  /**
   * Generates a complete wallet (private key, public key, and address)
   * This is a convenience function that combines generateKeys and getAddress
   */
  generateWallet: (options?: KeyOptions, addressType?: string) => Wallet;
}
