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
}

/**
 * Options for message signing and verification.
 */
export interface SigningOptions extends KeyOptions {
  readonly curve?: Curve;
  readonly hash?: boolean;
}

/**
 * Network type.
 * Known values are `"mainnet"` and `"testnet"`;
 * any other chain-specific network name is accepted as well.
 */
export type NetworkType = string;

/**
 * Common blockchain options interface
 */
export interface Options {
  readonly network?: NetworkType;
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
   * Derives a complete wallet from a BIP39 mnemonic and derivation path.
   */
  deriveHDWallet?: (
    mnemonic: string,
    path: string,
    options?: HDWalletOptions,
    addressType?: string,
  ) => Wallet;

  /**
   * Generates a complete wallet (private key, public key, and address)
   * This is a convenience function that combines generateKeys and getAddress
   */
  generateWallet: (options?: KeyOptions, addressType?: string) => Wallet;
}
