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
 * All blockchain address types
 */
export type AddressType = BitcoinAddressType | CardanoAddressType | string;

/**
 * Specific options for key derivation
 */
export interface KeyOptions {
  compressed?: boolean;
  encoding?: "hex" | "base64" | "binary";
  scheme?: string; // For blockchain implementations that support multiple signature schemes
  curve?: Curve;
  hash?: boolean;
  // Extend with more specific options as needed
}

/**
 * Network type
 */
export type NetworkType = "mainnet" | "testnet" | string;

/**
 * Common blockchain options interface
 */
export interface Options {
  network?: NetworkType;
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
  signMessage: (message: string | Uint8Array, keyPrivate: string, options?: KeyOptions) => string;

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
    options?: KeyOptions,
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
   * Generates a complete wallet (private key, public key, and address)
   * This is a convenience function that combines generateKeys and getAddress
   */
  generateWallet: (options?: KeyOptions, addressType?: string) => Wallet;
}
