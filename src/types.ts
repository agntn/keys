import type { PathLevels } from "./utils/bip44/paths.ts";

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
 * Options of a wallet written from a key or a seed.
 */
export interface WalletOptions extends KeyOptions {
  /** Address type to write, on chains with more than one. Default: the chain's own */
  readonly addressType?: AddressType;
}

/**
 * Options for deriving a wallet from a BIP39 mnemonic.
 */
export interface HDWalletOptions extends WalletOptions {
  /** Derivation path, such as `m/44'/0'/0'/0/0`. */
  readonly path: string;
  readonly passphrase?: string;
  /** Skip only the checksum. Words from the list and a BIP39 length stay required. Default: false. */
  readonly allowInvalidChecksum?: boolean;
  /** Word list of the mnemonic, from `loadWordlist` in `@agntn/keys/bip39`. Default: English. */
  readonly wordlist?: readonly string[];
  /** Ian Coleman's lengths too, warned when not BIP39's own; Polkadot refuses. Default: false */
  readonly coleman?: boolean;
}

/** Options for deriving a wallet from an Electrum seed. */
export interface ElectrumWalletOptions extends WalletOptions {
  /** Derivation path, `m/0/0` for standard seeds and `m/0'/0/0` for SegWit ones. */
  readonly path: string;
}

/** Options for deriving a watch-only wallet from an extended public key. */
export interface XpubWalletOptions {
  /** Normal levels below the key, such as `m/0/5`. */
  readonly path: string;
  /** Address type that wins over the one the prefix stands for. */
  readonly addressType?: AddressType;
}

/** The account, branch and address a derivation path points at, each from 0. */
export interface DerivationPathOptions extends KeyOptions, PathLevels {}

/** Standard or SegWit Electrum seed, as `deriveSeed` in `@agntn/keys/electrum` returns it. */
export interface ElectrumSeed {
  readonly scheme: "electrum";
  readonly seedType: "standard" | "segwit";
  /** 64 bytes of PBKDF2 output, not a master private key. */
  readonly seed: Uint8Array;
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
  /** Curve of the key. Default: `secp256k1`. */
  readonly curve?: Curve;
  /** On secp256k1, `false` skips SHA-256 and signs the bytes as a ready digest. Default: true. */
  readonly hash?: boolean;
  /** Which Monero key signs, as `monero-wallet-cli sign --spend` or `--view`. Default: `spend`. */
  readonly signingKey?: MoneroSigningKey;
  /** Monero only: account of the subaddress that signs, as `sign <account>,<index>`. Default: 0. */
  readonly account?: number;
  /** Monero only: address within that account; 0/0 is the standard one. Default: 0. */
  readonly addressIndex?: number;
}

/** Options for signing a message: the key, then how the chain signs with it. */
export type SignMessageOptions<T extends KeyOptions = SigningOptions> = T & {
  /** The private key as hex. */
  readonly privateKey: string;
};

/** Options for verifying a message: the signature, the key that should have made it, and how. */
export type VerifyMessageOptions<T extends KeyOptions = SigningOptions> = T & {
  /** The signature as the chain writes it. */
  readonly signature: string;
  /** The public key as hex. */
  readonly publicKey: string;
};

/** The two Monero keys a SigV2 signature can come from. */
export type MoneroSigningKey = "spend" | "view";

/**
 * Network type.
 * Known values are `"mainnet"` and `"testnet"`, and `"stagenet"` on Monero. A chain whose
 * addresses depend on the network throws on any other name; the rest ignore it.
 */
export type NetworkType = string;

/**
 * Common blockchain options interface
 */
export interface Options {
  readonly network?: NetworkType;
  /** Bech32 prefix of a Cosmos SDK chain, such as `osmo`; `cosmos` by default, other chains ignore it. */
  readonly prefix?: string;
  /** SLIP-0044 coin type of a Cosmos SDK path; the registry's for the prefix, else 118. */
  readonly coinType?: number;
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
   * @param options - The private key as a hex string, then how to sign
   * @returns The signature as a hex string
   */
  signMessage: (message: string | Uint8Array, options: SignMessageOptions) => string;

  /**
   * Verifies a message signature
   * @param message - The original message (string or Uint8Array)
   * @param options - The signature and the public key as hex, then how they were made
   * @returns Whether the signature is valid
   */
  verifyMessage: (message: string | Uint8Array, options: VerifyMessageOptions) => boolean;

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
  deriveWallet?: (keyPrivate: string, options?: WalletOptions) => Wallet;

  /**
   * Builds the derivation path the chain's wallets use for an account.
   */
  getDerivationPath?: (options?: DerivationPathOptions) => string;

  /**
   * Derives a complete wallet from a BIP39 mnemonic and derivation path.
   */
  deriveHDWallet?: (mnemonic: string, options: HDWalletOptions) => Wallet;

  /** Derives a complete wallet from an Electrum seed and derivation path. */
  deriveElectrumWallet?: (seed: ElectrumSeed, options: ElectrumWalletOptions) => Wallet;

  /**
   * Derives a watch-only wallet from an extended public key and normal levels below it.
   */
  deriveXpubWallet?: (extendedKey: string, options: XpubWalletOptions) => XpubWallet;

  /**
   * Derives a wallet from a chain's own seed string, such as an XRPL family seed (`s...`).
   */
  deriveSeedWallet?: (seed: string, options?: WalletOptions) => Wallet;

  /**
   * Generates a complete wallet (private key, public key, and address)
   * This is a convenience function that combines generateKeys and getAddress
   */
  generateWallet: (options?: WalletOptions) => Wallet;
}
