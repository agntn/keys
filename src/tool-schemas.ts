import { Type } from "@agntn/tools";
import {
  TOOL_CHAINS,
  TOOL_ADDRESS_TYPES,
  SUI_ADDRESS_TYPES,
  MAX_BIP39_LOOKUP_ITEMS,
  BIP39_ENTROPY_SCHEMA_PATTERN,
  BIP39_WORD_SCHEMA_PATTERN,
  DERIVATION_PATH_SCHEMA_PATTERN,
  XPUB_PATH_SCHEMA_PATTERN,
  PRIVATE_KEY_SCHEMA_PATTERN,
  PUBLIC_KEY_SCHEMA_PATTERN,
  CORE_SIGNATURE_SCHEMA_PATTERN,
  MESSAGE_SIGNATURE_SCHEMA_PATTERN,
  TOOL_WIF_CHAINS,
  TOOL_NETWORKS,
  TOOL_MNEMONIC_WORD_COUNTS,
  MAX_BIP39_SEED_INPUT_LENGTH,
  MAX_BIP38_ADDRESS_LENGTH,
  MAX_BIP38_PASSPHRASE_LENGTH,
  MAX_KEYSTORE_LENGTH,
  MAX_KEYSTORE_PASSWORD_LENGTH,
  MAX_ADDRESS_LENGTH,
  MAX_BRAINWALLET_INPUT_LENGTH,
  MAX_SCRYPT_BLOCKS,
  KDF_COST_LIMITS,
} from "./tool-parameters.ts";
import { BIP39_LANGUAGES } from "./utils/bip39/languages.ts";

/** The default list is English. Language is never inferred. */
export const BIP39_LANGUAGE_PARAMETER = Type.Optional(
  Type.String({
    enum: BIP39_LANGUAGES,
    minLength: 1,
    maxLength: 19,
    description: "Official BIP39 language key. Default: english",
  }),
);

/** Shared MCP and Pi schema for generating a disposable mnemonic. */
export const GENERATE_MNEMONIC_PARAMETERS = Type.Object(
  {
    language: BIP39_LANGUAGE_PARAMETER,
    words: Type.Optional(
      Type.Integer({
        enum: TOOL_MNEMONIC_WORD_COUNTS,
        description: "Mnemonic word count: 12, 15, 18, 21 or 24. Default: 12",
      }),
    ),
  },
  { additionalProperties: false },
);

const wifContext = {
  chain: Type.String({
    enum: TOOL_WIF_CHAINS,
    description: `Native WIF chain: ${TOOL_WIF_CHAINS.join(", ")}`,
  }),
  network: Type.Optional(
    Type.String({
      enum: TOOL_NETWORKS,
      description: "Expected network. Default: mainnet; Decred testnet means testnet3",
    }),
  ),
};

/** Shared MCP and Pi schema for exporting a disposable private key. */
export const WIF_ENCODE_PARAMETERS = Type.Object(
  {
    ...wifContext,
    privateKey: Type.String({
      minLength: 64,
      maxLength: 64,
      pattern: PRIVATE_KEY_SCHEMA_PATTERN,
      description: "Disposable private key as 64 hex characters without 0x",
    }),
    compressed: Type.Optional(
      Type.Boolean({ description: "Compressed public key. Default: true; Decred requires true" }),
    ),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for reading a disposable WIF. */
export const WIF_DECODE_PARAMETERS = Type.Object(
  {
    ...wifContext,
    wif: Type.String({
      minLength: 1,
      maxLength: 54,
      pattern: "^[1-9A-HJ-NP-Za-km-z]+$",
      description: "Public or disposable WIF string",
    }),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for reading a BIP38 key without its passphrase. */
export const INSPECT_BIP38_PARAMETERS = Type.Object(
  {
    encrypted: Type.String({
      minLength: 1,
      maxLength: 64,
      pattern: "^[1-9A-HJ-NP-Za-km-z]+$",
      description: "BIP38 encrypted private key, 58 characters starting with 6P",
    }),
    address: Type.Optional(
      Type.String({
        minLength: 1,
        maxLength: MAX_BIP38_ADDRESS_LENGTH,
        description: "Address to compare with the address hash stored in the key",
      }),
    ),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for opening a BIP38 key with its passphrase. */
export const DECRYPT_BIP38_PARAMETERS = Type.Object(
  {
    encrypted: Type.String({
      minLength: 1,
      maxLength: 64,
      pattern: "^[1-9A-HJ-NP-Za-km-z]+$",
      description: "BIP38 encrypted private key, 58 characters starting with 6P",
    }),
    passphrase: Type.String({
      maxLength: MAX_BIP38_PASSPHRASE_LENGTH,
      description: "Public or disposable passphrase, NFC normalized and hashed as UTF-8",
    }),
    revealKey: Type.Optional(
      Type.Boolean({
        description:
          "Also return the mainnet WIF when the passphrase is right, so it enters the transcript. Default: false",
      }),
    ),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for opening a Web3 Secret Storage keystore. */
export const DECRYPT_STORE_PARAMETERS = Type.Object(
  {
    keystore: Type.String({
      minLength: 2,
      maxLength: MAX_KEYSTORE_LENGTH,
      description:
        "Version 3 keystore JSON (UTC--... file) from geth, ethers, Foundry or MyEtherWallet, as text",
    }),
    password: Type.String({
      maxLength: MAX_KEYSTORE_PASSWORD_LENGTH,
      description: "Public or disposable password, hashed as UTF-8 without normalization",
    }),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for SEC1 public key conversion. */
export const CONVERT_PUBLIC_KEY_PARAMETERS = Type.Object(
  {
    publicKey: Type.String({
      minLength: 66,
      maxLength: 130,
      pattern: "^(?:0[23][0-9A-Fa-f]{64}|04[0-9A-Fa-f]{128})$",
      description: "Compressed or uncompressed SEC1 secp256k1 public key as hex, without 0x",
    }),
    compressed: Type.Optional(
      Type.Boolean({ description: "Output compressed SEC1 encoding. Default: true" }),
    ),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi schema for deriving a disposable BIP39 seed. */
export const DERIVE_BIP39_SEED_PARAMETERS = Type.Object(
  {
    mnemonic: Type.String({
      minLength: 1,
      maxLength: MAX_BIP39_SEED_INPUT_LENGTH,
      pattern: "\\S",
      description: "Public or disposable BIP39 mnemonic; whitespace is collapsed",
    }),
    passphrase: Type.Optional(
      Type.String({
        maxLength: MAX_BIP39_SEED_INPUT_LENGTH,
        description: "BIP39 passphrase. Default: empty. NFKD normalized, never trimmed",
      }),
    ),
    language: BIP39_LANGUAGE_PARAMETER,
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi parameters for an explicitly selected Electrum wallet. */
export const DERIVE_ELECTRUM_WALLET_PARAMETERS = Type.Object(
  {
    mnemonic: Type.String({
      minLength: 1,
      maxLength: 4096,
      pattern: "\\S+",
      description:
        "Complete public or disposable Electrum phrase: standard, SegWit, or an old (pre-2.0) seed as words or 32 or 64 hex digits",
    }),
    path: Type.Optional(
      Type.String({
        minLength: 1,
        maxLength: 256,
        pattern: DERIVATION_PATH_SCHEMA_PATTERN,
        description:
          "Exact BIP32 path, required for standard and SegWit seeds; no path search or inference. Old seeds take change and index instead",
      }),
    ),
    passphrase: Type.Optional(
      Type.String({
        maxLength: 4096,
        description:
          "Electrum seed extension. Normalized like the phrase; default empty. Old seeds take none",
      }),
    ),
    change: Type.Optional(
      Type.Integer({
        minimum: 0,
        maximum: 1,
        description: "Old seeds only: 0 for receiving, 1 for change. Default: 0",
      }),
    ),
    index: Type.Optional(
      Type.Integer({
        minimum: 0,
        maximum: 2147483647,
        description: "Old seeds only: address index on that chain. Default: 0",
      }),
    ),
    network: Type.Optional(
      Type.String({ enum: TOOL_NETWORKS, description: "Bitcoin network. Default: mainnet" }),
    ),
  },
  { additionalProperties: false },
);

/** Shared MCP and Pi parameters for a salted or plain brainwallet with an explicit recipe. */
export const DERIVE_BRAINWALLET_PARAMETERS = Type.Object(
  {
    passphrase: Type.String({
      maxLength: MAX_BRAINWALLET_INPUT_LENGTH,
      description: "Public or disposable passphrase, hashed as UTF-8, never trimmed or normalized",
    }),
    salt: Type.Optional(
      Type.String({
        maxLength: MAX_BRAINWALLET_INPUT_LENGTH,
        description:
          "scrypt and pbkdf2 only, required there: salt, read as saltEncoding says. Empty for none",
      }),
    ),
    saltEncoding: Type.Optional(
      Type.String({
        enum: ["utf8", "hex"],
        description:
          "scrypt and pbkdf2 only, required there: utf8 hashes the salt text, hex decodes it to bytes first",
      }),
    ),
    kdf: Type.String({
      enum: ["scrypt", "pbkdf2", "sha256", "keccak256"],
      description:
        "scrypt takes N, r and p; pbkdf2 takes iterations and digest. sha256 (brainwallet.org) and keccak256 hash the passphrase straight into the key, with no salt",
    }),
    N: Type.Optional(
      Type.Integer({
        minimum: 2,
        maximum: KDF_COST_LIMITS.N,
        description: `scrypt only, required there: CPU and memory cost, a power of 2. N * r at most ${MAX_SCRYPT_BLOCKS}`,
      }),
    ),
    r: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: KDF_COST_LIMITS.r,
        description: "scrypt only, required there: block size",
      }),
    ),
    p: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: KDF_COST_LIMITS.p,
        description: "scrypt only, required there: parallelization",
      }),
    ),
    iterations: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: KDF_COST_LIMITS.iterations,
        description:
          "pbkdf2: required iteration count. sha256 and keccak256: how many times the digest runs, default 1",
      }),
    ),
    digest: Type.Optional(
      Type.String({
        enum: ["sha256", "sha512"],
        description: "pbkdf2 only, required there: hash under HMAC",
      }),
    ),
    keyLength: Type.Optional(
      Type.Integer({
        minimum: 1,
        maximum: KDF_COST_LIMITS.keyLength,
        description: "KDF output length in bytes. Default: 32",
      }),
    ),
    hashed: Type.Optional(
      Type.String({
        enum: ["bytes", "hex"],
        description:
          "scrypt and pbkdf2 only, required there: what SHA-256 reads after the KDF to make the key, its raw bytes or their lowercase hex as text (brainwallet.io)",
      }),
    ),
    chain: Type.Optional(
      Type.String({
        enum: ["bitcoin", "ethereum"],
        description: "Chain of the address: bitcoin writes P2PKH. Default: bitcoin",
      }),
    ),
    compressed: Type.Optional(
      Type.Boolean({
        description:
          "bitcoin only, required there: compressed SEC1 public key for the address. Old brainwallets write uncompressed",
      }),
    ),
    network: Type.Optional(
      Type.String({ enum: TOOL_NETWORKS, description: "Network. Default: mainnet" }),
    ),
    target: Type.Optional(
      Type.String({
        minLength: 1,
        maxLength: MAX_ADDRESS_LENGTH,
        description: "Address to compare with the derived one",
      }),
    ),
  },
  { additionalProperties: false },
);

const chainArgument = Type.String({
  description: `Blockchain name (${TOOL_CHAINS.join(", ")})`,
  minLength: 1,
  maxLength: 32,
});

const networkArgument = Type.Optional(
  Type.String({
    description: "Network (mainnet or testnet). Default: mainnet",
    enum: TOOL_NETWORKS,
  }),
);

const addressTypeArgument = Type.Optional(
  Type.String({
    description: "Chain-specific address type, such as segwit, taproot, stake, or secp256k1",
    enum: TOOL_ADDRESS_TYPES,
  }),
);

export const GENERATE_WALLET_PARAMETERS = Type.Object(
  { chain: chainArgument, network: networkArgument, addressType: addressTypeArgument },
  { additionalProperties: false },
);

export const DERIVE_WALLET_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    privateKey: Type.String({
      pattern: PRIVATE_KEY_SCHEMA_PATTERN,
      description: "Private key as 64 hex characters without 0x",
    }),
    addressType: addressTypeArgument,
    network: networkArgument,
    compressed: Type.Optional(
      Type.Boolean({
        description:
          "secp256k1 only: SEC1 form of the public key, which a legacy address hashes. Old wallets and brainwallets wrote uncompressed. ethereum, base and tron hash the uncompressed key and refuse true, sui refuses false. Default: true",
      }),
    ),
  },
  { additionalProperties: false },
);

export const DERIVE_HD_WALLET_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    mnemonic: Type.Optional(
      Type.String({
        description: "BIP39 mnemonic in the selected language. Pass this or entropy, not both",
        minLength: 1,
        pattern: "\\S",
      }),
    ),
    entropy: Type.Optional(
      Type.String({
        description:
          "BIP39 entropy as 32, 40, 48, 56, or 64 hexadecimal characters, encoded into words of the selected language. Pass this or mnemonic, not both",
        pattern: BIP39_ENTROPY_SCHEMA_PATTERN,
      }),
    ),
    language: BIP39_LANGUAGE_PARAMETER,
    path: Type.String({
      description: "Derivation path such as m/84'/0'/0'/0/0",
      pattern: DERIVATION_PATH_SCHEMA_PATTERN,
    }),
    passphrase: Type.Optional(Type.String({ description: "BIP39 passphrase. Default: empty" })),
    allowInvalidChecksum: Type.Optional(
      Type.Boolean({
        description:
          "Accept an invalid checksum with a warning. Words from the selected list and BIP39 word counts are still required. Default: false",
      }),
    ),
    addressType: addressTypeArgument,
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const DERIVE_XPUB_WALLET_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    extendedKey: Type.String({
      description:
        "Extended public key: xpub, or tpub on testnet; Bitcoin, Bitcoin Gold and Litecoin also take ypub and zpub (upub and vpub), Litecoin Ltub and Mtub (ttub)",
      minLength: 1,
      maxLength: 128,
      pattern: "^[1-9A-HJ-NP-Za-km-z]+$",
    }),
    path: Type.String({
      description: "Normal levels below the key, such as m/0/0 for the first receiving address",
      maxLength: 256,
      pattern: XPUB_PATH_SCHEMA_PATTERN,
    }),
    addressType: addressTypeArgument,
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const INSPECT_MNEMONIC_PARAMETERS = Type.Object(
  {
    language: BIP39_LANGUAGE_PARAMETER,
    mnemonic: Type.String({
      description: "BIP39 mnemonic candidate",
      minLength: 1,
      pattern: "\\S",
    }),
  },
  { additionalProperties: false },
);

export const ENCODE_BIP39_ENTROPY_PARAMETERS = Type.Object(
  {
    language: BIP39_LANGUAGE_PARAMETER,
    entropy: Type.String({
      description: "BIP39 entropy as 32, 40, 48, 56, or 64 hexadecimal characters",
      pattern: BIP39_ENTROPY_SCHEMA_PATTERN,
    }),
  },
  { additionalProperties: false },
);

export const LOOKUP_BIP39_INDICES_PARAMETERS = Type.Object(
  {
    indices: Type.Array(
      Type.Integer({
        description: "A position from 0 to 2047 for base 0, or 1 to 2048 for base 1",
        minimum: 0,
        maximum: 2048,
      }),
      { minItems: 1, maxItems: MAX_BIP39_LOOKUP_ITEMS },
    ),
    language: BIP39_LANGUAGE_PARAMETER,
    indexBase: Type.Optional(
      Type.Integer({
        enum: [0, 1],
        description: "Whether positions start at 0 or 1. Default: 0",
      }),
    ),
  },
  { additionalProperties: false },
);

export const LOOKUP_BIP39_WORDS_PARAMETERS = Type.Object(
  {
    words: Type.Array(
      Type.String({
        description: "A word to check against the selected BIP39 list",
        minLength: 1,
        maxLength: 32,
        pattern: BIP39_WORD_SCHEMA_PATTERN,
      }),
      { minItems: 1, maxItems: MAX_BIP39_LOOKUP_ITEMS },
    ),
    language: BIP39_LANGUAGE_PARAMETER,
  },
  { additionalProperties: false },
);

export const RECOVER_MNEMONIC_WORD_PARAMETERS = Type.Object(
  {
    mnemonic: Type.String({
      description: "BIP39 mnemonic template in the selected language containing one ? placeholder",
      minLength: 1,
      pattern: "\\?",
    }),
    language: BIP39_LANGUAGE_PARAMETER,
  },
  { additionalProperties: false },
);

export const GET_ADDRESS_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    publicKey: Type.String({
      pattern: PUBLIC_KEY_SCHEMA_PATTERN,
      description:
        "Public key as hex without 0x: 32-byte ed25519, or compressed or uncompressed SEC1 secp256k1",
    }),
    addressType: addressTypeArgument,
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const VALIDATE_ADDRESS_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    address: Type.String({
      description: "Address to validate",
      minLength: 1,
      maxLength: MAX_ADDRESS_LENGTH,
    }),
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const SIGN_MESSAGE_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    message: Type.String({ description: "Message to sign" }),
    privateKey: Type.String({
      pattern: PRIVATE_KEY_SCHEMA_PATTERN,
      description: "Private key as 64 hex characters without 0x",
    }),
    network: networkArgument,
    recovered: Type.Optional(
      Type.Boolean({
        description:
          "Return the recoverable form: 65-byte r||s||v hex on ethereum, base and tron, the form ethers, viem and TronWeb read; base64 of a header byte, r and s on the Bitcoin family and decred, the form signmessage prints. Default: false",
      }),
    ),
  },
  { additionalProperties: false },
);

export const VERIFY_MESSAGE_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    message: Type.String({ description: "Original message" }),
    signature: Type.String({
      pattern: MESSAGE_SIGNATURE_SCHEMA_PATTERN,
      description:
        "Signature as hex without 0x: 64 bytes, or 65 with the recovery byte. The Bitcoin family and decred also take signmessage's base64",
    }),
    publicKey: Type.String({
      pattern: PUBLIC_KEY_SCHEMA_PATTERN,
      description:
        "Public key as hex without 0x: 32-byte ed25519, or compressed or uncompressed SEC1 secp256k1",
    }),
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const RECOVER_MESSAGE_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    message: Type.String({ description: "Message that was signed" }),
    signature: Type.String({
      pattern: CORE_SIGNATURE_SCHEMA_PATTERN,
      description:
        "Base64 signature as bitcoin-cli signmessage, Electrum and Sparrow print it: a header byte, then r and s",
    }),
    address: Type.Optional(
      Type.String({
        description: "Address the signer should hold, compared with the recovered key",
        minLength: 1,
        maxLength: MAX_ADDRESS_LENGTH,
      }),
    ),
    network: networkArgument,
  },
  { additionalProperties: false },
);

export const BIP44_PARSE_PARAMETERS = Type.Object(
  {
    path: Type.String({
      description: "BIP44 path to parse, such as m/44'/0'/0'/0/0",
      minLength: 1,
    }),
  },
  { additionalProperties: false },
);

export const BIP44_GENERATE_PARAMETERS = Type.Object(
  {
    chain: chainArgument,
    account: Type.Optional(
      Type.Integer({
        description: "Account index. Default: 0",
        minimum: 0,
      }),
    ),
    change: Type.Optional(
      Type.Integer({
        description:
          "Change branch: 0 for external, 1 for internal; on Cardano the CIP-1852 role, up to 5. Default: 0",
        minimum: 0,
      }),
    ),
    addressIndex: Type.Optional(
      Type.Integer({
        description: "Address index. Default: 0",
        minimum: 0,
      }),
    ),
    addressType: Type.Optional(
      Type.String({
        description: "Signature scheme on Sui, ed25519 or secp256k1. Default: ed25519",
        enum: SUI_ADDRESS_TYPES,
      }),
    ),
  },
  { additionalProperties: false },
);
