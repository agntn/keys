/** The key tools, declared once for MCP, Pi and OMP. The executors load on the first call. */

import { defineTool, type ToolDefinition } from "@agntn/tools";
import {
  BIP44_GENERATE_PARAMETERS,
  BIP44_PARSE_PARAMETERS,
  CONVERT_PUBLIC_KEY_PARAMETERS,
  DERIVE_BIP39_SEED_PARAMETERS,
  DERIVE_BRAINWALLET_PARAMETERS,
  DERIVE_ELECTRUM_WALLET_PARAMETERS,
  DERIVE_HD_WALLET_PARAMETERS,
  DERIVE_WALLET_PARAMETERS,
  DERIVE_XPUB_WALLET_PARAMETERS,
  ENCODE_BIP39_ENTROPY_PARAMETERS,
  GENERATE_MNEMONIC_PARAMETERS,
  GENERATE_WALLET_PARAMETERS,
  GET_ADDRESS_PARAMETERS,
  INSPECT_BIP38_PARAMETERS,
  INSPECT_MNEMONIC_PARAMETERS,
  LOOKUP_BIP39_INDICES_PARAMETERS,
  LOOKUP_BIP39_WORDS_PARAMETERS,
  RECOVER_MNEMONIC_WORD_PARAMETERS,
  SIGN_MESSAGE_PARAMETERS,
  VALIDATE_ADDRESS_PARAMETERS,
  VERIFY_MESSAGE_PARAMETERS,
  WIF_DECODE_PARAMETERS,
  WIF_ENCODE_PARAMETERS,
} from "./tool-schemas.ts";

let operations: Promise<typeof import("./tool-operations.ts")> | undefined;

/**
 * Loads the shared executors once.
 *
 * @returns {Promise<typeof import("./tool-operations.ts")>} The executors.
 */
function loadOperations(): Promise<typeof import("./tool-operations.ts")> {
  operations ??= import("./tool-operations.ts");
  return operations;
}

export const electrumWalletDeriveTool = defineTool({
  name: "keys_electrum_wallet_derive",
  title: "Derive Electrum Wallet",
  description:
    "Derive a Bitcoin public key and address from a complete Electrum standard or SegWit phrase and an exact path. Rejects legacy and 2FA seeds. Inputs enter the transcript; use only public or disposable material, never real wallet secrets.",
  effect: "read",
  input: DERIVE_ELECTRUM_WALLET_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).deriveElectrumWallet(
      params.mnemonic,
      params.path,
      params.passphrase,
      params.network,
    ),
});

export const brainwalletDeriveTool = defineTool({
  name: "keys_brainwallet_derive",
  title: "Derive Brainwallet",
  description:
    "Derive the Bitcoin public key and P2PKH address of a salted brainwallet from its full recipe: scrypt or PBKDF2 over the passphrase and salt, then SHA-256 of the output bytes or of their hex text. Given a target address, reports whether it matches. The private key is never returned; the passphrase enters the transcript, so use only public or disposable material.",
  effect: "read",
  input: DERIVE_BRAINWALLET_PARAMETERS,
  execute: async (params) => (await loadOperations()).deriveBrainwallet(params),
});

export const bip39SeedDeriveTool = defineTool({
  name: "keys_bip39_seed_derive",
  title: "Derive BIP39 Seed",
  description:
    "Derive a 64-byte BIP39 seed from a valid mnemonic and optional passphrase. Not a BIP32 master key. Inputs and seed enter the transcript; use only public or disposable material, never keys controlling real funds.",
  effect: "read",
  input: DERIVE_BIP39_SEED_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).deriveBip39Seed(params.mnemonic, params.passphrase, params.language),
});

export const secp256k1PublicKeyConvertTool = defineTool({
  name: "keys_secp256k1_public_key_convert",
  title: "Convert Public Key",
  description:
    "Convert a secp256k1 public key between compressed and uncompressed SEC1 hex. No private key required. Rejects hybrid and x-only encodings.",
  effect: "read",
  input: CONVERT_PUBLIC_KEY_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).convertPublicKey(params.publicKey, params.compressed),
});

export const wifEncodeTool = defineTool({
  name: "keys_wif_encode",
  title: "Encode WIF",
  description:
    "Encode a disposable private key as Bitcoin, Litecoin, Dash, Decred or Dogecoin ECDSA WIF. WIF is not encryption; inputs and results enter the transcript. Never use keys controlling real funds.",
  effect: "read",
  input: WIF_ENCODE_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).encodeWif(
      params.chain,
      params.privateKey,
      params.network,
      params.compressed,
    ),
});

export const wifDecodeTool = defineTool({
  name: "keys_wif_decode",
  title: "Decode WIF",
  description:
    "Decode public or disposable Bitcoin, Litecoin, Dash, Decred or Dogecoin ECDSA WIF into a hex private key and wallet options. Specify the expected chain and network; Bitcoin, Litecoin and Dash testnet WIFs overlap. Both forms enter the transcript.",
  effect: "read",
  input: WIF_DECODE_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).decodeWif(params.chain, params.wif, params.network),
});

export const bip38InspectTool = defineTool({
  name: "keys_bip38_inspect",
  title: "Inspect BIP38",
  description:
    "Read a BIP38 encrypted private key (6P...) without its passphrase: EC multiply or not, compression, lot and sequence, owner entropy, and the stored address hash. Given an address, reports whether its hash matches. Nothing is decrypted.",
  effect: "read",
  input: INSPECT_BIP38_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).inspectBip38(params.encrypted, params.address),
});

export const walletGenerateTool = defineTool({
  name: "keys_wallet_generate",
  title: "Generate Wallet",
  description:
    "Generate a disposable private key, public key, and address for a supported blockchain. The plaintext private key enters the transcript, so never use the result for real funds.",
  snippet: "Use to create a new wallet with keys and address for Bitcoin, Ethereum, Solana, etc.",
  guidelines: [
    "Provide a chain name (bitcoin, bitcoincash, bitcoingold, bitcoinsv, litecoin, dash, decred, dogecoin, zcash, ecash, ethereum, base, solana, stellar, aptos, tron, sui, cardano)",
    "Optionally specify network (mainnet/testnet) and address type",
    "Bitcoin and Litecoin address types: legacy, p2sh, segwit, p2wsh, taproot",
    "Bitcoin Gold address types: legacy, p2sh, segwit, p2wsh; it never activated taproot",
    "Decred supports legacy ECDSA P2PKH addresses only",
    "Bitcoin Cash supports legacy P2PKH only, written as CashAddr",
    "Bitcoin SV supports legacy P2PKH only, in base58 like Bitcoin",
    "Dash and Dogecoin support legacy P2PKH only; neither has SegWit",
    "Zcash supports transparent P2PKH only (t1); it writes no shielded or unified addresses",
    "eCash supports legacy P2PKH only, written as CashAddr under ecash:",
    "Cardano address types: payment, stake, enterprise",
    "Returns hex private key, hex public key, and address",
  ],
  effect: "write",
  idempotent: false,
  input: GENERATE_WALLET_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).generateWallet(params.chain, params.network, params.addressType),
});

export const walletDeriveTool = defineTool({
  name: "keys_wallet_derive",
  title: "Derive Wallet",
  description:
    "Derive a public key and address from an existing private key. Use only public or disposable keys because tool arguments enter the transcript.",
  snippet: "Use to derive the public key and address for an existing burner private key.",
  guidelines: [
    "Provide a chain name and private key as hex",
    "Optionally specify network and address type",
    "Bitcoin and Litecoin address types: legacy, p2sh, segwit, p2wsh, taproot",
    "Bitcoin Gold address types: legacy, p2sh, segwit, p2wsh",
    "For Sui, use ed25519 or secp256k1 as the address type",
  ],
  effect: "read",
  input: DERIVE_WALLET_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).deriveWallet(
      params.chain,
      params.privateKey,
      params.addressType,
      params.network,
    ),
});

export const hdWalletDeriveTool = defineTool({
  name: "keys_hd_wallet_derive",
  title: "Derive HD Wallet",
  description:
    "Derive a public key and address from BIP39 words and a path. Use allowInvalidChecksum for public puzzle candidates that fail only the checksum. Words are not repaired. Inputs enter the transcript, so use only public or disposable material.",
  snippet: "Use to see which address a public puzzle mnemonic reaches on a given derivation path.",
  guidelines: [
    "Provide a chain, a BIP39 mnemonic, and a full derivation path",
    "keys_hd_wallet_derive accepts an explicit BIP39 language; omission means english, not automatic detection",
    "Common paths: Bitcoin m/44'/0'/0'/0/0 (legacy), m/49'/0'/0'/0/0 (p2sh), m/84'/0'/0'/0/0 (segwit), m/86'/0'/0'/0/0 (taproot); Bitcoin Cash m/44'/145'/0'/0/0; Bitcoin Gold m/44'/156'/0'/0/0 or m/84'/156'/0'/0/0 (segwit); Bitcoin SV m/44'/236'/0'/0/0, or m/44'/0'/0'/0/0 for ElectrumSV; Dash m/44'/5'/0'/0/0; Dogecoin m/44'/3'/0'/0/0; Zcash m/44'/133'/0'/0/0; eCash m/44'/899'/0'/0/0, or m/44'/1899'/0'/0/0 for Cashtab and m/44'/145'/0'/0/0 for wallets from before the split; Ethereum m/44'/60'/0'/0/0; Solana m/44'/501'/0'/0'; Stellar m/44'/148'/0'; Aptos m/44'/637'/0'/0'/0'; Sui m/44'/784'/0'/0'/0'",
    "Bitcoin, Bitcoin Gold and Litecoin pick the address type from the path purpose unless addressType is set",
    "Optionally pass a BIP39 passphrase, a network, or an address type",
    "For public puzzles, allowInvalidChecksum=true accepts a checksum failure with a warning, but still requires words from the selected list and BIP39 word counts",
    "Never repair words just to satisfy the checksum. A bad checksum does not rule out a puzzle candidate",
    "Whitespace is collapsed and BIP39 NFKD normalization still applies, not raw text hashing",
    "Decred HD derivation is not supported because it differs from standard BIP32",
    "Cardano is not supported because CIP-1852 derives from entropy, not from the BIP39 seed",
    "Use only public or disposable mnemonics because tool arguments are saved in the transcript",
    "Returns the path, public key, and address, never the mnemonic or private key",
  ],
  effect: "read",
  input: DERIVE_HD_WALLET_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).deriveHdWallet(
      params.chain,
      params.mnemonic,
      params.path,
      params.passphrase,
      params.addressType,
      params.network,
      params.allowInvalidChecksum,
      params.language,
    ),
});

export const xpubWalletDeriveTool = defineTool({
  name: "keys_xpub_wallet_derive",
  title: "Derive Xpub Wallet",
  description:
    "Derive a watch-only public key and address from an extended public key and normal levels below it, such as m/0/0 for the first receiving address. secp256k1 BIP32 chains only; hardened levels and extended private keys are refused. A zpub writes SegWit and a ypub P2SH, but many wallets export a BIP84 or BIP49 account as xpub, so pass addressType segwit or p2sh for those. The key reveals every address of its account and enters the transcript.",
  snippet: "Use to list the addresses behind a published xpub, ypub or zpub without any secret.",
  guidelines: [
    "Provide a chain, the extended public key, and normal levels below it: m/0/i for receiving addresses, m/1/i for change",
    "secp256k1 BIP32 chains only; hardened levels and extended private keys are refused",
    "Bitcoin, Bitcoin Gold and Litecoin write SegWit for a zpub and P2SH for a ypub unless addressType is set",
    "Many wallets export a BIP84 or BIP49 account as xpub; pass addressType segwit or p2sh for those",
    "The key reveals every address of its account and is saved in the transcript",
  ],
  effect: "read",
  input: DERIVE_XPUB_WALLET_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).deriveXpubWallet(
      params.chain,
      params.extendedKey,
      params.path,
      params.addressType,
      params.network,
    ),
});

export const bip39GenerateTool = defineTool({
  name: "keys_bip39_generate",
  title: "Generate BIP39 Mnemonic",
  description:
    "Generate a random BIP39 mnemonic for tests or disposable wallets. The result enters the transcript. Never use it for real funds.",
  snippet: "Use when a test needs a fresh BIP39 mnemonic rather than supplied entropy.",
  guidelines: [
    "keys_bip39_generate accepts an explicit BIP39 language; omission means english, not automatic detection",
    "Choose 12, 15, 18, 21 or 24 words. Default: 12",
    "The result is saved in the transcript. Never use it for real funds",
  ],
  effect: "write",
  idempotent: false,
  input: GENERATE_MNEMONIC_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).generateBip39Mnemonic(params.words, params.language),
});

export const bip39InspectTool = defineTool({
  name: "keys_bip39_inspect",
  title: "Inspect Mnemonic",
  description:
    "Inspect BIP39 word count, dictionary membership and checksum separately. Recover entropy only when valid. A bad checksum does not rule out a puzzle candidate. The phrase enters the transcript, so use only public or disposable candidates.",
  snippet: "Use to check mnemonic candidates from public crypto puzzles.",
  guidelines: [
    "keys_bip39_inspect accepts an explicit BIP39 language; omission means english, not automatic detection",
    "Provide a BIP39 mnemonic",
    "Use only public or disposable candidates because tool arguments are saved in the transcript",
    "Returns wordCountValid, wordlistValid and checksumValid separately, with entropy only for valid mnemonics",
    "checksumValid is null when word count or dictionary membership prevents checking it",
    "A checksum failure is not proof that a puzzle candidate is wrong. keys_hd_wallet_derive accepts allowInvalidChecksum=true explicitly",
  ],
  effect: "read",
  input: INSPECT_MNEMONIC_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).inspectMnemonic(params.mnemonic, params.language),
});

export const bip39EntropyEncodeTool = defineTool({
  name: "keys_bip39_entropy_encode",
  title: "Encode BIP39 Entropy",
  description:
    "Encode 16, 20, 24, 28, or 32 bytes of hexadecimal entropy as a BIP39 mnemonic. Both forms enter the transcript, so use only public or disposable material.",
  snippet: "Use to turn public puzzle entropy into BIP39 words.",
  guidelines: [
    "keys_bip39_entropy_encode accepts an explicit BIP39 language; omission means english, not automatic detection",
    "Provide 16, 20, 24, 28, or 32 bytes as hexadecimal text",
    "Use only public or disposable entropy because tool arguments are saved in the transcript",
    "Returns the canonical mnemonic with its word count",
  ],
  effect: "read",
  input: ENCODE_BIP39_ENTROPY_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).encodeBip39Entropy(params.entropy, params.language),
});

export const bip39IndicesLookupTool = defineTool({
  name: "keys_bip39_indices_lookup",
  title: "Look Up BIP39 Indices",
  description:
    "Read words at numeric positions in an official BIP39 list, preserving the supplied order and index convention.",
  snippet: "Use to map public puzzle indices to BIP39 words.",
  guidelines: [
    "Provide up to 100 integer positions",
    "Set index base to match the puzzle convention. Default: 0",
    "Choose an official BIP39 language when the puzzle is not English",
    "Returns words in the same order as the supplied positions",
  ],
  effect: "read",
  input: LOOKUP_BIP39_INDICES_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).lookupBip39Indices(params.indices, params.language, params.indexBase),
});

export const bip39WordsLookupTool = defineTool({
  name: "keys_bip39_words_lookup",
  title: "Look Up BIP39 Words",
  description:
    "Check word membership in an official BIP39 list and return both zero-based and one-based indices.",
  snippet: "Use to map public puzzle words to their BIP39 indices.",
  guidelines: [
    "Provide up to 100 public or disposable words",
    "Choose an official BIP39 language when the puzzle is not English",
    "Returns both zero-based and one-based indices because puzzle conventions differ",
    "Words are matched case-insensitively with Unicode NFKD normalization",
  ],
  effect: "read",
  input: LOOKUP_BIP39_WORDS_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).lookupBip39Words(params.words, params.language),
});

export const bip39WordRecoverTool = defineTool({
  name: "keys_bip39_word_recover",
  title: "Recover Mnemonic Word",
  description:
    "List the BIP39 words that make the checksum valid for one missing position. Use this filter only when canonical BIP39 generation is established, not for puzzles that may have invalid checksums. Inputs enter the transcript, so use only public or disposable candidates.",
  snippet: "Use to narrow one missing word in a public BIP39 puzzle candidate.",
  guidelines: [
    "Replace exactly one word with ? in a mnemonic containing 12, 15, 18, 21, or 24 words",
    "keys_bip39_word_recover accepts an explicit BIP39 language; omission means english, not automatic detection",
    "Every other word must be in the selected list, so a typo is refused by position instead of returning no candidates",
    "Use checksum candidates only when the puzzle proves canonical BIP39 generation",
    "Use only public or disposable candidates because tool arguments are saved in the transcript",
    "Returns candidate words, not wallets or target matches",
  ],
  effect: "read",
  input: RECOVER_MNEMONIC_WORD_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).recoverMnemonicWord(params.mnemonic, params.language),
});

export const addressGetTool = defineTool({
  name: "keys_address_get",
  title: "Get Address",
  description: "Derive a blockchain address from a public key.",
  snippet: "Use to get an address from a public key for any supported blockchain.",
  guidelines: [
    "Provide chain, public key (hex), and optionally address type",
    "Returns the derived address",
  ],
  effect: "read",
  input: GET_ADDRESS_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).getAddress(
      params.chain,
      params.publicKey,
      params.addressType,
      params.network,
    ),
});

export const addressValidateTool = defineTool({
  name: "keys_address_validate",
  title: "Validate Address",
  description: "Check whether an address matches one blockchain's format rules.",
  snippet: "Use to verify an address is valid for a given blockchain.",
  guidelines: [
    "Provide chain and address to validate",
    "Returns true/false",
    "Zcash checks transparent t1, t3 and tex1 addresses; shielded and unified ones come back invalid",
  ],
  effect: "read",
  input: VALIDATE_ADDRESS_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).validateAddress(params.chain, params.address, params.network),
});

export const messageSignTool = defineTool({
  name: "keys_message_sign",
  title: "Sign Message",
  description:
    "Sign a message with a blockchain private key. Ask for recovered on Ethereum, base or tron when the signature goes to ethers, viem or TronWeb, which need v to recover the signer. The key, message, and signature enter the transcript, so use only public or disposable material.",
  snippet: "Use to sign a message with a private key for any supported blockchain.",
  guidelines: [
    "Provide chain, message text, and private key (hex)",
    "Returns the signature as hex string",
    "Bitcoin, Bitcoin Gold, Dash, Dogecoin, eCash, Litecoin and Zcash each use their own message preamble; Bitcoin Cash and Bitcoin SV sign with Bitcoin's",
    "Ethereum/Base use EIP-191 prefix",
    "Pass recovered on Ethereum, Base or TRON for 65-byte r||s||v, what ethers and TronWeb need",
  ],
  effect: "write",
  idempotent: true,
  input: SIGN_MESSAGE_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).signMessage(
      params.chain,
      params.message,
      params.privateKey,
      params.network,
      params.recovered,
    ),
});

export const messageVerifyTool = defineTool({
  name: "keys_message_verify",
  title: "Verify Message",
  description: "Verify a message signature against a blockchain public key.",
  snippet: "Use to verify that a signature is valid for a given message and public key.",
  guidelines: [
    "Provide chain, original message, signature (hex), and public key (hex)",
    "Returns true if signature is valid, false otherwise",
  ],
  effect: "read",
  input: VERIFY_MESSAGE_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).verifyMessage(
      params.chain,
      params.message,
      params.signature,
      params.publicKey,
      params.network,
    ),
});

export const bip44ParseTool = defineTool({
  name: "keys_bip44_parse",
  title: "Parse BIP44 Path",
  description:
    "Parse a BIP44 derivation path into its purpose, coin type, account, change branch and address index. Hardened levels take ' or h.",
  snippet:
    "Use to read the purpose, coin type, account, change branch and address index out of a BIP44 path.",
  guidelines: ["Hardened levels take ' or h, as in m/44'/0'/0'/0/0 or m/44h/0h/0h/0/0"],
  effect: "read",
  input: BIP44_PARSE_PARAMETERS,
  execute: async (params) => (await loadOperations()).parseBip44Path(params.path),
});

export const bip44GenerateTool = defineTool({
  name: "keys_bip44_generate",
  title: "Generate BIP44 Path",
  description:
    "Generate the derivation path a blockchain's wallets use for an account: BIP44 on secp256k1 chains, every level hardened on ed25519 chains (Stellar stops at the account, Solana at the change branch), CIP-1852 with roles on Cardano, and on Sui the scheme picks between the two.",
  snippet:
    "Use to generate the path a chain's wallets use: BIP44 on secp256k1 chains, every level hardened on ed25519 chains, CIP-1852 with roles on Cardano, the scheme picking the shape on Sui.",
  guidelines: [
    "account, change and addressIndex default to 0; addressType picks the Sui scheme, ed25519 by default",
    "Stellar paths end at the account and Solana paths at the change branch; a deeper index on those chains is an error",
    "Cardano reads change as the CIP-1852 role: 0 external, 1 internal, 2 staking, up to 5",
  ],
  effect: "read",
  input: BIP44_GENERATE_PARAMETERS,
  execute: async (params) =>
    (await loadOperations()).generateBip44Path(
      params.chain,
      params.account,
      params.change,
      params.addressIndex,
      params.addressType,
    ),
});

/** Every key tool in listing order. */
export const keysTools: readonly ToolDefinition[] = [
  electrumWalletDeriveTool,
  brainwalletDeriveTool,
  bip39SeedDeriveTool,
  secp256k1PublicKeyConvertTool,
  wifEncodeTool,
  wifDecodeTool,
  bip38InspectTool,
  walletGenerateTool,
  walletDeriveTool,
  hdWalletDeriveTool,
  xpubWalletDeriveTool,
  bip39GenerateTool,
  bip39InspectTool,
  bip39EntropyEncodeTool,
  bip39IndicesLookupTool,
  bip39WordsLookupTool,
  bip39WordRecoverTool,
  addressGetTool,
  addressValidateTool,
  messageSignTool,
  messageVerifyTool,
  bip44ParseTool,
  bip44GenerateTool,
];

/**
 * Shortens a message for a status line.
 * @param value - The message argument.
 * @returns {string} The message quoted, cut to 30 characters.
 */
function preview(value: unknown): string {
  const text = String(value);
  return text.length > 30 ? `"${text.slice(0, 30)}…"` : `"${text}"`;
}

/** What the Pi and OMP status lines show after a tool's title; a secret argument never appears. */
export const callSummaries: Readonly<
  Record<string, (args: Readonly<Record<string, unknown>>) => string>
> = {
  keys_wallet_generate: (args) => String(args.chain),
  keys_wallet_derive: (args) => String(args.chain),
  keys_hd_wallet_derive: (args) => `${String(args.chain)} ${String(args.path)}`,
  keys_xpub_wallet_derive: (args) => `${String(args.chain)} ${String(args.path)}`,
  keys_bip39_indices_lookup: (args) =>
    `${Array.isArray(args.indices) ? args.indices.length : 0} indices`,
  keys_bip39_words_lookup: (args) => `${Array.isArray(args.words) ? args.words.length : 0} words`,
  keys_address_get: (args) => String(args.chain),
  keys_address_validate: (args) => String(args.address),
  keys_message_sign: (args) => preview(args.message),
  keys_message_verify: (args) => preview(args.message),
  keys_bip44_parse: (args) => String(args.path),
  keys_bip44_generate: (args) => String(args.chain),
};
