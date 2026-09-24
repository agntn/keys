/** Pi extension exposing blockchain key, mnemonic, address, and signing tools. */
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import type * as KeysTools from "../../../dist/tool-operations.d.mts";
import {
  CONVERT_PUBLIC_KEY_PARAMETERS,
  WIF_ENCODE_PARAMETERS,
  WIF_DECODE_PARAMETERS,
  GENERATE_MNEMONIC_PARAMETERS,
  DERIVE_BIP39_SEED_PARAMETERS,
  DERIVE_ELECTRUM_WALLET_PARAMETERS,
  GENERATE_WALLET_PARAMETERS,
  DERIVE_WALLET_PARAMETERS,
  DERIVE_HD_WALLET_PARAMETERS,
  INSPECT_MNEMONIC_PARAMETERS,
  ENCODE_BIP39_ENTROPY_PARAMETERS,
  LOOKUP_BIP39_INDICES_PARAMETERS,
  LOOKUP_BIP39_WORDS_PARAMETERS,
  RECOVER_MNEMONIC_WORD_PARAMETERS,
  GET_ADDRESS_PARAMETERS,
  VALIDATE_ADDRESS_PARAMETERS,
  SIGN_MESSAGE_PARAMETERS,
  VERIFY_MESSAGE_PARAMETERS,
  BIP44_PATH_PARAMETERS,
} from "../../../src/tool-schemas.ts";

const sourceModuleUrl = new URL("../../../src/tool-operations.ts", import.meta.url);
const distributionModuleUrl = new URL("../../../dist/tool-operations.mjs", import.meta.url);
let toolOperationsPromise: Promise<typeof KeysTools> | undefined;

/**
 * Loads the executors shared with the MCP server.
 * @returns {Promise<typeof KeysTools>} Shared tool operations module.
 */
function loadToolOperations(): Promise<typeof KeysTools> {
  toolOperationsPromise ??= import(
    existsSync(fileURLToPath(sourceModuleUrl)) ? sourceModuleUrl.href : distributionModuleUrl.href
  ) as Promise<typeof KeysTools>;
  return toolOperationsPromise;
}

export default function keysExtension(pi: ExtensionAPI) {
  pi.registerTool({
    name: "keys_derive_electrum_wallet",
    label: "Derive Electrum Wallet",
    description:
      "Derive a Bitcoin public key and address from a complete Electrum standard or SegWit phrase and an exact path. Rejects legacy and 2FA seeds. Inputs enter the transcript; use only public or disposable material, never real wallet secrets.",
    parameters: DERIVE_ELECTRUM_WALLET_PARAMETERS,
    renderCall() {
      return new Text("Derive Electrum wallet", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).deriveElectrumWallet(
        params.mnemonic,
        params.path,
        params.passphrase,
        params.network,
      );
    },
  });
  pi.registerTool({
    name: "keys_derive_bip39_seed",
    label: "Derive BIP39 Seed",
    description:
      "Derive a 64-byte BIP39 seed from a valid mnemonic and optional passphrase. Not a BIP32 master key. Inputs and seed enter the transcript; use only public or disposable material, never keys controlling real funds.",
    parameters: DERIVE_BIP39_SEED_PARAMETERS,
    renderCall() {
      return new Text("Derive BIP39 seed", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).deriveBip39Seed(
        params.mnemonic,
        params.passphrase,
        params.language,
      );
    },
  });
  pi.registerTool({
    name: "keys_convert_public_key",
    label: "Convert Public Key",
    description:
      "Convert a secp256k1 public key between compressed and uncompressed SEC1 hex. No private key required. Rejects hybrid and x-only encodings.",
    parameters: CONVERT_PUBLIC_KEY_PARAMETERS,
    renderCall() {
      return new Text("Convert public key", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).convertPublicKey(params.publicKey, params.compressed);
    },
  });
  pi.registerTool({
    name: "keys_encode_wif",
    label: "Encode WIF",
    description:
      "Encode a disposable private key as Bitcoin, Litecoin or Decred ECDSA WIF. WIF is not encryption; inputs and results enter the transcript. Never use keys controlling real funds.",
    parameters: WIF_ENCODE_PARAMETERS,
    renderCall() {
      return new Text("🔐 Encode WIF", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).encodeWif(
        params.chain,
        params.privateKey,
        params.network,
        params.compressed,
      );
    },
  });
  pi.registerTool({
    name: "keys_decode_wif",
    label: "Decode WIF",
    description:
      "Decode public or disposable Bitcoin, Litecoin or Decred ECDSA WIF into a hex private key and wallet options. Specify the expected chain and network; Bitcoin and Litecoin testnet WIFs overlap. Both forms enter the transcript.",
    parameters: WIF_DECODE_PARAMETERS,
    renderCall() {
      return new Text("🔐 Decode WIF", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).decodeWif(params.chain, params.wif, params.network);
    },
  });
  // ─── generate_wallet ────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_generate_wallet",
    label: "Generate Wallet",
    description:
      "Generate a new wallet (private key, public key, and address) for any supported blockchain",
    promptSnippet:
      "Use to create a new wallet with keys and address for Bitcoin, Ethereum, Solana, etc.",
    promptGuidelines: [
      "Provide a chain name (bitcoin, bitcoincash, bitcoinsv, litecoin, decred, ethereum, base, solana, stellar, aptos, tron, sui, cardano)",
      "Optionally specify network (mainnet/testnet) and address type",
      "Bitcoin and Litecoin address types: legacy, p2sh, segwit, p2wsh, taproot",
      "Decred supports legacy ECDSA P2PKH addresses only",
      "Bitcoin Cash supports legacy P2PKH only, written as CashAddr",
      "Bitcoin SV supports legacy P2PKH only, in base58 like Bitcoin",
      "Cardano address types: payment, stake, enterprise",
      "Returns hex private key, hex public key, and address",
    ],
    parameters: GENERATE_WALLET_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`🔑 Generate wallet: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).generateWallet(
        params.chain,
        params.network,
        params.addressType,
      );
    },
  });

  pi.registerTool({
    name: "keys_derive_wallet",
    label: "Derive Wallet",
    description: "Derive a public key and address from an existing private key",
    promptSnippet: "Use to derive the public key and address for an existing burner private key.",
    promptGuidelines: [
      "Provide a chain name and private key as hex",
      "Optionally specify network and address type",
      "Bitcoin and Litecoin address types: legacy, p2sh, segwit, p2wsh, taproot",
      "For Sui, use ed25519 or secp256k1 as the address type",
    ],
    parameters: DERIVE_WALLET_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`🔐 Derive wallet: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).deriveWallet(
        params.chain,
        params.privateKey,
        params.addressType,
        params.network,
      );
    },
  });

  pi.registerTool({
    name: "keys_derive_hd_wallet",
    label: "Derive HD Wallet",
    description:
      "Derive a public key and address from English BIP39 words and a path, optionally accepting an invalid checksum for public puzzles",
    promptSnippet:
      "Use to see which address a public puzzle mnemonic reaches on a given derivation path.",
    promptGuidelines: [
      "Provide a chain, an English BIP39 mnemonic, and a full derivation path",
      "Common paths: Bitcoin m/44'/0'/0'/0/0 (legacy), m/49'/0'/0'/0/0 (p2sh), m/84'/0'/0'/0/0 (segwit), m/86'/0'/0'/0/0 (taproot); Bitcoin Cash m/44'/145'/0'/0/0; Bitcoin SV m/44'/236'/0'/0/0, or m/44'/0'/0'/0/0 for ElectrumSV; Ethereum m/44'/60'/0'/0/0; Solana m/44'/501'/0'/0'; Stellar m/44'/148'/0'; Aptos m/44'/637'/0'/0'/0'; Sui m/44'/784'/0'/0'/0'",
      "Bitcoin and Litecoin pick the address type from the path purpose unless addressType is set",
      "Optionally pass a BIP39 passphrase, a network, or an address type",
      "For public puzzles, allowInvalidChecksum=true accepts a checksum failure with a warning, but still requires English BIP39 words and word counts",
      "Never repair words just to satisfy the checksum. A bad checksum does not rule out a puzzle candidate",
      "Whitespace is collapsed and BIP39 NFKD normalization still applies, not raw text hashing",
      "Decred HD derivation is not supported because it differs from standard BIP32",
      "Cardano is not supported because CIP-1852 derives from entropy, not from the BIP39 seed",
      "Use only public or disposable mnemonics because tool arguments are saved in the transcript",
      "Returns the path, public key, and address, never the mnemonic or private key",
    ],
    parameters: DERIVE_HD_WALLET_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`🧩 Derive HD wallet: ${args.chain} ${args.path}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).deriveHdWallet(
        params.chain,
        params.mnemonic,
        params.path,
        params.passphrase,
        params.addressType,
        params.network,
        params.allowInvalidChecksum,
      );
    },
  });

  pi.registerTool({
    name: "keys_generate_mnemonic",
    label: "Generate BIP39 Mnemonic",
    description: "Generate a random BIP39 mnemonic for tests or disposable wallets",
    promptSnippet: "Use when a test needs a fresh BIP39 mnemonic rather than supplied entropy.",
    promptGuidelines: [
      "keys_generate_mnemonic accepts an explicit BIP39 language; omission means english, not automatic detection",
      "Choose 12, 15, 18, 21 or 24 words. Default: 12",
      "The result is saved in the transcript. Never use it for real funds",
    ],
    parameters: GENERATE_MNEMONIC_PARAMETERS,
    renderCall(_args, _theme) {
      return new Text("🧩 Generate disposable BIP39 mnemonic", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).generateBip39Mnemonic(params.words, params.language);
    },
  });

  pi.registerTool({
    name: "keys_inspect_mnemonic",
    label: "Inspect Mnemonic",
    description:
      "Inspect BIP39 word count, dictionary membership and checksum, with entropy only when valid",
    promptSnippet: "Use to check mnemonic candidates from public crypto puzzles.",
    promptGuidelines: [
      "keys_inspect_mnemonic accepts an explicit BIP39 language; omission means english, not automatic detection",
      "Provide a BIP39 mnemonic",
      "Use only public or disposable candidates because tool arguments are saved in the transcript",
      "Returns wordCountValid, wordlistValid and checksumValid separately, with entropy only for valid mnemonics",
      "checksumValid is null when word count or dictionary membership prevents checking it",
      "A checksum failure is not proof that a puzzle candidate is wrong. keys_derive_hd_wallet accepts allowInvalidChecksum=true explicitly",
    ],
    parameters: INSPECT_MNEMONIC_PARAMETERS,
    renderCall(_args, _theme) {
      return new Text("🧩 Inspect BIP39 mnemonic", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).inspectMnemonic(params.mnemonic, params.language);
    },
  });

  pi.registerTool({
    name: "keys_encode_bip39_entropy",
    label: "Encode BIP39 Entropy",
    description: "Encode hexadecimal entropy as a BIP39 mnemonic",
    promptSnippet: "Use to turn public puzzle entropy into BIP39 words.",
    promptGuidelines: [
      "keys_encode_bip39_entropy accepts an explicit BIP39 language; omission means english, not automatic detection",
      "Provide 16, 20, 24, 28, or 32 bytes as hexadecimal text",
      "Use only public or disposable entropy because tool arguments are saved in the transcript",
      "Returns the canonical mnemonic with its word count",
    ],
    parameters: ENCODE_BIP39_ENTROPY_PARAMETERS,
    renderCall(_args, _theme) {
      return new Text("🧩 Encode BIP39 entropy", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).encodeBip39Entropy(params.entropy, params.language);
    },
  });

  pi.registerTool({
    name: "keys_lookup_bip39_indices",
    label: "Lookup BIP39 Indices",
    description: "Read words at numeric positions in an official BIP39 list",
    promptSnippet: "Use to map public puzzle indices to BIP39 words.",
    promptGuidelines: [
      "Provide up to 100 integer positions",
      "Set index base to match the puzzle convention. Default: 0",
      "Choose an official BIP39 language when the puzzle is not English",
      "Returns words in the same order as the supplied positions",
    ],
    parameters: LOOKUP_BIP39_INDICES_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`🧩 Lookup ${args.indices.length} BIP39 indices`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).lookupBip39Indices(
        params.indices,
        params.language,
        params.indexBase,
      );
    },
  });

  pi.registerTool({
    name: "keys_lookup_bip39_words",
    label: "Lookup BIP39 Words",
    description: "Look up word membership and indices in an official BIP39 list",
    promptSnippet: "Use to map public puzzle words to their BIP39 indices.",
    promptGuidelines: [
      "Provide up to 100 public or disposable words",
      "Choose an official BIP39 language when the puzzle is not English",
      "Returns both zero-based and one-based indices because puzzle conventions differ",
      "Words are matched case-insensitively with Unicode NFKD normalization",
    ],
    parameters: LOOKUP_BIP39_WORDS_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`🧩 Lookup ${args.words.length} BIP39 words`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).lookupBip39Words(params.words, params.language);
    },
  });

  pi.registerTool({
    name: "keys_recover_mnemonic_word",
    label: "Recover Mnemonic Word",
    description: "List English BIP39 words that make the checksum valid for one missing position",
    promptSnippet: "Use to narrow one missing word in a public BIP39 puzzle candidate.",
    promptGuidelines: [
      "Replace exactly one word with ? in a mnemonic containing 12, 15, 18, 21, or 24 words",
      "Use checksum candidates only when the puzzle proves canonical BIP39 generation",
      "Use only public or disposable candidates because tool arguments are saved in the transcript",
      "Returns candidate words, not wallets or target matches",
    ],
    parameters: RECOVER_MNEMONIC_WORD_PARAMETERS,
    renderCall(_args, _theme) {
      return new Text("🧩 Recover BIP39 word", 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).recoverMnemonicWord(params.mnemonic);
    },
  });

  // ─── get_address ────────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_get_address",
    label: "Get Address",
    description: "Derive a blockchain address from a public key",
    promptSnippet: "Use to get an address from a public key for any supported blockchain.",
    promptGuidelines: [
      "Provide chain, public key (hex), and optionally address type",
      "Returns the derived address",
    ],
    parameters: GET_ADDRESS_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`📬 Get address: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).getAddress(
        params.chain,
        params.publicKey,
        params.addressType,
        params.network,
      );
    },
  });

  // ─── validate_address ───────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_validate_address",
    label: "Validate Address",
    description: "Check if a blockchain address is valid",
    promptSnippet: "Use to verify an address is valid for a given blockchain.",
    promptGuidelines: ["Provide chain and address to validate", "Returns true/false"],
    parameters: VALIDATE_ADDRESS_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`✅ Validate: ${args.address}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).validateAddress(
        params.chain,
        params.address,
        params.network,
      );
    },
  });

  // ─── sign_message ───────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_sign_message",
    label: "Sign Message",
    description: "Sign a message using a blockchain private key",
    promptSnippet: "Use to sign a message with a private key for any supported blockchain.",
    promptGuidelines: [
      "Provide chain, message text, and private key (hex)",
      "Returns the signature as hex string",
      "Bitcoin and Litecoin each use their own message preamble; Bitcoin Cash and Bitcoin SV sign with Bitcoin's",
      "Ethereum/Base use EIP-191 prefix",
      "Pass recovered on Ethereum, Base or TRON for 65-byte r||s||v, what ethers and TronWeb need",
    ],
    parameters: SIGN_MESSAGE_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`✍️ Sign: "${args.message.slice(0, 30)}…"`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).signMessage(
        params.chain,
        params.message,
        params.privateKey,
        params.network,
        params.recovered,
      );
    },
  });

  // ─── verify_message ─────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_verify_message",
    label: "Verify Message",
    description: "Verify a message signature using a blockchain public key",
    promptSnippet: "Use to verify that a signature is valid for a given message and public key.",
    promptGuidelines: [
      "Provide chain, original message, signature (hex), and public key (hex)",
      "Returns true if signature is valid, false otherwise",
    ],
    parameters: VERIFY_MESSAGE_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(`🔍 Verify: "${args.message.slice(0, 30)}…"`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).verifyMessage(
        params.chain,
        params.message,
        params.signature,
        params.publicKey,
        params.network,
      );
    },
  });

  // ─── bip44_path ─────────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_bip44_path",
    label: "BIP44 Path",
    description: "Get or parse a derivation path for a blockchain",
    promptSnippet:
      "Use to parse BIP44 paths or generate the path a chain's wallets use: BIP44 on secp256k1 chains, every level hardened on ed25519 chains, CIP-1852 with roles on Cardano, the scheme picking the shape on Sui.",
    promptGuidelines: [
      "Provide a path by itself to parse it, or a chain name to generate a path",
      "For generation only: account, change, addressIndex (defaults to 0), addressType (Sui scheme, ed25519 by default)",
      "Stellar paths end at the account and Solana paths at the change branch; a deeper index on those chains is an error",
      "Cardano reads change as the CIP-1852 role: 0 external, 1 internal, 2 staking, up to 5",
    ],
    parameters: BIP44_PATH_PARAMETERS,
    renderCall(args, _theme) {
      return new Text(args.path ? `🛤️ Parse: ${args.path}` : `🛤️ BIP44: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params) {
      return (await loadToolOperations()).bip44Path(
        params.chain,
        params.path,
        params.account,
        params.change,
        params.addressIndex,
        params.addressType,
      );
    },
  });
}
