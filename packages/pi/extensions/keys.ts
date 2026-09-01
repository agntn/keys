/**
 * Pi extension exposing blockchain key, mnemonic, address, and signing tools.
 */
import type { AgentToolResult, ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { Type } from "typebox";

/**
 * Lazy-load the library.
 *
 * @returns {Promise<typeof import("@agntn/keys")>} The `@agntn/keys` module (dist build, or the source entry as dev fallback).
 */
async function loadLib() {
  const mod = await import("@agntn/keys").catch(() => {
    // Runtime fallback for dev before dist is built (same package source).
    return import("../../../src/index.ts");
  });
  return mod as typeof import("@agntn/keys");
}

async function loadBIP39() {
  return import("@agntn/keys/bip39").catch(() => import("../../../src/utils/bip39/index.ts"));
}

const CHAINS = [
  "bitcoin",
  "ethereum",
  "base",
  "solana",
  "aptos",
  "tron",
  "sui",
  "cardano",
] as const;

type ChainName = (typeof CHAINS)[number];

/**
 * Format a blockchain's curve declaration for display.
 *
 * @param curve - A single curve name or the list of supported curves
 * @returns {string} The curve name, or a comma-separated list of curve names
 */
function formatCurve(curve: string | readonly string[]): string {
  return typeof curve === "string" ? curve : curve.join(", ");
}

async function getBlockchain(chain: string, network?: string) {
  const lib = await loadLib();
  const key = chain.toLowerCase() as ChainName;
  if (!Object.hasOwn(lib.blockchains, key)) {
    throw new Error(`Unknown chain "${chain}". Supported: ${CHAINS.join(", ")}`);
  }
  const loadBlockchain = lib.blockchains[key];
  const blockchain = await loadBlockchain({ network: network ?? "mainnet" })();
  return lib.useBlockchain(blockchain);
}

export default function keysExtension(pi: ExtensionAPI) {
  // ─── generate_wallet ────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_generate_wallet",
    label: "Generate Wallet",
    description:
      "Generate a new wallet (private key, public key, and address) for any supported blockchain",
    promptSnippet:
      "Use to create a new wallet with keys and address for Bitcoin, Ethereum, Solana, etc.",
    promptGuidelines: [
      "Provide a chain name (bitcoin, ethereum, base, solana, aptos, tron, sui, cardano)",
      "Optionally specify network (mainnet/testnet) and address type",
      "Bitcoin address types: legacy, p2sh, segwit, p2wsh, taproot",
      "Cardano address types: payment, stake, enterprise",
      "Returns hex private key, hex public key, and address",
    ],
    parameters: Type.Object({
      chain: Type.String({
        description: `Blockchain name (${CHAINS.join(", ")})`,
      }),
      network: Type.Optional(
        Type.String({
          description: "Network (mainnet or testnet). Default: mainnet",
        }),
      ),
      addressType: Type.Optional(
        Type.String({
          description: "Address type (e.g. segwit for Bitcoin, stake for Cardano)",
        }),
      ),
    }),
    renderCall(args, _theme) {
      return new Text(`🔑 Generate wallet: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const wallet = blockchain.generateWallet({}, params.addressType);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [
              `Chain: ${blockchain.name} (${blockchain.network ?? "mainnet"})`,
              `Curve: ${formatCurve(blockchain.curve)}`,
              `BIP44: ${blockchain.bip44}`,
              `Private key: ${wallet.keys.private}`,
              `Public key: ${wallet.keys.public}`,
              `Address: ${wallet.address}`,
            ].join("\n"),
          },
        ],
      };
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
      "Bitcoin address types: legacy, p2sh, segwit, p2wsh, taproot",
      "For Sui, use ed25519 or secp256k1 as the address type",
    ],
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      privateKey: Type.String({ description: "Private key as hex string" }),
      addressType: Type.Optional(
        Type.String({ description: "Address type (e.g. segwit, taproot, secp256k1)" }),
      ),
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`🔐 Derive wallet: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const wallet = blockchain.deriveWallet(params.privateKey, {}, params.addressType);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [`Public key: ${wallet.keys.public}`, `Address: ${wallet.address}`].join("\n"),
          },
        ],
      };
    },
  });

  pi.registerTool({
    name: "keys_inspect_mnemonic",
    label: "Inspect Mnemonic",
    description: "Validate an English BIP39 mnemonic and recover its entropy",
    promptSnippet: "Use to check mnemonic candidates from public crypto puzzles.",
    promptGuidelines: [
      "Provide an English BIP39 mnemonic",
      "Use only public or disposable candidates because tool arguments are saved in the transcript",
      "Returns checksum validity, word count, and entropy for valid mnemonics",
    ],
    parameters: Type.Object({
      mnemonic: Type.String({
        minLength: 1,
        pattern: "\\S",
        description: "English BIP39 mnemonic candidate",
      }),
    }),
    renderCall(_args, _theme) {
      return new Text("🧩 Inspect BIP39 mnemonic", 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const bip39 = await loadBIP39();
      const normalizedMnemonic = params.mnemonic.trim().replaceAll(/\s+/gu, " ");
      const wordCount = normalizedMnemonic === "" ? 0 : normalizedMnemonic.split(" ").length;
      const valid = bip39.validateMnemonic(normalizedMnemonic);
      const lines = [`Valid BIP39: ${valid ? "yes" : "no"}`, `Words: ${wordCount}`];

      if (valid) {
        const entropy = bip39.mnemonicToEntropy(normalizedMnemonic);
        lines.push(`Entropy: ${Buffer.from(entropy).toString("hex")}`);
      }

      return {
        details: undefined,
        content: [{ type: "text", text: lines.join("\n") }],
      };
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
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      publicKey: Type.String({ description: "Public key as hex string" }),
      addressType: Type.Optional(
        Type.String({ description: "Address type (e.g. segwit, taproot)" }),
      ),
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`📬 Get address: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const address = blockchain.getAddress(params.publicKey, params.addressType);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: `Address: ${address}`,
          },
        ],
      };
    },
  });

  // ─── validate_address ───────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_validate_address",
    label: "Validate Address",
    description: "Check if a blockchain address is valid",
    promptSnippet: "Use to verify an address is valid for a given blockchain.",
    promptGuidelines: ["Provide chain and address to validate", "Returns true/false"],
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      address: Type.String({ description: "Address to validate" }),
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`✅ Validate: ${args.address}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const valid = blockchain.validateAddress(params.address);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: valid
              ? `✅ ${params.address} is a valid ${params.chain} address`
              : `❌ ${params.address} is NOT a valid ${params.chain} address`,
          },
        ],
      };
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
      "Bitcoin uses its own message preamble format",
      "Ethereum/Base use EIP-191 prefix",
    ],
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      message: Type.String({ description: "Message to sign" }),
      privateKey: Type.String({ description: "Private key as hex string" }),
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`✍️ Sign: "${args.message.slice(0, 30)}…"`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const signature = blockchain.signMessage(params.message, params.privateKey);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: `Signature: ${signature}`,
          },
        ],
      };
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
    parameters: Type.Object({
      chain: Type.String({ description: "Blockchain name" }),
      message: Type.String({ description: "Original message" }),
      signature: Type.String({ description: "Signature as hex string" }),
      publicKey: Type.String({ description: "Public key as hex string" }),
      network: Type.Optional(Type.String({ description: "Network (mainnet/testnet)" })),
    }),
    renderCall(args, _theme) {
      return new Text(`🔍 Verify: "${args.message.slice(0, 30)}…"`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const blockchain = await getBlockchain(params.chain, params.network);
      const valid = blockchain.verifyMessage(params.message, params.signature, params.publicKey);
      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: valid ? "✅ Signature is valid" : "❌ Signature is INVALID",
          },
        ],
      };
    },
  });

  // ─── bip44_path ─────────────────────────────────────────────────────────
  pi.registerTool({
    name: "keys_bip44_path",
    label: "BIP44 Path",
    description: "Get or parse a BIP44 derivation path for a blockchain",
    promptSnippet:
      "Use to generate or parse BIP44 derivation paths (m/44'/coin'/account'/change/index).",
    promptGuidelines: [
      "Provide either a chain name to generate a path, or a path string to parse it",
      "Optional: account, change, addressIndex (defaults to 0)",
    ],
    parameters: Type.Object({
      chain: Type.Optional(
        Type.String({
          description: "Blockchain name (to generate a path)",
        }),
      ),
      path: Type.Optional(
        Type.String({
          description: "BIP44 path string to parse (e.g. m/44'/0'/0'/0/0)",
        }),
      ),
      account: Type.Optional(Type.Number({ description: "Account index (default 0)" })),
      change: Type.Optional(
        Type.Number({
          description: "Change level (0=external, 1=internal, default 0)",
        }),
      ),
      addressIndex: Type.Optional(Type.Number({ description: "Address index (default 0)" })),
    }),
    renderCall(args, _theme) {
      return new Text(args.path ? `🛤️ Parse: ${args.path}` : `🛤️ BIP44: ${args.chain}`, 0, 0);
    },
    async execute(_toolCallId, params): Promise<AgentToolResult<undefined>> {
      const lib = await loadLib();

      // Parse mode
      if (params.path) {
        const parsed = lib.parseBIP44Path(params.path);
        if (!parsed) {
          return {
            details: undefined,
            content: [
              {
                type: "text",
                text: `❌ Invalid BIP44 path: ${params.path}`,
              },
            ],
          };
        }
        return {
          details: undefined,
          content: [
            {
              type: "text",
              text: [
                `Path: ${params.path}`,
                `Purpose: ${parsed.purpose}`,
                `Coin type: ${parsed.coinType}`,
                `Account: ${parsed.account}`,
                `Change: ${parsed.change}`,
                `Address index: ${parsed.addressIndex}`,
              ].join("\n"),
            },
          ],
        };
      }

      // Generate mode
      if (!params.chain) {
        return {
          details: undefined,
          content: [
            {
              type: "text",
              text: "❌ Provide either a chain name or a path string",
            },
          ],
        };
      }

      const key = params.chain.toLowerCase() as ChainName;
      if (!Object.hasOwn(lib.blockchains, key)) {
        return {
          details: undefined,
          content: [
            {
              type: "text",
              text: `Unknown chain "${params.chain}". Supported: ${CHAINS.join(", ")}`,
            },
          ],
        };
      }

      const loadBlockchain = lib.blockchains[key];
      const blockchain = await loadBlockchain()();
      const path = lib.getBlockchainPath(
        blockchain,
        params.account ?? 0,
        params.change ?? 0,
        params.addressIndex ?? 0,
      );

      return {
        details: undefined,
        content: [
          {
            type: "text",
            text: [
              `Chain: ${blockchain.name} (BIP44 coin type: ${blockchain.bip44})`,
              `Path: ${path}`,
            ].join("\n"),
          },
        ],
      };
    },
  });
}
