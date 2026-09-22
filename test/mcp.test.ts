import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  bip39TestVectors,
  electrumVectors,
  ethereumTestVectors,
  publicKeyEncodingVector,
  litecoinTestVectors,
  decredTestVectors,
  stellarTestVectors,
  wifTestVectors,
  localizedMnemonicVectors,
  invalidChecksumPuzzle,
} from "./fixtures.ts";
import { createMcpServer } from "../src/mcp.ts";

const TOOL_NAMES = [
  "keys_derive_electrum_wallet",
  "keys_derive_bip39_seed",
  "keys_convert_public_key",
  "keys_encode_wif",
  "keys_decode_wif",
  "keys_generate_wallet",
  "keys_derive_wallet",
  "keys_derive_hd_wallet",
  "keys_generate_mnemonic",
  "keys_inspect_mnemonic",
  "keys_encode_bip39_entropy",
  "keys_lookup_bip39_indices",
  "keys_lookup_bip39_words",
  "keys_recover_mnemonic_word",
  "keys_get_address",
  "keys_validate_address",
  "keys_sign_message",
  "keys_verify_message",
  "keys_bip44_path",
] as const;

const openConnections: Array<{ close(): Promise<void> }> = [];

async function connectTestClient(): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer();
  const client = new Client({ name: "keys-test", version: "1.0.0" });
  openConnections.push(client, server);
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

function text(content: unknown): string {
  return (content as Array<{ type: string; text?: string }>)
    .map((item) => (item.type === "text" ? (item.text ?? "") : ""))
    .join("");
}

afterEach(async () => {
  await Promise.all(openConnections.splice(0).map((connection) => connection.close()));
});

describe("keys MCP server", () => {
  it.each([1, 12, 24, 100])("labels both indices once for a %i-word lookup", async (size) => {
    const client = await connectTestClient();
    const words = Array.from({ length: size }, (_, index) => (index % 2 === 0 ? "ZOO" : "eleven"));
    const result = await client.callTool({
      name: "keys_lookup_bip39_words",
      arguments: { words },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content).split("\n")).toEqual([
      "Language: english",
      "Indices: zero-based, one-based",
      ...Array.from({ length: size }, (_, index) =>
        index % 2 === 0 ? "zoo: 2047, 2048" : "eleven: not in BIP39",
      ),
    ]);
  });

  it("derives an explicitly selected Electrum wallet through MCP", async () => {
    const client = await connectTestClient();
    const vector = electrumVectors[0];
    const result = await client.callTool({
      name: "keys_derive_electrum_wallet",
      arguments: { mnemonic: vector.mnemonic, path: vector.path },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content)).toContain(vector.address);
    expect(text(result.content)).toContain("Scheme: electrum");
    expect(text(result.content)).not.toContain(vector.mnemonic);
    for (const args of [
      { mnemonic: "secret-phrase", path: vector.path },
      { mnemonic: vector.mnemonic, path: vector.path, passphrase: false },
    ]) {
      const failed = await client.callTool({
        name: "keys_derive_electrum_wallet",
        arguments: args,
      });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).not.toContain("secret-phrase");
    }
  });
  it("derives a BIP39 seed through MCP", async () => {
    const client = await connectTestClient();
    const result = await client.callTool({
      name: "keys_derive_bip39_seed",
      arguments: { mnemonic: bip39TestVectors.mnemonic },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content)).toContain(bip39TestVectors.seed);
  });

  it("rejects invalid seed inputs without echoing secrets through MCP", async () => {
    const client = await connectTestClient();
    for (const args of [
      { mnemonic: "abandon ".repeat(12).trim() },
      { mnemonic: "unknown-secret" },
      { mnemonic: bip39TestVectors.mnemonic, passphrase: false },
      { mnemonic: bip39TestVectors.mnemonic, language: "unknown-secret" },
      { mnemonic: bip39TestVectors.mnemonic, extra: "unknown-secret" },
    ]) {
      const result = await client.callTool({ name: "keys_derive_bip39_seed", arguments: args });
      expect(result.isError).toBe(true);
      expect(text(result.content)).not.toContain("unknown-secret");
    }
  });

  it("converts public keys through MCP and rejects invalid points", async () => {
    const client = await connectTestClient();
    const { compressed, uncompressed } = publicKeyEncodingVector;
    for (const [publicKey, flag, expected] of [
      [compressed, false, uncompressed],
      [uncompressed, true, compressed],
    ] as const) {
      const result = await client.callTool({
        name: "keys_convert_public_key",
        arguments: { publicKey, compressed: flag },
      });
      expect(result.isError).not.toBe(true);
      expect(JSON.parse(text(result.content))).toEqual({ publicKey: expected, compressed: flag });
    }
    for (const args of [
      { publicKey: "02" + "ff".repeat(32) },
      { publicKey: compressed, compressed: "false" },
      { publicKey: compressed, chain: "bitcoin" },
    ]) {
      const result = await client.callTool({ name: "keys_convert_public_key", arguments: args });
      expect(result.isError).toBe(true);
    }
  });

  it("encodes and inspects localized mnemonics through MCP", async () => {
    const client = await connectTestClient();
    for (const { language, entropy, mnemonic } of localizedMnemonicVectors) {
      const encoded = await client.callTool({
        name: "keys_encode_bip39_entropy",
        arguments: { language, entropy },
      });
      expect(encoded.isError).not.toBe(true);
      expect(text(encoded.content)).toContain(`Language: ${language}`);
      expect(text(encoded.content)).toContain(`Mnemonic: ${mnemonic}`);
      const inspected = await client.callTool({
        name: "keys_inspect_mnemonic",
        arguments: { language, mnemonic },
      });
      expect(inspected.isError).not.toBe(true);
      expect(text(inspected.content)).toContain(`Language: ${language}`);
      expect(text(inspected.content)).toContain(`Entropy: ${entropy}`);
      expect(text(inspected.content)).toContain("Word count valid: yes");
      expect(text(inspected.content)).toContain("Wordlist valid: yes");
      expect(text(inspected.content)).toContain("Checksum valid: yes");
    }
    const generated = await client.callTool({
      name: "keys_generate_mnemonic",
      arguments: { language: "japanese", words: 15 },
    });
    expect(generated.isError).not.toBe(true);
    const mnemonic = /Mnemonic: ([^\n]+)/u.exec(text(generated.content))?.[1];
    expect(mnemonic?.split("\u3000")).toHaveLength(15);
    const inspected = await client.callTool({
      name: "keys_inspect_mnemonic",
      arguments: { language: "japanese", mnemonic },
    });
    expect(text(inspected.content)).toContain("Valid BIP39: yes");
    for (const [name, args] of [
      ["keys_generate_mnemonic", {}],
      ["keys_inspect_mnemonic", { mnemonic }],
      ["keys_encode_bip39_entropy", { entropy: "00".repeat(16) }],
    ] as const) {
      const result = await client.callTool({
        name,
        arguments: { ...args, language: "unsupported-secret" },
      });
      expect(result.isError).toBe(true);
      expect(text(result.content)).not.toContain("unsupported-secret");
    }
  });

  it("generates fresh mnemonics with a default length through MCP", async () => {
    const client = await connectTestClient();
    const mnemonics: string[] = [];
    for (const args of [{}, {}, { words: 24 }]) {
      const result = await client.callTool({ name: "keys_generate_mnemonic", arguments: args });
      expect(result.isError).not.toBe(true);
      const mnemonic = /Mnemonic: ([a-z ]+)/.exec(text(result.content))?.[1];
      if (!mnemonic) throw new Error("Missing mnemonic");
      expect(mnemonic.split(" ")).toHaveLength(args.words ?? 12);
      expect(text(result.content)).toContain("Never use it for real funds");
      const inspected = await client.callTool({
        name: "keys_inspect_mnemonic",
        arguments: { mnemonic },
      });
      expect(text(inspected.content)).toContain("Valid BIP39: yes");
      mnemonics.push(mnemonic);
    }
    expect(new Set(mnemonics).size).toBe(3);
    const listed = await client.listTools();
    expect(
      listed.tools.find((tool) => tool.name === "keys_generate_mnemonic")?.annotations,
    ).toMatchObject({ readOnlyHint: false, idempotentHint: false, openWorldHint: false });
    for (const args of [{ words: 13 }, { words: "12" }, { words: null }, { extra: true }]) {
      const result = await client.callTool({ name: "keys_generate_mnemonic", arguments: args });
      expect(result.isError).toBe(true);
    }
  });

  it.each(wifTestVectors)("converts $chain $network WIF through MCP", async (vector) => {
    const client = await connectTestClient();
    const { chain, network, compressed, privateKey, wif } = vector;
    const encoded = await client.callTool({
      name: "keys_encode_wif",
      arguments: { chain, network, compressed, privateKey },
    });
    expect(encoded.isError).not.toBe(true);
    expect(JSON.parse(text(encoded.content))).toEqual({ chain, network, compressed, wif });
    const decoded = await client.callTool({
      name: "keys_decode_wif",
      arguments: { chain, network, wif },
    });
    expect(decoded.isError).not.toBe(true);
    expect(JSON.parse(text(decoded.content))).toEqual({ chain, network, compressed, privateKey });
  });

  it("rejects malformed WIF tool inputs without echoing secrets", async () => {
    const client = await connectTestClient();
    const secret = "burner-secret-not-valid-WIF";
    for (const args of [
      { chain: "ethereum", wif: secret },
      { chain: "bitcoin", wif: secret },
      { chain: "bitcoin", wif: "1".repeat(55) },
      { chain: "bitcoin", wif: "111", network: "unknown" },
      { chain: "bitcoin", wif: "111", extra: secret },
    ]) {
      const result = await client.callTool({ name: "keys_decode_wif", arguments: args });
      expect(result.isError).toBe(true);
      expect(text(result.content)).not.toContain(secret);
    }
    const vector = wifTestVectors[0];
    const wrongChain = await client.callTool({
      name: "keys_decode_wif",
      arguments: { chain: "litecoin", wif: vector.wif },
    });
    expect(wrongChain.isError).toBe(true);
    expect(text(wrongChain.content)).not.toContain(vector.wif);
  });

  it("advertises every keys tool with explicit safety annotations", async () => {
    const client = await connectTestClient();

    const response = await client.listTools();

    expect(response.tools.map((tool) => tool.name)).toEqual(TOOL_NAMES);
    const landing = readFileSync(
      new URL("../docs/app/components/content/LandingHome.vue", import.meta.url),
      "utf8",
    );
    const advertisedTools = landing.match(/value: "([0-9]+)", label: "MCP tools"/u)?.[1];
    expect(advertisedTools, "LandingHome.vue must declare the current MCP tool count").toBe(
      String(response.tools.length),
    );
    expect(
      response.tools.find((tool) => tool.name === "keys_generate_wallet")?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    });
    expect(
      response.tools.find((tool) => tool.name === "keys_sign_message")?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    });
    expect(
      response.tools.find((tool) => tool.name === "keys_validate_address")?.annotations,
    ).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    });
  });

  it("derives a disposable Bitcoin address from a public mnemonic", async () => {
    const client = await connectTestClient();
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const response = await client.callTool({
      name: "keys_derive_hd_wallet",
      arguments: { chain: "bitcoin", mnemonic, path: "m/84'/0'/0'/0/0" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain("Address: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    expect(text(response.content)).not.toContain(mnemonic);
  });

  it("requires an explicit checksum override and reports the warning through MCP", async () => {
    const client = await connectTestClient();
    const { mnemonic, path, address, publicKey } = invalidChecksumPuzzle;
    const args = { chain: "bitcoin", mnemonic, path };
    const strict = await client.callTool({ name: "keys_derive_hd_wallet", arguments: args });
    expect(strict.isError).toBe(true);
    expect(text(strict.content)).toContain("Invalid BIP39 mnemonic");
    const result = await client.callTool({
      name: "keys_derive_hd_wallet",
      arguments: { ...args, allowInvalidChecksum: true },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content)).toContain(address);
    expect(text(result.content)).toContain(publicKey);
    expect(text(result.content)).toContain("Warning: BIP39 checksum is invalid.");
    expect(text(result.content)).not.toContain(mnemonic);
    for (const allowInvalidChecksum of [false, "true", "false", 1, null]) {
      const rejected = await client.callTool({
        name: "keys_derive_hd_wallet",
        arguments: { ...args, allowInvalidChecksum },
      });
      expect(rejected.isError).toBe(true);
    }
    const inspection = await client.callTool({
      name: "keys_inspect_mnemonic",
      arguments: { mnemonic },
    });
    expect(text(inspection.content)).toContain("Word count valid: yes");
    expect(text(inspection.content)).toContain("Wordlist valid: yes");
    expect(text(inspection.content)).toContain("Checksum valid: no");
    expect(text(inspection.content)).not.toContain("Entropy:");
  });

  it("derives Litecoin through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const response = await client.callTool({
      name: "keys_derive_wallet",
      arguments: { chain: "litecoin", privateKey: litecoinTestVectors.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(litecoinTestVectors.address);
    expect(text(response.content)).not.toContain(litecoinTestVectors.privateKey);
  });

  it("derives Decred through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const response = await client.callTool({
      name: "keys_derive_wallet",
      arguments: { chain: "decred", privateKey: decredTestVectors.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(decredTestVectors.addresses.mainnet);
    expect(text(response.content)).not.toContain(decredTestVectors.privateKey);
  });

  it("derives and signs Stellar through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const [message, , signature] = stellarTestVectors.messages[1];
    const wallet = await client.callTool({
      name: "keys_derive_wallet",
      arguments: { chain: "stellar", privateKey: stellarTestVectors.privateKey },
    });
    expect(wallet.isError).not.toBe(true);
    expect(text(wallet.content)).toContain(stellarTestVectors.address);
    expect(text(wallet.content)).not.toContain(stellarTestVectors.privateKey);

    const signed = await client.callTool({
      name: "keys_sign_message",
      arguments: { chain: "stellar", message, privateKey: stellarTestVectors.privateKey },
    });
    expect(signed.isError).not.toBe(true);
    expect(text(signed.content)).toContain(signature);
  });

  it("signs an Ethereum message with the recovery byte on request", async () => {
    const client = await connectTestClient();
    const [message, , signatureWithV] = ethereumTestVectors.messages[1];

    const plain = await client.callTool({
      name: "keys_sign_message",
      arguments: {
        chain: "ethereum",
        message,
        privateKey: ethereumTestVectors.privateKey,
      },
    });
    expect(text(plain.content)).toContain(signatureWithV.slice(0, 128));
    expect(text(plain.content)).not.toContain(signatureWithV);

    const recovered = await client.callTool({
      name: "keys_sign_message",
      arguments: {
        chain: "ethereum",
        message,
        privateKey: ethereumTestVectors.privateKey,
        recovered: true,
      },
    });
    expect(recovered.isError).not.toBe(true);
    expect(text(recovered.content)).toContain(signatureWithV);

    const verified = await client.callTool({
      name: "keys_verify_message",
      arguments: {
        chain: "ethereum",
        message,
        signature: signatureWithV,
        publicKey: ethereumTestVectors.publicKey,
      },
    });
    expect(text(verified.content)).toContain("Signature is valid");
  });

  it("reports an error for a chain without an r||s||v form", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_sign_message",
      arguments: {
        chain: "litecoin",
        message: "hello",
        privateKey: litecoinTestVectors.privateKey,
        recovered: true,
      },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).toContain("base64 of header");
  });

  it("validates a known Bitcoin address", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_validate_address",
      arguments: { chain: "bitcoin", address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain("is a valid bitcoin address");
  });

  it("rejects arguments that miss the schema", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_validate_address",
      arguments: { chain: "bitcoin" },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).toContain("Invalid arguments");
  });

  it("generates paths the ed25519 chains derive and refuses levels they lack", async () => {
    const client = await connectTestClient();
    const { mnemonic } = bip39TestVectors;

    for (const [chain, expected] of [
      ["solana", "m/44'/501'/0'/0'"],
      ["stellar", "m/44'/148'/0'"],
      ["aptos", "m/44'/637'/0'/0'/0'"],
      ["sui", "m/44'/784'/0'/0'/0'"],
    ]) {
      const generated = await client.callTool({
        name: "keys_bip44_path",
        arguments: { chain },
      });
      expect(generated.isError).not.toBe(true);
      expect(text(generated.content)).toContain(`Path: ${expected}`);

      const derived = await client.callTool({
        name: "keys_derive_hd_wallet",
        arguments: { chain, mnemonic, path: expected },
      });
      expect(derived.isError).not.toBe(true);
      expect(text(derived.content)).toContain("Address: ");
    }

    const cardano = await client.callTool({
      name: "keys_bip44_path",
      arguments: { chain: "cardano", change: 2 },
    });
    expect(text(cardano.content)).toContain("Path: m/1852'/1815'/0'/2/0");

    const sui = await client.callTool({
      name: "keys_bip44_path",
      arguments: { chain: "sui", addressType: "secp256k1" },
    });
    expect(text(sui.content)).toContain("Path: m/54'/784'/0'/0/0");

    for (const [arguments_, message] of [
      [{ chain: "stellar", addressIndex: 1 }, "Stellar paths end at the account"],
      [{ chain: "solana", addressIndex: 1 }, "Solana paths end at the change branch"],
      [{ chain: "bitcoin", change: 2 }, "change must be an integer between 0 and 1"],
      [{ chain: "cardano", change: 6 }, "change must be an integer between 0 and 5"],
      [{ chain: "bitcoin", addressType: "secp256k1" }, "is not supported for bitcoin"],
      [{ chain: "bitcoin", addressType: "segwit" }, "Invalid arguments"],
    ] as const) {
      const rejected = await client.callTool({ name: "keys_bip44_path", arguments: arguments_ });
      expect(rejected.isError).toBe(true);
      expect(text(rejected.content)).toContain(message);
    }
  });

  it("rejects ambiguous BIP44 path modes at the schema", async () => {
    const client = await connectTestClient();
    const path = "m/44'/0'/0'/0/0";

    for (const arguments_ of [
      {},
      { account: 1 },
      { change: 1 },
      { addressIndex: 1 },
      { chain: "bitcoin", path },
      { path, account: 1 },
      { path, change: 1 },
      { path, addressIndex: 1 },
      { path, addressType: "secp256k1" },
    ]) {
      const response = await client.callTool({
        name: "keys_bip44_path",
        arguments: arguments_,
      });

      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain("Invalid arguments");
    }

    const parsed = await client.callTool({
      name: "keys_bip44_path",
      arguments: { path },
    });
    expect(parsed.isError).not.toBe(true);
    expect(text(parsed.content)).toContain("Coin type: 0");
  });

  it("rejects unsupported wallet options at the schema", async () => {
    const client = await connectTestClient();

    for (const arguments_ of [
      { chain: "bitcoin", network: "testnett" },
      { chain: "bitcoin", addressType: "bogus" },
    ]) {
      const response = await client.callTool({
        name: "keys_generate_wallet",
        arguments: arguments_,
      });

      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain("Invalid arguments");
    }
  });

  it("rejects prototype property names as unknown tools", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({ name: "toString", arguments: {} });

    expect(response.isError).toBe(true);
    expect(response.content).toEqual([{ type: "text", text: 'Unknown keys tool: "toString"' }]);
  });

  it("removes control bytes from an echoed unknown tool name", async () => {
    const client = await connectTestClient();
    const escape = String.fromCodePoint(27);

    const response = await client.callTool({
      name: `x\nforged${escape}[31m`,
      arguments: {},
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).not.toContain("\n");
    expect(text(response.content)).not.toContain(escape);
  });

  it("removes control bytes from an echoed invalid address", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_validate_address",
      arguments: { chain: "bitcoin", address: "not-an-address\nforged output" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).not.toContain("\n");
    expect(text(response.content)).toContain("is not a valid bitcoin address");
  });

  it("does not echo an invalid private key in errors", async () => {
    const client = await connectTestClient();
    const privateKey = "private-fixture-that-must-not-be-echoed";

    const response = await client.callTool({
      name: "keys_derive_wallet",
      arguments: { chain: "ethereum", privateKey },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).not.toContain(privateKey);
  });
});
