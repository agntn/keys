import { readFileSync } from "node:fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { afterEach, describe, expect, it } from "vite-plus/test";
import {
  bip39TestVectors,
  bitcoinTestVectors,
  electrumVectors,
  ethereumTestVectors,
  publicKeyEncodingVector,
  litecoinTestVectors,
  bitcoinCashTestVectors,
  bitcoinGoldTestVectors,
  bitcoinSVTestVectors,
  dashTestVectors,
  zcashTestVectors,
  eCashTestVectors,
  dogecoinTestVectors,
  decredTestVectors,
  stellarTestVectors,
  wifTestVectors,
  localizedMnemonicVectors,
  invalidChecksumPuzzle,
  slip132PrivateKey,
  secp256k1TestVectors,
  slip132Vectors,
  bip38Vectors,
} from "./fixtures.ts";
import { callTool, createMcpServer, toolListings } from "../src/mcp.ts";
import { TOOL_NAMES } from "../src/tool-parameters.ts";

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
      name: "keys_bip39_words_lookup",
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
      name: "keys_electrum_wallet_derive",
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
        name: "keys_electrum_wallet_derive",
        arguments: args,
      });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).not.toContain("secret-phrase");
    }
  });
  it("derives a BIP39 seed through MCP", async () => {
    const client = await connectTestClient();
    const result = await client.callTool({
      name: "keys_bip39_seed_derive",
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
      const result = await client.callTool({ name: "keys_bip39_seed_derive", arguments: args });
      expect(result.isError).toBe(true);
      expect(text(result.content)).not.toContain("unknown-secret");
    }
  });

  it("names the BIP39 check a seed input fails through MCP", async () => {
    const client = await connectTestClient();
    for (const [args, reason] of [
      [{ mnemonic: "abandon ".repeat(12).trim() }, "the checksum does not match"],
      [
        { mnemonic: bip39TestVectors.mnemonic, language: "french" },
        "word 12 is not in the french list",
      ],
    ] as const) {
      const result = await client.callTool({ name: "keys_bip39_seed_derive", arguments: args });
      expect(result.isError).toBe(true);
      expect(text(result.content)).toContain(`Invalid BIP39 mnemonic: ${reason}`);
      expect(text(result.content)).not.toContain("allowInvalidChecksum");
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
        name: "keys_secp256k1_public_key_convert",
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
      const result = await client.callTool({
        name: "keys_secp256k1_public_key_convert",
        arguments: args,
      });
      expect(result.isError).toBe(true);
    }
  });

  it("encodes and inspects localized mnemonics through MCP", async () => {
    const client = await connectTestClient();
    for (const { language, entropy, mnemonic } of localizedMnemonicVectors) {
      const encoded = await client.callTool({
        name: "keys_bip39_entropy_encode",
        arguments: { language, entropy },
      });
      expect(encoded.isError).not.toBe(true);
      expect(text(encoded.content)).toContain(`Language: ${language}`);
      expect(text(encoded.content)).toContain(`Mnemonic: ${mnemonic}`);
      const inspected = await client.callTool({
        name: "keys_bip39_inspect",
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
      name: "keys_bip39_generate",
      arguments: { language: "japanese", words: 15 },
    });
    expect(generated.isError).not.toBe(true);
    const mnemonic = /Mnemonic: ([^\n]+)/u.exec(text(generated.content))?.[1];
    expect(mnemonic?.split("\u3000")).toHaveLength(15);
    const inspected = await client.callTool({
      name: "keys_bip39_inspect",
      arguments: { language: "japanese", mnemonic },
    });
    expect(text(inspected.content)).toContain("Valid BIP39: yes");
    for (const [name, args] of [
      ["keys_bip39_generate", {}],
      ["keys_bip39_inspect", { mnemonic }],
      ["keys_bip39_entropy_encode", { entropy: "00".repeat(16) }],
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
      const result = await client.callTool({ name: "keys_bip39_generate", arguments: args });
      expect(result.isError).not.toBe(true);
      const mnemonic = /Mnemonic: ([a-z ]+)/.exec(text(result.content))?.[1];
      if (!mnemonic) throw new Error("Missing mnemonic");
      expect(mnemonic.split(" ")).toHaveLength(args.words ?? 12);
      expect(text(result.content)).toContain("Never use it for real funds");
      const inspected = await client.callTool({
        name: "keys_bip39_inspect",
        arguments: { mnemonic },
      });
      expect(text(inspected.content)).toContain("Valid BIP39: yes");
      mnemonics.push(mnemonic);
    }
    expect(new Set(mnemonics).size).toBe(3);
    const listed = await client.listTools();
    expect(
      listed.tools.find((tool) => tool.name === "keys_bip39_generate")?.annotations,
    ).toMatchObject({ readOnlyHint: false, idempotentHint: false, openWorldHint: false });
    for (const args of [{ words: 13 }, { words: "12" }, { words: null }, { extra: true }]) {
      const result = await client.callTool({ name: "keys_bip39_generate", arguments: args });
      expect(result.isError).toBe(true);
    }
  });

  it.each(wifTestVectors)("converts $chain $network WIF through MCP", async (vector) => {
    const client = await connectTestClient();
    const { chain, network, compressed, privateKey, wif } = vector;
    const encoded = await client.callTool({
      name: "keys_wif_encode",
      arguments: { chain, network, compressed, privateKey },
    });
    expect(encoded.isError).not.toBe(true);
    expect(JSON.parse(text(encoded.content))).toEqual({ chain, network, compressed, wif });
    const decoded = await client.callTool({
      name: "keys_wif_decode",
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
      const result = await client.callTool({ name: "keys_wif_decode", arguments: args });
      expect(result.isError).toBe(true);
      expect(text(result.content)).not.toContain(secret);
    }
    const vector = wifTestVectors[0];
    const wrongChain = await client.callTool({
      name: "keys_wif_decode",
      arguments: { chain: "litecoin", wif: vector.wif },
    });
    expect(wrongChain.isError).toBe(true);
    expect(text(wrongChain.content)).not.toContain(vector.wif);
  });

  it("reads a BIP38 header and checks an address through MCP", async () => {
    const client = await connectTestClient();
    const { encrypted, address, inspection } = bip38Vectors[3];

    const response = await client.callTool({
      name: "keys_bip38_inspect",
      arguments: { encrypted, address },
    });
    expect(response.isError).not.toBe(true);
    expect(JSON.parse(text(response.content))).toEqual({ ...inspection, addressMatches: true });

    const omitted = await client.callTool({
      name: "keys_bip38_inspect",
      arguments: { encrypted: bip38Vectors[0].encrypted },
    });
    expect(JSON.parse(text(omitted.content))).toEqual(bip38Vectors[0].inspection);

    for (const [args, message] of [
      [{ encrypted: encrypted.slice(0, -1) + "1" }, "Invalid BIP38 base58 encoding or checksum"],
      [{ encrypted: "0OIl" }, "Invalid arguments at /encrypted"],
      [{ encrypted, extra: true }, "Invalid arguments"],
    ] as const) {
      const failed = await client.callTool({ name: "keys_bip38_inspect", arguments: args });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).toContain(message);
    }
  });

  it.each([
    "README.md",
    "AGENTS.md",
    "packages/pi/README.md",
    "packages/pi/AGENTS.md",
    "docs/DESIGN.md",
    "docs/content/1.guide/1.index.md",
    "docs/app/components/content/LandingHero.vue",
    "docs/app/components/content/LandingHome.vue",
    "docs/app/components/OgImage/Landing.takumi.vue",
  ])("leaves the tool count out of %s, which TOOL_NAMES owns", (file) => {
    const text = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
    expect(text).not.toMatch(/\b\d+ (?:agent |MCP )?tools\b/iu);
    expect(text).not.toMatch(/\b(?:nineteen|twenty|thirty)[a-z-]* (?:agent |MCP )?tools\b/iu);
    expect(text).not.toMatch(/value: "\d+", unit: "", note: "MCP/u);
  });

  it("advertises every keys tool with explicit safety annotations", async () => {
    const client = await connectTestClient();

    const response = await client.listTools();

    expect(response.tools.map((tool) => tool.name)).toEqual(TOOL_NAMES);
    expect(
      response.tools.find((tool) => tool.name === "keys_wallet_generate")?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    });
    expect(
      response.tools.find((tool) => tool.name === "keys_message_sign")?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    });
    expect(
      response.tools.find((tool) => tool.name === "keys_address_validate")?.annotations,
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
      name: "keys_hd_wallet_derive",
      arguments: { chain: "bitcoin", mnemonic, path: "m/84'/0'/0'/0/0" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(
      "Address type: segwit\nPublic key: 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c\nAddress: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    );
    expect(text(response.content)).not.toContain(mnemonic);
  });

  it("takes the h hardened marker of BIP380 descriptors in every path argument", async () => {
    const client = await connectTestClient();
    const call = async (name: string, args: Readonly<Record<string, string>>) =>
      client.callTool({ name, arguments: args });
    const [electrum] = electrumVectors;

    const wallet = await call("keys_hd_wallet_derive", {
      chain: "bitcoin",
      mnemonic: bip39TestVectors.mnemonic,
      path: "m/84h/0h/0h/0/0",
    });
    expect(text(wallet.content)).toContain(
      "Address type: segwit\nPublic key: 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
    );
    const electrumWallet = await call("keys_electrum_wallet_derive", {
      mnemonic: electrum.mnemonic,
      path: electrum.path.replaceAll("'", "h"),
    });
    expect(text(electrumWallet.content)).toContain(electrum.address);
    const parsed = await call("keys_bip44_parse", { path: "m/44h/60h/0h/0/0" });
    expect(text(parsed.content)).toContain("Coin type: 60\nAccount: 0\nChange: 0");

    const rejected = await call("keys_hd_wallet_derive", {
      chain: "bitcoin",
      mnemonic: bip39TestVectors.mnemonic,
      path: "m/84H/0H/0H/0/0",
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Invalid arguments at /path");
  });

  it("says which address type keys_address_get wrote", async () => {
    const client = await connectTestClient();
    const publicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const address = async (args: Readonly<Record<string, string>>): Promise<string> =>
      text((await client.callTool({ name: "keys_address_get", arguments: args })).content);

    expect(await address({ chain: "bitcoin", publicKey })).toBe(
      "Address type: legacy\nAddress: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    );
    expect(await address({ chain: "bitcoin", publicKey, addressType: "taproot" })).toContain(
      "Address type: taproot\nAddress: bc1p",
    );
    expect(await address({ chain: "ethereum", publicKey })).toBe(
      "Address: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
    );
  });

  it("derives a watch-only address from an extended public key through MCP", async () => {
    const client = await connectTestClient();
    const [xpub, , zpub] = slip132Vectors;

    const response = await client.callTool({
      name: "keys_xpub_wallet_derive",
      arguments: { chain: "bitcoin", extendedKey: zpub.extendedKey, path: "m/0/0" },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toBe(
      [
        "Chain: bitcoin (mainnet)",
        "Extended key: zpub",
        "Path: m/0/0",
        "Address type: segwit",
        "Public key: 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        `Address: ${zpub.address}`,
      ].join("\n"),
    );

    for (const [args, message] of [
      [{ extendedKey: xpub.extendedKey, path: "m/0'/0" }, "Invalid arguments at /path"],
      [{ extendedKey: slip132PrivateKey, path: "m/0/0" }, "Extended private keys are not accepted"],
      [{ extendedKey: xpub.extendedKey, path: "m/0", chain: "solana" }, "solana does not derive"],
    ] as const) {
      const failed = await client.callTool({
        name: "keys_xpub_wallet_derive",
        arguments: { chain: "bitcoin", ...args },
      });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).toContain(message);
      expect(text(failed.content)).not.toContain(slip132PrivateKey.slice(4, 40));
    }
  });

  it("requires an explicit checksum override and reports the warning through MCP", async () => {
    const client = await connectTestClient();
    const { mnemonic, path, address, publicKey } = invalidChecksumPuzzle;
    const args = { chain: "bitcoin", mnemonic, path };
    const strict = await client.callTool({ name: "keys_hd_wallet_derive", arguments: args });
    expect(strict.isError).toBe(true);
    expect(text(strict.content)).toContain("Invalid BIP39 mnemonic");
    const result = await client.callTool({
      name: "keys_hd_wallet_derive",
      arguments: { ...args, allowInvalidChecksum: true },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content)).toContain(address);
    expect(text(result.content)).toContain(publicKey);
    expect(text(result.content)).toContain("Warning: BIP39 checksum is invalid.");
    expect(text(result.content)).not.toContain(mnemonic);
    for (const allowInvalidChecksum of [false, "true", "false", 1, null]) {
      const rejected = await client.callTool({
        name: "keys_hd_wallet_derive",
        arguments: { ...args, allowInvalidChecksum },
      });
      expect(rejected.isError).toBe(true);
    }
    const inspection = await client.callTool({
      name: "keys_bip39_inspect",
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
      name: "keys_wallet_derive",
      arguments: { chain: "litecoin", privateKey: litecoinTestVectors.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(litecoinTestVectors.address);
    expect(text(response.content)).not.toContain(litecoinTestVectors.privateKey);
  });

  it("derives and validates Bitcoin Cash through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const { privateKey, address } = bitcoinCashTestVectors.prize;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoincash", privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(address);
    expect(text(response.content)).not.toContain(privateKey);

    const validation = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoincash", address },
    });
    expect(text(validation.content)).toContain("is a valid bitcoincash address");

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoincash", privateKey, addressType: "segwit" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");
  });

  it("derives and validates Bitcoin Gold through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const { privateKey, segwitAddress } = bitcoinGoldTestVectors.signed;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoingold", privateKey, addressType: "segwit" },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(segwitAddress);
    expect(text(response.content)).not.toContain(privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoingold", privateKey, addressType: "taproot" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy, p2sh, segwit, p2wsh");

    const unprotected = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoingold", address: bitcoinGoldTestVectors.unprotected[0] },
    });
    expect(text(unprotected.content)).toContain("is not a valid bitcoingold address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "bitcoingold" },
    });
    expect(text(path.content)).toContain("m/44'/156'/0'/0/0");
  });

  it("derives and validates Bitcoin SV through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const { privateKey, address } = bitcoinSVTestVectors.keyOne;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoinsv", privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(address);
    expect(text(response.content)).not.toContain(privateKey);

    const rejected = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoinsv", address: bitcoinSVTestVectors.p2shAddress },
    });
    expect(text(rejected.content)).toContain("is not a valid bitcoinsv address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "bitcoinsv" },
    });
    expect(text(path.content)).toContain("m/44'/236'/0'/0/0");
  });

  it("derives and validates Dogecoin through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const [key] = dogecoinTestVectors.keys;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "dogecoin", privateKey: key.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(key.addressCompressed);
    expect(text(response.content)).not.toContain(key.privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "dogecoin", privateKey: key.privateKey, addressType: "p2sh" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");

    const script = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "dogecoin", address: dogecoinTestVectors.mainnet[1] },
    });
    expect(text(script.content)).toContain("is a valid dogecoin address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "dogecoin" },
    });
    expect(text(path.content)).toContain("m/44'/3'/0'/0/0");
  });

  it("derives and validates Dash through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const [key] = dashTestVectors.keys;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "dash", privateKey: key.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(key.addressCompressed);
    expect(text(response.content)).not.toContain(key.privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "dash", privateKey: key.privateKey, addressType: "p2sh" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");

    const script = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "dash", address: dashTestVectors.mainnet[1] },
    });
    expect(text(script.content)).toContain("is a valid dash address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "dash" },
    });
    expect(text(path.content)).toContain("m/44'/5'/0'/0/0");
  });

  it("derives and validates Zcash through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const [key] = zcashTestVectors.keys;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "zcash", privateKey: key.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(key.addressCompressed);
    expect(text(response.content)).not.toContain(key.privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "zcash", privateKey: key.privateKey, addressType: "p2sh" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");

    const tex = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "zcash", address: zcashTestVectors.tex.tex },
    });
    expect(text(tex.content)).toContain("is a valid zcash address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "zcash" },
    });
    expect(text(path.content)).toContain("m/44'/133'/0'/0/0");
  });

  it("derives and validates eCash through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const { privateKey } = eCashTestVectors.signed;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "ecash", privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain("ecash:q");
    expect(text(response.content)).not.toContain(privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "ecash", privateKey, addressType: "p2sh" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");

    const [{ p2sh }] = eCashTestVectors.encoded;
    const validation = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "ecash", address: p2sh },
    });
    expect(text(validation.content)).toContain("is a valid ecash address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "ecash" },
    });
    expect(text(path.content)).toContain("m/44'/899'/0'/0/0");
  });

  it("derives Decred through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const response = await client.callTool({
      name: "keys_wallet_derive",
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
      name: "keys_wallet_derive",
      arguments: { chain: "stellar", privateKey: stellarTestVectors.privateKey },
    });
    expect(wallet.isError).not.toBe(true);
    expect(text(wallet.content)).toContain(stellarTestVectors.address);
    expect(text(wallet.content)).not.toContain(stellarTestVectors.privateKey);

    const signed = await client.callTool({
      name: "keys_message_sign",
      arguments: { chain: "stellar", message, privateKey: stellarTestVectors.privateKey },
    });
    expect(signed.isError).not.toBe(true);
    expect(text(signed.content)).toContain(signature);
  });

  it("signs an Ethereum message with the recovery byte on request", async () => {
    const client = await connectTestClient();
    const [message, , signatureWithV] = ethereumTestVectors.messages[1];

    const plain = await client.callTool({
      name: "keys_message_sign",
      arguments: {
        chain: "ethereum",
        message,
        privateKey: ethereumTestVectors.privateKey,
      },
    });
    expect(text(plain.content)).toContain(signatureWithV.slice(0, 128));
    expect(text(plain.content)).not.toContain(signatureWithV);

    const recovered = await client.callTool({
      name: "keys_message_sign",
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
      name: "keys_message_verify",
      arguments: {
        chain: "ethereum",
        message,
        signature: signatureWithV,
        publicKey: ethereumTestVectors.publicKey,
      },
    });
    expect(text(verified.content)).toContain("Signature is valid");
  });

  it("rejects 0x hex at the schema instead of calling a valid signature invalid", async () => {
    const client = await connectTestClient();
    const [message, , signature] = ethereumTestVectors.messages[1];
    const { privateKey, publicKey } = ethereumTestVectors;

    for (const [name, arguments_, field] of [
      [
        "keys_message_verify",
        { chain: "ethereum", message, signature: `0x${signature}`, publicKey },
        "/signature",
      ],
      [
        "keys_message_verify",
        { chain: "ethereum", message, signature, publicKey: `0x${publicKey}` },
        "/publicKey",
      ],
      [
        "keys_message_sign",
        { chain: "ethereum", message, privateKey: `0x${privateKey}` },
        "/privateKey",
      ],
      ["keys_wallet_derive", { chain: "ethereum", privateKey: `0x${privateKey}` }, "/privateKey"],
      ["keys_address_get", { chain: "ethereum", publicKey: `0x${publicKey}` }, "/publicKey"],
    ] as const) {
      const response = await client.callTool({ name, arguments: arguments_ });
      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain(`Invalid arguments at ${field}`);
    }
  });

  it("reports an error for a chain without an r||s||v form", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_message_sign",
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
      name: "keys_address_validate",
      arguments: { chain: "bitcoin", address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain("is a valid bitcoin address");
  });

  it("names the network an address belongs to when it fails on the other", async () => {
    const client = await connectTestClient();
    const { mainnet, testnet } = bitcoinTestVectors.addresses.p2pkh;

    const onMainnet = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoin", address: testnet },
    });
    const onTestnet = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoin", address: mainnet, network: "testnet" },
    });

    expect(text(onMainnet.content)).toBe(
      `${testnet} is not a valid bitcoin address on mainnet, but it is valid on testnet`,
    );
    expect(text(onTestnet.content)).toBe(
      `${mainnet} is not a valid bitcoin address on testnet, but it is valid on mainnet`,
    );
  });

  it("rejects arguments that miss the schema", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_address_validate",
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
        name: "keys_bip44_generate",
        arguments: { chain },
      });
      expect(generated.isError).not.toBe(true);
      expect(text(generated.content)).toContain(`Path: ${expected}`);

      const derived = await client.callTool({
        name: "keys_hd_wallet_derive",
        arguments: { chain, mnemonic, path: expected },
      });
      expect(derived.isError).not.toBe(true);
      expect(text(derived.content)).toContain("Address: ");
    }

    const cardano = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "cardano", change: 2 },
    });
    expect(text(cardano.content)).toContain("Path: m/1852'/1815'/0'/2/0");

    const sui = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "sui", addressType: "secp256k1" },
    });
    expect(text(sui.content)).toContain("Path: m/54'/784'/0'/0/0");

    for (const [arguments_, message] of [
      [{ chain: "stellar", addressIndex: 1 }, "Stellar paths end at the account"],
      [{ chain: "solana", addressIndex: 1 }, "Solana paths end at the change branch"],
      [{ chain: "bitcoin", change: 2 }, "change must be an integer between 0 and 1"],
      [{ chain: "cardano", change: 6 }, "change must be an integer between 0 and 5"],
      [{ chain: "bitcoin", addressType: "secp256k1" }, "is not supported for bitcoin"],
      [
        { chain: "ethereum", addressType: "secp256k1" },
        'Address type "secp256k1" is not supported for ethereum',
      ],
      [{ chain: "bitcoin", addressType: "segwit" }, "Invalid arguments"],
    ] as const) {
      const rejected = await client.callTool({
        name: "keys_bip44_generate",
        arguments: arguments_,
      });
      expect(rejected.isError).toBe(true);
      expect(text(rejected.content)).toContain(message);
    }
  });

  it("fails an unparsable BIP44 path with sanitized text", async () => {
    const client = await connectTestClient();
    const result = await client.callTool({
      name: "keys_bip44_parse",
      arguments: { path: "m/\u009B31m" },
    });
    expect(result.isError).toBe(true);
    expect(text(result.content)).toBe('keys_bip44_parse failed: Invalid BIP44 path: "m/ 31m"');
  });

  it("keeps each BIP44 tool to its own arguments at the schema", async () => {
    const client = await connectTestClient();
    const path = "m/44'/0'/0'/0/0";

    for (const [name, arguments_] of [
      ["keys_bip44_parse", {}],
      ["keys_bip44_parse", { chain: "bitcoin", path }],
      ["keys_bip44_parse", { path, account: 1 }],
      ["keys_bip44_parse", { path, addressType: "secp256k1" }],
      ["keys_bip44_generate", {}],
      ["keys_bip44_generate", { account: 1 }],
      ["keys_bip44_generate", { chain: "bitcoin", path }],
    ] as const) {
      const response = await client.callTool({ name, arguments: arguments_ });

      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain("Invalid arguments");
    }

    const parsed = await client.callTool({
      name: "keys_bip44_parse",
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
        name: "keys_wallet_generate",
        arguments: arguments_,
      });

      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain("Invalid arguments");
    }
  });

  it("names the allowed values when an option is not one of them", async () => {
    const client = await connectTestClient();

    for (const [name, arguments_, message] of [
      [
        "keys_wallet_generate",
        { chain: "bitcoin", network: "testnett" },
        "Invalid arguments at /network: must be one of mainnet, testnet",
      ],
      [
        "keys_wif_decode",
        { chain: "ethereum", wif: wifTestVectors[0].wif },
        "Invalid arguments at /chain: must be one of bitcoin, litecoin, dash, decred, dogecoin",
      ],
      [
        "keys_bip39_generate",
        { words: 13 },
        "Invalid arguments at /words: must be one of 12, 15, 18, 21, 24",
      ],
      [
        "keys_bip39_indices_lookup",
        { indices: [1], indexBase: 2 },
        "Invalid arguments at /indexBase: must be one of 0, 1",
      ],
    ] as const) {
      const response = await client.callTool({ name, arguments: arguments_ });

      expect(response.isError).toBe(true);
      expect(text(response.content)).toBe(message);
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
      name: "keys_address_validate",
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
      name: "keys_wallet_derive",
      arguments: { chain: "ethereum", privateKey },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).not.toContain(privateKey);
  });

  it("exports the listings and calls the server answers with", async () => {
    const client = await connectTestClient();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;

    expect((await client.listTools()).tools).toEqual(toolListings);
    for (const [name, arguments_] of [
      ["keys_address_get", { chain: "bitcoin", publicKey: publicKeyCompressed }],
      ["keys_address_get", { chain: "bitcoin", publicKey: publicKeyCompressed, extra: 1 }],
      ["keys_wallet_derive", { chain: "nochain", privateKey }],
      ["keys_missing", {}],
    ] as const) {
      const direct = await callTool(name, arguments_);
      expect(direct).toEqual(await client.callTool({ name, arguments: arguments_ }));
    }
  });
});
