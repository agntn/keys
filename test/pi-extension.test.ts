import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { TSchema } from "typebox";
import { Value } from "typebox/value";
import { describe, expect, it } from "vitest";
import { litecoinTestVectors, decredTestVectors } from "./fixtures.ts";
import keysExtension from "../packages/pi/extensions/keys.ts";

interface RegisteredTool {
  readonly name: string;
  readonly parameters: TSchema;
  readonly execute: (
    toolCallId: string,
    params: Readonly<Record<string, unknown>>,
  ) => Promise<{
    readonly content: ReadonlyArray<{ readonly type: string; readonly text?: string }>;
  }>;
}

/**
 * SAFETY: the extension only calls registerTool during registration.
 * @returns {ReadonlyMap<string, RegisteredTool>} The tools captured from the extension
 */
function registerTools(): ReadonlyMap<string, RegisteredTool> {
  const tools = new Map<string, RegisteredTool>();
  const api = {
    registerTool(tool: RegisteredTool) {
      tools.set(tool.name, tool);
    },
  } as unknown as ExtensionAPI;

  keysExtension(api);
  return tools;
}

describe("keys Pi extension", () => {
  it("derives Litecoin through the registered Pi tool", async () => {
    const tool = registerTools().get("keys_derive_wallet");
    if (!tool) throw new Error("keys_derive_wallet was not registered");
    const args = { chain: "litecoin", privateKey: litecoinTestVectors.privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("litecoin", args);
    expect(result.content).toEqual([
      {
        type: "text",
        text: `Public key: ${litecoinTestVectors.publicKey}\nAddress: ${litecoinTestVectors.address}`,
      },
    ]);
  });

  it("derives Decred through the registered Pi tool", async () => {
    const tool = registerTools().get("keys_derive_wallet");
    if (!tool) throw new Error("keys_derive_wallet was not registered");
    const args = { chain: "decred", privateKey: decredTestVectors.privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("decred", args);
    expect(result.content).toEqual([
      {
        type: "text",
        text: `Public key: ${decredTestVectors.publicKey}\nAddress: ${decredTestVectors.addresses.mainnet}`,
      },
    ]);
  });

  it("rejects unsupported networks and address types on every relevant tool", async () => {
    const tools = registerTools();
    const networkCases = [
      ["keys_generate_wallet", { chain: "bitcoin" }],
      ["keys_derive_wallet", { chain: "ethereum", privateKey: "unused" }],
      ["keys_derive_hd_wallet", { chain: "base", mnemonic: "unused", path: "m/0" }],
      ["keys_get_address", { chain: "solana", publicKey: "unused" }],
      ["keys_validate_address", { chain: "aptos", address: "unused" }],
      ["keys_sign_message", { chain: "tron", message: "unused", privateKey: "unused" }],
      [
        "keys_verify_message",
        { chain: "sui", message: "unused", signature: "unused", publicKey: "unused" },
      ],
    ] as const;

    for (const [name, params] of networkCases) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`${name} was not registered`);
      const invalidParams = { ...params, network: "testnett" };

      expect(Value.Check(tool.parameters, invalidParams)).toBe(false);
      await expect(tool.execute("invalid-network", invalidParams)).rejects.toThrow(
        'Unsupported network "testnett"',
      );
    }

    const addressTypeCases = [
      ["keys_generate_wallet", { chain: "bitcoin", addressType: "stake" }],
      ["keys_derive_wallet", { chain: "ethereum", privateKey: "unused", addressType: "segwit" }],
      [
        "keys_derive_hd_wallet",
        { chain: "base", mnemonic: "unused", path: "m/0", addressType: "segwit" },
      ],
      ["keys_get_address", { chain: "solana", publicKey: "unused", addressType: "segwit" }],
      ["keys_generate_wallet", { chain: "aptos", addressType: "segwit" }],
      ["keys_derive_wallet", { chain: "tron", privateKey: "unused", addressType: "segwit" }],
      [
        "keys_derive_hd_wallet",
        { chain: "sui", mnemonic: "unused", path: "m/0", addressType: "taproot" },
      ],
      ["keys_get_address", { chain: "cardano", publicKey: "unused", addressType: "secp256k1" }],
    ] as const;

    for (const [name, params] of addressTypeCases) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`${name} was not registered`);

      expect(Value.Check(tool.parameters, params)).toBe(true);
      expect(Value.Check(tool.parameters, { ...params, addressType: "bogus" })).toBe(false);
      await expect(tool.execute("wrong-chain-address-type", params)).rejects.toThrow(
        /Address type/u,
      );
    }
  });

  it("maps BIP39 indices to words with an explicit base", async () => {
    const tool = registerTools().get("keys_lookup_bip39_indices");
    if (!tool) throw new Error("keys_lookup_bip39_indices was not registered");

    const zeroBasedResult = await tool.execute("call-1", {
      indices: [0, 1619, 2047],
    });
    const zeroBasedText = zeroBasedResult.content.map((part) => part.text ?? "").join("\n");

    expect(zeroBasedText).toContain("Index base: 0");
    expect(zeroBasedText).toContain("0: abandon");
    expect(zeroBasedText).toContain("1619: skill");
    expect(zeroBasedText).toContain("2047: zoo");

    const oneBasedResult = await tool.execute("call-2", {
      indices: [1, 1179, 2048],
      indexBase: 1,
      language: "italian",
    });
    const oneBasedText = oneBasedResult.content.map((part) => part.text ?? "").join("\n");

    expect(oneBasedText).toContain("Language: italian");
    expect(oneBasedText).toContain("Index base: 1");
    expect(oneBasedText).toContain("1: abaco");
    expect(oneBasedText).toContain("1179: orologio");
    expect(Value.Check(tool.parameters, { indices: [0, 2047] })).toBe(true);
    expect(Value.Check(tool.parameters, { indices: [1, 2048], indexBase: 1 })).toBe(true);
    expect(Value.Check(tool.parameters, { indices: [1.5] })).toBe(false);
    expect(Value.Check(tool.parameters, { indices: [] })).toBe(false);
    await expect(tool.execute("call-3", { indices: [0], indexBase: 1 })).rejects.toThrow(
      "BIP39 indices must be between 1 and 2048",
    );
  });

  it("looks up English BIP39 word membership and both index conventions", async () => {
    const tool = registerTools().get("keys_lookup_bip39_words");
    if (!tool) throw new Error("keys_lookup_bip39_words was not registered");

    const result = await tool.execute("call-1", {
      words: ["abandon", "Skill", "zoo", "eleven"],
    });
    const text = result.content.map((part) => part.text ?? "").join("\n");

    expect(text).toContain("abandon: zero-based 0, one-based 1");
    expect(text).toContain("skill: zero-based 1619, one-based 1620");
    expect(text).toContain("zoo: zero-based 2047, one-based 2048");
    expect(text).toContain("Language: english");
    expect(text).toContain("eleven: not in BIP39 (english)");
    expect(tool.parameters).toMatchObject({
      properties: { words: { items: { pattern: "^\\S+$" } } },
    });
    expect(Value.Check(tool.parameters, { words: ["skill"] })).toBe(true);
    expect(Value.Check(tool.parameters, { words: [] })).toBe(false);
    expect(Value.Check(tool.parameters, { words: ["two words"] })).toBe(false);
    const tooManyWords = Array.from({ length: 101 }, () => "zoo");
    expect(Value.Check(tool.parameters, { words: tooManyWords })).toBe(false);
    await expect(tool.execute("call-2", { words: "skill" })).rejects.toThrow("must be an array");
    await expect(tool.execute("call-3", { words: tooManyWords })).rejects.toThrow(
      "Provide between 1 and 100 words",
    );
    await expect(tool.execute("call-4", { words: ["two words"] })).rejects.toThrow(
      "must contain letters and combining marks only",
    );
  });

  it("looks up words from an explicit BIP39 language", async () => {
    const tool = registerTools().get("keys_lookup_bip39_words");
    if (!tool) throw new Error("keys_lookup_bip39_words was not registered");

    const result = await tool.execute("call-1", {
      words: ["orologio", "civetta"],
      language: "italian",
    });
    const text = result.content.map((part) => part.text ?? "").join("\n");

    expect(text).toContain("orologio: zero-based 1178, one-based 1179");
    expect(text).toContain("civetta: zero-based 361, one-based 362");
    expect(Value.Check(tool.parameters, { words: ["orologio"], language: "italian" })).toBe(true);
    expect(Value.Check(tool.parameters, { words: ["あいこくしん"], language: "japanese" })).toBe(
      true,
    );
    expect(Value.Check(tool.parameters, { words: ["orologio"], language: "unknown" })).toBe(false);
    await expect(
      tool.execute("call-2", { words: ["orologio"], language: "unknown" }),
    ).rejects.toThrow("Unknown BIP39 language");
  });

  it("lists words compatible with the checksum for one missing mnemonic position", async () => {
    const tool = registerTools().get("keys_recover_mnemonic_word");
    if (!tool) throw new Error("keys_recover_mnemonic_word was not registered");

    const template =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?";
    const result = await tool.execute("call-1", { mnemonic: template });
    const text = result.content.map((part) => part.text ?? "").join("\n");

    expect(text).toContain("Position: 12");
    expect(text).toContain("Candidates (128):");
    expect(text).toContain("Candidates (128): about,");
    expect(text).not.toContain(template);
    expect(Value.Check(tool.parameters, { mnemonic: template })).toBe(true);
    expect(Value.Check(tool.parameters, { mnemonic: template.replace("?", "about") })).toBe(false);
  });

  it("inspects a public BIP39 mnemonic without echoing its words", async () => {
    const tool = registerTools().get("keys_inspect_mnemonic");
    if (!tool) throw new Error("keys_inspect_mnemonic was not registered");

    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    const validResult = await tool.execute("call-1", { mnemonic });
    const validText = validResult.content.map((part) => part.text ?? "").join("\n");

    expect(validText).toContain("Valid BIP39: yes");
    expect(validText).toContain("Words: 12");
    expect(validText).toContain("Entropy: 00000000000000000000000000000000");
    expect(validText).not.toContain(mnemonic);

    const invalidResult = await tool.execute("call-2", {
      mnemonic:
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon wrong",
    });
    const invalidText = invalidResult.content.map((part) => part.text ?? "").join("\n");

    expect(invalidText).toContain("Valid BIP39: no");
    expect(invalidText).toContain("Words: 12");
    expect(invalidText).not.toContain("Entropy:");
    expect(Value.Check(tool.parameters, { mnemonic: "   " })).toBe(false);
  });

  it("encodes public entropy as an English BIP39 mnemonic", async () => {
    const tool = registerTools().get("keys_encode_bip39_entropy");
    if (!tool) throw new Error("keys_encode_bip39_entropy was not registered");

    const entropy = "00000000000000000000000000000000";
    const result = await tool.execute("call-1", { entropy });
    const text = result.content.map((part) => part.text ?? "").join("\n");

    expect(text).toContain("Words: 12");
    expect(text).toContain(
      "Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    expect(text).not.toContain(entropy);
    for (const bytes of [16, 20, 24, 28, 32]) {
      expect(Value.Check(tool.parameters, { entropy: "00".repeat(bytes) })).toBe(true);
    }
    expect(Value.Check(tool.parameters, { entropy: "AA".repeat(16) })).toBe(true);
    expect(Value.Check(tool.parameters, { entropy: "00".repeat(15) })).toBe(false);
    expect(Value.Check(tool.parameters, { entropy: "gg".repeat(16) })).toBe(false);
    await expect(tool.execute("call-2", { entropy: "00".repeat(15) })).rejects.toThrow(
      "16, 20, 24, 28, or 32 bytes",
    );
    await expect(tool.execute("call-3", { entropy: "gg".repeat(16) })).rejects.toThrow(
      "must be a hexadecimal string",
    );
  });

  it("derives an HD wallet from a public mnemonic and path", async () => {
    const tool = registerTools().get("keys_derive_hd_wallet");
    if (!tool) throw new Error("keys_derive_hd_wallet was not registered");
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const result = await tool.execute("call-1", {
      chain: "bitcoin",
      mnemonic,
      path: "m/84'/0'/0'/0/0",
    });
    const text = result.content.map((part) => part.text ?? "").join("\n");

    expect(text).toContain("Chain: bitcoin (mainnet)");
    expect(text).toContain("Path: m/84'/0'/0'/0/0");
    expect(text).toContain(
      "Public key: 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
    );
    expect(text).toContain("Address: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
    expect(text).not.toContain("abandon");
    expect(text).not.toContain("4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3");

    const passphraseResult = await tool.execute("call-2", {
      chain: "ethereum",
      mnemonic,
      path: "m/44'/60'/0'/0/0",
      passphrase: "TREZOR",
    });
    const passphraseText = passphraseResult.content.map((part) => part.text ?? "").join("\n");

    expect(passphraseText).toContain("Address: 0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6");
    expect(passphraseText).not.toContain("TREZOR");
    expect(
      Value.Check(tool.parameters, { chain: "solana", mnemonic, path: "m/44'/501'/0'/0'" }),
    ).toBe(true);
    expect(Value.Check(tool.parameters, { chain: "bitcoin", mnemonic })).toBe(false);
    expect(
      Value.Check(tool.parameters, { chain: "bitcoin", mnemonic, path: "44'/0'/0'/0/0" }),
    ).toBe(false);
    expect(Value.Check(tool.parameters, { chain: "bitcoin", mnemonic: "   ", path: "m/0" })).toBe(
      false,
    );
    await expect(
      tool.execute("call-3", { chain: "bitcoin", mnemonic, path: "m/84h/0" }),
    ).rejects.toThrow("must look like");
    await expect(
      tool.execute("call-4", { chain: "cardano", mnemonic, path: "m/1852'/1815'/0'/0/0" }),
    ).rejects.toThrow("CIP-1852");
    await expect(
      tool.execute("call-5", {
        chain: "bitcoin",
        mnemonic: mnemonic.replace("about", "abandon"),
        path: "m/84'/0'/0'/0/0",
      }),
    ).rejects.toThrow("Invalid BIP39 mnemonic");
  });

  it("keeps the BIP44 path schema portable and enforces one mode", async () => {
    const tool = registerTools().get("keys_bip44_path");
    if (!tool) throw new Error("keys_bip44_path was not registered");
    const path = "m/44'/0'/0'/0/0";

    expect(tool.parameters).toMatchObject({ type: "object" });
    expect(tool.parameters).not.toHaveProperty("oneOf");
    expect(Value.Check(tool.parameters, { chain: "bitcoin" })).toBe(true);
    expect(Value.Check(tool.parameters, { path })).toBe(true);
    const parsed = await tool.execute("parse-mode", { path });
    expect(parsed.content.map((part) => part.text ?? "").join("\n")).toContain("Coin type: 0");

    for (const params of [
      {},
      { account: 1 },
      { change: 1 },
      { addressIndex: 1 },
      { chain: "bitcoin", path },
      { path, account: 1 },
      { path, change: 1 },
      { path, addressIndex: 1 },
    ]) {
      expect(Value.Check(tool.parameters, params)).toBe(true);
      await expect(tool.execute("ambiguous-mode", params)).rejects.toThrow(
        "Provide path by itself, or chain with optional account, change, and addressIndex",
      );
    }
  });

  it("derives a Sui wallet from an existing private key", async () => {
    const tool = registerTools().get("keys_derive_wallet");
    if (!tool) throw new Error("keys_derive_wallet was not registered");

    const result = await tool.execute("call-1", {
      chain: "sui",
      privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
      addressType: "secp256k1",
    });

    const text = result.content.map((part) => part.text ?? "").join("\n");
    expect(text).toContain(
      "Public key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    );
    expect(text).toContain(
      "Address: 0xd4c3524e6642b2e54945c02378024f822ac3f80b0870a5f95f06e68a61890a6c",
    );
    expect(text).not.toContain("0000000000000000000000000000000000000000000000000000000000000001");
  });
});
