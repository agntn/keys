import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { TSchema } from "typebox";
import { Value } from "typebox/value";
import { describe, expect, it } from "vitest";
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
