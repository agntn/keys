import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { TSchema } from "typebox";
import { Value } from "typebox/value";
import { describe, expect, it } from "vitest";
import {
  bip39TestVectors,
  publicKeyEncodingVector,
  litecoinTestVectors,
  decredTestVectors,
  stellarTestVectors,
  wifTestVectors,
  localizedMnemonicVectors,
  invalidChecksumPuzzle,
} from "./fixtures.ts";
import keysExtension from "../packages/pi/extensions/keys.ts";
import { mnemonicToSeed, mnemonicToEntropy, validateMnemonic } from "../src/utils/bip39/index.ts";

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
  it("derives disposable BIP39 seeds without echoing the input", async () => {
    const tool = registerTools().get("keys_derive_bip39_seed");
    if (!tool) throw new Error("Missing BIP39 seed tool");
    const { mnemonic, passphrase, seed, seedWithPassphrase } = bip39TestVectors;
    for (const [args, expected] of [
      [{ mnemonic }, seed],
      [{ mnemonic: `  ${mnemonic.replaceAll(" ", "\n\t")}  `, passphrase }, seedWithPassphrase],
    ] as const) {
      expect(Value.Check(tool.parameters, args)).toBe(true);
      const result = await tool.execute("seed", args);
      expect(result).toMatchObject({ details: { language: "english", seed: expected } });
      expect(result.content[0]?.text).toContain(`Seed: ${expected}`);
      expect(result.content[0]?.text).toContain("Never use it for real funds");
      expect(JSON.stringify(result)).not.toContain(mnemonic);
      expect(JSON.stringify(result)).not.toContain(passphrase);
    }
    const composed = await tool.execute("seed", { mnemonic, passphrase: " café " });
    expect(composed).toEqual(await tool.execute("seed", { mnemonic, passphrase: " cafe\u0301 " }));
    expect(composed).not.toEqual(await tool.execute("seed", { mnemonic, passphrase: "café" }));
  });

  it("shares the JSON Schema character limit with the seed executor", async () => {
    const tool = registerTools().get("keys_derive_bip39_seed");
    if (!tool) throw new Error("Missing BIP39 seed tool");
    for (const character of ["x", "😀"]) {
      const args = { mnemonic: bip39TestVectors.mnemonic, passphrase: character.repeat(4096) };
      expect(Value.Check(tool.parameters, args)).toBe(true);
      const result = await tool.execute("boundary", args);
      expect(result.content[0]?.text).toMatch(/Seed: [0-9a-f]{128}\n/u);
      const over = { ...args, passphrase: args.passphrase + character };
      expect(Value.Check(tool.parameters, over)).toBe(false);
      await expect(tool.execute("boundary", over)).rejects.toThrow("4096");
    }
  });

  it.each(localizedMnemonicVectors)(
    "derives seeds for the $language list",
    async ({ language, mnemonic }) => {
      const tool = registerTools().get("keys_derive_bip39_seed");
      if (!tool) throw new Error("Missing BIP39 seed tool");
      const result = await tool.execute("seed", { language, mnemonic: mnemonic.normalize("NFC") });
      expect(result).toMatchObject({
        details: { language, seed: Buffer.from(mnemonicToSeed(mnemonic)).toString("hex") },
      });
    },
  );

  it("rejects malformed seed inputs even when the host skips schemas", async () => {
    const tool = registerTools().get("keys_derive_bip39_seed");
    if (!tool) throw new Error("Missing BIP39 seed tool");
    for (const args of [
      { mnemonic: null },
      { mnemonic: " " },
      { mnemonic: "abandon" },
      { mnemonic: "abandon ".repeat(12).trim() },
      { mnemonic: "unknown-secret ".repeat(12).trim() },
      { mnemonic: bip39TestVectors.mnemonic, passphrase: null },
      { mnemonic: bip39TestVectors.mnemonic, language: "unknown-secret" },
      { mnemonic: bip39TestVectors.mnemonic, language: "japanese" },
      { mnemonic: "x".repeat(4097) },
      { mnemonic: bip39TestVectors.mnemonic, passphrase: "x".repeat(4097) },
    ]) {
      const result = tool.execute("invalid", args);
      await expect(result).rejects.toThrow();
      await expect(result).rejects.not.toThrow("unknown-secret");
    }
    expect(
      Value.Check(tool.parameters, { mnemonic: bip39TestVectors.mnemonic, passphrase: null }),
    ).toBe(false);
    expect(
      Value.Check(tool.parameters, {
        mnemonic: bip39TestVectors.mnemonic,
        passphrase: "x".repeat(4097),
      }),
    ).toBe(false);
  });

  it("converts public keys and validates inputs when Pi skips its schema", async () => {
    const tool = registerTools().get("keys_convert_public_key");
    if (!tool) throw new Error("Missing public key conversion tool");
    const { compressed, uncompressed } = publicKeyEncodingVector;
    expect(await tool.execute("compress", { publicKey: uncompressed })).toMatchObject({
      details: { publicKey: compressed, compressed: true },
    });
    expect(
      await tool.execute("decompress", { publicKey: compressed, compressed: false }),
    ).toMatchObject({
      details: { publicKey: uncompressed, compressed: false },
    });
    for (const value of [null, "false", 0, {}]) {
      const args = { publicKey: compressed, compressed: value };
      expect(Value.Check(tool.parameters, args)).toBe(false);
      await expect(tool.execute("invalid", args)).rejects.toThrow("Compressed must be a boolean");
    }
    for (const publicKey of [null, 1, {}, "02" + "ff".repeat(32), "04" + "00".repeat(64)]) {
      await expect(tool.execute("invalid", { publicKey })).rejects.toThrow();
    }
  });

  it.each(localizedMnemonicVectors)(
    "encodes and inspects $language mnemonics through Pi",
    async ({ language, entropy, mnemonic }) => {
      const tools = registerTools();
      const encode = tools.get("keys_encode_bip39_entropy");
      const inspect = tools.get("keys_inspect_mnemonic");
      if (!encode || !inspect) throw new Error("Missing mnemonic tools");
      const encoded = await encode.execute("encode", { entropy, language });
      expect(encoded).toMatchObject({ details: { language, words: 12, mnemonic } });
      expect(encoded.content[0]?.text).toContain(`Language: ${language}`);
      expect(encoded.content[0]?.text).toContain(`Mnemonic: ${mnemonic}`);
      const inspected = await inspect.execute("inspect", {
        mnemonic: mnemonic.normalize("NFC"),
        language,
      });
      expect(inspected).toMatchObject({
        details: {
          language,
          valid: true,
          words: 12,
          entropy,
          wordCountValid: true,
          wordlistValid: true,
          checksumValid: true,
        },
      });
      expect(inspected.content[0]?.text).toContain(`Language: ${language}`);
      expect(inspected.content[0]?.text).not.toContain(mnemonic);
      for (const [tool, args] of [
        [encode, { entropy }],
        [inspect, { mnemonic }],
      ] as const) {
        expect(Value.Check(tool.parameters, { ...args, language })).toBe(true);
      }
    },
  );

  it.each(localizedMnemonicVectors)(
    "generates a $language mnemonic through Pi",
    async ({ language }) => {
      const tools = registerTools();
      const generate = tools.get("keys_generate_mnemonic");
      const inspect = tools.get("keys_inspect_mnemonic");
      if (!generate || !inspect) throw new Error("Missing mnemonic tools");
      expect(Value.Check(generate.parameters, { words: 24, language })).toBe(true);
      const generated = await generate.execute("generate", { words: 24, language });
      const fresh = generated.content[0]?.text?.match(/Mnemonic: ([^\n]+)/u)?.[1];
      if (!fresh) throw new Error("Missing generated mnemonic");
      expect(generated).toMatchObject({ details: { language, words: 24, mnemonic: fresh } });
      expect(generated.content[0]?.text).toContain("Never use it for real funds");
      expect(
        await inspect.execute("inspect-generated", { mnemonic: fresh, language }),
      ).toMatchObject({
        details: { language, valid: true, words: 24 },
      });
    },
  );

  it("rejects unsupported languages even when Pi skips schemas", async () => {
    const tools = registerTools();
    for (const [name, args] of [
      ["keys_generate_mnemonic", {}],
      ["keys_inspect_mnemonic", { mnemonic: localizedMnemonicVectors[8].mnemonic }],
      ["keys_encode_bip39_entropy", { entropy: "00".repeat(16) }],
    ] as const) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`Missing ${name}`);
      for (const language of ["unknown", "constructor", "__proto__", "", null, 42]) {
        expect(Value.Check(tool.parameters, { ...args, language })).toBe(false);
        await expect(tool.execute("invalid", { ...args, language })).rejects.toThrow(
          /BIP39 language/u,
        );
      }
    }
  });

  it("does not guess a language or repair invalid localized phrases", async () => {
    const tool = registerTools().get("keys_inspect_mnemonic");
    if (!tool) throw new Error("Missing inspection tool");
    const { mnemonic } = localizedMnemonicVectors[8];
    for (const args of [
      { mnemonic },
      { mnemonic, language: "french" },
      { mnemonic: mnemonic.replace("abierto", "ábaco"), language: "spanish" },
      { mnemonic: mnemonic.toUpperCase(), language: "spanish" },
      { mnemonic: mnemonic.replaceAll("á", "a"), language: "spanish" },
    ]) {
      const result = await tool.execute("invalid-phrase", args);
      expect(result).toMatchObject({ details: { valid: false, words: 12 } });
      expect(result.content[0]?.text).not.toContain("Entropy:");
      expect(result.content[0]?.text).not.toContain(args.mnemonic);
    }
  });

  it.each([12, 15, 18, 21, 24])(
    "generates a disposable %i-word mnemonic through Pi",
    async (words) => {
      const tool = registerTools().get("keys_generate_mnemonic");
      if (!tool) throw new Error("keys_generate_mnemonic was not registered");
      expect(Value.Check(tool.parameters, { words })).toBe(true);
      const result = await tool.execute("generate", { words });
      const mnemonic = result.content[0]?.text?.match(/Mnemonic: ([a-z ]+)/)?.[1];
      if (!mnemonic) throw new Error("Missing mnemonic");
      expect(validateMnemonic(mnemonic)).toBe(true);
      expect(mnemonic.split(" ")).toHaveLength(words);
      expect(mnemonicToEntropy(mnemonic)).toHaveLength((words / 3) * 4);
      expect(result).toMatchObject({ details: { words, mnemonic } });
      expect(result.content[0]?.text).toContain("Never use it for real funds");
    },
  );

  it("rejects invalid mnemonic lengths even when Pi skips schemas", async () => {
    const tool = registerTools().get("keys_generate_mnemonic");
    if (!tool) throw new Error("keys_generate_mnemonic was not registered");
    for (const words of [0, 11, 13, 25, 12.5, "12", null, true, NaN, Infinity]) {
      expect(Value.Check(tool.parameters, { words })).toBe(false);
      await expect(tool.execute("invalid", { words })).rejects.toThrow(
        "BIP39 word count must be 12, 15, 18, 21, or 24",
      );
    }
  });

  it.each(wifTestVectors)("converts $chain $network WIF through Pi", async (vector) => {
    const tools = registerTools();
    const encode = tools.get("keys_encode_wif");
    const decode = tools.get("keys_decode_wif");
    if (!encode || !decode) throw new Error("WIF tools not registered");
    const { chain, network, compressed, privateKey, wif } = vector;
    const encodeArgs = { chain, network, compressed, privateKey };
    const decodeArgs = { chain, network, wif };
    expect(Value.Check(encode.parameters, encodeArgs)).toBe(true);
    expect(Value.Check(decode.parameters, decodeArgs)).toBe(true);
    expect(await encode.execute("encode-wif", encodeArgs)).toEqual({
      content: [{ type: "text", text: JSON.stringify({ wif, chain, network, compressed }) }],
      details: { wif, chain, network, compressed },
    });
    expect(await decode.execute("decode-wif", decodeArgs)).toEqual({
      content: [{ type: "text", text: JSON.stringify({ privateKey, chain, network, compressed }) }],
      details: { privateKey, chain, network, compressed },
    });
  });

  it("validates WIF inputs even when Pi skips schema validation", async () => {
    const tools = registerTools();
    const encode = tools.get("keys_encode_wif");
    const decode = tools.get("keys_decode_wif");
    if (!encode || !decode) throw new Error("WIF tools not registered");
    const privateKey = wifTestVectors[0].privateKey;
    for (const args of [
      { chain: "ethereum", privateKey },
      { chain: "bitcoin", privateKey: "private-secret" },
      { chain: "bitcoin", privateKey, compressed: "false" },
      { chain: "bitcoin", privateKey, network: "unknown" },
    ]) {
      expect(Value.Check(encode.parameters, args)).toBe(false);
      await expect(encode.execute("invalid", args)).rejects.toThrow();
    }
    await expect(
      encode.execute("invalid", { chain: "decred", privateKey, compressed: false }),
    ).rejects.toThrow("Decred WIF requires");
    await expect(
      decode.execute("invalid", { chain: "bitcoin", wif: "private-secret" }),
    ).rejects.toThrow("Invalid WIF encoding or checksum");
  });

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

  it("derives Stellar through the registered Pi tool", async () => {
    const tool = registerTools().get("keys_derive_wallet");
    if (!tool) throw new Error("keys_derive_wallet was not registered");
    const args = { chain: "stellar", privateKey: stellarTestVectors.privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("stellar", args);
    expect(result.content).toEqual([
      {
        type: "text",
        text: `Public key: ${stellarTestVectors.publicKey}\nAddress: ${stellarTestVectors.address}`,
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
    expect(validResult).toMatchObject({
      details: { valid: true, wordCountValid: true, wordlistValid: true, checksumValid: true },
    });

    const invalidResult = await tool.execute("call-2", {
      mnemonic:
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon wrong",
    });
    const invalidText = invalidResult.content.map((part) => part.text ?? "").join("\n");

    expect(invalidText).toContain("Valid BIP39: no");
    expect(invalidText).toContain("Words: 12");
    expect(invalidText).not.toContain("Entropy:");
    expect(invalidResult).toMatchObject({
      details: { valid: false, wordCountValid: true, wordlistValid: true, checksumValid: false },
    });
    const unknown = await tool.execute("unknown-word", {
      mnemonic: mnemonic.replace("about", "notaword"),
    });
    expect(unknown).toMatchObject({
      details: { valid: false, wordCountValid: true, wordlistValid: false, checksumValid: null },
    });
    expect(unknown.content.map((part) => part.text ?? "").join("\n")).toContain(
      "Checksum valid: not checked",
    );
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

  it("exposes the checksum override and warning in Pi content and details", async () => {
    const tool = registerTools().get("keys_derive_hd_wallet");
    if (!tool) throw new Error("keys_derive_hd_wallet was not registered");
    const { mnemonic, path, address, publicKey } = invalidChecksumPuzzle;
    const args = { chain: "bitcoin", mnemonic, path, allowInvalidChecksum: true };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("puzzle", args);
    const text = result.content.map((part) => part.text ?? "").join("\n");
    expect(text).toContain(address);
    expect(text).toContain("Warning: BIP39 checksum is invalid.");
    expect(text).not.toContain(mnemonic);
    expect(result).toMatchObject({
      details: { address, publicKey, warnings: [expect.stringContaining("checksum is invalid")] },
    });
    await expect(tool.execute("strict", { ...args, allowInvalidChecksum: false })).rejects.toThrow(
      "Invalid BIP39 mnemonic",
    );
    for (const allowInvalidChecksum of ["true", "false", 1, null]) {
      expect(Value.Check(tool.parameters, { ...args, allowInvalidChecksum })).toBe(false);
      await expect(tool.execute("invalid-flag", { ...args, allowInvalidChecksum })).rejects.toThrow(
        "allowInvalidChecksum must be a boolean",
      );
    }
    await expect(
      tool.execute("invalid-words", { ...args, mnemonic: mnemonic.replace("path", "notaword") }),
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
