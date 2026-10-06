import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createJiti } from "jiti/static";
import type { TSchema } from "typebox";
import { Value } from "typebox/value";
import { describe, expect, it } from "vite-plus/test";
import {
  bip32ParentVector,
  hdScanVectors,
  bip39TestVectors,
  bip39WordOrderVector,
  bip39WordRepairVectors,
  electrumVectors,
  publicKeyEncodingVector,
  secp256k1MathVectors,
  litecoinTestVectors,
  bitcoinCashTestVectors,
  bitcoinGoldTestVectors,
  bitcoinSVTestVectors,
  dashTestVectors,
  zcashTestVectors,
  eCashTestVectors,
  xrplTestVectors,
  dogecoinTestVectors,
  decredTestVectors,
  stellarTestVectors,
  wifTestVectors,
  localizedMnemonicVectors,
  invalidChecksumPuzzle,
  ed25519TestVectors,
  ethereumTestVectors,
  secp256k1TestVectors,
  slip132Vectors,
  bip38Vectors,
  brainwalletInput,
  brainwalletVectors,
  storeVectors,
  reusedNonceVector,
  transactionVectors,
  descriptorVectors,
  multisigVector,
} from "./fixtures.ts";
import keysExtension from "../packages/pi/extensions/keys.ts";
import { keysTools } from "../src/tools.ts";
import { mnemonicToSeed, mnemonicToEntropy, validateMnemonic } from "../src/utils/bip39/index.ts";

interface RegisteredTool {
  readonly name: string;
  readonly parameters: TSchema;
  readonly execute: (
    toolCallId: string,
    params: Readonly<Record<string, unknown>>,
  ) => Promise<{
    readonly content: ReadonlyArray<{ readonly type: string; readonly text?: string }>;
    readonly details: unknown;
  }>;
}

/**
 * SAFETY: the extension only calls registerTool during registration.
 * @returns {Promise<ReadonlyMap<string, RegisteredTool>>} The tools captured from the extension
 */
async function registerTools(): Promise<ReadonlyMap<string, RegisteredTool>> {
  const tools = new Map<string, RegisteredTool>();
  const api = {
    registerTool(tool: RegisteredTool) {
      tools.set(tool.name, tool);
    },
  } as unknown as ExtensionAPI;

  await keysExtension(api);
  return tools;
}

/**
 * The tool's executor without the schema check in front of it, to prove its own guards.
 * @param tool - A registered tool.
 * @returns {RegisteredTool["execute"]} The executor, called like `execute`.
 */
function skipSchema(tool: RegisteredTool): RegisteredTool["execute"] {
  const definition = keysTools.find((candidate) => candidate.name === tool.name);
  if (!definition) throw new Error(`${tool.name} has no definition`);
  return async (_toolCallId, params) => await definition.execute(params as never, {});
}

describe("keys Pi extension", () => {
  it("summarizes a call on one clean line", async () => {
    interface RenderedTool {
      readonly name: string;
      readonly renderCall?: (args: unknown) => { render(width: number): string[] };
    }
    const pi = new Map<string, RenderedTool>();
    await keysExtension({
      registerTool(tool: RenderedTool) {
        pi.set(tool.name, tool);
      },
    } as unknown as ExtensionAPI);
    const render = (name: string, args: unknown) =>
      pi.get(name)?.renderCall?.(args).render(200).join("").trim();

    expect(render("keys_address_validate", { address: "1abc\u001B[31m\u2028forged" })).toBe(
      "Validate Address: 1abc forged",
    );
    expect(render("keys_wallet_generate", { chain: "bitcoin" })).toBe("Generate Wallet: bitcoin");
    expect(render("keys_bip39_seed_derive", { mnemonic: "secret words" })).toBe(
      "Derive BIP39 Seed",
    );
  });

  it("derives an Electrum wallet with the shared executor", async () => {
    const tool = (await registerTools()).get("keys_electrum_wallet_derive");
    if (!tool) throw new Error("Missing Electrum wallet tool");
    const vector = electrumVectors[0];
    const args = { mnemonic: vector.mnemonic, path: vector.path };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("electrum", args);
    expect(result).toMatchObject({
      details: { scheme: "electrum", seedType: "segwit", address: vector.address },
    });
    expect(JSON.stringify(result)).not.toContain(vector.mnemonic);
    await expect(tool.execute("electrum", { ...args, passphrase: false })).rejects.toThrow();
  });
  it("derives a watch-only wallet from an xpub with the shared executor", async () => {
    const tool = (await registerTools()).get("keys_xpub_wallet_derive");
    if (!tool) throw new Error("Missing xpub wallet tool");
    const [, ypub] = slip132Vectors;
    const args = { chain: "bitcoin", extendedKey: ypub.extendedKey, path: "m/0/0" };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { ...args, path: "m/0'/0" })).toBe(false);
    await expect(tool.execute("xpub", args)).resolves.toMatchObject({
      details: { prefix: "ypub", addressType: "p2sh", address: ypub.address },
    });
    await expect(skipSchema(tool)("xpub", { ...args, path: "m/0'/0" })).rejects.toThrow(
      "hardened levels need the private key",
    );
  });
  it("scans wallet paths with the shared executor and checks its arguments without the schema", async () => {
    const tool = (await registerTools()).get("keys_hd_wallet_scan");
    if (!tool) throw new Error("Missing wallet scan tool");
    const { mnemonic, address, path } = hdScanVectors.puzzle;
    const args = { chain: "bitcoin", mnemonic, address };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { ...args, indices: 0.5 })).toBe(false);
    await expect(tool.execute("scan", args)).resolves.toMatchObject({
      details: { found: true, checked: 1, match: { scheme: "bip44", path, address } },
    });
    for (const [bad, message] of [
      [{ ...args, accounts: 11 }, "accounts must be an integer between 1 and 10"],
      [{ ...args, indices: 0.5 }, "indices must be an integer between 1 and 100"],
      [{ ...args, allowInvalidChecksum: "yes" }, "allowInvalidChecksum must be a boolean"],
      [{ ...args, mnemonic: "a ".repeat(2049) }, "Mnemonic must not exceed 4096 characters"],
      [{ ...args, mnemonic: "   " }, "Mnemonic must not be empty"],
      [{ ...args, address: "1".repeat(257) }, "Address must be 1 to 256 characters"],
      [{ ...args, passphrase: 7 }, "Passphrase must be a string"],
    ] as const) {
      await expect(skipSchema(tool)("scan", bad)).rejects.toThrow(message);
    }
  });
  it("recovers a BIP32 parent with the shared executor and checks its arguments without the schema", async () => {
    const tool = (await registerTools()).get("keys_bip32_parent_recover");
    if (!tool) throw new Error("Missing BIP32 parent tool");
    const { xpub, xprv, fingerprint, child } = bip32ParentVector;
    const args = { extendedKey: xpub, child: child.privateKey, index: 0 };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { ...args, index: 0.5 })).toBe(false);
    const result = await tool.execute("parent", args);
    expect(result).toMatchObject({ details: { recovered: true, fingerprint } });
    expect(JSON.stringify(result)).not.toContain(xprv);
    await expect(tool.execute("parent", { ...args, revealKey: true })).resolves.toMatchObject({
      details: { extendedPrivateKey: xprv },
    });
    for (const [bad, message] of [
      [{ ...args, revealKey: "yes" }, "revealKey must be a boolean"],
      [{ ...args, index: 0.5 }, "Index must be an integer between 0 and 2147483647"],
      [{ ...args, child: "z".repeat(129) }, "Child key is too long"],
      [{ ...args, extendedKey: "x".repeat(129) }, "Extended key is too long"],
    ] as const) {
      await expect(skipSchema(tool)("parent", bad)).rejects.toThrow(message);
    }
  });
  it("computes secp256k1 points with the shared executor and checks its arguments without the schema", async () => {
    const tool = (await registerTools()).get("keys_secp256k1_point_compute");
    if (!tool) throw new Error("Missing secp256k1 point tool");
    const { g, twoG } = secp256k1MathVectors;
    const args = { operation: "add", point: g, other: g };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { ...args, operation: "double" })).toBe(false);
    await expect(tool.execute("point", args)).resolves.toMatchObject({
      details: { operation: "add", point: twoG },
    });
    for (const [bad, message] of [
      [{ ...args, operation: "double" }, "operation must be one of"],
      [{ ...args, other: 2 }, "other must be a string"],
      [{ ...args, compressed: "no" }, "Compressed must be a boolean"],
      [{ ...args, x: g.slice(2) }, "add does not take x"],
      [{ operation: "lift", x: `0x${g.slice(4)}` }, "x must be 64 hex digits"],
      [{ operation: "multiply", point: g, scalar: "0x03" }, "Scalar must be hex"],
    ] as const) {
      await expect(skipSchema(tool)("point", bad)).rejects.toThrow(message);
    }
  });
  it("computes on a curve the caller defines and checks its arguments without the schema", async () => {
    const tool = (await registerTools()).get("keys_curve_compute");
    if (!tool) throw new Error("Missing curve tool");
    const args = { operation: "double", a: "2", b: "2", p: "17", point: { x: "5", y: "1" } };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { ...args, point: { x: "5", y: "1", z: "1" } })).toBe(
      false,
    );
    await expect(tool.execute("curve", args)).resolves.toMatchObject({
      details: { operation: "double", point: { x: "6", y: "3" } },
    });
    for (const [bad, message] of [
      [{ ...args, operation: "subtract" }, "operation must be one of"],
      [{ ...args, p: 17 }, "p must be a string"],
      [{ ...args, a: "1e3" }, "a must be an integer"],
      [{ ...args, a: "9".repeat(161) }, "a must be an integer"],
      [{ ...args, point: [5, 1] }, "point must be an object with x and y"],
      [{ ...args, point: { x: "5", y: "1", z: "1" } }, "point takes only x and y"],
      [{ ...args, point: { x: "5" } }, "point.y must be a string"],
      [{ ...args, scalar: "2" }, "double does not take scalar"],
      [{ ...args, operation: "points", point: undefined, limit: 1001 }, "limit must be"],
      [{ ...args, operation: "points", point: undefined, limit: 0.5 }, "limit must be"],
      [{ ...args, operation: "points", point: undefined, limit: -5 }, "limit must be"],
      [{ ...args, operation: "points", point: undefined, limit: 0 }, "limit must be"],
    ] as const) {
      await expect(skipSchema(tool)("curve", bad)).rejects.toThrow(message);
    }
    await expect(
      skipSchema(tool)("curve", { ...args, operation: "points", point: undefined }),
    ).resolves.toMatchObject({ details: { total: "18", truncated: false } });
  });
  it("checks the nonce and transaction arguments without the schema", async () => {
    const tools = await registerTools();
    const nonce = tools.get("keys_secp256k1_nonce_recover");
    const extract = tools.get("keys_transaction_signatures_extract");
    if (!nonce || !extract) throw new Error("Missing nonce or transaction tool");
    const { r, first, second } = reusedNonceVector;
    const signatures = [
      { r, ...first },
      { r, ...second },
    ];
    await expect(skipSchema(nonce)("nonce", { signatures, type: "" })).resolves.toMatchObject({
      details: { type: "ecdsa" },
    });
    for (const [bad, message] of [
      [{ signatures: [signatures[0]] }, "signatures must be an array of 2 items"],
      [{ signatures: [signatures[0], { ...second, r, k: "1" }] }, "takes only r, s, z"],
      [{ signatures: [signatures[0], { ...second, r: "0x1" }] }, "signatures[1].r must be"],
      [{ signatures, type: "dsa" }, "type must be one of ecdsa, schnorr"],
      [{ signatures, publicKey: "zz" }, "Public key must be SEC1 or x-only hex"],
    ] as const) {
      await expect(skipSchema(nonce)("nonce", bad)).rejects.toThrow(message);
    }
    const { transaction, spent } = transactionVectors.reusedNonce2012;
    await expect(extract.execute("tx", { transaction, index: 0, spent })).resolves.toMatchObject({
      details: { index: 0, signatures: [{ r: transactionVectors.reusedNonce2012.r }] },
    });
    for (const [bad, message] of [
      [{ transaction: "0x", index: 0, spent }, "Transaction must be hex without 0x"],
      [{ transaction, index: -1, spent }, "Index must be an integer between 0 and 2999"],
      [{ transaction, index: 0, spent: [] }, "spent must be an array of 1 to 3000 items"],
      [
        { transaction, index: 0, spent: [{ script: "zz", value: 1 }] },
        "spent[0].script must be hex",
      ],
      [{ transaction, index: 0, spent: [{ script: "", value: 1.5 }] }, "spent[0].value must be"],
      [
        {
          transaction,
          index: 0,
          spent: Array.from({ length: 21 }, () => ({ script: "ab".repeat(10_000), value: 1 })),
        },
        "spent scripts together take at most 400000 hex digits",
      ],
      [
        { transaction, index: 0, spent: [{ script: "", value: 1, x: 1 }] },
        "takes only script, value",
      ],
    ] as const) {
      await expect(skipSchema(extract)("tx", bad)).rejects.toThrow(message);
    }
  });
  it("checks the script and descriptor arguments without the schema", async () => {
    const tools = await registerTools();
    const script = tools.get("keys_script_address_get");
    const descriptor = tools.get("keys_descriptor_derive");
    if (!script || !descriptor) throw new Error("Missing script or descriptor tool");
    const { keys } = multisigVector;
    await expect(
      skipSchema(script)("script", { script: "", threshold: 2, publicKeys: keys }),
    ).resolves.toMatchObject({ details: { addresses: { p2wsh: multisigVector.mainnet.p2wsh } } });
    for (const [bad, message] of [
      [{ script: "0x51" }, "Script must be hex without 0x"],
      [{ script: "5".repeat(20_002) }, "at most 20000 digits"],
      [{ threshold: 1, publicKeys: [...keys, "02"] }, "publicKeys must be 1 to 20"],
      [{ threshold: 1, publicKeys: Array.from({ length: 21 }, () => keys[0]) }, "1 to 20"],
      [{ threshold: 1.5, publicKeys: keys }, "threshold must be an integer from 1 to 2"],
      [{ threshold: 1, publicKeys: keys, sorted: "yes" }, "sorted must be a boolean"],
      [{ threshold: 1, publicKeys: keys, network: "regtest" }, "Unsupported network"],
    ] as const) {
      await expect(skipSchema(script)("script", bad)).rejects.toThrow(message);
    }
    const ranged = descriptorVectors.core[3];
    for (const [bad, message] of [
      [{ descriptor: "" }, "Descriptor must be 1 to 16384 characters"],
      [{ descriptor: "x".repeat(16_385) }, "Descriptor must be 1 to 16384 characters"],
      [{ descriptor: ranged.descriptor, count: 0 }, "count must be an integer from 1 to 100"],
      [{ descriptor: ranged.descriptor, index: -1 }, "index must be an integer between 0"],
    ] as const) {
      await expect(skipSchema(descriptor)("descriptor", bad)).rejects.toThrow(message);
    }
  });
  it("derives disposable BIP39 seeds without echoing the input", async () => {
    const tool = (await registerTools()).get("keys_bip39_seed_derive");
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
    const tool = (await registerTools()).get("keys_bip39_seed_derive");
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
      const tool = (await registerTools()).get("keys_bip39_seed_derive");
      if (!tool) throw new Error("Missing BIP39 seed tool");
      const result = await tool.execute("seed", { language, mnemonic: mnemonic.normalize("NFC") });
      expect(result).toMatchObject({
        details: { language, seed: Buffer.from(mnemonicToSeed(mnemonic)).toString("hex") },
      });
    },
  );

  it("rejects malformed seed inputs even when the host skips schemas", async () => {
    const tool = (await registerTools()).get("keys_bip39_seed_derive");
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
    const tool = (await registerTools()).get("keys_secp256k1_public_key_convert");
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
      await expect(skipSchema(tool)("invalid", args)).rejects.toThrow(
        "Compressed must be a boolean",
      );
      await expect(tool.execute("invalid", args)).rejects.toThrow(
        "Invalid arguments at /compressed",
      );
    }
    for (const publicKey of [null, 1, {}, "02" + "ff".repeat(32), "04" + "00".repeat(64)]) {
      await expect(tool.execute("invalid", { publicKey })).rejects.toThrow();
    }
  });

  it.each(localizedMnemonicVectors)(
    "encodes and inspects $language mnemonics through Pi",
    async ({ language, entropy, mnemonic }) => {
      const tools = await registerTools();
      const encode = tools.get("keys_bip39_entropy_encode");
      const inspect = tools.get("keys_bip39_inspect");
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
      const tools = await registerTools();
      const generate = tools.get("keys_bip39_generate");
      const inspect = tools.get("keys_bip39_inspect");
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
    const tools = await registerTools();
    for (const [name, args] of [
      ["keys_bip39_generate", {}],
      ["keys_bip39_inspect", { mnemonic: localizedMnemonicVectors[8].mnemonic }],
      ["keys_bip39_entropy_encode", { entropy: "00".repeat(16) }],
    ] as const) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`Missing ${name}`);
      for (const language of ["unknown", "constructor", "__proto__", "", null, 42]) {
        expect(Value.Check(tool.parameters, { ...args, language })).toBe(false);
        await expect(skipSchema(tool)("invalid", { ...args, language })).rejects.toThrow(
          /BIP39 language/u,
        );
      }
    }
  });

  it("does not guess a language or repair invalid localized phrases", async () => {
    const tool = (await registerTools()).get("keys_bip39_inspect");
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
      const tool = (await registerTools()).get("keys_bip39_generate");
      if (!tool) throw new Error("keys_bip39_generate was not registered");
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
    const tool = (await registerTools()).get("keys_bip39_generate");
    if (!tool) throw new Error("keys_bip39_generate was not registered");
    for (const words of [0, 11, 13, 25, 12.5, "12", null, true, NaN, Infinity]) {
      expect(Value.Check(tool.parameters, { words })).toBe(false);
      await expect(skipSchema(tool)("invalid", { words })).rejects.toThrow(
        "BIP39 word count must be 12, 15, 18, 21, or 24",
      );
    }
  });

  it.each(wifTestVectors)("converts $chain $network WIF through Pi", async (vector) => {
    const tools = await registerTools();
    const encode = tools.get("keys_wif_encode");
    const decode = tools.get("keys_wif_decode");
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

  it("derives a brainwallet with the shared executor and keeps its private key out", async () => {
    const tool = (await registerTools()).get("keys_brainwallet_derive");
    if (!tool) throw new Error("Missing brainwallet tool");
    const [vector] = brainwalletVectors;
    const { passphrase, salt } = brainwalletInput;
    const args = { passphrase, salt, saltEncoding: "utf8", compressed: false, ...vector.recipe };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { ...args, N: 1024.5 })).toBe(false);
    const result = await tool.execute("brainwallet", { ...args, target: vector.address });
    expect(result.details).toEqual({
      chain: "bitcoin",
      network: "mainnet",
      addressType: "legacy",
      compressed: false,
      publicKey: vector.publicKey,
      address: vector.address,
      matches: true,
    });
    expect(JSON.stringify(result)).not.toContain(vector.privateKey);
    await expect(skipSchema(tool)("brainwallet", { ...args, N: 1024.5 })).rejects.toThrow(
      "N must be an integer from 2 to 1048576",
    );
  });

  it("opens a keystore with the shared executor and keeps its private key out", async () => {
    const tool = (await registerTools()).get("keys_store_decrypt");
    if (!tool) throw new Error("Missing keystore tool");
    const { keystore, password, privateKey, publicKey, address } = storeVectors[2];
    const args = { keystore: JSON.stringify(keystore), password };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("store", args);
    expect(result.details).toEqual({
      version: 3,
      id: keystore.id,
      kdf: { kdf: "scrypt", n: 2, r: 8, p: 1, dklen: 32 },
      unlocked: true,
      chain: "ethereum",
      publicKey,
      address,
    });
    expect(JSON.stringify(result)).not.toContain(privateKey.slice(4));
    await expect(skipSchema(tool)("store", { ...args, password: 42 })).rejects.toThrow(
      "Password must be a string",
    );
  });

  it("reads a BIP38 header with the shared executor", async () => {
    const tool = (await registerTools()).get("keys_bip38_inspect");
    if (!tool) throw new Error("Missing BIP38 tool");
    const { encrypted, address, inspection } = bip38Vectors[2];
    const args = { encrypted, address };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { encrypted, address: "" })).toBe(false);
    await expect(tool.execute("bip38", args)).resolves.toMatchObject({
      details: { ...inspection, addressMatches: true },
    });
    await expect(skipSchema(tool)("bip38", { encrypted, address: "" })).resolves.toEqual({
      content: [{ type: "text", text: JSON.stringify(inspection) }],
      details: inspection,
    });
    await expect(skipSchema(tool)("bip38", { encrypted: 42 })).rejects.toThrow(
      "BIP38 key must be a string",
    );
    const longAddress = { encrypted, address: "1".repeat(129) };
    expect(Value.Check(tool.parameters, longAddress)).toBe(false);
    await expect(skipSchema(tool)("bip38", longAddress)).rejects.toThrow(
      "Address must not exceed 128 characters",
    );
  });

  it("opens a BIP38 key with the shared executor and checks revealKey without the schema", async () => {
    const tool = (await registerTools()).get("keys_bip38_decrypt");
    if (!tool) throw new Error("Missing BIP38 decrypt tool");
    const { encrypted, passphrase, wif, address } = bip38Vectors[2];
    expect(Value.Check(tool.parameters, { encrypted, passphrase })).toBe(true);
    expect(Value.Check(tool.parameters, { encrypted, passphrase, revealKey: "yes" })).toBe(false);
    await expect(tool.execute("bip38", { encrypted, passphrase })).resolves.toMatchObject({
      details: { mode: "ec-multiply", unlocked: true, chain: "bitcoin", address },
    });
    await expect(
      tool.execute("bip38", { encrypted, passphrase, revealKey: true }),
    ).resolves.toMatchObject({ details: { wif } });
    await expect(
      skipSchema(tool)("bip38", { encrypted, passphrase, revealKey: "yes" }),
    ).rejects.toThrow("revealKey must be a boolean");
    const longPassphrase = { encrypted, passphrase: "x".repeat(4097) };
    expect(Value.Check(tool.parameters, longPassphrase)).toBe(false);
    await expect(skipSchema(tool)("bip38", longPassphrase)).rejects.toThrow(
      "Passphrase must not exceed 4096 characters",
    );
  }, 30_000);

  it("refuses an overlong address even when Pi skips the schema", async () => {
    const tool = (await registerTools()).get("keys_address_validate");
    if (!tool) throw new Error("Missing address validation tool");
    const longest = { chain: "bitcoin", address: "1".repeat(256) };
    const longer = { chain: "bitcoin", address: "1".repeat(257) };
    expect(Value.Check(tool.parameters, longest)).toBe(true);
    expect(Value.Check(tool.parameters, longer)).toBe(false);
    await expect(tool.execute("validate", longest)).resolves.toMatchObject({
      details: { valid: false },
    });
    await expect(skipSchema(tool)("validate", longer)).rejects.toThrow(
      "Address must not exceed 256 characters",
    );
  });

  it("validates WIF inputs even when Pi skips schema validation", async () => {
    const tools = await registerTools();
    const encode = tools.get("keys_wif_encode");
    const decode = tools.get("keys_wif_decode");
    if (!encode || !decode) throw new Error("WIF tools not registered");
    const privateKey = wifTestVectors[0].privateKey;
    for (const args of [
      { chain: "ethereum", privateKey },
      { chain: "bitcoin", privateKey: "private-secret" },
      { chain: "bitcoin", privateKey, compressed: "false" },
      { chain: "bitcoin", privateKey, network: "unknown" },
    ]) {
      expect(Value.Check(encode.parameters, args)).toBe(false);
      await expect(skipSchema(encode)("invalid", args)).rejects.toThrow();
    }
    await expect(
      skipSchema(encode)("invalid", { chain: "decred", privateKey, compressed: false }),
    ).rejects.toThrow("Decred WIF requires");
    await expect(
      skipSchema(decode)("invalid", { chain: "bitcoin", wif: "private-secret" }),
    ).rejects.toThrow("Invalid WIF encoding or checksum");
  });

  it("derives Litecoin through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
    const args = { chain: "litecoin", privateKey: litecoinTestVectors.privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("litecoin", args);
    expect(result.content).toEqual([
      {
        type: "text",
        text: `Address type: legacy\nPublic key: ${litecoinTestVectors.publicKey}\nAddress: ${litecoinTestVectors.address}`,
      },
    ]);
  });

  it("derives Bitcoin Cash through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
    const { privateKey, address } = bitcoinCashTestVectors.keyOne;
    const args = { chain: "bitcoincash", privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("bitcoincash", args);
    expect(result.content).toEqual([
      {
        type: "text",
        text: `Public key: ${bitcoinCashTestVectors.keyOne.publicKey}\nAddress: ${address}`,
      },
    ]);
  });

  it("derives Bitcoin Gold through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
    const { privateKey, publicKey, legacyAddress } = bitcoinGoldTestVectors.signed;
    const args = { chain: "bitcoingold", privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("bitcoingold", args);
    expect(result.content).toEqual([
      {
        type: "text",
        text: `Address type: legacy\nPublic key: ${publicKey}\nAddress: ${legacyAddress}`,
      },
    ]);
  });

  it("derives Bitcoin SV through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
    const { privateKey, publicKey, address } = bitcoinSVTestVectors.keyOne;
    const args = { chain: "bitcoinsv", privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("bitcoinsv", args);
    expect(result.content).toEqual([
      { type: "text", text: `Public key: ${publicKey}\nAddress: ${address}` },
    ]);
  });

  it("derives Dogecoin through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
    const [key] = dogecoinTestVectors.keys;
    const args = { chain: "dogecoin", privateKey: key.privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("dogecoin", args);
    expect(JSON.stringify(result.content)).toContain(`Address: ${key.addressCompressed}`);
  });

  it("derives Dash through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
    const [key] = dashTestVectors.keys;
    const args = { chain: "dash", privateKey: key.privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("dash", args);
    expect(JSON.stringify(result.content)).toContain(`Address: ${key.addressCompressed}`);
  });

  it("derives Zcash through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
    const [key] = zcashTestVectors.keys;
    const args = { chain: "zcash", privateKey: key.privateKey };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("zcash", args);
    expect(JSON.stringify(result.content)).toContain(`Address: ${key.addressCompressed}`);
  });

  it("derives eCash through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_hd_wallet_derive");
    if (!tool) throw new Error("keys_hd_wallet_derive was not registered");
    const [path, address] = eCashTestVectors.hd.mainnet;
    const args = { chain: "ecash", mnemonic: bip39TestVectors.mnemonic, path };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("ecash", args);
    expect(JSON.stringify(result.content)).toContain(`Address: ${address}`);
  });

  it("derives XRPL from a family seed through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
    const { seed, address } = xrplTestVectors.seeds.ed25519;
    const args = { chain: "xrpl", privateKey: seed };
    expect(Value.Check(tool.parameters, args)).toBe(true);
    const result = await tool.execute("xrpl", args);
    expect(JSON.stringify(result.content)).toContain(`Address: ${address}`);
    expect(JSON.stringify(result.content)).toContain("Address type: ed25519");
  });

  it("derives Decred through the registered Pi tool", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
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
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");
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

  it("rejects 0x hex in the executor when the host skips the schema", async () => {
    const tools = await registerTools();
    const [message, , signature] = ethereumTestVectors.messages[1];
    const { privateKey, publicKey } = ethereumTestVectors;

    for (const [name, params, error] of [
      [
        "keys_message_verify",
        { chain: "ethereum", message, signature: `0x${signature}`, publicKey },
        "Signature must be 64 or 65 bytes of hex, or DER on xrpl, without 0x",
      ],
      [
        "keys_message_verify",
        { chain: "ethereum", message, signature, publicKey: `0x${publicKey}` },
        "Public key must be",
      ],
      [
        "keys_message_sign",
        { chain: "ethereum", message, privateKey: `0x${privateKey}` },
        "Private key must be 64 hex characters without 0x",
      ],
      ["keys_wallet_derive", { chain: "ethereum", privateKey: `0x${privateKey}` }, "Private key"],
      ["keys_address_get", { chain: "ethereum", publicKey: `0x${publicKey}` }, "Public key"],
    ] as const) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`${name} was not registered`);

      const rejection = skipSchema(tool)("prefixed-hex", params);
      await expect(rejection).rejects.toThrow(error);
      await expect(rejection).rejects.not.toThrow(privateKey);
    }
  });

  it("rejects unsupported networks and address types on every relevant tool", async () => {
    const tools = await registerTools();
    const networkCases = [
      ["keys_wallet_generate", { chain: "bitcoin" }],
      ["keys_wallet_derive", { chain: "ethereum", privateKey: secp256k1TestVectors.privateKey }],
      ["keys_hd_wallet_derive", { chain: "base", mnemonic: "unused", path: "m/0" }],
      ["keys_address_get", { chain: "solana", publicKey: ed25519TestVectors.publicKey }],
      ["keys_address_validate", { chain: "aptos", address: "unused" }],
      [
        "keys_message_sign",
        { chain: "tron", message: "unused", privateKey: secp256k1TestVectors.privateKey },
      ],
      [
        "keys_message_verify",
        {
          chain: "sui",
          message: "unused",
          signature: "00".repeat(64),
          publicKey: ed25519TestVectors.publicKey,
        },
      ],
    ] as const;

    for (const [name, params] of networkCases) {
      const tool = tools.get(name);
      if (!tool) throw new Error(`${name} was not registered`);
      const invalidParams = { ...params, network: "testnett" };

      expect(Value.Check(tool.parameters, invalidParams)).toBe(false);
      await expect(skipSchema(tool)("invalid-network", invalidParams)).rejects.toThrow(
        'Unsupported network "testnett"',
      );
    }

    const addressTypeCases = [
      ["keys_wallet_generate", { chain: "bitcoin", addressType: "stake" }],
      [
        "keys_wallet_derive",
        { chain: "ethereum", privateKey: secp256k1TestVectors.privateKey, addressType: "segwit" },
      ],
      [
        "keys_hd_wallet_derive",
        { chain: "base", mnemonic: "unused", path: "m/0", addressType: "segwit" },
      ],
      [
        "keys_address_get",
        { chain: "solana", publicKey: ed25519TestVectors.publicKey, addressType: "segwit" },
      ],
      ["keys_wallet_generate", { chain: "aptos", addressType: "segwit" }],
      [
        "keys_wallet_derive",
        { chain: "tron", privateKey: secp256k1TestVectors.privateKey, addressType: "segwit" },
      ],
      [
        "keys_hd_wallet_derive",
        { chain: "sui", mnemonic: "unused", path: "m/0", addressType: "taproot" },
      ],
      [
        "keys_address_get",
        { chain: "cardano", publicKey: ed25519TestVectors.publicKey, addressType: "secp256k1" },
      ],
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
    const tool = (await registerTools()).get("keys_bip39_indices_lookup");
    if (!tool) throw new Error("keys_bip39_indices_lookup was not registered");

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
    const tool = (await registerTools()).get("keys_bip39_words_lookup");
    if (!tool) throw new Error("keys_bip39_words_lookup was not registered");

    const result = await tool.execute("call-1", {
      words: ["abandon", "Skill", "zoo", "eleven", "abandon"],
    });
    const text = result.content.map((part) => part.text ?? "").join("\n");

    expect(text).toBe(
      "Language: english\nIndices: zero-based, one-based\nabandon: 0, 1\nskill: 1619, 1620\nzoo: 2047, 2048\neleven: not in BIP39\nabandon: 0, 1",
    );
    expect(result.details).toEqual({
      language: "english",
      lookups: [
        { word: "abandon", zeroBasedIndex: 0, oneBasedIndex: 1 },
        { word: "skill", zeroBasedIndex: 1619, oneBasedIndex: 1620 },
        { word: "zoo", zeroBasedIndex: 2047, oneBasedIndex: 2048 },
        { word: "eleven", zeroBasedIndex: null, oneBasedIndex: null },
        { word: "abandon", zeroBasedIndex: 0, oneBasedIndex: 1 },
      ],
    });
    expect(tool.parameters).toMatchObject({
      properties: { words: { items: { pattern: "^\\S+$" } } },
    });
    expect(Value.Check(tool.parameters, { words: ["skill"] })).toBe(true);
    expect(Value.Check(tool.parameters, { words: [] })).toBe(false);
    expect(Value.Check(tool.parameters, { words: ["two words"] })).toBe(false);
    const tooManyWords = Array.from({ length: 101 }, () => "zoo");
    expect(Value.Check(tool.parameters, { words: tooManyWords })).toBe(false);
    await expect(skipSchema(tool)("call-2", { words: "skill" })).rejects.toThrow(
      "must be an array",
    );
    await expect(skipSchema(tool)("call-3", { words: tooManyWords })).rejects.toThrow(
      "Provide between 1 and 100 words",
    );
    await expect(skipSchema(tool)("call-4", { words: ["two words"] })).rejects.toThrow(
      "must contain letters and combining marks only",
    );
  });

  it("looks up words from an explicit BIP39 language", async () => {
    const tool = (await registerTools()).get("keys_bip39_words_lookup");
    if (!tool) throw new Error("keys_bip39_words_lookup was not registered");

    const result = await tool.execute("call-1", {
      words: ["orologio", "civetta"],
      language: "italian",
    });
    const text = result.content.map((part) => part.text ?? "").join("\n");

    expect(text).toBe(
      "Language: italian\nIndices: zero-based, one-based\norologio: 1178, 1179\ncivetta: 361, 362",
    );
    expect(result.details).toEqual({
      language: "italian",
      lookups: [
        { word: "orologio", zeroBasedIndex: 1178, oneBasedIndex: 1179 },
        { word: "civetta", zeroBasedIndex: 361, oneBasedIndex: 362 },
      ],
    });
    expect(Value.Check(tool.parameters, { words: ["orologio"], language: "italian" })).toBe(true);
    expect(Value.Check(tool.parameters, { words: ["あいこくしん"], language: "japanese" })).toBe(
      true,
    );
    expect(Value.Check(tool.parameters, { words: ["orologio"], language: "unknown" })).toBe(false);
    await expect(
      skipSchema(tool)("call-2", { words: ["orologio"], language: "unknown" }),
    ).rejects.toThrow("Unknown BIP39 language");
  });

  it("lists every word an abbreviation starts in the lookup details", async () => {
    const tool = (await registerTools()).get("keys_bip39_words_lookup");
    if (!tool) throw new Error("keys_bip39_words_lookup was not registered");

    const result = await tool.execute("call-1", { words: ["orol", "ab"], language: "italian" });
    expect(result.details).toEqual({
      language: "italian",
      lookups: [
        {
          word: "orol",
          zeroBasedIndex: null,
          oneBasedIndex: null,
          prefixOf: [{ word: "orologio", zeroBasedIndex: 1178, oneBasedIndex: 1179 }],
        },
        { word: "ab", zeroBasedIndex: null, oneBasedIndex: null },
      ],
    });
  });

  it("orders scattered words with the shared executor and checks its arguments without the schema", async () => {
    const tool = (await registerTools()).get("keys_bip39_words_order");
    if (!tool) throw new Error("keys_bip39_words_order was not registered");
    const { template, words, orders, valid, first, mnemonic } = bip39WordOrderVector;
    const args = { words, template };

    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { ...args, limit: 101 })).toBe(false);
    expect(Value.Check(tool.parameters, { ...args, words: [] })).toBe(false);
    const result = await tool.execute("order", { ...args, limit: 100 });
    expect(result.details).toMatchObject({ language: "english", checked: orders, valid });
    expect(result.details).toHaveProperty("orders", expect.arrayContaining([first, mnemonic]));
    await expect(skipSchema(tool)("order", { ...args, template: " " })).rejects.toThrow(
      "A mnemonic must have 12, 15, 18, 21, or 24 words",
    );
    for (const [bad, message] of [
      [{ ...args, words: "yellow" }, "BIP39 words must be an array of strings"],
      [{ ...args, words: [] }, "Provide between 1 and 24 words"],
      [{ ...args, words: ["two words"] }, "must contain letters and combining marks only"],
      [{ ...args, template: 12 }, "Template must be a string"],
      [
        { ...args, template: `${template} `.repeat(100) },
        "Template must be at most 1024 characters",
      ],
      [{ ...args, limit: 0 }, "Limit must be an integer between 1 and 100"],
      [{ ...args, limit: 1.5 }, "Limit must be an integer between 1 and 100"],
      [{ ...args, language: "latin" }, "Unknown BIP39 language"],
    ] as const) {
      await expect(skipSchema(tool)("order", bad)).rejects.toThrow(message);
    }
  });

  it("repairs mistyped words with the shared executor and checks its arguments without the schema", async () => {
    const tool = (await registerTools()).get("keys_bip39_words_repair");
    if (!tool) throw new Error("keys_bip39_words_repair was not registered");
    const { written, mnemonic, combinations, valid } = bip39WordRepairVectors.twoWords;
    const args = { mnemonic: written };

    expect(Value.Check(tool.parameters, args)).toBe(true);
    expect(Value.Check(tool.parameters, { ...args, maxDistance: 4 })).toBe(false);
    expect(Value.Check(tool.parameters, { ...args, limit: 101 })).toBe(false);
    const result = await tool.execute("repair", { ...args, maxDistance: 1 });
    expect(result.details).toEqual({
      language: "english",
      maxDistance: 1,
      positions: [
        { position: 2, suggestions: [{ word: "winner", distance: 1 }] },
        {
          position: 12,
          suggestions: [
            { word: "below", distance: 1 },
            { word: "yellow", distance: 1 },
          ],
        },
      ],
      checked: 2,
      valid: 1,
      repairs: [{ mnemonic, distance: 2 }],
    });
    const wide = await tool.execute("repair", { ...args, limit: 100 });
    expect(wide.details).toMatchObject({ checked: combinations, valid });
    for (const [bad, message] of [
      [{ mnemonic: 12 }, "BIP39 mnemonic must be a string"],
      [{ mnemonic: "   " }, "BIP39 mnemonic must not be empty"],
      [{ mnemonic: `${written} `.repeat(20) }, "BIP39 mnemonic must be at most 1024 characters"],
      [{ mnemonic: "winnr yelow" }, "A mnemonic must have 12, 15, 18, 21, or 24 words"],
      [{ ...args, maxDistance: 0 }, "maxDistance must be an integer between 1 and 3"],
      [{ ...args, maxDistance: 1.5 }, "maxDistance must be an integer between 1 and 3"],
      [{ ...args, limit: 0 }, "Limit must be an integer between 1 and 100"],
      [{ ...args, language: "latin" }, "Unknown BIP39 language"],
    ] as const) {
      await expect(skipSchema(tool)("repair", bad)).rejects.toThrow(message);
    }
  });

  it("lists words compatible with the checksum for one missing mnemonic position", async () => {
    const tool = (await registerTools()).get("keys_bip39_word_recover");
    if (!tool) throw new Error("keys_bip39_word_recover was not registered");

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
    const tool = (await registerTools()).get("keys_bip39_inspect");
    if (!tool) throw new Error("keys_bip39_inspect was not registered");

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
    const tool = (await registerTools()).get("keys_bip39_entropy_encode");
    if (!tool) throw new Error("keys_bip39_entropy_encode was not registered");

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
    await expect(skipSchema(tool)("call-2", { entropy: "00".repeat(15) })).rejects.toThrow(
      "16, 20, 24, 28, or 32 bytes",
    );
    await expect(skipSchema(tool)("call-3", { entropy: "gg".repeat(16) })).rejects.toThrow(
      "must be a hexadecimal string",
    );
  });

  it("derives an HD wallet from a public mnemonic and path", async () => {
    const tool = (await registerTools()).get("keys_hd_wallet_derive");
    if (!tool) throw new Error("keys_hd_wallet_derive was not registered");
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
      skipSchema(tool)("call-3", { chain: "bitcoin", mnemonic, path: "m/84H/0" }),
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
    const tool = (await registerTools()).get("keys_hd_wallet_derive");
    if (!tool) throw new Error("keys_hd_wallet_derive was not registered");
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
      await expect(
        skipSchema(tool)("invalid-flag", { ...args, allowInvalidChecksum }),
      ).rejects.toThrow("allowInvalidChecksum must be a boolean");
    }
    await expect(
      tool.execute("invalid-words", { ...args, mnemonic: mnemonic.replace("path", "notaword") }),
    ).rejects.toThrow("Invalid BIP39 mnemonic");
  });

  it("parses a BIP44 path and refuses anything else", async () => {
    const tool = (await registerTools()).get("keys_bip44_parse");
    if (!tool) throw new Error("keys_bip44_parse was not registered");

    const parsed = await tool.execute("parse", { path: "m/44h/1h/2h/1/7" });
    expect(parsed.content.map((part) => part.text ?? "").join("\n")).toContain(
      "Coin type: 1\nAccount: 2\nChange: 1\nAddress index: 7",
    );
    expect(parsed.details).toEqual({
      path: "m/44h/1h/2h/1/7",
      purpose: 44,
      coinType: 1,
      account: 2,
      change: 1,
      addressIndex: 7,
    });

    for (const [params, message] of [
      [{ path: "m/not/a/path" }, 'Invalid BIP44 path: "m/not/a/path"'],
      [{ path: "m/84'/0'/0'/0/0" }, "Invalid BIP44 path"],
      [{}, "BIP44 path must be a string"],
    ] as const) {
      await expect(skipSchema(tool)("rejected", params)).rejects.toThrow(message);
    }
  });

  it("generates a chain's path with the indices defaulting to 0", async () => {
    const tool = (await registerTools()).get("keys_bip44_generate");
    if (!tool) throw new Error("keys_bip44_generate was not registered");

    const generated = await tool.execute("generate", { chain: "bitcoin" });
    expect(generated.details).toEqual({
      path: "m/44'/0'/0'/0/0",
      chain: "bitcoin",
      coinType: 0,
      account: 0,
      change: 0,
      addressIndex: 0,
    });
    const internal = await tool.execute("internal", { chain: "ethereum", account: 2, change: 1 });
    expect(internal.content.map((part) => part.text ?? "").join("\n")).toContain(
      "Path: m/44'/60'/2'/1/0",
    );
    await expect(skipSchema(tool)("no-chain", {})).rejects.toThrow("Chain must be a string");
  });

  it("derives a Sui wallet from an existing private key", async () => {
    const tool = (await registerTools()).get("keys_wallet_derive");
    if (!tool) throw new Error("keys_wallet_derive was not registered");

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

/**
 * Registers the tools the way the Pi host does: through jiti with the module cache off, so every
 * module is evaluated once per importer and two overlapping imports of a shared module re-enter it.
 * SAFETY: the extension only calls registerTool during registration.
 * @returns {Promise<ReadonlyMap<string, RegisteredTool>>} The tools captured from the extension
 */
async function registerThroughHostLoader(): Promise<ReadonlyMap<string, RegisteredTool>> {
  const jiti = createJiti(import.meta.url, { moduleCache: false });
  const extension = await jiti.import<typeof keysExtension>(
    fileURLToPath(new URL("../packages/pi/extensions/keys.ts", import.meta.url)),
    { default: true },
  );
  const tools = new Map<string, RegisteredTool>();
  await extension({
    registerTool(tool: RegisteredTool) {
      tools.set(tool.name, tool);
    },
  } as unknown as ExtensionAPI);
  return tools;
}

describe("Pi host loader", () => {
  it("answers parallel calls on chains that share modules", async () => {
    const calls = [
      ["keys_address_validate", { chain: "bitcoin", address: invalidChecksumPuzzle.address }],
      [
        "keys_hd_wallet_derive",
        { chain: "bitcoin", mnemonic: bip39TestVectors.mnemonic, path: "m/84'/0'/0'/0/0" },
      ],
      ["keys_address_get", { chain: "litecoin", publicKey: litecoinTestVectors.publicKey }],
    ] as const;
    const hosted = await registerThroughHostLoader();
    const direct = await registerTools();

    const answers = await Promise.all(
      calls.map(async ([name, params]) => {
        const tool = hosted.get(name);
        if (!tool) throw new Error(`Missing ${name}`);
        return (await tool.execute("parallel", params)).content;
      }),
    );

    for (const [index, [name, params]] of calls.entries()) {
      const expected = await direct.get(name)?.execute("direct", params);
      expect(answers[index], name).toEqual(expected?.content);
    }
    expect(answers[2]?.[0]?.text).toContain(litecoinTestVectors.address);
  }, 30_000);
});
