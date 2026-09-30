import { fileURLToPath } from "node:url";
import { createJiti } from "jiti/static";
import { describe, expect, it } from "vite-plus/test";
import {
  bip39TestVectors,
  bitcoinSVTestVectors,
  brainwalletInput,
  brainwalletVectors,
  ethereumTestVectors,
  wifTestVectors,
} from "./fixtures.ts";
import piExtension from "../packages/pi/extensions/keys.ts";
import { TOOL_NAMES } from "../src/tool-parameters.ts";
import { keysTools } from "../src/tools.ts";

/** The OMP package root is TypeScript for Bun; the extension takes only `Text` from it. */
const ompExtension = await createJiti(import.meta.url, {
  alias: {
    "@oh-my-pi/pi-coding-agent": fileURLToPath(new URL("fixtures/omp-host.ts", import.meta.url)),
  },
}).import<(pi: never) => Promise<void>>(
  fileURLToPath(new URL("../packages/omp/extensions/keys.ts", import.meta.url)),
  { default: true },
);

interface RegisteredTool {
  readonly name: string;
  readonly label: string;
  readonly description: string;
  readonly parameters: unknown;
  readonly approval?: string;
  readonly execute: (
    toolCallId: string,
    params: Readonly<Record<string, unknown>>,
  ) => Promise<{ readonly content: unknown; readonly details: unknown }>;
  readonly renderCall?: (args: unknown, options: object, theme: object) => { text?: string };
}

/**
 * Registers an extension on a host whose `Type.Unsafe` returns the JSON Schema, as OMP emits it.
 * @param extension - Extension entry point to register.
 * @returns {Promise<ReadonlyMap<string, RegisteredTool>>} The tools captured from the extension
 */
async function registerTools(
  extension: (pi: never) => void | Promise<void>,
): Promise<ReadonlyMap<string, RegisteredTool>> {
  const tools = new Map<string, RegisteredTool>();
  await extension({
    typebox: { Type: { Unsafe: (schema: unknown) => schema } },
    registerTool(tool: RegisteredTool) {
      tools.set(tool.name, tool);
    },
  } as unknown as never);
  return tools;
}

/** A theme that writes its styling calls into the output. */
const theme = {
  fg: (color: string, text: string) => `${color}(${text})`,
  styledSymbol: (symbol: string, color: string) => `${color}:${symbol}`,
};

describe("keys OMP extension", () => {
  it("registers the tool definitions Pi registers", async () => {
    const omp = await registerTools(ompExtension);
    const pi = await registerTools(piExtension);

    expect([...omp.keys()]).toEqual([...pi.keys()]);
    expect([...omp.keys()]).toEqual(keysTools.map((tool) => tool.name));
    expect(new Set(omp.keys())).toEqual(new Set(TOOL_NAMES));
    for (const definition of keysTools) {
      const tool = omp.get(definition.name);
      expect(tool?.label, definition.name).toBe(pi.get(definition.name)?.label);
      expect(tool?.description, definition.name).toBe(pi.get(definition.name)?.description);
      expect(tool?.parameters, definition.name).toEqual(definition.input);
      expect(tool?.approval, definition.name).toBe(definition.effect);
    }
  });

  it("answers through the shared executors", async () => {
    const params = { chain: "bitcoinsv", publicKey: bitcoinSVTestVectors.keyOne.publicKey };
    const omp = await (
      await registerTools(ompExtension)
    )
      .get("keys_address_get")
      ?.execute("omp", params);
    const pi = await (
      await registerTools(piExtension)
    )
      .get("keys_address_get")
      ?.execute("pi", params);

    expect(omp).toEqual(pi);
    expect(JSON.stringify(omp?.content)).toContain(bitcoinSVTestVectors.keyOne.address);
  });

  it("checks the schema itself, since the host may not", async () => {
    const tool = (await registerTools(ompExtension)).get("keys_address_get");
    await expect(
      tool?.execute("omp", { chain: "ethereum", publicKey: ethereumTestVectors.publicKey, x: 1 }),
    ).rejects.toThrow('Invalid arguments: unknown property "x"');
  });

  it("shows a clean call summary", async () => {
    const tool = (await registerTools(ompExtension)).get("keys_address_validate");
    const line = tool?.renderCall?.(
      { chain: "bitcoin", address: "1abc\u001B[31m\nforged" },
      { isPartial: false },
      theme,
    ).text;
    expect(line).toBe("success:status.done accent(Validate Address): muted(1abc forged)");
  });

  /** OMP drops a blank optional string the schema refuses; the executors read one as omitted. */
  it("takes a blank option as omitted in the executors", async () => {
    const call = async (name: string, params: Readonly<Record<string, unknown>>) =>
      JSON.stringify(
        (await keysTools.find((tool) => tool.name === name)?.execute(params as never, {}))?.content,
      );

    const address = await call("keys_address_get", {
      chain: "ethereum",
      publicKey: ethereumTestVectors.publicKey,
      addressType: "",
      network: " ",
    });
    expect(address).toContain(ethereumTestVectors.address);

    const path = await call("keys_bip44_generate", {
      chain: "bitcoin",
      account: 0,
      change: 0,
      addressIndex: 0,
      addressType: "",
    });
    expect(path).toContain("m/44'/0'/0'/0/0");
    expect(await call("keys_bip44_parse", { path: "m/44'/0'/0'/0/5" })).toContain(
      "Address index: 5",
    );

    const [wif] = wifTestVectors;
    const encoded = await call("keys_wif_encode", {
      chain: wif.chain,
      privateKey: wif.privateKey,
      network: "",
    });
    expect(encoded).toContain(wif.wif);
    const decoded = await call("keys_wif_decode", { chain: wif.chain, wif: wif.wif, network: "" });
    expect(decoded).toContain(wif.privateKey);

    const { mnemonic } = bip39TestVectors;
    const seed = (passphrase: string) => call("keys_bip39_seed_derive", { mnemonic, passphrase });
    expect(await seed("")).not.toBe(await seed(" "));

    const [scrypt, , pbkdf2] = brainwalletVectors;
    const { passphrase, salt } = brainwalletInput;
    const brainwallet = (vector: (typeof brainwalletVectors)[number], filled: object) =>
      call("keys_brainwallet_derive", {
        passphrase,
        salt,
        saltEncoding: "utf8",
        compressed: vector.compressed,
        keyLength: 0,
        network: "",
        target: "",
        ...filled,
        ...vector.recipe,
      });
    expect(await brainwallet(scrypt, { iterations: 0, digest: "" })).toContain(scrypt.address);
    expect(await brainwallet(pbkdf2, { N: 0, r: 0, p: 0 })).toContain(pbkdf2.address);
  });
});
