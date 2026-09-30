import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vite-plus/test";
import {
  bip39TestVectors,
  bitcoinSVTestVectors,
  brainwalletInput,
  brainwalletVectors,
  ethereumTestVectors,
  wifTestVectors,
} from "./fixtures.ts";
import ompExtension from "../packages/omp/extensions/keys.ts";
import piExtension from "../packages/pi/extensions/keys.ts";
import { TOOL_NAMES } from "../src/tool-parameters.ts";

interface RegisteredTool {
  readonly name: string;
  readonly label: string;
  readonly description: string;
  readonly parameters: unknown;
  readonly execute: (
    toolCallId: string,
    params: Readonly<Record<string, unknown>>,
  ) => Promise<{ readonly content: unknown; readonly details: unknown }>;
}

/**
 * SAFETY: both extensions only call registerTool during registration.
 * @param extension - Extension entry point to register.
 * @returns {ReadonlyMap<string, RegisteredTool>} The tools captured from the extension
 */
function registerTools(extension: (pi: ExtensionAPI) => void): ReadonlyMap<string, RegisteredTool> {
  const tools = new Map<string, RegisteredTool>();
  extension({
    registerTool(tool: RegisteredTool) {
      tools.set(tool.name, tool);
    },
  } as unknown as ExtensionAPI);
  return tools;
}

describe("keys OMP extension", () => {
  it("registers the same tools, descriptions and schemas as Pi", () => {
    const omp = registerTools(ompExtension);
    const pi = registerTools(piExtension);

    expect([...omp.keys()]).toEqual([...pi.keys()]);
    expect(new Set(omp.keys())).toEqual(new Set(TOOL_NAMES));
    for (const [name, tool] of omp) {
      const expected = pi.get(name);
      expect(tool.label, name).toBe(expected?.label);
      expect(tool.description, name).toBe(expected?.description);
      expect(tool.parameters, name).toBe(expected?.parameters);
    }
  });

  it("answers through the shared executors", async () => {
    const params = { chain: "bitcoinsv", publicKey: bitcoinSVTestVectors.keyOne.publicKey };
    const omp = await registerTools(ompExtension).get("keys_address_get")?.execute("omp", params);
    const pi = await registerTools(piExtension).get("keys_address_get")?.execute("pi", params);

    expect(omp).toEqual(pi);
    expect(JSON.stringify(omp?.content)).toContain(bitcoinSVTestVectors.keyOne.address);
  });

  it("takes the blank options OMP fills in as omitted", async () => {
    const tools = registerTools(ompExtension);
    const call = async (name: string, params: Readonly<Record<string, unknown>>) =>
      JSON.stringify((await tools.get(name)?.execute("omp", params))?.content);

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
