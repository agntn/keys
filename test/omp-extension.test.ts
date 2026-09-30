import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vite-plus/test";
import {
  bip39TestVectors,
  bitcoinSVTestVectors,
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
    const omp = await registerTools(ompExtension).get("keys_get_address")?.execute("omp", params);
    const pi = await registerTools(piExtension).get("keys_get_address")?.execute("pi", params);

    expect(omp).toEqual(pi);
    expect(JSON.stringify(omp?.content)).toContain(bitcoinSVTestVectors.keyOne.address);
  });

  it("takes the blank options OMP fills in as omitted", async () => {
    const tools = registerTools(ompExtension);
    const call = async (name: string, params: Readonly<Record<string, unknown>>) =>
      JSON.stringify((await tools.get(name)?.execute("omp", params))?.content);

    const address = await call("keys_get_address", {
      chain: "ethereum",
      publicKey: ethereumTestVectors.publicKey,
      addressType: "",
      network: " ",
    });
    expect(address).toContain(ethereumTestVectors.address);

    const path = await call("keys_bip44_path", { chain: "bitcoin", path: "", addressType: "" });
    expect(path).toContain("m/44'/0'/0'/0/0");

    const path5 = "m/44'/0'/0'/0/5";
    for (const params of [
      { chain: "bitcoin", path: path5, account: 0, change: 0, addressIndex: 5, addressType: "" },
      { chain: "", path: path5, account: 0, change: 0, addressIndex: 0, addressType: "" },
    ]) {
      expect(await call("keys_bip44_path", params)).toContain("Address index: 5");
    }

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
    const seed = (passphrase: string) => call("keys_derive_bip39_seed", { mnemonic, passphrase });
    expect(await seed("")).not.toBe(await seed(" "));
  });
});
