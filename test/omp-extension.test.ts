import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vite-plus/test";
import { bitcoinSVTestVectors } from "./fixtures.ts";
import ompExtension from "../packages/omp/extensions/keys.ts";
import piExtension from "../packages/pi/extensions/keys.ts";

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
    expect(omp.size).toBe(19);
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
});
