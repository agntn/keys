import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { describe, expect, it } from "vitest";
import keysExtension from "../packages/pi/extensions/keys.ts";

interface RegisteredTool {
  readonly name: string;
  readonly execute: (
    toolCallId: string,
    params: Readonly<{
      chain: string;
      privateKey: string;
      addressType?: string;
    }>,
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
