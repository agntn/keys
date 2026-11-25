import { invokeTool } from "@agntn/tools";
import { describe, expect, it } from "vite-plus/test";
import { keysTools } from "../src/tools.ts";
import { secp256k1TestVectors } from "./fixtures.ts";

const { privateKey } = secp256k1TestVectors;

/** One valid call for each tool that mints or signs. */
const writes: readonly (readonly [string, Readonly<Record<string, unknown>>])[] = [
  ["keys_wallet_generate", { chain: "bitcoin" }],
  ["keys_bip39_generate", {}],
  ["keys_message_sign", { chain: "bitcoin", message: "hi", privateKey }],
  ["keys_bip322_sign", { message: "hi", privateKey, addressType: "segwit" }],
];

describe("cancelled calls", () => {
  it("covers every write tool", () => {
    const named = keysTools.filter((tool) => tool.effect === "write").map((tool) => tool.name);
    expect([...named].sort()).toEqual(writes.map(([name]) => name).sort());
  });

  it.each(writes)("never runs %s once the call is cancelled", async (name, args) => {
    const tool = keysTools.find((candidate) => candidate.name === name);
    if (!tool) throw new Error(`${name} is missing`);
    const cancel = new AbortController();
    const call = invokeTool(tool, args, { signal: cancel.signal });
    cancel.abort();
    await expect(call).rejects.toMatchObject({ name: "AbortError" });
  });
});
