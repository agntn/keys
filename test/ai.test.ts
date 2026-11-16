import { generateText, isStepCount } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { describe, expect, it } from "vite-plus/test";
import { keysAiTools } from "../src/ai.ts";
import { callTool } from "../src/mcp.ts";
import { keysTools } from "../src/tools.ts";
import { bitcoinTestVectors } from "./fixtures.ts";

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: undefined, cacheWrite: undefined },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};

/**
 * A model that makes one tool call with the given input, then says it's done.
 * @param toolName - The tool it calls.
 * @param input - The arguments it sends.
 * @returns {MockLanguageModelV4} The scripted model.
 */
function scriptedModel(
  toolName: string,
  input: Readonly<Record<string, unknown>>,
): MockLanguageModelV4 {
  return new MockLanguageModelV4({
    doGenerate: [
      {
        content: [
          { type: "tool-call", toolCallId: "call-0", toolName, input: JSON.stringify(input) },
        ],
        finishReason: { unified: "tool-calls", raw: undefined },
        usage,
        warnings: [],
      },
      {
        content: [{ type: "text", text: "done" }],
        finishReason: { unified: "stop", raw: undefined },
        usage,
        warnings: [],
      },
    ],
  });
}

/**
 * One scripted call through `generateText`: the first step's parts and what the model read back.
 * @param toolName - The tool the model calls.
 * @param input - The arguments it sends.
 * @param approval - The caller's `toolApproval`, if any.
 * @returns {Promise<{ parts: readonly { type: string }[]; reply: unknown }>} The parts and the reply.
 */
async function callThroughModel(
  toolName: string,
  input: Readonly<Record<string, unknown>>,
  approval?: Readonly<Record<string, "approved">>,
): Promise<{ parts: readonly { type: string }[]; reply: unknown }> {
  const model = scriptedModel(toolName, input);
  const result = await generateText({
    model,
    tools: keysAiTools,
    ...(approval ? { toolApproval: approval } : {}),
    stopWhen: isStepCount(2),
    prompt: "check this address",
  });
  const reply = (model.doGenerateCalls[1]?.prompt ?? [])
    .flatMap((message) => (message.role === "tool" ? message.content : []))
    .find((part) => part.type === "tool-result")?.output;
  return { parts: result.steps[0]?.content ?? [], reply };
}

/**
 * The text of the first block `callTool` answers with.
 * @param name - The tool to call.
 * @param args - Its arguments.
 * @returns {Promise<string>} The text, or nothing when the block isn't text.
 */
async function mcpText(name: string, args: Readonly<Record<string, unknown>>): Promise<string> {
  const [block] = (await callTool(name, args)).content;
  return block?.type === "text" ? block.text : "";
}

const address = { chain: "bitcoin", address: bitcoinTestVectors.addresses.p2pkh.mainnet };

describe("@agntn/keys/ai", () => {
  it("keys every tool by the name MCP, Pi and OMP use", () => {
    expect(Object.keys(keysAiTools)).toEqual(keysTools.map((tool) => tool.name));
  });

  it("asks before exactly the tools that mint or sign", () => {
    const asking = Object.entries(keysAiTools)
      .filter(([, tool]) => tool.needsApproval === true)
      .map(([name]) => name)
      .sort();
    expect(asking).toEqual([
      "keys_bip322_sign",
      "keys_bip39_generate",
      "keys_message_sign",
      "keys_wallet_generate",
    ]);
  });

  it("gives the model the text the MCP server answers with", async () => {
    const { parts, reply } = await callThroughModel("keys_address_validate", address);
    const mcp = await mcpText("keys_address_validate", address);

    expect(mcp).toContain("is a valid bitcoin address");
    expect(parts[1]).toMatchObject({ type: "tool-result", output: { text: mcp } });
    expect(reply).toEqual({ type: "text", value: mcp });
  });

  it("holds a mnemonic back until someone approves it", async () => {
    const { parts } = await callThroughModel("keys_bip39_generate", {});
    expect(parts.map((part) => part.type)).toEqual(["tool-call", "tool-approval-request"]);
  });

  it("generates it once the caller's toolApproval says yes", async () => {
    const { parts } = await callThroughModel(
      "keys_bip39_generate",
      { words: 12 },
      { keys_bip39_generate: "approved" },
    );
    expect(parts.map((part) => part.type)).toEqual([
      "tool-call",
      "tool-approval-request",
      "tool-approval-response",
      "tool-result",
    ]);
    const { mnemonic, text } = (parts[3] as { output: { mnemonic: string; text: string } }).output;
    expect(mnemonic.split(" ")).toHaveLength(12);
    expect(text).toContain("saved in the transcript");
  });

  it("turns an input the schema refuses into a tool error, not a throw", async () => {
    const { parts } = await callThroughModel("keys_address_validate", { chain: "bitcoin" });
    expect(parts[1]).toMatchObject({ type: "tool-error" });
  });
});
