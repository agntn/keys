#!/usr/bin/env node

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import path from "node:path";

const server = path.resolve(import.meta.dirname, "../dist/cli.mjs");
const transport = new StdioClientTransport({ command: process.execPath, args: [server, "mcp"] });
const client = new Client({ name: "keys-eval", version: "1.0.0" });
const called = new Set();

/**
 * Narrows an unknown value to an array without leaking `any` from `Array.isArray`.
 * @param {unknown} value - Value to inspect.
 * @returns {value is unknown[]} Whether the value is an array.
 */
function isUnknownArray(value) {
  return Array.isArray(value);
}

/**
 * Reads text parts from one MCP result.
 * @param {unknown} response - MCP result to render.
 * @returns {string} Joined text content.
 */
function text(response) {
  if (typeof response !== "object" || response === null || !("content" in response)) return "";
  const { content } = response;
  if (!isUnknownArray(content)) return "";
  return content
    .map((part) =>
      typeof part === "object" &&
      part !== null &&
      "type" in part &&
      part.type === "text" &&
      "text" in part &&
      typeof part.text === "string"
        ? part.text
        : "",
    )
    .join("");
}

/**
 * Calls one tool and verifies its readable answer.
 * @param {string} name - Tool name.
 * @param {Readonly<Record<string, unknown>>} args - Tool arguments.
 * @param {Readonly<RegExp>} expected - Expected answer fragment.
 * @returns {Promise<string>} Tool text.
 */
async function call(name, args, expected) {
  called.add(name);
  const response = await client.callTool({ name, arguments: args }, undefined, { timeout: 10_000 });
  const rendered = text(response);
  if (response.isError === true || !expected.test(rendered)) {
    throw new Error(`${name} failed: ${rendered}`);
  }
  return rendered;
}

await client.connect(transport);

try {
  const listed = await client.listTools();
  if (listed.tools.length !== 13) throw new Error(`Expected 13 tools, got ${listed.tools.length}`);

  const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
  const mnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  const missing =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?";

  await call("keys_generate_wallet", { chain: "bitcoin" }, /Private key: [0-9a-f]{64}/);
  const derived = await call(
    "keys_derive_wallet",
    { chain: "ethereum", privateKey },
    /Address: 0x/,
  );
  const publicKey = /Public key: ([0-9a-f]+)/.exec(derived)?.[1];
  if (!publicKey) throw new Error("keys_derive_wallet returned no public key");

  await call(
    "keys_derive_hd_wallet",
    { chain: "bitcoin", mnemonic, path: "m/84'/0'/0'/0/0" },
    /bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu/,
  );
  await call("keys_inspect_mnemonic", { mnemonic }, /Valid BIP39: yes/);
  await call("keys_encode_bip39_entropy", { entropy: "00".repeat(16) }, /Words: 12/);
  await call("keys_lookup_bip39_indices", { indices: [0, 2047] }, /2047: zoo/);
  await call("keys_lookup_bip39_words", { words: ["skill", "zoo"] }, /zero-based 1619/);
  await call("keys_recover_mnemonic_word", { mnemonic: missing }, /Candidates \(128\):/);
  await call("keys_get_address", { chain: "ethereum", publicKey }, /Address: 0x/);
  await call(
    "keys_validate_address",
    { chain: "bitcoin", address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" },
    /is a valid bitcoin address/,
  );
  const signed = await call(
    "keys_sign_message",
    { chain: "ethereum", message: "disposable MCP test", privateKey },
    /Signature: [0-9a-f]+/,
  );
  const signature = /Signature: ([0-9a-f]+)/.exec(signed)?.[1];
  if (!signature) throw new Error("keys_sign_message returned no signature");
  await call(
    "keys_verify_message",
    { chain: "ethereum", message: "disposable MCP test", signature, publicKey },
    /Signature is valid/,
  );
  await call("keys_bip44_path", { chain: "bitcoin", change: 1 }, /m\/44'\/0'\/0'\/1\/0/);

  const missingCalls = listed.tools.map((tool) => tool.name).filter((name) => !called.has(name));
  if (missingCalls.length > 0) throw new Error(`Tools not exercised: ${missingCalls.join(", ")}`);
  console.log(`MCP stdio eval passed for ${called.size} tools.`);
} finally {
  await client.close();
}
