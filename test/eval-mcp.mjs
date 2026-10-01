#!/usr/bin/env node

import { Client } from "@modelcontextprotocol/client";
import { getDefaultEnvironment, StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import path from "node:path";
import {
  electrumVectors,
  invalidChecksumPuzzle,
  publicKeyEncodingVector,
  bip39TestVectors,
  slip132Vectors,
  bip38Vectors,
  brainwalletInput,
  brainwalletVectors,
} from "./fixtures.ts";
import { TOOL_NAMES } from "../src/tool-parameters.ts";

const server = path.resolve(import.meta.dirname, "../dist/cli.mjs");
/** `KEYS_DIST=1` keeps the bundle; a checkout would otherwise serve the live source. */
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [server, "mcp"],
  env: { ...getDefaultEnvironment(), KEYS_DIST: "1" },
});
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
  if (listed.tools.length !== TOOL_NAMES.length)
    throw new Error(`Expected ${TOOL_NAMES.length} tools, got ${listed.tools.length}`);

  await call(
    "keys_secp256k1_public_key_convert",
    { publicKey: publicKeyEncodingVector.compressed, compressed: false },
    new RegExp(publicKeyEncodingVector.uncompressed),
  );

  await call(
    "keys_brainwallet_derive",
    {
      passphrase: brainwalletInput.passphrase,
      salt: brainwalletInput.salt,
      saltEncoding: "utf8",
      compressed: brainwalletVectors[0].compressed,
      ...brainwalletVectors[0].recipe,
      target: brainwalletVectors[0].address,
    },
    new RegExp(`Address: ${brainwalletVectors[0].address}\nTarget: match`),
  );

  await call(
    "keys_bip38_inspect",
    { encrypted: bip38Vectors[3].encrypted, address: bip38Vectors[3].address },
    /"lot":263183,"sequence":1,"addressMatches":true/,
  );

  await call(
    "keys_xpub_wallet_derive",
    { chain: "bitcoin", extendedKey: slip132Vectors[2].extendedKey, path: "m/0/0" },
    new RegExp(
      `Address type: segwit\\nPublic key: [0-9a-f]{66}\\nAddress: ${slip132Vectors[2].address}`,
    ),
  );

  await call(
    "keys_electrum_wallet_derive",
    {
      mnemonic: electrumVectors[0].mnemonic,
      path: electrumVectors[0].path,
    },
    new RegExp(electrumVectors[0].address),
  );

  const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
  const mnemonic =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
  await call(
    "keys_bip39_seed_derive",
    { mnemonic, passphrase: bip39TestVectors.passphrase },
    new RegExp(bip39TestVectors.seedWithPassphrase),
  );
  const missing =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?";

  for (const chain of ["bitcoin", "litecoin", "decred"]) {
    for (const network of ["mainnet", "testnet"]) {
      const encoded = await call("keys_wif_encode", { chain, network, privateKey }, /"wif":/);
      const wif = /"wif":"([1-9A-HJ-NP-Za-km-z]+)"/.exec(encoded)?.[1];
      if (!wif) throw new Error("keys_wif_encode returned no WIF");
      await call("keys_wif_decode", { chain, network, wif }, new RegExp(privateKey));
    }
  }

  await call("keys_wallet_generate", { chain: "bitcoin" }, /Private key: [0-9a-f]{64}/);
  const derived = await call(
    "keys_wallet_derive",
    { chain: "ethereum", privateKey },
    /Address: 0x/,
  );
  const publicKey = /Public key: ([0-9a-f]+)/.exec(derived)?.[1];
  if (!publicKey) throw new Error("keys_wallet_derive returned no public key");

  await call(
    "keys_hd_wallet_derive",
    { chain: "bitcoin", mnemonic, path: "m/84'/0'/0'/0/0" },
    /bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu/,
  );
  await call(
    "keys_hd_wallet_derive",
    {
      chain: "bitcoin",
      mnemonic: "abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abete",
      path: "m/44'/0'/0'/0/0",
      language: "italian",
    },
    /16sisK5QAu6e1GHBLLEmZAHGQ9uj9He8SY/,
  );
  const generated = await call("keys_bip39_generate", { words: 24 }, /Words: 24/);
  const generatedMnemonic = /Mnemonic: ([a-z ]+)/.exec(generated)?.[1];
  if (!generatedMnemonic) throw new Error("keys_bip39_generate returned no mnemonic");
  await call("keys_bip39_inspect", { mnemonic: generatedMnemonic }, /Valid BIP39: yes/);
  const puzzleArgs = {
    chain: "bitcoin",
    mnemonic: invalidChecksumPuzzle.mnemonic,
    path: invalidChecksumPuzzle.path,
  };
  const strictPuzzle = await client.callTool({
    name: "keys_hd_wallet_derive",
    arguments: puzzleArgs,
  });
  if (strictPuzzle.isError !== true || !text(strictPuzzle).includes("Invalid BIP39 mnemonic")) {
    throw new Error("Invalid puzzle checksum must be rejected by default");
  }
  const puzzleWallet = await call(
    "keys_hd_wallet_derive",
    { ...puzzleArgs, allowInvalidChecksum: true },
    /Warning: BIP39 checksum is invalid\./,
  );
  if (
    !puzzleWallet.includes(invalidChecksumPuzzle.address) ||
    !puzzleWallet.includes(invalidChecksumPuzzle.publicKey)
  ) {
    throw new Error("Puzzle derivation did not reproduce the published wallet");
  }
  if (puzzleWallet.includes(invalidChecksumPuzzle.mnemonic)) {
    throw new Error("Puzzle derivation echoed the mnemonic");
  }
  await call("keys_bip39_inspect", { mnemonic }, /Valid BIP39: yes/);
  await call("keys_bip39_entropy_encode", { entropy: "00".repeat(16) }, /Words: 12/);
  for (const name of ["keys_bip39_generate", "keys_bip39_entropy_encode"]) {
    const args = name === "keys_bip39_generate" ? { words: 15 } : { entropy: "00".repeat(20) };
    const result = await call(name, { ...args, language: "japanese" }, /Words: 15/);
    const localized = /Mnemonic: ([^\n]+)/u.exec(result)?.[1];
    if (!localized || localized.split("\u3000").length !== 15) {
      throw new Error(`${name} did not return 15 Japanese words`);
    }
    await call(
      "keys_bip39_inspect",
      { mnemonic: localized, language: "japanese" },
      /Valid BIP39: yes/,
    );
  }
  await call("keys_bip39_indices_lookup", { indices: [0, 2047] }, /2047: zoo/);
  await call(
    "keys_bip39_words_lookup",
    { words: ["skill", "zoo"] },
    /^Language: english\nIndices: zero-based, one-based\nskill: 1619, 1620\nzoo: 2047, 2048$/,
  );
  await call("keys_bip39_word_recover", { mnemonic: missing }, /Candidates \(128\):/);
  await call(
    "keys_bip39_word_recover",
    {
      mnemonic: "abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco ?",
      language: "italian",
    },
    /Candidates \(128\): abete,/,
  );
  await call("keys_address_get", { chain: "ethereum", publicKey }, /Address: 0x/);
  await call(
    "keys_address_validate",
    { chain: "bitcoin", address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" },
    /is a valid bitcoin address/,
  );
  const signed = await call(
    "keys_message_sign",
    { chain: "ethereum", message: "disposable MCP test", privateKey },
    /Signature: [0-9a-f]+/,
  );
  const signature = /Signature: ([0-9a-f]+)/.exec(signed)?.[1];
  if (!signature) throw new Error("keys_message_sign returned no signature");
  await call(
    "keys_message_verify",
    { chain: "ethereum", message: "disposable MCP test", signature, publicKey },
    /Signature is valid/,
  );
  await call("keys_bip44_parse", { path: "m/44h/60h/0h/0/3" }, /Address index: 3$/m);
  await call("keys_bip44_generate", { chain: "bitcoin", change: 1 }, /m\/44'\/0'\/0'\/1\/0/);
  await call("keys_bip44_generate", { chain: "solana" }, /Path: m\/44'\/501'\/0'\/0'$/m);
  await call(
    "keys_bip44_generate",
    { chain: "sui", addressType: "secp256k1" },
    /Path: m\/54'\/784'\/0'\/0\/0$/m,
  );

  const missingCalls = listed.tools.map((tool) => tool.name).filter((name) => !called.has(name));
  if (missingCalls.length > 0) throw new Error(`Tools not exercised: ${missingCalls.join(", ")}`);
  console.log(`MCP stdio eval passed for ${called.size} tools.`);
} finally {
  await client.close();
}
