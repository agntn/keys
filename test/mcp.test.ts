import { readFileSync } from "node:fs";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { afterEach, describe, expect, it } from "vite-plus/test";
import { base64, hex } from "@scure/base";
import { HDKey } from "@scure/bip32";
import { mnemonicToSeedSync } from "@scure/bip39";
import {
  bip137MessageVectors,
  bip39TestVectors,
  bitcoinMessageVectors,
  bitcoinTestVectors,
  electrumOldVectors,
  electrumVectors,
  ethereumTestVectors,
  evmRecoverTestVectors,
  tronTestVectors,
  publicKeyEncodingVector,
  litecoinTestVectors,
  bitcoinCashTestVectors,
  bitcoinGoldTestVectors,
  bitcoinSVTestVectors,
  dashTestVectors,
  zcashTestVectors,
  eCashTestVectors,
  dogecoinTestVectors,
  decredTestVectors,
  stellarTestVectors,
  wifTestVectors,
  localizedMnemonicVectors,
  bip39EntropyWalletVector,
  invalidChecksumPuzzle,
  slip132PrivateKey,
  secp256k1TestVectors,
  slip132Vectors,
  bip38Vectors,
  brainwalletInput,
  brainwalletVectors,
  plainBrainwalletVectors,
  warpWalletVectors,
  storeVectors,
} from "./fixtures.ts";
import Bitcoin from "../src/blockchains/bitcoin.ts";
import { callTool, createMcpServer, toolListings } from "../src/mcp.ts";
import { TOOL_NAMES } from "../src/tool-parameters.ts";
import { decode as decodeWIF } from "../src/utils/wif/index.ts";

const openConnections: Array<{ close(): Promise<void> }> = [];

async function connectTestClient(): Promise<Client> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createMcpServer();
  const client = new Client({ name: "keys-test", version: "1.0.0" });
  openConnections.push(client, server);
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)]);
  return client;
}

function text(content: unknown): string {
  return (content as Array<{ type: string; text?: string }>)
    .map((item) => (item.type === "text" ? (item.text ?? "") : ""))
    .join("");
}

afterEach(async () => {
  await Promise.all(openConnections.splice(0).map((connection) => connection.close()));
});

describe("keys MCP server", () => {
  it.each([1, 12, 24, 100])("labels both indices once for a %i-word lookup", async (size) => {
    const client = await connectTestClient();
    const words = Array.from({ length: size }, (_, index) => (index % 2 === 0 ? "ZOO" : "eleven"));
    const result = await client.callTool({
      name: "keys_bip39_words_lookup",
      arguments: { words },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content).split("\n")).toEqual([
      "Language: english",
      "Indices: zero-based, one-based",
      ...Array.from({ length: size }, (_, index) =>
        index % 2 === 0 ? "zoo: 2047, 2048" : "eleven: not in BIP39",
      ),
    ]);
  });

  it("derives an explicitly selected Electrum wallet through MCP", async () => {
    const client = await connectTestClient();
    const vector = electrumVectors[0];
    const result = await client.callTool({
      name: "keys_electrum_wallet_derive",
      arguments: { mnemonic: vector.mnemonic, path: vector.path },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content)).toContain(vector.address);
    expect(text(result.content)).toContain("Scheme: electrum");
    expect(text(result.content)).not.toContain(vector.mnemonic);
    for (const args of [
      { mnemonic: "secret-phrase", path: vector.path },
      { mnemonic: vector.mnemonic, path: vector.path, passphrase: false },
    ]) {
      const failed = await client.callTool({
        name: "keys_electrum_wallet_derive",
        arguments: args,
      });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).not.toContain("secret-phrase");
    }
  });
  it("derives an old Electrum seed by change and index through MCP", async () => {
    const client = await connectTestClient();
    const [vector] = electrumOldVectors;
    const child = vector.children[1];
    const result = await client.callTool({
      name: "keys_electrum_wallet_derive",
      arguments: { mnemonic: vector.mnemonic, change: child.change, index: child.index },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content)).toBe(
      [
        "Scheme: electrum",
        "Seed type: old",
        "Chain: bitcoin (mainnet)",
        `Master public key: ${vector.masterPublicKey}`,
        `Change: ${child.change}`,
        `Index: ${child.index}`,
        `Public key: ${child.publicKey}`,
        `Address: ${child.address}`,
      ].join("\n"),
    );
    for (const [args, message] of [
      [{ mnemonic: vector.mnemonic, change: 2 }, "change"],
      [{ mnemonic: vector.mnemonic, path: "m/0/0" }, "Old Electrum seeds have no BIP32 path"],
    ] as const) {
      const failed = await client.callTool({
        name: "keys_electrum_wallet_derive",
        arguments: args,
      });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).toContain(message);
      expect(text(failed.content)).not.toContain(vector.mnemonic);
    }
  });

  it("derives a BIP39 seed through MCP", async () => {
    const client = await connectTestClient();
    const result = await client.callTool({
      name: "keys_bip39_seed_derive",
      arguments: { mnemonic: bip39TestVectors.mnemonic },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content)).toContain(bip39TestVectors.seed);
  });

  it("rejects invalid seed inputs without echoing secrets through MCP", async () => {
    const client = await connectTestClient();
    for (const args of [
      { mnemonic: "abandon ".repeat(12).trim() },
      { mnemonic: "unknown-secret" },
      { mnemonic: bip39TestVectors.mnemonic, passphrase: false },
      { mnemonic: bip39TestVectors.mnemonic, language: "unknown-secret" },
      { mnemonic: bip39TestVectors.mnemonic, extra: "unknown-secret" },
    ]) {
      const result = await client.callTool({ name: "keys_bip39_seed_derive", arguments: args });
      expect(result.isError).toBe(true);
      expect(text(result.content)).not.toContain("unknown-secret");
    }
  });

  it("names the BIP39 check a seed input fails through MCP", async () => {
    const client = await connectTestClient();
    for (const [args, reason] of [
      [{ mnemonic: "abandon ".repeat(12).trim() }, "the checksum does not match"],
      [
        { mnemonic: bip39TestVectors.mnemonic, language: "french" },
        "word 12 is not in the french list",
      ],
    ] as const) {
      const result = await client.callTool({ name: "keys_bip39_seed_derive", arguments: args });
      expect(result.isError).toBe(true);
      expect(text(result.content)).toContain(`Invalid BIP39 mnemonic: ${reason}`);
      expect(text(result.content)).not.toContain("allowInvalidChecksum");
    }
  });

  it("converts public keys through MCP and rejects invalid points", async () => {
    const client = await connectTestClient();
    const { compressed, uncompressed } = publicKeyEncodingVector;
    for (const [publicKey, flag, expected] of [
      [compressed, false, uncompressed],
      [uncompressed, true, compressed],
    ] as const) {
      const result = await client.callTool({
        name: "keys_secp256k1_public_key_convert",
        arguments: { publicKey, compressed: flag },
      });
      expect(result.isError).not.toBe(true);
      expect(JSON.parse(text(result.content))).toEqual({ publicKey: expected, compressed: flag });
    }
    for (const args of [
      { publicKey: "02" + "ff".repeat(32) },
      { publicKey: compressed, compressed: "false" },
      { publicKey: compressed, chain: "bitcoin" },
    ]) {
      const result = await client.callTool({
        name: "keys_secp256k1_public_key_convert",
        arguments: args,
      });
      expect(result.isError).toBe(true);
    }
  });

  it("encodes and inspects localized mnemonics through MCP", async () => {
    const client = await connectTestClient();
    for (const { language, entropy, mnemonic } of localizedMnemonicVectors) {
      const encoded = await client.callTool({
        name: "keys_bip39_entropy_encode",
        arguments: { language, entropy },
      });
      expect(encoded.isError).not.toBe(true);
      expect(text(encoded.content)).toContain(`Language: ${language}`);
      expect(text(encoded.content)).toContain(`Mnemonic: ${mnemonic}`);
      const inspected = await client.callTool({
        name: "keys_bip39_inspect",
        arguments: { language, mnemonic },
      });
      expect(inspected.isError).not.toBe(true);
      expect(text(inspected.content)).toContain(`Language: ${language}`);
      expect(text(inspected.content)).toContain(`Entropy: ${entropy}`);
      expect(text(inspected.content)).toContain("Word count valid: yes");
      expect(text(inspected.content)).toContain("Wordlist valid: yes");
      expect(text(inspected.content)).toContain("Checksum valid: yes");
    }
    const generated = await client.callTool({
      name: "keys_bip39_generate",
      arguments: { language: "japanese", words: 15 },
    });
    expect(generated.isError).not.toBe(true);
    const mnemonic = /Mnemonic: ([^\n]+)/u.exec(text(generated.content))?.[1];
    expect(mnemonic?.split("\u3000")).toHaveLength(15);
    const inspected = await client.callTool({
      name: "keys_bip39_inspect",
      arguments: { language: "japanese", mnemonic },
    });
    expect(text(inspected.content)).toContain("Valid BIP39: yes");
    for (const [name, args] of [
      ["keys_bip39_generate", {}],
      ["keys_bip39_inspect", { mnemonic }],
      ["keys_bip39_entropy_encode", { entropy: "00".repeat(16) }],
    ] as const) {
      const result = await client.callTool({
        name,
        arguments: { ...args, language: "unsupported-secret" },
      });
      expect(result.isError).toBe(true);
      expect(text(result.content)).not.toContain("unsupported-secret");
    }
  });

  it("generates fresh mnemonics with a default length through MCP", async () => {
    const client = await connectTestClient();
    const mnemonics: string[] = [];
    for (const args of [{}, {}, { words: 24 }]) {
      const result = await client.callTool({ name: "keys_bip39_generate", arguments: args });
      expect(result.isError).not.toBe(true);
      const mnemonic = /Mnemonic: ([a-z ]+)/.exec(text(result.content))?.[1];
      if (!mnemonic) throw new Error("Missing mnemonic");
      expect(mnemonic.split(" ")).toHaveLength(args.words ?? 12);
      expect(text(result.content)).toContain("Never use it for real funds");
      const inspected = await client.callTool({
        name: "keys_bip39_inspect",
        arguments: { mnemonic },
      });
      expect(text(inspected.content)).toContain("Valid BIP39: yes");
      mnemonics.push(mnemonic);
    }
    expect(new Set(mnemonics).size).toBe(3);
    const listed = await client.listTools();
    expect(
      listed.tools.find((tool) => tool.name === "keys_bip39_generate")?.annotations,
    ).toMatchObject({ readOnlyHint: false, idempotentHint: false, openWorldHint: false });
    for (const args of [{ words: 13 }, { words: "12" }, { words: null }, { extra: true }]) {
      const result = await client.callTool({ name: "keys_bip39_generate", arguments: args });
      expect(result.isError).toBe(true);
    }
  });

  it.each(wifTestVectors)("converts $chain $network WIF through MCP", async (vector) => {
    const client = await connectTestClient();
    const { chain, network, compressed, privateKey, wif } = vector;
    const encoded = await client.callTool({
      name: "keys_wif_encode",
      arguments: { chain, network, compressed, privateKey },
    });
    expect(encoded.isError).not.toBe(true);
    expect(JSON.parse(text(encoded.content))).toEqual({ chain, network, compressed, wif });
    const decoded = await client.callTool({
      name: "keys_wif_decode",
      arguments: { chain, network, wif },
    });
    expect(decoded.isError).not.toBe(true);
    expect(JSON.parse(text(decoded.content))).toEqual({ chain, network, compressed, privateKey });
  });

  it("rejects malformed WIF tool inputs without echoing secrets", async () => {
    const client = await connectTestClient();
    const secret = "burner-secret-not-valid-WIF";
    for (const args of [
      { chain: "ethereum", wif: secret },
      { chain: "bitcoin", wif: secret },
      { chain: "bitcoin", wif: "1".repeat(55) },
      { chain: "bitcoin", wif: "111", network: "unknown" },
      { chain: "bitcoin", wif: "111", extra: secret },
    ]) {
      const result = await client.callTool({ name: "keys_wif_decode", arguments: args });
      expect(result.isError).toBe(true);
      expect(text(result.content)).not.toContain(secret);
    }
    const vector = wifTestVectors[0];
    const wrongChain = await client.callTool({
      name: "keys_wif_decode",
      arguments: { chain: "litecoin", wif: vector.wif },
    });
    expect(wrongChain.isError).toBe(true);
    expect(text(wrongChain.content)).not.toContain(vector.wif);
  });

  it("reads a BIP38 header and checks an address through MCP", async () => {
    const client = await connectTestClient();
    const { encrypted, address, inspection } = bip38Vectors[3];

    const response = await client.callTool({
      name: "keys_bip38_inspect",
      arguments: { encrypted, address },
    });
    expect(response.isError).not.toBe(true);
    expect(JSON.parse(text(response.content))).toEqual({ ...inspection, addressMatches: true });

    const omitted = await client.callTool({
      name: "keys_bip38_inspect",
      arguments: { encrypted: bip38Vectors[0].encrypted },
    });
    expect(JSON.parse(text(omitted.content))).toEqual(bip38Vectors[0].inspection);

    for (const [args, message] of [
      [{ encrypted: encrypted.slice(0, -1) + "1" }, "Invalid BIP38 base58 encoding or checksum"],
      [{ encrypted: "0OIl" }, "Invalid arguments at /encrypted"],
      [{ encrypted, extra: true }, "Invalid arguments"],
    ] as const) {
      const failed = await client.callTool({ name: "keys_bip38_inspect", arguments: args });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).toContain(message);
    }
  });

  it("opens a BIP38 key through MCP, with its WIF only on request", async () => {
    const client = await connectTestClient();
    const { encrypted, passphrase, wif, address } = bip38Vectors[3];
    const privateKey = decodeWIF(wif, { chain: "bitcoin" }).privateKey;

    const opened = await client.callTool({
      name: "keys_bip38_decrypt",
      arguments: { encrypted, passphrase },
    });
    expect(opened.isError).not.toBe(true);
    expect(text(opened.content)).toMatch(
      new RegExp(
        `^BIP38: ec-multiply, uncompressed, lot 263183, sequence 1\nPassphrase: correct\nPublic key: 04[0-9a-f]{128}\nAddress: ${address}$`,
      ),
    );
    for (const secret of [wif, privateKey]) {
      expect(text(opened.content)).not.toContain(secret);
      expect(JSON.stringify(opened.structuredContent ?? {})).not.toContain(secret);
    }

    const revealed = await client.callTool({
      name: "keys_bip38_decrypt",
      arguments: { encrypted, passphrase, revealKey: true },
    });
    expect(text(revealed.content)).toBe(`${text(opened.content)}\nWIF: ${wif}`);

    const wrong = await client.callTool({
      name: "keys_bip38_decrypt",
      arguments: { encrypted, passphrase: "wrong", revealKey: true },
    });
    expect(wrong.isError).not.toBe(true);
    expect(text(wrong.content)).toBe(
      "BIP38: ec-multiply, uncompressed, lot 263183, sequence 1\nPassphrase: wrong, the address hash does not match",
    );

    for (const [args, message] of [
      [{ encrypted: encrypted.slice(0, -1) + "1", passphrase }, "Invalid BIP38 base58 encoding"],
      [{ encrypted, passphrase: 42 }, "Invalid arguments at /passphrase"],
      [{ encrypted, passphrase, revealKey: "yes" }, "Invalid arguments at /revealKey"],
      [{ encrypted, passphrase, extra: true }, "Invalid arguments"],
    ] as const) {
      const failed = await client.callTool({ name: "keys_bip38_decrypt", arguments: args });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).toContain(message);
      expect(text(failed.content)).not.toContain(passphrase);
    }
  }, 30_000);

  it("opens a keystore through MCP without its private key, and reports a wrong password", async () => {
    const client = await connectTestClient();
    const { keystore, password, privateKey, publicKey, address } = storeVectors[3];
    const json = JSON.stringify(keystore);

    const opened = await client.callTool({
      name: "keys_store_decrypt",
      arguments: { keystore: json, password },
    });
    expect(opened.isError).not.toBe(true);
    expect(text(opened.content)).toBe(
      [
        "Keystore: version 3, scrypt (n 1024, r 8, p 1), aes-128-ctr",
        `Stored address: ${address}`,
        "Password: correct",
        `Public key: ${publicKey}`,
        `Address: ${address}`,
      ].join("\n"),
    );
    expect(text(opened.content)).not.toContain(privateKey);
    expect(JSON.stringify(opened.structuredContent ?? {})).not.toContain(privateKey);

    const wrong = await client.callTool({
      name: "keys_store_decrypt",
      arguments: { keystore: json, password: "wrong" },
    });
    expect(wrong.isError).not.toBe(true);
    expect(text(wrong.content)).toContain("Password: wrong, the MAC does not match");
    expect(text(wrong.content)).not.toContain("Public key");

    const costly = {
      ...keystore,
      Crypto: { ...keystore.Crypto, kdfparams: { ...keystore.Crypto.kdfparams, n: 2 ** 21 } },
    };
    for (const [args, message] of [
      [{ keystore: JSON.stringify(costly), password }, "N must be an integer from 2 to 1048576"],
      [{ keystore: "{]", password }, "Keystore must be valid JSON"],
      [{ keystore: json, password: 42 }, "Invalid arguments at /password"],
    ] as const) {
      const failed = await client.callTool({ name: "keys_store_decrypt", arguments: args });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).toContain(message);
      expect(text(failed.content)).not.toContain(password);
    }
  });

  it.each(brainwalletVectors)(
    "derives the $recipe.kdf brainwallet at $address through MCP without its private key",
    async ({ recipe, compressed, publicKey, address, privateKey }) => {
      const client = await connectTestClient();
      const { passphrase, salt } = brainwalletInput;
      const response = await client.callTool({
        name: "keys_brainwallet_derive",
        arguments: {
          passphrase,
          salt,
          saltEncoding: "utf8",
          compressed,
          ...recipe,
          target: address,
        },
      });
      expect(response.isError).not.toBe(true);
      expect(text(response.content).split("\n")).toEqual([
        "Chain: bitcoin (mainnet)",
        `Address type: legacy, ${compressed ? "compressed" : "uncompressed"}`,
        `Public key: ${publicKey}`,
        `Address: ${address}`,
        "Target: match",
      ]);
      expect(text(response.content)).not.toContain(privateKey);
      expect(text(response.content)).not.toContain(passphrase);
    },
  );

  it("reads a hex salt, a testnet and a target that differs through MCP", async () => {
    const client = await connectTestClient();
    const [vector, other] = brainwalletVectors;
    const { passphrase, saltHex } = brainwalletInput;
    const response = await client.callTool({
      name: "keys_brainwallet_derive",
      arguments: {
        passphrase,
        salt: saltHex,
        saltEncoding: "hex",
        compressed: vector.compressed,
        ...vector.recipe,
        network: "testnet",
        target: other.testnetAddress,
      },
    });
    expect(text(response.content)).toContain(`Address: ${vector.testnetAddress}`);
    expect(text(response.content)).toContain("Target: no match");
  });

  it.each(plainBrainwalletVectors)(
    "derives the plain $recipe.kdf brainwallet at $address through MCP without its private key",
    async ({ passphrase, recipe, chain, compressed, publicKey, address, privateKey }) => {
      const client = await connectTestClient();
      const response = await client.callTool({
        name: "keys_brainwallet_derive",
        arguments: { passphrase, ...recipe, chain, compressed, target: address.toLowerCase() },
      });
      expect(response.isError).not.toBe(true);
      expect(text(response.content).split("\n")).toEqual([
        `Chain: ${chain} (mainnet)`,
        ...(compressed === undefined
          ? []
          : [`Address type: legacy, ${compressed ? "compressed" : "uncompressed"}`]),
        `Public key: ${publicKey}`,
        `Address: ${address}`,
        `Target: ${chain === "ethereum" ? "match" : "no match"}`,
      ]);
      expect(text(response.content)).not.toContain(privateKey);
      expect(text(response.content)).not.toContain(passphrase);
    },
  );

  it("derives WarpWallet challenge 1 through MCP without its private key", async () => {
    const client = await connectTestClient();
    const [{ passphrase, salt, publicKey, address, privateKey }] = warpWalletVectors;
    const response = await client.callTool({
      name: "keys_brainwallet_derive",
      arguments: {
        passphrase,
        salt,
        saltEncoding: "utf8",
        kdf: "warpwallet",
        compressed: false,
        target: address,
      },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content).split("\n")).toEqual([
      "Chain: bitcoin (mainnet)",
      "Address type: legacy, uncompressed",
      `Public key: ${publicKey}`,
      `Address: ${address}`,
      "Target: match",
    ]);
    expect(text(response.content)).not.toContain(privateKey);
  }, 30_000);

  it("refuses a brainwallet recipe it cannot run exactly, echoing no secret", async () => {
    const client = await connectTestClient();
    const { passphrase, salt } = brainwalletInput;
    const base = { passphrase, salt, saltEncoding: "utf8", hashed: "hex", compressed: false };
    const scrypt = { kdf: "scrypt", N: 1024, r: 8, p: 1 };
    for (const [args, message] of [
      [{ ...base, ...scrypt, iterations: 1000 }, "scrypt does not take iterations"],
      [
        { ...base, kdf: "pbkdf2", iterations: 1000, digest: "sha256", N: 1024 },
        "pbkdf2 does not take N",
      ],
      [{ ...base, ...scrypt, N: 1000 }, "N must be a power of 2"],
      [{ ...base, ...scrypt, N: 2 ** 19, r: 8 }, "N * r must not exceed 2097152"],
      [{ ...base, kdf: "scrypt", N: 1024, r: 8 }, "p must be an integer"],
      [{ ...base, kdf: "pbkdf2", iterations: 1000 }, "digest must be one of sha256, sha512"],
      [{ ...base, ...scrypt, salt: "abc", saltEncoding: "hex" }, "Salt must be hex digit pairs"],
      [{ ...base, ...scrypt, N: 2 ** 21 }, "Invalid arguments at /N"],
      [{ ...base, ...scrypt, compressed: undefined }, "compressed must be a boolean"],
      [{ passphrase, kdf: "scrypt", N: 1024, r: 8, p: 1, compressed: false }, "needs a salt"],
      [{ ...base, kdf: "sha256" }, "sha256 does not take salt, saltEncoding, hashed"],
      [{ passphrase, kdf: "keccak256", N: 1024, compressed: false }, "keccak256 does not take N"],
      [{ ...base, kdf: "warpwallet", N: 1024 }, "warpwallet does not take hashed, N"],
      [{ passphrase, kdf: "warpwallet", compressed: false }, "warpwallet needs a salt"],
      [{ passphrase, kdf: "sha256", chain: "ethereum", compressed: true }, "ethereum does not"],
      [{ passphrase, kdf: "sha256", chain: "solana" }, "Invalid arguments at /chain"],
    ] as const) {
      const failed = await client.callTool({ name: "keys_brainwallet_derive", arguments: args });
      expect(failed.isError, message).toBe(true);
      expect(text(failed.content)).toContain(message);
      expect(text(failed.content)).not.toContain(passphrase);
    }
  });

  it.each([
    "README.md",
    "AGENTS.md",
    "packages/pi/README.md",
    "packages/pi/AGENTS.md",
    "docs/DESIGN.md",
    "docs/content/1.guide/1.index.md",
    "docs/app/components/content/LandingHero.vue",
    "docs/app/components/content/LandingHome.vue",
    "docs/app/components/OgImage/Landing.takumi.vue",
  ])("leaves the tool count out of %s, which TOOL_NAMES owns", (file) => {
    const text = readFileSync(new URL(`../${file}`, import.meta.url), "utf8");
    expect(text).not.toMatch(/\b\d+ (?:agent |MCP )?tools\b/iu);
    expect(text).not.toMatch(/\b(?:nineteen|twenty|thirty)[a-z-]* (?:agent |MCP )?tools\b/iu);
    expect(text).not.toMatch(/value: "\d+", unit: "", note: "MCP/u);
  });

  it("advertises every keys tool with explicit safety annotations", async () => {
    const client = await connectTestClient();

    const response = await client.listTools();

    expect(response.tools.map((tool) => tool.name)).toEqual(TOOL_NAMES);
    expect(
      response.tools.find((tool) => tool.name === "keys_wallet_generate")?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    });
    expect(
      response.tools.find((tool) => tool.name === "keys_message_sign")?.annotations,
    ).toMatchObject({
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    });
    expect(
      response.tools.find((tool) => tool.name === "keys_address_validate")?.annotations,
    ).toMatchObject({
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    });
  });

  it("derives a disposable Bitcoin address from a public mnemonic", async () => {
    const client = await connectTestClient();
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const response = await client.callTool({
      name: "keys_hd_wallet_derive",
      arguments: { chain: "bitcoin", mnemonic, path: "m/84'/0'/0'/0/0" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(
      "Address type: segwit\nPublic key: 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c\nAddress: bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
    );
    expect(text(response.content)).not.toContain(mnemonic);
  });

  it("derives an HD wallet from the BIP39 list the language names", async () => {
    const client = await connectTestClient();
    const path = "m/44'/0'/0'/0/0";
    for (const { language, mnemonic } of localizedMnemonicVectors.filter((vector) =>
      ["italian", "japanese"].includes(vector.language),
    )) {
      const expected = HDKey.fromMasterSeed(mnemonicToSeedSync(mnemonic)).derive(path).publicKey;
      const response = await client.callTool({
        name: "keys_hd_wallet_derive",
        arguments: { chain: "bitcoin", mnemonic, path, language },
      });
      expect(response.isError).not.toBe(true);
      expect(text(response.content)).toContain(
        `Public key: ${hex.encode(expected ?? new Uint8Array())}`,
      );
    }

    const italian = localizedMnemonicVectors.find((vector) => vector.language === "italian");
    for (const [args, reason] of [
      [{ mnemonic: italian?.mnemonic }, "none of the words is in the english list"],
      [
        { mnemonic: italian?.mnemonic, allowInvalidChecksum: true },
        "none of the words is in the english list",
      ],
      [{ mnemonic: bip39TestVectors.mnemonic, language: "italian" }, "is in the italian list"],
      [{ mnemonic: italian?.mnemonic, language: "latin" }, "Invalid arguments at /language"],
    ] as const) {
      const rejected = await client.callTool({
        name: "keys_hd_wallet_derive",
        arguments: { chain: "bitcoin", path, ...args },
      });
      expect(rejected.isError).toBe(true);
      expect(text(rejected.content)).toContain(reason);
    }
  });

  it("derives an HD wallet from BIP39 entropy without the words", async () => {
    const client = await connectTestClient();
    const { entropy, path, publicKey, address } = bip39EntropyWalletVector;
    const response = await client.callTool({
      name: "keys_hd_wallet_derive",
      arguments: { chain: "bitcoin", entropy, path },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(`Public key: ${publicKey}\nAddress: ${address}`);
    expect(text(response.content)).not.toContain(entropy);

    for (const vector of localizedMnemonicVectors.filter((item) =>
      ["italian", "japanese"].includes(item.language),
    )) {
      const expected = HDKey.fromMasterSeed(mnemonicToSeedSync(vector.mnemonic)).derive(path);
      const localized = await client.callTool({
        name: "keys_hd_wallet_derive",
        arguments: { chain: "bitcoin", entropy: vector.entropy, path, language: vector.language },
      });
      expect(text(localized.content)).toContain(
        `Public key: ${hex.encode(expected.publicKey ?? new Uint8Array())}`,
      );
    }

    for (const [args, reason] of [
      [{ entropy, mnemonic: bip39TestVectors.mnemonic }, "not both"],
      [{}, "Pass a BIP39 mnemonic or its entropy"],
      [{ entropy: "00".repeat(15) }, "Invalid arguments at /entropy"],
    ] as const) {
      const rejected = await client.callTool({
        name: "keys_hd_wallet_derive",
        arguments: { chain: "bitcoin", path, ...args },
      });
      expect(rejected.isError).toBe(true);
      expect(text(rejected.content)).toContain(reason);
    }
  });

  it("recovers a missing word from the BIP39 list the language names", async () => {
    const client = await connectTestClient();
    const italian = localizedMnemonicVectors.find((vector) => vector.language === "italian");
    const template = italian?.mnemonic.replace(/abete$/u, "?");

    const response = await client.callTool({
      name: "keys_bip39_word_recover",
      arguments: { mnemonic: template, language: "italian" },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toMatch(
      /^Language: italian\nPosition: 12\nCandidates \(128\): abete, /u,
    );

    for (const [args, reason] of [
      [{ mnemonic: template }, "None of the mnemonic template words is in the english list"],
      [
        { mnemonic: bip39TestVectors.mnemonic.replace(/^abandon/u, "?"), language: "italian" },
        "is in the italian list",
      ],
      [{ mnemonic: template, language: "latin" }, "Invalid arguments at /language"],
    ] as const) {
      const rejected = await client.callTool({ name: "keys_bip39_word_recover", arguments: args });
      expect(rejected.isError).toBe(true);
      expect(text(rejected.content)).toContain(reason);
    }
  });

  it("takes the h hardened marker of BIP380 descriptors in every path argument", async () => {
    const client = await connectTestClient();
    const call = async (name: string, args: Readonly<Record<string, string>>) =>
      client.callTool({ name, arguments: args });
    const [electrum] = electrumVectors;

    const wallet = await call("keys_hd_wallet_derive", {
      chain: "bitcoin",
      mnemonic: bip39TestVectors.mnemonic,
      path: "m/84h/0h/0h/0/0",
    });
    expect(text(wallet.content)).toContain(
      "Address type: segwit\nPublic key: 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
    );
    const electrumWallet = await call("keys_electrum_wallet_derive", {
      mnemonic: electrum.mnemonic,
      path: electrum.path.replaceAll("'", "h"),
    });
    expect(text(electrumWallet.content)).toContain(electrum.address);
    const parsed = await call("keys_bip44_parse", { path: "m/44h/60h/0h/0/0" });
    expect(text(parsed.content)).toContain("Coin type: 60\nAccount: 0\nChange: 0");

    const rejected = await call("keys_hd_wallet_derive", {
      chain: "bitcoin",
      mnemonic: bip39TestVectors.mnemonic,
      path: "m/84H/0H/0H/0/0",
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Invalid arguments at /path");
  });

  it("says which address type keys_address_get wrote", async () => {
    const client = await connectTestClient();
    const publicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const address = async (args: Readonly<Record<string, string>>): Promise<string> =>
      text((await client.callTool({ name: "keys_address_get", arguments: args })).content);

    expect(await address({ chain: "bitcoin", publicKey })).toBe(
      "Address type: legacy\nAddress: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    );
    expect(await address({ chain: "bitcoin", publicKey, addressType: "taproot" })).toContain(
      "Address type: taproot\nAddress: bc1p",
    );
    expect(await address({ chain: "ethereum", publicKey })).toBe(
      "Address: 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
    );
  });

  it("derives a watch-only address from an extended public key through MCP", async () => {
    const client = await connectTestClient();
    const [xpub, , zpub] = slip132Vectors;

    const response = await client.callTool({
      name: "keys_xpub_wallet_derive",
      arguments: { chain: "bitcoin", extendedKey: zpub.extendedKey, path: "m/0/0" },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toBe(
      [
        "Chain: bitcoin (mainnet)",
        "Extended key: zpub",
        "Path: m/0/0",
        "Address type: segwit",
        "Public key: 0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        `Address: ${zpub.address}`,
      ].join("\n"),
    );

    for (const [args, message] of [
      [{ extendedKey: xpub.extendedKey, path: "m/0'/0" }, "Invalid arguments at /path"],
      [{ extendedKey: slip132PrivateKey, path: "m/0/0" }, "Extended private keys are not accepted"],
      [{ extendedKey: xpub.extendedKey, path: "m/0", chain: "solana" }, "solana does not derive"],
    ] as const) {
      const failed = await client.callTool({
        name: "keys_xpub_wallet_derive",
        arguments: { chain: "bitcoin", ...args },
      });
      expect(failed.isError).toBe(true);
      expect(text(failed.content)).toContain(message);
      expect(text(failed.content)).not.toContain(slip132PrivateKey.slice(4, 40));
    }
  });

  it("requires an explicit checksum override and reports the warning through MCP", async () => {
    const client = await connectTestClient();
    const { mnemonic, path, address, publicKey } = invalidChecksumPuzzle;
    const args = { chain: "bitcoin", mnemonic, path };
    const strict = await client.callTool({ name: "keys_hd_wallet_derive", arguments: args });
    expect(strict.isError).toBe(true);
    expect(text(strict.content)).toContain("Invalid BIP39 mnemonic");
    const result = await client.callTool({
      name: "keys_hd_wallet_derive",
      arguments: { ...args, allowInvalidChecksum: true },
    });
    expect(result.isError).not.toBe(true);
    expect(text(result.content)).toContain(address);
    expect(text(result.content)).toContain(publicKey);
    expect(text(result.content)).toContain("Warning: BIP39 checksum is invalid.");
    expect(text(result.content)).not.toContain(mnemonic);
    for (const allowInvalidChecksum of [false, "true", "false", 1, null]) {
      const rejected = await client.callTool({
        name: "keys_hd_wallet_derive",
        arguments: { ...args, allowInvalidChecksum },
      });
      expect(rejected.isError).toBe(true);
    }
    const inspection = await client.callTool({
      name: "keys_bip39_inspect",
      arguments: { mnemonic },
    });
    expect(text(inspection.content)).toContain("Word count valid: yes");
    expect(text(inspection.content)).toContain("Wordlist valid: yes");
    expect(text(inspection.content)).toContain("Checksum valid: no");
    expect(text(inspection.content)).not.toContain("Entropy:");
  });

  it("derives Litecoin through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "litecoin", privateKey: litecoinTestVectors.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(litecoinTestVectors.address);
    expect(text(response.content)).not.toContain(litecoinTestVectors.privateKey);
  });

  it("derives the uncompressed Bitcoin and Ethereum wallets through MCP", async () => {
    const client = await connectTestClient();
    const [rushwallet] = plainBrainwalletVectors;
    const bitcoin = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoin", privateKey: rushwallet.privateKey, compressed: false },
    });
    expect(bitcoin.isError).not.toBe(true);
    expect(text(bitcoin.content).split("\n")).toEqual([
      "Address type: legacy",
      `Public key: ${rushwallet.publicKey}`,
      `Address: ${rushwallet.address}`,
    ]);

    const ethereum = await client.callTool({
      name: "keys_wallet_derive",
      arguments: {
        chain: "ethereum",
        privateKey: ethereumTestVectors.privateKey,
        compressed: false,
      },
    });
    expect(text(ethereum.content).split("\n")).toEqual([
      `Public key: ${ethereumTestVectors.publicKeyUncompressed}`,
      `Address: ${ethereumTestVectors.address}`,
    ]);
  });

  it("refuses a compressed flag the chain's address would ignore", async () => {
    const client = await connectTestClient();
    const privateKey = secp256k1TestVectors.privateKey;
    for (const [args, message] of [
      [{ chain: "ethereum", compressed: true }, "ethereum addresses hash the uncompressed key"],
      [{ chain: "tron", compressed: true }, "tron addresses hash the uncompressed key"],
      [{ chain: "sui", addressType: "secp256k1", compressed: false }, "sui secp256k1 addresses"],
      [{ chain: "sui", compressed: true }, "sui ed25519 keys take no compressed"],
      [{ chain: "solana", compressed: false }, "solana ed25519 keys take no compressed"],
      [{ chain: "bitcoin", addressType: "segwit", compressed: false }, "take a compressed"],
    ] as const) {
      const failed = await client.callTool({
        name: "keys_wallet_derive",
        arguments: { ...args, privateKey },
      });
      expect(failed.isError, message).toBe(true);
      expect(text(failed.content)).toContain(message);
      expect(text(failed.content)).not.toContain(privateKey);
    }
  });

  it("derives and validates Bitcoin Cash through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const { privateKey, address } = bitcoinCashTestVectors.prize;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoincash", privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(address);
    expect(text(response.content)).not.toContain(privateKey);

    const validation = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoincash", address },
    });
    expect(text(validation.content)).toContain("is a valid bitcoincash address");

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoincash", privateKey, addressType: "segwit" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");
  });

  it("derives and validates Bitcoin Gold through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const { privateKey, segwitAddress } = bitcoinGoldTestVectors.signed;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoingold", privateKey, addressType: "segwit" },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(segwitAddress);
    expect(text(response.content)).not.toContain(privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoingold", privateKey, addressType: "taproot" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy, p2sh, segwit, p2wsh");

    const unprotected = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoingold", address: bitcoinGoldTestVectors.unprotected[0] },
    });
    expect(text(unprotected.content)).toContain("is not a valid bitcoingold address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "bitcoingold" },
    });
    expect(text(path.content)).toContain("m/44'/156'/0'/0/0");
  });

  it("derives and validates Bitcoin SV through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const { privateKey, address } = bitcoinSVTestVectors.keyOne;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "bitcoinsv", privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(address);
    expect(text(response.content)).not.toContain(privateKey);

    const rejected = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoinsv", address: bitcoinSVTestVectors.p2shAddress },
    });
    expect(text(rejected.content)).toContain("is not a valid bitcoinsv address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "bitcoinsv" },
    });
    expect(text(path.content)).toContain("m/44'/236'/0'/0/0");
  });

  it("derives and validates Dogecoin through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const [key] = dogecoinTestVectors.keys;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "dogecoin", privateKey: key.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(key.addressCompressed);
    expect(text(response.content)).not.toContain(key.privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "dogecoin", privateKey: key.privateKey, addressType: "p2sh" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");

    const script = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "dogecoin", address: dogecoinTestVectors.mainnet[1] },
    });
    expect(text(script.content)).toContain("is a valid dogecoin address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "dogecoin" },
    });
    expect(text(path.content)).toContain("m/44'/3'/0'/0/0");
  });

  it("derives and validates Dash through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const [key] = dashTestVectors.keys;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "dash", privateKey: key.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(key.addressCompressed);
    expect(text(response.content)).not.toContain(key.privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "dash", privateKey: key.privateKey, addressType: "p2sh" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");

    const script = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "dash", address: dashTestVectors.mainnet[1] },
    });
    expect(text(script.content)).toContain("is a valid dash address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "dash" },
    });
    expect(text(path.content)).toContain("m/44'/5'/0'/0/0");
  });

  it("derives and validates Zcash through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const [key] = zcashTestVectors.keys;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "zcash", privateKey: key.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(key.addressCompressed);
    expect(text(response.content)).not.toContain(key.privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "zcash", privateKey: key.privateKey, addressType: "p2sh" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");

    const tex = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "zcash", address: zcashTestVectors.tex.tex },
    });
    expect(text(tex.content)).toContain("is a valid zcash address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "zcash" },
    });
    expect(text(path.content)).toContain("m/44'/133'/0'/0/0");
  });

  it("derives and validates eCash through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const { privateKey } = eCashTestVectors.signed;
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "ecash", privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain("ecash:q");
    expect(text(response.content)).not.toContain(privateKey);

    const rejected = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "ecash", privateKey, addressType: "p2sh" },
    });
    expect(rejected.isError).toBe(true);
    expect(text(rejected.content)).toContain("Supported: legacy");

    const [{ p2sh }] = eCashTestVectors.encoded;
    const validation = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "ecash", address: p2sh },
    });
    expect(text(validation.content)).toContain("is a valid ecash address");

    const path = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "ecash" },
    });
    expect(text(path.content)).toContain("m/44'/899'/0'/0/0");
  });

  it("derives Decred through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "decred", privateKey: decredTestVectors.privateKey },
    });
    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain(decredTestVectors.addresses.mainnet);
    expect(text(response.content)).not.toContain(decredTestVectors.privateKey);
  });

  it("derives and signs Stellar through the MCP schema and executor", async () => {
    const client = await connectTestClient();
    const [message, , signature] = stellarTestVectors.messages[1];
    const wallet = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "stellar", privateKey: stellarTestVectors.privateKey },
    });
    expect(wallet.isError).not.toBe(true);
    expect(text(wallet.content)).toContain(stellarTestVectors.address);
    expect(text(wallet.content)).not.toContain(stellarTestVectors.privateKey);

    const signed = await client.callTool({
      name: "keys_message_sign",
      arguments: { chain: "stellar", message, privateKey: stellarTestVectors.privateKey },
    });
    expect(signed.isError).not.toBe(true);
    expect(text(signed.content)).toContain(signature);
  });

  it("signs an Ethereum message with the recovery byte on request", async () => {
    const client = await connectTestClient();
    const [message, , signatureWithV] = ethereumTestVectors.messages[1];

    const plain = await client.callTool({
      name: "keys_message_sign",
      arguments: {
        chain: "ethereum",
        message,
        privateKey: ethereumTestVectors.privateKey,
      },
    });
    expect(text(plain.content)).toContain(signatureWithV.slice(0, 128));
    expect(text(plain.content)).not.toContain(signatureWithV);

    const recovered = await client.callTool({
      name: "keys_message_sign",
      arguments: {
        chain: "ethereum",
        message,
        privateKey: ethereumTestVectors.privateKey,
        recovered: true,
      },
    });
    expect(recovered.isError).not.toBe(true);
    expect(text(recovered.content)).toContain(signatureWithV);

    const verified = await client.callTool({
      name: "keys_message_verify",
      arguments: {
        chain: "ethereum",
        message,
        signature: signatureWithV,
        publicKey: ethereumTestVectors.publicKey,
      },
    });
    expect(text(verified.content)).toContain("Signature is valid");
  });

  it("rejects 0x hex at the schema instead of calling a valid signature invalid", async () => {
    const client = await connectTestClient();
    const [message, , signature] = ethereumTestVectors.messages[1];
    const { privateKey, publicKey } = ethereumTestVectors;

    for (const [name, arguments_, field] of [
      [
        "keys_message_verify",
        { chain: "ethereum", message, signature: `0x${signature}`, publicKey },
        "/signature",
      ],
      [
        "keys_message_verify",
        { chain: "ethereum", message, signature, publicKey: `0x${publicKey}` },
        "/publicKey",
      ],
      [
        "keys_message_sign",
        { chain: "ethereum", message, privateKey: `0x${privateKey}` },
        "/privateKey",
      ],
      ["keys_wallet_derive", { chain: "ethereum", privateKey: `0x${privateKey}` }, "/privateKey"],
      ["keys_address_get", { chain: "ethereum", publicKey: `0x${publicKey}` }, "/publicKey"],
    ] as const) {
      const response = await client.callTool({ name, arguments: arguments_ });
      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain(`Invalid arguments at ${field}`);
    }
  });

  it("reports an error for a chain without a recoverable signature", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_message_sign",
      arguments: {
        chain: "solana",
        message: "hello",
        privateKey: secp256k1TestVectors.privateKey,
        recovered: true,
      },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).toContain("secp256k1 only");
  });

  it("signs Litecoin Core's base64 and verifies it against the key", async () => {
    const client = await connectTestClient();
    const { privateKey, message, signature } = litecoinTestVectors.signed;

    const signed = await client.callTool({
      name: "keys_message_sign",
      arguments: { chain: "litecoin", network: "testnet", message, privateKey, recovered: true },
    });
    expect(signed.isError).not.toBe(true);
    expect(text(signed.content)).toBe(`Signature: ${signature}`);

    const verified = await client.callTool({
      name: "keys_message_verify",
      arguments: {
        chain: "litecoin",
        message,
        signature,
        publicKey: bitcoinGoldTestVectors.signed.publicKey,
      },
    });
    expect(text(verified.content)).toBe("Signature is valid");
  });

  it("recovers the signer of Core's signature and matches its address", async () => {
    const client = await connectTestClient();
    const { message, compactSignature, address } = bitcoinMessageVectors;

    const response = await client.callTool({
      name: "keys_message_recover",
      arguments: {
        chain: "bitcoin",
        network: "testnet",
        message,
        signature: compactSignature,
        address,
      },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toBe(
      [
        "Chain: bitcoin (testnet)",
        `Public key: ${bitcoinGoldTestVectors.signed.publicKey}`,
        `Address: ${address} (legacy)`,
        "Given address: match (legacy)",
      ].join("\n"),
    );
  });

  it("matches a SegWit address signed under Electrum's P2PKH header, in any case", async () => {
    const client = await connectTestClient();
    const { message, signatures } = bip137MessageVectors;
    const [, , [, segwit, , electrum]] = signatures;
    const signature = base64.encode(hex.decode(electrum));

    const matched = await client.callTool({
      name: "keys_message_recover",
      arguments: { chain: "bitcoin", message, signature, address: segwit.toUpperCase() },
    });
    expect(text(matched.content)).toContain("Given address: match (segwit)");

    const otherMessage = await client.callTool({
      name: "keys_message_recover",
      arguments: { chain: "bitcoin", message: `${message}!`, signature, address: segwit },
    });
    expect(otherMessage.isError).not.toBe(true);
    expect(text(otherMessage.content)).toContain("Given address: no match");
  });

  it("holds a BIP137 header to the one address type it names", async () => {
    const client = await connectTestClient();
    const { message, signatures } = bip137MessageVectors;
    const [, [, p2sh, bip137]] = signatures;
    const signature = base64.encode(hex.decode(bip137));
    const signer = await client.callTool({
      name: "keys_message_recover",
      arguments: { chain: "bitcoin", message, signature, address: p2sh },
    });
    expect(text(signer.content)).toContain(`Address: ${p2sh} (p2sh)`);
    expect(text(signer.content)).toContain("Given address: match (p2sh)");

    const publicKey = /Public key: ([0-9a-f]+)/u.exec(text(signer.content))?.[1] ?? "";
    const segwit = new Bitcoin().getAddress(publicKey, "segwit");
    const response = await client.callTool({
      name: "keys_message_recover",
      arguments: { chain: "bitcoin", message, signature, address: segwit },
    });
    expect(text(response.content)).toContain("Given address: no match");
  });

  it("refuses what keys_message_recover cannot read instead of reporting no match", async () => {
    const client = await connectTestClient();
    const { message, compactSignature } = bitcoinMessageVectors;

    for (const [arguments_, error] of [
      [
        {
          chain: "bitcoin",
          message,
          signature: compactSignature,
          address: "1BoatSLRHtKNngkdXEeobR76b53LETtpyX",
        },
        "Address is not a valid bitcoin mainnet address",
      ],
      [{ chain: "ethereum", message, signature: compactSignature }, "65 bytes of r||s||v"],
      [{ chain: "solana", message, signature: compactSignature }, "solana does not write"],
      [{ chain: "bitcoin", message, signature: "00".repeat(65) }, "65 bytes of base64"],
      [
        { chain: "bitcoin", message, signature: "00".repeat(64) },
        "Invalid arguments at /signature",
      ],
    ] as const) {
      const response = await client.callTool({
        name: "keys_message_recover",
        arguments: arguments_,
      });
      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain(error);
    }

    const verified = await client.callTool({
      name: "keys_message_verify",
      arguments: {
        chain: "ethereum",
        message,
        signature: compactSignature,
        publicKey: bitcoinGoldTestVectors.signed.publicKey,
      },
    });
    expect(verified.isError).toBe(true);
    expect(text(verified.content)).toContain("65 bytes of r||s||v");
  });

  it("recovers personal_sign, EIP-712 and digest signers on EVM chains and TRON", async () => {
    const client = await connectTestClient();
    const { personalSign, mail, hunt } = evmRecoverTestVectors;
    const recover = async (arguments_: Readonly<Record<string, unknown>>): Promise<string> => {
      const response = await client.callTool({
        name: "keys_message_recover",
        arguments: arguments_,
      });
      expect(response.isError).not.toBe(true);
      return text(response.content);
    };

    expect(
      await recover({
        chain: "ethereum",
        message: personalSign.message,
        signature: personalSign.signature,
        address: personalSign.address.toLowerCase(),
      }),
    ).toMatch(/^Address: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266\nGiven address: match$/mu);

    expect(
      await recover({
        chain: "ethereum",
        typedData: JSON.stringify(mail.typedData),
        signature: mail.signature,
        address: mail.address,
      }),
    ).toBe(
      [
        "Chain: ethereum (mainnet)",
        `EIP-712 digest: ${mail.digest}`,
        `Public key: ${ethereumTestVectors.publicKeyUncompressed}`,
        `Address: ${mail.address}`,
        "Given address: match",
      ].join("\n"),
    );

    expect(
      await recover({
        chain: "base",
        typedData: JSON.stringify(hunt.typedData),
        signature: hunt.signature,
        address: personalSign.address,
      }),
    ).toContain("Given address: no match");

    expect(
      await recover({ chain: "ethereum", digest: mail.digest, signature: mail.signature }),
    ).toContain(`Address: ${mail.address}`);

    const [message, , signature] = tronTestVectors.messages[1];
    expect(
      await recover({ chain: "tron", message, signature, address: tronTestVectors.address }),
    ).toContain("Given address: match");
  });

  it("refuses recover input it cannot read on EVM chains", async () => {
    const client = await connectTestClient();
    const { mail } = evmRecoverTestVectors;
    for (const [arguments_, error] of [
      [
        { chain: "ethereum", signature: mail.signature },
        "exactly one of message, typedData and digest",
      ],
      [
        { chain: "ethereum", message: "x", digest: mail.digest, signature: mail.signature },
        "exactly one of message, typedData and digest",
      ],
      [
        { chain: "ethereum", typedData: "{nope", signature: mail.signature },
        "Typed data must be JSON",
      ],
      [
        { chain: "ethereum", typedData: "[1,2]", signature: mail.signature },
        "types, primaryType, domain and message",
      ],
      [
        {
          chain: "ethereum",
          typedData: JSON.stringify({ ...mail.typedData, primaryType: "Letter" }),
          signature: mail.signature,
        },
        'Primary type "Letter" is not one of types',
      ],
      [
        { chain: "ethereum", digest: `0x${mail.digest}`, signature: mail.signature },
        "Invalid arguments at /digest",
      ],
      [
        { chain: "bitcoin", digest: mail.digest, signature: mail.signature },
        "bitcoin does not sign digests",
      ],
      [
        { chain: "ethereum", digest: mail.digest, signature: `${mail.signature.slice(0, 128)}1d` },
        "v must be 27, 28, 0 or 1",
      ],
    ] as const) {
      const response = await client.callTool({
        name: "keys_message_recover",
        arguments: arguments_,
      });
      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain(error);
    }
  });

  it("calls a well formed base64 signature that recovers no key invalid, as Core does", async () => {
    const client = await connectTestClient();
    const { message, compactSignature } = bitcoinMessageVectors;
    const publicKey = bitcoinGoldTestVectors.signed.publicKey;
    const empty = base64.encode(Uint8Array.of(31, ...new Uint8Array(64)));
    const header = base64.encode(Uint8Array.of(26, ...base64.decode(compactSignature).subarray(1)));

    const verdict = await client.callTool({
      name: "keys_message_verify",
      arguments: { chain: "bitcoin", message, signature: empty, publicKey },
    });
    expect(verdict.isError).not.toBe(true);
    expect(text(verdict.content)).toBe("Signature is invalid");

    const refused = await client.callTool({
      name: "keys_message_verify",
      arguments: { chain: "bitcoin", message, signature: header, publicKey },
    });
    expect(refused.isError).toBe(true);
    expect(text(refused.content)).toContain("27 to 42");
  });

  it("validates a known Bitcoin address", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoin", address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).toContain("is a valid bitcoin address");
  });

  it("names the network an address belongs to when it fails on the other", async () => {
    const client = await connectTestClient();
    const { mainnet, testnet } = bitcoinTestVectors.addresses.p2pkh;

    const onMainnet = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoin", address: testnet },
    });
    const onTestnet = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoin", address: mainnet, network: "testnet" },
    });

    expect(text(onMainnet.content)).toBe(
      `${testnet} is not a valid bitcoin address on mainnet, but it is valid on testnet`,
    );
    expect(text(onTestnet.content)).toBe(
      `${mainnet} is not a valid bitcoin address on testnet, but it is valid on mainnet`,
    );
  });

  it("rejects arguments that miss the schema", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoin" },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).toContain("Invalid arguments");
  });

  it("generates paths the ed25519 chains derive and refuses levels they lack", async () => {
    const client = await connectTestClient();
    const { mnemonic } = bip39TestVectors;

    for (const [chain, expected] of [
      ["solana", "m/44'/501'/0'/0'"],
      ["stellar", "m/44'/148'/0'"],
      ["aptos", "m/44'/637'/0'/0'/0'"],
      ["sui", "m/44'/784'/0'/0'/0'"],
    ]) {
      const generated = await client.callTool({
        name: "keys_bip44_generate",
        arguments: { chain },
      });
      expect(generated.isError).not.toBe(true);
      expect(text(generated.content)).toContain(`Path: ${expected}`);

      const derived = await client.callTool({
        name: "keys_hd_wallet_derive",
        arguments: { chain, mnemonic, path: expected },
      });
      expect(derived.isError).not.toBe(true);
      expect(text(derived.content)).toContain("Address: ");
    }

    const cardano = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "cardano", change: 2 },
    });
    expect(text(cardano.content)).toContain("Path: m/1852'/1815'/0'/2/0");

    const sui = await client.callTool({
      name: "keys_bip44_generate",
      arguments: { chain: "sui", addressType: "secp256k1" },
    });
    expect(text(sui.content)).toContain("Path: m/54'/784'/0'/0/0");

    for (const [arguments_, message] of [
      [{ chain: "stellar", addressIndex: 1 }, "Stellar paths end at the account"],
      [{ chain: "solana", addressIndex: 1 }, "Solana paths end at the change branch"],
      [{ chain: "bitcoin", change: 2 }, "change must be an integer between 0 and 1"],
      [{ chain: "cardano", change: 6 }, "change must be an integer between 0 and 5"],
      [{ chain: "bitcoin", addressType: "secp256k1" }, "is not supported for bitcoin"],
      [
        { chain: "ethereum", addressType: "secp256k1" },
        'Address type "secp256k1" is not supported for ethereum',
      ],
      [{ chain: "bitcoin", addressType: "segwit" }, "Invalid arguments"],
    ] as const) {
      const rejected = await client.callTool({
        name: "keys_bip44_generate",
        arguments: arguments_,
      });
      expect(rejected.isError).toBe(true);
      expect(text(rejected.content)).toContain(message);
    }
  });

  it("fails an unparsable BIP44 path with sanitized text", async () => {
    const client = await connectTestClient();
    const result = await client.callTool({
      name: "keys_bip44_parse",
      arguments: { path: "m/\u009B31m" },
    });
    expect(result.isError).toBe(true);
    expect(text(result.content)).toBe('keys_bip44_parse failed: Invalid BIP44 path: "m/"');
  });

  it("keeps each BIP44 tool to its own arguments at the schema", async () => {
    const client = await connectTestClient();
    const path = "m/44'/0'/0'/0/0";

    for (const [name, arguments_] of [
      ["keys_bip44_parse", {}],
      ["keys_bip44_parse", { chain: "bitcoin", path }],
      ["keys_bip44_parse", { path, account: 1 }],
      ["keys_bip44_parse", { path, addressType: "secp256k1" }],
      ["keys_bip44_generate", {}],
      ["keys_bip44_generate", { account: 1 }],
      ["keys_bip44_generate", { chain: "bitcoin", path }],
    ] as const) {
      const response = await client.callTool({ name, arguments: arguments_ });

      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain("Invalid arguments");
    }

    const parsed = await client.callTool({
      name: "keys_bip44_parse",
      arguments: { path },
    });
    expect(parsed.isError).not.toBe(true);
    expect(text(parsed.content)).toContain("Coin type: 0");
  });

  it("rejects unsupported wallet options at the schema", async () => {
    const client = await connectTestClient();

    for (const arguments_ of [
      { chain: "bitcoin", network: "testnett" },
      { chain: "bitcoin", addressType: "bogus" },
    ]) {
      const response = await client.callTool({
        name: "keys_wallet_generate",
        arguments: arguments_,
      });

      expect(response.isError).toBe(true);
      expect(text(response.content)).toContain("Invalid arguments");
    }
  });

  it("names the allowed values when an option is not one of them", async () => {
    const client = await connectTestClient();

    for (const [name, arguments_, message] of [
      [
        "keys_wallet_generate",
        { chain: "bitcoin", network: "testnett" },
        "Invalid arguments at /network: must be one of mainnet, testnet",
      ],
      [
        "keys_wif_decode",
        { chain: "ethereum", wif: wifTestVectors[0].wif },
        "Invalid arguments at /chain: must be one of bitcoin, litecoin, dash, decred, dogecoin",
      ],
      [
        "keys_bip39_generate",
        { words: 13 },
        "Invalid arguments at /words: must be one of 12, 15, 18, 21, 24",
      ],
      [
        "keys_bip39_indices_lookup",
        { indices: [1], indexBase: 2 },
        "Invalid arguments at /indexBase: must be one of 0, 1",
      ],
    ] as const) {
      const response = await client.callTool({ name, arguments: arguments_ });

      expect(response.isError).toBe(true);
      expect(text(response.content)).toBe(message);
    }
  });

  it("rejects prototype property names as unknown tools", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({ name: "toString", arguments: {} });

    expect(response.isError).toBe(true);
    expect(response.content).toEqual([{ type: "text", text: 'Unknown keys tool: "toString"' }]);
  });

  it("removes control bytes from an echoed unknown tool name", async () => {
    const client = await connectTestClient();
    const escape = String.fromCodePoint(27);

    const response = await client.callTool({
      name: `x\nforged${escape}[31m`,
      arguments: {},
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).not.toContain("\n");
    expect(text(response.content)).not.toContain(escape);
  });

  it("removes control bytes from an echoed invalid address", async () => {
    const client = await connectTestClient();

    const response = await client.callTool({
      name: "keys_address_validate",
      arguments: { chain: "bitcoin", address: "not-an-address\nforged output" },
    });

    expect(response.isError).not.toBe(true);
    expect(text(response.content)).not.toContain("\n");
    expect(text(response.content)).toContain("is not a valid bitcoin address");
  });

  it("does not echo an invalid private key in errors", async () => {
    const client = await connectTestClient();
    const privateKey = "private-fixture-that-must-not-be-echoed";

    const response = await client.callTool({
      name: "keys_wallet_derive",
      arguments: { chain: "ethereum", privateKey },
    });

    expect(response.isError).toBe(true);
    expect(text(response.content)).not.toContain(privateKey);
  });

  it("names the secp256k1 key a tool cannot use", async () => {
    const { curveOrder } = secp256k1TestVectors;
    const privateKeyError =
      "secp256k1 private key must be 32 bytes of hex, above zero and below the curve order";
    for (const [name, arguments_, error] of [
      [
        "keys_address_get",
        { chain: "bitcoin", publicKey: `02${"00".repeat(32)}` },
        "Invalid SEC1 secp256k1 public key",
      ],
      [
        "keys_address_get",
        { chain: "tron", publicKey: `04${"00".repeat(64)}` },
        "Invalid SEC1 secp256k1 public key",
      ],
      ["keys_wallet_derive", { chain: "ethereum", privateKey: curveOrder }, privateKeyError],
      ["keys_wallet_derive", { chain: "bitcoin", privateKey: "00".repeat(32) }, privateKeyError],
      [
        "keys_message_sign",
        { chain: "decred", privateKey: curveOrder, message: "hi" },
        privateKeyError,
      ],
    ] as const) {
      const response = await callTool(name, arguments_);
      expect(response.isError).toBe(true);
      expect(text(response.content)).toBe(`${name} failed: ${error}`);
    }
  });

  it("exports the listings and calls the server answers with", async () => {
    const client = await connectTestClient();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;

    expect((await client.listTools()).tools).toEqual(toolListings);
    for (const [name, arguments_] of [
      ["keys_address_get", { chain: "bitcoin", publicKey: publicKeyCompressed }],
      ["keys_address_get", { chain: "bitcoin", publicKey: publicKeyCompressed, extra: 1 }],
      ["keys_wallet_derive", { chain: "nochain", privateKey }],
      ["keys_missing", {}],
    ] as const) {
      const direct = await callTool(name, arguments_);
      expect(direct).toEqual(await client.callTool({ name, arguments: arguments_ }));
    }
  });
});
