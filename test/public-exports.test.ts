import { cpSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { hex } from "@agntn/encodings/hex";
import { createJiti } from "jiti/static";
import { build } from "vite-plus";
import { describe, expect, it } from "vite-plus/test";
import type { HDWalletOptions } from "@agntn/keys";
import type { DecodedWIF, WIFOptions } from "@agntn/keys/wif";
import type { BIP39MnemonicInspection } from "@agntn/keys/bip39";
import type { ElectrumSeedType } from "@agntn/keys/electrum";
import type { PublicKeyEncodingOptions } from "@agntn/keys/secp256k1";
import {
  bip32ParentVector,
  bip38Vectors,
  bip322Vectors,
  brainwalletInput,
  brainwalletVectors,
  storeVectors,
  electrumVectors,
  wifTestVectors,
  localizedMnemonicVectors,
  invalidChecksumPuzzle,
  bip39TestVectors,
  bip39WordOrderVector,
  bip39WordRepairVectors,
  publicKeyEncodingVector,
  secp256k1MathVectors,
  secp256k1TestVectors,
  transactionVectors,
  curveVectors,
  slip132Vectors,
} from "./fixtures.ts";
import { blockchains as sourceChains } from "../src/_blockchains.ts";
import { ELECTRUM_LEGACY_WORDS } from "../src/utils/electrum/legacy.ts";

const EXPORTS = [
  ["@agntn/keys/bip32", "/dist/utils/bip32/index.mjs"],
  ["@agntn/keys/bip322", "/dist/utils/bip322/index.mjs"],
  ["@agntn/keys/bip38", "/dist/utils/bip38/index.mjs"],
  ["@agntn/keys/bip39", "/dist/utils/bip39/index.mjs"],
  ["@agntn/keys/brainwallet", "/dist/utils/brainwallet/index.mjs"],
  ["@agntn/keys/curve", "/dist/utils/curve/index.mjs"],
  ["@agntn/keys/bip44", "/dist/utils/bip44/index.mjs"],
  ["@agntn/keys/electrum", "/dist/utils/electrum/index.mjs"],
  ["@agntn/keys/secp256k1", "/dist/utils/secp256k1/index.mjs"],
  ["@agntn/keys/transaction", "/dist/utils/transaction/index.mjs"],
  ["@agntn/keys/slip10", "/dist/utils/slip10/index.mjs"],
  ["@agntn/keys/store", "/dist/utils/store/index.mjs"],
  ["@agntn/keys/wif", "/dist/utils/wif/index.mjs"],
] as const;

/** Static and dynamic import specifiers in the built ESM. */
const IMPORT_SPECIFIER = /(?:from|import)\s*\(?\s*["']([^"']+)["']/g;

/** Package part of a bare specifier, `@scope/name` or `name`; relative paths do not match. */
const PACKAGE_NAME = /^(?:@[^/.][^/]*\/)?[^/.][^/]*/u;

describe("Public WIF exports", () => {
  it("imports the built API and preserves compression when deriving a wallet", async () => {
    const { encode, decode } = await import("@agntn/keys/wif");
    const { blockchains } = await import("@agntn/keys");
    const vector = wifTestVectors[1];
    const options: WIFOptions = { chain: vector.chain, compressed: vector.compressed };
    expect(encode(vector.privateKey, options)).toBe(vector.wif);
    const decoded: DecodedWIF = decode(vector.wif, options);
    const btc = await blockchains.bitcoin()();
    const wallet = btc.deriveWallet(decoded.privateKey, { compressed: decoded.compressed });
    expect(wallet).toEqual(btc.deriveWallet(vector.privateKey, { compressed: false }));
    expect(wallet.address).not.toBe(btc.deriveWallet(decoded.privateKey).address);
  });

  it("keeps WIF out of the root entry", async () => {
    const root = await import("@agntn/keys");
    expect(root).not.toHaveProperty("encodeWIF");
    expect(root).not.toHaveProperty("decodeWIF");
  });
});

describe("Public BIP44 exports", () => {
  it("builds and parses a path from the built package", async () => {
    const { BIP44, BIP44Change, getPath, parse } = await import("@agntn/keys/bip44");
    const path = getPath(BIP44.LITECOIN, 1, BIP44Change.INTERNAL, 4);
    expect(path).toBe("m/44'/2'/1'/1/4");
    expect(parse(path)).toEqual({
      purpose: 44,
      coinType: 2,
      account: 1,
      change: 1,
      addressIndex: 4,
    });
  });

  it("keeps BIP44 out of the root entry and the other path shapes private", async () => {
    const root = await import("@agntn/keys");
    for (const name of ["BIP44", "BIP44Change", "getBIP44Path", "parseBIP44Path"]) {
      expect(root).not.toHaveProperty(name);
    }
    expect(root).toHaveProperty("getBlockchainPath");
    const bip44 = await import("@agntn/keys/bip44");
    expect(new Set(Object.keys(bip44))).toEqual(
      new Set(["BIP44", "BIP44Change", "getPath", "parse"]),
    );
  });
});

describe("Public secp256k1 exports", () => {
  it("converts a public key from the built package", async () => {
    const { convertPublicKey } = await import("@agntn/keys/secp256k1");
    const { compressed, uncompressed } = publicKeyEncodingVector;
    const options: PublicKeyEncodingOptions = { compressed: false };
    expect(convertPublicKey(compressed, options)).toBe(uncompressed);
    expect(convertPublicKey(uncompressed)).toBe(compressed);
  });

  it("adds points and lifts x from the built package", async () => {
    const { addPoints, liftX } = await import("@agntn/keys/secp256k1");
    const { g, minusG, twoG } = secp256k1MathVectors;
    expect(addPoints(g, g)).toBe(twoG);
    expect(liftX(g.slice(2))).toEqual({ even: g, odd: minusG });
  });

  it("keeps the conversion out of the root entry and key generation private", async () => {
    const root = await import("@agntn/keys");
    expect(root).not.toHaveProperty("convertSecp256k1PublicKey");
    const secp256k1 = await import("@agntn/keys/secp256k1");
    expect(new Set(Object.keys(secp256k1))).toEqual(
      new Set([
        "convertPublicKey",
        "addPoints",
        "subtractPoints",
        "negatePoint",
        "multiplyPoint",
        "multiplyGenerator",
        "addScalars",
        "subtractScalars",
        "multiplyScalars",
        "invertScalar",
        "liftX",
        "isOnCurve",
        "recoverReusedNonce",
      ]),
    );
  });
});

describe("Public curve exports", () => {
  it("does arithmetic on a curve the caller defines from the built package", async () => {
    const { defineCurve, doublePoint, pointOrder } = await import("@agntn/keys/curve");
    const { paar } = curveVectors;
    const curve = defineCurve(paar);
    expect(doublePoint(curve, { x: 5n, y: 1n })).toEqual({ x: 6n, y: 3n });
    expect(pointOrder(curve, { x: 5n, y: 1n })).toBe(paar.order);
  });

  it("exports the curve toolkit from its subpath only", async () => {
    const root = await import("@agntn/keys");
    expect(root).not.toHaveProperty("defineCurve");
    const curve = await import("@agntn/keys/curve");
    expect(new Set(Object.keys(curve))).toEqual(
      new Set([
        "defineCurve",
        "isOnCurve",
        "addPoints",
        "doublePoint",
        "negatePoint",
        "multiplyPoint",
        "countPoints",
        "listPoints",
        "pointOrder",
        "discreteLog",
        "MAX_COUNTED_PRIME",
        "MAX_FILTERED_PRIME",
        "MAX_ORDER_PRIME",
        "MAX_LOG_ORDER",
      ]),
    );
  });
});

describe("Public brainwallet exports", () => {
  it("derives a brainwallet key from the built package, and nothing else from there", async () => {
    const brainwallet = await import("@agntn/keys/brainwallet");
    const [vector] = brainwalletVectors;
    const { passphrase, salt } = brainwalletInput;
    expect(hex.encode(brainwallet.derive(passphrase, { ...vector.recipe, salt }))).toBe(
      vector.privateKey,
    );
    expect(Object.keys(brainwallet)).toEqual(["derive"]);
    expect(await import("@agntn/keys")).not.toHaveProperty("derive");
  });
});

describe("Public BIP38 exports", () => {
  it("reads and opens a BIP38 key from the built package, and nothing else from there", async () => {
    const bip38 = await import("@agntn/keys/bip38");
    const { encrypted, passphrase, wif, address } = bip38Vectors[3];
    expect(bip38.decrypt(encrypted, passphrase)).toMatchObject({ wif, address });
    expect(() => bip38.decrypt(encrypted, "wrong")).toThrow(bip38.BIP38PassphraseError);
    expect(new Set(Object.keys(bip38))).toEqual(
      new Set(["BIP38PassphraseError", "decrypt", "inspect"]),
    );
    expect(await import("@agntn/keys")).not.toHaveProperty("BIP38PassphraseError");
  }, 20_000);
});

describe("Public BIP322 exports", () => {
  it("verifies and signs from the built package, outside the root", async () => {
    const bip322 = await import("@agntn/keys/bip322");
    const { address, message, signature } = bip322Vectors.unprefixed;
    expect(bip322.verify(address, message, signature).state).toBe("valid");
    const signed = bip322.sign(message, secp256k1TestVectors.privateKey, "taproot");
    expect(signed.startsWith("smp")).toBe(true);
    expect(new Set(Object.keys(bip322))).toEqual(new Set(["sign", "verify"]));
    expect(await import("@agntn/keys")).not.toHaveProperty("verify");
  });
});

describe("Public transaction exports", () => {
  it("reads the reused r of 2012 and recovers its key from the built package", async () => {
    const transaction = await import("@agntn/keys/transaction");
    const { recoverReusedNonce } = await import("@agntn/keys/secp256k1");
    const { spent, r } = transactionVectors.reusedNonce2012;
    const [a, b] = [0, 1].flatMap((index) =>
      transaction.extractSignatures(transactionVectors.reusedNonce2012.transaction, index, spent),
    );
    expect([a?.r, b?.r]).toEqual([r, r]);
    if (a === undefined || b === undefined) throw new Error("missing signature");
    expect(recoverReusedNonce(a, b).publicKey).toMatch(/^0[23]dbd0c615/u);
    expect(new Set(Object.keys(transaction))).toEqual(new Set(["extractSignatures"]));
    expect(await import("@agntn/keys")).not.toHaveProperty("extractSignatures");
  });
});

describe("Public BIP32 exports", () => {
  it("recovers a parent from the built package, outside the root", async () => {
    const { recoverParent, BIP32ChildMismatchError } = await import("@agntn/keys/bip32");
    const { xpub, xprv, child } = bip32ParentVector;
    expect(recoverParent(xpub, child.xprv).parent.privateExtendedKey).toBe(xprv);
    expect(() => recoverParent(xpub, hex.decode(child.privateKey), 1)).toThrow(
      BIP32ChildMismatchError,
    );
    expect(await import("@agntn/keys")).not.toHaveProperty("recoverParent");
  });
});

describe("Public keystore exports", () => {
  it("opens and writes a keystore from the built package, and nothing else from there", async () => {
    const store = await import("@agntn/keys/store");
    const { keystore, password, privateKey } = storeVectors[1];
    expect(hex.encode(store.decrypt(keystore, password))).toBe(privateKey);
    const file = store.encrypt(hex.decode(privateKey), password, {
      kdf: { kdf: "pbkdf2", c: 16 },
    });
    expect(hex.encode(store.decrypt(file, password))).toBe(privateKey);
    expect(() => store.decrypt(keystore, "wrong")).toThrow(store.KeystorePasswordError);
    expect(new Set(Object.keys(store))).toEqual(
      new Set(["KeystorePasswordError", "decrypt", "encrypt", "inspect"]),
    );
    expect(await import("@agntn/keys")).not.toHaveProperty("encrypt");
  });
});

describe("Public derivation exports", () => {
  it("exports explicit Electrum derivation from the built package", async () => {
    const { deriveSeed, inspect } = await import("@agntn/keys/electrum");
    const { blockchains } = await import("@agntn/keys");
    const { getMasterKeyFromSeed } = await import("@agntn/keys/bip32");
    const vector = electrumVectors[0];
    const seedType: ElectrumSeedType = inspect(vector.mnemonic);
    expect(seedType).toBe("segwit");
    const { seed } = deriveSeed(vector.mnemonic);
    expect(Buffer.from(seed).toString("hex")).toBe(vector.seed);
    const child = getMasterKeyFromSeed(seed).derive(vector.path);
    if (!child.privateKey) throw new Error("Missing private key");
    const bitcoin = await blockchains.bitcoin()();
    expect(
      bitcoin.deriveWallet(
        Buffer.from(child.privateKey).toString("hex"),
        { compressed: true },
        "segwit",
      ).address,
    ).toBe(vector.address);
  });

  it("keeps Electrum out of the root entry and its normalizer private", async () => {
    const root = await import("@agntn/keys");
    expect(root).not.toHaveProperty("deriveElectrumSeed");
    expect(root).not.toHaveProperty("inspectElectrumMnemonic");
    const electrum = await import("@agntn/keys/electrum");
    expect(new Set(Object.keys(electrum))).toEqual(
      new Set(["deriveOldMasterPublicKey", "deriveOldPublicKey", "deriveSeed", "inspect"]),
    );
  });

  it("exports checksum diagnostics and the explicit HD override from the built package", async () => {
    const { blockchains } = await import("@agntn/keys");
    const { inspect } = await import("@agntn/keys/bip39");
    const { mnemonic, path, address } = invalidChecksumPuzzle;
    const inspection: BIP39MnemonicInspection = inspect(mnemonic);
    expect(inspection).toMatchObject({
      valid: false,
      wordCountValid: true,
      wordlistValid: true,
      checksumValid: false,
    });
    const options: HDWalletOptions = { allowInvalidChecksum: true };
    const chain = await blockchains.bitcoin()();
    expect(() => chain.deriveHDWallet(mnemonic, path)).toThrow("Invalid BIP39 mnemonic");
    const wallet = chain.deriveHDWallet(mnemonic, path, options);
    expect(wallet.address).toBe(address);
    expect(wallet.warnings).toEqual([expect.stringContaining("checksum is invalid")]);
  });

  it("orders scattered words and expands abbreviations from the built package", async () => {
    const { orderWords, countWordOrders, lookupPrefixes } = await import("@agntn/keys/bip39");
    const { template, words, orders, mnemonic } = bip39WordOrderVector;
    expect(countWordOrders(words, { template })).toBe(BigInt(orders));
    let position = 0;
    for (const order of orderWords(words, { template })) {
      position++;
      if (order.join(" ") === mnemonic) break;
    }
    expect(position).toBe(37);
    expect(await lookupPrefixes(["abou"])).toEqual([
      { prefix: "abou", matches: [{ word: "about", zeroBasedIndex: 3 }] },
    ]);
  });

  it("repairs a mistyped word from the built package", async () => {
    const { repairWords, suggestWords } = await import("@agntn/keys/bip39");
    const { written, mnemonic } = bip39WordRepairVectors.typo;
    expect(suggestWords(written, { maxDistance: 1 })).toEqual([
      { position: 12, suggestions: [{ word: "about", zeroBasedIndex: 3, distance: 1 }] },
    ]);
    expect(repairWords(written)[0]).toEqual({ words: mnemonic.split(" "), distance: 1 });
  });

  it("drops the family from BIP39 export names", async () => {
    const bip39 = await import("@agntn/keys/bip39");
    for (const name of [
      "inspect",
      "loadWordlist",
      "lookupIndices",
      "lookupWords",
      "lookupPrefixes",
      "orderWords",
      "countWordOrders",
      "repairWords",
      "suggestWords",
    ])
      expect(bip39).toHaveProperty(name);
    for (const name of [
      "inspectBIP39Mnemonic",
      "loadBIP39Wordlist",
      "lookupBIP39Indices",
      "lookupBIP39Words",
    ])
      expect(bip39).not.toHaveProperty(name);
  });

  it("loads localized lists for the published BIP39 codec", async () => {
    const { loadWordlist, bip39, generateMnemonic, validateMnemonic } =
      await import("@agntn/keys/bip39");
    expect(validateMnemonic(generateMnemonic())).toBe(true);
    for (const { language, entropy, mnemonic } of localizedMnemonicVectors) {
      const wordlist = await loadWordlist(language);
      expect(bip39.entropyToMnemonic(Buffer.from(entropy, "hex"), wordlist)).toBe(mnemonic);
      expect(bip39.validateMnemonic(mnemonic.normalize("NFC"), wordlist)).toBe(true);
      expect(Buffer.from(bip39.mnemonicToEntropy(mnemonic, wordlist)).toString("hex")).toBe(
        entropy,
      );
    }
  });

  it.each(EXPORTS)("resolves %s", (specifier, path) => {
    expect(import.meta.resolve(specifier).endsWith(path)).toBe(true);
  });

  it("imports no Node builtin anywhere the library entry reaches", () => {
    const specifiers = new Set<string>();
    const visited = new Set<string>();
    const walk = (file: string): void => {
      if (visited.has(file)) {
        return;
      }
      visited.add(file);
      for (const [, specifier = ""] of readFileSync(file, "utf8").matchAll(IMPORT_SPECIFIER)) {
        if (specifier.startsWith(".")) {
          walk(resolve(dirname(file), specifier));
        } else if (specifier !== "") {
          specifiers.add(specifier);
        }
      }
    };
    walk(fileURLToPath(import.meta.resolve("@agntn/keys")));
    expect(visited.size).toBeGreaterThan(1);
    expect([...specifiers].filter((specifier) => specifier.startsWith("node:"))).toEqual([]);
  });
});

describe("Consumer bundles", () => {
  /**
   * Builds an app that imports one export from the built package.
   * @param name - Export the app imports and logs
   * @param from - Package entry the export comes from
   * @returns {Promise<string[]>} Code of every chunk the Vite build emits
   */
  const bundle = async (name: string, from = "@agntn/keys"): Promise<string[]> => {
    const result = await build({
      configFile: false,
      logLevel: "silent",
      plugins: [
        {
          name: "entry",
          enforce: "pre",
          resolveId: (id) => (id === "entry" ? "\0entry" : null),
          load: (id) =>
            id === "\0entry" ? `import { ${name} } from "${from}"; console.log(${name});` : null,
        },
      ],
      build: { write: false, minify: false, rollupOptions: { input: "entry" } },
    });
    const outputs = Array.isArray(result) ? result : [result];
    return outputs.flatMap((output) =>
      "output" in output
        ? output.output.flatMap((chunk) => (chunk.type === "chunk" ? [chunk.code] : []))
        : [],
    );
  };

  it.each([
    ["encode", "@agntn/keys/wif"],
    ["decode", "@agntn/keys/wif"],
    ["convertPublicKey", "@agntn/keys/secp256k1"],
    ["defineCurve", "@agntn/keys/curve"],
    ["derive", "@agntn/keys/brainwallet"],
    ["decrypt", "@agntn/keys/store"],
    ["decrypt", "@agntn/keys/bip38"],
    ["verify", "@agntn/keys/bip322"],
    ["extractSignatures", "@agntn/keys/transaction"],
  ])(
    "leaves the chain registry and the Electrum list out of an app importing %s from %s",
    async (name, from) => {
      const chunks = await bundle(name, from);
      expect(chunks).toHaveLength(1);
      expect(chunks[0]).not.toContain([...ELECTRUM_LEGACY_WORDS].slice(0, 8).join(" "));
    },
  );

  it("still splits every chain into its own chunk for an app importing blockchains", async () => {
    expect((await bundle("blockchains")).length).toBeGreaterThan(Object.keys(sourceChains).length);
  });
});

describe("Published dependencies", () => {
  it("declares exactly the packages the built files import", () => {
    const dist = fileURLToPath(new URL("../dist/", import.meta.url));
    const imported = new Set<string>();
    for (const file of readdirSync(dist, { recursive: true, encoding: "utf8" })) {
      if (!/\.m[jt]s$/u.test(file)) {
        continue;
      }
      for (const [, specifier = ""] of readFileSync(join(dist, file), "utf8").matchAll(
        IMPORT_SPECIFIER,
      )) {
        const name = PACKAGE_NAME.exec(specifier)?.[0];
        if (name !== undefined && !name.startsWith("node:")) {
          imported.add(name);
        }
      }
    }
    const manifest = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { dependencies: Record<string, string> };
    expect(imported).toEqual(new Set(Object.keys(manifest.dependencies)));
  });
});

interface PackedTool {
  readonly name: string;
  readonly execute: (
    toolCallId: string,
    params: Readonly<Record<string, unknown>>,
  ) => Promise<{ readonly content: unknown }>;
}

/** The OMP package root is TypeScript for Bun; the extension takes only `Text` from it. */
const ompHost = new URL("fixtures/omp-host.ts", import.meta.url);

describe("Published extensions", () => {
  it.each(["pi", "omp"])(
    "runs a tool from the %s extension with only the files npm ships",
    async (host) => {
      const manifest = JSON.parse(
        readFileSync(new URL("../package.json", import.meta.url), "utf8"),
      ) as { files: readonly string[] };
      const cache = fileURLToPath(new URL("../node_modules/.cache/", import.meta.url));
      mkdirSync(cache, { recursive: true });
      const copy = mkdtempSync(join(cache, "keys-files-"));
      try {
        for (const entry of [...manifest.files, "package.json"]) {
          cpSync(fileURLToPath(new URL(`../${entry}`, import.meta.url)), join(copy, entry), {
            recursive: true,
          });
        }
        const jiti = createJiti(import.meta.url, {
          moduleCache: false,
          tryNative: false,
          alias: { "@oh-my-pi/pi-coding-agent": fileURLToPath(ompHost) },
        });
        const extension = await jiti.import<(pi: ExtensionAPI) => Promise<void>>(
          join(copy, "packages", host, "extensions/keys.ts"),
          { default: true },
        );
        const tools = new Map<string, PackedTool>();
        /** SAFETY: the extension only calls registerTool and reads typebox during registration. */
        await extension({
          typebox: { Type: { Unsafe: (schema: unknown) => schema } },
          registerTool(tool: PackedTool) {
            tools.set(tool.name, tool);
          },
        } as unknown as ExtensionAPI);
        const vector = slip132Vectors[2];
        const result = await tools.get("keys_hd_wallet_derive")?.execute("packed", {
          chain: "bitcoin",
          mnemonic: bip39TestVectors.mnemonic,
          path: `${vector.path}/0/0`,
        });

        expect(JSON.stringify(result?.content)).toContain(vector.address);
      } finally {
        rmSync(copy, { recursive: true, force: true });
      }
    },
    30_000,
  );
});
