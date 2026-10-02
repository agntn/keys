import { describe, expect, it } from "vite-plus/test";
import { blockchains } from "../../src/_blockchains.ts";
import { TOOL_CHAINS } from "../../src/tool-parameters.ts";
import { deriveHDKey, getMasterKeyFromSeed } from "../../src/utils/bip32/index.ts";
import { mnemonicToSeed } from "../../src/utils/bip39/index.ts";
import { nodeWalker, scanSchemes, walkScheme } from "../../src/utils/hd-scan.ts";
import { bip39TestVectors } from "../fixtures.ts";

const first = { account: "0", change: "0", index: "0" } as const;

describe("wallet scan schemes", () => {
  it.each(["mainnet", "testnet"])(
    "opens every chain with the path its own class writes on %s",
    async (network) => {
      for (const chain of TOOL_CHAINS) {
        const schemes = scanSchemes(chain, network);
        if (chain === "decred" || chain === "cardano") {
          expect(schemes, chain).toBeUndefined();
          continue;
        }
        const opening = schemes?.[0];
        if (!opening) throw new Error(`${chain} has no scheme`);
        const blockchain = await blockchains[chain]({ network })();
        expect(
          opening.path.replaceAll(/\{(\w+)\}/gu, (_, name: keyof typeof first) => first[name]),
          chain,
        ).toBe(blockchain.getDerivationPath(0, 0, 0));
      }
    },
  );

  it("walks coin type 1 and then the mainnet coin type on a UTXO testnet", () => {
    const mainnet = scanSchemes("dogecoin", "mainnet");
    expect(scanSchemes("dogecoin", "testnet")).toEqual([
      {
        name: "bip44-testnet",
        path: "m/44'/1'/{account}'/{change}/{index}",
        addressType: "legacy",
      },
      ...(mainnet ?? []),
    ]);
    expect(scanSchemes("ethereum", "testnet")).toEqual(scanSchemes("ethereum", "mainnet"));
  });

  it("walks each path once under one name on every chain and network", () => {
    for (const chain of TOOL_CHAINS) {
      for (const network of ["mainnet", "testnet"]) {
        const schemes = scanSchemes(chain, network) ?? [];
        for (const key of ["name", "path"] as const) {
          const values = schemes.map((scheme) => scheme[key]);
          expect(new Set(values).size, `${chain} ${network} ${key}`).toBe(values.length);
        }
      }
    }
    expect(scanSchemes("ecash", "testnet")?.map((scheme) => scheme.name)).toEqual([
      "bip44-testnet",
      "bip44",
      "cashtab",
      "bitcoincash",
    ]);
  });
});

describe("walkScheme", () => {
  const scheme = { name: "bip84", path: "m/84'/0'/{account}'/{change}/{index}" };

  it("counts every path of the ranges and shows them in the template", () => {
    const visited: string[] = [];
    const walk = walkScheme(
      scheme,
      { accounts: 2, indices: 3 },
      (path) => {
        visited.push(path);
        return { publicKey: "", address: path };
      },
      () => false,
    );
    expect(walk).toEqual({
      tried: { scheme: "bip84", path: "m/84'/0'/{0,1}'/{0,1}/{0..2}", addresses: 12 },
    });
    expect(visited.slice(0, 4)).toEqual([
      "m/84'/0'/0'/0/0",
      "m/84'/0'/0'/0/1",
      "m/84'/0'/0'/0/2",
      "m/84'/0'/0'/1/0",
    ]);
    expect(new Set(visited).size).toBe(12);
  });

  it("stops at the match", () => {
    const walk = walkScheme(
      scheme,
      { accounts: 1, indices: 1 },
      (path) => ({ publicKey: "02", address: path }),
      (address) => address === "m/84'/0'/0'/1/0",
    );
    expect(walk.tried).toMatchObject({ path: "m/84'/0'/0'/{0,1}/0", addresses: 2 });
    expect(walk.match).toEqual({
      scheme: "bip84",
      path: "m/84'/0'/0'/1/0",
      publicKey: "02",
      address: "m/84'/0'/0'/1/0",
    });
  });
});

describe("nodeWalker", () => {
  it("reaches the key a full derivation reaches, parents cached or not", () => {
    const master = getMasterKeyFromSeed(mnemonicToSeed(bip39TestVectors.mnemonic));
    const nodeAt = nodeWalker(master);
    for (const path of ["m/84'/0'/0'/0/7", "m/84'/0'/0'/1/0", "m/0/0", "m/84'/0'/0'/0/8"]) {
      expect(nodeAt(path).privateKey, path).toEqual(deriveHDKey(master, path).privateKey);
    }
  });
});
