import { describe, expect, it } from "vite-plus/test";
import { blockchains } from "../../src/_blockchains.ts";
import { getBlockchainPath } from "../../src/blockchain.ts";
import { recoverParent } from "../../src/utils/bip32/index.ts";
import * as bip39 from "../../src/utils/bip39/index.ts";
import { getPath } from "../../src/utils/bip44/index.ts";
import { deriveOldMasterPublicKey, deriveOldPublicKey } from "../../src/utils/electrum/index.ts";
import { deriveHDKey, getMasterKeyFromSeed } from "../../src/utils/slip10/index.ts";

const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const french = await bip39.loadWordlist("french");
const xpub =
  "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
const master = getMasterKeyFromSeed(new Uint8Array(32).fill(1));
const masterPublicKey = deriveOldMasterPublicKey(
  "powerful random nobody notice nothing important anyway look away hidden message over",
);

/* Unguarded, these ran on an empty passphrase or the English list, or threw the wrong error. */
const positionalCalls: [string, (...args: readonly never[]) => unknown, unknown[]][] = [
  ["mnemonicToSeed", bip39.mnemonicToSeed, [mnemonic, "TREZOR"]],
  ["validateMnemonic", bip39.validateMnemonic, [mnemonic, french]],
  ["mnemonicToEntropy", bip39.mnemonicToEntropy, [mnemonic, french]],
  ["entropyToMnemonic", bip39.entropyToMnemonic, [new Uint8Array(16), french]],
  ["inspect", bip39.inspect, [mnemonic, french, { coleman: true }]],
  ["getMnemonicWordCandidates", bip39.getMnemonicWordCandidates, [mnemonic, french, "French"]],
  ["slip10 deriveHDKey", deriveHDKey, [master, "m/0'", false]],
  ["deriveOldPublicKey", deriveOldPublicKey, [masterPublicKey, 0, 5]],
  ["recoverParent", recoverParent, [xpub, new Uint8Array(32).fill(1), 0]],
];

const names = Object.keys(blockchains) as (keyof typeof blockchains)[];

describe("calls still written with positional arguments", () => {
  it.each(names)("%s refuses a signature verified positionally", async (name) => {
    const chain = await blockchains[name]()();
    const wallet = chain.generateWallet();
    const signature = chain.signMessage("hi", { privateKey: wallet.keys.private });
    expect(chain.verifyMessage("hi", { signature, publicKey: wallet.keys.public })).toBe(true);
    expect(() => {
      Reflect.apply(chain.verifyMessage.bind(chain), undefined, [
        "hi",
        signature,
        wallet.keys.public,
      ]);
    }).toThrow(
      new TypeError(
        "verifyMessage takes the signature and the key in its options: verifyMessage(message, { signature, publicKey })",
      ),
    );
  });

  it.each(names)("%s refuses a key handed over positionally", async (name) => {
    const chain = await blockchains[name]()();
    const wallet = chain.generateWallet();
    expect(() => {
      Reflect.apply(chain.signMessage.bind(chain), undefined, ["hi", wallet.keys.private]);
    }).toThrow("signMessage takes the private key in its options");
  });

  /* Monero and Polkadot have no BIP44 path and throw for any arguments. */
  it.each(names.filter((name) => name !== "monero" && name !== "polkadot"))(
    "%s refuses an account number in place of the path options",
    async (name) => {
      const chain = await blockchains[name]()();
      expect(() => {
        Reflect.apply(chain.getDerivationPath.bind(chain), undefined, [1, 0, 5]);
      }).toThrow(TypeError);
      expect(() => {
        Reflect.apply(getBlockchainPath, undefined, [chain, 1, 0, 5]);
      }).toThrow("Derivation paths take their levels in an options object");
      expect(() => {
        Reflect.apply(chain.getDerivationPath.bind(chain), undefined, [[1, 0, 5]]);
      }).toThrow(TypeError);
    },
  );

  it("still reads a path left out or given as levels", async () => {
    const chain = await blockchains.bitcoin()();
    expect(getBlockchainPath(chain)).toBe("m/44'/0'/0'/0/0");
    expect(getBlockchainPath(chain, { account: 1, change: 1, addressIndex: 5 })).toBe(
      "m/44'/0'/1'/1/5",
    );
    expect(getBlockchainPath({ bip44: 2 }, { account: 3 })).toBe("m/44'/2'/3'/0/0");
  });

  it.each(positionalCalls)("%s refuses its old positional arguments", (_name, call, args) => {
    expect(() => {
      Reflect.apply(call, undefined, args);
    }).toThrow(/^Pass the options as an object: \w+\(/u);
  });

  it("lookupIndices rejects a language handed over positionally", async () => {
    await expect(
      Reflect.apply(bip39.lookupIndices, undefined, [[1], "italian", 1]),
    ).rejects.toThrow(
      "Pass the options as an object: lookupIndices(indices, { language, indexBase })",
    );
  });

  it("getPath refuses an account number in place of the levels", () => {
    expect(() => {
      Reflect.apply(getPath, undefined, [0, 1, 1, 5]);
    }).toThrow("Derivation paths take their levels in an options object");
    expect(getPath(0, { account: 1, change: 1, addressIndex: 5 })).toBe("m/44'/0'/1'/1/5");
  });
});
