import { describe, expect, it } from "vite-plus/test";
import { blockchains } from "../../src/index.ts";
import { getMasterKeyFromSeed as getBIP32MasterKey } from "../../src/utils/bip32/index.ts";
import { loadWordlist } from "../../src/utils/bip39/index.ts";
import { deriveSeed as deriveElectrumSeed } from "../../src/utils/electrum/index.ts";
import { deriveMnemonicKey } from "../../src/utils/hd.ts";
import { getMasterKeyFromSeed as getSLIP10MasterKey } from "../../src/utils/slip10/index.ts";
import { hex } from "@agntn/encodings/hex";
import {
  bip39TestVectors,
  colemanBadChecksum,
  colemanMnemonicVectors,
  electrumVectors,
  invalidChecksumPuzzle,
  italianBadChecksumVector,
  localizedMnemonicVectors,
} from "../fixtures.ts";

describe("HD checksum policy", () => {
  const { mnemonic, path, address, publicKey, withPassphrase, solana } = invalidChecksumPuzzle;

  it("requires an explicit override and reproduces the claimed puzzle address without repair", async () => {
    const chain = await blockchains.bitcoin()();
    expect(() => chain.deriveHDWallet(mnemonic, { path })).toThrow("Invalid BIP39 mnemonic");
    expect(() => chain.deriveHDWallet(mnemonic, { path, allowInvalidChecksum: false })).toThrow(
      "Invalid BIP39 mnemonic",
    );
    const wallet = chain.deriveHDWallet(mnemonic, { path, allowInvalidChecksum: true });
    expect(wallet.address).toBe(address);
    expect(wallet.keys.public).toBe(publicKey);
    expect(wallet.warnings).toEqual([
      "BIP39 checksum is invalid. Derived from the supplied words without repairing the checksum.",
    ]);
    expect(chain.deriveHDWallet(mnemonic.replace(/shine$/u, "solve"), { path }).address).not.toBe(
      address,
    );
  });

  it("preserves passphrase, path, network and explicit address type with the override", async () => {
    const chain = await blockchains.bitcoin({ network: "testnet" })();
    const { passphrase, path: changedPath, publicKey: expected } = withPassphrase;
    const wallet = chain.deriveHDWallet(mnemonic, {
      path: changedPath,
      passphrase,
      allowInvalidChecksum: true,
      addressType: "legacy",
    });
    expect(wallet.keys.public).toBe(expected);
    expect(wallet.address).toBe(chain.getAddress(expected, "legacy"));
    expect(wallet.address).not.toBe(address);
    expect(wallet.warnings).toHaveLength(1);
  });

  it("keeps valid mnemonics unchanged and preserves existing whitespace normalization", async () => {
    const chain = await blockchains.bitcoin()();
    const valid = bip39TestVectors.mnemonic;
    const original = chain.deriveHDWallet(valid, { path });
    expect(chain.deriveHDWallet(valid, { path, allowInvalidChecksum: true })).toEqual(original);
    expect(original).not.toHaveProperty("warnings");
    const messy = `  ${mnemonic.replaceAll(" ", "\n  ")} `;
    expect(chain.deriveHDWallet(messy, { path, allowInvalidChecksum: true })).toEqual(
      chain.deriveHDWallet(mnemonic, { path, allowInvalidChecksum: true }),
    );
  });

  it.each([
    "",
    "abandon",
    Array.from({ length: 13 }, () => "abandon").join(" "),
    invalidChecksumPuzzle.mnemonic.replace("path", "notaword"),
    invalidChecksumPuzzle.mnemonic.toUpperCase(),
  ])("does not bypass word count or dictionary checks for %j", async (candidate) => {
    const chain = await blockchains.bitcoin()();
    expect(() => chain.deriveHDWallet(candidate, { path, allowInvalidChecksum: true })).toThrow(
      "Invalid BIP39 mnemonic",
    );
  });

  it("names the failed check by word position without echoing the words", async () => {
    const chain = await blockchains.bitcoin()();
    const words = mnemonic.split(" ");
    const position = words.indexOf("path") + 1;
    const cases = [
      [
        words.slice(0, 11).join(" "),
        "Invalid BIP39 mnemonic: 11 words, expected 12, 15, 18, 21 or 24",
      ],
      [
        mnemonic.replace("path", "notaword"),
        `Invalid BIP39 mnemonic: word ${position} is not in the English list`,
      ],
      [
        words.map((word, index) => (index < 2 ? `${word}x` : word)).join(" "),
        "Invalid BIP39 mnemonic: words 1, 2 are not in the English list",
      ],
      [mnemonic.toUpperCase(), "Invalid BIP39 mnemonic: none of the words is in the English list"],
      [
        mnemonic,
        "Invalid BIP39 mnemonic: the checksum does not match. allowInvalidChecksum derives from it anyway",
      ],
    ] as const;
    for (const [candidate, message] of cases) {
      const failure = () => chain.deriveHDWallet(candidate, { path });
      expect(failure).toThrow(message);
      expect(failure).not.toThrow(/notaword|path|goddess|leopard|shine/iu);
    }
  });

  it.each(["true", "false", 1, null])(
    "rejects a non-boolean override %j",
    async (allowInvalidChecksum) => {
      const chain = await blockchains.bitcoin()();
      expect(() => {
        Reflect.apply(chain.deriveHDWallet.bind(chain), undefined, [
          mnemonic,
          { path, allowInvalidChecksum },
        ]);
      }).toThrow("allowInvalidChecksum must be a boolean");
    },
  );

  it("applies the same checksum policy to SLIP-10 without bypassing hardened paths", async () => {
    const chain = await blockchains.solana()();
    const wallet = chain.deriveHDWallet(mnemonic, {
      path: solana.path,
      allowInvalidChecksum: true,
    });
    expect(wallet.address).toBe(solana.address);
    expect(wallet.warnings).toHaveLength(1);
    expect(() => chain.deriveHDWallet(mnemonic, { path: solana.path })).toThrow(
      "Invalid BIP39 mnemonic",
    );
    expect(() =>
      chain.deriveHDWallet(mnemonic, { path: "m/44'/501'/0'/0", allowInvalidChecksum: true }),
    ).toThrow("level 4 of the derivation path needs ' or h");
  });
});

describe("HD curves", () => {
  it("refuses to walk BIP32 or SLIP-10 for an sr25519 key", () => {
    expect(() =>
      deriveMnemonicKey(bip39TestVectors.mnemonic, { path: "m/0'", curve: "sr25519" }),
    ).toThrow("sr25519 keys walk Substrate junctions");
  });
});

describe("HD word lists", () => {
  const path = "m/44'/0'/0'/0/0";
  const italian = localizedMnemonicVectors.find((vector) => vector.language === "italian");
  if (!italian) throw new Error("Missing the Italian vector");

  it.each(localizedMnemonicVectors)(
    "derives a $language mnemonic from its own list",
    async ({ language, mnemonic, publicKey: expected }) => {
      const chain = await blockchains.bitcoin()();
      const wallet = chain.deriveHDWallet(mnemonic, {
        path,
        passphrase: bip39TestVectors.passphrase,
        wordlist: await loadWordlist(language),
      });
      expect(wallet.keys.public).toBe(expected);
      expect(wallet).not.toHaveProperty("warnings");
    },
  );

  it("keeps English as the default list", async () => {
    const chain = await blockchains.bitcoin()();
    expect(() => chain.deriveHDWallet(italian.mnemonic, { path })).toThrow(
      "Invalid BIP39 mnemonic: none of the words is in the English list",
    );
    const wordlist = await loadWordlist("italian");
    expect(() => chain.deriveHDWallet(bip39TestVectors.mnemonic, { path, wordlist })).toThrow(
      "Invalid BIP39 mnemonic: none of the words is in the selected list",
    );
  });

  it("lets allowInvalidChecksum skip only the checksum of the selected list", async () => {
    const chain = await blockchains.bitcoin()();
    const wordlist = await loadWordlist("italian");
    const { mnemonic: badChecksum, publicKey: expected } = italianBadChecksumVector;
    expect(() => chain.deriveHDWallet(badChecksum, { path, wordlist })).toThrow(
      "the checksum does not match",
    );
    const wallet = chain.deriveHDWallet(badChecksum, {
      path,
      wordlist,
      allowInvalidChecksum: true,
    });
    expect(wallet.keys.public).toBe(expected);
    expect(wallet.warnings).toHaveLength(1);
    expect(() =>
      chain.deriveHDWallet(italian.mnemonic.replace(/abete$/u, "about"), {
        path,
        wordlist,
        allowInvalidChecksum: true,
      }),
    ).toThrow("Invalid BIP39 mnemonic: word 12 is not in the selected list");
  });

  it.each([[[]], [["abaco", "abete"]], ["abaco abete"]])(
    "refuses a word list that is not 2048 words: %j",
    async (wordlist) => {
      const chain = await blockchains.bitcoin()();
      expect(() => {
        Reflect.apply(chain.deriveHDWallet.bind(chain), undefined, [
          italian.mnemonic,
          { path, wordlist, allowInvalidChecksum: true },
        ]);
      }).toThrow("wordlist must be a BIP39 word list of 2048 words");
    },
  );
});

describe("Coleman lengths through the chain classes", () => {
  const [three, , six] = colemanMnemonicVectors;
  const lengthWarning =
    "Not a BIP39 length. Derived the way Ian Coleman's tool reads it; wallet apps will refuse these words.";

  it("walks the seed Coleman's codec gives, with a warning", async () => {
    const chain = await blockchains.bitcoin()();
    const path = "m/84'/0'/0'/0/0";
    const key = getBIP32MasterKey(hex.decode(six.seed)).derive(path).privateKey;
    const wallet = chain.deriveHDWallet(six.mnemonic, {
      path,
      passphrase: six.passphrase,
      coleman: true,
    });
    expect(wallet).toEqual({
      ...chain.deriveWallet(hex.encode(key ?? new Uint8Array()), { addressType: "segwit" }),
      warnings: [lengthWarning],
    });
    expect(() => chain.deriveHDWallet(six.mnemonic, { path })).toThrow(
      "Invalid BIP39 mnemonic: 6 words, expected 12, 15, 18, 21 or 24",
    );
  });

  it("walks SLIP-10 on ed25519 chains", async () => {
    const chain = await blockchains.solana()();
    const path = "m/44'/501'/0'/0'";
    const key = getSLIP10MasterKey(hex.decode(three.seed)).derive(path).privateKey;
    const wallet = chain.deriveHDWallet(three.mnemonic, { path, coleman: true });
    expect(wallet.keys.public).toBe(
      chain.deriveWallet(hex.encode(key ?? new Uint8Array())).keys.public,
    );
    expect(wallet.warnings).toEqual([lengthWarning]);
  });

  it("stacks the checksum warning and keeps standard lengths quiet", async () => {
    const chain = await blockchains.ethereum()();
    const path = "m/44'/60'/0'/0/0";
    expect(() => chain.deriveHDWallet(colemanBadChecksum, { path, coleman: true })).toThrow(
      "the checksum does not match",
    );
    const repaired = chain.deriveHDWallet(colemanBadChecksum, {
      path,
      coleman: true,
      allowInvalidChecksum: true,
    });
    expect(repaired.warnings).toHaveLength(2);
    expect(chain.deriveHDWallet(bip39TestVectors.mnemonic, { path, coleman: true })).toEqual(
      chain.deriveHDWallet(bip39TestVectors.mnemonic, { path }),
    );
    expect(() => chain.deriveHDWallet("abandon abandon", { path, coleman: true })).toThrow(
      "2 words, expected a multiple of 3 from 3 to 768",
    );
  });

  it("keeps the option out of the key options on Sui", async () => {
    const chain = await blockchains.sui()();
    const path = "m/54'/784'/0'/0/0";
    const wallet = chain.deriveHDWallet(three.mnemonic, {
      path,
      coleman: true,
      addressType: "secp256k1",
    });
    const key = getBIP32MasterKey(hex.decode(three.seed)).derive(path).privateKey;
    expect(wallet.keys.public).toBe(
      chain.deriveWallet(hex.encode(key ?? new Uint8Array()), { addressType: "secp256k1" }).keys
        .public,
    );
  });

  it("refuses it on Polkadot, which derives from entropy as subkey does", async () => {
    const chain = await blockchains.polkadot()();
    expect(() => chain.deriveHDWallet(three.mnemonic, { path: "m", coleman: true })).toThrow(
      "Polkadot reads BIP39 lengths only",
    );
  });
});

describe("Electrum wallets through the chain classes", () => {
  const [segwit] = electrumVectors;
  const seed = deriveElectrumSeed(segwit.mnemonic);

  it.each(["dogecoin", "ethereum", "cosmos"] as const)(
    "gives %s the key the seed walks to, in the chain's own address",
    async (name) => {
      const chain = await blockchains[name]()();
      const wallet = chain.deriveElectrumWallet(seed, { path: segwit.path });
      expect(wallet.keys.public).toBe(segwit.publicKey);
      expect(wallet.address).toBe(chain.getAddress(segwit.publicKey));
    },
  );

  it("walks secp256k1 on Sui when the scheme or the address type asks for it", async () => {
    const chain = await blockchains.sui()();
    const fromAddressType = chain.deriveElectrumWallet(seed, {
      path: segwit.path,
      addressType: "secp256k1",
    });
    const fromScheme = chain.deriveElectrumWallet(seed, { path: segwit.path, scheme: "secp256k1" });

    expect(fromAddressType).toEqual(fromScheme);
    expect(fromAddressType.keys.public).toBe(segwit.publicKey);
    expect(fromAddressType.address).toBe(chain.getAddress(segwit.publicKey, "secp256k1"));
    expect(() => chain.deriveElectrumWallet(seed, { path: segwit.path })).toThrow(
      "sui ed25519 keys do not derive from Electrum seeds",
    );
  });

  it.each(["solana", "cardano", "monero"] as const)(
    "refuses %s, whose keys are ed25519",
    async (name) => {
      const chain = await blockchains[name]()();
      expect(() => chain.deriveElectrumWallet(seed, { path: segwit.path })).toThrow(
        `${name} ed25519 keys do not derive from Electrum seeds`,
      );
    },
  );

  it.each(["sr25519", "ed25519"])("refuses polkadot %s keys", async (scheme) => {
    const chain = await blockchains.polkadot()();
    expect(() => chain.deriveElectrumWallet(seed, { path: segwit.path, scheme })).toThrow(
      `polkadot ${scheme} keys do not derive from Electrum seeds`,
    );
  });

  it("refuses ed25519 on the XRP Ledger and walks secp256k1", async () => {
    const chain = await blockchains.xrpl()();
    expect(() =>
      chain.deriveElectrumWallet(seed, { path: segwit.path, addressType: "ed25519" }),
    ).toThrow("xrpl ed25519 keys do not derive from Electrum seeds");
    const wallet = chain.deriveElectrumWallet(seed, { path: segwit.path });
    expect(wallet.keys.public).toBe(segwit.publicKey);
    expect(wallet.address).toBe(chain.getAddress(segwit.publicKey));
  });
});
