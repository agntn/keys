import { describe, expect, it } from "vite-plus/test";
import { bytesToHex } from "@noble/hashes/utils.js";
import { blockchains } from "../../src/index.ts";
import { mnemonicToSeed } from "../../src/utils/bip39/index.ts";
import { getMasterKeyFromSeed } from "../../src/utils/slip10/index.ts";
import { bip39TestVectors, invalidChecksumPuzzle } from "../fixtures.ts";

describe("HD checksum policy", () => {
  const { mnemonic, path, address, publicKey, withPassphrase } = invalidChecksumPuzzle;

  it("requires an explicit override and reproduces the claimed puzzle address without repair", async () => {
    const chain = await blockchains.bitcoin()();
    expect(() => chain.deriveHDWallet(mnemonic, path)).toThrow("Invalid BIP39 mnemonic");
    expect(() => chain.deriveHDWallet(mnemonic, path, { allowInvalidChecksum: false })).toThrow(
      "Invalid BIP39 mnemonic",
    );
    const wallet = chain.deriveHDWallet(mnemonic, path, { allowInvalidChecksum: true });
    expect(wallet.address).toBe(address);
    expect(wallet.keys.public).toBe(publicKey);
    expect(wallet.warnings).toEqual([
      "BIP39 checksum is invalid. Derived from the supplied words without repairing the checksum.",
    ]);
    expect(chain.deriveHDWallet(mnemonic.replace(/shine$/u, "solve"), path).address).not.toBe(
      address,
    );
  });

  it("preserves passphrase, path, network and explicit address type with the override", async () => {
    const chain = await blockchains.bitcoin({ network: "testnet" })();
    const { passphrase, path: changedPath, publicKey: expected } = withPassphrase;
    const wallet = chain.deriveHDWallet(
      mnemonic,
      changedPath,
      { passphrase, allowInvalidChecksum: true },
      "legacy",
    );
    expect(wallet.keys.public).toBe(expected);
    expect(wallet.address).toBe(chain.getAddress(expected, "legacy"));
    expect(wallet.address).not.toBe(address);
    expect(wallet.warnings).toHaveLength(1);
  });

  it("keeps valid mnemonics unchanged and preserves existing whitespace normalization", async () => {
    const chain = await blockchains.bitcoin()();
    const valid = bip39TestVectors.mnemonic;
    const original = chain.deriveHDWallet(valid, path);
    expect(chain.deriveHDWallet(valid, path, { allowInvalidChecksum: true })).toEqual(original);
    expect(original).not.toHaveProperty("warnings");
    const messy = `  ${mnemonic.replaceAll(" ", "\n  ")} `;
    expect(chain.deriveHDWallet(messy, path, { allowInvalidChecksum: true })).toEqual(
      chain.deriveHDWallet(mnemonic, path, { allowInvalidChecksum: true }),
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
    expect(() => chain.deriveHDWallet(candidate, path, { allowInvalidChecksum: true })).toThrow(
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
      const failure = () => chain.deriveHDWallet(candidate, path);
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
          path,
          { allowInvalidChecksum },
        ]);
      }).toThrow("allowInvalidChecksum must be a boolean");
    },
  );

  it("applies the same checksum policy to SLIP-10 without bypassing hardened paths", async () => {
    const chain = await blockchains.solana()();
    const solanaPath = "m/44'/501'/0'/0'";
    const key = getMasterKeyFromSeed(mnemonicToSeed(mnemonic)).derive(solanaPath).privateKey;
    const wallet = chain.deriveHDWallet(mnemonic, solanaPath, { allowInvalidChecksum: true });
    expect(wallet.address).toBe(chain.deriveWallet(bytesToHex(key)).address);
    expect(wallet.warnings).toHaveLength(1);
    expect(() => chain.deriveHDWallet(mnemonic, solanaPath)).toThrow("Invalid BIP39 mnemonic");
    expect(() =>
      chain.deriveHDWallet(mnemonic, "m/44'/501'/0'/0", { allowInvalidChecksum: true }),
    ).toThrow("Non-hardened");
  });
});
