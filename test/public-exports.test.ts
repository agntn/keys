import { describe, expect, it } from "vitest";
import type { DecodedWIF, WIFOptions, HDWalletOptions } from "@agntn/keys";
import type { BIP39MnemonicInspection } from "@agntn/keys/bip39";
import { wifTestVectors, localizedMnemonicVectors, invalidChecksumPuzzle } from "./fixtures.ts";

const EXPORTS = [
  ["@agntn/keys/bip32", "/dist/utils/bip32/index.mjs"],
  ["@agntn/keys/bip39", "/dist/utils/bip39/index.mjs"],
  ["@agntn/keys/slip10", "/dist/utils/slip10/index.mjs"],
] as const;

describe("Public WIF exports", () => {
  it("imports the built API and preserves compression when deriving a wallet", async () => {
    const { encodeWIF, decodeWIF, blockchains } = await import("@agntn/keys");
    const vector = wifTestVectors[1];
    const options: WIFOptions = { chain: vector.chain, compressed: vector.compressed };
    expect(encodeWIF(vector.privateKey, options)).toBe(vector.wif);
    const decoded: DecodedWIF = decodeWIF(vector.wif, options);
    const btc = await blockchains.bitcoin()();
    const wallet = btc.deriveWallet(decoded.privateKey, { compressed: decoded.compressed });
    expect(wallet).toEqual(btc.deriveWallet(vector.privateKey, { compressed: false }));
    expect(wallet.address).not.toBe(btc.deriveWallet(decoded.privateKey).address);
  });
});

describe("Public derivation exports", () => {
  it("exports checksum diagnostics and the explicit HD override from the built package", async () => {
    const { blockchains } = await import("@agntn/keys");
    const { inspectBIP39Mnemonic } = await import("@agntn/keys/bip39");
    const { mnemonic, path, address } = invalidChecksumPuzzle;
    const inspection: BIP39MnemonicInspection = inspectBIP39Mnemonic(mnemonic);
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

  it("loads localized lists for the published BIP39 codec", async () => {
    const { loadBIP39Wordlist, bip39, generateMnemonic, validateMnemonic } =
      await import("@agntn/keys/bip39");
    expect(validateMnemonic(generateMnemonic())).toBe(true);
    for (const { language, entropy, mnemonic } of localizedMnemonicVectors) {
      const wordlist = await loadBIP39Wordlist(language);
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
});
