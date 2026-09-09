import { describe, expect, it } from "vitest";
import type { DecodedWIF, WIFOptions } from "@agntn/keys";
import { wifTestVectors, localizedMnemonicVectors } from "./fixtures.ts";

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
