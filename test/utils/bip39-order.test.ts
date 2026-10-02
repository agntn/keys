import { describe, it, expect } from "vite-plus/test";
import {
  countWordOrders,
  orderWords,
  validateMnemonic,
  entropyToMnemonic,
  inspect,
  loadWordlist,
} from "../../src/utils/bip39";
import { bip39TestVectors, bip39WordOrderVector, localizedMnemonicVectors } from "../fixtures";

describe("BIP39 word orders", () => {
  it("yields every order of the loose words that passes the checksum", () => {
    const { mnemonic, template, words, orders, valid, first } = bip39WordOrderVector;
    const found = [...orderWords(words, { template })].map((order) => order.join(" "));

    expect(countWordOrders(words, { template })).toBe(BigInt(orders));
    expect(found).toHaveLength(valid);
    expect(new Set(found).size).toBe(valid);
    expect(found[0]).toBe(first);
    expect(found).toContain(mnemonic);
    for (const order of found) expect(validateMnemonic(order)).toBe(true);
  });

  it.each([16, 20, 24, 28, 32])(
    "matches a brute force checksum check at %i bytes of entropy",
    (bytes) => {
      const words = entropyToMnemonic(new Uint8Array(bytes).fill(0x7f)).split(" ");
      const loose = words.slice(-5);
      const known = words.slice(0, -5);
      const template = [...known, "?", "?", "?", "?", "?"].join(" ");
      const permute = (rest: readonly string[]): string[][] =>
        rest.length === 0
          ? [[]]
          : rest.flatMap((word, index) =>
              permute([...rest.slice(0, index), ...rest.slice(index + 1)]).map((tail) => [
                word,
                ...tail,
              ]),
            );
      const expected = new Set(
        permute(loose)
          .map((tail) => [...known, ...tail].join(" "))
          .filter((phrase) => validateMnemonic(phrase)),
      );

      const found = [...orderWords(loose, { template })].map((order) => order.join(" "));
      expect(new Set(found)).toEqual(expected);
      expect(found).toHaveLength(expected.size);
      expect(found).toContain(words.join(" "));
    },
  );

  it("gives an order once when a word appears twice", () => {
    const template = bip39TestVectors.mnemonic.split(" ").slice(0, 9).join(" ") + " ? ? ?";
    const words = ["about", "abandon", "abandon"];

    expect(countWordOrders(words, { template })).toBe(3n);
    expect([...orderWords(words, { template })].map((order) => order.join(" "))).toEqual([
      bip39TestVectors.mnemonic,
    ]);
  });

  it("opens every position without a template and counts past the safe integer range", async () => {
    const words = bip39TestVectors.mnemonic.split(" ");
    const distinct = (await loadWordlist()).slice(0, 24);

    expect(countWordOrders(words)).toBe(12n);
    expect([...orderWords(words)].map((order) => order.join(" "))).toEqual([
      bip39TestVectors.mnemonic,
    ]);
    expect(countWordOrders([...words, ...words])).toBe(276n);
    expect(countWordOrders(distinct)).toBe(620_448_401_733_239_439_360_000n);
  });

  it("reports progress once at the end of a short search and stops when the caller breaks", () => {
    const { template, words, orders } = bip39WordOrderVector;
    const progress: number[] = [];
    const all = [
      ...orderWords(words, { template, onProgress: (checked) => progress.push(checked) }),
    ];
    expect(all.length).toBeGreaterThan(0);
    expect(progress).toEqual([orders]);

    const early: number[] = [];
    for (const order of orderWords(words, {
      template,
      onProgress: (checked) => early.push(checked),
    })) {
      expect(validateMnemonic(order.join(" "))).toBe(true);
      break;
    }
    expect(early).toEqual([]);
  });

  it.each(localizedMnemonicVectors)(
    "orders scattered $language words from the selected list",
    async ({ language, mnemonic }) => {
      const wordlist = await loadWordlist(language);
      const words = mnemonic.normalize("NFKD").split(/\s+/u);
      const template = [...words.slice(0, -4), "?", "?", "?", "?"].join(" ");
      const found = [...orderWords(words.slice(-4).reverse(), { template, wordlist })];

      expect(found.map((order) => order.join(" "))).toContain(words.join(" "));
      for (const order of found) expect(inspect(order.join(" "), wordlist).valid).toBe(true);
    },
  );

  it("refuses words, templates and lists that cannot make a phrase, never echoing a word", async () => {
    const { template, words } = bip39WordOrderVector;
    const italian = await loadWordlist("italian");

    expect(() => countWordOrders(words.slice(1), { template })).toThrow(
      "The template has 6 open positions for 5 words",
    );
    expect(() => countWordOrders(["yellow", "thank"], { template: "legal ? ?" })).toThrow(
      "12, 15, 18, 21, or 24 words",
    );
    expect(() => [...orderWords(["yelow", ...words.slice(1)], { template })]).toThrow(
      "Word 1 is not in the English list",
    );
    expect(() => countWordOrders(words, { template: template.replace("wave", "wav") })).toThrow(
      "Template word 5 is not in the English list",
    );
    expect(() =>
      countWordOrders(words, { template, wordlist: italian, listName: "italian" }),
    ).toThrow("Words 1, 2, 3, 4, 5, 6 are not in the italian list");
    expect(() => countWordOrders(words, { template, wordlist: italian.slice(1) })).toThrow(
      "BIP39 word list of 2048 words",
    );
  });
});
