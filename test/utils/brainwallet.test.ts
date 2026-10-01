import { describe, expect, it } from "vite-plus/test";
import { hex } from "@scure/base";
import { derive } from "../../src/utils/brainwallet/index.ts";
import { brainwalletInput, brainwalletVectors, plainBrainwalletVectors } from "../fixtures.ts";

const { passphrase, salt, saltHex } = brainwalletInput;
const [scryptHex, scryptBytes] = brainwalletVectors;

describe("brainwallet derive", () => {
  it.each(brainwalletVectors)(
    "derives $privateKey from $recipe.kdf and hashed $recipe.hashed",
    ({ recipe, privateKey }) => {
      expect(hex.encode(derive(passphrase, { ...recipe, salt }))).toBe(privateKey);
    },
  );

  it("gives another key when SHA-256 reads the hex text instead of the bytes", () => {
    expect(scryptHex.privateKey).not.toBe(scryptBytes.privateKey);
  });

  it("reads a text salt as the UTF-8 bytes it encodes", () => {
    const key = derive(passphrase, { ...scryptHex.recipe, salt: hex.decode(saltHex) });
    expect(hex.encode(key)).toBe(scryptHex.privateKey);
  });

  it("keeps the passphrase exactly as given", () => {
    const padded = derive(` ${passphrase}`, { ...scryptHex.recipe, salt });
    expect(hex.encode(padded)).not.toBe(scryptHex.privateKey);
  });

  it("refuses an N that is not a power of 2", () => {
    expect(() => derive(passphrase, { ...scryptHex.recipe, N: 1000, salt })).toThrow(/N/);
  });

  it.each(plainBrainwalletVectors)(
    "derives $privateKey straight from $recipe.kdf of the passphrase",
    ({ passphrase: plain, recipe, privateKey }) => {
      expect(hex.encode(derive(plain, recipe))).toBe(privateKey);
    },
  );

  it("runs one round of the digest unless told otherwise", () => {
    const [, rounds] = plainBrainwalletVectors;
    const once = derive(rounds.passphrase, { kdf: "sha256" });
    expect(hex.encode(derive(rounds.passphrase, { kdf: "sha256", iterations: 1 }))).toBe(
      hex.encode(once),
    );
    expect(hex.encode(once)).not.toBe(rounds.privateKey);
  });

  it.each([0, 1.5, -1])("refuses %s rounds", (iterations) => {
    expect(() => derive(passphrase, { kdf: "sha256", iterations })).toThrow(/iterations/);
  });
});
