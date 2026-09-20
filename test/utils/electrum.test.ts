import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it } from "vitest";
import { deriveElectrumSeed, inspectElectrumMnemonic } from "../../src/index.ts";
import { normalizeElectrumText } from "../../src/utils/electrum.ts";
import { deriveElectrumWallet } from "../../src/tool-operations.ts";
import { deriveMnemonicKey } from "../../src/utils/hd.ts";
import { electrumVectors } from "../fixtures.ts";

describe("Electrum seed derivation", () => {
  it.each(electrumVectors)("matches upstream seed bytes and addresses: $name", async (vector) => {
    expect(inspectElectrumMnemonic(vector.mnemonic)).toBe(vector.seedType);
    const result = deriveElectrumSeed(vector.mnemonic, vector.passphrase);
    expect(bytesToHex(result.seed)).toBe(vector.seed);
    expect(result.scheme).toBe("electrum");
    const wallet = await deriveElectrumWallet(vector.mnemonic, vector.path, vector.passphrase);
    expect(wallet.details).toMatchObject({
      address: vector.address,
      publicKey: vector.publicKey,
      seedType: vector.seedType,
      scheme: "electrum",
    });
    expect(wallet.details).not.toHaveProperty("privateKey");
    expect(wallet.details).not.toHaveProperty("seed");
  });

  it("normalizes case, accents and whitespace in phrases and passphrases", () => {
    const vector = electrumVectors[0];
    expect(
      deriveElectrumSeed(
        `  ${vector.mnemonic.toUpperCase().replaceAll(" ", "\n\t")} `,
        "  CAFÉ\nTEST ",
      ),
    ).toEqual(deriveElectrumSeed(vector.mnemonic, "cafe test"));
    expect(normalizeElectrumText("a\u034F\uFE0F é \u0903")).toBe("a\u034F\uFE0F e \u0903");
    expect(normalizeElectrumText("眼 \u{20000} 悲")).toBe("眼\u{20000}悲");
    expect(normalizeElectrumText("a\u0085b\u001Cc")).toBe("a b c");
    expect(normalizeElectrumText("\uFEFFa\uFEFF")).toBe("\uFEFFa\uFEFF");
  });

  it.each([
    ["cell dumb heartbeat north boom tease ship baby bright kingdom rare squeeze", "old"],
    ["8edad31a95e7d59f8837667510d75a4d", "old"],
    ["science dawn member doll dutch real can brick knife deny drive list", "2fa"],
    ["science dawn member doll dutch real can brick knife deny drive list \u0301", "unknown"],
    ["agree install", "2fa_segwit"],
    ["not a seed", "unknown"],
  ])("rejects unsupported versions without exposing the phrase", (phrase, seedType) => {
    expect(inspectElectrumMnemonic(phrase)).toBe(seedType);
    expect(() => deriveElectrumSeed(phrase)).toThrow(
      "Unsupported or unrecognized Electrum seed version",
    );
  });

  it.each([12, 13, 19, 20, 21, 24, 25])(
    "preserves Electrum's 2FA classification at %i words",
    (count) => {
      const phrase = "science dawn member doll dutch real can brick knife deny drive list";
      const candidate = phrase + " \u0301".repeat(count - 12);
      expect(normalizeElectrumText(candidate)).toBe(phrase);
      expect(inspectElectrumMnemonic(candidate)).toBe(
        count === 12 || count >= 20 ? "2fa" : "unknown",
      );
    },
  );

  it("does not confuse BIP39 checksum bypass with Electrum derivation", async () => {
    const vector = electrumVectors[0];
    expect(() => deriveMnemonicKey(vector.mnemonic, vector.path, "secp256k1")).toThrow(
      "Invalid BIP39 mnemonic",
    );
    const bip39 = deriveMnemonicKey(vector.mnemonic, vector.path, "secp256k1", "", true);
    const { blockchains } = await import("../../src/index.ts");
    const bitcoin = await blockchains.bitcoin()();
    expect(bitcoin.deriveWallet(bip39.privateKey, { compressed: true }, "segwit").address).not.toBe(
      vector.address,
    );
  });

  it("rejects malformed direct executor inputs", async () => {
    const vector = electrumVectors[0];
    for (const args of [
      [vector.mnemonic, "m/not-a-path"],
      [vector.mnemonic, "m" + "/0".repeat(128)],
      [vector.mnemonic, vector.path, "\uD800"],
      [vector.mnemonic, vector.path, false],
      [vector.mnemonic, vector.path, "", "wrong-network"],
      ["x".repeat(4097), vector.path],
      [vector.mnemonic, vector.path, "x".repeat(4097)],
    ]) {
      await expect(deriveElectrumWallet(args[0], args[1], args[2], args[3])).rejects.toThrow();
    }
  });
});
