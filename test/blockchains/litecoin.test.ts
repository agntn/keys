import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { base58check, bech32, bech32m } from "@scure/base";
import { HDNodeWallet } from "ethers";
import { describe, expect, it } from "vitest";
import { blockchains, getBlockchainPath } from "../../src/index.ts";
import Bitcoin from "../../src/blockchains/bitcoin.ts";
import Litecoin, { Litecoin as NamedLitecoin } from "../../src/blockchains/litecoin.ts";
import {
  bip39TestVectors,
  bitcoinTestVectors,
  litecoinTestVectors as vector,
} from "../fixtures.ts";

const base58 = base58check(sha256);
const formats = ["legacy", "p2sh", "segwit", "p2wsh", "taproot"] as const;

describe("Litecoin", () => {
  it("loads through the public registry with SLIP-0044 coin type 2", async () => {
    const chain = await blockchains.litecoin()();
    expect(chain).toBeInstanceOf(NamedLitecoin);
    expect(chain.name).toBe("litecoin");
    expect(chain.curve).toBe("secp256k1");
    expect(getBlockchainPath(chain, 0, 1, 3)).toBe("m/44'/2'/0'/1/3");
    expect(chain.getKeyPublic(vector.privateKey)).toBe(vector.publicKey);
    expect(chain.deriveWallet(vector.privateKey).address).toBe(vector.address);
    expect(() => new Litecoin({ network: "regtest" })).toThrow("mainnet and testnet only");
  });

  for (const [network, p2pkh, p2sh, hrp] of [
    ["mainnet", 48, 50, "ltc"],
    ["testnet", 111, 58, "tltc"],
  ] as const) {
    const chain = new Litecoin({ network });
    const otherNetwork = new Litecoin({ network: network === "mainnet" ? "testnet" : "mainnet" });

    it(`${network} encodes the Core network prefixes and witness programs`, () => {
      const legacy = base58.decode(chain.getAddress(vector.publicKey));
      expect(legacy[0]).toBe(p2pkh);
      expect(bytesToHex(legacy.slice(1))).toBe(vector.publicKeyHash);
      const nested = base58.decode(chain.getAddress(vector.publicKey, "p2sh"));
      expect(nested[0]).toBe(p2sh);
      expect(nested.length).toBe(21);
      for (const type of ["segwit", "p2wsh", "taproot"] as const) {
        const codec = type === "taproot" ? bech32m : bech32;
        const decoded = codec.decode(chain.getAddress(vector.publicKey, type));
        expect(decoded.prefix).toBe(hrp);
        expect(decoded.words[0]).toBe(type === "taproot" ? 1 : 0);
        expect(codec.fromWords(decoded.words.slice(1)).length).toBe(type === "segwit" ? 20 : 32);
        if (type === "segwit") {
          expect(bytesToHex(codec.fromWords(decoded.words.slice(1)))).toBe(vector.publicKeyHash);
        }
      }
    });

    it.each(formats)(
      `${network} validates %s and rejects corruption and the other network`,
      (type) => {
        const address = chain.getAddress(vector.publicKey, type);
        expect(chain.validateAddress(address)).toBe(true);
        expect(otherNetwork.validateAddress(address)).toBe(false);
        expect(
          chain.validateAddress(address.slice(0, -1) + (address.endsWith("q") ? "p" : "q")),
        ).toBe(false);
        if (address.startsWith(hrp + "1")) {
          expect(chain.validateAddress(address.toUpperCase())).toBe(true);
          expect(chain.validateAddress(address[0]!.toUpperCase() + address.slice(1))).toBe(false);
        }
      },
    );

    it(`${network} accepts the old P2SH prefix without generating it`, () => {
      expect(chain.validateAddress(bitcoinTestVectors.addresses.p2sh[network])).toBe(true);
      expect(chain.getAddress(vector.publicKey, "p2sh")).not.toMatch(/^[32]/);
    });
  }

  it("rejects Bitcoin mainnet and witness addresses, malformed keys, and MWEB", () => {
    const chain = new Litecoin();
    const bitcoin = new Bitcoin();
    for (const type of ["legacy", "segwit", "taproot"]) {
      expect(chain.validateAddress(bitcoin.getAddress(vector.publicKey, type))).toBe(false);
    }
    for (const address of ["", "L".repeat(34), "ltcmweb1invalid"]) {
      expect(chain.validateAddress(address)).toBe(false);
    }
    expect(() => chain.getAddress("02")).toThrow();
    expect(() => chain.deriveWallet("00".repeat(32))).toThrow();
  });

  it.each([
    [44, "legacy"],
    [49, "p2sh"],
    [84, "segwit"],
    [86, "taproot"],
  ] as const)(
    "derives purpose %s through BIP32 and preserves an explicit address type",
    (purpose, format) => {
      const chain = new Litecoin();
      const path = `m/${purpose}'/2'/0'/1/2`;
      const wallet = chain.deriveHDWallet(bip39TestVectors.mnemonic, path, {
        passphrase: "TREZOR",
      });
      const independent = HDNodeWallet.fromPhrase(bip39TestVectors.mnemonic, "TREZOR", path);
      expect(wallet.keys.private).toBe(independent.privateKey.slice(2));
      expect(wallet.address).toBe(chain.getAddress(independent.publicKey.slice(2), format));
      expect(
        chain.deriveHDWallet(bip39TestVectors.mnemonic, path, { passphrase: "TREZOR" }, "legacy")
          .address,
      ).toBe(chain.getAddress(independent.publicKey.slice(2), "legacy"));
    },
  );

  it.each(vector.messageHashes)(
    "signs Core message vector %# without another hash",
    (message, digest) => {
      const chain = new Litecoin();
      const signature = chain.signMessage(message, vector.privateKey);
      expect(
        secp256k1.verify(hexToBytes(signature), hexToBytes(digest), hexToBytes(vector.publicKey), {
          prehash: false,
        }),
      ).toBe(true);
      expect(chain.verifyMessage(message, signature, vector.publicKey)).toBe(true);
      expect(chain.signMessage(new TextEncoder().encode(message), vector.privateKey)).toBe(
        signature,
      );
      expect(chain.verifyMessage(message + "!", signature, vector.publicKey)).toBe(false);
      expect(chain.verifyMessage(message, "invalid", vector.publicKey)).toBe(false);
      expect(
        chain.verifyMessage(
          message,
          new Bitcoin().signMessage(message, vector.privateKey),
          vector.publicKey,
        ),
      ).toBe(false);
    },
  );
});
