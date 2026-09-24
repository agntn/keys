import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { base58check, base64, bech32m } from "@scure/base";
import { describe, expect, it } from "vite-plus/test";
import { blockchains, decodeWIF, getBlockchainPath } from "../../src/index.ts";
import Bitcoin from "../../src/blockchains/bitcoin.ts";
import Zcash, { Zcash as NamedZcash } from "../../src/blockchains/zcash.ts";
import {
  bip39TestVectors,
  secp256k1TestVectors,
  testMessages,
  zcashTestVectors as vector,
} from "../fixtures.ts";

/**
 * The digest zcashd signs, written out here instead of borrowed from the driver: compact size
 * lengths and double SHA-256 over the magic string and the message.
 * @param message - Message text
 * @returns {Uint8Array} The 32 byte digest
 */
function zcashdDigest(message: string): Uint8Array {
  const magic = new TextEncoder().encode("Zcash Signed Message:\n");
  const body = new TextEncoder().encode(message);
  return sha256(
    sha256(concatBytes(Uint8Array.of(magic.length), magic, Uint8Array.of(body.length), body)),
  );
}

describe("Zcash", () => {
  it("loads through the public registry with SLIP-0044 coin type 133", async () => {
    const chain = await blockchains.zcash()();
    expect(chain).toBeInstanceOf(NamedZcash);
    expect(chain.name).toBe("zcash");
    expect(chain.curve).toBe("secp256k1");
    expect(getBlockchainPath(chain, 0, 1, 3)).toBe("m/44'/133'/0'/1/3");
    expect(() => new Zcash({ network: "regtest" })).toThrow("mainnet and testnet only");
  });

  it.each(vector.keys)("writes the node's address for $wif in both encodings", (key) => {
    const chain = new Zcash();
    expect(decodeWIF(key.wif, { chain: "bitcoin" }).privateKey).toBe(key.privateKey);
    const uncompressed = chain.getKeyPublic(key.privateKey, { compressed: false });
    const compressed = chain.getKeyPublic(key.privateKey);
    expect(chain.getAddress(uncompressed)).toBe(key.address);
    expect(chain.getAddress(compressed, "legacy")).toBe(key.addressCompressed);
  });

  it("writes testnet addresses under tm", () => {
    const chain = new Zcash({ network: "testnet" });
    const address = chain.getAddress(secp256k1TestVectors.publicKeyCompressed);
    expect(address).toMatch(/^tm/u);
    expect(chain.validateAddress(address)).toBe(true);
    expect(new Zcash().validateAddress(address)).toBe(false);
  });

  it("refuses every address type but legacy, and bytes that are not a key", () => {
    const chain = new Zcash();
    const { publicKeyCompressed } = secp256k1TestVectors;
    for (const type of ["p2sh", "segwit", "p2wsh", "taproot", "tex", ""]) {
      expect(() => chain.getAddress(publicKeyCompressed, type)).toThrow("transparent P2PKH only");
    }
    expect(() => chain.getAddress("02" + "00".repeat(32))).toThrow();
  });

  it("validates the node's P2PKH and P2SH vectors on their network only", () => {
    const mainnet = new Zcash();
    const testnet = new Zcash({ network: "testnet" });
    for (const address of vector.mainnet) {
      expect(mainnet.validateAddress(address)).toBe(true);
      expect(testnet.validateAddress(address)).toBe(false);
    }
    for (const address of vector.testnet) {
      expect(testnet.validateAddress(address)).toBe(true);
      expect(mainnet.validateAddress(address)).toBe(false);
    }
  });

  it("accepts the ZIP-320 TEX address beside its t1 twin, on mainnet only", () => {
    const mainnet = new Zcash();
    expect(mainnet.validateAddress(vector.tex.address)).toBe(true);
    expect(mainnet.validateAddress(vector.tex.tex)).toBe(true);
    expect(mainnet.validateAddress(vector.tex.tex.toUpperCase())).toBe(true);
    expect(mainnet.validateAddress(`${vector.tex.tex.slice(0, -1)}q`)).toBe(false);

    const testnet = new Zcash({ network: "testnet" });
    const hash = bech32m.fromWords(bech32m.decode(vector.tex.tex).words);
    expect(testnet.validateAddress(vector.tex.tex)).toBe(false);
    expect(testnet.validateAddress(bech32m.encode("textest", bech32m.toWords(hash)))).toBe(true);
    expect(mainnet.validateAddress(bech32m.encode("tex", bech32m.toWords(hash.slice(1))))).toBe(
      false,
    );
  });

  it("refuses a broken checksum, Bitcoin's prefixes and shielded addresses", () => {
    const chain = new Zcash();
    const [address] = vector.mainnet;
    expect(chain.validateAddress(`${address.slice(0, -1)}G`)).toBe(false);
    const short = base58check(sha256).encode(
      concatBytes(Uint8Array.of(0x1c, 0xb8), new Uint8Array(19)),
    );
    expect(chain.validateAddress(short)).toBe(false);
    expect(chain.validateAddress("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH")).toBe(false);
    expect(chain.validateAddress("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")).toBe(false);
    expect(
      chain.validateAddress(
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
      ),
    ).toBe(false);
    for (const address of vector.shielded) {
      expect(chain.validateAddress(address)).toBe(false);
    }
    expect(chain.validateAddress("")).toBe(false);
  });

  it("verifies Zallet's signature under the key it recovers to", () => {
    const chain = new Zcash();
    const { address, message, signature } = vector.signed;
    const compact = base64.decode(signature);
    const recovery = (compact[0] - 27) & 3;
    const publicKey = bytesToHex(
      secp256k1.recoverPublicKey(
        concatBytes(Uint8Array.of(recovery), compact.slice(1)),
        zcashdDigest(message),
        { prehash: false },
      ),
    );
    expect(chain.getAddress(publicKey)).toBe(address);
    const rs = bytesToHex(compact.slice(1));
    expect(chain.verifyMessage(message, rs, publicKey)).toBe(true);
    expect(chain.verifyMessage(`${message}!`, rs, publicKey)).toBe(false);
  });

  it("signs the digest zcashd signs and round trips", () => {
    const chain = new Zcash();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
    const signed = chain.signMessage(testMessages.simple, privateKey);
    const expected = secp256k1.sign(zcashdDigest(testMessages.simple), hexToBytes(privateKey), {
      prehash: false,
    });
    expect(signed).toBe(bytesToHex(expected));
    expect(chain.verifyMessage(testMessages.simple, signed, publicKeyCompressed)).toBe(true);
  });

  it("uses its own preamble, so a Bitcoin signature does not carry over", () => {
    const chain = new Zcash();
    const bitcoin = new Bitcoin();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
    for (const message of Object.values(testMessages)) {
      const signature = bitcoin.signMessage(message, privateKey);
      expect(chain.signMessage(message, privateKey)).not.toBe(signature);
      expect(chain.verifyMessage(message, signature, publicKeyCompressed)).toBe(false);
    }
    expect(() => chain.signMessage("hello", privateKey, { recovered: true })).toThrow();
  });

  it("derives the receive address Ledger Live gives for the public test mnemonic", () => {
    const chain = new Zcash();
    expect(chain.getDerivationPath(0)).toBe(vector.hd.path);
    expect(chain.deriveHDWallet(bip39TestVectors.mnemonic, vector.hd.path).address).toBe(
      vector.hd.address,
    );
  });

  it.each(["m/44'/133'/0'/0/0", "m/49'/133'/0'/0/0", "m/84'/133'/0'/0/0"])(
    "derives %s to a P2PKH address whatever the purpose",
    (path) => {
      const chain = new Zcash();
      const wallet = chain.deriveHDWallet(bip39TestVectors.mnemonic, path);
      expect(wallet.address).toBe(chain.getAddress(wallet.keys.public));
      expect(wallet.address).toMatch(/^t1/u);
      expect(() => chain.deriveHDWallet(bip39TestVectors.mnemonic, path, {}, "p2sh")).toThrow(
        "transparent P2PKH only",
      );
    },
  );
});
