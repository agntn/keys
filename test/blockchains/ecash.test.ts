import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { describe, expect, it } from "vite-plus/test";
import { blockchains, getBlockchainPath } from "../../src/index.ts";
import Bitcoin from "../../src/blockchains/bitcoin.ts";
import BitcoinCash from "../../src/blockchains/bitcoincash.ts";
import ECash, { ECash as NamedECash } from "../../src/blockchains/ecash.ts";
import { decodeCashAddr, encodeCashAddr } from "../../src/utils/cashaddr.ts";
import {
  bip39TestVectors,
  bitcoinCashTestVectors,
  eCashTestVectors as vector,
  secp256k1TestVectors,
  testMessages,
} from "../fixtures.ts";

/**
 * The digest Bitcoin ABC signs, written out here instead of borrowed from the driver: compact
 * size lengths and double SHA-256 over the magic string and the message.
 * @param message - Message text
 * @returns {Uint8Array} The 32 byte digest
 */
function bitcoinAbcDigest(message: string): Uint8Array {
  const magic = new TextEncoder().encode("eCash Signed Message:\n");
  const body = new TextEncoder().encode(message);
  return sha256(
    sha256(concatBytes(Uint8Array.of(magic.length), magic, Uint8Array.of(body.length), body)),
  );
}

describe("eCash", () => {
  it("loads through the public registry with SLIP-0044 coin type 899", async () => {
    const chain = await blockchains.ecash()();
    expect(chain).toBeInstanceOf(NamedECash);
    expect(chain.name).toBe("ecash");
    expect(chain.curve).toBe("secp256k1");
    expect(getBlockchainPath(chain, 0, 1, 3)).toBe("m/44'/899'/0'/1/3");
    expect(() => new ECash({ network: "regtest" })).toThrow(
      "eCash supports mainnet and testnet only",
    );
  });

  it("writes the P2PKH address Bitcoin ABC gives the key's hash", () => {
    const chain = new ECash();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
    const hash = decodeCashAddr(chain.getAddress(publicKeyCompressed), "ecash")?.hash;
    expect(bytesToHex(hash ?? new Uint8Array())).toBe(
      bytesToHex(
        decodeCashAddr(new BitcoinCash().getAddress(publicKeyCompressed), "bitcoincash")?.hash ??
          new Uint8Array(1),
      ),
    );
    expect(chain.deriveWallet(privateKey).address).toBe(chain.getAddress(publicKeyCompressed));
    for (const { hash: hex, p2pkh } of vector.encoded) {
      expect(encodeCashAddr("ecash", 0, hexToBytes(hex))).toBe(p2pkh);
    }
  });

  it("uses the ectest prefix on testnet and keeps each network to its own", () => {
    const mainnet = new ECash();
    const testnet = new ECash({ network: "testnet" });
    const address = testnet.getAddress(secp256k1TestVectors.publicKeyCompressed);
    expect(address).toMatch(/^ectest:q/u);
    expect(testnet.validateAddress(address)).toBe(true);
    expect(mainnet.validateAddress(address)).toBe(false);
    expect(testnet.validateAddress(vector.encoded[0].p2pkh)).toBe(false);
  });

  it("refuses every address type but legacy and bytes that are not a point", () => {
    const chain = new ECash();
    const { publicKeyCompressed } = secp256k1TestVectors;
    for (const type of ["p2sh", "segwit", "p2wsh", "taproot", "cashaddr"]) {
      expect(() => chain.getAddress(publicKeyCompressed, type)).toThrow(
        "eCash supports legacy P2PKH only",
      );
    }
    expect(() => chain.getAddress("02" + "00".repeat(32))).toThrow();
  });

  it.each(vector.encoded)("validates Bitcoin ABC's P2PKH and P2SH for $hash", (entry) => {
    const chain = new ECash();
    for (const address of [entry.p2pkh, entry.p2sh]) {
      expect(chain.validateAddress(address)).toBe(true);
      expect(chain.validateAddress(address.slice("ecash:".length))).toBe(true);
      expect(chain.validateAddress(address.toUpperCase())).toBe(true);
      expect(new BitcoinCash().validateAddress(address)).toBe(false);
    }
  });

  it.each(bitcoinCashTestVectors.mainnet)(
    "takes Bitcoin Cash payload %s under ecash only where Bitcoin ABC pays to it",
    (address) => {
      const content = decodeCashAddr(address, "bitcoincash");
      if (content === undefined) throw new Error(`${address} does not decode`);
      const moved = encodeCashAddr("ecash", content.type, content.hash);
      const paid = content.type < 2 && content.hash.length === 20;
      expect(new ECash().validateAddress(moved)).toBe(paid);
      expect(new ECash().validateAddress(address)).toBe(false);
    },
  );

  it("refuses base58, a broken checksum and hashes other than 20 bytes", () => {
    const chain = new ECash();
    const [{ p2pkh }] = vector.encoded;
    expect(
      chain.validateAddress(new Bitcoin().getAddress(secp256k1TestVectors.publicKeyCompressed)),
    ).toBe(false);
    expect(chain.validateAddress(`${p2pkh.slice(0, -1)}3`)).toBe(false);
    expect(chain.validateAddress(encodeCashAddr("ecash", 0, new Uint8Array(24)))).toBe(false);
    expect(chain.validateAddress(encodeCashAddr("ecash", 1, new Uint8Array(32)))).toBe(false);
    expect(chain.validateAddress("")).toBe(false);
  });

  it("verifies ecash-lib's signature under its key", () => {
    const chain = new ECash();
    const { privateKey, message, digest, signature } = vector.signed;
    expect(bytesToHex(bitcoinAbcDigest(message))).toBe(digest);
    const rs = bytesToHex(base64.decode(signature).slice(1));
    const publicKey = chain.getKeyPublic(privateKey);
    expect(chain.verifyMessage(message, rs, publicKey)).toBe(true);
    expect(chain.verifyMessage(`${message}!`, rs, publicKey)).toBe(false);
  });

  it("signs the digest Bitcoin ABC signs and round trips", () => {
    const chain = new ECash();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
    const signed = chain.signMessage(testMessages.simple, privateKey);
    const expected = secp256k1.sign(bitcoinAbcDigest(testMessages.simple), hexToBytes(privateKey), {
      prehash: false,
    });
    expect(signed).toBe(bytesToHex(expected));
    expect(chain.verifyMessage(testMessages.simple, signed, publicKeyCompressed)).toBe(true);
  });

  it("uses its own preamble, so a Bitcoin Cash signature does not carry over", () => {
    const chain = new ECash();
    const bitcoinCash = new BitcoinCash();
    const { privateKey, publicKeyCompressed } = secp256k1TestVectors;
    for (const message of Object.values(testMessages)) {
      const signature = bitcoinCash.signMessage(message, privateKey);
      expect(chain.signMessage(message, privateKey)).not.toBe(signature);
      expect(chain.verifyMessage(message, signature, publicKeyCompressed)).toBe(false);
    }
    expect(() => chain.signMessage("hello", privateKey, { recovered: true })).toThrow();
  });

  it("derives bip_utils' first receive address on each network", () => {
    const [mainnetPath, mainnetAddress] = vector.hd.mainnet;
    const [testnetPath, testnetAddress] = vector.hd.testnet;
    expect(new ECash().deriveHDWallet(bip39TestVectors.mnemonic, mainnetPath).address).toBe(
      mainnetAddress,
    );
    expect(
      new ECash({ network: "testnet" }).deriveHDWallet(bip39TestVectors.mnemonic, testnetPath)
        .address,
    ).toBe(testnetAddress);
  });

  it.each(["m/44'/899'/0'/0/0", "m/44'/1899'/0'/0/0", "m/84'/899'/0'/0/0"])(
    "derives %s to a P2PKH address whatever the path",
    (path) => {
      const chain = new ECash();
      const wallet = chain.deriveHDWallet(bip39TestVectors.mnemonic, path);
      expect(wallet.address).toBe(chain.getAddress(wallet.keys.public));
      expect(wallet.address).toMatch(/^ecash:q/u);
      expect(() => chain.deriveHDWallet(bip39TestVectors.mnemonic, path, {}, "p2sh")).toThrow(
        "legacy P2PKH only",
      );
    },
  );
});
