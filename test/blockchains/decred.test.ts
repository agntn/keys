import { secp256k1 } from "@noble/curves/secp256k1.js";
import { blake256 } from "@noble/hashes/blake1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { base58check } from "@scure/base";
import { describe, expect, it } from "vitest";
import Decred, { Decred as NamedDecred } from "../../src/blockchains/decred.ts";
import { blockchains, getBlockchainPath } from "../../src/index.ts";
import { deriveWallet, deriveHdWallet } from "../../src/tool-operations.ts";
import { bip39TestVectors, decredTestVectors as vector } from "../fixtures.ts";

const codec = base58check(blake256);

describe("Decred", () => {
  it("loads ECDSA wallets through the registry and shared tools", async () => {
    const chain = await blockchains.decred()();
    expect(chain).toBeInstanceOf(Decred);
    expect(Decred).toBe(NamedDecred);
    expect(chain.name).toBe("decred");
    expect(chain.curve).toBe("secp256k1");
    expect(getBlockchainPath(chain, 0, 1, 3)).toBe("m/44'/42'/0'/1/3");
    expect(chain.deriveWallet(vector.privateKey).address).toBe(vector.addresses.mainnet);
    expect(chain.getKeyPublic(vector.privateKey)).toBe(vector.publicKey);
    const result = await deriveWallet("decred", vector.privateKey);
    expect(result.details.address).toBe(vector.addresses.mainnet);
    expect(JSON.stringify(result)).not.toContain(vector.privateKey);
    const generated = chain.generateWallet();
    expect(chain.validateAddress(generated.address)).toBe(true);
    expect(chain.getKeyPublic(generated.keys.private)).toBe(generated.keys.public);
  });

  for (const network of ["mainnet", "testnet"] as const) {
    it(`${network} matches dcrd for compressed and uncompressed keys`, async () => {
      const chain = await blockchains.decred({ network })();
      expect(chain.getAddress(vector.publicKey)).toBe(vector.addresses[network]);
      const uncompressed = chain.getKeyPublic(vector.privateKey, { compressed: false });
      expect(chain.getAddress(uncompressed)).toBe(vector.uncompressedAddresses[network]);
      expect(chain.validateAddress(vector.addresses[network])).toBe(true);
      expect(chain.validateAddress(vector.uncompressedAddresses[network])).toBe(true);
      expect(
        chain.validateAddress(vector.addresses[network === "mainnet" ? "testnet" : "mainnet"]),
      ).toBe(false);
    });
  }

  it("rejects bad checksums, wrong payload sizes, prefixes and unsupported formats", async () => {
    const chain = await blockchains.decred()();
    const payload = codec.decode(vector.addresses.mainnet);
    for (const address of [
      "",
      "1".repeat(55),
      vector.addresses.mainnet.slice(0, -1) + "1",
      base58check(sha256).encode(payload),
      codec.encode(payload.slice(0, -1)),
      codec.encode(new Uint8Array([...payload, 0])),
      codec.encode(new Uint8Array([6, ...payload.slice(1)])),
      codec.encode(new Uint8Array([payload[0]!, 0x3e, ...payload.slice(2)])),
      "DeeUhrRoTp4DftsqddVW96yMGMW4sgQFYUE",
      "DcuQKx8BES9wU7C6Q5VmLBjw436r27hayjS",
      "DkM3ZigNyiwHrsXRjkDQ8t8tW6uKGW9g61qEkG3bMqQPQWYEf5X3J",
    ])
      expect(chain.validateAddress(address)).toBe(false);
    for (const key of ["02", "02" + "ff".repeat(32), "04" + "00".repeat(64)]) {
      expect(() => chain.getAddress(key)).toThrow();
    }
    for (const type of ["p2sh", "segwit", "taproot", "unknown"]) {
      expect(() => chain.getAddress(vector.publicKey, type)).toThrow("legacy");
    }
    await expect(blockchains.decred({ network: "simnet" })()).rejects.toThrow(
      "mainnet and testnet only",
    );
    await expect(deriveWallet("decred", vector.privateKey, "segwit")).rejects.toThrow(
      "not supported",
    );
  });

  it("refuses standard BIP32 rather than silently substituting it for Decred HD", async () => {
    await expect(
      deriveHdWallet("decred", bip39TestVectors.mnemonic, "m/44'/42'/0'/0/0"),
    ).rejects.toThrow("Decred HD derivation is not supported");
  });

  it.each(vector.messageHashes)("matches the dcrd message digest %#", async (message, digest) => {
    const chain = await blockchains.decred()();
    const signature = chain.signMessage(message, vector.privateKey);
    expect(
      secp256k1.verify(hexToBytes(signature), hexToBytes(digest), hexToBytes(vector.publicKey), {
        prehash: false,
      }),
    ).toBe(true);
    expect(chain.verifyMessage(message, signature, vector.publicKey)).toBe(true);
    expect(chain.signMessage(new TextEncoder().encode(message), vector.privateKey)).toBe(signature);
    expect(chain.verifyMessage(message + "!", signature, vector.publicKey)).toBe(false);
    expect(chain.verifyMessage(message, "invalid", vector.publicKey)).toBe(false);
    expect(chain.verifyMessage(message, signature, "02")).toBe(false);
  });

  it("verifies the compact r/s bytes from dcrd SignCompact", async () => {
    const chain = await blockchains.decred()();
    expect(chain.verifyMessage("hello", vector.signature, vector.publicKey)).toBe(true);
    expect(chain.signMessage("hello", vector.privateKey)).toBe(vector.signature);
  });
});
