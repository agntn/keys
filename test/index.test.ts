import { describe, expect, it } from "vite-plus/test";
import { bip39TestVectors } from "./fixtures";
import { AbstractBlockchain, AbstractEVMBlockchain, blockchains, useBlockchain } from "../src";
import Bitcoin, { Bitcoin as BitcoinClass } from "../src/blockchains/bitcoin";
import Ethereum from "../src/blockchains/ethereum";
import Litecoin from "../src/blockchains/litecoin";
import Sui from "../src/blockchains/sui";

describe("Blockchain class API", () => {
  it("exports the concrete class as both the named and default export", () => {
    expect(Bitcoin).toBe(BitcoinClass);
    expect(new Bitcoin()).toBeInstanceOf(AbstractBlockchain);
    expect(new Ethereum()).toBeInstanceOf(AbstractEVMBlockchain);
  });

  it("constructs concrete classes through the lazy registry", async () => {
    const blockchain = await blockchains.bitcoin({ network: "testnet" })();

    expect(blockchain).toBeInstanceOf(Bitcoin);
    expect(blockchain.network).toBe("testnet");
    expect(useBlockchain(blockchain)).toBe(blockchain);
  });

  it("preserves mainnet defaulting for empty network values", async () => {
    const blockchain = await blockchains.bitcoin({ network: "" })();

    expect(blockchain.network).toBe("mainnet");
  });
});

describe("Common blockchain functionality", () => {
  it("should expose useBlockchain function", () => {
    expect(typeof useBlockchain).toBe("function");
  });

  describe("generateKeys function", () => {
    it("should generate a valid key pair for Bitcoin", () => {
      const blockchain = useBlockchain(new Bitcoin());
      const keys = blockchain.generateKeys();

      // Verify structure
      expect(keys).toHaveProperty("keys");
      expect(keys.keys).toHaveProperty("private");
      expect(keys.keys).toHaveProperty("public");

      // Verify private key format
      expect(keys.keys.private).toMatch(/^[0-9a-f]{64}$/);

      // Verify public key format (compressed secp256k1 key)
      expect(keys.keys.public).toMatch(/^[0-9a-f]{66}$/);
      expect(keys.keys.public.startsWith("02") || keys.keys.public.startsWith("03")).toBe(true);

      // Verify that public key was correctly derived from private key
      const derivedPublicKey = blockchain.getKeyPublic(keys.keys.private);
      expect(keys.keys.public).toBe(derivedPublicKey);
    });

    it("should generate a valid key pair for Ethereum", () => {
      const blockchain = useBlockchain(new Ethereum());
      const keys = blockchain.generateKeys();

      // Verify structure
      expect(keys).toHaveProperty("keys");
      expect(keys.keys).toHaveProperty("private");
      expect(keys.keys).toHaveProperty("public");

      // Verify private key format
      expect(keys.keys.private).toMatch(/^[0-9a-f]{64}$/);

      // Verify public key format (compressed secp256k1 key)
      expect(keys.keys.public).toMatch(/^[0-9a-f]{66}$/);
      expect(keys.keys.public.startsWith("02") || keys.keys.public.startsWith("03")).toBe(true);

      // Verify that public key was correctly derived from private key
      const derivedPublicKey = blockchain.getKeyPublic(keys.keys.private);
      expect(keys.keys.public).toBe(derivedPublicKey);
    });

    it("should respect options passed to generateKeys", () => {
      const blockchain = useBlockchain(new Bitcoin());

      // Generate with default options (compressed key)
      const compressedKeys = blockchain.generateKeys();
      expect(compressedKeys.keys.public).toMatch(/^[0-9a-f]{66}$/);
      expect(
        compressedKeys.keys.public.startsWith("02") || compressedKeys.keys.public.startsWith("03"),
      ).toBe(true);

      // Generate with uncompressed key option
      const uncompressedKeys = blockchain.generateKeys({ compressed: false });
      expect(uncompressedKeys.keys.public).toMatch(/^[0-9a-f]{130}$/);
      expect(uncompressedKeys.keys.public.startsWith("04")).toBe(true);
    });

    it("should generate different key pairs each time", () => {
      const blockchain = useBlockchain(new Bitcoin());
      const keys1 = blockchain.generateKeys();
      const keys2 = blockchain.generateKeys();

      expect(keys1.keys.private).not.toBe(keys2.keys.private);
      expect(keys1.keys.public).not.toBe(keys2.keys.public);
    });

    it("should generate a valid wallet with address", () => {
      const blockchain = useBlockchain(new Bitcoin());
      const wallet = blockchain.generateWallet();

      // Verify structure
      expect(wallet).toHaveProperty("keys");
      expect(wallet.keys).toHaveProperty("private");
      expect(wallet.keys).toHaveProperty("public");
      expect(wallet).toHaveProperty("address");

      // Verify private key format
      expect(wallet.keys.private).toMatch(/^[0-9a-f]{64}$/);

      // Verify public key format (compressed secp256k1 key)
      expect(wallet.keys.public).toMatch(/^[0-9a-f]{66}$/);

      // Verify address format for Bitcoin (starts with 1 for default legacy address)
      expect(wallet.address.startsWith("1")).toBe(true);

      // Verify that address was correctly derived from public key
      const derivedAddress = blockchain.getAddress(wallet.keys.public);
      expect(wallet.address).toBe(derivedAddress);
    });

    it("should respect address type in generateWallet", () => {
      const blockchain = useBlockchain(new Bitcoin());

      // Default legacy address
      const legacyWallet = blockchain.generateWallet();
      expect(legacyWallet.address.startsWith("1")).toBe(true);

      // P2SH address
      const p2shWallet = blockchain.generateWallet({}, "p2sh");
      expect(p2shWallet.address.startsWith("3")).toBe(true);
    });

    it("derives a wallet from an existing private key", () => {
      const blockchain = useBlockchain(new Bitcoin());
      const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";

      expect(blockchain.deriveWallet(privateKey, {}, "segwit")).toEqual({
        keys: {
          private: privateKey,
          public: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        },
        address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        addressType: "segwit",
      });
    });
  });
});

describe("deriveHDWallet", () => {
  const blockchain = useBlockchain(new Bitcoin());
  const { mnemonic } = bip39TestVectors;

  it("collapses whitespace before validating the mnemonic", () => {
    const messy = `  ${mnemonic.replaceAll(" ", "\n  ")} `;

    expect(blockchain.deriveHDWallet(messy, "m/84'/0'/0'/0/0")).toEqual(
      blockchain.deriveHDWallet(mnemonic, "m/84'/0'/0'/0/0"),
    );
  });

  it("rejects a mnemonic with a bad checksum", () => {
    expect(() =>
      blockchain.deriveHDWallet(mnemonic.replace("about", "abandon"), "m/84'/0'/0'/0/0"),
    ).toThrow("Invalid BIP39 mnemonic");
  });

  it("rejects a path that does not start at the master key", () => {
    expect(() => blockchain.deriveHDWallet(mnemonic, "84'/0'/0'/0/0")).toThrow("Path must start");
  });
});

describe("address type of a wallet", () => {
  const { mnemonic } = bip39TestVectors;
  const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";

  it("names the type the path purpose picked", () => {
    const bitcoin = new Bitcoin();
    for (const [path, addressType, address] of [
      ["m/44'/0'/0'/0/0", "legacy", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"],
      ["m/49'/0'/0'/0/0", "p2sh", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"],
      ["m/84'/0'/0'/0/0", "segwit", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"],
      [
        "m/86'/0'/0'/0/0",
        "taproot",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
      ],
    ] as const) {
      expect(bitcoin.deriveHDWallet(mnemonic, path)).toMatchObject({ addressType, address });
    }
    expect(bitcoin.deriveHDWallet(mnemonic, "m/0'/0'/0'")).toEqual(
      bitcoin.deriveHDWallet(mnemonic, "m/0'/0'/0'", {}, "legacy"),
    );
    expect(bitcoin.deriveHDWallet(mnemonic, "m/0'/0'/0'").addressType).toBe("legacy");
    expect(bitcoin.deriveHDWallet(mnemonic, "m/84'/0'/0'/0/0", {}, "p2wsh").addressType).toBe(
      "p2wsh",
    );
  });

  it("names the default when none is given, and nothing on chains with one format", () => {
    expect(new Litecoin().deriveWallet(privateKey).addressType).toBe("legacy");
    expect(new Sui().generateWallet().addressType).toBe("ed25519");
    expect(new Sui().deriveWallet(privateKey, { scheme: "secp256k1" }).addressType).toBe(
      "secp256k1",
    );
    expect(new Ethereum().deriveWallet(privateKey)).not.toHaveProperty("addressType");
    expect(new Ethereum().defaultAddressType).toBeUndefined();
  });
});
