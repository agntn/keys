import { describe, it, expect } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { bip39TestVectors, slip10WalletVectors, suiTestVectors } from "../fixtures";
import Sui from "../../src/blockchains/sui";
import Ethereum from "../../src/blockchains/ethereum";
import { useBlockchain } from "../../src/blockchain";
import type { Options } from "../../src/types";

describe("Sui", () => {
  describe("Mainnet", () => {
    const blockchain = useBlockchain(new Sui());

    // Test vectors
    const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";
    const keyPublicEd25519 = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";
    const addressEd25519 = "0xd0c2c91eda34bbfbaec6cfb9c7bb913e57dab3cbec4018a4b3f5e55531cd63af";

    const keyPublicSecp256k1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const addressSecp256k1 = "0xd4c3524e6642b2e54945c02378024f822ac3f80b0870a5f95f06e68a61890a6c";

    describe("Keys and addresses", () => {
      it("should generate correct Ed25519 public key", () => {
        expect(blockchain.getKeyPublic(keyPrivate, { scheme: "ed25519" })).toBe(keyPublicEd25519);
      });

      it("should generate correct Secp256k1 public key", () => {
        expect(blockchain.getKeyPublic(keyPrivate, { scheme: "secp256k1" })).toBe(
          keyPublicSecp256k1,
        );
      });

      it("should generate correct Ed25519 Sui address", () => {
        expect(blockchain.getAddress(keyPublicEd25519, "ed25519")).toBe(addressEd25519);
      });

      it("should generate correct Secp256k1 Sui address", () => {
        expect(blockchain.getAddress(keyPublicSecp256k1, "secp256k1")).toBe(addressSecp256k1);
      });

      it("should default to Ed25519 when no scheme is specified", () => {
        expect(blockchain.getKeyPublic(keyPrivate)).toBe(keyPublicEd25519);
        expect(blockchain.getAddress(keyPublicEd25519)).toBe(addressEd25519);
      });
    });

    it("uses the key scheme when generating a wallet address", () => {
      const wallet = blockchain.generateWallet({ scheme: "secp256k1" });

      expect(wallet.address).toBe(blockchain.getAddress(wallet.keys.public, "secp256k1"));
      expect(wallet.address).not.toBe(blockchain.getAddress(wallet.keys.public, "ed25519"));
    });

    it("uses the key scheme when deriving a wallet address", () => {
      const wallet = blockchain.deriveWallet(keyPrivate, { scheme: "secp256k1" });

      expect(wallet.keys.public).toBe(keyPublicSecp256k1);
      expect(wallet.address).toBe(addressSecp256k1);
      expect(blockchain.deriveWallet(keyPrivate, { scheme: "ed25519" }, "secp256k1")).toEqual(
        wallet,
      );
    });

    describe("Address validation", () => {
      it("should validate correct Sui addresses", () => {
        expect(blockchain.validateAddress?.(addressEd25519)).toBe(true);
        expect(blockchain.validateAddress?.(addressSecp256k1)).toBe(true);
      });

      it("should reject invalid addresses", () => {
        // Wrong prefix
        expect(
          blockchain.validateAddress?.(
            "7e50de9ffb8ebbd709f774966c0a653f2bdecd96f3fe68f0d957fc9e855b3a13",
          ),
        ).toBe(false);

        // Wrong length
        expect(
          blockchain.validateAddress?.(
            "0x7e50de9ffb8ebbd709f774966c0a653f2bdecd96f3fe68f0d957fc9e855b3a",
          ),
        ).toBe(false);

        // Invalid characters
        expect(
          blockchain.validateAddress?.(
            "0x7e50de9ffb8ebbd709f774966c0a653f2bdecd96f3fe68f0d957fc9e855b3a1z",
          ),
        ).toBe(false);
      });
    });
  });

  describe("Testnet", () => {
    const options: Options = { network: "testnet" };
    const testnetBlockchain = useBlockchain(new Sui(options));

    describe("blockchain interface", () => {
      it("has correct name", () => {
        expect(testnetBlockchain.name).toBe("sui");
      });

      it("supports multiple curves", () => {
        expect(testnetBlockchain.curve).toEqual(["ed25519", "secp256k1"]);
      });

      it("has network property set to testnet", () => {
        expect(testnetBlockchain.network).toBe("testnet");
      });
    });

    describe("Keys and addresses", () => {
      const keyPrivate = "0000000000000000000000000000000000000000000000000000000000000001";
      const keyPublicEd25519 = "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29";
      const addressEd25519 = "0xd0c2c91eda34bbfbaec6cfb9c7bb913e57dab3cbec4018a4b3f5e55531cd63af";

      const keyPublicSecp256k1 =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
      const addressSecp256k1 = "0xd4c3524e6642b2e54945c02378024f822ac3f80b0870a5f95f06e68a61890a6c";

      it("should generate the same addresses as mainnet", () => {
        // Sui addresses are the same on testnet and mainnet
        expect(testnetBlockchain.getKeyPublic(keyPrivate, { scheme: "ed25519" })).toBe(
          keyPublicEd25519,
        );
        expect(testnetBlockchain.getAddress(keyPublicEd25519, "ed25519")).toBe(addressEd25519);

        expect(testnetBlockchain.getKeyPublic(keyPrivate, { scheme: "secp256k1" })).toBe(
          keyPublicSecp256k1,
        );
        expect(testnetBlockchain.getAddress(keyPublicSecp256k1, "secp256k1")).toBe(
          addressSecp256k1,
        );
      });
    });
  });

  describe("HD wallets from mnemonics", () => {
    const blockchain = useBlockchain(new Sui());
    const { mnemonic } = bip39TestVectors;
    const [, , vector] = slip10WalletVectors;
    const { path } = vector;

    it("generates the SDK path for each scheme", () => {
      expect(blockchain.getDerivationPath()).toBe(path);
      expect(blockchain.getDerivationPath(1, 0, 2, { scheme: "ed25519" })).toBe(
        "m/44'/784'/1'/0'/2'",
      );
      expect(blockchain.getDerivationPath(1, 0, 2, { scheme: "secp256k1" })).toBe(
        "m/54'/784'/1'/0/2",
      );
      expect(() => blockchain.getDerivationPath(0, 2, 0, { scheme: "secp256k1" })).toThrow(
        RangeError,
      );
    });

    it("derives the ed25519 wallet over SLIP-10 by default", () => {
      const wallet = blockchain.deriveHDWallet(mnemonic, path);

      expect(wallet.keys.public).toBe(vector.publicKey);
      expect(wallet.address).toBe(vector.address);
    });

    it("switches to BIP32 when the scheme is secp256k1", () => {
      const options = { scheme: "secp256k1" };
      const secp256k1Path = blockchain.getDerivationPath(0, 0, 0, options);
      expect(secp256k1Path).toBe("m/54'/784'/0'/0/0");
      const fromAddressType = blockchain.deriveHDWallet(mnemonic, secp256k1Path, {}, "secp256k1");
      const fromScheme = blockchain.deriveHDWallet(mnemonic, secp256k1Path, options);

      expect(fromAddressType).toEqual(fromScheme);
      expect(fromAddressType.keys.public).toMatch(/^0[23][0-9a-f]{64}$/);
      expect(fromAddressType).toEqual(
        blockchain.deriveWallet(fromAddressType.keys.private, {}, "secp256k1"),
      );
      expect(fromAddressType.address).not.toBe(blockchain.deriveHDWallet(mnemonic, path).address);
    });
  });

  describe("Message signing", () => {
    const blockchain = useBlockchain(new Sui());
    const vector = suiTestVectors;

    it.each(vector.messages)(
      "signs @mysten/sui signPersonalMessage vector %# on both schemes",
      (message, digest, ed25519Signature, secp256k1Signature) => {
        const digestBytes = hexToBytes(digest);
        expect(
          ed25519.verify(
            hexToBytes(ed25519Signature),
            digestBytes,
            hexToBytes(vector.ed25519.publicKey),
          ),
        ).toBe(true);
        expect(
          secp256k1.verify(
            hexToBytes(secp256k1Signature),
            digestBytes,
            hexToBytes(vector.secp256k1.publicKey),
            { prehash: true },
          ),
        ).toBe(true);

        const schemes = [
          ["ed25519", vector.ed25519.publicKey, ed25519Signature],
          ["secp256k1", vector.secp256k1.publicKey, secp256k1Signature],
        ] as const;
        for (const [scheme, publicKey, signature] of schemes) {
          const options = { scheme };
          expect(blockchain.signMessage(message, vector.privateKey, options)).toBe(signature);
          expect(
            blockchain.signMessage(new TextEncoder().encode(message), vector.privateKey, options),
          ).toBe(signature);
          expect(blockchain.verifyMessage(message, signature, publicKey, options)).toBe(true);
          expect(blockchain.verifyMessage(message + "!", signature, publicKey, options)).toBe(
            false,
          );
          expect(blockchain.verifyMessage(message, "invalid", publicKey, options)).toBe(false);
        }
      },
    );

    it("signs ed25519 without a scheme", () => {
      const [message, , signature] = vector.messages[1];
      expect(blockchain.signMessage(message, vector.privateKey)).toBe(signature);
      expect(blockchain.verifyMessage(message, signature, vector.ed25519.publicKey)).toBe(true);
    });

    it("rejects a signature from the other scheme", () => {
      const [message, , ed25519Signature, secp256k1Signature] = vector.messages[1];
      expect(blockchain.verifyMessage(message, secp256k1Signature, vector.ed25519.publicKey)).toBe(
        false,
      );
      expect(
        blockchain.verifyMessage(message, ed25519Signature, vector.secp256k1.publicKey, {
          scheme: "secp256k1",
        }),
      ).toBe(false);
    });

    it("refuses the recovery byte on either scheme", () => {
      const [message] = vector.messages[1];
      expect(() => blockchain.signMessage(message, vector.privateKey, { recovered: true })).toThrow(
        /flag\|\|signature\|\|publicKey/,
      );
      expect(() =>
        blockchain.signMessage(message, vector.privateKey, {
          scheme: "secp256k1",
          recovered: true,
        }),
      ).toThrow(/flag\|\|signature\|\|publicKey/);
    });

    it("rejects a raw ed25519 signature and an Ethereum preamble one", () => {
      const [message, , ed25519Signature, secp256k1Signature] = vector.messages[1];
      const raw = bytesToHex(
        ed25519.sign(new TextEncoder().encode(message), hexToBytes(vector.privateKey)),
      );
      const ethereum = new Ethereum().signMessage(message, vector.privateKey);

      expect(raw).not.toBe(ed25519Signature);
      expect(blockchain.verifyMessage(message, raw, vector.ed25519.publicKey)).toBe(false);
      expect(ethereum).not.toBe(secp256k1Signature);
      expect(
        blockchain.verifyMessage(message, ethereum, vector.secp256k1.publicKey, {
          scheme: "secp256k1",
        }),
      ).toBe(false);
    });
  });
});
