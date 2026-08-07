import { describe, it, expect } from "vitest";
import Sui from "../../src/blockchains/sui";
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
});
