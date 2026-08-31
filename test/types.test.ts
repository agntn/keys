import { describe, it, expect } from "vitest";
import type { Blockchain } from "../src/types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isCurveValue(value: unknown): boolean {
  return typeof value === "string" || Array.isArray(value);
}

function isOptionalValidateAddress(value: unknown): boolean {
  return value === undefined || typeof value === "function";
}

// Helper function to check proper implementation of interfaces
function isBlockchain(obj: unknown): obj is Blockchain {
  return (
    isRecord(obj) &&
    typeof obj.name === "string" &&
    isCurveValue(obj.curve) &&
    typeof obj.getKeyPublic === "function" &&
    typeof obj.getAddress === "function" &&
    isOptionalValidateAddress(obj.validateAddress)
  );
}

function isCompleteBlockchain(obj: unknown): obj is Blockchain {
  return (
    isRecord(obj) &&
    typeof obj.name === "string" &&
    isCurveValue(obj.curve) &&
    typeof obj.generateKeyPrivate === "function" &&
    typeof obj.getKeyPublic === "function" &&
    typeof obj.getAddress === "function" &&
    isOptionalValidateAddress(obj.validateAddress) &&
    typeof obj.generateKeys === "function" &&
    typeof obj.generateWallet === "function"
  );
}

describe("Types", () => {
  describe("Blockchain interface", () => {
    it("should detect valid Blockchain implementation", () => {
      const validBlockchain = {
        name: "test-chain",
        curve: "secp256k1",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
      };

      expect(isBlockchain(validBlockchain)).toBe(true);
    });

    it("should detect valid Blockchain implementation with validateAddress", () => {
      const validBlockchain = {
        name: "test-chain",
        curve: "secp256k1",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
        validateAddress: (address: string) => address.startsWith("addr-"),
      };

      expect(isBlockchain(validBlockchain)).toBe(true);
    });

    it("should reject invalid Blockchain implementations", () => {
      const missingName = {
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
      };

      const missingGenerateKeyPublic = {
        name: "test-chain",
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
      };

      const missingGenerateAddress = {
        name: "test-chain",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
      };

      const validateAddressWrongType = {
        name: "test-chain",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
        validateAddress: "not-a-function",
      };

      expect(isBlockchain(missingName)).toBe(false);
      expect(isBlockchain(missingGenerateKeyPublic)).toBe(false);
      expect(isBlockchain(missingGenerateAddress)).toBe(false);
      expect(isBlockchain(validateAddressWrongType)).toBe(false);
    });
  });

  describe("Complete Blockchain interface", () => {
    it("should detect valid complete Blockchain implementation", () => {
      const validBlockchain = {
        name: "test-chain",
        curve: "secp256k1",
        generateKeyPrivate: () => "priv-key",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
        generateKeys: () => ({
          keys: {
            private: "priv-key",
            public: "pub-key",
          },
        }),
        generateWallet: () => ({
          keys: {
            private: "priv-key",
            public: "pub-key",
          },
          address: "addr-pub-key",
        }),
      };

      expect(isCompleteBlockchain(validBlockchain)).toBe(true);

      // Create an instance that looks like the interface to test type safety
      const usedBlockchain: Blockchain = {
        name: "test-chain-2",
        curve: "ed25519",
        bip44: 501,
        signMessage: () => "signature",
        verifyMessage: () => true,
        generateKeyPrivate: () => "private-key",
        getKeyPublic: (keyPrivate: string) => `public-${keyPrivate}`,
        getAddress: (keyPublic: string) => `address-${keyPublic}`,
        validateAddress: (address: string) => address.startsWith("address-"),
        generateKeys: () => ({
          keys: {
            private: "private-key",
            public: "public-key",
          },
        }),
        generateWallet: () => ({
          keys: {
            private: "private-key",
            public: "public-key",
          },
          address: "address-key",
        }),
      };

      expect(usedBlockchain.name).toBe("test-chain-2");
      expect(usedBlockchain.generateKeyPrivate()).toBe("private-key");
      expect(usedBlockchain.getKeyPublic("test")).toBe("public-test");
      expect(usedBlockchain.getAddress("pub-key")).toBe("address-pub-key");
      expect(usedBlockchain.validateAddress?.("address-xyz")).toBe(true);
      expect(usedBlockchain.validateAddress?.("invalid")).toBe(false);
    });

    it("should detect valid complete Blockchain with validateAddress", () => {
      const validBlockchain = {
        name: "test-chain",
        curve: "secp256k1",
        generateKeyPrivate: () => "priv-key",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
        validateAddress: (address: string) => address.startsWith("addr-"),
        generateKeys: () => ({
          keys: {
            private: "priv-key",
            public: "pub-key",
          },
        }),
        generateWallet: () => ({
          keys: {
            private: "priv-key",
            public: "pub-key",
          },
          address: "addr-pub-key",
        }),
      };

      expect(isCompleteBlockchain(validBlockchain)).toBe(true);
    });

    it("should reject invalid complete Blockchain implementations", () => {
      const missingName = {
        generateKeyPrivate: () => "priv-key",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
      };

      const missingGenerateKeyPrivate = {
        name: "test-chain",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
      };

      const missingGenerateKeyPublic = {
        name: "test-chain",
        generateKeyPrivate: () => "priv-key",
        getAddress: (keyPublic: string) => `addr-${keyPublic}`,
      };

      const missingGenerateAddress = {
        name: "test-chain",
        generateKeyPrivate: () => "priv-key",
        getKeyPublic: (keyPrivate: string) => `pub-${keyPrivate}`,
      };

      expect(isCompleteBlockchain(missingName)).toBe(false);
      expect(isCompleteBlockchain(missingGenerateKeyPrivate)).toBe(false);
      expect(isCompleteBlockchain(missingGenerateKeyPublic)).toBe(false);
      expect(isCompleteBlockchain(missingGenerateAddress)).toBe(false);
    });
  });
});
