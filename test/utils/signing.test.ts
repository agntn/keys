import { describe, it, expect, expectTypeOf } from "vitest";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { signMessage, verifyMessage } from "../../src/utils/signing";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { evmSignMessage, evmVerifyMessage } from "../../src/utils/evm";
import { ed25519SignMessage, ed25519VerifyMessage } from "../../src/utils/ed25519-chains";
import { secp256k1TestVectors, ed25519TestVectors, testMessages } from "../fixtures";
import type { Blockchain, Curve, KeyOptions } from "../../src/types";

describe("Signing utilities", () => {
  // Use test vectors from fixtures
  const secp256k1TestPrivateKey = secp256k1TestVectors.privateKey;
  const secp256k1TestPublicKey = secp256k1TestVectors.publicKeyCompressed;

  const ed25519TestPrivateKey = ed25519TestVectors.privateKey;
  const ed25519TestPublicKey = ed25519TestVectors.publicKey;

  const testMessage = testMessages.simple;

  describe("Generic signing utilities", () => {
    it("should sign and verify with secp256k1", () => {
      const signature = signMessage(testMessage, secp256k1TestPrivateKey, {
        curve: "secp256k1",
      });

      expect(signature).toBeTypeOf("string");
      expect(hexToBytes(signature).length).toBeGreaterThanOrEqual(64); // Secp256k1 sigs are at least 64 bytes

      const isValid = verifyMessage(testMessage, signature, secp256k1TestPublicKey, {
        curve: "secp256k1",
      });

      expect(isValid).toBe(true);
    });

    it("hashes a secp256k1 message once before signing", () => {
      const signature = signMessage(testMessage, secp256k1TestPrivateKey, {
        curve: "secp256k1",
      });
      const digest = sha256(new TextEncoder().encode(testMessage));

      expect(
        secp256k1.verify(hexToBytes(signature), digest, hexToBytes(secp256k1TestPublicKey), {
          prehash: false,
        }),
      ).toBe(true);
      expect(
        signMessage(digest, secp256k1TestPrivateKey, { curve: "secp256k1", hash: false }),
      ).toBe(signature);
    });

    it("should sign and verify with ed25519", () => {
      const signature = signMessage(testMessage, ed25519TestPrivateKey, {
        curve: "ed25519",
      });

      expect(signature).toBeTypeOf("string");
      expect(hexToBytes(signature).length).toBe(64); // Ed25519 sigs are exactly 64 bytes

      const isValid = verifyMessage(testMessage, signature, ed25519TestPublicKey, {
        curve: "ed25519",
      });

      expect(isValid).toBe(true);
    });

    it("should fail verification with wrong message", () => {
      const signature = signMessage(testMessage, secp256k1TestPrivateKey, {
        curve: "secp256k1",
      });

      const isValid = verifyMessage("Wrong message", signature, secp256k1TestPublicKey, {
        curve: "secp256k1",
      });

      expect(isValid).toBe(false);
    });

    it("should fail verification with wrong public key", () => {
      const signature = signMessage(testMessage, secp256k1TestPrivateKey, {
        curve: "secp256k1",
      });

      const wrongPublicKey = "04" + bytesToHex(new Uint8Array(64).fill(1));

      const isValid = verifyMessage(testMessage, signature, wrongPublicKey, {
        curve: "secp256k1",
      });

      expect(isValid).toBe(false);
    });

    it("should return false for a malformed secp256k1 public key", () => {
      const signature = signMessage(testMessage, secp256k1TestPrivateKey, {
        curve: "secp256k1",
      });

      expect(
        verifyMessage(testMessage, signature, "not-hex", {
          curve: "secp256k1",
        }),
      ).toBe(false);
    });

    it("should return false for a malformed ed25519 public key", () => {
      const signature = signMessage(testMessage, ed25519TestPrivateKey, {
        curve: "ed25519",
      });

      expect(
        verifyMessage(testMessage, signature, "not-hex", {
          curve: "ed25519",
        }),
      ).toBe(false);
    });

    it("should separate signing options from key options", () => {
      type Signing = NonNullable<Parameters<Blockchain["signMessage"]>[2]>;
      type Verification = NonNullable<Parameters<Blockchain["verifyMessage"]>[3]>;
      type KeyGeneration = NonNullable<Parameters<Blockchain["generateKeys"]>[0]>;
      type EvmAdapter = NonNullable<Parameters<typeof evmSignMessage>[2]>;
      type Ed25519Adapter = NonNullable<Parameters<typeof ed25519SignMessage>[2]>;

      expectTypeOf<"curve" extends keyof Signing ? true : false>().toEqualTypeOf<true>();
      expectTypeOf<"hash" extends keyof Signing ? true : false>().toEqualTypeOf<true>();
      expectTypeOf<Signing["curve"]>().toEqualTypeOf<Curve | undefined>();
      expectTypeOf<Signing["hash"]>().toEqualTypeOf<boolean | undefined>();
      expectTypeOf<Verification>().toEqualTypeOf<Signing>();
      expectTypeOf<"curve" extends keyof KeyGeneration ? true : false>().toEqualTypeOf<false>();
      expectTypeOf<"hash" extends keyof KeyGeneration ? true : false>().toEqualTypeOf<false>();
      expectTypeOf<"curve" extends keyof EvmAdapter ? true : false>().toEqualTypeOf<false>();
      expectTypeOf<"hash" extends keyof EvmAdapter ? true : false>().toEqualTypeOf<false>();
      expectTypeOf<"recovered" extends keyof EvmAdapter ? true : false>().toEqualTypeOf<true>();
      expectTypeOf<EvmAdapter["recovered"]>().toEqualTypeOf<boolean | undefined>();
      expectTypeOf<
        "recovered" extends keyof Ed25519Adapter ? true : false
      >().toEqualTypeOf<false>();
      expectTypeOf<Ed25519Adapter>().toEqualTypeOf<KeyOptions>();
    });
  });

  describe("EVM specific signing", () => {
    it("should sign and verify EVM messages", () => {
      const signature = evmSignMessage(testMessage, secp256k1TestPrivateKey);

      expect(signature).toBeTypeOf("string");

      const isValid = evmVerifyMessage(testMessage, signature, secp256k1TestPublicKey);

      expect(isValid).toBe(true);
    });

    it("should apply EVM-specific preamble", () => {
      // EVM signature with preamble will be different than standard secp256k1
      const evmSig = evmSignMessage(testMessage, secp256k1TestPrivateKey);
      const basicSig = signMessage(testMessage, secp256k1TestPrivateKey, { curve: "secp256k1" });

      expect(evmSig).not.toBe(basicSig);
    });

    it("should not allow options to override EVM signing rules", () => {
      const signature = evmSignMessage(testMessage, secp256k1TestPrivateKey);
      const signatureWithOverrides = evmSignMessage(testMessage, secp256k1TestPrivateKey, {
        // @ts-expect-error Fixed EVM adapter rejects curve and hash overrides.
        curve: "ed25519",
        hash: true,
      });

      expect(signatureWithOverrides).toBe(signature);
    });

    it("should produce identical hash for string and equivalent Uint8Array", () => {
      const messageString = "Hello";
      const messageBytes = new TextEncoder().encode(messageString);

      const sigFromString = evmSignMessage(messageString, secp256k1TestPrivateKey);
      const sigFromBytes = evmSignMessage(messageBytes, secp256k1TestPrivateKey);

      expect(sigFromBytes).toBe(sigFromString);
    });

    it("should sign Uint8Array messages", () => {
      const messageBytes = new TextEncoder().encode(testMessage);

      const signature = evmSignMessage(messageBytes, secp256k1TestPrivateKey);

      expect(signature).toBeTypeOf("string");
      expect(hexToBytes(signature).length).toBeGreaterThanOrEqual(64);
    });
  });

  describe("Recoverable secp256k1 signatures", () => {
    const digest = sha256(new TextEncoder().encode(testMessage));

    it("appends v as 27 or 28 and keeps r||s unchanged", () => {
      const compact = signMessage(digest, secp256k1TestPrivateKey, { hash: false });
      const recovered = signMessage(digest, secp256k1TestPrivateKey, {
        hash: false,
        recovered: true,
      });

      expect(hexToBytes(recovered).length).toBe(65);
      expect(recovered.slice(0, 128)).toBe(compact);
      expect([27, 28]).toContain(Number.parseInt(recovered.slice(128), 16));
    });

    it("carries the v that recovers the signer", () => {
      const recovered = signMessage(digest, secp256k1TestPrivateKey, {
        hash: false,
        recovered: true,
      });
      const recovery = Number.parseInt(recovered.slice(128), 16) - 27;
      const signer = secp256k1.Signature.fromBytes(hexToBytes(recovered.slice(0, 128)), "compact")
        .addRecoveryBit(recovery)
        .recoverPublicKey(digest);

      expect(bytesToHex(signer.toBytes(true))).toBe(secp256k1TestPublicKey);
      expect(verifyMessage(digest, recovered, secp256k1TestPublicKey, { hash: false })).toBe(true);
    });

    it("rejects a signature whose v points at the other key", () => {
      const recovered = signMessage(digest, secp256k1TestPrivateKey, {
        hash: false,
        recovered: true,
      });
      const flipped = recovered.slice(0, 128) + (recovered.endsWith("1c") ? "1b" : "1c");
      const outOfRange = recovered.slice(0, 128) + "20";

      expect(verifyMessage(digest, flipped, secp256k1TestPublicKey, { hash: false })).toBe(false);
      expect(verifyMessage(digest, outOfRange, secp256k1TestPublicKey, { hash: false })).toBe(
        false,
      );
    });

    it("accepts the bare 0 or 1 other libraries emit", () => {
      const recovered = signMessage(digest, secp256k1TestPrivateKey, {
        hash: false,
        recovered: true,
      });
      const bare = recovered.slice(0, 128) + (recovered.endsWith("1c") ? "01" : "00");

      expect(verifyMessage(digest, bare, secp256k1TestPublicKey, { hash: false })).toBe(true);
    });

    it("has no ed25519 form and takes only a boolean", () => {
      expect(() =>
        signMessage(testMessage, ed25519TestPrivateKey, { curve: "ed25519", recovered: true }),
      ).toThrow(/secp256k1 only/);
      expect(() =>
        // @ts-expect-error The flag is a boolean, not a truthy value.
        signMessage(testMessage, secp256k1TestPrivateKey, { recovered: "yes" }),
      ).toThrow(TypeError);
      expect(() =>
        // @ts-expect-error Null is not an absent flag either.
        signMessage(testMessage, secp256k1TestPrivateKey, { recovered: null }),
      ).toThrow(TypeError);
    });
  });

  describe("Ed25519 specific signing", () => {
    it("should sign and verify Ed25519 messages", () => {
      const signature = ed25519SignMessage(testMessage, ed25519TestPrivateKey);

      expect(signature).toBeTypeOf("string");
      const isValid = ed25519VerifyMessage(testMessage, signature, ed25519TestPublicKey);

      expect(isValid).toBe(true);
    });

    it("should not allow options to override the Ed25519 curve", () => {
      const signature = ed25519SignMessage(testMessage, ed25519TestPrivateKey);
      const signatureWithOverride = ed25519SignMessage(testMessage, ed25519TestPrivateKey, {
        // @ts-expect-error Fixed Ed25519 adapter rejects curve overrides.
        curve: "secp256k1",
      });

      expect(signatureWithOverride).toBe(signature);
    });

    it("should have correct Ed25519 signature length", () => {
      const signature = ed25519SignMessage(testMessage, ed25519TestPrivateKey);

      expect(hexToBytes(signature).length).toBe(64);
    });
  });
});
