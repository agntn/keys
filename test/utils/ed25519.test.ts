import { expect, describe, it } from "vite-plus/test";
import { generateKeyPublic } from "../../src/utils/ed25519";

describe("Ed25519 Utils", () => {
  // Test vectors for Ed25519
  const vectors = [
    {
      keyPrivate: "0000000000000000000000000000000000000000000000000000000000000001",
      keyPublic: "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
    },
    {
      keyPrivate: "8a188feb3a3a3a8a599ea9e55ddfc63a360be1c477d0601d3ea5bfcb9c554e93",
      keyPublic: "aa87377d8d7b76ee40d14c033c8404eb4bdb19791aeab7c05186887dd244a96c",
    },
  ];

  // Test key generation
  it("generates the correct public key from a private key", () => {
    for (const vector of vectors) {
      const keyPublic = generateKeyPublic(vector.keyPrivate);
      expect(keyPublic).toBe(vector.keyPublic);
    }
  });
});
