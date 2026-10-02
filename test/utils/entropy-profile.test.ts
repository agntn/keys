import { hex } from "@scure/base";
import { describe, expect, it } from "vite-plus/test";
import { entropyHashAlgorithms, profileEntropy } from "../../src/utils/entropy-profile.ts";
import { entropyProfileVectors } from "../fixtures.ts";

const bytes = (value: string) => hex.decode(value);

describe("entropy profile", () => {
  it("reads printable entropy as text", () => {
    const { entropy, text } = entropyProfileVectors.text;
    expect(profileEntropy(bytes(entropy))).toEqual({ text, patterns: [], preimages: [] });
  });

  it("leaves bytes that are not mostly printable UTF-8 unread", () => {
    expect(profileEntropy(bytes("00".repeat(16))).text).toBeNull();
    expect(profileEntropy(bytes("ff".repeat(16))).text).toBeNull();
    expect(profileEntropy(bytes(`68656c6c6f${"00".repeat(11)}`)).text).toBeNull();
    expect(profileEntropy(bytes(`68656c6c6f20776f726c6421${"00".repeat(4)}`)).text).toBe(
      "hello world!\0\0\0\0",
    );
  });

  it.each([
    ["00".repeat(16), { kind: "all-zeros" }],
    ["ff".repeat(32), { kind: "all-ones" }],
    ["41".repeat(20), { kind: "repeated-byte", byte: "41" }],
    ["deadbeef".repeat(4), { kind: "repeated-block", block: "deadbeef" }],
    ["abc123".repeat(4), { kind: "repeated-block", block: "abc123" }],
    [`${"00".repeat(15)}2a`, { kind: "low-diversity", distinct: 2 }],
    ["01020304010203040102030401020301", { kind: "low-diversity", distinct: 4 }],
  ])("finds the pattern in %s", (entropy, pattern) => {
    expect(profileEntropy(bytes(entropy)).patterns).toEqual([pattern]);
  });

  it("finds no pattern in bytes that look drawn at random", () => {
    expect(profileEntropy(bytes("8d7f2a91c4e3b0657a1f9e2d3c4b5a69")).patterns).toEqual([]);
    expect(profileEntropy(bytes("0102030405060708090a0b0c0d0e0f10")).patterns).toEqual([]);
  });

  it("compares only the digests long enough for the entropy", () => {
    expect(entropyHashAlgorithms(16)).toEqual(["md5", "sha1", "sha256"]);
    expect(entropyHashAlgorithms(20)).toEqual(["sha1", "sha256"]);
    expect(entropyHashAlgorithms(24)).toEqual(["sha256"]);
    expect(entropyHashAlgorithms(32)).toEqual(["sha256"]);
  });

  it("matches built-in texts under each digest cut to the entropy length", () => {
    const { md5Empty, sha1Satoshi, sha256Bitcoin } = entropyProfileVectors;
    expect(profileEntropy(bytes(md5Empty)).preimages).toEqual([
      { algorithm: "md5", text: "", source: "built-in" },
    ]);
    expect(profileEntropy(bytes(sha1Satoshi)).preimages).toEqual([
      { algorithm: "sha1", text: "satoshi", source: "built-in" },
    ]);
    expect(profileEntropy(bytes(sha1Satoshi.slice(0, 32))).preimages).toEqual([
      { algorithm: "sha1", text: "satoshi", source: "built-in" },
    ]);
    for (const length of [16, 20, 24, 28, 32]) {
      expect(profileEntropy(bytes(sha256Bitcoin.slice(0, length * 2))).preimages).toEqual([
        { algorithm: "sha256", text: "bitcoin", source: "built-in" },
      ]);
    }
  });

  it("matches given texts as their exact UTF-8 bytes", () => {
    const { text, digest } = entropyProfileVectors.md5Given;
    const entropy = bytes(digest);
    expect(profileEntropy(entropy).preimages).toEqual([]);
    expect(profileEntropy(entropy, ["red", ` ${text}`, text.toUpperCase()]).preimages).toEqual([]);
    expect(profileEntropy(entropy, ["red", text]).preimages).toEqual([
      { algorithm: "md5", text, source: "given" },
    ]);
  });
});
