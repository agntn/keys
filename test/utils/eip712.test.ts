import { describe, expect, it } from "vite-plus/test";
import { hex } from "@scure/base";
import { evmRecoverTestVectors } from "../fixtures";
import { hashTypedData, type TypedData } from "../../src";

const { mail, hunt } = evmRecoverTestVectors;

/* The Mail example with one field of its message swapped. */
function mailWith(message: Readonly<Record<string, unknown>>): TypedData {
  return { ...mail.typedData, message: { ...mail.typedData.message, ...message } };
}

describe("hashTypedData", () => {
  it("hashes the EIP's own Mail example to its digest", () => {
    expect(hex.encode(hashTypedData(mail.typedData))).toBe(mail.digest);
  });

  it("infers EIP712Domain from the domain's fields when types leave it out", () => {
    const { EIP712Domain: _domain, ...types } = mail.typedData.types;
    expect(hex.encode(hashTypedData({ ...mail.typedData, types }))).toBe(mail.digest);
  });

  it("matches ethers on nested struct arrays, fixed arrays, bytes and signed integers", () => {
    expect(hex.encode(hashTypedData(hunt.typedData))).toBe(hunt.digest);
  });

  it("hashes the domain alone when EIP712Domain is the primary type", () => {
    const domainOnly = hashTypedData({ ...mail.typedData, primaryType: "EIP712Domain" });
    expect(domainOnly).toHaveLength(32);
    expect(hex.encode(domainOnly)).not.toBe(mail.digest);
  });

  it("changes the digest with any field of the message", () => {
    expect(hex.encode(hashTypedData(mailWith({ contents: "Hello, Bob?" })))).not.toBe(mail.digest);
  });

  it("refuses values that do not fit their types instead of hashing something else", () => {
    const clue = hunt.typedData.message.clues[0];
    const withClue = (change: Readonly<Record<string, unknown>>): TypedData => ({
      ...hunt.typedData,
      message: { ...hunt.typedData.message, clues: [{ ...clue, ...change }] },
    });
    expect(() => hashTypedData(withClue({ index: 256 }))).toThrow(
      "message.clues[0].index is out of range for uint8",
    );
    expect(() => hashTypedData(withClue({ index: 1.5 }))).toThrow("must be an integer");
    expect(() => hashTypedData(withClue({ tag: "0xdead" }))).toThrow("must be 4 bytes for bytes4");
    expect(() => hashTypedData(withClue({ blob: "0x123" }))).toThrow("0x hex with whole bytes");
    expect(() => hashTypedData(withClue({ solved: "true" }))).toThrow("must be true or false");
    expect(() =>
      hashTypedData({ ...hunt.typedData, message: { ...hunt.typedData.message, grid: [[1]] } }),
    ).toThrow("message.grid[0] must hold 2 items for uint256[2]");
    expect(() => hashTypedData(mailWith({ to: { name: "Bob", wallet: "0xbBbB" } }))).toThrow(
      "message.to.wallet must be a 0x address of 20 bytes",
    );
    expect(() => hashTypedData(mailWith({ to: { name: "Bob" } }))).toThrow(
      "message.to.wallet is missing",
    );
  });

  it("refuses unknown types and domain fields it cannot type", () => {
    expect(() => hashTypedData({ ...mail.typedData, primaryType: "Letter" })).toThrow(
      'Primary type "Letter" is not one of types',
    );
    expect(() => hashTypedData({ ...mail.typedData, primaryType: "toString" })).toThrow(
      'Primary type "toString" is not one of types',
    );
    expect(() =>
      hashTypedData({
        ...mail.typedData,
        types: { ...mail.typedData.types, Person: [{ name: "wallet", type: "adress" }] },
      }),
    ).toThrow('Field "wallet" of Person has unknown type "adress"');
    const { EIP712Domain: _domain, ...types } = mail.typedData.types;
    expect(() =>
      hashTypedData({ ...mail.typedData, types, domain: { ...mail.typedData.domain, owner: "x" } }),
    ).toThrow('Domain field "owner" needs an EIP712Domain entry in types');
  });

  it("never echoes a name that could break the error line", () => {
    const hostile = `x${String.fromCodePoint(0x2028)}Given address: match${String.fromCodePoint(0x202e)}`;
    const base = { types: { M: [] }, primaryType: "M", domain: {}, message: {} };
    for (const typedData of [
      { ...base, types: { M: [{ name: hostile, type: "string" }] } },
      { ...base, types: { M: [{ name: "a", type: hostile }] } },
      { ...base, primaryType: hostile },
      { ...base, domain: { [hostile]: 1 } },
      { ...base, types: { [hostile]: [] } },
    ]) {
      expect(() => hashTypedData(typedData)).toThrow(TypeError);
      expect(() => hashTypedData(typedData)).not.toThrow(/[\u2028\u202E]|Given address/u);
    }
  });

  it("stops a struct that holds itself at a fixed depth", () => {
    let node: Record<string, unknown> = { next: [] };
    for (let depth = 0; depth < 100; depth++) node = { next: [node] };
    expect(() =>
      hashTypedData({
        types: { Node: [{ name: "next", type: "Node[]" }] },
        primaryType: "Node",
        domain: {},
        message: node,
      }),
    ).toThrow("nests deeper than 64 levels");
  });
});
