import { hex } from "@agntn/encodings/hex";
import { describe, expect, it } from "vite-plus/test";
import { checksum, parse } from "../../src/utils/descriptor/index.ts";
import { descriptorVectors } from "../fixtures.ts";

const { generator: g, double } = descriptorVectors;
const xpub =
  "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";

/* The message parse throws for a descriptor, or an empty string when it parses. */
const failure = (descriptor: string): string => {
  try {
    parse(descriptor);
    return "";
  } catch (error) {
    return String(error);
  }
};

describe("Descriptor checksum", () => {
  it("matches the BIP380 vector and leaves a carried checksum out", () => {
    const { descriptor, checksum: expected } = descriptorVectors.checksum;
    expect(checksum(descriptor)).toBe(expected);
    expect(checksum(`${descriptor}#qqqqqqqq`)).toBe(expected);
  });

  it("refuses a second # and a character outside the BIP380 set", () => {
    expect(() => checksum("raw(deedbeef)##9f8spxm")).toThrow("more than one #");
    expect(() => checksum("raw(Ü)")).toThrow("outside the BIP380 set at position 5");
  });
});

describe("Descriptor outputs", () => {
  it.each(descriptorVectors.bip)("writes the BIP scripts of $descriptor", (vector) => {
    const descriptor = parse(vector.descriptor);
    expect(descriptor.ranged).toBe(vector.scripts.length > 1);
    const scripts = vector.scripts.map((_, index) =>
      hex.encode(descriptor.derive(descriptor.ranged ? index : undefined).script),
    );
    expect(scripts).toEqual(vector.scripts);
  });

  it.each(descriptorVectors.core)(
    "gives Core's checksum and addresses for $descriptor",
    (vector) => {
      const network = "network" in vector ? vector.network : "mainnet";
      const descriptor = parse(vector.descriptor, { network });
      if ("checksum" in vector) expect(descriptor.checksum).toBe(vector.checksum);
      const first = "first" in vector ? vector.first : 0;
      const addresses = vector.addresses.map(
        (_, offset) => descriptor.derive(descriptor.ranged ? first + offset : undefined).address,
      );
      expect(addresses).toEqual(vector.addresses);
    },
  );

  it("checks a carried checksum", () => {
    const [vector] = descriptorVectors.core;
    expect(parse(`${vector.descriptor}#${vector.checksum}`).checksum).toBe(vector.checksum);
    expect(() => parse(`${vector.descriptor}#qqqqqqqq`)).toThrow(
      `Checksum qqqqqqqq does not match the descriptor, which sums to ${vector.checksum}`,
    );
    expect(() => parse(`${vector.descriptor}#`)).toThrow("must be 8 characters of the bech32 set");
    expect(failure(`${vector.descriptor}#qqqq\u2028qqq`)).not.toContain("\u2028");
  });

  it("takes an index only when a key ends in /*", () => {
    const ranged = parse(`wpkh(${xpub}/0/*)`);
    expect(() => ranged.derive()).toThrow("Ranged descriptor needs an index");
    expect(() => ranged.derive(2 ** 31)).toThrow("from 0 to 2^31 - 1");
    expect(() => parse(`wpkh(${g})`).derive(0)).toThrow("takes no index");
  });

  it.each([
    [`pk(${g})`, "pk() has no address here"],
    [`raw(00)`, "raw() has no address here"],
    [`sh(sh(pkh(${g})))`, "sh() is not allowed here"],
    [`wsh(wpkh(${g}))`, "wpkh() is not allowed here"],
    [`sh(tr(${g.slice(2)}))`, "tr() is not allowed here"],
    [`wsh(multi_a(1,${g}))`, "multi_a() is not allowed here"],
    [`tr(${g},multi(1,${g}))`, "multi() is not allowed in a tr() tree"],
    [`tr(${g},{pk(${g})})`, "holds exactly two parts"],
    [`tr(${g},pk(${g}),pk(${double}))`, "at most one tree"],
    [`pkh(${g},${double})`, "pkh() takes one key"],
    [`wsh(multi(0,${g}))`, "threshold must be from 1 to the number of keys, 1"],
    [`wsh(multi(1))`, "multi() takes a threshold, then 1 to 20 keys"],
    [`wpkh(${g.slice(2)})`, "x-only keys belong in tr() only"],
    [`wpkh(${xpub}/0h/*)`, "Hardened steps need the extended private key"],
    [`wpkh(${xpub}/<0;1>/*)`, "Multipath <a;b> steps are not supported"],
    [`wpkh(${g}/0)`, "Only extended keys take derivation steps"],
    [`wpkh([deadbeef][deadbeef]${g})`, "more than one origin"],
    [`wpkh([deadbeef/2147483648]${g})`, "not a number below 2^31"],
    [`wpkh([deadbeef/0h/2147483648]${g})`, "not a number below 2^31"],
    [`wpkh(${g})`.replace(")", ""), "opening bracket without its closing one"],
    [`wsh(pk(${g})))`, "closing bracket without its opening one"],
    [`wpkh(KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJZ)`, "Key is not hex, a mainnet WIF"],
  ])("refuses %s", (descriptor, message) => {
    expect(() => parse(descriptor)).toThrow(message);
  });

  it("refuses an xpub on testnet and a key it cannot read without echoing it", () => {
    expect(() => parse(`wpkh(${xpub})`, { network: "testnet" })).toThrow(
      "Extended key on testnet must be a tpub or tprv",
    );
    const wif = "KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJZ";
    expect(() => parse(`pkh(${wif})`)).toThrow("Key is not hex");
    expect(failure(`pkh(${wif})`)).not.toContain(wif);
  });
});
