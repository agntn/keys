import { describe, it, expect } from "vite-plus/test";
import {
  HARDENED_OFFSET,
  getMasterKeyFromSeed,
  getHDKeyFromExtended,
  deriveHDKey,
  deriveHDChild,
  hardenedIndex,
  isHardenedIndex,
  formatIndex,
  recoverParent,
  BIP32ChildMismatchError,
  HDKey,
} from "../../src/utils/bip32";
import { hex } from "@scure/base";
import { bip32ParentVector, slip132PrivateKey, slip132Vectors } from "../fixtures";

describe("BIP32 Utils", () => {
  // Vector 1 from BIP32 test vectors
  const testSeed = hex.decode("000102030405060708090a0b0c0d0e0f");
  const expectedMasterKey =
    "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";

  it("creates a master key from seed", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);
    expect(masterKey.privateExtendedKey).toBe(expectedMasterKey);
  });

  it("creates HDKey from extended key", () => {
    const hdkey = getHDKeyFromExtended(expectedMasterKey);
    expect(hdkey.privateExtendedKey).toBe(expectedMasterKey);
  });

  it("derives child keys using path", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);

    // Test vector 1 - m/0'
    const child1 = deriveHDKey(masterKey, "m/0'");
    expect(child1.privateExtendedKey).toBe(
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    );
    expect(child1.publicExtendedKey).toBe(
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw",
    );

    // Test vector 1 - m/0'/1
    const child2 = deriveHDKey(masterKey, "m/0'/1");
    expect(child2.privateExtendedKey).toBe(
      "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
    );
    expect(child2.publicExtendedKey).toBe(
      "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ",
    );
  });

  it("reads h as the hardened marker, as BIP380 descriptors write it", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);

    expect(deriveHDKey(masterKey, "m/0h/1").privateExtendedKey).toBe(
      deriveHDKey(masterKey, "m/0'/1").privateExtendedKey,
    );
    for (const path of ["m/0H/1", "m/0hh/1", "m/0'h/1", "m/0h'/1", "m/h/1", "mh/1"]) {
      expect(() => deriveHDKey(masterKey, path), path).toThrow();
    }
  });

  it("derives child key at specific index", () => {
    const masterKey = getMasterKeyFromSeed(testSeed);
    const hardened0 = deriveHDChild(masterKey, HARDENED_OFFSET);

    expect(hardened0.privateExtendedKey).toBe(
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
    );
  });

  it("creates hardened index", () => {
    expect(hardenedIndex(0)).toBe(0x80_00_00_00);
    expect(hardenedIndex(44)).toBe(0x80_00_00_2c);
    expect(hardenedIndex(0x7f_ff_ff_ff)).toBe(0xff_ff_ff_ff);
  });

  it.each([-1, 0.5, 0x80_00_00_00, Number.NaN, Infinity, -Infinity])(
    "rejects invalid index %s before hardening",
    (index) => {
      expect(() => hardenedIndex(index)).toThrow(RangeError);
    },
  );

  it("checks if index is hardened", () => {
    expect(isHardenedIndex(0)).toBe(false);
    expect(isHardenedIndex(HARDENED_OFFSET)).toBe(true);
  });

  it("formats index correctly", () => {
    expect(formatIndex(0)).toBe("0");
    expect(formatIndex(44)).toBe("44");
    expect(formatIndex(HARDENED_OFFSET)).toBe("0'");
    expect(formatIndex(HARDENED_OFFSET + 44)).toBe("44'");
  });
});

describe("recoverParent", () => {
  const { xpub, xprv, child, hardenedGrandchild } = bip32ParentVector;

  it("recovers BIP32 vector 2 from its xpub and the xprv of m/0", () => {
    const recovered = recoverParent(xpub, child.xprv);
    expect(recovered.parent.privateExtendedKey).toBe(xprv);
    expect(recovered.index).toBe(child.index);
  });

  it("takes a bare child key with its index", () => {
    const recovered = recoverParent(xpub, hex.decode(child.privateKey), child.index);
    expect(recovered.parent.privateExtendedKey).toBe(xprv);
  });

  it("recovers an account xprv below the master", () => {
    const account = HDKey.fromExtendedKey(slip132PrivateKey);
    const leaked = account.deriveChild(7);
    const recovered = recoverParent(account.publicExtendedKey, leaked.privateExtendedKey);
    expect(recovered.parent.privateExtendedKey).toBe(slip132PrivateKey);
    expect(account.publicExtendedKey).toBe(slip132Vectors[0].extendedKey);
  });

  it.each([
    ["xpub", 0x0488b21e, "xprv"],
    ["ypub", 0x049d7cb2, "yprv"],
    ["zpub", 0x04b24746, "zprv"],
    ["tpub", 0x043587cf, "tprv"],
    ["upub", 0x044a5262, "uprv"],
    ["vpub", 0x045f1cf6, "vprv"],
    ["Ltub", 0x019da462, "Ltpv"],
    ["Mtub", 0x01b26ef6, "Mtpv"],
    ["ttub", 0x0436f6e1, "ttpv"],
  ])("writes the parent of a %s with the %s private prefix", (prefix, version, privatePrefix) => {
    const master = HDKey.fromMasterSeed(hex.decode("000102030405060708090a0b0c0d0e0f"), {
      public: version,
      private: 0x0488ade4,
    });
    expect(master.publicExtendedKey.startsWith(prefix)).toBe(true);
    const leaked = master.deriveChild(3).privateKey;
    if (leaked === null) throw new Error("Missing child key");
    const { parent } = recoverParent(master.publicExtendedKey, leaked, 3);
    expect(parent.privateExtendedKey.startsWith(privatePrefix)).toBe(true);
    expect(parent.publicExtendedKey).toBe(master.publicExtendedKey);
    expect(parent.privateKey).toEqual(master.privateKey);
  });

  it("reports a child that does not belong to the xpub, with the index it checked", () => {
    const check = (run: () => unknown, index: number) => {
      try {
        run();
      } catch (error) {
        expect(error).toBeInstanceOf(BIP32ChildMismatchError);
        expect((error as BIP32ChildMismatchError).index).toBe(index);
        return;
      }
      throw new Error("Expected a mismatch");
    };
    check(() => recoverParent(xpub, hex.decode(child.privateKey), 1), 1);
    check(() => recoverParent(slip132Vectors[0].extendedKey, child.xprv), 0);
    const node = HDKey.fromExtendedKey(child.xprv);
    const zprvChild = new HDKey({
      versions: { public: 0x04b24746, private: 0x04b2430c },
      depth: node.depth,
      index: node.index,
      parentFingerprint: node.parentFingerprint,
      chainCode: node.chainCode ?? undefined,
      privateKey: node.privateKey ?? undefined,
    });
    check(() => recoverParent(xpub, zprvChild.privateExtendedKey), 0);
  });

  it("refuses a hardened child, a private parent, a public child and a missing index", () => {
    expect(() => recoverParent(child.xpub, hardenedGrandchild)).toThrow(
      "A hardened child does not reveal its parent",
    );
    expect(() => recoverParent(xpub, hex.decode(child.privateKey), 0x80000000)).toThrow(
      "A hardened child does not reveal its parent",
    );
    expect(() => recoverParent(xprv, child.xprv)).toThrow("not a private one");
    expect(() => recoverParent(xpub, child.xpub)).toThrow("not a public one");
    expect(() => recoverParent(xpub, hex.decode(child.privateKey))).toThrow(
      "A bare child key needs its index",
    );
    expect(() => recoverParent(xpub, child.xprv, 1)).toThrow("which is at 0");
    expect(() => recoverParent(xpub, new Uint8Array(32), 0)).toThrow("valid 32 byte");
    expect(() => recoverParent(`${xpub.slice(0, -1)}C`, child.xprv)).toThrow(
      "Invalid extended public key encoding or checksum",
    );
  });

  it("names the accepted prefixes and keeps the child key out of every error", () => {
    const dgub = HDKey.fromMasterSeed(new Uint8Array(16), { public: 0x02facafd, private: 0 });
    expect(() => recoverParent(dgub.publicExtendedKey, child.xprv)).toThrow(
      /^Extended key "dgub" is not accepted\. Accepted: xpub, ypub, zpub, tpub, upub, vpub, Ltub, Mtub, ttub$/u,
    );
    for (const run of [
      () => recoverParent(xpub, `${child.xprv.slice(0, -1)}1`),
      () => recoverParent(xpub, hex.decode(child.privateKey), 1),
      () => recoverParent(xpub, child.xprv, 1),
    ]) {
      expect(run).toThrow();
      try {
        run();
      } catch (error) {
        expect(String(error)).not.toContain(child.xprv.slice(4, 20));
        expect(String(error)).not.toContain(child.privateKey);
      }
    }
  });
});
