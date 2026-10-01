import { describe, expect, it } from "vite-plus/test";
import { hex } from "@scure/base";
import { KeystorePasswordError, decrypt, encrypt, inspect } from "../../src/utils/store/index.ts";
import { storeVectors } from "../fixtures.ts";

const [pbkdf2Vector, shortKey, , ethersVector] = storeVectors;
const privateKey = hex.decode(pbkdf2Vector.privateKey);
const cheap = { kdf: "scrypt", n: 2, r: 8, p: 1 } as const;

describe("keystore decrypt", () => {
  it.each(storeVectors)(
    "opens the $name keystore",
    { timeout: 30_000 },
    ({ keystore, password, privateKey }) => {
      expect(hex.encode(decrypt(keystore, password))).toBe(privateKey);
    },
  );

  it("reads the file as JSON text too", () => {
    const { keystore, password, privateKey } = ethersVector;
    expect(hex.encode(decrypt(JSON.stringify(keystore), password))).toBe(privateKey);
  });

  it("throws KeystorePasswordError for a wrong password, naming no password", () => {
    const run = () => decrypt(shortKey.keystore, "bar");
    expect(run).toThrow(KeystorePasswordError);
    expect(run).not.toThrow(/bar|foo/);
  });

  it("keeps the password exactly as given", () => {
    expect(() => decrypt(shortKey.keystore, " foo")).toThrow(KeystorePasswordError);
  });

  it("refuses a key that is not the key of the stored address", () => {
    const keystore = { ...ethersVector.keystore, address: "00".repeat(20) };
    expect(() => decrypt(keystore, ethersVector.password)).toThrow(/address/);
  });
});

describe("keystore inspect", () => {
  it("reads KDF, costs and the stored address without the password", () => {
    const file = inspect(ethersVector.keystore);
    expect(file).toMatchObject({
      version: 3,
      id: "33333333-3333-4333-b333-333333333333",
      address: ethersVector.address,
      kdf: "scrypt",
      n: 1024,
      r: 8,
      p: 1,
      dklen: 32,
      cipher: "aes-128-ctr",
    });
    expect(inspect(pbkdf2Vector.keystore)).toMatchObject({ kdf: "pbkdf2", c: 262144 });
    expect(inspect(pbkdf2Vector.keystore)).not.toHaveProperty("address");
  });

  it.each([
    ["not JSON", "{", /JSON/],
    ["version 1", { ...shortKey.keystore, version: 1 }, /version/],
    [
      "AES-128-CBC",
      { ...shortKey.keystore, crypto: { ...shortKey.keystore.crypto, cipher: "aes-128-cbc" } },
      /cipher/,
    ],
    [
      "a short IV",
      { ...shortKey.keystore, crypto: { ...shortKey.keystore.crypto, cipherparams: { iv: "00" } } },
      /iv/,
    ],
    [
      "a dklen under 32",
      {
        ...shortKey.keystore,
        crypto: {
          ...shortKey.keystore.crypto,
          kdfparams: { ...shortKey.keystore.crypto.kdfparams, dklen: 16 },
        },
      },
      /dklen/,
    ],
    [
      "an n that is not a power of 2",
      {
        ...shortKey.keystore,
        crypto: {
          ...shortKey.keystore.crypto,
          kdfparams: { ...shortKey.keystore.crypto.kdfparams, n: 1000 },
        },
      },
      /power of 2/,
    ],
    [
      "a PRF other than HMAC-SHA256",
      {
        ...pbkdf2Vector.keystore,
        crypto: {
          ...pbkdf2Vector.keystore.crypto,
          kdfparams: { ...pbkdf2Vector.keystore.crypto.kdfparams, prf: "hmac-sha512" },
        },
      },
      /prf/,
    ],
  ])("refuses %s", (_name, keystore, message) => {
    expect(() => inspect(keystore)).toThrow(message);
  });
});

describe("keystore encrypt", () => {
  it.each([cheap, { kdf: "pbkdf2", c: 16 }] as const)("round trips a key through $kdf", (kdf) => {
    const file = encrypt(privateKey, "zażółć gęślą jaźń", { kdf });
    expect(file.crypto.kdf).toBe(kdf.kdf);
    expect(hex.encode(decrypt(file, "zażółć gęślą jaźń"))).toBe(pbkdf2Vector.privateKey);
  });

  it("writes the file ethers writes for the same salt, IV, id and costs", () => {
    const { keystore, password } = ethersVector;
    const file = encrypt(privateKey, password, {
      kdf: { kdf: "scrypt", n: 1024, r: 8, p: 1 },
      salt: hex.decode(keystore.Crypto.kdfparams.salt),
      iv: hex.decode(keystore.Crypto.cipherparams.iv),
      id: keystore.id,
    });
    expect(file.address).toBe(keystore.address);
    expect(file.crypto.ciphertext).toBe(keystore.Crypto.ciphertext);
    expect(file.crypto.mac).toBe(keystore.Crypto.mac);
  });

  it("defaults to geth's scrypt cost", { timeout: 30_000 }, () => {
    const file = encrypt(privateKey, "testpassword");
    expect(file.crypto.kdfparams).toMatchObject({ dklen: 32, n: 262144, r: 8, p: 1 });
  });

  it("draws a new salt, IV and UUID v4 for every file unless given", () => {
    const [first, second] = [
      encrypt(privateKey, "", { kdf: cheap }),
      encrypt(privateKey, "", { kdf: cheap }),
    ];
    expect(first.crypto.cipherparams.iv).not.toBe(second.crypto.cipherparams.iv);
    expect(first.crypto.kdfparams.salt).not.toBe(second.crypto.kdfparams.salt);
    expect(first.id).not.toBe(second.id);
    expect(first.id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
  });

  it("refuses a key outside the curve order and an IV of the wrong size", () => {
    expect(() => encrypt(new Uint8Array(32), "", { kdf: cheap })).toThrow(/scalar/);
    expect(() => encrypt(privateKey, "", { kdf: cheap, iv: new Uint8Array(8) })).toThrow(/IV/);
  });
});
