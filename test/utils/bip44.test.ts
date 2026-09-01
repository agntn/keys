import { expect, test, describe } from "vitest";
import {
  BIP44,
  BIP44Change,
  getBIP44Path,
  parseBIP44Path,
  getBlockchainPath,
} from "../../src/utils/bip44";
import { useBlockchain } from "../../src/blockchain";
import Bitcoin from "../../src/blockchains/bitcoin";
import Ethereum from "../../src/blockchains/ethereum";
import Solana from "../../src/blockchains/solana";

describe("BIP44 Path Generation", () => {
  test("should generate correct BIP44 path for Bitcoin", () => {
    const path = getBIP44Path(BIP44.BITCOIN);
    expect(path).toBe("m/44'/0'/0'/0/0");
  });

  test("should generate correct BIP44 path for Ethereum", () => {
    const path = getBIP44Path(BIP44.ETHEREUM);
    expect(path).toBe("m/44'/60'/0'/0/0");
  });

  test("should generate correct BIP44 path with custom account", () => {
    const path = getBIP44Path(BIP44.BITCOIN, 5);
    expect(path).toBe("m/44'/0'/5'/0/0");
  });

  test("should generate correct BIP44 path with internal chain", () => {
    const path = getBIP44Path(BIP44.ETHEREUM, 0, BIP44Change.INTERNAL);
    expect(path).toBe("m/44'/60'/0'/1/0");
  });

  test("should generate correct BIP44 path with custom address index", () => {
    const path = getBIP44Path(BIP44.SOLANA, 0, BIP44Change.EXTERNAL, 42);
    expect(path).toBe("m/44'/501'/0'/0/42");
  });

  test("should generate a path with the largest BIP32 level indices", () => {
    const path = getBIP44Path(2_147_483_647, 2_147_483_647, BIP44Change.INTERNAL, 2_147_483_647);

    expect(path).toBe("m/44'/2147483647'/2147483647'/1/2147483647");
  });

  test.each([
    ["a negative coin type", () => getBIP44Path(-1)],
    ["a coin type above the BIP32 range", () => getBIP44Path(2_147_483_648)],
    ["a negative account", () => getBIP44Path(BIP44.BITCOIN, -1)],
    ["a change level other than 0 or 1", () => getBIP44Path(BIP44.BITCOIN, 0, 2)],
    ["a negative address index", () => getBIP44Path(BIP44.BITCOIN, 0, 0, -1)],
    ["a fractional address index", () => getBIP44Path(BIP44.BITCOIN, 0, 0, 1.5)],
  ])("should reject %s", (_description, generate) => {
    expect(generate).toThrow(RangeError);
  });
});

describe("BIP44 Path Parsing", () => {
  test("should parse valid BIP44 path correctly", () => {
    const result = parseBIP44Path("m/44'/60'/0'/0/0");
    expect(result).toEqual({
      purpose: 44,
      coinType: 60,
      account: 0,
      change: 0,
      addressIndex: 0,
    });
  });

  test("should parse path with custom values correctly", () => {
    const result = parseBIP44Path("m/44'/501'/3'/1/7");
    expect(result).toEqual({
      purpose: 44,
      coinType: 501,
      account: 3,
      change: 1,
      addressIndex: 7,
    });
  });

  test("should return null for invalid BIP44 path with wrong purpose", () => {
    const result = parseBIP44Path("m/43'/60'/0'/0/0");
    expect(result).toBeUndefined();
  });

  test("should return null for path with wrong structure", () => {
    const result = parseBIP44Path("m/44'/60'/0'/0");
    expect(result).toBeUndefined();
  });

  test("should return null when non-hardened path segments are incorrect", () => {
    const result = parseBIP44Path("m/44'/60'/0'/0'/0");
    expect(result).toBeUndefined();
  });

  test.each([
    ["non-numeric segments", "m/44'/abc'/0'/0/xyz"],
    ["a non-numeric address index", "m/44'/60'/0'/0/abc"],
    ["a hex literal coin type", "m/44'/0x10'/0'/0/0"],
    ["an exponent coin type", "m/44'/1e3'/0'/0/0"],
    ["a fractional address index", "m/44'/60'/0'/0/5.9"],
    ["trailing characters after the digits", "m/44'/60'/0'/0/0abc"],
    ["leading whitespace", "m/44'/60'/0'/0/ 5"],
    ["an empty segment", "m/44'/60'/0'/0/"],
    ["a negative address index", "m/44'/60'/0'/0/-1"],
  ])("should return undefined for %s", (_description, path) => {
    expect(parseBIP44Path(path)).toBeUndefined();
  });

  test("should return undefined when a level exceeds the BIP32 index range", () => {
    const result = parseBIP44Path("m/44'/2147483648'/0'/0/0");
    expect(result).toBeUndefined();
  });

  test("should parse the largest level index BIP32 allows", () => {
    const result = parseBIP44Path("m/44'/2147483647'/0'/0/2147483647");
    expect(result).toEqual({
      purpose: 44,
      coinType: 2_147_483_647,
      account: 0,
      change: 0,
      addressIndex: 2_147_483_647,
    });
  });
});

describe("Blockchain Path Integration", () => {
  test("should generate correct path for bitcoin blockchain", () => {
    const chain = useBlockchain(new Bitcoin());
    const path = getBlockchainPath(chain);
    expect(path).toBe("m/44'/0'/0'/0/0");
  });

  test("should generate correct path for ethereum blockchain", () => {
    const chain = useBlockchain(new Ethereum());
    const path = getBlockchainPath(chain);
    expect(path).toBe("m/44'/60'/0'/0/0");
  });

  test("should generate correct path for solana blockchain", () => {
    const chain = useBlockchain(new Solana());
    const path = getBlockchainPath(chain);
    expect(path).toBe("m/44'/501'/0'/0/0");
  });

  test("should respect custom account parameters", () => {
    const chain = useBlockchain(new Bitcoin());
    const path = getBlockchainPath(chain, 2, BIP44Change.INTERNAL, 5);
    expect(path).toBe("m/44'/0'/2'/1/5");
  });
});
