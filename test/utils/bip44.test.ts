import { expect, test, describe } from "vitest";
import {
  BIP44,
  BIP44Change,
  getBIP32Path,
  getBIP44Path,
  getHardenedPath,
  parseBIP44Path,
  getBlockchainPath,
} from "../../src/utils/bip44";
import { bip39TestVectors } from "../fixtures";
import { useBlockchain } from "../../src/blockchain";
import Bitcoin from "../../src/blockchains/bitcoin";
import Ethereum from "../../src/blockchains/ethereum";
import Solana from "../../src/blockchains/solana";
import Stellar from "../../src/blockchains/stellar";
import Aptos from "../../src/blockchains/aptos";
import Sui from "../../src/blockchains/sui";
import Cardano from "../../src/blockchains/cardano";

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

describe("Purpose and hardened paths", () => {
  test("should build the five level layout under any purpose", () => {
    expect(getBIP32Path(84, BIP44.BITCOIN)).toBe("m/84'/0'/0'/0/0");
    expect(getBIP32Path(1852, BIP44.CARDANO, 2, BIP44Change.INTERNAL, 7)).toBe(
      "m/1852'/1815'/2'/1/7",
    );
  });

  test("should leave the change level to the purpose, BIP44 alone pins it to 0 and 1", () => {
    expect(getBIP32Path(1852, BIP44.CARDANO, 0, 2)).toBe("m/1852'/1815'/0'/2/0");
    expect(() => getBIP32Path(44, BIP44.BITCOIN, 0, -1)).toThrow(RangeError);
    expect(() => getBIP44Path(BIP44.BITCOIN, 0, 2)).toThrow(RangeError);
  });

  test("should reject a purpose outside the BIP32 range", () => {
    expect(() => getBIP32Path(-1, BIP44.BITCOIN)).toThrow(RangeError);
    expect(() => getBIP32Path(2_147_483_648, BIP44.BITCOIN)).toThrow(RangeError);
  });

  test("should harden every level and stop at the depth given", () => {
    expect(getHardenedPath(BIP44.STELLAR, [0])).toBe("m/44'/148'/0'");
    expect(getHardenedPath(BIP44.SOLANA, [3, 1])).toBe("m/44'/501'/3'/1'");
    expect(getHardenedPath(BIP44.SUI, [0, 0, 42])).toBe("m/44'/784'/0'/0'/42'");
  });

  test.each([
    ["no levels", () => getHardenedPath(BIP44.SOLANA, [])],
    ["a fourth level", () => getHardenedPath(BIP44.SOLANA, [0, 0, 0, 0])],
    ["a negative account", () => getHardenedPath(BIP44.SOLANA, [-1])],
    [
      "a change branch above the BIP32 range",
      () => getHardenedPath(BIP44.SOLANA, [0, 2_147_483_648]),
    ],
    ["a coin type above the BIP32 range", () => getHardenedPath(2_147_483_648, [0])],
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

  test("should respect custom account parameters", () => {
    const chain = useBlockchain(new Bitcoin());
    const path = getBlockchainPath(chain, 2, BIP44Change.INTERNAL, 5);
    expect(path).toBe("m/44'/0'/2'/1/5");
  });

  test("should fall back to BIP44 for a chain that only carries a coin type", () => {
    expect(getBlockchainPath({ bip44: BIP44.SOLANA })).toBe("m/44'/501'/0'/0/0");
  });

  test.each([
    ["solana", new Solana(), "m/44'/501'/0'/0'"],
    ["stellar", new Stellar(), "m/44'/148'/0'"],
    ["aptos", new Aptos(), "m/44'/637'/0'/0'/0'"],
    ["sui", new Sui(), "m/44'/784'/0'/0'/0'"],
    ["cardano", new Cardano(), "m/1852'/1815'/0'/0/0"],
  ])("should generate the path %s wallets use", (_name, chain, expected) => {
    expect(getBlockchainPath(useBlockchain(chain))).toBe(expected);
  });

  test("should hand the scheme to a chain with two curves", () => {
    const chain = useBlockchain(new Sui());
    expect(getBlockchainPath(chain, 0, 0, 0, { scheme: "secp256k1" })).toBe("m/54'/784'/0'/0/0");
  });

  test.each([
    ["solana", new Solana()],
    ["stellar", new Stellar()],
    ["aptos", new Aptos()],
    ["sui", new Sui()],
  ])("should generate a path %s can derive over SLIP-10", (_name, chain) => {
    const blockchain = useBlockchain(chain);
    const path = getBlockchainPath(blockchain, 1);
    const wallet = blockchain.deriveHDWallet(bip39TestVectors.mnemonic, path);
    expect(blockchain.validateAddress(wallet.address)).toBe(true);
  });
});
