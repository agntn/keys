import { expect, test, describe } from "vite-plus/test";
import { BIP44, BIP44Change, getPath, parse } from "../../src/utils/bip44";
import { getBIP32Path, getHardenedPath } from "../../src/utils/bip44/paths";
import { bip39TestVectors, slip10WalletVectors, stellarTestVectors } from "../fixtures";
import { getBlockchainPath, useBlockchain } from "../../src/blockchain";
import { blockchains } from "../../src/_blockchains";
import Bitcoin from "../../src/blockchains/bitcoin";
import Ethereum from "../../src/blockchains/ethereum";
import Solana from "../../src/blockchains/solana";
import Stellar from "../../src/blockchains/stellar";
import Aptos from "../../src/blockchains/aptos";
import Sui from "../../src/blockchains/sui";
import Cardano from "../../src/blockchains/cardano";

describe("BIP44 Path Generation", () => {
  test("should generate correct BIP44 path for Bitcoin", () => {
    const path = getPath(BIP44.BITCOIN);
    expect(path).toBe("m/44'/0'/0'/0/0");
  });

  test("should generate correct BIP44 path for Ethereum", () => {
    const path = getPath(BIP44.ETHEREUM);
    expect(path).toBe("m/44'/60'/0'/0/0");
  });

  test("should generate correct BIP44 path with custom account", () => {
    const path = getPath(BIP44.BITCOIN, 5);
    expect(path).toBe("m/44'/0'/5'/0/0");
  });

  test("should generate correct BIP44 path with internal chain", () => {
    const path = getPath(BIP44.ETHEREUM, 0, BIP44Change.INTERNAL);
    expect(path).toBe("m/44'/60'/0'/1/0");
  });

  test("should generate correct BIP44 path with custom address index", () => {
    const path = getPath(BIP44.SOLANA, 0, BIP44Change.EXTERNAL, 42);
    expect(path).toBe("m/44'/501'/0'/0/42");
  });

  test("should generate a path with the largest BIP32 level indices", () => {
    const path = getPath(2_147_483_647, 2_147_483_647, BIP44Change.INTERNAL, 2_147_483_647);

    expect(path).toBe("m/44'/2147483647'/2147483647'/1/2147483647");
  });

  test.each([
    ["a negative coin type", () => getPath(-1)],
    ["a coin type above the BIP32 range", () => getPath(2_147_483_648)],
    ["a negative account", () => getPath(BIP44.BITCOIN, -1)],
    ["a change level other than 0 or 1", () => getPath(BIP44.BITCOIN, 0, 2)],
    ["a negative address index", () => getPath(BIP44.BITCOIN, 0, 0, -1)],
    ["a fractional address index", () => getPath(BIP44.BITCOIN, 0, 0, 1.5)],
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

  test("should pin change to 0 and 1 unless the purpose allows more", () => {
    expect(() => getBIP32Path(1852, BIP44.CARDANO, 0, 2)).toThrow(RangeError);
    expect(getBIP32Path(1852, BIP44.CARDANO, 0, 2, 0, 5)).toBe("m/1852'/1815'/0'/2/0");
    expect(() => getBIP32Path(1852, BIP44.CARDANO, 0, 6, 0, 5)).toThrow(RangeError);
  });

  test.each([Number.NaN, -1, 2_147_483_648])("should reject %s as the change ceiling", (max) => {
    expect(() => getBIP32Path(1852, BIP44.CARDANO, 0, 0, 0, max)).toThrow(RangeError);
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
    ["a change branch other than 0 or 1", () => getHardenedPath(BIP44.SOLANA, [0, 2])],
    ["a coin type above the BIP32 range", () => getHardenedPath(2_147_483_648, [0])],
  ])("should reject %s", (_description, generate) => {
    expect(generate).toThrow(RangeError);
  });
});

describe("BIP44 Path Parsing", () => {
  test("should parse valid BIP44 path correctly", () => {
    const result = parse("m/44'/60'/0'/0/0");
    expect(result).toEqual({
      purpose: 44,
      coinType: 60,
      account: 0,
      change: 0,
      addressIndex: 0,
    });
  });

  test("should parse path with custom values correctly", () => {
    const result = parse("m/44'/501'/3'/1/7");
    expect(result).toEqual({
      purpose: 44,
      coinType: 501,
      account: 3,
      change: 1,
      addressIndex: 7,
    });
  });

  test.each(["m/44h/501h/3h/1/7", "m/44'/501h/3'/1/7"])(
    "should read h as the hardened marker in %s, as BIP380 descriptors write it",
    (path) => {
      expect(parse(path)).toEqual(parse("m/44'/501'/3'/1/7"));
    },
  );

  test.each(["m/44H/60H/0H/0/0", "m/44h/60h/0h/0h/0", "m/44hh/60h/0h/0/0", "m/44'h/60h/0h/0/0"])(
    "should return undefined for the hardened markers of %s",
    (path) => {
      expect(parse(path)).toBeUndefined();
    },
  );

  test("should return null for invalid BIP44 path with wrong purpose", () => {
    const result = parse("m/43'/60'/0'/0/0");
    expect(result).toBeUndefined();
  });

  test("should return null for path with wrong structure", () => {
    const result = parse("m/44'/60'/0'/0");
    expect(result).toBeUndefined();
  });

  test("should return null when non-hardened path segments are incorrect", () => {
    const result = parse("m/44'/60'/0'/0'/0");
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
    expect(parse(path)).toBeUndefined();
  });

  test("should return undefined when a level exceeds the BIP32 index range", () => {
    const result = parse("m/44'/2147483648'/0'/0/0");
    expect(result).toBeUndefined();
  });

  test("should parse the largest level index BIP32 allows", () => {
    const result = parse("m/44'/2147483647'/0'/0/2147483647");
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

  test.each([
    "bitcoin",
    "litecoin",
    "bitcoingold",
    "bitcoincash",
    "bitcoinsv",
    "dash",
    "dogecoin",
    "zcash",
    "ecash",
    "decred",
  ] as const)("should give a %s testnet wallet coin type 1", async (name) => {
    const testnet = await blockchains[name]({ network: "testnet" })();
    expect(testnet.coinType).toBe(BIP44.TESTNET);
    expect(getBlockchainPath(testnet, 0, 1, 3)).toBe("m/44'/1'/0'/1/3");
    const mainnet = await blockchains[name]()();
    expect(mainnet.coinType).toBe(mainnet.bip44);
  });

  test("should keep the coin type of a chain whose testnet wallets share it", () => {
    expect(getBlockchainPath(new Ethereum({ network: "testnet" }))).toBe("m/44'/60'/0'/0/0");
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

  test.each(slip10WalletVectors)(
    "should generate the path that lands on the known $chain wallet",
    async ({ chain, address }) => {
      const blockchain = await blockchains[chain]()();
      const path = getBlockchainPath(blockchain);
      expect(blockchain.deriveHDWallet(bip39TestVectors.mnemonic, path).address).toBe(address);
    },
  );

  test("should generate the SEP-0005 path that lands on the known Stellar wallet", () => {
    const blockchain = useBlockchain(new Stellar());
    const { mnemonic, accounts } = stellarTestVectors.hd;
    for (const [index, [, , address]] of accounts.entries()) {
      const path = getBlockchainPath(blockchain, index);
      expect(blockchain.deriveHDWallet(mnemonic, path).address).toBe(address);
    }
  });
});
