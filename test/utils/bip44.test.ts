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
