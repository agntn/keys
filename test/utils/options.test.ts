import { describe, expect, it } from "vite-plus/test";
import { blockchains } from "../../src/_blockchains.ts";
import { getBlockchainPath } from "../../src/blockchain.ts";

const names = Object.keys(blockchains) as (keyof typeof blockchains)[];

describe("calls still written with positional arguments", () => {
  it.each(names)("%s refuses a signature verified positionally", async (name) => {
    const chain = await blockchains[name]()();
    const wallet = chain.generateWallet();
    const signature = chain.signMessage("hi", { privateKey: wallet.keys.private });
    expect(chain.verifyMessage("hi", { signature, publicKey: wallet.keys.public })).toBe(true);
    expect(() => {
      Reflect.apply(chain.verifyMessage.bind(chain), undefined, [
        "hi",
        signature,
        wallet.keys.public,
      ]);
    }).toThrow(
      new TypeError(
        "verifyMessage takes the signature and the key in its options: verifyMessage(message, { signature, publicKey })",
      ),
    );
  });

  it.each(names)("%s refuses a key handed over positionally", async (name) => {
    const chain = await blockchains[name]()();
    const wallet = chain.generateWallet();
    expect(() => {
      Reflect.apply(chain.signMessage.bind(chain), undefined, ["hi", wallet.keys.private]);
    }).toThrow("signMessage takes the private key in its options");
  });

  /* Monero and Polkadot have no BIP44 path and throw for any arguments. */
  it.each(names.filter((name) => name !== "monero" && name !== "polkadot"))(
    "%s refuses an account number in place of the path options",
    async (name) => {
      const chain = await blockchains[name]()();
      expect(() => {
        Reflect.apply(chain.getDerivationPath.bind(chain), undefined, [1, 0, 5]);
      }).toThrow(TypeError);
      expect(() => {
        Reflect.apply(getBlockchainPath, undefined, [chain, 1, 0, 5]);
      }).toThrow("Derivation paths take their levels in an options object");
      expect(() => {
        Reflect.apply(chain.getDerivationPath.bind(chain), undefined, [[1, 0, 5]]);
      }).toThrow(TypeError);
    },
  );

  it("still reads a path left out or given as levels", async () => {
    const chain = await blockchains.bitcoin()();
    expect(getBlockchainPath(chain)).toBe("m/44'/0'/0'/0/0");
    expect(getBlockchainPath(chain, { account: 1, change: 1, addressIndex: 5 })).toBe(
      "m/44'/0'/1'/1/5",
    );
    expect(getBlockchainPath({ bip44: 2 }, { account: 3 })).toBe("m/44'/2'/3'/0/0");
  });
});
