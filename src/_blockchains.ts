import type { AbstractBlockchain } from "./blockchain.ts";
import type { Options } from "./types.ts";

type BlockchainConstructor<T extends AbstractBlockchain> = new (options?: Options) => T;
type BlockchainModule<T extends AbstractBlockchain> = { default?: BlockchainConstructor<T> };

/** The last chain module import in flight; the next one starts only after it settles. */
let importQueue: Promise<unknown> = Promise.resolve();

/**
 * Creates a lazy-loaded blockchain class constructor.
 * The import is deferred until the returned async function is called.
 *
 * Chain modules load one after another on purpose. They share base classes and utilities, and a
 * host loader that evaluates a module once per importer, such as the jiti loader Pi runs extensions
 * under, re-enters those shared modules when two imports overlap and hands the second importer a
 * half-initialized namespace.
 * @param name - Chain name, used in the error when the module has no class to construct
 * @param loader - Dynamic import of the module whose default export is the blockchain class
 * @returns {(options?: Options) => () => Promise<T>} Factory capturing constructor options that returns an async loader constructing the blockchain
 */
export function lazy<T extends AbstractBlockchain>(
  name: string,
  loader: () => Promise<BlockchainModule<T>>,
) {
  return (options?: Options) => async (): Promise<T> => {
    const loading = importQueue.then(loader);
    importQueue = loading.catch(() => undefined);
    const { default: Blockchain } = await loading;
    if (typeof Blockchain !== "function") {
      throw new TypeError(`The ${name} module loaded without a blockchain class`);
    }
    return new Blockchain(options);
  };
}

/**
 * Blockchain classes with lazy loading for improved performance and reduced bundle size.
 */
export const blockchains = {
  bitcoin: lazy("bitcoin", () => import("./blockchains/bitcoin.ts")),
  decred: lazy("decred", () => import("./blockchains/decred.ts")),
  litecoin: lazy("litecoin", () => import("./blockchains/litecoin.ts")),
  solana: lazy("solana", () => import("./blockchains/solana.ts")),
  stellar: lazy("stellar", () => import("./blockchains/stellar.ts")),
  aptos: lazy("aptos", () => import("./blockchains/aptos.ts")),
  tron: lazy("tron", () => import("./blockchains/tron.ts")),
  sui: lazy("sui", () => import("./blockchains/sui.ts")),
  ethereum: lazy("ethereum", () => import("./blockchains/ethereum.ts")),
  base: lazy("base", () => import("./blockchains/base.ts")),
  cardano: lazy("cardano", () => import("./blockchains/cardano.ts")),
};
