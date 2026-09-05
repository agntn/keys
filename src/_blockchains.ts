import type { AbstractBlockchain } from "./blockchain.ts";
import type { Options } from "./types.ts";

type BlockchainConstructor<T extends AbstractBlockchain> = new (options?: Options) => T;
type BlockchainModule<T extends AbstractBlockchain> = { default: BlockchainConstructor<T> };

/**
 * Creates a lazy-loaded blockchain class constructor.
 * The import is deferred until the returned async function is called.
 * @param loader - Dynamic import of the module whose default export is the blockchain class
 * @returns {(options?: Options) => () => Promise<T>} Factory capturing constructor options that returns an async loader constructing the blockchain
 */
function lazy<T extends AbstractBlockchain>(loader: () => Promise<BlockchainModule<T>>) {
  return (options?: Options) => async (): Promise<T> => {
    const { default: Blockchain } = await loader();
    return new Blockchain(options);
  };
}

/**
 * Blockchain classes with lazy loading for improved performance and reduced bundle size.
 */
export const blockchains = {
  bitcoin: lazy(() => import("./blockchains/bitcoin.ts")),
  decred: lazy(() => import("./blockchains/decred.ts")),
  litecoin: lazy(() => import("./blockchains/litecoin.ts")),
  solana: lazy(() => import("./blockchains/solana.ts")),
  aptos: lazy(() => import("./blockchains/aptos.ts")),
  tron: lazy(() => import("./blockchains/tron.ts")),
  sui: lazy(() => import("./blockchains/sui.ts")),
  ethereum: lazy(() => import("./blockchains/ethereum.ts")),
  base: lazy(() => import("./blockchains/base.ts")),
  cardano: lazy(() => import("./blockchains/cardano.ts")),
};
