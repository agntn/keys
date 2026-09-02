/** Every blockchain exposed by the tool surfaces. */
export const TOOL_CHAINS = [
  "bitcoin",
  "ethereum",
  "base",
  "solana",
  "aptos",
  "tron",
  "sui",
  "cardano",
] as const;

/** Blockchain name accepted by the tool surfaces. */
export type ToolChain = (typeof TOOL_CHAINS)[number];

/** Every network exposed by the tool surfaces. */
export const TOOL_NETWORKS = ["mainnet", "testnet"] as const;

/** Network name accepted by the tool surfaces. */
export type ToolNetwork = (typeof TOOL_NETWORKS)[number];

const BITCOIN_ADDRESS_TYPES = ["legacy", "p2sh", "segwit", "p2wsh", "taproot"] as const;
const CARDANO_ADDRESS_TYPES = ["payment", "stake", "enterprise"] as const;
const SUI_ADDRESS_TYPES = ["ed25519", "secp256k1"] as const;

/** Every address type exposed by the tool surfaces. */
export const TOOL_ADDRESS_TYPES = [
  ...BITCOIN_ADDRESS_TYPES,
  ...CARDANO_ADDRESS_TYPES,
  ...SUI_ADDRESS_TYPES,
] as const;

/** Address types accepted for each tool chain. */
export const TOOL_ADDRESS_TYPES_BY_CHAIN: Readonly<Record<ToolChain, readonly string[]>> = {
  bitcoin: BITCOIN_ADDRESS_TYPES,
  ethereum: [],
  base: [],
  solana: [],
  aptos: [],
  tron: [],
  sui: SUI_ADDRESS_TYPES,
  cardano: CARDANO_ADDRESS_TYPES,
};
