import { deriveAddresses, type AddressRow, type Derivation, type ExplorerChains } from "../utils/derive";
import { isParsedKey, parseHexKey, stepKey, type ParsedKey } from "../utils/parse-key";

export const KEY_ONE_HEX = "1".padStart(64, "0");

export const landingStaticRows: readonly AddressRow[] = [
  {
    id: "btc-segwit",
    chain: "Bitcoin",
    curve: "secp256k1",
    format: "segwit",
    address: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  },
  {
    id: "eth",
    chain: "Ethereum",
    curve: "secp256k1",
    format: "EIP-55",
    address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
  },
  {
    id: "base",
    chain: "Base",
    curve: "secp256k1",
    format: "EIP-55",
    address: "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf",
  },
  {
    id: "tron",
    chain: "TRON",
    curve: "secp256k1",
    format: "base58check",
    address: "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC",
  },
  {
    id: "sol",
    chain: "Solana",
    curve: "ed25519",
    format: "base58",
    address: "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt",
  },
  {
    id: "aptos",
    chain: "Aptos",
    curve: "ed25519",
    format: "hex",
    address: "0xf90391c81027f03cdea491ed8b36ffaced26b6df208a9b569e5baf2590eb9b16",
  },
  {
    id: "sui-ed25519",
    chain: "Sui",
    curve: "ed25519",
    format: "ed25519",
    address: "0xd0c2c91eda34bbfbaec6cfb9c7bb913e57dab3cbec4018a4b3f5e55531cd63af",
  },
  {
    id: "ada-enterprise",
    chain: "Cardano",
    curve: "ed25519",
    format: "enterprise",
    address: "addr1v8qvqahau6y67jdq0kfm9dy0hjmgv4u962nmk9pslsl7ryq5mvnl7",
  },
];

const LANDING_IDS = new Set(landingStaticRows.map((row) => row.id));

export type Pipeline = {
  readonly publicKey: string;
  readonly legacy: string;
  readonly segwit: string;
  readonly taproot: string;
};

export const landingStaticPipeline: Pipeline = {
  publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  legacy: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
  segwit: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
  taproot: "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
};

function toPipeline(derivation: Derivation): Pipeline {
  const address = (id: string) => derivation.addresses.find((row) => row.id === id)?.address ?? "";
  return {
    publicKey: derivation.secp256k1PublicCompressed,
    legacy: address("btc-legacy"),
    segwit: address("btc-segwit"),
    taproot: address("btc-taproot"),
  };
}

/** Public BIP39 test vector. Never a real wallet. */
export const TEST_MNEMONIC =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

export type HdSample = {
  readonly index: number;
  readonly path: string;
  readonly address: string;
};

const HD_STATIC: HdSample = {
  index: 0,
  path: "m/44'/60'/0'/0/0",
  address: "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
};

export function useLandingKey() {
  const hex = ref(KEY_ONE_HEX);
  const decimal = ref(1n);
  const rows = ref<readonly AddressRow[]>(landingStaticRows);
  const pipeline = ref<Pipeline>(landingStaticPipeline);
  const hd = ref<HdSample>(HD_STATIC);
  const ready = ref(false);
  const paused = ref(false);
  const tick = ref(0);
  const changedBytes = ref<ReadonlySet<number>>(new Set());

  let chains: ExplorerChains | undefined;
  let current: ParsedKey = { hex: KEY_ONE_HEX, decimal: 1n };
  let timer: number | undefined;

  function derive(nextHex: string): { rows: readonly AddressRow[]; pipeline: Pipeline } {
    if (!chains) {
      return { rows: landingStaticRows, pipeline: landingStaticPipeline };
    }
    const derivation = deriveAddresses(nextHex, chains);
    return {
      rows: derivation.addresses.filter((row) => LANDING_IDS.has(row.id)),
      pipeline: toPipeline(derivation),
    };
  }

  function advanceHd() {
    if (!chains) {
      return;
    }
    const index = (hd.value.index + 1) % 10;
    const path = `m/44'/60'/0'/0/${index}`;
    hd.value = { index, path, address: chains.ethereum.deriveHDWallet(TEST_MNEMONIC, path).address };
  }

  function applyKey(parsed: ParsedKey) {
    changedBytes.value = diffBytes(current.hex, parsed.hex);
    current = parsed;
    hex.value = parsed.hex;
    decimal.value = parsed.decimal;
    const derived = derive(parsed.hex);
    rows.value = derived.rows;
    pipeline.value = derived.pipeline;
    advanceHd();
    tick.value += 1;
  }

  function step(delta: bigint) {
    if (!chains) {
      return;
    }
    applyKey(stepKey(current.decimal, delta));
  }

  function randomKey() {
    if (!chains) {
      return;
    }
    const parsed = parseHexKey(chains.bitcoin.generateKeyPrivate());
    if (isParsedKey(parsed)) {
      applyKey(parsed);
    }
  }

  function stopWalk() {
    if (timer !== undefined) {
      window.clearInterval(timer);
      timer = undefined;
    }
  }

  function startWalk() {
    stopWalk();
    if (!import.meta.client || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }
    timer = window.setInterval(() => {
      if (!paused.value && !document.hidden) {
        step(1n);
      }
    }, 2400);
  }

  onMounted(async () => {
    const { useBlockchain, blockchains } = await import("@agntn/keys");
    const [bitcoin, ethereum, base, tron, solana, aptos, sui, cardano] = await Promise.all([
      blockchains.bitcoin()(),
      blockchains.ethereum()(),
      blockchains.base()(),
      blockchains.tron()(),
      blockchains.solana()(),
      blockchains.aptos()(),
      blockchains.sui()(),
      blockchains.cardano()(),
    ]);
    chains = {
      bitcoin: useBlockchain(bitcoin),
      ethereum: useBlockchain(ethereum),
      base: useBlockchain(base),
      tron: useBlockchain(tron),
      solana: useBlockchain(solana),
      aptos: useBlockchain(aptos),
      sui: useBlockchain(sui),
      cardano: useBlockchain(cardano),
    };
    applyKey(current);
    ready.value = true;
    startWalk();
  });

  onUnmounted(stopWalk);

  return { hex, decimal, rows, pipeline, hd, ready, paused, tick, changedBytes, step, randomKey };
}

export function diffBytes(previous: string, next: string): ReadonlySet<number> {
  const changed = new Set<number>();
  for (let index = 0; index < 32; index += 1) {
    if (previous.slice(index * 2, index * 2 + 2) !== next.slice(index * 2, index * 2 + 2)) {
      changed.add(index);
    }
  }
  return changed;
}
