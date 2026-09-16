import {
  deriveAddresses,
  loadExplorerChains,
  type AddressRow,
  type ExplorerChains,
} from "../utils/derive";
import {
  HD_STATIC,
  KEY_ONE_HEX,
  LANDING_IDS,
  TEST_MNEMONIC,
  diffBytes,
  landingStaticPipeline,
  landingStaticRows,
  toPipeline,
  type HdSample,
  type Pipeline,
} from "../utils/landing";
import { isParsedKey, parseHexKey, stepKey, type ParsedKey } from "../utils/parse-key";

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
  let unmounted = false;

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

  /** The chain modules can land after a quick navigation away; nothing may start then. */
  onMounted(async () => {
    const loaded = await loadExplorerChains(await import("@agntn/keys"));
    if (unmounted) {
      return;
    }
    chains = loaded;
    applyKey(current);
    ready.value = true;
    startWalk();
  });

  onUnmounted(() => {
    unmounted = true;
    stopWalk();
  });

  return { hex, decimal, rows, pipeline, hd, ready, paused, tick, changedBytes, step, randomKey };
}
