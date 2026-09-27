<script setup lang="ts">
import {
  deriveAddresses,
  loadExplorerChains,
  toSnippet,
  type Derivation,
  type ExplorerChains,
} from "../../utils/derive";
import {
  isParsedKey,
  parseDecimalKey,
  parseHexKey,
  stepKey,
  type ParseError,
  type ParsedKey,
} from "../../utils/parse-key";
import { diffBytes } from "../../utils/landing";
import { CHAINS } from "../../utils/chains";
import { shortDecimal } from "../../utils/format";
import { ROSTER_TABLE_UI } from "../../utils/roster";

const hexInput = ref("1");
const decimalInput = ref("1");
const error = ref("");
const loading = ref(true);
const loadError = ref("");
const derivation = ref<Derivation | null>(null);
const { copied, copy } = useCopied();
const changedBytes = ref<ReadonlySet<number>>(new Set());

const bytes = computed(() => {
  const hex = current.hex;
  const firstSignificant = hex.search(/[^0]/u);
  const list: { value: string; dim: boolean; hot: boolean }[] = [];
  for (let index = 0; index < 32; index += 1) {
    list.push({
      value: hex.slice(index * 2, index * 2 + 2),
      dim: firstSignificant === -1 ? index < 31 : index * 2 + 1 < firstSignificant,
      hot: changedBytes.value.has(index),
    });
  }
  return list;
});

const publicKeys = computed(() =>
  derivation.value
    ? [
        { id: "c", label: "secp256k1 compressed", value: derivation.value.secp256k1PublicCompressed },
        { id: "u", label: "secp256k1 uncompressed", value: derivation.value.secp256k1PublicUncompressed },
        { id: "e", label: "ed25519", hint: "same 32 bytes as a secret", value: derivation.value.ed25519Public },
      ]
    : [],
);

const snippet = computed(() => toSnippet(hexInput.value));

/** The chain's token glyph, looked up by the label the derivation rows carry. */
function chainIcon(label: string): string {
  return CHAINS.find((chain) => chain.label === label)?.icon ?? "i-lucide-link";
}

/** Columns of the address table; the rows stack once the instrument is narrower than 52rem. */
const columns = [
  { accessorKey: "chain", header: "Chain", meta: { class: { th: "w-[10rem]" } } },
  { accessorKey: "format", header: "Format", meta: { class: { th: "w-[12rem]" } } },
  { accessorKey: "address", header: "Address" },
];

let chains: ExplorerChains | undefined;
const current = reactive<ParsedKey>({ hex: "1".padStart(64, "0"), decimal: 1n });

function applyKey(parsed: ParsedKey, writeHash = true) {
  changedBytes.value = diffBytes(current.hex, parsed.hex);
  current.hex = parsed.hex;
  current.decimal = parsed.decimal;
  hexInput.value = parsed.hex;
  decimalInput.value = parsed.decimal.toString();
  error.value = "";
  if (!chains) {
    return;
  }
  try {
    derivation.value = deriveAddresses(parsed.hex, chains);
  } catch (cause) {
    derivation.value = null;
    error.value = cause instanceof Error ? cause.message : "Derivation failed.";
    return;
  }
  if (writeHash && import.meta.client) {
    const shortHex = parsed.hex.replace(/^0+/u, "") || "0";
    history.replaceState(history.state, "", `#${shortHex}`);
  }
}

function onHex() {
  const parsed = parseHexKey(hexInput.value);
  if (!isParsedKey(parsed)) {
    error.value = parsed.error;
    derivation.value = null;
    return;
  }
  applyKey(parsed);
}

function onDecimal() {
  const parsed = parseDecimalKey(decimalInput.value);
  if (!isParsedKey(parsed)) {
    error.value = parsed.error;
    derivation.value = null;
    return;
  }
  applyKey(parsed);
}

function step(delta: bigint) {
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

/** The fragment is the shareable key. A bad one shows as typed instead of turning into key 1. */
function keyFromHash(): ParsedKey | ParseError | undefined {
  if (!import.meta.client) {
    return undefined;
  }
  const hash = window.location.hash.replace(/^#/u, "");
  return hash === "" ? undefined : parseHexKey(hash);
}

onMounted(async () => {
  try {
    chains = await loadExplorerChains(await import("@agntn/keys"));
    const linked = keyFromHash();
    if (linked && !isParsedKey(linked)) {
      hexInput.value = window.location.hash.replace(/^#/u, "");
      error.value = `The key in the link was rejected. ${linked.error}`;
      derivation.value = null;
    } else {
      applyKey(linked ?? current, false);
    }
  } catch (cause) {
    loadError.value = cause instanceof Error ? cause.message : "Failed to load blockchains.";
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <section class="tool-console console-wide explorer not-prose" aria-label="Keyspace explorer">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>

    <header class="console-bar">
      <span class="console-title"
        ><span class="console-tag">Key</span>k = {{ shortDecimal(current.decimal, 8) }}</span
      >
      <span class="console-meta">secp256k1 · 1 … n − 1</span>
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true">
      <span :key="current.hex" class="console-cursor" :class="{ 'console-cursor-busy': loading }" />
    </div>

    <div class="explorer-band">
      <p class="console-label console-rule-title">
        <span>01 Input <span aria-hidden="true">[ decimal or hex ]</span></span>
        <span class="console-mark" aria-hidden="true" />
      </p>
      <div class="console-readout explorer-input">
        <dl class="console-readout-rows">
          <div>
            <dt><label for="explorer-decimal">Decimal</label></dt>
            <dd>
              <input
                id="explorer-decimal"
                v-model="decimalInput"
                spellcheck="false"
                autocomplete="off"
                inputmode="numeric"
                :disabled="loading"
                @change="onDecimal"
                @keydown.enter="onDecimal"
              />
            </dd>
          </div>
          <div>
            <dt><label for="explorer-hex">Hex</label></dt>
            <dd>
              <input
                id="explorer-hex"
                v-model="hexInput"
                spellcheck="false"
                autocomplete="off"
                :disabled="loading"
                @change="onHex"
                @keydown.enter="onHex"
              />
            </dd>
          </div>
        </dl>
      </div>
      <p v-if="loadError || error" class="explorer-error" role="alert">
        <UIcon name="i-lucide-shield-alert" class="size-3.5" aria-hidden="true" />
        {{ loadError || error }}
      </p>
      <p v-else-if="loading" class="explorer-note">
        <UIcon name="i-lucide-loader-circle" class="size-3.5 animate-spin" aria-hidden="true" />
        Loading the chain modules into this tab
      </p>
    </div>

    <template v-if="derivation">
      <div class="explorer-band">
        <p class="console-label console-rule-title">
          <span>02 Secret <span aria-hidden="true">[ the scalar, big-endian ]</span></span>
          <span class="console-mark" aria-hidden="true" />
        </p>
        <p class="key-bytes" :aria-label="`Private key ${current.hex}`">
          <span
            v-for="(byte, index) in bytes"
            :key="`${index}-${byte.value}`"
            :class="{ 'key-byte-dim': byte.dim, 'key-byte-hot': byte.hot }"
            >{{ byte.value }}</span
          >
        </p>
      </div>

      <div class="explorer-band">
        <p class="console-label console-rule-title">
          <span>03 Public keys <span aria-hidden="true">[ k · G, or the bytes as a seed ]</span></span>
          <span class="console-mark" aria-hidden="true" />
        </p>
        <dl class="explorer-keys">
          <div v-for="key in publicKeys" :key="key.id">
            <dt>
              {{ key.label }}<span v-if="key.hint">{{ key.hint }}</span>
            </dt>
            <dd><LandingAddress :address="key.value" /></dd>
            <button
              type="button"
              class="console-button"
              :data-copied="copied === key.id"
              :aria-label="copied === key.id ? 'Copied' : `Copy ${key.label}`"
              @click="copy(key.id, key.value)"
            >
              <UIcon :name="copied === key.id ? 'i-lucide-check' : 'i-lucide-copy'" class="size-3" />
            </button>
          </div>
        </dl>
      </div>

      <div class="explorer-band explorer-table">
        <p class="console-label console-rule-title">
          <span
            >04 Addresses
            <span aria-hidden="true">[ {{ derivation.addresses.length }} formats · hash, then encode ]</span></span
          >
          <span class="console-mark" aria-hidden="true" />
        </p>
        <UTable
          :data="[...derivation.addresses]"
          :columns="columns"
          :get-row-id="(row) => row.id"
          :ui="ROSTER_TABLE_UI"
        >
          <template #chain-cell="{ row }">
            <span class="explorer-chain"
              ><UIcon :name="chainIcon(row.original.chain)" class="size-3.5 flex-none" aria-hidden="true" />{{
                row.original.chain
              }}</span
            >
          </template>
          <template #format-cell="{ row }">
            <span class="explorer-format">{{ row.original.format }}<span> · {{ row.original.curve }}</span></span>
          </template>
          <template #address-cell="{ row }">
            <span class="explorer-address-cell">
              <LandingAddress :address="row.original.address" class="explorer-address" />
              <button
                type="button"
                class="console-button"
                :data-copied="copied === row.original.id"
                :aria-label="
                  copied === row.original.id
                    ? 'Copied'
                    : `Copy ${row.original.chain} ${row.original.format} address`
                "
                @click="copy(row.original.id, row.original.address)"
              >
                <UIcon
                  :name="copied === row.original.id ? 'i-lucide-check' : 'i-lucide-copy'"
                  class="size-3"
                />
              </button>
            </span>
          </template>
        </UTable>
      </div>
    </template>

    <footer class="console-footer console-footer-plain">
      <button
        v-if="derivation"
        type="button"
        class="console-button"
        :data-copied="copied === 'snippet'"
        @click="copy('snippet', snippet)"
      >
        <UIcon :name="copied === 'snippet' ? 'i-lucide-check' : 'i-lucide-copy'" class="size-3" />
        {{ copied === "snippet" ? "copied" : "copy as code" }}
      </button>
      <span v-else>in this tab / nothing stored or sent</span>
      <div class="console-controls" aria-label="Private keys">
        <button type="button" aria-label="Previous key" :disabled="loading" @click="step(-1n)">
          <UIcon name="i-lucide-chevron-left" />
        </button>
        <span>Key</span>
        <button type="button" aria-label="Next key" :disabled="loading" @click="step(1n)">
          <UIcon name="i-lucide-chevron-right" />
        </button>
        <button type="button" aria-label="Random key" :disabled="loading" @click="randomKey">
          <UIcon name="i-lucide-dices" />
        </button>
      </div>
    </footer>
  </section>
</template>

<style scoped>
.explorer-band {
  padding: 18px 20px 20px;
}
.explorer-band + .explorer-band {
  border-top: 1px solid var(--console-line);
}
.explorer-band > .console-rule-title {
  margin: 0 0 12px;
}
.explorer-input .console-readout-rows > div {
  grid-template-columns: 6.5rem minmax(0, 1fr);
}
.explorer-input input {
  font-variant-numeric: tabular-nums;
}
.explorer-error,
.explorer-note {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 12px 0 0;
  font-family: var(--font-sans);
  font-size: 14px;
  color: var(--ui-text-muted);
}
.explorer-error {
  color: var(--keys-del);
}
.explorer-keys {
  display: grid;
  margin: 0;
}
.explorer-keys > div {
  display: grid;
  grid-template-columns: 13rem minmax(0, 1fr) auto;
  gap: 4px 16px;
  align-items: baseline;
  padding: 8px 0;
}
.explorer-keys > div + div {
  box-shadow: inset 0 1px 0 var(--console-line);
}
.explorer-keys dt {
  display: grid;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--ui-text-highlighted);
}
.explorer-keys dt > span {
  font-size: 10px;
  letter-spacing: 0.04em;
  color: var(--ui-text-dimmed);
}
.explorer-keys dd {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  color: var(--ui-text-highlighted);
  overflow-wrap: anywhere;
}
/* The address table sits on the band's padding, not the roster's own. */
.explorer-table {
  padding-inline: 0;
  padding-bottom: 0;
}
.explorer-table > .console-rule-title {
  margin-inline: 20px;
}
.explorer-chain {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-family: var(--font-mono);
  color: var(--ui-text-highlighted);
}
.explorer-format {
  white-space: nowrap;
  font-family: var(--font-mono);
  color: var(--ui-text-muted);
}
.explorer-format > span {
  color: var(--ui-text-dimmed);
}
.explorer-address-cell {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: baseline;
  gap: 12px;
}
.explorer-address {
  font-family: var(--font-mono);
  color: var(--ui-text-highlighted);
  overflow-wrap: anywhere;
}
.explorer .console-controls button:disabled {
  cursor: default;
  opacity: 0.5;
}
@media (width < 640px) {
  .explorer-band {
    padding-inline: 14px;
  }
  .explorer-table {
    padding-inline: 0;
  }
  .explorer-table > .console-rule-title {
    margin-inline: 14px;
  }
  .explorer-band > .console-rule-title > span:first-child > span {
    display: none;
  }
  .explorer-keys > div {
    grid-template-columns: minmax(0, 1fr) auto;
  }
  .explorer-keys dd {
    grid-column: 1 / -1;
    grid-row: 2;
  }
}
</style>
