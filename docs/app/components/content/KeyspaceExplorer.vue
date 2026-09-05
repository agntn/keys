<script setup lang="ts">
import { deriveAddresses, toSnippet, type Derivation, type ExplorerChains } from "../../utils/derive";
import {
  isParsedKey,
  parseDecimalKey,
  parseHexKey,
  stepKey,
  type ParsedKey,
} from "../../utils/parse-key";
import { diffBytes } from "../../composables/useLandingKey";
import { shortDecimal } from "../../utils/format";

const hexInput = ref("1");
const decimalInput = ref("1");
const error = ref("");
const loading = ref(true);
const loadError = ref("");
const derivation = ref<Derivation | null>(null);
const copied = ref("");
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
    history.replaceState(null, "", `#${shortHex}`);
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

async function copy(label: string, value: string) {
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    return;
  }
  copied.value = label;
  setTimeout(() => {
    if (copied.value === label) {
      copied.value = "";
    }
  }, 1200);
}

function keyFromHash(): ParsedKey | undefined {
  if (!import.meta.client) {
    return undefined;
  }
  const hash = window.location.hash.replace(/^#/u, "");
  if (hash === "") {
    return undefined;
  }
  const parsed = parseHexKey(hash);
  return isParsedKey(parsed) ? parsed : undefined;
}

onMounted(async () => {
  try {
    const { useBlockchain, blockchains } = await import("@agntn/keys");
    const [
      bitcoin,
      ethereum,
      base,
      tron,
      solana,
      aptos,
      sui,
      cardano,
    ] = await Promise.all([
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
    applyKey(keyFromHash() ?? current, false);
  } catch (cause) {
    loadError.value = cause instanceof Error ? cause.message : "Failed to load blockchains.";
  } finally {
    loading.value = false;
  }
});
</script>

<template>
  <ClientOnly>
    <div class="not-prose">
      <p v-if="loadError" class="keys-frame rounded-xl px-4 py-3 text-sm text-error">
        {{ loadError }}
      </p>
      <div
        v-else-if="loading"
        class="keys-frame flex items-center gap-2 rounded-xl px-4 py-6 text-sm text-muted"
      >
        <UIcon name="i-lucide-loader-circle" class="size-4 animate-spin" />
        Loading blockchain modules…
      </div>

      <div v-else class="keys-frame overflow-hidden rounded-xl">
        <div class="flex flex-wrap items-center justify-between gap-3 border-b border-muted px-5 py-3">
          <p class="font-mono text-xs text-muted">
            private key
            <span class="keys-azure ms-2 text-sm tabular-nums" :title="current.decimal.toString()">
              {{ shortDecimal(current.decimal) }}
            </span>
          </p>
          <p class="font-mono text-xs text-dimmed">secp256k1 · 1 … n − 1</p>
        </div>

        <div class="grid gap-3 border-b border-muted p-5 md:grid-cols-[minmax(0,2fr)_minmax(0,3fr)]">
          <label class="flex flex-col gap-1 text-sm">
            <span class="font-mono text-xs text-muted">decimal</span>
            <input
              v-model="decimalInput"
              class="keys-field font-mono"
              spellcheck="false"
              autocomplete="off"
              inputmode="numeric"
              @change="onDecimal"
              @keydown.enter="onDecimal"
            >
          </label>
          <label class="flex flex-col gap-1 text-sm">
            <span class="font-mono text-xs text-muted">hex</span>
            <input
              v-model="hexInput"
              class="keys-field font-mono"
              spellcheck="false"
              autocomplete="off"
              @change="onHex"
              @keydown.enter="onHex"
            >
          </label>
          <p v-if="error" class="text-sm text-error md:col-span-2">
            {{ error }}
          </p>
        </div>

        <ol v-if="derivation" class="keys-pipeline">
          <li class="keys-step">
            <div class="keys-step-head">
              <span class="keys-step-index">1</span>
              <span class="keys-step-title">32-byte secret</span>
              <span class="keys-step-note">the scalar, big-endian</span>
            </div>
            <div class="keys-bytes">
              <span
                v-for="(byte, index) in bytes"
                :key="`${index}-${byte.value}`"
                class="keys-byte"
                :class="{ 'keys-byte-dim': byte.dim, 'keys-byte-hot': byte.hot }"
              >{{ byte.value }}</span>
            </div>
          </li>

          <li class="keys-step">
            <div class="keys-step-head">
              <span class="keys-step-index">2</span>
              <span class="keys-step-title">public keys</span>
              <span class="keys-step-note">k · G on secp256k1; the same bytes as an ed25519 seed</span>
            </div>
            <dl class="keys-formats">
              <div v-for="key in publicKeys" :key="key.id" class="keys-format keys-format-wide">
                <dt class="keys-format-label">
                  <span class="font-mono text-xs text-highlighted">{{ key.label }}</span>
                  <span v-if="key.hint" class="font-mono text-[10px] text-dimmed">{{ key.hint }}</span>
                </dt>
                <dd class="flex min-w-0 items-start gap-2">
                  <LandingAddress :address="key.value" class="keys-step-value min-w-0 flex-1" />
                  <button
                    type="button"
                    class="keys-copy"
                    :data-copied="copied === key.id"
                    :aria-label="`Copy ${key.label}`"
                    @click="copy(key.id, key.value)"
                  >
                    <UIcon :name="copied === key.id ? 'i-lucide-check' : 'i-lucide-copy'" class="size-3.5" />
                  </button>
                </dd>
              </div>
            </dl>
          </li>

          <li class="keys-step">
            <div class="keys-step-head">
              <span class="keys-step-index">3</span>
              <span class="keys-step-title">addresses</span>
              <span class="keys-step-note">hash, then encode, per chain</span>
            </div>
            <div class="keys-table-wrap -ms-13 -me-5 -mb-4.5">
              <table class="keys-table">
                <thead>
                  <tr>
                    <th class="ps-13!">Chain</th>
                    <th>Curve</th>
                    <th>Format</th>
                    <th>Address</th>
                    <th class="w-px"><span class="sr-only">Copy</span></th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="row in derivation.addresses" :key="row.id">
                    <td class="ps-13! whitespace-nowrap">{{ row.chain }}</td>
                    <td class="font-mono text-xs text-muted">{{ row.curve }}</td>
                    <td class="font-mono text-xs text-muted">{{ row.format }}</td>
                    <td class="font-mono text-xs break-all"><LandingAddress :address="row.address" /></td>
                    <td>
                      <button
                        type="button"
                        class="keys-copy"
                        :data-copied="copied === row.id"
                        :aria-label="`Copy ${row.chain} ${row.format} address`"
                        @click="copy(row.id, row.address)"
                      >
                        <UIcon :name="copied === row.id ? 'i-lucide-check' : 'i-lucide-copy'" class="size-3.5" />
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </li>
        </ol>

        <div class="flex flex-wrap items-center gap-2 border-t border-muted px-5 py-3">
          <button type="button" class="keys-btn" @click="step(-1n)">
            <UIcon name="i-lucide-chevron-left" class="size-4" />
            Previous
          </button>
          <button type="button" class="keys-btn" @click="step(1n)">
            Next
            <UIcon name="i-lucide-chevron-right" class="size-4" />
          </button>
          <button type="button" class="keys-btn" @click="randomKey">
            <UIcon name="i-lucide-dices" class="size-4" />
            Random
          </button>
          <button
            v-if="derivation"
            type="button"
            class="keys-copy ms-auto"
            :data-copied="copied === 'snippet'"
            aria-label="Copy snippet"
            @click="copy('snippet', snippet)"
          >
            <UIcon :name="copied === 'snippet' ? 'i-lucide-check' : 'i-lucide-copy'" class="size-3.5" />
            <span>{{ copied === 'snippet' ? "copied" : "copy as code" }}</span>
          </button>
        </div>
      </div>
    </div>
    <template #fallback>
      <p class="text-sm text-muted">Loading explorer…</p>
    </template>
  </ClientOnly>
</template>
