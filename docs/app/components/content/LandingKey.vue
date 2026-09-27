<script setup lang="ts">
import { CHAINS } from "../../utils/chains";
import type { AddressRow } from "../../utils/derive";
import { shortDecimal } from "../../utils/format";
import type { Pipeline } from "../../utils/landing";

const props = defineProps<{
  hex: string;
  decimal: bigint;
  rows: readonly AddressRow[];
  pipeline: Pipeline;
  tick: number;
  ready: boolean;
}>();
const emit = defineEmits<{ step: [delta: bigint]; random: [] }>();

/** The leading zero bytes of the scalar, dimmed so the significant part reads first. */
const hexParts = computed(() => {
  const significant = props.hex.search(/[^0]/u);
  const cut = significant === -1 ? props.hex.length - 1 : significant - (significant % 2);
  return { zeros: props.hex.slice(0, cut), rest: props.hex.slice(cut) };
});

/** One cell per chain, in registry order, with the address this key gets there. */
const cells = computed(() =>
  CHAINS.map((chain) => {
    const row = props.rows.find((candidate) => candidate.id === chain.row);
    return { ...chain, format: row?.format ?? "", address: row?.address ?? "" };
  }),
);

/** The cell the walk points at, one step per key. */
const active = computed(() => props.tick % CHAINS.length);

const publicShort = computed(
  () => `${props.pipeline.publicKey.slice(0, 10)}…${props.pipeline.publicKey.slice(-8)}`,
);
const keyspaceLink = computed(() => `/keyspace#${props.hex.replace(/^0+/u, "") || "0"}`);
</script>

<template>
  <section class="tool-console console-wide landing-key" aria-label="One private key on every chain">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>

    <header class="console-bar">
      <span class="console-title"
        ><span class="console-tag">Call</span>chain.<span class="tok-fn">getAddress</span>(k ·
        G)</span
      >
      <span class="console-meta">{{ CHAINS.length }} chains · 2 curves</span>
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true">
      <span :key="hex" class="console-cursor" :class="{ 'console-cursor-busy': !ready }" />
    </div>

    <div class="console-band console-subject-band">
      <div :key="hex" class="console-scan" aria-hidden="true" />
      <div class="console-identity-block">
        <ConsoleReticle :key="hex" icon="i-lucide-key-round" />
        <div class="console-name">
          <span class="console-label">Private key</span>
          <h3 class="key-decimal">
            <UTooltip :text="decimal.toString()"
              ><span tabindex="0">{{ shortDecimal(decimal) }}</span></UTooltip
            >
          </h3>
          <p class="key-hex">
            <span class="key-hex-zeros">{{ hexParts.zeros }}</span>{{ hexParts.rest }}
          </p>
        </div>
      </div>

      <div class="console-readout">
        <svg class="console-link" viewBox="0 0 32 40" fill="none" aria-hidden="true">
          <circle cx="3" cy="12" r="2.5" />
          <path d="M5.5 12H14L22 20H32" />
        </svg>
        <dl class="console-readout-rows">
          <div>
            <dt>Public key</dt>
            <dd>
              <UTooltip :text="pipeline.publicKey"
                ><span tabindex="0" class="key-nowrap">{{ publicShort }}</span></UTooltip
              >
            </dd>
          </div>
          <div>
            <dt>Range</dt>
            <dd>1 … n − 1</dd>
          </div>
          <div>
            <dt>Addresses</dt>
            <dd class="console-accent">{{ CHAINS.length }} from one key</dd>
          </div>
        </dl>
      </div>
    </div>

    <div class="console-band">
      <p class="console-label console-rule-title">
        <span>Addresses <span aria-hidden="true">[ one key · every chain ]</span></span>
        <span class="console-mark" aria-hidden="true" />
      </p>
      <ul class="key-cells">
        <li v-for="(cell, index) in cells" :key="cell.driver">
          <NuxtLink
            :to="cell.to"
            class="key-cell"
            :data-active="index === active || undefined"
            :aria-label="`${cell.label}, ${cell.format}: ${cell.address}`"
          >
            <UIcon :name="cell.icon" class="key-cell-icon" aria-hidden="true" />
            <span class="key-cell-name">{{ cell.label }}</span>
            <span class="key-cell-format">{{ cell.format }}</span>
            <span class="key-cell-node" aria-hidden="true" />
            <LandingAddress :address="cell.address" class="key-cell-address" />
          </NuxtLink>
        </li>
      </ul>
    </div>

    <footer class="console-footer console-footer-plain">
      <NuxtLink :to="keyspaceLink" class="key-link"
        ><span aria-hidden="true">→ </span>this key in the keyspace</NuxtLink
      >
      <div class="console-controls" aria-label="Private keys">
        <button type="button" aria-label="Previous key" :disabled="!ready" @click="emit('step', -1n)">
          <UIcon name="i-lucide-chevron-left" />
        </button>
        <span>Key</span>
        <button type="button" aria-label="Next key" :disabled="!ready" @click="emit('step', 1n)">
          <UIcon name="i-lucide-chevron-right" />
        </button>
        <button type="button" aria-label="Random key" :disabled="!ready" @click="emit('random')">
          <UIcon name="i-lucide-dices" />
        </button>
      </div>
    </footer>
  </section>
</template>

<style scoped>
.key-decimal {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  overflow-wrap: anywhere;
}
.key-decimal span:focus-visible,
.key-nowrap:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 2px;
}
.key-hex {
  margin: 0;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  letter-spacing: 0.02em;
  color: var(--ui-text-highlighted);
  overflow-wrap: anywhere;
}
.key-hex-zeros {
  color: var(--ui-text-dimmed);
}
.key-nowrap {
  white-space: nowrap;
}
/* The addresses as a manifest: one cell per chain, the state on the node, not in a word. */
.key-cells {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(min(100%, 15.5rem), 1fr));
  gap: 0 20px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.key-cell {
  display: grid;
  grid-template-columns: 16px minmax(0, 1fr) auto 5px;
  align-items: center;
  gap: 2px 8px;
  padding: 7px 0;
  box-shadow: inset 0 -1px 0 var(--console-line);
  font-family: var(--font-mono);
  font-size: 12px;
}
.key-cell-icon {
  width: 14px;
  height: 14px;
  color: var(--ui-text-muted);
}
.key-cell-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-highlighted);
}
.key-cell-format {
  font-size: 10px;
  letter-spacing: 0.04em;
  color: var(--ui-text-dimmed);
}
.key-cell-node {
  width: 5px;
  height: 5px;
  box-shadow: inset 0 0 0 1px var(--console-corner);
}
.key-cell-address {
  grid-column: 2 / -1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 11px;
  color: var(--ui-text-muted);
}
.key-cell:hover .key-cell-name,
.key-cell:hover .key-cell-icon {
  color: var(--console-accent);
}
.key-cell[data-active] .key-cell-icon,
.key-cell[data-active] .key-cell-address {
  color: var(--console-accent);
}
.key-cell[data-active] .key-cell-node {
  background: var(--console-accent);
  box-shadow: none;
}
.key-cell:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 2px;
}
.key-link {
  color: var(--ui-text-highlighted);
}
.key-link:hover {
  color: var(--console-accent);
}
.key-link:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 3px;
}
.landing-key .console-controls button:disabled {
  cursor: default;
  opacity: 0.5;
}
</style>
