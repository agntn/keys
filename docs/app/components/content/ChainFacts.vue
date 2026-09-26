<script setup lang="ts">
import { CHAINS, chainEntry } from "../../utils/chains";
import { landingStaticRows } from "../../utils/landing";

const props = defineProps<{
  driver: string;
  curve: string;
  formats: string;
  coin: string | number;
}>();

const entry = computed(() => chainEntry(props.driver));
const position = computed(() => CHAINS.findIndex((chain) => chain.driver === props.driver) + 1);
const formats = computed(() => props.formats.split(", "));
const curves = computed(() => props.curve.split(", "));

/** The address private key 1 gets on this chain, from the same fixture the landing prints and the tests derive. */
const keyOne = computed(() => landingStaticRows.find((row) => row.id === entry.value?.row));

/**
 * `bc1qw508d6…v8f3t4`: long enough to recognise, short enough for one line of the readout.
 *
 * @param {string} address - The full address.
 * @returns {string} The address with its middle elided.
 */
function short(address: string): string {
  return address.length > 20 ? `${address.slice(0, 10)}…${address.slice(-6)}` : address;
}
</script>

<template>
  <section class="tool-console console-wide not-prose my-6" aria-label="Chain record">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>

    <header class="console-bar">
      <span class="console-title"
        ><span class="console-tag">ID</span>{{ driver
        }}<span v-if="position > 0" class="console-file"
          >{{ String(position).padStart(2, "0") }} / {{ CHAINS.length }}</span
        ></span
      >
      <span class="console-meta">SLIP-44 {{ coin }}'</span>
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true"><span class="console-cursor" /></div>

    <div class="console-band console-subject-band">
      <div class="console-scan" aria-hidden="true" />
      <div class="console-identity-block">
        <ConsoleReticle :key="driver" :icon="entry?.icon ?? 'i-lucide-circle-help'" />
        <div class="console-name">
          <span class="console-label">Chain</span>
          <h3>{{ entry?.label ?? driver }}</h3>
          <p class="console-aliases">
            <span v-for="name in curves" :key="name" class="console-chain">{{ name }}</span>
          </p>
          <ul class="chain-formats" aria-label="Address formats">
            <li v-for="format in formats" :key="format">{{ format }}</li>
          </ul>
        </div>
      </div>

      <div class="console-readout">
        <svg class="console-link" viewBox="0 0 32 40" fill="none" aria-hidden="true">
          <circle cx="3" cy="12" r="2.5" />
          <path d="M5.5 12H14L22 20H32" />
        </svg>
        <dl class="console-readout-rows">
          <div>
            <dt>Formats</dt>
            <dd>{{ formats.length }}</dd>
          </div>
          <div>
            <dt>Coin type</dt>
            <dd>{{ coin }}'</dd>
          </div>
          <div v-if="keyOne">
            <dt>Key 1</dt>
            <dd class="console-accent">
              <UTooltip :text="`${keyOne.format} · ${keyOne.address}`">
                <span class="chain-address">{{ short(keyOne.address) }}</span>
              </UTooltip>
            </dd>
          </div>
        </dl>
      </div>
    </div>

    <div class="console-band">
      <p class="console-label console-rule-title">
        <span>Access <span aria-hidden="true">[ library · browser ]</span></span>
        <span class="console-mark" aria-hidden="true" />
      </p>
      <dl class="chain-access">
        <dd class="console-lead">
          <span class="console-tag">Load</span>
          <code class="chain-code"
            >blockchains.<span class="tok-fn">{{ driver }}</span>()()</code
          >
          <span class="console-leader" aria-hidden="true" />
        </dd>
        <dd class="console-lead">
          <span class="console-tag">Import</span>
          <code class="chain-code"
            ><span class="tok-str">@agntn/keys/blockchains/{{ driver }}</span></code
          >
          <span class="console-leader" aria-hidden="true" />
        </dd>
        <dd class="console-lead">
          <span class="console-tag">Walk</span>
          <NuxtLink to="/keyspace"
            >keyspace<span class="chain-dim"> in the browser</span></NuxtLink
          >
          <span class="console-leader" aria-hidden="true" />
        </dd>
      </dl>
    </div>

    <footer class="console-footer console-footer-plain">
      <ul class="console-links">
        <li>
          <NuxtLink to="/blockchains"><span aria-hidden="true">→ </span>All blockchains</NuxtLink>
        </li>
      </ul>
      <span class="console-meta">derived locally / no network</span>
    </footer>
  </section>
</template>

<style scoped>
.chain-address {
  white-space: nowrap;
}
.chain-formats {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.chain-formats > li {
  padding: 1px 7px;
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  color: var(--ui-text-highlighted);
  box-shadow: inset 0 0 0 1px var(--console-line);
}
.chain-code {
  font: inherit;
  color: var(--ui-text-highlighted);
}
.chain-dim {
  color: var(--ui-text-dimmed);
}
.console-lead > a:hover .chain-dim {
  color: inherit;
}
.chain-access {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(min(100%, 22rem), 1fr));
  gap: 0 28px;
  margin: 0;
}
.chain-access > .console-lead {
  margin: 0 0 8px;
  flex-wrap: nowrap;
}
@media (width < 640px) {
  .chain-access .console-leader {
    display: none;
  }
}
</style>
