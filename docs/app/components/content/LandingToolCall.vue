<script setup lang="ts">
import { chainEntry } from "../../utils/chains";
import type { AddressRow } from "../../utils/derive";

const props = defineProps<{ rows: readonly AddressRow[]; publicKey: string; tick: number }>();

/**
 * The secp256k1 drivers, since the walked public key is a secp256k1 point. `row` is the derive.ts
 * row that answers the request, so the result and the address type agree.
 */
const SECP = [
  { row: "btc-segwit", chain: "bitcoin", addressType: "segwit" },
  { row: "bch", chain: "bitcoincash" },
  { row: "btg-segwit", chain: "bitcoingold", addressType: "segwit" },
  { row: "bsv", chain: "bitcoinsv" },
  { row: "ltc-segwit", chain: "litecoin", addressType: "segwit" },
  { row: "dash", chain: "dash" },
  { row: "dcr", chain: "decred" },
  { row: "doge", chain: "dogecoin" },
  { row: "zec", chain: "zcash" },
  { row: "xec", chain: "ecash" },
  { row: "eth", chain: "ethereum" },
  { row: "base", chain: "base" },
  { row: "tron", chain: "tron" },
] as const;

const current = computed(() => SECP[props.tick % SECP.length]!);
const entry = computed(() => chainEntry(current.value.chain));
const address = computed(
  () => props.rows.find((row) => row.id === current.value.row)?.address ?? "",
);
</script>

<template>
  <div class="tool-console landing-call">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>
    <header class="console-bar">
      <!-- prettier-ignore -->
      <span class="console-title call-title"
        ><span class="console-tag">Call</span
        ><span class="call-text">keys_get_address(<span class="tok-str">"{{ current.chain }}"</span>)</span></span
      >
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true">
      <span :key="current.chain" class="console-cursor" />
    </div>

    <!-- The chain it asked for on the crosses grid; the arguments, then the answer, in the readout. -->
    <div class="call-subject">
      <div :key="current.chain" class="console-scan" aria-hidden="true" />
      <div class="call-identity">
        <ConsoleReticle :key="current.chain" :icon="entry?.icon ?? 'i-lucide-link'" />
        <div class="call-name">
          <span class="console-label">Address / mainnet</span>
          <h3>{{ entry?.label ?? current.chain }}</h3>
          <p class="call-aliases">
            <span>{{ entry?.curve }}</span>
          </p>
        </div>
      </div>
      <div class="console-readout call-readout">
        <dl class="console-readout-rows">
          <div>
            <dt>Public key</dt>
            <dd class="call-dim">
              <UTooltip :text="publicKey"
                ><span tabindex="0" class="call-line">{{ publicKey }}</span></UTooltip
              >
            </dd>
          </div>
          <div>
            <dt>Type</dt>
            <dd :class="{ 'call-dim': !('addressType' in current) }">
              {{ "addressType" in current ? current.addressType : "default" }}
            </dd>
          </div>
          <div>
            <dt>Address</dt>
            <dd class="console-accent">
              <UTooltip :text="address"
                ><span tabindex="0" class="call-line"><LandingAddress :address="address" /></span
              ></UTooltip>
            </dd>
          </div>
        </dl>
      </div>
    </div>

    <footer class="console-footer console-footer-plain">
      <span aria-label="Supported hosts: MCP, Pi and OMP, no network"
        >MCP · Pi · OMP / no network</span
      >
      <span class="console-meta">keys mcp · stdio</span>
    </footer>
  </div>
</template>

<style scoped>
.call-title {
  display: flex;
  align-items: center;
  min-width: 0;
  white-space: nowrap;
}
.call-text {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
}
.call-subject {
  position: relative;
  display: grid;
  gap: 16px;
  padding: 18px 20px 20px;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='36' height='36'%3E%3Cpath d='M16 18h4m-2-2v4' fill='none' stroke='%23818a94' stroke-opacity='.1'/%3E%3C/svg%3E");
  background-size: 36px 36px;
  background-position: 24px 20px;
}
.call-subject > :not(.console-scan) {
  position: relative;
}
.call-identity {
  display: grid;
  grid-template-columns: 76px minmax(0, 1fr);
  gap: 16px;
  align-items: center;
}
.call-name {
  min-width: 0;
}
.call-name h3 {
  margin: 4px 0 6px;
  font-family: var(--font-sans);
  font-size: 22px;
  font-weight: 500;
  line-height: 1.25;
  color: var(--ui-text-highlighted);
}
.call-aliases {
  margin: 0;
  font-size: 11px;
  letter-spacing: 0.06em;
  text-transform: uppercase;
  color: var(--ui-text-muted);
}
.call-readout .console-readout-rows > div {
  grid-template-columns: 6.5rem minmax(0, 1fr);
  padding: 8px 12px;
}
.call-line {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.call-line:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 2px;
}
.call-dim {
  color: var(--ui-text-dimmed) !important;
}
@media (width < 400px) {
  .call-subject {
    padding-inline: 14px;
  }
  .call-identity {
    grid-template-columns: 64px minmax(0, 1fr);
    gap: 12px;
  }
}
</style>
