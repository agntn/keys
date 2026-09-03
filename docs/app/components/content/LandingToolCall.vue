<script setup lang="ts">
import type { AddressRow } from "../../utils/derive";

const props = defineProps<{ rows: readonly AddressRow[]; publicKey: string; tick: number }>();

const SECP = [
  { chain: "Bitcoin", slug: "bitcoin", addressType: "segwit" },
  { chain: "Ethereum", slug: "ethereum" },
  { chain: "Base", slug: "base" },
  { chain: "TRON", slug: "tron" },
] as const;

const current = computed(() => SECP[props.tick % SECP.length]!);
const address = computed(
  () => props.rows.find((row) => row.chain === current.value.chain)?.address ?? "",
);
const shortKey = computed(() => `${props.publicKey.slice(0, 18)}…${props.publicKey.slice(-6)}`);
</script>

<template>
  <div class="keys-frame overflow-hidden rounded-xl">
    <div class="flex items-center justify-between gap-3 border-b border-muted px-4 py-3">
      <p class="font-mono text-xs text-muted">
        <span class="text-dimmed">tool</span>
        <span class="ms-2 text-highlighted">keys_get_address</span>
      </p>
      <p class="font-mono text-[11px] text-dimmed">stdio · keys mcp</p>
    </div>
    <div class="divide-y divide-muted">
      <div class="px-4 py-4">
        <p class="keys-eyebrow mb-3">request</p>
        <pre class="keys-tool"><code>{
  <span class="tok-key">"blockchain"</span>: <span :key="current.slug" class="tok-str keys-derive">"{{ current.slug }}"</span>,
  <span class="tok-key">"publicKey"</span>: <span class="tok-str">"{{ shortKey }}"</span><template v-if="'addressType' in current">,
  <span class="tok-key">"addressType"</span>: <span class="tok-str">"{{ current.addressType }}"</span></template>
}</code></pre>
      </div>
      <div class="px-4 py-4">
        <p class="keys-eyebrow mb-3">result</p>
        <pre class="keys-tool"><code>{
  <span class="tok-key">"chain"</span>: <span :key="current.slug" class="tok-str keys-derive">"{{ current.slug }}"</span>,
  <span class="tok-key">"network"</span>: <span class="tok-str">"mainnet"</span>,
  <span class="tok-key">"address"</span>: <span class="tok-str">"<LandingAddress :address="address" />"</span>
}</code></pre>
      </div>
    </div>
  </div>
</template>
