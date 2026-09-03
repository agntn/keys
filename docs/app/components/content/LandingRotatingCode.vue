<script setup lang="ts">
import type { AddressRow } from "../../utils/derive";
import { shortDecimal } from "../../utils/format";

const props = defineProps<{ rows: readonly AddressRow[]; tick: number; decimal: bigint }>();

const SLUGS: Record<string, string> = {
  Bitcoin: "bitcoin",
  Ethereum: "ethereum",
  Base: "base",
  TRON: "tron",
  Solana: "solana",
  Aptos: "aptos",
  Sui: "sui",
  Cardano: "cardano",
};

const current = computed(() => props.rows[props.tick % props.rows.length] ?? props.rows[0]!);
const slug = computed(() => SLUGS[current.value.chain] ?? "bitcoin");
</script>

<template>
  <div class="keys-frame overflow-hidden rounded-xl">
    <div class="flex items-center gap-2 border-b border-muted px-4 py-3">
      <span class="font-mono text-[10px] font-bold text-primary">TS</span>
      <span class="text-sm text-default">
        <Transition name="keys-roll" mode="out-in">
          <span :key="slug">{{ slug }}.ts</span>
        </Transition>
      </span>
    </div>
    <pre class="keys-rotating"><code><span class="tok-kw">import</span> { useBlockchain, blockchains } <span class="tok-kw">from</span> <span class="tok-str">"@agntn/keys"</span>;

<span class="tok-kw">const</span> chain = <span class="tok-fn">useBlockchain</span>(<span class="tok-kw">await</span> blockchains.<Transition name="keys-roll" mode="out-in"><span :key="slug" class="tok-fn keys-roll-slot">{{ slug }}</span></Transition>()());
<span class="tok-kw">const</span> wallet = chain.<span class="tok-fn">generateWallet</span>();
<span class="tok-kw">const</span> signature = chain.<span class="tok-fn">signMessage</span>(<span class="tok-str">"hello"</span>, wallet.private);

<span class="tok-cm">// address of private key {{ shortDecimal(decimal) }} on this chain</span>
<span class="tok-cm">// <LandingAddress :address="current.address" /></span></code></pre>
  </div>
</template>
