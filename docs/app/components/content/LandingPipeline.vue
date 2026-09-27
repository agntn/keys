<script setup lang="ts">
import type { Pipeline } from "../../utils/landing";
import { shortDecimal } from "../../utils/format";

const props = defineProps<{
  hex: string;
  decimal: bigint;
  pipeline: Pipeline;
  changedBytes: ReadonlySet<number>;
  ready: boolean;
}>();

const emit = defineEmits<{
  step: [delta: bigint];
  random: [];
}>();

/** The scalar as 32 bytes: leading zero bytes dimmed, the ones the last step changed lit. */
const bytes = computed(() => {
  const firstSignificant = props.hex.search(/[^0]/u);
  return Array.from({ length: 32 }, (_, index) => ({
    value: props.hex.slice(index * 2, index * 2 + 2),
    dim: firstSignificant === -1 ? index < 31 : index * 2 + 1 < firstSignificant,
    hot: props.changedBytes.has(index),
  }));
});

/** The three steps after the secret: the point, then the hash encoded three ways. One line each. */
const readout = computed(() => [
  { id: "Public key", note: "k · G, compressed, 33 bytes", value: props.pipeline.publicKey },
  { id: "Legacy", note: "P2PKH · base58check", value: props.pipeline.legacy, accent: true },
  { id: "Segwit", note: "P2WPKH · bech32", value: props.pipeline.segwit },
  { id: "Taproot", note: "P2TR · bech32m", value: props.pipeline.taproot },
]);
</script>

<template>
  <section class="tool-console landing-pipeline" aria-label="From private key to Bitcoin address">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>
    <header class="console-bar">
      <span class="console-title"
        ><span class="console-tag">Call</span>bitcoin.<span class="tok-fn">getAddress</span
        >(k · G)</span
      >
      <span class="console-meta">k = {{ shortDecimal(decimal, 6) }}</span>
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true"><span :key="hex" class="console-cursor" /></div>

    <div class="pipeline-band">
      <p class="key-bytes" :aria-label="`Private key ${hex}`">
        <span
          v-for="(byte, index) in bytes"
          :key="`${index}-${byte.value}`"
          :class="{ 'key-byte-dim': byte.dim, 'key-byte-hot': byte.hot }"
          >{{ byte.value }}</span
        >
      </p>
      <div class="console-readout pipeline-readout">
        <dl class="console-readout-rows">
          <div v-for="row in readout" :key="row.id">
            <dt>{{ row.id }}</dt>
            <dd :class="{ 'console-accent': row.accent }">
              <UTooltip :text="`${row.note} · ${row.value}`"
                ><span tabindex="0" class="pipeline-value"
                  ><LandingAddress :address="row.value" /></span
              ></UTooltip>
            </dd>
          </div>
        </dl>
      </div>
    </div>

    <footer class="console-footer console-footer-plain">
      <span>Bitcoin · secp256k1 / in this tab</span>
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
/* The secret on top, the point and the addresses in one readout under it: the panel stays as tall as the copy beside it. */
.pipeline-band {
  display: grid;
  gap: 12px;
  padding: 12px 20px 14px;
}
.pipeline-readout .console-readout-rows > div {
  grid-template-columns: 6.5rem minmax(0, 1fr);
  padding-block: 6px;
}
.pipeline-value {
  display: block;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.pipeline-value:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 2px;
}
.landing-pipeline .console-controls button:disabled {
  cursor: default;
  opacity: 0.5;
}
@media (width < 640px) {
  .pipeline-band {
    padding-inline: 14px;
  }
}
</style>
