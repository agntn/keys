<script setup lang="ts">
import type { Pipeline } from "../../composables/useLandingKey";
import { shortDecimal } from "../../utils/format";

const props = defineProps<{
  hex: string;
  decimal: bigint;
  pipeline: Pipeline;
  changedBytes: ReadonlySet<number>;
}>();

const emit = defineEmits<{
  step: [delta: bigint];
  random: [];
  pause: [value: boolean];
}>();

const bytes = computed(() => {
  const firstSignificant = props.hex.search(/[^0]/u);
  const list: { value: string; dim: boolean; hot: boolean }[] = [];
  for (let index = 0; index < 32; index += 1) {
    list.push({
      value: props.hex.slice(index * 2, index * 2 + 2),
      dim: firstSignificant === -1 ? index < 31 : index * 2 + 1 < firstSignificant,
      hot: props.changedBytes.has(index),
    });
  }
  return list;
});

const formats = computed(() => [
  { id: "legacy", label: "legacy", note: "P2PKH · base58check", value: props.pipeline.legacy },
  { id: "segwit", label: "segwit", note: "P2WPKH · bech32", value: props.pipeline.segwit },
  { id: "taproot", label: "taproot", note: "P2TR · bech32m", value: props.pipeline.taproot },
]);
</script>

<template>
  <div
    class="keys-frame overflow-hidden rounded-xl"
    @mouseenter="emit('pause', true)"
    @mouseleave="emit('pause', false)"
  >
    <div class="flex items-center justify-between gap-3 border-b border-muted px-5 py-3">
      <p class="font-mono text-xs text-muted">
        private key
        <span class="keys-azure ms-2 text-sm tabular-nums" :title="decimal.toString()">{{ shortDecimal(decimal) }}</span>
      </p>
      <p class="font-mono text-xs text-dimmed">Bitcoin · secp256k1</p>
    </div>

    <ol class="keys-pipeline">
      <li class="keys-step">
        <div class="keys-step-head">
          <span class="keys-step-index">1</span>
          <span class="keys-step-title">32-byte secret</span>
          <span class="keys-step-note">integer in 1 … n − 1</span>
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
          <span class="keys-step-title">public key</span>
          <span class="keys-step-note">k · G, compressed, 33 bytes</span>
        </div>
        <LandingAddress :address="pipeline.publicKey" class="keys-step-value" />
      </li>

      <li class="keys-step">
        <div class="keys-step-head">
          <span class="keys-step-index">3</span>
          <span class="keys-step-title">address</span>
          <span class="keys-step-note">hash, then encode</span>
        </div>
        <ul class="keys-formats">
          <li v-for="format in formats" :key="format.id" class="keys-format">
            <span class="keys-format-label">
              <span class="font-mono text-xs text-highlighted">{{ format.label }}</span>
              <span class="font-mono text-[10px] text-dimmed">{{ format.note }}</span>
            </span>
            <LandingAddress :address="format.value" class="keys-step-value" />
          </li>
        </ul>
      </li>
    </ol>

    <div class="flex flex-wrap items-center gap-2 border-t border-muted px-5 py-3">
      <button type="button" class="keys-btn" @click="emit('step', -1n)">
        <UIcon name="i-lucide-chevron-left" class="size-4" />
        Previous
      </button>
      <button type="button" class="keys-btn" @click="emit('step', 1n)">
        Next
        <UIcon name="i-lucide-chevron-right" class="size-4" />
      </button>
      <button type="button" class="keys-btn" @click="emit('random')">
        <UIcon name="i-lucide-dices" class="size-4" />
        Random
      </button>
      <NuxtLink
        :to="`/keyspace#${hex.replace(/^0+/u, '') || '0'}`"
        class="ms-auto inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
      >
        all chains in the explorer
        <UIcon name="i-lucide-arrow-up-right" class="size-3.5" />
      </NuxtLink>
    </div>
  </div>
</template>
