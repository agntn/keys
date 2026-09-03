<script setup lang="ts">
const props = defineProps<{
  driver: string;
  curve: string;
  formats: string;
  coin: string | number;
}>();

const facts = computed(() => [
  { label: "driver", value: props.driver, mono: true },
  { label: "curve", value: props.curve, mono: true },
  { label: "address formats", value: props.formats, mono: false },
  { label: "SLIP-44 coin", value: `${props.coin}'`, mono: true },
]);
</script>

<template>
  <dl class="keys-frame not-prose my-6 grid grid-cols-2 overflow-hidden rounded-xl sm:grid-cols-4">
    <div
      v-for="(fact, index) in facts"
      :key="fact.label"
      class="border-muted px-4 py-3.5"
      :class="{ 'border-t sm:border-t-0': index >= 2, 'border-l': index % 2 === 1, 'sm:border-l': index > 0 }"
    >
      <dt class="font-mono text-[10px] tracking-[0.12em] text-dimmed uppercase">{{ fact.label }}</dt>
      <dd class="mt-1 text-sm text-highlighted" :class="{ 'font-mono text-[13px]': fact.mono }">{{ fact.value }}</dd>
    </div>
  </dl>
</template>
