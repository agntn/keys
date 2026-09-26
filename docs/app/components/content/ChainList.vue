<script setup lang="ts">
import type { TableColumn } from "@nuxt/ui";
import { CHAINS, type ChainEntry } from "../../utils/chains";
import { ROSTER_CLASS, ROSTER_TABLE_UI } from "../../utils/roster";

/** Empty until a header is clicked: the rows then keep the order the landing numbers them in. */
const sorting = ref<{ id: string; desc: boolean }[]>([]);

const roster = useTemplateRef<HTMLElement>("roster");
useRosterFlip(
  () => roster.value,
  () => sorting.value,
);

const columns: TableColumn<ChainEntry>[] = [
  {
    accessorKey: "label",
    header: "Chain",
    sortingFn: "text",
    meta: { class: { th: "w-[11rem]" } },
  },
  { accessorKey: "driver", header: "Key", meta: { class: { th: "w-[9.5rem]" } } },
  { accessorKey: "blurb", header: "About", enableSorting: false },
  { accessorKey: "curve", header: "Curve", sortingFn: "text", meta: { class: { th: "w-[13rem]" } } },
];

const order = computed(() => {
  const [first] = sorting.value;
  if (first === undefined) return "registry order";
  const label = columns.find(
    (column) => "accessorKey" in column && column.accessorKey === first.id,
  )?.header;
  return `by ${String(label).toLowerCase()} ${first.desc ? "descending" : "ascending"}`;
});

/**
 * The blurb split at backticks, so code reads as code without `v-html`.
 *
 * @param {string} text - The blurb.
 * @returns {{ text: string; code: boolean }[]} Plain and code segments in order.
 */
function segments(text: string): { text: string; code: boolean }[] {
  return text.split("`").map((part, index) => ({ text: part, code: index % 2 === 1 }));
}
</script>

<template>
  <section ref="roster" class="roster not-prose my-6" aria-label="Blockchains">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>
    <header :class="ROSTER_CLASS.bar">
      <span :class="ROSTER_CLASS.title">blockchains</span>
      <span :class="ROSTER_CLASS.meta">{{ CHAINS.length }} drivers · {{ order }}</span>
    </header>
    <div class="roster-ruler" aria-hidden="true" />
    <UTable
      v-model:sorting="sorting"
      :data="[...CHAINS]"
      :columns="columns"
      :get-row-id="(row) => row.driver"
      :ui="ROSTER_TABLE_UI"
    >
      <template #label-header="{ column }"><RosterSort :column="column" label="Chain" /></template>
      <template #driver-header="{ column }"><RosterSort :column="column" label="Key" /></template>
      <template #curve-header="{ column }"><RosterSort :column="column" label="Curve" /></template>
      <template #label-cell="{ row }">
        <NuxtLink :to="row.original.to" :class="[ROSTER_CLASS.name, 'items-baseline']">
          <UIcon
            :name="row.original.icon"
            class="relative top-0.5 size-3.5 flex-none"
            aria-hidden="true"
          />
          <span>{{ row.original.label }}</span>
        </NuxtLink>
      </template>
      <template #driver-cell="{ row }">
        <span :class="ROSTER_CLASS.id">{{ row.original.driver }}</span>
      </template>
      <template #blurb-cell="{ row }">
        <span :class="ROSTER_CLASS.about"
          ><template v-for="(part, index) in segments(row.original.blurb)" :key="index"
            ><code v-if="part.code" class="keys-code">{{ part.text }}</code
            ><template v-else>{{ part.text }}</template></template
          ></span
        >
      </template>
      <template #curve-cell="{ row }">
        <span :class="ROSTER_CLASS.count"
          ><span :class="ROSTER_CLASS.leader" aria-hidden="true" /><span
            class="whitespace-nowrap text-muted"
            >{{ row.original.curve }}</span
          ></span
        >
      </template>
    </UTable>
    <footer :class="ROSTER_CLASS.footer">
      <span>one class shape / no network</span>
      <span :class="ROSTER_CLASS.meta">blockchains.&lt;key&gt;()() loads one</span>
    </footer>
  </section>
</template>

<style scoped>
/* Code in a 13 px blurb stays a step smaller than the text around it, like a tag. */
.keys-code {
  font-size: 11.5px;
}
</style>
