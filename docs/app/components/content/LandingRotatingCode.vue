<script setup lang="ts">
import { CHAINS } from "../../utils/chains";
import type { AddressRow } from "../../utils/derive";
import { shortDecimal } from "../../utils/format";
import { tokens } from "../../utils/tokens";

const props = defineProps<{ rows: readonly AddressRow[]; tick: number; decimal: bigint }>();

const { copied, copy } = useCopied();

/** The walk steps through the drivers in registry order, one per key. */
const chain = computed(() => CHAINS[props.tick % CHAINS.length]!);
const address = computed(
  () => props.rows.find((row) => row.id === chain.value.row)?.address ?? "",
);

/** Every chain gets the same seven lines, so the file keeps one height while the driver changes. */
const lines = computed(() => [
  'import { useBlockchain, blockchains } from "@agntn/keys";',
  "",
  `const chain = useBlockchain(await blockchains.${chain.value.driver}()());`,
  "const wallet = chain.generateWallet();",
  'const signature = chain.signMessage("hello", wallet.private);',
  "",
  `// key ${shortDecimal(props.decimal, 6)} on ${chain.value.label}: ${address.value}`,
]);
</script>

<template>
  <section class="tool-console landing-file" aria-label="The same calls on every chain">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>
    <header class="console-bar">
      <span class="console-title file-name"
        ><span class="console-tag">File</span
        ><Transition name="keys-roll" mode="out-in"
          ><span :key="chain.driver" class="keys-roll-slot">{{ chain.driver }}.ts</span></Transition
        ></span
      >
      <span class="console-meta">same shape · {{ CHAINS.length }} drivers</span>
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true"><span :key="chain.driver" class="console-cursor" /></div>

    <div class="file-body">
      <p class="console-label console-rule-title">
        <span>Driver <span aria-hidden="true">[ swap the import ]</span></span>
        <span class="console-mark" aria-hidden="true" />
        <button
          type="button"
          class="console-button"
          :aria-label="copied === 'file' ? 'Copied' : 'Copy the file'"
          :data-copied="copied === 'file'"
          @click="copy('file', lines.join('\n'))"
        >
          <UIcon
            :name="copied === 'file' ? 'i-lucide-check' : 'i-lucide-copy'"
            class="size-3"
            aria-hidden="true"
          />
          {{ copied === "file" ? "copied" : "copy" }}
        </button>
      </p>
      <!-- prettier-ignore -->
      <pre class="console-snippet console-lines file-lines"><code><span v-for="(line, index) in lines" :key="index"><span v-for="(token, part) in tokens(line)" :key="part" :class="token.cls">{{ token.text }}</span></span></code></pre>
    </div>

    <footer class="console-footer console-footer-plain">
      <NuxtLink :to="chain.to" class="file-link"
        ><span aria-hidden="true">→ </span>{{ chain.label }}<span> · {{ chain.curve }}</span></NuxtLink
      >
      <span class="console-meta">lazy import / no network</span>
    </footer>
  </section>
</template>

<style scoped>
.file-name {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.file-name :deep(.keys-roll-slot) {
  display: inline;
}
.file-body {
  padding: 14px 20px 16px;
}
.file-body > .console-rule-title {
  margin-bottom: 10px;
}
/* One line per code line whatever the chain: long addresses end in an ellipsis, copy hands out the whole line. */
.file-lines > code > span {
  overflow: hidden;
  padding-left: calc(2.25em + 1em);
  text-indent: 0;
  text-overflow: ellipsis;
  white-space: pre;
}
.file-lines > code > span::before {
  margin-left: calc(-2.25em - 1em);
}
.file-lines > code > span :deep(*) {
  white-space: pre;
  overflow-wrap: normal;
}
.file-link {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ui-text-highlighted);
}
.file-link > span:last-child {
  color: var(--ui-text-dimmed);
}
.file-link:hover {
  color: var(--console-accent);
}
.file-link:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 3px;
}
@media (width < 640px) {
  .file-body > .console-rule-title > .console-mark {
    display: none;
  }
}
@media (width < 400px) {
  .file-body {
    padding-inline: 14px;
  }
  .file-body > .console-rule-title > span:first-child > span {
    display: none;
  }
}
</style>
