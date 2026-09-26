<script setup lang="ts">
import { TEST_MNEMONIC, type HdSample } from "../../utils/landing";

const props = defineProps<{ hd: HdSample }>();

/** The BIP44 levels of the walked path; only the index moves. */
const levels = computed(() => [
  { segment: "m", label: "master" },
  { segment: "44'", label: "purpose" },
  { segment: "60'", label: "coin" },
  { segment: "0'", label: "account" },
  { segment: "0", label: "change" },
  { segment: String(props.hd.index), label: "index", live: true },
]);

const words = TEST_MNEMONIC.split(" ");
const mnemonic = `${words[0]} ${words[1]} … ${words.at(-1)}`;
</script>

<template>
  <section class="tool-console landing-path" aria-label="Mnemonic to wallet">
    <span class="console-cross console-cross-tl" aria-hidden="true">+</span>
    <span class="console-cross console-cross-br" aria-hidden="true">+</span>
    <header class="console-bar">
      <span class="console-title path-title"
        ><span class="console-tag">Call</span>ethereum.<span class="tok-fn">deriveHDWallet</span
        >(mnemonic, <span class="tok-str">"{{ hd.path }}"</span>)</span
      >
      <span class="console-mark" aria-hidden="true" />
    </header>
    <div class="console-ruler" aria-hidden="true"><span :key="hd.index" class="console-cursor" /></div>

    <div class="path-band">
      <p class="console-label console-rule-title">
        <span>Path <span aria-hidden="true">[ BIP44 · six levels ]</span></span>
        <span class="console-mark" aria-hidden="true" />
      </p>
      <ol class="path-levels">
        <li v-for="level in levels" :key="level.label" :data-live="level.live || undefined">
          <Transition name="keys-roll" mode="out-in"
            ><span :key="level.segment" class="path-segment">{{ level.segment }}</span></Transition
          >
          <span class="path-label">{{ level.label }}</span>
        </li>
      </ol>
    </div>

    <div class="path-band">
      <div class="console-readout path-readout">
        <dl class="console-readout-rows">
          <div>
            <dt>Mnemonic</dt>
            <dd>
              <UTooltip :text="TEST_MNEMONIC"
                ><span tabindex="0" class="path-words">{{ mnemonic }}</span></UTooltip
              >
            </dd>
          </div>
          <div>
            <dt>Address</dt>
            <dd class="console-accent path-address"><LandingAddress :address="hd.address" /></dd>
          </div>
        </dl>
      </div>
    </div>

    <footer class="console-footer console-footer-plain">
      <span>BIP39 test vector / never a real wallet</span>
      <span class="console-meta">BIP32 · secp256k1</span>
    </footer>
  </section>
</template>

<style scoped>
.path-title {
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.path-band {
  padding: 16px 20px 18px;
}
.path-band + .path-band {
  border-top: 1px solid var(--console-line);
}
.path-band > .console-rule-title {
  margin: 0 0 12px;
}
/* The levels as boxed cells joined by the slash they are written with; the index is the one that moves. */
.path-levels {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
  counter-reset: level;
}
.path-levels > li {
  position: relative;
  display: grid;
  justify-items: center;
  gap: 2px;
  padding: 8px 4px 6px;
  box-shadow: inset 0 0 0 1px var(--console-line);
}
.path-levels > li + li::before {
  content: "/";
  position: absolute;
  top: 8px;
  left: -7px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--ui-text-dimmed);
}
.path-segment {
  font-family: var(--font-mono);
  font-size: 15px;
  color: var(--ui-text-highlighted);
}
.path-label {
  font-family: var(--font-mono);
  font-size: 9px;
  letter-spacing: 0.1em;
  text-transform: uppercase;
  color: var(--ui-text-dimmed);
}
.path-levels > li[data-live] {
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--console-accent) 55%, transparent);
}
.path-levels > li[data-live] .path-segment {
  color: var(--console-accent);
}
.path-readout .console-readout-rows > div {
  grid-template-columns: 6.5rem minmax(0, 1fr);
}
.path-words {
  white-space: nowrap;
}
.path-words:focus-visible {
  outline: 1px solid var(--ui-primary);
  outline-offset: 2px;
}
.path-address {
  overflow-wrap: anywhere;
}
@media (width < 640px) {
  .path-band {
    padding-inline: 14px;
  }
  .path-band > .console-rule-title > span:first-child > span {
    display: none;
  }
  .path-words {
    white-space: normal;
  }
  .path-levels {
    grid-template-columns: repeat(3, minmax(0, 1fr));
  }
  .path-levels > li:nth-child(4)::before {
    display: none;
  }
}
</style>
