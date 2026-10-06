<script setup lang="ts">
import { version } from "../../../package.json";
import { CHAINS } from "../utils/chains";
import { spellOut } from "../utils/tools";

definePageMeta({ layout: "default" });

const title = "Keyspace";
const description =
  `Walk secp256k1 private keys in the browser and derive addresses for ${spellOut(CHAINS.length).toLowerCase()} chains. Nothing is stored or sent.`;

useSeo({ title, description, type: "article" });

defineOgImage(
  "Docs",
  { headline: "Explorer", title, description },
  { alt: "Keyspace explorer. Walk secp256k1 private keys in the browser" },
);
</script>

<template>
  <div class="keys-landing not-prose">
    <header class="keys-hero hero-page">
      <div class="hero-zone">
        <span class="hero-cross hero-cross-tl" aria-hidden="true">+</span>
        <span class="hero-cross hero-cross-tr" aria-hidden="true">+</span>
        <span class="hero-bracket hero-bracket-l" aria-hidden="true" />
        <span class="hero-bracket hero-bracket-r" aria-hidden="true" />

        <p class="console-id">
          <span class="console-id-tag">ID</span>
          <span>keyspace</span>
          <span class="console-id-sep" aria-hidden="true">/</span>
          <span>@agntn/keys v{{ version }}</span>
        </p>

        <h1 class="hero-title">Keyspace. <span>Walk it live.</span></h1>
        <p class="hero-lead">
          Private keys on secp256k1 are integers from 1 to n − 1. Type one, or step from the one you
          have, and every chain derives its address in this tab. The link carries the key, so any
          state can be shared.
        </p>

        <dl class="hero-metrics">
          <div>
            <dt>Chains</dt>
            <dd>{{ CHAINS.length }}</dd>
            <dd class="hero-metric-sub">every driver</dd>
          </div>
          <div>
            <dt>Keys</dt>
            <dd>≈ 2²⁵⁶</dd>
            <dd class="hero-metric-sub">n − 1 scalars</dd>
          </div>
          <div>
            <dt>Network</dt>
            <dd class="hero-metric-accent">0 <span>calls</span></dd>
            <dd class="hero-metric-sub">nothing sent</dd>
          </div>
        </dl>

        <p class="keyspace-note">
          <span class="console-tag">Burned</span>
          <span
            >Never paste a key that controls real funds: every key here is treated as public. ed25519
            rows reuse the same 32 bytes as a seed, an overlay, not the secp256k1 scalar.</span
          >
        </p>
      </div>

      <div class="hero-instrument hero-instrument-keep">
        <svg class="hero-circuit" viewBox="0 0 160 56" aria-hidden="true">
          <path class="hero-circuit-rail" d="M80 0V16L96 32V56" />
          <path class="hero-circuit-live" d="M80 0V16L96 32V56" pathLength="1" />
          <path class="hero-circuit-seg" d="M96 38V48" />
          <rect class="hero-circuit-node" x="92.5" y="52.5" width="7" height="7" />
        </svg>
        <span class="hero-circuit-tag" aria-hidden="true">k</span>
        <KeyspaceExplorer />
      </div>
    </header>
  </div>
</template>

<style scoped>
/* The warning reads as a line of the zone, like the playground note in puzzles: no box of its own. */
.keyspace-note {
  display: flex;
  justify-content: center;
  align-items: baseline;
  gap: 12px;
  max-width: 44rem;
  margin: 28px auto 0;
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.6;
  text-align: left;
  color: var(--ui-text-muted);
}
.keyspace-note > .console-tag {
  flex: none;
  margin: 0;
  color: var(--keys-del);
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--keys-del) 55%, transparent);
}
</style>
