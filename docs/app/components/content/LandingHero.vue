<script setup lang="ts">
import { version } from "../../../../package.json";
import { CHAINS } from "../../utils/chains";
import { TOOL_COUNT } from "../../utils/tools";
import type { AddressRow } from "../../utils/derive";
import type { Pipeline } from "../../utils/landing";

defineProps<{
  hex: string;
  decimal: bigint;
  rows: readonly AddressRow[];
  pipeline: Pipeline;
  tick: number;
  ready: boolean;
}>();
const emit = defineEmits<{ pause: [paused: boolean]; step: [delta: bigint]; random: [] }>();

const INSTALL = "pnpm add @agntn/keys";
const { copied, copy } = useCopied();
</script>

<template>
  <header class="keys-hero hero-page">
    <div class="hero-zone">
      <span class="hero-cross hero-cross-tl" aria-hidden="true">+</span>
      <span class="hero-cross hero-cross-tr" aria-hidden="true">+</span>
      <span class="hero-bracket hero-bracket-l" aria-hidden="true" />
      <span class="hero-bracket hero-bracket-r" aria-hidden="true" />

      <p class="console-id">
        <span class="console-id-tag">ID</span>
        <span>@agntn/keys</span>
        <span class="console-id-sep" aria-hidden="true">/</span>
        <span>v{{ version }}</span>
      </p>

      <h1 class="hero-title">One key. <span>Every chain.</span></h1>
      <p class="hero-lead">
        Key generation, address derivation and message signing for eighteen blockchains, typed and
        built on noble, scure and our own hashes. One interface in TypeScript, the same tools
        over MCP, Pi and OMP, and nothing ever leaves the process.
      </p>

      <dl class="hero-metrics">
        <div>
          <dt>Chains</dt>
          <dd>{{ CHAINS.length }}</dd>
          <dd class="hero-metric-sub">two curves</dd>
        </div>
        <div>
          <dt>Tools</dt>
          <dd>{{ TOOL_COUNT }}</dd>
          <dd class="hero-metric-sub">MCP · Pi · OMP</dd>
        </div>
        <div>
          <dt>Network</dt>
          <dd class="hero-metric-accent">0 <span>calls</span></dd>
          <dd class="hero-metric-sub">in process</dd>
        </div>
      </dl>

      <div class="console-actions">
        <NuxtLink to="/guide" class="console-action console-action-primary">
          <span class="console-action-label">Get started</span>
          <span class="console-action-cell" aria-hidden="true"
            ><UIcon name="i-lucide-arrow-right" class="size-4"
          /></span>
        </NuxtLink>
        <NuxtLink to="https://github.com/agntn/keys" target="_blank" class="console-action">
          <span class="console-action-cell" aria-hidden="true"
            ><UIcon name="i-simple-icons-github" class="size-4"
          /></span>
          <span class="console-action-label">Star on GitHub</span>
        </NuxtLink>
      </div>
      <div class="console-install">
        <span class="console-install-tag">Install</span>
        <code><span class="console-install-prompt">$</span> {{ INSTALL }}</code>
        <button
          type="button"
          class="console-button"
          :data-copied="copied === 'install'"
          :aria-label="copied === 'install' ? 'Copied' : 'Copy install command'"
          @click="copy('install', INSTALL)"
        >
          <UIcon
            :name="copied === 'install' ? 'i-lucide-check' : 'i-lucide-copy'"
            class="size-3.5"
          />
        </button>
      </div>
    </div>

    <div
      class="hero-instrument"
      @mouseenter="emit('pause', true)"
      @mouseleave="emit('pause', false)"
      @focusin="emit('pause', true)"
      @focusout="emit('pause', false)"
    >
      <svg :key="hex" class="hero-circuit" viewBox="0 0 160 56" aria-hidden="true">
        <path class="hero-circuit-rail" d="M80 0V16L96 32V56" />
        <path class="hero-circuit-live" d="M80 0V16L96 32V56" pathLength="1" />
        <path class="hero-circuit-seg" d="M96 38V48" />
        <rect class="hero-circuit-node" x="92.5" y="52.5" width="7" height="7" />
      </svg>
      <span :key="`tag-${hex}`" class="hero-circuit-tag" aria-hidden="true">k · G</span>
      <LandingKey
        :hex="hex"
        :decimal="decimal"
        :rows="rows"
        :pipeline="pipeline"
        :tick="tick"
        :ready="ready"
        @step="emit('step', $event)"
        @random="emit('random')"
      />
    </div>
  </header>
</template>
