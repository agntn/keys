<script setup lang="ts">
definePageMeta({ layout: "default" });

useSeoMeta({
  title: "Keyspace · @agntn/keys",
  description: "Walk secp256k1 private keys in the browser and derive addresses for eight chains.",
});
</script>

<template>
  <div class="keys-landing not-prose">
    <header class="keys-hero mx-auto w-full max-w-[var(--ui-container)] px-8 pt-20 pb-14 text-center sm:px-12 lg:px-16">
      <p class="keys-eyebrow justify-center">explorer</p>
      <h1 class="keys-enter mx-auto mt-4 max-w-3xl text-4xl leading-[1.08] font-medium tracking-tight text-highlighted sm:text-5xl lg:text-[3.5rem]">
        Keyspace. <span class="text-primary">Walk it live.</span>
      </h1>
      <p class="keys-enter keys-enter-2 mx-auto mt-6 max-w-xl text-base leading-7 text-muted">
        Private keys on secp256k1 are integers from 1 to n − 1. Type one, or step from the one
        you have, and every chain derives its address in this tab. Nothing is stored or sent.
      </p>
      <p class="keys-enter keys-enter-3 mx-auto mt-5 inline-flex max-w-xl items-start gap-2 text-left text-sm leading-6 text-dimmed">
        <UIcon name="i-lucide-shield-alert" class="mt-1 size-4 shrink-0 text-error" />
        <span>
          <span class="text-error">Never paste a key that controls real funds.</span>
          Every key here is treated as burned. ed25519 rows reuse the same 32 bytes as a seed,
          which is an overlay, not the secp256k1 scalar.
        </span>
      </p>
    </header>

    <section class="keys-section">
      <div class="mx-auto w-full max-w-[var(--ui-container)] px-8 py-14 sm:px-12 lg:px-16">
        <KeyspaceExplorer />
      </div>
    </section>
  </div>
</template>
