<script setup lang="ts">
import { CHAINS } from "../../utils/chains";

const { hex, decimal, rows, pipeline, hd, ready, paused, tick, changedBytes, step, randomKey } =
  useLandingKey();
</script>

<template>
  <div class="keys-landing not-prose">
    <LandingHero
      :hex="hex"
      :decimal="decimal"
      :rows="rows"
      :pipeline="pipeline"
      :tick="tick"
      :ready="ready"
      @pause="paused = $event"
      @step="step"
      @random="randomKey"
    />

    <LandingFeature
      title="Keys in, addresses out"
      to="/keyspace"
      link="Open the keyspace"
      :checks="[
        'Both curves from @noble, nothing else underneath',
        'Legacy, SegWit, Taproot, EIP-55, base58check, bech32',
        'Same 32 bytes, eighteen chains, derived in this tab',
      ]"
    >
      A private key is an integer. Multiply it by the generator, hash the result, encode the hash,
      and you have an address. Every chain is the same three steps with different rules. The panel
      walks the keyspace live.
      <template #visual>
        <div
          @mouseenter="paused = true"
          @mouseleave="paused = false"
          @focusin="paused = true"
          @focusout="paused = false"
        >
          <LandingPipeline
            :hex="hex"
            :decimal="decimal"
            :pipeline="pipeline"
            :changed-bytes="changedBytes"
            :ready="ready"
            @step="step"
            @random="randomKey"
          />
        </div>
      </template>
    </LandingFeature>

    <LandingFeature
      title="Same calls, every chain"
      to="/guide/keys"
      link="Working with keys"
      :checks="[
        'generateWallet, getAddress, signMessage on every driver',
        'Drivers load lazily, only the chains you use ship',
        'Custom chains extend the same abstract class',
      ]"
      reverse
    >
      Every blockchain is a class with the same shape. Swap the import and the rest of the code
      stays. A chain that can't do what you asked throws, Decred on a segwit address, Cardano on an
      HD walk, instead of handing you something that only looks right.
      <template #visual>
        <LandingRotatingCode :rows="rows" :tick="tick" :decimal="decimal" />
      </template>
    </LandingFeature>

    <LandingFeature
      title="Mnemonic to wallet in one call"
      to="/guide/wallets"
      link="Generating wallets"
      :checks="[
        'BIP32 for secp256k1, SLIP-10 for ed25519',
        'Bitcoin, Bitcoin Gold and Litecoin infer the address type from the purpose',
        'Broken checksum? Derive anyway and get a warning with the wallet',
      ]"
    >
      Walk a BIP39 mnemonic down a BIP44 path and get the wallet at the end of it. Paths are parsed
      and validated, so a hardened segment in the wrong place fails before derivation. Puzzle
      phrases with a bad checksum go through on request, words untouched.
      <template #visual>
        <LandingPath :hd="hd" />
      </template>
    </LandingFeature>

    <section class="keys-section">
      <div class="mx-auto w-full max-w-[var(--ui-container)] px-8 py-20 sm:px-12 lg:px-16">
        <div class="max-w-2xl">
          <h2 class="text-2xl font-medium tracking-tight text-highlighted sm:text-[1.75rem]">
            {{ CHAINS.length }} drivers, one class shape
          </h2>
          <p class="mt-4 text-sm leading-6 text-muted">
            Each chain is an adapter over the shared primitives: its hashing, its encoding and the
            arguments that matter there. Adding one means writing those rules, not the
            cryptography. Every driver has a page with its formats and the traps.
          </p>
          <p class="landing-entry">
            <span class="console-tag">Import</span>
            <code>@agntn/keys/blockchains/&lt;key&gt;</code>
          </p>
        </div>
        <ChainList class="mt-10" />
      </div>
    </section>

    <LandingFeature
      title="Twenty-one tools over MCP"
      to="/guide#agents"
      link="MCP server setup"
      :checks="[
        'Keys, WIF, mnemonics, BIP44 paths, addresses, signing',
        'stdio server started with one command',
        'A generated mnemonic comes back marked as already in the transcript',
      ]"
      reverse
    >
      Everything the library does is exposed as an MCP tool with the same parameters. Point an
      agent at it and it derives, validates and signs without touching the network. The Pi and OMP
      extensions run the same executors.
      <template #visual>
        <LandingToolCall :rows="rows" :public-key="pipeline.publicKey" :tick="tick" />
      </template>
    </LandingFeature>

    <section class="keys-section">
      <div class="mx-auto w-full max-w-[var(--ui-container)] px-8 py-20 sm:px-12 lg:px-16">
        <LandingStart />
      </div>
    </section>
  </div>
</template>

<style scoped>
.landing-entry {
  display: flex;
  align-items: baseline;
  flex-wrap: wrap;
  gap: 6px 12px;
  margin-top: 14px;
  font-family: var(--font-mono);
  font-size: 13px;
}
.landing-entry > .console-tag {
  margin: 0;
}
.landing-entry > code {
  min-width: 0;
  overflow-wrap: anywhere;
  color: var(--ui-text-highlighted);
}
</style>
