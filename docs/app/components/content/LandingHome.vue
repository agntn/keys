<script setup lang="ts">
const { hex, decimal, rows, pipeline, hd, paused, tick, changedBytes, step, randomKey } = useLandingKey();

const stats = [
  { value: "8", label: "chains" },
  { value: "2", label: "curves" },
  { value: "0", label: "network calls" },
  { value: "13", label: "MCP tools" },
] as const;

const chains = [
  { label: "Bitcoin", curve: "secp256k1", icon: "i-simple-icons-bitcoin", to: "/blockchains/bitcoin" },
  { label: "Ethereum", curve: "secp256k1", icon: "i-simple-icons-ethereum", to: "/blockchains/ethereum" },
  { label: "Base", curve: "secp256k1", icon: "i-lucide-layers", to: "/blockchains/base" },
  { label: "TRON", curve: "secp256k1", icon: "i-lucide-zap", to: "/blockchains/tron" },
  { label: "Solana", curve: "ed25519", icon: "i-simple-icons-solana", to: "/blockchains/solana" },
  { label: "Aptos", curve: "ed25519", icon: "i-lucide-hexagon", to: "/blockchains/aptos" },
  { label: "Sui", curve: "ed25519 · secp256k1", icon: "i-simple-icons-sui", to: "/blockchains/sui" },
  { label: "Cardano", curve: "ed25519", icon: "i-simple-icons-cardano", to: "/blockchains/cardano" },
] as const;

const path = computed(() => [
  { segment: "m", label: "master" },
  { segment: "44'", label: "purpose" },
  { segment: "60'", label: "coin" },
  { segment: "0'", label: "account" },
  { segment: "0", label: "change" },
  { segment: String(hd.value.index), label: "index", live: true },
]);

const activeChain = computed(() => tick.value % chains.length);

const copied = ref(false);

async function copyInstall() {
  try {
    await navigator.clipboard.writeText("pnpm add @agntn/keys");
  } catch {
    return;
  }
  copied.value = true;
  setTimeout(() => {
    copied.value = false;
  }, 1200);
}
</script>

<template>
  <div class="keys-landing not-prose">
    <header class="keys-hero mx-auto w-full max-w-[var(--ui-container)] px-8 pt-24 pb-20 text-center sm:px-12 lg:px-16">
      <h1 class="keys-enter mx-auto max-w-3xl text-4xl leading-[1.08] font-medium tracking-tight text-highlighted sm:text-5xl lg:text-[3.75rem]">
        One key. <span class="text-primary">Every chain.</span>
      </h1>
      <p class="keys-enter keys-enter-2 mx-auto mt-6 max-w-xl text-base leading-7 text-muted">
        Typed key generation, address derivation, and message signing for eight blockchains.
        One interface in TypeScript, the same thirteen operations over MCP, and nothing ever leaves the process.
      </p>
      <div class="keys-enter keys-enter-3 mt-8 flex flex-wrap items-center justify-center gap-2">
        <UButton to="/guide" color="primary" trailing-icon="i-lucide-arrow-right">
          Get started
        </UButton>
        <UButton to="https://github.com/agntn/keys" target="_blank" color="neutral" variant="outline" icon="i-simple-icons-github">
          Star on GitHub
        </UButton>
      </div>
      <button
        type="button"
        class="keys-enter keys-enter-4 keys-install mt-5"
        :aria-label="copied ? 'Copied' : 'Copy install command'"
        @click="copyInstall"
      >
        <span class="text-dimmed">$</span>
        <span>pnpm add @agntn/keys</span>
        <UIcon :name="copied ? 'i-lucide-check' : 'i-lucide-copy'" class="size-3.5 text-dimmed" />
      </button>

      <div
        class="keys-enter keys-enter-4 mx-auto mt-16 hidden max-w-6xl md:block"
        @mouseenter="paused = true"
        @mouseleave="paused = false"
      >
        <LandingFlow :hex="hex" :decimal="decimal" :rows="rows" :tick="tick" />
      </div>
    </header>

    <dl class="keys-section grid grid-cols-2 sm:grid-cols-4">
      <div
        v-for="(stat, index) in stats"
        :key="stat.label"
        class="border-default px-6 py-7 text-center"
        :class="{ 'border-t sm:border-t-0': index >= 2, 'border-l': index % 2 === 1, 'sm:border-l': index > 0 }"
      >
        <dd class="font-mono text-2xl text-highlighted">{{ stat.value }}</dd>
        <dt class="mt-1 font-mono text-[11px] tracking-[0.12em] text-dimmed uppercase">{{ stat.label }}</dt>
      </div>
    </dl>

    <LandingFeature
      eyebrow="Derivation"
      title="Keys in, addresses out"
      to="/keyspace"
      link="Open the explorer"
      :checks="[
        'secp256k1 through @noble, ed25519 through SLIP-10',
        'Legacy, SegWit, Taproot, EIP-55, base58check, bech32',
        'Same 32 bytes, eight chains, derived in this tab',
      ]"
    >
      A private key is an integer. Multiply it by the generator, hash the result, encode the
      hash, and you have an address. Every chain is the same three steps with different rules.
      The panel walks the keyspace live.
      <template #visual>
        <LandingPipeline
          :hex="hex"
          :decimal="decimal"
          :pipeline="pipeline"
          :changed-bytes="changedBytes"
          @step="step"
          @random="randomKey"
          @pause="paused = $event"
        />
      </template>
    </LandingFeature>

    <LandingFeature
      eyebrow="One interface"
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
      stays. Options that a chain does not support are rejected, not ignored.
      <template #visual>
        <LandingRotatingCode :rows="rows" :tick="tick" :decimal="decimal" />
      </template>
    </LandingFeature>

    <LandingFeature
      eyebrow="HD wallets"
      title="Mnemonic to wallet in one call"
      to="/guide/wallets"
      link="Generating wallets"
      :checks="[
        'BIP39 mnemonics in ten languages, checksum enforced',
        'BIP32 for secp256k1, SLIP-10 for ed25519',
        'Bitcoin infers the address type from the purpose',
      ]"
    >
      Walk a BIP39 mnemonic down a BIP44 path and get the wallet at the end of it. Paths are
      parsed and validated, so a hardened segment in the wrong place fails before derivation.
      <template #visual>
        <div class="keys-frame overflow-hidden rounded-xl">
          <div class="flex items-center justify-between border-b border-muted px-4 py-3">
            <p class="font-mono text-xs text-muted">derivation path</p>
            <p class="font-mono text-xs text-dimmed">BIP44 · Ethereum · test vector</p>
          </div>
          <div class="flex flex-wrap items-stretch gap-2 px-4 py-6">
            <template v-for="(part, index) in path" :key="part.label">
              <span v-if="index > 0" class="self-center font-mono text-sm text-dimmed">/</span>
              <span class="keys-path" :class="{ 'keys-path-live': part.live }">
                <Transition name="keys-roll" mode="out-in">
                  <span :key="part.segment" class="font-mono text-base text-highlighted">{{ part.segment }}</span>
                </Transition>
                <span class="font-mono text-[10px] tracking-[0.1em] text-dimmed uppercase">{{ part.label }}</span>
              </span>
            </template>
          </div>
          <pre class="keys-rotating border-t border-muted"><code><span class="tok-kw">const</span> wallet = chain.<span class="tok-fn">deriveHDWallet</span>(mnemonic, <span class="tok-str">"{{ hd.path }}"</span>);
<span class="tok-cm">// wallet.address</span>
<span class="tok-cm">// <LandingAddress :address="hd.address" /></span></code></pre>
        </div>
      </template>
    </LandingFeature>

    <LandingFeature
      eyebrow="Blockchains"
      title="Eight drivers, one shape"
      to="/blockchains"
      link="All blockchains"
      :checks="[
        'Mainnet and testnet address formats',
        'Address validation for every chain',
        'Sui on both curves, Cardano enterprise and stake',
      ]"
      reverse
    >
      Each chain is an adapter over the shared primitives. Adding one means implementing the
      hashing and encoding rules, not the cryptography.
      <template #visual>
        <div class="keys-frame grid grid-cols-2 overflow-hidden rounded-xl sm:grid-cols-4">
          <NuxtLink
            v-for="(chain, index) in chains"
            :key="chain.to"
            :to="chain.to"
            class="group flex flex-col gap-3 border-muted px-5 py-5 transition-colors duration-500 hover:bg-muted"
            :class="{
              'border-t': index >= 2,
              'sm:border-t-0': index < 4,
              'border-l': index % 2 === 1,
              'sm:border-l': index % 4 !== 0,
              'keys-cell-active': index === activeChain,
            }"
          >
            <UIcon
              :name="chain.icon"
              class="size-5 text-muted transition-colors duration-500 group-hover:text-primary"
              :class="{ 'text-primary': index === activeChain }"
            />
            <span>
              <span class="block text-sm font-medium text-highlighted">{{ chain.label }}</span>
              <span class="mt-0.5 block font-mono text-[11px] text-dimmed">{{ chain.curve }}</span>
            </span>
          </NuxtLink>
        </div>
      </template>
    </LandingFeature>

    <LandingFeature
      eyebrow="Agents"
      title="Thirteen tools over MCP"
      to="/guide"
      link="MCP server setup"
      :checks="[
        'Keys, mnemonics, BIP44 paths, addresses, signing',
        'stdio server started with one command',
        'Ambiguous or unsupported inputs are rejected with a reason',
      ]"
    >
      Everything the library does is exposed as an MCP tool with the same parameters. Point an
      agent at it and it derives, validates, and signs without touching the network.
      <template #visual>
        <LandingToolCall :rows="rows" :public-key="pipeline.publicKey" :tick="tick" />
      </template>
    </LandingFeature>

    <section class="keys-section">
      <div class="mx-auto w-full max-w-[var(--ui-container)] px-8 py-20 text-center sm:px-12 lg:px-16">
        <h2 class="text-2xl font-medium tracking-tight text-highlighted sm:text-3xl">
          Start with one command
        </h2>
        <p class="mx-auto mt-3 max-w-md text-sm leading-6 text-muted">
          Experimental until 1.0. Pin exact versions and keep real funds on a hardware wallet.
        </p>
        <div class="mt-8 flex flex-wrap items-center justify-center gap-2">
          <UButton to="/guide" color="primary" trailing-icon="i-lucide-arrow-right">
            Read the guide
          </UButton>
          <UButton to="/keyspace" color="neutral" variant="outline">
            Open explorer
          </UButton>
        </div>
      </div>
    </section>
  </div>
</template>
