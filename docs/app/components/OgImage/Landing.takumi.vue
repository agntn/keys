<script lang="ts" setup>
/** Overrides the Docus landing template. Takumi has no CSS variables, so tokens are literals. */
defineProps<{ title?: string; description?: string }>();

const TAGLINE =
  "Keys to addresses to signatures on eleven chains. From a mnemonic or from nothing at all. Nothing leaves the process.";

const { name: siteName } = useSiteConfig();

const CHAINS = ["Bitcoin", "Ethereum", "Solana", "Sui", "Cardano", "+6 more"];
</script>

<template>
  <div
    class="w-full h-full flex flex-col justify-between px-[72px] py-[56px]"
    style="background-color: #0b0d10; font-family: &quot;Space Grotesk&quot;; color: #d5e4ee"
  >
    <div
      class="absolute top-0 left-[150px] w-[900px] h-[560px]"
      style="
        background-image: radial-gradient(
          ellipse at top,
          rgba(111, 208, 247, 0.18) 0%,
          rgba(111, 208, 247, 0.05) 45%,
          transparent 70%
        );
      "
    />

    <div class="flex items-center justify-between w-full">
      <p class="m-0 text-[22px]" style="font-family: &quot;Space Mono&quot;; color: #f0f4f8">
        {{ siteName }}
      </p>
      <div
        class="flex items-center px-[16px] h-[38px] rounded-[8px] text-[18px] leading-none"
        style="
          font-family: &quot;Space Mono&quot;;
          color: #a5b0bc;
          background-color: #11141a;
          border: 1px solid #262c35;
          line-height: 38px;
          white-space: nowrap;
        "
      >
        $ pnpm add @agntn/keys
      </div>
    </div>

    <div class="flex-1 flex flex-col justify-center items-center w-full">
      <div class="flex items-baseline">
        <h1
          class="m-0 text-[76px] font-medium leading-[1.05] tracking-[-0.03em]"
          style="color: #f0f4f8"
        >
          One key.
        </h1>
        <h1
          class="m-0 ml-[22px] text-[76px] font-medium leading-[1.05] tracking-[-0.03em]"
          style="color: #6fd0f7"
        >
          Every chain.
        </h1>
      </div>
      <p
        class="m-0 mt-[24px] text-[26px] leading-[1.4] text-center max-w-[880px]"
        style="color: #8a97a5"
      >
        {{ TAGLINE }}
      </p>
    </div>

    <div class="flex items-center justify-between w-full">
      <div class="flex items-center">
        <div
          v-for="(chain, index) in CHAINS"
          :key="chain"
          class="flex items-center mr-[10px] px-[12px] h-[36px] rounded-[8px] text-[16px] leading-none"
          :style="{
            fontFamily: 'Space Mono',
            color: index === 0 ? '#6fd0f7' : '#a5b0bc',
            backgroundColor: '#11141a',
            border: index === 0 ? '1px solid rgba(111, 208, 247, 0.5)' : '1px solid #262c35',
            lineHeight: '36px',
            whiteSpace: 'nowrap',
          }"
        >
          {{ chain }}
        </div>
      </div>
      <p
        class="m-0 ml-[24px] text-[16px]"
        style="font-family: &quot;Space Mono&quot;; color: #6d7884; white-space: nowrap"
      >
        keys.agntn.dev
      </p>
    </div>
  </div>
</template>
