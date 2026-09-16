<script setup lang="ts">
const props = defineProps<{ address: string }>();

const GLYPHS = "0123456789abcdefABCDEFghjkmnpqrstuvwxyzGHJKLMNPQRSTUVWXYZ";
const DURATION = 520;

const shown = ref(props.address);
let frame: number | undefined;

function cancel() {
  if (frame !== undefined) {
    cancelAnimationFrame(frame);
    frame = undefined;
  }
}

function settle(target: string) {
  cancel();
  if (!import.meta.client || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    shown.value = target;
    return;
  }
  const start = performance.now();
  const keepPrefix = target.startsWith("0x") ? 2 : target.startsWith("bc1") ? 3 : target.startsWith("addr1") ? 5 : 0;
  const run = (now: number) => {
    const progress = Math.min(1, Math.max(0, (now - start) / DURATION));
    const resolved = Math.min(
      target.length,
      keepPrefix + Math.floor((target.length - keepPrefix) * progress),
    );
    let next = target.slice(0, resolved);
    for (let index = resolved; index < target.length; index += 1) {
      next += GLYPHS[Math.floor(Math.random() * GLYPHS.length)];
    }
    shown.value = next;
    if (progress < 1) {
      frame = requestAnimationFrame(run);
    } else {
      frame = undefined;
    }
  };
  frame = requestAnimationFrame(run);
}

watch(() => props.address, settle);
onUnmounted(cancel);
</script>

<template>
  <span class="keys-address">{{ shown }}</span>
</template>
