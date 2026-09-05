<script setup lang="ts">
import type { AddressRow } from "../../utils/derive";
import { shortDecimal } from "../../utils/format";

const props = defineProps<{
  hex: string;
  decimal: bigint;
  rows: readonly AddressRow[];
  tick: number;
}>();

const W = 1200;
const H = 420;
const KEY = { x: 24, y: 150, w: 250, h: 120 };
const CURVES = [
  { id: "secp256k1", label: "secp256k1", note: "BIP32", x: 480, y: 92, w: 190, h: 60 },
  { id: "ed25519", label: "ed25519", note: "SLIP-10", x: 480, y: 268, w: 190, h: 60 },
] as const;
const CHAIN_X = 890;
const CHAIN_W = 286;
const CHAIN_H = 40;
const CHAIN_GAP = 48;

const chains = computed(() =>
  props.rows.map((row, index) => ({
    ...row,
    x: CHAIN_X,
    y: 16 + index * CHAIN_GAP,
    curveIndex: row.curve === "secp256k1" ? 0 : 1,
  })),
);

function curvePath(x1: number, y1: number, x2: number, y2: number) {
  const mid = (x1 + x2) / 2;
  return `M ${x1} ${y1} C ${mid} ${y1}, ${mid} ${y2}, ${x2} ${y2}`;
}

const trunkPaths = computed(() =>
  CURVES.map((curve) =>
    curvePath(KEY.x + KEY.w, KEY.y + KEY.h / 2, curve.x, curve.y + curve.h / 2),
  ),
);

const branchPaths = computed(() =>
  chains.value.map((chain) => {
    const curve = CURVES[chain.curveIndex]!;
    return curvePath(curve.x + curve.w, curve.y + curve.h / 2, chain.x, chain.y + CHAIN_H / 2);
  }),
);

function short(address: string) {
  return address.length > 26 ? `${address.slice(0, 14)}…${address.slice(-8)}` : address;
}

const shortHex = computed(() => `${props.hex.slice(0, 12)}…${props.hex.slice(-12)}`);
</script>

<template>
  <svg
    :viewBox="`0 0 ${W} ${H}`"
    class="keys-flow"
    role="img"
    aria-label="Private key derives through secp256k1 and ed25519 into eight chain addresses"
  >
    <g class="keys-flow-wires">
      <path v-for="(d, index) in trunkPaths" :key="`t${index}`" :d="d" />
      <path v-for="(d, index) in branchPaths" :key="`b${index}`" :d="d" />
    </g>
    <g :key="tick" class="keys-flow-pulses">
      <path v-for="(d, index) in trunkPaths" :key="`pt${index}`" :d="d" class="keys-flow-pulse" />
      <path
        v-for="(d, index) in branchPaths"
        :key="`pb${index}`"
        :d="d"
        class="keys-flow-pulse keys-flow-pulse-late"
      />
    </g>

    <g class="keys-flow-node">
      <rect :x="KEY.x" :y="KEY.y" :width="KEY.w" :height="KEY.h" rx="10" />
      <text :x="KEY.x + 18" :y="KEY.y + 30" class="keys-flow-label">private key</text>
      <text :x="KEY.x + 18" :y="KEY.y + 66" class="keys-flow-value keys-flow-accent">
        <title>{{ decimal.toString() }}</title>
        {{ shortDecimal(decimal, 5) }}
      </text>
      <text :x="KEY.x + 18" :y="KEY.y + 96" class="keys-flow-mono">{{ shortHex }}</text>
    </g>

    <g v-for="curve in CURVES" :key="curve.id" class="keys-flow-node">
      <rect :x="curve.x" :y="curve.y" :width="curve.w" :height="curve.h" rx="8" />
      <text :x="curve.x + 16" :y="curve.y + 27" class="keys-flow-title">{{ curve.label }}</text>
      <text :x="curve.x + 16" :y="curve.y + 46" class="keys-flow-label">{{ curve.note }}</text>
    </g>

    <g v-for="chain in chains" :key="chain.id" class="keys-flow-node">
      <rect :x="chain.x" :y="chain.y" :width="CHAIN_W" :height="CHAIN_H" rx="8" />
      <text :x="chain.x + 14" :y="chain.y + 25" class="keys-flow-title">{{ chain.chain }}</text>
      <text :x="chain.x + 90" :y="chain.y + 25" class="keys-flow-mono">
        <tspan :key="chain.address" class="keys-derive">{{ short(chain.address) }}</tspan>
      </text>
    </g>
  </svg>
</template>
