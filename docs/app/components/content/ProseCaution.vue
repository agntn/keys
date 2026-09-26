<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <KeysCallout kind="caution" :title="title"><slot mdc-unwrap="p" /></KeysCallout>
</template>
