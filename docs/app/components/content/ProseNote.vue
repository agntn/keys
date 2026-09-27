<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <KeysCallout kind="note" :title="title"><slot mdc-unwrap="p" /></KeysCallout>
</template>
