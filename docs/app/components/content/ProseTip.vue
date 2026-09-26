<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <KeysCallout kind="tip" :title="title"><slot mdc-unwrap="p" /></KeysCallout>
</template>
