<script setup lang="ts">
defineProps<{ title?: string }>();
</script>

<template>
  <KeysCallout kind="warning" :title="title"><slot mdc-unwrap="p" /></KeysCallout>
</template>
