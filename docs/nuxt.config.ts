export default defineNuxtConfig({
  extends: ["docus"],
  site: {
    url: "https://keys.agntn.dev",
    name: "@agntn/keys",
  },
  llms: {
    domain: "https://keys.agntn.dev",
  },
  icon: {
    clientBundle: {
      icons: [
        "lucide:arrow-right",
        "lucide:arrow-up-right",
        "lucide:book-open",
        "lucide:boxes",
        "lucide:check",
        "lucide:chevron-left",
        "lucide:chevron-right",
        "lucide:copy",
        "lucide:cpu",
        "lucide:dices",
        "lucide:hexagon",
        "lucide:key",
        "lucide:layers",
        "lucide:loader-circle",
        "lucide:map-pin",
        "lucide:plus",
        "lucide:shield-alert",
        "lucide:wallet",
        "lucide:zap",
        "simple-icons:bitcoin",
        "simple-icons:cardano",
        "simple-icons:coinbase",
        "simple-icons:ethereum",
        "simple-icons:github",
        "simple-icons:npm",
        "simple-icons:solana",
        "simple-icons:sui",
        "vscode-icons:file-type-js",
        "vscode-icons:file-type-typescript",
        "vscode-icons:file-type-json",
        "vscode-icons:file-type-shell",
      ],
    },
  },
  colorMode: {
    preference: "dark",
  },
  fonts: {
    families: [
      { name: "Space Grotesk", weights: [400, 500, 600] },
      { name: "Space Mono", weights: [400, 700] },
    ],
  },
  content: {
    build: {
      markdown: {
        highlight: {
          theme: {
            default: "github-light",
            light: "github-light",
            dark: "poimandres",
          },
        },
      },
    },
  },
});
