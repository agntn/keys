import type { ContentNavigationItem } from "@nuxt/content";

const NAV_ICONS: Record<string, string> = {
  "/guide": "i-lucide-book-open",
  "/guide/keys": "i-lucide-key",
  "/guide/addresses": "i-lucide-map-pin",
  "/guide/wallets": "i-lucide-wallet",
  "/guide/evm": "i-lucide-cpu",
  "/guide/custom": "i-lucide-plus",
  "/blockchains": "i-lucide-boxes",
  "/blockchains/bitcoin": "i-token-btc",
  "/blockchains/litecoin": "i-token-ltc",
  "/blockchains/dash": "i-token-dash",
  "/blockchains/decred": "i-token-dcr",
  "/blockchains/dogecoin": "i-token-doge",
  "/blockchains/zcash": "i-token-zec",
  "/blockchains/ecash": "i-token-xec",
  "/blockchains/bitcoincash": "i-token-bch",
  "/blockchains/bitcoingold": "i-token-btg",
  "/blockchains/bitcoinsv": "i-token-bsv",
  "/blockchains/ethereum": "i-token-eth",
  "/blockchains/base": "i-token-base",
  "/blockchains/solana": "i-token-sol",
  "/blockchains/stellar": "i-token-xlm",
  "/blockchains/cardano": "i-token-ada",
  "/blockchains/sui": "i-token-sui",
  "/blockchains/aptos": "i-token-apt",
  "/blockchains/tron": "i-token-trx",
  "/blockchains/xrpl": "i-token-xrp",
  "/blockchains/near": "i-token-near",
  "/blockchains/cosmos": "i-token-atom",
  "/blockchains/polkadot": "i-token-dot",
  "/blockchains/monero": "i-token-xmr",
  "/keyspace": "i-lucide-key",
};

function withIcons(items: readonly ContentNavigationItem[]): ContentNavigationItem[] {
  return items.map((item) => ({
    ...item,
    icon: NAV_ICONS[item.path] ?? item.icon,
    /** Leaf pages match exactly, so /guide isn't highlighted together with /guide/keys. */
    exact: !item.children?.length,
    children: item.children ? withIcons(item.children) : item.children,
  }));
}

/**
 * The first page under a section, which is where its tab in the header leads.
 *
 * @param {ContentNavigationItem} item - A section of the tree.
 * @returns {string} The path of its first page.
 */
function firstPagePath(item: ContentNavigationItem): string {
  let current = item;
  while (current.children?.length) current = current.children[0]!;
  return current.path;
}

/**
 * The navigation with this site's icons. With sub-navigation in the header the sidebar holds the
 * current section only, title included; `sections` feeds the header's tabs and `fullNavigation` the
 * mobile menu, which has no tabs and needs every section.
 *
 * @returns {object} `sidebarNavigation`, `fullNavigation` and `sections`.
 */
export function useSubNavigation() {
  const route = useRoute();
  const appConfig = useAppConfig();
  const navigation = inject<Ref<ContentNavigationItem[]>>("navigation");

  const subNavigationMode = computed(() =>
    route.meta.layout === "docs"
      ? (appConfig.navigation as { sub?: "header" | "aside" } | undefined)?.sub
      : undefined,
  );

  const currentSection = computed(() => {
    if (!subNavigationMode.value || !navigation?.value) return undefined;
    return navigation.value.find(
      (item) => route.path === item.path || route.path.startsWith(`${item.path}/`),
    );
  });

  const fullNavigation = computed(() => withIcons(navigation?.value ?? []));

  const sidebarNavigation = computed(() =>
    subNavigationMode.value === "header" && currentSection.value
      ? withIcons([currentSection.value])
      : fullNavigation.value,
  );

  const sections = computed(() =>
    fullNavigation.value.map((item) => ({
      title: item.title,
      icon: item.icon,
      to: firstPagePath(item),
      active: route.path === item.path || route.path.startsWith(`${item.path}/`),
    })),
  );

  return { sidebarNavigation, fullNavigation, sections };
}
