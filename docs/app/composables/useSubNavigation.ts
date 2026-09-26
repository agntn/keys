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
  "/keyspace": "i-lucide-key",
};

export function getFirstPagePath(item: ContentNavigationItem): string {
  let current = item;
  while (current.children?.length) {
    current = current.children[0]!;
  }
  return current.path;
}

function withIcons(items: ContentNavigationItem[]): ContentNavigationItem[] {
  return items.map((item) => ({
    ...item,
    icon: NAV_ICONS[item.path] ?? item.icon,
    /** Leaf pages match exactly, so /guide isn't highlighted together with /guide/keys. */
    exact: !item.children?.length,
    children: item.children ? withIcons(item.children) : item.children,
  }));
}

export function useSubNavigation(
  providedNavigation?: Ref<ContentNavigationItem[] | null | undefined>,
) {
  const route = useRoute();
  const appConfig = useAppConfig();
  const navigation = providedNavigation ?? inject<Ref<ContentNavigationItem[]>>("navigation");

  const isDocsPage = computed(() => route.meta.layout === "docs");

  const subNavigationMode = computed(() => {
    if (!isDocsPage.value) return undefined;
    return (appConfig.navigation as { sub?: "header" | "aside" } | undefined)?.sub;
  });

  const currentSection = computed(() => {
    if (!subNavigationMode.value || !navigation?.value) return undefined;
    return navigation.value.find(
      (item) => route.path === item.path || route.path.startsWith(`${item.path}/`),
    );
  });

  const sections = computed(() => {
    if (!subNavigationMode.value || !navigation?.value) return [];
    return navigation.value
      .filter((item) => item.children?.length)
      .map((item) => ({
        label: item.title,
        icon: (NAV_ICONS[item.path] ?? item.icon) as string | undefined,
        to: getFirstPagePath(item),
        active: route.path === item.path || route.path.startsWith(`${item.path}/`),
      }));
  });

  const sidebarNavigation = computed(() => {
    const items =
      subNavigationMode.value && currentSection.value
        ? currentSection.value.children || []
        : navigation?.value || [];
    return withIcons(items);
  });

  return {
    subNavigationMode,
    sections,
    currentSection,
    sidebarNavigation,
  };
}
