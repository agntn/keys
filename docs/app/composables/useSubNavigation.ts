import type { ContentNavigationItem } from "@nuxt/content";

const NAV_ICONS: Record<string, string> = {
  "/guide": "i-lucide-book-open",
  "/guide/keys": "i-lucide-key",
  "/guide/addresses": "i-lucide-map-pin",
  "/guide/wallets": "i-lucide-wallet",
  "/guide/evm": "i-lucide-cpu",
  "/guide/custom": "i-lucide-plus",
  "/blockchains": "i-lucide-boxes",
  "/blockchains/bitcoin": "i-simple-icons-bitcoin",
  "/blockchains/ethereum": "i-simple-icons-ethereum",
  "/blockchains/base": "i-simple-icons-coinbase",
  "/blockchains/solana": "i-simple-icons-solana",
  "/blockchains/cardano": "i-simple-icons-cardano",
  "/blockchains/sui": "i-simple-icons-sui",
  "/blockchains/aptos": "i-lucide-hexagon",
  "/blockchains/tron": "i-lucide-zap",
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
    /** Leaf pages match exactly, so /guide is not highlighted together with /guide/keys. */
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
