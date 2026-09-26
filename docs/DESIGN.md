# Design system

The shared rules (direction, color roles, type, the `console-*` grammar, hero, docs chrome, density, motion, checks) live in the one agntn design system document, kept with the agntn skills until it ships in the shared package; [agntn/puzzles/docs/DESIGN.md](https://github.com/agntn/puzzles/blob/main/docs/DESIGN.md) is the closest public copy. This file records only what keys owns and where it departs from the shared rules. It does not repeat them.

The instruments keys owns:

| Instrument                                                       | Where                    | Object                                                                  |
| ---------------------------------------------------------------- | ------------------------ | ----------------------------------------------------------------------- |
| [LandingHero.vue](app/components/content/LandingHero.vue)         | landing, first screen    | hero zone, circuit `k · G` into the key instrument                      |
| [LandingKey.vue](app/components/content/LandingKey.vue)           | under the hero           | one private key and the address it gets on every chain                  |
| [LandingPipeline.vue](app/components/content/LandingPipeline.vue) | "Keys in, addresses out" | secret bytes, public key, three Bitcoin formats                         |
| [LandingRotatingCode.vue](app/components/content/LandingRotatingCode.vue) | "Same calls, every chain" | the same seven lines with the driver swapped, as a file         |
| [LandingPath.vue](app/components/content/LandingPath.vue)         | "Mnemonic to wallet"     | the BIP44 path levels and the derived address                           |
| [LandingToolCall.vue](app/components/content/LandingToolCall.vue) | "Twenty tools over MCP"  | `keys_get_address` arguments and result                                 |
| [LandingStart.vue](app/components/content/LandingStart.vue)       | closing section          | install, notes, first address as a file                                 |
| [ChainList.vue](app/components/content/ChainList.vue)             | landing and `/blockchains` | roster of the drivers on `UTable`, sortable                           |
| [ChainFacts.vue](app/components/content/ChainFacts.vue)           | every chain page         | chain dossier: ID bar with position, reticle, formats, readout, access  |
| [KeyspaceExplorer.vue](app/components/content/KeyspaceExplorer.vue) | `/keyspace`            | input, secret, public keys, every address, under a hero zone            |
| [Landing.takumi.vue](app/components/OgImage/Landing.takumi.vue), [Docs.takumi.vue](app/components/OgImage/Docs.takumi.vue) | OG images | the hero zone in 1200 by 600; a docs page as one instrument with the section tag, ruler and tool tags |

The chain names, curves, icons, blurbs and fixture rows come from [chains.ts](app/utils/chains.ts). Addresses on the landing before the library loads come from [landing.ts](app/utils/landing.ts), which the root test derives again from `src/`.

## Anatomy

- **Key instrument.** Bar `Call chain.getAddress(k · G)`, meta with the chain and curve count. Subject band: reticle with `key-round`, the key as a short decimal with the whole number in a tooltip, the 64 hex digits with the leading zeros dimmed. Readout: public key, range, address count in the accent. Band `Addresses [ one key · every chain ]`: one cell per chain (glyph, name, format, node, address with an ellipsis), the cell the walk points at lit on its node and address. Footer: link to the key in the keyspace, previous, next and random.
- **Chain dossier.** ID bar with the driver key and `01 / 18`, meta `SLIP-44 0'`. Subject band: reticle with the token glyph, label `Chain`, name, curves in uppercase, formats as boxed identifiers in their own case. Readout of three short values: format count, coin type, the address of private key 1 in the accent (full value and format in the tooltip). Access band with leads `Load`, `Import`, `Walk`. Footer back to the index.
- **Pipeline.** The secret as `.key-bytes` right under the ruler, then one readout: public key, legacy (in the accent), segwit, taproot, each on one line with an ellipsis and the format note and full value in a `UTooltip`. A band per step with its own rule title made the panel 509 px tall beside 286 px of copy.
- **Tool call.** No request band: the chain is in the bar and the name, the arguments (public key, address type, `default` when absent) are the first readout rows and the address the last, so every sample has the same height.
- **Driver file.** Every chain gets the same seven lines, so the file keeps one height; each line stays on one line and ends in an ellipsis, the copy button hands out the whole text.
- **Explorer.** Inputs sit in a readout (focus is the accent edge of the row), then bytes, the three public keys with copy buttons, and the address table on `UTable` with the roster classes, copy inside the address cell so a stacked row keeps two lines.

## Motion

| Change                      | Motion                                                        |
| --------------------------- | ------------------------------------------------------------- |
| new key (walk, click)       | ruler cursor once, scan over the subject, reticle arcs, address scramble, changed bytes lit |
| chain modules still loading | ruler cursor loops (`console-cursor-busy`), controls disabled |
| driver file advances        | file name rolls (`keys-roll`)                                 |
| reduced motion              | no walk timer, no scramble, no roll; manual steps still work  |

## Differences

Departures from the shared rules and from puzzles, recorded for the shared package so it knows what has to become a prop:

- The version comes from the root `package.json`; puzzles imports `version` from the library.
- The logo glyph (`key-round` against `lock-keyhole`), the header areas and the footer sentence differ; the components are otherwise identical.
- No data version exists, so the ID strips and footers carry none.
- The hero has no share bar: the chains split by curve with Sui on both, so a two part bar would not add up to the chain count.
- `.key-bytes` is new: a byte grid no puzzles instrument needs.
- The OG images ship local Figtree and Fira Code TTFs; puzzles relies on `@nuxt/fonts` and its OG falls back to Inter.
- The entity dossier (`.dossier-*`), playground, status pill and lock styles are left out, since nothing here uses them.

## Checks

Beyond the shared checks: `/keyspace#ff` at 390 px (the address table stacks, copy stays on the address line) and the four feature pairs within 40 px (today 286/315, 310/302, 332/313, 332/326 at 1440).
