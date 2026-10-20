# @agntn/keys

[![npm version](https://npmx.dev/api/registry/badge/version/@agntn/keys)](https://npmx.dev/package/@agntn/keys)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/@agntn/keys)](https://npmx.dev/package/@agntn/keys)
[![license](https://npmx.dev/api/registry/badge/license/@agntn/keys)](https://npmx.dev/package/@agntn/keys)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/agntn/keys)

🔑 Keys, addresses and signatures from Bitcoin to the XRP Ledger, from a mnemonic or from nothing at all. Bitcoin gets its five address types, Solana gets ed25519, your agent gets them as MCP tools, and none of it should ever meet real money.

> [!WARNING]
> **@agntn/keys is experimental.** The public API and the tool surfaces can still move before the first stable release. Pin exact versions if you build on it now.

> [!CAUTION]
> **Not audited.** This code has never had a security audit. Do not use it in production, with real funds or with sensitive data. It is meant for agents, puzzles and local experiments only. It comes as is, without warranty of any kind, and the authors are not liable for any loss, as the MIT license states. Anything that matters wants an audited library.

## Why?

Every chain has its own wallet library and its own idea of what a key is. One wants a Buffer, one a Uint8Array, one has a KeyPair class and a second one for testnet. Then a puzzle hands you a mnemonic, and all of them say "invalid checksum" and stop talking to you. So here it's one `Blockchain` interface and the same `generateWallet()` on every chain. The puzzle cases live in the API, not in a fork.

The docs live at [keys.agntn.dev](https://keys.agntn.dev), keyspace explorer included.

## ✨ Features

- ⛓️ **Twenty-four chains, one interface.** Bitcoin and its forks, Ethereum, Solana, Cosmos, Monero, TON and the rest of the table below. Same methods on every one.
- 🧬 **Two curves.** secp256k1 and ed25519. Sui and the XRP Ledger take either.
- 🏠 **Bitcoin the way Bitcoin wants it.** Legacy, P2SH, segwit, P2WSH and taproot. Your path picks the type.
- 🌱 **Mnemonic in, wallet out.** BIP39 into BIP32 or SLIP-10, passphrase optional, all ten word lists.
- 👀 **An xpub is enough to watch.** Addresses from an xpub, ypub or zpub, no secret anywhere in the call.
- 🧩 **Puzzle mnemonics are welcome.** Bad checksum, missing word, wrong order, a typo. There's a function for each.
- ✍️ **Signatures the way wallets write them.** Core's `signmessage`, ethers, Keplr, polkadot.js, `monero-wallet-cli` and more, each on the chain it belongs to.
- 🔌 **One chain at a time.** `blockchains.solana()()` imports Solana and nothing else. A Bitcoin tool never pays for Cardano.
- 🤖 **Tools for your agent.** MCP over stdio or HTTP, plus Pi and OMP extensions. Same code behind all of them.

## 📦 Install

```bash
pnpm add @agntn/keys
```

Node.js 26 or newer. Pure JavaScript all the way down, nothing to compile.

## 🚀 First wallet

```ts
import { blockchains, useBlockchain } from "@agntn/keys";

const eth = useBlockchain(await blockchains.ethereum()());
console.log(eth.generateWallet());
```

```
{
  keys: {
    private: 'ac959e31102bc6ac0c9404f162d79ef83d4c2542efe6ad760fe9def09367c912',
    public: '02c162cbe709894b813b9c107c6021bb875ba6c86a1628a17c97a75103686131a1'
  },
  address: '0xf322A26408EcE18b4b4b41f3923E3B325954e8CA'
}
```

That private key now lives in a README on GitHub. Most burned key you'll see today. Good, that's the only kind this package is for. The double call is the lazy loader: the first takes options, the second imports the chain. No network anywhere, it's all math.

The most public mnemonic on earth, one path per address type:

```ts
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const btc = useBlockchain(await blockchains.bitcoin()());

for (const path of ["m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/0/0", "m/86'/0'/0'/0/0"]) {
  console.log(path, btc.deriveHDWallet(mnemonic, { path }).address);
}
```

```
m/44'/0'/0'/0/0 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
m/49'/0'/0'/0/0 37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf
m/84'/0'/0'/0/0 bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
m/86'/0'/0'/0/0 bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
```

Nobody passed an address type. 44 is legacy, 49 is P2SH, 84 is segwit, 86 is taproot. The path already said which one you meant. Disagree with your own path? Put `addressType` right next to it.

Only have the public half? The account's extended public key walks the normal levels under it:

```ts
const zpub =
  "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
console.log(btc.deriveXpubWallet(zpub, { path: "m/0/0" }));
```

```
{
  keys: {
    public: '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c'
  },
  address: 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu',
  prefix: 'zpub',
  addressType: 'segwit'
}
```

Same address as `m/84'/0'/0'/0/0` above, and the `z` picked segwit. Don't lean on that too hard. Plenty of wallets export a BIP84 account as a plain `xpub`, so pass `addressType: "segwit"` with the path. Hardened levels and `xprv` get refused.

## 🧠 Library

```ts
import { blockchains, useBlockchain } from "@agntn/keys";
import { convertPublicKey } from "@agntn/keys/secp256k1";
import { encode } from "@agntn/keys/wif";

const sol = useBlockchain(await blockchains.solana()());
const wallet = sol.deriveHDWallet(mnemonic, { path: "m/44'/501'/0'/0'", passphrase: "TREZOR" });
const signature = sol.signMessage("hello", { privateKey: wallet.keys.private });
sol.verifyMessage("hello", { signature, publicKey: wallet.keys.public }); // true
sol.validateAddress(wallet.address); // true

const btc = useBlockchain(await blockchains.bitcoin()());
const { keys } = btc.generateWallet();
encode(keys.private, { chain: "bitcoin" }); // WIF, K... or L..., compressed
convertPublicKey(keys.public, { compressed: false }); // 04..., 130 hex chars
```

There isn't much more to it. Every chain has `generateKeyPrivate`, `getKeyPublic`, `getAddress`, `validateAddress`, `signMessage` and `verifyMessage`. One trap: a legacy address hashes the public key bytes. Compressed and uncompressed give two addresses from one key, so keep the `compressed` flag next to it. Checking an Ethereum signature with ethers? Sign with `{ recovered: true }`. Skip it and ethers reads your 64 bytes as EIP-2098 compact, then answers with the wrong address instead of an error. Everything else: [Keys](https://keys.agntn.dev/guide/keys), [Addresses](https://keys.agntn.dev/guide/addresses), [Wallets](https://keys.agntn.dev/guide/wallets), [EVM chains](https://keys.agntn.dev/guide/evm).

## 🧩 Puzzles

A puzzle mnemonic with a broken checksum is not a wrong answer, it's Tuesday. The [claimed Movie Enigma solution](https://github.com/floflo777/open-crypto-puzzles/issues/24) has one:

```ts
import { inspect, getMnemonicWordCandidates } from "@agntn/keys/bip39";

const puzzle =
  "path mad alien apology escape spare miss goddess leopard crime visit clock start first blade guard close barrel term screen matrix toy ghost shine";

console.log(inspect(puzzle));
const wallet = btc.deriveHDWallet(puzzle, { path: "m/84'/0'/0'/0/0", allowInvalidChecksum: true });
console.log(wallet.address);
console.log(wallet.warnings);
console.log(getMnemonicWordCandidates(puzzle.replace(/shine$/, "?")));
```

```
{
  valid: false,
  words: 24,
  wordCountValid: true,
  wordlistValid: true,
  checksumValid: false
}
bc1q94ecsn0qk8lap2gefrycnms3ruepy889z969a6
[
  'BIP39 checksum is invalid. Derived from the supplied words without repairing the checksum.'
]
[
  'aware',  'divide',
  'embark', 'globe',
  'pact',   'roof',
  'solve',  'today'
]
```

Without the flag `deriveHDWallet` throws. With it you get the wallet, a warning and your words exactly as given. The checksum would take eight last words, and `shine` isn't one of them. Each of the eight opens a different wallet. That's how a "fixed" mnemonic loses a puzzle, so the fixing stays with you.

Holding something else? Here's what to reach for. Every module below lives under `@agntn/keys/`.

| You've got                                 | Library                                                    | Agent tool                                                            | More                                                                                       |
| ------------------------------------------ | ---------------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| Four letters off a steel plate             | `lookupPrefixes` in `bip39`                                | `keys_bip39_words_lookup`                                             | [Wallets](https://keys.agntn.dev/guide/wallets#only-four-letters-on-the-plate)             |
| `yelow`, copied off a photo                | `repairWords` in `bip39`                                   | `keys_bip39_words_repair`                                             | [Wallets](https://keys.agntn.dev/guide/wallets#copied-from-a-photo)                        |
| The right words, one per clue, no order    | `orderWords` in `bip39`                                    | `keys_bip39_words_order`                                              | [Wallets](https://keys.agntn.dev/guide/wallets#one-word-per-clue)                          |
| The right words and still no coins         |                                                            | `keys_hd_wallet_scan`                                                 | [Wallets](https://keys.agntn.dev/guide/wallets#which-path-was-it)                          |
| An Electrum seed                           | `deriveSeed` in `electrum`                                 | `keys_electrum_wallet_derive`                                         | [Wallets](https://keys.agntn.dev/guide/wallets#electrum-is-a-different-scheme)             |
| A brainwallet phrase, salted or plain      | `derive` in `brainwallet`                                  | `keys_brainwallet_derive`                                             | [Wallets](https://keys.agntn.dev/guide/wallets#salted-brainwallets)                        |
| An xpub and one leaked child xprv          | `recoverParent` in `bip32`                                 | `keys_bip32_parent_recover`                                           | [Wallets](https://keys.agntn.dev/guide/wallets#one-leaked-child-opens-the-whole-account)   |
| A `6P...` key                              | `decrypt` in `bip38`                                       | `keys_bip38_decrypt`                                                  | [Keys](https://keys.agntn.dev/guide/keys#bip38)                                            |
| A `UTC--...` keystore file                 | `decrypt` in `store`                                       | `keys_store_decrypt`                                                  | [Keys](https://keys.agntn.dev/guide/keys#keystore-files)                                   |
| An Arweave keyfile                         | `getAddress` in `arweave`                                  | `keys_arweave_address_get`                                            | [Keys](https://keys.agntn.dev/guide/keys#arweave-keyfiles)                                 |
| A signed message                           | `recoverMessageSigner` on the chain                        | `keys_message_recover`                                                | [EVM chains](https://keys.agntn.dev/guide/evm#who-signed-this)                             |
| A `bc1q` or `bc1p` proof                   | `verify` in `bip322`                                       | `keys_bip322_verify`                                                  | [Bitcoin](https://keys.agntn.dev/blockchains/bitcoin#proving-a-bc1-address-with-bip322)    |
| The same `r` on two signatures             | `extractSignatures` in `transaction`, `recoverReusedNonce` | `keys_transaction_signatures_extract`, `keys_secp256k1_nonce_recover` | [Bitcoin](https://keys.agntn.dev/blockchains/bitcoin#recovering-a-key-from-a-reused-nonce) |
| A multisig, a `redeemScript`, a descriptor | `script` and `descriptor`                                  | `keys_script_address_get`, `keys_descriptor_derive`                   | [Bitcoin](https://keys.agntn.dev/blockchains/bitcoin#multisig-and-other-scripts)           |

The tools that open a secret answer agents with an address, a public key or a fingerprint. BIP38 and the parent recovery hand over the key itself only with `revealKey: true`. And one trap no table shows: any well formed signature recovers some key for any message. Check the address match, not just that a key came out.

## ⛓️ Chains

| Chain            | Curve              | Address Formats                      | Testnet |
| ---------------- | ------------------ | ------------------------------------ | ------- |
| **Bitcoin**      | secp256k1          | legacy, p2sh, segwit, p2wsh, taproot | ✅      |
| **Bitcoin Cash** | secp256k1          | legacy P2PKH in CashAddr             | ✅      |
| **Bitcoin Gold** | secp256k1          | legacy, p2sh, segwit, p2wsh          | ✅      |
| **Bitcoin SV**   | secp256k1          | legacy P2PKH                         | ✅      |
| **Litecoin**     | secp256k1          | legacy, p2sh, segwit, p2wsh, taproot | ✅      |
| **Dash**         | secp256k1          | legacy P2PKH                         | ✅      |
| **Decred**       | secp256k1          | legacy ECDSA P2PKH                   | ✅      |
| **Dogecoin**     | secp256k1          | legacy P2PKH                         | ✅      |
| **Zcash**        | secp256k1          | transparent P2PKH                    | ✅      |
| **eCash**        | secp256k1          | legacy P2PKH in CashAddr             | ✅      |
| **Ethereum**     | secp256k1          | EIP-55 checksum                      | -       |
| **Base**         | secp256k1          | EVM-compatible                       | -       |
| **Solana**       | ed25519            | base58                               | -       |
| **Stellar**      | ed25519            | StrKey                               | -       |
| **Aptos**        | ed25519            | 0x-prefixed hex                      | -       |
| **Cardano**      | ed25519            | payment, stake, enterprise           | ✅      |
| **SUI**          | ed25519, secp256k1 | 0x-prefixed hex (blake2b)            | -       |
| **TRON**         | secp256k1          | base58check                          | ✅      |
| **XRP Ledger**   | secp256k1, ed25519 | classic `r` address (base58)         | -       |
| **NEAR**         | ed25519            | implicit account (hex)               | -       |
| **Cosmos**       | secp256k1          | bech32 under any prefix              | -       |
| **Polkadot**     | sr25519, ed25519   | SS58 under any network prefix        | ✅      |
| **Monero**       | ed25519            | standard, subaddress, integrated     | ✅      |
| **TON**          | ed25519            | v3r2, v4r2, v5r1 wallets, UQ and EQ  | ✅      |

Most of them need nothing past the loader. A few have opinions:

- Cosmos takes a `prefix`, so `blockchains.cosmos({ prefix: "osmo" })()` writes Osmosis addresses.
- Polkadot takes `ss58Prefix`, 2 for Kusama. It writes sr25519 like the wallets, until `addressType: "ed25519"` says otherwise.
- Monero, TON and the XRP Ledger restore from their own seeds through `deriveSeedWallet`.
- TON writes one address per wallet contract, so `addressType` picks `v4r2`, `v5r1` or `v3r2`.
- Decred and Cardano refuse `deriveHDWallet` on purpose.

Testnet is a constructor option, `blockchains.bitcoin({ network: "testnet" })()`, and segwit starts with `tb1q`. Per chain quirks: [Blockchains](https://keys.agntn.dev/blockchains).

## 💻 Terminal

```bash
npx @agntn/keys wallet-derive --chain bitcoin --private-key 0000000000000000000000000000000000000000000000000000000000000001
```

```
Address type: legacy
Public key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

Yes, that's private key 1, the most famous throwaway in Bitcoin. Every agent tool is a command too: `keys_wallet_derive` is `keys wallet-derive`. The flags come from the tool schema through `runCli` of [`@agntn/tools`](https://tools.agntn.dev/guide/cli), so `--help` can't drift from what MCP lists. Add `--json` for the details. Want the bare `keys`? `pnpm add -g @agntn/keys`. A real key typed here lands in your shell history.

## 🤖 Agents

```bash
npx -y @agntn/keys mcp
claude mcp add --transport http keys https://keys.agntn.dev/mcp # nothing to install
pi install npm:@agntn/keys
omp install @agntn/keys
```

```json
{
  "mcpServers": {
    "keys": { "command": "npx", "args": ["-y", "@agntn/keys", "mcp"] }
  }
}
```

Every tool runs on every one of these. The Pi and OMP extensions in [`extensions`](./extensions) call the same executors as the server. Ask for a mnemonic and this is the whole answer:

```
Language: english
Mnemonic: donate crumble bridge february pottery photo swear cactus tobacco timber climb elite
Words: 12
This mnemonic is saved in the transcript. Never use it for real funds.
```

That last line is not decoration. Keys, seeds and signatures cross the model's context as plain text and stay in the transcript. The [HTTP server](https://keys.agntn.dev/guide#remote-mcp) adds a Cloudflare worker on the way. Public puzzle material and throwaway keys only.

## 🚫 What this does not do

Balances, transactions, broadcasting, anything that needs a node. [@agntn/explorers](https://github.com/agntn/explorers) reads chains and [@agntn/chains](https://github.com/agntn/chains) describes them, this one only makes keys. It doesn't keep them either. Where your keystore file lives is your call. Curve math moved out too: adding points or lifting an x lives in [@agntn/curves](https://github.com/agntn/curves), and `@agntn/keys/secp256k1` still hands out those functions. Keys keeps the keys.

## 🔐 Security

Curves and HD derivation come from [@paulmillr](https://github.com/paulmillr): [@noble/curves](https://github.com/paulmillr/noble-curves), [@scure/bip32](https://github.com/paulmillr/scure-bip32) and [@scure/bip39](https://github.com/paulmillr/scure-bip39), [micro-key-producer](https://github.com/paulmillr/micro-key-producer) for SLIP-10. Hashes come from our own [@agntn/hashes](https://github.com/agntn/hashes), plain TypeScript with no `node:crypto` underneath. Base encodings come from our own [@agntn/encodings](https://github.com/agntn/encodings), CashAddr and StrKey included. Random bytes come from `globalThis.crypto` through noble's `randomSecretKey`. No `node:` import in the library, so a browser bundle needs no shim. None of that makes this package audited.

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Generated and signed material is handled as plaintext. Treat every key it touches as burned the moment it is produced. Generate fresh throwaway keys for testing only and assume anything passing through `@agntn/keys` is compromised. Keys that control real funds belong on a hardware wallet, never in a process, log, or agent transcript.

## ➕ Adding a chain

Want a twenty-fifth? Extend `AbstractBlockchain`, or `AbstractEVMBlockchain` if it's EVM, where a `name` and a `bip44` coin type is the whole class. Register it in the lazy loader and mirror a test file. The docs site lists chains by hand, so the [checklist](./CONTRIBUTING.md#adding-a-chain) covers that too. Walkthrough: [Creating custom blockchains](https://keys.agntn.dev/guide/custom).

## 🛠️ Development

```bash
pnpm install
pnpm --dir docs install   # the /mcp test borrows Zod and the toolkit from here
pnpm dev          # vp test in watch mode
pnpm lint         # builds first, then vp lint and vp fmt --check
pnpm test:types   # tsc over the library and the type tests, vue-tsc over the docs app
pnpm build        # obuild
pnpm test:mcp     # builds, then calls every tool over stdio
pnpm playground playground/bip39-demo.ts
```

## 💛 Thanks

Building this package was possible thanks to the open source programs from Anthropic and OpenAI, [Claude for Open Source](https://claude.com/contact-sales/claude-for-oss) and [Codex for Open Source](https://developers.openai.com/community/codex-for-oss) <3

## 📄 License

[MIT](./LICENSE.md)
