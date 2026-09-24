# @agntn/keys

[![npm version](https://npmx.dev/api/registry/badge/version/@agntn/keys)](https://npmx.dev/package/@agntn/keys)
[![npm downloads](https://npmx.dev/api/registry/badge/downloads/@agntn/keys)](https://npmx.dev/package/@agntn/keys)
[![license](https://npmx.dev/api/registry/badge/license/@agntn/keys)](https://npmx.dev/package/@agntn/keys)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/agntn/keys)

🔑 Keys, addresses and signatures for fifteen chains, from a mnemonic or from nothing at all. Bitcoin gets its five address types, Solana gets ed25519, your agent gets 19 tools, and none of it should ever meet real money.

> [!WARNING]
> **@agntn/keys is experimental.** The public API and the tool surfaces can still move before the first stable release. Pin exact versions if you build on it now.

## Why?

Every chain has its own wallet library and its own idea of what a key is. One wants a Buffer, one wants a Uint8Array, one has a KeyPair class and a second one for testnet. Then a mnemonic shows up from a puzzle instead of a wallet app and all of them answer "invalid checksum" and stop talking to you. So this is one `Blockchain` interface over noble curves, the same `generateWallet()` on every chain, and the puzzle cases live in the API instead of in a fork.

The docs live at [keys.agntn.dev](https://keys.agntn.dev), keyspace explorer included.

## ✨ Features

- ⛓️ **Fifteen chains, one interface.** Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Decred, Dogecoin, Ethereum, Base, Solana, Stellar, Aptos, Cardano, Sui and TRON, each a class with the same methods on it.
- 🧬 **Two curves.** secp256k1 and ed25519, and Sui will take either.
- 🏠 **Bitcoin the way Bitcoin wants it.** Legacy, P2SH, segwit, P2WSH and taproot, testnet included, and the purpose level of your path picks the type for you.
- 🌱 **Mnemonic in, wallet out.** BIP39 into BIP32 on secp256k1 and SLIP-10 on ed25519, passphrase optional.
- 🧩 **Puzzle mnemonics are welcome.** Wrong checksum? Derive anyway and get a warning with the wallet, or ask which words would make it valid.
- 🌍 **All ten BIP39 word lists.** Look a word up in Italian, generate in Japanese with the ideographic spaces, map indices from base 0 or base 1.
- ✍️ **Signing on both curves.** Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Decred and Dogecoin hash the message the way Core does, EVM chains the way ethers does, TRON the way TronWeb's `signMessageV2` does, Sui the way the Sui SDK's `signPersonalMessage` does on either curve, Stellar the way the Stellar SDK's `signMessage` does under SEP-53, and Solana, Aptos and Cardano sign the raw bytes. What comes back is 64 bytes of compact `r||s` hex, so it's not Core's base64.
- 🔁 **`v` when you need it.** `{ recovered: true }` on Ethereum, Base or TRON gives 65 bytes of `r||s||v`, byte for byte what ethers and TronWeb produce. Skip it and ethers reads your 64 bytes as an EIP-2098 compact signature and answers with the wrong address instead of an error.
- 🔌 **Loads one chain at a time.** `blockchains.solana()()` imports Solana and nothing else, so a Bitcoin tool never pays for Cardano.
- 🤖 **19 agent tools.** MCP over stdio and a Pi extension run the same code, and a generated mnemonic comes back with a note that it's in the transcript now.

## 📦 Install

```bash
pnpm add @agntn/keys
```

Node.js 24 or newer. Pure JavaScript all the way down, nothing to compile.

## 🚀 First wallet

```ts
import { blockchains, useBlockchain } from "@agntn/keys";

const eth = useBlockchain(await blockchains.ethereum()());
console.log(eth.generateWallet());
```

```
{
  keys: {
    private: 'ce4d2129932b3d254d080c5d2cd6d23ed450c59d01718602ee7b2defd118c089',
    public: '027d45d17b53cbbd7e94562b96adfce14689ade4d47a5b058dce2b83c08d9563fa'
  },
  address: '0xc792A6d3c616EfDc6684e5C82cd9397E35B50846'
}
```

That private key now lives in a README on GitHub, which makes it the most burned key you'll see today. Good, that is the only kind this package is for, see the caution at the bottom. The double call is the lazy loader: `blockchains.ethereum(options)` takes the config, the second `()` imports the chain and builds it. No network anywhere, it's all math, so it runs the same offline. Browsers are another story, see Security.

The most public mnemonic on earth, one path per address type:

```ts
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const btc = useBlockchain(await blockchains.bitcoin()());

for (const path of ["m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0", "m/84'/0'/0'/0/0", "m/86'/0'/0'/0/0"]) {
  console.log(path, btc.deriveHDWallet(mnemonic, path).address);
}
```

```
m/44'/0'/0'/0/0 1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA
m/49'/0'/0'/0/0 37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf
m/84'/0'/0'/0/0 bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu
m/86'/0'/0'/0/0 bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
```

Nobody passed an address type. 44 is legacy, 49 is P2SH, 84 is segwit, 86 is taproot, the path already says which one you meant. You can still pass one as the fourth argument if you disagree with your own path.

## 🧠 Library

```ts
import { blockchains, useBlockchain, encodeWIF, convertSecp256k1PublicKey } from "@agntn/keys";

const sol = useBlockchain(await blockchains.solana()());
const wallet = sol.deriveHDWallet(mnemonic, "m/44'/501'/0'/0'", { passphrase: "TREZOR" });
const signature = sol.signMessage("hello", wallet.keys.private);
sol.verifyMessage("hello", signature, wallet.keys.public); // true
sol.validateAddress(wallet.address); // true

const btc = useBlockchain(await blockchains.bitcoin()());
const { keys } = btc.generateWallet();
encodeWIF(keys.private, { chain: "bitcoin" }); // K... or L..., compressed
convertSecp256k1PublicKey(keys.public, { compressed: false }); // 04..., 130 hex chars
```

There isn't much more to it. Every chain has `generateKeyPrivate`, `getKeyPublic`, `getAddress`, `validateAddress`, `signMessage` and `verifyMessage`, the HD walk is BIP32 on secp256k1 and SLIP-10 on ed25519, so Solana paths are hardened all the way down. Ethereum and Base give the same address for the same key, as they should. WIF goes both ways on Bitcoin, Litecoin and Decred, and `convertSecp256k1PublicKey` flips compressed to uncompressed and back. Mind that a legacy address hashes those bytes, so the two encodings are two different addresses from one key, keep the `compressed` flag next to it. Everything else, traps included: [Keys](https://keys.agntn.dev/guide/keys), [Addresses](https://keys.agntn.dev/guide/addresses), [Wallets](https://keys.agntn.dev/guide/wallets), [EVM chains](https://keys.agntn.dev/guide/evm).

## 🧩 Puzzles

A puzzle mnemonic with a broken checksum is not a wrong answer, it's Tuesday. The [claimed Movie Enigma solution](https://github.com/floflo777/open-crypto-puzzles/issues/24) has one:

```ts
import { inspectBIP39Mnemonic, getMnemonicWordCandidates } from "@agntn/keys/bip39";

const puzzle =
  "path mad alien apology escape spare miss goddess leopard crime visit clock start first blade guard close barrel term screen matrix toy ghost shine";

console.log(inspectBIP39Mnemonic(puzzle));
const wallet = btc.deriveHDWallet(puzzle, "m/84'/0'/0'/0/0", { allowInvalidChecksum: true });
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

Without the flag `deriveHDWallet` throws. With it you get the wallet and a warning, the words exactly as given, nothing repaired. Ask the checksum which last words it would accept and you get eight, `shine` is not one of them, and each of the eight opens a different wallet. That is how a "fixed" mnemonic loses a puzzle, so the fixing stays with you, not with the library.

`inspectBIP39Mnemonic` splits the verdict three ways, count, dictionary and checksum, so you see which one failed. The candidate filter and `deriveHDWallet` are English only. The other nine word lists are there for lookups and generation: `lookupBIP39Words(["orologio", "civetta"], "italian")` finds them, orologio at 1178 and civetta at 361 counting from zero, and `loadBIP39Wordlist("japanese")` fed to the `bip39` codec gives you mnemonics with the ideographic spaces the spec asks for. The flag in the docs: [Wallets](https://keys.agntn.dev/guide/wallets).

## ⛓️ Chains

| Chain            | Curve              | Address Formats                      | Testnet |
| ---------------- | ------------------ | ------------------------------------ | ------- |
| **Bitcoin**      | secp256k1          | legacy, p2sh, segwit, p2wsh, taproot | ✅      |
| **Bitcoin Cash** | secp256k1          | legacy P2PKH in CashAddr             | ✅      |
| **Bitcoin Gold** | secp256k1          | legacy, p2sh, segwit, p2wsh          | ✅      |
| **Bitcoin SV**   | secp256k1          | legacy P2PKH                         | ✅      |
| **Litecoin**     | secp256k1          | legacy, p2sh, segwit, p2wsh, taproot | ✅      |
| **Decred**       | secp256k1          | legacy ECDSA P2PKH                   | ✅      |
| **Dogecoin**     | secp256k1          | legacy P2PKH                         | ✅      |
| **Ethereum**     | secp256k1          | EIP-55 checksum                      | -       |
| **Base**         | secp256k1          | EVM-compatible                       | -       |
| **Solana**       | ed25519            | base58                               | -       |
| **Stellar**      | ed25519            | StrKey                               | -       |
| **Aptos**        | ed25519            | 0x-prefixed hex                      | -       |
| **Cardano**      | ed25519            | payment, stake, enterprise           | ✅      |
| **SUI**          | ed25519, secp256k1 | 0x-prefixed hex (blake2b)            | -       |
| **TRON**         | secp256k1          | base58check                          | ✅      |

Decred and Cardano throw on `deriveHDWallet`, on purpose, `deriveWallet` with a private key works on both. Sui is ed25519 unless you ask for secp256k1. Testnet is a constructor option, `blockchains.bitcoin({ network: "testnet" })()` and your segwit addresses start with `tb1q`. Chain pages with prefixes and testnets: [Blockchains](https://keys.agntn.dev/blockchains).

## 🤖 Agents

```bash
npx -y @agntn/keys mcp
```

```json
{
  "mcpServers": {
    "keys": { "command": "npx", "args": ["-y", "@agntn/keys", "mcp"] }
  }
}
```

19 tools, `keys_derive_electrum_wallet` through `keys_bip44_path`, and the Pi extension in [`packages/pi`](./packages/pi) runs the exact same executors from a checkout. Ask for a mnemonic and this is the whole answer:

```
Language: english
Mnemonic: problem install faint crime flee local figure deny hurdle ten dragon search
Words: 12
This mnemonic is saved in the transcript. Never use it for real funds.
```

That last line is not decoration. Keys, seeds, signatures, all of it crosses the model's context as plain text and stays in the transcript. Public puzzle material and throwaway keys only, the same rule as everywhere else in this package.

## 🚫 What this does not do

Balances, transactions, broadcasting, anything that needs a node. [@agntn/explorers](https://github.com/agntn/explorers) reads chains and [@agntn/chains](https://github.com/agntn/chains) describes them, this one only makes keys. It doesn't keep them either: no keystore, no encryption, a private key here is a hex string in a variable and WIF is just another spelling of it.

## 🔐 Security

Everything cryptographic comes from [@paulmillr](https://github.com/paulmillr): [@noble/curves](https://github.com/paulmillr/noble-curves) and [@noble/hashes](https://github.com/paulmillr/noble-hashes), [@scure/base](https://github.com/paulmillr/scure-base), [@scure/bip32](https://github.com/paulmillr/scure-bip32) and [@scure/bip39](https://github.com/paulmillr/scure-bip39), [micro-key-producer](https://github.com/paulmillr/micro-key-producer) for SLIP-10. Random bytes come from `globalThis.crypto` through noble's `randomSecretKey`, so there's no `node:` import in the library and a browser bundle needs no shim.

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Generated and signed material is handled as plaintext. Treat every key it touches as burned the moment it is produced. Generate fresh throwaway keys for testing only and assume anything passing through `@agntn/keys` is compromised. Keys that control real funds belong on a hardware wallet, never in a process, log, or agent transcript.

## ➕ Adding a chain

Want a fifteenth? Extend `AbstractBlockchain`, or `AbstractEVMBlockchain` if it's EVM, where a `name` and a `bip44` coin type is the whole class. Register it in the lazy loader, mirror the test file, done. Walkthrough: [Creating custom blockchains](https://keys.agntn.dev/guide/custom).

## 🛠️ Development

```bash
pnpm install
pnpm dev          # vp test in watch mode
pnpm lint         # builds first, then vp lint and vp fmt --check
pnpm test:types   # tsc over the library and the type tests
pnpm build        # vp pack
pnpm test:mcp     # builds, then calls all 19 tools over stdio
pnpm playground playground/bip39-demo.ts
```

## 💛 Thanks

Building this package was possible thanks to the open source programs from Anthropic and OpenAI, [Claude for Open Source](https://claude.com/contact-sales/claude-for-oss) and [Codex for Open Source](https://developers.openai.com/community/codex-for-oss) <3

## 📄 License

[MIT](./LICENSE.md)
