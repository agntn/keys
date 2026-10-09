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

Every chain has its own wallet library and its own idea of what a key is. One wants a Buffer, one wants a Uint8Array, one has a KeyPair class and a second one for testnet. Then a mnemonic shows up from a puzzle instead of a wallet app and all of them answer "invalid checksum" and stop talking to you. So this is one `Blockchain` interface over noble curves, the same `generateWallet()` on every chain, and the puzzle cases live in the API instead of in a fork.

The docs live at [keys.agntn.dev](https://keys.agntn.dev), keyspace explorer included.

## ✨ Features

- ⛓️ **A pile of chains, one interface.** Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Dash, Decred, Dogecoin, Zcash, eCash, Ethereum, Base, Solana, Stellar, Aptos, Cardano, Sui, TRON, the XRP Ledger, NEAR, Cosmos, Polkadot and Monero, each a class with the same methods on it.
- 🧬 **Two curves.** secp256k1 and ed25519, and Sui and the XRP Ledger will take either.
- 🌌 **Every Cosmos chain in one class.** `blockchains.cosmos({ prefix: "osmo" })()` and the Hub's key comes out as an Osmosis address. Say `terra` and the path moves to Terra's coin type 330 as well, so nobody has to remember it.
- 🟣 **Polkadot, Kusama, any Substrate chain.** SS58 under the network number you pick, and BIP39 words walk `//hard` junctions like subkey does. ed25519 for now, sr25519 is next in line.
- 🕶️ **Monero from its 25 words.** `deriveSeedWallet` restores the spend key, the view key and the `4...` address. Only the first three letters of each word count, the same as in monero-wallet-cli.
- 🌊 **XRP family seeds.** Paste an `s...` or `sEd...` secret into `deriveSeedWallet` and get the wallet rippled would, genesis account included.
- 🏠 **Bitcoin the way Bitcoin wants it.** Legacy, P2SH, segwit, P2WSH and taproot, testnet included, and the purpose level of your path picks the type for you.
- 🌱 **Mnemonic in, wallet out.** BIP39 into BIP32 on secp256k1 and SLIP-10 on ed25519, passphrase optional.
- 👀 **An xpub is enough to watch.** Hand over an account's xpub, ypub or zpub and get the address at `m/0/5`, no secret anywhere in the call.
- 🧩 **Puzzle mnemonics are welcome.** Wrong checksum? Derive anyway and get a warning with the wallet, or ask which words would make it valid.
- 🌍 **All ten BIP39 word lists.** Look a word up in Italian, generate in Japanese with the ideographic spaces, map indices from base 0 or base 1.
- ✍️ **Signing on both curves.** Bitcoin, Bitcoin Cash, Bitcoin Gold, Bitcoin SV, Litecoin, Dash, Decred, Dogecoin, Zcash and eCash hash the message the way Core does, EVM chains the way ethers does, TRON the way TronWeb's `signMessageV2` does, Sui the way the Sui SDK's `signPersonalMessage` does on either curve, Stellar the way the Stellar SDK's `signMessage` does under SEP-53, the XRP Ledger the way ripple-keypairs does, DER on secp256k1, Cosmos the way Keplr's `signArbitrary` does under ADR-036, Polkadot the way the polkadot.js extension's `signRaw` does, and Solana, Aptos, Cardano and NEAR sign the raw bytes. By default you get 64 bytes of compact `r||s` hex.
- 🔁 **The signer rides along.** `{ recovered: true }` gives 65 bytes of `r||s||v` on Ethereum, Base and TRON, and the base64 `bitcoin-cli signmessage` prints on the Bitcoin family and Decred. Skip it on Ethereum and ethers reads your 64 bytes as EIP-2098 compact, then answers with the wrong address instead of an error.
- 🔌 **Loads one chain at a time.** `blockchains.solana()()` imports Solana and nothing else, so a Bitcoin tool never pays for Cardano.
- 🤖 **Tools for your agent.** MCP over stdio, MCP over HTTP from [keys.agntn.dev/mcp](https://keys.agntn.dev/guide#remote-mcp) and a Pi extension run the same code, and a generated mnemonic comes back with a note that it's in the transcript now.

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

Nobody passed an address type. 44 is legacy, 49 is P2SH, 84 is segwit, 86 is taproot, the path already says which one you meant, and the wallet hands it back as `addressType`. You can still pass one as the fourth argument if you disagree with your own path.

Only have the public half? The account's extended public key walks the normal levels under it:

```ts
const zpub =
  "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
console.log(btc.deriveXpubWallet(zpub, "m/0/0"));
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

Same address as `m/84'/0'/0'/0/0` above, and the `z` picked segwit. Don't lean on that too hard. Plenty of wallets export a BIP84 account as a plain `xpub`, and then the prefix says legacy while the coins sit on segwit. Pass `"segwit"` as the third argument. Hardened levels and `xprv` get refused, this path never sees a secret.

Careful with that xpub, though. Leak the private key of one normal child next to it and the parent is gone. `recoverParent(xpub, childXprv)` from `@agntn/keys/bip32` hands back the parent xprv, and every sibling with it. Agents get `keys_bip32_parent_recover`. Parent fingerprint only, unless they ask with `revealKey: true`. Hardened children are safe. More: [Wallets](https://keys.agntn.dev/guide/wallets).

Looking for curve math? It packed its bags. Adding two public keys, lifting an x, the order of a point on a toy curve over F17: that all lives in [@agntn/curves](https://github.com/agntn/curves) now, agent tools included. `@agntn/keys/secp256k1` and `@agntn/keys/curve` still hand out the same functions, borrowed from there. Keys keeps the keys.

## 🧠 Library

```ts
import { blockchains, useBlockchain } from "@agntn/keys";
import { convertPublicKey } from "@agntn/keys/secp256k1";
import { encode } from "@agntn/keys/wif";

const sol = useBlockchain(await blockchains.solana()());
const wallet = sol.deriveHDWallet(mnemonic, "m/44'/501'/0'/0'", { passphrase: "TREZOR" });
const signature = sol.signMessage("hello", wallet.keys.private);
sol.verifyMessage("hello", signature, wallet.keys.public); // true
sol.validateAddress(wallet.address); // true

const btc = useBlockchain(await blockchains.bitcoin()());
const { keys } = btc.generateWallet();
encode(keys.private, { chain: "bitcoin" }); // WIF, K... or L..., compressed
convertPublicKey(keys.public, { compressed: false }); // 04..., 130 hex chars
```

There isn't much more to it. Every chain has `generateKeyPrivate`, `getKeyPublic`, `getAddress`, `validateAddress`, `signMessage` and `verifyMessage`, the HD walk is BIP32 on secp256k1 and SLIP-10 on ed25519, so Solana paths are hardened all the way down. Ethereum and Base give the same address for the same key, as they should. WIF goes both ways on Bitcoin, Litecoin, Dash, Decred and Dogecoin through `@agntn/keys/wif`, and `convertPublicKey` from `@agntn/keys/secp256k1` flips compressed to uncompressed and back. Mind that a legacy address hashes those bytes, so the two encodings are two different addresses from one key, keep the `compressed` flag next to it. Everything else, traps included: [Keys](https://keys.agntn.dev/guide/keys), [Addresses](https://keys.agntn.dev/guide/addresses), [Wallets](https://keys.agntn.dev/guide/wallets), [EVM chains](https://keys.agntn.dev/guide/evm).

## 🧩 Puzzles

A puzzle mnemonic with a broken checksum is not a wrong answer, it's Tuesday. The [claimed Movie Enigma solution](https://github.com/floflo777/open-crypto-puzzles/issues/24) has one:

```ts
import { inspect, getMnemonicWordCandidates } from "@agntn/keys/bip39";

const puzzle =
  "path mad alien apology escape spare miss goddess leopard crime visit clock start first blade guard close barrel term screen matrix toy ghost shine";

console.log(inspect(puzzle));
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

`inspect` splits the verdict three ways, count, dictionary and checksum, so you see which one failed. All ten lists work everywhere, the candidate filter included. Pass `wordlist: await loadWordlist("italian")` and `deriveHDWallet` takes an Italian phrase. `lookupWords(["orologio", "civetta"], "italian")` finds orologio at 1178 and civetta at 361, counting from zero. And `generateMnemonic(128, await loadWordlist("japanese"))` hands you a Japanese phrase with the ideographic spaces the spec asks for, no reaching into the raw codec. The flag in the docs: [Wallets](https://keys.agntn.dev/guide/wallets).

Got the words but not the order? Puzzles that hand out one word per clue do that. `orderWords` from `@agntn/keys/bip39` tries every order of the loose words. Only the orders that pass the checksum come out, about 1 in 16 for twelve words. Four letters off a steel plate? `lookupPrefixes` turns `abou` back into `about`. Agents get `keys_bip39_words_order`, a million orders per call at most. `keys_bip39_words_lookup` reads prefixes without being asked. More: [Wallets](https://keys.agntn.dev/guide/wallets).

Copied the phrase off a photo and got `yelow`? `repairWords` tries the list words a few edits away. A typo counts as one. So does a swap, or an OCR slip like `rn` for `m`. Whatever passes the checksum comes out, fewest edits first. A wrong word that's still a real word gets through, nothing marks it. Agents get `keys_bip39_words_repair`, two bad words per call. More: [Wallets](https://keys.agntn.dev/guide/wallets).

Right words and still no coins? Usually it's the path. `keys_hd_wallet_scan` walks the usual suspects for agents: `bip44` to `bip86`, Ledger Live, a native Electrum seed, a few accounts and indices each. It answers with the path that hit. Or with every scheme it tried, so a miss says exactly what it ruled out. Nothing outside that list. More: [Wallets](https://keys.agntn.dev/guide/wallets).

Brainwallets are a puzzle favorite too, and the salted kind hides a trap. brainwallet.io runs scrypt, then SHA-256 over the hex of the result, not its bytes. Miss that and you get a valid key to the wrong address. `derive` from `@agntn/keys/brainwallet` takes the whole recipe: KDF, costs, salt and what SHA-256 reads. The old plain kind is just `kdf: "sha256"`, or `"keccak256"` for Ethereum. WarpWallet is `kdf: "warpwallet"` plus a salt, scrypt and PBKDF2 XORed at its own fixed costs. Agents get `keys_brainwallet_derive`. It answers with the public key, the address and a match against your target. Never the private key. Recipes: [Wallets](https://keys.agntn.dev/guide/wallets).

Got an old `UTC--...` file from MyEtherWallet or geth? That's a keystore, and `@agntn/keys/store` opens it. `decrypt(file, password)` gives the key back, `encrypt` writes a new file, `inspect` reads the KDF without a password. Agents get `keys_store_decrypt`. It says whether the password fits and gives the address, never the key. More: [Keys](https://keys.agntn.dev/guide/keys).

A `6P...` key is the same story with BIP38. `decrypt(key, passphrase)` from `@agntn/keys/bip38` gives the WIF and the address, both modes. A wrong passphrase throws, `inspect` reads the header without one. Agents get `keys_bip38_decrypt`. Address only, unless they ask for the WIF with `revealKey: true`. More: [Keys](https://keys.agntn.dev/guide/keys).

And a signed message is a clue. Somebody proves they hold an address with `signmessage`? That base64 gives away the public key behind it. `btc.recoverMessageSigner(message, signature)` reads it back. Ethereum, Base and TRON do the same with 65 bytes of `r||s||v`. EIP-712? `hashTypedData` builds the digest and `recoverDigestSigner` takes it from there. `keys_message_recover` does all of that for agents. Any well formed signature recovers some key for any message, though. So check the address match, not just that a key came out.

Core's `signmessage` stops at P2PKH. A `bc1q` or `bc1p` address proves itself with BIP322 instead. `verify(address, message, signature)` from `@agntn/keys/bip322` answers `valid`, `invalid` or `inconclusive`, and says why. Multisig and script paths land on `inconclusive`. No guessing. `sign` writes one for your own key. Agents get `keys_bip322_verify` and `keys_bip322_sign`. More: [Bitcoin](https://keys.agntn.dev/blockchains/bitcoin).

Same `r` on two signatures? Somebody reused a nonce, and the key falls right out. `extractSignatures` from `@agntn/keys/transaction` reads `r`, `s` and the sighash `z` of a transaction input. Legacy, SegWit and Taproot key path, every hash type. `recoverReusedNonce` from `@agntn/keys/secp256k1` takes two of those and hands back the key. Only after it verifies both, though. Agents get `keys_transaction_signatures_extract` and `keys_secp256k1_nonce_recover`, which names the public key and nothing more. More: [Bitcoin](https://keys.agntn.dev/blockchains/bitcoin).

Not every prize sits behind one key. A 2-of-2 or a published `redeemScript` pays to a script. `multisig` and `address` from `@agntn/keys/script` give its P2SH, P2WSH or P2SH-P2WSH address, keys in order or sorted as BIP67 sorts them. Got a descriptor from a wallet export? `parse` from `@agntn/keys/descriptor` reads `pkh`, `wpkh`, `sh`, `wsh` and `tr`, checks the `#checksum` and derives any index. Agents get `keys_script_address_get` and `keys_descriptor_derive`. More: [Bitcoin](https://keys.agntn.dev/blockchains/bitcoin).

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
| **Polkadot**     | ed25519            | SS58 under any network prefix        | ✅      |
| **Monero**       | ed25519            | standard address (block base58)      | ✅      |

Decred and Cardano throw on `deriveHDWallet`, on purpose, `deriveWallet` with a private key works on both. Sui is ed25519 unless you ask for secp256k1. The XRP Ledger goes the other way, secp256k1 unless you ask or its `sEd...` seed does. NEAR doesn't even encode: the account is the public key in hex, and `getAddress` reads NEAR's own `ed25519:` form too. Cosmos takes a `prefix` next to `network`, so `blockchains.cosmos({ prefix: "celestia" })()` writes Celestia addresses, and `coinType` for a wallet that left the chain's own path. Polkadot takes `ss58Prefix`, 2 for Kusama, and its testnet is the generic 42. Monero takes `stagenet` next to `testnet`, signs nothing yet and wants its seed in `deriveSeedWallet`, not `deriveHDWallet`. Testnet is a constructor option, `blockchains.bitcoin({ network: "testnet" })()` and your segwit addresses start with `tb1q`. Chain pages with prefixes and testnets: [Blockchains](https://keys.agntn.dev/blockchains).

## 💻 Terminal

```bash
npx @agntn/keys wallet-derive --chain bitcoin --private-key 0000000000000000000000000000000000000000000000000000000000000001
```

```
Address type: legacy
Public key: 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Address: 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
```

Every agent tool is a command too. `keys_wallet_derive` is `keys wallet-derive`, `keys_bip39_inspect` is `keys bip39-inspect`. Where do the flags come from? The tool schema, through `runCli` of [`@agntn/tools`](https://tools.agntn.dev/guide/cli). So `--help` can't drift from what MCP lists. You read what a model reads, and `--json` prints the details. Yes, that's private key 1, the most famous throwaway in Bitcoin. A real key typed here lands in your shell history. Throwaway keys only.

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

Every tool from `keys_electrum_wallet_derive` through `keys_bip44_generate` runs here, and the Pi and OMP extensions in [`packages`](./packages) run the exact same executors, installed from npm or from a checkout. Ask for a mnemonic and this is the whole answer:

```
Language: english
Mnemonic: problem install faint crime flee local figure deny hurdle ten dragon search
Words: 12
This mnemonic is saved in the transcript. Never use it for real funds.
```

That last line is not decoration. Keys, seeds, signatures, all of it crosses the model's context as plain text and stays in the transcript. Public puzzle material and throwaway keys only, the same rule as everywhere else in this package. The HTTP server adds one more hop, since every argument goes through a Cloudflare worker on its way to the tool.

## 🚫 What this does not do

Balances, transactions, broadcasting, anything that needs a node. [@agntn/explorers](https://github.com/agntn/explorers) reads chains and [@agntn/chains](https://github.com/agntn/chains) describes them, this one only makes keys. It doesn't keep them either. A private key here is a hex string in a variable, and WIF is just another spelling of it. `@agntn/keys/store` reads and writes keystore files, but where that file lives is your call, not ours.

## 🔐 Security

Curves and HD derivation come from [@paulmillr](https://github.com/paulmillr): [@noble/curves](https://github.com/paulmillr/noble-curves), [@scure/bip32](https://github.com/paulmillr/scure-bip32) and [@scure/bip39](https://github.com/paulmillr/scure-bip39), [micro-key-producer](https://github.com/paulmillr/micro-key-producer) for SLIP-10. Hashes come from our own [@agntn/hashes](https://github.com/agntn/hashes), plain TypeScript with no `node:crypto` underneath. Base encodings come from our own [@agntn/encodings](https://github.com/agntn/encodings) too, CashAddr and Stellar's StrKey included. Random bytes come from `globalThis.crypto` through noble's `randomSecretKey`, so there's no `node:` import in the library and a browser bundle needs no shim. None of that makes this package audited, the caution at the top still stands.

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Generated and signed material is handled as plaintext. Treat every key it touches as burned the moment it is produced. Generate fresh throwaway keys for testing only and assume anything passing through `@agntn/keys` is compromised. Keys that control real funds belong on a hardware wallet, never in a process, log, or agent transcript.

## ➕ Adding a chain

Want a nineteenth? Extend `AbstractBlockchain`, or `AbstractEVMBlockchain` if it's EVM, where a `name` and a `bip44` coin type is the whole class. Register it in the lazy loader, mirror the test file, done. Walkthrough: [Creating custom blockchains](https://keys.agntn.dev/guide/custom).

## 🛠️ Development

```bash
pnpm install
pnpm --dir docs install   # the /mcp test borrows Zod and the toolkit from here
pnpm dev          # vp test in watch mode
pnpm lint         # builds first, then vp lint and vp fmt --check
pnpm test:types   # tsc over the library and the type tests
pnpm build        # obuild
pnpm test:mcp     # builds, then calls every tool over stdio
pnpm playground playground/bip39-demo.ts
```

## 💛 Thanks

Building this package was possible thanks to the open source programs from Anthropic and OpenAI, [Claude for Open Source](https://claude.com/contact-sales/claude-for-oss) and [Codex for Open Source](https://developers.openai.com/community/codex-for-oss) <3

## 📄 License

[MIT](./LICENSE.md)
