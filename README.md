# @agntn/keys

[![npm version](https://img.shields.io/npm/v/%40agntn%2Fkeys?style=flat&colorA=130f40&colorB=474787)](https://npmjs.com/package/@agntn/keys)
[![npm downloads](https://img.shields.io/npm/dm/%40agntn%2Fkeys?style=flat&colorA=130f40&colorB=474787)](https://npm.chart.dev/@agntn/keys)
[![license](https://img.shields.io/github/license/agntn/keys?style=flat&colorA=130f40&colorB=474787)](https://github.com/agntn/keys/blob/main/LICENSE.md)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/agntn/keys)

Typed key generation, address derivation, and message signing across ten blockchains and two curves.

> [!WARNING]
> **@agntn/keys is experimental.** The package name, public API, provider model, and tool surfaces may change before the first stable release. Pin exact versions if you build on it now.

## Features

- 🔑 **Key generation** - cryptographically secure private keys via Web Crypto API
- 📫 **Address generation** - all major formats per chain (legacy, segwit, taproot, base58, hex)
- ✅ **Address validation** - verify validity and checksums for every supported format
- 💼 **Wallet construction** - generate a new wallet, or derive one from a private key or from a BIP39 mnemonic and derivation path
- ✍️ **Message signing** - sign and verify with secp256k1 or ed25519
- 🛤️ **BIP44 paths** - derivation path utilities for all supported chains
- 🧩 **BIP39 puzzles** - validate phrases, narrow one missing word, and map words or indices across all 10 official lists
- 🔌 **Lazy loading** - blockchain implementations load on demand for smaller bundles
- 🤖 **MCP server** - the same 16 key, mnemonic, address, and signing tools over stdio
- 📐 **Fully typed** - TypeScript definitions for every interface

## Install

```bash
pnpm add @agntn/keys
```

## Usage

Concrete blockchain classes are lazy-loaded. The double-call pattern `blockchains.chain(options)()` first passes config, then imports and constructs the class.

### Generate a wallet

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const ethereum = await blockchains.ethereum()();
const chain = useBlockchain(ethereum);

const wallet = chain.generateWallet();
console.log(wallet.keys.private); // hex private key
console.log(wallet.keys.public); // hex public key
console.log(wallet.address); // 0x... checksum address
```

### Bitcoin address types

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const btc = useBlockchain(await blockchains.bitcoin()());

const privateKey = btc.generateKeyPrivate();
const publicKey = btc.getKeyPublic(privateKey);

btc.getAddress(publicKey); // legacy (1...)
btc.getAddress(publicKey, "segwit"); // native segwit (bc1q...)
btc.getAddress(publicKey, "taproot"); // taproot (bc1p...)
btc.getAddress(publicKey, "p2sh"); // pay-to-script-hash (3...)
btc.getAddress(publicKey, "p2wsh"); // witness script hash

// testnet
const testnet = useBlockchain(await blockchains.bitcoin({ network: "testnet" })());
testnet.getAddress(publicKey, "segwit"); // tb1q...
```

### Import and export WIF

```ts
import { encodeWIF, decodeWIF, blockchains } from "@agntn/keys";

const privateKey = "00".repeat(31) + "01";
const wif = encodeWIF(privateKey, { chain: "bitcoin" });
const decoded = decodeWIF(wif, { chain: "bitcoin" });
const btc = await blockchains.bitcoin()();
const wallet = btc.deriveWallet(decoded.privateKey, { compressed: decoded.compressed });
```

Choose `chain: "bitcoin"`, `"litecoin"` or `"decred"`, the three chains in this package with native WIF support. Both functions default to `network: "mainnet"`; pass `network: "testnet"` for testnet (testnet3 on Decred). `encodeWIF` takes exactly 64 hex characters without `0x` and defaults to `compressed: true`. Bitcoin and Litecoin also accept `compressed: false`. Decred uses its native BLAKE-256 checksum and ECDSA scheme, and rejects uncompressed exports or other signature schemes.

`decodeWIF` checks the selected chain/network and returns `{ privateKey, chain, network, compressed }`. Both functions reject invalid secp256k1 scalars; decoding also checks the checksum, payload length and compression marker. Bitcoin and Litecoin share a testnet prefix, so the returned chain is the requested context, not proof of ownership. Other chains, networks and BIP38 encrypted keys are not supported.

Agents can use `keys_encode_wif` and `keys_decode_wif` through MCP or Pi with the same chain/network choices. Encoding accepts `privateKey` and optional `compressed`; decoding accepts `wif`. Both return the converted secret and effective wallet options.

Preserve `compressed` when deriving a wallet: the same private key can produce a different address without it. WIF is not encryption. Use disposable test keys only.

### Litecoin

```ts
import { blockchains } from "@agntn/keys";

const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ltc = await blockchains.litecoin()();
const wallet = ltc.deriveHDWallet(mnemonic, "m/84'/2'/0'/0/0");
const testnet = await blockchains.litecoin({ network: "testnet" })();
```

Litecoin uses the same five address types as Bitcoin, with `L`/`M`/`ltc1` on mainnet and `m` or `n`/`Q`/`tltc1` on testnet. Old P2SH prefixes (`3` and `2`) are accepted, not generated. Those old addresses overlap with Bitcoin, so validation alone cannot identify the chain. MWEB and regtest are outside this implementation.

Message signing uses the Litecoin Core message digest and returns a compact signature of 64 bytes as hex, not Core's recoverable base64 format. Verify against the public key with `verifyMessage`.

### Decred

```ts
import { blockchains } from "@agntn/keys";

const dcr = await blockchains.decred()();
const wallet = dcr.generateWallet();
const testnet = await blockchains.decred({ network: "testnet" })();
```

Decred supports ECDSA P2PKH addresses (`legacy`), with `Ds` on mainnet and `Ts` on testnet3. Both compressed and uncompressed public keys work. Other address formats and signature schemes are outside this implementation.

Message signing uses the Decred message digest and returns 64 bytes of compact r/s as hex, not the recoverable base64 format used by dcrd. Use `verifyMessage` with the public key. `deriveHDWallet` throws: Decred's HD derivation strips leading zeros, so ordinary BIP32 is not a safe substitute. BIP44 path generation uses coin type 42, not the historical type 20.

### Sign and verify messages

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const chain = useBlockchain(await blockchains.solana()());

const { keys } = chain.generateKeys();
const signature = chain.signMessage("hello", keys.private);
const valid = chain.verifyMessage("hello", signature, keys.public); // true
```

### EVM chains share addresses

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const eth = useBlockchain(await blockchains.ethereum()());
const base = useBlockchain(await blockchains.base()());

const privateKey = eth.generateKeyPrivate();
const pubKey = eth.getKeyPublic(privateKey);

eth.getAddress(pubKey) === base.getAddress(pubKey); // true
```

### Derive HD keys

```ts
import { mnemonicToSeed } from "@agntn/keys/bip39";
import { getMasterKeyFromSeed, deriveHDKey } from "@agntn/keys/bip32";

const seed = mnemonicToSeed(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const master = getMasterKeyFromSeed(seed);
const account = deriveHDKey(master, "m/84'/0'/0'/0/0");
```

Use `@agntn/keys/slip10` instead of `@agntn/keys/bip32` for ed25519 derivation.

### Derive a wallet from a mnemonic

```ts
import { useBlockchain, blockchains } from "@agntn/keys";

const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

const btc = useBlockchain(await blockchains.bitcoin()());
btc.deriveHDWallet(mnemonic, "m/84'/0'/0'/0/0").address; // bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu

const sol = useBlockchain(await blockchains.solana()());
sol.deriveHDWallet(mnemonic, "m/44'/501'/0'/0'", { passphrase: "TREZOR" }).address;
```

secp256k1 chains walk BIP32 and ed25519 chains walk SLIP-10, which accepts hardened segments only. Bitcoin and Litecoin read the address type off the purpose level (44, 49, 84, 86) unless one is passed. Decred throws because its HD derivation differs from standard BIP32. Cardano throws, because CIP-1852 starts from the entropy rather than the BIP39 seed.

### Recover one missing BIP39 word

```ts
import { getMnemonicWordCandidates } from "@agntn/keys/bip39";

const candidates = getMnemonicWordCandidates(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?",
);
```

The result only satisfies the BIP39 checksum. It does not prove that a candidate belongs to the wallet or puzzle target.

### Map localized BIP39 words and indices

```ts
import { lookupBIP39Indices, lookupBIP39Words } from "@agntn/keys/bip39";

const wordMatches = await lookupBIP39Words(["orologio", "civetta"], "italian");
const indexMatches = await lookupBIP39Indices([1, 1179, 2048], "italian", 1);
```

Language keys cover the 10 official BIP39 lists. Word lookup is case-insensitive and normalizes Unicode to NFKD. Index lookup uses base 0 by default and accepts base 1 explicitly.

### Generate and inspect localized mnemonics

```ts
import { bip39, loadBIP39Wordlist } from "@agntn/keys/bip39";

const words = await loadBIP39Wordlist("spanish");
const mnemonic = bip39.generateMnemonic(words, 128);
const valid = bip39.validateMnemonic(mnemonic, words);
const entropy = bip39.mnemonicToEntropy(mnemonic, words);
const restored = bip39.entropyToMnemonic(entropy, words);
```

Localized lists load on demand; each call returns a copy. Existing synchronous helpers such as `generateMnemonic()` and `validateMnemonic()` still use English. The `bip39` codec handles Unicode NFKD and emits Japanese mnemonics with ideographic spaces.

In MCP and Pi, `keys_generate_mnemonic`, `keys_inspect_mnemonic` and `keys_encode_bip39_entropy` accept the same optional `language` key and report the selected language. Omit it for English; there is no automatic language detection. A checksum match is not proof of a language, since some lists share words. Inspection does not change case or guess missing accents.

`keys_derive_hd_wallet` and `keys_recover_mnemonic_word` still require English. Re-encoding entropy in another language can change the BIP39 seed; it is not a safe shortcut to an English wallet.

## MCP server

The package includes a stdio MCP server with the same 16 operations used by the Pi extension. After installing the package, configure an MCP client to run `keys mcp`. A checkout can run the built entry directly:

```json
{
  "mcpServers": {
    "keys": {
      "command": "node",
      "args": ["/absolute/path/to/keys/dist/cli.mjs", "mcp"]
    }
  }
}
```

Hosts that own their transport can import `createMcpServer` from `@agntn/keys/mcp`.

Use `keys_generate_mnemonic` with `{ "words": 24 }` for a fresh English BIP39 mnemonic, or `{}` for 12 words. Add `"language": "japanese"`, for example, to select another official list. It also accepts 15, 18 and 21 words. Generation uses the library's cryptographic randomness, not entropy supplied by the model. The result is saved in the transcript, so it is for tests and disposable wallets only.

The server handles private keys, mnemonics, entropy, messages, and signatures as plaintext MCP arguments or results. They enter client transcripts. Use only public puzzle material or disposable test keys, never a wallet that controls real funds.

## Supported Blockchains

| Chain        | Curve              | Address Formats                      | Testnet |
| ------------ | ------------------ | ------------------------------------ | ------- |
| **Bitcoin**  | secp256k1          | legacy, p2sh, segwit, p2wsh, taproot | ✅      |
| **Litecoin** | secp256k1          | legacy, p2sh, segwit, p2wsh, taproot | ✅      |
| **Decred**   | secp256k1          | legacy ECDSA P2PKH                   | ✅      |
| **Ethereum** | secp256k1          | EIP-55 checksum                      | -       |
| **Base**     | secp256k1          | EVM-compatible                       | -       |
| **Solana**   | ed25519            | base58                               | -       |
| **Aptos**    | ed25519            | 0x-prefixed hex                      | -       |
| **Cardano**  | ed25519            | payment, stake, enterprise           | ✅      |
| **SUI**      | ed25519, secp256k1 | 0x-prefixed hex (blake2b)            | -       |
| **TRON**     | secp256k1          | base58check                          | ✅      |

All chains support key generation, address derivation, address validation, and message signing.

## Security

Built on audited cryptographic packages from [@paulmillr](https://github.com/paulmillr):

- [@noble/curves](https://github.com/paulmillr/noble-curves) - elliptic curve implementations (secp256k1, ed25519)
- [@noble/hashes](https://github.com/paulmillr/noble-hashes) - SHA-256, Keccak, BLAKE-256, BLAKE2b, SHA3
- [@scure/base](https://github.com/paulmillr/scure-base) - base58, bech32, hex encoding
- [@scure/bip32](https://github.com/paulmillr/scure-bip32) - HD wallet key derivation
- [micro-key-producer](https://github.com/paulmillr/micro-key-producer) - SLIP-0010 for ed25519

> [!CAUTION]
> **Never use this with real funds or with any wallet that has ever been used.** Generated and signed material is handled as plaintext; treat every key it touches as burned the moment it is produced. Generate fresh throwaway keys for testing only and assume anything passing through `@agntn/keys` is compromised. Keys that control real funds belong on a hardware wallet, never in a process, log, or agent transcript.

## License

[MIT](./LICENSE.md)
