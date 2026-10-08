---
title: Cosmos
icon: i-token-atom
description: secp256k1 keys and BIP39 words to Cosmos SDK addresses. One driver and a prefix option cover the Hub and Osmosis and Celestia.
seo:
  title: Cosmos SDK addresses from keys and BIP39 words
---

::chain-facts{driver="cosmos" curve="secp256k1" formats="bech32 under any prefix" coin="118"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const cosmosChain = useBlockchain(await blockchains.cosmos()());
const osmosis = useBlockchain(await blockchains.cosmos({ prefix: "osmo" })());
```

Every Cosmos SDK chain hashes the key the same way. What changes is the bit in front of the `1`, and on a few chains the coin type in the path. So it's an option, not twenty classes. Leave it out and you get the Hub, `cosmos`.

Testnets keep their mainnet's prefix, so the `network` option changes nothing here.

## What's in an address?

Bitcoin's hash160 of the compressed key, written as bech32 under the chain's prefix.

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = cosmosChain.getKeyPublic(privateKey);

cosmosChain.getAddress(publicKey);
// cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c
osmosis.getAddress(publicKey);
// osmo1w508d6qejxtdg4y5r3zarvary0c5xw7kjxy2e2
```

Same 20 bytes, `w508d6qejxtdg4y5r3zarvary0c5xw7k`, and only the checksum at the end moves with the prefix.

Look at the middle again. Seen it before? It's the [Bitcoin](/blockchains/bitcoin) segwit address of the same key, `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4`. Bitcoin puts a `q` in front for witness version 0. Cosmos doesn't bother. The rest is the same hash. Two ecosystems that love to argue, one address underneath.

An uncompressed key works too. It gets compressed before hashing, because Cosmos only ever hashes the 33 byte form. That's also why `deriveWallet(key, { compressed: false })` throws. Otherwise you'd get a key that doesn't match its own address.

## Which prefix?

The one the chain's explorer shows. `cosmos` for the Hub, `osmo` for Osmosis, `stars` for Stargaze, and plain `celestia`, `juno` or `akash`. Bech32 takes up to 83 printable ASCII characters, so `fren-1` and `c4e` work too, as long as they're lowercase. Anything else throws when you load the chain. Better a typo fails there than three steps later, as an address nobody can use.

`validateAddress` checks the prefix too. An `osmo1...` address is `false` for `cosmos`, good checksum or not. Accounts are 20 bytes and contracts get 32, but the SDK's own check takes anything from 1 to 255. So does this one.

```js
cosmosChain.validateAddress("cosmos1w508d6qejxtdg4y5r3zarvary0c5xw7k6ah60c"); // true
cosmosChain.validateAddress("osmo1w508d6qejxtdg4y5r3zarvary0c5xw7kjxy2e2"); // false
```

Not every chain with a bech32 address fits, though. Injective and Evmos hash Ethereum style keys, and no prefix fixes that.

## Mnemonics

BIP32 at `m/44'/118'/0'/0/0`, the path Keplr and `gaiad keys add` start at.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

cosmosChain.getDerivationPath(); // "m/44'/118'/0'/0/0"
cosmosChain.deriveHDWallet(mnemonic, "m/44'/118'/0'/0/0").address;
// cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4
osmosis.deriveHDWallet(mnemonic, "m/44'/118'/0'/0/0").address;
// osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8
```

One phrase, one account on every chain that uses 118. That's why a Keplr wallet shows a different address per chain with the same middle.

### Why does Terra get another middle?

Because Terra never used 118. It walks `m/44'/330'`, Secret walks 529, Kava 459. The prefix knows that now. A table of the [chain registry](https://github.com/cosmos/chain-registry)'s `slip44` values maps 27 prefixes to their own coin type. Every other prefix stays on 118.

```js
const terra = useBlockchain(await blockchains.cosmos({ prefix: "terra" })());

terra.getDerivationPath(); // "m/44'/330'/0'/0/0"
terra.deriveHDWallet(mnemonic, terra.getDerivationPath()).address;
// terra1amdttz2937a3dytmxmkany53pp6ma6dy4vsllv
```

Wallet went its own way, or the table missed your chain? `coinType` wins over the table.

```js
const hubPath = useBlockchain(await blockchains.cosmos({ prefix: "terra", coinType: 118 })());

hubPath.deriveHDWallet(mnemonic, hubPath.getDerivationPath()).address;
// terra19rl4cm2hmr8afy4kldpxz3fka4jguq0a6yhaa4
```

Same middle as the Hub's `cosmos19rl4...` up there. Of course it is, it's the Hub's path.

Don't know which account the phrase used? `keys_hd_wallet_scan` walks accounts and indices under the chain's coin type, `prefix` and all.

## Signing

`signMessage` signs like Keplr's `signArbitrary`, ADR-036. The message goes into a sign doc as base64, next to the signer's address. Fee and sequence stay zero. The SHA-256 of that JSON is what gets signed. You get 64 bytes of `r||s` in hex, no recovery byte. Keplr hands over the same bytes in base64.

```js
const signature = cosmosChain.signMessage("Hello, Cosmos!", privateKey);
cosmosChain.verifyMessage("Hello, Cosmos!", signature, publicKey); // true
osmosis.verifyMessage("Hello, Cosmos!", signature, publicKey); // false
```

That last `false` is correct. The signer's address sits inside the signed bytes, prefix included, so a signature for `cosmos1...` says nothing about `osmo1...`.

## Agents

Every tool that writes, checks or signs for a chain takes `prefix` next to `chain: "cosmos"`. On any other chain it refuses the prefix instead of quietly ignoring it.

`keys_bip44_generate` and `keys_hd_wallet_scan` take `coinType` too, for when the table guessed wrong. Hand it to `bitcoin` and you get an error, not a path nobody walks.

## Where it lives

`src/blockchains/cosmos.ts`. The curve comes from `@noble/curves`, the hashes from `@agntn/hashes`, bech32 and base64 from `@agntn/encodings`.
