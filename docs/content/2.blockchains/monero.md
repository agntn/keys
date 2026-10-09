---
title: Monero
icon: i-token-xmr
description: Monero standard addresses from a 25-word seed or a spend key. Both key pairs come out the way monero-wallet-cli restores them.
seo:
  title: Monero addresses and keys from a 25-word seed
---

::chain-facts{driver="monero" curve="ed25519" formats="standard address" coin="128"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const monero = useBlockchain(await blockchains.monero()());
const stagenet = useBlockchain(await blockchains.monero({ network: "stagenet" })());
```

Three networks, one class. `mainnet`, `testnet` and `stagenet`, and anything else throws. Only the first byte of the address changes.

## The seed

Monero doesn't do BIP39. A wallet gives you 25 words from its own list of 1626. Hand them to `deriveSeedWallet`:

```js
const seed =
  "velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits " +
  "benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted";

const wallet = monero.deriveSeedWallet(seed);
wallet.address;
// 42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm
```

That seed comes from Monero's own functional tests, and so does the address. Nice when the source agrees with you.

Three words make four bytes, so 24 words are the 32-byte key. The 25th is a checksum. It repeats one of the other 24, picked by a CRC-32 over their first three letters.

Here's the fun part. Only the first three letters count. `VELxyz LYMzz GIDdy...` restores the same wallet, any case, any whitespace. That's what monero-wallet-cli does too. Got a smudged backup where only the starts are readable? That might be enough.

Drop the 25th word and 24 still work. But then every word has to be whole, since no checksum backs the guess.

What throws? A count other than 24 or 25, a word off the list, a checksum word that doesn't match. And three words that spell more than 32 bits, which the math allows and Monero refuses.

English only, for now. The other Monero lists and Polyseed's 16 words aren't here.

## Keys

The 32 bytes from the seed get reduced mod l, the ed25519 group order. That's the private spend key. The private view key is keccak256 of the spend key, reduced again. One seed, two key pairs.

```js
wallet.keys.private; // 148d78d2...86640e, the spend key
monero.getViewKey(wallet.keys.private); // 49774391...809100
wallet.keys.public; // 1b3bd040...7be2ab231c9bf834...247e99
```

`keys.public` is 64 bytes. The public spend key, then the public view key. Weird? Every Monero address needs both, so a wallet carries both.

Plain hex works too. `deriveWallet` reduces whatever 32 bytes you give it, the way Monero's wallet does, and the wallet shows the reduced key. A random key is above l most of the time, so don't be surprised when it comes back different.

## What's in an address?

A network byte, both public keys and four bytes of keccak256. Then base58, but Monero's version. It cuts the bytes into blocks of eight and pads every block to 11 characters. So the address is always 95 characters long.

```js
monero.getAddress(wallet.keys.public); // 42ey1afD...TfJJQAWDm
monero.validateAddress("42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm"); // true
```

Mainnet starts with `4`, stagenet with `5`, testnet with `9` or `A`. `validateAddress` wants this instance's network, a good checksum and both keys on the curve.

Standard addresses only. Subaddresses start with `8` and come back `false`, integrated addresses too. They're next.

## What it doesn't do

No BIP39 words and no BIP44 paths. `deriveHDWallet` and `getDerivationPath()` throw, and `keys_hd_wallet_scan` has nothing to walk. A Monero wallet is its seed.

No message signing either. Monero signs with its own SigV2 scheme, and `signMessage` throws until it's here.

## Agents

On `chain: "monero"` the `privateKey` of `keys_wallet_derive` takes the seed words as well as hex. `keys_address_get` wants the 64-byte public key, the one `keys_wallet_derive` prints.

## Where it lives

`src/blockchains/monero.ts`, with the seed words in `src/utils/monero-seed.ts` and block base58 in `src/utils/monero-base58.ts`. ed25519 comes from `@noble/curves`, keccak256 and CRC-32 from `@agntn/hashes`, base58 from `@agntn/encodings`.
