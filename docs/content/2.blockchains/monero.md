---
title: Monero
icon: i-token-xmr
description: Monero addresses from a 25-word seed or a spend key. Subaddresses and integrated addresses come out the way monero-wallet-cli writes them.
seo:
  title: Monero addresses and keys from a 25-word seed
---

::chain-facts{driver="monero" curve="ed25519" formats="standard, subaddress, integrated" coin="128"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const monero = useBlockchain(await blockchains.monero()());
const stagenet = useBlockchain(await blockchains.monero({ network: "stagenet" })());
```

Three networks, one class. `mainnet`, `testnet` and `stagenet`, and anything else throws. Same keys on every network. The network byte up front changes, and the checksum over it.

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

Plain hex works too. `deriveWallet` reduces whatever 32 bytes you give it, the way Monero's wallet does, and the wallet shows the reduced key. A random key is above l most of the time, so don't be surprised when it comes back different. A key that reduces to zero throws. No spend key, no wallet.

## What's in an address?

A network byte, both public keys and four bytes of keccak256. Then base58, but Monero's version. It cuts the bytes into blocks of eight and pads every block to 11 characters. So a standard address is always 95 characters long.

```js
monero.getAddress(wallet.keys.public); // 42ey1afD...TfJJQAWDm
monero.validateAddress("42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm"); // true
```

Mainnet starts with `4`, stagenet with `5`, testnet with `9` or `A`. `validateAddress` wants this instance's network, a good checksum and two real keys. Not the identity, not a torsion point, the same `check_address` monero-wallet-cli runs. It takes all three kinds below, each under its own network byte.

## Subaddresses

Want a fresh address for every payment without a new seed? That's what subaddresses are for. monero-wallet-cli hands them out with `address new` and `account new`. Here's the same list:

```js
const viewKey = monero.getViewKey(wallet.keys.private);

monero.getSubaddress(wallet.keys.public, viewKey, 0, 1);
// 84QRUYawRNrU3NN1VpFRndSukeyEb3Xpv8qZjjsoJZnTYpDYceuUTpog13D7qPxpviS7J29bSgSkR11hFFoXWk2yNdsR9WF
monero.getSubaddress(wallet.keys.public, viewKey, 1, 0);
// 82pP87g1Vkd3LUMssBCumk3MfyEsFqLAaGDf6oxddu61EgSFzt8gCwUD4tr3kp9TUfdPs2CnpD7xLZzyC1Ei9UsW3oyCWDf
```

Two numbers pick one. The account first, then the address inside it. Account 0, index 0 is the wallet's own `4...` address. Every other pair starts with `8` on mainnet, `7` on stagenet and `B` on testnet. Both indices go up to 2^32 - 1, since wallet2 keeps them as uint32.

Notice what's missing? The spend key. A subaddress hashes the private view key with both indices. That scalar times G lands on the public spend key, and the view key multiplies the sum. So a view only wallet hands out subaddresses just fine.

Pass a view key from another wallet and it throws. Better than an address nobody can spend.

Only want the keys? `getSubaddressKeyPublic` returns the 64-byte pair, and `getAddress(pair, "subaddress")` writes it. A whole wallet stays on its standard address, so `deriveWallet` refuses an address type.

## Integrated addresses

Older trick, same goal. The standard keys plus an 8-byte payment ID, packed into one address:

```js
monero.getIntegratedAddress(wallet.keys.public, "1234567890abcdef");
// 4CMe2PUhs4J4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfSbyvqonpbf2Tzcs8kx
```

Same `4` up front, 106 characters long. Wallets push subaddresses these days. But an old integrated address still has to check out, and now it does.

Every address on this page comes from monero-wallet-cli 0.18.5.3, restored offline from that seed. The tests hold the library to them.

## Signing a message

Want to show an address is yours without moving a single piconero? Monero wallets have `sign` for that, and keys writes the same SigV2:

```js
const signature = monero.signMessage("foo", wallet.keys.private);
// SigV2 and 88 characters of base58, with a fresh nonce every time

monero.verifyMessage("foo", signature, wallet.keys.public);
// true
```

The private key is the spend key, like everywhere on this page. Pass `{ signingKey: "view" }` and the view key signs instead, like `sign --view`.

And the other way round? Here's what monero-wallet-rpc 0.18.5.3 signed for that same wallet:

```js
monero.verifyMessage(
  "foo",
  "SigV28r6htFqF3fA4brb5tVALH661nNdrpfociHRduyn29JYpSJ2b9jUudSNbziPuGkQfiS4idjLzHHxrfKs6kC8vgEPj",
  wallet.keys.public,
);
// true
```

`verifyMessage` tries both keys, the way `monero-wallet-cli verify` does. The hash covers a `MoneroMessageSignature` tag, both public keys, which key signed and the message. So a view key signature can't pose as a spend key one. Old `SigV1` signatures hash the bare message, and they still check out.

Won something paid to an `8...` address? Proving it with the wallet's `4...` one is showing the wrong ID. Pass `account` and `addressIndex`, the same two numbers `getSubaddress` takes, and keys signs as that subaddress, like `sign 1,2` in monero-wallet-cli:

```js
const signature = monero.signMessage("foo", wallet.keys.private, { account: 1, addressIndex: 2 });

monero.verifyMessage("foo", signature, monero.getSubaddressKeyPublic(wallet.keys.public, viewKey, 1, 2));
// true
monero.verifyMessage("foo", signature, wallet.keys.public);
// false
```

That `false` is the good news. A subaddress signs with `b + m` and `a * (b + m)`, the secrets behind its own two keys, so it can't vouch for the wallet or for its siblings. `signingKey: "view"` works here too. monero-wallet-rpc 0.18.5.3 accepts what keys signs this way, and the tests check keys against what the RPC signed.

Hex, base64 or a truncated signature throws instead of answering `false`. A typo isn't a verdict.

## What it doesn't do

No BIP39 words and no BIP44 paths. `deriveHDWallet` and `getDerivationPath()` throw, and `keys_hd_wallet_scan` has nothing to walk. A Monero wallet is its seed.

## Agents

On `chain: "monero"` the `privateKey` of `keys_wallet_derive` takes the seed words as well as hex, and `network` takes `stagenet` too. Add `account` and `addressIndex` and it prints that subaddress, the view key never leaving the call. `keys_address_get` wants the 64-byte public key, the one `keys_wallet_derive` prints. `addressType: "subaddress"` writes a subaddress pair, `paymentId` the integrated address. `keys_message_sign` writes SigV2, with `signingKey: "view"` for the view key and `account` with `addressIndex` for a subaddress. `keys_message_verify` takes SigV2 or SigV1 against the 64-byte key of the address that signed.

## Where it lives

`src/blockchains/monero.ts`, with the seed words in `src/utils/monero-seed.ts` and block base58 in `src/utils/monero-base58.ts`. ed25519 comes from `@noble/curves`, keccak256 and CRC-32 from `@agntn/hashes`, base58 from `@agntn/encodings`.
