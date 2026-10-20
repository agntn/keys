---
title: TON
icon: i-token-ton
description: TON wallets from Tonkeeper's 24 words or from BIP39. Addresses for three wallet contracts in both spellings.
seo:
  title: TON wallet addresses from 24 words and BIP39
---

::chain-facts{driver="ton" curve="ed25519" formats="v3r2, v4r2, v5r1 wallets, bounceable or not" coin="607"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const ton = useBlockchain(await blockchains.ton()());
const testnet = useBlockchain(await blockchains.ton({ network: "testnet" })());
```

Same keys on both networks. Testnet flips one flag bit, and v5r1 folds the network into its wallet ID too.

## Where's the key in the address?

Nowhere, really. Most chains hash the public key and call it a day. TON doesn't.

An account on TON is a smart contract, and the wallet is one too. Its address is the hash of the contract's starting state: the code, plus a data cell with the key inside. Change the code and the address moves.

So one key has three addresses here, one per wallet contract:

```js
const publicKey = "fa86305ed66920ddc1b041db6ba756147b7e627d5bcffbe5cd2bfd0039fa9152";

ton.getAddress(publicKey); // UQDxrCm53vVUKOIgj1f3IiyjLDYLvaBR9-D5ZxVdH5nXVMEH, v4r2
ton.getAddress(publicKey, "v5r1"); // UQAa7ATvJFkxQN73j8_PiZeEb5-yFPvs7JDHzQfsHGAhO3kg
ton.getAddress(publicKey, "v3r2"); // UQAcPB8EuQQwVzKX2UynNmE1nPbAziMowreDYObVdeyiCtug
```

Why v4r2 by default? Ledger and Trust Wallet deploy it, and most wallets on chain still run it. Tonkeeper's newer W5 is `v5r1`.

Found a puzzle address that matches none of them? Try the other two contracts first. Then start doubting the key.

## Bounceable or not

Same account, two spellings. That's TON's user-friendly form.

```js
ton.getAddress(publicKey, "v4r2"); // UQDxrCm53vVUKOIgj1f3IiyjLDYLvaBR9-D5ZxVdH5nXVMEH
ton.getAddress(publicKey, "v4r2-bounceable"); // EQDxrCm53vVUKOIgj1f3IiyjLDYLvaBR9-D5ZxVdH5nXVJzC
```

One flag byte up front, then the workchain, the 32-byte hash and a CRC16. Base64url on top, 48 characters. The flag tells a sender what to do when the wallet isn't deployed yet. `EQ` bounces the coins back, `UQ` lets them land.

Wallet apps show `UQ` these days, so that's what keys writes. Add `-bounceable` for the `EQ` one. Testnet sets one more bit, and the prefixes turn into `0Q` and `kQ`.

`validateAddress` takes all of it. Raw `0:` and hex, both flags, either base64 alphabet, masterchain `-1:` too. The checksum has to hold. A testnet address on a mainnet instance comes back `false`, and the other way round as well.

## Tonkeeper's 24 words

They look like BIP39. Same English list, 24 words. They're not, and that's the fun part.

There's no checksum word. TON hashes the whole phrase with HMAC-SHA512, stretches it under `TON seed version`, and wants the first byte to be zero. One phrase in 256 passes. The key comes from another PBKDF2, 100,000 rounds under `TON default seed`.

```js
const phrase =
  "open you repeat drift approve view between cover myth feed rice cloud " +
  "library index chase crime minute roast vault error kid abandon velvet vacuum";

const wallet = ton.deriveSeedWallet(phrase);
wallet.keys.public; // fa86305ed66920ddc1b041db6ba756147b7e627d5bcffbe5cd2bfd0039fa9152
wallet.address; // UQDxrCm53vVUKOIgj1f3IiyjLDYLvaBR9-D5ZxVdH5nXVMEH
```

Case and whitespace don't matter, the way `@ton/crypto` reads it. The wallet takes `addressType` like everywhere else.

Shuffled words fail the check on that first byte. So do BIP39 phrases, almost always. A word off the list throws with its position, never the word. A phrase locked with a password throws too, and says so. keys doesn't take TON passwords yet.

And those 100,000 rounds? About half a second. TON wanted brute force to hurt, and it does.

## BIP39 words

Some wallets import a plain BIP39 phrase for TON. They walk SLIP-10 on ed25519 under coin type 607, every level hardened. Which levels? Depends who you ask.

```js
ton.getDerivationPath(); // m/44'/607'/0'
ton.getDerivationPath({ account: 1 }); // m/44'/607'/1'

ton.deriveHDWallet(
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  { path: "m/44'/607'/0'" },
).address;
// UQAzWZa6nM5mJev91wGc7VCSfBoIsYRqKJpV78N8Add9-RKY
```

Trust Wallet and Coin Wallet stop at the account, so that's what `getDerivationPath` writes. Ledger goes three levels deeper, `m/44'/607'/0'/0'/{account}'/0'`. Pass that one as `path`.

Tonkeeper's 24 words in `deriveHDWallet` fail BIP39's checksum. The error then points you at `deriveSeedWallet`, instead of just shrugging.

## Signing a message

Raw ed25519 over the message bytes, like Solana and NEAR.

```js
const signature = ton.signMessage("ton me", { privateKey: wallet.keys.private });
ton.verifyMessage("ton me", { signature, publicKey: wallet.keys.public }); // true
```

That's what `sign` in `@ton/crypto` writes too. TON Connect's `signData` wraps the message in its own envelope first, so a wallet's `signData` signature won't check out here.

## Where these vectors come from

The phrase and every address above come from `@ton/crypto` 3.3.0 and `@ton/ton` 16.3.0, frozen in the tests. Three deployed mainnet wallets back them up. Their keys came from `get_public_key` on chain, and keys lands on each account.

## Agents

On `chain: "ton"` the `privateKey` of `keys_wallet_derive` takes the 24 words as well as hex. `addressType` picks the contract and the spelling. `keys_hd_wallet_derive` takes BIP39 words, and refuses Tonkeeper's with a pointer back. `keys_hd_wallet_scan` walks `m/44'/607'/{index}'` and Ledger's path, both on v4r2. Any spelling of the target matches, raw included.

## Where it lives

`src/blockchains/ton.ts`, with the address in `src/utils/ton-address.ts` and the 24 words in `src/utils/ton-mnemonic.ts`. No BOC parser in here. The address only needs the depth and hash of each contract's code cell, so those two numbers are all keys keeps. SHA-256, HMAC, PBKDF2 and CRC16 come from `@agntn/hashes`, base64 from `@agntn/encodings`, ed25519 from `@noble/curves`.
