---
title: NEAR
icon: i-token-near
description: ed25519 keys and BIP39 words to NEAR implicit accounts. The account ID is the public key in hex. Named accounts stay on chain.
seo:
  title: NEAR implicit accounts from keys and BIP39 words
---

::chain-facts{driver="near" curve="ed25519" formats="implicit account (hex)" coin="397"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const nearChain = useBlockchain(await blockchains.near()());
```

Mainnet and testnet write the same accounts. The `network` option changes nothing here.

## What's an implicit account?

The public key. In hex. That's the whole recipe.

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = nearChain.getKeyPublic(privateKey);

nearChain.getAddress(publicKey);
// 4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29
```

No hash, no checksum, not even base58. Even Solana bothers with base58. NEAR looked at 32 bytes and said, good enough.

The hex is lowercase. NEAR refuses uppercase in account IDs, so `validateAddress` does too.

## And the `ed25519:` thing?

That's how NEAR prints a key: `ed25519:` and the 32 bytes in base58. Wallets, near-cli and the RPC all show it this way. `getAddress` and `verifyMessage` take it as is.

```js
nearChain.getAddress("ed25519:6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt");
// 4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29
```

Look at that base58 again. Seen it before? It's the [Solana](/blockchains/solana) address of the same private key. Solana's address is base58 of the key, NEAR's key is base58 of the key. One chain calls it an address, the other a key with a label on it.

Agents get the same deal. `keys_address_get` and `keys_message_verify` take the `ed25519:` form on `near`, and every other chain asks for hex instead.

## What about `alice.near`?

Named accounts are made by a transaction on chain. No key derives one, so nothing here writes them.

```js
nearChain.validateAddress(nearChain.getAddress(publicKey)); // true
nearChain.validateAddress("alice.near"); // false
```

`false` doesn't mean `alice.near` is broken. It means no key leads there. The `0x` ETH-implicit accounts get `false` for the same reason, they come from secp256k1 keys.

One more trap. The account ID names the key that created it, not the key that holds it today. Owners add keys and delete the first one, and the account keeps its name. It happens on mainnet, not just in theory. So a key that matches the ID tells you who opened the account. Who can sign now is on chain, in `view_access_key_list`.

## Mnemonics

SLIP-10 on ed25519, every level hardened. near-seed-phrase stops at `m/44'/397'/0'`, and that's what `getDerivationPath` writes. Account `a` is `m/44'/397'/a'`, and there's no change branch or index below it.

```js
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

nearChain.getDerivationPath(); // "m/44'/397'/0'"
nearChain.deriveHDWallet(mnemonic, "m/44'/397'/0'").address;
// 5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412
```

Ledger went its own way, of course. Its NEAR app defaults to `m/44'/397'/0'/0'/1'`, five levels deep. Pass that path to `deriveHDWallet` as it is.

```js
nearChain.deriveHDWallet(mnemonic, "m/44'/397'/0'/0'/1'").address;
// c571e33e2e36c2c728d617ea77a88e2320c8697eac8b463adfc0128b96825cbf
```

Not sure which wallet made the phrase? `keys_hd_wallet_scan` walks both, `bip44` over the account level and `ledger` over the last one.

## Signing

`signMessage` signs the raw message bytes with ed25519, like Solana and Aptos.

```js
const signature = nearChain.signMessage("Hello, NEAR!", privateKey);
nearChain.verifyMessage("Hello, NEAR!", signature, publicKey); // true
```

Wallets that sign under NEP-413 won't match this. They wrap a nonce and a recipient around the message first and sign the hash of that. Different bytes, different signature.

## Where it lives

`src/blockchains/near.ts`, and it's short. The curve comes from `@noble/curves`, base58 from `@agntn/encodings`.
