---
title: Solana
icon: i-token-sol
description: ed25519. The address is the public key itself in base58 with nothing hashed.
---

::chain-facts{driver="solana" curve="ed25519" formats="base58" coin="501"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const solanaChain = useBlockchain(await blockchains.solana()());
```

## The address

```js
const publicKey = solanaChain.getKeyPublic(privateKey); // 32 bytes, 64 hex chars
solanaChain.getAddress(publicKey); // base58 of the same 32 bytes
```

No hash, no version byte, no checksum. The address is the public key with a friendlier encoding, that's it. It makes Solana the easiest chain in the package and the one where `validateAddress` can say the least: any 32 bytes that decode from base58 pass, including a program address that no private key controls.

## Validation

```js
solanaChain.validateAddress("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"); // true
```

Decodes as base58 and is exactly 32 bytes. That is the whole check.

## Mnemonics

Solana derives with SLIP-10, which only has hardened children. Every segment of the path needs the tick:

```js
solanaChain.deriveHDWallet(mnemonic, { path: "m/44'/501'/0'/0'" }).address;
```

A path with an unhardened segment throws before derivation, there isn't a soft child to give you. Phantom and Solflare use exactly this shape, so the first account matches what those wallets show. `solanaChain.getDerivationPath({ account: 1 })` gives the next one, `m/44'/501'/1'/0'`.

## Keypair files

Got the `id.json` the Solana CLI writes, or a secret exported from Phantom or Solflare? Pass it straight to `deriveSeedWallet`. No slicing bytes by hand first.

```js
solanaChain.deriveSeedWallet("2Ana1pUpv2ZbMVkwF5FXapYeBEjdxDatLn7nvJkhgTSdZd8hbDHTd21as7EAsg7ypityqfsw2pMQKJcVDVcAEsd").address;
// 9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj, and the id.json array of the same 64 bytes gives the same
```

The seed in this public test vector just counts from 1 to 32. The other half is the public key, so the file carries its own answer key. Halves that don't match throw instead of handing you some other address.

You get `keys.private` as the 32-byte seed in hex, the key every other Solana method here takes. `keys_wallet_derive` reads both forms as `privateKey` too.

## Program addresses

Remember how `validateAddress` waves through a program address no key controls? Here's where those come from. A program derived address (PDA) starts with SHA-256. It hashes seeds, a bump byte, the program ID and `"ProgramDerivedAddress"`. The result must land off the ed25519 curve, so no private key exists for it. All offline, no RPC.

```js
const seeds = [new TextEncoder().encode("helloWorld")];
solanaChain.findProgramAddress(seeds, "BPFLoaderUpgradeab1e11111111111111111111111");
// { address: "BkJopytB5Ah8hxg8A9joeGLjQxPVNigk1D8JDj5JkPqq", bump: 255 }
```

`findProgramAddress` searches down from 255 for the first off-curve bump. That's the canonical bump, matching Rust's `find_program_address` and `@solana/web3.js`. Whether 255 works on the first try is a coin flip.

Already know the bump? Put it last in the seeds for `createProgramAddress`. That method throws if the result lands on the curve. Seeds are `Uint8Array` values, at most 32 bytes each. You can use 15 seeds, plus the bump. Encode a `u64` as eight little-endian bytes.

### Token accounts

```js
import { TOKEN_2022_PROGRAM } from "@agntn/keys/blockchains/solana";

const usdc = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
solanaChain.getAssociatedTokenAddress("9C6hybhQ6Aycep9jaUnP6uL9ZYvDjUp1aSkFWPUFJtpj", { mint: usdc }).address;
// FjCjyojZLVYVQ2dEdDKQx76msks96TdH9xqvc8BQ9UUx
```

`getAssociatedTokenAddress` gives you a wallet's associated token account (ATA) for a mint. It uses SPL Token by default. For a Token-2022 mint, pass `tokenProgram: TOKEN_2022_PROGRAM`. A PDA can own the account too. Check the program carefully: the wrong one gives you a valid address that never holds a token, with no warning.

Agents get `keys_solana_program_address_get` and `keys_solana_token_address_get`. Each program address seed is an object with one of `text`, `hex`, `address` or `u64`. Every address here comes from `@solana/web3.js` 1.99.0 and `@solana/spl-token` 0.4.15, and the tests hold the library to them.

## Signing

`signMessage` is a plain ed25519 signature over the message bytes, hex encoded, and `verifyMessage` checks it against the public key. That is the format `nacl.sign.detached` produces, minus the base58 wrapper some wallets add on top.
