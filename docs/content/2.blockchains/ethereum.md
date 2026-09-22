---
title: Ethereum
icon: i-token-eth
description: secp256k1 with EIP-55 checksummed addresses and personal_sign message signatures.
---

::chain-facts{driver="ethereum" curve="secp256k1" formats="EIP-55 hex" coin="60"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const ethereumChain = useBlockchain(await blockchains.ethereum()());
```

## The address

Uncompressed public key without the `04`, Keccak-256, last 20 bytes, `0x`, then the EIP-55 case checksum.

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = ethereumChain.getKeyPublic(privateKey);

ethereumChain.getAddress(publicKey); // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
```

Yes, that's the address of private key `1`. It shows up in a lot of test suites.

## Validation

```js
ethereumChain.validateAddress("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"); // true
ethereumChain.validateAddress("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"); // true, no checksum to check
ethereumChain.validateAddress("0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf"); // false, bad checksum
```

Lowercase and uppercase pass, mixed case has to match. A rejected mixed case address is almost always a copy and paste that lost a character somewhere, so treat `false` as "look at it again", not as "this address doesn't exist".

## Signing

`signMessage` prepends `"\x19Ethereum Signed Message:\n" + length`, hashes with Keccak-256, and signs with secp256k1. That's `personal_sign`, the same hash MetaMask, ethers and viem sign. Default output is 64 bytes of `r||s`, which `verifyMessage` here checks against a public key.

```js
const signature = ethereumChain.signMessage("hello", privateKey);
ethereumChain.verifyMessage("hello", signature, publicKey); // true
```

Anything that recovers the signer from the signature needs `v`, so pass `recovered`:

```js
const recoverable = ethereumChain.signMessage("hello", privateKey, { recovered: true });
// 65 bytes, r||s||v, identical to what ethers signMessage gives for the same key
ethereumChain.verifyMessage("hello", recoverable, publicKey); // true, and the v has to match
```

`verifyMessage` takes either length. On 65 bytes it also recovers from the `v`, so a signature carrying the other one fails instead of passing on `r||s` alone. The 64-byte form is what you want inside this package, the 65-byte form is what you send out. See the [EVM guide](/guide/evm) for what ethers does with the short one, it's not an error and that's the problem.

## One driver, every EVM chain

Ethereum is `AbstractEVMBlockchain` with a name and coin type 60. Base is the same class with a different name. The [EVM guide](/guide/evm) explains why one private key gives one address on every EVM chain and how to add another one in two lines.
