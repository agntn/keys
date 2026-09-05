---
title: Base
icon: i-lucide-layers
description: Ethereum's driver under another name. Same key, same address, same signatures.
---

::chain-facts{driver="base" curve="secp256k1" formats="EIP-55 hex" coin="60"}
::

## Load it

```js
import { useBlockchain, blockchains } from "@agntn/keys";

const baseChain = useBlockchain(await blockchains.base()());
```

## There is nothing Base specific here

Base is an Ethereum L2, and for keys and addresses that means it is Ethereum. The driver is `AbstractEVMBlockchain` with `name = "base"` and coin type 60, because wallets do not give L2s their own coin type.

```js
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";

baseChain.getAddress(baseChain.getKeyPublic(privateKey)); // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
```

Same address as Ethereum for the same key, same EIP-55 checksum, same `personal_sign` preamble on `signMessage`. Everything on the [Ethereum page](/blockchains/ethereum) applies verbatim.

## So why a separate driver

Two reasons. `name` is what the MCP tools and the lazy loader key on, so an agent can say `base` and mean it. And `deriveHDWallet` on Base still uses `m/44'/60'/...`, which is what every wallet does, but having the driver state it keeps that decision visible instead of implied.

If you only ever call `getAddress`, using the Ethereum driver for Base is fine and you will not be able to tell the difference. The funds will not either, which is the part to be careful about: an address is the same on both chains, the balance is not.
