----
icon: simple-icons:coinbase
---

# Base

## Introduction

Base implementation using the secp256k1 curve, with EIP-55 checksum support for addresses. Base is an Ethereum Layer 2 (L2) blockchain that uses the same address format as Ethereum.

## Usage

**Driver name:** `base`

```js
import { useBlockchain } from "ubichain";
import Base from "ubichain/blockchains/base";

const baseChain = useBlockchain(new Base());
```

## Features

- **Curve**: secp256k1
- **Address Format**: Hex addresses with '0x' prefix and EIP-55 checksum
- **Public Key Formats**:
  - Compressed (default) - 33 bytes (66 hex chars)
  - Uncompressed - 65 bytes (130 hex chars)

## Examples

### Generate a Wallet

```js
const wallet = baseChain.generateWallet();
console.log("Private Key:", wallet.keys.private);
console.log("Public Key:", wallet.keys.public);
console.log("Address:", wallet.address); // 0x-prefixed address with EIP-55 checksum
```

### Generate Address with Known Private Key

```js
// Private key with decimal value 1
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = baseChain.getKeyPublic(privateKey);
const address = baseChain.getAddress(publicKey);

console.log("Address:", address); // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
```

### Validate an Address

```js
// Validate a checksummed address
const isValidChecksum = baseChain.validateAddress("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");
console.log("Is valid:", isValidChecksum); // true

// Validate a lowercase address (also valid)
const isValidLowercase = baseChain.validateAddress("0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
console.log("Is valid:", isValidLowercase); // true

// Invalid checksum (wrong case)
const isInvalidChecksum = baseChain.validateAddress("0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf");
console.log("Is valid:", isInvalidChecksum); // false
```

## Technical Details

### EVM Compatibility

Base is an EVM (Ethereum Virtual Machine) compatible blockchain, which means:

1. It shares the same address generation process as Ethereum
2. The same private key will generate the same address on both Ethereum and Base
3. All Base addresses can be used on Ethereum, and vice versa

Base extends ubichain's common EVM base class:

```js
import { AbstractEVMBlockchain } from "../utils/evm";
import { BIP44 } from "../utils/bip44";

export default class Base extends AbstractEVMBlockchain {
  readonly name = "base";
  readonly bip44 = BIP44.ETHEREUM;
}
```

### Address Generation

Base addresses are generated following the Ethereum standard:

1. **Public Key Processing**:
   - For compressed public keys (33 bytes), decompress to 65 bytes first
   - Remove the first byte (0x04) from the uncompressed public key

2. **Address Derivation**:

   ```
   hash = Keccak-256(publicKeyWithoutPrefix)
   address = '0x' + last20Bytes(hash) // With EIP-55 checksum applied
   ```

3. **EIP-55 Checksum**:

   ```
   lowercase = address without '0x' prefix, in lowercase
   hash = Keccak-256(lowercase)

   for each character in lowercase:
     if corresponding hash character >= 8:
       make character uppercase
     else:
       keep character lowercase
   ```

### Key Generation

- **Private Key**: 32 random bytes (256 bits), represented as a 64-character hex string
- **Public Key**: Derived from the private key using the secp256k1 elliptic curve
  - Compressed: 33 bytes (66 hex chars), starting with 02 or 03
  - Uncompressed: 65 bytes (130 hex chars), starting with 04

## Source Code

The Base implementation is located in `src/blockchains/base.ts` and extends `AbstractEVMBlockchain` from `src/utils/evm.ts`.

```js
// Base implementation
import { AbstractEVMBlockchain } from "../utils/evm";
import { BIP44 } from "../utils/bip44";

export default class Base extends AbstractEVMBlockchain {
  readonly name = "base";
  readonly bip44 = BIP44.ETHEREUM;
}
```

See the [Ethereum documentation](/blockchains/ethereum) for more details on the EVM implementation.

## L2 vs L1

Base is an Ethereum Layer 2 solution, which means:

1. It inherits the security of Ethereum
2. It uses the same address format and cryptographic primitives
3. Transactions are typically faster and less expensive
4. It ultimately settles transactions on the Ethereum mainnet (L1)

For blockchain address and key operations, there is no difference between Base and Ethereum in terms of implementation.
