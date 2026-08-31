----
icon: simple-icons:ethereum
---

# Ethereum

## Introduction

Ethereum implementation using the secp256k1 curve, with EIP-55 checksum support for addresses.

## Usage

**Driver name:** `ethereum`

```js
import { useBlockchain } from "@agntn/keys";
import Ethereum from "@agntn/keys/blockchains/ethereum";

const ethereumChain = useBlockchain(new Ethereum());
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
const wallet = ethereumChain.generateWallet();
console.log("Private Key:", wallet.keys.private);
console.log("Public Key:", wallet.keys.public);
console.log("Address:", wallet.address); // 0x-prefixed address with EIP-55 checksum
```

### Generate Address with Known Private Key

```js
// Private key with decimal value 1
const privateKey = "0000000000000000000000000000000000000000000000000000000000000001";
const publicKey = ethereumChain.getKeyPublic(privateKey);
const address = ethereumChain.getAddress(publicKey);

console.log("Address:", address); // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
```

### Validate an Address

```js
// Validate a checksummed address
const isValidChecksum = ethereumChain.validateAddress("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf");

// Validate a lowercase address (also valid)
const isValidLowercase = ethereumChain.validateAddress(
  "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
);

// Invalid checksum (wrong case)
const isInvalidChecksum = ethereumChain.validateAddress(
  "0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf",
);
```

## Technical Details

### Address Generation

Ethereum addresses are generated as follows:

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

## EVM Compatibility

Ethereum uses the Ethereum Virtual Machine (EVM). Every EVM chain in `@agntn/keys` inherits the same behavior from `AbstractEVMBlockchain`.

This means that the same private key will generate the same address on all EVM chains, including Ethereum, Base, and any other EVM-compatible blockchains that may be added in the future.

## Source Code

The Ethereum implementation is located in `src/blockchains/ethereum.ts` and extends the common EVM base class from `src/utils/evm.ts`.

```js
// Ethereum implementation
import { AbstractEVMBlockchain } from "../utils/evm";
import { BIP44 } from "../utils/bip44";

export default class Ethereum extends AbstractEVMBlockchain {
  readonly name = "ethereum";
  readonly bip44 = BIP44.ETHEREUM;
}
```

The core EVM functions include:

```js
// Core EVM address generation
function generateAddress(keyPublic) {
  // Process public key
  const publicKeyForHashing = /* process public key */;

  // Apply Keccak-256 hash
  const keccakHash = keccak_256(publicKeyForHashing);

  // Take the last 20 bytes
  const addressBytes = keccakHash.slice(keccakHash.length - 20);

  // Convert to hex and add checksum
  return '0x' + toChecksumAddress(bytesToHex(addressBytes));
}

// EIP-55 checksum implementation
function toChecksumAddress(address) {
  const lowercaseAddress = address.toLowerCase();
  const addressHash = bytesToHex(keccak_256(lowercaseAddress));

  let result = '';
  for (let i = 0; i < lowercaseAddress.length; i++) {
    if (parseInt(addressHash[i], 16) >= 8) {
      result += lowercaseAddress[i].toUpperCase();
    } else {
      result += lowercaseAddress[i];
    }
  }

  return result;
}
```
