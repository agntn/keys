----
icon: simple-icons:solana
---

# Solana

## Introduction

Solana implementation using the ed25519 curve, with simple base58-encoded addresses.

## Usage

**Driver name:** `solana`

```js
import { useBlockchain } from "ubichain";
import Solana from "ubichain/blockchains/solana";

const solanaChain = useBlockchain(new Solana());
```

## Features

- **Curve**: ed25519
- **Address Format**: Base58-encoded public key
- **Public Key**: 32 bytes (64 hex chars) - ED25519 public key

## Examples

### Generate a Wallet

```js
const wallet = solanaChain.generateWallet();
console.log("Private Key:", wallet.keys.private);
console.log("Public Key:", wallet.keys.public);
console.log("Address:", wallet.address); // Base58-encoded public key
```

### Generate Address from Known Private Key

```js
const privateKey = "your_private_key_as_hex";
const publicKey = solanaChain.getKeyPublic(privateKey);
const address = solanaChain.getAddress(publicKey);

console.log("Address:", address);
```

### Validate an Address

```js
// Validate a Solana address
const isValid = solanaChain.validateAddress("9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin");
console.log("Is valid:", isValid); // true or false
```

## Technical Details

### Address Generation

Solana addresses are unique among blockchains in their simplicity:

1. **Address Generation**:
   ```
   address = Base58(publicKey)
   ```

This means that for Solana, the address is simply the public key encoded in Base58 format without any hashing or additional transformation.

### Validation

A Solana address is valid if:

- It can be decoded as Base58
- The decoded bytes are exactly 32 bytes (the size of an Ed25519 public key)

### Key Generation

- **Private Key**: 32 random bytes (256 bits), represented as a 64-character hex string
- **Public Key**: Derived from the private key using the ed25519 elliptic curve
  - 32 bytes (64 hex chars)

## Source Code

The Solana implementation is located in `src/blockchains/solana.ts`.

```js
// Core functions
function getAddress(keyPublic) {
  // For Solana, the address is the same as the public key
  // We just need to convert from hex to base58
  const keyBytes = hexToBytes(keyPublic);
  return base58.encode(keyBytes);
}

function validateAddress(address) {
  try {
    // Try to decode as base58
    const decoded = base58.decode(address);
    // Solana addresses are 32 bytes (Ed25519 public key)
    return decoded.length === 32;
  } catch (error) {
    return false;
  }
}
```

## Future Plans

Future updates may include support for:

- Account/program derivation (PDAs)
- Multisig addresses
- Transaction creation and signing
