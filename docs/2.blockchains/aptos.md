----
icon: simple-icons:aptos
---

# Aptos

## Introduction

Aptos implementation using the ed25519 curve, with addresses derived using SHA3-256 hash.

## Usage

**Driver name:** `aptos`

```js
import { useBlockchain } from "ubichain";
import Aptos from "ubichain/blockchains/aptos";

const aptosChain = useBlockchain(new Aptos());
```

## Features

- **Curve**: ed25519
- **Address Format**: Hex-encoded 32-byte SHA3-256 hash with '0x' prefix
- **Public Key**: 32 bytes (64 hex chars) - ED25519 public key

## Examples

### Generate a Wallet

```js
const wallet = aptosChain.generateWallet();
console.log("Private Key:", wallet.keys.private);
console.log("Public Key:", wallet.keys.public);
console.log("Address:", wallet.address); // 0x-prefixed address
```

### Generate Address from Known Private Key

```js
const privateKey = "your_private_key_as_hex";
const publicKey = aptosChain.getKeyPublic(privateKey);
const address = aptosChain.getAddress(publicKey);

console.log("Address:", address); // e.g., 0x7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936
```

### Validate an Address

```js
// Validate an Aptos address
const isValid = aptosChain.validateAddress(
  "0x7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936",
);
console.log("Is valid:", isValid); // true

// Invalid address (wrong format)
const isInvalid = aptosChain.validateAddress(
  "7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936",
);
console.log("Is valid:", isInvalid); // false (missing 0x prefix)
```

## Technical Details

### Address Generation

Aptos addresses are generated as follows:

1. **Address Generation**:
   ```
   dataToHash = publicKey + 0x00  // Concatenate the public key with scheme identifier byte 0x00
   address = '0x' + SHA3-256(dataToHash)
   ```

The scheme identifier byte (0x00) indicates a single Ed25519 signer scheme.

### Validation

An Aptos address is valid if:

- It starts with '0x' prefix
- It contains exactly 64 hex characters after the prefix (32 bytes)
- All characters are valid hex characters (0-9, a-f, A-F)

### Key Generation

- **Private Key**: 32 random bytes (256 bits), represented as a 64-character hex string
- **Public Key**: Derived from the private key using the ed25519 elliptic curve
  - 32 bytes (64 hex chars)

## Source Code

The Aptos implementation is located in `src/blockchains/aptos.ts`.

```js
function getAddress(keyPublic) {
  // Convert hex public key to bytes
  const keyPublicBytes = hexToBytes(keyPublic);

  // Concatenate with scheme identifier byte (0x00 for single Ed25519)
  const dataToHash = new Uint8Array(keyPublicBytes.length + 1);
  dataToHash.set(keyPublicBytes);
  dataToHash[keyPublicBytes.length] = 0x00; // Single signer scheme identifier

  // Hash with SHA3-256
  const addressBytes = sha3_256(dataToHash);

  // Return as hex string with 0x prefix
  return "0x" + bytesToHex(addressBytes);
}

function validateAddress(address) {
  try {
    // Check if the address starts with '0x'
    if (!address.startsWith("0x")) {
      return false;
    }

    // Remove the '0x' prefix and check if it's a valid hex string
    const addressHex = address.slice(2);
    if (!/^[0-9a-f]{64}$/i.test(addressHex)) {
      return false;
    }

    return true;
  } catch (error) {
    return false;
  }
}
```

## Future Plans

Future updates may include support for:

- Multi-signature accounts
- Resource accounts
- Transaction creation and signing
- Move smart contract interaction
