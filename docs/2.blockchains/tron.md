----
icon: simple-icons:tron
---

# TRON

## Introduction

TRON implementation using the secp256k1 curve, with Base58Check-encoded addresses that start with 'T'.

## Usage

**Driver name:** `tron`

```js
import { useBlockchain } from "@agntn/keys";
import Tron from "@agntn/keys/blockchains/tron";

const tronChain = useBlockchain(new Tron());
```

## Features

- **Curve**: secp256k1
- **Address Format**: Base58Check-encoded with version byte 0x41, starting with 'T'
- **Public Key Formats**:
  - Compressed (default) - 33 bytes (66 hex chars)
  - Uncompressed - 65 bytes (130 hex chars)

## Examples

### Generate a Wallet

```js
const wallet = tronChain.generateWallet();
console.log("Private Key:", wallet.keys.private);
console.log("Public Key:", wallet.keys.public);
console.log("Address:", wallet.address); // Address starting with 'T'
```

### Generate Address from Known Private Key

```js
const privateKey = "your_private_key_as_hex";
const publicKey = tronChain.getKeyPublic(privateKey);
const address = tronChain.getAddress(publicKey);

console.log("Address:", address); // e.g., TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW
```

### Validate an Address

```js
// Validate a TRON address
const isValid = tronChain.validateAddress("TJCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW");
console.log("Is valid:", isValid); // true

// Invalid address (wrong prefix)
const isInvalid = tronChain.validateAddress("1JCnKsPa7y5okkXvQAidZBzqx3QyQ6sxMW");
console.log("Is valid:", isInvalid); // false (doesn't start with T)
```

## Technical Details

### Address Generation

TRON addresses are generated as follows:

1. **Public Key Processing**:

   ```
   hash = Keccak-256(publicKey)
   addressBytes = last 20 bytes of hash
   ```

2. **Version Byte**:
   ```
   hashVersioned = 0x41 + addressBytes  // Add version byte 0x41
   address = Base58Check(hashVersioned)
   ```

The version byte 0x41 ensures that TRON addresses always start with 'T'.

### Validation

A TRON address is valid if:

- It starts with 'T'
- It can be decoded using Base58Check
- The decoded data has the correct version byte (0x41)
- The decoded data has the correct length (21 bytes: 1 version byte + 20 bytes hash)

### Key Generation

- **Private Key**: 32 random bytes (256 bits), represented as a 64-character hex string
- **Public Key**: Derived from the private key using the secp256k1 elliptic curve
  - Compressed: 33 bytes (66 hex chars), starting with 02 or 03
  - Uncompressed: 65 bytes (130 hex chars), starting with 04

## Source Code

The TRON implementation is located in `src/blockchains/tron.ts`.

```js
function getAddress(keyPublic) {
  // Convert public key to bytes
  const keyPublicBytes = hexToBytes(keyPublic);

  // Apply Keccak-256 hash to the public key
  const keccakHash = keccak_256(keyPublicBytes);

  // Take the last 20 bytes of the hash result
  const addressBytes = keccakHash.slice(keccakHash.length - 20);

  // Create versioned hash with TRON version byte 0x41
  const hashVersioned = createVersionedHash(addressBytes, 0x41);

  // Encode with Base58Check
  return encodeBase58Check(hashVersioned);
}

function validateAddress(address) {
  return validateBase58Check(address, 0x41, "T");
}
```

## TRON vs Ethereum

TRON's address derivation is similar to Ethereum's, with these key differences:

- TRON uses the Base58Check encoding (like Bitcoin) instead of hex encoding
- TRON adds a version byte (0x41) to ensure addresses start with 'T'
- TRON doesn't use an EIP-55 style checksum

Despite these differences, the core process (taking the last 20 bytes of the Keccak-256 hash of the public key) is the same, making TRON and Ethereum address derivation conceptually similar.

## Future Plans

Future updates may include support for:

- Transaction creation and signing
- Smart contract interaction
- TRC-10 and TRC-20 token support
- Multi-signature accounts
