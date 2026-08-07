----
icon: simple-icons:sui
---

# SUI

## Introduction

SUI implementation supporting both ed25519 and secp256k1 curves, with addresses derived using BLAKE2b-256 hash.

## Usage

**Driver name:** `sui`

```js
import { useBlockchain } from "ubichain";
import Sui from "ubichain/blockchains/sui";

const suiChain = useBlockchain(new Sui());
```

## Features

- **Curves**: ed25519 (default) and secp256k1
- **Address Format**: Hex-encoded 32-byte BLAKE2b hash with '0x' prefix
- **Public Key Formats**:
  - ed25519: 32 bytes (64 hex chars)
  - secp256k1: 33 bytes (66 hex chars) - compressed

## Examples

### Generate a Wallet with Default Curve (ed25519)

```js
const wallet = suiChain.generateWallet();
console.log("Private Key:", wallet.keys.private);
console.log("Public Key:", wallet.keys.public);
console.log("Address:", wallet.address); // 0x-prefixed address (ed25519)
```

### Generate a Wallet with Secp256k1 Curve

```js
const walletSecp = suiChain.generateWallet({ scheme: "secp256k1" }, "secp256k1");
console.log("Private Key:", walletSecp.keys.private);
console.log("Public Key:", walletSecp.keys.public);
console.log("Address:", walletSecp.address); // 0x-prefixed address (secp256k1)
```

### Generate Address from Known Private Key

```js
// Using ed25519 (default)
const privateKey = "your_private_key_as_hex";
const publicKey = suiChain.getKeyPublic(privateKey);
const address = suiChain.getAddress(publicKey);

console.log("Address (ed25519):", address);

// Using secp256k1
const publicKeySecp = suiChain.getKeyPublic(privateKey, { scheme: "secp256k1" });
const addressSecp = suiChain.getAddress(publicKeySecp, "secp256k1");

console.log("Address (secp256k1):", addressSecp);
```

### Validate an Address

```js
// Validate a SUI address
const isValid = suiChain.validateAddress(
  "0x7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936",
);
console.log("Is valid:", isValid); // true

// Invalid address (wrong format)
const isInvalid = suiChain.validateAddress(
  "7e08ac7940568c91564ddc6f5f3bf91b15a9334194ab7855daeac51c5cc74936",
);
console.log("Is valid:", isInvalid); // false (missing 0x prefix)
```

## Technical Details

### Address Generation

SUI addresses are generated as follows:

1. **Flag Byte**:

   ```
   flagByte = 0x00 for ed25519 or 0x01 for secp256k1
   ```

2. **Address Generation**:
   ```
   input = flagByte + publicKey  // Concatenate flag byte with public key
   address = '0x' + BLAKE2b-256(input)  // Hash with BLAKE2b-256
   ```

### Signature Scheme Flags

SUI supports multiple signature schemes, identified by flag bytes:

- `0x00`: Ed25519
- `0x01`: Secp256k1
- `0x02`: Secp256r1 (not currently supported in ubichain)
- `0x03`: Multisig (not currently supported in ubichain)

### Validation

A SUI address is valid if:

- It starts with '0x' prefix
- It contains exactly 64 hex characters after the prefix (32 bytes)
- All characters are valid hex characters (0-9, a-f, A-F)

### Key Generation

- **Private Key**: 32 random bytes (256 bits), represented as a 64-character hex string
- **Public Key**:
  - ed25519: 32 bytes (64 hex chars)
  - secp256k1: 33 bytes (66 hex chars) - compressed

## Source Code

The SUI implementation is located in `src/blockchains/sui.ts`.

```js
function getKeyPublic(keyPrivate, options) {
  // Extract scheme from options or use default 'ed25519'
  const scheme = options?.scheme || "ed25519";

  if (scheme.toLowerCase() === "secp256k1") {
    return getSecp256k1KeyPublic(keyPrivate, { compressed: true });
  }

  // Default to Ed25519
  return getEd25519KeyPublic(keyPrivate);
}

function getAddress(keyPublic, type) {
  // Convert public key to bytes
  const keyPublicBytes = hexToBytes(keyPublic);

  // Determine flag byte based on scheme
  let flagByte;
  if (type?.toLowerCase() === "secp256k1") {
    flagByte = SIGNATURE_SCHEME_FLAGS.SECP256K1; // 0x01
  } else {
    // Default to Ed25519
    flagByte = SIGNATURE_SCHEME_FLAGS.ED25519; // 0x00
  }

  // Create input for hashing: flag byte + public key
  const input = new Uint8Array(keyPublicBytes.length + 1);
  input[0] = flagByte;
  input.set(keyPublicBytes, 1);

  // Hash with BLAKE2b-256
  const hash = blake2b(input, { dkLen: 32 }); // 32 bytes = 256 bits

  // Return hex representation of the hash with 0x prefix
  return "0x" + bytesToHex(hash);
}

function validateAddress(address) {
  if (!address.startsWith("0x")) {
    return false;
  }

  // Remove '0x' prefix
  const addressWithoutPrefix = address.slice(2);

  // Check if it's 32 bytes (64 hex chars)
  if (addressWithoutPrefix.length !== 64) {
    return false;
  }

  // Check if it's valid hex
  const hexRegex = /^[0-9a-fA-F]+$/;
  return hexRegex.test(addressWithoutPrefix);
}
```

## Multi-curve Support

SUI is unique among the supported blockchains in that it natively supports multiple cryptographic curves for the same blockchain:

1. **Options for Key Generation**:
   - Use the `scheme` option when generating a public key:
     ```js
     const publicKey = suiChain.getKeyPublic(privateKey, { scheme: "secp256k1" });
     ```

2. **Options for Address Generation**:
   - Use the address type parameter when generating an address:
     ```js
     const address = suiChain.getAddress(publicKey, "secp256k1");
     ```
   - Or when generating a wallet:
     ```js
     const wallet = suiChain.generateWallet({ scheme: "secp256k1" }, "secp256k1");
     ```

## Future Plans

Future updates may include support for:

- Secp256r1 curve support
- Multisig addresses
- Transaction creation and signing
- Object ID handling
- Move smart contract interaction
