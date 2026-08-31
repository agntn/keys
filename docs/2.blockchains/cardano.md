# Cardano

This document explains how to use the Cardano blockchain functionality in @agntn/keys.

## Importing

```javascript
import { useBlockchain } from "@agntn/keys";
import Cardano from "@agntn/keys/blockchains/cardano";

const cardanoBlockchain = useBlockchain(new Cardano());
```

## Features

Cardano implementation provides:

- Private key generation using the Ed25519 curve
- Public key derivation
- Address generation (Base, Enterprise, Reward/Stake, Testnet)
- Address validation
- Complete wallet generation

## Address Types

Cardano has several address types:

| Type         | Description                                                          | Format                              |
| ------------ | -------------------------------------------------------------------- | ----------------------------------- |
| Base         | Default address that includes both payment and staking functionality | `addr1...`                          |
| Enterprise   | Address without staking capabilities (no stake rights)               | `addr1e...`                         |
| Reward/Stake | Used for receiving staking rewards                                   | `stake1...`                         |
| Testnet      | Testnet versions of the above addresses                              | `addr_test1...` or `stake_test1...` |

## Examples

### Generate Keys

```javascript
// Generate a private key
const privateKey = cardanoBlockchain.generateKeyPrivate();
// '7b8074a3fd154ec3b43ec3c313f95ecccfa6badd0c23c41e2a3e9fad5693f8e3'

// Derive public key
const publicKey = cardanoBlockchain.getKeyPublic(privateKey);
// '4a4c0a3874ce48978a9b0e5842b22b1a96de44fd91e3be9c651d6af3b4e3d326'

// Generate both at once
const { keys } = cardanoBlockchain.generateKeys();
// { private: '...', public: '...' }
```

### Generate Addresses

```javascript
// Generate base address (default)
const baseAddress = cardanoBlockchain.getAddress(publicKey);
// 'addr1...'

// Generate enterprise address
const enterpriseAddress = cardanoBlockchain.getAddress(publicKey, "enterprise");
// 'addr1e...'

// Generate reward/stake address
const stakeAddress = cardanoBlockchain.getAddress(publicKey, "stake");
// 'stake1...'

// Generate testnet address
const testnetAddress = cardanoBlockchain.getAddress(publicKey, "testnet");
// 'addr_test1...'
```

### Validate Addresses

```javascript
// Validate an address
const isValid = cardanoBlockchain.validateAddress(
  "addr1q9kytfmxk3vdze7s5prpnrjl6j3qldqssvn7mkcpnpvd2p0ltsyswunewxmf58504d9tkqelz2vf02w0msgtvcuzdmsdhq0z4",
);
// true or false
```

### Generate Wallet

```javascript
// Generate wallet with default base address
const wallet = cardanoBlockchain.generateWallet();
// { keys: { private: '...', public: '...' }, address: 'addr1...' }

// Generate wallet with enterprise address
const enterpriseWallet = cardanoBlockchain.generateWallet(undefined, "enterprise");
// { keys: { private: '...', public: '...' }, address: 'addr1e...' }

// Generate wallet with reward/stake address
const stakeWallet = cardanoBlockchain.generateWallet(undefined, "stake");
// { keys: { private: '...', public: '...' }, address: 'stake1...' }

// Generate wallet with testnet address
const testnetWallet = cardanoBlockchain.generateWallet(undefined, "testnet");
// { keys: { private: '...', public: '...' }, address: 'addr_test1...' }
```

## Technical Implementation

This implementation provides a simplified version of Cardano addresses with the following characteristics:

- Uses Blake2b-224 for public key hashing (28 bytes), which is standard for Cardano
- Employs base58 encoding for the data portion of the address
- Uses proper prefixes to distinguish different address types:
  - `addr1` for mainnet payment addresses
  - `addr1e` for enterprise addresses
  - `addr_test1` for testnet payment addresses
  - `stake1` for mainnet staking addresses
  - `stake_test1` for testnet staking addresses

Note that this is a simplified implementation that follows Cardano's address format patterns but doesn't implement the full Cardano address specification with CBOR serialization. It is suitable for development and testing purposes.
