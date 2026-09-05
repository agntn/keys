/**
 * Common test fixtures
 * This file contains shared test data used across different test files
 */

// Secp256k1 keys - used for Bitcoin, Ethereum, etc.
export const secp256k1TestVectors = {
  // These are constant test vectors, not meant for production use
  privateKey: "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
  privateKeyWith0x: "0xc85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
  /** Not paired with `privateKey`; used only by the self-consistent address tests. */
  publicKeyCompressed: "0329fa449dde1228c0bacb3283310bca03022458709ad6f3fbb869a2a59c30b7d7",
};

// Ed25519 keys - used for Solana, Cardano, etc.
export const ed25519TestVectors = {
  // Standard test vector for ed25519
  privateKey: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
  publicKey: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
};

// BIP39 test vectors
export const bip39TestVectors = {
  mnemonic:
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  seed: "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
  passphrase: "TREZOR",
};

// Bitcoin test vectors
export const bitcoinTestVectors = {
  // Valid addresses for testing
  addresses: {
    p2pkh: {
      mainnet: "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
      testnet: "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
    },
    p2sh: {
      mainnet: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
      testnet: "2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc",
    },
  },
};

// Ethereum test vectors
export const ethereumTestVectors = {
  // Valid addresses for testing
  addresses: {
    mainnet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
  },
};

// Test messages
export const testMessages = {
  simple: "Test message",
  medium: "This is a longer test message for cryptographic signing operations",
  long: "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec a diam lectus. Sed sit amet ipsum mauris. Maecenas congue ligula ac quam viverra nec consectetur ante hendrerit.",
};

/** Disposable key 1 and Litecoin Core message hashes, independently serialized and SHA256d hashed. */
export const litecoinTestVectors = {
  privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
  publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  publicKeyHash: "751e76e8199196d454941c45d1b3a323f1433bd6",
  address: "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ",
  messageHashes: [
    ["hello", "51bd869e89676860cf1d778b8735f5e6768da32023d3dcd951711bd21c669d4c"],
    ["é".repeat(127), "08bebd99b9d1fbd73231de22e544e9b0b75c0c54ab6e3128f53665cdf944477f"],
  ],
} as const;

/** Disposable key 1, dcrd stdaddr v4.1.2 and chainhash v1.0.5 with wire v1.7.5. */
export const decredTestVectors = {
  privateKey: "00".repeat(31) + "01",
  publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  addresses: {
    mainnet: "DsmcYVbP1Nmag2H4AS17UTvmWXmGeA7nLDx",
    testnet: "TsmfmUitQApgnNxQypdGd2x36djCCpDpERU",
  },
  uncompressedAddresses: {
    mainnet: "DsbnCMAYV13buumdjHuwiJeJWZWvgjZRTbE",
    testnet: "TsbqRLJ3so6i2GSzYgY6rsfa6fUrFMfSDJD",
  },
  signature:
    "4e590293bb394c5d2a5d21fc2c166fb372c706068dc120e3fe71aaccad831006586d0eb88c6c92b6eb04432fec4550d6ccf9351e02112efa3833f5c0b00e9b36",
  messageHashes: [
    ["", "edec5d11d20ee5ea952da86dba18b453f520d778d40b1004908ed93ea22f93ce"],
    ["hello", "776fea952d41c5269b91e9710afcd91103ad41a06e814f8ecba72f49044fdfe6"],
    ["żółw 🐢", "6e3c8c1752e8b6fd010c84c21bfd51496ef47ff4fcc2c81142f80c208e42093b"],
    ["a".repeat(252), "2c729fc2b4296dfb76b3413208d655beda09aa4fd7b64715c26fe7f85e690e3a"],
    ["a".repeat(253), "f7fafe4c0f9f82d637608c35852c1a0056c9ef22d52ca43735b321d64c88cde6"],
    ["a".repeat(65535), "2f3422e725451a9834251b25b1f7ade328740cf70a7e14c4119b32d469175481"],
    ["a".repeat(65536), "5097489a2d963b9deec6554a0edc4528bef4fc2fe530279c486967efdab79bd7"],
  ],
} as const;
