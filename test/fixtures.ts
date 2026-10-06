/**
 * Common test fixtures
 * This file contains shared test data used across different test files
 */

// Secp256k1 keys - used for Bitcoin, Ethereum, etc.
export const secp256k1TestVectors = {
  // These are constant test vectors, not meant for production use
  privateKey: "c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4",
  /** The compressed key of `privateKey`, the same bytes ethers derives in `ethereumTestVectors`. */
  publicKeyCompressed: "030947751e3022ecf3016be03ec77ab0ce3c2662b4843898cb068d74f698ccc8ad",
  /** The group order n, one above the largest valid private key. */
  curveOrder: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
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
  seedWithPassphrase:
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
};

/** Trezor's `7f7f...` vector, last six words scattered; 51 of 720 orders pass `@scure/bip39`. */
export const bip39WordOrderVector = {
  mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
  template: "legal winner thank year wave sausage ? ? ? ? ? ?",
  words: ["yellow", "thank", "winner", "legal", "useful", "worth"],
  orders: 720,
  valid: 51,
  first: "legal winner thank year wave sausage legal thank worth yellow useful winner",
};

/** The typo from #200 and Trezor's `7f7f...` vector with two words off. */
export const bip39WordRepairVectors = {
  typo: {
    written:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abuot",
    mnemonic:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  },
  twoWords: {
    written: "legal winnr thank year wave sausage worth useful legal winner thank yelow",
    mnemonic: "legal winner thank year wave sausage worth useful legal winner thank yellow",
    positions: [2, 12],
    combinations: 54,
    valid: 7,
  },
};

/** Wallets bip_utils 2.9.3 derives from the BIP39 reference mnemonic at each chain's own path. */
export const slip10WalletVectors = [
  {
    chain: "solana",
    path: "m/44'/501'/0'/0'",
    address: "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk",
  },
  {
    chain: "aptos",
    path: "m/44'/637'/0'/0'/0'",
    address: "0xeb663b681209e7087d681c5d3eed12aaa8e1915e7c87794542c3f96e94b3d3bf",
  },
  {
    chain: "sui",
    path: "m/44'/784'/0'/0'/0'",
    publicKey: "900b4d81eecea3df2f74b14200c4f4cf3f49afaca7a634ffd2cf6ff82bdaecf2",
    address: "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1",
  },
] as const;

/** Public, claimed Bitcoin Movie Enigma solution: floflo777/open-crypto-puzzles#24. */
export const invalidChecksumPuzzle = {
  mnemonic:
    "path mad alien apology escape spare miss goddess leopard crime visit clock start first blade guard close barrel term screen matrix toy ghost shine",
  path: "m/84'/0'/0'/0/0",
  address: "bc1q94ecsn0qk8lap2gefrycnms3ruepy889z969a6",
  publicKey: "022c17f7486b4107b42a243a62e4d0919af3e8ee858a272319bffb0536486b9405",
  /** ethers 6.17.0 `HDNodeWallet.fromSeed` over the BIP39 PBKDF2 seed of the same words. */
  withPassphrase: {
    passphrase: " e\u0301 ",
    path: "m/84'/0'/0'/1/2",
    publicKey: "0248b84ccd2a9aefdd556e3550eb4dff2de903b2eef7718be305ddc9394f43a5ab",
  },
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

/**
 * Key and compact r/s from Bitcoin Core `rpc_signmessagewithprivkey.py`.
 * Digests serialized and SHA256d hashed independently of the library.
 */
export const bitcoinMessageVectors = {
  wif: "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N",
  privateKey: "d2b8a0116d641fe7d3036f8464628fb595b480414c13a301b3d4038c811c28b0",
  address: "mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB",
  message: "This is just a test message",
  signature:
    "d6d59d6e1ee8f7919acbf6420bbc36ea29beb56391cc686feb17f0e7191b44802e15b26d48f330b3dd02c5c8e3a61919bd0a4134628bec16210cd1a46fd4f92d",
  /** `expected_signature` from the same test, whole: the header byte, then r and s, in base64. */
  compactSignature:
    "INbVnW4e6PeRmsv2Qgu8NuopvrVjkcxob+sX8OcZG0SALhWybUjzMLPdAsXI46YZGb0KQTRii+wWIQzRpG/U+S0=",
  messageHashes: [
    ["", "80e795d4a4caadd7047af389d9f7f220562feb6196032e2131e10563352c4bcc"],
    ["hello", "cf0447ec85f0ce7150a257db32ebfcb7523dae17c36dbd1be598779fec0484f4"],
    ["żółw 🐢", "b92600fa044f4cd79dcce11da333de64ebf17ceeb32c4d847226b1e9b5a23c06"],
    ["a".repeat(252), "b7b164ef991d52735c6bb888642ad7eb6b6939dc984a7fceff4376be041d142f"],
    ["a".repeat(253), "df167ad249ff5837e6acada677118b2ecc6757ab4cdade39caead99ef0220230"],
    ["a".repeat(65535), "fade4e6ebe191b9dcf869e37c4ab6a2d5f9ffc1160fbfb84370afb579af7de8d"],
    ["a".repeat(65536), "d5db7ae9446693355e5674d5d17e7b0a29f13fc174055077d9613e9ab2b462fe"],
  ],
} as const;

/**
 * Trezor `test_signmessage.py` signatures in hex, under the BIP137 header, then Electrum's.
 * @see https://github.com/trezor/trezor-firmware/blob/c33f81554a51b8b182082535ccedd3dde8f07005/tests/device_tests/bitcoin/test_signmessage.py
 */
export const bip137MessageVectors = {
  message: "This is an example of a signed message.",
  signatures: [
    [
      "legacy",
      "1JAd7XCBzGudGpJQSDSfpmJhiygtLQWaGL",
      "20fd8f2f7db5238fcdd077d5204c3e6949c261d700269cefc1d9d2dcef6b95023630ee617f6c8acf9eb40c8edd704c9ca74ea4afc393f43f35b4e8958324cbdd1c",
      "20fd8f2f7db5238fcdd077d5204c3e6949c261d700269cefc1d9d2dcef6b95023630ee617f6c8acf9eb40c8edd704c9ca74ea4afc393f43f35b4e8958324cbdd1c",
    ],
    [
      "p2sh",
      "3L6TyTisPBmrDAj6RoKmDzNnj4eQi54gD2",
      "23744de4516fac5c140808015664516a32fead94de89775cec7e24dbc24fe133075ac09301c4cc8e197bea4b6481661d5b8e9bf19d8b7b8a382ecdb53c2ee0750d",
      "1f744de4516fac5c140808015664516a32fead94de89775cec7e24dbc24fe133075ac09301c4cc8e197bea4b6481661d5b8e9bf19d8b7b8a382ecdb53c2ee0750d",
    ],
    [
      "segwit",
      "bc1qannfxke2tfd4l7vhepehpvt05y83v3qsf6nfkk",
      "28b55d7600d9e9a7e2a49155ddf3cfdb8e796c207faab833010fa41fb7828889bc47cf62348a7aaa0923c0832a589fab541e8f12eb54fb711c90e2307f0f66b194",
      "20b55d7600d9e9a7e2a49155ddf3cfdb8e796c207faab833010fa41fb7828889bc47cf62348a7aaa0923c0832a589fab541e8f12eb54fb711c90e2307f0f66b194",
    ],
  ],
} as const;

/**
 * `secp256k1TestVectors.privateKey` through ethers 6.17.0: `SigningKey` public keys, the
 * `Wallet` address, `hashMessage` digests and `signMessage` signatures.
 */
export const ethereumTestVectors = {
  privateKey: secp256k1TestVectors.privateKey,
  publicKey: "030947751e3022ecf3016be03ec77ab0ce3c2662b4843898cb068d74f698ccc8ad",
  publicKeyUncompressed:
    "040947751e3022ecf3016be03ec77ab0ce3c2662b4843898cb068d74f698ccc8ad75aa17564ae80a20bb044ee7a6d903e8e8df624b089c95d66a0570f051e5a05b",
  address: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
  /** Message, its EIP-191 digest, the signature with the recovery byte. */
  messages: [
    [
      "",
      "5f35dce98ba4fba25530a026ed80b2cecdaa31091ba4958b99b52ea1d068adad",
      "68c36703cfae77b264e66cf9587aa39dd76b66ff1317e563b4566d9ea5d8d60e5b9be8c58a324e1dbb424365aa778a2faec2d3f922bf0339cda43d76c492a5ab1c",
    ],
    [
      "Test message",
      "d81bbffb92157b72ceae3da72eb8224976ba42a49621822789edb0735a0e0395",
      "be6796821c2054a4e5dc8beef695d7cd8df747bbf04750e95067052f50ba17b05f764771f7cf0d646b0df0164ca09b6fdf78940115ecb3bbdda3a494693dc2991c",
    ],
    [
      "This is a longer test message for cryptographic signing operations",
      "e30363a6bebbdf88c11906195f420253bdae8d6cfe1ec1c5fa3bef235bc5718b",
      "099d52a5cd3ab8f9a43bb29e1e323fa846898bf85043fe45a345d9a7948813dd71ac7e96df41ccd3d66ff7e23c961f05a82721782aa6b8f5b3c0a8baf55dc1001b",
    ],
    [
      "żółw 🐢",
      "8d43eecb992097c0aebe89bbee97a384f1565c97fac4661ab7ce2b8c4a53fa42",
      "c9d2e75a94c028974713fbb611ffc40443b3876cf977fec48cde46d28c291ee52a32ffc4cc81fdfc8ddef247d66a8c1d6accd17bb54966556dfef7883e6b6d921c",
    ],
    [
      "a".repeat(256),
      "5e00ae3038bc416a1354dc7d995adb1cd435ff7dcfc7bfe50a7d3035b6576e54",
      "751891552b4523e721b5985083780ab2de24a365618c671a6bdcdda7c3ffa0a03b748e0f1e749dda4d491db1169ecac51dd14d00b9b3a9fd3b7755be0ffffbec1c",
    ],
  ],
} as const;

/**
 * Disposable key 1 through @solana/web3.js 1.98.4 and tweetnacl 1.0.3: the `Keypair.fromSeed`
 * public key and address, `nacl.sign.detached` signatures the way wallet adapters sign messages.
 */
export const solanaTestVectors = {
  privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
  publicKey: "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
  address: "6ASf5EcmmEHTgDJ4X4ZT5vT6iHVJBXPg5AN5YoTCpGWt",
  /** Message, its signature. */
  messages: [
    [
      "",
      "7e1b9dc1e332c4238edcd07a68101474b640fdcb1b7b84fb711ac4bfbc85eb85a77480950d69398dcd19f61e1ea74d0f183cfbf34df8f6e7733ebfb9f944f106",
    ],
    [
      "Test message",
      "dbc97709329484d8d3b3ed7e9b8b0c916f4ed7a6be9c31d2f9e5801ee7e70fbe538af669d99b9a047a9d6595f409c7d6d1be7f90fb348aeb7da5d694b16f0f08",
    ],
    [
      "This is a longer test message for cryptographic signing operations",
      "742ce226b09cfd7ddf96d6ba33f852c01f7c5f490fa3426b61ced033a2e6366c4d86749c3e7578ad0755c7226d7cbcf21964909cf64c42d813c238f3e267c200",
    ],
    [
      "żółw 🐢",
      "8246ac7fd8fe6b7ee71695b9a8f4590b7d397ba2612e88503f8dcc6d357fb1609a71954ed7a33d578ff9a1d0d9d616460c248069e55d0f6fec856764ad6f880b",
    ],
    [
      "a".repeat(256),
      "fb5a01cfc088e45c904d410a0008c0f1b5e459e03e83c1b63e58389cd5b5296414656bab34241f359c1d41d571dfbfb5ccc0e18d0543d27b81179ff1a7cbaa06",
    ],
  ],
} as const;

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
  /** Each format of the key, its prefix and program checked once with `@scure/base` 2.4.0. */
  addresses: {
    mainnet: {
      legacy: "LVuDpNCSSj6pQ7t9Pv6d6sUkLKoqDEVUnJ",
      p2sh: "MR8UQSBr5ULwWheBHznrHk2jxyxkHQu8vB",
      segwit: "ltc1qw508d6qejxtdg4y5r3zarvary0c5xw7kgmn4n9",
      p2wsh: "ltc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qmu8tk5",
      taproot: "ltc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sszjagvq",
    },
    testnet: {
      legacy: "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r",
      p2sh: "QdqJHJa9kv3x4AksVMTQAkD3122J1Pbb8p",
      segwit: "tltc1qw508d6qejxtdg4y5r3zarvary0c5xw7klfsuq0",
      p2wsh: "tltc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qsnr4fp",
      taproot: "tltc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5ssfaekn4",
    },
  },
  messageHashes: [
    ["hello", "51bd869e89676860cf1d778b8735f5e6768da32023d3dcd951711bd21c669d4c"],
    ["é".repeat(127), "08bebd99b9d1fbd73231de22e544e9b0b75c0c54ab6e3128f53665cdf944477f"],
  ],
  /**
   * Litecoin Core's `signmessagewithprivkey` case, on Bitcoin Core's key and testnet address.
   * @see https://github.com/litecoin-project/litecoin/blob/ec1b6489a900d09cf5991e220dce089c77a232a2/test/functional/rpc_signmessage.py
   */
  signed: {
    privateKey: "d2b8a0116d641fe7d3036f8464628fb595b480414c13a301b3d4038c811c28b0",
    address: "mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB",
    message: "This is just a test message",
    signature:
      "IGve8AOjIcu+a/nYW1PABSfmp2oQlEqLIOwPgNW5/Y5teggr8S0vy4SMdjL2Viv3iuBZjJbhvyBo0tv5m3H63b8=",
  },
  /**
   * ethers 6.17.0 `HDNodeWallet.fromPhrase` with the TREZOR passphrase at
   * `m/<purpose>'/2'/0'/1/2`: purpose, its address type, private key, public key.
   */
  hd: [
    [
      44,
      "legacy",
      "3282733e395ba097d4fd27e5200230627ab2ff5ee67e04dc04919c9d5d485600",
      "022da301385edaa8db654667235e83ee55efe5593fe68769d60818778f4288067e",
    ],
    [
      49,
      "p2sh",
      "76bc000dffb77db140f68da9772a375b35856b23d100f243059c037b52772232",
      "0377151352b1cef4760dfc15802d64472280b7a2b5462a3ffc0e1547f28a11b9c0",
    ],
    [
      84,
      "segwit",
      "44098b21e37b0032915f998ca37745222efd201f76b1b8f72004823232526c19",
      "0306255d1a2346537e2afb8ff0546f8e135640209df38a0e8da2652d4744ecf2c3",
    ],
    [
      86,
      "taproot",
      "9106c4220ad0ff7bcd2c01d9522c4eac4997d463bb75da3271acf7ac47ef7fef",
      "020d12c167a74f47363ca017c419cbed0f1d0b6921b20e76f102264f28410e88c1",
    ],
  ],
} as const;

/**
 * Signer recovery vectors: `personalSign` from viem as issue #195 gives it, `mail` from the EIP's
 * own `Example.js` (key: keccak256 of `cow`, `secp256k1TestVectors.privateKey`), and `hunt`
 * signed with that key through ethers 6.17.0 `TypedDataEncoder.hash` and `Wallet.signTypedData`.
 */
export const evmRecoverTestVectors = {
  personalSign: {
    message: "hello",
    signature:
      "f16ea9a3478698f695fd1401bfe27e9e4a7e8e3da94aa72b021125e31fa899cc573c48ea3fe1d4ab61a9db10c19032026e3ed2dbccba5a178235ac27f94504311c",
    address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
  },
  mail: {
    typedData: {
      types: {
        EIP712Domain: [
          { name: "name", type: "string" },
          { name: "version", type: "string" },
          { name: "chainId", type: "uint256" },
          { name: "verifyingContract", type: "address" },
        ],
        Person: [
          { name: "name", type: "string" },
          { name: "wallet", type: "address" },
        ],
        Mail: [
          { name: "from", type: "Person" },
          { name: "to", type: "Person" },
          { name: "contents", type: "string" },
        ],
      },
      primaryType: "Mail",
      domain: {
        name: "Ether Mail",
        version: "1",
        chainId: 1,
        verifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
      },
      message: {
        from: { name: "Cow", wallet: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826" },
        to: { name: "Bob", wallet: "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB" },
        contents: "Hello, Bob!",
      },
    },
    digest: "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2",
    signature:
      "4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c",
    address: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
  },
  hunt: {
    typedData: {
      types: {
        Clue: [
          { name: "index", type: "uint8" },
          { name: "offset", type: "int64" },
          { name: "solved", type: "bool" },
          { name: "tag", type: "bytes4" },
          { name: "blob", type: "bytes" },
        ],
        Hunt: [
          { name: "title", type: "string" },
          { name: "owner", type: "address" },
          { name: "clues", type: "Clue[]" },
          { name: "grid", type: "uint256[2][]" },
          { name: "words", type: "string[]" },
        ],
      },
      primaryType: "Hunt",
      domain: {
        name: "Puzzle",
        chainId: 8453,
        salt: "0xabababababababababababababababababababababababababababababababab",
      },
      message: {
        title: "żółw",
        owner: "0x000000000000000000000000000000000000dEaD",
        clues: [
          { index: 7, offset: -42, solved: true, tag: "0xdeadbeef", blob: "0x" },
          {
            index: 255,
            offset: "-9223372036854775808",
            solved: false,
            tag: "0x00000001",
            blob: "0x0102030405",
          },
        ],
        grid: [
          [1, 2],
          [
            "0xff",
            "115792089237316195423570985008687907853269984665640564039457584007913129639935",
          ],
        ],
        words: ["abandon", ""],
      },
    },
    digest: "5479f477cc907f5435100a6974f3e8b7dba026c9a0be9994524fb40d4d603f69",
    signature:
      "cbe874b5da1385b53a1aba0e88531d1df82db0fba5dcfe38cf3988a34ad7cf16107221f67b4a3b2b41afbb365ebec1be625878b318d85eddd2de2998958cb7291c",
    address: "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
  },
} as const;

/** Disposable key 1 through TronWeb 6.5.1: `hashMessage` digests and `signMessageV2` signatures. */
export const tronTestVectors = {
  privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
  publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  address: "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC",
  messages: [
    [
      "",
      "5beedb3d65d99ecaf9857d8695e750cc56278093f4ccbd1cc4e561fc82b1d189",
      "5fc8883facaeb9dbebe71ec179c2744f83dc0e4868c6c9a6d63d47b949f33ae4317dc553f28a9c64b06838dc1adf7f24da330394f05e4ea6318d18608293ffe91b",
    ],
    [
      "Test message",
      "2cb3644091a57a35cca1396e16625a0bff896ba9ff8c4eaa93d89e9f131c7435",
      "b88e4ef1a8c86ee2bc9b89383a65f758b6f1bb16c0b4b24c4c6704059cec6dbe1a2a5e1d5586eae5cef80041ac200071cde08aa06736dd25c30da452f0f60df11c",
    ],
    [
      "żółw 🐢",
      "b7a27900510b74e563c19d2d27a7035ffa7824459584701c1b035101c1114e78",
      "c767e7e02259fb22b7e54f54782e313a66343c78533385cc31b33582a0ca77130894b6bd0341a77770a25ab3af909e7c3c1e88879797e57a4bdc30c22afdf9031b",
    ],
    [
      "a".repeat(256),
      "96e2d5cbc09c351edbb3980269c1ad387c002a75cbcc0c190ab9c5c1dc469e30",
      "7dd4e536adb0bc06cb27ee146f44e9eb7be17084ed5ff0a648dfe180edb54c0a4109b4b0a4d1642267aecfb5dfcc482b1142b743842c80b90ac1d58f18df40441c",
    ],
  ],
} as const;

/** Disposable key 1 through @mysten/sui 2.31.2: `signPersonalMessage` digests and signatures. */
export const suiTestVectors = {
  privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
  ed25519: {
    publicKey: "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
    address: "0xd0c2c91eda34bbfbaec6cfb9c7bb913e57dab3cbec4018a4b3f5e55531cd63af",
  },
  secp256k1: {
    publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    address: "0xd4c3524e6642b2e54945c02378024f822ac3f80b0870a5f95f06e68a61890a6c",
  },
  /** Message, its personal message digest, the ed25519 signature, the secp256k1 signature. */
  messages: [
    [
      "",
      "8c039ff7caa17ccebfcadc44bd9fce6a4b6699c4d03de2e3349aa1dc11193cd7",
      "6bc078f207deeabc4af04577c90a5421d75a690103e2d05f570935ff5d6e20154a70ffc0e1509e41579ab21a181005263b5262cea4ab1eb0545dd313ee38200e",
      "808c7c786b87342dd8b2d6897707acb5e6730893a1f7b099310010a28cfc529d2c7c4f38f8bb93f0527052e37d88da1b3ec26d456ebf8b596e4254715a55b7e8",
    ],
    [
      "Test message",
      "110d270cf8e11730b64fd208fe074dee4406e8c7b5d38ff37c6a4bf895b3c2f8",
      "d9c974f42754fb75c996712d474b3e80ab10e232593aa4402e5a725c2fa7d9f37258d062563cf45ef73ffe24949e11a2eacc94fa25e81d40c7b9da394ccb5f01",
      "47120cf0e39145bc9db74eca6bba8fc3afb3727df94b22618951d7f6cc1b4d1b575b2282271477e152bb3333eeab5c44f7a9be78622d7d75fd33772c3cbce328",
    ],
    [
      "żółw 🐢",
      "276ae078c862bd0ba7a528c36f37297335bfbb4c1c5d27c95fd0f9711aefc012",
      "f1fe5a849bca9a67133397cff17d4079e155005ce38b53c17285d67bcda0e81b84b418c195d419495d7832a0fa590293dfa9ccd1f1915850f73669d14898da06",
      "7e2379b525bbc563b3cc1580fe6588fc789cf3777c2360ceffd2b144156e034e7516850d3f5839fb1437b66fef7a20b236cc22898e7e1ca8239245333c1b4907",
    ],
    [
      "a".repeat(256),
      "5488dc294edbb02a0a9105597a4ebf0c14f12aaf7fb67897103a835993055577",
      "8b7ac04d371ce61185c3cdccab95bbc86409c07ccb3ac687879d3dbef63bb3aaf844458467e451517246c74f8ce5f623f2599c7fa662494172d072d09e77f20d",
      "63b2c7172fc7148d670e12b950d09398b01bf067486527170d09d051027db14b3679dc4ebc4cdde544d75b8d90722639049785f29b361c8d381ae141269e5f20",
    ],
  ],
} as const;

/**
 * XRP Ledger vectors from ripple-keypairs 3.1.0 and xrpl 5.3.0. `master` is the genesis account
 * of the passphrase `masterpassphrase`; the other seeds carry the entropy 00 to 0f.
 */
export const xrplTestVectors = {
  seeds: {
    master: {
      seed: "snoPBrXtMeMyMHUVTgbuqAfg1SUTb",
      privateKey: "1acaaedece405b2a958212629e16f2eb46b153eee94cdd350fdeff52795525b7",
      publicKey: "0330e7fc9d56bb25d6893ba3f317ae5bcf33b3291bd63db32654a313222f7fd020",
      address: "rHb9CJAWyB4rj91VRWn96DkukG4bwdtyTh",
    },
    secp256k1: {
      seed: "sp6JdwovBCsiwnMhXuvZGZtPUoGVj",
      privateKey: "baa795362c6e48b9722325d0dcbd5a1e2cd4935c6cb12816daec50f87487bf84",
      publicKey: "0257cf4f3929f535518d624292d62ace47e9da563d7dfa7ea4c6bc24258ab467b7",
      address: "rU2k1U7W1xToQrFQW8gyWiXQFqVkJwrSn9",
    },
    ed25519: {
      seed: "sEdSJHdnVumf99WfaHTnU8DaQkx5Q4n",
      privateKey: "daa295beed4e2ee94c24015b56af626b4f21ef9f44f2b3d40fc41c90900a6bf1",
      publicKey: "ed951bf8b3b7c8aa4bc1b91790fc1b3ff7155cd729c2e6f038a93f5f3b9035dd85",
      address: "rGMTQpyhaDwWTqmw4dcYHj5NPJhtWNhtRW",
    },
  },
  /** The same seeds read under the other scheme, as `deriveKeypair` does with an algorithm. */
  crossed: {
    secp256k1AsEd25519: {
      seed: "sp6JdwovBCsiwnMhXuvZGZtPUoGVj",
      privateKey: "daa295beed4e2ee94c24015b56af626b4f21ef9f44f2b3d40fc41c90900a6bf1",
      publicKey: "ed951bf8b3b7c8aa4bc1b91790fc1b3ff7155cd729c2e6f038a93f5f3b9035dd85",
      address: "rGMTQpyhaDwWTqmw4dcYHj5NPJhtWNhtRW",
    },
    ed25519AsSecp256k1: {
      seed: "sEdSJHdnVumf99WfaHTnU8DaQkx5Q4n",
      privateKey: "baa795362c6e48b9722325d0dcbd5a1e2cd4935c6cb12816daec50f87487bf84",
      publicKey: "0257cf4f3929f535518d624292d62ace47e9da563d7dfa7ea4c6bc24258ab467b7",
      address: "rU2k1U7W1xToQrFQW8gyWiXQFqVkJwrSn9",
    },
  },
  secp256k1: {
    privateKey: secp256k1TestVectors.privateKey,
    publicKey: "030947751e3022ecf3016be03ec77ab0ce3c2662b4843898cb068d74f698ccc8ad",
    address: "rPbAjuQPsy9EsZ8bbW7vuehzFgkQuSbgDn",
  },
  ed25519: {
    privateKey: ed25519TestVectors.privateKey,
    publicKey: "edd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    address: "rGoMvPW8NFU9vkcAQVuFj9buMLjxhxRsVS",
  },
  /** `sign` from ripple-keypairs over the UTF-8 of the message: DER on secp256k1, raw ed25519. */
  message: "Hello, XRPL!",
  signatures: {
    secp256k1:
      "3044022046dd48c3be34085bcb8d7be30b9ffb606b76b0e57e68b4ad29055da6d97f19e0022079b9fd73393c0c58c548fb8beaf56fc0c9dad212eb570db757d77891b35974a8",
    ed25519:
      "9868a85b8b76eba315c116ab5fe9213ad00e0b873dc9c7fd596362eabe02ecb14534dcf32ca886fae54558a8a78b80e73d8fe7e36c4a0de4297ea08c407dd800",
  },
  /** Path, public key and address of `bip39TestVectors.mnemonic` through `Wallet.fromMnemonic`. */
  hd: [
    [
      "m/44'/144'/0'/0/0",
      "031d68bc1a142e6766b2bdfb006ccfe135ef2e0e2e94abb5cf5c9ab6104776fbae",
      "rHsMGQEkVNJmpGWs8XUBoTBiAAbwxZN5v3",
    ],
    [
      "m/44'/144'/0'/0/1",
      "038bf420b5271ada2d7479358ff98a29954cf18dc25155184aead05796da737e89",
      "r3AgF9mMBFtaLhKcg96weMhbbEFLZ3mx17",
    ],
    [
      "m/44'/144'/1'/0/0",
      "03ac5dad4e5953653175bf01d566788a3c4c1d101dfc5144a541244b0c68e10446",
      "rNAB7uPziNwZAkdzyeo6xRA9pKTsJxZ6td",
    ],
  ],
  /** X-address of `secp256k1.address`, a format `validateAddress` leaves to the classic one. */
  xAddress: "XVjUbnJUzL9Vb5zXMPdoFURPqGtaRzBkr5DuJfResXEzcKh",
} as const;

/**
 * BIP39 reference wallets from near-seed-phrase 0.2.1, the last at the near-ledger-js default path.
 * The signature is tweetnacl 1.0.3 over the message bytes with the first key.
 */
export const nearTestVectors = {
  wallets: [
    [
      "m/44'/397'/0'",
      "0c158d858a52316667d03d1d04aad51b3b542cd705215810629b78c501492fba",
      "5510e2b44cae6eb807e3e0e45d579dda058c274abcba15e5cb84636f5d1ee412",
      "ed25519:6j4b6zUaty6fD1awqcGCCU9JYGCWYUgdJhQrzfZhqE25",
    ],
    [
      "m/44'/397'/1'",
      "a20b5f6c6f2148bc42fe70cbfa5c367e95672c8bcffddfe4feb1f326dac40e4a",
      "3b93b03253b9715213ec314eb50ecc99d25602ccb5b059f91f51d24710d54326",
      "ed25519:51ZftJ8qPN8mJ3oqgQb3fqPbotQVZfTC4mxLgwz34FTK",
    ],
    [
      "m/44'/397'/0'/0'/1'",
      "f91834d6b845460fe0e9929bff2fbf564b6a9e4b0453af77c0141220ab519942",
      "c571e33e2e36c2c728d617ea77a88e2320c8697eac8b463adfc0128b96825cbf",
      "ed25519:EHk3HArKPRpX7564aTMD7VJdbQRoWA9JvJaEvbta2iSz",
    ],
  ],
  message: "near me",
  signature:
    "5d5bac2d9f2457d2f3de4b2d1d8e82cec5b3f079cc629fdddcba5ddf259963ff007ae06716761d7c7722728c8502d0df2839dc115702d1068a254806f4db3203",
} as const;

/**
 * BIP39 wallets from @cosmjs/amino 0.39.0 under three prefixes. The signature is its `signAmino`
 * over `makeADR36AminoSignDoc` from @keplr-wallet/cosmos 0.13.41, and `verifyADR36Amino` accepts it.
 */
export const cosmosTestVectors = {
  wallets: [
    [
      "m/44'/118'/0'/0/0",
      "c4a48e2fce1481cd3294b4490f6678090ea98d3d0e5cd984558ab0968741b104",
      "024f4e2ad99c34d60b9ba6283c9431a8418af8673212961f97a77b6377fcd05b62",
      "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0auqdal4",
      "osmo19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8",
      "celestia19rl4cm2hmr8afy4kldpxz3fka4jguq0ad2ud9c",
    ],
    [
      "m/44'/118'/0'/0/1",
      "c9ba8e1818baf4ceb063420dcedc7a482056a1580e4dbe797af3484aff7b8651",
      "03a9a0776157f1dee1fe2d65628747059a8796de9a379f3015c4dcf483f64840a6",
      "cosmos1jrkmdcwgq94uaamx6zax2luewlhf7u4kucx3kz",
      "osmo1jrkmdcwgq94uaamx6zax2luewlhf7u4k5r4pqs",
      "celestia1jrkmdcwgq94uaamx6zax2luewlhf7u4kdjhpv0",
    ],
    [
      "m/44'/118'/1'/0/0",
      "3992639e9c460fa71cde7fba107fb9d344ee312293a307fbf9d086e1d535742c",
      "02b74657437c7b173c2f4e442f1c863b24857fa97283385c5ec172ff63ff18b7be",
      "cosmos1tehv5km5e9y706rc2gzk9yyun9dljjjnvyt3u0",
      "osmo1tehv5km5e9y706rc2gzk9yyun9dljjjnylcp2a",
      "celestia1tehv5km5e9y706rc2gzk9yyun9dljjjnaw6pxz",
    ],
  ],
  /** `secp256k1TestVectors.publicKeyCompressed` as cosmjs `pubkeyToAddress` writes it. */
  fixtureAddress: "cosmos17lhf4defwy62pnx8du74p62daut53rev66jw7a",
  /** `toBech32` from @cosmjs/encoding over the bytes 1, 2, 3 and on, 32 and 21 of them. */
  contractAddress: "cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z5tpwxqergd3c8g7rusqqlvp8l",
  shortAddress: "cosmos1qypqxpq9qcrsszg2pvxq6rs0zqg3yyc5z56fjcee",
  message: "cosmos me",
  signature:
    "01eb03d69c0e8ca0147939c00975c1078fbff0c3978848671fde7224ded0924556492b91ec2a8882181ef7b75c33b6f3e1d56b5512e3052abcbbdb0f44b3fbfb",
} as const;

/**
 * Disposable key 1 through @stellar/stellar-sdk 17.1.0: SEP-53 `signMessage` digests and
 * signatures. The HD rows are SEP-0005 test case 1, the SDK derives the same keys.
 */
export const stellarTestVectors = {
  privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
  publicKey: "4cb5abf6ad79fbf5abbccafcc269d85cd2651ed4b885b5869f241aedf0a5ba29",
  address: "GBGLLK7WVV47X5NLXTFPZQTJ3BONEZI62S4ILNMGT4SBV3PQUW5CTECA",
  /** The same key as a secret seed StrKey, which is not an address. */
  secret: "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD24K",
  /** Message, its SEP-53 digest, the signature. */
  messages: [
    [
      "",
      "b3948f32c6969cad88be428667e118f83f7e47f8773388c46f488eaeb505aec4",
      "789e3e2dad8e219d8509f671936f92c439b5d69748fef515d2544487138591c57dbce49cfd372a584e8556d4b142a4c42fc3853a4055968f13451d488ae83503",
    ],
    [
      "Test message",
      "903f36e3e5caafd185881060c51985d7e2629fd32d8990833df9104c2afd0b1f",
      "7426585b09c1d16c0928400cc0f3bdfd5eb124ef9c10cac98bd4a0c4bd1ba692f976983add636eeeff095ba3ecf11a01c72d0f9b56ac68131e2a73d8b9644507",
    ],
    [
      "żółw 🐢",
      "456be91a6a7c1e05eb0fc7fd161f8ab730a6304125ed32b5d52efa9ad43107b1",
      "afbe82ba9f17ecf977f0affbb44262aaa14ff37588b32486418672bae53172e39fd6c2746d76694d9f87925e40b47d5379f02a6d0d8fe99b8f14b6b197a31607",
    ],
    [
      "a".repeat(256),
      "b5a9bc5872262e492b9a387886e28e57fef24389ef16d845dc17744d5f20ac3b",
      "b0dcd3e1d5dcacc759e92f294a21b5945ef45041990b0df539e00c08a72fc93e876f86991b7a12e106f593aa140e523f9957eece77e19a17eb82404b3cf72102",
    ],
  ],
  hd: {
    mnemonic: "illness spike retreat truth genius clock brain pass fit cave bargain toe",
    /** Path, the private key at it, the account StrKey. */
    accounts: [
      [
        "m/44'/148'/0'",
        "4d691bc19b44a1383b1a0a130aaca3e05c3c1a371dbe45930ef9b761f7a74691",
        "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6",
      ],
      [
        "m/44'/148'/1'",
        "88f296c601bafd56fd19d1856ee46670b9e2c87db0455ca792b5d8d588a353f1",
        "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX",
      ],
      [
        "m/44'/148'/2'",
        "c085ac991481ef8e847eef47e53f6e0df51ab1673d707d5d85ad441803a6459b",
        "GAY5PRAHJ2HIYBYCLZXTHID6SPVELOOYH2LBPH3LD4RUMXUW3DOYTLXW",
      ],
    ],
  },
  /** A muxed account and a contract StrKey the Stellar SDK accepts, both valid addresses. */
  muxedAddress: "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
  contractAddress: "CA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUWDA",
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
  /**
   * dcrd's `verifymessage` cases for key 1: one signature under each header, then one over "test".
   * @see https://github.com/decred/dcrd/blob/6f6cf21bd26d523ade261a683e7617a8e3f0ab56/internal/rpcserver/rpcserverhandlers_test.go
   */
  signed: {
    message: "test message",
    compressed:
      "H18ier4CIfSBOk0FKPjO4mggno0ES1w2P+41GpJnnyiSRWdE2n02YwE29Sw0n2ALT3M1Q1+GQW7moKqsem1COF8=",
    uncompressed:
      "G18ier4CIfSBOk0FKPjO4mggno0ES1w2P+41GpJnnyiSRWdE2n02YwE29Sw0n2ALT3M1Q1+GQW7moKqsem1COF8=",
    otherMessage:
      "II57fsP8WEHAwfrSlx3u3wu4PHqTnP1fk/r0LM9dzm0lYr6GAD+HAFIHWUTAN623ONsG+yq6onSbZvu5vW8YI/0=",
  },
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

/**
 * Bitcoin Cash P2PKH in CashAddr. `prize` is RetiredCoder's mini-puzzle for puzzle 130: its key
 * hashes to the same hash160 as `1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua`. Key 1 carries the address
 * libraries quote for `1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH`.
 */
export const bitcoinCashTestVectors = {
  prize: {
    privateKey: "33e7665705359f04f28b88cf897c603c9".padStart(64, "0"),
    publicKeyHash: "a24922852051a9002ebf4c864a55acb75bb4cf75",
    address: "bitcoincash:qz3yjg59ypg6jqpwhaxgvjj44jm4hdx0w5wsxw2qez",
    bitcoinAddress: "1Fo65aKq8s8iquMt6weF1rku1moWVEd5Ua",
  },
  keyOne: {
    privateKey: "00".repeat(31) + "01",
    publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    address: "bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h",
  },
  /**
   * Trezor's device tests on its default seed, twelve times `all`.
   * @see https://github.com/trezor/trezor-firmware/blob/main/tests/device_tests/bitcoin/test_getaddress.py
   */
  hd: {
    mnemonic: Array.from({ length: 12 }, () => "all").join(" "),
    addresses: [
      ["m/44'/145'/0'/0/0", "bitcoincash:qr08q88p9etk89wgv05nwlrkm4l0urz4cyl36hh9sv"],
      ["m/44'/145'/0'/0/1", "bitcoincash:qr23ajjfd9wd73l87j642puf8cad20lfmqdgwvpat4"],
      ["m/44'/145'/0'/1/0", "bitcoincash:qzc5q87w069lzg7g3gzx0c8dz83mn7l02scej5aluw"],
    ],
  },
  /**
   * The spec's encoding table: type, address, hash, over every hash size and four prefixes.
   * @see https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md
   */
  spec: [
    [
      0,
      "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2",
      "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ],
    [
      1,
      "bchtest:pr6m7j9njldwwzlg9v7v53unlr4jkmx6eyvwc0uz5t",
      "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ],
    [
      1,
      "pref:pr6m7j9njldwwzlg9v7v53unlr4jkmx6ey65nvtks5",
      "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ],
    [
      15,
      "prefix:0r6m7j9njldwwzlg9v7v53unlr4jkmx6ey3qnjwsrf",
      "f5bf48b397dae70be82b3cca4793f8eb2b6cdac9",
    ],
    [
      0,
      "bitcoincash:q9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2ws4mr9g0",
      "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ],
    [
      1,
      "bchtest:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2u94tsynr",
      "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ],
    [
      1,
      "pref:p9adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2khlwwk5v",
      "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ],
    [
      15,
      "prefix:09adhakpwzztepkpwp5z0dq62m6u5v5xtyj7j3h2p29kc2lp",
      "7adbf6c17084bc86c1706827b41a56f5ca32865925e946ea",
    ],
    [
      0,
      "bitcoincash:qgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcw59jxxuz",
      "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ],
    [
      1,
      "bchtest:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcvs7md7wt",
      "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ],
    [
      1,
      "pref:pgagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkcrsr6gzkn",
      "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ],
    [
      15,
      "prefix:0gagf7w02x4wnz3mkwnchut2vxphjzccwxgjvvjmlsxqwkc5djw8s9g",
      "3a84f9cf51aae98a3bb3a78bf16a6183790b18719126325bfc0c075b",
    ],
    [
      0,
      "bitcoincash:qvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq5nlegake",
      "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ],
    [
      1,
      "bchtest:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq7fqng6m6",
      "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ],
    [
      1,
      "pref:pvch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxq4k9m7qf9",
      "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ],
    [
      15,
      "prefix:0vch8mmxy0rtfrlarg7ucrxxfzds5pamg73h7370aa87d80gyhqxqsh6jgp6w",
      "3173ef6623c6b48ffd1a3dcc0cc6489b0a07bb47a37f47cfef4fe69de825c060",
    ],
    [
      0,
      "bitcoincash:qnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv39gr3uvz",
      "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ],
    [
      1,
      "bchtest:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvmgm6ynej",
      "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ],
    [
      1,
      "pref:pnq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklv0vx5z0w3",
      "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ],
    [
      15,
      "prefix:0nq8zwpj8cq05n7pytfmskuk9r4gzzel8qtsvwz79zdskftrzxtar994cgutavfklvwsvctzqy",
      "c07138323e00fa4fc122d3b85b9628ea810b3f381706385e289b0b25631197d194b5c238beb136fb",
    ],
    [
      0,
      "bitcoincash:qh3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqex2w82sl",
      "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ],
    [
      1,
      "bchtest:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqnzf7mt6x",
      "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ],
    [
      1,
      "pref:ph3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqjntdfcwg",
      "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ],
    [
      15,
      "prefix:0h3krj5607v3qlqh5c3wq3lrw3wnuxw0sp8dv0zugrrt5a3kj6ucysfz8kxwv2k53krr7n933jfsunqakcssnmn",
      "e361ca9a7f99107c17a622e047e3745d3e19cf804ed63c5c40c6ba763696b98241223d8ce62ad48d863f4cb18c930e4c",
    ],
    [
      0,
      "bitcoincash:qmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqscw8jd03f",
      "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ],
    [
      1,
      "bchtest:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqs6kgdsg2g",
      "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ],
    [
      1,
      "pref:pmvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsammyqffl",
      "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ],
    [
      15,
      "prefix:0mvl5lzvdm6km38lgga64ek5jhdl7e3aqd9895wu04fvhlnare5937w4ywkq57juxsrhvw8ym5d8qx7sz7zz0zvcypqsgjrqpnw8",
      "d9fa7c4c6ef56dc4ff423baae6d495dbff663d034a72d1dc7d52cbfe7d1e6858f9d523ac0a7a5c34077638e4dd1a701bd017842789982041",
    ],
    [
      0,
      "bitcoincash:qlg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mtky5sv5w",
      "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ],
    [
      1,
      "bchtest:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mc773cwez",
      "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ],
    [
      1,
      "pref:plg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96mg7pj3lh8",
      "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ],
    [
      15,
      "prefix:0lg0x333p4238k0qrc5ej7rzfw5g8e4a4r6vvzyrcy8j3s5k0en7calvclhw46hudk5flttj6ydvjc0pv3nchp52amk97tqa5zygg96ms92w6845",
      "d0f346310d5513d9e01e299978624ba883e6bda8f4c60883c10f28c2967e67ec77ecc7eeeaeafc6da89fad72d11ac961e164678b868aeeec5f2c1da08884175b",
    ],
  ],
  /** Checksums that hold under `bitcoincash` over payloads Bitcoin Cash Node pays to, from the CashTokens CHIP. */
  mainnet: [
    "bitcoincash:zr6m7j9njldwwzlg9v7v53unlr4jkmx6eycnjehshe",
    "bitcoincash:ppawqn2h74a4t50phuza84kdp3794pq3ccvm92p8sh",
    "bitcoincash:rpawqn2h74a4t50phuza84kdp3794pq3cct3k50p0y",
    "bitcoincash:pvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqpkp7fqn0",
    "bitcoincash:rvqqqqqqqqqqqqqqqqqqqqqqzg69v7ysqqqqqqqqqqqqqqqqqqqqqn9alsp2y",
  ],
} as const;

/** Bitcoin SV vectors from the BSV Blockchain SDKs, published there as WIF and compact base64. */
export const bitcoinSVTestVectors = {
  keyOne: {
    privateKey: "00".repeat(31) + "01",
    publicKey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    address: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
    testnetAddress: "mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r",
  },
  /** A script hash address; the node decodes it, but Genesis rejects every payment to it. */
  p2shAddress: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
  /**
   * BIP44 keys under SLIP-0044 coin type 236, from bsv-sdk 2.4.0 (py-sdk).
   * @see https://github.com/bsv-blockchain/py-sdk/blob/c16fd32814a0a2c23588f140446069acdb7b5b5e/tests/bsv/hd/test_hd.py
   */
  hd: {
    mnemonic:
      "chief december immune nominee forest scheme slight tornado cupboard post summer program",
    wifs: [
      ["m/44'/236'/0'/0/0", "L4toENSefoBpDJcfGAwrSMcyqBNmfSYjgkAP2qeNujw5oPQGvNtM"],
      ["m/44'/236'/0'/0/1", "KzwYj8kMuNqmxLModB1nyPoZjPskCqPXJHf6oUdpHkBK6ZgDUoHE"],
    ],
  },
  /**
   * Bitcoin Signed Message, as header byte then r||s in base64, from @bsv/sdk 2.0.16 (ts-sdk).
   * @see https://github.com/bsv-blockchain/ts-sdk/blob/9e3ede6b6302480005259ca36cbc73d9b6509d53/src/compat/__tests/BSM.test.ts
   */
  signed: {
    wif: "L211enC224G1kV8pyyq7bjVd9SxZebnRYEzzM3i7ZHCc1c5E7dQu",
    message: "hello world",
    signature:
      "H4T8Asr0WkC6wYfBESR6pCAfECtdsPM4fwiSQ2qndFi8dVtv/mrOFaySx9xQE7j24ugoJ4iGnsRwAC8QwaoHOXk=",
  },
  /** The verification vector from the same ts-sdk test file. */
  verified: {
    publicKey: "03d4d1a6c5d8c03b0e671bc1891b69afaecb40c0686188fe9019f93581b43e8334",
    message: "Texas",
    signature:
      "IAV89EkfHSzAIA8cEWbbKHUYzJqcShkpWaXGJ5+mf4+YIlf3XNlr0bj9X60sNe1A7+x9qyk+zmXropMDY4370n8=",
  },
} as const;

/**
 * Bitcoin Gold vectors from the node's own tests at BTCGPU v0.21.3.
 * @see https://github.com/BTCGPU/BTCGPU/blob/1b85f0953725812dedcfc5a7ac077c16d419e4ba/test/functional/rpc_signmessage.py
 * @see https://github.com/BTCGPU/BTCGPU/blob/1b85f0953725812dedcfc5a7ac077c16d419e4ba/src/test/data/key_io_valid.json
 */
export const bitcoinGoldTestVectors = {
  /**
   * `signmessagewithprivkey` under "Bitcoin Gold Signed Message:\n", header byte then r||s in
   * base64. The mainnet addresses re-encode the hash160 of `address` with the reference base58
   * and bech32 encoders under Bitcoin Gold's version byte and `btg` prefix.
   */
  signed: {
    wif: "cUeKHd5orzT3mz8P9pxyREHfsWtVfgsfDjiZZBcjUBAaGk1BTj7N",
    privateKey: "d2b8a0116d641fe7d3036f8464628fb595b480414c13a301b3d4038c811c28b0",
    publicKey: "03c150061989643d77162902b725409087959f15914649d4f06b6cc3f8c87bb238",
    message: "This is just a test message",
    signature:
      "III9QOR7R8wULQSY7ymo6mN7b2QLXfc4dHbYAKS7YTU0SEbJToWkWKQegTvb87iZr8HOuHoi+hdNA49RUpoSaw4=",
    address: "mpLQjfK79b7CCV4VMJWEWAj5Mpx8Up5zxB",
    segwitTestnetAddress: "tbtg1qvza2pay5kwxw8j2qm6n87wqym3fdr7u53wjd8n",
    legacyAddress: "GSfNrjZ5KRHEVqtAZgBy71reR19GaCw5Lc",
    p2shAddress: "AMqi6hwDz9e94pUg8CiXrYz11kuYZTqgKB",
    segwitAddress: "btg1qvza2pay5kwxw8j2qm6n87wqym3fdr7u5xu3y5e",
  },
  /** Addresses the node decodes, one per format and network. */
  mainnet: [
    "GUHcigT74ggLsmbxHFTLfn2ZUNJUWiXaMG",
    "Aa6QUX6pRcncJN7vm7FG8vsy62gyKuANy6",
    "btg1q5cuatynjmk4szh40mmunszfzh7zrc5xmn8padv",
    "btg1qkw7lz3ahms6e0ajv27mzh7g62tchjpmve4afc29u7w49tddydy2s2vtjh5",
  ],
  testnet: [
    "mhJuoGLgnJC8gdBgBzEigsoyG4omQXejPT",
    "2N5VpzKEuYvZJbmg6eUNGnfrrD1ir92FWGu",
    "tbtg1q74fxwnvhsue0l8wremgq66xzvn48jlc5fkf03n",
    "tbtg1qpt7cqgq8ukv92dcraun9c3n0s3aswrt62vtv8nqmkfpa2tjfghes7zflt9",
  ],
  /** Witness v1 and v2 outputs the node decodes but Bitcoin Gold consensus never protected. */
  unprotected: [
    "btg1p5rgvqejqh9dh37t9g94dd9cm8vtqns7dndgj423egwggsggcdzms7pg7wc",
    "btg1zr4pqk06j6k",
  ],
} as const;

/**
 * Dogecoin vectors from the node's own tests at Dogecoin Core v1.14.9, whose WIFs decode under
 * version byte `0x9e`, and the Dogecoin message fixtures of bitcoinjs-message.
 * @see https://github.com/dogecoin/dogecoin/blob/e0a1c157791544e818c901bd9341896965afbf9d/src/test/key_tests.cpp
 * @see https://github.com/dogecoin/dogecoin/blob/e0a1c157791544e818c901bd9341896965afbf9d/src/test/data/base58_keys_valid.json
 * @see https://github.com/bitcoinjs/bitcoinjs-message/blob/281289ef04ad5573b2c5bc86cdb3188364f5876b/test/fixtures.json
 * @see https://github.com/LedgerHQ/ledger-live/blob/b3ffa2f4bf735f2cfeed2a8028ea92d4bc3588e3/libs/coin-modules/coin-bitcoin/src/constants.ts
 */
export const dogecoinTestVectors = {
  /** `strSecret1` and `strSecret2` with the addresses the node gives each key, both encodings. */
  keys: [
    {
      wif: "6JFPe8b4jbpup7petSB98M8tcaqXCigji8fGrC8bEbbDQxQkQ68",
      privateKey: "0f6055b44781882c04d6683d8e11a8282d068ef139a78f9d45e9ba290d1ce25f",
      address: "DSpgzjPyfQB6ZzeSbMWpaZiTTxGf2oBCs4",
      addressCompressed: "D8jZ6R8uuyQwiybupiVs3eDCedKdZ5bYV3",
    },
    {
      wif: "6KLE6U3w8x3rM7nA1ZQxR4KnyEzeirPEt4YaXWdY4roF7Tt96rq",
      privateKey: "9e0d4307370dc9ad2feaa8fbeb2b43eb472b70a928f8c927b30a510f108f3246",
      address: "DR9VqfbWgEHZhNst34KQnABQXpPWXeLAJD",
      addressCompressed: "DP7rGcDbpAvMb1dKup981zNt1heWUuVLP7",
    },
  ],
  /** Ledger Live's first Dogecoin receive address for the BIP39 `abandon ... about` mnemonic. */
  hd: { path: "m/44'/3'/0'/0/0", address: "DBus3bamQjgJULBJtYXpEzDWQRwF5iwxgC" },
  /** `strAddressBad`: a `D` string whose checksum fails. */
  badAddress: "DRjyUS2uuieEPkhZNdQz8hE5YycxVEqSXA",
  /** P2PKH then P2SH, one pair per network. */
  mainnet: ["DD4KSSuBJqcjuTcvUg1CgUKeurPUFeEZkE", "A7HRQk3GFCW2QasvdZxXuYj8kkQK5QrYLs"],
  testnet: ["nhRsrUaxZou6sewjqaS37cJrMRJRgwVXdk", "2MsvyG12kxxipe276Au4zKqvd2xdrBuHWb3"],
  /**
   * Key 1 under "Dogecoin Signed Message:\n", header byte then r||s in base64. The `sign` fixture
   * carries the uncompressed header, the `verify` fixture the compressed one and its address.
   */
  signed: {
    privateKey: "00".repeat(31) + "01",
    message: "vires is numeris",
    address: "DFpN6QqFfUm3gKNaxN6tNcab1FArL9cZLE",
    signatures: [
      "G6k+dZwJ8oOei3PCSpdj603fDvhlhQ+sqaFNIDvo/bI+Xh6zyIKGzZpyud6YhZ1a5mcrwMVtTWL+VXq/hC5Zj7s=",
      "H6k+dZwJ8oOei3PCSpdj603fDvhlhQ+sqaFNIDvo/bI+Xh6zyIKGzZpyud6YhZ1a5mcrwMVtTWL+VXq/hC5Zj7s=",
    ],
  },
} as const;

/**
 * Dash vectors from the node's own tests at Dash Core v23.1.8, whose WIFs decode under version
 * byte `0xcc`, and Ledger Live's first receive address for the BIP39 test mnemonic.
 * @see https://github.com/dashpay/dash/blob/728f5055836c6d29806412fc7223ac8fe05af991/src/test/key_tests.cpp
 * @see https://github.com/dashpay/dash/blob/728f5055836c6d29806412fc7223ac8fe05af991/src/test/util_tests.cpp
 * @see https://github.com/dashpay/dash/blob/728f5055836c6d29806412fc7223ac8fe05af991/src/test/data/key_io_valid.json
 * @see https://github.com/LedgerHQ/ledger-live/blob/b3ffa2f4bf735f2cfeed2a8028ea92d4bc3588e3/libs/coin-modules/coin-bitcoin/src/constants.ts
 */
export const dashTestVectors = {
  /** `strSecret1` and `strSecret2` with the addresses the node gives each key, both encodings. */
  keys: [
    {
      wif: "7qh6LYnLN2w2ntz2wwUhRUEgkQ2j8XB16FGw77ZRDZmC29bn7cD",
      privateKey: "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747",
      address: "Xywgfc872nn5CKtpATCoAjZCc4v96pJczy",
      addressCompressed: "XxV9h4Xmv6Pup8tVAQmH97K6grzvDwMG9F",
    },
    {
      wif: "7rve4MxeWFQHGbSYH6J2yaaZd3MBUqoDEwN6ZAZ6ZHmhTT4r3hW",
      privateKey: "b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117",
      address: "XpmouUj9KKJ99ZuU331ZS1KqsboeFnLGgK",
      addressCompressed: "Xn7ZrYdExuk79Dm7CJCw7sfUWi2qWJSbRy",
    },
  ],
  /** Ledger Live's first Dash receive address for the BIP39 `abandon ... about` mnemonic. */
  hd: { path: "m/44'/5'/0'/0/0", address: "XoJA8qE3N2Y3jMLEtZ3vcN42qseZ8LvFf5" },
  /** `strAddressBad`: an `X` string whose checksum fails. */
  badAddress: "Xta1praZQjyELweyMByXyiREw1ZRsjXzVP",
  /** P2PKH then P2SH, one pair per network. */
  mainnet: ["XqZHYpoksmbEPtWstAEki3o8pJ8ZsPfXpK", "7XShCrc5u9rZZv7j18WqbUMZMxp8k1Hq4z"],
  testnet: ["yf7WoPrbJCGhLLtpeBe7tteKEKwpvZ1w97", "8yCvxUt2TYKEQb5Ak6n9DYiCx22xfa3Lio"],
  /**
   * The `message_sign` case: its key signs "Trust no one" under "DarkCoin Signed Message:\n", and
   * `message_verify` checks the result against the compressed key's address.
   */
  signed: {
    privateKey: "d97f5108f11cda6eeebaaa420fef0726b1f898060b98489fa3098463c0032866",
    message: "Trust no one",
    address: "XetGnWHsPXV9VSkWzB6Wn2KhZLD24gqa5j",
    signature:
      "IIOzMDkvw3GtLWXkeEYRRRH53MOLHM44sJ428Nu4NNacTPJTGcKesMJ+3s3OadYK34tpSQIhu922EviNNWTsiQg=",
  },
} as const;

/**
 * Zcash vectors from zcashd v6.20.0 tests, whose WIFs are Bitcoin's, Ledger Live's first receive
 * address for the BIP39 test mnemonic, the TEX example in ZIP-320 and a signature Zallet verifies.
 * @see https://github.com/zcash/zcash/blob/6966f30a8541b0e5998837dce14250ca9e15b16a/src/test/key_tests.cpp
 * @see https://github.com/zcash/zcash/blob/6966f30a8541b0e5998837dce14250ca9e15b16a/src/test/data/base58_keys_valid.json
 * @see https://github.com/LedgerHQ/ledger-live/blob/b3ffa2f4bf735f2cfeed2a8028ea92d4bc3588e3/libs/coin-modules/coin-bitcoin/src/constants.ts
 * @see https://github.com/zcash/zips/blob/main/zips/zip-0320.rst
 * @see https://github.com/zcash/librustzcash/blob/cd5eae71a000d426a63906be740952b5f232a558/components/zcash_address/src/encoding.rs
 * @see https://github.com/zcash/zallet/blob/f9dcd4d31439feb813c95ac2516814421f5b04df/zallet-core/src/components/json_rpc/methods/verify_message.rs
 */
export const zcashTestVectors = {
  /** `strSecret1` and `strSecret2` with the addresses the node gives each key, both encodings. */
  keys: [
    {
      wif: "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj",
      privateKey: "12b004fff7f4b69ef8650e767f18f11ede158148b425660723b9f9a66e61f747",
      address: "t1h8SqgtM3QM5e2M8EzhhT1yL2PXXtA6oqe",
      addressCompressed: "t1ffus9J1vhxvFqLoExGBRPjE7BcJxiSCTC",
    },
    {
      wif: "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3",
      privateKey: "b524c28b61c9b2c49b2c7dd4c2d75887abb78768c054bd7c01af4029f6c0d117",
      address: "t1Xxa5ZVPKvs9bGMn7aWTiHjyHvR31XkUst",
      addressCompressed: "t1VJL2dPUyXK7avDRGqhqQA5bw2eEMdhyg6",
    },
  ],
  /** Ledger Live's first Zcash receive address for the BIP39 `abandon ... about` mnemonic. */
  hd: { path: "m/44'/133'/0'/0/0", address: "t1XVXWCvpMgBvUaed4XDqWtgQgJSu1Ghz7F" },
  /** P2PKH then P2SH, one pair per network. */
  mainnet: ["t1T8yaLVhNqxA5KJcmiqqFN88e8DNp2PBfF", "t3VDyGHn9mbyCf448m2cHTu5uXvsJpKHbiZ"],
  testnet: ["tmHMBeeYRuc2eVicLNfP15YLxbQsooCA6jb", "t2Fbo6DBKKVYw1SfrY8bEgz56hYEhywhEN6"],
  /** Sapling and unified addresses from librustzcash, which a transparent driver must refuse. */
  shielded: [
    "zs1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqpq6d8g",
    "u1qpatys4zruk99pg59gcscrt7y6akvl9vrhcfyhm9yxvxz7h87q6n8cgrzzpe9zru68uq39uhmlpp5uefxu0su5uqyqfe5zp3tycn0ecl",
  ],
  /** ZIP-320: the same key hash as a `t1` address and as a TEX address. */
  tex: {
    address: "t1VmmGiyjVNeCjxDZzg7vZmd99WyzVby9yC",
    tex: "tex1s2rt77ggv6q989lr49rkgzmh5slsksa9khdgte",
  },
  /**
   * Zallet's `verifymessage` case: a compact signature in base64 under "Zcash Signed Message:\n"
   * for the key behind `address`. No private key comes with it, so the test recovers the key.
   */
  signed: {
    address: "t1VydNnkjBzfL1iAMyUbwGKJAF7PgvuCfMY",
    message: "20251117: 1 Yay; 2 Yay; 3 Yay; 4 Yay; 5 Nay; 6 Nay; 7 Yay; 8 Yay; 9 Nay",
    signature:
      "H3RY+6ZfWUbzaaXxK8I42thf+f3tOrwKP2elphxAxq8tKypwJG4+V7EGR+sTWMZ5MFyvTQW8ZIV0yGU+93JTioA=",
  },
} as const;

/**
 * eCash vectors from Bitcoin ABC's CashAddr tests, bip_utils 2.12.2 BIP44 tests on the seed of the BIP39
 * `abandon ... about` mnemonic and ecash-lib's message tests.
 * @see https://github.com/Bitcoin-ABC/bitcoin-abc/blob/b53096bc43db49bc90a4c6c39a7c0106d4be2d78/src/test/cashaddrenc_tests.cpp
 * @see https://github.com/ebellocchia/bip_utils/blob/db8b849251e12f52ce8b77830c0d32b7e2de16b5/tests/bip/bip44/test_bip44.py
 * @see https://github.com/Bitcoin-ABC/bitcoin-abc/blob/b53096bc43db49bc90a4c6c39a7c0106d4be2d78/modules/ecash-lib/src/messages.test.ts
 */
export const eCashTestVectors = {
  /** `test_encode_address`: each hash as P2PKH and as P2SH under `ecash`. */
  encoded: [
    {
      hash: "76a04053bda0a88bda5177b86a15c3b29f559873",
      p2pkh: "ecash:qpm2qsznhks23z7629mms6s4cwef74vcwva87rkuu2",
      p2sh: "ecash:ppm2qsznhks23z7629mms6s4cwef74vcwv2zrv3l8h",
    },
    {
      hash: "cb481232299cd5743151ac4b2d63ae198e7bb0a9",
      p2pkh: "ecash:qr95sy3j9xwd2ap32xkykttr4cvcu7as4ykdcjcn6n",
      p2sh: "ecash:pr95sy3j9xwd2ap32xkykttr4cvcu7as4ypg9alspw",
    },
    {
      hash: "011f28e473c95f4013d7d53ec5fbc3b42df8ed10",
      p2pkh: "ecash:qqq3728yw0y47sqn6l2na30mcw6zm78dzq653y7pv5",
      p2sh: "ecash:pqq3728yw0y47sqn6l2na30mcw6zm78dzqd3vtezhf",
    },
  ],
  /**
   * bip_utils' first eCash receive addresses. Its mainnet walks Bitcoin Cash's coin type 145, the
   * path older eCash wallets kept, and its testnet walks coin type 1.
   */
  hd: {
    mainnet: ["m/44'/145'/0'/0/0", "ecash:qqyx49mu0kkn9ftfj6hje6g2wfer34yfnqdxfumtxd"],
    testnet: ["m/44'/1'/0'/0/0", "ectest:qqaz6s295ncfs53m86qj0uw6sl8u2kuw0yqy9a2fy0"],
  },
  /**
   * ecash-lib's `signMsg` case: its test key, the double SHA-256 it signs and the base64 compact
   * signature with a header byte. Its nonce differs from the RFC 6979 one this library takes, so only verification carries over.
   */
  signed: {
    privateKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    message: "Hello, world!",
    digest: "8f6b3f5a9e73fa9bcee1e28c749813665b94b4e9019d71844aee89f928af8fb3",
    signature:
      "IEwA92jxphriBKyCd1RI4PM0uhbVUS8qW69h/tKIMrNpGRNOqfTlBATvylddM7H5dqsjkkOc72Zc0hNdOzUiIKI=",
  },
} as const;

/**
 * Public WIF interoperability vectors.
 * @see https://github.com/bitcoinjs/wif/blob/master/test/fixtures.json
 * @see https://github.com/litecoin-project/litecoin/blob/master/src/test/data/key_io_valid.json
 * @see https://github.com/decred/dcrd/blob/master/dcrutil/wif_test.go
 * @see https://github.com/dashpay/dash/blob/728f5055836c6d29806412fc7223ac8fe05af991/src/test/data/key_io_valid.json
 * @see https://github.com/dogecoin/dogecoin/blob/e0a1c157791544e818c901bd9341896965afbf9d/src/test/data/base58_keys_valid.json
 */
export const wifTestVectors = [
  {
    wif: "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
    privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
    chain: "bitcoin",
    network: "mainnet",
    compressed: true,
  },
  {
    wif: "5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf",
    privateKey: "0000000000000000000000000000000000000000000000000000000000000001",
    chain: "bitcoin",
    network: "mainnet",
    compressed: false,
  },
  {
    wif: "KxhEDBQyyEFymvfJD96q8stMbJMbZUb6D1PmXqBWZDU2WvbvVs9o",
    privateKey: "2bfe58ab6d9fd575bdc3a624e4825dd2b375d64ac033fbc46ea79dbab4f69a3e",
    chain: "bitcoin",
    network: "mainnet",
    compressed: true,
  },
  {
    wif: "KzrA86mCVMGWnLGBQu9yzQa32qbxb5dvSK4XhyjjGAWSBKYX4rHx",
    privateKey: "6c4313b03f2e7324d75e642f0ab81b734b724e13fec930f309e222470236d66b",
    chain: "bitcoin",
    network: "mainnet",
    compressed: true,
  },
  {
    wif: "5JdxzLtFPHNe7CAL8EBC6krdFv9pwPoRo4e3syMZEQT9srmK8hh",
    privateKey: "6c4313b03f2e7324d75e642f0ab81b734b724e13fec930f309e222470236d66b",
    chain: "bitcoin",
    network: "mainnet",
    compressed: false,
  },
  {
    wif: "cRD9b1m3vQxmwmjSoJy7Mj56f4uNFXjcWMCzpQCEmHASS4edEwXv",
    privateKey: "6c4313b03f2e7324d75e642f0ab81b734b724e13fec930f309e222470236d66b",
    chain: "bitcoin",
    network: "testnet",
    compressed: true,
  },
  {
    wif: "92Qba5hnyWSn5Ffcka56yMQauaWY6ZLd91Vzxbi4a9CCetaHtYj",
    privateKey: "6c4313b03f2e7324d75e642f0ab81b734b724e13fec930f309e222470236d66b",
    chain: "bitcoin",
    network: "testnet",
    compressed: false,
  },
  {
    wif: "L5oLkpV3aqBjhki6LmvChTCV6odsp4SXM6FfU2Gppt5kFLaHLuZ9",
    privateKey: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
    chain: "bitcoin",
    network: "mainnet",
    compressed: true,
  },
  {
    wif: "6vqpCruyRS9bEY6ZVrL8S9EL5h2MnQZffzzqrpNP9i8YozvXTKs",
    privateKey: "e2993b1b4a8b1e00c024715e106d7c79ada82528b80b938a566cfc71f9ffcf42",
    chain: "litecoin",
    network: "mainnet",
    compressed: false,
  },
  {
    wif: "T5MZ5z9WqJxzVxYyVPecTJUSDkzDWrUYe1JuSX2AqJ9jKmLJrvTE",
    privateKey: "44b78d45adc801a65949661d5df1c4a44f532cd422be413a505d776784ddbe25",
    chain: "litecoin",
    network: "mainnet",
    compressed: true,
  },
  {
    wif: "927w9fGHSbrUEWHdfBd5AU4mDFmhEnBkxLyfsRn4oNwPTLQw7qS",
    privateKey: "466d8cbefaa702b2f597ade1c4f9fa4b0e709527e214443990c13e3fdcb53deb",
    chain: "litecoin",
    network: "testnet",
    compressed: false,
  },
  {
    wif: "cQaeKQwuakynYD9iebyxsKiBKF8RT3G6zoqRNUDybMsAimANRypo",
    privateKey: "597b8f070b98ee1f997fa3cb976466fa0e931256246b8c7177d2b067eed06ad7",
    chain: "litecoin",
    network: "testnet",
    compressed: true,
  },
  {
    wif: "7sUh9RiHaovsNoNToDz3gfSzbETZBodKCY8ZkLtxbDdcEueuNdd",
    privateKey: "fdeca3b08e38af53d7c4c60e3ad208ce5066441036e9f191e0b75036a77f65e2",
    chain: "dash",
    network: "mainnet",
    compressed: false,
  },
  {
    wif: "XK9kG3y8JeDgSNrXdomWiCiBMs7D2eNJSrux1rx7GuGLWpMxEH3w",
    privateKey: "eaa4752443233fbe8f8943bf956de595665c38ffff23827e17c10cdc1c27a028",
    chain: "dash",
    network: "mainnet",
    compressed: true,
  },
  {
    wif: "938BPMAhPitw3MZW9V5UBFVtKwJRkzJGkQuS4EsGiczaHH7Xed6",
    privateKey: "caae6c9810626198ff778740f88ddcf102aeb81daee289c044c4a4571c4b6f28",
    chain: "dash",
    network: "testnet",
    compressed: false,
  },
  {
    wif: "cRUCRTHRBX9rA9CXDvVEmuPMyRfWNvg8gpMiFiN77wNTJetkFari",
    privateKey: "7400f4b8e0b843f880c32d81e91bdea04cd7a3819b32275fc3298af4c7ec87eb",
    chain: "dash",
    network: "testnet",
    compressed: true,
  },
  {
    wif: "PmQdMn8xafwaQouk8ngs1CccRCB1ZmsqQxBaxNR4vhQi5a5QB5716",
    privateKey: "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d",
    chain: "decred",
    network: "mainnet",
    compressed: true,
  },
  {
    wif: "PtWVDUidYaiiNT5e2Sfb1Ah4evbaSopZJkkpFBuzkJYcYteugvdFg",
    privateKey: "dda35a1488fb97b6eb3fe6e9ef2a25814e396fb5dc295fe994b96789b21a0398",
    chain: "decred",
    network: "testnet",
    compressed: true,
  },
  {
    wif: "6K7a8wZW8A1oZxNd7wZz8PhgAAaDxybkzNpD1sGVvmSaBmc3Hg2",
    privateKey: "81517fd848ebfeda7e2c684e7a3f5ebbb28b15d52d33d8a201d8873a0cdaf761",
    chain: "dogecoin",
    network: "mainnet",
    compressed: false,
  },
  {
    wif: "QP5rQxpaP8HHPEdCEqxTjiHGWRvsyPvzZJeJ9BCxpfT13FN9VesQ",
    privateKey: "0e017cc6ad98c6646a1139114e8dcd9bf2537f3e0306a2f43dea03f91fea370a",
    chain: "dogecoin",
    network: "mainnet",
    compressed: true,
  },
  {
    wif: "96MAePnF8ppQm8165ABvzSEShnNy3vgxjmMhcqEkQVZ9FtPV2XL",
    privateKey: "73423bf1fa6526ee571f3b4b4ad19799c81d40ce5c18a37d87dc38b55746627d",
    chain: "dogecoin",
    network: "testnet",
    compressed: false,
  },
  {
    wif: "ckaDjxhDsVyZTHLUF7uoojCXVYcciUGeEk53VFzKUJsKUKhnbUnZ",
    privateKey: "ae03398655b29f80badf1e6909e75ccf9bcdb6062e8886d0aca4b3d46a82aa83",
    chain: "dogecoin",
    network: "testnet",
    compressed: true,
  },
] as const;

/** trezor/python-mnemonic vectors.json, blob d362a5d4eb1ba800a52aec30116915cd4576e1fd. */
export const localizedMnemonicVectors = [
  {
    language: "czech",
    entropy: "00000000000000000000000000000000",
    mnemonic:
      "abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace abdikace agrese",
  },
  {
    language: "english",
    entropy: "00000000000000000000000000000000",
    mnemonic:
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
  },
  {
    language: "french",
    entropy: "00000000000000000000000000000000",
    mnemonic:
      "abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abaisser abeille",
  },
  {
    language: "italian",
    entropy: "00000000000000000000000000000000",
    mnemonic: "abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abaco abete",
  },
  {
    language: "japanese",
    entropy: "00000000000000000000000000000000",
    mnemonic:
      "あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あいこくしん　あおぞら",
  },
  {
    language: "korean",
    entropy: "00000000000000000000000000000000",
    mnemonic: "가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가격 가능",
  },
  {
    language: "portuguese",
    entropy: "00000000000000000000000000000000",
    mnemonic:
      "abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abacate abater",
  },
  {
    language: "simplified-chinese",
    entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    mnemonic: "枪 疫 霉 尝 俩 闹 饿 贤 枪 疫 霉 卿",
  },
  {
    language: "spanish",
    entropy: "00000000000000000000000000000000",
    mnemonic: "ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco ábaco abierto",
  },
  {
    language: "traditional-chinese",
    entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
    mnemonic: "槍 疫 黴 嘗 倆 鬧 餓 賢 槍 疫 黴 卿",
  },
] as const;

/** Quizchain block 74 in agntn/puzzles: entropy from the thread, public key from its claim. */
export const bip39EntropyWalletVector = {
  entropy: "0a7c902815f9dc9d26057280592b2553",
  path: "m/44'/0'/0'/0/0",
  publicKey: "0312b422a56647895f549b81db0f36a964479696ec86b374be8b353167257825dd",
  address: "1HbUcHKfpkUSssNtcfS3vKzdTMue3EByMQ",
} as const;

/** SEC 2 v2 section 2.4.1: secp256k1 generator G, in SEC1 encodings. */
export const publicKeyEncodingVector = {
  compressed: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  uncompressed:
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
};

/** Multiples of G as SEC1 hex and scalars mod n, the usual published secp256k1 constants. */
export const secp256k1MathVectors = {
  g: publicKeyEncodingVector.compressed,
  minusG: "0379be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  twoG: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  threeG: "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
  threeGUncompressed:
    "04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" +
    "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672",
  orderMinusOne: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
  inverseOfTwo: "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1",
  /** No point of the curve has x = 5. */
  xWithoutPoint: "0000000000000000000000000000000000000000000000000000000000000005",
};

/**
 * Textbook curves: y^2 = x^3 + 2x + 2 over F17 with the multiples of (5, 1) from Paar and Pelzl,
 * Understanding Cryptography, chapter 9, and y^2 = x^3 + x + 1 over F23.
 */
export const curveVectors = {
  paar: {
    a: 2n,
    b: 2n,
    p: 17n,
    order: 19n,
    multiples: [
      [5n, 1n],
      [6n, 3n],
      [10n, 6n],
      [3n, 1n],
      [9n, 16n],
      [16n, 13n],
      [0n, 6n],
      [13n, 7n],
      [7n, 6n],
      [7n, 11n],
      [13n, 10n],
      [0n, 11n],
      [16n, 4n],
      [9n, 1n],
      [3n, 16n],
      [10n, 11n],
      [6n, 14n],
      [5n, 16n],
    ],
  },
  f23: {
    a: 1n,
    b: 1n,
    p: 23n,
    count: 28n,
    /** The one point with y = 0, so its double is infinity. */
    orderTwo: { x: 4n, y: 0n },
    orderSeven: [
      [5n, 4n],
      [5n, 19n],
      [13n, 7n],
      [13n, 16n],
      [17n, 3n],
      [17n, 20n],
    ],
  },
  /** secp256k1 given as a, b and p, with G and 3G from `secp256k1MathVectors`. */
  secp256k1: {
    a: 0n,
    b: 7n,
    p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
    g: {
      x: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
      y: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
    },
    threeG: {
      x: 0xf9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9n,
      y: 0x388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672n,
    },
  },
} as const;

/** Electrum 9da4c342 tests/test_mnemonic.py; addresses checked with Electrum 4.8.1. */
export const electrumVectors = [
  {
    name: "english",
    mnemonic: "wild father tree among universe such mobile favorite target dynamic credit identify",
    passphrase: "",
    seed: "aac2a6302e48577ab4b46f23dbae0774e2e62c796f797d0a1b5faeb528301e3064342dafb79069e7c4c6b8c38ae11d7a973bec0d4f70626f8cc5184a8d0b0756",
    seedType: "segwit",
    path: "m/0'/0/0",
    publicKey: "022e085af92c30eabc5fdd71b29a82cb8fba988ae5cc44831d5718ee673cd30cf1",
    address: "bc1q4794m2uuw9jmjszmplfj4wvvr5j272fpnx2cse",
  },
  {
    name: "english_with_passphrase",
    mnemonic: "wild father tree among universe such mobile favorite target dynamic credit identify",
    passphrase: "Did you ever hear the tragedy of Darth Plagueis the Wise?",
    seed: "4aa29f2aeb0127efb55138ab9e7be83b36750358751906f86c662b21a1ea1370f949e6d1a12fa56d3d93cadda93038c76ac8118597364e46f5156fde6183c82f",
    seedType: "segwit",
    path: "m/0'/0/0",
    publicKey: "023ee11455fef61d50886604a18c0463185cdbeda57a88e4b31d11aabef4701c09",
    address: "bc1qd95tuv3qp38wjnw0u56m6t8ku4hl66vwjr72az",
  },
  {
    name: "japanese",
    mnemonic:
      "なのか ひろい しなん まなぶ つぶす さがす おしゃれ かわく おいかける けさき かいとう さたん",
    passphrase: "",
    seed: "d3eaf0e44ddae3a5769cb08a26918e8b308258bcb057bb704c6f69713245c0b35cb92c03df9c9ece5eff826091b4e74041e010b701d44d610976ce8bfb66a8ad",
    seedType: "standard",
    path: "m/0/0",
    publicKey: "027e127c4a73642f907749504c6de35f6146726204efaa6dd6b7c9d72f9f3d7dba",
    address: "1EHQKxw2CJ1Mf8ePxQx66TtwP4x3fg2hYi",
  },
  {
    name: "chinese",
    mnemonic: "眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬",
    passphrase: "",
    seed: "0b9077db7b5a50dbb6f61821e2d35e255068a5847e221138048a20e12d80b673ce306b6fe7ac174ebc6751e11b7037be6ee9f17db8040bb44f8466d519ce2abf",
    seedType: "segwit",
    path: "m/0'/0/0",
    publicKey: "02ca595d8a4a8e117dafb627738fbc88f258f6f75303e80d6ea11c9567ca81ac26",
    address: "bc1qe26k9rvz2frkjkepsml7jku9ses5jupls7t8e9",
  },
  {
    name: "chinese_with_passphrase",
    mnemonic: "眼 悲 叛 改 节 跃 衡 响 疆 股 遂 冬",
    passphrase: "给我一些测试向量谷歌",
    seed: "6c03dd0615cf59963620c0af6840b52e867468cc64f20a1f4c8155705738e87b8edb0fc8a6cee4085776cb3a629ff88bb1a38f37085efdbf11ce9ec5a7fa5f71",
    seedType: "segwit",
    path: "m/0'/0/0",
    publicKey: "039a474a7aa049251c44406c1c7d9558bea69175b69986db0178f22fb2a3ea5dae",
    address: "bc1qqxxe9jvuv4jc9c5mee5y7x7y7ttap422u68kva",
  },
  {
    name: "spanish",
    mnemonic:
      "almíbar tibio superar vencer hacha peatón príncipe matar consejo polen vehículo odisea",
    passphrase: "",
    seed: "18bffd573a960cc775bbd80ed60b7dc00bc8796a186edebe7fc7cf1f316da0fe937852a969c5c79ded8255cdf54409537a16339fbe33fb9161af793ea47faa7a",
    seedType: "standard",
    path: "m/0/0",
    publicKey: "0346188ff23aa9de6188cfbfb6786c0ba6b875b8b588946e10b158f92ff4b019b3",
    address: "1FckJut2asycDsV3qADcZf3htcjqgxw3Fw",
  },
  {
    name: "spanish_with_passphrase",
    mnemonic:
      "almíbar tibio superar vencer hacha peatón príncipe matar consejo polen vehículo odisea",
    passphrase: "araña difícil solución término cárcel",
    seed: "363dec0e575b887cfccebee4c84fca5a3a6bed9d0e099c061fa6b85020b031f8fe3636d9af187bf432d451273c625e20f24f651ada41aae2c4ea62d87e9fa44c",
    seedType: "standard",
    path: "m/0/0",
    publicKey: "0250fcc6b6d6bef9390cb78cbb716a7c95be8787210e72231ce820d2a743376550",
    address: "1PnidNAh53Et2pWmvpwn7eHEELUvt6mK29",
  },
  {
    name: "spanish2",
    mnemonic: "equipo fiar auge langosta hacha calor trance cubrir carro pulmón oro áspero",
    passphrase: "",
    seed: "001ebce6bfde5851f28a0d44aae5ae0c762b600daf3b33fc8fc630aee0d207646b6f98b18e17dfe3be0a5efe2753c7cdad95860adbbb62cecad4dedb88e02a64",
    seedType: "segwit",
    path: "m/0'/0/0",
    publicKey: "0265439f9f47c031595c163acc0b3d0d561ae98af1b902b4bbb01aa43627ae5abf",
    address: "bc1qv09z768ffaqf4hp7rx5gqlfpnxtmagz303wx97",
  },
  {
    name: "spanish3",
    mnemonic: "vidrio jabón muestra pájaro capucha eludir feliz rotar fogata pez rezar oír",
    passphrase:
      "¡Viva España! repiten veinte pueblos y al hablar dan fe del ánimo español... ¡Marquen arado martillo y clarín",
    seed: "c274665e5453c72f82b8444e293e048d700c59bf000cacfba597629d202dcf3aab1cf9c00ba8d3456b7943428541fed714d01d8a0a4028fc3a9bb33d981cb49f",
    seedType: "segwit",
    path: "m/0'/0/0",
    publicKey: "02b3d453ef7a9a956cffecaa22e1e4bd33dde432603e75108d659ad6319bc37192",
    address: "bc1q0fp4hfqy8zylxrfv50mxtehdc9xe0crjet3q4y",
  },
] as const;

/**
 * SLIP-0132 test vectors (satoshilabs/slips slip-0132.md): account keys of the BIP39
 * `abandon … about` mnemonic and the address at `0/0` below each.
 */
export const slip132Vectors = [
  {
    prefix: "xpub",
    addressType: "legacy",
    path: "m/44'/0'/0'",
    extendedKey:
      "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
    address: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
  },
  {
    prefix: "ypub",
    addressType: "p2sh",
    path: "m/49'/0'/0'",
    extendedKey:
      "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
    address: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
  },
  {
    prefix: "zpub",
    addressType: "segwit",
    path: "m/84'/0'/0'",
    extendedKey:
      "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
    address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
  },
] as const;

/** SLIP-0132 private counterpart of the `xpub` vector, which the watch-only path refuses. */
export const slip132PrivateKey =
  "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb";

/**
 * BIP32 test vector 2 (bitcoin/bips bip-0032.mediawiki): the master xpub and xprv, its normal
 * child m/0, and the hardened m/0/2147483647' below that child with the child's xpub.
 */
export const bip32ParentVector = {
  xpub: "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB",
  xprv: "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
  fingerprint: "bd16bee5",
  child: {
    index: 0,
    xpub: "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH",
    xprv: "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
    privateKey: "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
  },
  hardenedGrandchild:
    "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
} as const;

/**
 * BIP38 test vectors (bitcoin/bips bip-0038.mediawiki): the header of each key, read without its
 * passphrase, and the passphrase and WIF the spec gives. `address` is the one the spec lists; the
 * compressed vector lists none. The first passphrase is decomposed and NFC turns it into `cf93...`.
 */
export const bip38Vectors = [
  {
    encrypted: "6PRW5o9FLp4gJDDVqJQKJFTpMvdsSGJxMYHtHaQBF3ooa8mwD69bapcDQn",
    address: "16ktGzmfrurhbhi6JGqsMWf7TyqK9HNAeF",
    passphrase: "\u03D2\u0301\u0000\u{10400}\u{1F4A9}",
    wif: "5Jajm8eQ22H3pGWLEVCXyvND8dQZhiQhoLJNKjYXk9roUFTMSZ4",
    inspection: {
      mode: "non-ec",
      flagByte: 0xc0,
      compressed: false,
      hasLotSequence: false,
      addressHash: "f4e775a8",
    },
  },
  {
    encrypted: "6PYNKZ1EAgYgmQfmNVamxyXVWHzK5s6DGhwP4J5o44cvXdoY7sRzhtpUeo",
    address: undefined,
    passphrase: "TestingOneTwoThree",
    wif: "L44B5gGEpqEDRS9vVPz7QT35jcBG2r3CZwSwQ4fCewXAhAhqGVpP",
    inspection: {
      mode: "non-ec",
      flagByte: 0xe0,
      compressed: true,
      hasLotSequence: false,
      addressHash: "43be4179",
    },
  },
  {
    encrypted: "6PfQu77ygVyJLZjfvMLyhLMQbYnu5uguoJJ4kMCLqWwPEdfpwANVS76gTX",
    address: "1PE6TQi6HTVNz5DLwB1LcpMBALubfuN2z2",
    passphrase: "TestingOneTwoThree",
    wif: "5K4caxezwjGCGfnoPTZ8tMcJBLB7Jvyjv4xxeacadhq8nLisLR2",
    inspection: {
      mode: "ec-multiply",
      flagByte: 0x00,
      compressed: false,
      hasLotSequence: false,
      addressHash: "62b5b722",
      ownerEntropy: "a50dba6772cb9383",
      ownerSalt: "a50dba6772cb9383",
    },
  },
  {
    encrypted: "6PgNBNNzDkKdhkT6uJntUXwwzQV8Rr2tZcbkDcuC9DZRsS6AtHts4Ypo1j",
    address: "1Jscj8ALrYu2y9TD8NrpvDBugPedmbj4Yh",
    passphrase: "MOLON LABE",
    wif: "5JLdxTtcTHcfYcmJsNVy1v2PMDx432JPoYcBTVVRHpPaxUrdtf8",
    inspection: {
      mode: "ec-multiply",
      flagByte: 0x04,
      compressed: false,
      hasLotSequence: true,
      addressHash: "bb458cef",
      ownerEntropy: "4fca5a974040f001",
      ownerSalt: "4fca5a97",
      lot: 263183,
      sequence: 1,
    },
  },
] as const;

/**
 * Salted brainwallets of `example passphrase` with `example salt`. Each `privateKey` comes from
 * Python's `hashlib.scrypt` or `pbkdf2_hmac` and `sha256`; public key and addresses from it.
 */
export const brainwalletVectors = [
  {
    recipe: { kdf: "scrypt", N: 1024, r: 8, p: 1, hashed: "hex" },
    compressed: false,
    privateKey: "89d8021942b4241334ca682fbe2a212ee94920f4ea55c345743e1429d9bbd74a",
    publicKey:
      "04230b1e542924b40e8fa88667c93daa19e68288f7e7fede1ce6d9357679bfc942697e337b1ac45889076f6fc172c8e02d6d484e1bbca220dbd43b761600299d57",
    address: "12j4woaXhDT5YfdmHSaC8hDUG4X8di7JAM",
    testnetAddress: "mhF2ErfWWEtLKn7P11YZxcRo847qc5XhUb",
  },
  {
    recipe: { kdf: "scrypt", N: 1024, r: 8, p: 1, hashed: "bytes" },
    compressed: false,
    privateKey: "c1cc2e47e68caf25a7dcc4e8c9058d979df41d2316019af163a0b0a039ddef1e",
    publicKey:
      "044e7663f74542805c5d31768e6239a5a78fbd8af5e6a127c15b0fa61ee400131c6f663dccd4f404305472cfdda7d461a938a775dcdbe51c41e11c75504e1cb156",
    address: "1J9JW57dqgrH6TGuXRnLp8BKSP3QWLjt72",
    testnetAddress: "mxfFo8CceiHXsZkXEzkie3PeJNe7QH4TSb",
  },
  {
    recipe: { kdf: "pbkdf2", iterations: 1000, digest: "sha512", hashed: "bytes" },
    compressed: true,
    privateKey: "1e1e4bf6918c3f5713adffaee6faea3fb3859a761d4fefeb0a1dae82c6c7193b",
    publicKey: "03ee2b4bbf4bc8b3820a992c24ca166f7e7df660f7cce0ee9dfaf38c96680b59cc",
    address: "1CA2Xkf5EGW5yqwxAMnDzSGLJRQRK8r8CV",
    testnetAddress: "mrfypok43HwLkxRZsvkbpMUfAR18DbVCgq",
  },
  {
    recipe: { kdf: "pbkdf2", iterations: 1000, digest: "sha256", hashed: "hex", keyLength: 64 },
    compressed: true,
    privateKey: "d930872d990ef9c789771f480b8aba1edc0cc1f197b6538fb84ab1d8ccb775b9",
    publicKey: "032920154c36303cc151514c0d5cfbf5b7a3df72267169d9bd236e304221024ab2",
    address: "143jSNCEzfsBEKriKVcLnRHC5ScioHpqrX",
    testnetAddress: "miZgjRHDohJS1SLL34aicLVWwSDRhcGQV2",
  },
] as const;

/** Plain brainwallets, `rushwallet/1` first. Keys by `@agntn/hashes`, addresses by `keys mcp`. */
export const plainBrainwalletVectors = [
  {
    passphrase: "5784623964023 578462396402",
    recipe: { kdf: "sha256" },
    chain: "bitcoin",
    compressed: false,
    privateKey: "af9a17713338d255ca023b7014c2c9dfcbef656d61a3370156bb804269b74a0d",
    publicKey:
      "040f5492295b3374ac3d746beb5b1e3629f19e4b7caa228e7d02a1862430e237a7c406b11d339dea846001feb79410a4bd61212f2022538c13cb24b5ad0cb44d52",
    address: "1NKUXbr2URfQyzREPUzoj4MR4ytF5mEm8u",
  },
  {
    passphrase: "example passphrase",
    recipe: { kdf: "sha256", iterations: 3 },
    chain: "bitcoin",
    compressed: true,
    privateKey: "bddfabd33719c10fa1701f6da9ea7a9caa829b906d860a2d21ca1c39aa5d0eda",
    publicKey: "030c892dea4afc3ff5c22ed654b2082a4abe1ebb5bc5fb52e0d951db15c66fab10",
    address: "1BUUmQB5bjarzbQRb23czCexTmrWPdv8u8",
  },
  {
    passphrase: "example passphrase",
    recipe: { kdf: "keccak256" },
    chain: "ethereum",
    compressed: undefined,
    privateKey: "80c6781db380d4b92b845801b889b1f04ea93433fac5b19c9d0be7edb0b6e5e7",
    publicKey: "0248877131c564fe7001a1e8c3abc13a2cc30144b4bfc9527e38a09fab0577bac2",
    address: "0x98f5895db6EA91E06A60A875662ea0a626944866",
  },
] as const;

/**
 * WarpWallet keys of `Je`, checked with `node:crypto`. The first is WarpWallet challenge 1
 * (`warp/challenge-1` in `agntn/puzzles`), its public key from the claim transaction.
 */
export const warpWalletVectors = [
  {
    passphrase: "Je",
    salt: "",
    privateKey: "20f5df9cba8251e90a66d3aa1ca2849b12eaca135abb837671ac4a2bc2014e2b",
    publicKey:
      "045f751d820a69524eb71d48ddc6a231ba019b1461f58b0266cbbec617f9e80c6e573582b37014ce7ba7eaf9031265c5f022d8cb286f2194344f207eaa44bb51af",
    address: "1JKb1617p68H5MPkoNaMtaJCqKDU3h8qSn",
  },
  {
    passphrase: "Je",
    salt: "a@b.c",
    privateKey: "ec0ab56e294ad0ca880f4fd6ec0968ee7d084762288d0842a8f15bd44903b15a",
  },
] as const;

/** Passphrase and salt of `brainwalletVectors`, the salt also as the hex the tool takes. */
export const brainwalletInput = {
  passphrase: "example passphrase",
  salt: "example salt",
  saltHex: "6578616d706c652073616c74",
} as const;

/**
 * Version 3 keystores. The first three are geth's `accounts/keystore/testdata/v3_test_vector.json`,
 * the two short keys from early geth that dropped leading zeros. The last one comes from ethers v6
 * `encryptKeystoreJsonSync` with fixed salt, IV and UUID, and writes `Crypto` capitalized.
 * Addresses and public keys from ethers.
 */
export const storeVectors = [
  {
    name: "geth pbkdf2",
    keystore: {
      crypto: {
        cipher: "aes-128-ctr",
        cipherparams: { iv: "6087dab2f9fdbbfaddc31a909735c1e6" },
        ciphertext: "5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46",
        kdf: "pbkdf2",
        kdfparams: {
          c: 262144,
          dklen: 32,
          prf: "hmac-sha256",
          salt: "ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd",
        },
        mac: "517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2",
      },
      id: "3198bc9c-6672-5ab3-d995-4942343ae5b6",
      version: 3,
    },
    password: "testpassword",
    privateKey: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
    publicKey: "0332d87c5cd4b31d81c5b010af42a2e413af253dc3a91bd3d53c6b2c45291c3de7",
    address: "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b",
  },
  {
    name: "geth 31 byte key",
    keystore: {
      crypto: {
        cipher: "aes-128-ctr",
        cipherparams: { iv: "e0c41130a323adc1446fc82f724bca2f" },
        ciphertext: "9517cd5bdbe69076f9bf5057248c6c050141e970efa36ce53692d5d59a3984",
        kdf: "scrypt",
        kdfparams: {
          dklen: 32,
          n: 2,
          r: 8,
          p: 1,
          salt: "711f816911c92d649fb4c84b047915679933555030b3552c1212609b38208c63",
        },
        mac: "d5e116151c6aa71470e67a7d42c9620c75c4d23229847dcc127794f0732b0db5",
      },
      id: "fecfc4ce-e956-48fd-953b-30f8b52ed66c",
      version: 3,
    },
    password: "foo",
    privateKey: "00fa7b3db73dc7dfdf8c5fbdb796d741e4488628c41fc4febd9160a866ba0f35",
    publicKey: "0380eabc89985bd5928ce8ae28daceec6491d8f0d9891b5fe439f4b420138e818a",
    address: "0xd1E64E5480bFaf733Ba7D48712DEcb8227797a4e",
  },
  {
    name: "geth 30 byte key",
    keystore: {
      crypto: {
        cipher: "aes-128-ctr",
        cipherparams: { iv: "3ca92af36ad7c2cd92454c59cea5ef00" },
        ciphertext: "108b7d34f3442fc26ab1ab90ca91476ba6bfa8c00975a49ef9051dc675aa",
        kdf: "scrypt",
        kdfparams: {
          dklen: 32,
          n: 2,
          r: 8,
          p: 1,
          salt: "d0769e608fb86cda848065642a9c6fa046845c928175662b8e356c77f914cd3b",
        },
        mac: "75d0e6759f7b3cefa319c3be41680ab6beea7d8328653474bd06706d4cc67420",
      },
      id: "a37e1559-5955-450d-8075-7b8931b392b2",
      version: 3,
    },
    password: "foo",
    privateKey: "000081c29e8142bb6a81bef5a92bda7a8328a5c85bb2f9542e76f9b0f94fc018",
    publicKey: "0210e472f71385288eba6e66a8d63beb83fc663d962e8546bc61e1035d59ed634a",
    address: "0x31e9D1e6D844bd3a536800Ef8d8Be6A9975Db509",
  },
  {
    name: "ethers scrypt",
    keystore: {
      address: "008aeeda4d805471df9b2a5b0f38a0c3bcba786b",
      id: "33333333-3333-4333-b333-333333333333",
      version: 3,
      Crypto: {
        cipher: "aes-128-ctr",
        cipherparams: { iv: "22222222222222222222222222222222" },
        ciphertext: "8bf4b5ca6bdf32b5ac036bb2cffa775045e38cffa364c4e9e3916899cac0e952",
        kdf: "scrypt",
        kdfparams: {
          salt: "1111111111111111111111111111111111111111111111111111111111111111",
          n: 1024,
          dklen: 32,
          p: 1,
          r: 8,
        },
        mac: "25c8e4853b36ed31a5068ebcc98429b4d486e4e62b5eae1c989acbc769d26061",
      },
    },
    password: "zażółć gęślą jaźń",
    privateKey: "7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d",
    publicKey: "0332d87c5cd4b31d81c5b010af42a2e413af253dc3a91bd3d53c6b2c45291c3de7",
    address: "0x008AeEda4D805471dF9b2A5B0f38A0C3bCBA786b",
  },
] as const;

/**
 * Old seeds: Electrum 94a400fa `test_electrum_seed_old`, then hex and 24 words of our own.
 * Every key and address checked with Electrum 4.8.1 `keystore.from_seed`.
 */
export const electrumOldVectors = [
  {
    name: "vector",
    mnemonic:
      "powerful random nobody notice nothing important anyway look away hidden message over",
    hexSeed: "acb740e454c3134901d7c8f16497cc1c",
    masterPublicKey:
      "e9d4b7866dd1e91c862aebf62a49548c7dbf7bcc6e4b7b8c9da820c7737968df9c09d5a3e271dc814a29981f81b3faaf2737b551ef5dcc6189cf0f8252c442b3",
    children: [
      {
        change: 0,
        index: 0,
        publicKey:
          "045f7ba332df2a7b4f5d13f246e307c9174cfa9b8b05f3b83410a3c23ef8958d610be285963d67c7bc1feb082f168fa9877c25999963ff8b56b242a852b23e25ed",
        address: "1FJEEB8ihPMbzs2SkLmr37dHyRFzakqUmo",
      },
      {
        change: 1,
        index: 0,
        publicKey:
          "04c291245c2ee3babb2a35c39389df56540867f93794215f743b9aa97f5ba114c4cdee8d49d877966728b76bc649bb349efd73adef1d77452a9aac26f8c51ae1dd",
        address: "1KRW8pH6HFHZh889VDq6fEKvmrsmApwNfe",
      },
      {
        change: 0,
        index: 5,
        publicKey:
          "04935970bd7c9e51bfe8e1135bb89a8ce09f8876d60d81ba4432f5e6fa394e6d09c9ba78f8d87aa7c519892a6adb5e7b39702379411dd7ba49f324f8c7e4e51f17",
        address: "19iKVhJM5LYQWgecruHP3CjvhK2jmL1cHg",
      },
    ],
  },
  {
    name: "hex32",
    mnemonic: "00112233445566778899aabbccddeeff",
    masterPublicKey:
      "8209d4eb034ca5f7ec2783b52f1905f81a2a0e6aaace9277833d868e4531989a5abe1162beaf6e86e97f97618ef79f1e2ce3beef1cfd65243c35e4199a3b7c81",
    children: [
      {
        change: 0,
        index: 0,
        publicKey:
          "0443f5a3a03ee20f4cdb7ed7d12521db4a0fe09324d7f8363ae50bd17e509e7f5740de821f35c7cd45e7a74bd5e32e28d7e33b26dfe35a0d5ae5eab04073a0c167",
        address: "1JWcDJsfwi2oFYdWYq3qMQPW52mu2XPUyY",
      },
      {
        change: 1,
        index: 0,
        publicKey:
          "042d9b00840b01934c8d28bcc59e8643e54ba3e48d15d5d13c1296ba0bb935d8ae18b58e4c43a7adfac5a6604c08a627052f72d18a70c20210827cad1e4bfde5c0",
        address: "1FRP6p5MoagpJABos6y95KhoKshYjTcbLB",
      },
      {
        change: 0,
        index: 5,
        publicKey:
          "04534078d0fb75f8773633e2eafe6acd731ca8da0fd4aa0a4ed789abd281433a8a740cf31a7823f04649e7e4c610b46969c4ebf66126f5c7509d0390caf566fdf8",
        address: "12AxrizFd89sXtkgcqEokzLGC8hLdhUSgg",
      },
    ],
  },
  {
    name: "hex64",
    mnemonic: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    masterPublicKey:
      "419b285b5750889fe303ed2aef2e5d554ecbf3d7816a9b56b9efd048c58d7018ca82eea9e60782c72ef2d90f93fb7e75cdab7f1a8d873d3ef31e3c7880814e05",
    children: [
      {
        change: 0,
        index: 0,
        publicKey:
          "04be24f1058514d73c34bdf92777a1008cf20803bb635568875cd19ab8dc598655eac680230c723d1c95088f3bdcbb81a7d9d23f134c932d523ef8c3e0f2143fb8",
        address: "14UzaxxhBMk3Ardn2GKthzAnHTifMCLMzg",
      },
      {
        change: 1,
        index: 0,
        publicKey:
          "0453b81c6389e4cce576bf3af3bfd621dd5c28cbea6d4dc15d0a665d1550ffa47024ebda1f55119716cc94f0f4cfccf529dc94d2aeede973a4c05dd6adb4550049",
        address: "14B5L6G39ybSK7TcBCZ2Kii4wrVK6C5Uim",
      },
      {
        change: 0,
        index: 5,
        publicKey:
          "0476d7fbad6344a30d6adc86e4509f0ed0b12a5774ff8328f8bafd984e611516ff9a4fa7ffb1488106dbf949b3ae99296eff829a551f6975021c918ae8f523c2c4",
        address: "1M3HM6nzkYL783CPx9coFtAnxFBWrgsJLp",
      },
    ],
  },
  {
    name: "words24",
    mnemonic:
      "like like like like like like like like like like like like like like like like like like like like like like like like",
    masterPublicKey:
      "60cd6d0d5d7f32b92c9ee7b37ff37c2327eaf22a6df66613b6f11fca22145465fd8a576a9ba858dd2426dd149714f0d0ad66cecd186e810b6148bf9f84d34a15",
    children: [
      {
        change: 0,
        index: 0,
        publicKey:
          "0417a4667a00a6395a5c99e06c24f8f5dc8a545a72559a0bcdec2ce67fa1b962359a2506f44fdab6aca989e662a92ac4d107f6078d6d6144933fdfdc76df72e937",
        address: "13advkyrVrsYnnURbdtsDa4p8CaG7tLFc7",
      },
      {
        change: 1,
        index: 0,
        publicKey:
          "04459a0c87fb8bbc6d3330c3c3837f3cb187a10a21242da5de6494aa7db161d3735d2b8937fa287a0c442e9c2bff034ffdae2091aa7e5e16847e8d118e46fcb6e2",
        address: "16WPFmLPcqKwnLui1g5bXUDKmKqBq4LUM5",
      },
      {
        change: 0,
        index: 5,
        publicKey:
          "041d07c359f567f28548646bb28814680f7052b88f0160e8b6014dff2f299263bc4ec2eefdd4627c8c66f1208262febc0cbff7ae6bda0633d69fa70577d94d2f32",
        address: "13PFwGsbfpbsPC3oGJjNRv2G3Nbzf9Ef6Y",
      },
    ],
  },
] as const;

/** Addresses the wallet scan has to reach, each from a source outside this library. */
export const hdScanVectors = {
  /** Solved quizchain block 74, the vector of agntn/keys#188. */
  puzzle: {
    mnemonic: "apology tonight anxiety cloud oven excess object purity leopard sing sing poet",
    address: "1HbUcHKfpkUSssNtcfS3vKzdTMue3EByMQ",
    path: "m/44'/0'/0'/0/0",
  },
  /** First receiving addresses of the BIP84 and BIP86 test vectors, from the reference mnemonic. */
  segwit: { address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", path: "m/84'/0'/0'/0/0" },
  taproot: {
    address: "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
    path: "m/86'/0'/0'/0/0",
  },
} as const;

/** Entropy that means something. Digests from coreutils `md5sum`, `sha1sum` and `sha256sum`. */
export const entropyProfileVectors = {
  text: {
    entropy: "68656c6c6f20776f726c642031323334",
    text: "hello world 1234",
    mnemonic: "half clock brand tattoo alter response situate milk cage maze mimic harbor",
  },
  md5Empty: "d41d8cd98f00b204e9800998ecf8427e",
  sha1Satoshi: "df60cdc9182e4ce7d68b6baaaf2312f27a7a025c",
  sha256Bitcoin: "6b88c087247aa2f07ee1c5956b8e1a9f4c7f892a70e324f1bb3d161e05ca107b",
  md5Given: { text: "red blue green", digest: "0f26a0352db2265b7ce21e58c8525881" },
} as const;

/**
 * BIP322 vectors from bitcoin/bips: `bip-0322/basic-test-vectors.json` and the btcd generated set,
 * `generated-test-vectors.json` (btcsuite/btcd#2521). `unprefixed` is the one agntn/keys#198 quotes.
 */
export const bip322Vectors = {
  hashes: [
    {
      message: "",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      messageHash: "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1",
      toSpend: "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7",
      toSign: "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6",
    },
    {
      message: "Hello World",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      messageHash: "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a",
      toSpend: "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b",
      toSign: "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf",
    },
    {
      message: "UTF-8 support: öäüéàè 测试文本 😄",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      messageHash: "43936b237ea38c7794eb5d755e0d220b6db92ebfc5c8f482759d22b1286376d7",
      toSpend: "c8f4f525fe8afb1bc09b44175bd2096f079c98425e8a1be676b712add1fb62f0",
      toSign: "8f488e06b89eafd019ec528109eafaf7f1d1811fd617aa1eeb9658f1c1be6586",
    },
  ],
  /** One key signs both `""` and `Hello World`; RFC 6979 makes its ECDSA signatures exact. */
  segwitKey: "L3VFeEujGtevx9w18HD1fhRbCH67Az2dpCymeRE1SoPK6XQtaN2k",
  simple: [
    {
      addressType: "segwit",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "",
      signature:
        "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    },
    {
      addressType: "segwit",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "",
      signature:
        "smpAkgwRQIhAPkJ1Q4oYS0htvyuSFHLxRQpFAY56b70UvE7Dxazen0ZAiAtZfFz1S6T6I23MWI2lK/pcNTWncuyL8UL+oMdydVgzAEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
    },
    {
      addressType: "segwit",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "Hello World",
      signature:
        "smpAkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    },
    {
      addressType: "segwit",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "Hello World",
      signature:
        "smpAkgwRQIhAOzyynlqt93lOKJr+wmmxIens//zPzl9tqIOua93wO6MAiBi5n5EyAcPScOjf1lAqIUIQtr3zKNeavYabHyR8eGhowEhAsfxIAMZZEKUPYWI4BruhAQjzFT8FSFSajuFwrDL1Yhy",
    },
    {
      addressType: "taproot",
      address: "bc1pss0zhytly75awhm6x2hhvd5lnzv3vssgrf9axfheq8ldyzn88ges79fler",
      message: "No prefix fallback",
      signature:
        "AUCJYOwOjxYAvatTAGYaVlNXBVyFuc4MwNQkOuK2tl8xhfKDONd0NjfYyNSYcRqeCp8hsAnCEPHAVEkO9h6vbQ/R",
    },
    {
      addressType: "taproot",
      address: "bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38",
      message: "PURVOQ544B6HUATVBJZN5EZJUU",
      signature:
        "smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8",
    },
  ],
  unprefixed: {
    address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
    message: "Hello World",
    signature:
      "AkcwRAIgZRfIY3p7/DoVTty6YZbWS71bc5Vct9p9Fia83eRmw2QCICK/ENGfwLtptFluMGs2KsqoNSk89pO7F29zJLUx9a/sASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
  },
  /** Each one sets version 2, lock time 2016 and sequence 2016 on `to_sign`. */
  full: [
    {
      addressType: "legacy",
      address: "13vU5PUSuArDXJdCWZvUFEbgJ2wcmtSJWn",
      message: "MOISC5NCQ42ADH2SUXLELUJOWH",
      signature:
        "fulAgAAAAGn3Z6t/gsHNyHdgZTOVro0Hej+qbd/ilU1ACalKoHX3gAAAABqRzBEAiB+8t/tm8Jm6zYv9JGZZVlAUjmqg7ZglIA39U+bim8EKQIgDv3E5cHOagN+xYgN3ZQjTYlAJp/WyslwJWuFP1TmM3IBIQJcPK2h9SY+Ki1oussvHnMdFAhJgsYBFPl+rNcMv9P1ROAHAAABAAAAAAAAAAABauAHAAA=",
    },
    {
      addressType: "segwit",
      address: "bc1qrqtlzcq86850yzgsyq9sssawx2qxlx5yq3xpkd",
      message: "KLE5MMJBTNF4AVZXIO3GIL5UWF",
      signature:
        "fulAgAAAAABAUrfzHHOLAKmgCIFSTT3krp+cQxj1BDPBN4GBg3tRmFXAAAAAADgBwAAAQAAAAAAAAAAAWoCSDBFAiEAjYj85zyhQKa9DbMO0reDwdhkNwKJkF3q2qFcijXDgMUCIAaQ75s3fwqrCeYIUJugLvhxZFxQIVquGN90vIKCW3QLASEDMurnDzvc0zABUwVwCADfGXoDx/M3SQnYt7e3IHDoU3PgBwAA",
    },
    {
      addressType: "taproot",
      address: "bc1pve87s3l2levjmhetzr2f9xvep3y266xty0hnefmyv8tkxc3e4qssll2kdu",
      message: "XQMVC3YR6AOGZIHLSUQ2NSSBI2",
      signature:
        "fulAgAAAAABAROFPNY6Zt8hFK0YQq5Wb6wk/CnUYEPtQ0HTHDyzNROrAAAAAADgBwAAAQAAAAAAAAAAAWoBQNRdLOo5XZY0SBqAsLZNr/z3Bqrmo3OxVn7e4tD/OOD4H9U/L1unq5Nmdz+S1w7SHtt46bFwnd8xnRVan8BofFfgBwAA",
    },
    {
      addressType: "p2sh",
      address: "32Utb7Seg6EXq7UesMNJXhQ1gdohYNyzQ9",
      message: "EMYGZHEY3LIANYKCR7XJF3NMFQ",
      signature:
        "fulAgAAAAABAe5xLNMlYQH4OGjJ3h4lqQaVp0Cic7mwxkvyWswqFMXeAAAAABcWABSy/hpDH/KLAi4x25Tmb2UaO1xtWeAHAAABAAAAAAAAAAABagJHMEQCIDEleqb0n1R5c21TGkWRXNFae98wbwI0QOyh/YmRuQX1AiAcv1MhyTzPOVgZ1VIwuu0tDxrVJUHK8lhOUOXpsZnGwwEhAsjeDEoWX8hvEC8A/692yGQsPh6JBO8Zf4aITEQsKAcJ4AcAAA==",
    },
  ],
  inconclusive: [
    {
      addressType: "p2wsh",
      witness: true,
      address: "bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9",
      message: "This will be a p2wsh 3-of-3 multisig BIP 322 signed message",
      signature:
        "smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=",
    },
    {
      addressType: "taproot",
      witness: true,
      address: "bc1p6vffkx7vcyezrjq7pg9qqdjv7vmtanfhk8ukwsn4syejwmarmhxqp0rw5x",
      message: "AY2VOQOXYI5CN2EHZKLOX7ZI37",
      signature:
        "fulAgAAAAABAaza7/ukfX9ZdxCUvK7CPJgADDdPdF7ikXVKWctd5EHrAAAAAADgBwAAAQAAAAAAAAAAAWoEQPvuT0enYGwsab2lsPZU0U3OcRkGng+o/PAt4QU2lc8hG7lTUmflkt0To+eoipv2vptf0TlGOBCsKU5xE3kXKcMAS2MgrYfXhOkh0CvwuJpB+O3tal2ECfO0v7k1/A4PTlGcQiBnAuAHsnUgJjLn4tl5ytgC8CNTyITXmg4rx9ctxPedwRMPEBvfoUBorCHBJjLn4tl5ytgC8CNTyITXmg4rx9ctxPedwRMPEBvfoUDgBwAA",
    },
    {
      addressType: "p2sh",
      witness: false,
      address: "3Nye4j1GUFqCEBR3do2KEFZAs9oLe8NZ6X",
      message: "7OKFLKRXSP6J42VQOMSG7MVXEP",
      signature:
        "fulAgAAAAEvAyd4zsoz8gcVU5H19GLYokTAN5PxuKCBlEPjODJ86gAAAADaAEcwRAIgT6rcfxgCmG6b3DpzNV6UG0jiCQGclG9sfiSpV45HDXMCIGgtqjFBuJ7rbi+cgnG0TZiKZaxMk0KI+gQd0pHJfEYCAUgwRQIhANCvCLjGMuZMzH+nCEkNhWhR45T6QRYMLin8utpuF9r1AiBTjG2NLjkre7ec+HPg8UUhK1jL1vgq7YKjq5ROv+h07AFHUiEDhKjcb/Pv1/7AYutzOXwgec08wwD/VwiPm58Lc0xjohghAhycjpwdBuP33orQXAH1CAsrgSkuspxM2+FPQ4OCVhQWUq7gBwAAAQAAAAAAAAAAAWrgBwAA",
    },
    {
      addressType: "p2sh",
      witness: true,
      address: "3PGZjFkYBL1m9WBWkWbCW5FEFTaS1Hj4EB",
      message: "NQVRV3DJYLKBANM3OPTNBULEU3",
      signature:
        "fulAgAAAAABAVscdBvYDFN98A//Rt/fAWcN7mdM0x2yWzBjC33c7X5HAAAAACMiACDkkR/DseXy+GXBPtxHvHehUjHt+9XjRmZAgxuuomAC4eAHAAABAAAAAAAAAAABagQASDBFAiEA47YK5XeIGBMQC9bCfWb+IIfirIWlqAzQVc6E/lgBPZICIA0k/EO2t3YhqmYR5WdXUBGgAzR+IqgZ5/mxvj+4UoDTAUgwRQIhAPCIVZCSoIaOjY9BzYIXWEvbhpOl4JR88p/xYVoZObd6AiADyJXNqpDg/Lc2viPX14N2d0jQdEjamY4SmiU7GNbIOgFHUiED+4JBU/wACiE8VFbQF4DR8pKgz7+8X2+PHccTcGxVGdEhA9uIzp+4CB5QRgvrN1OXQbBmfW8kOd0cooPWMYJCHBCxUq7gBwAA",
    },
  ],
  invalid: [
    {
      description: "invalid base64 encoding",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "",
      signature: "not-valid-base64!!!",
    },
    {
      description: "empty signature",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "",
      signature: "",
    },
    {
      description: "wrong message for valid simple p2wpkh signature (empty message was signed)",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "Wrong message that was not signed",
      signature:
        "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    },
    {
      description: "wrong address for valid simple p2wpkh signature (signed for different address)",
      address: "bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9",
      message: "",
      signature:
        "smpAkcwRAIgM2gBAQqvZX15ZiysmKmQpDrG83avLIT492QBzLnQIxYCIBaTpOaD20qRlEylyxFSeEA2ba9YOixpX8z46TSDtS40ASECx/EgAxlkQpQ9hYjgGu6EBCPMVPwVIVJqO4XCsMvViHI=",
    },
    {
      description: "empty witness stack (single zero byte)",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "",
      signature: "smpAA==",
    },
    {
      description: "wrong message for valid simple p2wsh 3-of-3 multisig signature",
      address: "bc1qp0ahvfh83088w49k405szqgg4f3pptr7p2g06tdxfjcd40z4lh4q95lsz9",
      message: "This is not the message that was signed",
      signature:
        "smpBQBHMEQCIFX9aaqPJWq2Ff2kpen5bFDTid+ehgUOpHV0LfjncXy4AiA3GNicF7aKPzdpa9PCpmaYQs3pHd+qbvvhXdxOCKCAMAFIMEUCIQD/ELXg6CNYyUQijCg96JtgvgjZb9dsl1Ctof4QAeyTcQIgVM/1AAblFl/DCt6A1gJg+T/i2qU5SQD09+chFJzolRwBSDBFAiEAlqRfSFyWNVQhvaCnmeV5tyneiCWMTcFbuujoD/pFa3wCIGnZjfQb8NolSYq9asV+ZeBSkCGHJcqnaV4JYS5MYPEGAWlTIQJ1aLEfEi/4p7wcV+XHZCBVvGGJZ7L3v+jhH+mZA8lN0yECCovfec+kIdllXpKCgA8RX/HZ2x5yHOtCSKP8/sf6pnwhAwxSng6kCgCXXSAmJOOZFdr3vdK3HzGqCFloOHgc5fM6U64=",
    },
    {
      description: "invalid signature prefix",
      address: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l",
      message: "",
      signature: "fooAA==",
    },
    {
      description: "incorrect prefix type",
      address: "bc1pyrgrm6cu6n54jrvkdjd9rvyd3xfyu84s2623awu2srn6mxhscwpsm5644w",
      message: "incorrect prefix",
      signature:
        "fulAUDZwFXUp+adN+/UZj5dVrGAbB3zKs1Vcalz5fCF9srxS63eSWNGvH1NYbrBkPt1BJDUyWUz9zgUxfc63/QheT6M",
    },
    {
      description: "wrong message for p2tr simple signature",
      address: "bc1pcquvhrqv0q68t4m0hfq6tpn006qrskyc7yrqnp2uyrf2emg3wynsdjyk38",
      message: "56VM6YK6Y76XTBXNPITF232EPX",
      signature:
        "smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8",
    },
    {
      description: "wrong signer for p2tr simple signature",
      address: "bc1pltvk000nd54v3hrrcn7lsffdra72hphpm40rhzf9hn8arqkgermq2p9029",
      message: "PURVOQ544B6HUATVBJZN5EZJUU",
      signature:
        "smpAUB6B2Rbupzua8LTQIF06516wzl+cwKy1be8RgoiW0riyXdKwe6GTz/5Hnb37m67pJwIKCh+D5jDueG6KpvYpmu8",
    },
    {
      description: "wrong message for p2pkh full signature",
      address: "13vU5PUSuArDXJdCWZvUFEbgJ2wcmtSJWn",
      message: "TCHG6CQ5E2T5S4S7DPLAEFVDY2",
      signature:
        "fulAgAAAAGn3Z6t/gsHNyHdgZTOVro0Hej+qbd/ilU1ACalKoHX3gAAAABqRzBEAiB+8t/tm8Jm6zYv9JGZZVlAUjmqg7ZglIA39U+bim8EKQIgDv3E5cHOagN+xYgN3ZQjTYlAJp/WyslwJWuFP1TmM3IBIQJcPK2h9SY+Ki1oussvHnMdFAhJgsYBFPl+rNcMv9P1ROAHAAABAAAAAAAAAAABauAHAAA=",
    },
    {
      description: "wrong signer for p2pkh full signature",
      address: "1BxMhvfWLnGLqVhJ3j39oDBk7qf5D86BFe",
      message: "MOISC5NCQ42ADH2SUXLELUJOWH",
      signature:
        "fulAgAAAAGn3Z6t/gsHNyHdgZTOVro0Hej+qbd/ilU1ACalKoHX3gAAAABqRzBEAiB+8t/tm8Jm6zYv9JGZZVlAUjmqg7ZglIA39U+bim8EKQIgDv3E5cHOagN+xYgN3ZQjTYlAJp/WyslwJWuFP1TmM3IBIQJcPK2h9SY+Ki1oussvHnMdFAhJgsYBFPl+rNcMv9P1ROAHAAABAAAAAAAAAAABauAHAAA=",
    },
    {
      description: "wrong message for p2sh-p2wpkh full signature",
      address: "32Utb7Seg6EXq7UesMNJXhQ1gdohYNyzQ9",
      message: "CPVOBEXDTFAXS6N4YASD753CZV",
      signature:
        "fulAgAAAAABAe5xLNMlYQH4OGjJ3h4lqQaVp0Cic7mwxkvyWswqFMXeAAAAABcWABSy/hpDH/KLAi4x25Tmb2UaO1xtWeAHAAABAAAAAAAAAAABagJHMEQCIDEleqb0n1R5c21TGkWRXNFae98wbwI0QOyh/YmRuQX1AiAcv1MhyTzPOVgZ1VIwuu0tDxrVJUHK8lhOUOXpsZnGwwEhAsjeDEoWX8hvEC8A/692yGQsPh6JBO8Zf4aITEQsKAcJ4AcAAA==",
    },
    {
      description: "wrong signer for p2sh-p2wpkh full signature",
      address: "3QMEQj2LTUtKKR1UatUK44z1NwrWrcVSGh",
      message: "EMYGZHEY3LIANYKCR7XJF3NMFQ",
      signature:
        "fulAgAAAAABAe5xLNMlYQH4OGjJ3h4lqQaVp0Cic7mwxkvyWswqFMXeAAAAABcWABSy/hpDH/KLAi4x25Tmb2UaO1xtWeAHAAABAAAAAAAAAAABagJHMEQCIDEleqb0n1R5c21TGkWRXNFae98wbwI0QOyh/YmRuQX1AiAcv1MhyTzPOVgZ1VIwuu0tDxrVJUHK8lhOUOXpsZnGwwEhAsjeDEoWX8hvEC8A/692yGQsPh6JBO8Zf4aITEQsKAcJ4AcAAA==",
    },
  ],
} as const;

/**
 * Core's sighash.json (sighash reversed), the signed BIP143 examples, BIP341 `keyPathSpending[0]`
 * and txid 9ec4bc49...c4b1 from 2012, two inputs under one nonce and loose DER.
 */
export const transactionVectors = {
  legacy: {
    none: {
      transaction:
        "2f7353dd02e395b0a4d16da0f7472db618857cd3de5b9e2789232952a9b154d249102245fd030000000151617fd88f103280b85b0a198198e438e7cab1a4c92ba58409709997cc7a65a619eb9eec3c0200000003636aabffffffff0397481c0200000000045300636a0dc97803000000000009d389030000000003ac6a53134007bb",
      script: "0000536552526a",
      index: 0,
      hashType: -1912746174,
      sighash: "30c4cd4bd6b291f7e9489cc4b4440a083f93a7664ea1f93e77a9597dab8ded9c",
    },
    single: {
      transaction:
        "6f62138301436f33a00b84a26a0457ccbfc0f82403288b9cbae39986b34357cb2ff9b889b302000000045253655335a7ff6701bac9960400000000086552ab656352635200000000",
      script: "6aac51",
      index: 0,
      hashType: 1444414211,
      sighash: "502a2435fd02898d2ff3ab08a3c19078414b32ec9b73d64a944834efc9dae10c",
    },
    allAnyoneCanPay: {
      transaction:
        "e3cdbfb4014d90ae6a4401e85f7ac717adc2c035858bf6ff48979dd399d155bce1f150daea0300000002ac51a67a0d39017f6c71040000000005535200535200000000",
      script: "",
      index: 0,
      hashType: -1899950911,
      sighash: "c1c7df8206e661d593f6455db1d61a364a249407f88e99ecad05346e495b38d7",
    },
    codeSeparator: {
      transaction:
        "b240517501334021240427adb0b413433641555424f6d24647211e3e6bfbb22a8045cbda2f000000000071bac8630112717802000000000000000000",
      script: "6a5165abac52656551",
      index: 0,
      hashType: 1790414254,
      sighash: "2c8be597620d95abd88f9c1cf4967c1ae3ca2309f3afec8928058c9598660e9e",
    },
  },
  p2wpkh: {
    transaction:
      "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000",
    spent: [
      {
        script: "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac",
        value: 625000000,
      },
      {
        script: "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1",
        value: 600000000,
      },
    ],
    sighash: "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670",
    publicKey: "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357",
    p2pkPublicKey: "03c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432",
  },
  p2shP2wpkh: {
    transaction:
      "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000",
    spent: [
      {
        script: "a9144733f37cf4db86fbc2efed2500b4f4e49f31202387",
        value: 1000000000,
      },
    ],
    sighash: "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6",
    publicKey: "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873",
  },
  p2shP2wsh: {
    transaction:
      "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000",
    spent: [
      {
        script: "a9149993a429037b5d912407a71c252019287b8d27a587",
        value: 987654321,
      },
    ],
    signatures: [
      [
        1,
        "185c0be5263dce5b4bb50a047973c1b6272bfbd0103a89444597dc40b248ee7c",
        "0307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba3",
      ],
      [
        2,
        "e9733bc60ea13c95c6527066bb975a2ff29a925e80aa14c213f686cbae5d2f36",
        "03b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b",
      ],
      [
        3,
        "1e1f1c303dc025bd664acb72e583e933fae4cff9148bf78c157d1e8f78530aea",
        "034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a",
      ],
      [
        129,
        "2a67f03e63a6a422125878b40b82da593be8d4efaafe88ee528af6e5a9955c6e",
        "033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f4",
      ],
      [
        130,
        "781ba15f3779d5542ce8ecb5c18716733a5ee42a6f51488ec96154934e2c890a",
        "03a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac16",
      ],
      [
        131,
        "511e8e52ed574121fc1b654970395502128263f62662e076dc6baf05c2e6a99b",
        "02d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b",
      ],
    ],
  },
  taproot: {
    unsigned:
      "02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d",
    signed:
      "020000000001097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a41842000000006b4830450221008f3b8f8f0537c420654d2283673a761b7ee2ea3c130753103e08ce79201cf32a022079e7ab904a1980ef1c5890b648c8783f4d10103dd62f740d13daa79e298d50c201210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0141ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c030141052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f83000141ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a010140b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f0247304402202b795e4de72646d76eab3f0ab27dfa30b810e856ff3a46c9a702df53bb0d8cc302203ccc4d822edab5f35caddb10af1be93583526ccfbade4b4ead350781e2f8adcd012102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f90141a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee0020141ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c4820141bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd9810065cd1d",
    spent: [
      {
        script: "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        value: 420000000,
      },
      {
        script: "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        value: 462000000,
      },
      {
        script: "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
        value: 294000000,
      },
      {
        script: "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e",
        value: 504000000,
      },
      {
        script: "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605",
        value: 630000000,
      },
      {
        script: "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc",
        value: 378000000,
      },
      {
        script: "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831",
        value: 672000000,
      },
      {
        script: "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5",
        value: 546000000,
      },
      {
        script: "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220",
        value: 588000000,
      },
    ],
    inputs: [
      {
        index: 0,
        hashType: 3,
        sighash: "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555",
      },
      {
        index: 1,
        hashType: 131,
        sighash: "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d",
      },
      {
        index: 3,
        hashType: 1,
        sighash: "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669",
      },
      {
        index: 4,
        hashType: 0,
        sighash: "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef",
      },
      {
        index: 6,
        hashType: 2,
        sighash: "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85",
      },
      {
        index: 7,
        hashType: 130,
        sighash: "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10",
      },
      {
        index: 8,
        hashType: 129,
        sighash: "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2",
      },
    ],
  },
  reusedNonce2012: {
    transaction:
      "0100000002f64c603e2f9f4daf70c2f4252b2dcdb07cc0192b7238bc9c3dacbae555baf701010000008a4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1022044e1ff2dfd8102cf7a47c21d5c9fd5701610d04953c6836596b4fe9dd2f53e3e014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ffffffffff29f841db2ba0cafa3a2a893cd1d8c3e962e8678fc61ebe89f415a46bc8d9854a010000008a4730440220d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad102209a5f1c75e461d7ceb1cf3cab9013eb2dc85b6d0da8c3c6e27e3a5a5b3faa5bab014104dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ffffffffff01a0860100000000001976a91470792fb74a5df745bac07df6fe020f871cbb293b88ac00000000",
    spent: [
      {
        script: "76a91470792fb74a5df745bac07df6fe020f871cbb293b88ac",
        value: 130000,
      },
      {
        script: "76a91470792fb74a5df745bac07df6fe020f871cbb293b88ac",
        value: 20000,
      },
    ],
    r: "d47ce4c025c35ec440bc81d99834a624875161a26bf56ef7fdc0f5d52f843ad1",
    publicKey:
      "04dbd0c61532279cf72981c3584fc32216e0127699635c2789f549e0730c059b81ae133016a69c21e23f1859a95f06d52b7bf149a8f2fe4e8535c8a829b449c5ff",
  },
} as const;

/** The nonce reuse vector of agntn/keys#196: z1 is SHA-256 of "one", z2 of "two". */
export const reusedNonceVector = {
  privateKey: "1234567890abcdef",
  nonce: "0badc0ffee",
  r: "719d9d9b90eb4cd45ca9db4248429d1f9e8097c15bd0ec8cd5f492711d42dba1",
  first: {
    s: "a408a6a0ed88e5f7ab22fce472b2099672306596282d9fc2d3caeb1cf49c2c54",
    z: "7692c3ad3540bb803c020b3aee66cd8887123234ea0c6e7143c0add73ff431ed",
  },
  second: {
    s: "7d6c4c5f3f0c0b7757fa64f3748d40672c88f184d61b7f87e7a8959d7ddf97c8",
    z: "3fc4ccfe745870e2c0d99f71f30ff0656c8dedd41cc1d7d3d376b0dbe685e2f3",
  },
} as const;

/** BIP 381 to 387 descriptors with scripts at indices 0 to 2; Core v31.1 checksums, addresses. */
export const descriptorVectors = {
  generator: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  double: "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  bip: [
    {
      descriptor: "pkh([deadbeef/1/2'/3/4']L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
      scripts: ["76a9149a1c78a507689f6f54b847ad1cef1e614ee23f1e88ac"],
    },
    {
      descriptor:
        "pkh(04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235)",
      scripts: ["76a914b5bd079c4d57cc7fc28ecf8213a6b791625b818388ac"],
    },
    {
      descriptor: "sh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
      scripts: ["a9141857af51a5e516552b3086430fd8ce55f7c1a52487"],
    },
    {
      descriptor: "sh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
      scripts: ["a9141a31ad23bf49c247dd531a623c2ef57da3c400c587"],
    },
    {
      descriptor:
        "pkh([bd16bee5/2147483647h]xpub69H7F5dQzmVd3vPuLKtcXJziMEQByuDidnX3YdwgtNsecY5HRGtAAQC5mXTt4dsv9RzyjgDjAQs9VGVV6ydYCHnprc9vvaA5YtqWyL6hyds/0)",
      scripts: ["76a914ebdc90806a9c4356c1c88e42216611e1cb4c1c1788ac"],
    },
    {
      descriptor:
        "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)",
      scripts: [
        "0014326b2249e3a25d5dc60935f044ee835d090ba859",
        "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7",
        "00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27",
      ],
    },
    {
      descriptor:
        "sh(wpkh(xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*h))",
      scripts: [
        "a9149a4d9901d6af519b2a23d4a2f51650fcba87ce7b87",
        "a914bed59fc0024fae941d6e20a3b44a109ae740129287",
        "a9148483aa1116eb9c05c482a72bada4b1db24af654387",
      ],
    },
    {
      descriptor: "wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
      scripts: ["0020338e023079b91c58571b20e602d7805fb808c22473cbc391a41b1bd3a192e75b"],
    },
    {
      descriptor: "wsh(pk(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd))",
      scripts: ["00202e271faa2325c199d25d22e1ead982e45b64eeb4f31e73dbdf41bd4b5fec23fa"],
    },
    {
      descriptor:
        "sh(wsh(pkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)))",
      scripts: ["a914b61b92e2ca21bac1e72a3ab859a742982bea960a87"],
    },
    {
      descriptor:
        "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))",
      scripts: ["a91445a9a622a8b0a1269944be477640eedc447bbd8487"],
    },
    {
      descriptor:
        "wsh(multi(2,xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U/2147483647'/0,xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*,xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi/10/20/30/40/*'))",
      scripts: [
        "0020b92623201f3bb7c3771d45b2ad1d0351ea8fbf8cfe0a0e570264e1075fa1948f",
        "002036a08bbe4923af41cf4316817c93b8d37e2f635dd25cfff06bd50df6ae7ea203",
        "0020a96e7ab4607ca6b261bfe3245ffda9c746b28d3f59e83d34820ec0e2b36c139c",
      ],
    },
    {
      descriptor:
        "wsh(multi(20,KzoAz5CanayRKex3fSLQ2BwJpN7U52gZvxMyk78nDMHuqrUxuSJy,KwGNz6YCCQtYvFzMtrC6D3tKTKdBBboMrLTsjr2NYVBwapCkn7Mr,KxogYhiNfwxuswvXV66eFyKcCpm7dZ7TqHVqujHAVUjJxyivxQ9X,L2BUNduTSyZwZjwNHynQTF14mv2uz2NRq5n5sYWTb4FkkmqgEE9f,L1okJGHGn1kFjdXHKxXjwVVtmCMR2JA5QsbKCSpSb7ReQjezKeoD,KxDCNSST75HFPaW5QKpzHtAyaCQC7p9Vo3FYfi2u4dXD1vgMiboK,L5edQjFtnkcf5UWURn6UuuoFrabgDQUHdheKCziwN42aLwS3KizU,KzF8UWFcEC7BYTq8Go1xVimMkDmyNYVmXV5PV7RuDicvAocoPB8i,L3nHUboKG2w4VSJ5jYZ5CBM97oeK6YuKvfZxrefdShECcjEYKMWZ,KyjHo36dWkYhimKmVVmQTq3gERv3pnqA4xFCpvUgbGDJad7eS8WE,KwsfyHKRUTZPQtysN7M3tZ4GXTnuov5XRgjdF2XCG8faAPmFruRF,KzCUbGhN9LJhdeFfL9zQgTJMjqxdBKEekRGZX24hXdgCNCijkkap,KzgpMBwwsDLwkaC5UrmBgCYaBD2WgZ7PBoGYXR8KT7gCA9UTN5a3,KyBXTPy4T7YG4q9tcAM3LkvfRpD1ybHMvcJ2ehaWXaSqeGUxEdkP,KzJDe9iwJRPtKP2F2AoN6zBgzS7uiuAwhWCfGdNeYJ3PC1HNJ8M8,L1xbHrxynrqLKkoYc4qtoQPx6uy5qYXR5ZDYVYBSRmCV5piU3JG9,KzRedjSwMggebB3VufhbzpYJnvHfHe9kPJSjCU5QpJdAW3NSZxYS,Kyjtp5858xL7JfeV4PNRCKy2t6XvgqNNepArGY9F9F1SSPqNEMs3,L2D4RLHPiHBidkHS8ftx11jJk1hGFELvxh8LoxNQheaGT58dKenW,KyLPZdwY4td98bKkXqEXTEBX3vwEYTQo1yyLjX2jKXA63GBpmSjv))",
      scripts: ["0020376bd8344b8b6ebe504ff85ef743eaa1aa9272178223bcb6887e9378efb341ac"],
    },
    {
      descriptor: "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
      scripts: ["512077aab6e066f8a7419c5ab714c12c67d25007ed55a43cadcacb4d7a970a093f11"],
    },
    {
      descriptor:
        "tr(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/0/*,pk(xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc/1/*))",
      scripts: [
        "512078bc707124daa551b65af74de2ec128b7525e10f374dc67b64e00ce0ab8b3e12",
        "512001f0a02a17808c20134b78faab80ef93ffba82261ccef0a2314f5d62b6438f11",
        "512021024954fcec88237a9386fce80ef2ced5f1e91b422b26c59ccfc174c8d1ad25",
      ],
    },
    {
      descriptor:
        "tr(a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd,{pk(xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334/0),{{pk(xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL),pk(02df12b7035bdac8e3bab862a3a83d06ea6b17b6753d52edecba9be46f5d09e076)},pk(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)}})",
      scripts: ["512071fff39599a7b78bc02623cbe814efebf1a404f5d8ad34ea80f213bd8943f574"],
    },
    {
      descriptor:
        "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))",
      scripts: ["512016fa6a6ba7e98c54b5bf43b3144912b78a61b60b02f6a74172b8dcb35b12bc30"],
    },
    {
      descriptor:
        "tr(50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0,sortedmulti_a(2,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/*,xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y/0/0/*))",
      scripts: [
        "5120abd47468515223f58a1a18edfde709a7a2aab2b696d59ecf8c34f0ba274ef772",
        "5120fe62e7ed20705bd1d3678e072bc999acb014f07795fa02cb8f25a7aa787e8cbd",
        "51201311093750f459039adaa2a5ed23b0f7a8ae2c2ffb07c5390ea37e2fb1050b41",
      ],
    },
  ],
  core: [
    {
      descriptor:
        "wsh(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))",
      checksum: "e7d75zev",
      addresses: ["bc1qnwvyc7aw8m7acw3lpgs0lqdlaz0drls8luf72cs5nmn9f0kcghdse7d78q"],
    },
    {
      descriptor:
        "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,{pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5),pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)})",
      checksum: "03sk89am",
      addresses: ["bc1pwgupz6agmgdltvcz287xzqqfjjwdfffl33g0g4e5zf2lcvfhj9dsrcy5kf"],
    },
    {
      descriptor:
        "tr(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))",
      addresses: ["bc1pptw3pzy7xtj0fflss9rryyargekdy3cm4ya4vnnq5r9804c9erls70zeww"],
    },
    {
      descriptor:
        "wsh(sortedmulti(1,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/0/*))",
      checksum: "r2fy2fzj",
      first: 5,
      addresses: [
        "bc1q3aut6vqv60hdsm4pe2mvz3jf6yh65hnexkzcdw796mu7x0ntpc4q8fay6w",
        "bc1q4a9q8r6whz8x20dxmcxvwn54l3fjfzkgtzq5km8x4zpep8x89lus07kwvh",
        "bc1qf3svjksfgxe9lfv02ytts68u9exk7xztfng87p5vv0hjdlam75fq6al4eg",
      ],
    },
    {
      descriptor:
        "tr(tpubD6NzVbkrYhZ4Y529GvCkRKDNJ6AAF8VptYbpg3GSbqTkUQnNi3cYTzzDtjPqfcoZdii14nQRPLt4A9LCHGUUzL6RC3z1ZPUdP1yCaAwR3nZ/2/*)",
      network: "testnet",
      checksum: "arkg57je",
      addresses: [
        "tb1p88p72aflunwmqdd7t5v3gqcjdapxpuexnmznuuchr86sxj0nx9mqe8la9q",
        "tb1ppfrknfvxfhjdt69e9xe30jv4vns34xly27jrsgtm64ssvpynx26qee26nl",
      ],
    },
  ],
  /** The valid checksum of BIP380. */
  checksum: { descriptor: "raw(deadbeef)", checksum: "89f8spxm" },
} as const;

/** The 2-of-2 of G and 2G from agntn/keys#192; Core v31.1 `decodescript` gives these addresses. */
export const multisigVector = {
  keys: [
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
    "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
  ],
  script:
    "52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f817982102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee552ae",
  mainnet: {
    p2sh: "33RQmypKhD6f4tMquiR5a3C6dRT7eBpaiG",
    p2wsh: "bc1qnwvyc7aw8m7acw3lpgs0lqdlaz0drls8luf72cs5nmn9f0kcghdse7d78q",
    "p2sh-p2wsh": "3FN44kGaMLLdhxsFgedfBBzjwUtZNEA22T",
  },
  testnet: {
    p2sh: "2MtycqikMJfc1GfzPar2xBzBMqmfHSdGF9s",
    p2wsh: "tb1qnwvyc7aw8m7acw3lpgs0lqdlaz0drls8luf72cs5nmn9f0kcghdswkm3a0",
    "p2sh-p2wsh": "2N6vG8VCbxnqyukVoMnFXo8z19q6jCJiChQ",
  },
} as const;
