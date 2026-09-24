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
  messageHashes: [
    ["hello", "51bd869e89676860cf1d778b8735f5e6768da32023d3dcd951711bd21c669d4c"],
    ["é".repeat(127), "08bebd99b9d1fbd73231de22e544e9b0b75c0c54ab6e3128f53665cdf944477f"],
  ],
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
 * Public WIF interoperability vectors.
 * @see https://github.com/bitcoinjs/wif/blob/master/test/fixtures.json
 * @see https://github.com/litecoin-project/litecoin/blob/master/src/test/data/key_io_valid.json
 * @see https://github.com/decred/dcrd/blob/master/dcrutil/wif_test.go
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

/** SEC 2 v2 section 2.4.1: secp256k1 generator G, in SEC1 encodings. */
export const publicKeyEncodingVector = {
  compressed: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
  uncompressed:
    "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" +
    "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
};

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
