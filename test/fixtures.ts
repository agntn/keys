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
  seedWithPassphrase:
    "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
};

/** Public, claimed Bitcoin Movie Enigma solution: floflo777/open-crypto-puzzles#24. */
export const invalidChecksumPuzzle = {
  mnemonic:
    "path mad alien apology escape spare miss goddess leopard crime visit clock start first blade guard close barrel term screen matrix toy ghost shine",
  path: "m/84'/0'/0'/0/0",
  address: "bc1q94ecsn0qk8lap2gefrycnms3ruepy889z969a6",
  publicKey: "022c17f7486b4107b42a243a62e4d0919af3e8ee858a272319bffb0536486b9405",
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
