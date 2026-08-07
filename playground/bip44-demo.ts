import { useBlockchain, BIP44Change, getBlockchainPath } from "../src";
import Bitcoin from "../src/blockchains/bitcoin";
import Ethereum from "../src/blockchains/ethereum";
import Solana from "../src/blockchains/solana";
import Cardano from "../src/blockchains/cardano";
import Tron from "../src/blockchains/tron";
import Aptos from "../src/blockchains/aptos";
import Sui from "../src/blockchains/sui";
import Base from "../src/blockchains/base";

import { mnemonicToSeed } from "../src/utils/bip39";
import {
  getMasterKeyFromSeed as bip32MasterKey,
  deriveHDKey as bip32Derive,
} from "../src/utils/bip32";
import {
  getMasterKeyFromSeed as slip10MasterKey,
  deriveHDKey as slip10Derive,
} from "../src/utils/slip10";

// Create blockchain instances
const chains = [
  useBlockchain(new Bitcoin()),
  useBlockchain(new Ethereum()),
  useBlockchain(new Solana()),
  useBlockchain(new Cardano()),
  useBlockchain(new Tron()),
  useBlockchain(new Aptos()),
  useBlockchain(new Sui()),
  useBlockchain(new Base()),
];

// Display BIP44 codes for each blockchain
console.log("BIP44 Coin Types:");
for (const chain of chains) {
  console.log(`${chain.name}: ${chain.bip44}`);
}

// Generate BIP44 paths for different blockchains
console.log("\nBIP44 Derivation Paths:");
for (const chain of chains) {
  const path = getBlockchainPath(chain);
  console.log(`${chain.name}: ${path}`);
}

// Create paths with different accounts and address indexes
console.log("\nBIP44 Paths for Bitcoin with different accounts:");
for (let account = 0; account < 3; account++) {
  const path = getBlockchainPath(chains[0], account);
  console.log(`Account ${account}: ${path}`);
}

// Demonstrate change addresses (external vs internal)
console.log("\nBIP44 Paths for Ethereum with external/internal chains:");
const externalPath = getBlockchainPath(chains[1], 0, BIP44Change.EXTERNAL);
const internalPath = getBlockchainPath(chains[1], 0, BIP44Change.INTERNAL);
console.log(`External (receiving): ${externalPath}`);
console.log(`Internal (change): ${internalPath}`);

// Generate multiple address indexes
console.log("\nBIP44 Paths for Solana with multiple address indexes:");
for (let index = 0; index < 5; index++) {
  const path = getBlockchainPath(chains[2], 0, BIP44Change.EXTERNAL, index);
  console.log(`Address index ${index}: ${path}`);
}

// Demo with a test mnemonic and deriving keys across multiple chains
const testMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const testSeed = mnemonicToSeed(testMnemonic);

// Generate the master keys
const bipMasterKey = bip32MasterKey(testSeed);
const slipMasterKey = slip10MasterKey(testSeed);

console.log("\nMulti-chain wallet from single seed:");

// Derive keys for each blockchain
for (const chain of chains) {
  const path = getBlockchainPath(chain);
  if (!path) {
    console.log(`${chain.name}: Path derivation not supported`);
    continue;
  }

  try {
    // Use BIP32 for secp256k1 chains and SLIP-10 for ed25519 chains
    const key =
      chain.curve === "secp256k1" ||
      (Array.isArray(chain.curve) && chain.curve.includes("secp256k1"))
        ? bip32Derive(bipMasterKey, path)
        : slip10Derive(slipMasterKey, path, true);

    const privateKey = Buffer.from(
      chain.curve === "secp256k1" ||
        (Array.isArray(chain.curve) && chain.curve.includes("secp256k1"))
        ? key.privateKey!
        : key.privateKey,
    ).toString("hex");

    console.log(`${chain.name} (${path}): ${privateKey}`);
  } catch (error) {
    console.log(`${chain.name}: Error deriving key - ${error.message}`);
  }
}
