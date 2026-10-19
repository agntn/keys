import { generateMnemonic, validateMnemonic, mnemonicToSeed } from "../src/utils/bip39";
import {
  getMasterKeyFromSeed as bip32MasterKey,
  deriveHDKey as bip32Derive,
} from "../src/utils/bip32";
import {
  getMasterKeyFromSeed as slip10MasterKey,
  deriveHDKey as slip10Derive,
} from "../src/utils/slip10";

// 1. Generate a new random mnemonic (default 128 bits, 12 words)
console.log("1. Generating a new random mnemonic:");
const mnemonic = generateMnemonic();
console.log(mnemonic);
console.log(`Mnemonic is valid: ${validateMnemonic(mnemonic)}`);

// 2. Generate a stronger mnemonic (256 bits, 24 words)
console.log("\n2. Generating a stronger mnemonic (256 bits):");
const strongMnemonic = generateMnemonic(256);
console.log(strongMnemonic);

// 3. Convert mnemonic to seed (no password)
console.log("\n3. Converting mnemonic to seed:");
const seed = mnemonicToSeed(mnemonic);
console.log(`Seed: ${Buffer.from(seed).toString("hex")}`);

// 4. Convert mnemonic to seed (with password)
console.log("\n4. Converting mnemonic to seed with password:");
const seedWithPassword = mnemonicToSeed(mnemonic, { passphrase: "my secure passphrase" });
console.log(`Seed with password: ${Buffer.from(seedWithPassword).toString("hex")}`);

// 5. Create BIP32 master key from seed
console.log("\n5. Creating BIP32 master key from seed:");
const bip32Master = bip32MasterKey(seed);
console.log(`Master extended private key: ${bip32Master.privateExtendedKey}`);

// 6. Derive BIP32 keys for Bitcoin
console.log("\n6. Deriving Bitcoin wallet:");
const bitcoinKey = bip32Derive(bip32Master, "m/84'/0'/0'/0/0");
console.log(`Bitcoin private key: ${Buffer.from(bitcoinKey.privateKey!).toString("hex")}`);

// 7. Create SLIP-10 master key from same seed
console.log("\n7. Creating SLIP-10 master key from same seed:");
const slip10Master = slip10MasterKey(seed);
console.log(`SLIP-10 master private key: ${Buffer.from(slip10Master.privateKey).toString("hex")}`);

// 8. Derive SLIP-10 keys for Solana
console.log("\n8. Deriving Solana wallet:");
const solanaKey = slip10Derive(slip10Master, { path: "m/44'/501'/0'/0'" });
console.log(`Solana private key: ${Buffer.from(solanaKey.privateKey).toString("hex")}`);

// 9. Complete wallet generation workflow example
console.log("\n9. Complete wallet generation workflow:");
console.log(
  "Mnemonic: abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
);
const testMnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const testSeed = mnemonicToSeed(testMnemonic);
console.log(`Seed: ${Buffer.from(testSeed).toString("hex")}`);

// Generate wallets for multiple chains from the same mnemonic
const chains = [
  { name: "Bitcoin", path: "m/84'/0'/0'/0/0", method: "bip32" },
  { name: "Ethereum", path: "m/44'/60'/0'/0/0", method: "bip32" },
  { name: "Solana", path: "m/44'/501'/0'/0'", method: "slip10" },
  { name: "Cardano", path: "m/1852'/1815'/0'/0'/0'", method: "slip10" },
];

console.log("\n10. Multi-chain wallet from single mnemonic:");
const bipMasterKey = bip32MasterKey(testSeed);
const slipMasterKey = slip10MasterKey(testSeed);

for (const chain of chains) {
  const key =
    chain.method === "bip32"
      ? bip32Derive(bipMasterKey, chain.path)
      : slip10Derive(slipMasterKey, { path: chain.path });

  const privateKey = Buffer.from(
    chain.method === "bip32" ? key.privateKey! : key.privateKey,
  ).toString("hex");

  console.log(`${chain.name} (${chain.path}): ${privateKey}`);
}
