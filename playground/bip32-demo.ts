import {
  HDKey,
  getMasterKeyFromSeed,
  deriveHDKey,
  formatIndex,
  HARDENED_OFFSET,
} from "../src/utils/bip32";
import { sha256 } from "@agntn/hashes";
import { hex } from "@agntn/encodings/hex";

// Commented out but kept for reference
// Generate a seed from random bytes
// const getRandomSeed = (): Uint8Array => {
//   // In production, use a secure random source
//   const randomBytes = new Uint8Array(32);
//   crypto.getRandomValues(randomBytes);
//   return randomBytes;
// };

// Use a static seed for reproducible results in this example
const testSeed = hex.decode("000102030405060708090a0b0c0d0e0f");

// Create master key from seed
console.log("1. Creating master key from seed");
const masterKey = getMasterKeyFromSeed(testSeed);
console.log(`Master private key: ${masterKey.privateExtendedKey}`);
console.log(`Master public key: ${masterKey.publicExtendedKey}`);

// Derive BIP44-style wallet for Bitcoin (m/44'/0'/0'/0/0)
console.log("\n2. Deriving BIP44 path for Bitcoin");
const bitcoinPath = "m/44'/0'/0'/0/0";
const bitcoinKey = deriveHDKey(masterKey, bitcoinPath);
console.log(`Path: ${bitcoinPath}`);
console.log(`Private key: ${Buffer.from(bitcoinKey.privateKey!).toString("hex")}`);
console.log(`Public key: ${Buffer.from(bitcoinKey.publicKey!).toString("hex")}`);

// Derive BIP44-style wallet for Ethereum (m/44'/60'/0'/0/0)
console.log("\n3. Deriving BIP44 path for Ethereum");
const ethPath = "m/44'/60'/0'/0/0";
const ethKey = deriveHDKey(masterKey, ethPath);
console.log(`Path: ${ethPath}`);
console.log(`Private key: ${Buffer.from(ethKey.privateKey!).toString("hex")}`);
console.log(`Public key: ${Buffer.from(ethKey.publicKey!).toString("hex")}`);

// Derive multiple accounts
console.log("\n4. Deriving multiple accounts from same HD wallet");
const accountBase = "m/44'/0'/";
for (let i = 0; i < 3; i++) {
  const accountPath = `${accountBase}${i}'/0/0`;
  const accountKey = deriveHDKey(masterKey, accountPath);
  console.log(`Account ${i} (${accountPath}):`);
  console.log(`  Private key: ${Buffer.from(accountKey.privateKey!).toString("hex")}`);
}

// Show extended keys that can be imported into wallets
console.log("\n5. Extended keys for Bitcoin account");
const btcAccount = deriveHDKey(masterKey, "m/44'/0'/0'");
console.log(`Extended private key: ${btcAccount.privateExtendedKey}`);
console.log(`Extended public key: ${btcAccount.publicExtendedKey}`);

// Demonstrate hardened vs non-hardened derivation
console.log("\n6. Hardened vs Non-hardened derivation");
const parentKey = deriveHDKey(masterKey, "m/44'/0'");

// Hardened derivation - requires private key
const hardenedChild = deriveHDKey(parentKey, `m/44'/0'/0'`);
console.log(
  `Hardened key (index ${formatIndex(HARDENED_OFFSET)}): ${hardenedChild.publicExtendedKey}`,
);

// Non-hardened derivation - can use public key only
console.log(
  `Non-hardened key (index 0): ${deriveHDKey(parentKey, `m/44'/0'/0/0`).publicExtendedKey}`,
);

// Demonstrate watch-only wallet (public derivation)
console.log("\n7. Watch-only wallet with xpub");
const xpub = btcAccount.publicExtendedKey;
const watchOnlyKey = HDKey.fromExtendedKey(xpub);
console.log(`Master xpub: ${xpub}`);

// Can only derive non-hardened child keys from xpub
for (let i = 0; i < 3; i++) {
  const childKey = deriveHDKey(watchOnlyKey, `m/0/${i}`);
  const address = sha256(childKey.publicKey!).slice(0, 20); // Simplified address derivation for demo
  console.log(`Address ${i}: ${Buffer.from(address).toString("hex")}`);
}

console.log(
  "\nNote: This is a demonstration only. In a real application, use complete blockchain implementations.",
);
