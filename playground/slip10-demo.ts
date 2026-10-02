import { getMasterKeyFromSeed, deriveHDKey } from "../src/utils/slip10";
import { hex } from "@agntn/encodings/hex";

// Use a static seed for reproducible results
const testSeed = hex.decode("000102030405060708090a0b0c0d0e0f");

// Create master key from seed
console.log("1. Creating master key from seed");
const masterKey = getMasterKeyFromSeed(testSeed);
console.log(`Master private key: ${Buffer.from(masterKey.privateKey).toString("hex")}`);
console.log(`Master public key: ${Buffer.from(masterKey.publicKeyRaw).toString("hex")}`);
console.log(`Master chain code: ${Buffer.from(masterKey.chainCode).toString("hex")}`);

// Derive BIP44-style wallet for Solana (m/44'/501'/0'/0')
console.log("\n2. Deriving BIP44 path for Solana");
const solanaPath = "m/44'/501'/0'/0'";
const solanaKey = deriveHDKey(masterKey, solanaPath);
console.log(`Path: ${solanaPath}`);
console.log(`Private key: ${Buffer.from(solanaKey.privateKey).toString("hex")}`);
console.log(`Public key: ${Buffer.from(solanaKey.publicKeyRaw).toString("hex")}`);

// Derive BIP44-style wallet for Cardano (m/1852'/1815'/0'/0/0)
console.log("\n3. Deriving BIP44 path for Cardano");
const cardanoPath = "m/1852'/1815'/0'/0/0";
try {
  const cardanoKey = deriveHDKey(masterKey, cardanoPath);
  console.log(`Path: ${cardanoPath}`);
  console.log(`Private key: ${Buffer.from(cardanoKey.privateKey).toString("hex")}`);
  console.log(`Public key: ${Buffer.from(cardanoKey.publicKeyRaw).toString("hex")}`);
} catch {
  console.log(
    `Note: ${cardanoPath} fails because the last indices are non-hardened and SLIP-0010 requires hardened derivation for ed25519`,
  );

  // With force hardened = true
  const cardanoHardenedPath = "m/1852'/1815'/0'/0'/0'";
  const cardanoKey = deriveHDKey(masterKey, cardanoHardenedPath);
  console.log(`Using hardened path instead: ${cardanoHardenedPath}`);
  console.log(`Private key: ${Buffer.from(cardanoKey.privateKey).toString("hex")}`);
  console.log(`Public key: ${Buffer.from(cardanoKey.publicKeyRaw).toString("hex")}`);
}

// Derive multiple accounts
console.log("\n4. Deriving multiple accounts from same HD wallet");
const accountBase = "m/44'/501'/";
for (let i = 0; i < 3; i++) {
  const accountPath = `${accountBase}${i}'/0'`;
  const accountKey = deriveHDKey(masterKey, accountPath);
  console.log(`Account ${i} (${accountPath}):`);
  console.log(`  Private key: ${Buffer.from(accountKey.privateKey).toString("hex")}`);
}

// Demonstrate hardened derivation requirement
console.log("\n5. SLIP-0010 Ed25519 Hardened Derivation Requirements");
const parentKey = deriveHDKey(masterKey, "m/44'/501'");

try {
  // This will fail because we're trying non-hardened derivation
  const nonHardenedChild = deriveHDKey(parentKey, "m/44'/501'/0", false);
  console.log(
    `Non-hardened derivation succeeded (unexpected): ${Buffer.from(nonHardenedChild.publicKeyRaw).toString("hex")}`,
  );
} catch {
  console.log(
    "Non-hardened derivation failed as expected: ed25519 curve in SLIP-0010 requires hardened derivation",
  );

  // This will work because we force hardened
  const forcedHardenedChild = deriveHDKey(parentKey, "m/44'/501'/0", true);
  console.log(
    `Forced hardened derivation succeeds: ${Buffer.from(forcedHardenedChild.publicKeyRaw).toString("hex")}`,
  );
}

// Compare with BIP32 (if used for Solana, which is incorrect)
console.log("\n6. Comparison with other derivation paths");
console.log(`Solana: m/44'/501'/0'/0'`);
console.log(`Aptos: m/44'/637'/0'/0'/0'`);
console.log(`Sui: m/44'/784'/0'/0'/0'`);

console.log(
  "\nNote: This is a demonstration only. In a real application, use the complete blockchain implementations.",
);
console.log("Remember: SLIP-0010 with ed25519 requires all derivation indices to be hardened.");
