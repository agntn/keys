import { webcrypto } from "node:crypto";
import { bytesToHex } from "@noble/hashes/utils.js";
import { useBlockchain } from "../src/blockchain";

// Dynamiczne importy blockchainów
const ethereumImport = await import("../src/blockchains/ethereum");
const solanaImport = await import("../src/blockchains/solana");

const Ethereum = ethereumImport.default;
const Solana = solanaImport.default;

// Generate random private keys
function generateRandomKeyPrivate(): string {
  const keyPrivateBytes = webcrypto.getRandomValues(new Uint8Array(32));
  return bytesToHex(keyPrivateBytes);
}

// Demo dla podpisów Ethereum (EVM)
console.log("--- Ethereum Signing Demo ---");
const ethBlockchain = useBlockchain(new Ethereum());
const ethWallet = ethBlockchain.generateWallet({
  compressed: false, // Ethereum uses uncompressed public keys
});

console.log(`Generated Ethereum wallet:`);
console.log(`Address: ${ethWallet.address}`);
console.log(`Public key: ${ethWallet.keys.public}`);
console.log(`Private key: ${ethWallet.keys.private}`);

// Podpisanie wiadomości
const ethMessage = "Hello Ethereum World!";
console.log(`\nSigning message: "${ethMessage}"`);
const ethSignature = ethBlockchain.signMessage(ethMessage, ethWallet.keys.private);
console.log(`Signature: ${ethSignature}`);

// Weryfikacja podpisu
const ethValid = ethBlockchain.verifyMessage(ethMessage, ethSignature, ethWallet.keys.public);
console.log(`Verification result: ${ethValid ? "Valid ✓" : "Invalid ✗"}`);

// Test negatywny (zły klucz publiczny)
const ethRandomPubkey = ethBlockchain.getKeyPublic(generateRandomKeyPrivate());
const ethInvalid = ethBlockchain.verifyMessage(ethMessage, ethSignature, ethRandomPubkey);
console.log(`Verification with wrong key: ${ethInvalid ? "Valid (error!)" : "Invalid ✓"}`);

// Demo dla podpisów Solana (Ed25519)
console.log("\n\n--- Solana Signing Demo ---");
const solBlockchain = useBlockchain(new Solana());
const solWallet = solBlockchain.generateWallet();

console.log(`Generated Solana wallet:`);
console.log(`Address: ${solWallet.address}`);
console.log(`Public key: ${solWallet.keys.public}`);
console.log(`Private key: ${solWallet.keys.private}`);

// Podpisanie wiadomości
const solMessage = "Hello Solana World!";
console.log(`\nSigning message: "${solMessage}"`);
const solSignature = solBlockchain.signMessage(solMessage, solWallet.keys.private);
console.log(`Signature: ${solSignature}`);

// Weryfikacja podpisu
const solValid = solBlockchain.verifyMessage(solMessage, solSignature, solWallet.keys.public);
console.log(`Verification result: ${solValid ? "Valid ✓" : "Invalid ✗"}`);

// Test negatywny (zła wiadomość)
const solInvalid = solBlockchain.verifyMessage(
  "Different message",
  solSignature,
  solWallet.keys.public,
);
console.log(`Verification with wrong message: ${solInvalid ? "Valid (error!)" : "Invalid ✓"}`);

// Różnice między podpisami EVM i Ed25519
console.log("\n\n--- Comparing Signatures ---");
console.log(`Ethereum signature length: ${ethSignature.length} chars`);
console.log(`Solana signature length: ${solSignature.length} chars`);
console.log("\nEthereum uses secp256k1 with specialized preamble for message signing");
console.log("Solana uses pure Ed25519 signatures");
