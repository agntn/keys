import { describe, it, expect } from "vitest";
import { Keypair } from "@solana/web3.js";
import { SigningKey, Wallet } from "ethers";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { useBlockchain } from "../../src/blockchain";
import Ethereum from "../../src/blockchains/ethereum";
import Solana from "../../src/blockchains/solana";
import { ed25519 } from "@noble/curves/ed25519.js";
import { secp256k1TestVectors, testMessages } from "../fixtures";

describe("Signing Integration Tests", () => {
  describe("Solana Signature Compatibility", () => {
    it("should generate compatible keys with @solana/web3.js", () => {
      // Generate keys using Solana Web3.js
      const solanaKeypair = Keypair.generate();
      const solanaSecretKey = solanaKeypair.secretKey;
      const solanaPrivateKeyHex = bytesToHex(solanaSecretKey.slice(0, 32));
      const solanaPublicKeyHex = bytesToHex(solanaKeypair.publicKey.toBytes());
      const solanaBlockchain = useBlockchain(new Solana());
      const keysPublicKey = solanaBlockchain.getKeyPublic(solanaPrivateKeyHex);

      // Verify that public keys match
      expect(keysPublicKey).toBe(solanaPublicKeyHex);

      // Generate a new address
      const keysAddress = solanaBlockchain.getAddress(keysPublicKey);
      const solanaAddress = solanaKeypair.publicKey.toBase58();

      // Verify that addresses match
      expect(keysAddress).toBe(solanaAddress);

      // Print keys and addresses for confirmation
      console.log("\nSolana Keys:");
      console.log(`Private Key: ${solanaPrivateKeyHex}`);
      console.log(`Solana Public Key: ${solanaPublicKeyHex}`);
      console.log(`@agntn/keys Public Key: ${keysPublicKey}`);
      console.log(`Solana Address: ${solanaAddress}`);
      console.log(`@agntn/keys Address: ${keysAddress}`);
    });

    it("should produce valid signatures for Solana", () => {
      const solanaBlockchain = useBlockchain(new Solana());
      const keysWallet = solanaBlockchain.generateWallet();
      const message = testMessages.medium;
      const messageBytes = new TextEncoder().encode(message);
      const keysSignature = solanaBlockchain.signMessage(message, keysWallet.keys.private);
      const keysSignatureBytes = hexToBytes(keysSignature);

      // Verify signature using @noble/curves/ed25519 (the same library we use internally)
      const publicKeyBytes = hexToBytes(keysWallet.keys.public);

      // Verify using the library that we use internally
      const verificationResult = ed25519.verify(keysSignatureBytes, messageBytes, publicKeyBytes);

      // Sign message directly using the library
      const privateKeyBytes = hexToBytes(keysWallet.keys.private);
      const directSignature = ed25519.sign(messageBytes, privateKeyBytes);
      const directSignatureHex = bytesToHex(directSignature);

      // Display results
      console.log("\nSolana Signature Verification:");
      console.log(`Message: "${message}"`);
      console.log(`@agntn/keys Signature: ${keysSignature}`);
      console.log(`Direct Ed25519 Signature: ${directSignatureHex}`);
      console.log(`Noble Curves verification result: ${verificationResult}`);
      const keysVerificationOfDirect = solanaBlockchain.verifyMessage(
        message,
        directSignatureHex,
        keysWallet.keys.public,
      );

      console.log(`@agntn/keys verification of direct signature: ${keysVerificationOfDirect}`);

      // Check if verifications succeeded
      expect(verificationResult).toBe(true);
      expect(keysVerificationOfDirect).toBe(true);
      expect(keysSignature).toBe(directSignatureHex);
    });
  });

  describe("Ethereum Signature Compatibility", () => {
    it("should generate compatible keys with ethers.js", () => {
      // Create a private key with 0x prefix (required by ethers)
      const privateKeyHex = secp256k1TestVectors.privateKeyWith0x;

      // Create instances of both libraries
      const ethersSigningKey = new SigningKey(privateKeyHex);
      const ethereumBlockchain = useBlockchain(new Ethereum());

      // Get public keys
      const ethersPublicKey = ethersSigningKey.publicKey.slice(2); // remove '0x' prefix
      const keysPublicKey = ethereumBlockchain.getKeyPublic(privateKeyHex.slice(2), {
        compressed: false,
      });

      // Verify that public keys match (ethers returns without 0x)
      expect(keysPublicKey).toBe(ethersPublicKey);

      // Display information
      console.log("\nEthereum Keys:");
      console.log(`Private Key: ${privateKeyHex}`);
      console.log(`Ethers Public Key: ${ethersPublicKey}`);
      console.log(`@agntn/keys Public Key: ${keysPublicKey}`);
    });

    it("should verify messages between libraries", () => {
      // Use same private key for both libraries
      const privateKeyHex = secp256k1TestVectors.privateKeyWith0x;
      const privateKeyNoPrefix = privateKeyHex.slice(2);

      // Create Ethereum instance and derive keys from the same private key
      const ethereumBlockchain = useBlockchain(new Ethereum());
      const publicKey = ethereumBlockchain.getKeyPublic(privateKeyNoPrefix, { compressed: false });
      const keysAddress = ethereumBlockchain.getAddress(publicKey);

      // Create ethers.js wallet from same private key
      const ethersWallet = new Wallet(privateKeyHex);
      const ethersAddress = ethersWallet.address;

      // Addresses MUST match
      expect(keysAddress.toLowerCase()).toBe(ethersAddress.toLowerCase());

      console.log("\nEthereum Addresses:");
      console.log(`@agntn/keys: ${keysAddress}`);
      console.log(`Ethers: ${ethersAddress}`);

      // Message to sign
      const message = testMessages.medium;
      const keysSignature = ethereumBlockchain.signMessage(message, privateKeyNoPrefix);
      const keysVerified = ethereumBlockchain.verifyMessage(message, keysSignature, publicKey);

      console.log("\nEthereum Signatures:");
      console.log(`Message: "${message}"`);
      console.log(`@agntn/keys Signature: ${keysSignature}`);
      console.log(`Verification result: ${keysVerified}`);

      // Check if verification succeeded
      expect(keysVerified).toBe(true);
    });
  });
});
