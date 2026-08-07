import { useBlockchain, blockchains } from "../src";

console.log("Lazy class demo: only imports the implementation when needed");

// Bitcoin
console.log("\n--- Bitcoin ---");
const bitcoinImpl = await blockchains.bitcoin()();
const btcBlockchain = useBlockchain(bitcoinImpl);

const btcWallet = btcBlockchain.generateWallet();
console.log("Bitcoin address:", btcWallet.address);

// Ethereum
console.log("\n--- Ethereum ---");
const ethereumImpl = await blockchains.ethereum()();
const ethBlockchain = useBlockchain(ethereumImpl);

const ethWallet = ethBlockchain.generateWallet();
console.log("Ethereum address:", ethWallet.address);

// With options
console.log("\n--- Bitcoin Testnet ---");
const testnetImpl = await blockchains.bitcoin({ network: "testnet" })();
const testnetBlockchain = useBlockchain(testnetImpl);

const testnetWallet = testnetBlockchain.generateWallet();
console.log("Bitcoin testnet address:", testnetWallet.address);

// Solana
console.log("\n--- Solana ---");
const solanaImpl = await blockchains.solana()();
const solanaBlockchain = useBlockchain(solanaImpl);

const solanaWallet = solanaBlockchain.generateWallet();
console.log("Solana address:", solanaWallet.address);
