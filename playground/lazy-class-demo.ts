import { useBlockchain, blockchains } from "../src";

console.log("Lazy class demo: imports and constructs each concrete class only when needed");

// Bitcoin
console.log("\n--- Bitcoin ---");
const bitcoin = await blockchains.bitcoin()();
const btcBlockchain = useBlockchain(bitcoin);

const btcWallet = btcBlockchain.generateWallet();
console.log("Bitcoin address:", btcWallet.address);

// Ethereum
console.log("\n--- Ethereum ---");
const ethereum = await blockchains.ethereum()();
const ethBlockchain = useBlockchain(ethereum);

const ethWallet = ethBlockchain.generateWallet();
console.log("Ethereum address:", ethWallet.address);

// With options
console.log("\n--- Bitcoin Testnet ---");
const testnet = await blockchains.bitcoin({ network: "testnet" })();
const testnetBlockchain = useBlockchain(testnet);

const testnetWallet = testnetBlockchain.generateWallet();
console.log("Bitcoin testnet address:", testnetWallet.address);

// Solana
console.log("\n--- Solana ---");
const solana = await blockchains.solana()();
const solanaBlockchain = useBlockchain(solana);

const solanaWallet = solanaBlockchain.generateWallet();
console.log("Solana address:", solanaWallet.address);
