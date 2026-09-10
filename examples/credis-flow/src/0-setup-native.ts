/**
 * 0-setup-native.ts
 *
 * Ensures user and CCA have sufficient native (COEN) balances.
 *
 *   1. Ensure user has native balance (funds gas + the EntryPoint deposit step 5 needs)
 *   2. Ensure CCA has native balance (gas, its EntryPoint deposit, and the COEN stake
 *      requestCredis now takes - see CCA_MIN_NATIVE)
 *
 * Usage: npx tsx src/0-setup-native.ts [envName]
 */

import { ethers, Wallet } from "ethers";
import { coen, formatCoen, DEFAULT_ENV, loadEnv, requireEnv } from "./utils.js";

// `requestCredis` is payable and takes a stake equal to the pledged collateral, so
// the CCA needs COEN proportional to the credit it originates - at the seeded
// COEN/USD rate a 1-stable pledge costs 1 COEN - plus gas and its EntryPoint
// deposit. 50 COEN covers the documented pledges with headroom and stays far under
// the ~10,000 COEN a genesis account is prefunded with.
const CCA_MIN_NATIVE = coen("50");
const USER_FUND_NATIVE = coen("100");

const envName = process.argv[2] || DEFAULT_ENV;
const { envPath } = loadEnv(import.meta.url, envName, { deploymentEnv: true });

const rpcUrl = requireEnv("RPC_URL", envPath);
const ownerPrivateKey = requireEnv("PRIVATE_KEY", envPath);
const userAddress = requireEnv("USER_ADDRESS", envPath);
const ccaAddress = requireEnv("CCA_ADDRESS", envPath);

async function main() {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const ownerWallet = new Wallet(ownerPrivateKey, provider);

  console.log("=== Setup Native ===");
  console.log(`Env:   ${envName}`);
  console.log(`RPC:   ${rpcUrl}`);
  console.log(`Owner: ${ownerWallet.address}`);
  console.log(`User:  ${userAddress}`);
  console.log(`CCA:   ${ccaAddress}`);

  // -- Step 1: Ensure user has native balance --------------------------------

  console.log("\n[1] Checking user native balance...");
  const userNative = await provider.getBalance(userAddress);
  console.log(`    Current: ${formatCoen(userNative)} COEN`);

  if (userNative < USER_FUND_NATIVE) {
    const tx = await ownerWallet.sendTransaction({ to: userAddress, value: USER_FUND_NATIVE });
    await tx.wait();
    console.log(`    Funded user with ${formatCoen(USER_FUND_NATIVE)} COEN (tx: ${tx.hash})`);
  } else {
    console.log("    Sufficient - skipping");
  }

  // -- Step 2: Ensure CCA has native balance ---------------------------------

  console.log("\n[2] Checking CCA native balance...");
  const ccaNative = await provider.getBalance(ccaAddress);
  console.log(`    Current: ${formatCoen(ccaNative)} COEN`);

  if (ccaNative < CCA_MIN_NATIVE) {
    const tx = await ownerWallet.sendTransaction({ to: ccaAddress, value: CCA_MIN_NATIVE });
    await tx.wait();
    console.log(`    Funded CCA with ${formatCoen(CCA_MIN_NATIVE)} COEN (tx: ${tx.hash})`);
  } else {
    console.log("    Sufficient - skipping");
  }

  console.log("\n=== Setup Native complete ===");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
