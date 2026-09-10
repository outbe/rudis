/**
 * 2-top-up-smart-account.ts
 *
 * Runs on behalf of the user to:
 *   1. Check if a smart account exists, create if not
 *   2. Transfer 1000 ERC20 tokens from user EOA to the smart account
 *
 * Prerequisites:
 *   - Run 0-setup.ts first to ensure balances
 *   - .{envName}.env and .{envName}.deployment.env populated
 *
 * Usage: npx tsx src/2-top-up-smart-account.ts [envName]
 */

import { ethers, Wallet } from "ethers";
import { IERC20__factory, SmartAccountFactory__factory } from "./contracts/index.js";
import { DEFAULT_ENV, formatToken, fetchTokenMeta, loadEnv, requireEnv } from "./utils.js";

const SALT = 0n;
const TRANSFER_AMOUNT = 1_000_000_000n;       // 1,000 tokens (6 decimals)

// Parse CLI args: [envName]
const envName = process.argv[2] || DEFAULT_ENV;

// Load env files
const { envPath } = loadEnv(import.meta.url, envName, { deploymentEnv: true });

const rpcUrl = requireEnv("RPC_URL", envPath);
const userPrivateKey = requireEnv("USER_PRIVATE_KEY", envPath);
const ccaAddress = requireEnv("CCA_ADDRESS", envPath);
const smartAccountFactoryAddress = requireEnv("SMART_ACCOUNT_FACTORY_ADDRESS", envPath);
const erc20Address = requireEnv("ERC20_ADDRESS", envPath);
const vaultRouterAddress = requireEnv("VAULT_ROUTER_ADDRESS", envPath);

async function main(): Promise<void> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const userWallet = new Wallet(userPrivateKey, provider);
  const userAddr = userWallet.address;

  const factory = SmartAccountFactory__factory.connect(smartAccountFactoryAddress, userWallet);
  const token = IERC20__factory.connect(erc20Address, userWallet);

  // Fetch token metadata
  const { decimals: tokenDecimals, symbol: tokenSymbol } = await fetchTokenMeta(token);

  console.log("=== Top-Up smart account ===");
  console.log(`Env:     ${envName}`);
  console.log(`User     : ${userAddr}`);
  console.log(`CCA      : ${ccaAddress}`);
  console.log(`Token    : ${erc20Address} (${tokenSymbol}, ${tokenDecimals} decimals)`);
  console.log(`Factory  : ${smartAccountFactoryAddress}`);

  // -- Step 1: Predict smart account address ---------------------------------

  console.log("\n[1] Predicting smart account address...");
  const accountAddr = await factory.getAccountAddress(userAddr, ccaAddress, [erc20Address], [vaultRouterAddress], SALT);
  console.log(`    -> ${accountAddr}`);

  // -- Step 2: Deploy if not exists ------------------------------------------

  console.log("\n[2] Checking if account exists...");
  const code = await provider.getCode(accountAddr);
  if (code === "0x") {
    console.log("    Account not deployed - creating...");
    const tx = await factory.createAccount(userAddr, ccaAddress, [erc20Address], [vaultRouterAddress], SALT);
    const receipt = await tx.wait();
    console.log(`    Deployed at block ${receipt!.blockNumber}, tx: ${tx.hash}`);
  } else {
    console.log("    Already deployed - skipping");
  }

  // -- Step 3: Transfer ERC20 to smart account ------------------------------

  console.log("\n[3] Checking smart account ERC20 balance...");
  const accountBal = await token.balanceOf(accountAddr);

  if (accountBal < TRANSFER_AMOUNT) {
    const tx = await token.transfer(accountAddr, TRANSFER_AMOUNT);
    await tx.wait();
    const newBal = await token.balanceOf(accountAddr);
    console.log(`    TopUp ${formatToken(TRANSFER_AMOUNT, tokenDecimals, tokenSymbol)} -> account balance: ${formatToken(newBal, tokenDecimals, tokenSymbol)}`);
  } else {
    console.log(`    Balance sufficient (${formatToken(accountBal, tokenDecimals, tokenSymbol)}) - skipping transfer`);
  }

  console.log("\n[OK] Done");
}

main().catch((err: unknown) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
