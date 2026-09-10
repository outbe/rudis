/**
 * 0-setup-erc20.ts
 *
 * Ensures user and vault have sufficient ERC20 balances using a dedicated
 * holder wallet (ERC20_HOLDER_PRIVATE_KEY) as the source of distributed tokens.
 * The owner (PRIVATE_KEY) mints fresh tokens to the holder only when the
 * holder's balance is insufficient to cover the deficits.
 *
 *   1. Compute user + vault deficits (targets: 1,000 / 10,000 tokens)
 *   2. Ensure holder has enough tokens (mint via owner if short)
 *   3. Transfer to user (from holder) if user deficit > 0
 *   4. Deposit to vault (from holder) if vault deficit > 0
 *
 * Usage: npx tsx src/0-setup-erc20.ts [envName]
 */

import { ethers, Wallet } from "ethers";
import { IERC20__factory, IVaultRouter__factory } from "./contracts/index.js";
import { DEFAULT_ENV, formatToken, fetchTokenMeta, loadEnv, requireEnv } from "./utils.js";

const USER_TARGET = 1_000_000_000n;    // 1,000 tokens (6 decimals)
const VAULT_TARGET = 10_000_000_000n;  // 10,000 tokens (6 decimals)
const INBOUND_FLOW = 3;                 // CredisCostAmount

const envName = process.argv[2] || DEFAULT_ENV;
const { envPath } = loadEnv(import.meta.url, envName, { deploymentEnv: true });

const rpcUrl = requireEnv("RPC_URL", envPath);
const ownerPrivateKey = requireEnv("PRIVATE_KEY", envPath);
const holderPrivateKey = requireEnv("ERC20_HOLDER_PRIVATE_KEY", envPath);
// Optional: the VaultRouter owner may be a third key, distinct from owner/holder.
const vaultRouterPrivateKey = process.env.VAULT_ROUTER_PRIVATE_KEY;
const userAddress = requireEnv("USER_ADDRESS", envPath);
const erc20Address = requireEnv("ERC20_ADDRESS", envPath);
const vaultRouterAddress = requireEnv("VAULT_ROUTER_ADDRESS", envPath);

async function main() {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const ownerWallet = new Wallet(ownerPrivateKey, provider);
  const holderWallet = new Wallet(holderPrivateKey, provider);
  const vaultRouterWallet = vaultRouterPrivateKey ? new Wallet(vaultRouterPrivateKey, provider) : undefined;

  const tokenAsOwner = IERC20__factory.connect(erc20Address, ownerWallet);
  const tokenAsHolder = IERC20__factory.connect(erc20Address, holderWallet);
  // MockUSD-specific mint() is outside the IERC20 surface; bind it inline so the
  // setup flow can still top up the holder against a mintable test token.
  const mintableToken = new ethers.Contract(
    erc20Address,
    ["function mint(address to, uint256 amount)"],
    ownerWallet,
  );
  const vaultRouterAsOwner = IVaultRouter__factory.connect(vaultRouterAddress, ownerWallet);
  const vaultRouterAsHolder = IVaultRouter__factory.connect(vaultRouterAddress, holderWallet);

  const { decimals: tokenDecimals, symbol: tokenSymbol } = await fetchTokenMeta(tokenAsOwner);
  const fmt = (v: bigint) => formatToken(v, tokenDecimals, tokenSymbol);

  console.log("=== Setup ERC20 ===");
  console.log(`Env:            ${envName}`);
  console.log(`RPC:            ${rpcUrl}`);
  console.log(`Owner:          ${ownerWallet.address}`);
  console.log(`Holder:         ${holderWallet.address}`);
  console.log(`User:           ${userAddress}`);
  console.log(`ERC20:          ${erc20Address} (${tokenSymbol}, ${tokenDecimals} decimals)`);
  console.log(`Vault Router: ${vaultRouterAddress}`);

  // -- Step 1: Compute deficits ----------------------------------------------

  console.log("\n[1] Computing deficits...");
  const userBalance = await tokenAsOwner.balanceOf(userAddress);
  const underlyingVaultAddr = await vaultRouterAsOwner.assetVaultAt(erc20Address, 0);
  const vaultBalance = await tokenAsOwner.balanceOf(underlyingVaultAddr);

  const userDeficit = userBalance >= USER_TARGET ? 0n : USER_TARGET - userBalance;
  const vaultDeficit = vaultBalance >= VAULT_TARGET ? 0n : VAULT_TARGET - vaultBalance;
  const totalNeeded = userDeficit + vaultDeficit;

  console.log(`    User balance:  ${fmt(userBalance)} (target ${fmt(USER_TARGET)})`);
  console.log(`    Vault balance: ${fmt(vaultBalance)} (target ${fmt(VAULT_TARGET)})`);
  console.log(`    User deficit:  ${fmt(userDeficit)}`);
  console.log(`    Vault deficit: ${fmt(vaultDeficit)}`);

  if (totalNeeded === 0n) {
    console.log("\nSufficient - skipping");
    console.log("\n=== Setup ERC20 complete ===");
    return;
  }

  // -- Step 2: Ensure holder has enough tokens -------------------------------

  console.log("\n[2] Checking holder ERC20 balance...");
  const holderBalance = await tokenAsOwner.balanceOf(holderWallet.address);
  console.log(`    Current: ${fmt(holderBalance)}`);

  if (holderBalance < totalNeeded) {
    const mintAmount = totalNeeded - holderBalance;
    const tx = await mintableToken.mint(holderWallet.address, mintAmount);
    await tx.wait();
    const newBal = await tokenAsOwner.balanceOf(holderWallet.address);
    console.log(`    Minted ${fmt(mintAmount)} -> holder balance: ${fmt(newBal)}`);
  } else {
    console.log("    Sufficient - skipping mint");
  }

  // -- Step 3: Transfer to user ----------------------------------------------

  if (userDeficit > 0n) {
    console.log("\n[3] Transferring to user...");
    const tx = await tokenAsHolder.transfer(userAddress, userDeficit);
    await tx.wait();
    const newBal = await tokenAsOwner.balanceOf(userAddress);
    console.log(`    Sent ${fmt(userDeficit)} -> user balance: ${fmt(newBal)}`);
  } else {
    console.log("\n[3] User balance sufficient - skipping transfer");
  }

  // -- Step 4: Deposit to vault ----------------------------------------------

  if (vaultDeficit > 0n) {
    console.log("\n[4] Depositing to vault...");

    const ownableVaultRouter = new ethers.Contract(
      vaultRouterAddress,
      ["function owner() view returns (address)"],
      provider,
    );
    const vaultRouterOwner: string = await ownableVaultRouter.owner();

    let alreadyRegistered = false;
    const sourcesCount = await vaultRouterAsOwner.liquiditySourcesCount();
    for (let i = 0n; i < sourcesCount; i++) {
      const { sourceAddress } = await vaultRouterAsOwner.liquiditySourceAt(i);
      if (sourceAddress.toLowerCase() === holderWallet.address.toLowerCase()) {
        alreadyRegistered = true;
        break;
      }
    }

    if (alreadyRegistered) {
      console.log(`    Holder already registered as liquidity source`);
    } else {
      const candidates = [ownerWallet, holderWallet, vaultRouterWallet].filter(
        (w): w is Wallet => w !== undefined,
      );
      const signerForRegistration = candidates.find(
        (w) => w.address.toLowerCase() === vaultRouterOwner.toLowerCase(),
      );
      if (!signerForRegistration) {
        throw new Error(
          `VaultRouter owner ${vaultRouterOwner} matches none of PRIVATE_KEY / ERC20_HOLDER_PRIVATE_KEY / VAULT_ROUTER_PRIVATE_KEY (${candidates
            .map((w) => w.address)
            .join(", ")}); cannot register holder as liquidity source`,
        );
      }
      const vaultRouterForRegistration = IVaultRouter__factory.connect(vaultRouterAddress, signerForRegistration);
      const setFlowTx = await vaultRouterForRegistration.addLiquiditySource(holderWallet.address, INBOUND_FLOW);
      await setFlowTx.wait();
      console.log(`    Registered holder as liquidity source (signed by ${signerForRegistration.address})`);
    }

    const approveTx = await tokenAsHolder.approve(vaultRouterAddress, vaultDeficit);
    await approveTx.wait();
    const depositTx = await vaultRouterAsHolder.deposit(erc20Address, vaultDeficit);
    await depositTx.wait();
    const newBal = await tokenAsOwner.balanceOf(underlyingVaultAddr);
    console.log(`    Deposited ${fmt(vaultDeficit)} -> vault balance: ${fmt(newBal)}`);
  } else {
    console.log("\n[4] Vault balance sufficient - skipping deposit");
  }

  console.log("\n=== Setup ERC20 complete ===");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
