import { ethers, Wallet } from "ethers";
import {
  SmartAccountFactory__factory,
  IERC20__factory,
  ITokenBundle__factory,
  IEntryPoint__factory,
} from "./contracts/index.js";
import {
  formatTokenMeta,
  fetchTokenMeta,
  TokenMeta,
  DEFAULT_ENV,
  loadEnv,
  requireEnv, formatTokenMeta2,
  ownerPermissionId,
  permissionNonceKey,
  encodePermissionSignature,
  ENTRYPOINT_MIN_DEPOSIT,
  ENTRYPOINT_TOPUP,
  formatCoen,
} from "./utils.js";

const SALT = 0n;

// Parse CLI args: <amount> [envName]
if (!process.argv[2]) {
  console.error("Usage: npx tsx src/4.1-user-sa-withdraw.ts <amount> [envName]");
  console.error("  amount  - withdrawal amount in human-readable format (e.g. 5.5 for 5.5 tokens)");
  console.error("  envName - environment name (default: local-dev)");
  process.exit(1);
}

const withdrawAmountArg = process.argv[2];
const envName = process.argv[3] || DEFAULT_ENV;

// Load env files
const { envPath } = loadEnv(import.meta.url, envName, { deploymentEnv: true });

const rpcUrl = requireEnv("RPC_URL", envPath);
const userPrivateKey = requireEnv("USER_PRIVATE_KEY", envPath);
const userAddress = requireEnv("USER_ADDRESS", envPath);
const ccaAddress = requireEnv("CCA_ADDRESS", envPath);
const smartAccountFactoryAddress = requireEnv("SMART_ACCOUNT_FACTORY_ADDRESS", envPath);
const bundleModulePluginAddress = requireEnv("BUNDLE_MODULE_PLUGIN_ADDRESS", envPath);
const entryPointAddress = requireEnv("ENTRYPOINT_ADDRESS", envPath);
const erc20Address = requireEnv("ERC20_ADDRESS", envPath);
const vaultRouterAddress = requireEnv("VAULT_ROUTER_ADDRESS", envPath);

async function main() {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const userWallet = new Wallet(userPrivateKey, provider);

  const saFactory = SmartAccountFactory__factory.connect(smartAccountFactoryAddress, provider);
  const token = IERC20__factory.connect(erc20Address, provider);
  const bundlePlugin = ITokenBundle__factory.connect(bundleModulePluginAddress, provider);

  const erc20Meta = await fetchTokenMeta(token);
  const WITHDRAW_AMOUNT = ethers.parseUnits(withdrawAmountArg, erc20Meta.decimals);

  // Predict smart account address
  const smartAccountAddr = await saFactory.getAccountAddress(
    userAddress,
    ccaAddress,
    [erc20Address],
    [vaultRouterAddress],
    SALT,
  );

  console.log("=== User smart account Withdraw ===");
  console.log(`Env:              ${envName}`);
  console.log(`RPC:              ${rpcUrl}`);
  console.log(`User:             ${userAddress}`);
  console.log(`smart account:    ${smartAccountAddr}`);
  console.log(`EntryPoint:       ${entryPointAddress}`);
  console.log(`Owner permission: ${ownerPermissionId()}`);
  console.log(`ERC20:            ${erc20Address} (${erc20Meta.symbol})`);
  console.log(`Withdraw amount:  ${formatTokenMeta(WITHDRAW_AMOUNT, erc20Meta)}`);

  // Verify smart account is deployed
  const code = await provider.getCode(smartAccountAddr);
  if (code === "0x") {
    console.error("smart account not deployed. Run `npm run top-up-bundle-account` first.");
    process.exit(1);
  }

  // State before
  const [bundleBalBefore, accountBalBefore, userBalBefore] = await Promise.all([
    bundlePlugin.balanceOf(smartAccountAddr, erc20Address).catch(() => 0n),
    token.balanceOf(smartAccountAddr),
    token.balanceOf(userAddress),
  ]);

  console.log("\n=== State BEFORE ===");
  printBalances(accountBalBefore, bundleBalBefore, userBalBefore, smartAccountAddr, erc20Meta);

  const personalBal = accountBalBefore - bundleBalBefore;
  if (personalBal < WITHDRAW_AMOUNT) {
    console.error(`Insufficient personal balance: have ${formatTokenMeta(personalBal, erc20Meta)}, need ${formatTokenMeta(WITHDRAW_AMOUNT, erc20Meta)}`);
    process.exit(1);
  }

  // -- Build UserOp with the owner permission validation ---------------------
  // Kernel v4 models the owner as a permission (SudoPolicy + ECDSASigner) carrying
  // BundleSpendProtectorHook, so the UserOp uses the permission nonce type (0x02).
  const nonceKey = permissionNonceKey(ownerPermissionId());

  const entryPoint = IEntryPoint__factory.connect(entryPointAddress, userWallet);

  const nonce = await entryPoint.getNonce(smartAccountAddr, nonceKey);

  // Ensure EntryPoint has deposit for gas
  const epDeposit: bigint = await entryPoint.balanceOf(smartAccountAddr);
  if (epDeposit < ENTRYPOINT_MIN_DEPOSIT) {
    console.log("\nFunding EntryPoint deposit for smart account...");
    const depositTx = await entryPoint.depositTo(smartAccountAddr, { value: ENTRYPOINT_TOPUP });
    await depositTx.wait();
    console.log(`  Deposited ${formatCoen(ENTRYPOINT_TOPUP)} COEN into EntryPoint`);
  }

  // callData = executeUserOp.selector || execute(execMode, encodeSingle(token, 0, transfer(user, amount)))
  const erc20Iface = new ethers.Interface(["function transfer(address to, uint256 amount) returns (bool)"]);
  const transferCalldata = erc20Iface.encodeFunctionData("transfer", [userAddress, WITHDRAW_AMOUNT]);
  const executionCalldata = ethers.solidityPacked(
    ["address", "uint256", "bytes"],
    [erc20Address, 0n, transferCalldata],
  );
  const execModeBytes32 = "0x" + "00".repeat(32);
  const kernelIface = new ethers.Interface([
    "function execute(bytes32 mode, bytes calldata executionCalldata)",
  ]);
  const innerExecute = kernelIface.encodeFunctionData("execute", [execModeBytes32, executionCalldata]);
  const executeUserOpSel = "0x8dd7712f";
  const callData = ethers.concat([executeUserOpSel, innerExecute]);

  const accountGasLimits = ethers.solidityPacked(["uint128", "uint128"], [2_000_000n, 2_000_000n]);
  const gasFees = ethers.solidityPacked(["uint128", "uint128"], [1n, 1n]);

  const op = {
    sender: smartAccountAddr,
    nonce: nonce,
    initCode: "0x",
    callData: callData,
    accountGasLimits: accountGasLimits,
    preVerificationGas: 1_000_000n,
    gasFees: gasFees,
    paymasterAndData: "0x",
    signature: "0x",
  };

  // Kernel v4 permission signature: abi.encode(bytes[]{ policy slice (empty), owner ECDSA sig }).
  const userOpHash = await entryPoint.getUserOpHash(op);
  const sig = await userWallet.signMessage(ethers.getBytes(userOpHash));
  op.signature = encodePermissionSignature(sig);

  console.log("\nSending UserOp via EntryPoint.handleOps...");
  console.log(`  Nonce:      ${nonce}`);
  console.log(`  UserOpHash: ${userOpHash}`);

  const tx = await entryPoint.handleOps([op], userWallet.address);
  const receipt = await tx.wait();
  console.log(`  TX hash:    ${receipt!.hash}`);
  console.log(`  Block:      ${receipt!.blockNumber}`);
  console.log(`  Gas used:   ${receipt!.gasUsed}`);

  // -- State after -----------------------------------------------------------

  const [bundleBalAfter, accountBalAfter, userBalAfter] = await Promise.all([
    bundlePlugin.balanceOf(smartAccountAddr, erc20Address).catch(() => 0n),
    token.balanceOf(smartAccountAddr),
    token.balanceOf(userAddress),
  ]);

  console.log("\n=== State AFTER ===");
  printBalances(accountBalAfter, bundleBalAfter, userBalAfter, smartAccountAddr, erc20Meta);

  console.log("\n=== CHANGES ===");
  const bundleDiff = bundleBalAfter - bundleBalBefore;
  const accountDiff = accountBalAfter - accountBalBefore;
  const userDiff = userBalAfter - userBalBefore;
  console.log(`  SA total:     ${accountDiff >= 0n ? "+" : ""}${formatTokenMeta(accountDiff, erc20Meta)}`);
  console.log(`  SA bundle:    ${bundleDiff >= 0n ? "+" : ""}${formatTokenMeta(bundleDiff, erc20Meta)}`);
  console.log(`  User EOA:     ${userDiff >= 0n ? "+" : ""}${formatTokenMeta(userDiff, erc20Meta)}`);
}

function printBalances(
  accountBal: bigint,
  bundleBal: bigint,
  userBal: bigint,
  smartAccountAddr: string,
  erc20Meta: TokenMeta,
) {
  const personalBal = accountBal - bundleBal;
  const bundleBalance2 = bundleBal / 2n;
  console.log(`  smart account (${smartAccountAddr}):`);
  console.log(`    ERC20 total:   ${formatTokenMeta(accountBal, erc20Meta)}`);
  console.log(`    Bundle:        ${formatTokenMeta(bundleBal, erc20Meta)} (${formatTokenMeta2(bundleBalance2, erc20Meta)} + ${formatTokenMeta2(bundleBalance2, erc20Meta)})`);
  console.log(`    Personal:      ${formatTokenMeta(personalBal, erc20Meta)}`);
  console.log(`  User EOA (${userAddress}):`);
  console.log(`    ERC20 balance: ${formatTokenMeta(userBal, erc20Meta)}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
