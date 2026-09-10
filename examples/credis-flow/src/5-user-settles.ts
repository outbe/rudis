import { ethers, Wallet } from "ethers";
import {
  ICredisFactory__factory,
  ICredis__factory,
  SmartAccountFactory__factory,
  IERC20__factory,
  IVaultRouter__factory,
  IGratis__factory,
  IEntryPoint__factory,
} from "./contracts/index.js";
import {
  DEFAULT_GRATIS_ADDRESS,
  DEFAULT_CREDIS_FACTORY_ADDRESS,
  DEFAULT_CREDIS_ADDRESS,
  formatTokenMeta,
  formatTokenDiff,
  fetchTokenMeta,
  TokenMeta,
  DEFAULT_ENV,
  loadEnv,
  requireEnv, formatToken,
  ownerPermissionId,
  permissionNonceKey,
  encodePermissionSignature,
  ENTRYPOINT_MIN_DEPOSIT,
  ENTRYPOINT_TOPUP,
  formatCoen,
} from "./utils.js";
import { deriveGratisKeys, decryptBalance } from "./confidential.js";
import { findLatestTicket } from "./ticket.js";

const SALT = 0n;

// Parse CLI args: [positionId] [amount] [envName]. When positionId is omitted it is
// read from the latest pledge ticket (written by request-credis). `amount` is in the
// ERC20's smallest unit and defaults to exactly what the next installment still owes;
// any amount is accepted - it settles installments in order and may leave the last one
// partially paid. Overpaying is safe: only the outstanding balance is pulled.
let positionIdArg: string | undefined;
let amountArg: string | undefined;
let envName = DEFAULT_ENV;
for (const a of process.argv.slice(2)) {
  if (/^\d+$/.test(a) || a.startsWith("0x")) {
    if (positionIdArg === undefined) positionIdArg = a;
    else amountArg = a;
  } else envName = a;
}
const ticketPositionId = findLatestTicket()?.ticket.positionId;
if (!positionIdArg && !ticketPositionId) {
  console.error(
    "No positionId given and no ticket with one found. Run `npm run request-credis` first, or pass a positionId.",
  );
  process.exit(1);
}
const positionId = BigInt(positionIdArg ?? ticketPositionId!);

// Load env files
const { envPath, deploymentEnvPath } = loadEnv(import.meta.url, envName, { deploymentEnv: true });
const envContext = `${envPath} or ${deploymentEnvPath}`;

const rpcUrl = requireEnv("RPC_URL", envContext);
const userPrivateKey = requireEnv("USER_PRIVATE_KEY", envContext);
const userAddress = requireEnv("USER_ADDRESS", envContext);
const ccaAddress = requireEnv("CCA_ADDRESS", envContext);
const credisFactoryAddress = process.env["CREDIS_FACTORY_ADDRESS"] || DEFAULT_CREDIS_FACTORY_ADDRESS;
const credisAddress = process.env["CREDIS_ADDRESS"] || DEFAULT_CREDIS_ADDRESS;
const gratisAddress = process.env["GRATIS_ADDRESS"] || DEFAULT_GRATIS_ADDRESS;
const smartAccountFactoryAddress = requireEnv("SMART_ACCOUNT_FACTORY_ADDRESS", envContext);
const entryPointAddress = requireEnv("ENTRYPOINT_ADDRESS", envContext);
const erc20Address = requireEnv("ERC20_ADDRESS", envContext);
const vaultRouterAddress = requireEnv("VAULT_ROUTER_ADDRESS", envContext);

function formatDate(timestamp: bigint): string {
  if (timestamp === 0n) return "N/A";
  return new Date(Number(timestamp) * 1000).toISOString();
}

const ERROR_STRING_SELECTOR = "0x08c379a0";
const PANIC_SELECTOR = "0x4e487b71";
const KNOWN_ERROR_SIGS: Record<string, string> = {
  // Kernel.executeUserOp wraps inner failure in this error
  [ethers.id("ExecutionReverted()").slice(0, 10)]: "ExecutionReverted()",
  [ethers.id("InsufficientFreeBalance()").slice(0, 10)]: "InsufficientFreeBalance()",
  [ethers.id("InvalidCallType()").slice(0, 10)]: "InvalidCallType()",
  [ethers.id("InvalidSelector()").slice(0, 10)]: "InvalidSelector()",
};

function decodeRevert(data: string): string {
  if (!data || data === "0x") return "(empty)";
  const sel = data.slice(0, 10).toLowerCase();
  const abi = ethers.AbiCoder.defaultAbiCoder();
  try {
    if (sel === ERROR_STRING_SELECTOR) {
      const [reason] = abi.decode(["string"], "0x" + data.slice(10));
      return `Error("${reason}")`;
    }
    if (sel === PANIC_SELECTOR) {
      const [code] = abi.decode(["uint256"], "0x" + data.slice(10));
      return `Panic(0x${code.toString(16)})`;
    }
  } catch {
    // fall through to raw
  }
  if (KNOWN_ERROR_SIGS[sel]) return KNOWN_ERROR_SIGS[sel];
  const bytes = data.startsWith("0x") ? data.slice(2) : data;
  if (bytes.length > 0 && bytes.length % 2 === 0) {
    const buf = Buffer.from(bytes, "hex");
    if (buf.every((b) => (b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x09)) {
      return `"${buf.toString("utf8")}"`;
    }
  }
  return `raw=${data}`;
}

/// Mirrors `enum State` in contracts/precompiles/src/ICredis.sol.
const STATE_NAMES = ["Open", "Called", "Settled", "Void"];

interface State {
  saErc20Balance: bigint;
  vaultErc20Balance: bigint;
  hasCalled: boolean;
}

async function getState(
  token: ReturnType<typeof IERC20__factory.connect>,
  credis: ReturnType<typeof ICredis__factory.connect>,
  smartAccountAddr: string,
  underlyingVaultAddr: string,
): Promise<State> {
  const [saErc20Balance, vaultErc20Balance, hasCalled] = await Promise.all([
    token.balanceOf(smartAccountAddr),
    token.balanceOf(underlyingVaultAddr),
    credis.hasCalledPosition(smartAccountAddr).catch(() => false),
  ]);
  return { saErc20Balance, vaultErc20Balance, hasCalled };
}

function printState(label: string, state: State, erc20Meta: TokenMeta, smartAccountAddr: string) {
  console.log(`\n=== ${label} ===`);
  console.log(`  smart account (${smartAccountAddr}):`);
  console.log(`    ERC20 balance: ${formatTokenMeta(state.saErc20Balance, erc20Meta)}`);
  console.log(`  Vault Router (${vaultRouterAddress}):`);
  console.log(`    Vault ERC20:   ${formatTokenMeta(state.vaultErc20Balance, erc20Meta)}`);
  console.log(`  Credis:`);
  console.log(`    Has called:    ${state.hasCalled}`);
}

async function main() {
  console.log("=== User Settles Credis ===");
  console.log(`Env:              ${envName}`);
  console.log(`RPC:              ${rpcUrl}`);
  console.log(`User:             ${userAddress}`);
  console.log(`CredisFactory:    ${credisFactoryAddress}`);
  console.log(`Credis:           ${credisAddress}`);
  console.log(`ERC20:            ${erc20Address}`);
  console.log(`Vault Router:   ${vaultRouterAddress}`);
  console.log(`Position ID:      ${positionId}`);

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const userWallet = new Wallet(userPrivateKey, provider);

  const saFactory = SmartAccountFactory__factory.connect(smartAccountFactoryAddress, provider);
  const token = IERC20__factory.connect(erc20Address, provider);
  const credis = ICredis__factory.connect(credisAddress, provider);

  const vaultRouter = IVaultRouter__factory.connect(vaultRouterAddress, provider);

  const [erc20Meta, underlyingVaultAddr] = await Promise.all([
    fetchTokenMeta(token),
    vaultRouter.assetVaultAt(erc20Address, 0),
  ]);

  // Predict smart account address
  const smartAccountAddr = await saFactory.getAccountAddress(
    userAddress,
    ccaAddress,
    [erc20Address],
    [vaultRouterAddress],
    SALT,
  );
  console.log(`smart account:    ${smartAccountAddr}`);

  // Verify smart account is deployed
  const code = await provider.getCode(smartAccountAddr);
  if (code === "0x") {
    console.error("smart account not deployed. Run `npm run top-up-bundle-account` first.");
    process.exit(1);
  }

  // Fetch position to validate it exists
  const position = await credis.getPosition(positionId);
  if (position.originatedAt === 0n) {
    console.error(`Position ${positionId} does not exist.`);
    process.exit(1);
  }

  // Interest is not accrued per block: the chain computes it at settlement from
  // the whole UTC days elapsed since the accrual anchor, ACT/365 on the
  // outstanding principal. Read it now so the payment covers it.
  const interest = await credis.accruedInterest(positionId);

  console.log(`\nPosition:`);
  console.log(`  smart account: ${position.smartAccount}`);
  console.log(`  State:         ${STATE_NAMES[Number(position.state)] ?? position.state}`);
  console.log(`  Principal:     ${formatTokenMeta(position.principal, erc20Meta)}`);
  console.log(`  Outstanding:   ${formatTokenMeta(position.outstanding, erc20Meta)}`);
  console.log(`  Interest due:  ${formatTokenMeta(interest, erc20Meta)}`);
  console.log(`  Originated:    ${formatDate(position.originatedAt)}`);

  if (position.outstanding === 0n) {
    console.error("Position is fully settled. Nothing outstanding.");
    process.exit(1);
  }

  // Interest is always collected in full before any principal, so a payment below
  // it is rejected outright. Default to closing the position: interest + the whole
  // outstanding principal. The chain pulls only what the position needs, so
  // over-approving would just leave a dangling allowance.
  const payoff = interest + position.outstanding;
  const requested = amountArg !== undefined ? BigInt(amountArg) : payoff;
  const settleAmount = requested > payoff ? payoff : requested;
  console.log(`  Paying:        ${formatTokenMeta(settleAmount, erc20Meta)}`);

  if (settleAmount < interest) {
    console.error(
      `Payment must cover the accrued interest of ${formatTokenMeta(interest, erc20Meta)} first.`,
    );
    process.exit(1);
  }
  if (settleAmount === 0n) {
    console.error("Nothing to pay.");
    process.exit(1);
  }

  // On payment the chain automatically releases the collateral share matching the
  // debt just paid down back to the ORIGINAL pledger's confidential Gratis balance -
  // no reclaim note, no second transaction. The user reads their own (encrypted)
  // balance with their view key.
  const gratis = IGratis__factory.connect(gratisAddress, provider);
  const userKeys = await deriveGratisKeys(userWallet);
  const gratisBalBefore = decryptBalance(userKeys.viewKey, userAddress, await gratis.balanceOf(userAddress));
  console.log(
    `\nThis payment unlocks the matching share of collateral back to ${userAddress}` +
      ` (up to ${formatToken(position.collateralLocked, 6, "GRATIS")} still locked).`,
  );
  console.log(`  User Gratis balance before: ${formatToken(gratisBalBefore, 6, "GRATIS")} (decrypted)`);

  // State before
  const before = await getState(token, credis, smartAccountAddr, underlyingVaultAddr);
  printState("State BEFORE", before, erc20Meta, smartAccountAddr);

  if (before.saErc20Balance < settleAmount) {
    console.error(`Insufficient SA balance: have ${formatTokenMeta(before.saErc20Balance, erc20Meta)}, need ${formatTokenMeta(settleAmount, erc20Meta)}`);
    process.exit(1);
  }

  // -- Build batch UserOp: approve + settle ------------------------------

  // Owner permission validation (Kernel v4 permission nonce type 0x02); the owner permission
  // carries BundleSpendProtectorHook, so this batch executeUserOp is checked against the reserve.
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

  // Encode batch: [approve(credisFactory, settleAmount), settle(positionId, settleAmount)].
  // The runtime applies the payment interest first and principal second, pulls only
  // what the position needed, and releases the collateral share proportional to the
  // principal covered back to the pledger's (userAddress) encrypted balance - the
  // enclave recovers the EOA from the position's sealed ciphertext, so it is not
  // passed in calldata.
  const approveCalldata = IERC20__factory.createInterface().encodeFunctionData("approve", [credisFactoryAddress, settleAmount]);
  const payCalldata = ICredisFactory__factory.createInterface().encodeFunctionData("settle", [positionId, settleAmount]);

  // Batch execution: execMode byte[0] = 0x01 (CALLTYPE_BATCH)
  const execModeBatch = "0x01" + "00".repeat(31);
  const abiCoder = ethers.AbiCoder.defaultAbiCoder();
  const executionCalldata = abiCoder.encode(
    ["tuple(address,uint256,bytes)[]"],
    [[
      [erc20Address, 0n, approveCalldata],
      [credisFactoryAddress, 0n, payCalldata],
    ]],
  );

  const kernelIface = new ethers.Interface([
    "function execute(bytes32 mode, bytes calldata executionCalldata)",
  ]);
  const innerExecute = kernelIface.encodeFunctionData("execute", [execModeBatch, executionCalldata]);
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

  // -- Pre-simulate the inner execute() so a precompile revert surfaces here
  // rather than being swallowed by handleOps (which catches inner reverts and
  // still reports the outer tx as successful).
  console.log("\nSimulating inner execute() from EntryPoint...");
  try {
    await provider.call({
      from: entryPointAddress,
      to: smartAccountAddr,
      data: innerExecute,
    });
    console.log("  Simulation OK");
  } catch (err) {
    const data = (err as { data?: string; info?: { error?: { data?: string } } }).data
      ?? (err as { info?: { error?: { data?: string } } }).info?.error?.data
      ?? "0x";
    console.error(`  Simulation reverted: ${decodeRevert(data)}`);
    process.exit(1);
  }

  console.log("\nSending UserOp via EntryPoint.handleOps...");
  console.log(`  Nonce:      ${nonce}`);
  console.log(`  UserOpHash: ${userOpHash}`);

  const tx = await entryPoint.handleOps([op], userWallet.address);
  const receipt = await tx.wait();
  console.log(`  TX hash:    ${receipt!.hash}`);
  console.log(`  Block:      ${receipt!.blockNumber}`);
  console.log(`  Gas used:   ${receipt!.gasUsed}`);

  // Parse events
  const interfaces = [
    { name: "EntryPoint", iface: IEntryPoint__factory.createInterface() },
    { name: "ICredisFactory", iface: ICredisFactory__factory.createInterface() },
    { name: "ICredis", iface: ICredis__factory.createInterface() },
    { name: "VaultRouter", iface: IVaultRouter__factory.createInterface() },
    { name: "IGratis", iface: IGratis__factory.createInterface() },
    { name: "ERC20", iface: IERC20__factory.createInterface() },
  ];

  let userOpSuccess: boolean | null = null;
  let userOpRevertReason: string | null = null;

  console.log("\n=== Transaction Events ===");
  for (const log of receipt?.logs ?? []) {
    let parsed = false;
    for (const { name: contractName, iface } of interfaces) {
      try {
        const event = iface.parseLog({ topics: log.topics as string[], data: log.data });
        if (event) {
          console.log(`  [${contractName}] ${event.name}:`);
          const fragment = event.fragment;
          for (let i = 0; i < fragment.inputs.length; i++) {
            const paramName = fragment.inputs[i].name;
            const value = event.args[i];
            console.log(`    ${paramName}: ${value}`);
          }
          if (contractName === "EntryPoint" && event.args.userOpHash === userOpHash) {
            if (event.name === "UserOperationEvent") userOpSuccess = event.args.success;
            if (event.name === "UserOperationRevertReason") userOpRevertReason = event.args.revertReason;
          }
          parsed = true;
          break;
        }
      } catch {
        // Not from this interface
      }
    }
    if (!parsed) {
      console.log(`  [Unknown] address=${log.address} topics=${log.topics[0]}`);
    }
  }

  if (userOpSuccess === false) {
    console.error("\n!! UserOperation reverted - outer handleOps tx still succeeded (ERC-4337 swallows inner reverts).");
    if (userOpRevertReason && userOpRevertReason !== "0x") {
      console.error(`  Decoded: ${decodeRevert(userOpRevertReason)}`);
    } else {
      console.error("  No UserOperationRevertReason emitted (validation phase failure or zero-length revert data).");
    }
    process.exit(1);
  }

  // State after
  const after = await getState(token, credis, smartAccountAddr, underlyingVaultAddr);
  printState("State AFTER", after, erc20Meta, smartAccountAddr);

  // Diff
  console.log("\n=== CHANGES ===");
  const saErc20Diff = after.saErc20Balance - before.saErc20Balance;
  const vaultErc20Diff = after.vaultErc20Balance - before.vaultErc20Balance;
  console.log(`  SA ERC20:        ${formatTokenDiff(saErc20Diff, erc20Meta.decimals, erc20Meta.symbol)}`);
  console.log(`  Vault ERC20:     ${formatTokenDiff(vaultErc20Diff, erc20Meta.decimals, erc20Meta.symbol)}`);

  // The collateral share unlocked automatically to the pledger's confidential
  // balance - verify it by decrypting with the user's view key. No reclaim note
  // or follow-up unpledge is needed.
  const gratisBalAfter = decryptBalance(userKeys.viewKey, userAddress, await gratis.balanceOf(userAddress));
  const unlocked = gratisBalAfter - gratisBalBefore;
  console.log(`  User Gratis:     ${formatTokenDiff(unlocked, 6, "GRATIS")} (collateral released to the pledger)`);

  // The release is proportional to the debt paid down, so it must be positive and can
  // never exceed what the position still had locked.
  const positionAfter = await credis.getPosition(positionId);
  const principalPaid = position.outstanding - positionAfter.outstanding;
  console.log(`  Principal paid:  ${formatTokenMeta(principalPaid, erc20Meta)}`);
  console.log(`  Interest paid:   ${formatTokenMeta(settleAmount - principalPaid, erc20Meta)}`);
  console.log(`  Outstanding:     ${formatTokenMeta(positionAfter.outstanding, erc20Meta)}`);
  if (unlocked <= 0n || unlocked > position.collateralLocked) {
    console.warn(
      `  WARNING: unlocked ${formatToken(unlocked, 6, "GRATIS")} outside the expected` +
        ` (0, ${formatToken(position.collateralLocked, 6, "GRATIS")}] range`,
    );
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
