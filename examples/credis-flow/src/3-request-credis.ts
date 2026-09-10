import { ethers, Wallet } from "ethers";
import {
  IGratis__factory,
  ICredisFactory__factory,
  ICredis__factory,
  SmartAccountFactory__factory,
  IERC20__factory,
  IVaultRouter__factory,
} from "./contracts/index.js";
import {
  DEFAULT_GRATIS_ADDRESS,
  DEFAULT_CREDIS_ADDRESS,
  DEFAULT_CREDIS_FACTORY_ADDRESS,
  formatTokenMeta,
  formatCoen,
  protocolAmountToNativeCoen,
  formatTokenDiff,
  fetchTokenMeta,
  DEFAULT_ENV,
  loadEnv,
  requireEnv,
} from "./utils.js";
import { pledgeSecret as derivePledgeSecret, spendAuth, positionId as computePositionId } from "./confidential.js";
import { findLatestTicket, readTicket, writeTicket, type Ticket } from "./ticket.js";

const SALT = 0n;

// ISO 4217 code of the threshold anchor the CCA elects for the position. It gates
// only the call - the loan stays denominated in the disbursed asset's currency.
const REFERENCE_CURRENCY = 840; // USD

// The CCA calls requestCredis with the confidential pledge handle + a spend
// authorization that binds it to the user's smart account. The CCA holds the
// `pledgeSecret` the user handed over (in the ticket for the demo); it does NOT
// hold the user's view key, so it cannot read the user's encrypted Gratis
// balance - only the pledge is consumed and the loan disbursed to the bundle.
//
// CLI: [ticketPath?] [envName?]
let ticketPath: string | undefined;
let envName = DEFAULT_ENV;
for (const a of process.argv.slice(2)) {
  if (a.endsWith(".json")) ticketPath = a;
  else envName = a;
}

const { envPath, deploymentEnvPath } = loadEnv(import.meta.url, envName, { deploymentEnv: true });
const envContext = `${envPath} or ${deploymentEnvPath}`;

const rpcUrl = requireEnv("RPC_URL", envContext);
const ccaPrivateKey = requireEnv("CCA_PRIVATE_KEY", envContext);
const ccaAddress = requireEnv("CCA_ADDRESS", envContext);
const userAddress = requireEnv("USER_ADDRESS", envContext);
const gratisAddress = process.env["GRATIS_ADDRESS"] || DEFAULT_GRATIS_ADDRESS;
const credisFactoryAddress = process.env["CREDIS_FACTORY_ADDRESS"] || DEFAULT_CREDIS_FACTORY_ADDRESS;
const credisAddress = process.env["CREDIS_ADDRESS"] || DEFAULT_CREDIS_ADDRESS;
const smartAccountFactoryAddress = requireEnv("SMART_ACCOUNT_FACTORY_ADDRESS", envContext);
const vaultRouterAddress = requireEnv("VAULT_ROUTER_ADDRESS", envContext);
const erc20Address = requireEnv("ERC20_ADDRESS", envContext);

function loadTicket(): { ticket: Ticket; path: string } {
  if (ticketPath) return { ticket: readTicket(ticketPath), path: ticketPath };
  const latest = findLatestTicket();
  if (!latest) {
    console.error("No ticket found under tickets/. Run `npm run pledge-gratis` first.");
    process.exit(1);
  }
  return latest;
}

async function main() {
  const { ticket, path: usedTicketPath } = loadTicket();

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const ccaWallet = new Wallet(ccaPrivateKey, provider);

  // Predict the smart account address - the credis receiver, and the account
  // the pledge spend is bound to.
  const saFactory = SmartAccountFactory__factory.connect(smartAccountFactoryAddress, provider);
  const smartAccount = await saFactory.getAccountAddress(
    userAddress,
    ccaAddress,
    [erc20Address],
    [vaultRouterAddress],
    SALT,
  );

  const credisFactory = ICredisFactory__factory.connect(credisFactoryAddress, ccaWallet);
  const credis = ICredis__factory.connect(credisAddress, provider);
  const token = IERC20__factory.connect(erc20Address, provider);
  const gratis = IGratis__factory.connect(gratisAddress, provider);

  const [erc20Meta, network] = await Promise.all([fetchTokenMeta(token), provider.getNetwork()]);

  // Bind the pledge to this smart account with the spend authorization derived
  // from the pledge secret the user handed to the CCA.
  const secret = ethers.getBytes(ticket.pledgeSecret);
  const spend = spendAuth(secret, smartAccount);

  console.log("=== Request Credis (confidential / TEE) ===");
  console.log(`Env:            ${envName}`);
  console.log(`Ticket:         ${usedTicketPath}`);
  console.log(`CCA:            ${ccaAddress}`);
  console.log(`User (pledger): ${userAddress}`);
  console.log(`CredisFactory:  ${credisFactoryAddress}`);
  console.log(`smart account: ${smartAccount}`);
  console.log(`ERC20:          ${erc20Address} (${erc20Meta.symbol})`);
  console.log(`Pledge handle:  ${ticket.pledgeHandle}`);
  console.log(`Spend auth:     ${spend}`);
  console.log(`Chain ID:       ${network.chainId}`);

  const bundleErc20Before = await token.balanceOf(smartAccount);
  console.log(`\nBundle ERC20 before: ${formatTokenMeta(bundleErc20Before, erc20Meta)}`);

  // Neither the pledger EOA nor the asset/amount are passed in calldata: the enclave
  // reads the EOA from the pledge ticket, debits its pledged ledger, and returns it
  // sealed so it is stored as ciphertext on the position (no EOA<->bundle linkage
  // on-chain); the asset and the disbursed amount were sealed into the same ticket at
  // pledge time, so the loan is issued at the price the user accepted.
  // The CCA matches the user's collateral one for one in native COEN. The required
  // amount is the gratis the quote cost, which the ticket recorded at pledge time -
  // it is not in calldata, because it was sealed into the pledge.
  const stake = protocolAmountToNativeCoen(BigInt(ticket.amount));
  console.log(
    `CCA stake:      ${formatCoen(stake)} COEN (matches the pledged collateral, paid to the smart account)`,
  );

  // The loan is delivered by a call into the smart account, so the precompile now
  // rejects an undeployed one. Fail here with a runnable instruction rather than
  // paying gas for a mined revert carrying an opaque precompile string.
  const saCode = await provider.getCode(smartAccount);
  if (saCode === "0x") {
    console.error("smart account not deployed. Run `npm run top-up-bundle-account` first.");
    process.exit(1);
  }

  // requestCredis is payable and takes the stake from the CCA, so an underfunded
  // CCA fails inside the EVM with no useful message.
  const ccaNative = await provider.getBalance(ccaAddress);
  if (ccaNative < stake) {
    console.error(
      `CCA holds ${formatCoen(ccaNative)} COEN but must stake ${formatCoen(stake)}. ` +
        "Run `npm run setup-native` first.",
    );
    process.exit(1);
  }

  console.log(
    "\nSending requestCredis(smartAccount, pledgeHandle, spendAuth, referenceCurrency)...",
  );
  const tx = await credisFactory.requestCredis(
    smartAccount,
    ticket.pledgeHandle,
    spend,
    REFERENCE_CURRENCY,
    { value: stake },
  );
  console.log(`  TX hash: ${tx.hash}`);
  const receipt = await tx.wait();
  if (!receipt) throw new Error("requestCredis tx receipt missing");
  console.log(`  Block:   ${receipt.blockNumber}`);

  // Log the events across the involved interfaces.
  const interfaces = [
    { name: "ICredisFactory", iface: ICredisFactory__factory.createInterface() },
    { name: "ICredis", iface: ICredis__factory.createInterface() },
    { name: "VaultRouter", iface: IVaultRouter__factory.createInterface() },
    { name: "IGratis", iface: IGratis__factory.createInterface() },
    { name: "ERC20", iface: IERC20__factory.createInterface() },
  ];
  let eventPositionId: bigint | null = null;
  console.log("\n=== Transaction Events ===");
  for (const log of receipt.logs ?? []) {
    for (const { name, iface } of interfaces) {
      try {
        const event = iface.parseLog({ topics: log.topics as string[], data: log.data });
        if (event) {
          console.log(`  [${name}] ${event.name}`);
          if (event.name === "PositionCreated") eventPositionId = event.args[0] as bigint;
          break;
        }
      } catch {
        // not from this interface
      }
    }
  }

  // Position id is deterministic: keccak256(pledgeHandle || smartAccount).
  const positionId = computePositionId(ticket.pledgeHandle, smartAccount);
  if (eventPositionId !== null && eventPositionId !== positionId) {
    throw new Error(
      `PositionCreated id ${eventPositionId} != computed ${positionId} - check position_id parity`,
    );
  }

  const bundleErc20After = await token.balanceOf(smartAccount);
  const position = await credis.getPosition(positionId);

  console.log("\n=== Position ===");
  console.log(`  positionId:        ${positionId}`);
  console.log(`  smartAccount:     ${position.smartAccount}`);
  console.log(`  principal:         ${formatTokenMeta(position.principal, erc20Meta)}`);
  console.log(`  outstanding:       ${formatTokenMeta(position.outstanding, erc20Meta)}`);
  console.log(`  collateral:        ${position.collateral}`);
  console.log(`  policyRate:        ${position.policyRate}`);
  console.log(`  entryPrice:        ${position.entryPrice}`);
  console.log(`  callPrice:         ${position.callPrice}`);
  console.log(`  issuanceCurrency:  ${position.issuanceCurrency}`);
  console.log(`  referenceCurrency: ${position.referenceCurrency}`);
  console.log(`\nBundle ERC20 change: ${formatTokenDiff(bundleErc20After - bundleErc20Before, erc20Meta.decimals, erc20Meta.symbol)}`);

  // Persist the position + bundle for settlement.
  ticket.positionId = positionId.toString();
  ticket.smartAccount = smartAccount;
  writeTicket(ticket);
  console.log(`\nTicket updated: ${usedTicketPath}`);
  console.log("Run `npm run user-settles` to settle any amount (collateral releases in proportion).");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
