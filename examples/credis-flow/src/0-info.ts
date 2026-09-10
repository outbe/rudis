import { ethers, toBigInt, Wallet } from "ethers";
import {
  IGratis__factory,
  ICredis__factory,
  IFidelity__factory,
  SmartAccountFactory__factory,
  IERC20__factory,
  ITokenBundle__factory,
  IVaultRouter__factory,
} from "./contracts/index.js";
import {
  DEFAULT_GRATIS_ADDRESS,
  DEFAULT_GRATIS_FACTORY_ADDRESS,
  DEFAULT_CREDIS_FACTORY_ADDRESS,
  DEFAULT_CREDIS_ADDRESS,
  DEFAULT_FIDELITY_ADDRESS,
  formatToken,
  formatTokenMeta,
  fetchTokenMeta,
  TokenMeta,
  DEFAULT_ENV,
  loadEnv,
  requireEnv, formatTokenMeta2,
  formatCoen,
} from "./utils.js";
import {
  deriveGratisKeys,
  decryptBalance,
  decryptPledged,
  signFidelityQueryAuth,
  type GratisKeys,
} from "./confidential.js";
import { listTickets } from "./ticket.js";

const SALT = 0n;

// Parse CLI args: [envName]
const envName = process.argv[2] || DEFAULT_ENV;

// Load env files
const { envPath } = loadEnv(import.meta.url, envName, { deploymentEnv: true });

const rpcUrl = requireEnv("RPC_URL", envPath);
const userAddress = requireEnv("USER_ADDRESS", envPath);
// Optional: needed only to sign the ownership proof that fetches the user's view
// key (so this read-only script can decrypt their Gratis balances).
const userPrivateKey = process.env["USER_PRIVATE_KEY"];
const ccaAddress = requireEnv("CCA_ADDRESS", envPath);
const gratisAddress = process.env["GRATIS_ADDRESS"] || DEFAULT_GRATIS_ADDRESS;
const gratisFactoryAddress = process.env["GRATIS_FACTORY_ADDRESS"] || DEFAULT_GRATIS_FACTORY_ADDRESS;
const credisFactoryAddress = process.env["CREDIS_FACTORY_ADDRESS"] || DEFAULT_CREDIS_FACTORY_ADDRESS;
const credisAddress = process.env["CREDIS_ADDRESS"] || DEFAULT_CREDIS_ADDRESS;
const fidelityAddress = process.env["FIDELITY_ADDRESS"] || DEFAULT_FIDELITY_ADDRESS;
const smartAccountFactoryAddress = requireEnv("SMART_ACCOUNT_FACTORY_ADDRESS", envPath);
const bundleModulePluginAddress = requireEnv("BUNDLE_MODULE_PLUGIN_ADDRESS", envPath);
const erc20Address = requireEnv("ERC20_ADDRESS", envPath);
const vaultRouterAddress = requireEnv("VAULT_ROUTER_ADDRESS", envPath);

function formatDate(timestamp: bigint): string {
  if (timestamp === 0n) return "N/A";
  return new Date(Number(timestamp) * 1000).toISOString();
}

async function main() {
  const provider = new ethers.JsonRpcProvider(rpcUrl);

  const gratis = IGratis__factory.connect(gratisAddress, provider);
  const credis = ICredis__factory.connect(credisAddress, provider);
  const fidelity = IFidelity__factory.connect(fidelityAddress, provider);
  const saFactory = SmartAccountFactory__factory.connect(smartAccountFactoryAddress, provider);
  const token = IERC20__factory.connect(erc20Address, provider);
  const bundlePlugin = ITokenBundle__factory.connect(bundleModulePluginAddress, provider);
  const vaultRouter = IVaultRouter__factory.connect(vaultRouterAddress, provider);

  console.log("=== Credis Info ===");
  console.log(`Env:              ${envName}`);
  console.log(`RPC:              ${rpcUrl}`);
  console.log(`Gratis:           ${gratisAddress}  TotalSupply: ${(await gratis.totalSupply()).toString()}`);
  console.log(`GratisFactory:    ${gratisFactoryAddress}`);
  console.log(`CredisFactory:    ${credisFactoryAddress}`);
  console.log(`Credis:           ${credisAddress}`);
  console.log(`SA Factory:       ${smartAccountFactoryAddress}`);
  console.log(`Bundle Plugin:    ${bundleModulePluginAddress}`);
  console.log(`ERC20:            ${erc20Address}  TotalSupply: ${(await token.totalSupply()).toString()} ${await token.name()}`);
  console.log(`Vault Router:   ${vaultRouterAddress}`);

  const [gratisMeta, erc20Meta] = await Promise.all([fetchTokenMeta(gratis), fetchTokenMeta(token)]);

  // The user's Gratis balances are confidential. Fetching the view key requires
  // signing an ownership proof, so it needs USER_PRIVATE_KEY; without it (or if
  // the enclave/DKG isn't up) balances are shown as ciphertext.
  let userKeys: GratisKeys | null = null;
  // The same account key that unlocks the Gratis view key also signs the
  // Fidelity index query authorization, so build the wallet once.
  const userWallet = userPrivateKey ? new Wallet(userPrivateKey, provider) : null;
  if (userWallet) {
    try {
      userKeys = await deriveGratisKeys(userWallet);
    } catch (e) {
      console.warn(`\n(!) Could not fetch Gratis view key (${(e as Error).message}); balances shown as ciphertext.`);
    }
  } else {
    console.warn("\n(!) USER_PRIVATE_KEY not set - Gratis balances shown as ciphertext (the account key is needed to fetch its view key).");
  }

  const smartAccountAddr = await saFactory.getAccountAddress(
    userAddress,
    ccaAddress,
    [erc20Address],
    [vaultRouterAddress],
    SALT,
  );

  await printUserInfo(provider, gratis, token, fidelity, gratisMeta, erc20Meta, userKeys, userWallet);
  await printSmartAccountInfo(provider, token, bundlePlugin, smartAccountAddr, erc20Meta);
  await printCredisInfo(credis, smartAccountAddr, erc20Meta);
  await printCcaInfo(provider, token, erc20Meta);
  await printVaultRouterInfo(vaultRouter, token, erc20Address, erc20Meta);
}

async function printUserInfo(
  provider: ethers.JsonRpcProvider,
  gratis: ReturnType<typeof IGratis__factory.connect>,
  token: ReturnType<typeof IERC20__factory.connect>,
  fidelity: ReturnType<typeof IFidelity__factory.connect>,
  gratisMeta: TokenMeta,
  erc20Meta: TokenMeta,
  keys: GratisKeys | null,
  wallet: Wallet | null,
) {
  const [nativeBalance, erc20Balance, gratisBlob, pledgedBlob, pledgedTotal] = await Promise.all([
    provider.getBalance(userAddress),
    token.balanceOf(userAddress),
    gratis.balanceOf(userAddress),
    gratis.pledgedOf(userAddress),
    gratis.pledgedTotalSupply(),
  ]);

  const showGratis = keys
    ? formatTokenMeta(decryptBalance(keys.viewKey, userAddress, gratisBlob), gratisMeta)
    : `${gratisBlob} (ciphertext - need view key)`;
  const showPledged = keys
    ? formatTokenMeta(decryptPledged(keys.viewKey, userAddress, pledgedBlob), gratisMeta)
    : `${pledgedBlob} (ciphertext - need view key)`;

  // Pending pledges live in enclave-encrypted PledgeLockTickets (not readable with the
  // view key) and are NOT yet in `pledgedOf` - that ledger fills only at requestCredis.
  // The local ticket JSON is the only client-visible source, so sum this chain's tickets
  // that haven't been consumed into a credis position yet (no positionId).
  const { chainId } = await provider.getNetwork();
  const pending = listTickets()
    .filter((t) => !t.ticket.positionId && t.ticket.chainId === chainId.toString())
    .reduce((sum, t) => sum + BigInt(t.ticket.amount), 0n);

  const fid = await fetchFidelity(provider, fidelity, wallet);

  console.log(`\n=== User: ${userAddress} ===`);
  console.log(`  Native balance:  ${formatCoen(nativeBalance)} COEN`);
  console.log(`  ERC20 balance:   ${formatTokenMeta(erc20Balance, erc20Meta)}`);
  console.log(`  Gratis balance:  ${showGratis}   ${keys ? "(decrypted with view key)" : ""}`);
  console.log(`  Active pledged:  ${showPledged} (credited to the pledged ledger at requestCredis)`);
  console.log(`  Pending pledged: ${formatTokenMeta(pending, gratisMeta)} (local tickets not yet requested)`);
  console.log(`  Pledged total:   ${formatTokenMeta(pledgedTotal, gratisMeta)} (system-wide, plaintext aggregate)`);
  console.log(`  Fidelity index:  ${fid.index}`);
  console.log(`  League:          ${fid.league}`);
}

/** Mirror of `outbe_fidelity_math::league_from_rcfi` (1..=4096, saturating). */
function leagueFromRcfi(rcfi: bigint, maxRcfi: bigint, minLeague: bigint, maxLeague: bigint): bigint {
  if (maxRcfi === 0n) return minLeague;
  const slot = (rcfi * maxLeague) / maxRcfi;
  const capped = slot < maxLeague - 1n ? slot : maxLeague - 1n;
  return minLeague + capped;
}

/**
 * Read the EOA's Fidelity Index (RCFI) and derive its league. The cohort ledger
 * is TEE-encrypted, so the index read needs an owner-signed, expiring
 * authorization (the same account key); without USER_PRIVATE_KEY only the
 * plaintext league bounds/max are available. League is derived client-side from
 * the index vs the plaintext synthetic maximum - no separate on-chain read.
 */
async function fetchFidelity(
  provider: ethers.JsonRpcProvider,
  fidelity: ReturnType<typeof IFidelity__factory.connect>,
  wallet: Wallet | null,
): Promise<{ index: string; league: string }> {
  let decimals: bigint, minLeague: bigint, maxLeague: bigint, maxRcfi: bigint, now: bigint;
  try {
    const block = await provider.getBlock("latest");
    now = BigInt(block?.timestamp ?? 0);
    [decimals, minLeague, maxLeague, maxRcfi] = await Promise.all([
      fidelity.decimals().then((d) => BigInt(d)),
      fidelity.minLeague().then((l) => BigInt(l)),
      fidelity.maxLeague().then((l) => BigInt(l)),
      fidelity.maxFidelityIndexAt(now),
    ]);
  } catch (e) {
    return { index: `(unavailable: ${(e as Error).message})`, league: "N/A" };
  }

  if (!wallet) {
    return { index: "(need USER_PRIVATE_KEY to sign the query authorization)", league: "N/A" };
  }

  try {
    const { chainId } = await provider.getNetwork();
    const expiry = now + 3600n; // authorize a 1-hour window past the current block
    const signature = await signFidelityQueryAuth(wallet, chainId, userAddress, expiry);
    // Evaluate the index at the same `now` as the synthetic max above, so the
    // derived league is exact (the auth message doesn't bind the query time).
    const rcfi = await fidelity.getFidelityIndexAt(userAddress, now, expiry, signature);
    const league = leagueFromRcfi(rcfi, maxRcfi, minLeague, maxLeague);
    return {
      index: `${ethers.formatUnits(rcfi, Number(decimals))} decayed-days (raw ${rcfi})`,
      league: `${league} / ${maxLeague}`,
    };
  } catch (e) {
    return { index: `(query failed: ${(e as Error).message})`, league: "N/A" };
  }
}

async function printSmartAccountInfo(
  provider: ethers.JsonRpcProvider,
  token: ReturnType<typeof IERC20__factory.connect>,
  bundlePlugin: ReturnType<typeof ITokenBundle__factory.connect>,
  smartAccountAddr: string,
  erc20Meta: TokenMeta,
) {
  const code = await provider.getCode(smartAccountAddr);
  const deployed = code !== "0x";

  console.log(`\n=== User's smart account: ${smartAccountAddr} ===`);
  console.log(`  Deployed:        ${deployed}`);

  if (!deployed) return;

  const [nativeBalance, erc20Balance, bundleBalance] = await Promise.all([
    provider.getBalance(smartAccountAddr),
    token.balanceOf(smartAccountAddr),
    bundlePlugin.balanceOf(smartAccountAddr, erc20Address).catch(() => 0n),
  ]);

  const bundleBalance2 = bundleBalance / toBigInt(2);
  const personalBalance = erc20Balance - bundleBalance;
  console.log(`  Native balance:  ${formatCoen(nativeBalance)} COEN`);
  console.log(`  ERC20 balance (total):   ${formatTokenMeta(erc20Balance, erc20Meta)}`);
  console.log(`     Bundle:               ${formatTokenMeta(bundleBalance, erc20Meta)} (${formatTokenMeta2(bundleBalance2, erc20Meta)} + ${formatTokenMeta2(bundleBalance2, erc20Meta)})`);
  console.log(`     Personal:             ${formatTokenMeta(personalBalance, erc20Meta)}`);
}

/// Mirrors `enum State` in contracts/precompiles/src/ICredis.sol.
const STATE_NAMES = ["Open", "Called", "Settled", "Void"];

async function printCredisInfo(
  credis: ReturnType<typeof ICredis__factory.connect>,
  smartAccountAddr: string,
  erc20Meta: TokenMeta,
) {
  const [count, hasCalled] = await Promise.all([
    credis.balanceOf(smartAccountAddr).catch(() => 0n),
    credis.hasCalledPosition(smartAccountAddr).catch(() => false),
  ]);

  // The ABI enumerates rather than returning an unbounded array, so walk the
  // owner index one position at a time.
  const positions = await Promise.all(
    Array.from({ length: Number(count) }, (_, i) =>
      credis.positionOfAddressByIndex(smartAccountAddr, i),
    ),
  );

  console.log(`\n=== Credis Positions (smart account: ${smartAccountAddr}) ===`);
  console.log(`  Positions:       ${count} (called: ${hasCalled})`);

  for (const p of positions) {
    const interest = await credis.accruedInterest(p.positionId).catch(() => 0n);
    console.log(`    Position ${p.positionId} :`);
    console.log(`      state: ${STATE_NAMES[Number(p.state)] ?? p.state}`);
    console.log(`      principal: ${formatTokenMeta(p.principal, erc20Meta)}, outstanding: ${formatTokenMeta(p.outstanding, erc20Meta)}`);
    console.log(`      accrued interest: ${formatTokenMeta(interest, erc20Meta)} (policy rate ${formatToken(p.policyRate, 6, "")}/yr, ACT/365)`);
    console.log(`      collateral: ${formatToken(p.collateral, 6, "GRATIS")}, locked: ${formatToken(p.collateralLocked, 6, "GRATIS")}`);
    console.log(`      entry: ${formatToken(p.entryPrice, 6, "")}, call: ${formatToken(p.callPrice, 6, "")}`);
    console.log(`      originated: ${formatDate(p.originatedAt)}, accrual anchor: ${formatDate(p.lastSettledAt)}`);
    if (p.calledAt > 0n) {
      console.log(`      called: ${formatDate(p.calledAt)}`);
    }
  }
}

async function printCcaInfo(
  provider: ethers.JsonRpcProvider,
  token: ReturnType<typeof IERC20__factory.connect>,
  erc20Meta: TokenMeta,
) {
  const [nativeBalance, erc20Balance] = await Promise.all([
    provider.getBalance(ccaAddress),
    token.balanceOf(ccaAddress),
  ]);

  console.log(`\n=== CCA: ${ccaAddress} ===`);
  console.log(`  Native balance:  ${formatCoen(nativeBalance)} COEN`);
  console.log(`  ERC20 balance:   ${formatTokenMeta(erc20Balance, erc20Meta)}`);
}

async function printVaultRouterInfo(
  vaultRouter: ReturnType<typeof IVaultRouter__factory.connect>,
  token: ReturnType<typeof IERC20__factory.connect>,
  assetAddress: string,
  erc20Meta: TokenMeta,
) {
  console.log(`\n=== Vault Router: ${vaultRouterAddress} ===`);

  const vaultCount = await vaultRouter.assetVaultsCount(assetAddress);
  if (vaultCount === 0n) {
    console.log(`  No vaults registered for asset ${assetAddress}`);
    return;
  }

  const underlyingVault = await vaultRouter.assetVaultAt(assetAddress, 0);
  const sharesBalance = await vaultRouter.sharesBalance(underlyingVault);
  const vaultErc20Balance = await token.balanceOf(underlyingVault);

  console.log(`  Underlying Outbe vault:  ${underlyingVault}`);
  console.log(`  Shares balance:          ${sharesBalance}`);
  console.log(`  Vault ERC20 bal:         ${formatTokenMeta(vaultErc20Balance, erc20Meta)}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
