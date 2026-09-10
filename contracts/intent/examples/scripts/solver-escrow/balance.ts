import { ethers, JsonRpcProvider, formatUnits } from 'ethers';
import { chains, privateKey, ROUTER } from '../../config';
import { Router__factory, SolverEscrow__factory } from '../../typechain';
import { getTokenDecimals, getTokenSymbol } from '../../lib/common';

/**
 * Show solver collateral balances (total / locked / available).
 *
 * Usage: tsx scripts/solver-escrow/balance.ts <chain> [solver] <token1|native,token2,...>
 *   If solver is omitted, uses PRIVATE_KEY address.
 */
async function main() {
  console.log('SolverEscrow - Balances\n');

  const [chainName, secondArg, thirdArg] = process.argv.slice(2);

  if (!chainName || !secondArg) {
    console.error('Usage: tsx scripts/solver-escrow/balance.ts <chain> [solver] <token1|native,token2,...>');
    process.exit(1);
  }

  if (!chains[chainName]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const chain = chains[chainName];
  const provider = new JsonRpcProvider(chain.rpc);

  // If thirdArg exists: secondArg=solver, thirdArg=tokens. Otherwise: secondArg=tokens.
  const isAddress = secondArg.startsWith('0x') && secondArg.length === 42;
  const solver = ethers.getAddress(
    thirdArg || !isAddress ? (isAddress ? secondArg : new ethers.Wallet(privateKey!).address) : secondArg
  );
  const tokensArg = thirdArg || (!isAddress ? secondArg : undefined);

  if (!tokensArg) {
    console.error('Please specify tokens: native, 0xTokenAddr, or comma-separated list');
    process.exit(1);
  }

  const router = Router__factory.connect(ethers.getAddress(ROUTER), provider);
  const escrowAddress = await router.SOLVER_ESCROW();
  if (escrowAddress === ethers.ZeroAddress) {
    console.error('SolverEscrow not configured on router', ROUTER);
    process.exit(1);
  }

  const escrow = SolverEscrow__factory.connect(ethers.getAddress(escrowAddress), provider);
  const tokens = tokensArg.split(',').map((t) => t.trim() === 'native' ? ethers.ZeroAddress : ethers.getAddress(t.trim()));

  const balances = await escrow.getBalances(solver, tokens);
  const collateralBps = await escrow.collateralBps();

  console.log(`  Chain:         ${chain.name}`);
  console.log(`  Solver:        ${solver}`);
  console.log(`  Escrow:        ${escrowAddress}`);
  console.log(`  CollateralBps: ${collateralBps} (${Number(collateralBps) / 100}%)`);
  console.log();

  for (const info of balances) {
    const decimals = await getTokenDecimals(info.token, provider);
    const symbol = await getTokenSymbol(info.token, provider);

    console.log(`  ${symbol} (${info.token})`);
    console.log(`    Total:     ${formatUnits(info.total, decimals)}`);
    console.log(`    Locked:    ${formatUnits(info.locked, decimals)}`);
    console.log(`    Available: ${formatUnits(info.available, decimals)}`);
    console.log();
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
