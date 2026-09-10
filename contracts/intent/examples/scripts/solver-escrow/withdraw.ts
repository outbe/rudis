import { ethers, formatUnits, JsonRpcProvider, Wallet } from 'ethers';
import { chains, privateKey, ROUTER } from '../../config';
import { Router__factory, SolverEscrow__factory } from '../../typechain';
import { getTokenDecimals, getTokenSymbol, isNativeToken } from '../../lib/common';

/**
 * Withdraw solver collateral from SolverEscrow.
 *
 * Usage: tsx scripts/solver-escrow/withdraw.ts <chain> <token|native> <amount>
 *   amount in human-readable units (e.g. 1.5 for 1.5 ETH/tokens)
 *
 * Example:
 *   tsx scripts/solver-escrow/withdraw.ts outbe_dev 0x5cDF...Ece 1.5
 *   tsx scripts/solver-escrow/withdraw.ts outbe_dev native 0.1
 */
async function main() {
  console.log('SolverEscrow - Withdraw\n');

  const [chainName, tokenArg, amountArg] = process.argv.slice(2);

  if (!chainName || !tokenArg || !amountArg) {
    console.error('Usage: tsx scripts/solver-escrow/withdraw.ts <chain> <token|native> <amount|all>');
    console.error('  amount in human-readable units (e.g. 1.5), or "all" to withdraw everything');
    process.exit(1);
  }

  if (!chains[chainName]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const chain = chains[chainName];
  const provider = new JsonRpcProvider(chain.rpc);
  const wallet = new Wallet(privateKey!, provider);
  const userAddress = await wallet.getAddress();

  // Get escrow address from router
  const router = Router__factory.connect(ROUTER, provider);
  const escrowAddress = await router.SOLVER_ESCROW();
  if (escrowAddress === ethers.ZeroAddress) {
    console.error('SolverEscrow not configured on router', ROUTER);
    process.exit(1);
  }

  const escrow = SolverEscrow__factory.connect(escrowAddress, wallet);
  const token = tokenArg === 'native' ? ethers.ZeroAddress : tokenArg;

  const decimals = await getTokenDecimals(token, provider);
  const symbol = isNativeToken(token) ? 'Native' : await getTokenSymbol(token, provider);
  const isAll = amountArg.toLowerCase() === 'all';
  let amount = 0n;
  if (isAll) {
    const balance = await escrow.getBalance(userAddress, token);
    amount = balance.available;
  } else {
    amount = ethers.parseUnits(amountArg, decimals);
  }

  console.log(`  Chain:             ${chain.name}`);
  console.log(`  Escrow:            ${escrowAddress}`);
  console.log(`  Solver:            ${userAddress}`);
  console.log(`  Token:             ${token} (${symbol})`);
  console.log(`  Amount:            ${formatUnits(amount, decimals)} ${symbol}`);
  console.log('');

  console.log('Withdrawing...');
  const tx = await escrow.withdraw(token, amount, { gasLimit: 500_000 });
  const receipt = await tx.wait();

  console.log('\nWithdrawal successful!');
  console.log(`  Tx: ${receipt!.hash}`);

  // Show updated balance
  const balance = await escrow.getBalance(userAddress, token);
  console.log(`\n  Balance after:`);
  console.log(`    Total:     ${formatUnits(balance.total, decimals)} ${symbol}`);
  console.log(`    Locked:    ${formatUnits(balance.locked, decimals)} ${symbol}`);
  console.log(`    Available: ${formatUnits(balance.available, decimals)} ${symbol}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Error:', error.message);
    process.exit(1);
  });
