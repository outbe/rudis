import { ethers, Contract, JsonRpcProvider, Wallet, parseUnits, formatUnits } from 'ethers';
import { chains, privateKey, ROUTER } from '../../config';
import { Router__factory, SolverEscrow__factory, ERC20__factory } from '../../typechain';
import { getTokenDecimals, getTokenSymbol, isNativeToken } from '../../lib/common';

const COMPACT_ABI = [
  'function isOperator(address owner, address operator) view returns (bool)',
  'function setOperator(address operator, bool approved) returns (bool)',
];

/**
 * Deposit solver collateral into SolverEscrow.
 *
 * Usage: tsx scripts/solver-escrow/deposit.ts <chain> <token|native> <amount>
 *
 * Example:
 *   tsx scripts/solver-escrow/deposit.ts outbe_dev 0x5cDF...Ece 100
 *   tsx scripts/solver-escrow/deposit.ts outbe_dev native 0.1
 */
async function main() {
  console.log('SolverEscrow - Deposit\n');

  const [chainName, tokenArg, amountArg] = process.argv.slice(2);

  if (!chainName || !tokenArg || !amountArg) {
    console.error('Usage: tsx scripts/solver-escrow/deposit.ts <chain> <token|native> <amount>');
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
  const native = isNativeToken(token);

  const decimals = await getTokenDecimals(token, provider);
  const symbol = native ? 'Native' : await getTokenSymbol(token, provider);
  const amount = parseUnits(amountArg, decimals);

  console.log(`  Chain:   ${chain.name}`);
  console.log(`  Escrow:  ${escrowAddress}`);
  console.log(`  Solver:  ${userAddress}`);
  console.log(`  Token:   ${token} (${symbol})`);
  console.log(`  Amount:  ${amountArg} ${symbol}`);
  console.log('');

  // Ensure solver has approved escrow as ERC6909 operator on The Compact
  const compactAddress = await escrow.COMPACT();
  const compact = new Contract(compactAddress, COMPACT_ABI, wallet);
  const isOp = await compact.isOperator(userAddress, escrowAddress);
  if (!isOp) {
    console.log('Setting escrow as ERC6909 operator on The Compact...');
    const opTx = await compact.setOperator(escrowAddress, true);
    await opTx.wait();
    console.log('  Operator approved\n');
  }

  // Approve ERC20 if needed
  if (!native) {
    const erc20 = ERC20__factory.connect(token, wallet);
    const allowance = await erc20.allowance(userAddress, escrowAddress);
    if (allowance < amount) {
      console.log('Approving tokens...');
      const tx = await erc20.approve(escrowAddress, amount);
      await tx.wait();
      console.log('  Approved\n');
    }
  }

  console.log('Depositing...');
  const tx = native
    ? await escrow.deposit(ethers.ZeroAddress, 0, { value: amount })
    : await escrow.deposit(token, amount);

  const receipt = await tx.wait();

  // Parse Deposited event
  const log = receipt!.logs
    .map((l) => { try { return escrow.interface.parseLog(l); } catch { return null; } })
    .find((e) => e?.name === 'Deposited');

  console.log('\nDeposit successful!');
  console.log(`  Tx:     ${receipt!.hash}`);
  if (log) {
    console.log(`  Amount: ${formatUnits(log.args.amount, decimals)} ${symbol}`);
  }

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
