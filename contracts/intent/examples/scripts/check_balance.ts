import { ethers, JsonRpcProvider, formatUnits } from 'ethers';
import { chains, INPUT_TOKEN, OUTPUT_TOKEN } from '../config';
import { ERC20__factory } from '../typechain';
import { getTokenDecimals } from '../lib/common';
import Table from 'cli-table3';

/**
 * Check INPUT_TOKEN and OUTPUT_TOKEN balances on origin/destination chains.
 *
 * Usage: tsx scripts/check_balance.ts <address> [originChain] [destChain]
 */
async function main() {
  console.log('Router - Check Balance\n');

  const [address, originChainName = 'bsc', destChainName = 'outbe_dev'] = process.argv.slice(2);
  if (!address || !ethers.isAddress(address)) {
    console.error('Usage: tsx scripts/check_balance.ts <address> [originChain] [destChain]');
    process.exit(1);
  }
  if (!chains[originChainName]) {
    console.error('Invalid origin chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }
  if (!chains[destChainName]) {
    console.error('Invalid dest chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const originChain = chains[originChainName];
  const destChain = chains[destChainName];

  console.log(`  Address:     ${address}`);
  console.log(`  Origin:      ${originChain.name} (${originChainName})`);
  console.log(`  Destination: ${destChain.name} (${destChainName})`);
  console.log(`  Input Token: ${INPUT_TOKEN}`);
  console.log(`  Output Token: ${OUTPUT_TOKEN}\n`);

  const originProvider = new JsonRpcProvider(originChain.rpc);
  const destProvider = new JsonRpcProvider(destChain.rpc);

  async function tokenBalance(
    tokenAddr: string,
    provider: JsonRpcProvider,
  ): Promise<{ symbol: string; balance: string }> {
    if (tokenAddr === ethers.ZeroAddress) {
      const bal = await provider.getBalance(address);
      const decimals = await getTokenDecimals(tokenAddr, provider);
      return { symbol: 'NATIVE', balance: formatUnits(bal, decimals) };
    }
    const token = ERC20__factory.connect(tokenAddr, provider);
    const decimals = await getTokenDecimals(tokenAddr, provider);
    const bal = await token.balanceOf(address);
    let symbol: string;
    try { symbol = await token.symbol(); } catch { symbol = 'UNKNOWN'; }
    return { symbol, balance: formatUnits(bal, decimals) };
  }

  const [input, output] = await Promise.all([
    tokenBalance(INPUT_TOKEN, originProvider),
    tokenBalance(OUTPUT_TOKEN, destProvider),
  ]);

  const table = new Table({
    head: ['Chain', 'Token Type', 'Token Address', 'Symbol', 'Balance'],
    style: { head: ['cyan'] },
  });

  table.push(
    [originChain.name, 'INPUT_TOKEN', INPUT_TOKEN, input.symbol, input.balance],
    [destChain.name, 'OUTPUT_TOKEN', OUTPUT_TOKEN, output.symbol, output.balance],
  );

  console.log(table.toString());
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
