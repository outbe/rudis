import { ethers, JsonRpcProvider, formatUnits } from 'ethers';
import { chains, ROUTER, privateKey } from '../config';
import { Router__factory, Auction__factory } from '../typechain';
import { getTokenDecimals, getProviderByDomain, getOrderData } from '../lib/common';
import Table from 'cli-table3';

/**
 * List all revealed quotes for a specific order and show the current winner.
 *
 * Usage: tsx scripts/list_quotes.ts <chain> <orderId>
 */
async function main() {
  console.log('Auction - List Quotes\n');

  const [chainName, orderIdHex] = process.argv.slice(2);
  if (!chainName || !orderIdHex) {
    console.error('Usage: tsx scripts/list_quotes.ts <chain> <orderId>');
    process.exit(1);
  }
  if (!chains[chainName]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const chain = chains[chainName];
  const provider = new JsonRpcProvider(chain.rpc);
  const router = Router__factory.connect(ROUTER, provider);

  // Read order data from on-chain storage
  const { orderData } = await getOrderData(orderIdHex, router);

  // Destination chain
  const destProvider = getProviderByDomain(orderData.destinationDomain);
  const destWallet = new ethers.Wallet(privateKey!, destProvider);
  const destRouter = Router__factory.connect(ROUTER, destWallet);

  const inputTokenAddress = ethers.toBeHex(orderData.inputToken);
  const outputTokenAddress = ethers.toBeHex(orderData.outputToken);
  const [inputDecimals, outputDecimals] = await Promise.all([
    getTokenDecimals(inputTokenAddress, provider),
    getTokenDecimals(outputTokenAddress, provider),
  ]);

  console.log(`  Input Token:  ${inputTokenAddress}`);
  console.log(`  Output Token: ${outputTokenAddress}`);
  console.log(`  Amount In:    ${formatUnits(orderData.amountIn, inputDecimals)}`);
  console.log(`  Amount Out:   ${formatUnits(orderData.amountOut, outputDecimals)} (min)`);
  console.log(`  Deadline:     ${new Date(Number(orderData.fillDeadline) * 1000).toISOString()}`);

  const auction = Auction__factory.connect(await destRouter.AUCTION(), destProvider);

  const [commitDeadline, revealDeadline, isAuctionEnded] = await Promise.all([
    auction.getCommitDeadline(orderIdHex),
    auction.getRevealDeadline(orderIdHex),
    auction.isAuctionEnded(orderIdHex),
  ]);

  console.log(`\n  Commit Deadline: ${Number(commitDeadline) > 0 ? new Date(Number(commitDeadline) * 1000).toISOString() : 'N/A'}`);
  console.log(`  Reveal Deadline: ${Number(revealDeadline) > 0 ? new Date(Number(revealDeadline) * 1000).toISOString() : 'N/A'}`);
  console.log(`  Auction Status:  ${isAuctionEnded ? 'Ended' : 'In progress'}\n`);

  const quotes = await auction.getQuotes(orderIdHex);
  if (quotes.length === 0) { console.log('  No quotes revealed yet'); return; }

  console.log(`Found ${quotes.length} revealed quote(s)\n`);

  const sortedQuotes = [...quotes].sort((a, b) => {
    if (a.outputAmount > b.outputAmount) return -1;
    if (a.outputAmount < b.outputAmount) return 1;
    return 0;
  });

  const table = new Table({
    head: ['Rank', 'Solver', 'Output Amount', 'Improvement'],
    style: { head: ['cyan'] },
  });

  for (const [index, quote] of sortedQuotes.entries()) {
    const improvement = ((Number(quote.outputAmount - orderData.amountOut) / Number(orderData.amountOut)) * 100).toFixed(2);
    table.push([
      index === 0 ? '1 (best)' : `${index + 1}`,
      quote.solver,
      formatUnits(quote.outputAmount, outputDecimals),
      `+${improvement}%`,
    ]);
  }

  console.log(table.toString());

  // Winner (Vickrey second-price)
  if (isAuctionEnded) {
    const [winnerAddress, winnerAmount] = await auction.getWinner(orderIdHex);
    const improvement = ((Number(winnerAmount - orderData.amountOut) / Number(orderData.amountOut)) * 100).toFixed(2);
    console.log(`\nWinner: ${winnerAddress}`);
    console.log(`  Pays (2nd price): ${formatUnits(winnerAmount, outputDecimals)} (+${improvement}%)`);
  } else {
    const now = Math.floor(Date.now() / 1000);
    const commitLeft = Number(commitDeadline) - now;
    const revealLeft = Number(revealDeadline) - now;
    if (commitLeft > 0) {
      console.log(`\nCommit phase open. Time left: ${commitLeft}s`);
    } else if (revealLeft > 0) {
      console.log(`\nReveal phase open. Time left: ${revealLeft}s`);
    }
  }

  // Summary
  const avgAmount = quotes.reduce((sum, q) => sum + q.outputAmount, 0n) / BigInt(quotes.length);
  const maxAmount = quotes.reduce((max, q) => (q.outputAmount > max ? q.outputAmount : max), 0n);
  const minAmount = quotes.reduce((min, q) => (q.outputAmount < min ? q.outputAmount : min), quotes[0].outputAmount);

  console.log('\nSummary:');
  console.log(`  Total Quotes:  ${quotes.length}`);
  console.log(`  Average Output: ${formatUnits(avgAmount, outputDecimals)}`);
  console.log(`  Best Output:    ${formatUnits(maxAmount, outputDecimals)}`);
  console.log(`  Worst Output:   ${formatUnits(minAmount, outputDecimals)}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
