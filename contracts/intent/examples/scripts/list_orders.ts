import { ethers, JsonRpcProvider, formatUnits } from 'ethers';
import { chains, ROUTER, QUERY_BLOCKS_BACK } from '../config';
import { Router__factory } from '../typechain';
import * as OrderEncoder from '../lib/OrderEncoder';
import { queryEventsWithChunking } from '../lib/eventQuery';
import { getProviderByDomain, getTokenDecimals } from '../lib/common';
import Table from 'cli-table3';

/**
 * List all Router orders from recent Open events.
 *
 * Usage: tsx scripts/list_orders.ts [chain]
 */
async function main() {
  console.log('Router - List Orders\n');

  const [chainName = 'bsc'] = process.argv.slice(2);
  if (!chains[chainName]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const chain = chains[chainName];
  const provider = new JsonRpcProvider(chain.rpc);
  const router = Router__factory.connect(ROUTER, provider);

  const currentBlock = await provider.getBlockNumber();
  const fromBlock = Math.max(0, currentBlock - QUERY_BLOCKS_BACK);

  console.log(`  Chain: ${chain.name} (${chainName})`);
  console.log(`  Blocks: ${fromBlock} - ${currentBlock}`);
  console.log(`  Router: ${ROUTER}\n`);

  const events = await queryEventsWithChunking(
    router, router.filters.Open(), fromBlock, currentBlock, provider
  );

  console.log(`Found ${events.length} orders\n`);
  if (events.length === 0) return;

  const [OPENED, FILLED, REFUNDED, SETTLED] = await Promise.all([
    router.OPENED(), router.FILLED(), router.REFUNDED(), router.SETTLED(),
  ]);

  const orders = await Promise.all(
    events.map(async (event) => {
      const orderId = event.args.orderId;
      const originData = event.args.resolvedOrder.fillInstructions[0].originData;
      const orderData = OrderEncoder.decode(originData);
      const destProvider = getProviderByDomain(orderData.destinationDomain);

      const inputTokenAddress = ethers.toBeHex(orderData.inputToken);
      const outputTokenAddress = ethers.toBeHex(orderData.outputToken);
      const [inputDecimals, outputDecimals, status] = await Promise.all([
        getTokenDecimals(inputTokenAddress, provider),
        getTokenDecimals(outputTokenAddress, destProvider),
        router.orderStatus(orderId),
      ]);

      let statusText = 'UNKNOWN';
      if (status === OPENED) statusText = 'OPENED';
      else if (status === FILLED) statusText = 'FILLED';
      else if (status === SETTLED) statusText = 'SETTLED';
      else if (status === REFUNDED) statusText = 'REFUNDED';

      const deadline = new Date(Number(orderData.fillDeadline) * 1000);
      if (statusText === 'OPENED' && new Date() > deadline) statusText = 'EXPIRED';

      return {
        orderId: ethers.toBeHex(orderId),
        user: ethers.toBeHex(orderData.sender),
        inputToken: inputTokenAddress,
        outputToken: outputTokenAddress,
        amountIn: formatUnits(orderData.amountIn, inputDecimals),
        amountOut: formatUnits(orderData.amountOut, outputDecimals),
        originDomain: orderData.originDomain,
        destDomain: orderData.destinationDomain,
        deadline: deadline.toISOString().slice(0, 19).replace('T', ' '),
        status: statusText,
      };
    })
  );

  const table = new Table({
    head: ['OrderId', 'User', 'In Token', 'Out Token', 'Amount In', 'Amount Out', 'Origin', 'Dest', 'Deadline', 'Status'],
    style: { head: ['cyan'] },
  });

  for (const o of orders) {
    table.push([
      o.orderId.slice(0, 10) + '...', o.user, o.inputToken, o.outputToken,
      o.amountIn, o.amountOut, o.originDomain, o.destDomain, o.deadline, o.status,
    ]);
  }

  console.log(table.toString());

  const statusCounts = orders.reduce((acc, o) => {
    acc[o.status] = (acc[o.status] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  console.log('\nSummary:');
  console.log(`  Total: ${orders.length}`);
  for (const [status, count] of Object.entries(statusCounts)) {
    console.log(`  ${status}: ${count}`);
  }
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
