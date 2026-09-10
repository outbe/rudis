import { ethers, JsonRpcProvider } from 'ethers';
import { chains, privateKey, ROUTER, QUERY_BLOCKS_BACK } from '../config';
import { Router__factory } from '../typechain';
import type { OnchainCrossChainOrderStruct } from '../typechain/Router';
import * as OrderEncoder from '../lib/OrderEncoder';
import { estimateGasWithBuffer, calculateRefundFee } from '../lib/gasEstimation';
import { queryEventsWithChunking } from '../lib/eventQuery';

/**
 * Refund all expired orders in recent blocks.
 *
 * Usage: tsx scripts/refund_all_latest.ts [originChain] [destChain] [blocksBack]
 */
async function main() {
  console.log('Router - Refund All Expired Orders\n');

  const [originChain = 'bsc', destChain = 'sepolia', blocksBackArg] = process.argv.slice(2);
  const blocksBack = blocksBackArg ? parseInt(blocksBackArg) : QUERY_BLOCKS_BACK;

  if (!chains[originChain] || !chains[destChain]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const origin = chains[originChain];
  const dest = chains[destChain];

  const provider = new JsonRpcProvider(origin.rpc);
  const destProvider = new JsonRpcProvider(dest.rpc);
  const wallet = new ethers.Wallet(privateKey!, provider);
  const destWallet = new ethers.Wallet(privateKey!, destProvider);

  const router = Router__factory.connect(ROUTER, wallet);
  const destRouter = Router__factory.connect(ROUTER, destWallet);

  const blockInfo = await provider.getBlock('latest');
  const currentBlock = await provider.getBlockNumber();
  const fromBlock = Math.max(0, currentBlock - blocksBack);

  console.log(`  Origin:      ${origin.name} (${originChain})`);
  console.log(`  Destination: ${dest.name} (${destChain})`);
  console.log(`  Blocks:      ${fromBlock} - ${currentBlock}\n`);

  const events = await queryEventsWithChunking(
    router, router.filters.Open(), fromBlock, currentBlock, provider
  );

  console.log(`Found ${events.length} total orders\n`);
  if (events.length === 0) return;

  const OPENED = await router.OPENED();
  const currentTime = blockInfo?.timestamp || Math.floor(Date.now() / 1000);

  // Filter expired, opened orders matching origin/dest
  const expiredOrders: { orderId: string; order: OnchainCrossChainOrderStruct }[] = [];

  for (const event of events) {
    const originData = event.args.resolvedOrder.fillInstructions[0].originData;
    const orderData = OrderEncoder.decode(originData);

    if (orderData.originDomain != origin.chainId || orderData.destinationDomain != dest.chainId) continue;
    if (currentTime < Number(orderData.fillDeadline)) continue;

    const status = await router.orderStatus(event.args.orderId);
    if (status !== OPENED) continue;

    expiredOrders.push({
      orderId: event.args.orderId,
      order: {
        fillDeadline: Number(orderData.fillDeadline),
        orderDataType: OrderEncoder.ORDER_DATA_TYPE_HASH,
        orderData: originData,
      },
    });
  }

  if (expiredOrders.length === 0) {
    console.log('No expired orders found.');
    return;
  }

  console.log(`Found ${expiredOrders.length} expired orders to refund\n`);

  const ordersToRefund = expiredOrders.map((item) => item.order);
  const orderIds = expiredOrders.map((item) => item.orderId);

  const isSameChain = origin.chainId === dest.chainId;
  let value = 0n;

  if (isSameChain) {
    console.log(`  Same-chain orders - no LZ fee\n`);
  } else {
    const fee = await calculateRefundFee(destRouter, origin.chainId, orderIds);
    value = fee;
    console.log(`  LZ Fee: ${ethers.formatEther(fee)}\n`);
  }

  console.log('Refunding...');
  const gasLimit = await estimateGasWithBuffer(() =>
    destRouter.refund.estimateGas(ordersToRefund, { value })
  );

  const refundTx = await destRouter.refund(ordersToRefund, { value, gasLimit });
  const receipt = await refundTx.wait();

  console.log(`\nRefunded! tx: ${receipt?.hash}`);
  console.log(`  Block:   ${receipt?.blockNumber}`);
  console.log(`  Gas:     ${receipt?.gasUsed.toString()}`);
  console.log(`  Orders:  ${ordersToRefund.length}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
