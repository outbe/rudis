import { ethers, JsonRpcProvider } from 'ethers';
import { chains, privateKey, ROUTER } from '../config';
import { Router__factory } from '../typechain';
import type { OnchainCrossChainOrderStruct } from '../typechain/Router';
import * as OrderEncoder from '../lib/OrderEncoder';
import { estimateGasWithBuffer, calculateRefundFee } from '../lib/gasEstimation';
import { getProviderByDomain, getOrderData } from '../lib/common';

/**
 * Refund a specific order by orderId. Auto-detects destination chain.
 *
 * Usage: tsx scripts/refund_by_id.ts <originChain> <orderId>
 */
async function main() {
  console.log('Router - Refund Order by ID\n');

  const [originChain, orderId] = process.argv.slice(2);
  if (!originChain || !orderId) {
    console.error('Usage: tsx scripts/refund_by_id.ts <originChain> <orderId>');
    process.exit(1);
  }
  if (!chains[originChain]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const origin = chains[originChain];
  const provider = new JsonRpcProvider(origin.rpc);
  const wallet = new ethers.Wallet(privateKey!, provider);
  const router = Router__factory.connect(ROUTER, wallet);

  // Read order data from on-chain storage
  const blockInfo = await provider.getBlock('latest');
  const { originData, orderData } = await getOrderData(orderId, router);

  // Destination chain
  const destProvider = getProviderByDomain(orderData.destinationDomain);
  const destWallet = new ethers.Wallet(privateKey!, destProvider);
  const destRouter = Router__factory.connect(ROUTER, destWallet);

  console.log(`  User:     ${orderData.sender}`);
  console.log(`  Amount In:  ${ethers.formatEther(orderData.amountIn)}`);
  console.log(`  Amount Out: ${ethers.formatEther(orderData.amountOut)}`);
  console.log(`  Deadline:   ${new Date(Number(orderData.fillDeadline) * 1000).toISOString()}`);

  // Verify status is OPENED
  const OPENED = await router.OPENED();
  const status = await router.orderStatus(orderId);
  if (status !== OPENED) {
    console.error('Order is not OPENED. Cannot refund.');
    process.exit(1);
  }

  // Verify deadline passed
  const currentTime = blockInfo?.timestamp || Math.floor(Date.now() / 1000);
  const deadline = Number(orderData.fillDeadline);
  if (currentTime < deadline) {
    console.error(`Deadline not passed. Remaining: ${Math.floor((deadline - currentTime) / 60)} minutes`);
    process.exit(1);
  }

  const order: OnchainCrossChainOrderStruct = {
    fillDeadline: deadline,
    orderDataType: OrderEncoder.ORDER_DATA_TYPE_HASH,
    orderData: originData,
  };

  const isSameChain = Number(orderData.originDomain) === Number(orderData.destinationDomain);
  let value = 0n;

  if (isSameChain) {
    console.log(`\n  Same-chain order - no LZ fee\n`);
  } else {
    const fee = await calculateRefundFee(destRouter, origin.chainId, [orderId]);
    value = fee;
    console.log(`\n  LZ Fee: ${ethers.formatEther(fee)}\n`);
  }

  console.log('Refunding...');
  const gasLimit = await estimateGasWithBuffer(() =>
    destRouter.refund.estimateGas([order], { value })
  );

  const refundTx = await destRouter.refund([order], { value, gasLimit });
  const receipt = await refundTx.wait();

  console.log(`\nRefunded! tx: ${receipt?.hash}`);
  console.log(`  Block: ${receipt?.blockNumber}`);
  console.log(`  Gas:   ${receipt?.gasUsed.toString()}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
