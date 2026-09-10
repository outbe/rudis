import { ethers, JsonRpcProvider } from 'ethers';
import { chains, privateKey, ROUTER } from '../config';
import { Router__factory } from '../typechain';
import { estimateGasWithBuffer, calculateSettleFee } from '../lib/gasEstimation';
import { getProviderByDomain, getOrderData } from '../lib/common';

/**
 * Settle a filled order by orderId. Sends cross-chain message to pay the filler.
 *
 * Usage: tsx scripts/settle_by_id.ts <originChain> <orderId>
 */
async function main() {
  console.log('Router - Settle Order by ID\n');

  const [originChain, orderId] = process.argv.slice(2);
  if (!originChain || !orderId) {
    console.error('Usage: tsx scripts/settle_by_id.ts <originChain> <orderId>');
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
  const { orderData } = await getOrderData(orderId, router);

  // Destination chain
  const destProvider = getProviderByDomain(orderData.destinationDomain);
  const destWallet = new ethers.Wallet(privateKey!, destProvider);
  const destRouter = Router__factory.connect(ROUTER, destWallet);

  console.log(`  User:       ${orderData.sender}`);
  console.log(`  Amount In:  ${ethers.formatEther(orderData.amountIn)}`);
  console.log(`  Amount Out: ${ethers.formatEther(orderData.amountOut)}`);

  // Verify FILLED status on destination
  const FILLED = await destRouter.FILLED();
  const status = await destRouter.orderStatus(orderId);
  if (status !== FILLED) {
    console.error('Order is not FILLED on destination. Cannot settle.');
    process.exit(1);
  }

  // Read filler data from on-chain storage
  const [, fillerData] = await destRouter.filledOrders(orderId);
  if (!fillerData || fillerData === '0x') { console.error('Filled order not found'); process.exit(1); }
  const fillerAddress = ethers.AbiCoder.defaultAbiCoder().decode(['bytes32'], fillerData)[0];
  const fillerAddressHex = ethers.getAddress('0x' + fillerAddress.slice(26));

  console.log(`  Filler:     ${fillerAddressHex}\n`);

  const isSameChain = Number(orderData.originDomain) === Number(orderData.destinationDomain);
  let value = 0n;

  if (isSameChain) {
    console.log(`  Same-chain order - no LZ fee\n`);
  } else {
    const fee = await calculateSettleFee(destRouter, origin.chainId, [orderId], [fillerData]);
    value = fee;
    console.log(`  LZ Fee: ${ethers.formatEther(fee)}\n`);
  }

  console.log('Settling...');
  const gasLimit = await estimateGasWithBuffer(() =>
    destRouter.settle.estimateGas([orderId], { value })
  );

  const settleTx = await destRouter.settle([orderId], { value, gasLimit });
  const receipt = await settleTx.wait();

  console.log(`\nSettled! tx: ${receipt?.hash}`);
  console.log(`  Block: ${receipt?.blockNumber}`);
  console.log(`  Gas:   ${receipt?.gasUsed.toString()}`);
  console.log(`\nFiller ${fillerAddressHex} will receive ${ethers.formatEther(orderData.amountIn)} on ${origin.name}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
