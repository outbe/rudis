import { JsonRpcProvider, Wallet, parseUnits } from 'ethers';
import { chains, privateKey, ROUTER, INPUT_TOKEN, OUTPUT_TOKEN, FILL_DEADLINE_SECONDS } from '../config';
import { Router__factory, ERC20__factory } from '../typechain';
import type { OnchainCrossChainOrderStruct } from '../typechain/Router';
import * as OrderEncoder from '../lib/OrderEncoder';
import { estimateGasWithBuffer } from '../lib/gasEstimation';
import { getTokenDecimals, getTokenSymbol, isNativeToken } from '../lib/common';

/**
 * Open a Router cross-chain order.
 *
 * Usage: tsx scripts/open_order.ts <origin> <dest> <amountIn> [amountOut]
 *
 * Example:
 *   tsx scripts/open_order.ts bsc sepolia 1
 *   tsx scripts/open_order.ts bsc sepolia 1 0.5
 */
async function main() {
  console.log('Router - Open Order\n');

  const [originChain = 'bsc', destChain = 'sepolia', amountIn = '1', amountOut = amountIn] =
    process.argv.slice(2);

  if (!chains[originChain] || !chains[destChain]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const origin = chains[originChain];
  const dest = chains[destChain];
  const fillDeadline = Math.floor(Date.now() / 1000) + FILL_DEADLINE_SECONDS;

  const provider = new JsonRpcProvider(origin.rpc);
  const destProvider = new JsonRpcProvider(dest.rpc);
  const wallet = new Wallet(privateKey!, provider);
  const userAddress = await wallet.getAddress();

  const router = Router__factory.connect(ROUTER, wallet);

  const [inputDecimals, outputDecimals, symbol] = await Promise.all([
    getTokenDecimals(INPUT_TOKEN, provider),
    getTokenDecimals(OUTPUT_TOKEN, destProvider),
    getTokenSymbol(INPUT_TOKEN, provider),
  ]);

  const amountInWei = parseUnits(amountIn, inputDecimals);
  const amountOutWei = parseUnits(amountOut, outputDecimals);
  const native = isNativeToken(INPUT_TOKEN);

  console.log(`  Origin:      ${origin.name} (${originChain})`);
  console.log(`  Destination: ${dest.name} (${destChain})`);
  console.log(`  User:        ${userAddress}`);
  console.log(`  Input:       ${amountIn} ${symbol}${native ? ' (native)' : ''}`);
  console.log(`  Output:      ${amountOut}`);
  console.log(`  Deadline:    ${new Date(fillDeadline * 1000).toISOString()} (${FILL_DEADLINE_SECONDS}s)`);
  console.log('');

  // Approve ERC20 if needed
  if (!native) {
    const token = ERC20__factory.connect(INPUT_TOKEN, wallet);
    const allowance = await token.allowance(userAddress, ROUTER);
    if (allowance < amountInWei) {
      console.log('Approving tokens...');
      const tx = await token.approve(ROUTER, amountInWei);
      await tx.wait();
      console.log('  Approved\n');
    }
  }

  const orderData = OrderEncoder.createOrderData({
    sender: userAddress,
    recipient: userAddress,
    inputToken: INPUT_TOKEN,
    outputToken: OUTPUT_TOKEN,
    amountIn: amountInWei,
    amountOut: amountOutWei,
    senderNonce: BigInt(Date.now()),
    originDomain: origin.chainId,
    destinationDomain: dest.chainId,
    destinationSettler: ROUTER,
    fillDeadline: fillDeadline,
    data: '0x',
  });

  const order: OnchainCrossChainOrderStruct = {
    fillDeadline: fillDeadline,
    orderDataType: OrderEncoder.ORDER_DATA_TYPE_HASH,
    orderData: OrderEncoder.encode(orderData),
  };

  console.log('Opening order...');

  const txOptions: any = native ? { value: amountInWei } : {};
  const gasLimit = await estimateGasWithBuffer(() => router.open.estimateGas(order, txOptions));
  txOptions.gasLimit = gasLimit;

  const openTx = await router.open(order, txOptions);
  const receipt = await openTx.wait();

  // Parse orderId from this transaction's own Open event. Reading the block's events instead would
  // pick up orders opened by other senders in the same block and report their id as ours.
  const orderId =
    receipt!.logs
      .map((l) => { try { return router.interface.parseLog(l); } catch { return null; } })
      .find((e) => e?.name === 'Open')?.args.orderId ?? 'Not found';

  console.log('\nOrder created!');
  console.log(`  OrderId: ${orderId}`);
  console.log(`  Tx:      ${receipt!.hash}`);
  console.log(`  Block:   ${receipt!.blockNumber}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error('Error:', error.message);
    process.exit(1);
  });
