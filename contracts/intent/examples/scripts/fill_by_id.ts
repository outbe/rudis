import { ethers, JsonRpcProvider, formatUnits } from 'ethers';
import { chains, privateKey, ROUTER } from '../config';
import { Router__factory, ERC20__factory, Auction__factory } from '../typechain';
import { estimateGasWithBuffer } from '../lib/gasEstimation';
import { getTokenDecimals, getProviderByDomain, getOrderData } from '../lib/common';

/**
 * Fill a specific order by orderId after winning the auction.
 *
 * Usage: tsx scripts/fill_by_id.ts <originChain> <orderId> [fillerAddress]
 */
async function main() {
  console.log('Router - Fill Order by ID\n');

  const [originChain, orderId, fillerAddressArg] = process.argv.slice(2);
  if (!originChain || !orderId) {
    console.error('Usage: tsx scripts/fill_by_id.ts <originChain> <orderId> [fillerAddress]');
    process.exit(1);
  }
  if (!chains[originChain]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const provider = new JsonRpcProvider(chains[originChain].rpc);
  const wallet = new ethers.Wallet(privateKey!, provider);
  const userAddress = await wallet.getAddress();
  const router = Router__factory.connect(ROUTER, wallet);

  // Read order data from on-chain storage
  const { originData, orderData } = await getOrderData(orderId, router);

  // Connect to destination
  const destProvider = getProviderByDomain(orderData.destinationDomain);
  const destWallet = new ethers.Wallet(privateKey!, destProvider);
  const destRouter = Router__factory.connect(ROUTER, destWallet);

  // Get token decimals
  const inputTokenAddress = ethers.toBeHex(orderData.inputToken);
  const outputTokenAddress = ethers.toBeHex(orderData.outputToken);
  const inputDecimals = await getTokenDecimals(inputTokenAddress, provider);
  const outputDecimals = await getTokenDecimals(outputTokenAddress, destProvider);

  console.log('Order Details:');
  console.log(`  User: ${ethers.toBeHex(orderData.sender)}`);
  console.log(`  Amount In: ${formatUnits(orderData.amountIn, inputDecimals)}`);
  console.log(`  Amount Out (min): ${formatUnits(orderData.amountOut, outputDecimals)}`);
  console.log(`  Fill Deadline: ${new Date(Number(orderData.fillDeadline) * 1000).toISOString()}`);

  // Verify order is claimed
  const CLAIMED = await destRouter.CLAIMED();
  if ((await destRouter.orderStatus(orderId)) !== CLAIMED) {
    console.error('Order is not CLAIMED. Must be claimed first (call claimOrder).');
    process.exit(1);
  }

  // Check deadline
  const currentDestBlock = await destProvider.getBlock('latest');
  const currentTime = currentDestBlock?.timestamp || Math.floor(Date.now() / 1000);
  if (currentTime > Number(orderData.fillDeadline)) {
    console.error('Order deadline has passed.');
    process.exit(1);
  }

  // Verify caller is auction winner
  const auction = Auction__factory.connect(await destRouter.AUCTION(), destWallet);
  const [winnerAddress, winnerAmount] = await auction.getWinner(orderId);
  console.log(`\n  Winner: ${winnerAddress}`);
  console.log(`  Winning bid: ${formatUnits(winnerAmount, outputDecimals)}`);

  if (userAddress.toLowerCase() !== winnerAddress.toLowerCase()) {
    console.error('You are not the auction winner:', winnerAddress);
    process.exit(1);
  }

  // Determine filler address for settlement
  const fillerAddress = fillerAddressArg || userAddress;
  const fillerData = ethers.AbiCoder.defaultAbiCoder().encode(
    ['bytes32'],
    [ethers.zeroPadValue(fillerAddress, 32)]
  );

  const isNativeOutput = orderData.outputToken === ethers.zeroPadValue('0x', 32);

  // Approve ERC20 if needed
  if (!isNativeOutput) {
    const outputToken = ERC20__factory.connect(outputTokenAddress, destWallet);
    const currentAllowance = await outputToken.allowance(userAddress, ROUTER);

    if (currentAllowance < winnerAmount) {
      console.log('\nApproving ERC20 token...');
      const approveTx = await outputToken.approve(ROUTER, winnerAmount);
      await approveTx.wait();
      console.log('  Approval confirmed');
    }
  }

  // Fill order
  console.log('\nFilling order...');
  const txParams = isNativeOutput ? { value: winnerAmount } : {};

  const gasLimit = await estimateGasWithBuffer(() =>
    destRouter.fill.estimateGas(orderId, originData, fillerData, txParams)
  );

  const fillTx = await destRouter.fill(orderId, originData, fillerData, { ...txParams, gasLimit });
  const receipt = await fillTx.wait();

  console.log(`\nFilled! tx: ${receipt?.hash}`);
  console.log(`  Gas Used: ${receipt?.gasUsed.toString()}`);
  console.log(`\nNext: settle on origin chain to receive ${formatUnits(orderData.amountIn, inputDecimals)} at ${fillerAddress}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
