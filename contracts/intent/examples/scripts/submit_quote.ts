import { ethers, JsonRpcProvider, Wallet, parseUnits, formatUnits } from 'ethers';
import { chains, privateKey, ROUTER } from '../config';
import { Router__factory, Auction__factory } from '../typechain';
import { getTokenDecimals, getProviderByDomain, getOrderData, sleep } from '../lib/common';

/**
 * Submit a quote via commit-reveal auction.
 * Commits a blinded hash, waits for the reveal phase, then reveals automatically.
 *
 * Usage: tsx scripts/submit_quote.ts <chain> <orderId> <outputAmount>
 */

async function main() {
  console.log('Auction - Submit Quote (commit-reveal)\n');

  const [chainName, orderIdHex, outputAmount] = process.argv.slice(2);
  if (!chainName || !orderIdHex || !outputAmount) {
    console.error('Usage: tsx scripts/submit_quote.ts <chain> <orderId> <outputAmount>');
    process.exit(1);
  }
  if (!chains[chainName]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const chain = chains[chainName];
  const provider = new JsonRpcProvider(chain.rpc);
  const wallet = new Wallet(privateKey!, provider);
  const solverAddress = await wallet.getAddress();
  const router = Router__factory.connect(ROUTER, wallet);

  // Check order is OPENED
  const OPENED = await router.OPENED();
  const orderStatus = await router.orderStatus(orderIdHex);
  if (orderStatus !== OPENED) { console.error('Order is not OPENED'); process.exit(1); }

  // Read order data from on-chain storage
  const { originData, orderData } = await getOrderData(orderIdHex, router);

  const inputTokenAddress = ethers.toBeHex(orderData.inputToken);
  const outputTokenAddress = ethers.toBeHex(orderData.outputToken);

  // Destination chain
  const destProvider = getProviderByDomain(orderData.destinationDomain);

  // Input decimals from origin, output decimals from destination
  const [inputDecimals, outputDecimals] = await Promise.all([
    getTokenDecimals(inputTokenAddress, provider),
    getTokenDecimals(outputTokenAddress, destProvider),
  ]);

  console.log(`  Input Token:  ${inputTokenAddress}`);
  console.log(`  Output Token: ${outputTokenAddress}`);
  console.log(`  Amount In:    ${formatUnits(orderData.amountIn, inputDecimals)}`);
  console.log(`  Amount Out:   ${formatUnits(orderData.amountOut, outputDecimals)} (min)`);
  console.log(`  Deadline:     ${new Date(Number(orderData.fillDeadline) * 1000).toISOString()}`);

  const destWallet = new ethers.Wallet(privateKey!, destProvider);
  const destRouter = Router__factory.connect(ROUTER, destWallet);

  const auction = Auction__factory.connect(await destRouter.AUCTION(), destWallet);

  // Check if auction already ended
  const isEnded = await auction.isAuctionEnded(orderIdHex);
  if (isEnded) { console.error('Auction has already ended'); process.exit(1); }

  // Check if already committed
  const alreadyCommitted = await auction.hasSolverCommitted(orderIdHex, solverAddress);
  if (alreadyCommitted) { console.error('Already committed for this order'); process.exit(1); }

  const outputAmountWei = parseUnits(outputAmount, outputDecimals);
  if (outputAmountWei < orderData.amountOut) {
    console.error(`Output must be at least ${formatUnits(orderData.amountOut, outputDecimals)}`);
    process.exit(1);
  }

  // Generate random salt
  const salt = ethers.hexlify(ethers.randomBytes(32));

  // Compute commit hash: keccak256(abi.encode(orderId, outputAmount, salt))
  const commitHash = ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ['bytes32', 'uint256', 'bytes32'],
      [orderIdHex, outputAmountWei, salt]
    )
  );

  // === PHASE 1: COMMIT ===
  console.log('\n[1/2] Committing...');
  const commitTx = await auction.commit(orderIdHex, commitHash);
  const commitReceipt = await commitTx.wait();
  console.log(`  Committed! tx: ${commitReceipt?.hash}`);

  // === WAIT FOR REVEAL PHASE ===
  const commitDeadline = await auction.getCommitDeadline(orderIdHex);
  const destBlock = await destProvider.getBlock('latest');
  const now = destBlock!.timestamp;
  const waitSeconds = Number(commitDeadline) - now + 2; // +2s buffer

  if (waitSeconds > 0) {
    console.log(`\n  Waiting ${waitSeconds}s for reveal phase...`);
    await sleep(waitSeconds * 1000);
  }

  // === PHASE 2: REVEAL ===
  console.log('\n[2/2] Revealing...');
  const revealTx = await auction.reveal(orderIdHex, outputAmountWei, salt, originData);
  const revealReceipt = await revealTx.wait();

  const quoteCount = await auction.getQuoteCount(orderIdHex);

  console.log(`  Revealed! tx: ${revealReceipt?.hash}`);
  console.log(`\nQuote submitted!`);
  console.log(`  Solver: ${solverAddress}`);
  console.log(`  Amount: ${outputAmount}`);
  console.log(`  Total quotes for order: ${quoteCount}`);
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
