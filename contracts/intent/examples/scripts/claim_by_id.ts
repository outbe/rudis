import { ethers, JsonRpcProvider, formatUnits } from 'ethers';
import { chains, privateKey, ROUTER } from '../config';
import { Router__factory, Auction__factory } from '../typechain';
import { getTokenDecimals, getProviderByDomain, getOrderData } from '../lib/common';

/**
 * Claim an order after quoting ends - locks winner's collateral.
 * If winner lacks collateral, auction restarts automatically.
 *
 * Usage: tsx scripts/claim_by_id.ts <originChain> <orderId>
 */
async function main() {
  console.log('Router - Claim Order\n');

  const [originChain, orderId] = process.argv.slice(2);
  if (!originChain || !orderId) {
    console.error('Usage: tsx scripts/claim_by_id.ts <originChain> <orderId>');
    process.exit(1);
  }
  if (!chains[originChain]) {
    console.error('Invalid chain. Available:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const provider = new JsonRpcProvider(chains[originChain].rpc);
  const wallet = new ethers.Wallet(privateKey!, provider);
  const router = Router__factory.connect(ROUTER, wallet);

  // Read order data from on-chain storage
  const { originData, orderData } = await getOrderData(orderId, router);

  // Connect to destination
  const destWallet = new ethers.Wallet(privateKey!, getProviderByDomain(orderData.destinationDomain));
  const destRouter = Router__factory.connect(ROUTER, destWallet);

  const auction = Auction__factory.connect(await destRouter.AUCTION(), destWallet);

  const outputDecimals = await getTokenDecimals(ethers.toBeHex(orderData.outputToken), destWallet.provider!);
  const [winner, winnerAmount] = await auction.getWinner(orderId);

  console.log('  Winner:', winner);
  console.log('  Bid:', formatUnits(winnerAmount, outputDecimals));

  const tx = await destRouter.claimOrder(orderId, originData);
  const receipt = await tx.wait();

  const CLAIMED = await destRouter.CLAIMED();
  const isClaimed = (await destRouter.orderStatus(orderId)) === CLAIMED;

  console.log(isClaimed
    ? `\nClaimed! tx: ${receipt?.hash}`
    : `\nAuction restarted (winner lacked collateral). tx: ${receipt?.hash}`
  );
}

main()
  .then(() => process.exit(0))
  .catch((error) => { console.error('Error:', error.message); process.exit(1); });
