import type { Provider, ContractEventName, BaseContract } from 'ethers';

/**
 * Event query utilities
 */

/**
 * Queries contract events with automatic chunking to avoid RPC limits
 * @param contract - Contract instance
 * @param filter - Event filter
 * @param fromBlock - Starting block number
 * @param toBlock - Ending block number or 'latest'
 * @param provider - Provider instance
 * @param chunkSize - Maximum blocks per query (default: 50000)
 * @returns Array of events
 */
export async function queryEventsWithChunking<T extends BaseContract>(
  contract: T,
  filter: any,
  fromBlock: number,
  toBlock: number | 'latest',
  provider: Provider,
  chunkSize: number = 50000
): Promise<any[]> {
  const currentBlock = toBlock === 'latest' ? await provider.getBlockNumber() : toBlock;

  let events: any[] = [];
  let startBlock = fromBlock;

  while (startBlock <= currentBlock) {
    const endBlock = Math.min(startBlock + chunkSize - 1, currentBlock);
    console.log(`  Querying blocks ${startBlock} to ${endBlock}...`);

    const chunkEvents = await contract.queryFilter(filter, startBlock, endBlock);
    events = events.concat(chunkEvents);

    startBlock = endBlock + 1;
  }

  return events;
}
