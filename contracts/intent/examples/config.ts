import { config as dotenvConfig } from 'dotenv';
import { ethers } from 'ethers';

dotenvConfig();

export interface ChainConfig {
  name: string;
  rpc: string;
  chainId: number;
  /** Decimals of the chain's native token; rudis and standard EVM natives are 18.
   *  Not discoverable over RPC, so it has to be configured per chain. */
  nativeDecimals: number;
}

function requiredAddress(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} must name a confirmed deployment for the selected networks`);
  return ethers.getAddress(value);
}

// Deployment addresses are explicitly configured for each example run.
export const ROUTER = requiredAddress('ROUTER');
export const INPUT_TOKEN = requiredAddress('INPUT_TOKEN');
export const OUTPUT_TOKEN = requiredAddress('OUTPUT_TOKEN');

// Fill deadline (seconds after order creation)
export const FILL_DEADLINE_SECONDS = parseInt(process.env.FILL_DEADLINE_SECONDS || '86400'); // Default: 24 hours

// Number of blocks to query back from current block (for event queries)
// Default: 1999 blocks (safe for most RPC providers that limit to 2000 blocks)
export const QUERY_BLOCKS_BACK = parseInt(process.env.QUERY_BLOCKS_BACK || '1999');

export const chains: Record<string, ChainConfig> = {
  bsc: {
    name: 'BSC Testnet',
    rpc: process.env.BSC_TESTNET_RPC || 'https://bsc-testnet-rpc.publicnode.com',
    chainId: parseInt(process.env.BSC_CHAIN_ID || '97'),
    nativeDecimals: 18,
  },
  sepolia: {
    name: 'Sepolia',
    rpc: process.env.SEPOLIA_RPC || 'https://ethereum-sepolia-rpc.publicnode.com',
    chainId: parseInt(process.env.SEPOLIA_CHAIN_ID || '11155111'),
    nativeDecimals: 18,
  },
  outbe_priv: {
    name: 'Outbe Privnet',
    rpc: process.env.OUTBE_PRIV_RPC || 'https://eth.p.outbe.net',
    chainId: parseInt(process.env.OUTBE_PRIV_CHAIN_ID || '512512'),
    nativeDecimals: 18,
  },

  outbe_dev: {
    name: 'Outbe Devnet',
    rpc: process.env.OUTBE_DEV_RPC || 'https://eth.d.outbe.net',
    chainId: parseInt(process.env.OUTBE_DEV_CHAIN_ID || '424242'),
    nativeDecimals: 18,
  },

  outbe_testnet_old: {
    name: 'Outbe Testnet (old)',
    rpc: process.env.OUTBE_TESTNET_OLD_RPC || 'https://eth.testnet.outbe.net',
    chainId: parseInt(process.env.OUTBE_TESTNET_OLD_CHAIN_ID || '512215'),
    nativeDecimals: 18,
  },

  outbe_testnet: {
    name: 'Rehearsal Network',
    get rpc() {
      if (!process.env.OUTBE_TESTNET_RPC) throw new Error('OUTBE_TESTNET_RPC is required for Rehearsal Network');
      return process.env.OUTBE_TESTNET_RPC;
    },
    chainId: parseInt(process.env.OUTBE_TESTNET_CHAIN_ID || '70860602'),
    nativeDecimals: 18,
  },
};

/** Native decimals keyed by chain id, for lookups that only have a provider. */
export const nativeDecimalsByChainId: Record<number, number> = Object.fromEntries(
  Object.values(chains).map((chain) => [chain.chainId, chain.nativeDecimals])
);

export const privateKey = process.env.PRIVATE_KEY;

if (!privateKey) {
  throw new Error('PRIVATE_KEY not set in .env file');
}
