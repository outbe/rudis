import { type Address, type Hex, keccak256 } from "viem";

/**
 * Deterministic commit/reveal binding for IntexAuction bids.
 *
 * There is no separate salt. The commit hash is `keccak256(signature)` where
 * `signature` is the EIP-712 RevealBid signature. ECDSA signatures are
 * deterministic (RFC 6979), so re-signing the same (key, day, qty, rate, pair) at
 * reveal reproduces the identical signature - nothing is stored between commit
 * and reveal, and it works across sessions and machines.
 *
 * Scheme (verbatim from contracts/intex/src/target/IntexAuction.sol):
 *  - domain  EIP712("IntexAuction", "1"), chainId = target chain, verifyingContract = auction
 *  - type    RevealBid(uint32 worldwideDay,address bidder,uint16 quantity,uint32 bidRate,
 *            uint16 issuanceCurrency,uint16 referenceCurrency)
 *  - commit  commitHash = keccak256(signature)
 *  - reveal  recovered signer must equal the bidder and keccak256(signature) the commit
 */

export interface RevealBidParams {
  chainId: number;
  verifyingContract: Address;
  worldwideDay: number;
  bidder: Address;
  quantity: number;
  /** Bid rate, scale-1e6 fixed-point (% of strike); 1_000_000 = 100%. Fits uint32. */
  bidRate: number;
  /** Declared issuance currency (ISO 4217 numeric). */
  issuanceCurrency: number;
  /** Reference currency the bid prices in; the day must carry it. */
  referenceCurrency: number;
}

/** The EIP-712 typed-data object for a RevealBid, for viem `signTypedData`. */
export function revealBidTypedData(p: RevealBidParams) {
  return {
    domain: {
      name: "IntexAuction",
      version: "1",
      chainId: p.chainId,
      verifyingContract: p.verifyingContract,
    },
    types: {
      RevealBid: [
        { name: "worldwideDay", type: "uint32" },
        { name: "bidder", type: "address" },
        { name: "quantity", type: "uint16" },
        { name: "bidRate", type: "uint32" },
        { name: "issuanceCurrency", type: "uint16" },
        { name: "referenceCurrency", type: "uint16" },
      ],
    },
    primaryType: "RevealBid",
    message: {
      worldwideDay: p.worldwideDay,
      bidder: p.bidder,
      quantity: p.quantity,
      bidRate: p.bidRate,
      issuanceCurrency: p.issuanceCurrency,
      referenceCurrency: p.referenceCurrency,
    },
  } as const;
}

/** Commit hash = keccak256 of the EIP-712 reveal signature. */
export function commitHash(signature: Hex): Hex {
  return keccak256(signature);
}
