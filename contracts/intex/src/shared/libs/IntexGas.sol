// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @title IntexGas
/// @author Outbe
/// @notice Transport-independent destination-gas budgets for intex cross-chain messages. The numbers here are the
///         single source of gas policy; each messenger passes the result into `ERC7786MessengerBase._send`, which
///         wraps it as the ERC-7786 executionGasLimit attribute honored by whichever gateway is active. Swapping
///         transport never touches these values.
/// @dev Every budget is 1.5x the measured cost of its heaviest message, taking the failure path where one
///      exists. `test/foundry/cross-chain/GasBudget.t.sol` fails if a formula drifts under the measurement,
///      and measures with `forge test --isolate`: a delivery is its own transaction against cold storage,
///      which the default shared-context run understates by a third or more.
library IntexGas {
    // --- Outbe -> target chain fixed-size messages (TargetRouter handlers) ---
    /// @dev auctionStart creates the series' auction on the target chain.
    /// @notice Fixed head of an AUCTION_STAGE_START, before its price rows.
    /// @dev Measured at ~361k for the six-row maximum.
    uint256 internal constant AUCTION_STAGE_START_BASE = 350_000;
    /// @notice Marginal cost of storing one reference-price row on the target.
    uint256 internal constant AUCTION_STAGE_START_PER_PRICE = 35_000;
    /// @dev Also relays the day's bids from inside the same delivery, a cost the origin cannot see, so the
    ///      target caps that relay and a heavier day parks. Measured at ~5.0M once the cap binds.
    uint256 internal constant AUCTION_STAGE_CLEARING = 7_500_000;
    /// @dev Measured at ~125k.
    uint256 internal constant AUCTION_RESULT = 190_000;
    /// @dev A mark is a bounded state flip, and slotting one for a series that has not landed yet is the
    ///      dearer path, so both budgets are cut from it. Called carries a call time and stores it beside
    ///      the slot, which is why its marginal is the larger of the two. Called measured ~114k at one
    ///      series and ~476k at eight; Qualified ~102k and ~318k.
    uint256 internal constant MARK_CALLED_BASE = 95_000;
    uint256 internal constant MARK_CALLED_PER_SERIES = 78_000;
    uint256 internal constant MARK_QUALIFIED_BASE = 110_000;
    uint256 internal constant MARK_QUALIFIED_PER_SERIES = 47_000;

    /// @notice Ceiling the target puts on one series' mark. Uncapped, a runaway series takes 63/64 of the
    ///         message's gas and starves the slot write, sending the whole batch into endless redelivery.
    ///         Kept under what `markCalled` allows per series so a runaway still fits its own budget.
    uint256 internal constant MARK_APPLY_CAP = 60_000;

    /// @notice Ceiling the target puts on the bids relay an inbound CLEARING fires. Its cost grows with the
    ///         day's bid count, which the origin cannot know, so past this the relay parks for a flush.
    uint256 internal constant RELAY_BIDS_CAP = 5_000_000;
    /// @dev Destination hook for composed proceeds: WCOEN unwrap + IntexFactory distribute registration.
    uint256 internal constant PROCEEDS_COMPOSE = 300_000;

    // --- Variable-size messages: base + per-item marginal ---
    /// @notice Destination gas for a fixed-size BIDS_DONE completeness marker. Measured at ~66k.
    uint256 internal constant BIDS_DONE = 100_000;

    /// @dev Outside the rule: the receiver forwards into the Desis precompile, which no test can execute.
    ///      The router's own share of a 64-bid batch is ~73k; the rest of this stands for the precompile.
    uint256 internal constant BIDS_BASE = 1_300_000;
    uint256 internal constant BIDS_PER_ITEM = 160_000;
    /// @dev Handler overhead only; createSeries is charged per series. Measured ~6.02M for the widest chunk.
    uint256 internal constant ISSUANCE_BASE = 200_000;
    uint256 internal constant ISSUANCE_PER_SERIES = 305_000;
    uint256 internal constant ISSUANCE_PER_ITEM = 270_000;
    /// @dev Measured at ~3.31M for a full 64-bidder chunk, and ~440k for a two-bidder one: the
    ///      chunk completing a day also routes the paid wCOEN home at a fixed cost, which lands on
    ///      the base. `LocalLoopback.t.sol` walks the narrow case.
    uint256 internal constant REFUND_BASE = 500_000;
    uint256 internal constant REFUND_PER_ITEM = 75_000;
    /// @dev Sized on the failure path: a rejected item is recorded with its revert bytes while the tokens
    ///      are already burned on the source. Measured ~4.64M for a full rejected batch.
    uint256 internal constant NFT_MINT_BASE = 150_000;
    uint256 internal constant NFT_MINT_PER_ITEM = 430_000;

    /// @notice Destination gas for a BIDS_BATCH carrying `itemCount` bids.
    function bidsBatch(uint256 itemCount) internal pure returns (uint256) {
        return BIDS_BASE + itemCount * BIDS_PER_ITEM;
    }

    /// @notice Destination gas for an AUCTION_STAGE_START carrying `priceCount` rows.
    function auctionStart(uint256 priceCount) internal pure returns (uint256) {
        return AUCTION_STAGE_START_BASE + priceCount * AUCTION_STAGE_START_PER_PRICE;
    }

    /// @notice Destination gas for an ISSUANCE_INSTRUCTIONS creating `seriesCount` series and
    ///         minting to `recipientCount` recipients.
    function issuance(uint256 seriesCount, uint256 recipientCount) internal pure returns (uint256) {
        return ISSUANCE_BASE + seriesCount * ISSUANCE_PER_SERIES + recipientCount * ISSUANCE_PER_ITEM;
    }

    /// @notice Destination gas for a MARK_CALLED carrying `seriesCount` series.
    function markCalled(uint256 seriesCount) internal pure returns (uint256) {
        return MARK_CALLED_BASE + seriesCount * MARK_CALLED_PER_SERIES;
    }

    /// @notice Destination gas for a MARK_QUALIFIED carrying `seriesCount` series.
    function markQualified(uint256 seriesCount) internal pure returns (uint256) {
        return MARK_QUALIFIED_BASE + seriesCount * MARK_QUALIFIED_PER_SERIES;
    }

    /// @notice Destination gas for a REFUND_INSTRUCTIONS with `bidderCount` bidders.
    function refund(uint256 bidderCount) internal pure returns (uint256) {
        return REFUND_BASE + bidderCount * REFUND_PER_ITEM;
    }

    /// @notice Destination gas for a bridge batch/multi message crosschainMinting `itemCount` items.
    function nftMint(uint256 itemCount) internal pure returns (uint256) {
        return NFT_MINT_BASE + itemCount * NFT_MINT_PER_ITEM;
    }
}
