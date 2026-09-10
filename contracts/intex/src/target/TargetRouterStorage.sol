// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IIntexAuction} from "./interfaces/IIntexAuction.sol";
import {IIntexNFT1155} from "../shared/interfaces/IIntexNFT1155.sol";
import {IEscrowAdapter} from "./interfaces/IEscrowAdapter.sol";
import {IERC7786TokenBridge} from "./interfaces/IERC7786TokenBridge.sol";

/// @notice A bids relay parked because its outbound send reverted (e.g. relay float too low); retried via
///         `flushPendingBidsRelay`. Bids stay in auction state, so only the worldwideDay is snapshotted.
struct PendingBidsRelay {
    uint32 worldwideDay;
    bool exists;
    bool done;
}

/// @notice An issuance parked because a recipient's ERC-1155 receiver hook reverted; retried via
///         `flushPendingIssuance`.
struct PendingIssuance {
    bytes14 seriesId;
    address recipient;
    uint256 quantity;
    bool exists;
    bool done;
}

/// @custom:storage-location erc7201:outbe.intex.TargetRouter
struct TargetRouterStorage {
    /// @dev Auction contract that originates outbound bids and receives inbound stage transitions.
    IIntexAuction auction;
    /// @dev IntexNFT1155 contract that issuance, mark-called, and mark-qualified messages apply to.
    IIntexNFT1155 intex;
    /// @dev EscrowAdapter contract that refund instructions are forwarded to for finalization.
    IEscrowAdapter escrowAdapter;
    /// @dev Parked BIDS_BATCH relays awaiting permissionless retry, keyed by enqueue index.
    mapping(uint256 idx => PendingBidsRelay) pendingBidsRelays;
    /// @dev Next index to assign in `pendingBidsRelays`; also the count of relays ever enqueued.
    uint256 nextPendingBidsRelayIdx;
    /// @dev Monotonic per-series counter stamped on every BIDS_BATCH send/flush. The Outbe receiver
    ///      replaces a lower generation's bids when a higher one arrives, so re-flushing a parked
    ///      relay cannot double-count demand.
    mapping(uint32 worldwideDay => uint32 generation) bidsRelayGeneration;
    /// @dev Parked issuances awaiting permissionless retry, keyed by enqueue index.
    mapping(uint256 idx => PendingIssuance) pendingIssuances;
    /// @dev Next index to assign in `pendingIssuances`; also the count ever enqueued.
    uint256 nextPendingIssuanceIdx;
    /// @dev Composed-transfer token bridge that routes auction proceeds to Outbe.
    IERC7786TokenBridge tokenBridge;
    /// @dev OriginRouter address on Outbe that receives and distributes the proceeds.
    address originRouter;
    /// @dev Parked proceeds routes awaiting permissionless retry, keyed by enqueue index.
    mapping(uint256 idx => PendingProceedsRoute) pendingProceedsRoutes;
    /// @dev Next index to assign in `pendingProceedsRoutes`; also the count ever enqueued.
    uint256 nextPendingProceedsRouteIdx;
    /// @dev Set once the CLEARING for a day has triggered its bids relay, so a redelivered CLEARING never
    ///      re-relays under a fresh generation.
    mapping(uint32 worldwideDay => bool relayed) clearingRelayed;
    /// @dev Bit per applied refund chunk, so a redelivered one neither re-counts nor
    ///      completes the day. One word covers `MAX_CHUNKS`.
    mapping(uint32 worldwideDay => uint256 bitmap) refundChunksApplied;
    /// @dev Proceeds accrued so far, routed as one transfer once every chunk has arrived:
    ///      the origin marks a chain paid on first delivery, so a partial sum closes the
    ///      creator-reward fan-in early.
    mapping(uint32 worldwideDay => uint128 accrued) refundProceedsAccrued;
    /// @dev How many of the day's refund chunks have been applied.
    mapping(uint32 worldwideDay => uint16 applied) refundChunksSeen;
    /// @dev How many refund chunks the day's run spans, as the first applied chunk declared; a chunk
    ///      claiming another total is a conflict, so an under-totaled header cannot close the day early.
    mapping(uint32 worldwideDay => uint16 total) refundTotalChunks;
    /// @dev Lifecycle mark waiting for its series to land here (codec msgType, 0 = none); Called overrides
    ///      Qualified. Applied when ISSUANCE creates the series, or via `applyPendingMark`.
    mapping(bytes14 seriesId => uint8 msgType) pendingMark;
    /// @dev The origin's call time for a waiting Called mark, so a slot applied later still derives the
    ///      deadline settlement honours rather than one from its own arrival.
    mapping(bytes14 seriesId => uint32 calledAt) pendingMarkCalledAt;
    /// @dev Winners already issued their allocation of a series; a repeated instruction for the pair is ignored.
    mapping(bytes14 seriesId => mapping(address recipient => bool issued)) issued;
    /// @dev How many issuance chunks the day's run spans on this chain, as the first applied chunk declared.
    mapping(uint32 worldwideDay => uint16 total) issuanceTotalChunks;
    /// @dev How many of the day's issuance chunks have been applied.
    mapping(uint32 worldwideDay => uint16 seen) issuanceChunksSeen;
    /// @dev Issuance chunks already applied, so a repeat neither issues nor counts.
    mapping(uint32 worldwideDay => mapping(uint16 chunkIndex => bool applied)) issuanceChunkApplied;
}

/// @notice A proceeds route parked because its outbound send reverted (e.g. relay float too low); retried
///         via `flushPendingProceedsRoute`. The WCOEN is already held here, so only series+amount is snapshotted.
struct PendingProceedsRoute {
    uint32 worldwideDay;
    uint128 amount;
    bool exists;
    bool done;
}
