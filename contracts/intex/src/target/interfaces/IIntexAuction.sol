// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/**
 * @title IntexAuction Contract Interfaces
 * @author Outbe
 * @notice Public API, events, errors, and data types for `IntexAuction`.
 * @dev All auctions are keyed by `worldwideDay` (uint32, yyyymmdd).
 */
interface IIntexAuction {
    // --- Types ---

    /// @notice Auction lifecycle stages.
    enum AuctionStage {
        CommittingBids,
        RevealingBids,
        Issuance,
        Completed,
        Cancelled
    }

    /// @notice Worldwide-day state, final at `auctionStart`.
    /// @dev `Green` = live auction, `Red` = cancelled record; `Unknown` never persists.
    enum WorldwideDayState {
        Unknown,
        Green,
        Red
    }

    /// @notice Revealed bid payload. Slot-packed: slot 0 holds
    ///         `bidderAddress` (20B) + `intexBidRate` (4B) + `intexQuantity` (2B) + `timestamp` (4B) = 30B.
    struct SubmittedBidData {
        /// @notice Bidder IBA address.
        address bidderAddress;
        /// @notice Bid rate the bidder accepts (`1e6` fixed-point, % of the escrow basis).
        uint32 intexBidRate;
        /// @notice Requested quantity (Intex units).
        uint16 intexQuantity;
        /// @notice Timestamp assigned at reveal (ordering only).
        uint32 timestamp;
        /// @notice Declared issuance currency (ISO numeric).
        uint16 issuanceCurrency;
        /// @notice Reference currency the bid prices in (ISO numeric).
        uint16 referenceCurrency;
    }

    /// @notice Auction schedule - stage-end timestamps.
    /// @dev Computed on the Outbe side (Desis) and passed into `auctionStart`.
    struct AuctionSchedule {
        /// @notice End of the commit stage (UNIX seconds).
        uint32 commitEnd;
        /// @notice End of the reveal stage (UNIX seconds).
        uint32 revealEnd;
        /// @notice End of the issuance stage (UNIX seconds).
        uint32 issuanceEnd;
    }

    /// @notice Call-trigger parameters governing when a series is forced into Called.
    struct IntexCallTrigger {
        /// @notice Call-trigger observation window in seconds.
        uint32 callWindow;
        /// @notice Call-trigger threshold in seconds.
        uint32 callThreshold;
        /// @notice Called->deadline window in seconds; stored verbatim, the issuer must supply a non-zero value.
        uint32 callNoticePeriod;
    }

    /// @notice Entry, floor and call price of one reference currency for a day.
    struct ReferenceCurrencyPrice {
        uint16 isoCode;
        uint64 entryPriceMinor;
        uint64 floorPriceMinor;
        uint64 callPriceMinor;
    }

    /// @notice Auction input parameters, stored per auction.
    struct AuctionParams {
        /// @notice PROMIS-units per Intex unit (1e6).
        uint128 promisLoadMinor;
        /// @notice Call-trigger parameters (window/threshold/period).
        IntexCallTrigger callTrigger;
        /// @notice Minimum allowed bid rate (`1e6` fixed-point, % of the escrow basis); rejects bids below it on reveal.
        uint32 minIntexBidRate;
        /// @notice Minimum quantity per bid (Intex units).
        uint16 minIntexBidQuantity;
        /// @notice One row per currency the day can clear in; the bid's reference
        ///         currency must appear here.
        ReferenceCurrencyPrice[] prices;
        /// @notice Entry bond (payment-token minor units) taken at `commitBid` and returned on
        ///         reveal/cancel; 0 disables the bond.
        uint128 commitBondMinor;
    }

    /// @notice Auction results and statistics (final, set at clearing).
    struct AuctionResult {
        /// @notice Uniform auction clearing rate (`1e6` fixed-point) used to issue Intex.
        uint64 auctionClearingRate;
        /// @notice Number of winning bids (provided by Outbe).
        uint32 wonBidsCount;
        /// @notice Number of Intex units issued.
        uint32 issuedIntexCount;
        /// @notice Total Promis loaded into the issued Intex (`issuedIntexCount * promisLoadMinor`); derived on-chain at clearing.
        uint128 issuedIntexLoadedPromis;
    }

    /// @notice Live bid counters tracked while the auction runs.
    struct AuctionRunningCounts {
        uint32 committedBidsCount;
        uint32 revealedBidsCount;
    }

    /// @notice Auction parameters and state, keyed by `worldwideDay`.
    struct AuctionData {
        WorldwideDayState worldwideDayState;
        AuctionSchedule schedule;
        AuctionParams params;
        AuctionResult result;
    }

    // --- Events ---

    /// @notice Emitted when the auction stage is updated.
    /// @param worldwideDay Worldwide day (yyyymmdd, uint32).
    /// @param auctionStage Target stage.
    /// @param timestamp New stage timestamp (UNIX seconds).
    /// @param reason Optional reason (e.g. "Red day - auction cancelled"); empty if not applicable.
    event AuctionStageUpdated(uint32 indexed worldwideDay, AuctionStage auctionStage, uint32 timestamp, string reason);

    /// @notice Emitted when an auction is cleared.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param auctionClearingRate Uniform auction clearing rate (`1e6` fixed-point).
    /// @param issuedIntexCount Total number of issued Intex units.
    event AuctionClearingExecuted(uint32 indexed worldwideDay, uint64 auctionClearingRate, uint32 issuedIntexCount);

    /// @notice Emitted on `commitBid` with the sealed commit hash.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address (commit owner).
    /// @param commitHash The committed `keccak256(signature)`.
    event BidCommitted(uint32 indexed worldwideDay, address indexed bidder, bytes32 commitHash);

    /// @notice Emitted on `revealBid` after a successful reveal.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address.
    /// @param quantity Revealed Intex quantity.
    /// @param bidRate Revealed bid rate (`1e6` fixed-point, % of the escrow basis).
    event BidRevealed(
        uint32 indexed worldwideDay,
        address indexed bidder,
        uint16 indexed quantity,
        uint32 bidRate,
        uint16 issuanceCurrency,
        uint16 referenceCurrency
    );

    /// @notice Emitted on `cancelCommit` after the bidder withdraws their commit during the commit stage.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address.
    event CommitCancelled(uint32 indexed worldwideDay, address indexed bidder);
    /// @notice A terminal auction's stored revealed-bid records were reclaimed; `remaining` still to reap.
    event AuctionReaped(uint32 indexed worldwideDay, uint256 remaining);

    /// @notice Emitted on `wire` after the escrow contract address is set.
    /// @param previous Escrow contract address before the update.
    /// @param current Escrow contract address after the update.
    event EscrowWired(address previous, address current);

    // --- Errors ---

    /// @notice Zero address provided.
    /// @param f Field name.
    error ZeroAddress(string f);
    /// @notice Zero value provided where non-zero is required.
    /// @param f Field name.
    error ZeroValue(string f);
    /// @notice Operation requires a different stage.
    error StageRequired(AuctionStage requiredStage, AuctionStage currentStage);
    /// @notice `reapAuction` was called before the auction passed its issuance deadline.
    error TooEarlyToReap();
    /// @notice Commit already registered for this bidder in this auction.
    error BidAlreadyCommitted();
    /// @notice Commit not found for this bidder in this auction.
    error BidNotFound();
    /// @notice Bid already revealed for this bidder in this auction.
    error BidAlreadyRevealed();
    /// @notice Reveal payload does not match the commit hash.
    error RevealHashMismatch();
    /// @notice Bid rate is below `minIntexBidRate`.
    error BidBelowMinIntexBidRate();
    /// @notice Bid rate exceeds 100% of the escrow basis (scale `1e6`).
    error BidRateAboveMax(uint32 bidRate);
    /// @notice Bid quantity is below `minIntexBidQuantity`.
    error BidBelowMinIntexBidQuantity();
    /// @notice The 18-decimal WCOEN lock derived from protocol-scale inputs exceeds uint128.
    error BidAmountOverflow(uint16 quantity, uint32 bidRate);
    /// @notice `issuedIntexCount * promisLoadMinor` exceeds the uint128 loaded-Promis range.
    error IssuedPromisOverflow(uint32 issuedIntexCount, uint128 promisLoadMinor);
    /// @notice `wire` called while the current escrow still holds live locks.
    error EscrowHasLiveLocks();
    /// @notice Auction does not exist.
    error AuctionNotFound();
    /// @notice Auction already exists.
    error AuctionAlreadyExists();
    /// @notice Clearing result claims more winners than were revealed on-chain.
    error WonBidsExceedRevealed(uint32 wonBidsCount, uint32 revealedBidsCount);
    /// @notice Clearing rate is below the configured minimum bid rate.
    error ClearingRateBelowMin(uint64 clearingRate, uint32 minIntexBidRate);
    /// @notice Schedule timestamps are not strictly increasing or are in the past.
    error InvalidSchedule();
    /// @notice `auctionStart` requires a final Green or Red day state.
    error InvalidDayState();
    /// @notice The day does not carry a price for this reference currency.
    error ReferenceCurrencyNotPriced(uint32 worldwideDay, uint16 isoCode);
    /// @notice The declared issuance currency is not a three-digit ISO code.
    error InvalidIssuanceCurrency(uint16 isoCode);
    /// @notice Commit hash must be non-zero.
    error InvalidCommitHash();
    /// @notice Chain id mismatch between the caller-supplied value and `block.chainid`.
    error WrongChain(uint256 expected, uint256 got);
    /// @notice `claimCommitBond` was called before the no-reveal penalty window elapsed.
    /// @param claimableAt Earliest unix-seconds timestamp the bond can be claimed at.
    /// @param nowTs Current block timestamp.
    error CommitBondNotYetClaimable(uint32 claimableAt, uint32 nowTs);

    // --- Admin ---

    /// @notice Wire contract dependencies.
    /// @param _escrow Escrow contract address.
    function wire(address _escrow) external;

    /// @notice Point the bid-commit gate at a Whitelist registry.
    /// @param registry Registry address; the zero address leaves commitBid open to everyone.
    function setWhitelist(address registry) external;

    /// @notice Registry currently gating {commitBid}, or the zero address when ungated.
    function whitelist() external view returns (address);

    // --- Lifecycle ---

    /// @notice Create and start a new auction for `worldwideDay`.
    /// @dev The schedule (`commitEnd`/`revealEnd`/`issuanceEnd`) is computed on the
    ///      Outbe side (Desis) and passed in. `dayState` is final at creation:
    ///      Green opens the commit stage, Red records the series born Cancelled.
    ///      Stage transitions follow the stored timestamps.
    /// @param worldwideDay Worldwide day (yyyymmdd, uint32).
    /// @param dayState Final worldwide-day state (Green or Red).
    /// @param schedule Stage-end timestamps.
    /// @param params Auction input parameters.
    function auctionStart(
        uint32 worldwideDay,
        WorldwideDayState dayState,
        AuctionSchedule calldata schedule,
        AuctionParams calldata params
    ) external;

    /// @notice Advance the auction to the issuance stage (bridge-driven clearing signal from Outbe).
    /// @dev Early signal snaps `revealEnd` forward; `issuanceEnd` is unchanged.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    function startClearingStage(uint32 worldwideDay) external;

    /// @notice Execute auction clearing with final data from Outbe.
    /// @dev `issuedIntexLoadedPromis` is derived on-chain (`issuedIntexCount * promisLoadMinor`).
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param issuedIntexCount Final number of issued Intex units.
    /// @param auctionClearingRate Uniform clearing rate (`1e6` fixed-point) calculated by Outbe.
    /// @param wonBidsCount Number of winning bids (from Outbe).
    function executeAuctionClearing(
        uint32 worldwideDay,
        uint32 issuedIntexCount,
        uint64 auctionClearingRate,
        uint32 wonBidsCount
    ) external;

    // --- User Actions ---

    /// @notice Commit a sealed bid hash for an auction.
    /// @dev When the series carries a non-zero `commitBondMinor`, the bond is pulled from the
    ///      caller into escrow in the same transaction (requires prior payment-token approval on
    ///      the escrow adapter). Reveal/cancel return it immediately; a green-day no-reveal locks
    ///      it until `revealEnd + UNREVEALED_BOND_LOCK_PERIOD` (see `claimCommitBond`).
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param commitHash `keccak256(signature)`, where `signature` is an EIP-712 typed-data
    ///                   signature over `RevealBid(uint32 worldwideDay,address bidder,uint16 quantity,uint32 bidRate)`
    ///                   under the `IntexAuction` v1 domain (`chainId`, `verifyingContract = address(this)`).
    function commitBid(uint32 worldwideDay, bytes32 commitHash) external;

    /// @notice Cancel an existing commit during the commit stage.
    /// @dev Only callable before `commitEnd`. Once the commit window closes a commit can no longer
    ///      be cancelled or revealed - an unrevealed commit is permanently forfeited (its bond
    ///      stays claimable via `claimCommitBond`). Cancelling returns the bond immediately.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    function cancelCommit(uint32 worldwideDay) external;

    /// @notice Reclaim a terminal, past-issuance auction's stored revealed-bid records.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param limit Maximum records to delete this call; paginate large sets across calls.
    function reapAuction(uint32 worldwideDay, uint256 limit) external;

    /// @notice Reveal a bid.
    /// @dev Returns the commit bond (if any) before locking the bid escrow, so the bond can fund
    ///      the bid in the same transaction.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param quantity Requested quantity (Intex units).
    /// @param bidRate Bid rate (`1e6` fixed-point, % of the escrow basis).
    /// @param issuanceCurrency Declared issuance currency (ISO numeric); only its three-digit range
    ///                         is checked, since the network keeps no list of issuance currencies.
    /// @param referenceCurrency Reference currency the bid prices in; must be one the day carries.
    /// @param chainId Chain id; must equal `block.chainid` (belt-and-braces; the EIP-712 domain
    ///                already binds it inside the signature).
    /// @param signature 65-byte ECDSA signature over the EIP-712 `RevealBid` typed data.
    function revealBid(
        uint32 worldwideDay,
        uint16 quantity,
        uint32 bidRate,
        uint16 issuanceCurrency,
        uint16 referenceCurrency,
        uint64 chainId,
        bytes memory signature
    ) external;

    /// @notice Permissionless commit-bond claim for a bidder who committed but never revealed.
    ///         A cancelled (red-day) auction releases immediately; otherwise the bond is claimable
    ///         only after `revealEnd + UNREVEALED_BOND_LOCK_PERIOD`. Pays the stored bidder, not the
    ///         caller. The escrow-local time-based valve (`claimAbandonedCommitBond`) backs this up
    ///         if the auction contract itself is rotated away.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose bond is being claimed.
    function claimCommitBond(uint32 worldwideDay, address bidder) external;

    // --- Views ---

    /// @notice Get auction information by series id.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @return auctionData Auction information including schedule, params and result.
    function getAuctionInfo(uint32 worldwideDay) external view returns (AuctionData memory auctionData);

    /// @notice Get auction information plus the revealed bids by series id.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @return auctionData Auction information.
    /// @return bidsData Array of revealed bids.
    function getAuctionDetails(uint32 worldwideDay)
        external
        view
        returns (AuctionData memory auctionData, SubmittedBidData[] memory bidsData);

    /// @notice Get the current auction stage by series id.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @return Current auction stage.
    function getAuctionStage(uint32 worldwideDay) external view returns (AuctionStage);
}
