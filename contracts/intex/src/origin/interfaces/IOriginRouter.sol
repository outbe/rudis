// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @title IOriginRouter
/// @author Outbe
/// @notice Interface for the Outbe-side router. Broadcasts auction/series messages to every registered target chain
///         and receives BIDS_BATCH / BIDS_DONE back from each over the protocol-agnostic ERC-7786 bridge.
/// @dev Auction messages are keyed by `worldwideDay`; series (issuance/mark) messages by `seriesId`. The target set is
///      a registry (see {addTarget}); it is snapshotted per day at STAGE_START so a mid-day membership change never
///      reshapes an in-flight auction. Broadcast sends fan out over the snapshot; addressed sends carry a leading
///      `dstChainId` and are checked against it. Every leg is isolated (see {flushPendingSend}) - a single failing leg
///      is parked, never reverting the fan-out. Sends are funded from the contract's relay float (`msg.value` must be
///      0); `quote*` return the native fee. Inbound delivery arrives via {ERC7786MessengerBase-receiveMessage}.
interface IOriginRouter {
    // --- Events ---
    /// @notice Emitted when a BIDS_BATCH is received from a target chain.
    /// @param srcChainId Source chainId the message was authenticated against.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidsCount Number of bids received.
    event BidsBatchReceived(uint32 indexed srcChainId, uint32 indexed worldwideDay, uint256 bidsCount);

    /// @notice Emitted when a BIDS_DONE completeness marker is received from a target chain.
    /// @param srcChainId Source chainId the message was authenticated against.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param totalBatches Number of BIDS_BATCH messages the source relayed for this day/generation.
    /// @param totalBids Total bids the source relayed for this day/generation.
    event BidsDoneReceived(
        uint32 indexed srcChainId, uint32 indexed worldwideDay, uint16 totalBatches, uint32 totalBids
    );

    /// @notice Emitted when a chain is registered as an auction target.
    event TargetAdded(uint32 indexed chainId);
    /// @notice Emitted when a chain is deregistered as an auction target.
    event TargetRemoved(uint32 indexed chainId);

    /// @notice Emitted when an outbound leg fails to dispatch and is parked for a permissionless flush.
    /// @param idx Parked-send index.
    /// @param dstChainId Destination chainId of the parked leg.
    /// @param msgType Codec message type of the parked payload.
    event SendParked(uint256 indexed idx, uint32 indexed dstChainId, uint8 msgType);
    /// @notice Emitted when a parked outbound leg is flushed successfully.
    event PendingSendFlushed(uint256 indexed idx, uint32 indexed dstChainId, bytes32 sendId);

    /// @notice Emitted when an auction stage message is sent to a target chain.
    /// @param sendId Bridge send identifier.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param stageType Codec message type (start/reveal/clearing).
    event AuctionStageSent(bytes32 indexed sendId, uint32 indexed worldwideDay, uint8 stageType);

    /// @notice Emitted when an auction result is sent to a target chain.
    /// @param sendId Bridge send identifier.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param issuedIntexCount Number of Intex units issued.
    /// @param clearingRate Uniform clearing rate (`1e6` fixed-point).
    event AuctionResultSent(
        bytes32 indexed sendId, uint32 indexed worldwideDay, uint32 issuedIntexCount, uint64 clearingRate
    );

    /// @notice Emitted when issuance instructions are sent to a target chain.
    /// @param sendId Bridge send identifier.
    /// @param seriesId Series identifier.
    /// @param recipientsCount Number of recipients.
    event IssuanceInstructionsSent(bytes32 indexed sendId, bytes14 indexed seriesId, uint256 recipientsCount);

    /// @notice Emitted when refund instructions are sent to a target chain.
    /// @param sendId Bridge send identifier.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param instructionsCount Number of finalization instructions.
    event RefundInstructionsSent(bytes32 indexed sendId, uint32 indexed worldwideDay, uint256 instructionsCount);

    /// @notice Emitted when a mark-called message is sent to a target chain.
    /// @param sendId Bridge send identifier.
    /// @param seriesId Series identifier.
    event MarkCalledSent(bytes32 indexed sendId, bytes14 indexed seriesId);

    /// @notice Emitted when a mark-qualified message is sent to a target chain.
    /// @param sendId Bridge send identifier.
    /// @param seriesId Series identifier.
    event MarkQualifiedSent(bytes32 indexed sendId, bytes14 indexed seriesId);

    /// @notice Emitted when `wire` updates the `desis` and `intexFactory` dependencies and rotates their roles.
    /// @param desisOld Previous `desis` (zero on first wiring).
    /// @param desisNew New `desis` granted `DESIS_ROLE`.
    /// @param intexFactoryOld Previous `intexFactory` (zero on first wiring).
    /// @param intexFactoryNew New `intexFactory` granted `INTEX_FACTORY_ROLE`.
    event DependenciesWired(address desisOld, address desisNew, address intexFactoryOld, address intexFactoryNew);

    /// @notice Emitted when `sweepNative` transfers native tokens out of the contract.
    /// @param to Recipient of the swept native balance.
    /// @param amount Amount of native tokens (wei) swept.
    event NativeSwept(address indexed to, uint256 amount);

    /// @notice Emitted when the proceeds route (token bridge + WCOEN) is set.
    event ProceedsRouteSet(address tokenBridge, address wrudis);
    /// @notice Emitted when inbound auction proceeds are handed to the factory for creator payout.
    event ProceedsDistributed(uint32 indexed worldwideDay, uint256 amount);
    /// @notice Emitted when distribution failed and the proceeds were parked for retry.
    event ProceedsParked(uint256 indexed idx, uint32 indexed worldwideDay, uint256 amount);
    /// @notice Emitted when a parked distribution was retried successfully.
    event ProceedsRetried(uint256 indexed idx, uint32 indexed worldwideDay, uint256 amount);

    /// @notice Caller of the proceeds hook is not the wired token bridge.
    error UnauthorizedProceedsCaller(address caller);
    /// @notice Proceeds arrived from a chain that is not a target of the series.
    error UnexpectedProceedsSource(uint32 sourceDomain);
    /// @notice Proceeds arrived from a source sender other than the registered peer for its chain.
    error UnauthorizedProceedsSender(bytes from);
    /// @notice No live parked distribution at `idx`.
    error NoParkedProceeds(uint256 idx);

    // --- Types ---
    /// @notice Auction proceeds unwrapped on Outbe but not yet distributed, awaiting permissionless retry.
    struct ParkedProceeds {
        uint32 worldwideDay;
        uint32 srcChainId;
        uint128 amount;
        bool settled;
    }

    /// @notice An outbound leg that failed to dispatch, retained for a permissionless flush.
    struct ParkedSend {
        uint32 dstChainId;
        uint64 gasLimit;
        bool sent;
        bytes payload;
    }

    /// @notice Entry, floor and call price of one reference currency for a day.
    struct ReferenceCurrencyPrice {
        uint16 isoCode;
        uint64 entryPriceMinor;
        uint64 floorPriceMinor;
        uint64 callPriceMinor;
    }

    /// @notice Auction stage start parameters grouped to keep the calldata layout resilient against stack limits.
    struct AuctionStageStartParams {
        uint32 worldwideDay;
        /// @notice End of the commit stage (UNIX seconds).
        uint32 commitEnd;
        /// @notice End of the reveal stage (UNIX seconds).
        uint32 revealEnd;
        /// @notice End of the issuance stage (UNIX seconds).
        uint32 issuanceEnd;
        /// @notice PROMIS-units per Intex unit (1e6).
        uint128 promisLoadMinor;
        /// @notice Minimum acceptable bid rate (`1e6` fixed-point, % of the escrow basis).
        uint32 minIntexBidRate;
        /// @notice Entry, floor and call price of every currency the day can clear in.
        ReferenceCurrencyPrice[] prices;
        /// @notice Called->deadline window in seconds (0 = default).
        uint32 callNoticePeriod;
        /// @notice Call-trigger observation window in seconds.
        uint32 callWindow;
        /// @notice Call-trigger threshold in seconds.
        uint32 callThreshold;
        /// @notice Minimum quantity per bid (Intex units).
        uint16 minIntexBidQuantity;
        /// @notice Commit-entry bond (payment-token minor units); 0 disables the bond.
        uint128 commitBondMinor;
        /// @notice Final worldwide-day state (1 = Green, 2 = Red).
        uint8 dayState;
    }

    /// @notice Issuance instructions parameters grouped to keep the calldata layout resilient against stack limits.
    /// @dev `issuedIntexCount` is the auction-cleared cap that pins `mint` on the destination NFT
    ///      contract. Must equal the auction's cleared count.
    struct IssuanceInstructionsParams {
        bytes14 seriesId;
        /// @notice Worldwide day the series was derived from (provenance; carried to the destination NFT).
        uint32 worldwideDay;
        uint32 issuedIntexCount;
        uint128 promisLoadMinor;
        uint64 entryPriceMinor;
        uint64 floorPriceMinor;
        /// @notice Duration in seconds for the Called -> deadline window (0 = default).
        uint32 callNoticePeriod;
        uint16 issuanceCurrency;
        uint16 referenceCurrency;
        uint32 callWindow;
        uint32 callThreshold;
        uint64 callPriceMinor;
        address[] recipients;
        uint256[] quantities;
    }

    // --- Errors ---
    /// @notice Zero address provided.
    /// @param field Field name that contains zero address.
    error ZeroAddress(string field);
    /// @notice Zero chainId provided.
    error ZeroChainId();
    /// @notice Chain is already a registered target.
    error TargetAlreadyRegistered(uint32 chainId);
    /// @notice Chain is not a registered target.
    error TargetNotRegistered(uint32 chainId);
    /// @notice No targets are registered, so a broadcast has no destinations.
    error NoTargets();
    /// @notice Addressed send targets a chain outside the series' STAGE_START snapshot.
    error NotSeriesTarget(uint32 worldwideDay, uint32 dstChainId);
    /// @notice `sendLeg` is an internal self-call seam; caller was not this contract.
    error OnlySelf();
    /// @notice No live parked send at `idx`.
    error NoParkedSend(uint256 idx);
    /// @notice Array lengths do not match.
    error ArrayLengthMismatch();
    /// @notice Empty array provided.
    error EmptyArray();

    /// @notice An authenticated inbound message, or one item of it, was acknowledged without effect.
    /// @param srcChainId Source chainId the message was authenticated against.
    /// @param msgType Codec message type.
    /// @param key Identity of the ignored effect (worldwide day, series id, chunk, ...) as the handler keys it.
    /// @param reason One of the `InboundReason` codes.
    event InboundMessageIgnored(uint32 indexed srcChainId, uint8 indexed msgType, bytes32 indexed key, uint8 reason);

    /// @notice Address wired as `desis` does not advertise `IDesis` via ERC-165 or is an EOA.
    /// @param wired Address that failed the interface probe.
    error InvalidDesisInterface(address wired);
    /// @notice Native-token sweep transfer failed.
    error NativeSweepFailed();
    /// @notice Native-token balance is insufficient for the requested sweep.
    /// @param available Current contract balance.
    /// @param requested Amount the admin attempted to sweep.
    error NativeBalanceInsufficient(uint256 available, uint256 requested);

    // --- Admin ---
    /// @notice Wire contract dependencies and grant the demand/supply roles.
    /// @param desis Desis contract - must advertise `IDesis` via ERC-165; granted `DESIS_ROLE`.
    /// @param intexFactory IntexFactory precompile; granted `INTEX_FACTORY_ROLE`.
    function wire(address desis, address intexFactory) external;

    /// @notice Register (or clear) the matching messenger on `chainId` as an ERC-7930 interoperable address.
    /// @param chainId Destination/source chainId.
    /// @param interop ERC-7930 interoperable address (empty to clear).
    function setRemoteMessenger(uint32 chainId, bytes calldata interop) external;

    /// @notice Register `chainId` as an auction target; its peer messenger must already be set. Restricted to admin.
    function addTarget(uint32 chainId) external;
    /// @notice Deregister `chainId` as an auction target (swap-pop). In-flight series keep their own snapshot.
    ///         Restricted to admin.
    function removeTarget(uint32 chainId) external;
    /// @notice The currently registered target chainIds.
    function targets() external view returns (uint32[] memory);
    /// @notice Whether `chainId` is a registered target.
    function isTarget(uint32 chainId) external view returns (bool);
    /// @notice The frozen target snapshot taken for `worldwideDay` at STAGE_START (empty if never started).
    function targetsOf(uint32 worldwideDay) external view returns (uint32[] memory);

    /// @notice Sweep native tokens (the relay-funded float) from the contract to an admin recipient.
    /// @param to Recipient address (must be non-zero).
    /// @param amount Amount in wei to sweep; must be <= contract balance.
    function sweepNative(address payable to, uint256 amount) external;

    // --- Quote ---
    /// @notice Native fee to broadcast auction stage start (summed over the registered targets).
    function quoteSendAuctionStageStart(AuctionStageStartParams calldata params) external view returns (uint256 fee);
    /// @notice Native fee to broadcast auction stage clearing (summed over the registered targets).
    function quoteSendAuctionStageClearing(uint32 worldwideDay) external view returns (uint256 fee);
    /// @notice Native fee to send auction result to a single target chain.
    function quoteSendAuctionResult(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint32 issuedIntexCount,
        uint64 auctionClearingRate,
        uint32 wonBidsCount
    ) external view returns (uint256 fee);
    /// @notice Native fee to send one issuance chunk to `dstChainId`.
    function quoteSendIssuanceInstructions(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        IssuanceInstructionsParams[] calldata series
    ) external view returns (uint256 fee);
    /// @notice Native fee to send one chunk of a day's refund instructions to a single target chain.
    function quoteSendRefundInstructions(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        address[] calldata bidders,
        uint128[] calldata refundedAmounts,
        uint128[] calldata paidAmounts
    ) external view returns (uint256 fee);
    /// @notice Native fee to broadcast mark-called (summed over the day's snapshot targets).
    function quoteSendMarkCalled(uint32 worldwideDay, uint32 calledAt, bytes14[] calldata seriesIds)
        external
        view
        returns (uint256 fee);
    /// @notice Native fee to broadcast mark-qualified (summed over the day's snapshot targets).
    function quoteSendMarkQualified(uint32 worldwideDay, bytes14[] calldata seriesIds)
        external
        view
        returns (uint256 fee);

    // --- Send ---
    /// @notice Broadcast auction stage start to every registered target, snapshotting the target set for the day.
    ///         Restricted to `DESIS_ROLE`.
    function sendAuctionStageStart(AuctionStageStartParams calldata params) external payable;
    /// @notice Broadcast auction stage clearing over the day's snapshot. Restricted to `DESIS_ROLE`.
    function sendAuctionStageClearing(uint32 worldwideDay) external payable;
    /// @notice Send auction result to a single target chain. Restricted to `DESIS_ROLE`.
    function sendAuctionResult(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint32 issuedIntexCount,
        uint64 auctionClearingRate,
        uint32 wonBidsCount
    ) external payable returns (bytes32 sendId);
    /// @notice Send one chain one chunk (`chunkIndex` of `totalChunks`) of the series of `worldwideDay` it must
    ///         create and the winners to mint to. Empty `recipients` creates the series only. Restricted to
    ///         `INTEX_FACTORY_ROLE`.
    function sendIssuanceInstructions(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        IssuanceInstructionsParams[] calldata series
    ) external payable returns (bytes32 sendId);
    /// @notice Send one chunk of a day's refund instructions to a single target chain.
    ///         Restricted to `DESIS_ROLE`.
    function sendRefundInstructions(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        address[] calldata bidders,
        uint128[] calldata refundedAmounts,
        uint128[] calldata paidAmounts
    ) external payable returns (bytes32 sendId);
    /// @notice Broadcast mark-called for one day's series over its snapshot. A batch is one day's
    ///         series that share both the decision that called them and its timestamp.
    ///         Restricted to `INTEX_FACTORY_ROLE`.
    /// @dev `calledAt` is the origin's own stamp, so delivery lag never lengthens a target's deadline.
    function sendMarkCalled(uint32 worldwideDay, uint32 calledAt, bytes14[] calldata seriesIds) external payable;
    /// @notice Broadcast mark-qualified for one day's series over its snapshot, flipping them to
    ///         Qualified. Restricted to `INTEX_FACTORY_ROLE`.
    function sendMarkQualified(uint32 worldwideDay, bytes14[] calldata seriesIds) external payable;

    /// @notice Permissionless flush of a parked outbound leg.
    function flushPendingSend(uint256 idx) external;
    /// @notice Parked outbound leg by index.
    function parkedSend(uint256 idx) external view returns (ParkedSend memory);

    // --- Proceeds ---
    /// @notice Set the WCOEN token bridge (authorized proceeds-hook caller) and the WCOEN token to unwrap.
    function setProceedsRoute(address _tokenBridge, address _wrudis) external;
    /// @notice WCOEN token bridge authorized to invoke the proceeds hook.
    function tokenBridge() external view returns (address);
    /// @notice WCOEN token unwrapped to native before distribution.
    function wrudis() external view returns (address);
    /// @notice Parked proceeds awaiting retry, by enqueue index.
    function parkedProceeds(uint256 idx) external view returns (ParkedProceeds memory);
    /// @notice Permissionless retry of a parked distribution.
    function retryProceeds(uint256 idx) external;
}
