// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

import {ERC7786MessengerBase} from "../shared/ERC7786MessengerBase.sol";
import {IOriginRouter} from "./interfaces/IOriginRouter.sol";
import {IDesis} from "./interfaces/IDesis.sol";
import {IIntexFactory} from "./interfaces/IIntexFactory.sol";
import {IWCOEN} from "./interfaces/IWCOEN.sol";
import {IERC7786TokenReceiver} from "./interfaces/IERC7786TokenReceiver.sol";
import {BridgeMsgCodec} from "../shared/libs/BridgeMsgCodec.sol";
import {IntexGas} from "../shared/libs/IntexGas.sol";
import {InboundReason} from "../shared/libs/InboundReason.sol";

/// @title OriginRouter
/// @author Outbe
/// @notice Outbe-side router: broadcasts auction/series messages to every registered target chain and receives
///         BIDS_BATCH / BIDS_DONE back from each over the protocol-agnostic ERC-7786 bridge (the `crosschain` hub).
///         The active transport is selected on the bridge.
/// @dev UUPS upgradeable behind an ERC1967 proxy; the bridge is an implementation immutable (from
///      {ERC7786MessengerBase}), so every upgrade must pass the same bridge to the constructor. Auction messages are
///      keyed by `worldwideDay`, series (issuance/mark) by `seriesId`. The target set is a registry snapshotted per
///      day at STAGE_START; every leg is isolated so one failing destination never wedges the fan-out.
contract OriginRouter is
    IOriginRouter,
    IERC7786TokenReceiver,
    ERC7786MessengerBase,
    AccessControlUpgradeable,
    ReentrancyGuardTransient,
    UUPSUpgradeable
{
    /// @notice Gates the demand-side sends: auction stages, AUCTION_RESULT, REFUND_INSTRUCTIONS.
    bytes32 public constant DESIS_ROLE = keccak256("DESIS_ROLE");
    /// @notice Gates the supply-side sends: ISSUANCE_INSTRUCTIONS, MARK_QUALIFIED, MARK_CALLED.
    bytes32 public constant INTEX_FACTORY_ROLE = keccak256("INTEX_FACTORY_ROLE");

    /// @custom:storage-location erc7201:outbe.intex.OriginRouter
    struct OriginRouterStorage {
        /// @dev Desis recipient that processes inbound BIDS_BATCH payloads (and holds `DESIS_ROLE`).
        address desis;
        /// @dev IntexFactory authorized for the supply-side sends (holds `INTEX_FACTORY_ROLE`).
        address intexFactory;
        /// @dev WCOEN token bridge authorized to invoke the proceeds hook.
        address tokenBridge;
        /// @dev WCOEN token unwrapped to native before distribution.
        address wcoen;
        /// @dev Parked distributions awaiting permissionless retry, by enqueue index.
        mapping(uint256 idx => ParkedProceeds) parkedProceeds;
        /// @dev Next index to assign in `parkedProceeds`.
        uint256 nextParkedProceedsIdx;
        // --- Multi-target registry (tail-appended; upgrade-safe) ---
        /// @dev Registered target chainIds; membership is via `targetIndexPlus1`.
        uint32[] targetChainIds;
        /// @dev 1-based index in `targetChainIds` (0 = absent); 1-based disambiguates the first target under swap-pop.
        mapping(uint32 chainId => uint256 indexPlus1) targetIndexPlus1;
        /// @dev Per-day target snapshot frozen at STAGE_START; the day's sends fan out over this, not the live registry.
        mapping(uint32 worldwideDay => uint32[] chainIds) seriesTargets;
        /// @dev Outbound legs that failed to dispatch, awaiting a permissionless flush.
        mapping(uint256 idx => ParkedSend) parkedSends;
        /// @dev Next index to assign in `parkedSends`.
        uint256 nextParkedSendIdx;
    }

    // keccak256(abi.encode(uint256(keccak256("outbe.intex.OriginRouter")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE_SLOT = 0x2c9073d8b0cd30aa4aa3061d90da176c3d040651b0847724f0e9a4a76777f100;

    function _os() private pure returns (OriginRouterStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            $.slot := _STORAGE_SLOT
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor(address bridge_) ERC7786MessengerBase(bridge_) {
        _disableInitializers();
    }

    /// @notice Initializes the proxy: contract admin.
    /// @param _delegate Receiver of `DEFAULT_ADMIN_ROLE`.
    function initialize(address _delegate) external initializer {
        if (_delegate == address(0)) revert ZeroAddress("delegate");
        __AccessControl_init();
        _grantRole(DEFAULT_ADMIN_ROLE, _delegate);
    }

    /// @dev Upgrades are gated by the admin role.
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // --- Storage getters ---
    /// @notice Desis recipient that processes inbound BIDS_BATCH payloads (and holds `DESIS_ROLE`).
    function desis() external view returns (address) {
        return _os().desis;
    }

    /// @notice IntexFactory authorized for the supply-side sends (holds `INTEX_FACTORY_ROLE`).
    function intexFactory() external view returns (address) {
        return _os().intexFactory;
    }

    // --- Admin ---
    /// @inheritdoc IOriginRouter
    function wire(address _desis, address _intexFactory) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_desis == address(0)) revert ZeroAddress("desis");
        if (_intexFactory == address(0)) revert ZeroAddress("intexFactory");
        _assertDesisInterface(_desis);

        OriginRouterStorage storage $ = _os();
        address desisOld = $.desis;
        address intexFactoryOld = $.intexFactory;

        if ($.desis != address(0)) _revokeRole(DESIS_ROLE, $.desis);
        if ($.intexFactory != address(0)) _revokeRole(INTEX_FACTORY_ROLE, $.intexFactory);

        $.desis = _desis;
        $.intexFactory = _intexFactory;

        _grantRole(DESIS_ROLE, _desis);
        _grantRole(INTEX_FACTORY_ROLE, _intexFactory);

        emit DependenciesWired(desisOld, _desis, intexFactoryOld, _intexFactory);
    }

    /// @inheritdoc IOriginRouter
    function setRemoteMessenger(uint32 chainId, bytes calldata interop) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _setRemoteMessenger(chainId, interop);
    }

    // --- Targets registry ---
    /// @inheritdoc IOriginRouter
    function addTarget(uint32 chainId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (chainId == 0) revert ZeroChainId();
        // Require the peer messenger first, so a registered target is always routable.
        _remoteMessenger(chainId);
        OriginRouterStorage storage $ = _os();
        if ($.targetIndexPlus1[chainId] != 0) revert TargetAlreadyRegistered(chainId);
        $.targetChainIds.push(chainId);
        $.targetIndexPlus1[chainId] = $.targetChainIds.length; // 1-based
        emit TargetAdded(chainId);
    }

    /// @inheritdoc IOriginRouter
    function removeTarget(uint32 chainId) external onlyRole(DEFAULT_ADMIN_ROLE) {
        OriginRouterStorage storage $ = _os();
        uint256 idxPlus1 = $.targetIndexPlus1[chainId];
        if (idxPlus1 == 0) revert TargetNotRegistered(chainId);
        uint32[] storage arr = $.targetChainIds;
        uint256 i = idxPlus1 - 1;
        uint256 last = arr.length - 1;
        if (i != last) {
            uint32 moved = arr[last];
            arr[i] = moved;
            $.targetIndexPlus1[moved] = i + 1; // keep the moved element 1-based
        }
        arr.pop();
        delete $.targetIndexPlus1[chainId];
        emit TargetRemoved(chainId);
    }

    /// @inheritdoc IOriginRouter
    function targets() external view returns (uint32[] memory) {
        return _os().targetChainIds;
    }

    /// @inheritdoc IOriginRouter
    function isTarget(uint32 chainId) external view returns (bool) {
        return _os().targetIndexPlus1[chainId] != 0;
    }

    /// @inheritdoc IOriginRouter
    function targetsOf(uint32 worldwideDay) external view returns (uint32[] memory) {
        return _os().seriesTargets[worldwideDay];
    }

    // --- Per-leg send isolation ---
    /// @dev External self-call seam so `try/catch` can isolate one leg; only the contract itself may call it.
    function sendLeg(uint32 dstChainId, bytes calldata payload, uint256 gasLimit) external returns (bytes32) {
        if (msg.sender != address(this)) revert OnlySelf();
        return _send(dstChainId, payload, gasLimit);
    }

    /// @dev Send one leg; on any failure park it for a permissionless flush and continue. Returns 0 when parked.
    function _sendOrPark(uint32 dstChainId, bytes memory payload, uint256 gasLimit) private returns (bytes32 sendId) {
        try this.sendLeg(dstChainId, payload, gasLimit) returns (bytes32 id) {
            sendId = id;
        } catch {
            OriginRouterStorage storage $ = _os();
            uint256 idx = $.nextParkedSendIdx++;
            ParkedSend storage p = $.parkedSends[idx];
            p.dstChainId = dstChainId;
            p.gasLimit = SafeCast.toUint64(gasLimit);
            p.payload = payload;
            emit SendParked(idx, dstChainId, uint8(payload[1])); // header layout: [version, msgType, ...]
        }
    }

    /// @inheritdoc IOriginRouter
    function flushPendingSend(uint256 idx) external nonReentrant {
        ParkedSend storage p = _os().parkedSends[idx];
        if (p.payload.length == 0 || p.sent) revert NoParkedSend(idx);
        p.sent = true; // CEI; a revert in `_send` rolls this back, keeping the entry retryable
        bytes32 sendId = _send(p.dstChainId, p.payload, p.gasLimit);
        emit PendingSendFlushed(idx, p.dstChainId, sendId);
    }

    /// @inheritdoc IOriginRouter
    function parkedSend(uint256 idx) external view returns (ParkedSend memory) {
        return _os().parkedSends[idx];
    }

    /// @dev Whether `chainId` is in the series' STAGE_START snapshot (the frozen day-of target set).
    function _isSeriesTarget(uint32 worldwideDay, uint32 chainId) private view returns (bool) {
        uint32[] storage snapshot = _os().seriesTargets[worldwideDay];
        uint256 len = snapshot.length;
        for (uint256 i = 0; i < len; ++i) {
            if (snapshot[i] == chainId) return true;
        }
        return false;
    }

    /// @dev Revert unless `dstChainId` is in the series' STAGE_START snapshot; addressed sends route only to a chain
    ///      the day was actually started on (immune to a mid-day removeTarget).
    function _requireSeriesTarget(uint32 worldwideDay, uint32 dstChainId) private view {
        if (!_isSeriesTarget(worldwideDay, dstChainId)) revert NotSeriesTarget(worldwideDay, dstChainId);
    }

    /// @dev Reverts `InvalidDesisInterface(_desis)` if the target is an EOA or does not advertise `IDesis` via
    ///      ERC-165. Catches the common operator mistake of wiring a typo'd address that would brick inbound.
    function _assertDesisInterface(address _desis) private view {
        if (_desis.code.length == 0) revert InvalidDesisInterface(_desis);
        try IERC165(_desis).supportsInterface(type(IDesis).interfaceId) returns (bool supported) {
            if (!supported) revert InvalidDesisInterface(_desis);
        } catch {
            revert InvalidDesisInterface(_desis);
        }
    }

    // --- Quote ---
    /// @dev Sum the per-target fee to broadcast `payload` over `chainIds` with `gasLimit` destination gas.
    function _broadcastFee(uint32[] memory chainIds, bytes memory payload, uint256 gasLimit)
        private
        view
        returns (uint256 fee)
    {
        for (uint256 i = 0; i < chainIds.length; ++i) {
            fee += _quoteFee(chainIds[i], payload, gasLimit);
        }
    }

    /// @inheritdoc IOriginRouter
    function quoteSendAuctionStageStart(AuctionStageStartParams calldata params) external view returns (uint256) {
        return _broadcastFee(
            _os().targetChainIds, _encodeAuctionStageStart(params), IntexGas.auctionStart(params.prices.length)
        );
    }

    /// @inheritdoc IOriginRouter
    function quoteSendAuctionStageClearing(uint32 worldwideDay) external view returns (uint256) {
        return _broadcastFee(
            _seriesOrRegistry(worldwideDay),
            BridgeMsgCodec.encodeAuctionStageClearing(worldwideDay),
            IntexGas.AUCTION_STAGE_CLEARING
        );
    }

    /// @inheritdoc IOriginRouter
    function quoteSendAuctionResult(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint32 issuedIntexCount,
        uint64 auctionClearingRate,
        uint32 wonBidsCount
    ) external view returns (uint256) {
        return _quoteFee(
            dstChainId,
            BridgeMsgCodec.encodeAuctionResult(worldwideDay, issuedIntexCount, auctionClearingRate, wonBidsCount),
            IntexGas.AUCTION_RESULT
        );
    }

    /// @inheritdoc IOriginRouter
    function quoteSendIssuanceInstructions(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        IssuanceInstructionsParams[] calldata series
    ) external view returns (uint256) {
        uint256 recipients;
        for (uint256 i = 0; i < series.length; i++) {
            recipients += series[i].recipients.length;
        }
        return _quoteFee(
            dstChainId,
            BridgeMsgCodec.encodeIssuanceInstructions(worldwideDay, chunkIndex, totalChunks, _toCodecPayloads(series)),
            IntexGas.issuance(series.length, recipients)
        );
    }

    /// @inheritdoc IOriginRouter
    function quoteSendRefundInstructions(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        address[] calldata bidders,
        uint128[] calldata refundedAmounts,
        uint128[] calldata paidAmounts
    ) external view returns (uint256) {
        return _quoteFee(
            dstChainId,
            BridgeMsgCodec.encodeRefundInstructions(
                worldwideDay, chunkIndex, totalChunks, bidders, refundedAmounts, paidAmounts
            ),
            IntexGas.refund(bidders.length)
        );
    }

    /// @inheritdoc IOriginRouter
    function quoteSendMarkCalled(uint32 worldwideDay, uint32 calledAt, bytes14[] calldata seriesIds)
        external
        view
        returns (uint256)
    {
        return _broadcastFee(
            _seriesOrRegistry(worldwideDay),
            BridgeMsgCodec.encodeMarkCalled(worldwideDay, calledAt, seriesIds),
            IntexGas.markCalled(seriesIds.length)
        );
    }

    /// @inheritdoc IOriginRouter
    function quoteSendMarkQualified(uint32 worldwideDay, bytes14[] calldata seriesIds) external view returns (uint256) {
        return _broadcastFee(
            _seriesOrRegistry(worldwideDay),
            BridgeMsgCodec.encodeMarkQualified(worldwideDay, seriesIds),
            IntexGas.markQualified(seriesIds.length)
        );
    }

    /// @dev The day's frozen snapshot if one exists, else the live registry (used only for pre-start fee quotes).
    function _seriesOrRegistry(uint32 worldwideDay) private view returns (uint32[] memory) {
        OriginRouterStorage storage $ = _os();
        uint32[] memory snapshot = $.seriesTargets[worldwideDay];
        return snapshot.length != 0 ? snapshot : $.targetChainIds;
    }

    // --- Send ---
    /// @inheritdoc IOriginRouter
    function sendAuctionStageStart(AuctionStageStartParams calldata params) external payable onlyRole(DESIS_ROLE) {
        OriginRouterStorage storage $ = _os();
        uint32[] memory snapshot = $.targetChainIds;
        if (snapshot.length == 0) revert NoTargets();
        $.seriesTargets[params.worldwideDay] = snapshot; // freeze the fan-out set for the whole day
        bytes memory payload = _encodeAuctionStageStart(params);
        for (uint256 i = 0; i < snapshot.length; ++i) {
            bytes32 sendId = _sendOrPark(snapshot[i], payload, IntexGas.auctionStart(params.prices.length));
            emit AuctionStageSent(sendId, params.worldwideDay, BridgeMsgCodec.MSG_AUCTION_STAGE_START);
        }
    }

    /// @inheritdoc IOriginRouter
    function sendAuctionStageClearing(uint32 worldwideDay) external payable onlyRole(DESIS_ROLE) {
        uint32[] memory snapshot = _os().seriesTargets[worldwideDay];
        if (snapshot.length == 0) revert NoTargets();
        bytes memory payload = BridgeMsgCodec.encodeAuctionStageClearing(worldwideDay);
        for (uint256 i = 0; i < snapshot.length; ++i) {
            bytes32 sendId = _sendOrPark(snapshot[i], payload, IntexGas.AUCTION_STAGE_CLEARING);
            emit AuctionStageSent(sendId, worldwideDay, BridgeMsgCodec.MSG_AUCTION_STAGE_CLEARING);
        }
    }

    /// @inheritdoc IOriginRouter
    function sendAuctionResult(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint32 issuedIntexCount,
        uint64 auctionClearingRate,
        uint32 wonBidsCount
    ) external payable onlyRole(DESIS_ROLE) returns (bytes32 sendId) {
        _requireSeriesTarget(worldwideDay, dstChainId);
        sendId = _sendOrPark(
            dstChainId,
            BridgeMsgCodec.encodeAuctionResult(worldwideDay, issuedIntexCount, auctionClearingRate, wonBidsCount),
            IntexGas.AUCTION_RESULT
        );
        emit AuctionResultSent(sendId, worldwideDay, issuedIntexCount, auctionClearingRate);
    }

    /// @inheritdoc IOriginRouter
    function sendIssuanceInstructions(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        IssuanceInstructionsParams[] calldata series
    ) external payable onlyRole(INTEX_FACTORY_ROLE) returns (bytes32 sendId) {
        // Empty `recipients` is valid: a snapshot chain with no local winners still needs the series created.
        uint256 recipients = _requireIssuanceBatch(dstChainId, worldwideDay, series);
        sendId = _sendOrPark(
            dstChainId,
            BridgeMsgCodec.encodeIssuanceInstructions(worldwideDay, chunkIndex, totalChunks, _toCodecPayloads(series)),
            IntexGas.issuance(series.length, recipients)
        );
        emit IssuanceInstructionsSent(sendId, series[0].seriesId, recipients);
    }

    /// @dev Validates a batch and returns its total recipient count. The day must be one this chain is a
    ///      target of; the codec owns the wire format (chunk header, per-series day and counts).
    function _requireIssuanceBatch(uint32 dstChainId, uint32 worldwideDay, IssuanceInstructionsParams[] calldata series)
        private
        view
        returns (uint256 recipients)
    {
        if (series.length == 0) revert EmptyArray();
        _requireSeriesTarget(worldwideDay, dstChainId);
        for (uint256 i = 0; i < series.length; i++) {
            if (series[i].recipients.length != series[i].quantities.length) revert ArrayLengthMismatch();
            recipients += series[i].recipients.length;
        }
    }

    /// @inheritdoc IOriginRouter
    function sendRefundInstructions(
        uint32 dstChainId,
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        address[] calldata bidders,
        uint128[] calldata refundedAmounts,
        uint128[] calldata paidAmounts
    ) external payable onlyRole(DESIS_ROLE) returns (bytes32 sendId) {
        uint256 len = bidders.length;
        if (len == 0) revert EmptyArray();
        if (len != refundedAmounts.length || len != paidAmounts.length) revert ArrayLengthMismatch();
        _requireSeriesTarget(worldwideDay, dstChainId);
        sendId = _sendOrPark(
            dstChainId,
            BridgeMsgCodec.encodeRefundInstructions(
                worldwideDay, chunkIndex, totalChunks, bidders, refundedAmounts, paidAmounts
            ),
            IntexGas.refund(len)
        );
        emit RefundInstructionsSent(sendId, worldwideDay, len);
    }

    /// @inheritdoc IOriginRouter
    function sendMarkCalled(uint32 worldwideDay, uint32 calledAt, bytes14[] calldata seriesIds)
        external
        payable
        onlyRole(INTEX_FACTORY_ROLE)
    {
        uint32[] memory snapshot = _os().seriesTargets[worldwideDay];
        if (snapshot.length == 0) revert NoTargets();
        bytes memory payload = BridgeMsgCodec.encodeMarkCalled(worldwideDay, calledAt, seriesIds);
        uint256 gasLimit = IntexGas.markCalled(seriesIds.length);
        for (uint256 i = 0; i < snapshot.length; ++i) {
            bytes32 sendId = _sendOrPark(snapshot[i], payload, gasLimit);
            for (uint256 s = 0; s < seriesIds.length; ++s) {
                emit MarkCalledSent(sendId, seriesIds[s]);
            }
        }
    }

    /// @inheritdoc IOriginRouter
    function sendMarkQualified(uint32 worldwideDay, bytes14[] calldata seriesIds)
        external
        payable
        onlyRole(INTEX_FACTORY_ROLE)
    {
        uint32[] memory snapshot = _os().seriesTargets[worldwideDay];
        if (snapshot.length == 0) revert NoTargets();
        bytes memory payload = BridgeMsgCodec.encodeMarkQualified(worldwideDay, seriesIds);
        uint256 gasLimit = IntexGas.markQualified(seriesIds.length);
        for (uint256 i = 0; i < snapshot.length; ++i) {
            bytes32 sendId = _sendOrPark(snapshot[i], payload, gasLimit);
            for (uint256 s = 0; s < seriesIds.length; ++s) {
                emit MarkQualifiedSent(sendId, seriesIds[s]);
            }
        }
    }

    // --- Receive ---
    /// @inheritdoc ERC7786MessengerBase
    /// @dev Guards the authenticated inbound path against re-entry through the Desis recipient.
    function receiveMessage(bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        public
        payable
        override
        nonReentrant
        returns (bytes4)
    {
        return super.receiveMessage(receiveId, sender, payload);
    }

    /// @dev Decodes an authenticated inbound message and dispatches by msgType. BIDS_BATCH and BIDS_DONE are inbound
    ///      here; a premature message reverts and is redelivered by the transport once its prerequisite has landed.
    function _dispatch(
        uint32 srcChainId,
        bytes32,
        /*receiveId*/
        bytes calldata payload
    )
        internal
        override
    {
        uint8 msgType = BridgeMsgCodec.readHeader(payload);
        BridgeMsgCodec.assertMinLength(payload, msgType);

        if (msgType == BridgeMsgCodec.MSG_BIDS_BATCH) {
            _handleBidsBatch(srcChainId, payload);
        } else if (msgType == BridgeMsgCodec.MSG_BIDS_DONE) {
            _handleBidsDone(srcChainId, payload);
        } else {
            revert BridgeMsgCodec.UnknownMsgType(msgType);
        }
    }

    /// @dev Decode a BIDS_BATCH and forward it to Desis; the body `srcChainId` is cross-checked against the
    ///      authenticated source. Clearing is not fired here - the Desis begin-block gate owns that.
    function _handleBidsBatch(uint32 srcChainId, bytes calldata payload) internal {
        (
            uint32 worldwideDay,
            uint32 bodySrcChainId,
            uint32 relayGeneration,
            uint16 batchIndex,
            uint16 totalBatches,
            address[] memory bidderAddresses,
            uint256[] memory packedBids
        ) = BridgeMsgCodec.decodeBidsBatch(payload);

        if (!_acceptBids(srcChainId, bodySrcChainId, worldwideDay, BridgeMsgCodec.MSG_BIDS_BATCH)) return;

        IDesis(_os().desis)
            .processBidsBatch(
                worldwideDay, srcChainId, relayGeneration, batchIndex, totalBatches, bidderAddresses, packedBids
            );

        emit BidsBatchReceived(srcChainId, worldwideDay, bidderAddresses.length);
    }

    /// @dev Decode a BIDS_DONE marker and forward it to Desis; the body `srcChainId` is cross-checked as in BIDS_BATCH.
    function _handleBidsDone(uint32 srcChainId, bytes calldata payload) internal {
        (uint32 worldwideDay, uint32 bodySrcChainId, uint32 relayGeneration, uint16 totalBatches, uint32 totalBids) =
            BridgeMsgCodec.decodeBidsDone(payload);

        if (!_acceptBids(srcChainId, bodySrcChainId, worldwideDay, BridgeMsgCodec.MSG_BIDS_DONE)) return;

        IDesis(_os().desis).processBidsDone(worldwideDay, srcChainId, relayGeneration, totalBatches, totalBids);

        emit BidsDoneReceived(srcChainId, worldwideDay, totalBatches, totalBids);
    }

    /// @dev Whether a relayed bids message may reach Desis. A body naming another source than the one the bridge
    ///      authenticated, or a source outside the day's frozen snapshot, can never become acceptable: it is
    ///      acknowledged without effect (a rogue/late-registered source would otherwise leave storage residue
    ///      Desis never clears - it resets only snapshot chains).
    function _acceptBids(uint32 srcChainId, uint32 bodySrcChainId, uint32 worldwideDay, uint8 msgType)
        private
        returns (bool)
    {
        bytes32 key = bytes32((uint256(worldwideDay) << 32) | srcChainId);
        if (bodySrcChainId != srcChainId) {
            emit InboundMessageIgnored(srcChainId, msgType, key, InboundReason.CONFLICT);
            return false;
        }
        if (!_isSeriesTarget(worldwideDay, srcChainId)) {
            emit InboundMessageIgnored(srcChainId, msgType, key, InboundReason.NOT_FOUND);
            return false;
        }
        return true;
    }

    // --- Internal helpers ---
    /// @dev Encode an AUCTION_STAGE_START message from the grouped params struct.
    function _encodeAuctionStageStart(AuctionStageStartParams calldata p) private pure returns (bytes memory) {
        return BridgeMsgCodec.encodeAuctionStageStart(
            p.worldwideDay,
            p.commitEnd,
            p.revealEnd,
            p.issuanceEnd,
            p.promisLoadMinor,
            p.minIntexBidRate,
            p.prices,
            p.callNoticePeriod,
            p.callWindow,
            p.callThreshold,
            p.minIntexBidQuantity,
            p.commitBondMinor,
            p.dayState
        );
    }

    function _toCodecPayloads(IssuanceInstructionsParams[] calldata series)
        private
        pure
        returns (BridgeMsgCodec.IssuanceInstructionsPayload[] memory payloads)
    {
        payloads = new BridgeMsgCodec.IssuanceInstructionsPayload[](series.length);
        for (uint256 i = 0; i < series.length; i++) {
            payloads[i] = _toCodecPayload(series[i]);
        }
    }

    function _toCodecPayload(IssuanceInstructionsParams calldata p)
        private
        pure
        returns (BridgeMsgCodec.IssuanceInstructionsPayload memory payload)
    {
        // Member-wise assignment (rather than a struct literal) keeps the payload within the IR stack bound.
        payload.seriesId = p.seriesId;
        payload.worldwideDay = p.worldwideDay;
        payload.issuedIntexCount = p.issuedIntexCount;
        payload.promisLoadMinor = p.promisLoadMinor;
        payload.entryPriceMinor = p.entryPriceMinor;
        payload.floorPriceMinor = p.floorPriceMinor;
        payload.callNoticePeriod = p.callNoticePeriod;
        payload.issuanceCurrency = p.issuanceCurrency;
        payload.referenceCurrency = p.referenceCurrency;
        payload.callWindow = p.callWindow;
        payload.callThreshold = p.callThreshold;
        payload.callPriceMinor = p.callPriceMinor;
        payload.recipients = p.recipients;
        payload.quantities = p.quantities;
    }

    /// @notice ERC-165 support check, resolving the AccessControl interface ids.
    function supportsInterface(bytes4 interfaceId) public view override(AccessControlUpgradeable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    /// @inheritdoc IOriginRouter
    function sweepNative(address payable to, uint256 amount) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (to == address(0)) revert ZeroAddress("to");
        uint256 balance = address(this).balance;
        if (amount > balance) revert NativeBalanceInsufficient(balance, amount);

        // admin-only native recovery; arbitrary destination is intentional
        // slither-disable-next-line arbitrary-send-eth
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert NativeSweepFailed();

        emit NativeSwept(to, amount);
    }

    // --- Proceeds route ---
    /// @inheritdoc IOriginRouter
    function setProceedsRoute(address _tokenBridge, address _wrudis) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (_tokenBridge == address(0)) revert ZeroAddress("tokenBridge");
        if (_wrudis == address(0)) revert ZeroAddress("wrudis");
        OriginRouterStorage storage $ = _os();
        $.tokenBridge = _tokenBridge;
        $.wcoen = _wrudis;
        emit ProceedsRouteSet(_tokenBridge, _wrudis);
    }

    /// @inheritdoc IOriginRouter
    function tokenBridge() external view returns (address) {
        return _os().tokenBridge;
    }

    /// @inheritdoc IOriginRouter
    function wrudis() external view returns (address) {
        return _os().wcoen;
    }

    /// @inheritdoc IOriginRouter
    function parkedProceeds(uint256 idx) external view returns (ParkedProceeds memory) {
        return _os().parkedProceeds[idx];
    }

    /// @inheritdoc IERC7786TokenReceiver
    /// @dev The token bridge credits WCOEN before this call; we unwrap it and hand the native to the factory
    ///      precompile, which pays the series' creators. A distribution failure parks the native for retry so
    ///      the transfer still settles (returning the magic value) instead of bricking on redelivery.
    function onCrosschainTokensReceived(
        uint32 sourceDomain,
        bytes calldata from,
        uint256 amount,
        bytes calldata extraData
    ) external nonReentrant returns (bytes4) {
        OriginRouterStorage storage $ = _os();
        if (msg.sender != $.tokenBridge) revert UnauthorizedProceedsCaller(msg.sender);

        uint32 worldwideDay = abi.decode(extraData, (uint32));
        // Source must be in the day's frozen snapshot.
        if (!_isSeriesTarget(worldwideDay, sourceDomain)) revert UnexpectedProceedsSource(sourceDomain);
        // The bridge is permissionless: pin the source sender to the registered peer (its TargetRouter), else
        // anyone could open a distribution for any series and wipe its contributor provenance.
        if (keccak256(from) != keccak256(_remoteMessenger(sourceDomain))) revert UnauthorizedProceedsSender(from);

        IWCOEN($.wcoen).withdraw(amount);
        _distributeOrPark(worldwideDay, sourceDomain, SafeCast.toUint128(amount));

        return IERC7786TokenReceiver.onCrosschainTokensReceived.selector;
    }

    /// @inheritdoc IOriginRouter
    function retryProceeds(uint256 idx) external nonReentrant {
        ParkedProceeds storage p = _os().parkedProceeds[idx];
        if (p.amount == 0 || p.settled) revert NoParkedProceeds(idx);
        p.settled = true;
        IIntexFactory(_os().intexFactory).distribute{value: p.amount}(p.worldwideDay, p.srcChainId);
        emit ProceedsRetried(idx, p.worldwideDay, p.amount);
    }

    /// @dev Hand native proceeds to the factory precompile; park them for retry on failure. `srcChainId` lets the
    ///      factory track fan-in across the day's paying chains.
    function _distributeOrPark(uint32 worldwideDay, uint32 srcChainId, uint128 amount) private {
        // The sole caller (onCrosschainTokensReceived) is nonReentrant, so the catch-branch park write is safe.
        // slither-disable-next-line reentrancy-eth
        try IIntexFactory(_os().intexFactory).distribute{value: amount}(worldwideDay, srcChainId) {
            emit ProceedsDistributed(worldwideDay, amount);
        } catch {
            OriginRouterStorage storage $ = _os();
            uint256 idx = $.nextParkedProceedsIdx++;
            $.parkedProceeds[idx] =
                ParkedProceeds({worldwideDay: worldwideDay, srcChainId: srcChainId, amount: amount, settled: false});
            emit ProceedsParked(idx, worldwideDay, amount);
        }
    }
}
