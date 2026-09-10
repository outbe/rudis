// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IIntexAuction} from "../../target/interfaces/IIntexAuction.sol";
import {IOriginRouter} from "../../origin/interfaces/IOriginRouter.sol";

/// @title BridgeMsgCodec
/// @author Outbe
/// @notice Library for encoding and decoding bridge messages between the target chains and Outbe.
/// @dev Auction messages (stages, bids, result, refunds) are keyed by `worldwideDay`; series messages
///      (issuance, mark) are keyed by `seriesId` and carry their day alongside it.
/// @dev Wire layout: `[bodyVersion(1)][msgType(1)][body]`. `bodyVersion` lets the format
///      evolve independently of `msgType`; decoders reject unknown versions.
library BridgeMsgCodec {
    /// @notice Active body version emitted by every `encode*` and required by every `decode*`.
    uint8 internal constant BODY_VERSION_V1 = 1;

    // Message types: target chain -> Outbe
    uint8 internal constant MSG_BIDS_BATCH = 1;
    uint8 internal constant MSG_BIDS_DONE = 2;

    // Message types: Outbe -> target chain
    uint8 internal constant MSG_AUCTION_STAGE_START = 3;
    uint8 internal constant MSG_AUCTION_STAGE_CLEARING = 4;
    uint8 internal constant MSG_AUCTION_RESULT = 5;
    uint8 internal constant MSG_ISSUANCE_INSTRUCTIONS = 6;
    uint8 internal constant MSG_REFUND_INSTRUCTIONS = 7;
    uint8 internal constant MSG_MARK_CALLED = 8;
    uint8 internal constant MSG_MARK_QUALIFIED = 9;

    /// @notice Upper bound on every caller-supplied cross-chain payload array
    ///         (`BIDS_BATCH`, `ISSUANCE_INSTRUCTIONS`, `REFUND_INSTRUCTIONS`).
    /// @dev One system-wide cap (unified with the bridge `MAX_BATCH_SIZE`). Derived from the binding
    ///      `maxMessageSize = 10_000` byte ceiling (bids ~128 B/item caps near 78) with
    ///      destination-gas headroom. Enforced OUTBOUND inside every `encode*` function (fail-fast
    ///      at the source) AND re-checked INBOUND inside the variable-length `decode*` functions
    ///      (defence-in-depth against a peer compromise or future encoder change). An inbound
    ///      over-cap revert is caught by the drop-don't-block handler so the ORDERED lane stays
    ///      live.
    uint16 internal constant MAX_PAYLOAD_ARRAY_LEN = 64;

    /// @notice Series one ISSUANCE_INSTRUCTIONS message may carry. With `MAX_RECIPIENTS_PER_ISSUANCE`
    ///         recipients split across them the worst case stays inside the 10_000-byte send cap.
    uint16 internal constant MAX_SERIES_PER_ISSUANCE = 8;

    /// @notice Recipients one ISSUANCE_INSTRUCTIONS may carry across all its series. Narrower than
    ///         `MAX_PAYLOAD_ARRAY_LEN`: a recipient costs a mint, so a wider day spans several messages.
    uint16 internal constant MAX_RECIPIENTS_PER_ISSUANCE = 24;

    /// @notice Series one MARK_CALLED or MARK_QUALIFIED message may carry. A batch is one day's series
    ///         that took the same decision at the same moment, so it is short.
    uint16 internal constant MAX_SERIES_PER_MARK = 8;

    /// @notice Chunks one day's fan-out may span; keeps a receiver's arrival set in one word.
    uint16 internal constant MAX_CHUNKS = 256;

    /// @notice Numeric fixed-point scale for bid/clearing rates (`1e6` = 100%).
    uint32 internal constant SCALE_1E6 = 1_000_000;

    // --- Minimum encoded lengths ---
    // Header is fixed at 2 bytes: [bodyVersion(1)][msgType(1)].
    uint16 internal constant HEADER_LEN = 2;

    // Fixed head of AUCTION_STAGE_START; the price rows follow it.
    uint16 internal constant MIN_LEN_AUCTION_STAGE_START = 70;
    /// @notice Bytes per reference-price row: [iso(2)][entry(8)][floor(8)][call(8)].
    uint16 internal constant REFERENCE_PRICE_LEN = 26;
    /// @notice The oracle's reference list is short; a day may not exceed this.
    uint8 internal constant MAX_REFERENCE_PRICES = 6;
    uint16 internal constant MIN_LEN_AUCTION_STAGE_CLEARING = 6;
    uint16 internal constant MIN_LEN_AUCTION_RESULT = 22;
    // MARK_CALLED: header + abi.encode(worldwideDay, calledAt, seriesIds); one series is 5 words.
    uint16 internal constant MIN_LEN_MARK_CALLED = HEADER_LEN + 160;
    // MARK_QUALIFIED: header + abi.encode(worldwideDay, seriesIds); one series is 4 words.
    uint16 internal constant MIN_LEN_MARK_QUALIFIED = HEADER_LEN + 128;
    // BIDS_DONE: [ver(1)][type(1)][worldwideDay(4)][srcChainId(4)][relayGeneration(4)][totalBatches(2)][totalBids(4)]
    uint16 internal constant MIN_LEN_BIDS_DONE = 20;

    // abi.encode payloads have variable length. The minimum corresponds to all
    // dynamic arrays being empty:
    //   BIDS_BATCH(uint32, uint32, uint32, uint16, uint16, address[], uint256[]):
    //     5 static head words + 2 dynamic head offsets + 2 empty length words = 9x32 = 288
    //   REFUND_INSTRUCTIONS(uint32, uint16, uint16, address[], uint64[], uint64[]):
    //     3 static head words + 3 dynamic offsets + 3 empty length words = 9x32 = 288
    //   ISSUANCE_INSTRUCTIONS(3 static head words + dynamic array of a struct with 12 static + 2 dynamic fields):
    //     3 head words + array offset(32) + array length(32) + one element's offset(32) + 12 static
    //     + 2 inner offsets + 2 empty length words = 22x32 = 704
    uint16 internal constant MIN_LEN_BIDS_BATCH = HEADER_LEN + 288;
    uint16 internal constant MIN_LEN_REFUND_INSTRUCTIONS = HEADER_LEN + 288;
    uint16 internal constant MIN_LEN_ISSUANCE_INSTRUCTIONS = HEADER_LEN + 704;

    /// @notice Per-message cap on inbound BIDS_BATCH entries. Bounds the crosschainMint/storage loop the
    ///         receiver runs so one oversized batch cannot exceed the inbound gas limit and stall
    ///         the ordered lane; larger bid sets are chunked into multiple batches by the sender.
    /// @dev Unified with the outbound `MAX_PAYLOAD_ARRAY_LEN` so inbound and outbound
    ///      agree on one number. The earlier value of 256 was the original ticket figure and is
    ///      physically unsendable: a bids batch is ~128 B/item, so 256 items is ~32 KB - over 3x
    ///      ERC-7786's send-side `maxMessageSize = 10_000` byte cap (an over-cap send reverts on
    ///      the source chain). The real byte ceiling lands near 78 items; 64 sits under it with gas
    ///      headroom, and the outbound encoder already rejects anything larger.
    uint256 internal constant MAX_BIDS_BATCH = MAX_PAYLOAD_ARRAY_LEN;

    /// @notice Body decoded with an unsupported `bodyVersion` byte.
    /// @param got The version byte read from the payload.
    error UnsupportedBodyVersion(uint8 got);

    /// @notice Inbound payload is shorter than the minimum encoding for its `msgType`.
    /// @param msgType The message-type byte read from the payload.
    /// @param got The actual length of the inbound payload.
    /// @param minimum The minimum required length for this `msgType`.
    error InvalidPayloadLength(uint8 msgType, uint256 got, uint256 minimum);

    /// @notice Inbound payload's `msgType` is not in the handler's accepted set.
    /// @param got The unrecognised type byte.
    error UnknownMsgType(uint8 got);

    /// @notice A `bytes32` interpreted as an address has non-zero high bits.
    /// @dev The Solidity address ABI uses the low 20 bytes; high 12 bytes must be zero.
    /// @param got The malformed `bytes32` slot.
    error MalformedAddress(bytes32 got);

    /// @notice REFUND_INSTRUCTIONS parallel arrays decoded to unequal lengths.
    /// @param bidders Length of the bidders array.
    /// @param refundedAmounts Length of the refunded-amounts array.
    /// @param paidAmounts Length of the paid-amounts array.
    error RefundArrayLengthMismatch(uint256 bidders, uint256 refundedAmounts, uint256 paidAmounts);

    /// @notice Inbound BIDS_BATCH exceeds the per-message entry cap.
    /// @param count Decoded number of bidders.
    /// @param max Maximum permitted entries per batch.
    error BidsBatchTooLarge(uint256 count, uint256 max);

    /// @notice BIDS_BATCH parallel arrays decoded to unequal lengths.
    /// @param bidders Length of the bidder-addresses array.
    /// @param packedBids Length of the packed-bid array.
    error BidsArrayLengthMismatch(uint256 bidders, uint256 packedBids);

    /// @notice ISSUANCE_INSTRUCTIONS parallel arrays decoded to unequal lengths.
    /// @param recipients Length of the recipients array.
    /// @param quantities Length of the quantities array.
    error IssuanceArrayLengthMismatch(uint256 recipients, uint256 quantities);

    /// @notice Inbound ISSUANCE_INSTRUCTIONS exceeds the per-message recipient cap.
    /// @param count Decoded number of recipients.
    /// @param max Maximum permitted recipients per message.
    error IssuanceBatchTooLarge(uint256 count, uint256 max);

    /// @notice A mark message carries no series; there is nothing for the target to apply.
    error EmptyMarkBatch();

    /// @notice A mark message exceeds the per-message series cap.
    /// @param count Number of series in the batch.
    /// @param max Maximum permitted series per mark message.
    error MarkBatchTooLarge(uint256 count, uint256 max);

    /// @notice Inbound REFUND_INSTRUCTIONS exceeds the per-message bidder cap.
    /// @param count Decoded number of bidders.
    /// @param max Maximum permitted bidders per message.
    error RefundBatchTooLarge(uint256 count, uint256 max);
    /// @notice A live day was encoded without a single reference price to bid against.
    error MissingReferencePrices();
    /// @notice An ISSUANCE_INSTRUCTIONS message carried no series at all.
    error EmptyIssuanceBatch();
    /// @notice An ISSUANCE_INSTRUCTIONS message carried more series than one may hold.
    error IssuanceSeriesBatchTooLarge(uint256 count, uint256 max);
    /// @notice The refund chunk header is inconsistent: no chunks claimed, more than
    ///         `MAX_CHUNKS`, or an index outside the claimed count.
    error InvalidRefundChunk(uint16 chunkIndex, uint16 totalChunks);
    /// @notice The issuance chunk header is inconsistent: no chunks claimed or an index outside the claimed count.
    error InvalidIssuanceChunk(uint16 chunkIndex, uint16 totalChunks);
    /// @notice A series in an ISSUANCE_INSTRUCTIONS message belongs to a different day than the message header.
    error IssuanceDayMismatch(bytes14 seriesId, uint32 seriesDay, uint32 messageDay);

    /// @notice An outbound payload array exceeds `MAX_PAYLOAD_ARRAY_LEN`.
    /// @dev Fail-fast on the source chain so the relayer learns before any bridge fee is burned.
    /// @param got The actual array length the encoder was given.
    /// @param max The configured `MAX_PAYLOAD_ARRAY_LEN`.
    error PayloadArrayTooLong(uint256 got, uint256 max);

    // --- Encoding ---

    /// @notice Reverts `PayloadArrayTooLong` if `_actual` exceeds `_max`.
    /// @dev The outbound cross-chain array cap. Called only from `encode*`.
    /// @param _actual The array length the encoder was given.
    /// @param _max The configured upper bound.
    function requireMaxArrayLen(uint256 _actual, uint256 _max) internal pure {
        if (_actual > _max) revert PayloadArrayTooLong(_actual, _max);
    }

    /// @notice Encodes a BIDS_DONE marker: source chain `_srcChainId` has sent all `_totalBatches` batches
    ///         of this flush generation for `_worldwideDay`.
    /// @dev Fixed-length encodePacked. `_totalBids` is an integrity check: the receiver requires it to equal the
    ///      sum of the arrived batch sizes before it treats the chain as complete. Redundant with the per-batch
    ///      `totalBatches` field, kept as the explicit completeness marker + a cross-check.
    /// @return The wire-encoded BIDS_DONE message.
    function encodeBidsDone(
        uint32 _worldwideDay,
        uint32 _srcChainId,
        uint32 _relayGeneration,
        uint16 _totalBatches,
        uint32 _totalBids
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            BODY_VERSION_V1, MSG_BIDS_DONE, _worldwideDay, _srcChainId, _relayGeneration, _totalBatches, _totalBids
        );
    }

    /// @notice Encodes BIDS_BATCH message.
    /// @dev A bid set larger than `MAX_PAYLOAD_ARRAY_LEN` is relayed as multiple batches sharing one
    ///      `_relayGeneration`; the receiver collects all `_totalBatches` (in any order) before finalizing
    ///      and replaces a re-flushed generation rather than double-counting it. Reverts `PayloadArrayTooLong`
    ///      if `_bidderAddresses` exceeds `MAX_PAYLOAD_ARRAY_LEN`.
    /// @param _worldwideDay The worldwide day (yyyymmdd).
    /// @param _srcChainId The source chainId the bids originated from.
    /// @param _relayGeneration The flush generation stamp the receiver uses to replace re-flushed sets.
    /// @param _batchIndex Index of this batch within the flush (0-based).
    /// @param _totalBatches Total number of batches in this flush (the receiver waits for all of them).
    /// @param _bidderAddresses The bidder addresses (parallel with `_packedBids`).
    /// @param _packedBids One [`packBid`] word per bidder: quantity, rate, timestamp and the pair.
    /// @return The wire-encoded BIDS_BATCH message.
    function encodeBidsBatch(
        uint32 _worldwideDay,
        uint32 _srcChainId,
        uint32 _relayGeneration,
        uint16 _batchIndex,
        uint16 _totalBatches,
        address[] memory _bidderAddresses,
        uint256[] memory _packedBids
    ) internal pure returns (bytes memory) {
        // Decoder rejects parallel-array mismatch with BidsArrayLengthMismatch; fail-fast at the
        // source so a sender-side bug aborts before paying the bridge fee.
        if (_bidderAddresses.length != _packedBids.length) {
            revert BidsArrayLengthMismatch(_bidderAddresses.length, _packedBids.length);
        }
        requireMaxArrayLen(_bidderAddresses.length, MAX_PAYLOAD_ARRAY_LEN);
        return abi.encodePacked(
            BODY_VERSION_V1,
            MSG_BIDS_BATCH,
            abi.encode(
                _worldwideDay, _srcChainId, _relayGeneration, _batchIndex, _totalBatches, _bidderAddresses, _packedBids
            )
        );
    }

    /// @notice Packs one bid's scalars into a single word: 64 bytes per bid rather than 128.
    /// @dev Layout, low bits up: [referenceCurrency(16)][issuanceCurrency(16)][timestamp(32)]
    ///      [bidRate(32)][quantity(16)].
    function packBid(
        uint16 _quantity,
        uint32 _bidRate,
        uint32 _timestamp,
        uint16 _issuanceCurrency,
        uint16 _referenceCurrency
    ) internal pure returns (uint256) {
        return uint256(_referenceCurrency) | (uint256(_issuanceCurrency) << 16) | (uint256(_timestamp) << 32)
            | (uint256(_bidRate) << 64) | (uint256(_quantity) << 96);
    }

    /// @notice Inverse of [`packBid`].
    function unpackBid(uint256 _packed)
        internal
        pure
        returns (uint16 quantity, uint32 bidRate, uint32 timestamp, uint16 issuanceCurrency, uint16 referenceCurrency)
    {
        referenceCurrency = uint16(_packed);
        issuanceCurrency = uint16(_packed >> 16);
        timestamp = uint32(_packed >> 32);
        bidRate = uint32(_packed >> 64);
        quantity = uint16(_packed >> 96);
    }

    /// @notice Encodes AUCTION_STAGE_START message.
    /// @dev encodePacked layout, 70 bytes of head plus 26 per priced currency:
    ///      [bodyVersion(1)][msgType(1)][worldwideDay(4)][commitEnd(4)][revealEnd(4)][issuanceEnd(4)]
    ///      [promisLoadMinor(16)][minIntexBidRate(4)][callNoticePeriod(4)][callWindow(4)]
    ///      [callThreshold(4)][minIntexBidQuantity(2)][commitBondMinor(16)][dayState(1)][priceCount(1)]
    ///      then [isoCode(2)][entryPrice(8)][floorPrice(8)][callPrice(8)] per currency.
    /// @param _worldwideDay The worldwide day (yyyymmdd).
    /// @param _commitEnd The commit-stage end timestamp.
    /// @param _revealEnd The reveal-stage end timestamp.
    /// @param _issuanceEnd The issuance-stage end timestamp.
    /// @param _promisLoadMinor The Promis load (minor units) for the series.
    /// @param _minIntexBidRate The minimum acceptable intex bid rate (`1e6` fixed-point).
    /// @param _prices Entry, floor and call price of every currency the day can clear in.
    /// @param _callNoticePeriod The Called->deadline window in seconds (0 = default).
    /// @param _callWindow The call-trigger observation window in seconds.
    /// @param _callThreshold The call-trigger threshold in seconds.
    /// @param _minIntexBidQuantity The minimum acceptable intex bid quantity.
    /// @param _commitBondMinor The commit-entry bond (payment-token minor units); 0 disables the bond.
    /// @param _dayState The final worldwide-day state (1 = Green, 2 = Red).
    /// @return The wire-encoded AUCTION_STAGE_START message.
    function encodeAuctionStageStart(
        uint32 _worldwideDay,
        uint32 _commitEnd,
        uint32 _revealEnd,
        uint32 _issuanceEnd,
        uint128 _promisLoadMinor,
        uint32 _minIntexBidRate,
        IOriginRouter.ReferenceCurrencyPrice[] memory _prices,
        uint32 _callNoticePeriod,
        uint32 _callWindow,
        uint32 _callThreshold,
        uint16 _minIntexBidQuantity,
        uint128 _commitBondMinor,
        uint8 _dayState
    ) internal pure returns (bytes memory) {
        if (_prices.length > MAX_REFERENCE_PRICES) {
            revert PayloadArrayTooLong(_prices.length, MAX_REFERENCE_PRICES);
        }
        // A live day must price something to bid against; a cancelled one is a closed record.
        if (_prices.length == 0 && _dayState != uint8(IIntexAuction.WorldwideDayState.Red)) {
            revert MissingReferencePrices();
        }
        bytes memory rows = abi.encodePacked(uint8(_prices.length));
        for (uint256 i = 0; i < _prices.length; ++i) {
            rows = abi.encodePacked(
                rows,
                _prices[i].isoCode,
                _prices[i].entryPriceMinor,
                _prices[i].floorPriceMinor,
                _prices[i].callPriceMinor
            );
        }
        // Split into packed halves: this many packed args in one call is too deep for the IR
        // pipeline. Concatenation of encodePacked results is byte-identical to a single call.
        return abi.encodePacked(
            abi.encodePacked(
                BODY_VERSION_V1,
                MSG_AUCTION_STAGE_START,
                _worldwideDay,
                _commitEnd,
                _revealEnd,
                _issuanceEnd,
                _promisLoadMinor,
                _minIntexBidRate
            ),
            _callNoticePeriod,
            _callWindow,
            _callThreshold,
            _minIntexBidQuantity,
            _commitBondMinor,
            _dayState,
            rows
        );
    }

    /// @notice Encodes AUCTION_STAGE_CLEARING message.
    /// @dev encodePacked layout (6 bytes): [bodyVersion(1)][msgType(1)][worldwideDay(4)]
    /// @param _worldwideDay The worldwide day (yyyymmdd).
    /// @return The wire-encoded AUCTION_STAGE_CLEARING message.
    function encodeAuctionStageClearing(uint32 _worldwideDay) internal pure returns (bytes memory) {
        return abi.encodePacked(BODY_VERSION_V1, MSG_AUCTION_STAGE_CLEARING, _worldwideDay);
    }

    /// @notice Encodes AUCTION_RESULT message.
    /// @dev encodePacked layout (22 bytes):
    ///      [bodyVersion(1)][msgType(1)][worldwideDay(4)][issuedIntexCount(4)][auctionClearingRate(8)][wonBidsCount(4)]
    /// @param _worldwideDay The worldwide day (yyyymmdd).
    /// @param _issuedIntexCount The number of intex issued by the cleared auction.
    /// @param _auctionClearingRate The uniform auction clearing rate (`1e6` fixed-point).
    /// @param _wonBidsCount The number of winning bids.
    /// @return The wire-encoded AUCTION_RESULT message.
    function encodeAuctionResult(
        uint32 _worldwideDay,
        uint32 _issuedIntexCount,
        uint64 _auctionClearingRate,
        uint32 _wonBidsCount
    ) internal pure returns (bytes memory) {
        return abi.encodePacked(
            BODY_VERSION_V1, MSG_AUCTION_RESULT, _worldwideDay, _issuedIntexCount, _auctionClearingRate, _wonBidsCount
        );
    }

    /// @notice Issuance instructions payload - grouped into a struct to keep the
    ///         encoder/decoder API resilient against EVM stack depth limits.
    /// @dev `issuedIntexCount` mirrors the auction-cleared count; the destination chain
    ///      pins it on `SeriesData` and `IntexNFT1155.issue` rejects any issue
    ///      that would push `totalSupply` past it.
    struct IssuanceInstructionsPayload {
        bytes14 seriesId;
        /// @notice Worldwide day the series was derived from - carried so the destination records real provenance.
        uint32 worldwideDay;
        uint32 issuedIntexCount;
        uint128 promisLoadMinor;
        uint64 entryPriceMinor;
        uint64 floorPriceMinor;
        /// @notice Duration in seconds between Called and the settlement deadline; 0 uses default.
        uint32 callNoticePeriod;
        uint16 issuanceCurrency;
        uint16 referenceCurrency;
        uint32 callWindow;
        uint32 callThreshold;
        uint64 callPriceMinor;
        address[] recipients;
        uint256[] quantities;
    }

    /// @notice Decode AUCTION_STAGE_START straight into the auction schedule + params structs.
    ///         Kept `external` so the struct construction lives in the linked library, off the
    ///         router's runtime size (EIP-170). Mirrors `encodeAuctionStageStart`'s layout:
    ///         [bodyVersion(1)][msgType(1)][worldwideDay(4)][commitEnd(4)][revealEnd(4)][issuanceEnd(4)]
    ///         [promisLoadMinor(16)][minIntexBidRate(4)][callNoticePeriod(4)][callWindow(4)]
    ///         [callThreshold(4)][minIntexBidQuantity(2)][commitBondMinor(16)][dayState(1)][priceCount(1)]
    /// @param _msg The wire-encoded AUCTION_STAGE_START message.
    /// @return worldwideDay The worldwide day (yyyymmdd).
    /// @return dayState The final worldwide-day state (Green or Red).
    /// @return schedule The decoded commit/reveal/issuance schedule.
    /// @return params The decoded auction params.
    function decodeAuctionParams(bytes calldata _msg)
        external
        pure
        returns (
            uint32 worldwideDay,
            IIntexAuction.WorldwideDayState dayState,
            IIntexAuction.AuctionSchedule memory schedule,
            IIntexAuction.AuctionParams memory params
        )
    {
        _assertMinLength(_msg, MSG_AUCTION_STAGE_START, MIN_LEN_AUCTION_STAGE_START);
        _assertBodyVersion(_msg);
        worldwideDay = uint32(bytes4(_msg[2:6]));
        uint8 rawDayState = uint8(_msg[68]);
        if (rawDayState > uint8(IIntexAuction.WorldwideDayState.Red)) revert IIntexAuction.InvalidDayState();
        dayState = IIntexAuction.WorldwideDayState(rawDayState);
        schedule = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(bytes4(_msg[6:10])),
            revealEnd: uint32(bytes4(_msg[10:14])),
            issuanceEnd: uint32(bytes4(_msg[14:18]))
        });
        params = IIntexAuction.AuctionParams({
            promisLoadMinor: uint128(bytes16(_msg[18:34])),
            callTrigger: IIntexAuction.IntexCallTrigger({
                callWindow: uint32(bytes4(_msg[42:46])),
                callThreshold: uint32(bytes4(_msg[46:50])),
                callNoticePeriod: uint32(bytes4(_msg[38:42]))
            }),
            minIntexBidRate: uint32(bytes4(_msg[34:38])),
            minIntexBidQuantity: uint16(bytes2(_msg[50:52])),
            prices: new IIntexAuction.ReferenceCurrencyPrice[](0),
            commitBondMinor: uint128(bytes16(_msg[52:68]))
        });

        params.prices = _referencePrices(_msg);
    }

    /// @notice Every priced row the message carries.
    function _referencePrices(bytes calldata _msg)
        private
        pure
        returns (IIntexAuction.ReferenceCurrencyPrice[] memory rows)
    {
        uint256 count = uint8(_msg[69]);
        // Re-checked inbound: more rows than the quoted gas covers would revert and redeliver.
        if (count > MAX_REFERENCE_PRICES) {
            revert PayloadArrayTooLong(count, MAX_REFERENCE_PRICES);
        }
        if (_msg.length != MIN_LEN_AUCTION_STAGE_START + count * REFERENCE_PRICE_LEN) {
            revert InvalidPayloadLength(MSG_AUCTION_STAGE_START, _msg.length, MIN_LEN_AUCTION_STAGE_START);
        }
        rows = new IIntexAuction.ReferenceCurrencyPrice[](count);
        for (uint256 i = 0; i < count; ++i) {
            uint256 at = MIN_LEN_AUCTION_STAGE_START + i * REFERENCE_PRICE_LEN;
            rows[i] = IIntexAuction.ReferenceCurrencyPrice({
                isoCode: uint16(bytes2(_msg[at:at + 2])),
                entryPriceMinor: uint64(bytes8(_msg[at + 2:at + 10])),
                floorPriceMinor: uint64(bytes8(_msg[at + 10:at + 18])),
                callPriceMinor: uint64(bytes8(_msg[at + 18:at + 26]))
            });
        }
    }

    /// @notice Encodes one chunk of the ISSUANCE_INSTRUCTIONS a chain receives from one day.
    /// @dev Capped at `MAX_SERIES_PER_ISSUANCE` series and `MAX_RECIPIENTS_PER_ISSUANCE` recipients;
    ///      a larger set is split by the sender into `_totalChunks` numbered messages.
    /// @param _worldwideDay The worldwide day (yyyymmdd) every series in the message belongs to.
    /// @param _chunkIndex Position of this chunk in the chain-day's run of issuance messages.
    /// @param _totalChunks How many chunks the chain-day's issuance spans.
    /// @param _series The per-series issuance payloads carried by this message.
    /// @return The wire-encoded ISSUANCE_INSTRUCTIONS message.
    function encodeIssuanceInstructions(
        uint32 _worldwideDay,
        uint16 _chunkIndex,
        uint16 _totalChunks,
        IssuanceInstructionsPayload[] memory _series
    ) internal pure returns (bytes memory) {
        _assertIssuanceLimits(_worldwideDay, _chunkIndex, _totalChunks, _series);
        return abi.encodePacked(
            BODY_VERSION_V1, MSG_ISSUANCE_INSTRUCTIONS, abi.encode(_worldwideDay, _chunkIndex, _totalChunks, _series)
        );
    }

    /// @dev Chunk header sanity, per-series day and array parity, plus the series and recipient counts.
    function _assertIssuanceLimits(
        uint32 _worldwideDay,
        uint16 _chunkIndex,
        uint16 _totalChunks,
        IssuanceInstructionsPayload[] memory _series
    ) private pure {
        if (_totalChunks == 0 || _chunkIndex >= _totalChunks) {
            revert InvalidIssuanceChunk(_chunkIndex, _totalChunks);
        }
        if (_series.length == 0) revert EmptyIssuanceBatch();
        if (_series.length > MAX_SERIES_PER_ISSUANCE) {
            revert IssuanceSeriesBatchTooLarge(_series.length, MAX_SERIES_PER_ISSUANCE);
        }
        uint256 recipients;
        for (uint256 i = 0; i < _series.length; i++) {
            if (_series[i].worldwideDay != _worldwideDay) {
                revert IssuanceDayMismatch(_series[i].seriesId, _series[i].worldwideDay, _worldwideDay);
            }
            if (_series[i].recipients.length != _series[i].quantities.length) {
                revert IssuanceArrayLengthMismatch(_series[i].recipients.length, _series[i].quantities.length);
            }
            recipients += _series[i].recipients.length;
        }
        if (recipients > MAX_RECIPIENTS_PER_ISSUANCE) {
            revert IssuanceBatchTooLarge(recipients, MAX_RECIPIENTS_PER_ISSUANCE);
        }
    }

    /// @notice Encodes one chunk of a day's REFUND_INSTRUCTIONS.
    /// @dev Reverts `PayloadArrayTooLong` if `_bidders` exceeds `MAX_PAYLOAD_ARRAY_LEN`.
    /// @param _worldwideDay The worldwide day (yyyymmdd).
    /// @param _bidders The bidder addresses (parallel with `_refundedAmounts` and `_paidAmounts`).
    /// @param _refundedAmounts The amount refunded to each bidder.
    /// @param _paidAmounts The amount paid by each bidder.
    /// @return The wire-encoded REFUND_INSTRUCTIONS message.
    function encodeRefundInstructions(
        uint32 _worldwideDay,
        uint16 _chunkIndex,
        uint16 _totalChunks,
        address[] memory _bidders,
        uint128[] memory _refundedAmounts,
        uint128[] memory _paidAmounts
    ) internal pure returns (bytes memory) {
        if (_bidders.length != _refundedAmounts.length || _bidders.length != _paidAmounts.length) {
            revert RefundArrayLengthMismatch(_bidders.length, _refundedAmounts.length, _paidAmounts.length);
        }
        requireMaxArrayLen(_bidders.length, MAX_PAYLOAD_ARRAY_LEN);
        if (_totalChunks == 0 || _totalChunks > MAX_CHUNKS || _chunkIndex >= _totalChunks) {
            revert InvalidRefundChunk(_chunkIndex, _totalChunks);
        }
        return abi.encodePacked(
            BODY_VERSION_V1,
            MSG_REFUND_INSTRUCTIONS,
            abi.encode(_worldwideDay, _chunkIndex, _totalChunks, _bidders, _refundedAmounts, _paidAmounts)
        );
    }

    /// @notice Encodes MARK_CALLED message for one day's batch of series.
    /// @dev Layout: [bodyVersion(1)][msgType(1)] ++ abi.encode(worldwideDay, calledAt, seriesIds); the
    ///      origin's stamp travels so every chain derives the same deadline.
    /// @param _worldwideDay The worldwide day the series were derived from.
    /// @param _calledAt Unix time the origin marked the series Called.
    /// @param _seriesIds The auction series identifiers, 1..`MAX_SERIES_PER_MARK` of them.
    /// @return The wire-encoded MARK_CALLED message.
    function encodeMarkCalled(uint32 _worldwideDay, uint32 _calledAt, bytes14[] memory _seriesIds)
        internal
        pure
        returns (bytes memory)
    {
        _assertMarkBatch(_seriesIds);
        return abi.encodePacked(BODY_VERSION_V1, MSG_MARK_CALLED, abi.encode(_worldwideDay, _calledAt, _seriesIds));
    }

    /// @notice Encodes MARK_QUALIFIED message for one day's batch of series.
    /// @dev Layout: [bodyVersion(1)][msgType(1)] ++ abi.encode(worldwideDay, seriesIds)
    /// @param _worldwideDay The worldwide day the series were derived from.
    /// @param _seriesIds The auction series identifiers, at most `MAX_SERIES_PER_MARK`.
    /// @return The wire-encoded MARK_QUALIFIED message.
    function encodeMarkQualified(uint32 _worldwideDay, bytes14[] memory _seriesIds)
        internal
        pure
        returns (bytes memory)
    {
        _assertMarkBatch(_seriesIds);
        return abi.encodePacked(BODY_VERSION_V1, MSG_MARK_QUALIFIED, abi.encode(_worldwideDay, _seriesIds));
    }

    /// @dev A mark batch carries at least one series and at most `MAX_SERIES_PER_MARK`.
    function _assertMarkBatch(bytes14[] memory _seriesIds) private pure {
        if (_seriesIds.length == 0) revert EmptyMarkBatch();
        if (_seriesIds.length > MAX_SERIES_PER_MARK) {
            revert MarkBatchTooLarge(_seriesIds.length, MAX_SERIES_PER_MARK);
        }
    }

    // --- Decoding ---

    /// @notice Decodes a BIDS_DONE marker.
    /// @param _msg The wire-encoded BIDS_DONE message.
    /// @return worldwideDay The worldwide day (yyyymmdd).
    /// @return srcChainId The source chainId that finished sending its bids.
    /// @return relayGeneration The flush generation this marker stamps.
    /// @return totalBatches Total batches the source chain sent for this generation.
    /// @return totalBids Total bids across those batches (integrity cross-check).
    function decodeBidsDone(bytes calldata _msg)
        internal
        pure
        returns (uint32 worldwideDay, uint32 srcChainId, uint32 relayGeneration, uint16 totalBatches, uint32 totalBids)
    {
        _assertExactLength(_msg, MSG_BIDS_DONE, MIN_LEN_BIDS_DONE);
        _assertBodyVersion(_msg);
        worldwideDay = uint32(bytes4(_msg[2:6]));
        srcChainId = uint32(bytes4(_msg[6:10]));
        relayGeneration = uint32(bytes4(_msg[10:14]));
        totalBatches = uint16(bytes2(_msg[14:16]));
        totalBids = uint32(bytes4(_msg[16:20]));
    }

    /// @notice Returns the body version byte (offset 0).
    /// @param _msg The wire-encoded bridge message.
    /// @return The body version byte at offset 0.
    function bodyVersion(bytes calldata _msg) internal pure returns (uint8) {
        return uint8(_msg[0]);
    }

    /// @notice Returns the message type byte (offset 1).
    /// @param _msg The wire-encoded bridge message.
    /// @return The message-type byte at offset 1.
    function msgType(bytes calldata _msg) internal pure returns (uint8) {
        return uint8(_msg[1]);
    }

    /// @dev Validates `_msg[0] == BODY_VERSION_V1`; reverts `UnsupportedBodyVersion` otherwise.
    function _assertBodyVersion(bytes calldata _msg) private pure {
        uint8 v = uint8(_msg[0]);
        if (v != BODY_VERSION_V1) revert UnsupportedBodyVersion(v);
    }

    /// @dev Asserts a fixed-width payload is *exactly* `_expected` bytes.
    ///      Closes (truncated/empty payloads would index past the slice and `Panic`)
    ///      and (over-long payloads were silently truncated to their valid prefix)
    ///      in one guard. Called *before* `_assertBodyVersion` so an empty payload yields a
    ///      typed `InvalidPayloadLength` rather than an out-of-bounds panic on `_msg[0]`.
    function _assertExactLength(bytes calldata _msg, uint8 _msgType, uint16 _expected) private pure {
        if (_msg.length != _expected) revert InvalidPayloadLength(_msgType, _msg.length, _expected);
    }

    /// @dev Asserts a variable-width payload carries at least its fixed head; the
    ///      exact length is checked against the row count once that head is read.
    function _assertMinLength(bytes calldata _msg, uint8 _msgType, uint16 _minimum) private pure {
        if (_msg.length < _minimum) revert InvalidPayloadLength(_msgType, _msg.length, _minimum);
    }

    /// @notice Decodes BIDS_BATCH message.
    /// @dev Reverts `UnsupportedBodyVersion` on a stale version byte,
    ///      `BidsArrayLengthMismatch` if the four parallel arrays differ in length, and
    ///      `BidsBatchTooLarge` if the batch exceeds `MAX_BIDS_BATCH`.
    /// @param _msg The wire-encoded BIDS_BATCH message.
    /// @return worldwideDay The worldwide day (yyyymmdd).
    /// @return srcChainId The source chainId the bids originated from.
    /// @return relayGeneration The flush generation stamp the receiver uses to replace re-flushed sets.
    /// @return batchIndex Index of this batch within the flush (0-based).
    /// @return totalBatches Total number of batches in this flush (the receiver waits for all of them).
    /// @return bidderAddresses The bidder addresses (parallel with `packedBids`).
    /// @return packedBids One [`packBid`] word per bidder.
    function decodeBidsBatch(bytes calldata _msg)
        internal
        pure
        returns (
            uint32 worldwideDay,
            uint32 srcChainId,
            uint32 relayGeneration,
            uint16 batchIndex,
            uint16 totalBatches,
            address[] memory bidderAddresses,
            uint256[] memory packedBids
        )
    {
        // Match the fixed-length decoders' typed empty-payload revert (mirrors readHeader and the
        // _assertExactLength helpers) so the symmetric path produces InvalidPayloadLength rather
        // than an out-of-bounds Panic(0x32) on `_msg[0]`.
        if (_msg.length < HEADER_LEN) revert InvalidPayloadLength(MSG_BIDS_BATCH, _msg.length, HEADER_LEN);
        _assertBodyVersion(_msg);
        (worldwideDay, srcChainId, relayGeneration, batchIndex, totalBatches, bidderAddresses, packedBids) =
            abi.decode(_msg[2:], (uint32, uint32, uint32, uint16, uint16, address[], uint256[]));
        // The two arrays are indexed in lockstep downstream; unequal lengths would index out of
        // bounds and panic inside the ordered lane. Reject with a typed error instead.
        if (bidderAddresses.length != packedBids.length) {
            revert BidsArrayLengthMismatch(bidderAddresses.length, packedBids.length);
        }
        // Cap the batch so the receiver's crosschainMint/storage loop cannot exceed the inbound gas limit.
        if (bidderAddresses.length > MAX_BIDS_BATCH) revert BidsBatchTooLarge(bidderAddresses.length, MAX_BIDS_BATCH);
    }

    /// @notice Decodes AUCTION_STAGE_CLEARING message.
    /// @dev encodePacked layout (6 bytes): [bodyVersion(1)][msgType(1)][worldwideDay(4)]
    ///      Reverts `InvalidPayloadLength` unless exactly 6 bytes, then `UnsupportedBodyVersion`.
    /// @param _msg The wire-encoded AUCTION_STAGE_CLEARING message.
    /// @return worldwideDay The worldwide day (yyyymmdd).
    function decodeAuctionStageClearing(bytes calldata _msg) internal pure returns (uint32 worldwideDay) {
        _assertExactLength(_msg, MSG_AUCTION_STAGE_CLEARING, MIN_LEN_AUCTION_STAGE_CLEARING);
        _assertBodyVersion(_msg);
        worldwideDay = uint32(bytes4(_msg[2:6]));
    }

    /// @notice Decodes AUCTION_RESULT message.
    /// @dev encodePacked layout (22 bytes):
    ///      [bodyVersion(1)][msgType(1)][worldwideDay(4)][issuedIntexCount(4)][auctionClearingRate(8)][wonBidsCount(4)]
    ///      Reverts `InvalidPayloadLength` unless exactly 22 bytes, then `UnsupportedBodyVersion`.
    /// @param _msg The wire-encoded AUCTION_RESULT message.
    /// @return worldwideDay The worldwide day (yyyymmdd).
    /// @return issuedIntexCount The number of intex issued by the cleared auction.
    /// @return auctionClearingRate The uniform auction clearing rate (`1e6` fixed-point).
    /// @return wonBidsCount The number of winning bids.
    function decodeAuctionResult(bytes calldata _msg)
        internal
        pure
        returns (uint32 worldwideDay, uint32 issuedIntexCount, uint64 auctionClearingRate, uint32 wonBidsCount)
    {
        _assertExactLength(_msg, MSG_AUCTION_RESULT, MIN_LEN_AUCTION_RESULT);
        _assertBodyVersion(_msg);
        worldwideDay = uint32(bytes4(_msg[2:6]));
        issuedIntexCount = uint32(bytes4(_msg[6:10]));
        auctionClearingRate = uint64(bytes8(_msg[10:18]));
        wonBidsCount = uint32(bytes4(_msg[18:22]));
    }

    /// @notice Decodes ISSUANCE_INSTRUCTIONS message.
    /// @dev Reverts `UnsupportedBodyVersion` on a stale version byte, `InvalidIssuanceChunk` on a bad chunk
    ///      header, `IssuanceDayMismatch` if a series names another day, `IssuanceArrayLengthMismatch` if
    ///      `recipients` and `quantities` differ in length, and `IssuanceBatchTooLarge` if `recipients`
    ///      exceeds `MAX_RECIPIENTS_PER_ISSUANCE`.
    /// @param _msg The wire-encoded ISSUANCE_INSTRUCTIONS message.
    /// @return worldwideDay The worldwide day (yyyymmdd) every series in the message belongs to.
    /// @return chunkIndex Position of this chunk in the chain-day's run of issuance messages.
    /// @return totalChunks How many chunks the chain-day's issuance spans.
    /// @return series The decoded per-series issuance payloads.
    function decodeIssuanceInstructions(bytes calldata _msg)
        external
        pure
        returns (
            uint32 worldwideDay,
            uint16 chunkIndex,
            uint16 totalChunks,
            IssuanceInstructionsPayload[] memory series
        )
    {
        if (_msg.length < HEADER_LEN) {
            revert InvalidPayloadLength(MSG_ISSUANCE_INSTRUCTIONS, _msg.length, HEADER_LEN);
        }
        _assertBodyVersion(_msg);
        // Decode in a dedicated frame so the struct ABI-decoder's locals don't share this
        // function's stack - keeps the 14-field payload within bounds under via_ir.
        (worldwideDay, chunkIndex, totalChunks, series) = _decodeIssuancePayload(_msg[2:]);
        // Re-checked inbound against a bad peer, as every variable-length decode here is.
        _assertIssuanceLimits(worldwideDay, chunkIndex, totalChunks, series);
    }

    /// @dev Isolated frame for the issuance ABI decode (via_ir stack relief).
    function _decodeIssuancePayload(bytes calldata _body)
        private
        pure
        returns (uint32, uint16, uint16, IssuanceInstructionsPayload[] memory)
    {
        return abi.decode(_body, (uint32, uint16, uint16, IssuanceInstructionsPayload[]));
    }

    /// @notice Decodes REFUND_INSTRUCTIONS message.
    /// @dev Reverts `UnsupportedBodyVersion` on a stale version byte and
    ///      `RefundArrayLengthMismatch` if the three parallel arrays differ in length.
    /// @param _msg The wire-encoded REFUND_INSTRUCTIONS message.
    /// @return worldwideDay The worldwide day (yyyymmdd).
    /// @return chunkIndex Position of this chunk in the chain-day's run of refunds.
    /// @return totalChunks How many chunks the chain-day's refunds span.
    /// @return bidders The bidder addresses (parallel with `refundedAmounts` and `paidAmounts`).
    /// @return refundedAmounts The amount refunded to each bidder.
    /// @return paidAmounts The amount paid by each bidder.
    function decodeRefundInstructions(bytes calldata _msg)
        external
        pure
        returns (
            uint32 worldwideDay,
            uint16 chunkIndex,
            uint16 totalChunks,
            address[] memory bidders,
            uint128[] memory refundedAmounts,
            uint128[] memory paidAmounts
        )
    {
        if (_msg.length < HEADER_LEN) {
            revert InvalidPayloadLength(MSG_REFUND_INSTRUCTIONS, _msg.length, HEADER_LEN);
        }
        _assertBodyVersion(_msg);
        (worldwideDay, chunkIndex, totalChunks, bidders, refundedAmounts, paidAmounts) =
            abi.decode(_msg[2:], (uint32, uint16, uint16, address[], uint128[], uint128[]));
        if (totalChunks == 0 || totalChunks > MAX_CHUNKS || chunkIndex >= totalChunks) {
            revert InvalidRefundChunk(chunkIndex, totalChunks);
        }
        // The three arrays are indexed in lockstep downstream; unequal lengths would index
        // out of bounds and panic inside the ordered lane. Reject with a typed error instead.
        if (bidders.length != refundedAmounts.length || bidders.length != paidAmounts.length) {
            revert RefundArrayLengthMismatch(bidders.length, refundedAmounts.length, paidAmounts.length);
        }
        // Symmetric with the BIDS and ISSUANCE inbound caps: a peer compromise or a future encoder
        // change could deliver an over-cap REFUND that exhausts the receiver's gas in the
        // per-bidder loop. The drop-don't-block handler catches this typed revert.
        if (bidders.length > MAX_PAYLOAD_ARRAY_LEN) {
            revert RefundBatchTooLarge(bidders.length, MAX_PAYLOAD_ARRAY_LEN);
        }
    }

    /// @notice Decodes MARK_CALLED message.
    /// @dev Reverts `InvalidPayloadLength` below the one-series minimum, then
    ///      `UnsupportedBodyVersion`, then the batch bounds, re-checked inbound.
    /// @param _msg The wire-encoded MARK_CALLED message.
    /// @return worldwideDay The worldwide day the series were derived from.
    /// @return calledAt Unix time the origin marked the series Called.
    /// @return seriesIds The auction series identifiers.
    function decodeMarkCalled(bytes calldata _msg)
        external
        pure
        returns (uint32 worldwideDay, uint32 calledAt, bytes14[] memory seriesIds)
    {
        if (_msg.length < MIN_LEN_MARK_CALLED) {
            revert InvalidPayloadLength(MSG_MARK_CALLED, _msg.length, MIN_LEN_MARK_CALLED);
        }
        _assertBodyVersion(_msg);
        (worldwideDay, calledAt, seriesIds) = abi.decode(_msg[2:], (uint32, uint32, bytes14[]));
        _assertMarkBatch(seriesIds);
    }

    /// @notice Decodes MARK_QUALIFIED message.
    /// @dev Reverts `InvalidPayloadLength` below the one-series minimum, then
    ///      `UnsupportedBodyVersion`, then the batch bounds.
    /// @param _msg The wire-encoded MARK_QUALIFIED message.
    /// @return worldwideDay The worldwide day the series were derived from.
    /// @return seriesIds The auction series identifiers.
    function decodeMarkQualified(bytes calldata _msg)
        external
        pure
        returns (uint32 worldwideDay, bytes14[] memory seriesIds)
    {
        return _decodeMark(_msg, MSG_MARK_QUALIFIED, MIN_LEN_MARK_QUALIFIED);
    }

    /// @dev Shared body of the two mark decoders; they differ only in which type they report.
    function _decodeMark(bytes calldata _msg, uint8 _msgType, uint16 _minLen)
        private
        pure
        returns (uint32 worldwideDay, bytes14[] memory seriesIds)
    {
        if (_msg.length < _minLen) revert InvalidPayloadLength(_msgType, _msg.length, _minLen);
        _assertBodyVersion(_msg);
        (worldwideDay, seriesIds) = abi.decode(_msg[2:], (uint32, bytes14[]));
        _assertMarkBatch(seriesIds);
    }

    // --- Validation helpers ---

    /// @notice Returns the minimum encoded length for the given `msgType`, or 0 if not recognised.
    /// @dev Caller is expected to validate `msgType in allowedSet` separately via
    ///      `UnknownMsgType` - a 0 return here means "unknown to the codec".
    /// @param _msgType The message-type byte to look up.
    /// @return The minimum encoded length for `_msgType`, or 0 if unknown to the codec.
    function minLengthFor(uint8 _msgType) internal pure returns (uint16) {
        if (_msgType == MSG_AUCTION_STAGE_START) return MIN_LEN_AUCTION_STAGE_START;
        if (_msgType == MSG_AUCTION_STAGE_CLEARING) return MIN_LEN_AUCTION_STAGE_CLEARING;
        if (_msgType == MSG_AUCTION_RESULT) return MIN_LEN_AUCTION_RESULT;
        if (_msgType == MSG_MARK_CALLED) return MIN_LEN_MARK_CALLED;
        if (_msgType == MSG_MARK_QUALIFIED) return MIN_LEN_MARK_QUALIFIED;
        if (_msgType == MSG_BIDS_BATCH) return MIN_LEN_BIDS_BATCH;
        if (_msgType == MSG_BIDS_DONE) return MIN_LEN_BIDS_DONE;
        if (_msgType == MSG_REFUND_INSTRUCTIONS) return MIN_LEN_REFUND_INSTRUCTIONS;
        if (_msgType == MSG_ISSUANCE_INSTRUCTIONS) return MIN_LEN_ISSUANCE_INSTRUCTIONS;
        return 0;
    }

    /// @notice Reverts `InvalidPayloadLength` if `_msg.length < minLengthFor(msgType)`.
    /// @dev Must be called *after* msgType validation; assumes `_msg.length >= 2`.
    /// @param _msg The wire-encoded bridge message.
    /// @param _msgType The message-type byte governing the minimum length.
    function assertMinLength(bytes calldata _msg, uint8 _msgType) internal pure {
        uint16 minLen = minLengthFor(_msgType);
        if (_msg.length < minLen) revert InvalidPayloadLength(_msgType, _msg.length, minLen);
    }

    /// @notice Validates the 2-byte header and returns the `msgType` byte.
    /// @dev Reverts `InvalidPayloadLength(0, got, HEADER_LEN)` if shorter than the header.
    ///      Does NOT validate the `msgType` is in any particular handler's accepted set -
    ///      that check is the caller's responsibility (revert `UnknownMsgType` on mismatch).
    /// @param _msg The wire-encoded bridge message.
    /// @return _msgType The message-type byte read from offset 1.
    function readHeader(bytes calldata _msg) internal pure returns (uint8 _msgType) {
        if (_msg.length < HEADER_LEN) revert InvalidPayloadLength(0, _msg.length, HEADER_LEN);
        _msgType = uint8(_msg[1]);
    }

    /// @notice Reverts `MalformedAddress(got)` if `_value` cannot be losslessly cast to `address`.
    /// @dev The Solidity address ABI uses the low 20 bytes; the high 12 bytes must be zero.
    /// @param _value The `bytes32` slot interpreted as an address.
    function assertAddress(bytes32 _value) internal pure {
        if (uint256(_value) >> 160 != 0) revert MalformedAddress(_value);
    }
}
