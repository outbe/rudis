// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IOracle
/// @notice Oracle precompile at 0x000000000000000000000000000000000000EE05
interface IOracle {
    // Events - precompile dispatch (appear in transaction receipts)
    event VoteSubmitted(address indexed validator, uint32 tupleCount);
    event FeederDelegated(address indexed validator, address indexed feeder);
    event VoteTargetDeactivated(address indexed base, address indexed quote);
    event VoteTargetActivated(address indexed base, address indexed quote);
    event ExchangeRateSet(address indexed base, address indexed quote, uint256 rate);

    // Events - block hooks (emitted during tally/slash/S-curve processing)
    event ExchangeRateUpdated(address indexed base, address indexed quote, uint256 rate, uint64 blockNumber);
    event TallyCompleted(uint64 blockNumber, uint32 pairsUpdated);
    event ValidatorSlashed(address indexed validator, uint64 slashPercent);
    event ValidatorForcedExit(address indexed validator);
    event ScurvePeakDetected(address indexed base, address indexed quote, uint256 peakPrice, uint64 peakDay);
    /// @notice Emitted once per pair when a closed UTC calendar day's VWAP is
    /// finalized into state. `utcDay` is a yyyymmdd UTC date key (e.g. 20260625).
    /// @dev Uses all three indexable topics; no further field can be indexed.
    event VwapCalculated(uint32 indexed utcDay, address indexed base, address indexed quote, uint256 vwap);

    /// @notice One quoted rate in an aggregate vote.
    /// @dev `base` and `quote` must match the direction the pair was registered
    ///      in. The storage key is order-independent, so a flipped quote would
    ///      otherwise submit an uninverted rate for the same pair; it reverts.
    ///      COEN/ISO rates and COEN volumes use six decimals. Generic pairs keep
    ///      their existing decimal18 contract.
    struct ExchangeRateTuple {
        address base;
        address quote;
        uint256 exchangeRate;
        uint256 volume;
    }

    /// @notice Returns the current exchange rate for a market, quoted in the
    ///         caller's direction.
    /// @dev Generic pairs preserve their registered orientation; COEN/ISO uses
    ///      COEN as base. Quoting a market backwards returns `scale^2 / rate`:
    ///      `1e12 / rate` for COEN/ISO and `1e36 / rate` for generic pairs. An
    ///      unpublished rate is `0` from either side. Reverts
    ///      if the market is not registered. Unlike the other pair-scoped reads,
    ///      this one accepts either direction - a spot rate is the only value
    ///      here that has a well-defined inverse.
    function getExchangeRate(address base, address quote) external view returns (uint256 rate);

    /// @notice `getExchangeRate` for `COEN/<isoCode>`. COEN is the zero address
    ///         and so always sorts first: this is never the inverted direction.
    ///         Every ISO reference currency uses the six-decimal COEN/ISO contract.
    function getRudisExchangeRateFor(uint16 isoCode) external view returns (uint256 rate);

    /// @notice `amount`, denominated in `fromIso`, re-expressed in `toIso` via
    ///         both COEN legs: `amount * rate(COEN/toIso) / rate(COEN/fromIso)`,
    ///         rounded up. Equal currencies return `amount` unchanged.
    /// @dev Reverts when either leg has no registered pair or no published rate.
    function currencyCrossRate(uint16 fromIso, uint16 toIso, uint256 amount) external view returns (uint256 converted);

    /// @notice `getExchangeRate` plus when the rate was last written. The block
    ///         and timestamp describe the stored observation and are the same
    ///         whichever direction the market is quoted in.
    function getExchangeRateData(address base, address quote)
        external
        view
        returns (uint256 rate, uint64 lastBlock, uint64 lastTimestamp);

    /// @notice Returns VWAP in the pair's registered scale over a lookback period.
    function getVwap(address base, address quote, uint64 lookbackSeconds) external view returns (uint256 vwap);

    /// @notice Returns VWAP in the pair's registered scale for an explicit range.
    function getVwapForTimeRange(address base, address quote, uint64 startTime, uint64 endTime)
        external
        view
        returns (uint256 vwap);

    /// @notice Returns the maximum active S-curve value in the pair's scale.
    function getScurveValue(address base, address quote, uint64 timestamp) external view returns (uint256 value);

    /// @notice Returns oracle parameters.
    function getParams()
        external
        view
        returns (
            uint64 votePeriod,
            uint256 rewardBand,
            uint64 slashWindow,
            uint256 minValidPerWindow,
            uint256 slashFraction,
            uint64 lookbackDuration,
            bool enabled
        );

    /// @notice Returns vote penalty counters for a validator.
    function getVotePenaltyCounter(address validator)
        external
        view
        returns (uint64 success, uint64 abstain, uint64 miss);

    /// @notice Returns the feeder address delegated by a validator.
    function getFeederDelegation(address validator) external view returns (address feeder);

    /// @notice Returns whether a pair is an active vote target.
    function isVoteTarget(address base, address quote) external view returns (bool);

    /// @notice Returns the number of registered pairs.
    function getPairCount() external view returns (uint32 count);

    /// @notice The pair at a 1-based registry index, in registered orientation,
    ///         with the decimals each side is quoted in.
    /// @dev Together with `getPairCount` this is how the whole registry is
    ///      enumerated. Reverts outside `1..getPairCount()`.
    function getPairByIndex(uint32 index)
        external
        view
        returns (address base, address quote, uint8 baseScale, uint8 quoteScale);

    /// @notice Returns all active vote target pairs.
    function getVoteTargets() external view returns (address[] memory bases, address[] memory quotes);

    /// @notice Returns the pending aggregate vote for a validator.
    function getAggregateVote(address validator)
        external
        view
        returns (
            bool exists,
            address[] memory bases,
            address[] memory quotes,
            uint256[] memory rates,
            uint256[] memory volumes
        );

    /// @notice Returns slash window progress for a validator.
    function getSlashWindowProgress(address validator)
        external
        view
        returns (uint64 success, uint64 abstain, uint64 miss, uint64 slashWindow);

    // todo delete?
    /// @notice Bootstrap write: set exchange rate (system-only, Address::ZERO caller).
    function setExchangeRate(address base, address quote, uint256 rate) external;

    /// @notice Delegate feeder consent from validator to feeder address.
    function delegateFeederConsent(address feeder) external;

    /// @notice Submit aggregate oracle vote.
    function submitVote(ExchangeRateTuple[] calldata tuples) external;

    /// @notice Deactivate a pair's vote target status (system-only).
    function deactivateVoteTarget(address base, address quote) external;

    /// @notice Activate a pair's vote target status (system-only).
    function activateVoteTarget(address base, address quote) external;

    // --- New query functions (ORC-AUD-027) ---

    /// @notice Returns price snapshot history for a pair (most recent first).
    function getPriceSnapshotHistory(address base, address quote, uint32 count)
        external
        view
        returns (uint64[] memory timestamps, uint256[] memory rates, uint256[] memory volumes);

    /// @notice Returns flattened price snapshot history across all pairs (most recent snapshots first).
    function getAllPriceSnapshotHistory(uint32 count)
        external
        view
        returns (
            uint64[] memory snapshotIds,
            uint64[] memory timestamps,
            address[] memory bases,
            address[] memory quotes,
            uint256[] memory rates,
            uint256[] memory volumes
        );

    /// @notice Returns TWAP (time-weighted average price) for a pair.
    function getTwap(address base, address quote, uint64 lookbackSeconds) external view returns (uint256 twap);

    /// @notice Returns TWAPs for all active vote-target pairs. The input
    /// `lookback` is the requested lookback window in seconds; the returned
    /// `lookbackSeconds` array reports the lookback actually used per pair.
    function getTwaps(uint64 lookback)
        external
        view
        returns (
            address[] memory bases,
            address[] memory quotes,
            uint256[] memory twaps,
            uint64[] memory lookbackSeconds
        );

    /// @notice Returns VWAP over the last 24 hours for a pair.
    function getDayVwap(address base, address quote) external view returns (uint256 vwap);

    /// @notice Returns the finalized VWAP for a full UTC calendar day.
    /// @param utcDay yyyymmdd UTC date key (e.g. 20260625). Reverts if the day
    ///        is not yet finalized or had no oracle data for the pair. For the
    ///        in-progress current day use `getVwapForTimeRange` instead.
    function getUtcDayVwap(address base, address quote, uint32 utcDay) external view returns (uint256 vwap);

    /// @notice Returns VWAPs for all active vote-target pairs over an explicit WorldwideDay-style window.
    function getWorldwideDayVwap(uint64 startTime, uint64 endTime)
        external
        view
        returns (
            address[] memory bases,
            address[] memory quotes,
            uint256[] memory vwaps,
            uint64[] memory lookbackSeconds
        );

    /// @notice Returns a stored WorldwideDay VWAP snapshot by WWD key.
    function getWorldwideDayVwapSnapshot(uint32 worldwideDay)
        external
        view
        returns (
            uint64 startTime,
            uint64 endTime,
            address[] memory bases,
            address[] memory quotes,
            uint256[] memory vwaps,
            uint64[] memory lookbackSeconds
        );

    /// @notice Returns all active S-curve entries for a pair.
    function getScurveEntries(address base, address quote)
        external
        view
        returns (uint64[] memory peakDays, uint256[] memory peakPrices, uint256[] memory currentValues);

    /// @notice Returns S-curve values for a pair at a timestamp.
    function getScurveValues(address base, address quote, uint64 timestamp)
        external
        view
        returns (uint64 targetDay, uint64[] memory peakDays, uint256[] memory peakPrices, uint256[] memory values);

    /// @notice Returns all S-curve data across all pairs.
    function getAllScurveData()
        external
        view
        returns (address[] memory bases, address[] memory quotes, uint64[] memory peakDays, uint256[] memory peakPrices);

    /// @notice Returns all S-curve data for one pair.
    function getAllScurveDataForPair(address base, address quote)
        external
        view
        returns (uint64[] memory peakDays, uint256[] memory peakPrices);

    /// @notice Returns the S-curve adjusted nominal price for a pair at a timestamp.
    function getNominalPrice(address base, address quote, uint64 timestamp) external view returns (uint256 price);

    /// @notice Returns nominal price components where nominal = max(VWAP, S-curve).
    function getNominalPriceComponents(address base, address quote, uint64 timestamp)
        external
        view
        returns (uint256 nominalPrice, uint256 vwap, uint256 maxScurve, string memory source);

    /// @notice Returns all registered reference currencies as ISO 4217 numeric codes.
    function getReferenceCurrencies() external view returns (uint16[] memory isoCodes);

    /// @notice Returns every ISO code with an independently configured policy rate.
    function getPolicyRateCurrencies() external view returns (uint16[] memory isoCodes);

    /// @notice Returns the annualized policy rate (scale 1e6) for an ISO 4217
    ///         code. Reverts when no policy rate is configured for the code.
    function getPolicyRate(uint16 isoCode) external view returns (uint256 rate);
}
