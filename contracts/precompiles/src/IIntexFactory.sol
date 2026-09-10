// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IIntexFactory
/// @notice User-facing call surface for the IntexFactory runtime precompile:
///         settlement, Promis mining, and the dual-wallet authorized-settler
///         setter. Issuance is a module-to-module call (Desis -> IntexFactory)
///         exposed through the Rust `api`, not a precompile selector. Series
///         identity + lifecycle live in Intex; this precompile owns
///         settlement bookkeeping and the autonomous qualification index.
interface IIntexFactory {
    /// @notice Settle `amount` Issued Intexes of `seriesId` held by
    ///         `intexHolder`. Caller must be the holder or its authorized
    ///         settler. Allowed in Qualified (voluntary) and Called (forced).
    /// @dev The cost is paid by spending a PayNote, so this call moves no
    ///      tokens: the underlying assets reached the reserve vault when the
    ///      note was deposited.
    /// @param payNoteProof `outbe.paynote` spend proof. Must name the caller as its
    ///        spender, carry a token registered with the vault router under either of
    ///        the series' currencies, and cover the settlement cost. The issuance
    ///        currency converts through COEN and needs fresh rates.
    function settle(bytes14 seriesId, address intexHolder, uint256 amount, bytes calldata payNoteProof) external;

    /// @notice What settling one Intex of `seriesId` with `paymentToken` costs, and
    ///         which of the series' two currencies that token settles on. Reverts
    ///         for a token the series does not accept.
    /// @return settlementCurrency ISO 4217 code the payment is denominated in.
    /// @return payableUnits Amount to pay, in `paymentToken`'s own minor units.
    function quoteSettlement(bytes14 seriesId, address paymentToken)
        external
        view
        returns (uint16 settlementCurrency, uint256 payableUnits);

    /// @notice Burn settled Intexes and mint confidential Promis, gated by
    ///         off-chain proof of work. Caller is the holder. Authorized by the
    ///         holder's Promis modify key: `mac = HMAC(modifyKey, op-preimage)`
    ///         where `opNonce` MUST equal the holder's current on-chain promis
    ///         op-nonce (fetch via `rudis_deriveKeys` + `IPromis.opNonceOf`) and the
    ///         bound amount is `promis_load_minor * amount`. Returns the minted
    ///         Promis amount.
    function minePromis(bytes14 seriesId, uint256 amount, uint64 nonce, bytes32 mac, uint64 opNonce)
        external
        returns (uint256 promisAmount);

    /// @notice Authorize `settler` to settle the caller's position in `seriesId`.
    function setAuthorizedSettler(bytes14 seriesId, address settler) external;

    /// @notice Credit auction proceeds (native COEN, sent as msg.value) from
    ///         `srcChainId` into the day's pot. Callable only by the OriginRouter.
    ///         Creators are paid, proportional to each owner's Tribute Nominal
    ///         Amount, once every winning chain has routed its proceeds (or the
    ///         fan-in deadline passes); the payout itself is drained over later
    ///         blocks by the begin-block hook.
    /// @param worldwideDay Worldwide day (yyyymmdd) whose creators receive the proceeds.
    /// @param srcChainId Target chain the proceeds arrived from (for fan-in completeness).
    function distribute(uint32 worldwideDay, uint32 srcChainId) external payable;

    /// @notice One certified contributor record, exactly as Lysis committed it.
    ///         The canonical 84-byte leaf the chain re-hashes is
    ///         `owner ++ sourceTributeId ++ nominal`.
    struct ContributorLeaf {
        address owner;
        uint256 sourceTributeId;
        uint256 nominal;
    }

    /// @notice Pay one chunk-aligned range of certified contributors.
    /// @dev Permissionless: correctness comes from `proof`, not from the caller.
    ///      Each leaf receives `roundAmount * nominal / eligibleNominalTotal` and
    ///      is marked paid, so a replayed batch reverts before any transfer.
    /// @param worldwideDay Day whose payout round is open.
    /// @param startIndex Global index of the first leaf; must be a multiple of 256.
    /// @param leaves Records of one result chunk: a full 256-leaf chunk, or the
    ///        final partial chunk of the day.
    /// @param proof Sibling hashes above the chunk subtree, bottom-up.
    function payContributorBatch(
        uint32 worldwideDay,
        uint32 startIndex,
        ContributorLeaf[] calldata leaves,
        bytes32[] calldata proof
    ) external;

    /// @notice Progress of one day's payout round.
    struct ContributorRound {
        uint256 amount;
        uint32 contributorCount;
        uint256 paidSoFar;
        uint32 paidLeafCount;
    }

    /// @notice Read the open payout round for `worldwideDay`. All fields are
    ///         zero when no round is open.
    function contributorPayoutRound(uint32 worldwideDay) external view returns (ContributorRound memory);

    /// @notice Read one 256-leaf word of the paid bitmap; bit `b` of word `w`
    ///         is leaf `256 * w + b`.
    function contributorPaidWord(uint32 worldwideDay, uint32 wordIndex) external view returns (uint256);

    /// @notice A new series was created from a cleared auction.
    event SeriesIssued(bytes14 indexed seriesId, uint32 issuedIntexCount, uint256 entryPrice);

    /// @notice `amount` Issued Intexes of `seriesId` were settled.
    event Settled(bytes14 indexed seriesId, address indexed intexHolder, address indexed settler, uint256 amount);

    /// @notice Settled Intexes were burned and `promisAmount` Promis minted.
    event PromisMined(bytes14 indexed seriesId, address indexed holder, uint256 amount, uint256 promisAmount);

    /// @notice The series qualified (Issued -> Qualified).
    event SeriesQualified(bytes14 indexed seriesId);

    /// @notice The series was force-called (Qualified -> Called).
    event SeriesCalled(bytes14 indexed seriesId, uint32 calledAt);

    /// @notice The series' settlement window closed. Both are zero when every unit
    ///         was realized in time.
    event SeriesExpired(bytes14 indexed seriesId, uint32 forfeitedUnits, uint256 returnedPromis);

    /// @notice One chain routed `amount` native COEN of `worldwideDay`'s auction
    ///         proceeds into the day's pot. Emitted once per delivery, so a chain
    ///         routing its proceeds in parts emits once per part.
    event ProceedsCredited(uint32 indexed worldwideDay, uint32 indexed srcChainId, uint256 amount);

    /// @notice The day's auction proceeds were fully paid out to `contributors`
    ///         tribute owners, totalling `amount` native COEN.
    event ProceedsDistributed(uint32 indexed worldwideDay, uint256 amount, uint32 contributors);

    /// @notice Ownerless proceeds for the day (no contributors recorded) were
    ///         burned instead of being distributed.
    event ProceedsBurned(uint32 indexed worldwideDay, uint256 amount);

    /// @notice Proceeds for `worldwideDay` are collected and its payout round is
    ///         open: `amount` native COEN is now split across `contributorCount`
    ///         certified contributors.
    event ContributorPayoutOpened(uint32 indexed worldwideDay, uint256 amount, uint32 contributorCount);

    /// @notice One verified batch of `leafCount` contributors starting at
    ///         `startIndex` was paid `paidAmount` native COEN in total.
    event ContributorBatchPaid(uint32 indexed worldwideDay, uint32 startIndex, uint32 leafCount, uint256 paidAmount);

    /// @notice Every contributor of `worldwideDay` has been paid. `burnedAmount`
    ///         is what per-leaf floor division left behind and was destroyed;
    ///         the day accepts no further batches.
    event ContributorRoundClosed(uint32 indexed worldwideDay, uint256 paidAmount, uint256 burnedAmount);

    /// @notice Proceeds arrived for `worldwideDay` after its payout round had
    ///         already opened, missing the fan-in window, and were burned.
    event LateProceedsBurned(uint32 indexed worldwideDay, uint256 amount);
}
