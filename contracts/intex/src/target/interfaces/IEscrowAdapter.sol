// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title EscrowAdapter Contract Interface
 * @author Outbe
 * @notice Public API, events, errors, and data types for escrow operations with The Compact.
 * @dev Integrates with The Compact protocol for locking bid funds and handles auction
 *      finalization. All escrow state is keyed by `worldwideDay` (uint32).
 */
interface IEscrowAdapter {
    // --- Types ---

    /// @notice Lock status for a bid.
    enum LockStatus {
        None,
        Locked,
        Finalized
    }

    /// @notice Bid lock data stored per series per bidder.
    /// @dev Slot-packed: `lockedAmount` (16B) + `lockedAt` (4B) + `status` (1B) = 21B, one slot;
    ///      `failedRefund` (16B) + `splitRecorded` (1B) = 17B, a second slot.
    struct BidLock {
        /// @notice Amount of payment-token locked.
        uint128 lockedAmount;
        /// @notice Timestamp when the lock was created (UNIX seconds).
        uint32 lockedAt;
        /// @notice Current status of the lock.
        LockStatus status;
        /// @notice Refund-portion of the finalization instruction that failed for this bidder.
        /// @dev Valid only when `splitRecorded` is true. Drives the post-finalize `claimRefund`
        ///      payout so a stranded winner is refunded only what they are owed, not the full lock.
        uint128 failedRefund;
        /// @notice Whether a validated failed split was recorded for this bidder.
        bool splitRecorded;
    }

    /// @notice Finalization instruction for a single bid.
    struct FinalizationInstruction {
        /// @notice Bidder address.
        address bidder;
        /// @notice Amount to refund to the bidder.
        uint128 refundedAmount;
        /// @notice Winning portion: routed to the proceeds recipient at finalization, burned on
        ///         the recovery paths (the series was already routed on Outbe by then).
        uint128 paidAmount;
    }

    /// @notice Per-series escrow state.
    struct AuctionEscrowState {
        /// @notice Total payment-token currently locked for the series.
        uint128 totalLocked;
        /// @notice Number of bid locks created for the series.
        uint32 lockCount;
        /// @notice Timestamp when `finalizeAuction` flipped `finalized = true` (UNIX seconds).
        /// @dev Drives the post-finalize window on `claimRefund`. 0 if never finalized.
        uint32 finalizedAt;
        /// @notice Whether the series escrow has been finalized.
        bool finalized;
    }

    /// @notice Commit-entry bond taken at `commitBid` and held until reveal/cancel/claim.
    /// @dev Existence sentinel is `amount > 0`; the record is deleted on release so a
    ///      commit->cancel->commit cycle can re-lock within the same series.
    struct CommitBond {
        /// @notice Amount of payment-token bonded.
        uint128 amount;
        /// @notice Timestamp when the bond was locked (UNIX seconds). Anchors the
        ///         escrow-local `claimAbandonedCommitBond` safety window.
        uint32 lockedAt;
    }

    // --- Events ---

    /// @notice Emitted when funds are locked for a bid during reveal.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose funds were locked.
    /// @param amount Amount of payment-token locked.
    event FundsLocked(uint32 indexed worldwideDay, address indexed bidder, uint128 amount);

    /// @notice Emitted when a commit-entry bond is locked at `commitBid`.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose bond was taken.
    /// @param amount Amount of payment-token bonded.
    event CommitBondLocked(uint32 indexed worldwideDay, address indexed bidder, uint128 amount);

    /// @notice Emitted when a commit-entry bond is returned to its owner (reveal, cancel,
    ///         auction-side claim, or the escrow-local abandoned-bond claim).
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder the bond was returned to.
    /// @param amount Amount of payment-token returned.
    event CommitBondReleased(uint32 indexed worldwideDay, address indexed bidder, uint128 amount);

    /// @notice Emitted when funds are refunded to a bidder.
    /// @param receiveId Inbound bridge message that triggered the refund, or `bytes32(0)` for a
    ///        permissionless `claimRefund` (not bridge-triggered).
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder who received the refund.
    /// @param amount Amount refunded to the bidder.
    event FundsRefunded(bytes32 indexed receiveId, uint32 indexed worldwideDay, address indexed bidder, uint128 amount);

    /// @notice Emitted when an undistributable winning portion is burned (sent to the canonical
    ///         dead address): `retryFinalize` residuals and post-finalize `claimRefund` remainders,
    ///         where the series proceeds were already routed on Outbe.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose winning portion was burned.
    /// @param amount Amount of payment-token burned.
    event ProceedsBurned(uint32 indexed worldwideDay, address indexed bidder, uint128 amount);

    /// @notice Emitted when a series escrow is finalized.
    /// @param receiveId Inbound bridge message that triggered finalization.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param totalRefunded Total refunded to bidders.
    /// @param totalPaid Total winning portion routed to the proceeds recipient.
    /// @param bidsProcessed Number of bids processed.
    event AuctionEscrowFinalized(
        bytes32 indexed receiveId,
        uint32 indexed worldwideDay,
        uint128 totalRefunded,
        uint128 totalPaid,
        uint32 bidsProcessed
    );

    /// @notice Emitted on each successful `wire()` call (initial + rotations).
    /// @dev Carries old+new for every dependency so a rotation is reconstructible from the log
    ///      alone; the `*Old` fields are `address(0)` on the initial wire.
    /// @param intexAuctionOld IntexAuction address before this wire.
    /// @param intexAuctionNew IntexAuction address after this wire.
    /// @param compactOld The Compact address before this wire.
    /// @param compactNew The Compact address after this wire.
    /// @param paymentTokenOld Active payment-token address before this wire.
    /// @param paymentTokenNew Active payment-token address after this wire.
    event Wired(
        address intexAuctionOld,
        address intexAuctionNew,
        address compactOld,
        address compactNew,
        address paymentTokenOld,
        address paymentTokenNew
    );

    /// @notice Emitted when a single bidder's finalization step fails. The lock stays in
    ///         `Locked` status and can be recovered via `retryFinalize` (RELAYER) or `claimRefund`
    ///         (permissionless, after the post-finalize safety window).
    /// @param receiveId Inbound bridge message that triggered the failed finalization.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose finalization step failed.
    /// @param reason Raw revert data from the failed per-bidder finalization call.
    event BidderRefundFailed(
        bytes32 indexed receiveId, uint32 indexed worldwideDay, address indexed bidder, bytes reason
    );

    /// @notice Emitted on a successful `retryFinalize` call.
    /// @param receiveId Original inbound bridge message the relayer is retrying for.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose finalization was retried.
    /// @param refundedAmount Amount refunded to the bidder on retry.
    /// @param paidAmount Winning portion burned on retry (the series was already routed).
    event BidderRetried(
        bytes32 indexed receiveId,
        uint32 indexed worldwideDay,
        address indexed bidder,
        uint128 refundedAmount,
        uint128 paidAmount
    );

    /// @notice Emitted when `finalizeAuction` settled zero bidders (every instruction failed). The
    ///         series is finalized but degenerate; bidders are recoverable only via `retryFinalize`.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidsProcessed Number of instructions processed, all of which failed.
    event FinalizationNoOp(uint32 indexed worldwideDay, uint32 bidsProcessed);

    /// @notice Emitted when the finalized-proceeds recipient is configured.
    /// @param recipient Address receiving each series' finalized proceeds.
    event ProceedsRecipientSet(address recipient);

    // --- Errors ---

    /// @notice Zero address provided.
    /// @param f Field name.
    error ZeroAddress(string f);
    /// @notice Zero value provided where non-zero is required.
    /// @param f Field name.
    error ZeroValue(string f);
    /// @notice Payment token does not report 18 decimals.
    /// @param actual Decimals the token reports.
    error PaymentTokenDecimals(uint8 actual);
    /// @notice Bidder already has locked funds for this series.
    error BidAlreadyLocked();
    /// @notice Lock is not in the active state required for this operation.
    error LockNotActive();
    /// @notice Series escrow has already been finalized.
    error AlreadyFinalized();
    /// @notice Refund + payout amounts do not match the locked amount.
    /// @param locked Locked amount.
    /// @param requested Requested total.
    error AmountMismatch(uint128 locked, uint128 requested);
    /// @notice `attest` was called for a lock id that does not match this escrow's `lockId`.
    /// @param id The unexpected lock id passed to `attest`.
    error UnexpectedLockId(uint256 id);
    /// @notice `authorizeClaim` is not a supported allocator operation on this escrow.
    error ClaimAuthorizationUnsupported();
    /// @notice The Compact forced withdrawal returned false (e.g. the reset period has not elapsed).
    error ForcedWithdrawalFailed();
    /// @notice No deposits made yet (lock id not set).
    error NoDeposits();
    /// @notice Cannot rotate the active payment token (or Compact) while funds remain locked.
    /// @dev The ERC6909 balance returned by The Compact is `uint256`; surfacing the full width
    ///      avoids silent truncation in the revert payload if the balance ever exceeds `uint128`.
    /// @param outstanding Total balance still held in The Compact for live locks.
    error LiveLocksOutstanding(uint256 outstanding);
    /// @notice Self-call helper invoked by an external caller (only `address(this)` is allowed).
    error NotSelf();
    /// @notice Finalization produced proceeds but no recipient is configured.
    error ProceedsRecipientNotSet();
    /// @notice `retryFinalize` invoked before the series was finalized at least once.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    error NotFinalizedYet(uint32 worldwideDay);
    /// @notice `claimRefund` was called before the safety window elapsed.
    /// @param claimableAt Earliest unix-seconds timestamp the refund can be claimed at.
    /// @param now_ Current block timestamp.
    error RefundNotYetClaimable(uint32 claimableAt, uint32 now_);
    /// @notice Post-finalize `claimRefund` has no validated split (bidder omitted or mismatched).
    ///         Reverts only until `NO_SPLIT_REFUND_DELAY`, after which the full principal is refundable.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose split was never recorded.
    error SplitNotRecorded(uint32 worldwideDay, address bidder);
    /// @notice `lockCommitBond` called while the bidder already holds a live bond for the series.
    error CommitBondAlreadyLocked();
    /// @notice No live commit bond exists for the series/bidder pair.
    error CommitBondNotFound();
    /// @notice `claimAbandonedCommitBond` was called before the escrow-local safety window elapsed.
    /// @param claimableAt Earliest unix-seconds timestamp the bond can be claimed at.
    /// @param now_ Current block timestamp.
    error CommitBondNotYetAbandoned(uint32 claimableAt, uint32 now_);

    // --- Admin ---

    /// @notice Wire contract dependencies.
    /// @dev After the first wiring, rotating `_paymentToken` or `_compact` reverts with
    ///      `LiveLocksOutstanding` while any locked balance remains in The Compact.
    /// @param _intexAuction IntexAuction contract address.
    /// @param _compact The Compact contract address.
    /// @param _paymentToken Active payment-token address.
    function wire(address _intexAuction, address _compact, address _paymentToken) external;

    // --- Auction Integration ---

    /// @notice Lock funds for a bid during the reveal stage. Callable only by the IntexAuction contract.
    /// @dev The bidder must approve this contract to spend `paymentToken` beforehand.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address.
    /// @param amount Amount to lock (`intexQuantity * intexBidPrice`).
    function lockFunds(uint32 worldwideDay, address bidder, uint128 amount) external;

    /// @notice Lock the commit-entry bond at `commitBid`. Callable only by the IntexAuction contract.
    /// @dev The bidder must approve this contract to spend `paymentToken` beforehand. The bond is
    ///      held in The Compact under the same lock id as bid escrow.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address the bond is taken from (and later returned to).
    /// @param amount Bond amount (the series' `commitBondMinor`).
    function lockCommitBond(uint32 worldwideDay, address bidder, uint128 amount) external;

    /// @notice Return a live commit bond to its owner. Callable only by the IntexAuction contract
    ///         (reveal, cancel, and the auction-side stage-aware claim path).
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose bond is returned.
    function releaseCommitBond(uint32 worldwideDay, address bidder) external;

    /// @notice Active payment token used for bid escrow (WCOEN).
    function paymentToken() external view returns (IERC20);

    /// @notice Recipient of finalized auction proceeds (the router routing them cross-chain).
    function proceedsRecipient() external view returns (address);

    /// @notice Set the recipient of finalized auction proceeds.
    function setProceedsRecipient(address recipient) external;

    // --- Bridge Finalization ---

    /// @notice Finalize part of a day's escrow with per-bidder refund/payout instructions.
    /// @dev Called once per arriving set of a day's bidders. A lock leaves `Locked` on its
    ///      first instruction, so no bidder settles twice; `completesDay` closes the day.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param receiveId Inbound bridge message id that carried the refund instructions; threaded into the
    ///        emitted events so an indexer can attribute each fund movement to its source packet.
    /// @param instructions Array of finalization instructions per bidder.
    /// @param completesDay Whether this set is the last of the day's bidders.
    /// @return totalPaid Proceeds transferred to the caller for cross-chain routing to creators.
    function finalizeAuction(
        uint32 worldwideDay,
        bytes32 receiveId,
        FinalizationInstruction[] calldata instructions,
        bool completesDay
    ) external returns (uint128 totalPaid);

    // --- Recovery ---

    /// @notice Permissionless refund: full principal when the relayer never finalizes
    ///         (`UNFINALIZED_REFUND_DELAY`) or once `NO_SPLIT_REFUND_DELAY` elapses for an
    ///         omitted/mismatched `Locked` bidder; the recorded refund portion - with the
    ///         remainder burned - for a failed bidder with a validated split
    ///         (`POST_FINALIZE_REFUND_DELAY`). Pays the stored `bidder`, not `msg.sender`.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address whose locked principal is being claimed.
    function claimRefund(uint32 worldwideDay, address bidder) external;

    /// @notice Per-bidder retry after `finalizeAuction` left a bidder in `BidderRefundFailed`.
    ///         Gated by `RELAYER_ROLE` (operational, not admin). Lets the relayer deliver the
    ///         correct refund/payout split for a failed bidder once the upstream issue is fixed.
    /// @param worldwideDay Worldwide day (yyyymmdd) (must be already finalized).
    /// @param receiveId Original inbound bridge message id being retried; threaded into the emitted events.
    /// @param inst Finalization instruction for the single bidder being retried.
    function retryFinalize(uint32 worldwideDay, bytes32 receiveId, FinalizationInstruction calldata inst) external;

    /// @notice Escrow-local safety valve for a commit bond stranded past
    ///         `COMMIT_BOND_ABANDON_DELAY` (e.g. the auction contract was rotated away while the
    ///         bond was live). Time-based only - never consults the auction - and pays the stored
    ///         `bidder`, not `msg.sender`. The stage-aware fast path lives on IntexAuction.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder whose bond is being claimed.
    function claimAbandonedCommitBond(uint32 worldwideDay, address bidder) external;

    // --- Views ---

    /// @notice Get bid lock information.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address whose lock is being read.
    /// @return lock The stored `BidLock` record for the series/bidder pair.
    function getBidLock(uint32 worldwideDay, address bidder) external view returns (BidLock memory lock);

    /// @notice Get commit bond information. A zero `amount` means no live bond.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address whose bond is being read.
    /// @return bond The stored `CommitBond` record for the series/bidder pair.
    function getCommitBond(uint32 worldwideDay, address bidder) external view returns (CommitBond memory bond);

    /// @notice Get series escrow status.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @return hasLocks True if the series has at least one lock.
    /// @return isFinalized True if the series escrow is finalized.
    /// @return totalLocked Total payment-token currently locked for the series.
    function getAuctionStatus(uint32 worldwideDay)
        external
        view
        returns (bool hasLocks, bool isFinalized, uint128 totalLocked);

    /// @notice True while any lock is still live in The Compact under the active lock id.
    function hasOutstandingLocks() external view returns (bool outstanding);
}
