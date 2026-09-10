// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC6909} from "@openzeppelin/contracts/interfaces/IERC6909.sol";
import {IEscrowAdapter} from "./interfaces/IEscrowAdapter.sol";
import {ITheCompact} from "../vendor/the-compact/interfaces/ITheCompact.sol";
import {IAllocator} from "../vendor/the-compact/interfaces/IAllocator.sol";
import {Scope} from "../vendor/the-compact/types/Scope.sol";
import {ResetPeriod} from "../vendor/the-compact/types/ResetPeriod.sol";

/**
 * @title EscrowAdapter
 * @author Outbe
 * @notice Adapter contract for managing auction bid escrow via The Compact protocol.
 * @dev UUPS upgradeable: deployed behind an ERC1967 proxy, configured via `initialize`.
 *      Integrates with The Compact for fund locking and handles auction finalization.
 *      EscrowAdapter acts as SPONSOR (owns ERC6909 in Compact) and ALLOCATOR (attest);
 *      both roles bind to the proxy address.
 *      All escrow state is keyed by `worldwideDay` (uint32).
 */
contract EscrowAdapter is
    AccessControlUpgradeable,
    ReentrancyGuardTransient,
    UUPSUpgradeable,
    IEscrowAdapter,
    IAllocator
{
    using SafeERC20 for IERC20;

    // Roles
    /// @notice Role identifier for bridge operations (finalization).
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Role identifier for auction contract integration.
    bytes32 public constant AUCTION_ROLE = keccak256("AUCTION_ROLE");

    /// @notice Safety window before the bidder of a never-finalized series can `claimRefund` the
    ///         full principal, anchored at the lock's `lockedAt`. MUST exceed the longest
    ///         legitimate finalization latency (settlement window + cross-chain delivery).
    uint32 public constant UNFINALIZED_REFUND_DELAY = 72 hours;

    /// @notice Relayer-priority window after `finalizeAuction` for a failed bidder, anchored at
    ///         `finalizedAt`: time to `retryFinalize` (possibly with a corrected split) before the
    ///         recorded split becomes permissionlessly payable via `claimRefund`.
    uint32 public constant POST_FINALIZE_REFUND_DELAY = 72 hours;

    /// @notice Window after which an omitted/mismatched `Locked` bidder of a finalized series
    ///         (no recorded split) can `claimRefund` the full principal, anchored at
    ///         `finalizedAt`. MUST exceed `POST_FINALIZE_REFUND_DELAY`. Governance param.
    uint32 public constant NO_SPLIT_REFUND_DELAY = 30 days;

    /// @notice Escrow-local safety window on `claimAbandonedCommitBond`, anchored at the bond's
    ///         `lockedAt`. Deliberately time-only (never consults the auction) so a bond survives
    ///         an auction-contract rotation. MUST exceed the auction-side no-reveal gate
    ///         (`revealEnd + UNREVEALED_BOND_LOCK_PERIOD`), which holds while auction schedules span
    ///         less than 29 days (daily series span ~2).
    uint32 public constant COMMIT_BOND_ABANDON_DELAY = 30 days;

    /// @notice Decimals every payment token must report.
    uint8 public constant PAYMENT_TOKEN_DECIMALS = 18;

    /// @notice Canonical dead address receiving burned proceeds (the payment token has no burn()).
    address public constant BURN_ADDRESS = 0x000000000000000000000000000000000000dEaD;

    /// @custom:storage-location erc7201:outbe.intex.EscrowAdapter
    struct EscrowAdapterStorage {
        /// @dev IntexAuction contract address.
        address intexAuctionContract;
        /// @dev The Compact contract address.
        ITheCompact compact;
        /// @dev Active payment token used for bid escrow.
        IERC20 paymentToken;
        /// @dev The Compact resource lock ID for our deposits.
        uint256 lockId;
        /// @dev Allocator ID from __registerAllocator.
        uint96 allocatorId;
        /// @dev Lock tag (allocatorId + scope + reset period) for deposits.
        bytes12 lockTag;
        /// @dev Bid locks: worldwideDay => bidder => BidLock.
        mapping(uint32 worldwideDay => mapping(address bidder => BidLock)) bidLocks;
        /// @dev Per-series escrow state.
        mapping(uint32 worldwideDay => AuctionEscrowState) auctionEscrowState;
        /// @dev Commit-entry bonds: worldwideDay => bidder => CommitBond.
        mapping(uint32 worldwideDay => mapping(address bidder => CommitBond)) commitBonds;
        /// @dev Recipient of finalized auction proceeds (the router routing them cross-chain).
        address proceedsRecipient;
    }

    // keccak256(abi.encode(uint256(keccak256("outbe.intex.EscrowAdapter")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE_SLOT = 0x9dc6707131c30ec20e38ebcfbc4641faad640e3439439d400ea9dd2fe8f83a00;

    function _s() private pure returns (EscrowAdapterStorage storage $) {
        // solhint-disable-next-line no-inline-assembly
        assembly ("memory-safe") {
            $.slot := _STORAGE_SLOT
        }
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initializes the proxy with its role holders.
    /// @param defaultAdmin Receiver of `DEFAULT_ADMIN_ROLE`.
    function initialize(address defaultAdmin) external initializer {
        if (defaultAdmin == address(0)) revert ZeroAddress("defaultAdmin");

        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
    }

    /// @dev Upgrades are gated by the admin role.
    /// @param newImplementation Address of the implementation the proxy switches to.
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    // --- Storage getters ---
    /// @notice IntexAuction contract address.
    /// @return The wired auction contract.
    function intexAuctionContract() external view returns (address) {
        return _s().intexAuctionContract;
    }

    /// @notice The Compact contract address.
    /// @return The wired Compact instance.
    function compact() external view returns (ITheCompact) {
        return _s().compact;
    }

    /// @notice Active payment token used for bid escrow.
    /// @return The wired payment token.
    function paymentToken() external view override returns (IERC20) {
        return _s().paymentToken;
    }

    /// @inheritdoc IEscrowAdapter
    function proceedsRecipient() external view override returns (address) {
        return _s().proceedsRecipient;
    }

    /// @inheritdoc IEscrowAdapter
    function setProceedsRecipient(address recipient) external override onlyRole(DEFAULT_ADMIN_ROLE) {
        if (recipient == address(0)) revert ZeroAddress("recipient");
        _s().proceedsRecipient = recipient;
        emit ProceedsRecipientSet(recipient);
    }

    /// @notice The Compact resource lock ID for our deposits.
    /// @return The lock id (zero before the first deposit).
    function lockId() external view returns (uint256) {
        return _s().lockId;
    }

    /// @notice Allocator ID from `__registerAllocator`.
    /// @return The registered allocator id (zero before wiring).
    function allocatorId() external view returns (uint96) {
        return _s().allocatorId;
    }

    /// @notice Lock tag (allocatorId + scope + reset period) for deposits.
    /// @return The lock tag derived at allocator registration.
    function lockTag() external view returns (bytes12) {
        return _s().lockTag;
    }

    /// @notice Bid lock record for a bidder within a series. Flattened to match the original
    ///         public-mapping getter ABI.
    function bidLocks(uint32 worldwideDay, address bidder)
        external
        view
        returns (uint128 lockedAmount, uint32 lockedAt, LockStatus status, uint128 failedRefund, bool splitRecorded)
    {
        BidLock storage l = _s().bidLocks[worldwideDay][bidder];
        return (l.lockedAmount, l.lockedAt, l.status, l.failedRefund, l.splitRecorded);
    }

    /// @notice Per-series escrow state. Flattened to match the original public-mapping getter ABI.
    function auctionEscrowState(uint32 worldwideDay)
        external
        view
        returns (uint128 totalLocked, uint32 lockCount, uint32 finalizedAt, bool finalized)
    {
        AuctionEscrowState storage e = _s().auctionEscrowState[worldwideDay];
        return (e.totalLocked, e.lockCount, e.finalizedAt, e.finalized);
    }

    // --- Admin ---
    /// @inheritdoc IEscrowAdapter
    function wire(address _intexAuction, address _compact, address _paymentToken)
        external
        override
        onlyRole(DEFAULT_ADMIN_ROLE)
    {
        if (_intexAuction == address(0)) revert ZeroAddress("intexAuction");
        if (_compact == address(0)) revert ZeroAddress("compact");
        if (_paymentToken == address(0)) revert ZeroAddress("paymentToken");

        uint8 tokenDecimals = IERC20Metadata(_paymentToken).decimals();
        if (tokenDecimals != PAYMENT_TOKEN_DECIMALS) revert PaymentTokenDecimals(tokenDecimals);

        EscrowAdapterStorage storage $ = _s();

        // Block rotating the active payment token (or Compact) while locks are still in flight:
        // existing locks reference the prior `paymentToken` and `lockId` via the global
        // state, so swapping these out would route refunds/claims through the wrong asset.
        bool rotatingPaymentToken = address($.paymentToken) != address(0) && _paymentToken != address($.paymentToken);
        bool rotatingCompact = address($.compact) != address(0) && _compact != address($.compact);
        if (rotatingPaymentToken || rotatingCompact) {
            // aderyn-fp-next-line(reentrancy-state-change)
            uint256 outstanding = $.lockId == 0 ? 0 : IERC6909(address($.compact)).balanceOf(address(this), $.lockId);
            if (outstanding != 0) revert LiveLocksOutstanding(outstanding);
            // Reset lockId so the first deposit under the new token/Compact re-bootstraps the lock.
            $.lockId = 0;
            // A new Compact needs its own allocator registration; drop the stale allocatorId/lockTag.
            if (rotatingCompact) {
                $.allocatorId = 0;
                $.lockTag = bytes12(0);
            }
        }

        // Revoke role from the previous auction if rewiring.
        if ($.intexAuctionContract != address(0)) {
            _revokeRole(AUCTION_ROLE, $.intexAuctionContract);
        }

        // Capture the pre-rotation dependencies so `Wired` is log-reconstructible (old+new).
        address intexAuctionOld = $.intexAuctionContract;
        address compactOld = address($.compact);
        address paymentTokenOld = address($.paymentToken);

        $.intexAuctionContract = _intexAuction;
        $.compact = ITheCompact(_compact);
        $.paymentToken = IERC20(_paymentToken);

        _grantRole(AUCTION_ROLE, _intexAuction);
        $.paymentToken.forceApprove(_compact, 0);
        $.paymentToken.forceApprove(_compact, type(uint256).max);

        // CEI deviation: allocatorId / lockTag depend on __registerAllocator's return.
        // Admin-only; a re-entrant `compact` lacks DEFAULT_ADMIN_ROLE, so re-entry can't reach here.
        if ($.allocatorId == 0) {
            // aderyn-fp-next-line(reentrancy-state-change)
            $.allocatorId = $.compact.__registerAllocator(address(this), "");
            $.lockTag = _buildLockTag($.allocatorId, Scope.ChainSpecific, ResetPeriod.OneMinute);
        }

        emit Wired(intexAuctionOld, _intexAuction, compactOld, _compact, paymentTokenOld, _paymentToken);
    }

    // --- IAllocator Implementation ---
    /// @inheritdoc IAllocator
    function attest(address _operator, address _from, address _to, uint256 id, uint256 _amount)
        external
        view
        override
        returns (bytes4)
    {
        if (id != _s().lockId) revert UnexpectedLockId(id);
        return IAllocator.attest.selector;
    }

    /// @inheritdoc IAllocator
    function authorizeClaim(
        bytes32 _claimHash,
        address _arbiter,
        address _sponsor,
        uint256 _nonce,
        uint256 _expires,
        uint256[2][] calldata _idsAndAmounts,
        bytes calldata _allocatorData
    ) external pure override returns (bytes4) {
        revert ClaimAuthorizationUnsupported();
    }

    /// @inheritdoc IAllocator
    function isClaimAuthorized(
        bytes32 _claimHash,
        address _arbiter,
        address _sponsor,
        uint256 _nonce,
        uint256 _expires,
        uint256[2][] calldata _idsAndAmounts,
        bytes calldata _allocatorData
    ) external pure override returns (bool) {
        return false;
    }

    // --- Auction Integration ---
    /// @inheritdoc IEscrowAdapter
    function lockFunds(uint32 worldwideDay, address bidder, uint128 amount)
        external
        override
        onlyRole(AUCTION_ROLE)
        nonReentrant
    {
        _validateLockInputs(worldwideDay, bidder, amount);
        _executeLock(worldwideDay, bidder, amount);
    }

    // --- Commit bonds ---
    /// @inheritdoc IEscrowAdapter
    /// @dev Trust boundary: `bidder` is the original `msg.sender` of `IntexAuction.commitBid`,
    ///      forwarded through the `AUCTION_ROLE`-gated entry point (mirrors `lockFunds`).
    function lockCommitBond(uint32 worldwideDay, address bidder, uint128 amount)
        external
        override
        onlyRole(AUCTION_ROLE)
        nonReentrant
    {
        if (worldwideDay == 0) revert ZeroValue("worldwideDay");
        if (bidder == address(0)) revert ZeroAddress("bidder");
        if (amount == 0) revert ZeroValue("amount");
        EscrowAdapterStorage storage $ = _s();
        if ($.commitBonds[worldwideDay][bidder].amount != 0) revert CommitBondAlreadyLocked();

        // CEI deviation mirrors `_executeLock`: the one-time lockId bootstrap inside
        // `_depositToCompact` needs depositERC20's return; nonReentrant covers the deviation.
        // slither-disable-next-line arbitrary-send-erc20
        $.paymentToken.safeTransferFrom(bidder, address(this), amount);
        _depositToCompact(amount);

        $.commitBonds[worldwideDay][bidder] = CommitBond({amount: amount, lockedAt: uint32(block.timestamp)});
        emit CommitBondLocked(worldwideDay, bidder, amount);
    }

    /// @inheritdoc IEscrowAdapter
    function releaseCommitBond(uint32 worldwideDay, address bidder)
        external
        override
        onlyRole(AUCTION_ROLE)
        nonReentrant
    {
        _releaseCommitBond(worldwideDay, bidder);
    }

    /// @inheritdoc IEscrowAdapter
    function claimAbandonedCommitBond(uint32 worldwideDay, address bidder) external override nonReentrant {
        CommitBond storage bond = _s().commitBonds[worldwideDay][bidder];
        if (bond.amount == 0) revert CommitBondNotFound();
        uint32 claimableAt = bond.lockedAt + COMMIT_BOND_ABANDON_DELAY;
        if (block.timestamp < claimableAt) revert CommitBondNotYetAbandoned(claimableAt, uint32(block.timestamp));
        _releaseCommitBond(worldwideDay, bidder);
    }

    /// @dev Delete the bond record, withdraw from The Compact, and pay the stored bidder.
    ///      CEI: the delete precedes both external calls; a re-claim reverts `CommitBondNotFound`.
    function _releaseCommitBond(uint32 worldwideDay, address bidder) internal {
        EscrowAdapterStorage storage $ = _s();
        uint128 amount = $.commitBonds[worldwideDay][bidder].amount;
        if (amount == 0) revert CommitBondNotFound();

        // Effects
        delete $.commitBonds[worldwideDay][bidder];

        // Interactions
        _withdrawFromCompact(amount);
        $.paymentToken.safeTransfer(bidder, amount);
        emit CommitBondReleased(worldwideDay, bidder, amount);
    }

    // --- Bridge Finalization ---
    /// @inheritdoc IEscrowAdapter
    function finalizeAuction(
        uint32 worldwideDay,
        bytes32 receiveId,
        FinalizationInstruction[] calldata instructions,
        bool completesDay
    ) external override onlyRole(RELAYER_ROLE) nonReentrant returns (uint128 totalPaid) {
        EscrowAdapterStorage storage $ = _s();
        // A closed day takes no more instructions; within an open one each bidder is
        // guarded by its own lock leaving `Locked`.
        if ($.auctionEscrowState[worldwideDay].finalized) {
            revert AlreadyFinalized();
        }
        if (instructions.length == 0) revert ZeroValue("instructions");

        // Effects before any external interaction. The completing set closes the day, which
        // anchors the post-finalize `claimRefund` window (POST_FINALIZE_REFUND_DELAY).
        if (completesDay) {
            $.auctionEscrowState[worldwideDay].finalized = true;
            $.auctionEscrowState[worldwideDay].finalizedAt = uint32(block.timestamp);
        }

        uint128 totalRefunded = 0;
        uint32 bidsProcessed = 0;
        uint32 bidsSettled = 0;

        // Per-bidder try/catch: a single failed iteration emits BidderRefundFailed and the loop
        // continues. The failed bidder's lock stays in `Locked` status (the inner revert rolls
        // back its state writes) and can be recovered via retryFinalize or claimRefund.
        for (uint256 i = 0; i < instructions.length; ++i) {
            FinalizationInstruction calldata inst = instructions[i];
            try this.processFinalizationOne(worldwideDay, receiveId, inst) {
                totalRefunded += inst.refundedAmount;
                totalPaid += inst.paidAmount;
                ++bidsSettled;
            } catch (bytes memory reason) {
                // Record the intended refund split (in the outer frame, since the failing inner
                // call's writes roll back), but only if it is economically valid. A later
                // claimRefund then pays exactly this, never the full principal. A mismatched split
                // records nothing, so claimRefund stays blocked until the relayer retries.
                BidLock storage failed = $.bidLocks[worldwideDay][inst.bidder];
                if (
                    failed.status == LockStatus.Locked
                        && uint256(inst.refundedAmount) + inst.paidAmount == failed.lockedAmount
                ) {
                    failed.failedRefund = inst.refundedAmount;
                    failed.splitRecorded = true;
                }
                emit BidderRefundFailed(receiveId, worldwideDay, inst.bidder, reason);
            }
            ++bidsProcessed;
        }

        emit AuctionEscrowFinalized(receiveId, worldwideDay, totalRefunded, totalPaid, bidsProcessed);
        // Surface a degenerate finalize (every instruction failed) so it is not silently "done".
        if (bidsSettled == 0) emit FinalizationNoOp(worldwideDay, bidsProcessed);

        // Hand proceeds to the configured recipient (the messenger) for cross-chain routing.
        if (totalPaid > 0) {
            address recipient = $.proceedsRecipient;
            if (recipient == address(0)) revert ProceedsRecipientNotSet();
            $.paymentToken.safeTransfer(recipient, totalPaid);
        }
    }

    /// @notice Self-call helper for `finalizeAuction`'s per-bidder try/catch. Reverts on any
    ///         non-self call. Not part of the public surface - bundled here because Solidity
    ///         `try/catch` only works on external/public function calls.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param receiveId Inbound bridge message id threaded into the emitted events.
    /// @param inst Finalization instruction for the single bidder being processed.
    function processFinalizationOne(uint32 worldwideDay, bytes32 receiveId, FinalizationInstruction calldata inst)
        external
    {
        if (msg.sender != address(this)) revert NotSelf();
        _processFinalizationInstruction(receiveId, worldwideDay, inst.bidder, inst.refundedAmount, inst.paidAmount);
    }

    /// @inheritdoc IEscrowAdapter
    function retryFinalize(uint32 worldwideDay, bytes32 receiveId, FinalizationInstruction calldata inst)
        external
        override
        onlyRole(RELAYER_ROLE)
        nonReentrant
    {
        if (!_s().auctionEscrowState[worldwideDay].finalized) {
            revert NotFinalizedYet(worldwideDay);
        }
        _processFinalizationInstruction(receiveId, worldwideDay, inst.bidder, inst.refundedAmount, inst.paidAmount);

        // Stranded recovery: series already routed on Outbe, burn the residual.
        if (inst.paidAmount > 0) {
            _burnProceeds(worldwideDay, inst.bidder, inst.paidAmount);
        }

        emit BidderRetried(receiveId, worldwideDay, inst.bidder, inst.refundedAmount, inst.paidAmount);
    }

    /// @inheritdoc IEscrowAdapter
    function claimRefund(uint32 worldwideDay, address bidder) external override nonReentrant {
        if (bidder == address(0)) revert ZeroAddress("bidder");

        EscrowAdapterStorage storage $ = _s();
        BidLock storage lock = $.bidLocks[worldwideDay][bidder];
        if (lock.status != LockStatus.Locked) revert LockNotActive();

        AuctionEscrowState storage state = $.auctionEscrowState[worldwideDay];
        uint128 lockedAmount = lock.lockedAmount;

        if (state.finalized) {
            // Post-finalize: the bidder's instruction failed during finalization. Refund only the
            // validated refund portion - never the full principal - so a stranded winner cannot
            // over-draw the shared Compact pool against other series' funds. Without a recorded
            // split the amount is unknowable on-chain; the relayer must retryFinalize instead.
            uint32 claimableAt = state.finalizedAt + POST_FINALIZE_REFUND_DELAY;
            if (block.timestamp < claimableAt) revert RefundNotYetClaimable(claimableAt, uint32(block.timestamp));

            if (!lock.splitRecorded) {
                // Omitted/mismatched bidder: relayer gets the retryFinalize window; after
                // NO_SPLIT_REFUND_DELAY the lock becomes permissionlessly terminal with a
                // full-principal refund.
                uint32 abandonAt = state.finalizedAt + NO_SPLIT_REFUND_DELAY;
                if (block.timestamp < abandonAt) revert SplitNotRecorded(worldwideDay, bidder);

                lock.status = LockStatus.Finalized;
                state.totalLocked -= lockedAmount;
                _withdrawFromCompact(lockedAmount);
                $.paymentToken.safeTransfer(bidder, lockedAmount);
                emit FundsRefunded(bytes32(0), worldwideDay, bidder, lockedAmount);
                return;
            }

            // Refund the bidder's validated portion and burn the winning remainder (the series
            // proceeds were already routed on Outbe) - terminal in one transaction.
            uint128 refundAmount = lock.failedRefund;
            uint128 burnAmount = lockedAmount - refundAmount;

            lock.status = LockStatus.Finalized;
            state.totalLocked -= lockedAmount;
            _withdrawFromCompact(lockedAmount);
            if (refundAmount > 0) {
                $.paymentToken.safeTransfer(bidder, refundAmount);
                emit FundsRefunded(bytes32(0), worldwideDay, bidder, refundAmount);
            }
            if (burnAmount > 0) {
                _burnProceeds(worldwideDay, bidder, burnAmount);
            }
        } else {
            // Never-finalized: the relayer never settled the series, so a full-principal refund is
            // correct - no clearing result exists on this chain.
            uint32 claimableAt = lock.lockedAt + UNFINALIZED_REFUND_DELAY;
            if (block.timestamp < claimableAt) revert RefundNotYetClaimable(claimableAt, uint32(block.timestamp));

            lock.status = LockStatus.Finalized;
            state.totalLocked -= lockedAmount;

            _withdrawFromCompact(lockedAmount);
            $.paymentToken.safeTransfer(bidder, lockedAmount);
            emit FundsRefunded(bytes32(0), worldwideDay, bidder, lockedAmount);
        }
    }

    // --- Views ---
    /// @inheritdoc IEscrowAdapter
    function getBidLock(uint32 worldwideDay, address bidder) external view override returns (BidLock memory) {
        return _s().bidLocks[worldwideDay][bidder];
    }

    /// @inheritdoc IEscrowAdapter
    function getCommitBond(uint32 worldwideDay, address bidder) external view override returns (CommitBond memory) {
        return _s().commitBonds[worldwideDay][bidder];
    }

    /// @inheritdoc IEscrowAdapter
    function getAuctionStatus(uint32 worldwideDay)
        external
        view
        override
        returns (bool hasLocks, bool isFinalized, uint128 totalLocked)
    {
        AuctionEscrowState memory state = _s().auctionEscrowState[worldwideDay];
        return (state.lockCount > 0, state.finalized, state.totalLocked);
    }

    /// @inheritdoc IEscrowAdapter
    function hasOutstandingLocks() external view override returns (bool) {
        EscrowAdapterStorage storage $ = _s();
        if ($.lockId == 0) return false;
        return IERC6909(address($.compact)).balanceOf(address(this), $.lockId) != 0;
    }

    // --- Internal helpers ---
    /// @notice Validate lock inputs before any state write.
    /// @dev Rejects a zero `worldwideDay`, zero `bidder`, zero `amount`, and a bidder that already
    ///      holds a non-`None` lock for the series.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address.
    /// @param amount Amount to lock.
    function _validateLockInputs(uint32 worldwideDay, address bidder, uint128 amount) internal view {
        // Cheap sanity floor: the AUCTION_ROLE gate already guarantees a real, stage-gated series,
        // but a zero id is obviously bogus and is rejected before any state write.
        if (worldwideDay == 0) revert ZeroValue("worldwideDay");
        if (bidder == address(0)) revert ZeroAddress("bidder");
        if (amount == 0) revert ZeroValue("amount");
        if (_s().bidLocks[worldwideDay][bidder].status != LockStatus.None) {
            revert BidAlreadyLocked();
        }
    }

    /// @notice Execute the lock operation - transfer from the bidder and deposit to The Compact.
    /// @dev Bootstraps `lockId` and forced withdrawal on the first deposit, then records the
    ///      `BidLock` and bumps the per-series escrow stats.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address.
    /// @param amount Amount to lock.
    /// @dev Trust boundary: `bidder` is the original `msg.sender` of `IntexAuction.revealBid`,
    ///      forwarded through the `AUCTION_ROLE`-gated `lockFunds` entry point. Safety relies
    ///      on `AUCTION_ROLE` only ever being granted to the wired `IntexAuction` contract.
    function _executeLock(uint32 worldwideDay, address bidder, uint128 amount) internal {
        EscrowAdapterStorage storage $ = _s();
        // CEI deviation: only the one-time lockId bootstrap needs depositERC20's return before
        // writing. Per-call bidLocks / auctionEscrowState writes follow for locality and could
        // move above; nonReentrant on every outer entrypoint covers the deviation regardless.
        // slither-disable-next-line arbitrary-send-erc20
        $.paymentToken.safeTransferFrom(bidder, address(this), amount);
        _depositToCompact(amount);

        // Store lock data.
        $.bidLocks[worldwideDay][bidder] = BidLock({
            lockedAmount: amount,
            lockedAt: uint32(block.timestamp),
            status: LockStatus.Locked,
            failedRefund: 0,
            splitRecorded: false
        });

        // Update series escrow stats.
        ++$.auctionEscrowState[worldwideDay].lockCount;
        $.auctionEscrowState[worldwideDay].totalLocked += amount;

        emit FundsLocked(worldwideDay, bidder, amount);
    }

    /// @notice Process a single finalization instruction: validate the split, mark the lock
    ///         `Finalized`, refund the bidder, and collect the paid portion for the caller to route.
    /// @dev Reverts `AmountMismatch` when `refundedAmount + paidAmount != lockedAmount`.
    /// @param receiveId Inbound bridge message id threaded into the emitted refund/payout events.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @param bidder Bidder address.
    /// @param refundedAmount Amount to refund to the bidder.
    /// @param paidAmount Auction proceeds left in this contract for the caller to route.
    function _processFinalizationInstruction(
        bytes32 receiveId,
        uint32 worldwideDay,
        address bidder,
        uint128 refundedAmount,
        uint128 paidAmount
    ) internal {
        if (bidder == address(0)) revert ZeroAddress("bidder");

        EscrowAdapterStorage storage $ = _s();
        BidLock storage lock = $.bidLocks[worldwideDay][bidder];
        if (lock.status != LockStatus.Locked) revert LockNotActive();

        // Validate the refund + payout split matches the locked amount. Sum in uint256 so a
        // mismatch is surfaced rather than silently wrapping when the split exceeds the lock.
        uint128 lockedAmount = lock.lockedAmount;
        uint256 total = uint256(refundedAmount) + paidAmount;
        if (total != lockedAmount) {
            revert AmountMismatch(lockedAmount, uint128(total));
        }

        // CEI ok: state writes below precede every external call in this function.
        lock.status = LockStatus.Finalized;
        $.auctionEscrowState[worldwideDay].totalLocked -= lockedAmount;

        // Interactions
        _withdrawFromCompact(lockedAmount);

        if (refundedAmount > 0) {
            $.paymentToken.safeTransfer(bidder, refundedAmount);
            emit FundsRefunded(receiveId, worldwideDay, bidder, refundedAmount);
        }

        // Paid portion stays in this contract; the caller routes it.
    }

    /// @dev Burn an undistributable winning portion: park it at the canonical dead address (the
    ///      payment token exposes no burn of its own) and emit the burn marker.
    function _burnProceeds(uint32 worldwideDay, address bidder, uint128 amount) internal {
        _s().paymentToken.safeTransfer(BURN_ADDRESS, amount);
        emit ProceedsBurned(worldwideDay, bidder, amount);
    }

    /// @notice Deposit `amount` of the payment token into The Compact (we receive ERC6909 tokens).
    /// @dev Bootstraps `lockId` and enables forced withdrawal on the first-ever deposit. The
    ///      returned `withdrawableAt` is informational; withdrawals invoke forcedWithdrawal directly.
    /// @param amount Amount to deposit.
    function _depositToCompact(uint128 amount) internal {
        EscrowAdapterStorage storage $ = _s();
        uint256 returnedLockId = $.compact.depositERC20(address($.paymentToken), $.lockTag, amount, address(this));
        if ($.lockId == 0) {
            $.lockId = returnedLockId;
            // slither-disable-next-line unused-return
            $.compact.enableForcedWithdrawal(returnedLockId);
        }
    }

    /// @notice Withdraw tokens from The Compact via forced withdrawal.
    /// @dev Reverts `NoDeposits` if `lockId` is unset and `ForcedWithdrawalFailed` if the reset
    ///      period has not elapsed (The Compact returns false).
    /// @param amount Amount to withdraw.
    function _withdrawFromCompact(uint128 amount) internal {
        EscrowAdapterStorage storage $ = _s();
        if ($.lockId == 0) revert NoDeposits();
        // The Compact itself checks the reset period - if not ready, returns false.
        bool success = $.compact.forcedWithdrawal($.lockId, address(this), amount);
        if (!success) revert ForcedWithdrawalFailed();
    }

    /// @dev Build the lock tag for The Compact deposits.
    /// @notice Combines allocatorId, scope, and reset period into a single 12-byte identifier.
    ///         This tag is used by The Compact to identify which resource lock to use for deposits.
    /// @param _allocatorId Our allocator ID from The Compact registration.
    /// @param scope Whether the lock is multichain or chain-specific.
    /// @param resetPeriod Time period before forced withdrawal is allowed.
    /// @return lockTag 12-byte identifier used for all deposits.
    function _buildLockTag(uint96 _allocatorId, Scope scope, ResetPeriod resetPeriod) internal pure returns (bytes12) {
        uint256 packed =
            (uint256(uint8(scope)) << 255) | (uint256(uint8(resetPeriod)) << 252) | (uint256(_allocatorId) << 160);
        // forge-lint: disable-next-line(unsafe-typecast) -- intentional truncation to the tag's top 12 bytes
        return bytes12(uint96(packed >> 160));
    }

    /// @notice Check if the contract supports a given interface.
    /// @dev Returns true for `IAllocator` and any interface advertised by `AccessControl`.
    /// @param interfaceId Interface ID to check.
    /// @return True if the interface is supported.
    function supportsInterface(bytes4 interfaceId) public view override(AccessControlUpgradeable) returns (bool) {
        return interfaceId == type(IAllocator).interfaceId || super.supportsInterface(interfaceId);
    }
}
