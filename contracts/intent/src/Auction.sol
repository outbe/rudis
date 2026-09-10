// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

import {IAuction} from "./interfaces/IAuction.sol";
import {OrderValidator} from "./libs/OrderValidator.sol";

/// @title Auction
/// @notice Commit-reveal Vickrey auction for competitive solver selection
/// @dev Phases: commit (10s) -> reveal (10s) -> getWinner.
///      Winner = highest outputAmount, pays second-highest price.
contract Auction is IAuction, Ownable2Step {
    // ============ Phase Constants ============

    uint8 internal constant PHASE_NONE = 0;
    uint8 internal constant PHASE_COMMIT = 1;
    uint8 internal constant PHASE_REVEAL = 2;
    uint8 internal constant PHASE_ENDED = 3;

    // ============ Errors ============

    /// @notice Thrown when caller is not the router
    error UnauthorizedRouter();
    /// @notice Thrown when an invalid period is set
    error InvalidPeriod();
    /// @notice Thrown when an invalid max quotes value is set
    error InvalidMaxQuotes();

    // ============ Storage ============

    /// @notice Duration of the commit phase in seconds
    uint256 public commitPeriod = 10 seconds;

    /// @notice Duration of the reveal phase in seconds
    uint256 public revealPeriod = 10 seconds;

    /// @notice Maximum number of revealed quotes allowed per order
    uint256 public maxQuotesPerOrder = 10;

    /// @notice Router contract - authorized caller
    address public router;

    /// @notice Revealed quotes per order
    mapping(bytes32 => Quote[]) internal _quotes;

    /// @notice Auction start time (set on first commit, 0 = no auction)
    mapping(bytes32 => uint256) internal _auctionStartedAt;

    /// @notice Per-order auction epoch, incremented on every resetAuction so prior-round commits
    ///         become unreachable without enumerating the (non-enumerable) _commits mapping.
    mapping(bytes32 => uint256) internal _auctionEpoch;

    /// @notice Commitment hashes: orderId => epoch => solver => commitHash
    mapping(bytes32 => mapping(uint256 => mapping(address => bytes32))) internal _commits;

    // ============ Modifiers ============

    modifier onlyRouter() {
        _onlyRouter();
        _;
    }

    function _onlyRouter() internal view {
        if (msg.sender != router) revert UnauthorizedRouter();
    }

    // ============ Constructor ============

    constructor(address _owner) Ownable(_owner) {}

    // ============ Commit-Reveal Functions ============

    /// @inheritdoc IAuction
    function commit(bytes32 orderId, bytes32 commitHash) external {
        // First commit starts the auction
        if (_auctionStartedAt[orderId] == 0) {
            _auctionStartedAt[orderId] = block.timestamp;
        }

        if (_phase(orderId) != PHASE_COMMIT) revert CommitPhaseEnded();
        uint256 epoch = _auctionEpoch[orderId];
        if (_commits[orderId][epoch][msg.sender] != bytes32(0)) revert AlreadyCommitted();

        _commits[orderId][epoch][msg.sender] = commitHash;

        emit Committed(orderId, msg.sender);
    }

    /// @inheritdoc IAuction
    function reveal(bytes32 orderId, uint256 outputAmount, bytes32 salt, bytes calldata originData) external {
        if (_phase(orderId) != PHASE_REVEAL) revert RevealPhaseNotActive();
        if (_quotes[orderId].length >= maxQuotesPerOrder) revert MaxQuotesReached();

        OrderValidator.decodeAndCheck(originData, orderId, outputAmount);

        uint256 epoch = _auctionEpoch[orderId];
        bytes32 commitHash = _commits[orderId][epoch][msg.sender];
        if (commitHash == bytes32(0)) revert NotCommitted();

        // TODO fix note[asm-keccak256]: use of inefficient hashing mechanism; consider using inline assembly
        bytes32 expected = keccak256(abi.encode(orderId, outputAmount, salt));
        if (commitHash != expected) revert InvalidReveal();

        // Clear commit (prevent double reveal + gas refund)
        _commits[orderId][epoch][msg.sender] = bytes32(0);

        // Bound against the uint128 quote storage: an unchecked downcast would silently truncate
        // outputAmount > type(uint128).max, letting a sub-floor value enter Vickrey ranking.
        if (outputAmount > type(uint128).max) revert OutputAmountTooLarge();
        _quotes[orderId].push(Quote({solver: msg.sender, outputAmount: uint128(outputAmount)}));

        emit QuoteSubmitted(orderId, msg.sender, outputAmount);
    }

    // ============ Router Functions ============

    /// @inheritdoc IAuction
    function resetAuction(bytes32 orderId, address winner) external onlyRouter {
        delete _quotes[orderId];
        _auctionEpoch[orderId]++;
        _auctionStartedAt[orderId] = block.timestamp;

        emit AuctionRestarted(orderId, winner);
    }

    // ============ Admin Functions ============

    /// @inheritdoc IAuction
    function setCommitPeriod(uint256 newPeriod) external onlyOwner {
        if (newPeriod == 0) revert InvalidPeriod();
        uint256 oldPeriod = commitPeriod;
        commitPeriod = newPeriod;
        emit CommitPeriodUpdated(oldPeriod, newPeriod);
    }

    /// @inheritdoc IAuction
    function setRevealPeriod(uint256 newPeriod) external onlyOwner {
        if (newPeriod == 0) revert InvalidPeriod();
        uint256 oldPeriod = revealPeriod;
        revealPeriod = newPeriod;
        emit RevealPeriodUpdated(oldPeriod, newPeriod);
    }

    /// @inheritdoc IAuction
    function setMaxQuotesPerOrder(uint256 newMax) external onlyOwner {
        if (newMax == 0) revert InvalidMaxQuotes();
        uint256 oldMax = maxQuotesPerOrder;
        maxQuotesPerOrder = newMax;
        emit MaxQuotesUpdated(oldMax, newMax);
    }

    /// @inheritdoc IAuction
    function setRouter(address newRouter) external onlyOwner {
        if (newRouter == address(0)) revert ZeroRouter();
        address oldRouter = router;
        router = newRouter;
        emit RouterUpdated(oldRouter, newRouter);
    }

    // ============ View Functions ============

    /// @inheritdoc IAuction
    function getWinner(bytes32 orderId) public view returns (address solver, uint256 amount) {
        Quote[] storage quotes = _quotes[orderId];
        if (quotes.length == 0) revert NoQuotes();
        if (_phase(orderId) < PHASE_ENDED) revert RevealNotEnded();

        uint128 bestAmount;
        uint128 secondAmount;
        address bestSolver;

        for (uint256 i = 0; i < quotes.length; i++) {
            if (quotes[i].outputAmount > bestAmount) {
                secondAmount = bestAmount;
                bestAmount = quotes[i].outputAmount;
                bestSolver = quotes[i].solver;
            } else if (quotes[i].outputAmount > secondAmount) {
                secondAmount = quotes[i].outputAmount;
            }
        }

        return (bestSolver, secondAmount > 0 ? secondAmount : bestAmount);
    }

    /// @inheritdoc IAuction
    function isAuctionEnded(bytes32 orderId) external view returns (bool) {
        return _phase(orderId) == PHASE_ENDED;
    }

    /// @inheritdoc IAuction
    function getQuotes(bytes32 orderId) external view returns (Quote[] memory) {
        return _quotes[orderId];
    }

    /// @inheritdoc IAuction
    function getQuoteCount(bytes32 orderId) external view returns (uint256) {
        return _quotes[orderId].length;
    }

    /// @inheritdoc IAuction
    function getCommitDeadline(bytes32 orderId) external view returns (uint256) {
        uint256 start = _auctionStartedAt[orderId];
        if (start == 0) return 0;
        return start + commitPeriod;
    }

    /// @inheritdoc IAuction
    function getRevealDeadline(bytes32 orderId) external view returns (uint256) {
        uint256 start = _auctionStartedAt[orderId];
        if (start == 0) return 0;
        return start + commitPeriod + revealPeriod;
    }

    /// @inheritdoc IAuction
    function hasSolverCommitted(bytes32 orderId, address solver) external view returns (bool) {
        return _commits[orderId][_auctionEpoch[orderId]][solver] != bytes32(0);
    }

    /// @inheritdoc IAuction
    function auctionStartedAt(bytes32 orderId) external view returns (uint256) {
        return _auctionStartedAt[orderId];
    }

    // ============ Internal ============

    /// @notice Returns the current auction phase for an order
    function _phase(bytes32 orderId) internal view returns (uint8) {
        uint256 start = _auctionStartedAt[orderId];
        if (start == 0) return PHASE_NONE;
        if (block.timestamp < start + commitPeriod) return PHASE_COMMIT;
        if (block.timestamp < start + commitPeriod + revealPeriod) return PHASE_REVEAL;
        return PHASE_ENDED;
    }
}
