// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ERC1155Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC1155/ERC1155Upgradeable.sol";
import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IIntexNFT1155} from "./interfaces/IIntexNFT1155.sol";
import {IERC1155Bridgeable} from "./interfaces/IERC1155Bridgeable.sol";
import {IntexMetadata} from "./libs/IntexMetadata.sol";

/**
 * @title IntexNFT1155
 * @author Outbe
 * @notice ERC1155 representation of Intex - a conditional right to obtain promis.
 *
 * @dev UUPS upgradeable: deployed behind an ERC1967 proxy, configured via `initialize`.
 * @dev One auction produces one series with shared parameters for all winners.
 * @dev State transitions affect the entire series simultaneously (O(1) gas).
 * @dev Series lifecycle: Issued -> Qualified -> Called.
 *      Expiry is not an on-chain state: it is derived from `calledAt + callNoticePeriod`
 *      against the clock (settle/bridge gates, metadata rendering).
 * @dev Each series has two token ids: issued = `uint112(seriesId)`,
 *      settled = `keccak256("SETTLED", seriesId)`.
 */
contract IntexNFT1155 is ERC1155Upgradeable, AccessControlUpgradeable, UUPSUpgradeable, IIntexNFT1155 {
    /// @notice Bridge relayer role; gates series lifecycle, issue, and
    ///         bridge crosschainBurn/crosschainMint.
    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");
    /// @notice Settlement contract role; allowed to call `settle` (burn Issued + mint Settled).
    bytes32 public constant SETTLEMENT_ROLE = keccak256("SETTLEMENT_ROLE");
    /// @notice Promis facade role; allowed to call `burnSettled`.
    bytes32 public constant PROMIS_ROLE = keccak256("PROMIS_ROLE");
    /// @notice Gem factory role; allowed to call `parkIntex`.
    bytes32 public constant GEM_ROLE = keccak256("GEM_ROLE");

    /// @dev Domain prefix for `settledTokenId` derivation; isolates Settled ids from the
    ///      issued token-id space.
    bytes constant _SETTLED_DOMAIN = bytes("SETTLED");

    /// @custom:storage-location erc7201:outbe.intex.IntexNFT1155
    struct IntexNFT1155Storage {
        /// @dev Unused; retained so later members keep their storage slots.
        string collectionDescription;
        /// @dev Series-level data, stored per token id. One entry per class: both carry the
        ///      immutable series identity; mutable lifecycle fields live on the Issued entry only.
        mapping(uint256 tokenId => IIntexNFT1155.SeriesData) seriesData;
        /// @dev Amount won at auction per address per token id (recorded at mint, never changes).
        mapping(uint256 tokenId => mapping(address account => uint16 count)) auctionWonCount;
        /// @dev Array of all token IDs (series) that have been created.
        uint256[] allSeries;
        /// @dev Per-owner array of owned token IDs (series with balance > 0).
        mapping(address owner => uint256[]) ownedSeries;
        /// @dev Index of token ID in ownedSeries[owner] array (for efficient removal).
        mapping(address owner => mapping(uint256 tokenId => uint256 index)) ownedSeriesIndex;
        /// @dev Whether owner has a specific token ID in their ownedSeries.
        mapping(address owner => mapping(uint256 tokenId => bool owns)) ownsToken;
        /// @dev Total balance across all series for each owner.
        mapping(address owner => uint256 balance) totalBalance;
        /// @dev Series ids issued per worldwide day.
        mapping(uint32 worldwideDay => bytes14[] seriesIds) seriesOfDay;
    }

    // keccak256(abi.encode(uint256(keccak256("outbe.intex.IntexNFT1155")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE_SLOT = 0xe941cbaf65abb9f7003c3006add9c5d12ba7e339abdf88d4afd5defeb8932900;

    function _s() private pure returns (IntexNFT1155Storage storage $) {
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
        if (defaultAdmin == address(0)) revert ZeroAddress("defaultAdmin", defaultAdmin);

        __ERC1155_init("");
        __AccessControl_init();

        _grantRole(DEFAULT_ADMIN_ROLE, defaultAdmin);
    }

    /// @dev Upgrades are gated by the admin role.
    /// @param newImplementation Address of the implementation the proxy switches to.
    // solhint-disable-next-line no-empty-blocks
    function _authorizeUpgrade(address newImplementation) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    /// @notice Series-level data, stored per token id. Flattened to match the original
    ///         public-mapping getter ABI, with the call-trigger returned as its struct (collapsing
    ///         the three flat trigger fields keeps the return arity within the via_ir stack bound).
    function seriesData(uint256 tokenId)
        external
        view
        returns (
            uint16 issuanceCurrency,
            uint16 referenceCurrency,
            uint32 issuedIntexCount,
            uint128 promisLoadMinor,
            uint64 entryPriceMinor,
            uint64 floorPriceMinor,
            uint64 callPriceMinor,
            IIntexNFT1155.IntexCallTrigger memory callTrigger,
            uint32 issuedAt,
            uint32 calledAt,
            uint32 totalSupply,
            IIntexNFT1155.IntexStatus status,
            IIntexNFT1155.IntexState state
        )
    {
        IIntexNFT1155.SeriesData memory d = _s().seriesData[tokenId];
        issuanceCurrency = d.issuanceCurrency;
        referenceCurrency = d.referenceCurrency;
        issuedIntexCount = d.issuedIntexCount;
        promisLoadMinor = d.promisLoadMinor;
        entryPriceMinor = d.entryPriceMinor;
        floorPriceMinor = d.floorPriceMinor;
        callPriceMinor = d.callPriceMinor;
        callTrigger = d.callTrigger;
        issuedAt = d.issuedAt;
        calledAt = d.calledAt;
        totalSupply = d.totalSupply;
        status = d.status;
        state = _effectiveState(d);
    }

    /// @notice Amount won at auction per address per token id (recorded at mint, never changes).
    /// @param tokenId Issued token id.
    /// @param account Auction winner address.
    /// @return The recorded won amount.
    function auctionWonCount(uint256 tokenId, address account) external view returns (uint16) {
        return _s().auctionWonCount[tokenId][account];
    }

    /// @inheritdoc IIntexNFT1155
    function worldwideDayOf(bytes14 seriesId) external view returns (uint32) {
        return _s().seriesData[_issuedTokenId(seriesId)].worldwideDay;
    }

    /// @inheritdoc IIntexNFT1155
    function seriesIdsByWorldwideDay(uint32 worldwideDay) external view returns (bytes14[] memory) {
        return _s().seriesOfDay[worldwideDay];
    }

    /// @inheritdoc IIntexNFT1155
    function createSeries(IIntexNFT1155.CreateSeriesParams calldata params) external onlyRole(RELAYER_ROLE) {
        IntexNFT1155Storage storage $ = _s();
        uint256 iTok = _issuedTokenId(params.seriesId);

        if ($.seriesData[iTok].issuedAt != 0) {
            revert TokenAlreadyExists(iTok);
        }

        // The cap is part of the series's birth identity; a zero cap would mean "a series no
        // one can mint into," which never matches an auction-cleared result.
        if (params.issuedIntexCount == 0) revert ZeroIssuedIntexCount();

        IIntexNFT1155.SeriesData memory seed = IIntexNFT1155.SeriesData({
            issuanceCurrency: params.issuanceCurrency,
            referenceCurrency: params.referenceCurrency,
            issuedIntexCount: params.issuedIntexCount,
            promisLoadMinor: params.promisLoadMinor,
            entryPriceMinor: params.entryPriceMinor,
            floorPriceMinor: params.floorPriceMinor,
            callPriceMinor: params.callPriceMinor,
            callTrigger: IIntexNFT1155.IntexCallTrigger({
                callWindow: params.callTrigger.callWindow,
                callThreshold: params.callTrigger.callThreshold,
                callNoticePeriod: params.callTrigger.callNoticePeriod
            }),
            issuedAt: uint32(block.timestamp),
            calledAt: 0,
            totalSupply: 0,
            status: IIntexNFT1155.IntexStatus.Issued,
            state: IIntexNFT1155.IntexState.Issued,
            worldwideDay: params.worldwideDay,
            seriesId: params.seriesId
        });
        $.seriesData[iTok] = seed;

        // The Settled record shares the series's immutable identity so lookups and metadata work
        // for either class; mutable lifecycle fields (state, calledAt) are never written on it.
        uint256 sTok = _settledTokenId(params.seriesId);
        seed.status = IIntexNFT1155.IntexStatus.Settled;
        $.seriesData[sTok] = seed;

        // Series remain in allSeries permanently even after supply reaches 0 -
        // preserves the historical record and avoids O(n) removal. Only the Issued id is
        // enumerated; clients derive the Settled id via `settledTokenId(seriesId)`.
        $.allSeries.push(iTok);
        $.seriesOfDay[params.worldwideDay].push(params.seriesId);

        emit MetadataUpdate(iTok);
    }

    /// @inheritdoc IIntexNFT1155
    function issue(address to, uint256 quantity, bytes14 seriesId) external onlyRole(RELAYER_ROLE) {
        if (to == address(0)) {
            revert ZeroAddress("to", to);
        }

        IntexNFT1155Storage storage $ = _s();
        uint256 tokenId = _issuedTokenId(seriesId);
        IIntexNFT1155.SeriesData storage data = $.seriesData[tokenId];
        if (data.issuedAt == 0) {
            revert NonexistentToken(tokenId);
        }

        // A per-recipient mint quantity is one bidder's auction win, bounded by their bid's
        // `intexQuantity` (uint16); keeps the ERC1155 balance, `totalSupply` and `auctionWonCount` consistent.
        if (quantity > type(uint16).max) revert QuantityTooLarge(quantity);

        // Cap is enforced against live `totalSupply`; a burn frees cap room. The intermediate
        // is widened to uint256 so a series with `issuedIntexCount` near `type(uint32).max`
        // surfaces the typed `SupplyCapExceeded` revert rather than a raw arithmetic panic.
        uint256 newTotal = uint256(data.totalSupply) + quantity;
        if (newTotal > data.issuedIntexCount) {
            revert SupplyCapExceeded(seriesId, newTotal, data.issuedIntexCount);
        }

        // CEI ok: write totalSupply before _mint so the ERC1155 receiver callback observes a
        // consistent (totalSupply == sum balanceOf) snapshot - closes the read-only-reentrancy
        // window. Cast is safe because the cap check bounded `newTotal <= issuedIntexCount <= uint32.max`.
        // forge-lint: disable-next-line(unsafe-typecast) -- bounded by cap check above
        data.totalSupply = uint32(newTotal);
        _mint(to, tokenId, quantity, "");

        if ($.auctionWonCount[tokenId][to] == 0) {
            // forge-lint: disable-next-line(unsafe-typecast) -- quantity bounded to uint16 above
            $.auctionWonCount[tokenId][to] = uint16(quantity);
        }

        emit IntexIssued(msg.sender, tokenId, to, quantity);
    }

    /// @inheritdoc IIntexNFT1155
    function markQualified(bytes14 seriesId) external onlyRole(RELAYER_ROLE) {
        uint256 tokenId = _issuedTokenId(seriesId);
        IIntexNFT1155.SeriesData storage data = _s().seriesData[tokenId];
        if (data.issuedAt == 0) {
            revert NonexistentToken(tokenId);
        }
        if (data.state != IIntexNFT1155.IntexState.Issued) {
            revert InvalidState(uint8(IIntexNFT1155.IntexState.Issued), uint8(data.state));
        }

        IIntexNFT1155.IntexState previousState = data.state;
        data.state = IIntexNFT1155.IntexState.Qualified;

        emit IntexStatusUpdated(
            msg.sender, tokenId, previousState, IIntexNFT1155.IntexState.Qualified, uint32(block.timestamp), 0
        );
        emit MetadataUpdate(tokenId);
    }

    /// @inheritdoc IIntexNFT1155
    function markCalled(bytes14 seriesId, uint32 calledAt) external onlyRole(RELAYER_ROLE) {
        uint256 tokenId = _issuedTokenId(seriesId);
        IIntexNFT1155.SeriesData storage data = _s().seriesData[tokenId];
        if (data.issuedAt == 0) {
            revert NonexistentToken(tokenId);
        }
        // Allow Issued -> Called and Qualified -> Called; the relayer drives the qualification oracle.
        if (data.state != IIntexNFT1155.IntexState.Issued && data.state != IIntexNFT1155.IntexState.Qualified) {
            revert InvalidState(uint8(IIntexNFT1155.IntexState.Qualified), uint8(data.state));
        }

        // Zero is the "not called" sentinel, and a future stamp would outlast the origin's window.
        if (calledAt == 0 || calledAt > block.timestamp) revert CalledAtInvalid(calledAt, uint32(block.timestamp));

        IIntexNFT1155.IntexState previousState = data.state;
        data.state = IIntexNFT1155.IntexState.Called;
        data.calledAt = calledAt;

        uint32 derivedDeadline = calledAt + data.callTrigger.callNoticePeriod;

        emit IntexStatusUpdated(
            msg.sender, tokenId, previousState, IIntexNFT1155.IntexState.Called, calledAt, derivedDeadline
        );
        emit MetadataUpdate(tokenId);
    }

    /// @inheritdoc IERC1155Bridgeable
    /// @dev Bridge crosschainBurn gating:
    ///      - Settled token ids are soulbound - always reverts.
    ///      - Series states `Issued` and `Qualified`: bridge allowed for `RELAYER_ROLE`
    ///        (voluntary, holder-initiated moves while the series is tradable).
    ///      - Series state `Called`: allowed only when the destination holder is the source holder -
    ///        ownership is frozen once a series is Called - and only inside the call window.
    function crosschainBurn(address from, address to, uint256 tokenId, uint256 amount) external onlyRole(RELAYER_ROLE) {
        IIntexNFT1155.SeriesData storage data = _s().seriesData[tokenId];
        if (data.status == IIntexNFT1155.IntexStatus.Settled) {
            revert BridgeOnSettledForbidden(tokenId);
        }
        if (data.issuedAt == 0) revert NonexistentToken(tokenId);
        if (from == address(0)) revert ZeroAddress("from", from);

        if (data.state == IIntexNFT1155.IntexState.Called) {
            // A bridge hop that changes holder is a transfer, which Called forbids.
            if (to != from) revert TransferOnCalledForbidden(tokenId);
            // Past `calledAt + callNoticePeriod` the series is settlement-complete and balances freeze,
            // so no hop may still move one out (or `crosschainMint` re-inflate one back in).
            uint32 derivedDeadline = data.calledAt + data.callTrigger.callNoticePeriod;
            if (block.timestamp > derivedDeadline) {
                revert BridgeAfterDeadline(tokenId, derivedDeadline);
            }
        }

        // CEI ok: write before _burn for symmetry with mint. _burn fires no acceptance callback
        // (OZ ERC1155 skips it when to == address(0)), so no read-only-reentrancy surface here.
        // forge-lint: disable-next-line(unsafe-typecast) -- amount <= balance <= totalSupply (uint32); _burn reverts otherwise
        data.totalSupply -= uint32(amount);
        _burn(from, tokenId, amount);
    }

    /// @inheritdoc IERC1155Bridgeable
    /// @dev Bridge crosschainMint mirrors `crosschainBurn`: `RELAYER_ROLE` throughout, and inside the
    ///      call window a Called series may still be minted into so a bridged balance lands.
    function crosschainMint(address to, uint256 tokenId, uint256 amount) external onlyRole(RELAYER_ROLE) {
        if (to == address(0)) revert ZeroAddress("to", to);
        IIntexNFT1155.SeriesData storage data = _s().seriesData[tokenId];
        if (data.status == IIntexNFT1155.IntexStatus.Settled) {
            revert BridgeOnSettledForbidden(tokenId);
        }
        if (data.issuedAt == 0) revert NonexistentToken(tokenId);

        if (data.state == IIntexNFT1155.IntexState.Called) {
            // Mirror of `crosschainBurn`: no bridge-in past the settlement deadline.
            uint32 derivedDeadline = data.calledAt + data.callTrigger.callNoticePeriod;
            if (block.timestamp > derivedDeadline) {
                revert BridgeAfterDeadline(tokenId, derivedDeadline);
            }
        }

        // A crosschainMinted balance can be a holder's full transferable balance (<= totalSupply, uint32).
        if (amount > type(uint32).max) revert QuantityTooLarge(amount);

        // Bridge-in cap: enforce `totalSupply + amount <= issuedIntexCount` at all times. The
        // live-supply invariant matches mint, which also caps on live `totalSupply`.
        // Intermediate widened to uint256 so the cap revert surfaces as `SupplyCapExceeded`
        // even at the `issuedIntexCount == type(uint32).max` boundary.
        uint256 newTotal = uint256(data.totalSupply) + amount;
        // Only the Issued path reaches here: the status guard above already rejected Settled ids.
        if (newTotal > data.issuedIntexCount) {
            revert SupplyCapExceeded(bytes14(uint112(tokenId)), newTotal, data.issuedIntexCount);
        }

        // CEI ok: write totalSupply before _mint (see mint()). Cast is safe because the cap
        // check bounded `newTotal <= issuedIntexCount <= uint32.max`.
        // forge-lint: disable-next-line(unsafe-typecast) -- bounded by cap check above
        data.totalSupply = uint32(newTotal);
        _mint(to, tokenId, amount, "");
    }

    /// @inheritdoc IIntexNFT1155
    function settle(bytes14 seriesId, address from, address to, uint256 amount) external onlyRole(SETTLEMENT_ROLE) {
        if (from == address(0)) revert ZeroAddress("from", from);
        if (to == address(0)) revert ZeroAddress("to", to);
        if (amount == 0) revert ZeroAmount();

        IntexNFT1155Storage storage $ = _s();
        uint256 iTok = _issuedTokenId(seriesId);
        IIntexNFT1155.SeriesData storage data = $.seriesData[iTok];
        if (data.issuedAt == 0) revert NonexistentToken(iTok);

        if (data.state != IIntexNFT1155.IntexState.Qualified && data.state != IIntexNFT1155.IntexState.Called) {
            revert InvalidStateForSettle(uint8(data.state));
        }

        if (data.state == IIntexNFT1155.IntexState.Called) {
            // No new Settled tokens past the call window (mirrors the crosschainBurn/crosschainMint freeze).
            uint32 derivedDeadline = data.calledAt + data.callTrigger.callNoticePeriod;
            if (block.timestamp > derivedDeadline) {
                revert SettleAfterDeadline(iTok, derivedDeadline);
            }
        }

        uint256 sTok = _settledTokenId(seriesId);

        // CEI ok: update both Issued and Settled totalSupply mirrors before the external _mint
        // callback fires - keeps (totalSupply == sum balanceOf) consistent mid-callback.
        // Burn `amount` Issued from `from` and mint the same `amount` of Settled to `to`.
        // forge-lint: disable-next-line(unsafe-typecast) -- amount <= issued balance <= totalSupply (uint32); _burn reverts otherwise
        data.totalSupply -= uint32(amount);
        _burn(from, iTok, amount);

        // forge-lint: disable-next-line(unsafe-typecast) -- amount mirrors the issued amount burned above
        $.seriesData[sTok].totalSupply += uint32(amount);
        _mint(to, sTok, amount, "");

        emit IntexSettled(seriesId, to, amount);
    }

    /// @inheritdoc IIntexNFT1155
    function burnSettled(address holder, bytes14 seriesId, uint256 amount) external onlyRole(PROMIS_ROLE) {
        if (holder == address(0)) revert ZeroAddress("holder", holder);
        if (amount == 0) revert ZeroAmount();

        IntexNFT1155Storage storage $ = _s();
        uint256 iTok = _issuedTokenId(seriesId);
        IIntexNFT1155.SeriesData storage iData = $.seriesData[iTok];
        // Series must exist; we look up via the Issued id storage.
        if (iData.issuedAt == 0) revert NonexistentToken(iTok);

        // Mirror `settle`'s precondition: Settled balances only exist after a settle, which
        // is only permitted from Qualified or Called. Making the gate explicit (instead of
        // relying on `_burn`'s zero-balance revert) keeps a future change that pre-mints
        // Settled tokens - e.g. an airdrop variant - from accidentally opening an early-burn
        // window. The gate is `state in {Qualified, Called}`, not a fictional Settled state value.
        if (iData.state != IIntexNFT1155.IntexState.Qualified && iData.state != IIntexNFT1155.IntexState.Called) {
            revert InvalidState(uint8(IIntexNFT1155.IntexState.Qualified), uint8(iData.state));
        }

        uint256 sTok = _settledTokenId(seriesId);
        // CEI ok: write before _burn for symmetry with mint; _burn fires no acceptance callback
        // (to == address(0)), so no read-only-reentrancy surface here.
        // forge-lint: disable-next-line(unsafe-typecast) -- amount <= settled balance <= totalSupply (uint32); _burn reverts otherwise
        $.seriesData[sTok].totalSupply -= uint32(amount);
        _burn(holder, sTok, amount);

        emit IntexCompleted(seriesId, holder, amount);
    }

    /// @inheritdoc IIntexNFT1155
    function parkIntex(address holder, bytes14 seriesId, uint256 amount) external onlyRole(GEM_ROLE) returns (uint256) {
        if (holder == address(0)) revert ZeroAddress("holder", holder);
        if (amount == 0) revert ZeroAmount();

        uint256 iTok = _issuedTokenId(seriesId);
        IIntexNFT1155.SeriesData storage data = _s().seriesData[iTok];
        if (data.issuedAt == 0) revert NonexistentToken(iTok);

        if (data.state != IIntexNFT1155.IntexState.Issued && data.state != IIntexNFT1155.IntexState.Qualified) {
            revert InvalidState(uint8(IIntexNFT1155.IntexState.Qualified), uint8(data.state));
        }

        // forge-lint: disable-next-line(unsafe-typecast) -- amount <= issued balance <= totalSupply (uint32); _burn reverts otherwise
        data.totalSupply -= uint32(amount);
        _burn(holder, iTok, amount);

        emit IntexParked(seriesId, holder, amount);
        return amount;
    }

    /// @inheritdoc IIntexNFT1155
    function seriesExists(bytes14 seriesId) external view returns (bool) {
        return _s().seriesData[_issuedTokenId(seriesId)].issuedAt != 0;
    }

    /// @inheritdoc IIntexNFT1155
    function issuedTokenId(bytes14 seriesId) external pure returns (uint256) {
        return _issuedTokenId(seriesId);
    }

    /// @inheritdoc IIntexNFT1155
    function settledTokenId(bytes14 seriesId) external pure returns (uint256) {
        return _settledTokenId(seriesId);
    }

    /// @inheritdoc IIntexNFT1155
    function tokenIds(bytes14 seriesId) external pure returns (uint256 issued, uint256 settled) {
        return (_issuedTokenId(seriesId), _settledTokenId(seriesId));
    }

    /// @dev Pure helper used internally and exposed via `issuedTokenId`.
    function _issuedTokenId(bytes14 seriesId) private pure returns (uint256) {
        return uint256(uint112(seriesId));
    }

    /// @dev Pure helper used internally and exposed via `settledTokenId`.
    function _settledTokenId(bytes14 seriesId) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(_SETTLED_DOMAIN, seriesId)));
    }

    /// @inheritdoc IIntexNFT1155
    function statusOf(uint256 tokenId) external view returns (IIntexNFT1155.IntexStatus) {
        return _s().seriesData[tokenId].status;
    }

    /// @inheritdoc IIntexNFT1155
    function readData(bytes14 seriesId) external view returns (IIntexNFT1155.SeriesData memory) {
        IntexNFT1155Storage storage $ = _s();
        uint256 tokenId = _issuedTokenId(seriesId);
        // `issuedAt == 0` is the canonical existence sentinel for seriesData entries.
        // slither-disable-next-line incorrect-equality
        if ($.seriesData[tokenId].issuedAt == 0) {
            revert NonexistentToken(tokenId);
        }
        IIntexNFT1155.SeriesData memory data = $.seriesData[tokenId];
        data.state = _effectiveState(data);
        return data;
    }

    /// @dev Derived, never stored: no transaction arrives at the deadline to write it.
    function _effectiveState(IIntexNFT1155.SeriesData memory data) private view returns (IIntexNFT1155.IntexState) {
        if (
            data.state == IIntexNFT1155.IntexState.Called
                && block.timestamp > uint256(data.calledAt) + data.callTrigger.callNoticePeriod
        ) {
            return IIntexNFT1155.IntexState.Expired;
        }
        return data.state;
    }

    /// @inheritdoc IIntexNFT1155
    function holderBalances(bytes14 seriesId, address holder)
        external
        view
        returns (IIntexNFT1155.HolderBalances memory)
    {
        uint256 iTok = _issuedTokenId(seriesId);
        uint256 sTok = _settledTokenId(seriesId);
        return IIntexNFT1155.HolderBalances({
            issued: uint32(balanceOf(holder, iTok)), settled: uint32(balanceOf(holder, sTok))
        });
    }

    /// @inheritdoc IIntexNFT1155
    function totalSupply(uint256 tokenId) external view returns (uint256) {
        return _s().seriesData[tokenId].totalSupply;
    }

    /// @inheritdoc IIntexNFT1155
    function getAuctionWonCount(bytes14 seriesId, address account) external view returns (uint16) {
        return _s().auctionWonCount[_issuedTokenId(seriesId)][account];
    }

    /// @inheritdoc IIntexNFT1155
    function uri(uint256 tokenId) public view override(ERC1155Upgradeable, IIntexNFT1155) returns (string memory) {
        IIntexNFT1155.SeriesData memory data = _s().seriesData[tokenId];
        data.state = _effectiveState(data);
        return IntexMetadata.tokenURI(data);
    }

    /// @inheritdoc IIntexNFT1155
    function contractURI() external pure returns (string memory) {
        return IntexMetadata.contractURI();
    }

    /// @notice ERC1155 transfer hook: enforces soulbound Settled tokens, freezes Called
    ///         series, and maintains the owned-series enumeration index.
    /// @dev Transfer lock and soulbound enforcement.
    ///      - Mint/burn paths (from/to address(0)) are always allowed (settle, burnSettled,
    ///        bridge crosschainBurn/crosschainMint on Issued, mint).
    ///      - Holder-to-holder transfers:
    ///          * Settled token ids are soulbound - always reverts.
    ///          * Issued token ids are transferable while the series is Issued or Qualified.
    ///            A Called series freezes holder-to-holder transfers: the settlement
    ///            obligation stays with the holder and cannot be passed on. Bridge gating
    ///            is separate and lives in `crosschainBurn` / `crosschainMint`.
    /// @param from Sender address (address(0) for mints).
    /// @param to Receiver address (address(0) for burns).
    /// @param ids Array of token IDs.
    /// @param values Array of amounts.
    function _update(address from, address to, uint256[] memory ids, uint256[] memory values) internal override {
        IntexNFT1155Storage storage $ = _s();
        if (from != address(0) && to != address(0)) {
            for (uint256 i = 0; i < ids.length; i++) {
                IIntexNFT1155.SeriesData storage data = $.seriesData[ids[i]];
                if (data.status == IIntexNFT1155.IntexStatus.Settled) {
                    revert SoulboundSettled(ids[i]);
                }
                if (data.state == IIntexNFT1155.IntexState.Called) {
                    revert TransferOnCalledForbidden(ids[i]);
                }
            }
        }

        // Snapshot pre-transfer balances - checked BEFORE super._update, verified AFTER
        // to handle duplicate tokenIds in batch correctly.
        bool[] memory fromHadTokens = new bool[](ids.length);
        bool[] memory toHadTokens = new bool[](ids.length);

        for (uint256 i = 0; i < ids.length; i++) {
            if (values[i] == 0) continue;
            if (from != address(0)) {
                fromHadTokens[i] = balanceOf(from, ids[i]) > 0;
                $.totalBalance[from] -= values[i];
            }
            if (to != address(0)) {
                toHadTokens[i] = balanceOf(to, ids[i]) > 0;
                $.totalBalance[to] += values[i];
            }
        }

        super._update(from, to, ids, values);

        // Post-transfer: add/remove are idempotent, safe for duplicate tokenIds in batch.
        for (uint256 i = 0; i < ids.length; i++) {
            if (values[i] == 0) continue;

            if (from != address(0) && fromHadTokens[i] && balanceOf(from, ids[i]) == 0) {
                _removeOwnedSeries(from, ids[i]);
            }
            if (to != address(0) && !toHadTokens[i] && balanceOf(to, ids[i]) > 0) {
                _addOwnedSeries(to, ids[i]);
            }
        }
    }

    /// @dev Add `tokenId` to `owner`'s owned-series enumeration (idempotent).
    /// @param owner Owner address.
    /// @param tokenId Token ID to add.
    function _addOwnedSeries(address owner, uint256 tokenId) internal {
        IntexNFT1155Storage storage $ = _s();
        if (!$.ownsToken[owner][tokenId]) {
            $.ownedSeriesIndex[owner][tokenId] = $.ownedSeries[owner].length;
            $.ownedSeries[owner].push(tokenId);
            $.ownsToken[owner][tokenId] = true;
        }
    }

    /// @dev Remove `tokenId` from `owner`'s owned-series enumeration (swap-and-pop, idempotent).
    /// @param owner Owner address.
    /// @param tokenId Token ID to remove.
    function _removeOwnedSeries(address owner, uint256 tokenId) internal {
        IntexNFT1155Storage storage $ = _s();
        if ($.ownsToken[owner][tokenId]) {
            uint256 lastIndex = $.ownedSeries[owner].length - 1;
            uint256 tokenIndex = $.ownedSeriesIndex[owner][tokenId];

            if (tokenIndex != lastIndex) {
                uint256 lastTokenId = $.ownedSeries[owner][lastIndex];
                $.ownedSeries[owner][tokenIndex] = lastTokenId;
                $.ownedSeriesIndex[owner][lastTokenId] = tokenIndex;
            }

            $.ownedSeries[owner].pop();
            delete $.ownedSeriesIndex[owner][tokenId];
            $.ownsToken[owner][tokenId] = false;
        }
    }

    // --- Enumerable view functions ---

    /// @inheritdoc IIntexNFT1155
    function getAllSeries() external view returns (uint256[] memory) {
        return _s().allSeries;
    }

    /// @inheritdoc IIntexNFT1155
    function getSeriesPaginated(uint256 offset, uint256 limit)
        external
        view
        returns (uint256[] memory series, uint256 total)
    {
        uint256[] storage allSeries = _s().allSeries;
        total = allSeries.length;
        if (offset >= total) return (new uint256[](0), total);

        uint256 end = offset + limit;
        if (end > total) end = total;

        series = new uint256[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            series[i - offset] = allSeries[i];
        }
    }

    /// @inheritdoc IIntexNFT1155
    function totalSeries() external view returns (uint256) {
        return _s().allSeries.length;
    }

    /// @inheritdoc IIntexNFT1155
    function getOwnedSeries(address owner) external view returns (uint256[] memory) {
        return _s().ownedSeries[owner];
    }

    /// @inheritdoc IIntexNFT1155
    function getOwnedSeriesPaginated(address owner, uint256 offset, uint256 limit)
        external
        view
        returns (uint256[] memory series, uint256 total)
    {
        uint256[] storage owned = _s().ownedSeries[owner];
        total = owned.length;
        if (offset >= total) return (new uint256[](0), total);

        uint256 end = offset + limit;
        if (end > total) end = total;

        series = new uint256[](end - offset);
        for (uint256 i = offset; i < end; i++) {
            series[i - offset] = owned[i];
        }
    }

    /// @inheritdoc IIntexNFT1155
    function ownedSeriesCount(address owner) external view returns (uint256) {
        return _s().ownedSeries[owner].length;
    }

    /// @inheritdoc IIntexNFT1155
    function totalBalance(address owner) external view returns (uint256) {
        return _s().totalBalance[owner];
    }

    /// @inheritdoc IIntexNFT1155
    function getOwnedSeriesWithBalances(address owner)
        external
        view
        returns (uint256[] memory ownedTokenIds, uint256[] memory balances)
    {
        ownedTokenIds = _s().ownedSeries[owner];
        balances = new uint256[](ownedTokenIds.length);

        for (uint256 i = 0; i < ownedTokenIds.length; i++) {
            balances[i] = balanceOf(owner, ownedTokenIds[i]);
        }

        return (ownedTokenIds, balances);
    }

    /// @inheritdoc IIntexNFT1155
    function getOwnedSeriesWithBalancesPaginated(address owner, uint256 offset, uint256 limit)
        external
        view
        returns (uint256[] memory ownedTokenIds, uint256[] memory balances, uint256 total)
    {
        uint256[] storage owned = _s().ownedSeries[owner];
        total = owned.length;
        if (offset >= total) return (new uint256[](0), new uint256[](0), total);

        uint256 end = offset + limit;
        if (end > total) end = total;

        uint256 n = end - offset;
        ownedTokenIds = new uint256[](n);
        balances = new uint256[](n);
        for (uint256 i = 0; i < n; i++) {
            uint256 tokenId = owned[offset + i];
            ownedTokenIds[i] = tokenId;
            balances[i] = balanceOf(owner, tokenId);
        }
    }

    /// @notice ERC-165 interface detection.
    /// @dev Reports support for `IIntexNFT1155` and `IERC1155Bridgeable` in addition to the
    ///      interfaces advertised by ERC1155 and AccessControl.
    /// @param interfaceId The ERC-165 interface identifier to query.
    /// @return True if the contract implements `interfaceId`.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(IERC165, ERC1155Upgradeable, AccessControlUpgradeable)
        returns (bool)
    {
        // 0x49064906 = ERC-4906; literal because OZ's IERC4906 extends IERC721.
        return interfaceId == type(IIntexNFT1155).interfaceId || interfaceId == type(IERC1155Bridgeable).interfaceId
            || interfaceId == bytes4(0x49064906) || super.supportsInterface(interfaceId);
    }
}
