// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IERC1155} from "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";
import {IERC1155Bridgeable} from "./IERC1155Bridgeable.sol";

/**
 * @title IntexNFT1155 Contract Interface
 * @author Outbe
 * @notice Public API, events, errors, and data types for `IntexNFT1155`.
 * @dev Series are keyed by `seriesId` (uint32). Each series has two ERC1155 token ids:
 * issued = `uint256(seriesId)`, settled = `keccak256("SETTLED", seriesId)`.
 * Also implements `IERC1155Bridgeable` for ERC-7786 cross-chain compatibility.
 * @dev Keep continuation lines flush against the leading `*`. The Rust
 * precompiles bind this interface with `sol!`, which re-emits this block as a
 * doc comment; a 4-space indent there parses as a Rust code block and is then
 * compiled as a doctest.
 */
interface IIntexNFT1155 is IERC1155, IERC1155Bridgeable {
    // The following standard methods are inherited and available on implementers (from OpenZeppelin IERC1155/ERC1155):
    // - balanceOf(address account, uint256 id) external view returns (uint256)
    // - balanceOfBatch(address[] calldata accounts, uint256[] calldata ids) external view returns (uint256[] memory)
    // - setApprovalForAll(address operator, bool approved) external
    // - isApprovedForAll(address account, address operator) external view returns (bool)
    // - safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external
    // - safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external

    // --- Types ---

    /// @notice Series lifecycle state.
    /// @dev Lifecycle: Issued -> Qualified -> Called -> Expired. `Expired` is read-only:
    ///      storage keeps `Called` so the transfer and bridge freezes, which compare the
    ///      stored field, keep applying.
    enum IntexState {
        Issued,
        Qualified,
        Called,
        Expired
    }

    /// @notice Per-token classification within a series.
    /// @dev Each series has an Issued token (transferable, gated by series state) and a
    ///      Settled token (soulbound, minted on settle, burned on Promis mining).
    enum IntexStatus {
        Issued,
        Settled
    }

    /// @notice Per-holder, per-series balance pair. Widths match the `uint32` supply cap so a
    ///         balance accumulated above `type(uint16).max` is reported without truncation.
    struct HolderBalances {
        uint32 issued;
        uint32 settled;
    }

    /// @notice Forced-call trigger parameters (window/threshold/period).
    struct IntexCallTrigger {
        /// @notice Call-trigger observation window in seconds.
        uint32 callWindow;
        /// @notice Call-trigger threshold in seconds.
        uint32 callThreshold;
        /// @notice Called->deadline window in seconds; stored verbatim, the issuer must supply a non-zero value.
        uint32 callNoticePeriod;
    }

    /// @notice Series-level data, stored per token id (one entry for the Issued token id
    ///         and one for the Settled token id; `status` distinguishes them).
    /// @dev `issuedIntexCount` is meaningful only on the Issued entry; it caps the current
    ///      `totalSupply` minted via `mint` (a burn frees cap room).
    struct SeriesData {
        /// @notice Issuance currency (ISO numeric); single USD (840) until multi-currency.
        uint16 issuanceCurrency;
        /// @notice Reference currency (ISO numeric); single USD (840) until multi-currency.
        uint16 referenceCurrency;
        /// @notice Auction-cleared cap on the Issued mint quantity. Set once at `createSeries`,
        ///         never mutated; `mint` rejects pushing `totalSupply` past it.
        uint32 issuedIntexCount;
        /// @notice PROMIS-units per Intex unit (1e6).
        uint128 promisLoadMinor;
        /// @notice Per-unit entry price in ISO stable-units (1e6).
        uint64 entryPriceMinor;
        /// @notice Floor price in ISO stable-units (1e6).
        uint64 floorPriceMinor;
        /// @notice Call price in ISO stable-units (1e6).
        uint64 callPriceMinor;
        /// @notice Forced-call trigger (window/threshold/period).
        IntexCallTrigger callTrigger;
        /// @notice Timestamp when the series was created (UNIX seconds).
        uint32 issuedAt;
        /// @notice Timestamp when the series entered the Called state (UNIX seconds, 0 if not called).
        uint32 calledAt;
        /// @notice Total supply of this token id across all holders.
        uint32 totalSupply;
        /// @notice Token classification (Issued or Settled).
        IntexStatus status;
        /// @notice Current series lifecycle state.
        IntexState state;
        /// @notice Worldwide day whose tributes fed this series.
        uint32 worldwideDay;
        /// @notice Series identifier - the readable id this record belongs to.
        bytes14 seriesId;
    }

    // --- Events ---

    /// @notice Emitted when a new Intex series is issued.
    /// @param operator Caller that minted the Issued tokens (`RELAYER_ROLE`).
    /// @param tokenId Issued token id (= `uint256(seriesId)`).
    /// @param to Recipient of the minted Issued tokens.
    /// @param quantity Amount of Issued tokens minted to `to`.
    event IntexIssued(address indexed operator, uint256 indexed tokenId, address indexed to, uint256 quantity);

    /// @notice Emitted when a series lifecycle state changes.
    /// @param operator Caller that drove the transition (`RELAYER_ROLE`).
    /// @param tokenId Issued token id (= `uint256(seriesId)`).
    /// @param fromState Lifecycle state before the transition.
    /// @param toState Lifecycle state after the transition.
    /// @param at Timestamp of the state change.
    /// @param callDeadlineAt Effective settlement deadline (`calledAt + callNoticePeriod`, 0 if not applicable).
    event IntexStatusUpdated(
        address indexed operator,
        uint256 indexed tokenId,
        IntexState fromState,
        IntexState toState,
        uint32 at,
        uint32 callDeadlineAt
    );

    /// @notice Emitted when token metadata is updated (ERC-4906; `tokenId` is non-indexed per the EIP).
    /// @param tokenId Token id whose metadata changed.
    event MetadataUpdate(uint256 tokenId);

    /// @notice Emitted when settlement burns Issued and mints Settled.
    /// @param seriesId Series identifier.
    /// @param to Recipient of the newly minted Settled tokens.
    /// @param amount Amount of Issued burned and Settled minted.
    event IntexSettled(bytes14 indexed seriesId, address indexed to, uint256 amount);

    /// @notice Emitted when Settled Intex are consumed to mine Promis.
    /// @param seriesId Series identifier.
    /// @param holder Holder whose Settled tokens were burned.
    /// @param amount Amount of Settled tokens burned.
    event IntexCompleted(bytes14 indexed seriesId, address indexed holder, uint256 amount);

    /// @notice Emitted when Issued Intex are burned on parking in the Gem Factory.
    /// @param seriesId Series identifier.
    /// @param holder Holder whose Issued tokens were burned.
    /// @param amount Amount of Issued tokens burned.
    event IntexParked(bytes14 indexed seriesId, address indexed holder, uint256 amount);

    // --- Errors ---

    /// @notice Zero address provided.
    error ZeroAddress(string field, address value);
    /// @notice Invalid lifecycle state transition.
    error InvalidState(uint8 expected, uint8 actual);
    /// @notice Token id does not exist.
    error NonexistentToken(uint256 tokenId);
    /// @notice Series already exists for this token id.
    error TokenAlreadyExists(uint256 tokenId);
    /// @notice `createSeries` was called with a zero issued-intex count (the supply cap cannot be zero).
    error ZeroIssuedIntexCount();
    /// @notice A settlement or burn amount was zero.
    error ZeroAmount();
    /// @notice A mint or crosschainMint quantity exceeds the range its packed storage field can hold.
    error QuantityTooLarge(uint256 quantity);
    /// @notice Settle attempted in a series state that does not allow it.
    error InvalidStateForSettle(uint8 state);
    /// @notice Transfer or bridge attempted on a Settled (soulbound) token.
    error SoulboundSettled(uint256 tokenId);
    /// @notice Holder-to-holder transfer attempted while the series is Called.
    error TransferOnCalledForbidden(uint256 tokenId);
    /// @notice Bridge crosschainBurn/crosschainMint attempted on a Settled token.
    error BridgeOnSettledForbidden(uint256 tokenId);
    /// @notice Bridge crosschainBurn/crosschainMint attempted while the series state disallows it.
    error BridgeStateForbidden(uint256 tokenId, uint8 state);
    /// @notice Bridge crosschainBurn/crosschainMint attempted on a `Called` series after the settlement
    ///         deadline (`calledAt + callNoticePeriod`) has passed.
    error BridgeAfterDeadline(uint256 tokenId, uint32 deadline);
    /// @notice Settle attempted on a `Called` series after the settlement deadline
    ///         (`calledAt + callNoticePeriod`) has passed.
    error SettleAfterDeadline(uint256 tokenId, uint32 deadline);
    /// @notice `markCalled` was given a call time of zero or one the destination clock has not reached.
    error CalledAtInvalid(uint32 calledAt, uint32 nowTs);
    /// @notice A mint or batch sum would push `totalSupply` past `issuedIntexCount`.
    error SupplyCapExceeded(bytes14 seriesId, uint256 attempted, uint256 cap);

    // --- Writes ---

    /// @notice Identity inputs for a new series, set once at `createSeries`.
    /// @dev `worldwideDay` is the day the series was derived from; it is the provenance key
    ///      (`seriesOfDay`), stored verbatim rather than inferred from `seriesId`.
    struct CreateSeriesParams {
        bytes14 seriesId;
        uint32 worldwideDay;
        uint16 issuanceCurrency;
        uint16 referenceCurrency;
        uint32 issuedIntexCount;
        uint128 promisLoadMinor;
        uint64 entryPriceMinor;
        uint64 floorPriceMinor;
        uint64 callPriceMinor;
        IntexCallTrigger callTrigger;
    }

    /// @notice Create a new Intex series (one per auction) with its identity fields.
    /// @param params Series identity (id, currencies, cap, promis load, prices, call trigger).
    function createSeries(CreateSeriesParams calldata params) external;

    /// @notice Mint Intex to a specific address.
    /// @param to Recipient of the minted Issued tokens.
    /// @param quantity Amount to mint (bounded by `type(uint16).max` and the series supply cap).
    /// @param seriesId Series identifier.
    function issue(address to, uint256 quantity, bytes14 seriesId) external;

    /// @notice Mark a series as Qualified (Issued -> Qualified).
    /// @param seriesId Series identifier.
    function markQualified(bytes14 seriesId) external;

    /// @notice Mark a series as Called (Issued/Qualified -> Called).
    /// @param seriesId Series identifier.
    /// @param calledAt Unix time the origin marked the series Called; the deadline derives from it.
    function markCalled(bytes14 seriesId, uint32 calledAt) external;

    /// @notice Burn `amount` Issued Intex from `from` and mint the same `amount` of Settled Intex to `to`.
    /// @dev Settlement-contract entry point under SETTLEMENT_ROLE. Series must be Qualified or Called.
    /// @param seriesId Series identifier.
    /// @param from Holder whose Issued tokens are burned.
    /// @param to Recipient of the newly minted Settled tokens.
    /// @param amount Amount of Issued burned and Settled minted.
    function settle(bytes14 seriesId, address from, address to, uint256 amount) external;

    /// @notice Burn `amount` Settled Intex from `holder`.
    /// @dev Promis-facade entry point under PROMIS_ROLE.
    /// @param holder Holder whose Settled tokens are burned.
    /// @param seriesId Series identifier.
    /// @param amount Amount of Settled tokens to burn.
    function burnSettled(address holder, bytes14 seriesId, uint256 amount) external;

    /// @notice Burn `amount` Issued Intex from `holder` when the tokens are parked in the Gem Factory.
    /// @dev Gem-factory entry point under GEM_ROLE. Only allowed while the series is tradable
    ///      (Issued or Qualified - no Call Event yet). The parked capacity record lives in the
    ///      Gem Factory; the burned Intex is thereby non-tradable, call-exempt and Outbe-only.
    /// @param holder Holder whose Issued tokens are burned.
    /// @param seriesId Series identifier.
    /// @param amount Amount of Issued tokens to burn.
    /// @return The amount of burned tokens.
    function parkIntex(address holder, bytes14 seriesId, uint256 amount) external returns (uint256);

    // --- Reads ---

    /// @notice Whether the series has been created here.
    /// @param seriesId Series identifier.
    /// @return True once `createSeries` has run for it.
    function seriesExists(bytes14 seriesId) external view returns (bool);

    /// @notice Issued token id for a series (= `uint256(uint112(seriesId))`). Pure helper.
    /// @param seriesId Series identifier.
    /// @return The Issued token id.
    function issuedTokenId(bytes14 seriesId) external pure returns (uint256);

    /// @notice Settled (soulbound) token id for a series (= `keccak256("SETTLED", seriesId)`). Pure helper.
    /// @param seriesId Series identifier.
    /// @return The Settled token id.
    function settledTokenId(bytes14 seriesId) external pure returns (uint256);

    /// @notice Worldwide day whose tributes fed the series (0 if the series does not exist).
    /// @param seriesId Series identifier.
    /// @return The worldwide day (yyyymmdd).
    function worldwideDayOf(bytes14 seriesId) external view returns (uint32);

    /// @notice Series ids issued for a worldwide day.
    /// @param worldwideDay Worldwide day (yyyymmdd).
    /// @return The series ids of that day.
    function seriesIdsByWorldwideDay(uint32 worldwideDay) external view returns (bytes14[] memory);

    /// @notice Both token ids for a series in one call.
    /// @param seriesId Series identifier.
    /// @return issued The Issued token id.
    /// @return settled The Settled token id.
    function tokenIds(bytes14 seriesId) external pure returns (uint256 issued, uint256 settled);

    /// @notice Token classification (Issued/Settled) for a token id.
    /// @param tokenId Token id to classify.
    /// @return The token classification.
    function statusOf(uint256 tokenId) external view returns (IntexStatus);

    /// @notice Read series data by series id.
    /// @param seriesId Series identifier.
    /// @return The full series data for the Issued token id.
    function readData(bytes14 seriesId) external view returns (SeriesData memory);

    /// @notice Issued and Settled balances for a holder in a given series.
    /// @param seriesId Series identifier.
    /// @param holder Holder address to read.
    /// @return The holder's Issued and Settled balance pair.
    function holderBalances(bytes14 seriesId, address holder) external view returns (HolderBalances memory);

    /// @notice Total supply for a specific token id.
    /// @param tokenId Token id to read.
    /// @return The total supply of that token id across all holders.
    function totalSupply(uint256 tokenId) external view returns (uint256);

    /// @notice Token URI with on-chain metadata.
    /// @param tokenId Token id to render.
    /// @return The token URI containing on-chain metadata.
    function uri(uint256 tokenId) external view returns (string memory);

    /// @notice Collection-level metadata as an on-chain JSON data URI (ERC-7572).
    /// @return The collection metadata URI.
    function contractURI() external view returns (string memory);

    /// @notice Amount won at auction for a specific address in a series (recorded at mint, never changes).
    /// @param seriesId Series identifier.
    /// @param account Address to read.
    /// @return The amount won at auction for `account` in the series.
    function getAuctionWonCount(bytes14 seriesId, address account) external view returns (uint16);

    // --- Enumerable reads ---

    /// @notice All series (token ids) that have been created.
    /// @return The Issued token ids of every created series.
    function getAllSeries() external view returns (uint256[] memory);

    /// @notice Series with pagination.
    /// @param offset Index into the full series array.
    /// @param limit Maximum slice length to return.
    /// @return series The requested slice of Issued token ids.
    /// @return total Total number of series created.
    function getSeriesPaginated(uint256 offset, uint256 limit)
        external
        view
        returns (uint256[] memory series, uint256 total);

    /// @notice Total number of series created.
    /// @return The count of created series.
    function totalSeries() external view returns (uint256);

    /// @notice All series (token ids) owned by an address.
    /// @param owner Owner address to read.
    /// @return The token ids the owner holds a balance in.
    function getOwnedSeries(address owner) external view returns (uint256[] memory);

    /// @notice Owned series with pagination.
    /// @param owner Owner address to read.
    /// @param offset Index into the owner's owned-series array.
    /// @param limit Maximum slice length to return.
    /// @return series The requested slice of owned token ids.
    /// @return total Total number of distinct series owned by `owner`.
    function getOwnedSeriesPaginated(address owner, uint256 offset, uint256 limit)
        external
        view
        returns (uint256[] memory series, uint256 total);

    /// @notice Number of distinct series owned by an address.
    /// @param owner Owner address to read.
    /// @return The count of distinct series owned by `owner`.
    function ownedSeriesCount(address owner) external view returns (uint256);

    /// @notice Total Intex balance for an address across all series.
    /// @param owner Owner address to read.
    /// @return The owner's total Intex balance across all series.
    function totalBalance(address owner) external view returns (uint256);

    /// @notice Owned series with their balances for an address.
    /// @param owner Owner address to read.
    /// @return ownedTokenIds The token ids the owner holds.
    /// @return balances Balances parallel to `ownedTokenIds`.
    function getOwnedSeriesWithBalances(address owner)
        external
        view
        returns (uint256[] memory ownedTokenIds, uint256[] memory balances);

    /// @notice Paginated owned series with balances for an address.
    /// @param owner Owner address to read.
    /// @param offset Start index into the owned-series set.
    /// @param limit Maximum number of entries to return.
    /// @return ownedTokenIds The token ids in the `[offset, offset+limit)` window.
    /// @return balances Balances parallel to `ownedTokenIds`.
    /// @return total Total number of owned series (for computing further pages).
    function getOwnedSeriesWithBalancesPaginated(address owner, uint256 offset, uint256 limit)
        external
        view
        returns (uint256[] memory ownedTokenIds, uint256[] memory balances, uint256 total);
}
