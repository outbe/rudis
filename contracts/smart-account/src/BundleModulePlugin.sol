// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {IModule} from "@zerodev/kernel/interfaces/IERC7579Modules.sol";
import {IERC7579Account} from "@zerodev/kernel/interfaces/IERC7579Account.sol";
import {MODULE_TYPE_FALLBACK, MODULE_TYPE_EXECUTOR} from "@zerodev/kernel/types/Constants.sol";
import {LibERC7579} from "solady/accounts/LibERC7579.sol";
import {ITokenBundle} from "./interfaces/ITokenBundle.sol";

contract BundleModulePlugin is IModule, ITokenBundle {
    // --- State (keyed by Kernel account address = msg.sender during lifecycle calls) ---
    mapping(address => bool) private installed;
    mapping(address account => address[]) private bundleTokens;
    /// @dev token-minor units. Stores 2x the deposited amount (purchase leg + COEN-buy leg); topUp
    ///      credits `received * 2` and decreaseBundleBalance burns `amount * 2`. BundleSpendProtectorHook
    ///      reads it as the reserve in `freeBalance = totalBalance - bundleBalance`.
    mapping(address account => mapping(address token => uint256)) private bundleBalance;

    /// @notice The sole authorized caller of `dispatchDecreaseBalance` - the BundleWithdrawHook.
    /// @dev Wired once post-deploy via `setWithdrawHook`: the hook takes this plugin's address as a
    ///      constructor immutable and so is deployed after this plugin, forbidding a constructor
    ///      immutable here. While unset, `dispatchDecreaseBalance` reverts for everyone (fail-closed).
    address public withdrawHook;
    /// @dev Authorized to call `setWithdrawHook`. Passed as a constructor arg (not captured from
    ///      `msg.sender`) because CREATE2-factory deploys run the constructor with `msg.sender` = the
    ///      deployment proxy (0x4e59...), not the operator.
    address private immutable _OWNER;

    error HasBundleBalance(address token);
    error BundleNotInstalled();
    error TokenNotInBundle(address token);
    error UnauthorizedHook();

    event BundleTransfer(address indexed from, address indexed to, address indexed token, uint256 value);
    /// @notice Emitted when a Credis spend decrements the bundle reserve, so off-chain monitoring can
    ///         observe reserve movement on the fund-holding account.
    event BundleBalanceDecreased(address indexed account, address indexed token, uint256 burned, uint256 newBalance);

    constructor(address owner_) {
        _OWNER = owner_;
    }

    /// @notice Authorize the sole `dispatchDecreaseBalance` caller (the BundleWithdrawHook).
    /// @dev Owner-gated. Call once after the hook is deployed and before the account factory goes
    ///      live; the hook cannot be a constructor immutable due to the circular construction order.
    function setWithdrawHook(address hook) external {
        require(msg.sender == _OWNER, UnauthorizedHook());
        withdrawHook = hook;
    }

    /// @dev Called by Kernel during module installation.
    ///      When installed as an executor with empty data, this is a no-op.
    ///      When installed as a fallback, `data` = `abi.encode(address[] bundleTokens)`.
    function onInstall(bytes calldata data) external payable override {
        if (data.length == 0) return;
        installed[msg.sender] = true;
        address[] memory tokens = abi.decode(data, (address[]));
        bundleTokens[msg.sender] = tokens;
    }

    function onUninstall(bytes calldata) external payable override {
        address[] memory tokens = bundleTokens[msg.sender];
        for (uint256 i = 0; i < tokens.length; i++) {
            if (bundleBalance[msg.sender][tokens[i]] > 0) {
                revert HasBundleBalance(tokens[i]);
            }
        }
        installed[msg.sender] = false;
    }

    function isModuleType(uint256 id) external pure override returns (bool) {
        return id == MODULE_TYPE_FALLBACK || id == MODULE_TYPE_EXECUTOR;
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        return installed[smartAccount];
    }

    /// @notice Pull `amount` of `token` from `sender` into the smart account.
    /// @dev Called via Kernel's fallback dispatch (CALLTYPE_SINGLE), so `msg.sender` is the
    ///      smart account. The transfer is executed by the smart account itself via
    ///      `executeFromExecutor`, which requires this plugin to also be installed as an executor.
    ///      Callers must approve the **smart account** (not this plugin) for the transfer amount.
    function topUp(address sender, address token, uint256 amount) external override {
        address thisAccount = msg.sender;
        require(installed[thisAccount], BundleNotInstalled());
        require(isBundleToken(thisAccount, token), TokenNotInBundle(token));
        // NB: enforce check to verify that the user made a topUp with owns funds to enable credis
        require(IERC20(token).balanceOf(thisAccount) >= amount, "Insufficient funds for Credis");

        // Have the smart account (msg.sender) execute transferFrom in its own context so that
        // the ERC20 sees the smart account as the spender, not this singleton plugin.
        bytes32 execMode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory transferCall = abi.encodeCall(IERC20.transferFrom, (sender, thisAccount, amount));

        // Credit the bundle from the measured balance delta, after the transfer. The transfer runs
        // through the account's executor (msg.sender must be the account, so SafeERC20 can't wrap it), and
        // a no-return / false-return or fee-on-transfer token would let a over-state the reserve.
        uint256 balBefore = IERC20(token).balanceOf(thisAccount);
        // ERC-7579 single execution encoding: target(20) || value(32) || callData.
        IERC7579Account(thisAccount).executeFromExecutor(execMode, abi.encodePacked(token, uint256(0), transferCall));
        uint256 received = IERC20(token).balanceOf(thisAccount) - balBefore;

        // NB: double the received amount - 50% funds purchases, 50% funds Coen buys.
        bundleBalance[thisAccount][token] += received * 2;
        emit BundleTransfer(sender, thisAccount, token, received);
    }

    function balanceOf(address owner, address token) external view override returns (uint256) {
        // NB: this returns the whole balance i.e. for user payments and for coen buys
        return bundleBalance[owner][token];
    }

    /// @notice The registered bundle tokens for `account`.
    /// @dev Used by BundleSpendProtectorHook to enforce the reserve invariant across every bundled
    ///      token in one pass, without needing to parse them out of the execution calldata.
    function bundleTokensOf(address account) external view override returns (address[] memory) {
        return bundleTokens[account];
    }

    /// @notice Returns true if `token` is a registered bundle token for `account`.
    function isBundleToken(address account, address token) public view returns (bool) {
        address[] memory tokens = bundleTokens[account];
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i] == token) return true;
        }
        return false;
    }

    /// @notice Decrease bundle balance for the calling smart account by min(amount, currentBalance).
    /// @dev Called via Kernel's executeFromExecutor dispatch from dispatchDecreaseBalance,
    ///      so msg.sender is always the smart account.
    function decreaseBundleBalance(address token, uint256 amount) external {
        address thisAccount = msg.sender;
        require(installed[thisAccount], BundleNotInstalled());
        uint256 bal = bundleBalance[thisAccount][token];
        // NB: decrease twice more balance from bundle
        uint256 bandleAmount = amount * 2;
        uint256 newBalance = bal > bandleAmount ? bal - bandleAmount : 0;
        bundleBalance[thisAccount][token] = newBalance;
        emit BundleBalanceDecreased(thisAccount, token, bal - newBalance, newBalance);
        // TODO: implement spending bundle for buying COENs
    }

    /// @notice Dispatch a decreaseBundleBalance call through the smart account's executor path.
    /// @dev Called by BundleWithdrawHook.postCheck (msg.sender = smartAccount there).
    ///      Uses this plugin's executor registration to call executeFromExecutor, ensuring
    ///      that decreaseBundleBalance is invoked with msg.sender = smartAccount.
    function dispatchDecreaseBalance(address smartAccount, address token, uint256 amount) external {
        require(msg.sender == withdrawHook, UnauthorizedHook());
        bytes32 execMode =
            LibERC7579.encodeMode(LibERC7579.CALLTYPE_SINGLE, LibERC7579.EXECTYPE_DEFAULT, bytes4(0), bytes22(0));
        bytes memory decreaseCall = abi.encodeCall(BundleModulePlugin.decreaseBundleBalance, (token, amount));
        IERC7579Account(smartAccount)
            .executeFromExecutor(execMode, abi.encodePacked(address(this), uint256(0), decreaseCall));
    }
}
