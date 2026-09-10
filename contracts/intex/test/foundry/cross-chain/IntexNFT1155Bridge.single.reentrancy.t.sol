// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {IIntexNFT1155Bridge, SendParam} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";

/// @dev Hostile ERC1155 receiver that, during the `onERC1155Received` callback fired
///      mid-`receiveMessage` (via `token.crosschainMint` -> `_mint`), re-enters the adapter's
///      `send` entrypoint. With both `receiveMessage` and `send` carrying `nonReentrant`, the
///      inner call reverts with `ReentrancyGuardReentrantCall` at the modifier check (before the
///      zero-`to` validation), and we capture the selector. Without the guards, the inner call
///      would revert with `InvalidReceiver` instead - distinguishing the two cases.
contract ReentrantSendProbe is IERC1155Receiver {
    address public immutable adapter;
    bool public attempted;
    bytes4 public observedSelector;

    constructor(address adapter_) {
        adapter = adapter_;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external returns (bytes4) {
        attempted = true;

        SendParam memory param = SendParam({dstChainId: 0, to: bytes32(0), tokenId: 0, amount: 0});

        try IIntexNFT1155Bridge(adapter).send{value: 0}(param) {
        // unexpected: re-entrant call should always revert (either with the guard or with InvalidReceiver)
        }
        catch (bytes memory err) {
            if (err.length >= 4) {
                bytes32 word;
                assembly {
                    word := mload(add(err, 0x20))
                }
                observedSelector = bytes4(word);
            }
        }

        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }
}

/// @title IntexNFT1155BridgeSingleReentrancyTest
/// @notice Behavioral test that `receiveMessage` and `send` are mutually `nonReentrant`-guarded.
/// @dev Source chain (A) caller initiates a transfer to the hostile probe on the destination chain (B). On B,
///      `receiveMessage` -> `_dispatch` -> `token.crosschainMint` -> `_mint` invokes the probe's `onERC1155Received`,
///      which attempts to re-enter `adapterB.send`. Expected: the inner call reverts with
///      `ReentrancyGuardReentrantCall` - proving the guard is held by `receiveMessage` AND that `send` carries the
///      modifier.
contract IntexNFT1155BridgeSingleReentrancyTest is CrossChainTest {
    uint32 private aChainId = 1;
    uint32 private bChainId = 2;

    IntexNFT1155 private tokenA;
    IntexNFT1155 private tokenB;
    IntexNFT1155Bridge private adapterA;
    IntexNFT1155Bridge private adapterB;

    address private user = address(0x1);
    uint32 private constant SERIES_ID_DAY = 20260401;
    bytes14 private constant SERIES_ID = "20260401-USD-U";
    uint256 private constant TOKEN_ID = uint256(uint112(SERIES_ID));
    uint256 private constant AMOUNT = 100;
    uint32 private constant ISSUED_INTEX_COUNT = 10_000;

    function setUp() public {
        vm.deal(user, 1000 ether);

        _setUpBridge();

        tokenA = DeployProxy.intexNFT1155(address(this), address(this));
        tokenB = DeployProxy.intexNFT1155(address(this), address(this));

        adapterA = DeployProxy.intexNFT1155Bridge(address(tokenA), address(bridge), address(this));
        adapterB = DeployProxy.intexNFT1155Bridge(address(tokenB), address(bridge), address(this));

        tokenA.grantRole(tokenA.RELAYER_ROLE(), address(adapterA));
        tokenB.grantRole(tokenB.RELAYER_ROLE(), address(adapterB));

        adapterA.setRemoteMessenger(bChainId, _interop(bChainId, address(adapterB)));
        adapterB.setRemoteMessenger(aChainId, _interop(aChainId, address(adapterA)));

        tokenA.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, ISSUED_INTEX_COUNT, 0));
        tokenB.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, ISSUED_INTEX_COUNT, 0));

        tokenA.markQualified(SERIES_ID);
        tokenB.markQualified(SERIES_ID);

        tokenA.issue(user, AMOUNT, SERIES_ID);
    }

    function test_receiveMessage_blocks_reentry_to_send() public {
        ReentrantSendProbe probe = new ReentrantSendProbe(address(adapterB));

        SendParam memory sendParam = SendParam({
            dstChainId: bChainId, to: bytes32(uint256(uint160(address(probe)))), tokenId: TOKEN_ID, amount: AMOUNT
        });

        uint256 fee = adapterA.quoteSend(sendParam);

        vm.prank(user);
        adapterA.send{value: fee}(sendParam);

        _deliver(aChainId, address(adapterA), address(adapterB), bridge.lastPayload());

        assertTrue(probe.attempted(), "probe callback never ran");
        assertEq(
            probe.observedSelector(),
            bytes4(keccak256("ReentrancyGuardReentrantCall()")),
            "receiveMessage / send reentrancy guard did not fire"
        );
    }
}
