// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {IStablecoin} from "../src/IStablecoin.sol";
import {IStablecoinFactory} from "../src/IStablecoinFactory.sol";
import {IStablecoinPolicyRegistry} from "../src/IStablecoinPolicyRegistry.sol";
import {IVote} from "../src/IVote.sol";

contract StablecoinInterfacesTest {
    function testCriticalSelectorsAreFrozen() public pure {
        _assertEq(IVote.createProposal.selector, 0x1f4f7d29);
        _assertEq(IVote.getProposalBond.selector, 0xb6e19328);
        _assertEq(IVote.unsettledBondLiabilities.selector, 0x112faae4);

        _assertEq(IStablecoinFactory.tokenCount.selector, 0x9f181b5e);
        _assertEq(IStablecoinFactory.listTokens.selector, 0xe30e5ae9);
        _assertEq(IStablecoinFactory.tokenById.selector, 0xce7127fb);
        _assertEq(IStablecoinFactory.tokenByTicker.selector, 0x5f637078);
        _assertEq(IStablecoinFactory.tokenIdOf.selector, 0x773c02d4);
        _assertEq(IStablecoinFactory.isStablecoin.selector, 0x1a650cc7);
        _assertEq(IStablecoinFactory.predictTokenAddress.selector, 0xc5ab0280);

        _assertEq(IStablecoinPolicyRegistry.createPolicy.selector, 0xe423fc67);
        _assertEq(IStablecoinPolicyRegistry.createDirectionalPolicy.selector, 0xbaa1725c);
        _assertEq(IStablecoinPolicyRegistry.addMembers.selector, 0x4ab6ba7c);
        _assertEq(IStablecoinPolicyRegistry.removeMembers.selector, 0x627cf4b0);
        _assertEq(IStablecoinPolicyRegistry.policyMemberCount.selector, 0x20aa751c);
        _assertEq(IStablecoinPolicyRegistry.listPolicyMembers.selector, 0xb54e0319);

        _assertEq(IStablecoin.transferWithMemo.selector, 0x95777d59);
        _assertEq(IStablecoin.transferFromWithMemo.selector, 0x929c2539);
        _assertEq(IStablecoin.mintWithMemo.selector, 0xe44f0b12);
        _assertEq(IStablecoin.burnWithMemo.selector, 0x38f23b0b);
        _assertEq(IStablecoin.burnFromWithMemo.selector, 0x93329d36);
        _assertEq(IStablecoin.forcedTransferWithMemo.selector, 0xea245fb8);
    }

    function testVoteStatusEncodingIsAppendOnly() public pure {
        require(uint8(IVote.ProposalStatus.Pending) == 0, "pending status");
        require(uint8(IVote.ProposalStatus.Approved) == 1, "approved status");
        require(uint8(IVote.ProposalStatus.Rejected) == 2, "rejected status");
        require(uint8(IVote.ProposalStatus.Expired) == 3, "expired status");
        require(uint8(IVote.ProposalStatus.Error) == 4, "error status");
    }

    function testPolicyOperationEncodingIsFrozen() public pure {
        require(uint8(IStablecoin.PolicyOperation.Send) == 0, "send operation");
        require(uint8(IStablecoin.PolicyOperation.Receive) == 1, "receive operation");
        require(uint8(IStablecoin.PolicyOperation.Mint) == 2, "mint operation");
    }

    function testErc7943FungibleInterfaceIdIsFrozen() public pure {
        bytes4 interfaceId = IStablecoin.canSend.selector ^ IStablecoin.canReceive.selector
            ^ IStablecoin.canTransfer.selector ^ IStablecoin.forcedTransfer.selector
            ^ IStablecoin.getFrozenTokens.selector ^ IStablecoin.setFrozenTokens.selector;
        _assertEq(interfaceId, 0x3edbb4c4);
    }

    function testCriticalEventTopicsAreFrozen() public pure {
        _assertEq(
            IStablecoinFactory.StablecoinCreated.selector,
            0x3bc7cf7e0d900433f10a105db3704bd383cbe686a86099bff51166e3c9e5fe02
        );
        _assertEq(
            IStablecoin.TransferWithMemo.selector, 0x57bc7354aa85aed339e000bccffabbc529466af35f0772c8f8ee1145927de7f0
        );
        _assertEq(IStablecoin.Frozen.selector, 0x68e0d8c112165d0949ce87205b719ed7d98c7401866c34a159f7c67c6f5620e7);
        _assertEq(
            IStablecoin.ForcedTransfer.selector, 0x7b3ce50c216d2ccf9919c6b9f1bfb33f0350a33010f188750b4af38e00448138
        );
        _assertEq(
            IVote.ProposalBondEscrowed.selector, 0xe2ad080d3ccd0b788a0338595ed81b3d2733eff3fefd424da9452a98c7ba7a79
        );
        _assertEq(
            IVote.ProposalBondRefunded.selector, 0x7950ce6864caac9d287350308e53b11c391f3bd7bc455e58e1c814db754ecf60
        );
        _assertEq(IVote.ProposalBondBurned.selector, 0xb7e5d2683c51bcb2296756a4963c8b5130542b95b0f975446e6f3ac3f02dfb89);
        _assertEq(IVote.ProposalErrored.selector, 0xc67a227da837cfcd61a6205491c7c4e5e187f7f490ff3ff1ba7735fe96f6f724);
    }

    function testFinalErc7943ErrorsAreFrozen() public pure {
        _assertEq(IStablecoin.ERC7943CannotSend.selector, 0x45bae9e2);
        _assertEq(IStablecoin.ERC7943CannotReceive.selector, 0x705c1eed);
        _assertEq(IStablecoin.ERC7943CannotTransfer.selector, 0x22dda4be);
        _assertEq(IStablecoin.ERC7943InsufficientUnfrozenBalance.selector, 0x00384e71);
    }

    function testPolicyEnumerationErrorIsFrozen() public pure {
        _assertEq(IStablecoinPolicyRegistry.PolicyMemberEnumerationUnsupported.selector, 0x1c8779ff);
    }

    function testRoleIdsAreFrozen() public pure {
        _assertEq(keccak256("ADMIN"), 0xdf8b4c520ffe197c5343c6f5aec59570151ef9a492f2c624fd45ddde6135ec42);
        _assertEq(keccak256("ISSUER"), 0x76afa8a5929fef1b4c03674b2152ae5aaad1d974b8a4021c59477bcc846ccc1e);
        _assertEq(keccak256("CAP_MANAGER"), 0xea85ad40095d48558c82add51498fcc17c0bbd84883ea60f8230c6b6b494ea40);
        _assertEq(keccak256("GUARDIAN"), 0x8b5b16d04624687fcf0d0228f19993c9157c1ed07b41d8d430fd9100eb099fe8);
        _assertEq(keccak256("COMPLIANCE"), 0xa67a057d728d16e162a15912cbf6e8d4fcd69e5b7b0d1f849a0a10ca6e14741c);
        _assertEq(keccak256("ENFORCER"), 0x98151564cba5aa82ec81644cc0eefc457cbd612a3d0184596373eb688d514497);
    }

    function testEip712TypeHashesAreFrozen() public pure {
        _assertEq(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9
        );
        _assertEq(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f
        );
    }

    function testEip712DomainVersionAndSeparatorsAreFrozen() public pure {
        bytes32 domainTypehash =
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        bytes32 versionHash = keccak256("1");
        _assertEq(versionHash, 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6);
        _assertEq(
            keccak256(
                abi.encode(
                    domainTypehash,
                    keccak256("Example Dollar"),
                    versionHash,
                    uint256(424242),
                    address(0x53c0438D2AA31f9642f6718cE7b1aB3253c7F350)
                )
            ),
            0xbad60a9ff5a489b59649a99c4bf6d3cf3ac4ed82c76304f0b14cbb2b8c9a83e9
        );
        _assertEq(
            keccak256(
                abi.encode(
                    domainTypehash,
                    keccak256("Example Dollar"),
                    versionHash,
                    uint256(70860602),
                    address(0x53c06885866f40057219Ad4fEdF304838f00D626)
                )
            ),
            0x6fd6dcb46e2f123e50eb7a225f84bca93ab0f49c8e40ec586cee374ec34cf167
        );
    }

    function testFactoryHasNoPublicCreationSelector() public pure {
        bytes4 forbidden = bytes4(keccak256("create(address,string,uint16,uint8,uint256,uint256)"));
        require(forbidden != IStablecoinFactory.tokenCount.selector, "public create selector");
        require(forbidden != IStablecoinFactory.listTokens.selector, "public create selector");
        require(forbidden != IStablecoinFactory.tokenById.selector, "public create selector");
        require(forbidden != IStablecoinFactory.tokenByTicker.selector, "public create selector");
        require(forbidden != IStablecoinFactory.tokenIdOf.selector, "public create selector");
        require(forbidden != IStablecoinFactory.isStablecoin.selector, "public create selector");
        require(forbidden != IStablecoinFactory.predictTokenAddress.selector, "public create selector");
    }

    function _assertEq(bytes4 actual, bytes4 expected) private pure {
        require(actual == expected, "bytes4 mismatch");
    }

    function _assertEq(bytes32 actual, bytes32 expected) private pure {
        require(actual == expected, "bytes32 mismatch");
    }
}
