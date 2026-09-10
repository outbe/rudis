// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Minimal self-contained EndpointV2 mock for local two-chain simulation. NOT for production.
// Ported from intent/test/mocks/MockLayerZeroEndpoint.sol. The struct layouts match
// ILayerZeroEndpointV2 so calls from OApp (send/quote/setDelegate) resolve by selector.

struct Origin {
    uint32 srcEid;
    bytes32 sender;
    uint64 nonce;
}

struct MessagingParams {
    uint32 dstEid;
    bytes32 receiver;
    bytes message;
    bytes options;
    bool payInLzToken;
}

struct MessagingFee {
    uint256 nativeFee;
    uint256 lzTokenFee;
}

struct MessagingReceipt {
    bytes32 guid;
    uint64 nonce;
    MessagingFee fee;
}

interface ILzOAppV2 {
    function lzReceive(
        Origin calldata origin,
        bytes32 guid,
        bytes calldata message,
        address executor,
        bytes calldata extraData
    ) external payable;
}

contract EndpointV2Mock {
    uint32 public immutable EID;

    mapping(uint32 => EndpointV2Mock) public remoteEndpoints;
    mapping(uint32 => bytes32) public peers;

    address public oapp;
    address public delegate;

    /// @dev Records the `options` bytes of the most recent send, so tests can inspect per-message gas.
    bytes public lastOptions;

    error NotOApp();
    error RemoteEndpointNotSet(uint32 eid);
    error PeerNotSet(uint32 eid);

    modifier onlyOApp() {
        if (msg.sender != oapp) revert NotOApp();
        _;
    }

    constructor(uint32 _eid) {
        EID = _eid;
    }

    function setOApp(address _oapp) external {
        oapp = _oapp;
    }

    function setDelegate(address _delegate) external {
        delegate = _delegate;
    }

    function setRemoteEndpoint(uint32 _remoteEid, EndpointV2Mock _remoteEndpoint) external {
        remoteEndpoints[_remoteEid] = _remoteEndpoint;
    }

    function setPeer(uint32 _remoteEid, bytes32 _peer) external {
        peers[_remoteEid] = _peer;
    }

    function quote(
        MessagingParams calldata,
        /*_params*/
        address /*_sender*/
    )
        external
        pure
        returns (MessagingFee memory)
    {
        // Fixed fee of 100 wei for testing.
        return MessagingFee({nativeFee: 100, lzTokenFee: 0});
    }

    function send(
        MessagingParams calldata _params,
        address /*_refundAddress*/
    )
        external
        payable
        onlyOApp
        returns (MessagingReceipt memory)
    {
        lastOptions = _params.options;

        EndpointV2Mock dstEndpoint = remoteEndpoints[_params.dstEid];
        if (address(dstEndpoint) == address(0)) revert RemoteEndpointNotSet(_params.dstEid);

        bytes32 peer = peers[_params.dstEid];
        if (peer == bytes32(0)) {
            peer = _params.receiver;
            if (peer == bytes32(0)) revert PeerNotSet(_params.dstEid);
        }

        bytes32 sender = bytes32(uint256(uint160(oapp)));

        dstEndpoint.deliverMessage(EID, sender, _params.message);

        return MessagingReceipt({
            guid: keccak256(abi.encodePacked(EID, sender, _params.dstEid)),
            nonce: 1,
            fee: MessagingFee({nativeFee: msg.value, lzTokenFee: 0})
        });
    }

    /// @notice External hook for delivering a message from another endpoint.
    function deliverMessage(uint32 _srcEid, bytes32 _sender, bytes calldata _message) external {
        Origin memory origin = Origin({srcEid: _srcEid, sender: _sender, nonce: 1});

        ILzOAppV2(oapp)
            .lzReceive(
                origin,
                keccak256(abi.encodePacked(_srcEid, _sender, EID)), // guid
                _message,
                msg.sender, // executor = calling endpoint
                bytes("")
            );
    }
}
