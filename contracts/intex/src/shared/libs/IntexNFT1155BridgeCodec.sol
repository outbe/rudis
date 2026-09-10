// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/**
 * @title IntexNFT1155BridgeCodec
 * @author Outbe
 * @notice Encode/decode for the `IntexNFT1155Bridge` ERC-7786 wire body.
 * @dev Wire layout: `[bodyVersion(1)][msgType(1)][abi.encode(payload)]`.
 *
 *      The body migrated from a hand-rolled `abi.encodePacked` packed concat
 *      - which grew the buffer one item at a time (O(n^2) recopy) and decoded by manual offset
 *      slicing - to single-pass `abi.encode`/`abi.decode` over named structs. The body version is
 *      bumped `V1 -> V2` so any stale V1 packet fails closed via {UnsupportedBodyVersion} instead
 *      of misdecoding. `MAX_BATCH_SIZE` caps the decoded array length; address well-formedness and
 *      the zero-recipient reject stay with the adapter (it owns the crosschainMint semantics).
 */
library IntexNFT1155BridgeCodec {
    /// @notice Active body version emitted by the encoders and required by every decoder.
    /// @dev V2 marks the `abi.encodePacked` -> `abi.encode` wire change. A V1 packet now
    ///      fails closed on {UnsupportedBodyVersion} rather than misdecoding into a wrong crosschainMint.
    uint8 internal constant BODY_VERSION_V2 = 2;

    /// @notice `msgType` for a single-recipient, multi-token batch (`BatchPayload`).
    uint8 internal constant SEND = 1;

    /// @notice `msgType` for a multi-recipient batch (`MultiPayload`).
    uint8 internal constant SEND_MULTI = 2;

    /// @notice Items one bridge message may carry. Narrower than the other payload caps because a rejected
    ///         item is recorded with its revert bytes, the dearest per-item work anywhere in the protocol.
    /// @dev Enforced on the inbound decoded array length here and on the outbound crosschainBurn loop in the
    ///      adapter, so an over-size batch fails fast on the source chain before paying a bridge fee.
    uint256 internal constant MAX_BATCH_SIZE = 16;

    /// @notice Length of the `[bodyVersion(1)][msgType(1)]` header that precedes `abi.encode(body)`.
    uint256 internal constant HEADER_LEN = 2;

    /// @notice Single-recipient, multi-token batch body (`SEND`).
    struct BatchPayload {
        bytes32 to;
        uint256[] tokenIds;
        uint256[] amounts;
    }

    /// @notice Multi-recipient batch body (`SEND_MULTI`): each entry has its own recipient.
    struct MultiPayload {
        bytes32[] recipients;
        uint256[] tokenIds;
        uint256[] amounts;
    }

    /// @notice Body decoded with an unsupported `bodyVersion` byte (e.g. a stale V1 packet).
    /// @param got The version byte read from the payload.
    error UnsupportedBodyVersion(uint8 got);

    /// @notice Inbound payload is shorter than the `[bodyVersion][msgType]` header.
    /// @param got The actual payload length.
    /// @param minimum The minimum required length (`HEADER_LEN`).
    error InvalidPayloadLength(uint256 got, uint256 minimum);

    /// @notice A `bytes32` interpreted as an address has non-zero high bits - a truncated/forged
    ///         recipient that would otherwise silently round-trip through `address(uint160(...))`.
    /// @param got The malformed `bytes32` slot.
    error MalformedAddress(bytes32 got);

    /// @notice A decoded batch exceeds `MAX_BATCH_SIZE`.
    /// @param size The decoded array length.
    /// @param max The cap (`MAX_BATCH_SIZE`).
    error BatchTooLarge(uint256 size, uint256 max);

    /// @notice Decoded payload arrays have differing lengths (a forged/inconsistent inbound body).
    error ArrayLengthMismatch();

    /// @notice The body is not the canonical `abi.encode` of the routed payload type. `abi.decode`
    ///         is permissive - it will misread a wrong-schema body (e.g. a `MultiPayload` encoding
    ///         routed as `SEND`) into a garbage payload, and it ignores trailing bytes. Re-encoding
    ///         the decoded value and requiring an exact match closes both, so a mismatched or
    ///         padded packet fails closed instead of crosschain-minting to a wrong recipient.
    error MalformedBody();

    /// @notice Encode a single-recipient batch body. Single-pass `abi.encode` - no growing buffer.
    /// @param _payload The single-recipient batch (`to`, `tokenIds`, `amounts`).
    /// @return The wire body: `[BODY_VERSION_V2][SEND][abi.encode(_payload)]`.
    function encodeBatch(BatchPayload memory _payload) internal pure returns (bytes memory) {
        return abi.encodePacked(BODY_VERSION_V2, SEND, abi.encode(_payload));
    }

    /// @notice Encode a multi-recipient batch body. Single-pass `abi.encode` - no growing buffer.
    /// @param _payload The multi-recipient batch (`recipients`, `tokenIds`, `amounts`).
    /// @return The wire body: `[BODY_VERSION_V2][SEND_MULTI][abi.encode(_payload)]`.
    function encodeMulti(MultiPayload memory _payload) internal pure returns (bytes memory) {
        return abi.encodePacked(BODY_VERSION_V2, SEND_MULTI, abi.encode(_payload));
    }

    /// @notice Decode + validate a `SEND` body. Reverts {UnsupportedBodyVersion} on a non-V2
    ///         header, {MalformedBody} on a non-canonical/wrong-schema body, {ArrayLengthMismatch}
    ///         on unequal tokenId/amount arrays, and {BatchTooLarge} past the cap. Address
    ///         well-formedness is the adapter's check (it casts + crosschain-mints).
    /// @param _message The full inbound wire body (including the 2-byte header).
    /// @return payload The decoded, length- and size-validated `BatchPayload`.
    function decodeBatch(bytes calldata _message) internal pure returns (BatchPayload memory payload) {
        _assertBodyVersion(_message);
        bytes calldata body = _message[HEADER_LEN:];
        payload = abi.decode(body, (BatchPayload));
        if (keccak256(abi.encode(payload)) != keccak256(body)) revert MalformedBody();
        uint256 n = payload.tokenIds.length;
        if (n != payload.amounts.length) revert ArrayLengthMismatch();
        if (n > MAX_BATCH_SIZE) revert BatchTooLarge(n, MAX_BATCH_SIZE);
    }

    /// @notice Decode + validate a `SEND_MULTI` body. Same guards as {decodeBatch} across all three
    ///         arrays (recipients/tokenIds/amounts).
    /// @param _message The full inbound wire body (including the 2-byte header).
    /// @return payload The decoded, length- and size-validated `MultiPayload`.
    function decodeMulti(bytes calldata _message) internal pure returns (MultiPayload memory payload) {
        _assertBodyVersion(_message);
        bytes calldata body = _message[HEADER_LEN:];
        payload = abi.decode(body, (MultiPayload));
        if (keccak256(abi.encode(payload)) != keccak256(body)) revert MalformedBody();
        uint256 n = payload.recipients.length;
        if (n != payload.tokenIds.length || n != payload.amounts.length) revert ArrayLengthMismatch();
        if (n > MAX_BATCH_SIZE) revert BatchTooLarge(n, MAX_BATCH_SIZE);
    }

    /// @notice Reverts {MalformedAddress} if `_value` cannot be losslessly cast to `address`
    ///         (the high 12 bytes must be zero).
    /// @param _value The `bytes32` slot to validate as an address.
    function assertAddress(bytes32 _value) internal pure {
        if (uint256(_value) >> 160 != 0) revert MalformedAddress(_value);
    }

    /// @notice Validates the leading `bodyVersion` header byte against {BODY_VERSION_V2}.
    /// @dev Enforces `_message.length >= HEADER_LEN` ({InvalidPayloadLength}) before reading the
    ///      leading version byte, then requires it to equal {BODY_VERSION_V2}
    ///      ({UnsupportedBodyVersion}).
    /// @param _message The full inbound wire body (including the 2-byte header).
    function _assertBodyVersion(bytes calldata _message) private pure {
        if (_message.length < HEADER_LEN) revert InvalidPayloadLength(_message.length, HEADER_LEN);
        uint8 v = uint8(_message[0]);
        if (v != BODY_VERSION_V2) revert UnsupportedBodyVersion(v);
    }
}
