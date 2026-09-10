// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity 0.8.30;

library TypeCasts {
    /// @notice Thrown when a bytes32 carries non-zero upper 96 bits and cannot narrow to an address.
    error Bytes32ToAddressOverflow(bytes32 value);

    // alignment preserving cast
    function addressToBytes32(address _addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(_addr)));
    }

    // alignment preserving cast
    function bytes32ToAddress(bytes32 _buf) internal pure returns (address) {
        if (uint256(_buf) > uint256(type(uint160).max)) revert Bytes32ToAddressOverflow(_buf);
        return address(uint160(uint256(_buf)));
    }
}
