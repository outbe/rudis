// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";

/// @dev Packs the parallel bid arrays the fixtures build into the wire's one-word-per-bid form.
library BidPackLib {
    function pack(uint16[] memory quantities, uint32[] memory rates, uint32[] memory timestamps)
        internal
        pure
        returns (uint256[] memory packed)
    {
        packed = new uint256[](quantities.length);
        for (uint256 i = 0; i < quantities.length; ++i) {
            packed[i] = BridgeMsgCodec.packBid(quantities[i], rates[i], timestamps[i], 840, 840);
        }
    }
}
