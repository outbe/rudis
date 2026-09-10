// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";

/// @dev An issuance message carries the set of series a chain receives from one day. Tests that
///      exercise a single series wrap it in a one-element batch.
library IssuanceBatchLib {
    function one(BridgeMsgCodec.IssuanceInstructionsPayload memory payload)
        internal
        pure
        returns (BridgeMsgCodec.IssuanceInstructionsPayload[] memory batch)
    {
        batch = new BridgeMsgCodec.IssuanceInstructionsPayload[](1);
        batch[0] = payload;
    }
}
