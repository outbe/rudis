// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";

/// @dev Builds a `CreateSeriesParams` for a given worldwide day. Currencies default to USD (840);
///      prices/promis carry non-zero defaults.
library CreateSeriesLib {
    /// @dev The readable id of that day's USD/USD series, e.g. `20260212-USD-U`.
    function seriesId(uint32 worldwideDay) internal pure returns (bytes14) {
        bytes memory out = "00000000-USD-U";
        for (uint256 i = 8; i > 0; --i) {
            out[i - 1] = bytes1(uint8(48 + (worldwideDay % 10)));
            worldwideDay /= 10;
        }
        return bytes14(out);
    }

    function params(uint32 worldwideDay, uint32 issuedIntexCount, uint32 callNoticePeriod)
        internal
        pure
        returns (IIntexNFT1155.CreateSeriesParams memory)
    {
        return IIntexNFT1155.CreateSeriesParams({
            seriesId: seriesId(worldwideDay),
            worldwideDay: worldwideDay,
            issuanceCurrency: 840,
            referenceCurrency: 840,
            issuedIntexCount: issuedIntexCount,
            promisLoadMinor: 100_000 * 1e6,
            entryPriceMinor: 1e6,
            floorPriceMinor: 100,
            callPriceMinor: 200,
            callTrigger: IIntexNFT1155.IntexCallTrigger({
                callWindow: 0, callThreshold: 0, callNoticePeriod: callNoticePeriod
            })
        });
    }
}
