// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @dev Decoding/matching helpers for base64 data-URI metadata assertions.
library MetadataTestLib {
    bytes internal constant JSON_PREFIX = "data:application/json;base64,";
    bytes internal constant SVG_KEY = "\"image\":\"data:image/svg+xml;base64,";

    /// @dev Strips the `data:application/json;base64,` prefix and decodes the JSON document.
    function decodeJsonDataUri(string memory uri) internal pure returns (bytes memory) {
        bytes memory uriBytes = bytes(uri);
        require(uriBytes.length > JSON_PREFIX.length, "not a json data uri");
        for (uint256 i = 0; i < JSON_PREFIX.length; ++i) {
            require(uriBytes[i] == JSON_PREFIX[i], "not a json data uri");
        }
        bytes memory b64 = new bytes(uriBytes.length - JSON_PREFIX.length);
        for (uint256 i = 0; i < b64.length; ++i) {
            b64[i] = uriBytes[i + JSON_PREFIX.length];
        }
        return b64decode(b64);
    }

    /// @dev Extracts and decodes the embedded SVG from a decoded JSON document.
    function decodeSvg(bytes memory json) internal pure returns (bytes memory) {
        int256 start = indexOf(json, SVG_KEY);
        require(start >= 0, "no svg image key");
        uint256 from = uint256(start) + SVG_KEY.length;
        uint256 end = from;
        while (end < json.length && json[end] != "\"") {
            ++end;
        }
        bytes memory b64 = new bytes(end - from);
        for (uint256 i = 0; i < b64.length; ++i) {
            b64[i] = json[from + i];
        }
        return b64decode(b64);
    }

    function contains(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        return indexOf(haystack, needle) >= 0;
    }

    function indexOf(bytes memory haystack, bytes memory needle) internal pure returns (int256) {
        if (needle.length == 0 || haystack.length < needle.length) return -1;
        for (uint256 i = 0; i <= haystack.length - needle.length; ++i) {
            bool matched = true;
            for (uint256 j = 0; j < needle.length; ++j) {
                if (haystack[i + j] != needle[j]) {
                    matched = false;
                    break;
                }
            }
            if (matched) return int256(i);
        }
        return -1;
    }

    function b64decode(bytes memory data) internal pure returns (bytes memory) {
        uint256 len = data.length;
        if (len == 0) return "";
        uint256 padding = 0;
        if (data[len - 1] == "=") padding++;
        if (data[len - 2] == "=") padding++;
        uint256 decodedLen = (len / 4) * 3 - padding;
        bytes memory result = new bytes(decodedLen);
        uint256 j = 0;
        for (uint256 i = 0; i < len; i += 4) {
            uint256 triple = (_b64char(data[i]) << 18) | (_b64char(data[i + 1]) << 12) | (_b64char(data[i + 2]) << 6)
                | _b64char(data[i + 3]);
            if (j < decodedLen) result[j++] = bytes1(uint8(triple >> 16));
            if (j < decodedLen) result[j++] = bytes1(uint8(triple >> 8));
            if (j < decodedLen) result[j++] = bytes1(uint8(triple));
        }
        return result;
    }

    function _b64char(bytes1 c) private pure returns (uint256) {
        uint8 x = uint8(c);
        if (x >= 65 && x <= 90) return x - 65; // A-Z
        if (x >= 97 && x <= 122) return x - 71; // a-z
        if (x >= 48 && x <= 57) return x + 4; // 0-9
        if (x == 43) return 62; // +
        if (x == 47) return 63; // /
        return 0; // '=' padding
    }
}
