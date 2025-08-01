// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {Call, LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";

/// @dev wrapper contract since the LibAuthenticatedHooks library only accepts
///      `calldata` params, not `memory` params.
contract LibAuthenticatedHooksCalldataProxy {
    function executeHooksMessageHash(Call[] calldata calls, bytes32 nonce, uint256 deadline)
        external
        pure
        returns (bytes32)
    {
        return LibAuthenticatedHooks.executeHooksMessageHash(calls, nonce, deadline);
    }

    function hashToSign(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes32 domainSeparator)
        external
        pure
        returns (bytes32)
    {
        return LibAuthenticatedHooks.hashToSign(calls, nonce, deadline, domainSeparator);
    }

    function callsHash(Call[] calldata calls) external pure returns (bytes32) {
        return LibAuthenticatedHooks.callsHash(calls);
    }

    function callHash(Call calldata cll) external pure returns (bytes32) {
        return LibAuthenticatedHooks.callHash(cll);
    }

    function decodeEOASignature(bytes calldata signature) external pure returns (bytes32 r, bytes32 s, uint8 v) {
        return LibAuthenticatedHooks.decodeEOASignature(signature);
    }
}
