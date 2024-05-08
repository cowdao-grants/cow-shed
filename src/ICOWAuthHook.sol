// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

struct Call {
    address target;
    uint256 value;
    bytes callData;
    bool allowFailure;
    bool isDelegateCall;
}

interface ICOWAuthHook {
    function executeHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes calldata signature) external;
    function trustedExecuteHooks(Call[] calldata calls) external;
    function updateTrustedExecutor(address who) external;
}
