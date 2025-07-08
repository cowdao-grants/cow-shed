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
    // @notice execute given calls after authenticating the signature,
    //         verifying nonce isnt reused and that the deadline hasn't passed.
    function executeHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes calldata signature) external;
    // @notice execute arbitrary calls, only callable by the trusted executor.
    function trustedExecuteHooks(Call[] calldata calls) external;
    // @notice update the trusted executor.
    function updateTrustedExecutor(address who) external;
    // @notice execute a set of pre-signed hooks.
    function executePreSignedHooks(Call[] calldata calls, uint256 deadline) external;
    // @notice sign a set of pre-signed hooks.
    function signHooks(Call[] calldata calls, uint256 deadline, bool signed) external;
}
