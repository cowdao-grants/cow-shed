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
    /// @notice execute given calls after authenticating the signature,
    ///         verifying nonce isnt reused and that the deadline hasn't passed.
    function executeHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes calldata signature) external;

    /// @notice execute arbitrary calls, only callable by the trusted executor.
    function trustedExecuteHooks(Call[] calldata calls) external;

    /// @notice update the trusted executor.
    function updateTrustedExecutor(address who) external;

    /// @notice Get the address of the presign storage contract
    function preSignStorage() external view returns (address);

    /// @notice Set the presign storage contract. This enables the presign functionality.
    ///         Only the admin can call this function.
    /// @param storageContract Address of the PreSignStateStorage contract, or address(0) to disable
    function setPreSignStorage(address storageContract) external;

    /// @notice on-chain sign a set of hooks. Once signed, the calls can be executed at
    /// any time until the deadline is passed.
    /// To sign, `signed` must be set to true. To revoke a signature, `signed` must be
    /// false.
    function preSignHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline, bool signed) external;

    /// @notice check if a hook is pre-signed.
    function isPreSignedHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline) external view returns (bool);

    /// @notice execute a set of pre-signed hooks.
    function executePreSignedHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline) external;
}
