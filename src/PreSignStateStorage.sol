// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

/// @notice Storage contract for presigned hashes, separate from main COWShed state
/// This allows users to clear presigned state by redeploying this contract
contract PreSignStateStorage {
    event PreSigned(bytes32 indexed hash, bool signed);

    address public immutable cowShed;

    mapping(bytes32 => bool) public presignedHashes;

    modifier onlyCowShed() {
        if (msg.sender != cowShed) {
            revert("Only COWShed can call this function");
        }
        _;
    }

    constructor(address _cowShed) {
        cowShed = _cowShed;
    }

    /// @notice Pre-sign a hash, or revoke a pre-signature.
    /// @param hash The hash to pre-sign or revoke
    /// @param signed Whether the hash is pre-signed or not
    function setPreSigned(bytes32 hash, bool signed) external onlyCowShed {
        presignedHashes[hash] = signed;
        emit PreSigned(hash, signed);
    }

    /// @notice Check if a hash is presigned or not.
    /// @param hash The hash to check
    /// @return Whether the hash is presigned or not
    function isPreSigned(bytes32 hash) external view returns (bool) {
        return presignedHashes[hash];
    }
}
