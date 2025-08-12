// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

/// @notice Storage contract for presigned hashes, separate from main COWShed state
/// This allows users to clear presigned state by redeploying this contract
contract PreSignStateStorage {
    address public immutable cowShed;

    mapping(bytes32 => bool) public presignedHashes;

    event PreSigned(bytes32 indexed hash, bool signed);

    constructor(address _cowShed) {
        cowShed = _cowShed;
    }

    modifier onlyCowShed() {
        if (msg.sender != cowShed) {
            revert("Only COWShed can call this function");
        }
        _;
    }

    /// @notice Set a hash as presigned or not
    function setPreSigned(bytes32 hash, bool signed) external onlyCowShed {
        presignedHashes[hash] = signed;
        emit PreSigned(hash, signed);
    }

    /// @notice Check if a hash is presigned
    function isPreSigned(bytes32 hash) external view returns (bool) {
        return presignedHashes[hash];
    }
}
