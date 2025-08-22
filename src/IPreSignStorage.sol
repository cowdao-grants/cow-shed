// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

interface IPreSignStorage {
    /// @notice Pre-sign a hash, or revoke a pre-signature.
    /// @param hash The hash to pre-sign or revoke
    /// @param signed Whether the hash is pre-signed or not
    function setPreSigned(bytes32 hash, bool signed) external;

    /// @notice Check if a hash is presigned or not.
    /// @param hash The hash to check
    /// @return Whether the hash is presigned or not
    function isPreSigned(bytes32 hash) external view returns (bool);
}
