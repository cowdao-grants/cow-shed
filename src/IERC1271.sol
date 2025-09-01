// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}
