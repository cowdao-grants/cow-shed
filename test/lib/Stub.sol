// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

/// @dev dummy contract for testing
contract Stub {
    error Revert();

    function willRevert() external pure {
        revert Revert();
    }

    function callWithValue() external payable {}

    function returnUint() external pure returns (uint256) {
        return 420;
    }

    function storeAt(bytes32 slot, bytes32 value) external {
        assembly {
            sstore(slot, value)
        }
    }
}
