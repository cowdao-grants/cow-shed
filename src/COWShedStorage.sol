// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {IPreSignStorage} from "./IPreSignStorage.sol";
import {LibBitmap} from "solady/utils/LibBitmap.sol";

/// @dev bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
bytes32 constant IMPLEMENTATION_STORAGE_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

interface IAdminView {
    function admin() external view returns (address);
}

contract COWShedStorage {
    using LibBitmap for LibBitmap.Bitmap;

    error NonceAlreadyUsed();
    error PreSignStorageNotSet();

    struct State {
        bool initialized;
        address trustedExecutor;
        IPreSignStorage preSignStorage;
        LibBitmap.Bitmap nonces;
    }

    bytes32 internal constant STATE_STORAGE_SLOT = keccak256("COWShed.State");

    function _state() internal pure returns (State storage state) {
        bytes32 stateSlot = STATE_STORAGE_SLOT;
        assembly {
            state.slot := stateSlot
        }
    }

    function _admin() internal view returns (address) {
        return IAdminView(address(this)).admin();
    }

    function _useNonce(bytes32 _nonce) internal {
        if (_isNonceUsed(_nonce)) revert NonceAlreadyUsed();
        _state().nonces.set(uint256(_nonce));
    }

    function _isNonceUsed(bytes32 _nonce) internal view returns (bool) {
        return _state().nonces.get(uint256(_nonce));
    }
}
