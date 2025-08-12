// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {LibBitmap} from "solady/utils/LibBitmap.sol";

/// @dev bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
bytes32 constant IMPLEMENTATION_STORAGE_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

interface IAdminView {
    function admin() external view returns (address);
}

interface IPreSignStateStorage {
    function setPreSigned(bytes32 hash, bool signed) external;
    function isPreSigned(bytes32 hash) external view returns (bool);
}

contract COWShedStorage {
    using LibBitmap for LibBitmap.Bitmap;

    error NonceAlreadyUsed();
    error PreSignStorageNotSet();

    struct State {
        bool initialized;
        address trustedExecutor;
        address preSignStorage; // Address of PreSignStateStorage contract, 0x0 if disabled
        LibBitmap.Bitmap nonces; // Local nonces for backward compatibility
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

    function _preSign(bytes32 _hash, bool _signed) internal {
        address storageContract = _state().preSignStorage;
        if (storageContract == address(0)) {
            revert PreSignStorageNotSet();
        }
        IPreSignStateStorage(storageContract).setPreSigned(_hash, _signed);
    }

    function _isPreSigned(bytes32 _hash) internal view returns (bool) {
        address storageContract = _state().preSignStorage;
        if (storageContract == address(0)) {
            return false; // If no storage contract, nothing is presigned
        }
        return IPreSignStateStorage(storageContract).isPreSigned(_hash);
    }

    function _setPreSignStorage(address _storage) internal {
        _state().preSignStorage = _storage;
    }

    function _getPreSignStorage() internal view returns (address) {
        return _state().preSignStorage;
    }
}
