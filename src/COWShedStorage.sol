/// @dev bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
///      ERC1967 standard storage slot for proxy admin
bytes32 constant ADMIN_STORAGE_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

/// @dev bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
bytes32 constant IMPLEMENTATION_STORAGE_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

contract COWShedStorage {
    struct State {
        bool initialized;
        address trustedExecutor;
        mapping(bytes32 => bool) nonces;
    }

    bytes32 internal constant STATE_STORAGE_SLOT = keccak256("COWShed.State");

    function _state() internal pure returns (State storage state) {
        bytes32 stateSlot = STATE_STORAGE_SLOT;
        assembly {
            state.slot := stateSlot
        }
    }

    function _admin() internal view returns (address) {
        address admin;
        assembly {
            admin := sload(ADMIN_STORAGE_SLOT)
        }
        return admin;
    }
}
