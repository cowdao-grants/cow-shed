/// @dev bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
bytes32 constant IMPLEMENTATION_STORAGE_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

interface IAdminView {
    function admin() external view returns (address);
}

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
        return IAdminView(address(this)).admin();
    }
}
