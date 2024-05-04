import { ICOWAuthHook, Call } from "./ICOWAuthHook.sol";
import { LibAuthenticatedHooks } from "./LibAuthenticatedHooks.sol";

/// @dev bytes32(uint256(keccak256('eip1967.proxy.admin')) - 1)
///      ERC1967 standard storage slot for proxy admin
bytes32 constant ADMIN_STORAGE_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

/// @dev bytes32(uint256(keccak256('eip1967.proxy.implementation')) - 1)
bytes32 constant IMPLEMENTATION_STORAGE_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

contract COWShedStorage {
    struct State {
        bool initialized;
        mapping(address => bool) trustedExecutors;
        mapping(bytes32 => bool) nonces;
    }

    /// @dev keccak256("COWShed.State")
    bytes32 internal constant STATE_STORAGE_SLOT = 0x68df44b1011761f481358c0f49a711192727fb02c377d697bcb0ea8ff8393ac0;

    function _state() internal pure returns (State storage state) {
        assembly {
            state.slot := STATE_STORAGE_SLOT
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

contract COWShed is ICOWAuthHook, COWShedStorage {
    error InvalidSignature();
    error NonceAlreadyUsed();
    error OnlyTrustedExecutor();
    error OnlySelf();
    error AlreadyInitialized();
    error OnlyAdmin();

    event TrustedExecutorUpdated(address indexed who, bool authorized);
    event AdminChanged(address previousAdmin, address newAdmin);
    event Upgraded(address indexed implementation);

    bytes32 internal constant domainTypeHash =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    modifier onlyTrustedExecutor() {
        if (!_state().trustedExecutors[msg.sender]) {
            revert OnlyTrustedExecutor();
        }
        _;
    }

    function initialize(address implementation, address admin, Call[] calldata calls) external {
        if (_state().initialized) {
            revert AlreadyInitialized();
        }
        _state().initialized = true;

        assembly {
            sstore(ADMIN_STORAGE_SLOT, admin)
            sstore(IMPLEMENTATION_STORAGE_SLOT, implementation)
        }
        emit AdminChanged(address(0), admin);
        emit Upgraded(implementation);

        LibAuthenticatedHooks.executeCalls(calls);
    }

    function executeHooks(Call[] calldata calls, bytes32 nonce, bytes32 r, bytes32 s, uint8 v) external {
        (bool authorized, address recovered) =
            LibAuthenticatedHooks.authenticateHooks(calls, nonce, r, s, v, domainSeparator());
        if (!authorized || recovered != _admin()) {
            revert InvalidSignature();
        }
        _executeCalls(calls, nonce);
    }

    /// @custom:todo doesn't make sense to commit some other contract's sigs nonce here.
    function trustedExecuteHooks(Call[] calldata calls) external onlyTrustedExecutor {
        LibAuthenticatedHooks.executeCalls(calls);
    }

    function updateTrustedExecutor(address who, bool authorized) external {
        if (msg.sender != address(this)) {
            revert OnlySelf();
        }
        _state().trustedExecutors[who] = authorized;
        emit TrustedExecutorUpdated(who, authorized);
    }

    function updateImplementation(address newImplementation) external {
        if (msg.sender != _admin()) {
            revert OnlyAdmin();
        }
        assembly {
            sstore(IMPLEMENTATION_STORAGE_SLOT, newImplementation)
        }
        emit Upgraded(newImplementation);
    }

    function domainSeparator() public view returns (bytes32) {
        string memory name = "COWShed";
        string memory version = "1.0.0";
        return keccak256(
            abi.encode(domainTypeHash, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, address(this))
        );
    }

    receive() external payable { }

    function _consumeNonce(bytes32 _nonce) internal {
        if (_state().nonces[_nonce]) {
            revert NonceAlreadyUsed();
        }
        _state().nonces[_nonce] = true;
    }

    function _executeCalls(Call[] calldata calls, bytes32 nonce) internal {
        _consumeNonce(nonce);
        LibAuthenticatedHooks.executeCalls(calls);
    }
}

contract COWShedProxy is COWShedStorage {
    error InvalidInitialization();

    fallback() external payable {
        address implementation;
        assembly {
            implementation := sload(IMPLEMENTATION_STORAGE_SLOT)
        }

        if (implementation == address(0)) {
            implementation = _initialize();
        }

        (bool success, bytes memory ret) = implementation.delegatecall(msg.data);
        if (!success) {
            // bubble up the revert
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    function _initialize() internal pure returns (address) {
        if (msg.sig != COWShed.initialize.selector) {
            revert InvalidInitialization();
        }
        return abi.decode(msg.data[4:], (address));
    }
}
