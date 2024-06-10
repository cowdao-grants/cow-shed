// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import { ICOWAuthHook, Call } from "./ICOWAuthHook.sol";
import { LibAuthenticatedHooks } from "./LibAuthenticatedHooks.sol";
import { COWShedStorage, IMPLEMENTATION_STORAGE_SLOT } from "./COWShedStorage.sol";
import { REVERSE_REGISTRAR } from "./ens.sol";

contract COWShed is ICOWAuthHook, COWShedStorage {
    error InvalidSignature();
    error OnlyTrustedExecutor();
    error OnlySelf();
    error AlreadyInitialized();
    error OnlyAdmin();
    error OnlyAdminOrTrustedExecutorOrSelf();

    event TrustedExecutorChanged(address previousExecutor, address newExecutor);
    event Upgraded(address indexed implementation);

    bytes32 internal constant domainTypeHash =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    modifier onlyTrustedExecutor() {
        if (msg.sender != _state().trustedExecutor) {
            revert OnlyTrustedExecutor();
        }
        _;
    }

    modifier onlyAdmin() {
        if (msg.sender != _admin()) {
            revert OnlyAdmin();
        }
        _;
    }

    function initialize(address factory, bool claimResolver) external {
        if (_state().initialized) {
            revert AlreadyInitialized();
        }
        _state().initialized = true;
        _state().trustedExecutor = factory;
        emit TrustedExecutorChanged(address(0), factory);

        if (block.chainid == 1 && claimResolver) {
            // transfer ownership of reverse ENS record to the factory contract
            // and also set it as the resolver
            REVERSE_REGISTRAR.claimWithResolver(factory, factory);
        }
    }

    /// @inheritdoc ICOWAuthHook
    function executeHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline, bytes calldata signature) external {
        address admin = _admin();
        (bool authorized) =
            LibAuthenticatedHooks.authenticateHooks(calls, nonce, deadline, admin, signature, domainSeparator());
        if (!authorized) {
            revert InvalidSignature();
        }
        _executeCalls(calls, nonce);
    }

    /// @custom:todo doesn't make sense to commit some other contract's sigs nonce here.
    /// @inheritdoc ICOWAuthHook
    function trustedExecuteHooks(Call[] calldata calls) external onlyTrustedExecutor {
        LibAuthenticatedHooks.executeCalls(calls);
    }

    /// @notice set resolver for reverse resolution. mostly a utility function for users who opted out of
    ///         ens at initialization, but want to initialize it after.
    function claimWithResolver(address resolver) external {
        if (msg.sender != _admin() && msg.sender != _state().trustedExecutor && msg.sender != address(this)) {
            revert OnlyAdminOrTrustedExecutorOrSelf();
        }
        // transfer ownership of reverse ENS record to the factory contract
        // and also set it as the resolver
        REVERSE_REGISTRAR.claimWithResolver(resolver, resolver);
    }

    /// @inheritdoc ICOWAuthHook
    function updateTrustedExecutor(address who) external {
        if (msg.sender != address(this)) {
            revert OnlySelf();
        }
        address prev = _state().trustedExecutor;
        _state().trustedExecutor = who;
        emit TrustedExecutorChanged(prev, who);
    }

    /// @notice Update the implementation of the proxy
    function updateImplementation(address newImplementation) external onlyAdmin {
        assembly {
            sstore(IMPLEMENTATION_STORAGE_SLOT, newImplementation)
        }
        emit Upgraded(newImplementation);
    }

    /// @notice Revoke a given nonce. Only the proxy owner/admin can do this.
    function revokeNonce(bytes32 nonce) external onlyAdmin {
        _useNonce(nonce);
    }

    receive() external payable { }

    /// @notice returns if a nonce is already used.
    function nonces(bytes32 nonce) external view returns (bool) {
        return _isNonceUsed(nonce);
    }

    /// @notice EIP712 domain separator for the user proxy.
    function domainSeparator() public view returns (bytes32) {
        string memory name = "COWShed";
        string memory version = "1.0.0";
        return keccak256(
            abi.encode(domainTypeHash, keccak256(bytes(name)), keccak256(bytes(version)), block.chainid, address(this))
        );
    }

    /// @notice trusted executor that can execute arbitrary calls without signature verifications.
    function trustedExecutor() external view returns (address) {
        return _state().trustedExecutor;
    }

    function _executeCalls(Call[] calldata calls, bytes32 nonce) internal {
        _useNonce(nonce);
        LibAuthenticatedHooks.executeCalls(calls);
    }
}
