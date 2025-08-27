// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShedStorage, IMPLEMENTATION_STORAGE_SLOT} from "./COWShedStorage.sol";
import {Call, ICOWAuthHook} from "./ICOWAuthHook.sol";
import {IPreSignStorage} from "./IPreSignStorage.sol";
import {LibAuthenticatedHooks} from "./LibAuthenticatedHooks.sol";
import {PreSignStateStorage} from "./PreSignStateStorage.sol";

contract COWShed is ICOWAuthHook, COWShedStorage {
    error InvalidSignature();
    error OnlyTrustedRole();
    error OnlySelf();
    error AlreadyInitialized();
    error OnlyAdmin();
    error OnlyAdminOrTrustedExecutorOrSelf();
    error NotPreSigned();

    event TrustedExecutorChanged(address previousExecutor, address newExecutor);
    event Upgraded(address indexed implementation);
    event PreSignStorageChanged(address indexed newStorage);

    string public constant VERSION = "2.0.0";
    IPreSignStorage public constant EMPTY_PRE_SIGN_STORAGE = IPreSignStorage(address(0));

    bytes32 internal constant domainTypeHash =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @notice only the admin or the trusted executor can call this function.
    modifier onlyTrustedRole() {
        if (msg.sender != _admin() && msg.sender != _state().trustedExecutor) {
            revert OnlyTrustedRole();
        }
        _;
    }

    /// @notice only the admin can call this function.
    modifier onlyAdmin() {
        if (msg.sender != _admin()) {
            revert OnlyAdmin();
        }
        _;
    }

    function initialize(address factory) external {
        if (_state().initialized) {
            revert AlreadyInitialized();
        }
        _state().initialized = true;
        _state().trustedExecutor = factory;
        emit TrustedExecutorChanged(address(0), factory);
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

    /// @inheritdoc ICOWAuthHook
    function resetPreSignStorage() external onlyAdmin returns (IPreSignStorage) {
        PreSignStateStorage storageContract = new PreSignStateStorage(address(this));
        _state().preSignStorage = storageContract;
        emit PreSignStorageChanged(address(storageContract));
        return storageContract;
    }

    /// @inheritdoc ICOWAuthHook
    function setPreSignStorage(IPreSignStorage storageContract) external onlyAdmin returns (IPreSignStorage) {
        _state().preSignStorage = storageContract;
        emit PreSignStorageChanged(address(storageContract));
        return storageContract;
    }

    /// @inheritdoc ICOWAuthHook
    function preSignStorage() external view returns (IPreSignStorage) {
        return _state().preSignStorage;
    }

    /// @inheritdoc ICOWAuthHook
    function isPreSignedHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline) external view returns (bool) {
        bytes32 hash = LibAuthenticatedHooks.executeHooksMessageHash(calls, nonce, deadline);
        return _isPreSignedHash(hash);
    }

    /// @inheritdoc ICOWAuthHook
    function preSignHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline, bool signed) external onlyAdmin {
        bytes32 hash = LibAuthenticatedHooks.executeHooksMessageHash(calls, nonce, deadline);

        IPreSignStorage storageContract = _state().preSignStorage;
        if (storageContract == EMPTY_PRE_SIGN_STORAGE) {
            revert PreSignStorageNotSet();
        }
        storageContract.setPreSigned(hash, signed);
    }

    /// @inheritdoc ICOWAuthHook
    function executePreSignedHooks(Call[] calldata calls, bytes32 nonce, uint256 deadline) external {
        LibAuthenticatedHooks.verifyDeadline(deadline);

        bytes32 hash = LibAuthenticatedHooks.executeHooksMessageHash(calls, nonce, deadline);

        if (!_isPreSignedHash(hash)) {
            revert NotPreSigned();
        }

        _executeCalls(calls, nonce);
    }

    /// @custom:todo doesn't make sense to commit some other contract's sigs nonce here.
    /// @inheritdoc ICOWAuthHook
    function trustedExecuteHooks(Call[] calldata calls) external onlyTrustedRole {
        LibAuthenticatedHooks.executeCalls(calls);
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

    receive() external payable {}

    /// @notice returns if a nonce is already used.
    function nonces(bytes32 nonce) external view returns (bool) {
        return _isNonceUsed(nonce);
    }

    /// @notice EIP712 domain separator for the user proxy.
    function domainSeparator() public view returns (bytes32) {
        string memory name = "COWShed";
        return keccak256(
            abi.encode(domainTypeHash, keccak256(bytes(name)), keccak256(bytes(VERSION)), block.chainid, address(this))
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

    function _isPreSignedHash(bytes32 _hash) internal view returns (bool) {
        IPreSignStorage storageContract = _state().preSignStorage;
        if (storageContract == EMPTY_PRE_SIGN_STORAGE) {
            return false; // If no storage contract, nothing is presigned
        }
        return storageContract.isPreSigned(_hash);
    }
}
