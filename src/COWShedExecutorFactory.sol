// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {COWShedFactory} from "./COWShedFactory.sol";
import {COWShedProxy} from "./COWShedProxy.sol";
import {Call} from "./ICOWAuthHook.sol";

/// @title COWShedExecutorFactory
/// @notice A COWShedFactory that can deploy proxies preconfigured with a specific trusted
///         executor, at an address that also commits to that executor and a caller-supplied
///         salt.
/// @dev Kept as a subclass so the canonical `COWShedFactory` bytecode (and hence its
///      deterministic deployment address) is untouched. The base per-owner path
///      (`proxyOf(address)` / `initializeProxy(address)` / `executeHooks(...)`) is inherited
///      unchanged; this contract only adds the preconfigured-executor overloads.
contract COWShedExecutorFactory is COWShedFactory {
    constructor(address impl) COWShedFactory(impl) {}

    /// @notice deterministic address for a proxy preconfigured with a specific trusted executor
    ///         and salt.
    /// @dev The trusted executor and salt are committed into the create2 salt (alongside the
    ///      owner, which is also part of the proxy init code). A different trusted executor or
    ///      salt therefore yields a different address, so nobody can front-run initialization to
    ///      preconfigure the proxy at this address with a different executor. The same owner can
    ///      also have multiple independent proxies by varying `salt`.
    /// @param owner           - The owner/admin of the proxy.
    /// @param trustedExecutor - The trusted executor the proxy is initialized with.
    /// @param salt            - Arbitrary salt to allow multiple proxies per (owner, executor).
    function proxyOf(address owner, address trustedExecutor, bytes32 salt) public view returns (address) {
        bytes32 initCodeHash = keccak256(abi.encodePacked(PROXY_CREATION_CODE, abi.encode(implementation, owner)));
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(hex"ff", address(this), _create2Salt(owner, trustedExecutor, salt), initCodeHash))
                )
            )
        );
    }

    /// @notice deploy a proxy preconfigured with a specific trusted executor if not already
    ///         deployed.
    /// @param owner           - The owner/admin of the proxy.
    /// @param trustedExecutor - The trusted executor to initialize the proxy with.
    /// @param salt            - Arbitrary salt to allow multiple proxies per (owner, executor).
    /// @return proxy          - The address of the (possibly newly) deployed proxy.
    function initializeProxy(address owner, address trustedExecutor, bytes32 salt) public returns (address proxy) {
        proxy = proxyOf(owner, trustedExecutor, salt);
        if (proxy.code.length == 0) {
            new COWShedProxy{salt: _create2Salt(owner, trustedExecutor, salt)}(implementation, owner);
            COWShed(payable(proxy)).initialize(trustedExecutor);
            emit COWShedBuilt(owner, proxy);

            // set reverse mapping of proxy to owner
            ownerOf[proxy] = owner;
        }
    }

    /// @notice execute hooks on a proxy preconfigured with a specific trusted executor.
    /// @dev Will deploy and initialize the proxy at a deterministic address if one doesn't
    ///      already exist. The authorization checks are implemented in COWShed.executeHooks.
    function executeHooks(
        Call[] calldata calls,
        bytes32 nonce,
        uint256 deadline,
        address owner,
        address trustedExecutor,
        bytes32 salt,
        bytes calldata signature
    ) external {
        address proxy = initializeProxy(owner, trustedExecutor, salt);
        COWShed(payable(proxy)).executeHooks(calls, nonce, deadline, signature);
    }

    /// @dev create2 salt committing to the owner, the preconfigured trusted executor and a
    ///      user-supplied salt. The keccak output is effectively always >= 2**160, so it can
    ///      never collide with the base per-owner salt `bytes32(uint256(uint160(owner)))`.
    function _create2Salt(address owner, address trustedExecutor, bytes32 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode(owner, trustedExecutor, salt));
    }
}
