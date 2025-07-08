// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {Call} from "./ICOWAuthHook.sol";
import {COWShedProxy} from "./COWShedProxy.sol";
import {COWShedResolver} from "./COWShedResolver.sol";

contract COWShedFactory is COWShedResolver {
    error InvalidSignature();
    error NoCodeAtImplementation();
    error NonceAlreadyUsed();
    error SettingEnsRecordsFailed();

    event COWShedBuilt(address user, address shed);

    /// @notice the cowshed proxy implementation address.
    address public immutable implementation;

    /// @notice mapping of proxy address to owner address.
    mapping(address => address) public ownerOf;

    constructor(address impl, bytes32 bName, bytes32 bNode) COWShedResolver(bName, bNode) {
        if (impl.code.length == 0) {
            revert NoCodeAtImplementation();
        }
        implementation = impl;
    }

    /// @notice deploy user proxy if not already deployed, optionally even setup the ens records.
    ///         if any user wants to opt-out of ens to save on gas, they need to initialize the proxy
    ///         prior to first hooks execution.
    /// @param user    - User to deploy the proxy for.
    /// @param withEns - whether to initialize the ens or not
    function initializeProxy(address user, bool withEns) external {
        address proxy = proxyOf(user);
        _initializeProxy(user, proxy, withEns);
        if (withEns) {
            if (!_initializeEns(user, proxy)) {
                revert SettingEnsRecordsFailed();
            }
        }
    }

    /// @notice initialize the ens records for given user proxy.
    /// @param user - User to set ens records for.
    function initializeEns(address user) external {
        address proxy = proxyOf(user);
        if (!_initializeEns(user, proxy)) {
            revert SettingEnsRecordsFailed();
        }
        COWShed(payable(proxy)).claimWithResolver(address(this));
    }

    /// @notice execute hooks on user proxy
    /// @dev Will deploy and initialize the user proxy at a deterministic address
    ///      if one doesn't already exist.
    function executeHooks(
        Call[] calldata calls,
        bytes32 nonce,
        uint256 deadline,
        address user,
        bytes calldata signature
    ) external {
        address proxy = _getInitializedProxy(user);

        // execute the hooks, the authorization checks are implemented in the
        // COWShed.executeHooks function
        COWShed(payable(proxy)).executeHooks(calls, nonce, deadline, signature);
    }

    /// @notice Pre-signs (or revokes a pre-signature) for some hooks.
    /// @dev Will deploy and initialize the user proxy at a deterministic address
    ///      if one doesn't already exist.
    function signHooks(Call[] calldata calls, uint256 deadline, bool signed) external {
        address proxy = _getInitializedProxy(msg.sender);

        // sign the hooks, because we use the msg.sender to get the proxy address, we can consider the call authenticated
        COWShed(payable(proxy)).trustedSignHooks(calls, deadline, signed);
    }

    /// @notice Execute a set of hooks as the admin.
    /// @dev Will deploy and initialize the user proxy at a deterministic address
    ///      if one doesn't already exist.
    function executeHooksAdmin(Call[] calldata calls) external {
        address proxy = _getInitializedProxy(msg.sender);

        // execute the hooks as the admin. Because we use the msg.sender to get the proxy address, we can consider the call authenticated
        COWShed(payable(proxy)).trustedExecuteHooks(calls);
    }

    /// @notice returns the address where the user proxy will get deployed. It is deterministic
    ///         deployment with create2.
    function proxyOf(address who) public view returns (address) {
        // unfortunately cannot cache the init hash since we use a constructor, which we need to use
        // to have an immutable admin variable in proxy, which is optimal for gas vs using a storage
        // variable in proxy.
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(type(COWShedProxy).creationCode, abi.encode(implementation, who)));
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(hex"ff", address(this), bytes32(uint256(uint160(who))), initCodeHash))
                )
            )
        );
    }

    function _initializeProxy(address user, address proxy, bool claimResolver) internal returns (bool newlyDeployed) {
        // deploy and initialize proxy if it doesnt exist
        if (proxy.code.length == 0) {
            COWShedProxy newProxy = new COWShedProxy{salt: bytes32(uint256(uint160(user)))}(implementation, user);
            COWShed(payable(proxy)).initialize(address(this), claimResolver);
            emit COWShedBuilt(user, address(newProxy));

            // set reverse mapping of proxy to owner
            ownerOf[proxy] = user;
            newlyDeployed = true;
        }
    }

    function _initializeEns(address user, address proxy) internal returns (bool success) {
        // if on mainnet, set the forward and reverse resolution nodes
        if (block.chainid == 1) {
            _setReverseNode(user, proxy);
            success = _setForwardNode(user, proxy);
        }
    }

    /// @notice Helper function that initializes proxy and ENS for a user and returns the proxy address
    /// @param user - User to initialize proxy for
    /// @return proxy - The proxy address for the user
    function _getInitializedProxy(address user) internal returns (address proxy) {
        proxy = proxyOf(user);
        // initialize the proxy
        bool newlyDeployed = _initializeProxy(user, proxy, true);

        // set ens records if it is a newly deployed proxy
        if (newlyDeployed) {
            // initialize the ens state, dont care if it fails, hence, ignoring the return value
            _initializeEns(user, proxy);
        }
    }
}
