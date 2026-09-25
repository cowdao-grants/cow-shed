// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {COWShed} from "./COWShed.sol";
import {COWShedProxy} from "./COWShedProxy.sol";
import {Call} from "./ICOWAuthHook.sol";

contract COWShedFactory {
    error InvalidSignature();
    error NoCodeAtImplementation();
    error NonceAlreadyUsed();
    error ProxyFundingFailed();

    event COWShedBuilt(address user, address shed);

    /// @notice the cowshed proxy implementation address.
    address public immutable implementation;

    /// @notice the deployment bytecode of a proxy as generated at compile
    /// time.
    bytes public constant PROXY_CREATION_CODE = type(COWShedProxy).creationCode;

    /// @notice mapping of proxy address to owner address.
    mapping(address => address) public ownerOf;

    constructor(address impl) {
        if (impl.code.length == 0) {
            revert NoCodeAtImplementation();
        }
        implementation = impl;
    }

    /// @notice deploy user proxy if not already deployed.
    /// @param user    - User to deploy the proxy for.
    /// @return proxy  - The deterministic address of the user proxy.
    function initializeProxy(address user) external returns (address proxy) {
        proxy = proxyOf(user);
        _initializeProxy(user, proxy);
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
        address proxy = proxyOf(user);
        // initialize the proxy
        _initializeProxy(user, proxy);

        // execute the hooks, the authorization checks are implemented in the
        // COWShed.executeHooks function
        COWShed(payable(proxy)).executeHooks(calls, nonce, deadline, signature);
    }

    /// @notice execute hooks on the caller's own proxy, without a signature.
    /// @dev Will deploy and initialize the caller's proxy at a deterministic address if one
    ///      doesn't already exist, optionally fund it with `msg.value`, and then execute the
    ///      hooks through this factory's trusted executor role.
    ///
    ///      Authorization is the caller itself: the proxy is derived from `msg.sender`, so a
    ///      caller can only ever execute hooks on the proxy it owns.
    ///
    ///      This exists because a freshly initialized proxy only trusts its owner and this
    ///      factory, which makes it impossible to deploy a proxy and call
    ///      `COWShed.trustedExecuteHooks` on it in a single transaction from an EOA.
    /// @param calls   - The hooks to execute on the caller's proxy.
    /// @return proxy  - The address of the caller's proxy.
    function executeOwnHooks(Call[] calldata calls) external payable returns (address proxy) {
        proxy = proxyOf(msg.sender);
        // initialize the proxy
        _initializeProxy(msg.sender, proxy);

        // fund the proxy so that the hooks can spend native tokens that weren't in the proxy
        // before this transaction
        if (msg.value > 0) {
            (bool success,) = proxy.call{value: msg.value}("");
            if (!success) {
                revert ProxyFundingFailed();
            }
        }

        // execute the hooks; this factory is the trusted executor of every proxy it
        // initializes, and the caller is the owner of `proxy` by construction
        COWShed(payable(proxy)).trustedExecuteHooks(calls);
    }

    /// @notice returns the address where the user proxy will get deployed. It is deterministic
    ///         deployment with create2.
    function proxyOf(address who) public view returns (address) {
        // unfortunately cannot cache the init hash since we use a constructor, which we need to use
        // to have an immutable admin variable in proxy, which is optimal for gas vs using a storage
        // variable in proxy.
        bytes32 initCodeHash = keccak256(abi.encodePacked(PROXY_CREATION_CODE, abi.encode(implementation, who)));
        return address(
            uint160(
                uint256(
                    keccak256(abi.encodePacked(hex"ff", address(this), bytes32(uint256(uint160(who))), initCodeHash))
                )
            )
        );
    }

    function _initializeProxy(address user, address proxy) internal returns (bool newlyDeployed) {
        // deploy and initialize proxy if it doesnt exist
        if (proxy.code.length == 0) {
            COWShedProxy newProxy = new COWShedProxy{salt: bytes32(uint256(uint160(user)))}(implementation, user);
            COWShed(payable(proxy)).initialize(address(this));
            emit COWShedBuilt(user, address(newProxy));

            // set reverse mapping of proxy to owner
            ownerOf[proxy] = user;
            newlyDeployed = true;
        }
    }
}
