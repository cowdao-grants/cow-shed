// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import { COWShed } from "./COWShed.sol";
import { Call } from "./ICOWAuthHook.sol";
import { COWShedProxy } from "./COWShedProxy.sol";
import { COWShedResolver } from "./COWShedResolver.sol";

contract COWShedFactory is COWShedResolver {
    error InvalidSignature();
    error NonceAlreadyUsed();

    event COWShedBuilt(address user, address shed);

    /// @notice the cowshed proxy implementation address.
    address public immutable implementation;

    /// @notice mapping of proxy address to owner address.
    mapping(address => address) public ownerOf;

    constructor(address impl, bytes32 bName, bytes32 bNode) COWShedResolver(bName, bNode) {
        implementation = impl;
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
        // deploy and initialize proxy if it doesnt exist
        if (proxy.code.length == 0) {
            COWShedProxy newProxy = new COWShedProxy{ salt: bytes32(uint256(uint160(user))) }(implementation, user);
            COWShed(payable(proxy)).initialize(address(this));
            emit COWShedBuilt(user, address(newProxy));

            // set reverse mapping of proxy to owner
            ownerOf[proxy] = user;

            // if on mainnet, set the forward and reverse resolution nodes
            if (block.chainid == 1) {
                _setReverseNode(user, proxy);
                _setForwardNode(user, proxy);
            }
        }
        // execute the hooks, the authorization checks are implemented in the
        // COWShed.executeHooks function
        COWShed(payable(proxy)).executeHooks(calls, nonce, deadline, signature);
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
}
