// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {
    INameResolver, IReverseRegistrar, IENS, IAddrResolver, ENS, ADDR_REVERSE_NODE, sha3HexAddress
} from "./ens.sol";
import { LibString } from "solady/utils/LibString.sol";

abstract contract COWShedResolver is INameResolver, IAddrResolver {
    /// @notice maps the `<proxy-address>.<base-name>` node to the user address
    mapping(bytes32 => address) public reverseResolutionNodeToAddress;
    /// @notice maps the subnode label hash(`<user>`) to the proxy address
    mapping(bytes32 => address) public forwardResolutionNodeToAddress;
    /// @dev the base name string expressed as immutable since solidity doesn't support
    ///      immutable strings. E.g. `cowhooks.eth`
    bytes32 immutable baseNameSmallString;
    /// @dev the namehash of the base name. computing at runtime is unnecessary code, so supply
    ///      precomputed. The script should use the `vm.ensNamehash` cheatcode to compute it and
    ///      provide the namehash.
    bytes32 public immutable baseNode;

    constructor(bytes32 bName, bytes32 bNode) {
        baseNameSmallString = bName;
        baseNode = bNode;
    }

    /// @notice Reverse resolution name for given node.
    function name(bytes32 node) external view returns (string memory) {
        address who = reverseResolutionNodeToAddress[node];
        if (who == address(0)) return "";
        return string(abi.encodePacked(LibString.toHexStringChecksummed(who), ".", baseName()));
    }

    /// @notice eth address for the given node.
    function addr(bytes32 node) external view returns (address) {
        address user = forwardResolutionNodeToAddress[node];
        if (user == address(0)) return address(0);
        return user;
    }

    /// @notice baseName/parentName of the factory.
    function baseName() public view returns (string memory) {
        return LibString.fromSmallString(baseNameSmallString);
    }

    function supportsInterface(bytes4 interfaceId) external view returns (bool) {
        return interfaceId == IAddrResolver.addr.selector || interfaceId == INameResolver.name.selector;
    }

    function _setReverseNode(address user, address proxy) internal {
        bytes32 node = keccak256(abi.encodePacked(ADDR_REVERSE_NODE, sha3HexAddress(proxy)));
        reverseResolutionNodeToAddress[node] = user;
    }

    /// @dev support resolving both checksummed and lower case addresses
    function _setForwardNode(address user, address proxy) internal {
        _setForwardNodeForAddressString(LibString.toHexStringChecksummed(user), proxy);
        _setForwardNodeForAddressString(LibString.toHexString(user), proxy);
    }

    function _setForwardNodeForAddressString(string memory labelString, address proxy) internal {
        bytes32 label = keccak256(abi.encodePacked(bytes(labelString)));
        ENS.setSubnodeRecord(baseNode, label, address(this), address(this), type(uint64).max);
        bytes32 subnode = keccak256(abi.encodePacked(baseNode, label));
        forwardResolutionNodeToAddress[subnode] = proxy;
    }
}
