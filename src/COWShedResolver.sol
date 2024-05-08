// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {
    INameResolver, IReverseRegistrar, IENS, IAddrResolver, ENS, ADDR_REVERSE_NODE, sha3HexAddress
} from "./ens.sol";
import { LibString } from "solady/utils/LibString.sol";

abstract contract COWShedResolver is INameResolver, IAddrResolver {
    mapping(bytes32 => address) public reverseResolutionNodeToAddress;
    mapping(bytes32 => address) public forwardResolutionNodeToAddress;
    bytes32 immutable baseNameSmallString;
    bytes32 immutable baseNode;

    constructor(bytes32 bName, bytes32 bNode) {
        baseNameSmallString = bName;
        baseNode = bNode;
    }

    function name(bytes32 node) external view returns (string memory) {
        address who = reverseResolutionNodeToAddress[node];
        if (who == address(0)) return "";
        return string(abi.encodePacked(LibString.toHexStringChecksummed(who), ".", baseName()));
    }

    function addr(bytes32 node) external view returns (address) {
        address user = forwardResolutionNodeToAddress[node];
        if (user == address(0)) return address(0);
        return user;
    }

    function baseName() public view returns (string memory) {
        return LibString.fromSmallString(baseNameSmallString);
    }

    function _setReverseNode(address user, address proxy) internal {
        bytes32 node = keccak256(abi.encodePacked(ADDR_REVERSE_NODE, sha3HexAddress(proxy)));
        reverseResolutionNodeToAddress[node] = user;
    }

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
