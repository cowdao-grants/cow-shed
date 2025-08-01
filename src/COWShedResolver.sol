// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {
    ADDR_REVERSE_NODE, ENS, IAddrResolver, IENS, INameResolver, IReverseRegistrar, sha3HexAddress
} from "./ens.sol";

import {IERC165} from "forge-std/interfaces/IERC165.sol";
import {LibString} from "solady/utils/LibString.sol";

abstract contract COWShedResolver is INameResolver, IAddrResolver, IERC165 {
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

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IAddrResolver).interfaceId || interfaceId == type(INameResolver).interfaceId
            || interfaceId == type(IERC165).interfaceId;
    }

    function _setReverseNode(address user, address proxy) internal {
        bytes32 node = keccak256(abi.encodePacked(ADDR_REVERSE_NODE, sha3HexAddress(proxy)));
        reverseResolutionNodeToAddress[node] = user;
    }

    /// @dev support resolving both checksummed and lower case addresses
    function _setForwardNode(address user, address proxy) internal returns (bool) {
        bool success1 = _trySetForwardNodeForAddressString(LibString.toHexStringChecksummed(user), proxy);
        bool success2 = _trySetForwardNodeForAddressString(LibString.toHexString(user), proxy);
        return success1 && success2;
    }

    function _trySetForwardNodeForAddressString(string memory labelString, address proxy)
        internal
        returns (bool success)
    {
        bytes32 label = keccak256(abi.encodePacked(bytes(labelString)));
        bytes32 subnode = keccak256(abi.encodePacked(baseNode, label));
        try ENS.setSubnodeRecord(baseNode, label, address(this), address(this), type(uint64).max) {
            success = true;
            forwardResolutionNodeToAddress[subnode] = proxy;
        } catch (bytes memory) {}
    }
}
