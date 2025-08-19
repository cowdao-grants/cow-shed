// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {BaseTest} from "../BaseTest.sol";
import {Test, Vm} from "forge-std/Test.sol";
import {LibString} from "solady/utils/LibString.sol";
import {COWShed, Call} from "src/COWShed.sol";
import {COWShedFactory} from "src/COWShedFactory.sol";
import {IMPLEMENTATION_STORAGE_SLOT} from "src/COWShedStorage.sol";
import {LibAuthenticatedHooks} from "src/LibAuthenticatedHooks.sol";
import {ENS, IAddrResolver, INameResolver} from "src/ens.sol";
import {ForkedRpc} from "test/forked/ForkedRpc.sol";
import {LibAuthenticatedHooksCalldataProxy} from "test/lib/LibAuthenticatedHooksCalldataProxy.sol";

/// @dev Simple single owner smart wallet account that will verify signatures against
///      pre-approved and stored signatures for given hashes.
contract SmartWallet {
    error OnlyOwner();

    address public immutable owner;
    mapping(bytes32 => bytes) signatures;

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert OnlyOwner();
        }
        _;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    function sign(bytes32 hash, bytes calldata signature) external onlyOwner {
        signatures[hash] = signature;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return (keccak256(signature) == keccak256(signatures[hash]) && signatures[hash].length > 0)
            ? LibAuthenticatedHooks.MAGIC_VALUE_1271
            : bytes4(0);
    }
}

contract BaseForkedTest is BaseTest {
    // Nothing special about this block, it's the latest at the time of writing.
    uint256 constant MAINNET_FORKED_BLOCK = 22947477;

    function setUp() public virtual override {
        ForkedRpc.forkEthereumMainnetAtBlock(vm, MAINNET_FORKED_BLOCK);

        uint256 nonce = vm.getNonce(address(this));
        uint256 nonceOffset = 2;
        address factoryAddressExpected = vm.computeCreateAddress(address(this), nonce + nonceOffset);
        _setOwnerForEns(baseNode, address(factoryAddressExpected));

        super.setUp();

        require(
            factoryAddressExpected == address(factory),
            "Invalid test setup: factory address doesn't match, try to adjust the nonce offset"
        );

        assertEq(
            _reverseResolve(0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045), "vitalik.eth", "reverse resolve impl failed"
        );
    }

    function _resolveAddr(bytes32 node) internal view returns (address) {
        return IAddrResolver(ENS.resolver(node)).addr(node);
    }

    function _reverseResolve(address addr) internal view returns (string memory) {
        bytes32 node =
            vm.ensNamehash(string(abi.encodePacked(LibString.toHexStringNoPrefix(addr), ".", "addr.reverse")));
        return INameResolver(ENS.resolver(node)).name(node);
    }

    function _recordOwnerSlotInEns(bytes32 node) internal pure returns (bytes32) {
        // records mapping is in slot 0
        // rest determined with https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#mappings-and-dynamic-arrays
        return keccak256(abi.encode(node, 0));
    }

    function _setOwnerForEns(bytes32 node, address owner) internal {
        vm.store(address(ENS), _recordOwnerSlotInEns(node), bytes32(uint256(uint160(address(owner)))));
        assertEq(ENS.owner(node), address(owner), "ens owner not set as expected");
    }
}
