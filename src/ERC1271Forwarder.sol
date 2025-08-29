// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.25;

import {IComposableCow} from "./IComposableCow.sol";

import {IERC1271} from "./IERC1271.sol";
import {LibCowOrder} from "./LibCowOrder.sol";
import {ECDSA} from "solady/utils/ECDSA.sol";

/**
 * @title ERC1271 Forwarder - An abstract contract that implements ERC1271 forwarding to ComposableCoW
 * @author mfw78 <mfw78@rndlabs.xyz>
 * @dev Designed to be extended from by a contract that wants to use ComposableCoW
 */
abstract contract ERC1271Forwarder is IERC1271 {
    IComposableCow public immutable composableCoW;

    constructor(IComposableCow _composableCoW) {
        composableCoW = _composableCoW;
    }

    // When the pre-image doesn't match the hash, revert with this error.
    error InvalidHash();

    /**
     * Re-arrange the request into something that ComposableCoW can understand
     * @param _hash GPv2Order.Data digest
     * @param signature The abi.encoded tuple of (GPv2Order.Data, ComposableCoW.PayloadStruct)
     */
    function isValidSignature(bytes32 _hash, bytes memory signature) public view override returns (bytes4) {
        (LibCowOrder.Data memory order, IComposableCow.PayloadStruct memory payload) =
            abi.decode(signature, (LibCowOrder.Data, IComposableCow.PayloadStruct));
        bytes32 domainSeparator = composableCoW.domainSeparator();
        if (!(LibCowOrder.hash(order, domainSeparator) == _hash)) {
            revert InvalidHash();
        }

        return composableCoW.isValidSafeSignature(
            payable(address(this)), // owner
            msg.sender, // sender
            _hash, // CoW Protocol order digest
            domainSeparator, // CoW Protocol domain separator
            bytes32(0), // typeHash (not used by Composable CoW)
            abi.encode(order), // CoW Protocol order
            abi.encode(payload) // ComposableCoW.PayloadStruct
        );
    }
}
